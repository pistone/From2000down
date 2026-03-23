"""Evaluation: run the filter on Firefox source and score against ground truth CVEs.

Measures:
  1. Recall — did the filter flag at least one region in each CVE's source directory?
  2. Volume — how many total regions survive the filter (→ LLM cost projection)?
  3. Cost — projected API spend to verify all surviving regions with Claude.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from .filters.base import SuspiciousRegion
from .filters.danger_collector import DangerCollector
from .filters.file_filter import filter_files
from .filters.safe_excluder import SafeExcluder

log = logging.getLogger(__name__)

# Opus 4.6 pricing
INPUT_COST_PER_TOKEN = 5e-6       # $5 / 1M tokens
OUTPUT_COST_PER_TOKEN = 25e-6     # $25 / 1M tokens
CACHED_INPUT_COST_PER_TOKEN = 0.5e-6  # ~$0.50 / 1M cached

# Estimated tokens per LLM call (system prompt cached after first call)
EST_INPUT_TOKENS_PER_CALL = 2000   # ~60 lines of code context
EST_OUTPUT_TOKENS_PER_CALL = 300   # JSON verdict
EST_SYSTEM_PROMPT_TOKENS = 500     # cached after first call


@dataclass
class CVEEntry:
    id: str
    component: str
    vuln_type: str
    severity: str
    source_dirs: list[str]
    source_files_hint: list[str]
    notes: str = ""


@dataclass
class CVERecall:
    """Whether the filter covered a specific CVE."""
    cve: CVEEntry
    covered: bool
    matching_regions: list[SuspiciousRegion] = field(default_factory=list)
    files_in_dir: int = 0  # how many C++ files exist in the CVE's source dirs


@dataclass
class EvalResult:
    # Ground truth
    total_cves: int = 0
    cves_covered: int = 0
    cves_missed: int = 0
    per_cve: list[CVERecall] = field(default_factory=list)

    # Pre-filter (file-level)
    total_files_found: int = 0
    files_skipped_by_prefilter: int = 0
    files_after_prefilter: int = 0

    # Filter output
    total_files_scanned: int = 0
    total_danger_sites: int = 0
    total_excluded: int = 0
    total_surviving_regions: int = 0

    # Cost projection
    projected_cost_usd: float = 0.0

    @property
    def recall(self) -> float:
        return self.cves_covered / self.total_cves if self.total_cves else 0.0

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "CHEAP-FILTER EVALUATION RESULTS",
            "=" * 60,
            "",
            "--- Ground Truth Recall ---",
            f"Total CVEs:          {self.total_cves}",
            f"CVEs covered:        {self.cves_covered}",
            f"CVEs missed:         {self.cves_missed}",
            f"Recall:              {self.recall:.1%}",
            "",
        ]

        # Per-CVE detail
        for cr in self.per_cve:
            icon = "PASS" if cr.covered else "MISS"
            regions = len(cr.matching_regions)
            lines.append(
                f"  [{icon}] {cr.cve.id}  {cr.cve.component:30s}  "
                f"{cr.cve.vuln_type:20s}  regions={regions}  "
                f"files_in_dir={cr.files_in_dir}"
            )

        prefilter_pct = (
            self.files_skipped_by_prefilter / self.total_files_found * 100
            if self.total_files_found else 0
        )
        lines += [
            "",
            "--- File Pre-Filter ---",
            f"Total C++ files:     {self.total_files_found:,}",
            f"Skipped (pre-filter):{self.files_skipped_by_prefilter:,} ({prefilter_pct:.0f}%)",
            f"Files to scan:       {self.files_after_prefilter:,}",
            "",
            "--- Danger Collector + Safe Excluder ---",
            f"Danger sites found:  {self.total_danger_sites:,}",
            f"Excluded (safe):     {self.total_excluded:,}",
            f"Surviving regions:   {self.total_surviving_regions:,}",
            f"Overall reduction:   {1 - self.total_surviving_regions / max(self.total_danger_sites, 1):.1%}",
            "",
            "--- Projected LLM Cost (Opus 4.6) ---",
            f"LLM calls needed:    {self.total_surviving_regions:,}",
            f"Projected cost:      ${self.projected_cost_usd:.2f}",
            f"  (input: ~{EST_INPUT_TOKENS_PER_CALL} tok/call, "
            f"output: ~{EST_OUTPUT_TOKENS_PER_CALL} tok/call, "
            f"system prompt cached)",
            "",
            "--- Comparison with Anthropic ---",
            f"Anthropic spent ~$2,000 on discovery stage",
            f"Anthropic scanned ~6,000 files, found 22 CVEs from 112 reports",
            f"Our projected cost:  ${self.projected_cost_usd:.2f} for {self.total_surviving_regions:,} LLM calls",
            "=" * 60,
        ]
        return "\n".join(lines)


def load_ground_truth(path: Path) -> list[CVEEntry]:
    data = json.loads(path.read_text())
    return [
        CVEEntry(
            id=c["id"],
            component=c["component"],
            vuln_type=c["vuln_type"],
            severity=c["severity"],
            source_dirs=c["source_dirs"],
            source_files_hint=c.get("source_files_hint", []),
            notes=c.get("notes", ""),
        )
        for c in data["cves"]
    ]


def _collect_cpp_files(root: Path) -> list[Path]:
    extensions = {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"}
    return sorted(
        p for p in root.rglob("*")
        if p.suffix in extensions and p.is_file()
    )


def run_eval(
    firefox_root: Path,
    ground_truth_path: Path,
    on_progress: "Callable[[str], None] | None" = None,
) -> EvalResult:
    """Run the inverted filter on Firefox source and score against ground truth."""
    cves = load_ground_truth(ground_truth_path)
    result = EvalResult(total_cves=len(cves))

    # Collect all C++ files
    if on_progress:
        on_progress("Collecting C++ files...")
    all_files = _collect_cpp_files(firefox_root)
    result.total_files_found = len(all_files)
    if on_progress:
        on_progress(f"Found {len(all_files):,} C++ files")

    # Apply file-level pre-filter
    scan_files, skipped_files = filter_files(all_files, firefox_root, on_progress=on_progress)
    result.files_skipped_by_prefilter = len(skipped_files)
    result.files_after_prefilter = len(scan_files)
    result.total_files_scanned = len(scan_files)

    # Build index: source_dir → list of files (use ALL files for recall scoring)
    dir_files: dict[str, list[Path]] = {}
    for f in all_files:
        try:
            rel = f.relative_to(firefox_root)
        except ValueError:
            continue
        for part_count in range(1, len(rel.parts)):
            dir_key = str(Path(*rel.parts[:part_count]))
            dir_files.setdefault(dir_key, []).append(f)

    # Run the inverted filter on surviving files only
    collector = DangerCollector()
    excluder = SafeExcluder()

    all_regions: dict[Path, list[SuspiciousRegion]] = {}
    file_lines_cache: dict[Path, list[str]] = {}
    total_danger = 0
    total_excluded = 0

    for i, f in enumerate(scan_files):
        if on_progress and i % 200 == 0:
            on_progress(f"Scanning {i:,}/{len(scan_files):,}: {f.name}")

        sites = collector.collect(f)
        total_danger += len(sites)

        if not sites:
            continue

        suspicious, excluded = excluder.filter(sites, file_lines_cache)
        total_excluded += len(excluded)

        if suspicious:
            all_regions[f] = suspicious

    result.total_danger_sites = total_danger
    result.total_excluded = total_excluded
    result.total_surviving_regions = sum(len(v) for v in all_regions.values())

    if on_progress:
        on_progress(
            f"Filter done: {total_danger:,} danger → "
            f"{total_excluded:,} excluded → "
            f"{result.total_surviving_regions:,} surviving"
        )

    # Score recall per CVE
    for cve in cves:
        cr = CVERecall(cve=cve, covered=False)

        # Count files in this CVE's source dirs
        cve_files: set[Path] = set()
        for d in cve.source_dirs:
            cve_files.update(dir_files.get(d, []))
        cr.files_in_dir = len(cve_files)

        # Check if any surviving region falls in a CVE source dir
        for f, regions in all_regions.items():
            try:
                rel = str(f.relative_to(firefox_root))
            except ValueError:
                continue
            for d in cve.source_dirs:
                if rel.startswith(d + "/") or rel.startswith(d + "\\"):
                    cr.covered = True
                    cr.matching_regions.extend(regions)
                    break

        # Also check specific file hints
        if not cr.covered and cve.source_files_hint:
            for hint in cve.source_files_hint:
                hint_path = firefox_root / hint
                if hint_path in all_regions:
                    cr.covered = True
                    cr.matching_regions.extend(all_regions[hint_path])

        if cr.covered:
            result.cves_covered += 1
        else:
            result.cves_missed += 1

        result.per_cve.append(cr)

    # Cost projection
    n = result.total_surviving_regions
    if n > 0:
        # First call: full system prompt. Rest: cached.
        first_call_input = EST_SYSTEM_PROMPT_TOKENS + EST_INPUT_TOKENS_PER_CALL
        rest_calls_input = EST_INPUT_TOKENS_PER_CALL  # system prompt cached
        cached_tokens = EST_SYSTEM_PROMPT_TOKENS * (n - 1)

        total_input = first_call_input + rest_calls_input * (n - 1)
        total_output = EST_OUTPUT_TOKENS_PER_CALL * n

        cost = (
            (total_input - cached_tokens) * INPUT_COST_PER_TOKEN
            + cached_tokens * CACHED_INPUT_COST_PER_TOKEN
            + total_output * OUTPUT_COST_PER_TOKEN
        )
        result.projected_cost_usd = cost

    return result
