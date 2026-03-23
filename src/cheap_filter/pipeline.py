"""Main pipeline: filter → snippet extraction → LLM verification.

Two filter modes:
  "classic"  — clang-tidy + clang-analyzer (flag known bugs → LLM confirms)
  "inverted" — danger collector + safe excluder (find all danger, subtract safety → LLM verifies)

The inverted mode is the core idea of this project: higher recall, let the LLM handle precision.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from .filters.base import FilterResult, SuspiciousRegion
from .filters.clang_analyzer import ClangAnalyzerFilter
from .filters.clang_tidy import ClangTidyFilter
from .filters.danger_collector import DangerCollector
from .filters.safe_excluder import SafeExcluder
from .llm.client import LLMClient, VulnVerdict
from .metrics import ScanMetrics

log = logging.getLogger(__name__)

CONTEXT_LINES = 30


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(errors="replace").splitlines()
    except OSError:
        return []


def _extract_snippet(region: SuspiciousRegion, lines: list[str]) -> str:
    start, end = region.context_window(CONTEXT_LINES)
    start = max(0, start - 1)
    end = min(len(lines), end)
    numbered = [f"{i+1:5d} | {lines[i]}" for i in range(start, end)]
    return "\n".join(numbered)


class Pipeline:
    """Orchestrates filter → LLM over a directory of C++ files."""

    def __init__(
        self,
        mode: str = "inverted",  # "inverted" or "classic"
        use_clang_analyzer: bool = True,
        use_clang_tidy: bool = True,
        compile_commands: Path | None = None,
        api_key: str | None = None,
        dry_run: bool = False,
    ) -> None:
        self.mode = mode
        self.dry_run = dry_run

        # Classic mode filters
        self.classic_filters: list[ClangAnalyzerFilter | ClangTidyFilter] = []
        if mode == "classic":
            if use_clang_analyzer:
                self.classic_filters.append(ClangAnalyzerFilter())
            if use_clang_tidy:
                self.classic_filters.append(ClangTidyFilter(compile_commands=compile_commands))

        # Inverted mode components
        self.danger_collector = DangerCollector() if mode == "inverted" else None
        self.safe_excluder = SafeExcluder() if mode == "inverted" else None

        self.llm = LLMClient(api_key=api_key) if not dry_run else None

    def scan(
        self,
        files: list[Path],
        on_verdict: Callable[[VulnVerdict], None] | None = None,
        on_filter_progress: Callable[[str], None] | None = None,
    ) -> ScanMetrics:
        metrics = ScanMetrics(files_scanned=len(files))

        if self.mode == "inverted":
            regions_by_file = self._filter_inverted(files, metrics, on_filter_progress)
        else:
            regions_by_file = self._filter_classic(files, metrics, on_filter_progress)

        if self.dry_run or self.llm is None:
            return metrics

        # --- LLM verification ---
        file_lines_cache: dict[Path, list[str]] = {}
        for path, regions in regions_by_file.items():
            lines = file_lines_cache.get(path) or _read_lines(path)
            file_lines_cache[path] = lines

            seen: set[int] = set()
            for region in regions:
                if region.line_start in seen:
                    continue
                seen.add(region.line_start)

                snippet = _extract_snippet(region, lines)
                verdict = self.llm.verify(region, snippet)
                metrics.record(verdict)
                if on_verdict:
                    on_verdict(verdict)

        return metrics

    def _filter_inverted(
        self,
        files: list[Path],
        metrics: ScanMetrics,
        on_progress: Callable[[str], None] | None,
    ) -> dict[Path, list[SuspiciousRegion]]:
        """Collect all danger sites, exclude known-safe, return remainder."""
        assert self.danger_collector and self.safe_excluder

        all_regions: dict[Path, list[SuspiciousRegion]] = {}
        file_lines_cache: dict[Path, list[str]] = {}
        total_danger = 0
        total_excluded = 0

        for i, f in enumerate(files):
            if on_progress and i % 50 == 0:
                on_progress(f"[inverted] scanning {i}/{len(files)}: {f.name}")

            sites = self.danger_collector.collect(f)
            total_danger += len(sites)

            if not sites:
                continue

            suspicious, excluded = self.safe_excluder.filter(sites, file_lines_cache)
            total_excluded += len(excluded)

            if suspicious:
                all_regions[f] = suspicious

        metrics.files_flagged_by_filter = len(all_regions)
        metrics.regions_flagged = sum(len(v) for v in all_regions.values())

        if on_progress:
            on_progress(
                f"[inverted] done: {total_danger} danger sites → "
                f"{total_excluded} excluded → "
                f"{metrics.regions_flagged} to LLM"
            )

        return all_regions

    def _filter_classic(
        self,
        files: list[Path],
        metrics: ScanMetrics,
        on_progress: Callable[[str], None] | None,
    ) -> dict[Path, list[SuspiciousRegion]]:
        """Run clang-tidy / clang-analyzer, return flagged regions."""
        all_regions: dict[Path, list[SuspiciousRegion]] = {}
        for filt in self.classic_filters:
            if on_progress:
                on_progress(f"[classic] running {type(filt).__name__}...")
            result: FilterResult = filt.run(files)
            for region in result.regions:
                all_regions.setdefault(region.file, []).append(region)

        metrics.files_flagged_by_filter = len(all_regions)
        metrics.regions_flagged = sum(len(v) for v in all_regions.values())
        return all_regions

    @staticmethod
    def collect_cpp_files(root: Path, max_files: int | None = None) -> list[Path]:
        extensions = {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"}
        files = [
            p for p in root.rglob("*")
            if p.suffix in extensions and p.is_file()
        ]
        files.sort()
        if max_files:
            files = files[:max_files]
        return files
