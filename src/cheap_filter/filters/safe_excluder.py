"""Safe Pattern Excluder: subtract known-safe patterns from the danger set.

This is the key innovation of cheap-filter. Instead of "find bugs" (high FN),
we "find all danger, remove known safety" (low FN, high FP — LLM handles FP).

Each exclusion rule is a function that returns True if the site is safe.
Rules are composed: if ANY rule says "safe", the site is excluded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .base import FilterResult, SuspiciousRegion, VulnClass
from .danger_collector import DangerCollector, DangerousSite


@dataclass
class ExclusionReason:
    rule: str
    explanation: str


# ---------------------------------------------------------------------------
# Exclusion rules — each returns an ExclusionReason if the site is safe, else None
# ---------------------------------------------------------------------------

def _rule_destructor_free(site: DangerousSite, file_lines: list[str]) -> ExclusionReason | None:
    """Free/delete inside a destructor with no raw-ptr escape is RAII-safe."""
    if site.is_in_destructor and site.kind in ("free", "delete"):
        return ExclusionReason(
            rule="destructor_free",
            explanation=f"Deallocation in destructor ~{site.enclosing_function}() — RAII pattern",
        )
    return None


def _rule_null_after_free(site: DangerousSite, file_lines: list[str]) -> ExclusionReason | None:
    """free(ptr); ptr = nullptr; with no use in between."""
    if site.kind not in ("free", "delete"):
        return None
    if site.pointer_name is None:
        return None

    # Look at the next 3 lines for `ptr = nullptr` or `ptr = NULL` or `ptr = 0`
    for offset in range(1, 4):
        idx = site.line - 1 + offset  # 0-indexed
        if idx >= len(file_lines):
            break
        line = file_lines[idx].strip()
        pattern = rf"\b{re.escape(site.pointer_name)}\s*=\s*(nullptr|NULL|0)\s*;"
        if re.search(pattern, line):
            return ExclusionReason(
                rule="null_after_free",
                explanation=f"{site.pointer_name} set to null immediately after free",
            )
    return None


def _rule_smart_ptr_release_with_reassign(
    site: DangerousSite, file_lines: list[str]
) -> ExclusionReason | None:
    """smart_ptr.release() where the result is immediately captured."""
    if site.kind != "release":
        return None
    # Check if the line contains an assignment: `auto* p = foo.release();`
    line = file_lines[site.line - 1] if site.line <= len(file_lines) else ""
    if "=" in line and "release()" in line:
        return ExclusionReason(
            rule="release_reassign",
            explanation="Smart pointer release() with immediate reassignment of ownership",
        )
    return None


def _rule_scope_local_only(site: DangerousSite, file_lines: list[str]) -> ExclusionReason | None:
    """Raw pointer declared and freed in the same small scope with no return/escape.

    Heuristic: if the pointer name only appears within ±15 lines and there's
    no `return ptr`, `*out = ptr`, or function call passing ptr, it's likely local.
    """
    if site.kind not in ("free", "delete"):
        return None
    if site.pointer_name is None:
        return None

    name = site.pointer_name
    start = max(0, site.line - 16)
    end = min(len(file_lines), site.line + 15)
    window = file_lines[start:end]
    window_text = "\n".join(window)

    # Check for escape patterns
    escape_patterns = [
        rf"\breturn\s+{re.escape(name)}\b",
        rf"\*\w+\s*=\s*{re.escape(name)}\b",  # *out = ptr
        # function call with ptr as argument (but not the free() itself)
        # This is a rough heuristic
    ]
    for pat in escape_patterns:
        if re.search(pat, window_text):
            return None  # pointer escapes — not safe

    # Count appearances: if only appears 2-3 times (decl, use, free), likely local
    count = len(re.findall(rf"\b{re.escape(name)}\b", window_text))
    if count <= 4:
        return ExclusionReason(
            rule="scope_local",
            explanation=f"{name} appears {count} times in ±15 lines with no escape — likely scope-local",
        )
    return None


def _rule_error_path_cleanup(site: DangerousSite, file_lines: list[str]) -> ExclusionReason | None:
    """Free inside an error-handling block (goto fail, if (err), etc.) is cleanup.

    Note: we do NOT exclude these — error paths are a common source of UAF bugs.
    This rule exists to document that we intentionally keep them.
    """
    return None  # Never excludes — error paths stay in the danger set


# Ordered list of all exclusion rules
ALL_RULES = [
    _rule_destructor_free,
    _rule_null_after_free,
    _rule_smart_ptr_release_with_reassign,
    _rule_scope_local_only,
    # _rule_error_path_cleanup is intentionally not excluding
]


class SafeExcluder:
    """Apply exclusion rules to a set of DangerousSites and emit remaining as SuspiciousRegions."""

    def __init__(self, rules: list | None = None) -> None:
        self.rules = rules or ALL_RULES

    def filter(
        self,
        sites: list[DangerousSite],
        file_lines_cache: dict[Path, list[str]] | None = None,
    ) -> tuple[list[SuspiciousRegion], list[tuple[DangerousSite, ExclusionReason]]]:
        """Return (suspicious, excluded) — suspicious goes to LLM, excluded is logged."""
        file_lines_cache = file_lines_cache or {}
        suspicious: list[SuspiciousRegion] = []
        excluded: list[tuple[DangerousSite, ExclusionReason]] = []

        for site in sites:
            lines = self._get_lines(site.file, file_lines_cache)
            reason = self._try_exclude(site, lines)
            if reason:
                excluded.append((site, reason))
            else:
                suspicious.append(self._to_region(site))

        return suspicious, excluded

    def _try_exclude(self, site: DangerousSite, file_lines: list[str]) -> ExclusionReason | None:
        for rule in self.rules:
            reason = rule(site, file_lines)
            if reason:
                return reason
        return None

    @staticmethod
    def _to_region(site: DangerousSite) -> SuspiciousRegion:
        kind_to_vuln = {
            "free": VulnClass.USE_AFTER_FREE,
            "delete": VulnClass.USE_AFTER_FREE,
            "release": VulnClass.USE_AFTER_FREE,
            "raw_ptr_decl": VulnClass.USE_AFTER_FREE,
        }
        return SuspiciousRegion(
            file=site.file,
            line_start=site.line,
            line_end=site.line,
            vuln_class=kind_to_vuln.get(site.kind, VulnClass.USE_AFTER_FREE),
            message=f"{site.kind}: {site.source_text}",
            checker=f"cheap-filter/{site.kind}",
        )

    @staticmethod
    def _get_lines(path: Path, cache: dict[Path, list[str]]) -> list[str]:
        if path not in cache:
            try:
                cache[path] = path.read_text(errors="replace").splitlines()
            except OSError:
                cache[path] = []
        return cache[path]
