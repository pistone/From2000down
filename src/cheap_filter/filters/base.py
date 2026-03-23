"""Base types for the filter layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class VulnClass(str, Enum):
    """Vulnerability classes targeted — mirrors Anthropic/Mozilla findings."""
    USE_AFTER_FREE = "use-after-free"
    BUFFER_OVERFLOW = "buffer-overflow"
    INTEGER_OVERFLOW = "integer-overflow"
    DOUBLE_FREE = "double-free"
    NULL_DEREF = "null-deref"
    TYPE_CONFUSION = "type-confusion"
    MEMORY_LEAK = "memory-leak"
    UNINITIALIZED = "uninitialized-read"


@dataclass
class SuspiciousRegion:
    """A code region flagged by the static filter."""
    file: Path
    line_start: int
    line_end: int
    vuln_class: VulnClass
    message: str
    checker: str  # e.g. "clang-analyzer-cplusplus.NewDelete"
    confidence: float = 1.0  # 0–1; static tools are usually binary

    def context_window(self, extra_lines: int = 20) -> tuple[int, int]:
        """Return (start, end) with padding for LLM context."""
        return max(1, self.line_start - extra_lines), self.line_end + extra_lines


@dataclass
class FilterResult:
    """Aggregated output of one filter pass over a set of files."""
    regions: list[SuspiciousRegion] = field(default_factory=list)
    files_scanned: int = 0
    files_flagged: int = 0

    def by_file(self) -> dict[Path, list[SuspiciousRegion]]:
        out: dict[Path, list[SuspiciousRegion]] = {}
        for r in self.regions:
            out.setdefault(r.file, []).append(r)
        return out

    def by_vuln_class(self) -> dict[VulnClass, list[SuspiciousRegion]]:
        out: dict[VulnClass, list[SuspiciousRegion]] = {}
        for r in self.regions:
            out.setdefault(r.vuln_class, []).append(r)
        return out
