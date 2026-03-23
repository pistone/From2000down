"""Clang Static Analyzer filter.

Runs `clang --analyze` with memory-safety checkers and parses plist output.
This is the highest-signal filter for UAF / double-free / memory bugs.
"""

from __future__ import annotations

import plistlib
import subprocess
import tempfile
from pathlib import Path

from .base import FilterResult, SuspiciousRegion, VulnClass

# Map clang checker IDs → our VulnClass
CHECKER_MAP: dict[str, VulnClass] = {
    "cplusplus.NewDelete": VulnClass.USE_AFTER_FREE,
    "cplusplus.NewDeleteLeaks": VulnClass.MEMORY_LEAK,
    "cplusplus.PlacementNew": VulnClass.USE_AFTER_FREE,
    "alpha.cplusplus.STLAlgorithmModeling": VulnClass.USE_AFTER_FREE,
    "security.insecureAPI.DeprecatedOrUnsafeBufferHandling": VulnClass.BUFFER_OVERFLOW,
    "alpha.security.ArrayBound": VulnClass.BUFFER_OVERFLOW,
    "alpha.security.ArrayBoundV2": VulnClass.BUFFER_OVERFLOW,
    "alpha.security.MallocOverflow": VulnClass.INTEGER_OVERFLOW,
    "core.NullDereference": VulnClass.NULL_DEREF,
    "core.UndefinedBinaryOperatorResult": VulnClass.UNINITIALIZED,
    "core.uninitialized.Assign": VulnClass.UNINITIALIZED,
    "core.uninitialized.ArraySubscript": VulnClass.UNINITIALIZED,
}

# Default checkers to enable
DEFAULT_CHECKERS = list(CHECKER_MAP.keys())


class ClangAnalyzerFilter:
    """Run `clang --analyze` over C++ files and return suspicious regions."""

    def __init__(
        self,
        checkers: list[str] | None = None,
        extra_args: list[str] | None = None,
        timeout: int = 120,
    ) -> None:
        self.checkers = checkers or DEFAULT_CHECKERS
        self.extra_args = extra_args or []
        self.timeout = timeout

    def run(self, files: list[Path]) -> FilterResult:
        result = FilterResult(files_scanned=len(files))
        flagged: set[Path] = set()

        for f in files:
            regions = self._analyze_file(f)
            if regions:
                result.regions.extend(regions)
                flagged.add(f)

        result.files_flagged = len(flagged)
        return result

    def _analyze_file(self, path: Path) -> list[SuspiciousRegion]:
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                "clang",
                "--analyze",
                "-Xanalyzer", "-analyzer-output=plist",
                f"-o", tmpdir,
            ]
            for checker in self.checkers:
                cmd += ["-Xanalyzer", f"-analyzer-checker={checker}"]
            cmd += self.extra_args
            cmd += [str(path)]

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return []

            return self._parse_plist_dir(path, tmpdir)

    def _parse_plist_dir(self, source: Path, plist_dir: str) -> list[SuspiciousRegion]:
        regions: list[SuspiciousRegion] = []
        for plist_file in Path(plist_dir).glob("*.plist"):
            try:
                data = plistlib.loads(plist_file.read_bytes())
            except Exception:
                continue

            for diag in data.get("diagnostics", []):
                checker = diag.get("check_name", "")
                vuln_class = self._map_checker(checker)
                if vuln_class is None:
                    continue

                loc = diag.get("location", {})
                line = loc.get("line", 0)
                regions.append(SuspiciousRegion(
                    file=source,
                    line_start=line,
                    line_end=line,
                    vuln_class=vuln_class,
                    message=diag.get("description", ""),
                    checker=checker,
                ))
        return regions

    def _map_checker(self, checker: str) -> VulnClass | None:
        for key, vuln in CHECKER_MAP.items():
            if key in checker:
                return vuln
        return None
