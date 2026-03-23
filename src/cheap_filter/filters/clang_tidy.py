"""Clang-Tidy filter.

Runs `clang-tidy` with security and C++ safety checks, parses its output.
Complementary to the static analyzer: catches coding-pattern bugs.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .base import FilterResult, SuspiciousRegion, VulnClass

# Clang-tidy check → VulnClass
CHECK_MAP: dict[str, VulnClass] = {
    "clang-analyzer-cplusplus.NewDelete": VulnClass.USE_AFTER_FREE,
    "clang-analyzer-cplusplus.NewDeleteLeaks": VulnClass.MEMORY_LEAK,
    "clang-analyzer-core.NullDereference": VulnClass.NULL_DEREF,
    "clang-analyzer-core.uninitialized": VulnClass.UNINITIALIZED,
    "clang-analyzer-security": VulnClass.BUFFER_OVERFLOW,
    "cppcoreguidelines-pro-bounds": VulnClass.BUFFER_OVERFLOW,
    "cppcoreguidelines-owning-memory": VulnClass.USE_AFTER_FREE,
    "bugprone-use-after-move": VulnClass.USE_AFTER_FREE,
    "bugprone-dangling-handle": VulnClass.USE_AFTER_FREE,
    "bugprone-integer-division": VulnClass.INTEGER_OVERFLOW,
    "cert-int": VulnClass.INTEGER_OVERFLOW,
    "cert-mem": VulnClass.DOUBLE_FREE,
    "hicpp-signed-bitwise": VulnClass.INTEGER_OVERFLOW,
}

DEFAULT_CHECKS = ",".join([
    "clang-analyzer-cplusplus.*",
    "clang-analyzer-core.NullDereference",
    "clang-analyzer-core.uninitialized.*",
    "clang-analyzer-security.*",
    "bugprone-use-after-move",
    "bugprone-dangling-handle",
    "bugprone-integer-division",
    "cppcoreguidelines-pro-bounds-*",
    "cppcoreguidelines-owning-memory",
    "cert-int*",
    "cert-mem*",
])

# Parse: path:line:col: warning: message [check-name]
_DIAG_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):\d+:\s+(?:warning|error):\s+(?P<msg>.+?)\s+\[(?P<check>[^\]]+)\]$"
)


class ClangTidyFilter:
    """Run `clang-tidy` over C++ files and return suspicious regions."""

    def __init__(
        self,
        checks: str | None = None,
        compile_commands: Path | None = None,
        extra_args: list[str] | None = None,
        timeout: int = 120,
    ) -> None:
        self.checks = checks or DEFAULT_CHECKS
        self.compile_commands = compile_commands
        self.extra_args = extra_args or []
        self.timeout = timeout

    def run(self, files: list[Path]) -> FilterResult:
        result = FilterResult(files_scanned=len(files))
        flagged: set[Path] = set()

        for f in files:
            regions = self._tidy_file(f)
            if regions:
                result.regions.extend(regions)
                flagged.add(f)

        result.files_flagged = len(flagged)
        return result

    def _tidy_file(self, path: Path) -> list[SuspiciousRegion]:
        cmd = ["clang-tidy", f"--checks={self.checks}"]
        if self.compile_commands:
            cmd += [f"-p={self.compile_commands}"]
        cmd += self.extra_args
        cmd += [str(path)]
        if not self.compile_commands:
            cmd += ["--", "-std=c++17"]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        return self._parse_output(path, proc.stdout + proc.stderr)

    def _parse_output(self, source: Path, output: str) -> list[SuspiciousRegion]:
        regions: list[SuspiciousRegion] = []
        seen: set[tuple[int, str]] = set()

        for line in output.splitlines():
            m = _DIAG_RE.match(line)
            if not m:
                continue
            # Only keep diagnostics for this source file
            if not str(source).endswith(m.group("file").lstrip(".")):
                if m.group("file") not in str(source):
                    continue

            lineno = int(m.group("line"))
            check = m.group("check")
            key = (lineno, check)
            if key in seen:
                continue
            seen.add(key)

            vuln_class = self._map_check(check)
            if vuln_class is None:
                continue

            regions.append(SuspiciousRegion(
                file=source,
                line_start=lineno,
                line_end=lineno,
                vuln_class=vuln_class,
                message=m.group("msg"),
                checker=check,
            ))
        return regions

    def _map_check(self, check: str) -> VulnClass | None:
        for prefix, vuln in CHECK_MAP.items():
            if check.startswith(prefix) or prefix in check:
                return vuln
        return None
