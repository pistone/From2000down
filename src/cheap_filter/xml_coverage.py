"""Compare XML error reports against the use-after-free ground truth."""

from __future__ import annotations

import json
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class ErrorRecord:
    file: str
    function: str


@dataclass(frozen=True)
class GroundTruthIssue:
    id: str
    source_files_hint: tuple[str, ...]
    functions: tuple[str, ...]


@dataclass(frozen=True)
class GroundTruthMatch:
    issue: GroundTruthIssue
    matched_records: tuple[ErrorRecord, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class CoverageSummary:
    total_xml_errors: int
    deduped_xml_issues: int
    total_ground_truth_issues: int
    covered_ground_truth_issues: int
    matches: tuple[GroundTruthMatch, ...]

    @property
    def coverage_ratio(self) -> float:
        if not self.total_ground_truth_issues:
            return 0.0
        return self.covered_ground_truth_issues / self.total_ground_truth_issues

    def to_dict(self) -> dict[str, object]:
        return {
            "total_xml_errors": self.total_xml_errors,
            "deduped_xml_issues": self.deduped_xml_issues,
            "total_ground_truth_issues": self.total_ground_truth_issues,
            "covered_ground_truth_issues": self.covered_ground_truth_issues,
            "coverage_ratio": self.coverage_ratio,
            "matches": [
                {
                    "id": match.issue.id,
                    "matched_records": [
                        {"file": record.file, "function": record.function}
                        for record in match.matched_records
                    ],
                }
                for match in self.matches
            ],
        }


def default_ground_truth_path() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "ground_truth.json"


def parse_error_xml(xml_path: Path) -> tuple[int, set[ErrorRecord]]:
    root = _load_xml_root(xml_path)
    total_errors = 0
    deduped: set[ErrorRecord] = set()

    for error in root.iter("error"):
        total_errors += 1
        file_text = _child_text(error, "file")
        function_text = _child_text(error, "function")
        if not file_text or not function_text:
            continue
        deduped.add(
            ErrorRecord(
                file=_normalize_file(file_text),
                function=_normalize_function_name(function_text),
            )
        )

    return total_errors, deduped


def load_uaf_ground_truth(path: Path) -> list[GroundTruthIssue]:
    data = json.loads(path.read_text())
    return [
        GroundTruthIssue(
            id=entry["id"],
            source_files_hint=tuple(_normalize_file(file) for file in entry.get("source_files_hint", [])),
            functions=tuple(_normalize_function_name(name) for name in entry.get("functions", [])),
        )
        for entry in data["cves"]
        if entry.get("vuln_type") == "use-after-free"
    ]


def compare_xml_to_ground_truth(
    xml_path: Path,
    ground_truth_path: Path | None = None,
) -> CoverageSummary:
    if ground_truth_path is None:
        ground_truth_path = default_ground_truth_path()

    total_xml_errors, records = parse_error_xml(xml_path)
    issues = load_uaf_ground_truth(ground_truth_path)

    matches: list[GroundTruthMatch] = []
    for issue in issues:
        matched_records = tuple(
            sorted(
                (
                    record
                    for record in records
                    if _record_matches_issue(record, issue)
                ),
                key=lambda record: (record.file, record.function),
            )
        )
        if matched_records:
            matches.append(GroundTruthMatch(issue=issue, matched_records=matched_records))

    return CoverageSummary(
        total_xml_errors=total_xml_errors,
        deduped_xml_issues=len(records),
        total_ground_truth_issues=len(issues),
        covered_ground_truth_issues=len(matches),
        matches=tuple(matches),
    )


def format_summary(summary: CoverageSummary) -> str:
    lines = [
        "XML error coverage summary",
        f"Total XML <error> records: {summary.total_xml_errors}",
        f"Total deduped XML issues: {summary.deduped_xml_issues}",
        (
            "Covered UAF ground-truth issues: "
            f"{summary.covered_ground_truth_issues}/{summary.total_ground_truth_issues} "
            f"({summary.coverage_ratio:.1%})"
        ),
    ]

    if summary.matches:
        lines.append("")
        lines.append("Covered CVEs:")
        for match in summary.matches:
            lines.append(
                f"- {match.issue.id}: {len(match.matched_records)} matching error pair(s)"
            )

    return "\n".join(lines)


def _child_text(node: ET.Element, tag: str) -> str:
    child = node.find(tag)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def _load_xml_root(xml_path: Path) -> ET.Element:
    text = xml_path.read_text()
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        if "junk after document element" not in str(exc):
            raise

    wrapped = f"<errors>\n{text}\n</errors>"
    return ET.fromstring(wrapped)


def _normalize_file(path_str: str) -> str:
    normalized = path_str.strip().replace("\\", "/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    return normalized.rstrip("/")


@lru_cache(maxsize=4096)
def _demangle_cpp_symbol(name: str) -> str:
    if not name:
        return name
    try:
        result = subprocess.run(
            ["c++filt", "-n", name],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return name

    if result.returncode != 0:
        return name

    demangled = result.stdout.strip()
    return demangled or name


def _normalize_function_name(name: str) -> str:
    text = " ".join(name.strip().split())
    if not text:
        return ""

    text = _demangle_cpp_symbol(text)

    if "(" in text:
        text = text.split("(", 1)[0]

    text = " ".join(text.split())
    if text.endswith(" const"):
        text = text[:-6].rstrip()
    if text.endswith(" noexcept"):
        text = text[:-9].rstrip()
    return text


def _file_matches_hint(record_file: str, hint: str) -> bool:
    return record_file == hint or record_file.endswith(f"/{hint}")


def _record_matches_issue(record: ErrorRecord, issue: GroundTruthIssue) -> bool:
    file_match = any(_file_matches_hint(record.file, hint) for hint in issue.source_files_hint)
    function_match = record.function in issue.functions
    return file_match and function_match
