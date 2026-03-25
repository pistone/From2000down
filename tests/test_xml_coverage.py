from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cheap_filter.xml_coverage import compare_xml_to_ground_truth
from cheap_filter.xml_coverage import default_ground_truth_path
from cheap_filter.xml_coverage import format_summary
from cheap_filter.xml_coverage import parse_error_xml


def test_parse_error_xml_dedupes_by_file_and_function(tmp_path: Path) -> None:
    xml_path = tmp_path / "report.xml"
    xml_path.write_text(
        textwrap.dedent(
            """\
            <results>
              <error>
                <file>/repo/dom/base/Document.cpp</file>
                <function>Document::HidePopover()</function>
              </error>
              <error>
                <file>/repo/dom/base/Document.cpp</file>
                <function>Document::HidePopover()</function>
              </error>
              <error>
                <file>/repo/dom/base/Document.cpp</file>
                <function>Document::ShowPopover()</function>
              </error>
            </results>
            """
        )
    )

    total_errors, records = parse_error_xml(xml_path)

    assert total_errors == 3
    assert len(records) == 2


def test_parse_error_xml_accepts_top_level_error_fragments(tmp_path: Path) -> None:
    xml_path = tmp_path / "report.xml"
    xml_path.write_text(
        textwrap.dedent(
            """\
            <error>
              <file>/repo/dom/base/Document.cpp</file>
              <function>Document::HidePopover()</function>
            </error>
            <error>
              <file>/repo/dom/base/Document.cpp</file>
              <function>Document::ShowPopover()</function>
            </error>
            """
        )
    )

    total_errors, records = parse_error_xml(xml_path)

    assert total_errors == 2
    assert len(records) == 2


def test_compare_xml_to_ground_truth_matches_suffix_paths_and_mangled_names(tmp_path: Path) -> None:
    xml_path = tmp_path / "report.xml"
    xml_path.write_text(
        textwrap.dedent(
            """\
            <results>
              <error>
                <file>/tmp/firefox/dom/base/Document.cpp</file>
                <function>_ZN8Document11HidePopoverEv</function>
              </error>
              <error>
                <file>/tmp/firefox/js/src/builtin/AtomicsObject.cpp</file>
                <function>_ZN2js19atomics_notify_implEP9JSContextjRKNS_8CallArgsE</function>
              </error>
              <error>
                <file>/tmp/firefox/elsewhere/not_a_match.cpp</file>
                <function>noop</function>
              </error>
            </results>
            """
        )
    )

    summary = compare_xml_to_ground_truth(xml_path)

    assert summary.deduped_xml_issues == 3
    assert summary.total_ground_truth_issues == 12
    assert summary.covered_ground_truth_issues == 2
    assert {match.issue.id for match in summary.matches} == {"CVE-2026-2765", "CVE-2026-2798"}


def test_compare_xml_to_ground_truth_matches_when_repo_root_names_differ(tmp_path: Path) -> None:
    xml_path = tmp_path / "report.xml"
    xml_path.write_text(
        textwrap.dedent(
            """\
            <results>
              <error>
                <file>/user/abc/proj1/some_repo/dir1/dir2/a.cpp</file>
                <function>do_work</function>
              </error>
            </results>
            """
        )
    )

    ground_truth_path = tmp_path / "ground_truth.json"
    ground_truth_path.write_text(
        json.dumps(
            {
                "cves": [
                    {
                        "id": "CVE-TEST-ROOT",
                        "vuln_type": "use-after-free",
                        "source_files_hint": ["repo_name_may_differ/dir1/dir2/a.cpp"],
                        "functions": ["do_work"],
                    }
                ]
            }
        )
    )

    summary = compare_xml_to_ground_truth(xml_path, ground_truth_path=ground_truth_path)

    assert summary.covered_ground_truth_issues == 1
    assert summary.matches[0].issue.id == "CVE-TEST-ROOT"


def test_compare_xml_to_ground_truth_matches_when_hint_is_substring(tmp_path: Path) -> None:
    xml_path = tmp_path / "report.xml"
    xml_path.write_text(
        textwrap.dedent(
            """\
            <results>
              <error>
                <file>/user/abc/proj1/some_repo/dir1/dir2/a.cpp.backup/real.cpp</file>
                <function>do_work</function>
              </error>
            </results>
            """
        )
    )

    ground_truth_path = tmp_path / "ground_truth.json"
    ground_truth_path.write_text(
        json.dumps(
            {
                "cves": [
                    {
                        "id": "CVE-TEST-SUBSTRING",
                        "vuln_type": "use-after-free",
                        "source_files_hint": ["some_repo/dir1/dir2/a.cpp"],
                        "functions": ["do_work"],
                    }
                ]
            }
        )
    )

    summary = compare_xml_to_ground_truth(xml_path, ground_truth_path=ground_truth_path)

    assert summary.covered_ground_truth_issues == 1
    assert summary.matches[0].issue.id == "CVE-TEST-SUBSTRING"


def test_compare_xml_to_ground_truth_uses_custom_ground_truth(tmp_path: Path) -> None:
    xml_path = tmp_path / "report.xml"
    xml_path.write_text(
        textwrap.dedent(
            """\
            <results>
              <error>
                <file>/repo/src/foo.c</file>
                <function>do_work</function>
              </error>
            </results>
            """
        )
    )

    ground_truth_path = tmp_path / "ground_truth.json"
    ground_truth_path.write_text(
        json.dumps(
            {
                "cves": [
                    {
                        "id": "CVE-TEST-1",
                        "vuln_type": "use-after-free",
                        "source_files_hint": ["src/foo.c"],
                        "functions": ["do_work"],
                    },
                    {
                        "id": "CVE-TEST-2",
                        "vuln_type": "type-confusion",
                        "source_files_hint": ["src/foo.c"],
                        "functions": ["do_work"],
                    },
                ]
            }
        )
    )

    summary = compare_xml_to_ground_truth(xml_path, ground_truth_path=ground_truth_path)

    assert summary.total_ground_truth_issues == 1
    assert summary.covered_ground_truth_issues == 1
    assert summary.matches[0].issue.id == "CVE-TEST-1"


def test_format_summary_includes_matched_file_names(tmp_path: Path) -> None:
    xml_path = tmp_path / "report.xml"
    xml_path.write_text(
        textwrap.dedent(
            """\
            <results>
              <error>
                <file>/repo/src/foo.c</file>
                <function>do_work</function>
              </error>
            </results>
            """
        )
    )

    ground_truth_path = tmp_path / "ground_truth.json"
    ground_truth_path.write_text(
        json.dumps(
            {
                "cves": [
                    {
                        "id": "CVE-TEST-1",
                        "vuln_type": "use-after-free",
                        "source_files_hint": ["src/foo.c"],
                        "functions": ["do_work"],
                    }
                ]
            }
        )
    )

    summary = compare_xml_to_ground_truth(xml_path, ground_truth_path=ground_truth_path)
    rendered = format_summary(summary)

    assert "CVE-TEST-1" in rendered
    assert "files: /repo/src/foo.c" in rendered


def test_default_ground_truth_path_points_to_repo_data() -> None:
    assert default_ground_truth_path().samefile(
        Path(__file__).resolve().parents[1] / "data" / "ground_truth.json"
    )
