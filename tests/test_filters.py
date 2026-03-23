"""Unit tests for the filter layer (no clang required — tests parsing logic)."""

import textwrap
from pathlib import Path

from cheap_filter.filters.clang_tidy import ClangTidyFilter
from cheap_filter.filters.base import VulnClass


def test_parse_clang_tidy_uaf(tmp_path):
    f = tmp_path / "foo.cpp"
    output = textwrap.dedent(f"""\
        {f}:42:5: warning: Use of memory after it is freed [clang-analyzer-cplusplus.NewDelete]
        {f}:88:3: warning: Dereference of null pointer [clang-analyzer-core.NullDereference]
    """)

    filt = ClangTidyFilter()
    regions = filt._parse_output(f, output)
    assert len(regions) == 2
    assert regions[0].vuln_class == VulnClass.USE_AFTER_FREE
    assert regions[0].line_start == 42
    assert regions[1].vuln_class == VulnClass.NULL_DEREF
    assert regions[1].line_start == 88


def test_deduplicate_same_line(tmp_path):
    f = tmp_path / "bar.cpp"
    output = (
        f"{f}:10:1: warning: Use of memory after it is freed [clang-analyzer-cplusplus.NewDelete]\n"
        f"{f}:10:5: warning: Use of memory after it is freed [clang-analyzer-cplusplus.NewDelete]\n"
    )
    filt = ClangTidyFilter()
    regions = filt._parse_output(f, output)
    assert len(regions) == 1
