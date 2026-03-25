#!/usr/bin/env python3
"""Compare XML error reports with use-after-free ground truth."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cheap_filter.xml_coverage import compare_xml_to_ground_truth
from cheap_filter.xml_coverage import default_ground_truth_path
from cheap_filter.xml_coverage import format_summary


@click.command()
@click.argument("xml_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--ground-truth",
    "-g",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to ground_truth.json. Defaults to data/ground_truth.json.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Print machine-readable JSON instead of a text summary.",
)
def main(xml_path: Path, ground_truth: Path | None, as_json: bool) -> None:
    """Scan XML <error> records, dedupe by (file, function), and score coverage."""
    summary = compare_xml_to_ground_truth(
        xml_path=xml_path,
        ground_truth_path=ground_truth or default_ground_truth_path(),
    )

    if as_json:
        click.echo(json.dumps(summary.to_dict(), indent=2))
        return

    click.echo(format_summary(summary))


if __name__ == "__main__":
    main()
