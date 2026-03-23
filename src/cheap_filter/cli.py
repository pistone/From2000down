"""CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

console = Console()


def _print_progress(msg: str) -> None:
    console.print(f"[dim]{msg}[/dim]")


@click.group()
def main() -> None:
    """cheap-filter: LLVM-based pre-filter + LLM vulnerability verification."""


@main.command()
@click.argument("source_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--mode", "-m", type=click.Choice(["inverted", "classic"]), default="inverted",
              help="Filter mode: 'inverted' (collect danger, subtract safety) or 'classic' (clang checkers).")
@click.option("--max-files", "-n", default=None, type=int, help="Limit number of files scanned.")
@click.option("--compile-commands", "-p", default=None, type=click.Path(path_type=Path),
              help="Path to compile_commands.json for clang-tidy (classic mode).")
@click.option("--no-analyzer", is_flag=True, help="Skip clang static analyzer (classic mode).")
@click.option("--no-tidy", is_flag=True, help="Skip clang-tidy (classic mode).")
@click.option("--dry-run", is_flag=True, help="Run filters only, skip LLM queries.")
@click.option("--output", "-o", default=None, type=click.Path(path_type=Path),
              help="Write JSON results to this file.")
@click.option("--api-key", envvar="ANTHROPIC_API_KEY", default=None, hidden=True)
def scan(
    source_dir: Path,
    mode: str,
    max_files: int | None,
    compile_commands: Path | None,
    no_analyzer: bool,
    no_tidy: bool,
    dry_run: bool,
    output: Path | None,
    api_key: str | None,
) -> None:
    """Scan a C++ codebase: LLVM filter → Claude verification.

    SOURCE_DIR  Root directory of the C++ source tree to scan.

    \b
    Modes:
      inverted  (default) Collect all free/delete/raw-ptr sites via Clang AST,
                subtract known-safe patterns, send remainder to Claude.
      classic   Run clang-tidy + clang-analyzer, send flagged regions to Claude.
    """
    from .llm.client import VulnVerdict
    from .pipeline import Pipeline

    def _print_verdict(v: VulnVerdict) -> None:
        colour = {"confirmed": "red", "false_positive": "dim", "uncertain": "yellow"}.get(
            v.verdict, "white"
        )
        icon = {"confirmed": "🐛", "false_positive": "✓", "uncertain": "?"}.get(v.verdict, " ")
        console.print(
            f"[{colour}]{icon} {v.verdict.upper()}[/{colour}]  "
            f"{v.region.file.name}:{v.region.line_start}  "
            f"[dim]{v.region.vuln_class.value}[/dim]  "
            f"[dim]{v.explanation[:80]}[/dim]"
        )

    pipeline = Pipeline(
        mode=mode,
        use_clang_analyzer=not no_analyzer,
        use_clang_tidy=not no_tidy,
        compile_commands=compile_commands,
        api_key=api_key,
        dry_run=dry_run,
    )

    files = Pipeline.collect_cpp_files(source_dir, max_files=max_files)
    console.print(
        f"[bold]cheap-filter[/bold]  mode=[cyan]{mode}[/cyan]  "
        f"scanning {len(files)} files in [cyan]{source_dir}[/cyan]"
    )
    if dry_run:
        console.print("[yellow]dry-run: filter only, no LLM queries[/yellow]")

    metrics = pipeline.scan(
        files,
        on_verdict=_print_verdict,
        on_filter_progress=_print_progress,
    )

    console.print()
    console.print(metrics.summary())

    if output and metrics.verdicts:
        data = [
            {
                "file": str(v.region.file),
                "line": v.region.line_start,
                "vuln_class": v.vuln_class,
                "verdict": v.verdict,
                "severity": v.severity,
                "explanation": v.explanation,
                "exploit_sketch": v.exploit_sketch,
                "cost_usd": v.cost_usd,
            }
            for v in metrics.verdicts
        ]
        output.write_text(json.dumps(data, indent=2))
        console.print(f"[dim]Results written to {output}[/dim]")


@main.command(name="eval")
@click.argument("firefox_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--ground-truth", "-g", default=None, type=click.Path(exists=True, path_type=Path),
              help="Path to ground_truth.json. Defaults to data/ground_truth.json.")
@click.option("--output", "-o", default=None, type=click.Path(path_type=Path),
              help="Write detailed JSON results to this file.")
def eval_cmd(
    firefox_root: Path,
    ground_truth: Path | None,
    output: Path | None,
) -> None:
    """Evaluate the filter against known Firefox CVEs (no LLM calls needed).

    \b
    FIREFOX_ROOT  Path to the extracted Firefox 147 source tree.

    \b
    Steps:
      1. Download Firefox 147:  ./scripts/fetch_firefox.sh
      2. Run eval:              cheap-filter eval data/firefox-147.0/

    Reports recall (did the filter cover each CVE's code?) and projected LLM cost.
    """
    from .eval import run_eval

    if ground_truth is None:
        # Try common locations
        for candidate in [
            Path("data/ground_truth.json"),
            Path(__file__).parent.parent.parent / "data" / "ground_truth.json",
        ]:
            if candidate.exists():
                ground_truth = candidate
                break
        if ground_truth is None:
            raise click.UsageError(
                "Cannot find ground_truth.json. Use --ground-truth to specify its path."
            )

    console.print(
        f"[bold]cheap-filter eval[/bold]  "
        f"firefox=[cyan]{firefox_root}[/cyan]  "
        f"ground_truth=[cyan]{ground_truth}[/cyan]"
    )
    console.print("[dim]This runs the inverted filter only — no LLM calls, no API cost.[/dim]")
    console.print()

    result = run_eval(
        firefox_root=firefox_root,
        ground_truth_path=ground_truth,
        on_progress=_print_progress,
    )

    console.print()
    console.print(result.summary())

    if output:
        data = {
            "recall": result.recall,
            "total_cves": result.total_cves,
            "cves_covered": result.cves_covered,
            "cves_missed": result.cves_missed,
            "total_files_scanned": result.total_files_scanned,
            "total_danger_sites": result.total_danger_sites,
            "total_excluded": result.total_excluded,
            "total_surviving_regions": result.total_surviving_regions,
            "projected_cost_usd": result.projected_cost_usd,
            "per_cve": [
                {
                    "id": cr.cve.id,
                    "component": cr.cve.component,
                    "vuln_type": cr.cve.vuln_type,
                    "covered": cr.covered,
                    "matching_regions": len(cr.matching_regions),
                    "files_in_dir": cr.files_in_dir,
                }
                for cr in result.per_cve
            ],
        }
        output.write_text(json.dumps(data, indent=2))
        console.print(f"[dim]Detailed results written to {output}[/dim]")
