# Contributing to cheap-filter

Thanks for your interest in contributing!

## Getting started

```bash
git clone https://github.com/pistone/From2000down.git
cd From2000down
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running tests

```bash
pytest tests/
```

## Running the linter

```bash
ruff check src/ tests/
ruff format src/ tests/
```

## Running the evaluation

```bash
./scripts/fetch_firefox.sh    # one-time: download Firefox 147 source
cheap-filter eval data/firefox-147.0/
```

## Areas for contribution

### High impact

- **More safe-exclusion rules**: Add patterns to `safe_excluder.py` that reduce danger sites without missing real bugs. Every rule must maintain 100% recall on the ground truth CVEs.
- **Deeper AST analysis**: The current danger collector is single-file. Cross-file pointer tracking would reduce false positives significantly.
- **More vulnerability classes**: Integer overflow detection (arithmetic on allocation sizes), type confusion patterns.

### Medium impact

- **Better ground truth**: The 22 CVEs in `ground_truth.json` have approximate file locations. Exact function-level mappings from the actual Firefox patches would improve evaluation precision.
- **compile_commands.json integration**: Use the compilation database to resolve includes properly, improving AST parse quality.
- **Performance**: The danger collector processes ~13K files sequentially. Parallelizing with multiprocessing would cut eval time.

### Good first issues

- Add more test cases to `tests/test_filters.py`
- Add a `--verbose` flag to the eval command showing per-directory breakdowns
- Document the JSON output format of `cheap-filter scan`

## Code style

- Python 3.11+, type annotations everywhere
- Ruff for formatting and linting (line length 100)
- Keep functions small and testable
- Docstrings on public functions

## Pull requests

1. Fork the repo
2. Create a feature branch
3. Make your changes
4. Run `ruff check` and `pytest`
5. Open a PR with a clear description of what changed and why
