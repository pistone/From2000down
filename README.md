# cheap-filter

**Cost-efficient C++ vulnerability scanner: static analysis pre-filter + LLM verification**

Anthropic spent ~$2,000 using Claude Opus 4.6 to discover 22 security vulnerabilities in Firefox 147 ([MFSA 2026-13](https://www.mozilla.org/en-US/security/advisories/mfsa2026-13/)). This project asks: can we get comparable results for less?

The idea is simple — instead of sending every C++ file to an LLM, use a cheap static analysis pass to narrow down *where* to look, then let the LLM focus only on suspicious code regions. We call this the **inverted filter** approach.

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│  Firefox 147 source (~13,000 C++ files)                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  1. File pre-filter                                          │
│     Skip third_party/, testing/, build/, vendored libs       │
│     (~57% of files removed)                                  │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  2. Danger collector (libclang AST)                          │
│     Find ALL free(), delete, raw pointer declarations        │
│     (~146K sites in remaining files)                         │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  3. Safe excluder                                            │
│     Remove known-safe patterns:                              │
│     - RAII destructor cleanup                                │
│     - null-after-free with no alias                          │
│     - smart pointer release with reassignment                │
│     - scope-local pointers that don't escape                 │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  4. LLM verification (Claude Opus 4.6)                       │
│     Send ±30 lines of context per surviving region           │
│     Ask: "Is this a real vulnerability?"                     │
└──────────────────────────────────────────────────────────────┘
```

## Key insight: invert the filter

Traditional static analyzers (clang-analyzer, clang-tidy) are designed as **bug finders** — they optimize for low false positives, which means high false negatives. That's the wrong tradeoff for a pre-filter.

We flip it:

| | Traditional (find bugs) | Inverted (find danger, subtract safety) |
|---|---|---|
| Starting set | Only what checkers flag | ALL free/delete/raw-ptr ops |
| Filter direction | Additive (flag bad) | Subtractive (remove known-safe) |
| False negative risk | **High** (misses subtle bugs) | **Low** (only misses if wrongly safe) |
| False positive risk | Low | **High** (but LLM handles that) |
| LLM cost | Cheap but misses bugs | More calls but catches more |

## Evaluation results

Against the 22 CVEs from MFSA 2026-13:

| Metric | Value |
|---|---|
| CVE recall | **22/22 (100%)** |
| Files after pre-filter | 5,556 / 13,187 (42%) |
| Danger sites found | 36,269 |
| Projected LLM cost | **~$567** |
| Anthropic's reported cost | ~$2,000 |

The filter achieves **100% recall** — every CVE location has at least one danger site flagged — at a projected cost 72% lower than the full-scan approach.

## Vulnerability classes covered

| Class | CVEs in ground truth | Filter mechanism |
|---|---|---|
| Use-after-free | 13 | free/delete + no safe pattern |
| JIT miscompilation | 2 | raw pointer ops in jit/ |
| Integer overflow | 1 | (future: arithmetic on sizes) |
| Boundary error | 2 | raw pointer array access |
| Sandbox escape | 3 | pointer ops in gfx/wr, indexedDB |
| Undefined behavior | 1 | raw pointer patterns |
| Uninitialized memory | 1 | (Android/Java — out of scope) |

## Quick start

### Install

```bash
git clone https://github.com/pistone/From2000down.git
cd From2000down
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Download Firefox 147 source

```bash
./scripts/fetch_firefox.sh
# Downloads ~500MB, extracts to data/firefox-147.0/
```

### Run the evaluation (no API key needed)

```bash
cheap-filter eval data/firefox-147.0/
```

This runs the filter against Firefox 147 and checks recall against the 22 known CVEs. No LLM calls are made — it measures whether the filter would have sent the right code to Claude.

### Run a full scan (requires API key)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
cheap-filter scan data/firefox-147.0/ --output results.json
```

### Dry run (filter only, no LLM)

```bash
cheap-filter scan data/firefox-147.0/ --dry-run
```

## Building Firefox 147 from source (Linux)

If you want to build Firefox to generate `compile_commands.json` for deeper analysis, here's how.

### System requirements

- **OS**: 64-bit Linux (Ubuntu 22.04+ recommended)
- **RAM**: 8 GB minimum (16 GB recommended)
- **Disk**: 60 GB free (source + build artifacts)
- **Python**: 3.9+

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install curl python3 python3-venv git mercurial

# Fedora
sudo dnf install curl python3 git mercurial
```

### Download source

```bash
# Option 1: Source tarball (no VCS needed, fastest)
wget https://archive.mozilla.org/pub/firefox/releases/147.0/source/firefox-147.0.source.tar.xz
tar xf firefox-147.0.source.tar.xz
cd firefox-147.0/

# Option 2: Mercurial (full history)
hg clone https://hg.mozilla.org/releases/mozilla-release -r FIREFOX_147_0_RELEASE
cd mozilla-release/
```

### Bootstrap build environment

```bash
./mach bootstrap
# Choose "Firefox for Desktop" when prompted
# Installs: clang, rust, node, cbindgen, sccache, nasm into ~/.mozbuild
```

### Configure and build

```bash
# Optional: create mozconfig for static analysis
cat > mozconfig << 'EOF'
ac_add_options --enable-debug
ac_add_options --disable-optimize
EOF

# Build (30-90 min depending on hardware)
./mach build
```

### Generate compile_commands.json

```bash
./mach build-backend --backend=CompileDB
# Output: obj-*/compile_commands.json

# Symlink to source root for tooling
ln -s obj-*/compile_commands.json .
```

### Common gotchas

- **Disk space**: Debug builds can exceed 50 GB. Plan for 60+ GB.
- **"Watchman unavailable"**: Safe to ignore — optional file watcher.
- **Old distros**: Ubuntu 18.04 has too-old Node.js and nasm. Use 22.04+.
- **Rust conflicts**: `./mach bootstrap` installs its own Rust in `~/.mozbuild`. System Rust won't interfere.
- **Regenerate compile_commands.json** after changing mozconfig or adding/removing source files.

## Project structure

```
cheap-filter/
├── src/cheap_filter/
│   ├── cli.py                  # CLI entry point (scan, eval commands)
│   ├── pipeline.py             # Orchestration: filter → LLM verification
│   ├── eval.py                 # Ground truth evaluation
│   ├── metrics.py              # Cost & effectiveness tracking
│   ├── filters/
│   │   ├── base.py             # VulnClass enum, SuspiciousRegion
│   │   ├── file_filter.py      # Directory/file pre-filter
│   │   ├── danger_collector.py # AST walk: find dangerous operations
│   │   ├── safe_excluder.py    # Known-safe pattern exclusion
│   │   ├── clang_analyzer.py   # clang --analyze wrapper
│   │   └── clang_tidy.py       # clang-tidy wrapper
│   └── llm/
│       ├── client.py           # Claude API integration
│       └── prompts.py          # System prompt & vuln guidance
├── scripts/
│   └── fetch_firefox.sh        # Download Firefox 147 source
├── tests/
│   └── test_filters.py         # Unit tests
├── data/
│   └── ground_truth.json       # 22 CVEs from MFSA 2026-13
└── pyproject.toml
```

## How the inverted filter works in detail

### Step 1: File pre-filter (`file_filter.py`)

Skips directories that won't contain Firefox's own bugs:
- `third_party/`, `gfx/skia/`, `gfx/angle/`, `media/libvpx/` — vendored libraries
- `testing/`, `js/src/tests/` — test code
- `build/`, `config/`, `python/`, `docs/` — build infrastructure

### Step 2: Danger collector (`danger_collector.py`)

Walks the Clang AST (via libclang Python bindings) to find every:
- `free()`, `cfree()`, `realloc()`, and Mozilla/GLib-specific deallocation functions
- C++ `delete` expressions
- Smart pointer `.release()` and `.reset()` calls
- Raw pointer variable declarations (excluding `const char*`)

Each site records: file, line, enclosing function, pointer name, and whether it's in a destructor.

### Step 3: Safe excluder (`safe_excluder.py`)

Applies heuristic rules to remove known-safe patterns:

1. **Destructor cleanup** — `free()`/`delete` inside a destructor is RAII-safe
2. **Null-after-free** — `free(ptr); ptr = nullptr;` within 3 lines, with no pointer aliases
3. **Smart pointer release with reassignment** — `auto* p = foo.release();` transfers ownership
4. **Scope-local pointers** — raw pointer declared and freed within ±15 lines, doesn't escape

Error-path cleanup is intentionally **not** excluded — it's a common source of UAF bugs.

### Step 4: LLM verification (`client.py`, `prompts.py`)

Surviving regions get ±30 lines of context sent to Claude Opus 4.6 with:
- A security auditor system prompt
- Vulnerability-class-specific guidance
- Strict instructions to only confirm with a concrete code path
- Prompt caching on the system prompt (saves ~90% on repeated calls)

## License

MIT

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
