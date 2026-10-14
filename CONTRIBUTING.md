# Contributing to TraceMend

[← Back to README](./README.md) · [Setup](./docs/setup.md) · [Project status](./docs/status.md)

Thanks for helping. TraceMend is a deterministic linter for AI agent execution traces:
it reads a trace, reports evidence-backed inefficiencies, and proposes reviewable
`AGENTS.md` fixes. Contributions that keep that core small, honest and reproducible are
the most valuable.

## Ways to contribute

- **Bug reports.** Open an issue with the trace format, the command you ran, the observed
  output and the expected output. Redact secrets and absolute paths first.
- **New detectors.** A rule for a waste pattern TraceMend does not yet catch — see
  [Adding a detector](#adding-a-detector).
- **New trace adapters.** Support for another agent framework's export, normalised into the
  shared models — see [Adding a trace adapter](#adding-a-trace-adapter).
- **Docs.** `README.md` and `docs/` (`setup.md`, `mcp.md`, `fix-workflow.md`,
  `detection-rules.md`, `containers.md`). Fixing a stale command or an unclear rule is a
  real contribution.
- **Tests.** Positive, negative and incomplete-trace cases for existing behaviour, plus
  redacted real agent exports used as fixtures.

For anything larger than a typo, open an issue first so the design is agreed before code
is written. Keep the deterministic core deterministic: no network calls and no language
model inside `analyzer`, `detectors`, `fixes`, `storage` or `security`.

## Development setup

The clone-and-install flow lives in [docs/setup.md](./docs/setup.md). The short version:

```bash
uv sync --extra dev
uv run tracemend --help
```

Python 3.12+ and `uv` are required; `uv` is the only supported runner. Run every command
from inside the clone. `--extra dev` adds `pytest`, `pytest-asyncio` and `ruff`.

## Running the checks

Run these before opening a pull request (the same set the CI `test` job runs):

```bash
# Lint: the configured ruff rule set (E, F, I, UP, B, SIM, C4, RUF).
uv run ruff check .

# Tests: the full suite (unittest-based, collected by pytest).
uv run pytest
```

- `uv run ruff check .` guards style and lint on `src/` and `tests/`.
- `uv run pytest` guards behaviour. A green run currently reports `225 passed, 28 subtests passed`.

There is no `[tool.ruff.format]` section in `pyproject.toml`, so `ruff format` is not
enforced here; match the surrounding file's existing style instead of reformatting.

**`UV_CACHE_DIR`.** Only needed when the default uv cache directory is not writable — for
example inside a restricted sandbox where `~/.cache/uv` cannot be created. When that
happens, point it somewhere writable:

```bash
UV_CACHE_DIR=/tmp/uvcache uv run pytest
```

Do not add it to committed scripts or CI; CI has a writable cache.

## Adding a detector

Detectors live in `src/tracemend/detectors.py`. Read that file first — its module docstring
defines the ownership rules that keep the same wasted work from being reported twice.

1. **Follow the signature.** Every detector is a pure function
   `def detect_<name>(run: TraceRun) -> list[Finding]:` that reads one normalized
   `TraceRun` and returns findings in a deterministic order. No I/O, no randomness.
2. **Reuse the helpers** rather than re-deriving tool semantics:
   `is_read_call`, `is_search_call`, `is_write_call`, `path_of_call`, `search_pattern_of`,
   `search_scope_of` and `normalize_path`. For grouping and scoring, reuse
   `_ordered_groups`, `_agent_ids`, `_evidence` (which enforces `MAX_EVIDENCE`) and
   `sort_findings`.
3. **Register the rule.** Add the new `TM00x` code to `DETECTOR_CODES`, add the public
   `detect_*` function to `__all__`, and call it from `run_detectors`. Add a human-readable
   title to `FINDING_CODES` in `src/tracemend/models.py` — `Finding.code` is validated
   against that mapping and rejects unknown codes.
4. **Build an honest `Finding`.** Cite real call ids in `Finding.evidence` (from `call.id`)
   and drop a group rather than reporting it without citable evidence. Give the finding a
   stable per-instance id with `make_finding_id(code, tool, key)` so re-analysing the same
   run yields the same id. Report `None` for absent metadata instead of guessing, and lower
   `confidence` (and severity) rather than asserting — for example when a repeat spans
   several agents, since a subagent may legitimately repeat a parent's call.
5. **Add tests** in `tests/test_detectors.py`: a positive case, a negative case where
   legitimate behaviour must not be flagged, and an incomplete-trace case.
6. **Document the rule** in `docs/detection-rules.md` (one section per detector) and note it
   in `README.md` if it changes the detector list.

## Adding a trace adapter

Adapters normalise a vendor export into the shared Pydantic models in `src/tracemend/models.py`.

1. **Start from the existing adapters.** Follow `src/tracemend/adapters/generic.py`
   (`parse_generic`) and `src/tracemend/adapters/opencode.py` (`parse_opencode`).
2. **Normalise into the shared models.** Produce `ToolCall` and `TraceRun` objects.
   Reuse the coercion helpers in `generic.py` — `first_present`, `coerce_text`,
   `coerce_int`, `coerce_float`, `timestamp_from_time`, `duration_from_time`,
   `extract_token_usage`, plus `build_event` and `finalise_events` — instead of writing new
   parsing utilities.
3. **Register the format** in `src/tracemend/adapters/__init__.py`: add the name to
   `SUPPORTED_FORMATS`, wire the parser into `_PARSERS`, and extend `detect_format` and its
   marker sets so the format is recognised automatically.
4. **Add a fixture.** New fixtures go under `examples/` (that is the fixture directory this
   repo uses; there is no `tests/fixtures/`). Keep them small and fully redacted — never
   commit a real export containing secrets, credentials or private paths.
5. **Add parser tests** in `tests/test_adapters.py`, covering the cases the existing suite
   covers for the other adapters: malformed JSON, an unknown/undetected format, missing
   fields, an empty event sequence, absent duration/token data, and subagent events.

## Writing tests

- The suite is **`unittest`-based**. `pytest` only collects it, so `class ...(unittest.TestCase)`
  with `self.assertEqual` / `self.assertRaises` is the style to match. The stdlib fallback is
  `python -m unittest discover -s tests -t .`.
- **Isolate state.** Use `tempfile.TemporaryDirectory()` and point TraceMend at it via
  `TRACEMEND_DATA_DIR` (or `--data-dir`). Tests must never read or write a real user data
  directory such as `~/Library/Application Support/tracemend` or `$XDG_DATA_HOME/tracemend`.
- **Never touch real agent configuration.** Do not read or write a real OpenCode/agent config
  tree, and do not apply fixes to anything outside a temporary directory. The apply path is
  destructive; every test of it must run against a copy under `tmp`.
- Fixtures are loaded from `examples/` (see `EXAMPLES_DIR` in `tests/test_detectors.py`).

## Code style

- **Typed Python.** Every module starts with `from __future__ import annotations` and uses
  type hints; keep public functions annotated.
- **Small, cohesive modules.** Match the existing layout (`detectors.py`, `adapters/`,
  `models.py`, `fixes.py`, `storage.py`, `security.py`) and put a short module docstring at
  the top explaining the module's job and its invariants.
- **No unnecessary dependencies.** The runtime dependency set is deliberately small
  (`click`, `mcp`, `pydantic`, `rich`). Adding a runtime dependency needs a strong reason.
  Test-only tooling belongs in the `dev` extra in `pyproject.toml`.
- **Ruff** is configured in `pyproject.toml`: `line-length = 100`, `target-version = "py312"`,
  and `select = ["E", "F", "I", "UP", "B", "SIM", "C4", "RUF"]` with `ignore = ["E501"]`.
  Tests ignore `S101`. Keep the tree clean under `uv run ruff check .`.

## Commit and pull-request guidelines

- Keep pull requests **small and focused** — one detector, one adapter or one fix per PR.
- Describe the **behaviour change**: what was wrong or missing before, and what changes now.
- **Note which checks you ran** (`uv run ruff check .`, `uv run pytest`) and any you could not run.
- When adding a detector, **reference the finding code** (`TM00x`) in the title/body and in
  `docs/detection-rules.md`.
- Keep the deterministic core deterministic and do not widen the write boundary: any change
  to the apply path must keep the approval-record, path-containment and hash checks intact.
- Do not mix unrelated cleanups into a behaviour change.

## Reporting security issues

Do not open a public issue for a security problem. Report it privately through GitHub
Security Advisories on the repository's **Security → Report a vulnerability** page
(<https://github.com/kartikav05/tracemend/security/advisories/new>). Include the affected
version, a reproduction and the impact. Relevant areas include the fix apply path, path
containment and symlink handling, and anything that could let an agent bypass the
interactive approval gate.
