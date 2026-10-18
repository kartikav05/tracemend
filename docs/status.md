# Project status

[← Back to README](../README.md) · [Setup](./setup.md) · [Architecture](./architecture.md)

## Version

TraceMend is a **v0.1.0 alpha**. It targets **Python 3.12+** (`requires-python = ">=3.12"` in `pyproject.toml`, classifier `Development Status :: 3 - Alpha`).

The interface is not frozen: the CLI commands, MCP tool/resource names, on-disk state layout and detection rules may all change before 1.0.

Verified in this pass:

```
$ tracemend --version
TraceMend 0.1.0
```

## Test suite

The suite is `unittest`-based, so `pytest` merely collects it. The exact command:

```bash
uv sync --extra dev
uv run pytest
```

Real output from this session (Python 3.12.12, pytest 9.1.1, run with `TRACEMEND_DATA_DIR=/private/tmp/tracemend-status`):

```
225 passed, 28 subtests passed in 1.56s
```

The stdlib-only fallback runs the same suite with no third-party dependency:

```
$ python -m unittest discover -s tests -t .
Ran 225 tests in 1.280s

OK
```

Coverage areas (test counts from the current files):

- **Parser / adapters** — `tests/test_adapters.py` (44 tests): generic JSON, OpenCode exports, malformed JSON, unknown formats, missing fields, empty sequences, absent duration/token data, subagent events.
- **Detectors** — `tests/test_detectors.py` (36): identical calls, changed arguments, retry loops, legitimate retries, reads after observed edits, incomplete traces.
- **Analyzer and reports** — `tests/test_analyzer.py` (17) and `tests/test_reports.py` (23).
- **Remediation and security** — `tests/test_fixes.py` (35) and `tests/test_security.py` (25): proposal generation, diffs, duplicate-fix prevention, approval enforcement, unauthorized application, modified-target rejection, symlink and traversal protection, atomic writes, backups, conflict-safe undo.
- **CLI** — `tests/test_cli.py` (15): the real `click` command group driven through `click.testing.CliRunner` with an isolated `--data-dir` per test — `--version`/`--help`, `analyze` text and JSON contracts, `--output`, clean failures on missing paths and unknown ids, `compare` deltas, the full propose → diff → approve → apply → undo path, and the refusal paths (no-TTY approval, apply-before-approval, double apply).
- **Storage** — `tests/test_storage.py` (16).
- **MCP integration** — `tests/test_mcp.py` (14): the real FastMCP server is driven through the official in-memory client (`mcp.shared.memory.create_connected_server_and_client_session`) — tool discovery, invocation, resource retrieval, prompt retrieval, structured responses, error handling and unauthorized-write rejection.

**Correction to a common assumption.** The CLI is built on `click`, not Typer, so the CLI tests use `click.testing.CliRunner` rather than Typer's runner. CLI behaviour is covered by `tests/test_cli.py` and was additionally exercised manually against a temporary state directory (`TRACEMEND_DATA_DIR`), listed under *Verified behaviour* below. The MCP tests separately cover the CLI-equivalent approval path (`tests/test_mcp.py::test_apply_after_cli_approval_then_undo`, "a human approval stored in the shared store").

Lint also re-run in this pass: `uv run ruff check .` → `All checks passed!` (ruff 0.17.0).

## Verified behaviour

These end-to-end behaviours were actually run and observed in this session, using `TRACEMEND_DATA_DIR=/private/tmp/tracemend-status` and a scratch workspace at `/private/tmp/tracemend-ws`:

- **CLI `analyze`** on `examples/inefficient_run.json` — produced run `run_bddb7682c206` with TM002 (repeated failing `bash`) and TM005 (informational tool hotspots) findings, plus a concrete `NEXT STEP`.
- **CLI `compare`** of `examples/inefficient_run.json` against `examples/optimized_run.json` — emitted the before/after metric table (29 → 10 total tool calls, −65.5%; duplicate calls −85.7%), with the note that metrics are behavioural signals, not proof of correctness.
- **CLI fix cycle** — `fix propose` (`prop_58dec7a2b1df`) → `fix diff` (exact unified diff) → `fix approve` (refused with `APPROVAL_REQUIRED` when no TTY is present; succeeded with `--yes`) → `fix apply` (atomic write with a timestamped backup) → `fix undo`. Undo restored `AGENTS.md`; `diff` against the original fixture confirmed the file was byte-identical to its starting state.
- **MCP discovery** through the real FastMCP server via the in-memory client — 10 tools (`analyze_trace`, `apply_approved_fix`, `compare_runs`, `get_findings`, `inspect_tool_calls`, `load_trace`, `preview_fix`, `propose_fix`, `submit_ai_fix_proposal`, `undo_fix`), 2 resource templates (`tracemend://runs/{run_id}/findings`, `tracemend://runs/{run_id}/report`), and 2 prompts (`explain_inefficiency`, `optimize_agent`).
- **Test suite and lint** as reported in *Test suite* above.

**Reported in the README, not re-verified in this pass:**

- **Container run.** The image build and in-container exercise (offline analysis/compare, `/data` volume persistence, `fix approve` TTY refusal) were **not** re-run here — this pass deliberately did not run any docker/podman build. The README's claim rests on a Podman 5.5.2 / Apple Silicon (arm64) run; the `docker build` CI path on amd64 is additionally stated in the README as not yet observed to pass.
- **CI.** The `.github/workflows/ci.yml` `test` and `container` jobs were not executed or observed in this pass.
- **OpenCode adapter against live OpenCode releases.** Only fixtures and documented shapes were exercised; real-release behaviour was not re-verified here.

## Current limitations

- **Native adapters still landing.** TraceMend generic JSON and OpenCode exports ship today. Native `claude-code` and `cursor` imports are in progress on the feature branch and not yet in a release; the OpenCode adapter has only been validated against documented shapes and fixtures, not every release.
- **`AGENTS.md` is the only fix target.** Instruction fixes only; TraceMend never edits source code, dependencies, MCP config or global agent settings.
- **The detectors are small rule-based heuristics.** They match identical normalized arguments, unchanged read windows and overlapping literal search patterns. There is no semantic similarity, no embedding model and no cross-run learning, so genuinely distinct work that merely looks repetitive can be flagged — which is why every finding carries a confidence level and a limitations list.
- **TM005 is informational only.** A tool hotspot is an observation about where a session spent effort, not a verdict that the tool use was wasteful.
- **No token or cost data when the trace lacks it.** Missing metrics render as `null` / `N/A`; they are never estimated, and TM005 skips the corresponding claim.
- **Instructions do not guarantee compliance.** An instruction fix cannot force an agent to comply; a patch may change nothing, or any improvement may come from something else entirely.
- **Compare metrics show behavioural change, not task correctness.** Lower call, failure or duplicate counts are signals, not proof that the task was completed more accurately.
- **No multi-agent comparison yet.** The `agent_id` / `parent_agent_id` fields exist in the model but per-agent and cross-agent analysis is not implemented.
- **Sanitized exports lose fields.** Detectors that depend on modification data, result fingerprints or timings degrade gracefully (lower confidence / explicit limitations) rather than inventing anything.
- **Secrets redaction is best-effort.** Traces can still contain sensitive content; sanitization reduces, but does not guarantee removal of, everything sensitive.
- **Cosmetic MCP version.** In a real session the server reports the `mcp` SDK version (for example `TraceMend 1.30.0`) rather than `0.1.0`, because FastMCP defaults its version to the `mcp` package.
- **Container image verified locally, not published.** Built and exercised with Podman 5.5.2 on Apple Silicon (arm64); the CI `docker build` path on amd64 has not itself been observed to pass.

## Roadmap

None of the following is implemented in v0.1. They are listed so the scope is explicit, and several were explicitly deferred beyond the initial build:

- **`tracemend doctor`** — cross-check project instructions against observed tool behaviour and report mismatches, only when both sides of the evidence exist.
- **Multi-agent analysis** — per-agent call counts, cross-agent duplicate detection and failure hotspots using the `agent_id` / `parent_agent_id` fields already in the model.
- **Native Claude Code and Cursor imports** — first-class `claude-code` and `cursor` source formats alongside generic and OpenCode.
- **Live analysis / capture hooks** — capture execution events through provider hooks instead of exporting after the fact.
- **Tool-call caching recommendations** — suggest safe reuse, never automatic caching of side-effecting operations.
- **Prompt-effectiveness evaluation** — measure whether an instruction change correlates with improved behaviour across repeated comparable runs.

## Related

- [Detection rules](./detection-rules.md)
- [Fix workflow](./fix-workflow.md)
- [Security model](./security.md)
- [Contributing](../CONTRIBUTING.md)
- [README](../README.md)
