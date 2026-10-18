# Setup

Get TraceMend running from a clone, then walk a trace through the analyze → fix workflow.

[← Back to README](../README.md) · [Containers](./containers.md) · [MCP](./mcp.md) · [Fix workflow](./fix-workflow.md)

## Set up from a prompt

If you would rather not run the steps by hand, hand this prompt to a coding agent (Claude Code,
Cursor, Codex, OpenCode) and let it do the clone and the setup:

> Clone the TraceMend repository and set it up on this machine.
>
> 1. Clone `https://github.com/kartikav05/tracemend` into `./tracemend`. If I forked it, use my
>    fork's URL instead.
> 2. Confirm that Python 3.12+ and `uv` are available. If `uv` is missing, stop and explain how
>    to install it — do not fall back to another installer.
> 3. Run `uv sync --extra dev` inside the clone.
> 4. Verify the install with `uv run tracemend --version` and `uv run pytest -q`. Both must
>    succeed; if either fails, report the failure instead of working around it.
> 5. Register the TraceMend MCP server for the client you are running in by following
>    `docs/mcp.md`.
> 6. Do not modify anything outside the clone, and do not commit or push.
> 7. Report the exact commands you ran and their real output.

This is safe to run unattended: TraceMend needs no credentials and makes no network calls at
runtime. Tell the agent the absolute path of the clone, so the MCP registration it writes can
reference that path.

## Requirements

Requires **Python 3.12+**. Runtime dependencies are intentionally small: `click`, `pydantic`,
`rich`, and the official `mcp` Python SDK (which ships the FastMCP server framework).

You need `uv` for the install below; it is the only supported runner.

## Install from a clone

TraceMend is not published to a package index — clone the repository and work from the clone:

```bash
git clone https://github.com/kartikav05/tracemend
cd tracemend
uv sync                 # runtime deps
uv sync --extra dev     # + pytest, pytest-asyncio, ruff
```

Then run every command through `uv` from inside the clone:

```bash
uv run tracemend --help
```

If you prefer a console script, install the project into the clone's own environment:

```bash
uv pip install -e .
tracemend --version
# TraceMend 0.1.0
```

> **Offline install note.** This project has also been verified in a network-isolated
> environment, where the equivalent install was
> `uv pip install --no-index --find-links <local wheelhouse> -e .` inside the clone. TraceMend
> itself makes no network calls at runtime, so a wheelhouse install behaves the same as
> `uv sync`.

## Quick start (manual)

```bash
# 1. Import and analyze a trace. This prints the report and stores the run locally.
uv run tracemend analyze session.json

# 2. See the findings, filtered if you like.
uv run tracemend findings <run-id> --severity high
uv run tracemend explain <run-id> <finding-id>

# 3. Turn one finding into a reviewable AGENTS.md patch.
uv run tracemend fix propose <run-id> <finding-id> --workspace .

# 4. Read the exact diff, then approve it deliberately in your terminal.
uv run tracemend fix diff <proposal-id>
uv run tracemend fix approve <proposal-id>

# 5. Apply it (atomic write + backup), then verify and compare.
uv run tracemend fix apply <proposal-id>
uv run tracemend compare before.json after.json

# 6. Roll it back if you change your mind.
uv run tracemend fix undo <patch-id>
```

The reasoning behind each propose → diff → approve → apply → undo step, and the rules that
produced the finding, live in [Fix workflow](./fix-workflow.md) and
[Detection rules](./detection-rules.md).

Machine-readable output is available on every read command:

```bash
uv run tracemend analyze session.json --format json
uv run tracemend analyze session.json --output report.json
uv run tracemend findings <run-id> --format json
uv run tracemend compare before.json after.json --format json
```

State lives in a single SQLite database (`tracemend.sqlite3`). Override the directory with
`--data-dir` or `TRACEMEND_DATA_DIR` (the latter is what the test suite uses to stay isolated).
The platform default is `~/Library/Application Support/tracemend` on macOS, and on Linux
`$XDG_DATA_HOME/tracemend` or `~/.local/share/tracemend`.

## Exporting an OpenCode session

TraceMend's first-class adapter targets OpenCode session exports. The export command
changed between OpenCode releases, so **check which one your installed version supports**
(`opencode --help`, `opencode session --help`) before you rely on the shape:

```bash
# Legacy OpenCode CLI
opencode export SESSION_ID --sanitize > session.json

# OpenCode V2
opencode session export SESSION_ID --sanitize > session.json
```

Both are handled defensively by `tracemend/adapters/opencode.py`, which understands three
payload shapes: a V2 session export (`{"info": {...}, "messages": [...]}`), a
message/part export (`{"messages": [{"parts": [{"type": "tool", ...}]}]}`), and a flat
legacy export (`{"tool_calls": [...]}`). Only assistant/tool `parts` with
`type == "tool"` become events.

Two honest caveats:

- **Sanitized exports can drop fields a detector needs.** If an export removes timings,
  token totals or result fingerprints, TraceMend records that in `run.warnings` and
  reports the affected metric as unavailable (`null`) instead of guessing. Detectors that
  depend on the missing data lower their own confidence or report a limitation.
- **Different OpenCode versions may not produce identical structures.** Verify the adapter
  against your own export before trusting a finding, and open an issue with a redacted
  fixture if the shape differs.

TraceMend was developed against the documented OpenCode export shapes plus synthetic
fixtures, and the adapter's field mapping was then cross-checked against a real OpenCode
v2.0.26 session database (12,293 tool parts). Three details from that data are handled
explicitly: the tool name is read from `name`, edited files appear as
`{"file": ..., "patch": ...}` objects in `state.metadata.files` (only the path is kept —
the embedded patch text is never copied onto an event), and tool timings arrive as
`{"created", "ran", "completed"}` rather than `{"start", "end"}`.

A live `opencode session export` could not be produced in the environment this was built
in (the CLI needs a writable state directory), so the export *wrapper* is still validated
against fixtures rather than a captured file. If your version writes something different,
please open an issue with a redacted export.

## Importing native Claude Code and Cursor traces

Two native adapters are being added so TraceMend can read transcripts you have
already captured on disk — no capture-hook installation, no history scanning, and
no new export or import commands. You point TraceMend at one explicitly chosen
file; it never walks a directory or aggregates a tree of subagent files on its own.

The planned source formats are `claude-code` and `cursor`. `tracemend analyze` and
`tracemend compare` accept `--source-format claude-code|cursor` to force a parser,
and the MCP `load_trace` tool already accepts a `format` argument (and auto-detects
when you omit it).

**Claude Code** — a session JSONL transcript. See
<https://code.claude.com/docs/en/sessions>. The format is internal and
version-sensitive: its shape can change between releases and is not a public
contract. Import only a file you have explicitly chosen; each file is imported
independently, and TraceMend does not promise to aggregate a directory of subagent
transcripts into one session.

**Cursor** — Cursor CLI NDJSON and already-captured hook JSONL. See
<https://cursor.com/docs/cli/reference/output-format> and
<https://cursor.com/docs/hooks>. TraceMend treats a CLI `stream-json` capture of a
*new* execution as distinct from an IDE transcript. It supports already-captured
`preToolUse`/`postToolUse` hook events; a conversational IDE transcript that lacks
enough tool evidence is reported as an error or a warning, and TraceMend does not
claim full IDE coverage.

**JSONL handling.** Both formats use a bounded, strict JSON Lines reader: a
malformed line is a hard error that names the line, and record-count and line-size
limits are enforced before any record is decoded. Anything the adapter cannot read
is surfaced as a warning or a skipped record — never invented — and tool token or
timing data that the source does not contain stays unknown (`null`), never
estimated. Import only transcripts you intend to analyze; do not read private agent
histories or credentials into a run.

## Supported trace formats

| Format id | Detection | Notes |
|---|---|---|
| `generic` (`tracemend.generic`) | `{"format": "tracemend.generic", ...}` | TraceMend's own normalized export. Recommended for CI fixtures and for tools that want a stable schema. |
| `opencode` | `{"info", "messages"}` / `{"messages": [...]}` / `{"tool_calls": [...]}` | OpenCode session export (legacy and V2 shapes). |
| `claude-code` | Claude Code session JSONL (planned) | Native Claude Code transcript; internal and version-sensitive (see the native-traces section above). |
| `cursor` | Cursor `stream-json` NDJSON / hook JSONL (planned) | Native Cursor capture (see the native-traces section above). |

Use `--source-format generic|opencode|claude-code|cursor` to force a parser when
auto-detection is not appropriate. Unknown layouts raise a `TraceParseError`
(`UNSUPPORTED_FORMAT`) with a hint rather than silently importing nothing.

Minimal generic trace:

```json
{
  "format": "tracemend.generic",
  "version": 1,
  "session": {
    "id": "session_fix-payment-api-bug",
    "title": "Fix payment API bug",
    "agent": "opencode-coding-agent",
    "model": "claude-sonnet-4",
    "created_at": "2026-10-13T09:12:00Z"
  },
  "events": [
    {
      "id": "call_001",
      "agent_id": "main",
      "tool": "grep",
      "arguments": { "pattern": "payment_status", "path": "src" },
      "status": "success",
      "timestamp": "2026-10-13T09:12:04Z",
      "duration_ms": 180,
      "tokens": { "input_tokens": 820, "output_tokens": 96 },
      "result_fingerprint": "fp_grep_payment_status_a1"
    }
  ]
}
```

Every event normalizes into the same Pydantic model (`ToolCall`) regardless of source:
`id`, `session_id`, `agent_id`, `parent_agent_id`, `tool`, `arguments`, `status`,
`timestamp`, `duration_ms`, `error`, `token_usage`, `cost`, plus optional
`result_fingerprint`, `modified_files` and `output_excerpt`. Event order is preserved, ids
are stable across re-imports, and anything the adapter cannot read is counted as a skipped
record and surfaced in `run.warnings` — never invented. Subagent calls are kept and tagged
with `agent_id` / `parent_agent_id`.

## Related

- [Back to README](../README.md)
- [Containers](./containers.md)
- [MCP integration](./mcp.md)
- [Detection rules](./detection-rules.md)
- [Fix workflow](./fix-workflow.md)
- [Status](./status.md)
