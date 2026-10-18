# MCP

TraceMend speaks the Model Context Protocol over **stdio** (FastMCP), launched as `tracemend mcp` — one thin adapter over the same deterministic engine the CLI uses.

[← Back to README](../README.md) · [Setup](./setup.md) · [Containers](./containers.md)

The server is a thin adapter over the same deterministic engine the CLI uses, and it reads and writes the same local SQLite state.
That shared state is the whole point of the design: an approval a human records in a real terminal with `tracemend fix approve` is stored in SQLite, so the MCP server sees it too, and `apply_approved_fix` can act on that exact proposal.
This guide documents how to wire a client to the stdio server, including a container-only variant.
Every fact below is derived from the TraceMend repository unless it is explicitly marked as a client convention.
Client configuration formats change between releases, so treat the snippets as starting points and verify the key names against your installed client's documentation.

## The MCP surface

Server name: `TraceMend` (from `SERVER_NAME` in `src/tracemend/mcp_server.py`).
Server command: `tracemend mcp` (the `mcp` subcommand in `src/tracemend/cli.py`, which calls `mcp_server.main()`).

### Tools

| Tool | Required arguments | Kind | Purpose |
|---|---|---|---|
| `load_trace` | `path` | Write (TraceMend's local store only; reads your trace file, touches no workspace file) | Import and validate a trace; returns `run_id`, `source`, `event_count`, `warnings`, `redactions` |
| `analyze_trace` | `run_id` | Write (persists the report in TraceMend's local store; modifies no workspace file) | Run the deterministic engine; returns `metrics`, `findings`, `notes` |
| `get_findings` | `run_id` | Read-only | List findings, optionally filtered by `severity`, with a bounded `limit` |
| `inspect_tool_calls` | `run_id` | Read-only | Bounded, redacted evidence for specific `call_ids` |
| `propose_fix` | `run_id`, `finding_id`, `workspace` | Propose (stores a PENDING proposal; writes nothing to your workspace) | Create a **pending** proposal that patches one file in a workspace |
| `preview_fix` | `proposal_id` | Read-only | Return the diff for a proposal without touching disk |
| `apply_approved_fix` | `proposal_id` | Mutating (the only tool that edits a user file; requires a prior CLI approval) | Apply a proposal **only** if the local CLI already approved it |
| `compare_runs` | `before_run_id`, `after_run_id` | Read-only | Compare two loaded runs |
| `undo_fix` | `patch_id` | Mutating (reverts TraceMend's own patch, subject to integrity checks) | Revert a TraceMend patch, subject to file-integrity checks |
| `submit_ai_fix_proposal` | `run_id`, `finding_id`, `workspace`, `proposed_instruction` | Propose (stores model text as a PENDING proposal; can never apply) | Accept model-authored instruction text as a pending proposal for human review |

Optional arguments (source of truth, not exhaustive here): `load_trace` accepts `format`; `get_findings` accepts `severity` and `limit`; `inspect_tool_calls` accepts `call_ids` and `limit`; `propose_fix` and `submit_ai_fix_proposal` accept `target_file` (default `AGENTS.md`).
The `format` argument (and the CLI's `--source-format`) accepts `generic` and `opencode` today, with native `claude-code` and `cursor` planned; `load_trace` auto-detects when `format` is omitted. See [setup.md](./setup.md) for what those formats accept and their caveats.
Note that `analyze_trace` is listed as a read-only tool in the server's module docstring and as a local-write tool in the same docstring; the precise behaviour is that it reads your workspace and writes only to TraceMend's own store.

`submit_ai_fix_proposal` treats model-written text as untrusted: it length-checks it, strips control characters, blocks fenced code blocks, restricts the target to a project-local `AGENTS.md`, and can only ever create a `pending` proposal.
It is the one place a model may contribute instruction text, and it can never apply, approve or verify a change.

### Findings are structured

Every finding is a stable record, not a paragraph, so an agent can act on fields instead of parsing prose.
Alongside `code`, `severity`, `confidence`, `tool`, `occurrences` and `evidence` (the call ids the finding came from), each finding carries a machine-readable `recommendation` string and a `fixable` boolean.
That is what `get_findings`, the report resource and the prompts hand to the model: measured metrics, the call ids behind each finding, and a recommendation the model can turn into a proposed `AGENTS.md` instruction.

### Resources

Two resource templates (FastMCP `@mcp.resource`, with concrete per-run variants registered under the same URIs):

- `tracemend://runs/{run_id}/report` — the structured analysis report for a run, as JSON text.
- `tracemend://runs/{run_id}/findings` — the findings for a run, as JSON text.

### Prompts

- `optimize_agent` — argument `run_id`; a structured prompt to diagnose and fix the findings of one analyzed run.
  It is a full role / evidence / procedure / constraints / output / safety prompt that hands the model the measured metrics, every finding with its evidence ids, and the exact JSON schema to answer in.
- `explain_inefficiency` — arguments `run_id`, `finding_id`; a focused prompt that explains one finding and its evidence.

The server also ships a top-level `INSTRUCTIONS` string describing the seven-step workflow (`load_trace` → `analyze_trace` → `get_findings` / `inspect_tool_calls` → `propose_fix` → `preview_fix` → `apply_approved_fix` → `compare_runs` / `undo_fix`) and the hard rules: no change without a human CLI approval, only a project-local `AGENTS.md` is ever modified, and all tool arguments and outputs are redacted and truncated.

## Connect it to your agent

One-line mental model: the agent calls the read-only tools to investigate a run, then `propose_fix`; a human approves in a terminal with `tracemend fix approve <proposal-id>`; only then may the agent call `apply_approved_fix`.

For the clone-and-install prompt that gets TraceMend onto your machine and into your client, see [`docs/setup.md`](./setup.md).

The server must share the same store as the CLI: point both at the same `TRACEMEND_DATA_DIR`, or mount the same `/data` volume in the container.
Otherwise the agent reads an empty store and every `run_id` looks missing.

## Launching the server

Prefer a launcher that resolves the executable itself, because the MCP client may not inherit your interactive shell `PATH`:

- From a checkout: `uv run --directory /ABS/PATH/TO/trace-mend tracemend mcp`
- From a path or package: `uvx --from /ABS/PATH/TO/trace-mend tracemend mcp`

A bare `command: "tracemend"` only works when the console script is already on the `PATH` the client actually uses.
`python -m tracemend.mcp_server` serves the same stdio server and is a useful fallback when the console script is not installed.

## Per-client setup

Config key names for these clients have changed across releases.
Confirm the exact keys against your installed client's docs before relying on any snippet below.

### Claude Code

Derived from client convention (the `claude mcp add` CLI form); the command is derived from the TraceMend repo.

```bash
claude mcp add tracemend -- uv run --directory /ABS/PATH/TO/trace-mend tracemend mcp
```

This registers a stdio server named `tracemend`.
Use `claude mcp list` to confirm it appears.

### Cursor

Derived from client convention (the `mcpServers` JSON block); the server command and args are derived from the TraceMend repo.

Global config lives at `~/.cursor/mcp.json`; project config lives at `.cursor/mcp.json`.

```json
{
  "mcpServers": {
    "tracemend": {
      "command": "uv",
      "args": ["run", "--directory", "/ABS/PATH/TO/trace-mend", "tracemend", "mcp"]
    }
  }
}
```

### OpenCode

Derived from client convention (the `mcp` block in `opencode.json`); the command is derived from the TraceMend repo.

```json
{
  "mcp": {
    "tracemend": {
      "type": "local",
      "command": ["uv", "run", "--directory", "/ABS/PATH/TO/trace-mend", "tracemend", "mcp"],
      "enabled": true
    }
  }
}
```

**Unverified:** the exact keys (`type`, `command`, `enabled`) vary between OpenCode releases.
Confirm against your installed version's docs; some releases expect a single string command and others expect an array.

### Generic stdio JSON

Most MCP clients accept this shape (client convention):

```json
{
  "mcpServers": {
    "tracemend": {
      "command": "uv",
      "args": ["run", "--directory", "/ABS/PATH/TO/trace-mend", "tracemend", "mcp"]
    }
  }
}
```

Set `TRACEMEND_DATA_DIR` in the server's `env` block to point the client at a specific store.

## Containerized MCP variant

The image contract (from the repo `Dockerfile`): non-root UID `10001`, `WORKDIR /workspace`, a `/data` volume, `ENV TRACEMEND_DATA_DIR=/data`, and `ENTRYPOINT ["tracemend"]`.
Build it once: `docker build -t tracemend:0.1.0 .` (or `podman build -t tracemend:0.1.0 .`).

```json
{
  "mcpServers": {
    "tracemend": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--network", "none",
        "-v", "/ABSOLUTE/WORKSPACE:/workspace",
        "-w", "/workspace",
        "-v", "tracemend-state:/data",
        "tracemend:0.1.0", "mcp"
      ]
    }
  }
}
```

- `-i` keeps stdin open, which is required: the stdio transport carries the JSON-RPC stream over stdin/stdout.
- Do **not** add `-t`. A pseudo-TTY mangles line endings and output buffering and corrupts the JSON-RPC framing.
- The `/data` named volume is mandatory. Approval records live in SQLite; without a persistent volume a fresh container loses them and the approve/apply boundary breaks between runs.
- `--network none` is safe because TraceMend makes no network calls.
- `-v /ABSOLUTE/WORKSPACE:/workspace -w /workspace` gives the server the same workspace the human approves fixes against.

Podman is identical, with `podman` in place of `docker`:

```json
{
  "mcpServers": {
    "tracemend": {
      "command": "podman",
      "args": [
        "run", "-i", "--rm", "--network", "none",
        "-v", "/ABSOLUTE/WORKSPACE:/workspace",
        "-w", "/workspace",
        "-v", "tracemend-state:/data",
        "tracemend:0.1.0", "mcp"
      ]
    }
  }
}
```

**Verification status:** the container entry above was exercised against a real container runtime (Podman 5.5.2, driven through its `docker` CLI). Over `run -i ... mcp` with no TTY, `initialize`, `tools/list`, `resources/templates/list` and `prompts/list` all returned, and `tools/call` round-trips for `get_findings`, `preview_fix`, `apply_approved_fix` and `undo_fix` were confirmed — including `APPROVAL_REQUIRED` for an unapproved proposal and a successful apply only after a human ran `fix approve` with `-it`. The client-specific parts — where each client keeps its config and the exact key names — have **not** been tested against installed copies of Claude Code, Cursor or OpenCode, because those formats change between releases.

## The approval boundary

There is **no tool that can approve or self-authorise a change**, and no parameter that accepts a consent or `force` boolean.
`apply_approved_fix` takes exactly one argument, `proposal_id`; it succeeds only when a human already ran `tracemend fix approve <proposal-id>` in a real terminal.
Until then it returns an `APPROVAL_REQUIRED` structured error and changes nothing.
A model-supplied boolean is never treated as approval.
The related CLI commands are `tracemend fix approve <proposal-id>`, `tracemend fix apply <proposal-id>`, `tracemend fix undo <patch-id>`, and `tracemend fix diff <proposal-id>`.

Without a real local approval the tool returns:

```json
{
  "error": "APPROVAL_REQUIRED",
  "hint": "Approve the proposal with `tracemend fix approve` first."
}
```

> The approval boundary protects against an MCP client merely *claiming* authorisation: it cannot fabricate the SQLite approval record.
> It does **not** protect against an agent that already has unrestricted shell access on your machine, because such an agent can run `tracemend fix approve` itself and impersonate the user.
> Treat the boundary as a guardrail for cooperative clients, not as a sandbox.

## Privacy

Anything a tool returns reaches whichever model the client is connected to.
Tool outputs are redacted and truncated by TraceMend, but trace evidence still travels to the model provider.
Prefer sanitized OpenCode exports (`opencode export <session-id> --sanitize`, or `opencode session export <session-id> --sanitize` on the V2 CLI) before importing a trace.
Check the absolute workspace path before connecting a client to it, so you never point the server at a directory you did not intend to analyze.

## Troubleshooting

- Server missing from the client's list: the client did not parse the config, or closed the process at startup. Check the client's MCP logs and confirm the JSON is valid and the key (`mcpServers` vs `mcp`) matches your client.
- `tracemend` not found on `PATH`: the client's environment differs from your shell. Use `uv run --directory /ABS/PATH/TO/trace-mend tracemend mcp`, `uvx --from ...`, or `python -m tracemend.mcp_server`.
- Stdio framing broken (`-t`, a shell banner, or login output): a pseudo-TTY or any text printed on stdout before the JSON-RPC stream corrupts framing. Remove `-t` and make sure the launcher prints nothing on stdout. TraceMend logs to stderr for exactly this reason.
- Empty `findings` output: the client ran with a different `TRACEMEND_DATA_DIR` than the CLI that imported the run, so it is reading a different SQLite store. Align `TRACEMEND_DATA_DIR` (and the container `/data` volume) between the CLI and the server.
- `APPROVAL_REQUIRED` on apply: expected. No approval record exists for that `proposal_id` in the server's store. Run `tracemend fix approve <proposal-id>` in a real terminal against the same `TRACEMEND_DATA_DIR`, then retry `apply_approved_fix`.

## Related

- [`../README.md`](../README.md) — what TraceMend is, the detectors, and the CLI workflow.
- [`./setup.md`](./setup.md) — clone-and-install prompt and first-run setup.
- [`./containers.md`](./containers.md) — building and running the container image.
- [`./fix-workflow.md`](./fix-workflow.md) — propose, approve, apply and undo in detail.
