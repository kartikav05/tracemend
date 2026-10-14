# Security and privacy

[← Back to README](../README.md) · [Fix workflow](./fix-workflow.md) · [MCP](./mcp.md)

Agent traces are sensitive: they contain source code, internal URLs, command output and
occasionally credentials. This page says what TraceMend actually protects, where in the
code each protection lives, and — just as importantly — what it does not protect.

Every claim below is derived from `src/tracemend/security.py`, `src/tracemend/fixes.py`,
`src/tracemend/storage.py` and `src/tracemend/mcp_server.py`. The real function names and
constants are cited so you can check them yourself.

## Threat model

TraceMend assumes a hostile or malformed trace file and a mildly adversarial MCP client.
It does not assume a hostile local user or a hostile process running as that user.

| Attack | Mitigation | Where enforced |
| --- | --- | --- |
| Oversized trace exhausts memory | Hard 32 MiB ceiling; the size is checked with `stat()` before the file is read | `read_text_limited`, `MAX_TRACE_BYTES` |
| Secrets inside trace text reach a report | Pattern redaction before rendering | `redact_text`, `redact_value`, `_SECRET_PATTERNS` |
| Hostile tool output floods a model context | Bounded previews with control-character stripping and truncation | `limit_preview`, `MAX_PREVIEW_CHARS`; MCP `_bounded_text`, `_bounded_arguments` |
| Path traversal (`../evil.md`, absolute paths, `~`) | Target validated as a relative, non-traversing path | `validate_target_file`, `ALLOWED_TARGET_NAME` |
| Symlink escape via the file or any parent directory | Symlinked parents and symlinked targets are rejected; resolved path re-checked for containment | `resolve_target_path`, `_iter_parents`, `is_within` |
| Workspace escape at write time | Workspace is re-resolved and the target re-validated on every apply; apply never trusts the stored path | `resolve_workspace`, `resolve_target_path`, `ensure_within_workspace` |
| Stale-hash race: file changes between proposal and apply | Original file hash re-checked immediately before writing; a mismatch aborts | `apply_proposal` (compares `security.sha256_file_or_empty` to `proposal.original_sha256`) |
| MCP client tries to self-approve a write | No approval-granting tool and no approval parameter exist on the MCP surface | `mcp_server.apply_approved_fix`, `fixes.verify_approval` |
| Partial or torn write leaves a corrupt file | Temp-file-plus-`os.replace` with `fsync`, plus a timestamped backup | `atomic_write_text`, `make_backup` |

What TraceMend does **not** defend against:

- A coding agent that already has unrestricted shell access on the machine. It can run
  `tracemend fix approve --yes` itself or edit `AGENTS.md` directly (see below).
- A local user or process that can read the SQLite state directory, back up the database,
  or write to it. There is no encryption at rest and no per-record authentication.
- Malicious content in the trace that is *not* a recognizable secret. Redaction is
  pattern-based, not semantic: novel credential formats pass through unless a pattern in
  `_SECRET_PATTERNS` matches.
- Denial of service below the 32 MiB ceiling (for example a deeply nested but small JSON
  document). `redact_value` caps recursion at depth 12, which bounds one class of this but
  is not a general parser-hardening guarantee.
- Confidentiality against the MCP client you connect. If you ask an MCP client for
  evidence, that evidence is sent to the client's model. See "Beware the external client".

## The trust boundary

The security boundary is deliberately narrow, and it is honest about its edge:

Interactive terminal approval protects against an MCP client that merely *claims* it is
authorized. `apply_approved_fix` accepts no approval, consent or `--force` parameter, so a
model-supplied value can never authorize a write: with no stored approval it returns a
structured `"error": "APPROVAL_REQUIRED"` and changes nothing.

It cannot defend against a coding agent that already has unrestricted shell access on your
machine and chooses to impersonate you. Such an agent could run
`tracemend fix approve <proposal_id> --yes` itself, or simply edit `AGENTS.md` directly with
its own tools. Approval raises the bar and makes the write deliberate and auditable; it is
not a sandbox. Run agents with the filesystem permissions you actually want them to have.

Because the CLI and the MCP server share one SQLite store, an approval a human records in a
real terminal is visible to the MCP server, and `apply_approved_fix` can act on that exact
proposal. The CLI is the only path to an approval; the MCP server can propose, preview and
apply already-approved work, but cannot authorize it.

## Trace content is untrusted input

Everything inside a trace — including text that says "ignore your instructions" — is data.
Tool arguments and the set of available MCP tools are taken from observed calls, never
trusted as policy.

- **Input size limit.** A single imported trace file is capped at `MAX_TRACE_BYTES`
  (32 MiB, `32 * 1024 * 1024`). `read_text_limited` stats the file first and raises
  `TraceTooLargeError` if it exceeds the limit, so an oversized file is refused rather than
  read. The cap is a ceiling, not a guarantee about parsing cost.
- **No network uploads.** TraceMend makes no network calls: no telemetry, no upload, no LLM
  provider dependency, no listening socket. MCP runs over stdio. `security.py` imports no
  HTTP client.
- **Redaction.** `redact_text` replaces detected secrets with `[REDACTED:<pattern>]`
  placeholders, and `redact_value` applies the same treatment recursively to JSON-compatible
  structures (capping recursion at depth 12, returning `"[REDACTED:depth]"` beyond that).
  `_SECRET_PATTERNS` covers private keys, `sk-…`/`sk-ant-…` keys, GitHub tokens and PATs,
  AWS `AKIA…` keys, Slack, Google API keys, JWTs, bearer tokens, `KEY=value`
  credential assignments, and connection strings with embedded credentials. Reports render
  through `redact_text` (see `reports.sanitize`), so secrets are stripped from
  human-readable output.
- **Bounded previews.** `limit_preview` strips control characters and trims tool output to
  `MAX_PREVIEW_CHARS` (400), appending `"... [truncated]"`. The MCP layer bounds evidence
  with `MAX_EVIDENCE_PREVIEW` and `MAX_ARGUMENT_PREVIEW` (both 400) and limits
  `inspect_tool_calls` to `MAX_INSPECT_CALLS` (50), defaulting to `DEFAULT_INSPECT_CALLS`
  (10) and clamping finding listings between `DEFAULT_FINDING_LIMIT` (20) and
  `MAX_FINDING_LIMIT` (200).
- **Instruction text is validated too.** `validate_instruction_text` rejects non-strings,
  empty or whitespace-only text, anything longer than `MAX_INSTRUCTION_CHARS` (4000), and
  any text containing a fenced code block (```` ``` ````) — TraceMend writes Markdown prose
  into `AGENTS.md`, not code.
- **Safe serialization.** Reports and MCP payloads are serialized with
  `json.dumps(..., default=str, sort_keys=True)` after redaction, so a non-JSON value
  becomes a string instead of failing the whole response.

## Path safety

Only a project-local `AGENTS.md` may ever be modified. `ALLOWED_TARGET_NAME` is
`"AGENTS.md"`.

- `validate_target_file` rejects a non-string or empty target, rejects absolute paths,
  `~`-prefixed paths and Windows drive paths, rejects any path containing a `..` part, and
  rejects any target whose final name is not `AGENTS.md`. The surviving path is rebuilt with
  `Path(*parts)` so it stays relative.
- `resolve_workspace` expands `~`, requires the workspace to exist and be a directory, and
  returns `resolve(strict=True)` — the canonical, symlink-free path. A missing or
  non-directory workspace is a `SecurityError`.
- `resolve_target_path` joins the validated relative path onto the resolved workspace, then
  walks every parent directory up to (but excluding) the workspace with `_iter_parents`,
  rejecting any symlinked parent. A symlinked target file itself is also rejected. The
  candidate is then re-resolved and must satisfy `is_within(workspace, candidate)`.
- `is_within` treats the workspace itself and anything beneath it as inside, using resolved
  parents, so `..` segments cannot smuggle a path back out.
- `ensure_within_workspace` is the general guard for any read or write performed on behalf
  of a workspace.

Resolution happens at apply time, not just at proposal time, so a symlink swapped in
between the two is caught.

## Safe writes

Writes are atomic, backed up, and hash-checked on both ends.

- **Atomic apply.** `apply_proposal` renders the new content, takes a backup, and writes
  through `atomic_write_text`: a `NamedTemporaryFile` in the *same* directory, flushed and
  `fsync`-ed, then `os.replace` onto the target. A crash leaves either the old file or the
  new one, never a half-written mix. On any exception the temp file is unlinked.
- **Backups.** `make_backup` copies the current file into `<data_dir>/backups` with a UTC
  microsecond timestamp (`<name>.<stamp>.bak`). If the file does not exist yet, it writes an
  empty marker so undo can restore the "did not exist" state.
- **Integrity before apply.** `apply_proposal` re-reads the current file hash with
  `sha256_file_or_empty` and compares it to `proposal.original_sha256`. A mismatch raises
  `StaleFileError` — a drifted file fails the write instead of being overwritten. It also
  refuses to apply a proposal that already has a patch, and refuses a no-op apply where the
  instruction is already present. After writing, the on-disk hash is re-read and must equal
  `sha256_text(updated_content)`, or the apply raises `ProposalConflictError`.
- **Conflict-safe rollback.** `undo_patch` re-hashes the target and requires it to equal
  `patch.applied_sha256`. If someone edited the file after TraceMend wrote it, undo refuses
  rather than clobbering their unrelated change. Undo then restores the backup via
  `atomic_write_text`, or removes the file if `original_sha256` was `EMPTY_SHA256`
  (`sha256(b"")`), and records `status = "undone"`.

`.gitignore`d or not, TraceMend only ever touches `AGENTS.md` inside the resolved
workspace; everything else is refused by `validate_target_file` before a path is built.

## Approval records

An approval is single-use and bound to one exact patch. `approve_proposal` refuses without
explicit confirmation (`confirm=True`, requiring the local CLI), and writes an
`ApprovalRecord` containing:

- `proposal_id` — which proposal was approved;
- `patch_sha256` — the hash of the proposed patch;
- `workspace` — the resolved workspace it applies to;
- `target_file` — the target path (always `AGENTS.md`);
- `original_sha256` — the hash of the file as it was when the proposal was built;
- `approved_at`, `approved_by` (default `"local-cli"`) and `status` (default `"granted"`).

`verify_approval` re-checks all four substantive fields against the live proposal and
raises `ApprovalRequiredError` listing exactly which of "patch hash", "workspace",
"target file" or "original file hash" changed. So editing a proposal after approval
invalidates the approval.

The MCP server exposes **no approval-granting tool and no parameter that can supply one**:
`apply_approved_fix` is the only mutating tool that touches a user file, and it refuses to
run without an approval stored by the local CLI. Approvals are created only by
`tracemend fix approve`.

## Data retention

State lives in a single SQLite database, `tracemend.sqlite3` (constant `DB_FILENAME`),
schema version `SCHEMA_VERSION = 1`.

- **Location.** `default_data_dir` resolves, in order: the `TRACEMEND_DATA_DIR` environment
  variable (constant `DATA_DIR_ENV`) if set; else `~/Library/Application Support/tracemend`
  on macOS; else `$XDG_DATA_HOME/tracemend`; else `~/.local/share/tracemend`.
  `resolve_data_dir` honours an explicit path argument, and `Store.from_env()` reads the
  environment.
- **What is stored.** Only derived, minimized data: run metadata, normalized events,
  analysis results, findings, fix proposals, approvals and applied patches. Backups live
  under `<data_dir>/backups`.
- **What is not stored.** Raw transcripts are never retained wholesale. Tool output is kept
  as a bounded excerpt (`limit_preview`), and the module docstring for `storage.py` states
  that raw transcripts are not retained beyond the normalized events.
- The database is local and unencrypted; treat the data directory as sensitive and delete
  it when you want to clear state.

## Reporting a vulnerability

Please report security issues privately through the repository's GitHub Security Advisories
("Report a vulnerability" under the Security tab) rather than opening a public issue.

Include the version, a minimal reproduction, and the impact you observed. There is no
security email address; advisories are the single channel.

## Related

- [Fix workflow](./fix-workflow.md) — propose, approve, apply and undo, with the exact
  boundary around what TraceMend may touch.
- [MCP](./mcp.md) — the stdio server, its tools, and why approval is CLI-only.
- [Containers](./containers.md) — running the CLI and MCP server from the shipped image.
- [Architecture](./architecture.md) — how the analyzer, detectors, fixes and storage fit
  together.
- [Back to README](../README.md)
