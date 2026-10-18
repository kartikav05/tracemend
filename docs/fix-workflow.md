# Fix workflow

How TraceMend proposes, approves, applies and undoes an instruction fix — and the exact boundary around what it is allowed to touch.

[← Back to README](../README.md) · [Detection rules](./detection-rules.md) · [Containers](./containers.md) · [MCP](./mcp.md)

TraceMend deliberately fixes **agent instructions**, not application code. The only supported target is a project-local `AGENTS.md`.

```
Detect ──▶ Propose ──▶ Preview ──▶ Approve ──▶ Apply ──▶ Undo
(analyze)  (fix      (fix diff)   (fix       (fix      (fix undo
            propose)               approve)    apply)    <patch-id>)
```

## The six steps

| Step | Command | What happens |
|---|---|---|
| Detect | `tracemend analyze session.json` | Findings are written to the local store; fixable ones are marked `fixable: true`. |
| Propose | `tracemend fix propose <run-id> <finding-id> --workspace .` | A deterministic template is rendered into a pending proposal. Nothing is written to disk. |
| Preview | `tracemend fix diff <proposal-id>` | Prints the exact unified diff, the patch hash and the base file hash. |
| Approve | `tracemend fix approve <proposal-id>` | Records a human approval bound to that exact patch. |
| Apply | `tracemend fix apply <proposal-id>` | Re-verifies the approval, then writes atomically with a backup. |
| Undo | `tracemend fix undo <patch-id>` | Restores the pre-patch bytes, refusing to clobber later edits. |

**Detect.** `tracemend analyze session.json` writes findings to the local store.
Findings that carry a remediation strategy are marked `fixable: true`.

**Propose.** `tracemend fix propose <run-id> <finding-id> --workspace .` renders a
deterministic template into a pending proposal. Four strategies exist —
`search_efficiency`, `retry_discipline`, `file_read_reuse`, `general_tool_efficiency` —
and the instruction text is written into a clearly marked managed block, so re-proposing
updates that block instead of appending a duplicate:

```markdown
## Tool efficiency (managed by TraceMend)
<!-- tracemend:begin -->
When a command fails, inspect the failure output and change your approach before running
it again. Do not re-run an identical failing command with identical arguments; adjust the
arguments, the working directory, or the strategy based on the error you observed.
<!-- tracemend:end -->
```

Proposals are idempotent for the same finding, strategy, workspace, target file and
original file state while the proposal is pending or approved. Changed content or
existence, a different workspace, or a terminal proposal requires a fresh proposal
and a new human approval; an undone proposal is not silently reused.

**Preview.** `tracemend fix diff <proposal-id>` prints the exact unified diff, the patch
hash and the base file hash:

```diff
--- a/AGENTS.md
+++ b/AGENTS.md
@@ -6,3 +6,8 @@

 - Run `pytest` before claiming a change is complete.
 - Prefer small, focused edits over broad refactors.
+
+## Tool efficiency (managed by TraceMend)
+<!-- tracemend:begin -->
+When a command fails, inspect the failure output and change your approach before running
+it again. Do not re-run an identical failing command with identical arguments; adjust the
+arguments, the working directory, or the strategy based on the error you observed.
+<!-- tracemend:end -->
```

**Approve.** `tracemend fix approve <proposal-id>` requires an interactive TTY and asks you
to type `approve`:

```
Type 'approve' to authorize this exact patch for /path/to/workspace/AGENTS.md:
```

Without a TTY it fails closed:

```
╭─ APPROVAL_REQUIRED ──────────────────────────────────────────────────────────╮
│ Error: approval requires an interactive terminal                             │
│  Hint: Run this command in a terminal, or pass --yes for a deliberate local  │
│        script.                                                               │
╰──────────────────────────────────────────────────────────────────────────────╯
```

`--yes` exists for scripted local use; it is a CLI-only flag and is not reachable over MCP.

> **Note.** Approval is a human act, so `fix approve` needs a terminal. In a container that
> means `docker run -it`; see [Containers](./containers.md) for the volume and TTY setup.

**Apply.** `tracemend fix apply <proposal-id>` re-verifies all of the above
under a cooperative workspace lock, saves a durable operation intent, then writes
atomically and records the patch. Existing file metadata is copied to the replacement
before it becomes visible; the backup is an independent snapshot, not a hard link:

```
──────────────────────────────── APPLIED PATCH ─────────────────────────────────
  Patch: patch_b9d70b7e4378
 Status: applied
 Target: /path/to/workspace/AGENTS.md
Applied: 2026-10-14T17:51:07.447995+00:00
 Backup: .../backups/AGENTS.md.20261014T175107447100Z.bak
```

**Undo.** `tracemend fix undo <patch-id>` restores the file from the recorded original
content — but only if the file still matches what TraceMend applied. If you edited the file
afterwards, the undo is refused rather than overwriting your work.
The backup must match the recorded original hash before restoration. An existing
empty `AGENTS.md` is restored as an empty file; a file is removed only when the patch
records that the original was absent. Legacy patches with unknown original existence
restore empty bytes rather than guessing that deletion is safe.

### Interrupted operations and concurrent writers

Apply and undo record intent in the local SQLite operation journal before changing
the target. Finalization updates the operation, patch and proposal together in one
transaction. Retrying the corresponding apply or undo reconciles an interrupted
operation under the workspace lock:

- If the target has the expected post-operation existence and content hash, the
  landed change can be recorded without writing the file again.
- If the original state remains, the untouched intent can be aborted before retry.
- An unrecognized state or unverifiable backup requires manual review; recovery
  does not overwrite the file or create a human approval.

After an interruption, inspect `tracemend fix list --format json` for the proposal
status and patch id. A retry may report that an operation is already applied or
undone after reconciling it; do not re-approve an old proposal to force another write.
The service also exposes `recover_pending(store)` for local callers; there is no
separate recovery CLI command or MCP tool.

Writers lock the canonical workspace directory itself, so separate local stores
targeting the same workspace serialize without creating a workspace lockfile.
These are advisory POSIX locks: unrelated editors and older TraceMend versions do
not participate, and network filesystem locking is not guaranteed. Hash and path
checks remain necessary. Ambiguous legacy duplicate applied patches are preserved
but block further apply/undo until manually resolved.

Schema v2 adds the operation journal without rewriting existing proposal, approval
or patch payloads. New records include original-file existence; legacy records may
leave it unknown. Databases from a newer schema version are rejected rather than
silently downgraded. Do not run older writers against the upgraded store.

Metadata preservation uses native macOS ACL/stat/xattr copying and Linux extended
attributes. Unsupported platforms, including Windows, fail closed for remediation
rather than silently losing metadata or proceeding without workspace locking.
Platform-specific checks do not imply that every filesystem supports these features.
New files retain the private `0600` creation mode (subject to a stricter umask),
rather than inheriting an unrelated file's permissions or enabling group/world access.
Invalid UTF-8 instruction files are refused rather than decoded with replacement
characters and silently rewritten.

Exit codes are stable for scripting: `2` parse/usage, `3` not found / not fixable,
`4` security refusal, `5` approval required / stale file / proposal conflict.

## What TraceMend will and will not touch

TraceMend edits exactly one thing: a project-local `AGENTS.md` inside the workspace you
name with `--workspace`. The target must be a relative path whose basename is exactly
`AGENTS.md`; absolute paths, `~` and `..` are rejected outright.

It never edits:

| Never touched | Example |
|---|---|
| Global OpenCode config | `~/.config/opencode/` |
| Global Claude Code or Cursor instructions | `~/.claude/CLAUDE.md`, `~/.cursor/rules/` |
| User-level MCP configuration | any user-scoped MCP server list |
| Shell profiles | `~/.zshrc`, `~/.bashrc` |
| Application source | any project `.py`, `.ts`, `.go`, … file |
| Arbitrary paths | anywhere outside the resolved workspace |

> **Note.** TraceMend v0.1 is intentionally narrow: it writes Markdown prose into
> `AGENTS.md` and nothing else. Instruction changes do not guarantee compliance, and
> TraceMend cannot verify that a fix caused an observed behaviour change.

## Strategies

The four templates below are the complete set that ships in
`src/tracemend/fixes.py`. Each is a fixed string, selected by the finding's recorded
`details["strategy"]` — no model is involved in choosing or wording them.

| Strategy | Title | Instruction (verbatim) |
|---|---|---|
| `search_efficiency` | Reuse search results and keep searches targeted | Reuse search results that are still valid instead of repeating the same search; prefer a targeted text search over a broad scan when you know the identifier, and prefer a semantic-search tool when one is actually available. |
| `retry_discipline` | Change strategy after a failure instead of retrying blindly | When a command fails, inspect the failure output and change your approach before running it again; do not re-run an identical failing command with identical arguments. |
| `file_read_reuse` | Reuse file contents that are still current | Reuse a file's contents from an earlier read when the file has not changed since; re-read only after you edit it. |
| `general_tool_efficiency` | Avoid repeating identical tool calls | Avoid repeating an identical tool call while its previous result is still valid; reuse that result instead of calling the tool again. |

Each template also carries a `limitations` list that is stored on the proposal, so the
caveats travel with the fix (for example, retrying a command verbatim is correct for a
transient network error, and semantic search only helps when such a tool is present).

Every proposal is **deterministic** (the same finding and strategy always render the same
bytes), **minimal** (one short instruction, never a rewrite of the file),
**evidence-backed** (the rationale names the detector code, the run, the tool and the
observed occurrences) and **idempotent** (proposing twice returns the same proposal;
applying twice is refused).

## The managed region

TraceMend owns exactly one region of `AGENTS.md`, delimited by two HTML comment markers:

| Marker | Constant | Value |
|---|---|---|
| Start | `MANAGED_BEGIN` | `<!-- tracemend:begin -->` |
| End | `MANAGED_END` | `<!-- tracemend:end -->` |
| Heading | `SECTION_HEADING` | `## Tool efficiency (managed by TraceMend)` |

Rendering is an in-place replace, not an append. If the current body already matches the
proposed instruction, the original text is returned unchanged. If it differs, only the
bytes between the markers are rewritten; everything before and after is preserved, and the
file's dominant newline style (`\n` or `\r\n`) is kept. A dangling start marker left by a
malformed edit is dropped so a fresh block can be written cleanly.

> **Note.** Because there is a single managed region, **the same instruction is never
> appended twice**. Hand-edits *inside* the markers are treated as TraceMend's to manage;
> hand-edits outside them are never touched.

## The approval record

The approval record is bound to the change, not to the conversation. Its stored fields map
directly onto the `ApprovalRecord` and the proposal it authorises:

| Field | Purpose |
|---|---|
| Proposal id | Which proposal was approved |
| Patch hash | The exact diff bytes that were authorized |
| Workspace path | Where the write is allowed to happen |
| Target file | Only `AGENTS.md` |
| Original file hash | Detects any drift since the proposal was created |
| Approval status | Single-use; re-approval for a different patch is a new record |
| Application status | Tracks `pending → approved → applied → undone` |

At apply time TraceMend re-checks the record against the proposal and refuses on any
mismatch. Approval is bound to the **exact patch hash, target file, workspace and original
content hash** — change any one of them and the approval no longer applies.

> **Note.** The approval record lives in SQLite under `TRACEMEND_DATA_DIR`. A fresh state
> directory (or a fresh container without a state volume) has no approval, so the
> propose → approve → apply boundary cannot be satisfied.

## Rejections that are actually enforced

These are not documentation promises; each is a check in `fixes.py` or `security.py` that
raises before anything reaches disk.

| Rejection | Raised as |
|---|---|
| Unknown proposal id | Not found |
| Unapproved proposal | `APPROVAL_REQUIRED` |
| Modified proposal (patch, workspace, target or original hash changed after approval) | `APPROVAL_REQUIRED` |
| Stale file hash (target changed since the proposal was created) | `STALE_FILE` |
| Paths outside the workspace | `SECURITY_ERROR` |
| Symlink-based escapes (symlinked target or symlinked parent directory) | `SECURITY_ERROR` |
| Repeated application (a patch already exists for the proposal) | `PROPOSAL_CONFLICT` |
| Unauthorised writes (non-`AGENTS.md` target, empty/oversized instruction, or instruction containing a fenced code block) | `SECURITY_ERROR` |

Applying a proposal that is already applied is a conflict, not a re-run:

```
╭─ PROPOSAL_CONFLICT ──────────────────────────────────────────────────────────╮
│ Error: proposal prop_c126ccdf255a is applied, not approved                   │
│  Hint: Only an approved proposal can be applied.                             │
╰──────────────────────────────────────────────────────────────────────────────╯
```

Path guarding resolves the workspace with `strict=True`, rejects any target whose basename
is not `AGENTS.md`, walks each parent directory checking for symlinks, and finally confirms
the resolved candidate is still inside the resolved workspace. Every one of these checks
runs on the read path as well as the write path.

## Atomicity, backups and rollback

Applying a fix is a sequence of guarded steps:

- re-read the target and refuse if it changed since the proposal was created (`STALE_FILE`);
- refuse if the instruction is already present;
- refuse if a patch was already applied for this proposal;
- resolve the target path, rejecting traversal and symlink escapes (`SECURITY_ERROR`);
- write atomically via a temp file in the same directory followed by `os.replace`, after
  copying a timestamped backup into the store's `backups/` directory;
- re-hash the file and confirm the write produced exactly the expected content, then record
  a `PatchRecord`.

Backups live under `<TRACEMEND_DATA_DIR>/backups/` and are named
`AGENTS.md.<UTC-timestamp>.bak`. A backup is written even when the target did not previously
exist, so undo can restore the "file did not exist" state.

Undo is conflict-safe. `tracemend fix undo <patch-id>` refuses when the file no longer
matches the content TraceMend applied, rather than clobbering an unrelated later edit:

- if the file changed after the patch, the undo raises `UNDO_CONFLICT` and stops;
- if the backup is missing, the original content cannot be restored and the undo stops;
- a patch that is not currently `applied` cannot be undone twice.

## Security boundary

The interactive `approve` step — a real TTY plus typing `approve`, or an explicit
`--yes` — protects against an **MCP client merely claiming authorisation**. A model-driven
tool call cannot approve its own patch: `apply_approved_fix` and `propose_fix` never
satisfy the approval check, and `--yes` is not reachable over MCP.

It cannot defend against a coding agent that already has unrestricted shell access to the
machine and deliberately impersonates the user. If an agent can run arbitrary commands, it
can set `TRACEMEND_DATA_DIR`, call `tracemend fix approve --yes` and then `tracemend fix
apply` itself, or simply edit `AGENTS.md` directly. The approval gate is a guardrail
against accidental or over-eager automation; it is not a sandbox, and it assumes the local
user is the one at the keyboard.

## Related

- [README](../README.md) — project overview and the full command reference.
- [Detection rules](./detection-rules.md) — what makes a finding fixable, and the detector codes.
- [Containers](./containers.md) — running the fix flow one container per step.
- [MCP](./mcp.md) — the `propose_fix`, `preview_fix`, `apply_approved_fix` and `undo_fix` tools.
