"""The safe auto-fix engine: propose, approve, apply and undo an instruction patch.

This module is TraceMend's main security boundary. It renders exactly one
idempotent managed section inside an ``AGENTS.md`` file and never writes to disk
without an explicit, patch-bound human approval.

Invariants enforced here:

* ``create_proposal`` is a pure database operation: it never touches the file.
* ``apply_proposal`` requires a stored :class:`ApprovalRecord` whose
  ``patch_sha256``, ``workspace``, ``target_file`` and ``original_sha256`` all
  match the proposal. A model-supplied boolean can never satisfy this.
* ``undo_patch`` refuses to clobber unrelated edits made after TraceMend wrote.
* Every path is validated through :mod:`tracemend.security`; only a
  project-local ``AGENTS.md`` is ever modified.
"""

from __future__ import annotations

import difflib
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import security
from .errors import (
    ApprovalRequiredError,
    NotFixableError,
    PatchNotFoundError,
    ProposalConflictError,
    ProposalNotFoundError,
    SecurityError,
    StaleFileError,
    UndoConflictError,
)
from .models import (
    ApprovalRecord,
    FixOperation,
    FixProposal,
    PatchRecord,
    new_id,
    sha256_text,
    utc_now,
)
from .storage import Store

__all__ = [
    "MANAGED_BEGIN",
    "MANAGED_END",
    "SECTION_HEADING",
    "STRATEGY_TEMPLATES",
    "StrategyTemplate",
    "apply_proposal",
    "approve_proposal",
    "build_unified_diff",
    "create_proposal",
    "diff_for_proposal",
    "recover_pending",
    "render_updated_content",
    "undo_patch",
    "verify_approval",
]

#: Markers that delimit the single region TraceMend owns inside AGENTS.md.
MANAGED_BEGIN = "<!-- tracemend:begin -->"
MANAGED_END = "<!-- tracemend:end -->"
#: The heading printed above the managed markers.
SECTION_HEADING = "## Tool efficiency (managed by TraceMend)"

#: Detector codes that carry an automatic remediation strategy.
FIXABLE_CODES: frozenset[str] = frozenset({"TM001", "TM002", "TM003", "TM004"})

_COMMON_LIMITATIONS: tuple[str, ...] = (
    "Instruction changes do not guarantee compliance.",
    "TraceMend cannot verify that a fix caused an observed behaviour change.",
)


@dataclass(frozen=True)
class StrategyTemplate:
    """A deterministic instruction template for one detector strategy."""

    strategy: str
    title: str
    instruction: str
    limitations: tuple[str, ...] = field(default_factory=tuple)


STRATEGY_TEMPLATES: dict[str, StrategyTemplate] = {
    "search_efficiency": StrategyTemplate(
        strategy="search_efficiency",
        title="Reuse search results and keep searches targeted",
        instruction=(
            "Reuse search results that are still valid instead of repeating the same search. "
            "When you already know the exact identifier, prefer a targeted text search over a "
            "broad scan. For conceptual or unfamiliar-code discovery, prefer a semantic-search "
            "tool when one is actually available in your toolset; do not assume any particular "
            "semantic-search MCP is installed. Avoid repeating an identical broad search unless "
            "repository state changed since the previous result."
        ),
        limitations=(
            "Semantic search is only faster when such a tool is actually available.",
            *_COMMON_LIMITATIONS,
        ),
    ),
    "retry_discipline": StrategyTemplate(
        strategy="retry_discipline",
        title="Change strategy after a failure instead of retrying blindly",
        instruction=(
            "When a command fails, inspect the failure output and change your approach before "
            "running it again. Do not re-run an identical failing command with identical "
            "arguments; adjust the arguments, the working directory, or the strategy based on "
            "the error you observed."
        ),
        limitations=(
            "Some commands must be retried verbatim (for example transient network errors).",
            *_COMMON_LIMITATIONS,
        ),
    ),
    "file_read_reuse": StrategyTemplate(
        strategy="file_read_reuse",
        title="Reuse file contents that are still current",
        instruction=(
            "Reuse a file's contents from an earlier read when the file has not changed since. "
            "Re-read only after you edit the file or when you specifically need its current "
            "state."
        ),
        limitations=(
            "Reusing a stale read is worse than re-reading; verify nothing changed it.",
            *_COMMON_LIMITATIONS,
        ),
    ),
    "general_tool_efficiency": StrategyTemplate(
        strategy="general_tool_efficiency",
        title="Avoid repeating identical tool calls",
        instruction=(
            "Avoid repeating an identical tool call while its previous result is still valid; "
            "reuse that result instead of calling the tool again."
        ),
        limitations=(
            "Applies only to calls whose result is still valid and unrelated to state changes.",
            *_COMMON_LIMITATIONS,
        ),
    ),
}


# --------------------------------------------------------------------- helpers


def _newline_for(text: str) -> str:
    """Return the dominant newline sequence so untouched regions keep their style."""
    return "\r\n" if "\r\n" in text else "\n"


def _normalise_newlines(text: str, newline: str) -> str:
    normalised = text.replace("\r\n", "\n").replace("\r", "\n")
    if newline == "\n":
        return normalised
    return normalised.replace("\n", newline)


def _managed_block(instruction: str, newline: str) -> str:
    body = _normalise_newlines(instruction, newline)
    return (
        f"{SECTION_HEADING}{newline}"
        f"{MANAGED_BEGIN}{newline}"
        f"{body}{newline}"
        f"{MANAGED_END}{newline}"
    )


# ------------------------------------------------------------------ rendering


def render_updated_content(original: str, instruction_text: str) -> str:
    """Return ``original`` with the managed section inserted or replaced in place.

    The managed section is the only region TraceMend ever rewrites. If the exact
    same instruction is already present the original string is returned
    unchanged, so the operation is idempotent and never appends twice.
    """
    text = original if isinstance(original, str) else ""
    instruction = (instruction_text or "").strip()
    if not instruction:
        raise SecurityError("instruction text must not be empty")

    newline = _newline_for(text)
    begin_index = text.find(MANAGED_BEGIN)
    end_index = text.find(MANAGED_END)

    if begin_index != -1 and end_index != -1 and end_index > begin_index:
        current_body = text[begin_index + len(MANAGED_BEGIN) : end_index]
        if _normalise_newlines(current_body, "\n").strip() == _normalise_newlines(
            instruction, "\n"
        ).strip():
            return original

        prefix = text[:begin_index]
        line_end = text.find(newline, end_index)
        tail = "" if line_end == -1 else text[line_end + len(newline) :]
        replacement = (
            f"{MANAGED_BEGIN}{newline}"
            f"{_normalise_newlines(instruction, newline)}{newline}"
            f"{MANAGED_END}{newline}"
        )
        return prefix + replacement + tail

    if begin_index != -1 and end_index == -1:
        # Malformed block: drop the dangling marker so a fresh block can be written.
        text = text[:begin_index]

    base = text.rstrip("\r\n")
    if base:
        # Keep a blank line between existing Markdown and the managed heading.
        base = base + newline * 2
    return base + _managed_block(instruction, newline)


def build_unified_diff(original: str, updated: str, target_file: str) -> str:
    """Unified diff of ``original`` -> ``updated``; empty string when unchanged."""
    if original == updated:
        return ""
    diff_lines = difflib.unified_diff(
        original.splitlines(),
        updated.splitlines(),
        fromfile=f"a/{target_file}",
        tofile=f"b/{target_file}",
        lineterm="",
    )
    return "\n".join(diff_lines)


# -------------------------------------------------------------- proposal build


def _rationale_for(finding, run_id: str) -> str:
    evidence_text = ", ".join(str(item) for item in finding.evidence) or "none recorded"
    return (
        "Hypothesis about agent instructions: the "
        f"{finding.code} ({finding.title}) pattern observed in run {run_id} may be "
        "discouraged by an explicit instruction in the agent's context. "
        f"Evidence: {evidence_text}. "
        f"Tool: {finding.tool}; occurrences: {finding.occurrences}. "
        "This is a hypothesis about agent instructions only; it is not a proven cause of "
        "the observed behaviour."
    )


def create_proposal(
    *,
    store: Store,
    run_id: str,
    finding_id: str,
    workspace: str | Path,
    origin: str = "deterministic",
    instruction_text: str | None = None,
    target_file: str = "AGENTS.md",
) -> FixProposal:
    """Build and persist a reviewable fix proposal. Never writes to disk."""
    finding = store.get_finding(run_id, finding_id)

    if not finding.fixable or finding.code not in FIXABLE_CODES:
        raise NotFixableError(
            f"finding {finding.code} ({finding_id}) has no automatic fix",
            hint="Only TM001-TM004 are auto-fixable; hotspots are reported for manual review.",
        )

    strategy = finding.details.get("strategy")
    if not isinstance(strategy, str) or strategy not in STRATEGY_TEMPLATES:
        raise NotFixableError(
            f"no remediation strategy recorded for finding {finding_id}",
            hint="Re-run the analyzer so the finding carries details['strategy'].",
        )
    template = STRATEGY_TEMPLATES[strategy]

    submitted = instruction_text if instruction_text is not None else template.instruction
    instruction = security.validate_instruction_text(submitted)

    relative_target = security.validate_target_file(target_file)

    workspace_path = security.resolve_workspace(workspace)
    target_path = security.resolve_target_path(workspace_path, relative_target)

    original_existed = target_path.exists()
    original_content = (
        _read_target_text(target_path) if original_existed else ""
    )
    original_sha256 = security.sha256_file_or_empty(target_path)

    updated_content = render_updated_content(original_content, instruction)

    existing = store.find_proposal_for(
        run_id,
        finding_id,
        relative_target,
        strategy,
        workspace=str(workspace_path),
        original_sha256=original_sha256,
        original_existed=original_existed,
    )

    if updated_content == original_content:
        if existing is not None:
            return existing
        raise ProposalConflictError(
            "the proposed instruction is already present in the managed section",
            hint="Nothing to fix; the target already contains this instruction.",
        )

    if existing is not None:
        if existing.instruction_text == instruction:
            return existing
        raise ProposalConflictError(
            "a proposal already exists for this finding and strategy",
            hint="Review or remove the existing proposal before proposing different text.",
        )

    patch = build_unified_diff(original_content, updated_content, relative_target)
    if not patch:
        raise ProposalConflictError(
            "the proposal would not change the target file",
            hint="Nothing to fix for this finding.",
        )

    proposal = FixProposal(
        proposal_id=new_id("prop"),
        run_id=run_id,
        finding_id=finding_id,
        code=finding.code,
        strategy=strategy,
        title=template.title,
        rationale=_rationale_for(finding, run_id),
        instruction_text=instruction,
        workspace=str(workspace_path),
        target_file=relative_target,
        original_sha256=original_sha256,
        original_content=original_content,
        proposed_sha256=sha256_text(updated_content),
        patch=patch,
        origin="ai" if origin == "ai" else "deterministic",
        evidence=list(finding.evidence),
        limitations=list(template.limitations),
        status="pending",
        original_existed=original_existed,
    )
    return store.save_proposal(proposal)


def diff_for_proposal(store: Store, proposal_id: str) -> str:
    """Return the stored unified diff for a proposal."""
    return store.get_proposal(proposal_id).patch


# ------------------------------------------------------------ approval / apply


def approve_proposal(
    store: Store, proposal_id: str, *, confirm: bool, approved_by: str = "local-cli"
) -> ApprovalRecord:
    """Record an explicit human approval bound to the exact proposal patch."""
    proposal = store.get_proposal(proposal_id)

    if proposal.status not in {"pending", "approved"}:
        raise ProposalConflictError(
            f"proposal {proposal_id} is {proposal.status}",
            hint="Create a fresh proposal before approving it again.",
        )

    if not confirm:
        raise ApprovalRequiredError(
            "approval requires explicit confirmation",
            hint="Re-run with confirm=True from the local CLI to approve this patch.",
        )

    record = ApprovalRecord(
        approval_id=new_id("appr"),
        proposal_id=proposal.proposal_id,
        patch_sha256=proposal.patch_sha256,
        workspace=proposal.workspace,
        target_file=proposal.target_file,
        original_sha256=proposal.original_sha256,
        approved_by=approved_by,
        original_existed=proposal.original_existed,
    )
    store.save_approval(record)

    proposal.status = "approved"
    proposal.approval_id = record.approval_id
    store.save_proposal(proposal)
    return record


def _approval_mismatches(proposal: FixProposal, record: ApprovalRecord) -> list[str]:
    mismatches: list[str] = []
    if record.patch_sha256 != proposal.patch_sha256:
        mismatches.append("patch hash")
    if record.workspace != proposal.workspace:
        mismatches.append("workspace")
    if record.target_file != proposal.target_file:
        mismatches.append("target file")
    if record.original_sha256 != proposal.original_sha256:
        mismatches.append("original file hash")
    if record.original_existed != proposal.original_existed:
        mismatches.append("original file existence")
    return mismatches


def verify_approval(store: Store, proposal_id: str) -> ApprovalRecord:
    """Return the stored approval only if it binds this exact proposal state."""
    proposal = store.get_proposal(proposal_id)
    record = store.get_approval(proposal_id)
    if record is None:
        raise ApprovalRequiredError(
            f"no approval recorded for proposal {proposal_id}",
            hint="Approve the proposal with `tracemend fix approve` first.",
        )
    mismatches = _approval_mismatches(proposal, record)
    if mismatches:
        raise ApprovalRequiredError(
            f"approval does not match proposal {proposal_id}: {'; '.join(mismatches)} changed",
            hint="Re-approve the current proposal before applying it.",
        )
    return record


# ------------------------------------------------------ journal and recovery


def _observe(target_path: Path) -> tuple[bool, str]:
    """Observe existence and bytes together; a missing file is not an empty one."""
    try:
        return True, security.sha256_file(target_path)
    except FileNotFoundError:
        return False, security.EMPTY_SHA256


def _read_target_text(target_path: Path) -> str:
    """Read the target as strict UTF-8 without newline translation.

    ``errors="replace"`` would silently turn invalid bytes into U+FFFD, so a
    later write could destroy the user's original file. Refuse instead.
    """
    size = target_path.stat().st_size
    if size > security.MAX_TRACE_BYTES:
        raise SecurityError(
            f"target file is {size} bytes, limit is {security.MAX_TRACE_BYTES} bytes",
            hint="Trim AGENTS.md before letting TraceMend edit it.",
        )
    try:
        with target_path.open("r", encoding="utf-8", newline="") as handle:
            return handle.read()
    except UnicodeDecodeError as exc:
        raise SecurityError(
            f"{target_path.name} is not valid UTF-8: {exc}",
            hint="Re-encode the file as UTF-8; TraceMend will not rewrite it.",
        ) from exc


def _resolve_edit_target(workspace: str, target_file: str) -> tuple[Path, Path]:
    workspace_path = security.resolve_workspace(workspace)
    return workspace_path, security.resolve_target_path(workspace_path, target_file)


def _fsync_file(path: Path) -> None:
    try:
        with path.open("rb") as handle:
            os.fsync(handle.fileno())
    except OSError as exc:
        raise SecurityError(f"cannot fsync {path}: {exc}") from exc


def _fsync_directory(directory: Path) -> None:
    """Make a deletion or rename durable; fail closed when it cannot be synced."""
    try:
        descriptor = os.open(directory, os.O_RDONLY)
    except OSError as exc:
        raise SecurityError(f"cannot open {directory} for fsync: {exc}") from exc
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise SecurityError(f"cannot fsync {directory}: {exc}") from exc
    finally:
        os.close(descriptor)


def _durability_barrier(target_path: Path) -> None:
    """Require a successful fsync of the file (if present) and its directory.

    A matching hash only proves the page cache agrees; it does not prove the
    mutation survives a crash. Every way of committing a landed operation must
    pass through this barrier, and a failure leaves the journal intent intact.
    """
    if target_path.exists():
        _fsync_file(target_path)
    _fsync_directory(target_path.parent)


def _operation_landed(operation: FixOperation, exists: bool, sha256: str) -> bool:
    if operation.kind == "apply":
        return exists and sha256 == operation.expected_sha256
    if operation.original_existed is False:
        return not exists
    return exists and sha256 == operation.expected_sha256


def _operation_untouched(operation: FixOperation, exists: bool, sha256: str) -> bool:
    if operation.kind == "apply":
        if sha256 != operation.original_sha256:
            return False
        if operation.original_existed is None:
            return True  # legacy proposal could not distinguish missing/empty
        return exists == operation.original_existed
    return exists and sha256 == operation.applied_sha256


def _mark_needs_review(store: Store, operation: FixOperation, detail: str) -> FixOperation:
    store.finish_operation(operation, status="needs_review", detail=detail)
    return operation


def _patch_for(
    operation: FixOperation, proposal: FixProposal, applied_sha256: str
) -> PatchRecord:
    return PatchRecord(
        patch_id=operation.patch_id,
        proposal_id=proposal.proposal_id,
        run_id=proposal.run_id,
        workspace=proposal.workspace,
        target_file=proposal.target_file,
        strategy=proposal.strategy,
        original_sha256=operation.original_sha256,
        applied_sha256=applied_sha256,
        backup_path=operation.backup_path,
        original_existed=operation.original_existed,
    )


def _finalize_landed(
    store: Store,
    operation: FixOperation,
    target_path: Path,
) -> FixOperation:
    """Record a filesystem mutation that demonstrably landed, without writing."""
    observed_exists, observed_sha256 = _observe(target_path)
    if not _operation_landed(operation, observed_exists, observed_sha256):
        return _mark_needs_review(
            store, operation, "target changed before the durability barrier"
        )
    # Never report durable success on hash alone: the barrier must succeed
    # before any journal/patch/proposal commit. A failure propagates and the
    # intent stays recoverable.
    _durability_barrier(target_path)

    proposal = store.get_proposal(operation.proposal_id)
    try:
        security.verify_backup(operation.backup_path, operation.original_sha256)
    except (OSError, SecurityError) as exc:
        return _mark_needs_review(
            store, operation, f"backup cannot be verified: {exc}"
        )

    if operation.kind == "apply":
        if proposal.status == "applied":
            if proposal.patch_id == operation.patch_id:
                store.finish_operation(operation, status="committed")
                return operation
            return _mark_needs_review(
                store, operation, "proposal was applied by a different patch"
            )
        if proposal.status != "approved":
            return _mark_needs_review(
                store, operation, f"proposal is {proposal.status}, not approved"
            )
        approval = store.get_approval(proposal.proposal_id)
        if approval is None or _approval_mismatches(proposal, approval):
            # Recovery never invents or refreshes a human approval.
            return _mark_needs_review(store, operation, "approval no longer binds")
        patch = _patch_for(operation, proposal, operation.expected_sha256)
        proposal.status = "applied"
        proposal.applied_at = utc_now()
        proposal.applied_sha256 = operation.expected_sha256
        proposal.patch_id = patch.patch_id
        store.finish_operation(
            operation, status="committed", patch=patch, proposal=proposal
        )
        return operation

    patch = store.get_patch(operation.patch_id)
    if patch.status == "undone":
        if proposal.status == "undone":
            store.finish_operation(operation, status="committed")
            return operation
        return _mark_needs_review(store, operation, "patch undone but proposal is not")
    if proposal.status != "applied":
        return _mark_needs_review(
            store, operation, f"proposal is {proposal.status}, not applied"
        )
    patch.status = "undone"
    patch.undone_at = utc_now()
    proposal.status = "undone"
    store.finish_operation(
        operation, status="committed", patch=patch, proposal=proposal
    )
    return operation


def _recover_operation(store: Store, operation: FixOperation) -> FixOperation:
    """Isolate a missing referenced record instead of starving later intents."""
    try:
        return _recover_one(store, operation)
    except (ProposalNotFoundError, PatchNotFoundError) as exc:
        return _mark_needs_review(
            store, operation, f"referenced record is missing: {exc}"
        )


def _recover_one(store: Store, operation: FixOperation) -> FixOperation:
    """Classify one intent by observed existence and hash; never guess-write."""
    # Resolve referenced records before touching the filesystem: an orphaned
    # intent must become needs_review, never be classified as "untouched".
    store.get_proposal(operation.proposal_id)
    if operation.kind == "undo":
        store.get_patch(operation.patch_id)
    try:
        _, target_path = _resolve_edit_target(operation.workspace, operation.target_file)
    except SecurityError as exc:
        return _mark_needs_review(store, operation, f"workspace is no longer safe: {exc}")

    exists, sha256 = _observe(target_path)
    if _operation_landed(operation, exists, sha256):
        return _finalize_landed(store, operation, target_path)
    if _operation_untouched(operation, exists, sha256):
        store.finish_operation(
            operation,
            status="aborted",
            detail="interrupted before the filesystem change; target untouched",
        )
        return operation
    return _mark_needs_review(
        store,
        operation,
        "target is in an unknown third state "
        f"(exists={exists}, sha256={sha256}); refusing to overwrite",
    )


def _recover_for(
    store: Store, *, proposal_id: str | None = None, patch_id: str | None = None
) -> None:
    """Recover live intents while the caller already holds the workspace lock."""
    for operation in store.list_live_operations(
        proposal_id=proposal_id, patch_id=patch_id
    ):
        try:
            _recover_operation(store, operation)
        except (ProposalConflictError, ProposalNotFoundError, PatchNotFoundError):
            continue


def recover_pending(store: Store) -> list[FixOperation]:
    """Reconcile every interrupted apply/undo; safe to call repeatedly.

    Recovery only observes files, verifies backups and updates metadata. It
    never writes the target and never grants an approval. One orphaned intent
    or durability failure must not starve unrelated recoverable intents.
    """
    recovered: list[FixOperation] = []
    first_error: SecurityError | None = None
    for operation in store.list_operations(status="intent"):
        try:
            try:
                workspace_path, _ = _resolve_edit_target(
                    operation.workspace, operation.target_file
                )
            except SecurityError:
                recovered.append(_recover_operation(store, operation))
                continue
            with security.workspace_lock(workspace_path, timeout=10.0):
                recovered.append(_recover_operation(store, operation))
        except (ProposalConflictError, ProposalNotFoundError, PatchNotFoundError):
            # Another writer already settled this intent; keep going.
            continue
        except SecurityError as exc:
            # The intent stays live and recoverable; report after the sweep.
            first_error = first_error or exc
            recovered.append(operation)
    if first_error is not None:
        raise first_error
    return recovered


def _require_review_free(store: Store, proposal_id: str) -> None:
    reviews = store.list_operations(status="needs_review", proposal_id=proposal_id)
    if reviews:
        raise ProposalConflictError(
            f"proposal {proposal_id} has an operation needing manual review",
            hint="Inspect AGENTS.md and the recorded backup before retrying.",
        )


def _settle_failed_write(
    store: Store, operation: FixOperation, target_path: Path
) -> FixOperation:
    exists, sha256 = _observe(target_path)
    if _operation_landed(operation, exists, sha256):
        return _finalize_landed(store, operation, target_path)
    if _operation_untouched(operation, exists, sha256):
        store.finish_operation(
            operation, status="aborted", detail="filesystem write failed; target untouched"
        )
        return operation
    return _mark_needs_review(
        store, operation, "write failed and the target is in an unknown third state"
    )


def apply_proposal(store: Store, proposal_id: str) -> PatchRecord:
    """Apply an approved proposal under a cooperative lock and durable journal."""
    proposal = store.get_proposal(proposal_id)

    if proposal.status != "approved":
        if store.get_approval(proposal_id) is None:
            raise ApprovalRequiredError(
                f"proposal {proposal_id} is not approved",
                hint="Approve the proposal before applying it.",
            )
        raise ProposalConflictError(
            f"proposal {proposal_id} is {proposal.status}, not approved",
            hint="Only an approved proposal can be applied.",
        )

    verify_approval(store, proposal_id)
    workspace_path = security.resolve_workspace(proposal.workspace)

    with security.workspace_lock(workspace_path, timeout=10.0):
        # Re-resolve the target under the lock so symlink/containment guards see
        # the state that will actually be written.
        _, target_path = _resolve_edit_target(
            proposal.workspace, proposal.target_file
        )
        live_apply = [
            operation
            for operation in store.list_live_operations(proposal_id=proposal_id)
            if operation.kind == "apply"
        ]
        _recover_for(store, proposal_id=proposal_id)
        proposal = store.get_proposal(proposal_id)
        if (
            proposal.status == "applied"
            and proposal.patch_id is not None
            and proposal.patch_id in {operation.patch_id for operation in live_apply}
        ):
            # This call's recovery committed an apply whose write had landed.
            return store.get_patch(proposal.patch_id)
        if proposal.status != "approved":
            raise ProposalConflictError(
                f"proposal {proposal_id} is {proposal.status}, not approved",
                hint="Create and approve a fresh proposal.",
            )
        verify_approval(store, proposal_id)
        _require_review_free(store, proposal_id)

        applied = store.applied_patch_count(proposal_id)
        if applied > 1:
            raise ProposalConflictError(
                f"proposal {proposal_id} has {applied} applied patches",
                hint="Patch history is ambiguous; resolve it manually before applying.",
            )
        if applied == 1:
            raise ProposalConflictError(
                f"proposal {proposal_id} has already been applied",
                hint="Undo the existing patch before applying again.",
            )

        exists, current_sha256 = _observe(target_path)
        if (
            proposal.original_existed is not None
            and exists != proposal.original_existed
        ):
            raise StaleFileError(
                f"{proposal.target_file} existence changed since the proposal was created",
                hint="Re-create the proposal against the current file contents.",
            )
        if current_sha256 != proposal.original_sha256:
            raise StaleFileError(
                f"{proposal.target_file} changed since the proposal was created",
                hint="Re-create the proposal against the current file contents.",
            )

        current_content = _read_target_text(target_path) if exists else ""
        updated_content = render_updated_content(current_content, proposal.instruction_text)
        if updated_content == current_content:
            raise ProposalConflictError(
                "the managed instruction is already present in the target file",
                hint="Nothing to apply; the target already contains this instruction.",
            )
        expected_sha256 = sha256_text(updated_content)

        backup_path = security.make_backup(target_path, store.backup_dir)
        security.verify_backup(backup_path, proposal.original_sha256)

        operation = FixOperation(
            operation_id=new_id("op"),
            kind="apply",
            proposal_id=proposal.proposal_id,
            patch_id=new_id("patch"),
            run_id=proposal.run_id,
            workspace=proposal.workspace,
            target_file=proposal.target_file,
            backup_path=str(backup_path),
            original_sha256=proposal.original_sha256,
            original_existed=proposal.original_existed,
            expected_sha256=expected_sha256,
        )
        store.begin_operation(operation)

        try:
            security.atomic_write_text(
                target_path,
                updated_content,
                metadata_source=str(target_path) if exists else None,
            )
        except BaseException:
            settled = _settle_failed_write(store, operation, target_path)
            if settled.status == "committed":
                return store.get_patch(operation.patch_id)
            raise

        exists_after, sha256_after = _observe(target_path)
        if not _operation_landed(operation, exists_after, sha256_after):
            _mark_needs_review(
                store, operation, "write did not produce the expected bytes"
            )
            raise ProposalConflictError(
                "the write did not produce the expected content",
                hint="The file was modified concurrently; review the target manually.",
            )

        finalized = _finalize_landed(store, operation, target_path)
        if finalized.status != "committed":
            raise ProposalConflictError(
                f"operation {operation.operation_id} needs manual review",
                hint="Inspect AGENTS.md and the recorded backup before retrying.",
            )
        return store.get_patch(operation.patch_id)


def undo_patch(store: Store, patch_id: str) -> PatchRecord:
    """Restore the pre-patch state, refusing to clobber later unrelated edits."""
    patch = store.get_patch(patch_id)

    if patch.status != "applied":
        raise ProposalConflictError(
            f"patch {patch_id} is already {patch.status}",
            hint="Only an applied patch can be undone.",
        )

    workspace_path = security.resolve_workspace(patch.workspace)

    with security.workspace_lock(workspace_path, timeout=10.0):
        # Re-resolve under the lock, matching the apply path's guards.
        _, target_path = _resolve_edit_target(patch.workspace, patch.target_file)
        live_undo = [
            operation
            for operation in store.list_live_operations(patch_id=patch_id)
            if operation.kind == "undo"
        ]
        _recover_for(store, patch_id=patch_id)
        patch = store.get_patch(patch_id)
        if patch.status == "undone" and live_undo:
            # This call recovered an interrupted undo whose restore had landed.
            return patch
        if patch.status != "applied":
            raise ProposalConflictError(
                f"patch {patch_id} is already {patch.status}",
                hint="Only an applied patch can be undone.",
            )
        _require_review_free(store, patch.proposal_id)
        if store.applied_patch_count(patch.proposal_id) > 1:
            raise ProposalConflictError(
                f"proposal {patch.proposal_id} has multiple applied patches",
                hint="Patch history is ambiguous; resolve it manually before undoing.",
            )

        exists, current_sha256 = _observe(target_path)
        if not exists or current_sha256 != patch.applied_sha256:
            raise UndoConflictError(
                f"{patch.target_file} changed after TraceMend applied its patch",
                hint="Revert the later edits manually; TraceMend will not overwrite them.",
            )

        backup_path = Path(patch.backup_path)
        security.verify_backup(backup_path, patch.original_sha256)

        operation = FixOperation(
            operation_id=new_id("op"),
            kind="undo",
            proposal_id=patch.proposal_id,
            patch_id=patch.patch_id,
            run_id=patch.run_id,
            workspace=patch.workspace,
            target_file=patch.target_file,
            backup_path=str(backup_path),
            original_sha256=patch.original_sha256,
            original_existed=patch.original_existed,
            expected_sha256=patch.original_sha256,
            applied_sha256=patch.applied_sha256,
        )
        store.begin_operation(operation)

        try:
            if patch.original_existed is False:
                target_path.unlink()
                _fsync_directory(target_path.parent)
            else:
                # Legacy ``None`` restores empty bytes instead of deleting.
                security.atomic_restore(target_path, backup_path)
        except BaseException:
            settled = _settle_failed_write(store, operation, target_path)
            if settled.status == "committed":
                return store.get_patch(patch_id)
            raise

        exists_after, sha256_after = _observe(target_path)
        if not _operation_landed(operation, exists_after, sha256_after):
            _mark_needs_review(
                store, operation, "restore did not produce the expected bytes"
            )
            raise UndoConflictError(
                "the restore did not produce the expected content",
                hint="The target was modified concurrently; review it manually.",
            )

        finalized = _finalize_landed(store, operation, target_path)
        if finalized.status != "committed":
            raise ProposalConflictError(
                f"operation {operation.operation_id} needs manual review",
                hint="Inspect AGENTS.md and the recorded backup before retrying.",
            )
        return store.get_patch(patch_id)
