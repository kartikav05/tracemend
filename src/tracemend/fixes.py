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
from dataclasses import dataclass, field
from pathlib import Path

from . import security
from .errors import (
    ApprovalRequiredError,
    NotFixableError,
    ProposalConflictError,
    SecurityError,
    StaleFileError,
    UndoConflictError,
)
from .models import ApprovalRecord, FixProposal, PatchRecord, new_id, sha256_text, utc_now
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

    original_content = (
        security.read_text_limited(target_path) if target_path.exists() else ""
    )
    original_sha256 = security.sha256_file_or_empty(target_path)

    updated_content = render_updated_content(original_content, instruction)

    existing = store.find_proposal_for(run_id, finding_id, relative_target, strategy)

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

    if proposal.status in {"applied", "undone"}:
        raise ProposalConflictError(
            f"proposal {proposal_id} is already {proposal.status}",
            hint="Nothing to approve.",
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
    )
    store.save_approval(record)

    proposal.status = "approved"
    proposal.approval_id = record.approval_id
    store.save_proposal(proposal)
    return record


def verify_approval(store: Store, proposal_id: str) -> ApprovalRecord:
    """Return the stored approval only if it binds this exact proposal state."""
    proposal = store.get_proposal(proposal_id)
    record = store.get_approval(proposal_id)
    if record is None:
        raise ApprovalRequiredError(
            f"no approval recorded for proposal {proposal_id}",
            hint="Approve the proposal with `tracemend fix approve` first.",
        )
    mismatches: list[str] = []
    if record.patch_sha256 != proposal.patch_sha256:
        mismatches.append("patch hash")
    if record.workspace != proposal.workspace:
        mismatches.append("workspace")
    if record.target_file != proposal.target_file:
        mismatches.append("target file")
    if record.original_sha256 != proposal.original_sha256:
        mismatches.append("original file hash")
    if mismatches:
        raise ApprovalRequiredError(
            f"approval does not match proposal {proposal_id}: {'; '.join(mismatches)} changed",
            hint="Re-approve the current proposal before applying it.",
        )
    return record


def apply_proposal(store: Store, proposal_id: str) -> PatchRecord:
    """Apply an approved proposal to disk, atomically and with a backup."""
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
    target_path = security.resolve_target_path(workspace_path, proposal.target_file)

    current_sha256 = security.sha256_file_or_empty(target_path)
    if current_sha256 != proposal.original_sha256:
        raise StaleFileError(
            f"{proposal.target_file} changed since the proposal was created",
            hint="Re-create the proposal against the current file contents.",
        )

    if store.list_patches(proposal_id=proposal_id):
        raise ProposalConflictError(
            f"proposal {proposal_id} has already been applied",
            hint="Undo the existing patch before applying again.",
        )

    current_content = security.read_text_limited(target_path) if target_path.exists() else ""
    updated_content = render_updated_content(current_content, proposal.instruction_text)
    if updated_content == current_content:
        raise ProposalConflictError(
            "the managed instruction is already present in the target file",
            hint="Nothing to apply; the target already contains this instruction.",
        )

    backup_path = security.make_backup(target_path, store.backup_dir)
    security.atomic_write_text(target_path, updated_content)

    applied_sha256 = security.sha256_file(target_path)
    if applied_sha256 != sha256_text(updated_content):
        raise ProposalConflictError(
            "the write did not produce the expected content",
            hint="The file was modified concurrently; review the target manually.",
        )

    patch = PatchRecord(
        patch_id=new_id("patch"),
        proposal_id=proposal.proposal_id,
        run_id=proposal.run_id,
        workspace=proposal.workspace,
        target_file=proposal.target_file,
        strategy=proposal.strategy,
        original_sha256=proposal.original_sha256,
        applied_sha256=applied_sha256,
        backup_path=str(backup_path),
        status="applied",
    )
    store.save_patch(patch)

    proposal.status = "applied"
    proposal.applied_at = utc_now()
    proposal.applied_sha256 = applied_sha256
    proposal.patch_id = patch.patch_id
    store.save_proposal(proposal)
    return patch


def undo_patch(store: Store, patch_id: str) -> PatchRecord:
    """Restore the pre-patch bytes, refusing to clobber later unrelated edits."""
    patch = store.get_patch(patch_id)

    if patch.status != "applied":
        raise ProposalConflictError(
            f"patch {patch_id} is already {patch.status}",
            hint="Only an applied patch can be undone.",
        )

    workspace_path = security.resolve_workspace(patch.workspace)
    target_path = security.resolve_target_path(workspace_path, patch.target_file)

    current_sha256 = security.sha256_file_or_empty(target_path)
    if current_sha256 != patch.applied_sha256:
        raise UndoConflictError(
            f"{patch.target_file} changed after TraceMend applied its patch",
            hint="Revert the later edits manually; TraceMend will not overwrite them.",
        )

    backup_path = Path(patch.backup_path)
    if not backup_path.exists():
        raise ProposalConflictError(
            f"backup for patch {patch_id} is missing",
            hint="The pre-patch content cannot be restored automatically.",
        )

    if patch.original_sha256 == security.EMPTY_SHA256:
        target_path.unlink(missing_ok=True)
    else:
        security.atomic_write_text(
            target_path, backup_path.read_text(encoding="utf-8")
        )

    patch.status = "undone"
    patch.undone_at = utc_now()
    store.save_patch(patch)

    proposal = store.get_proposal(patch.proposal_id)
    proposal.status = "undone"
    store.save_proposal(proposal)
    return patch
