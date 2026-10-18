"""Tests for the safe auto-fix engine (propose -> approve -> apply -> undo)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tracemend import fixes, security
from tracemend.errors import (
    ApprovalRequiredError,
    NotFixableError,
    ProposalConflictError,
    SecurityError,
    StaleFileError,
    UndoConflictError,
)
from tracemend.models import (
    AnalysisReport,
    ApprovalRecord,
    Finding,
    FixOperation,
    FixProposal,
    TraceRun,
    sha256_text,
)
from tracemend.storage import Store

RUN_ID = "run_fixtest"

FIXABLE_STRATEGIES = (
    ("TM001", "general_tool_efficiency"),
    ("TM002", "retry_discipline"),
    ("TM003", "file_read_reuse"),
    ("TM004", "search_efficiency"),
)

ORIGINAL = "# AGENTS.md\n\nAlways run the tests before finishing.\n"


def make_finding(code: str, strategy: str, *, fixable: bool = True, **overrides):
    payload = {
        "id": f"{code}:bash:{strategy}",
        "code": code,
        "run_id": RUN_ID,
        "severity": "medium",
        "confidence": "high",
        "title": f"{code} finding",
        "description": "an inefficiency was detected",
        "tool": "bash",
        "occurrences": 3,
        "evidence": ["ev-1", "ev-2"],
        "recommendation": "follow the instruction",
        "fixable": fixable,
        "details": {"strategy": strategy},
    }
    payload.update(overrides)
    return Finding(**payload)


class FixesTestBase(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.store = Store(self.root / "state")

    def seed(self, findings) -> None:
        self.store.save_run(TraceRun(run_id=RUN_ID, session_id="sess", title="t"))
        self.store.save_report(AnalysisReport(run_id=RUN_ID, findings=list(findings)))

    def agents_path(self) -> Path:
        return self.workspace / "AGENTS.md"

    def write_agents(self, text: str) -> Path:
        path = self.agents_path()
        path.write_text(text, encoding="utf-8")
        return path

    def propose(self, finding, **kwargs):
        return fixes.create_proposal(
            store=self.store,
            run_id=RUN_ID,
            finding_id=finding.id,
            workspace=self.workspace,
            **kwargs,
        )

    def approve_and_apply(self, finding):
        proposal = self.propose(finding)
        fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)
        patch = fixes.apply_proposal(self.store, proposal.proposal_id)
        return proposal, patch


class TestProposalGeneration(FixesTestBase):
    def test_proposal_for_each_fixable_strategy(self) -> None:
        for code, strategy in FIXABLE_STRATEGIES:
            with self.subTest(code=code):
                self.seed([make_finding(code, strategy)])
                self.write_agents(ORIGINAL)
                proposal = self.propose(make_finding(code, strategy))

                self.assertEqual(proposal.code, code)
                self.assertEqual(proposal.strategy, strategy)
                self.assertEqual(proposal.status, "pending")
                self.assertEqual(proposal.origin, "deterministic")
                self.assertEqual(proposal.target_file, "AGENTS.md")
                self.assertEqual(proposal.workspace, str(self.workspace.resolve()))
                self.assertTrue(proposal.proposal_id.startswith("prop_"))
                self.assertTrue(proposal.patch)
                self.assertEqual(proposal.evidence, ["ev-1", "ev-2"])
                self.assertEqual(proposal.original_sha256, security.sha256_file(self.agents_path()))
                self.assertNotIn(fixes.SECTION_HEADING, proposal.instruction_text)
                self.assertEqual(
                    proposal.instruction_text, fixes.STRATEGY_TEMPLATES[strategy].instruction
                )
                self.assertIn("hypothesis about agent instructions", proposal.rationale)
                self.assertIn("ev-1", proposal.rationale)
                self.assertIn(
                    "Instruction changes do not guarantee compliance.", proposal.limitations
                )
                self.assertIn(
                    "TraceMend cannot verify that a fix caused an observed behaviour change.",
                    proposal.limitations,
                )

    def test_tm005_hotspot_is_not_fixable(self) -> None:
        finding = make_finding("TM005", "hotspot", fixable=False)
        self.seed([finding])
        self.write_agents(ORIGINAL)
        with self.assertRaises(NotFixableError):
            self.propose(finding)

    def test_unknown_strategy_is_not_fixable(self) -> None:
        finding = make_finding("TM001", "mystery_strategy")
        self.seed([finding])
        with self.assertRaises(NotFixableError):
            self.propose(finding)

    def test_create_proposal_never_writes_to_disk(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        before = self.agents_path().read_bytes()
        self.propose(finding)
        self.assertEqual(self.agents_path().read_bytes(), before)
        self.assertNotIn(fixes.MANAGED_BEGIN, self.agents_path().read_text(encoding="utf-8"))

    def test_create_proposal_for_missing_file_uses_empty_hash(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        proposal = self.propose(finding)
        self.assertEqual(proposal.original_sha256, security.EMPTY_SHA256)
        self.assertEqual(proposal.original_content, "")
        self.assertFalse(self.agents_path().exists())


class TestRenderingAndDiff(FixesTestBase):
    def test_build_unified_diff_structure(self) -> None:
        diff = fixes.build_unified_diff("a\n", "a\nb\n", "AGENTS.md")
        lines = diff.splitlines()
        self.assertEqual(lines[0], "--- a/AGENTS.md")
        self.assertEqual(lines[1], "+++ b/AGENTS.md")
        self.assertTrue(any(line.startswith("@@") for line in lines))
        self.assertIn("+b", lines)

    def test_build_unified_diff_empty_when_unchanged(self) -> None:
        self.assertEqual(fixes.build_unified_diff("same\n", "same\n", "AGENTS.md"), "")

    def test_render_appends_then_replaces_in_place(self) -> None:
        first = fixes.render_updated_content(ORIGINAL, "Instruction one.")
        self.assertTrue(first.startswith(ORIGINAL))
        self.assertEqual(first.count(fixes.MANAGED_BEGIN), 1)
        self.assertEqual(first.count(fixes.MANAGED_END), 1)
        self.assertEqual(first.count(fixes.SECTION_HEADING), 1)
        self.assertTrue(first.endswith("\n"))
        self.assertNotIn("\n\n\n", first)

        repeated = fixes.render_updated_content(first, "Instruction one.")
        self.assertEqual(repeated, first)

        replaced = fixes.render_updated_content(first, "Instruction two.")
        self.assertEqual(replaced.count(fixes.MANAGED_BEGIN), 1)
        self.assertEqual(replaced.count(fixes.SECTION_HEADING), 1)
        self.assertIn("Instruction two.", replaced)
        self.assertNotIn("Instruction one.", replaced)
        self.assertEqual(replaced[: len(ORIGINAL)], ORIGINAL)

    def test_render_preserves_crlf_style(self) -> None:
        original = "line one\r\nline two\r\n"
        updated = fixes.render_updated_content(original, "Reuse reads.")
        self.assertTrue(updated.startswith(original))
        self.assertIn(f"{fixes.MANAGED_BEGIN}\r\n", updated)
        # Every newline must stay CRLF: no bare LF may appear in the output.
        self.assertNotIn("\n", updated.replace("\r\n", ""))
        # The managed heading is separated from existing prose by a blank line.
        self.assertIn("line two\r\n\r\n" + fixes.SECTION_HEADING, updated)

    def test_render_empty_original(self) -> None:
        updated = fixes.render_updated_content("", "Reuse reads.")
        self.assertTrue(updated.startswith(fixes.SECTION_HEADING))
        self.assertEqual(updated.count("\n"), 4)
        self.assertTrue(updated.endswith("\n"))


class TestDuplicatePrevention(FixesTestBase):
    def test_duplicate_proposal_returns_existing(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        first = self.propose(finding)
        second = self.propose(finding)
        self.assertEqual(first.proposal_id, second.proposal_id)
        self.assertEqual(len(self.store.list_proposals(run_id=RUN_ID)), 1)

    def test_identical_instruction_already_present_raises_conflict(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        template = fixes.STRATEGY_TEMPLATES["search_efficiency"]
        self.write_agents(
            fixes.render_updated_content(ORIGINAL, template.instruction)
        )
        before = self.agents_path().read_bytes()
        with self.assertRaises(ProposalConflictError):
            self.propose(finding)
        self.assertEqual(self.agents_path().read_bytes(), before)
        self.assertEqual(self.store.list_proposals(run_id=RUN_ID), [])

    def test_identical_instruction_returns_existing_proposal(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self.propose(finding)
        self.write_agents(fixes.render_updated_content(ORIGINAL, proposal.instruction_text))
        # The original state changed, so the pending proposal is not silently
        # reused; the caller must re-create it against the current file.
        with self.assertRaises(ProposalConflictError):
            self.propose(finding)
        self.assertEqual(len(self.store.list_proposals(run_id=RUN_ID)), 1)


class TestApproval(FixesTestBase):
    def test_approve_requires_explicit_confirmation(self) -> None:
        finding = make_finding("TM002", "retry_discipline")
        self.seed([finding])
        proposal = self.propose(finding)
        with self.assertRaises(ApprovalRequiredError):
            fixes.approve_proposal(self.store, proposal.proposal_id, confirm=False)
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "pending")

    def test_approve_records_patch_bound_approval(self) -> None:
        finding = make_finding("TM002", "retry_discipline")
        self.seed([finding])
        proposal = self.propose(finding)
        record = fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)
        self.assertEqual(record.patch_sha256, proposal.patch_sha256)
        self.assertEqual(record.original_sha256, proposal.original_sha256)
        self.assertEqual(record.workspace, proposal.workspace)
        self.assertEqual(record.target_file, proposal.target_file)
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "approved")
        verified = fixes.verify_approval(self.store, proposal.proposal_id)
        self.assertEqual(verified.approval_id, record.approval_id)

    def test_apply_without_approval_raises(self) -> None:
        finding = make_finding("TM002", "retry_discipline")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self.propose(finding)
        with self.assertRaises(ApprovalRequiredError):
            fixes.apply_proposal(self.store, proposal.proposal_id)
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), ORIGINAL)

    def test_apply_with_mismatched_patch_hash_raises(self) -> None:
        finding = make_finding("TM002", "retry_discipline")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self.propose(finding)
        fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)

        tampered = self.store.get_proposal(proposal.proposal_id)
        tampered.patch = tampered.patch + "\n+# tampered"
        self.store.save_proposal(tampered)

        with self.assertRaises(ApprovalRequiredError):
            fixes.apply_proposal(self.store, proposal.proposal_id)
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), ORIGINAL)


class TestApplySafety(FixesTestBase):
    def test_stale_file_raises(self) -> None:
        finding = make_finding("TM001", "general_tool_efficiency")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self.propose(finding)
        fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)
        self.write_agents(ORIGINAL + "\nUnrelated later edit.\n")
        with self.assertRaises(StaleFileError):
            fixes.apply_proposal(self.store, proposal.proposal_id)

    def test_non_agents_target_is_rejected(self) -> None:
        finding = make_finding("TM001", "general_tool_efficiency")
        self.seed([finding])
        with self.assertRaises(SecurityError):
            self.propose(finding, target_file="CLAUDE.md")

    def test_traversal_target_is_rejected(self) -> None:
        finding = make_finding("TM001", "general_tool_efficiency")
        self.seed([finding])
        for target in ("../AGENTS.md", "sub/../../AGENTS.md", "/tmp/AGENTS.md", "~/AGENTS.md"):
            with self.subTest(target=target), self.assertRaises(SecurityError):
                self.propose(finding, target_file=target)

    def test_symlink_target_is_rejected(self) -> None:
        finding = make_finding("TM001", "general_tool_efficiency")
        self.seed([finding])
        outside = self.root / "outside.md"
        outside.write_text("secret\n", encoding="utf-8")
        (self.workspace / "AGENTS.md").symlink_to(outside)
        with self.assertRaises(SecurityError):
            self.propose(finding)
        self.assertEqual(outside.read_text(encoding="utf-8"), "secret\n")

    def test_apply_writes_expected_content_and_updates_status(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal, patch = self.approve_and_apply(finding)

        expected = fixes.render_updated_content(ORIGINAL, proposal.instruction_text)
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), expected)
        self.assertEqual(patch.status, "applied")
        self.assertEqual(patch.original_sha256, sha256_text(ORIGINAL))
        self.assertEqual(patch.applied_sha256, security.sha256_file(self.agents_path()))

        stored = self.store.get_proposal(proposal.proposal_id)
        self.assertEqual(stored.status, "applied")
        self.assertEqual(stored.patch_id, patch.patch_id)
        self.assertEqual(stored.applied_sha256, patch.applied_sha256)
        self.assertIsNotNone(stored.applied_at)

    def test_apply_creates_backup(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        _, patch = self.approve_and_apply(finding)
        backup = Path(patch.backup_path)
        self.assertTrue(backup.exists())
        self.assertTrue(security.is_within(self.store.backup_dir, backup))
        self.assertEqual(backup.read_text(encoding="utf-8"), ORIGINAL)

    def test_double_apply_conflicts(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal, _ = self.approve_and_apply(finding)
        with self.assertRaises(ProposalConflictError):
            fixes.apply_proposal(self.store, proposal.proposal_id)

    def test_apply_creates_file_when_missing(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        proposal, patch = self.approve_and_apply(finding)
        self.assertTrue(self.agents_path().exists())
        self.assertEqual(
            self.agents_path().read_text(encoding="utf-8"),
            fixes.render_updated_content("", proposal.instruction_text),
        )
        self.assertEqual(patch.original_sha256, security.EMPTY_SHA256)


class TestUndo(FixesTestBase):
    def test_successful_undo_restores_original_bytes(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal, patch = self.approve_and_apply(finding)

        undone = fixes.undo_patch(self.store, patch.patch_id)
        self.assertEqual(undone.status, "undone")
        self.assertIsNotNone(undone.undone_at)
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), ORIGINAL)
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "undone")

    def test_undo_after_unrelated_edit_conflicts(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        _, patch = self.approve_and_apply(finding)
        modified = self.agents_path().read_text(encoding="utf-8") + "\nSomeone else edited.\n"
        self.agents_path().write_text(modified, encoding="utf-8")
        with self.assertRaises(UndoConflictError):
            fixes.undo_patch(self.store, patch.patch_id)
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), modified)

    def test_undo_twice_conflicts(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        _, patch = self.approve_and_apply(finding)
        fixes.undo_patch(self.store, patch.patch_id)
        with self.assertRaises(ProposalConflictError):
            fixes.undo_patch(self.store, patch.patch_id)

    def test_undo_deletes_file_tracemend_created(self) -> None:
        finding = make_finding("TM001", "general_tool_efficiency")
        self.seed([finding])
        _, patch = self.approve_and_apply(finding)
        self.assertTrue(self.agents_path().exists())
        fixes.undo_patch(self.store, patch.patch_id)
        self.assertFalse(self.agents_path().exists())

    def test_diff_for_proposal_matches_stored_patch(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self.propose(finding)
        self.assertEqual(fixes.diff_for_proposal(self.store, proposal.proposal_id), proposal.patch)


class TestAiOrigin(FixesTestBase):
    def test_ai_origin_rejects_fenced_code(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        with self.assertRaises(SecurityError):
            self.propose(finding, origin="ai", instruction_text="```\nrm -rf /\n```")

    def test_ai_origin_rejects_oversized_text(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        with self.assertRaises(SecurityError):
            self.propose(finding, origin="ai", instruction_text="a" * 6000)

    def test_ai_origin_rejects_empty_text(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        with self.assertRaises(SecurityError):
            self.propose(finding, origin="ai", instruction_text="   \n  ")

    def test_ai_origin_rejects_unsupported_target(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        with self.assertRaises(SecurityError):
            self.propose(
                finding,
                origin="ai",
                instruction_text="Reuse search results that are still valid.",
                target_file="notes.md",
            )

    def test_ai_origin_creates_pending_proposal_and_never_applies(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self.propose(
            finding,
            origin="ai",
            instruction_text="Reuse a still-valid search result before searching again.",
        )
        self.assertEqual(proposal.origin, "ai")
        self.assertEqual(proposal.status, "pending")
        with self.assertRaises(ApprovalRequiredError):
            fixes.apply_proposal(self.store, proposal.proposal_id)
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), ORIGINAL)


class TestExistenceIntegrity(FixesTestBase):
    def test_undo_keeps_preexisting_empty_file(self) -> None:
        """Regression: an empty file that already existed must not be deleted."""
        finding = make_finding("TM001", "general_tool_efficiency")
        self.seed([finding])
        self.write_agents("")
        _, patch = self.approve_and_apply(finding)
        self.assertTrue(patch.original_existed)
        self.assertEqual(patch.original_sha256, security.EMPTY_SHA256)

        fixes.undo_patch(self.store, patch.patch_id)
        self.assertTrue(self.agents_path().exists())
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), "")

    def test_apply_rejects_missing_then_empty(self) -> None:
        finding = make_finding("TM001", "general_tool_efficiency")
        self.seed([finding])
        proposal = self.propose(finding)
        self.assertFalse(proposal.original_existed)
        fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)
        self.write_agents("")
        with self.assertRaises(StaleFileError):
            fixes.apply_proposal(self.store, proposal.proposal_id)

    def test_approval_binds_original_existence(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self.propose(finding)
        record = fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)
        record.original_existed = False
        self.store.save_approval(record)
        with self.assertRaises(ApprovalRequiredError):
            fixes.apply_proposal(self.store, proposal.proposal_id)
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), ORIGINAL)

    def test_legacy_patch_without_existence_restores_empty_bytes(self) -> None:
        finding = make_finding("TM001", "general_tool_efficiency")
        self.seed([finding])
        _, patch = self.approve_and_apply(finding)
        legacy = self.store.get_patch(patch.patch_id)
        legacy.original_existed = None
        self.store.save_patch(legacy)
        fixes.undo_patch(self.store, patch.patch_id)
        self.assertTrue(self.agents_path().exists())
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), "")


class TestRecovery(FixesTestBase):
    def _crash_finalize(self, finding):
        proposal = self.propose(finding)
        fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)
        with mock.patch.object(
            Store, "finish_operation", side_effect=RuntimeError("crash")
        ), self.assertRaises(RuntimeError):
            fixes.apply_proposal(self.store, proposal.proposal_id)
        return proposal

    def test_crash_after_write_is_recovered(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self._crash_finalize(finding)
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "approved")
        self.assertEqual(len(self.store.list_live_operations()), 1)

        fixes.recover_pending(self.store)

        loaded = self.store.get_proposal(proposal.proposal_id)
        self.assertEqual(loaded.status, "applied")
        patches = self.store.list_patches(proposal_id=proposal.proposal_id)
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0].status, "applied")
        self.assertEqual(self.store.list_live_operations(), [])

    def test_crash_before_write_aborts_intent(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self.propose(finding)
        fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)
        with mock.patch.object(
            security, "atomic_write_text", side_effect=OSError("disk full")
        ), self.assertRaises(OSError):
            fixes.apply_proposal(self.store, proposal.proposal_id)
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), ORIGINAL)
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "approved")

        patch = fixes.apply_proposal(self.store, proposal.proposal_id)
        self.assertEqual(patch.status, "applied")

    def test_unknown_third_state_is_not_overwritten(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self._crash_finalize(finding)
        self.write_agents(ORIGINAL + "\nSomeone else edited.\n")
        fixes.recover_pending(self.store)

        self.assertEqual(
            self.agents_path().read_text(encoding="utf-8"),
            ORIGINAL + "\nSomeone else edited.\n",
        )
        reviews = self.store.list_operations(status="needs_review")
        self.assertEqual(len(reviews), 1)
        with self.assertRaises(ProposalConflictError):
            fixes.apply_proposal(self.store, proposal.proposal_id)

    def test_crash_after_undo_restore_is_recovered(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal, patch = self.approve_and_apply(finding)
        with mock.patch.object(
            Store, "finish_operation", side_effect=RuntimeError("crash")
        ), self.assertRaises(RuntimeError):
            fixes.undo_patch(self.store, patch.patch_id)

        fixes.recover_pending(self.store)

        self.assertEqual(self.store.get_patch(patch.patch_id).status, "undone")
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "undone")
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), ORIGINAL)

    def test_crash_before_undo_restore_keeps_patch_applied(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        _, patch = self.approve_and_apply(finding)
        with mock.patch.object(
            security, "atomic_restore", side_effect=OSError("interrupted")
        ), self.assertRaises(OSError):
            fixes.undo_patch(self.store, patch.patch_id)

        fixes.recover_pending(self.store)
        self.assertEqual(self.store.get_patch(patch.patch_id).status, "applied")
        undone = fixes.undo_patch(self.store, patch.patch_id)
        self.assertEqual(undone.status, "undone")
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), ORIGINAL)

    def test_tampered_backup_is_rejected(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        _, patch = self.approve_and_apply(finding)
        Path(patch.backup_path).write_text("tampered\n", encoding="utf-8")
        with self.assertRaises(ProposalConflictError):
            fixes.undo_patch(self.store, patch.patch_id)
        self.assertNotEqual(
            self.agents_path().read_text(encoding="utf-8"), "tampered\n"
        )


class TestProposalIdentity(FixesTestBase):
    def test_undone_proposal_is_not_reused(self) -> None:
        finding = make_finding("TM001", "general_tool_efficiency")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal, patch = self.approve_and_apply(finding)
        fixes.undo_patch(self.store, patch.patch_id)
        fresh = self.propose(finding)
        self.assertNotEqual(fresh.proposal_id, proposal.proposal_id)
        self.assertEqual(fresh.status, "pending")

    def test_workspace_is_part_of_proposal_identity(self) -> None:
        finding = make_finding("TM001", "general_tool_efficiency")
        self.seed([finding])
        first = self.propose(finding)
        other = self.root / "workspace-2"
        other.mkdir()
        second = fixes.create_proposal(
            store=self.store,
            run_id=RUN_ID,
            finding_id=finding.id,
            workspace=other,
        )
        self.assertNotEqual(first.proposal_id, second.proposal_id)
        self.assertNotEqual(first.workspace, second.workspace)


class TestTerminalStates(FixesTestBase):
    def test_terminal_proposal_cannot_be_approved_again(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal, patch = self.approve_and_apply(finding)
        fixes.undo_patch(self.store, patch.patch_id)
        with self.assertRaises(ProposalConflictError):
            fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)


class TestLifecycleIntegrity(FixesTestBase):
    def test_crlf_bytes_and_mode_survive_apply_and_undo(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        original = "# AGENTS.md\r\n\r\nAlways run the tests.\r\n"
        self.write_agents(original)
        self.agents_path().chmod(0o640)
        mode = self.agents_path().stat().st_mode & 0o777

        _, patch = self.approve_and_apply(finding)
        applied = self.agents_path().read_bytes()
        self.assertIn(b"\r\n", applied)
        self.assertEqual(self.agents_path().stat().st_mode & 0o777, mode)

        fixes.undo_patch(self.store, patch.patch_id)
        self.assertEqual(self.agents_path().read_bytes(), original.encode("utf-8"))
        self.assertEqual(self.agents_path().stat().st_mode & 0o777, mode)

    def test_rollback_failure_leaves_recoverable_intent(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self.propose(finding)
        fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)
        with (
            mock.patch.object(Store, "_write_patch", side_effect=RuntimeError("db")),
            self.assertRaises(RuntimeError),
        ):
            fixes.apply_proposal(self.store, proposal.proposal_id)
        self.assertEqual(len(self.store.list_live_operations()), 1)
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "approved")

        fixes.recover_pending(self.store)
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "applied")
        self.assertEqual(len(self.store.list_live_operations()), 0)

    def test_two_stores_serialise_the_same_proposal(self) -> None:
        import concurrent.futures as futures

        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self.propose(finding)
        fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)
        second_store = Store(self.store.data_dir)

        def run(store):
            try:
                return fixes.apply_proposal(store, proposal.proposal_id).status
            except ProposalConflictError:
                return "conflict"

        with futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(run, [self.store, second_store])
            )
        self.assertIn("applied", results)
        self.assertEqual(len(self.store.list_patches(proposal_id=proposal.proposal_id)), 1)


class TestEncodingIntegrity(FixesTestBase):
    def test_invalid_utf8_refuses_proposal_without_touching_file(self) -> None:
        finding = make_finding("TM001", "general_tool_efficiency")
        self.seed([finding])
        malformed = b"# AGENTS.md\n\nbad byte: \xff\xfe\n"
        self.agents_path().write_bytes(malformed)
        with self.assertRaises(SecurityError):
            self.propose(finding)
        self.assertEqual(self.agents_path().read_bytes(), malformed)
        self.assertEqual(self.store.list_proposals(run_id=RUN_ID), [])

    def test_legacy_proposal_cannot_write_malformed_bytes(self) -> None:
        finding = make_finding("TM001", "general_tool_efficiency")
        self.seed([finding])
        malformed = b"# AGENTS.md\n\nbad byte: \xff\n"
        self.agents_path().write_bytes(malformed)
        proposal = FixProposal(
            proposal_id="prop_legacy_bad",
            run_id=RUN_ID,
            finding_id=finding.id,
            code=finding.code,
            strategy="general_tool_efficiency",
            title="legacy",
            rationale="legacy hypothesis",
            instruction_text="Avoid repeating identical tool calls.",
            workspace=str(self.workspace.resolve()),
            target_file="AGENTS.md",
            original_sha256=security.sha256_bytes(malformed),
            original_content="# AGENTS.md\n",
            proposed_sha256=sha256_text("proposed"),
            patch="--- a/AGENTS.md\n+++ b/AGENTS.md\n",
            status="approved",
            original_existed=True,
        )
        self.store.save_proposal(proposal)
        self.store.save_approval(
            ApprovalRecord(
                approval_id="appr_legacy_bad",
                proposal_id=proposal.proposal_id,
                patch_sha256=proposal.patch_sha256,
                workspace=proposal.workspace,
                target_file=proposal.target_file,
                original_sha256=proposal.original_sha256,
                original_existed=True,
            )
        )
        with self.assertRaises(SecurityError):
            fixes.apply_proposal(self.store, proposal.proposal_id)
        self.assertEqual(self.agents_path().read_bytes(), malformed)
        self.assertEqual(self.store.list_patches(proposal_id=proposal.proposal_id), [])
        self.assertEqual(list(self.store.backup_dir.iterdir()), [])


class TestDurabilityBarrier(FixesTestBase):
    def _interrupt_barrier(self):
        return mock.patch.object(
            fixes, "_fsync_directory", side_effect=SecurityError("fsync denied")
        )

    def test_apply_fsync_failure_leaves_recoverable_intent(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self.propose(finding)
        fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)
        with self._interrupt_barrier(), self.assertRaises(SecurityError):
            fixes.apply_proposal(self.store, proposal.proposal_id)

        expected = fixes.render_updated_content(ORIGINAL, proposal.instruction_text)
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), expected)
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "approved")
        self.assertEqual(len(self.store.list_live_operations()), 1)

        fixes.recover_pending(self.store)
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "applied")
        self.assertEqual(self.store.list_live_operations(), [])

    def test_undo_existing_fsync_failure_is_recoverable(self) -> None:
        finding = make_finding("TM004", "search_efficiency")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal, patch = self.approve_and_apply(finding)
        with self._interrupt_barrier(), self.assertRaises(SecurityError):
            fixes.undo_patch(self.store, patch.patch_id)

        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), ORIGINAL)
        self.assertEqual(self.store.get_patch(patch.patch_id).status, "applied")
        self.assertEqual(len(self.store.list_live_operations()), 1)

        fixes.recover_pending(self.store)
        self.assertEqual(self.store.get_patch(patch.patch_id).status, "undone")
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "undone")

    def test_undo_missing_original_fsync_failure_is_recoverable(self) -> None:
        finding = make_finding("TM001", "general_tool_efficiency")
        self.seed([finding])
        _, patch = self.approve_and_apply(finding)
        with self._interrupt_barrier(), self.assertRaises(SecurityError):
            fixes.undo_patch(self.store, patch.patch_id)

        self.assertFalse(self.agents_path().exists())
        self.assertEqual(self.store.get_patch(patch.patch_id).status, "applied")
        self.assertEqual(len(self.store.list_live_operations()), 1)

        fixes.recover_pending(self.store)
        self.assertEqual(self.store.get_patch(patch.patch_id).status, "undone")
        self.assertFalse(self.agents_path().exists())

    def test_transient_fsync_failure_only_commits_after_success(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self.propose(finding)
        fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)
        real_fsync_directory = fixes._fsync_directory
        with (
            mock.patch.object(
                fixes,
                "_fsync_directory",
                side_effect=[SecurityError("transient"), real_fsync_directory],
            ),
            self.assertRaises(SecurityError),
        ):
            fixes.apply_proposal(self.store, proposal.proposal_id)
        self.assertEqual(len(self.store.list_operations(status="intent")), 1)
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "approved")

        fixes.recover_pending(self.store)
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "applied")
        self.assertEqual(len(self.store.list_operations(status="intent")), 0)


class TestRecoveryIsolation(FixesTestBase):
    def test_orphan_intent_does_not_starve_valid_intent(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        orphan = FixOperation(
            operation_id="op_orphan",
            kind="apply",
            proposal_id="prop_missing",
            patch_id="patch_orphan",
            run_id=RUN_ID,
            workspace=str(self.workspace.resolve()),
            target_file="AGENTS.md",
            backup_path=str(self.store.backup_dir / "missing.bak"),
            original_sha256=security.EMPTY_SHA256,
            original_existed=False,
            expected_sha256=sha256_text("orphan"),
        )
        self.store.begin_operation(orphan)

        proposal = self.propose(finding)
        fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)
        with mock.patch.object(
            Store, "finish_operation", side_effect=RuntimeError("crash")
        ), self.assertRaises(RuntimeError):
            fixes.apply_proposal(self.store, proposal.proposal_id)

        fixes.recover_pending(self.store)

        orphan_after = self.store.get_operation("op_orphan")
        self.assertEqual(orphan_after.status, "needs_review")
        self.assertIn("missing", orphan_after.detail or "")
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "applied")
        self.assertEqual(len(self.store.list_live_operations()), 0)


class TestFinalizationReviewErrors(FixesTestBase):
    def test_apply_reports_manual_review_when_finalization_cannot_commit(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal = self.propose(finding)
        fixes.approve_proposal(self.store, proposal.proposal_id, confirm=True)
        with (
            mock.patch.object(
                security, "verify_backup",
                side_effect=[None, SecurityError("backup became unavailable")],
            ),
            self.assertRaisesRegex(ProposalConflictError, "needs manual review"),
        ):
            fixes.apply_proposal(self.store, proposal.proposal_id)
        reviews = self.store.list_operations(status="needs_review")
        self.assertEqual(len(reviews), 1)
        self.assertEqual(self.store.list_patches(proposal_id=proposal.proposal_id), [])
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "approved")
        self.assertEqual(
            self.agents_path().read_text(encoding="utf-8"),
            fixes.render_updated_content(ORIGINAL, proposal.instruction_text),
        )

    def test_undo_reports_manual_review_instead_of_returning_applied_patch(self) -> None:
        finding = make_finding("TM003", "file_read_reuse")
        self.seed([finding])
        self.write_agents(ORIGINAL)
        proposal, patch = self.approve_and_apply(finding)
        with (
            mock.patch.object(
                security, "verify_backup",
                side_effect=[None, SecurityError("backup became unavailable")],
            ),
            self.assertRaisesRegex(ProposalConflictError, "needs manual review"),
        ):
            fixes.undo_patch(self.store, patch.patch_id)
        self.assertEqual(len(self.store.list_operations(status="needs_review")), 1)
        self.assertEqual(self.store.get_patch(patch.patch_id).status, "applied")
        self.assertEqual(self.store.get_proposal(proposal.proposal_id).status, "applied")
        self.assertEqual(self.agents_path().read_text(encoding="utf-8"), ORIGINAL)


if __name__ == "__main__":
    unittest.main()
