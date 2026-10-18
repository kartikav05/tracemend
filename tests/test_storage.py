"""Tests for the SQLite persistence layer in :mod:`tracemend.storage`."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from tracemend import security
from tracemend.errors import (
    FindingNotFoundError,
    PatchNotFoundError,
    ProposalConflictError,
    ProposalNotFoundError,
    RunNotFoundError,
    TraceMendError,
)
from tracemend.models import (
    AnalysisReport,
    ApprovalRecord,
    Finding,
    FixOperation,
    FixProposal,
    PatchRecord,
    RunMetrics,
    ToolCall,
    TraceRun,
    sha256_text,
)
from tracemend.storage import Store, resolve_data_dir

RUN_ID = "run_storage"


def make_run(run_id: str = RUN_ID, *, events=None) -> TraceRun:
    return TraceRun(
        run_id=run_id,
        session_id="sess-1",
        title="Storage test run",
        events=list(events or []),
    )


def make_finding(finding_id: str, *, severity: str = "medium", code: str = "TM001") -> Finding:
    return Finding(
        id=finding_id,
        code=code,
        run_id=RUN_ID,
        severity=severity,
        confidence="high",
        title=f"{code} finding",
        description="detected",
        tool="bash",
        occurrences=2,
        evidence=["ev-1"],
        fixable=True,
        details={"strategy": "general_tool_efficiency"},
    )


def make_proposal(proposal_id: str = "prop_1", *, status: str = "pending") -> FixProposal:
    return FixProposal(
        proposal_id=proposal_id,
        run_id=RUN_ID,
        finding_id="TM004:bash:abcdef",
        code="TM004",
        strategy="search_efficiency",
        title="Reuse search results",
        rationale="hypothesis about agent instructions; evidence ev-1",
        instruction_text="Reuse still-valid search results.",
        workspace="/tmp/workspace",
        target_file="AGENTS.md",
        original_sha256=security.EMPTY_SHA256,
        original_content="",
        proposed_sha256=sha256_text("proposed"),
        patch="--- a/AGENTS.md\n+++ b/AGENTS.md\n@@\n+Reuse still-valid search results.",
        evidence=["ev-1"],
        limitations=["Instruction changes do not guarantee compliance."],
        status=status,
    )


class StorageTestBase(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = Store(self.root / "state")


class TestRuns(StorageTestBase):
    def test_run_round_trip(self) -> None:
        call = ToolCall(id="c1", tool="bash", arguments={"command": "ls"}, status="success")
        self.store.save_run(make_run(events=[call]))
        loaded = self.store.get_run(RUN_ID)
        self.assertEqual(loaded.run_id, RUN_ID)
        self.assertEqual(loaded.title, "Storage test run")
        self.assertEqual(loaded.event_count, 1)
        self.assertEqual(loaded.events[0].tool, "bash")
        self.assertTrue(self.store.has_run(RUN_ID))
        self.assertFalse(self.store.has_run("run_missing"))

    def test_unknown_run_raises(self) -> None:
        with self.assertRaises(RunNotFoundError):
            self.store.get_run("run_missing")

    def test_save_run_upserts(self) -> None:
        self.store.save_run(make_run())
        updated = make_run()
        updated.title = "Renamed"
        self.store.save_run(updated)
        self.assertEqual(self.store.get_run(RUN_ID).title, "Renamed")
        self.assertEqual(len(self.store.list_runs()), 1)


class TestReportsAndFindings(StorageTestBase):
    def test_report_and_findings_round_trip(self) -> None:
        self.store.save_run(make_run())
        report = AnalysisReport(
            run_id=RUN_ID,
            title="Storage test run",
            metrics=RunMetrics(total_calls=5, duplicate_calls=2),
            findings=[
                make_finding("TM001:bash:low", severity="low", code="TM001"),
                make_finding("TM004:bash:high", severity="high", code="TM004"),
            ],
        )
        self.store.save_report(report)

        loaded = self.store.get_report(RUN_ID)
        self.assertEqual(len(loaded.findings), 2)
        self.assertEqual(loaded.metrics.total_calls, 5)
        self.assertTrue(self.store.has_report(RUN_ID))

        high = self.store.get_findings(RUN_ID, severity="high")
        self.assertEqual([finding.severity for finding in high], ["high"])
        self.assertEqual(len(self.store.get_findings(RUN_ID)), 2)

    def test_finding_lookup_and_missing(self) -> None:
        self.store.save_run(make_run())
        self.store.save_report(
            AnalysisReport(run_id=RUN_ID, findings=[make_finding("TM001:bash:one")])
        )
        found = self.store.get_finding(RUN_ID, "TM001:bash:one")
        self.assertEqual(found.id, "TM001:bash:one")
        with self.assertRaises(FindingNotFoundError):
            self.store.get_finding(RUN_ID, "TM001:bash:missing")

    def test_finding_lookup_accepts_unambiguous_code(self) -> None:
        self.store.save_run(make_run())
        self.store.save_report(
            AnalysisReport(
                run_id=RUN_ID,
                findings=[make_finding("TM002:bash:abc123", code="TM002")],
            )
        )
        self.assertEqual(self.store.get_finding(RUN_ID, "TM002").id, "TM002:bash:abc123")
        self.assertEqual(self.store.get_finding(RUN_ID, "tm002").id, "TM002:bash:abc123")

    def test_finding_lookup_rejects_ambiguous_code(self) -> None:
        self.store.save_run(make_run())
        self.store.save_report(
            AnalysisReport(
                run_id=RUN_ID,
                findings=[
                    make_finding("TM003:read:one", code="TM003"),
                    make_finding("TM003:read:two", code="TM003"),
                ],
            )
        )
        with self.assertRaises(FindingNotFoundError) as raised:
            self.store.get_finding(RUN_ID, "TM003")
        self.assertIn("matches 2 findings", str(raised.exception))
        self.assertIn("TM003:read:one", raised.exception.hint or "")
        self.assertIn("TM003:read:two", raised.exception.hint or "")

    def test_save_report_replaces_previous_findings(self) -> None:
        self.store.save_run(make_run())
        self.store.save_report(
            AnalysisReport(run_id=RUN_ID, findings=[make_finding("TM001:bash:old")])
        )
        self.store.save_report(
            AnalysisReport(run_id=RUN_ID, findings=[make_finding("TM002:bash:new", code="TM002")])
        )
        ids = [finding.id for finding in self.store.get_findings(RUN_ID)]
        self.assertEqual(ids, ["TM002:bash:new"])

    def test_delete_run_clears_findings_and_report(self) -> None:
        self.store.save_run(make_run())
        self.store.save_report(
            AnalysisReport(run_id=RUN_ID, findings=[make_finding("TM001:bash:x")])
        )
        self.store.delete_run(RUN_ID)
        self.assertFalse(self.store.has_run(RUN_ID))
        self.assertFalse(self.store.has_report(RUN_ID))
        self.assertEqual(self.store.get_findings(RUN_ID), [])
        with self.assertRaises(RunNotFoundError):
            self.store.get_report(RUN_ID)


class TestProposals(StorageTestBase):
    def test_proposal_upsert_and_identity_lookup(self) -> None:
        saved = self.store.save_proposal(make_proposal())
        self.assertEqual(saved.proposal_id, "prop_1")
        loaded = self.store.get_proposal("prop_1")
        self.assertEqual(loaded.strategy, "search_efficiency")

        updated = self.store.get_proposal("prop_1")
        updated.status = "approved"
        self.store.save_proposal(updated)
        self.assertEqual(self.store.get_proposal("prop_1").status, "approved")

        found = self.store.find_proposal_for(
            RUN_ID, "TM004:bash:abcdef", "AGENTS.md", "search_efficiency"
        )
        self.assertIsNotNone(found)
        self.assertEqual(found.proposal_id, "prop_1")
        self.assertIsNone(
            self.store.find_proposal_for(
                RUN_ID, "TM004:bash:abcdef", "AGENTS.md", "retry_discipline"
            )
        )

    def test_missing_proposal_raises(self) -> None:
        with self.assertRaises(ProposalNotFoundError):
            self.store.get_proposal("prop_missing")

    def test_list_proposals_filters(self) -> None:
        self.store.save_proposal(make_proposal("prop_1"))
        self.store.save_proposal(make_proposal("prop_2", status="approved"))
        self.assertEqual(len(self.store.list_proposals(run_id=RUN_ID)), 2)
        approved = self.store.list_proposals(run_id=RUN_ID, status="approved")
        self.assertEqual([proposal.proposal_id for proposal in approved], ["prop_2"])


class TestApprovals(StorageTestBase):
    def test_approval_upsert_and_retrieval(self) -> None:
        proposal = make_proposal()
        first = ApprovalRecord(
            approval_id="appr_1",
            proposal_id=proposal.proposal_id,
            patch_sha256=proposal.patch_sha256,
            workspace=proposal.workspace,
            target_file=proposal.target_file,
            original_sha256=proposal.original_sha256,
            approved_by="local-cli",
        )
        self.store.save_approval(first)
        self.assertEqual(self.store.get_approval("prop_1").approval_id, "appr_1")

        second = first.model_copy(update={"approval_id": "appr_2", "approved_by": "reexamined"})
        self.store.save_approval(second)
        latest = self.store.get_approval("prop_1")
        self.assertEqual(latest.approval_id, "appr_2")
        self.assertEqual(latest.approved_by, "reexamined")

        self.assertIsNone(self.store.get_approval("prop_missing"))


class TestPatches(StorageTestBase):
    def test_patch_save_list_and_missing(self) -> None:
        record = PatchRecord(
            patch_id="patch_1",
            proposal_id="prop_1",
            run_id=RUN_ID,
            workspace="/tmp/workspace",
            target_file="AGENTS.md",
            strategy="search_efficiency",
            original_sha256=security.EMPTY_SHA256,
            applied_sha256=sha256_text("applied"),
            backup_path="/tmp/backups/AGENTS.md.bak",
        )
        self.store.save_patch(record)
        loaded = self.store.get_patch("patch_1")
        self.assertEqual(loaded.status, "applied")

        self.assertEqual(len(self.store.list_patches(run_id=RUN_ID)), 1)
        self.assertEqual(len(self.store.list_patches(proposal_id="prop_1")), 1)
        self.assertEqual(self.store.list_patches(proposal_id="prop_missing"), [])

        record.status = "undone"
        self.store.save_patch(record)
        self.assertEqual(self.store.get_patch("patch_1").status, "undone")

        with self.assertRaises(PatchNotFoundError):
            self.store.get_patch("patch_missing")


class TestDataDir(unittest.TestCase):
    def test_env_var_is_honoured(self) -> None:
        original = os.environ.get("TRACEMEND_DATA_DIR")
        try:
            os.environ["TRACEMEND_DATA_DIR"] = "/tmp/tracemend-env-test"
            self.assertEqual(
                resolve_data_dir(None), Path("/tmp/tracemend-env-test")
            )
            self.assertEqual(
                resolve_data_dir("/tmp/explicit"), Path("/tmp/explicit")
            )
        finally:
            if original is None:
                os.environ.pop("TRACEMEND_DATA_DIR", None)
            else:
                os.environ["TRACEMEND_DATA_DIR"] = original

    def test_store_uses_explicit_data_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp)
            self.assertEqual(store.data_dir, Path(tmp))
            self.assertTrue(store.db_path.exists())
            self.assertTrue(store.backup_dir.exists())


class TestSchemaMigration(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.data_dir = Path(temporary.name)

    def _write_v1_db(self) -> None:
        import json
        import sqlite3

        from tracemend.storage import DB_FILENAME

        path = self.data_dir / DB_FILENAME
        connection = sqlite3.connect(path)
        try:
            connection.executescript(
                """
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE proposals (
                    proposal_id TEXT PRIMARY KEY, run_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL, strategy TEXT NOT NULL,
                    target_file TEXT NOT NULL, workspace TEXT NOT NULL,
                    status TEXT NOT NULL, created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE approvals (
                    approval_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL UNIQUE,
                    approved_at TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE patches (
                    patch_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL,
                    run_id TEXT NOT NULL, status TEXT NOT NULL,
                    applied_at TEXT NOT NULL, payload TEXT NOT NULL
                );
                """
            )
            connection.execute(
                "INSERT INTO meta VALUES('schema_version', '1')"
            )
            proposal = make_proposal(status="applied")
            proposal_payload = json.loads(proposal.model_dump_json())
            proposal_payload.pop("original_existed", None)
            connection.execute(
                "INSERT INTO proposals VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    proposal.proposal_id,
                    proposal.run_id,
                    proposal.finding_id,
                    proposal.strategy,
                    proposal.target_file,
                    proposal.workspace,
                    "applied",
                    proposal.created_at.isoformat(),
                    json.dumps(proposal_payload),
                ),
            )
            approval = ApprovalRecord(
                approval_id="appr_v1",
                proposal_id=proposal.proposal_id,
                patch_sha256=proposal.patch_sha256,
                workspace=proposal.workspace,
                target_file=proposal.target_file,
                original_sha256=proposal.original_sha256,
            )
            approval_payload = json.loads(approval.model_dump_json())
            approval_payload.pop("original_existed", None)
            connection.execute(
                "INSERT INTO approvals VALUES(?, ?, ?, ?)",
                (
                    approval.approval_id,
                    approval.proposal_id,
                    approval.approved_at.isoformat(),
                    json.dumps(approval_payload),
                ),
            )
            patch = PatchRecord(
                patch_id="patch_v1",
                proposal_id=proposal.proposal_id,
                run_id=RUN_ID,
                workspace=proposal.workspace,
                target_file=proposal.target_file,
                strategy=proposal.strategy,
                original_sha256=security.EMPTY_SHA256,
                applied_sha256=sha256_text("applied"),
                backup_path="/tmp/backups/AGENTS.md.bak",
            )
            patch_payload = json.loads(patch.model_dump_json())
            patch_payload.pop("original_existed", None)
            connection.execute(
                "INSERT INTO patches VALUES(?, ?, ?, ?, ?, ?)",
                (
                    patch.patch_id,
                    patch.proposal_id,
                    patch.run_id,
                    patch.status,
                    patch.applied_at.isoformat(),
                    json.dumps(patch_payload),
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def test_v1_to_v2_is_additive_and_preserves_rows(self) -> None:
        self._write_v1_db()
        store = Store(self.data_dir)
        self.assertEqual(store.get_proposal("prop_1").status, "applied")
        self.assertIsNone(store.get_proposal("prop_1").original_existed)
        self.assertEqual(store.get_approval("prop_1").approval_id, "appr_v1")
        patch = store.get_patch("patch_v1")
        self.assertEqual(patch.status, "applied")
        self.assertIsNone(patch.original_existed)
        self.assertEqual(store.list_operations(), [])
        self.assertEqual(store.applied_patch_count("prop_1"), 1)

    def test_future_schema_version_is_rejected(self) -> None:
        import sqlite3

        from tracemend.storage import DB_FILENAME

        path = self.data_dir / DB_FILENAME
        connection = sqlite3.connect(path)
        try:
            connection.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute("INSERT INTO meta VALUES('schema_version', '99')")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(TraceMendError):
            Store(self.data_dir)

    def test_duplicate_legacy_patches_are_preserved_and_flagged(self) -> None:
        store = Store(self.data_dir)
        for index in (1, 2):
            store.save_patch(
                PatchRecord(
                    patch_id=f"patch_dup_{index}",
                    proposal_id="prop_1",
                    run_id=RUN_ID,
                    workspace="/tmp/workspace",
                    target_file="AGENTS.md",
                    strategy="search_efficiency",
                    original_sha256=security.EMPTY_SHA256,
                    applied_sha256=sha256_text(f"applied-{index}"),
                    backup_path=f"/tmp/backups/{index}.bak",
                )
            )
        self.assertEqual(store.applied_patch_count("prop_1"), 2)
        self.assertEqual(len(store.list_patches(proposal_id="prop_1")), 2)
        operation = FixOperation(
            operation_id="op_dup",
            kind="apply",
            proposal_id="prop_1",
            patch_id="patch_new",
            run_id=RUN_ID,
            workspace="/tmp/workspace",
            target_file="AGENTS.md",
            backup_path="/tmp/backups/new.bak",
            original_sha256=security.EMPTY_SHA256,
            original_existed=False,
            expected_sha256=sha256_text("new"),
        )
        with self.assertRaises(ProposalConflictError):
            store.begin_operation(operation)
        self.assertEqual(len(store.list_patches(proposal_id="prop_1")), 2)


class TestOperations(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = Store(self.root / "state")

    def _operation(self, *, kind: str = "apply", operation_id: str = "op_1") -> FixOperation:
        return FixOperation(
            operation_id=operation_id,
            kind=kind,
            proposal_id="prop_1",
            patch_id="patch_1",
            run_id=RUN_ID,
            workspace="/tmp/workspace",
            target_file="AGENTS.md",
            backup_path="/tmp/backups/AGENTS.md.bak",
            original_sha256=security.EMPTY_SHA256,
            original_existed=False,
            expected_sha256=sha256_text("applied"),
        )

    def test_one_live_intent_per_proposal(self) -> None:
        self.store.begin_operation(self._operation())
        with self.assertRaises(ProposalConflictError):
            self.store.begin_operation(self._operation(operation_id="op_2"))
        self.assertEqual(len(self.store.list_live_operations()), 1)

    def test_finish_operation_commits_journal_patch_and_proposal(self) -> None:
        self.store.save_proposal(make_proposal(status="approved"))
        operation = self.store.begin_operation(self._operation())
        proposal = self.store.get_proposal("prop_1")
        patch = PatchRecord(
            patch_id="patch_1",
            proposal_id="prop_1",
            run_id=RUN_ID,
            workspace="/tmp/workspace",
            target_file="AGENTS.md",
            strategy="search_efficiency",
            original_sha256=security.EMPTY_SHA256,
            applied_sha256=sha256_text("applied"),
            backup_path="/tmp/backups/AGENTS.md.bak",
            original_existed=False,
        )
        proposal.status = "applied"
        proposal.patch_id = "patch_1"
        self.store.finish_operation(
            operation, status="committed", patch=patch, proposal=proposal
        )
        self.assertEqual(self.store.get_operation("op_1").status, "committed")
        self.assertEqual(self.store.get_patch("patch_1").status, "applied")
        self.assertEqual(self.store.get_proposal("prop_1").status, "applied")
        self.assertEqual(self.store.list_live_operations(), [])

    def test_abort_only_touches_the_journal(self) -> None:
        self.store.save_proposal(make_proposal(status="approved"))
        operation = self.store.begin_operation(self._operation())
        self.store.finish_operation(operation, status="aborted", detail="no write")
        self.assertEqual(self.store.get_operation("op_1").status, "aborted")
        self.assertEqual(self.store.get_proposal("prop_1").status, "approved")
        self.assertEqual(self.store.list_patches(proposal_id="prop_1"), [])

    def test_find_proposal_for_respects_status_workspace_and_state(self) -> None:
        legacy = make_proposal(status="undone")
        legacy.original_existed = False
        self.store.save_proposal(legacy)
        self.assertIsNone(
            self.store.find_proposal_for(
                RUN_ID,
                "TM004:bash:abcdef",
                "AGENTS.md",
                "search_efficiency",
                workspace="/tmp/workspace",
                original_existed=False,
            )
        )
        active = make_proposal(status="pending")
        active.original_existed = False
        self.store.save_proposal(active)
        found = self.store.find_proposal_for(
            RUN_ID,
            "TM004:bash:abcdef",
            "AGENTS.md",
            "search_efficiency",
            workspace="/tmp/workspace",
            original_existed=False,
        )
        self.assertIsNotNone(found)
        self.assertIsNone(
            self.store.find_proposal_for(
                RUN_ID,
                "TM004:bash:abcdef",
                "AGENTS.md",
                "search_efficiency",
                workspace="/other/workspace",
                original_existed=False,
            )
        )


if __name__ == "__main__":
    unittest.main()
