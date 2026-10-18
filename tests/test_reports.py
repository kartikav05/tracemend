"""Tests for the Rich/JSON presentation layer."""

from __future__ import annotations

import json
import unittest
from io import StringIO

from rich.console import Console

from tracemend import reports
from tracemend.errors import SecurityError
from tracemend.models import (
    AnalysisReport,
    ComparisonReport,
    Finding,
    FixProposal,
    MetricDelta,
    PatchRecord,
    RunMetrics,
    ToolCall,
    ToolStat,
    TraceRun,
)


def render(renderable) -> str:
    console = Console(file=StringIO(), width=100, no_color=True, legacy_windows=False)
    console.print(renderable)
    return console.file.getvalue()


def build_run() -> TraceRun:
    return TraceRun(
        run_id="run_test",
        session_id="s1",
        title="Fix payment API bug",
        source="generic",
        events=[
            ToolCall(id="call_001", tool="grep", arguments={"pattern": "payment_status"}, status="success"),
            ToolCall(id="call_002", tool="grep", arguments={"pattern": "payment_status"}, status="success"),
        ],
    )


def build_report() -> AnalysisReport:
    finding = Finding(
        id="TM001:grep:abc123",
        code="TM001",
        run_id="run_test",
        severity="high",
        confidence="high",
        title="Repeated identical search",
        description="Identical search executed 3 times.",
        tool="grep",
        occurrences=3,
        evidence=["call_001", "call_002"],
        recommendation="Reuse valid search results.",
        fixable=True,
        details={"strategy": "search_efficiency"},
    )
    metrics = RunMetrics(
        total_calls=26,
        failed_calls=3,
        duplicate_calls=11,
        distinct_tools=5,
        duration_ms=90_000,
        total_tokens=None,
        tool_stats={"grep": ToolStat(tool="grep", calls=8, failures=0, duplicate_calls=5, duration_ms=1400)},
    )
    return AnalysisReport(
        run_id="run_test",
        session_id="s1",
        title="Fix payment API bug",
        source="generic",
        metrics=metrics,
        findings=[finding],
        notes=["Behavioural observations only."],
    )


class TestFormatters(unittest.TestCase):
    def test_duration_variants(self) -> None:
        self.assertEqual(reports.format_duration(None), "N/A")
        self.assertEqual(reports.format_duration(250), "250ms")
        self.assertEqual(reports.format_duration(1500), "1.5s")
        self.assertEqual(reports.format_duration(90_000), "1m 30s")

    def test_number_and_percent_never_fabricate(self) -> None:
        self.assertEqual(reports.format_number(None), "N/A")
        self.assertEqual(reports.format_number(1234), "1,234")
        self.assertEqual(reports.format_percent(None), "N/A")
        self.assertEqual(reports.format_percent(-72.72), "-72.7%")

    def test_sanitize_redacts_secrets(self) -> None:
        cleaned = reports.sanitize("token sk-proj-EXAMPLENOTAREALKEY000000000000")
        self.assertNotIn("sk-proj-EXAMPLENOTAREALKEY", cleaned)
        self.assertIn("[REDACTED:", cleaned)


class TestAnalysisViews(unittest.TestCase):
    def test_summary_renders_metrics_and_na(self) -> None:
        output = render(reports.build_analysis_view(build_report(), run=build_run()))
        self.assertIn("EXECUTION SUMMARY", output)
        self.assertIn("26", output)
        self.assertIn("N/A", output)
        self.assertIn("TM001", output)
        self.assertIn("Reuse valid search results.", output)

    def test_findings_empty_state(self) -> None:
        report = build_report().model_copy(update={"findings": []})
        output = render(reports.build_findings_section(report))
        self.assertIn("No inefficiencies detected", output)

    def test_next_step_recommends_propose(self) -> None:
        output = render(reports.build_next_step(build_report()))
        self.assertIn("tracemend fix propose", output)
        self.assertIn("TM001", output)

    def test_next_step_hint_is_resolvable(self) -> None:
        """The printed `fix propose` token must be a finding id the store resolves."""
        report = build_report()
        output = render(reports.build_next_step(report))
        self.assertIn(f"tracemend fix propose {report.run_id} TM001", output)

    def test_next_step_uses_full_id_when_code_is_ambiguous(self) -> None:
        first = build_report().findings[0]
        second = first.model_copy(update={"id": "TM001:grep:def456"})
        report = build_report().model_copy(update={"findings": [first, second]})
        output = render(reports.build_next_step(report))
        self.assertIn("run_test TM001:grep:abc123", output)

    def test_next_step_skips_unfixable_findings(self) -> None:
        unfixable = Finding(
            id="TM005:bash:hot",
            code="TM005",
            run_id="run_test",
            severity="high",
            title="Tool hotspot: bash",
            description="bash dominated the run",
            tool="bash",
            fixable=False,
        )
        report = build_report().model_copy(
            update={"findings": [unfixable, *build_report().findings]}
        )
        output = render(reports.build_next_step(report))
        self.assertIn("TM001", output)
        self.assertNotIn("TM005", output)

    def test_next_step_handles_no_fixable_findings(self) -> None:
        unfixable = build_report().findings[0].model_copy(update={"fixable": False})
        report = build_report().model_copy(update={"findings": [unfixable]})
        output = render(reports.build_next_step(report))
        self.assertIn("No auto-fixable finding", output)
        self.assertIn("tracemend compare", output)

    def test_finding_panel_redacts_evidence(self) -> None:
        finding = build_report().findings[0]
        run = build_run()
        run.events[0].arguments = {"pattern": "sk-proj-EXAMPLENOTAREALKEY000000000000"}
        output = render(reports.build_finding_panel(finding, run))
        self.assertNotIn("sk-proj-EXAMPLENOTAREALKEY", output)
        self.assertIn("call_001", output)

    def test_metrics_table_lists_tools(self) -> None:
        output = render(reports.build_metrics_table(build_report().metrics))
        self.assertIn("grep", output)


class TestComparisonView(unittest.TestCase):
    def test_deltas_render_with_change(self) -> None:
        report = ComparisonReport(
            before_run_id="run_before",
            after_run_id="run_after",
            deltas=[
                MetricDelta(name="tool_calls", before=26, after=14, delta=-12, percent_change=-46.15),
                MetricDelta(name="failed_calls", before=3, after=0, delta=-3, percent_change=-100.0),
                MetricDelta(name="duplicate_calls", before=11, after=0, delta=-11, percent_change=-100.0),
                MetricDelta(name="duration_ms", before=90_000, after=68_000, delta=-22_000, percent_change=-24.4),
                MetricDelta(name="total_tokens", before=None, after=None, delta=None, percent_change=None, available=False),
            ],
            notes=["These metrics indicate behavioural changes, not necessarily improved task correctness."],
        )
        output = render(reports.build_comparison_view(report))
        self.assertIn("EXECUTION COMPARISON", output)
        self.assertIn("Duplicate calls", output)
        self.assertIn("-100.0%", output)
        self.assertIn("N/A", output)

    def test_delta_for_missing_metric(self) -> None:
        report = ComparisonReport(before_run_id="a", after_run_id="b")
        self.assertIsNone(report.delta_for("tool_calls"))


class TestOtherViews(unittest.TestCase):
    def test_proposal_view_shows_approval_hint(self) -> None:
        proposal = FixProposal(
            proposal_id="prop_1",
            run_id="run_test",
            finding_id="TM001:grep:abc123",
            code="TM001",
            strategy="search_efficiency",
            title="Search efficiency",
            rationale="Evidence: call_001, call_002.",
            instruction_text="Reuse valid search results.",
            workspace="/tmp/ws",
            target_file="AGENTS.md",
            original_sha256="a" * 64,
            original_content="# hi\n",
            proposed_sha256="b" * 64,
            patch="--- a/AGENTS.md\n+++ b/AGENTS.md\n",
            limitations=["Instruction changes do not guarantee compliance."],
        )
        output = render(reports.build_proposal_view(proposal))
        self.assertIn("FIX PROPOSAL", output)
        self.assertIn("NOT been applied", output)
        self.assertIn("tracemend fix approve prop_1", output)

    def test_diff_view_colours_and_metadata(self) -> None:
        proposal = FixProposal(
            proposal_id="prop_1",
            run_id="run_test",
            finding_id="TM001:grep:abc123",
            code="TM001",
            strategy="search_efficiency",
            title="Search efficiency",
            rationale="why",
            instruction_text="do it",
            workspace="/tmp/ws",
            original_sha256="a" * 64,
            original_content="x",
            proposed_sha256="b" * 64,
            patch="--- a/AGENTS.md\n+++ b/AGENTS.md\n@@ -1 +1,2 @@\n x\n+y\n",
        )
        output = render(reports.build_diff_view(proposal))
        self.assertIn("PROPOSED DIFF", output)
        self.assertIn("+y", output)

    def test_patch_view_and_error_view(self) -> None:
        record = PatchRecord(
            patch_id="patch_1",
            proposal_id="prop_1",
            run_id="run_test",
            workspace="/tmp/ws",
            target_file="AGENTS.md",
            strategy="search_efficiency",
            original_sha256="a" * 64,
            applied_sha256="b" * 64,
            backup_path="/tmp/backups/AGENTS.md.bak",
        )
        self.assertIn("APPLIED PATCH", render(reports.build_patch_view(record)))
        self.assertIn("SECURITY_ERROR", render(reports.build_error_view(SecurityError("nope", hint="hint"))))

    def test_import_view_warns(self) -> None:
        from tracemend.models import ImportSummary

        summary = ImportSummary(
            run_id="run_test",
            source="opencode",
            session_id="s1",
            title="Session",
            event_count=4,
            warnings=["sanitized export: tool results unavailable"],
            redactions_applied=2,
        )
        output = render(reports.build_import_view(summary))
        self.assertIn("IMPORTED TRACE", output)
        self.assertIn("WARNINGS", output)


class TestJsonPayloads(unittest.TestCase):
    def test_to_json_text_is_valid_json(self) -> None:
        payload = json.loads(reports.to_json_text({"b": 1, "a": [1, 2]}))
        self.assertEqual(payload, {"b": 1, "a": [1, 2]})

    def test_report_payload_roundtrip(self) -> None:
        payload = reports.report_to_payload(build_report())
        self.assertEqual(payload["run_id"], "run_test")
        self.assertEqual(payload["findings"][0]["code"], "TM001")
        self.assertEqual(payload["metrics"]["total_tokens"], None)

    def test_run_payload_omits_events_by_default(self) -> None:
        payload = reports.run_to_payload(build_run())
        self.assertNotIn("events", payload)
        self.assertEqual(payload["event_count"], 2)
        self.assertIn("events", reports.run_to_payload(build_run(), include_events=True))

    def test_proposal_payload_includes_patch_hash(self) -> None:
        proposal = FixProposal(
            proposal_id="prop_1",
            run_id="run_test",
            finding_id="TM001:grep:abc123",
            code="TM001",
            strategy="search_efficiency",
            title="t",
            rationale="r",
            instruction_text="i",
            workspace="/tmp/ws",
            original_sha256="a" * 64,
            original_content="x",
            proposed_sha256="b" * 64,
            patch="diff",
        )
        payload = reports.proposal_to_payload(proposal)
        self.assertEqual(payload["patch_sha256"], proposal.patch_sha256)

    def test_proposal_payload_hides_internal_content_and_redacts_text(self) -> None:
        """A workspace credential must not reach an outbound proposal payload."""
        secret = "sk-proj-WORKSPACESECRETNOTREAL0000000000"
        proposal = FixProposal(
            proposal_id="prop_1",
            run_id="run_1",
            finding_id="TM001:grep:abc123",
            code="TM001",
            strategy="search_efficiency",
            title="t",
            rationale="r",
            instruction_text="i",
            workspace="/tmp/ws",
            original_sha256="a" * 64,
            original_content=f"OPENAI_API_KEY={secret}\n",
            proposed_sha256="b" * 64,
            patch=f"""+OPENAI_API_KEY={secret}
""",
        )

        public = reports.proposal_to_payload(proposal)
        self.assertNotIn("original_content", public)
        self.assertNotIn(secret, json.dumps(public))
        self.assertIn("[REDACTED", json.dumps(public))
        # The hash still describes the exact patch that would be written.
        self.assertEqual(proposal.patch_sha256, public["patch_sha256"])

        internal = reports.proposal_to_payload(proposal, public=False)
        self.assertEqual(proposal.patch, internal["patch"])
        self.assertIn(secret, internal["patch"])

    def test_truncate_redacts_and_limits(self) -> None:
        text = reports.truncate("x" * 500 + " sk-proj-EXAMPLENOTAREALKEY000000000000", 20)
        self.assertLess(len(text), 60)
        self.assertNotIn("sk-proj-", text)


if __name__ == "__main__":
    unittest.main()
