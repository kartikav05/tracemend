"""End-to-end tests for the TraceMend MCP surface.

These tests drive the real FastMCP server through the official in-memory client
(``mcp.shared.memory.create_connected_server_and_client_session``); nothing about
the transport, the tools or the store is stubbed.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from mcp.shared.memory import create_connected_server_and_client_session

from tracemend import fixes
from tracemend.mcp_server import SERVER_NAME, build_server
from tracemend.storage import Store

REPO_ROOT = Path(__file__).resolve().parents[1]
TRACE_FIXTURE = REPO_ROOT / "examples" / "inefficient_run.json"
OPTIMIZED_FIXTURE = REPO_ROOT / "examples" / "optimized_run.json"
AGENTS_TEMPLATE = REPO_ROOT / "examples" / "AGENTS.md"

#: Fake credential that lives in examples/inefficient_run.json; it must never
#: travel back out through an MCP response.
FAKE_SECRET = "sk-proj-EXAMPLENOTAREALKEY000000000000"

EXPECTED_TOOLS = {
    "load_trace",
    "analyze_trace",
    "get_findings",
    "inspect_tool_calls",
    "propose_fix",
    "preview_fix",
    "apply_approved_fix",
    "compare_runs",
    "undo_fix",
    "submit_ai_fix_proposal",
}

OPTIMIZE_SECTIONS = (
    "Role",
    "Available evidence",
    "Analysis procedure",
    "Constraints",
    "Expected structured output",
    "Safety rules",
)

OPTIMIZE_KEYS = (
    "finding_id",
    "root_cause_hypothesis",
    "recommendation",
    "target",
    "proposed_instruction",
    "expected_behavior",
    "verification",
    "limitations",
)


class MCPTestCase(unittest.IsolatedAsyncioTestCase):
    """Shared fixture: temp store, temp workspace with a real AGENTS.md."""

    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.store = Store(root / "state")
        self.workspace = root / "workspace"
        self.workspace.mkdir()
        self.target_file = self.workspace / "AGENTS.md"
        shutil.copyfile(AGENTS_TEMPLATE, self.target_file)
        self.original_target = self.target_file.read_bytes()
        self.server = build_server(store=self.store)
        self.session = None

    @contextlib.asynccontextmanager
    async def client(self) -> Any:
        """Connected in-memory client session, entered and exited in one task."""
        async with create_connected_server_and_client_session(self.server) as session:
            self.session = session
            try:
                yield session
            finally:
                self.session = None

    @staticmethod
    def payload(result: Any) -> dict[str, Any]:
        """Return the JSON payload of a CallToolResult."""
        structured = getattr(result, "structuredContent", None)
        if structured:
            return structured
        text = result.content[0].text
        return json.loads(text)

    async def call(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self.session is not None, "call() must run inside `async with self.client()`"
        return self.payload(await self.session.call_tool(name, arguments or {}))

    async def loaded_run(self) -> str:
        payload = await self.call("load_trace", {"path": str(TRACE_FIXTURE)})
        self.assertNotIn("error", payload, payload)
        return payload["run_id"]

    async def analyzed_run(self) -> tuple[str, list[dict[str, Any]]]:
        run_id = await self.loaded_run()
        analysis = await self.call("analyze_trace", {"run_id": run_id})
        self.assertNotIn("error", analysis, analysis)
        return run_id, analysis["findings"]

    def assert_blocked(self, payload: dict[str, Any], proposal_id: str) -> None:
        self.assertEqual("APPROVAL_REQUIRED", payload["error"])
        self.assertTrue(payload["approval_required"])
        self.assertEqual(f"tracemend fix approve {proposal_id}", payload["cli_command"])
        self.assertIn("approve", payload["hint"].lower())
        self.assertIn("tracemend fix approve", " ".join(payload["next_steps"]))

    # -------------------------------------------------------------- tools
    async def test_list_tools_exposes_expected_surface(self) -> None:
        async with self.client() as session:
            result = await session.list_tools()
            names = {tool.name for tool in result.tools}
            self.assertEqual(EXPECTED_TOOLS, names)
            self.assertEqual("TraceMend", self.server.name)

            by_name = {tool.name: tool for tool in result.tools}
            for name, tool in by_name.items():
                self.assertTrue(tool.description, f"{name} needs a model-facing description")
            self.assertIn("read-only", by_name["preview_fix"].description.lower())
            # apply_approved_fix exposes no approval/consent parameter at all.
            self.assertEqual(
                {"proposal_id"},
                set(by_name["apply_approved_fix"].inputSchema["properties"]),
            )

    async def test_load_trace_reports_import_summary(self) -> None:
        async with self.client():
            payload = await self.call("load_trace", {"path": str(TRACE_FIXTURE)})
            self.assertNotIn("error", payload, payload)
            self.assertTrue(payload["run_id"])
            self.assertEqual("generic", payload["source"])
            self.assertGreater(payload["event_count"], 0)
            self.assertIsInstance(payload["warnings"], list)
            self.assertIsInstance(payload["redactions"], int)
            self.assertTrue(payload["source_path"])
            self.assertTrue(self.store.has_run(payload["run_id"]))

    async def test_analyze_trace_returns_metrics_and_findings(self) -> None:
        async with self.client():
            run_id, findings = await self.analyzed_run()
            analysis = await self.call("analyze_trace", {"run_id": run_id})
            self.assertEqual(run_id, analysis["run_id"])
            self.assertIn("metrics", analysis)
            self.assertGreater(analysis["metrics"]["total_calls"], 0)
            self.assertTrue(findings, "the inefficient fixture must produce findings")
            for finding in findings:
                self.assertIn("id", finding)
                self.assertIn(finding["severity"], {"info", "low", "medium", "high"})
            self.assertTrue(self.store.has_report(run_id))

    async def test_get_findings_filters_by_severity(self) -> None:
        async with self.client():
            run_id, findings = await self.analyzed_run()
            severities = {finding["severity"] for finding in findings}

            for severity in sorted(severities):
                payload = await self.call("get_findings", {"run_id": run_id, "severity": severity})
                self.assertNotIn("error", payload, payload)
                self.assertEqual(
                    len([f for f in findings if f["severity"] == severity]), payload["count"]
                )
                self.assertTrue(all(f["severity"] == severity for f in payload["findings"]))

            limited = await self.call("get_findings", {"run_id": run_id, "limit": 1})
            self.assertEqual(1, limited["count"])

            invalid = await self.call("get_findings", {"run_id": run_id, "severity": "critical"})
            self.assertEqual("INVALID_SEVERITY", invalid["error"])
            self.assertIn("hint", invalid)

    async def test_inspect_tool_calls_is_bounded_and_redacted(self) -> None:
        async with self.client():
            run_id, _ = await self.analyzed_run()

            bounded = await self.call("inspect_tool_calls", {"run_id": run_id, "limit": 3})
            self.assertNotIn("error", bounded, bounded)
            self.assertLessEqual(len(bounded["calls"]), 3)
            self.assertGreaterEqual(bounded["total_events"], len(bounded["calls"]))
            for call in bounded["calls"]:
                self.assertIn("status", call)
                self.assertIn("tool", call)
                self.assertIn("duration_ms", call)
                self.assertIn("timestamp", call)
                self.assertIn("error", call)
            self.assertNotIn(FAKE_SECRET, json.dumps(bounded))

            # The oversized cap is clamped, never honoured.
            huge = await self.call("inspect_tool_calls", {"run_id": run_id, "limit": 10_000})
            self.assertLessEqual(len(huge["calls"]), 50)

            # Targeted retrieval redacts secrets inside arguments/outputs.
            config_call = next(
                call
                for call in bounded["calls"] + huge["calls"]
                if "config" in json.dumps(call.get("arguments") or {})
            )
            targeted = await self.call(
                "inspect_tool_calls", {"run_id": run_id, "call_ids": [config_call["call_id"]]}
            )
            self.assertEqual(1, len(targeted["calls"]))
            self.assertNotIn(FAKE_SECRET, json.dumps(targeted))
            self.assertIn("REDACTED", json.dumps(targeted["calls"][0]["output_excerpt"]))

            missing = await self.call(
                "inspect_tool_calls", {"run_id": run_id, "call_ids": ["call_does_not_exist"]}
            )
            self.assertEqual([], missing["calls"])
            self.assertEqual(["call_does_not_exist"], missing["missing_call_ids"])

        # ---------------------------------------------------------- resources

    async def test_report_resource_is_listed_and_readable(self) -> None:
        async with self.client() as session:
            run_id, _ = await self.analyzed_run()

            listed = await session.list_resources()
            uris = {str(resource.uri) for resource in listed.resources}
            self.assertIn(f"tracemend://runs/{run_id}/report", uris)
            self.assertIn(f"tracemend://runs/{run_id}/findings", uris)

            templates = await session.list_resource_templates()
            self.assertIn(
                "tracemend://runs/{run_id}/report",
                {template.uriTemplate for template in templates.resourceTemplates},
            )

            report = await session.read_resource(f"tracemend://runs/{run_id}/report")
            body = json.loads(report.contents[0].text)
            self.assertEqual(run_id, body["run_id"])
            self.assertIn("metrics", body)
            self.assertTrue(body["findings"])

            findings = await session.read_resource(f"tracemend://runs/{run_id}/findings")
            body = json.loads(findings.contents[0].text)
            self.assertEqual(run_id, body["run_id"])
            self.assertTrue(body["findings"])

        # ------------------------------------------------------------ prompts

    async def test_prompts_are_listed_and_structured(self) -> None:
        async with self.client() as session:
            run_id, findings = await self.analyzed_run()

            listed = await session.list_prompts()
            names = {prompt.name for prompt in listed.prompts}
            self.assertIn("optimize_agent", names)
            self.assertIn("explain_inefficiency", names)

            result = await session.get_prompt("optimize_agent", {"run_id": run_id})
            text = result.messages[0].content.text
            self.assertTrue(text.strip())
            for section in OPTIMIZE_SECTIONS:
                self.assertIn(section, text)
            for key in OPTIMIZE_KEYS:
                self.assertIn(key, text)
            self.assertIn(findings[0]["id"], text)
            self.assertIn("approval", text.lower())
            self.assertNotIn(FAKE_SECRET, text)

            focused = await session.get_prompt(
                "explain_inefficiency", {"run_id": run_id, "finding_id": findings[0]["id"]}
            )
            focused_text = focused.messages[0].content.text
            self.assertIn(findings[0]["id"], focused_text)
            self.assertIn("root_cause_hypothesis", focused_text)

        # ------------------------------------------------- proposal lifecycle

    async def _fixable_finding(self, findings: list[dict[str, Any]]) -> str:
        fixable = [finding for finding in findings if finding["fixable"]]
        self.assertTrue(fixable, "the fixture must contain at least one fixable finding")
        return fixable[0]["id"]

    async def test_propose_fix_is_pending_and_approval_gated(self) -> None:
        async with self.client():
            run_id, findings = await self.analyzed_run()
            finding_id = await self._fixable_finding(findings)

            proposal = await self.call(
                "propose_fix",
                {
                    "run_id": run_id,
                    "finding_id": finding_id,
                    "workspace": str(self.workspace),
                },
            )
            self.assertNotIn("error", proposal, proposal)
            self.assertTrue(proposal["proposal_id"])
            self.assertEqual("AGENTS.md", proposal["target_file"])
            self.assertTrue(proposal["approval_required"])
            self.assertTrue(proposal["proposed_instruction"])
            self.assertIn("approve", " ".join(proposal["next_steps"]).lower())

            stored = self.store.get_proposal(proposal["proposal_id"])
            self.assertEqual("pending", stored.status)

            preview = await self.call("preview_fix", {"proposal_id": proposal["proposal_id"]})
            self.assertNotIn("error", preview, preview)
            self.assertTrue(preview["diff"].strip())
            self.assertIn("AGENTS.md", preview["diff"])
            self.assertNotIn(FAKE_SECRET, json.dumps(preview))

            blocked = await self.call(
                "apply_approved_fix", {"proposal_id": proposal["proposal_id"]}
            )
            self.assert_blocked(blocked, proposal["proposal_id"])
            self.assertEqual(self.original_target, self.target_file.read_bytes())
            self.assertEqual("pending", self.store.get_proposal(proposal["proposal_id"]).status)

    async def test_apply_after_cli_approval_then_undo(self) -> None:
        async with self.client():
            run_id, findings = await self.analyzed_run()
            finding_id = await self._fixable_finding(findings)
            proposal = await self.call(
                "propose_fix",
                {"run_id": run_id, "finding_id": finding_id, "workspace": str(self.workspace)},
            )
            proposal_id = proposal["proposal_id"]

            # Exactly the local CLI path: a human approval stored in the shared store.
            fixes.approve_proposal(self.store, proposal_id, confirm=True)

            applied = await self.call("apply_approved_fix", {"proposal_id": proposal_id})
            self.assertNotIn("error", applied, applied)
            self.assertTrue(applied["patch_id"])
            self.assertEqual("applied", applied["status"])
            self.assertTrue(applied["applied_sha256"])
            self.assertTrue(Path(applied["backup_path"]).exists())
            self.assertNotEqual(self.original_target, self.target_file.read_bytes())
            self.assertIn(
                proposal["proposed_instruction"].strip().splitlines()[0][:20],
                self.target_file.read_text(),
            )

            undone = await self.call("undo_fix", {"patch_id": applied["patch_id"]})
            self.assertNotIn("error", undone, undone)
            self.assertEqual("undone", undone["status"])
            self.assertEqual(self.original_target, self.target_file.read_bytes())

    async def test_submit_ai_fix_proposal_is_pending_and_cannot_apply(self) -> None:
        async with self.client():
            run_id, findings = await self.analyzed_run()
            finding_id = await self._fixable_finding(findings)
            instruction = (
                "Reuse the most recent read result instead of re-reading the same file "
                "in the same turn."
            )

            submitted = await self.call(
                "submit_ai_fix_proposal",
                {
                    "run_id": run_id,
                    "finding_id": finding_id,
                    "workspace": str(self.workspace),
                    "proposed_instruction": instruction,
                },
            )
            self.assertNotIn("error", submitted, submitted)
            self.assertEqual("pending", submitted["status"])
            self.assertEqual("ai", submitted["origin"])
            self.assertFalse(submitted["can_apply"])
            self.assertTrue(submitted["human_approval_required"])
            self.assertIn("approve", submitted["message"].lower())

            stored = self.store.get_proposal(submitted["proposal_id"])
            self.assertEqual("pending", stored.status)
            self.assertEqual("ai", stored.origin)
            self.assertEqual(instruction, stored.instruction_text)

            blocked = await self.call(
                "apply_approved_fix", {"proposal_id": submitted["proposal_id"]}
            )
            self.assert_blocked(blocked, submitted["proposal_id"])
            self.assertEqual(self.original_target, self.target_file.read_bytes())

            # Untrusted text is validated: oversized instruction text is rejected.
            rejected = await self.call(
                "submit_ai_fix_proposal",
                {
                    "run_id": run_id,
                    "finding_id": finding_id,
                    "workspace": str(self.workspace),
                    "proposed_instruction": "x" * 5000,
                },
            )
            self.assertIn("error", rejected)
            self.assertIn("hint", rejected)

    async def test_compare_runs_reports_deltas(self) -> None:
        async with self.client():
            before = await self.loaded_run()
            after_summary = await self.call("load_trace", {"path": str(OPTIMIZED_FIXTURE)})
            self.assertNotIn("error", after_summary, after_summary)
            after = after_summary["run_id"]

            comparison = await self.call(
                "compare_runs", {"before_run_id": before, "after_run_id": after}
            )
            self.assertNotIn("error", comparison, comparison)
            self.assertEqual(before, comparison["before_run_id"])
            self.assertEqual(after, comparison["after_run_id"])
            self.assertTrue(comparison["deltas"])

    async def test_unknown_ids_return_structured_errors(self) -> None:
        async with self.client():
            run_id, _ = await self.analyzed_run()

            cases = [
                ("analyze_trace", {"run_id": "run_missing"}),
                ("get_findings", {"run_id": "run_missing"}),
                ("inspect_tool_calls", {"run_id": "run_missing"}),
                ("propose_fix", {"run_id": run_id, "finding_id": "finding_missing", "workspace": str(self.workspace)}),
                ("propose_fix", {"run_id": "run_missing", "finding_id": "finding_missing", "workspace": str(self.workspace)}),
                ("preview_fix", {"proposal_id": "proposal_missing"}),
                ("apply_approved_fix", {"proposal_id": "proposal_missing"}),
                ("undo_fix", {"patch_id": "patch_missing"}),
                ("compare_runs", {"before_run_id": "run_missing", "after_run_id": run_id}),
            ]
            for name, arguments in cases:
                with self.subTest(tool=name, arguments=arguments):
                    payload = await self.call(name, arguments)
                    self.assertIn("error", payload, payload)
                    self.assertTrue(payload["message"])
                    self.assertIsInstance(payload["error"], str)
                    self.assertNotIn("Traceback", json.dumps(payload))

            # A bad workspace/finding never reaches disk.
            self.assertEqual(self.original_target, self.target_file.read_bytes())

    async def test_read_only_tools_do_not_touch_the_workspace(self) -> None:
        async with self.client():
            run_id, _findings = await self.analyzed_run()
            listing = await self.call("get_findings", {"run_id": run_id, "limit": 5})
            self.assertNotIn("error", listing, listing)
            await self.call("inspect_tool_calls", {"run_id": run_id, "limit": 5})
            self.assertEqual(self.original_target, self.target_file.read_bytes())
            self.assertEqual([], list(self.workspace.iterdir())[1:])  # only AGENTS.md exists

    async def test_server_name_and_fresh_instances(self) -> None:
        async with self.client():
            self.assertEqual("TraceMend", SERVER_NAME)
            other = build_server(store=Store(Path(self._tmp.name) / "state2"))
            self.assertIsNot(other, self.server)
            self.assertEqual("TraceMend", other.name)

if __name__ == "__main__":
    unittest.main()
