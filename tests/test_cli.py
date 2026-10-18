"""End-to-end tests for the TraceMend command line interface.

Every test drives the real ``tracemend`` click group through
``click.testing.CliRunner`` (the CLI is click-based, not Typer). All state is
confined to a per-test ``tempfile.TemporaryDirectory`` that is passed both as
the ``--data-dir`` option and through ``TRACEMEND_DATA_DIR``, so the real user
data directory is never touched.

``src/tracemend/storage.py`` resolves state with ``resolve_data_dir``: a value
given on the command line wins over ``TRACEMEND_DATA_DIR``, and the environment
variable only applies when no ``--data-dir`` is supplied. Because the CLI always
receives ``--data-dir`` here, the temporary directory is authoritative while the
environment variable is still set for any direct read performed by a test.

The remediation tests create their own workspace inside a temporary directory and
never point the fix commands at ``examples/``; the fixture ``examples/AGENTS.md``
is asserted byte-identical around those tests.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner, Result

from tracemend import __version__
from tracemend.cli import cli
from tracemend.storage import DB_FILENAME, Store

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures"
CLAUDE_CODE_FIXTURE = FIXTURES / "claude_code_session.jsonl"
CURSOR_CLI_FIXTURE = FIXTURES / "cursor_cli_session.jsonl"
CURSOR_HOOKS_FIXTURE = FIXTURES / "cursor_hooks_session.jsonl"
TRACE_FIXTURE = REPO_ROOT / "examples" / "inefficient_run.json"
OPTIMIZED_FIXTURE = REPO_ROOT / "examples" / "optimized_run.json"
AGENTS_FIXTURE = REPO_ROOT / "examples" / "AGENTS.md"

#: Exit code mapped by ``ApprovalRequiredError.exit_code`` in errors.py.
APPROVAL_REQUIRED_EXIT_CODE = 5
#: Exit code mapped by ``ProposalConflictError.exit_code`` in errors.py.
PROPOSAL_CONFLICT_EXIT_CODE = 5
#: Exit code mapped by ``RunNotFoundError`` / ``FindingNotFoundError``.
NOT_FOUND_EXIT_CODE = 3


class CliTestCase(unittest.TestCase):
    """Shared harness: an isolated data dir, workspace and CLI runner."""

    def setUp(self) -> None:
        self.runner = CliRunner()
        self.data_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.data_tmp.cleanup)
        self.workspace_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace_tmp.cleanup)
        self.data_dir = Path(self.data_tmp.name)
        self.workspace = Path(self.workspace_tmp.name)
        self.env = {"TRACEMEND_DATA_DIR": str(self.data_dir)}

    def invoke(self, *args: str, stdin: str | None = None) -> Result:
        """Run the real CLI against the per-test data dir."""
        return self.runner.invoke(
            cli,
            ["--data-dir", str(self.data_dir), *args],
            env=self.env,
            input=stdin,
        )

    def analyze(self, trace: Path = TRACE_FIXTURE) -> dict[str, object]:
        """Analyze a trace as JSON and return the parsed payload."""
        result = self.invoke("analyze", str(trace), "--format", "json")
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertIsInstance(payload, dict)
        return payload

    def analyzed_run_id(self) -> str:
        return str(self.analyze()["run_id"])

    def fixable_finding_id(self, run_id: str) -> str:
        """Return the first finding the fixture marks as fixable."""
        payload = json.loads(self.invoke("findings", run_id, "--format", "json").stdout)
        for finding in payload["findings"]:
            if finding.get("fixable"):
                return str(finding["id"])
        raise AssertionError("fixture has no fixable finding")

    def prepare_workspace(self) -> Path:
        """Copy the AGENTS.md fixture into the throwaway workspace."""
        target = self.workspace / "AGENTS.md"
        shutil.copyfile(AGENTS_FIXTURE, target)
        return target

    def propose(self, run_id: str, finding_id: str) -> str:
        result = self.invoke(
            "fix",
            "propose",
            run_id,
            finding_id,
            "--workspace",
            str(self.workspace),
            "--format",
            "json",
        )
        self.assertEqual(result.exit_code, 0, result.output)
        return str(json.loads(result.stdout)["proposal_id"])

    # ---------------------------------------------------------------- version
    def test_version_prints_program_and_version(self) -> None:
        result = self.invoke("--version")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(result.output.strip(), f"TraceMend {__version__}")

    def test_help_exits_zero_and_lists_commands(self) -> None:
        result = self.invoke("--help")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Usage:", result.output)
        for command in ("analyze", "findings", "explain", "compare", "fix"):
            self.assertIn(command, result.output)

    # ---------------------------------------------------------------- analyze
    def test_analyze_text_reports_summary_numbers(self) -> None:
        result = self.invoke("analyze", str(TRACE_FIXTURE))
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertRegex(result.output, r"Total tool calls\s+29")
        self.assertRegex(result.output, r"Failed calls\s+4")
        self.assertRegex(result.output, r"Duplicate calls\s+21")
        self.assertRegex(result.output, r"Potential inefficiencies\s+10")

    def test_analyze_json_is_the_only_stdout_contract(self) -> None:
        result = self.invoke("analyze", str(TRACE_FIXTURE), "--format", "json")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(result.stderr, "")
        # json.loads over the *entire* stdout fails if anything else is printed.
        payload = json.loads(result.stdout)
        self.assertTrue(result.stdout.strip().startswith("{"))
        self.assertTrue(result.stdout.strip().endswith("}"))
        self.assertIsInstance(payload, dict)
        self.assertEqual(len(payload["findings"]), 10)
        self.assertTrue(str(payload["run_id"]).startswith("run_"))

    def test_analyze_output_writes_report_file(self) -> None:
        report_path = self.workspace / "report.json"
        result = self.invoke("analyze", str(TRACE_FIXTURE), "--output", str(report_path))
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(report_path.is_file())
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(len(payload["findings"]), 10)

    def test_analyze_missing_trace_fails_cleanly(self) -> None:
        missing = self.workspace / "does_not_exist.json"
        result = self.invoke("analyze", str(missing))
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("does not exist", result.stderr)

    # --------------------------------------------------------- findings/explain
    def test_findings_and_explain_resolve_a_stored_run(self) -> None:
        run_id = self.analyzed_run_id()

        listed = self.invoke("findings", run_id)
        self.assertEqual(listed.exit_code, 0, listed.output)
        self.assertIn("TM002", listed.output)

        payload = json.loads(self.invoke("findings", run_id, "--format", "json").stdout)
        finding_id = str(payload["findings"][0]["id"])
        explained = self.invoke("explain", run_id, finding_id)
        self.assertEqual(explained.exit_code, 0, explained.output)
        self.assertIn(finding_id.split(":")[0], explained.output)

    def test_findings_unknown_run_errors_cleanly(self) -> None:
        result = self.invoke("findings", "run_does_not_exist")
        self.assertEqual(result.exit_code, NOT_FOUND_EXIT_CODE)
        self.assertIn("RUN_NOT_FOUND", result.output)
        self.assertNotIn("Traceback", result.output)

    def test_explain_unknown_finding_errors_cleanly(self) -> None:
        run_id = self.analyzed_run_id()
        result = self.invoke("explain", run_id, "TM999:bash:deadbeef")
        self.assertEqual(result.exit_code, NOT_FOUND_EXIT_CODE)
        self.assertIn("FINDING_NOT_FOUND", result.output)
        self.assertNotIn("Traceback", result.output)

    # ---------------------------------------------------------------- compare
    def test_compare_reports_real_deltas(self) -> None:
        result = self.invoke("compare", str(TRACE_FIXTURE), str(OPTIMIZED_FIXTURE))
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("-65.5%", result.output)
        self.assertIn("-75.0%", result.output)
        self.assertIn("-85.7%", result.output)

    # -------------------------------------------------------------------- fix
    def test_full_remediation_path(self) -> None:
        agents_before = AGENTS_FIXTURE.read_bytes()
        target = self.prepare_workspace()
        target_before = target.read_bytes()

        run_id = self.analyzed_run_id()
        finding_id = self.fixable_finding_id(run_id)
        proposal_id = self.propose(run_id, finding_id)

        preview = self.invoke("fix", "diff", proposal_id)
        self.assertEqual(preview.exit_code, 0, preview.output)
        self.assertIn("PROPOSED DIFF", preview.output)
        self.assertEqual(target.read_bytes(), target_before)

        approved = self.invoke("fix", "approve", proposal_id, "--yes")
        self.assertEqual(approved.exit_code, 0, approved.output)

        applied = self.invoke("fix", "apply", proposal_id, "--format", "json")
        self.assertEqual(applied.exit_code, 0, applied.output)
        patch_id = str(json.loads(applied.stdout)["patch_id"])
        self.assertNotEqual(target.read_bytes(), target_before)

        undone = self.invoke("fix", "undo", patch_id)
        self.assertEqual(undone.exit_code, 0, undone.output)
        self.assertEqual(target.read_bytes(), target_before)

        self.assertEqual(AGENTS_FIXTURE.read_bytes(), agents_before)

    def test_fix_approve_without_tty_is_refused(self) -> None:
        agents_before = AGENTS_FIXTURE.read_bytes()
        target = self.prepare_workspace()
        target_before = target.read_bytes()

        run_id = self.analyzed_run_id()
        finding_id = self.fixable_finding_id(run_id)
        proposal_id = self.propose(run_id, finding_id)

        # CliRunner provides a non-tty stdin, so the CLI must refuse approval.
        result = self.invoke("fix", "approve", proposal_id, stdin="")

        self.assertEqual(result.exit_code, APPROVAL_REQUIRED_EXIT_CODE)
        self.assertIn("APPROVAL_REQUIRED", result.output)
        self.assertIn("interactive terminal", result.output)
        self.assertNotIn("Traceback", result.output)

        store = Store(data_dir=self.data_dir)
        self.assertIsNone(store.get_approval(proposal_id))
        self.assertEqual(store.get_proposal(proposal_id).status, "pending")
        self.assertEqual(target.read_bytes(), target_before)
        self.assertEqual(AGENTS_FIXTURE.read_bytes(), agents_before)

    def test_fix_apply_before_approval_is_refused(self) -> None:
        agents_before = AGENTS_FIXTURE.read_bytes()
        target = self.prepare_workspace()
        target_before = target.read_bytes()

        run_id = self.analyzed_run_id()
        finding_id = self.fixable_finding_id(run_id)
        proposal_id = self.propose(run_id, finding_id)

        result = self.invoke("fix", "apply", proposal_id)

        self.assertEqual(result.exit_code, APPROVAL_REQUIRED_EXIT_CODE)
        self.assertIn("APPROVAL_REQUIRED", result.output)
        self.assertNotIn("Traceback", result.output)
        self.assertEqual(target.read_bytes(), target_before)
        self.assertEqual(AGENTS_FIXTURE.read_bytes(), agents_before)

    def test_fix_apply_twice_is_refused(self) -> None:
        agents_before = AGENTS_FIXTURE.read_bytes()
        self.prepare_workspace()

        run_id = self.analyzed_run_id()
        finding_id = self.fixable_finding_id(run_id)
        proposal_id = self.propose(run_id, finding_id)

        self.assertEqual(self.invoke("fix", "approve", proposal_id, "--yes").exit_code, 0)
        self.assertEqual(self.invoke("fix", "apply", proposal_id).exit_code, 0)

        second = self.invoke("fix", "apply", proposal_id)
        self.assertEqual(second.exit_code, PROPOSAL_CONFLICT_EXIT_CODE)
        self.assertIn("PROPOSAL_CONFLICT", second.output)
        self.assertNotIn("Traceback", second.output)
        self.assertEqual(AGENTS_FIXTURE.read_bytes(), agents_before)

    # -------------------------------------------------------------- isolation
    def test_data_dir_option_overrides_environment(self) -> None:
        env_dir = self.workspace / "env-data"
        cli_dir = self.workspace / "cli-data"
        result = self.runner.invoke(
            cli,
            ["--data-dir", str(cli_dir), "analyze", str(TRACE_FIXTURE)],
            env={"TRACEMEND_DATA_DIR": str(env_dir)},
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue((cli_dir / DB_FILENAME).is_file())
        self.assertFalse((env_dir / DB_FILENAME).exists())


class NativeFormatCliTests(CliTestCase):
    """Claude Code and Cursor imports through the real CLI."""

    def test_analyze_auto_detects_claude_code_jsonl(self) -> None:
        payload = self.analyze(CLAUDE_CODE_FIXTURE)
        self.assertEqual(payload["source"], "claude-code")
        self.assertEqual(payload["metrics"]["total_calls"], 4)

    def test_analyze_accepts_explicit_claude_code_format(self) -> None:
        result = self.invoke(
            "analyze", str(CLAUDE_CODE_FIXTURE), "--source-format", "claude-code",
            "--format", "json",
        )
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["source"], "claude-code")
        self.assertGreater(payload["metrics"]["total_calls"], 0)

    def test_analyze_accepts_cursor_hook_jsonl(self) -> None:
        payload = self.analyze(CURSOR_HOOKS_FIXTURE)
        self.assertEqual(payload["source"], "cursor")
        self.assertEqual(payload["metrics"]["total_calls"], 4)

    def test_compare_accepts_native_formats(self) -> None:
        result = self.invoke(
            "compare", str(CURSOR_CLI_FIXTURE), str(CURSOR_CLI_FIXTURE),
            "--source-format", "cursor", "--format", "json",
        )
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["before_run_id"], payload["after_run_id"])

    def test_malformed_jsonl_fails_with_line_number(self) -> None:
        broken = self.workspace / "broken.jsonl"
        valid = CLAUDE_CODE_FIXTURE.read_text(encoding="utf-8").splitlines()[1]
        broken.write_text(valid + "\n" + '{"type": "assistant", \n', encoding="utf-8")
        result = self.invoke("analyze", str(broken))
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("line 2", result.output)
        self.assertNotIn("Traceback", result.output)

    def test_help_lists_native_source_formats(self) -> None:
        result = self.invoke("analyze", "--help")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("claude-code", result.output)
        self.assertIn("cursor", result.output)

    def test_redaction_is_applied_before_persistence(self) -> None:
        payload = self.analyze(CURSOR_CLI_FIXTURE)
        run = Store(self.data_dir).get_run(str(payload["run_id"]))
        serialised = run.model_dump_json()
        self.assertNotIn("sk-proj-EXAMPLENOTAREALKEY000000000000", serialised)
        self.assertIn("openai_key", serialised)


if __name__ == "__main__":
    unittest.main()
