"""Tests for metrics, run comparison and report assembly."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from io import StringIO
from pathlib import Path

from rich.console import Console

from tracemend import reports
from tracemend.analyzer import analyze_run, compare_runs, compute_metrics
from tracemend.models import MetricDelta, TokenUsage, ToolCall, TraceRun, coerce_datetime
from tracemend.storage import Store

EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"
INEFFICIENT = EXAMPLES_DIR / "inefficient_run.json"
OPTIMIZED = EXAMPLES_DIR / "optimized_run.json"

EXPECTED_DELTA_NAMES = (
    "tool_calls",
    "failed_calls",
    "duplicate_calls",
    "duration_ms",
    "total_tokens",
)


def make_call(call_id: str, tool: str, arguments: dict | None = None, **kwargs) -> ToolCall:
    payload: dict = {"id": call_id, "tool": tool, "arguments": arguments or {}}
    tokens = kwargs.pop("tokens", None)
    payload.update(kwargs)
    if tokens is not None:
        payload["token_usage"] = TokenUsage(**tokens)
    return ToolCall(**payload)


def make_run(events, run_id: str = "run_test") -> TraceRun:
    return TraceRun(run_id=run_id, session_id="session_test", title="Test run", events=list(events))


def load_fixture(path: Path) -> TraceRun:
    """Small local loader: builds ToolCall objects straight from the fixture JSON."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    session = data.get("session") or {}
    events = []
    for index, raw in enumerate(data.get("events") or []):
        events.append(
            make_call(
                raw["id"],
                raw["tool"],
                raw.get("arguments") or {},
                status=raw.get("status") or "unknown",
                agent_id=raw.get("agent_id", "main"),
                parent_agent_id=raw.get("parent_agent_id"),
                sequence=index,
                timestamp=coerce_datetime(raw.get("timestamp")),
                duration_ms=raw.get("duration_ms"),
                error=raw.get("error"),
                tokens=raw.get("tokens"),
                cost=raw.get("cost"),
                result_fingerprint=raw.get("result_fingerprint"),
                modified_files=list(raw.get("modified_files") or []),
            )
        )
    return TraceRun(
        run_id="run_" + str(session.get("id") or Path(path).stem),
        session_id=str(session.get("id") or "session_unknown"),
        title=str(session.get("title") or "Fixture run"),
        events=events,
    )


class ComputeMetricsTests(unittest.TestCase):
    def test_hand_built_run_counts(self):
        run = make_run(
            [
                make_call(
                    "b1",
                    "bash",
                    {"command": "pytest -q"},
                    duration_ms=100,
                    tokens={"input_tokens": 10, "output_tokens": 5},
                ),
                make_call("b2", "bash", {"command": "pytest -q"}, status="error", duration_ms=50),
                make_call("r1", "read", {"path": "src/a.py"}, duration_ms=20),
                make_call(
                    "g1",
                    "grep",
                    {"pattern": "a", "path": "src"},
                    duration_ms=30,
                    tokens={"input_tokens": 1, "output_tokens": 1},
                    parent_agent_id="main",
                ),
            ]
        )
        metrics = compute_metrics(run)
        self.assertEqual(metrics.total_calls, 4)
        self.assertEqual(metrics.failed_calls, 1)
        self.assertEqual(metrics.duplicate_calls, 1)
        self.assertEqual(metrics.distinct_tools, 3)
        self.assertEqual(metrics.duration_ms, 200)
        self.assertEqual(metrics.total_tokens, 17)
        self.assertIsNone(metrics.total_cost)
        self.assertEqual(metrics.subagent_calls, 1)

    def test_tool_stats_are_populated(self):
        run = make_run(
            [
                make_call("b1", "bash", {"command": "a"}, duration_ms=100, tokens={"input_tokens": 10}),
                make_call("b2", "bash", {"command": "a"}, status="error", duration_ms=50),
                make_call("r1", "read", {"path": "src/a.py"}, duration_ms=20),
            ]
        )
        stats = compute_metrics(run).tool_stats
        self.assertEqual(sorted(stats), ["bash", "read"])
        bash = stats["bash"]
        self.assertEqual((bash.tool, bash.calls, bash.failures), ("bash", 2, 1))
        self.assertEqual(bash.duplicate_calls, 1)
        self.assertEqual(bash.duration_ms, 150)
        self.assertEqual(bash.tokens, 10)
        self.assertEqual(stats["read"].calls, 1)
        self.assertIsNone(stats["read"].tokens)

    def test_unknown_metadata_stays_none(self):
        run = make_run(
            [
                make_call("c1", "bash", {"command": "a"}),
                make_call("c2", "read", {"path": "src/a.py"}),
            ]
        )
        metrics = compute_metrics(run)
        self.assertIsNone(metrics.duration_ms)
        self.assertIsNone(metrics.total_tokens)
        self.assertIsNone(metrics.total_cost)
        self.assertIsNone(metrics.tool_stats["bash"].duration_ms)
        self.assertIsNone(metrics.tool_stats["bash"].tokens)

    def test_empty_run_has_zeroed_counts_and_unknown_measurements(self):
        metrics = compute_metrics(TraceRun(run_id="run_empty"))
        self.assertEqual(metrics.total_calls, 0)
        self.assertEqual(metrics.duplicate_calls, 0)
        self.assertEqual(metrics.distinct_tools, 0)
        self.assertIsNone(metrics.duration_ms)
        self.assertIsNone(metrics.total_tokens)
        self.assertEqual(metrics.tool_stats, {})


class CompareRunsTests(unittest.TestCase):
    def test_delta_names_are_exact(self):
        report = compare_runs(make_run([]), make_run([]))
        self.assertEqual(tuple(delta.name for delta in report.deltas), EXPECTED_DELTA_NAMES)
        self.assertIsNotNone(report.delta_for("total_tokens"))

    def test_percent_change_maths(self):
        before = make_run([make_call(f"b{i}", "bash", {"command": f"cmd {i}"}) for i in range(10)])
        after = make_run([make_call(f"a{i}", "bash", {"command": f"cmd {i}"}) for i in range(4)])
        report = compare_runs(before, after)
        calls = report.delta_for("tool_calls")
        self.assertEqual((calls.before, calls.after), (10, 4))
        self.assertEqual(calls.delta, -6)
        self.assertEqual(calls.percent_change, -60.0)
        self.assertTrue(calls.available)

    def test_percent_change_is_none_when_before_is_zero(self):
        before = make_run([make_call("b1", "bash", {"command": "cmd"})])
        after = make_run(
            [
                make_call("a1", "bash", {"command": "cmd"}),
                make_call("a2", "bash", {"command": "cmd"}),
            ]
        )
        report = compare_runs(before, after)
        failures = report.delta_for("failed_calls")
        self.assertEqual((failures.before, failures.after, failures.delta), (0, 0, 0))
        self.assertIsNone(failures.percent_change)
        duplicates = report.delta_for("duplicate_calls")
        self.assertEqual((duplicates.before, duplicates.after), (0, 1))
        self.assertIsNone(duplicates.percent_change)

    def test_unavailable_metrics_are_marked_not_faked(self):
        before = make_run(
            [
                make_call(
                    "b1",
                    "bash",
                    {"command": "pytest -q"},
                    duration_ms=100,
                    tokens={"input_tokens": 5, "output_tokens": 5},
                )
            ]
        )
        after = make_run([make_call("a1", "bash", {"command": "pytest -q"})])
        report = compare_runs(before, after)
        duration = report.delta_for("duration_ms")
        self.assertFalse(duration.available)
        self.assertIsNone(duration.before)
        self.assertIsNone(duration.after)
        self.assertIsNone(duration.delta)
        self.assertIsNone(duration.percent_change)
        tokens = report.delta_for("total_tokens")
        self.assertFalse(tokens.available)
        self.assertIsNone(tokens.before)
        self.assertIsNone(tokens.delta)
        self.assertTrue(report.delta_for("tool_calls").available)
        self.assertTrue(any("Token usage was unavailable" in note for note in report.notes))

    def test_notes_describe_behavioural_change_not_correctness(self):
        report = compare_runs(make_run([]), make_run([]))
        self.assertTrue(any("not necessarily improved task correctness" in note for note in report.notes))
        self.assertEqual(report.before_run_id, "run_test")
        for delta in report.deltas:
            self.assertIsInstance(delta, MetricDelta)


def render(renderable) -> str:
    console = Console(file=StringIO(), width=120, no_color=True, legacy_windows=False)
    console.print(renderable)
    return console.file.getvalue()


class NextStepHintTests(unittest.TestCase):
    """The `NEXT STEP` command printed by `analyze` must actually work.

    Regression guard: the hint used to print a bare detector code (``TM002``)
    for a run where a code can match several findings, so copy-pasting the
    suggested command failed with FINDING_NOT_FOUND.
    """

    def _hint_token(self, report) -> tuple[str, str]:
        text = render(reports.build_next_step(report))
        match = re.search(r"tracemend fix propose (\S+) (\S+) --workspace", text)
        assert match is not None, text
        return match.group(1), match.group(2)

    def test_printed_hint_resolves_through_the_store(self) -> None:
        report = analyze_run(load_fixture(INEFFICIENT))
        self.assertTrue(report.findings)
        run_token, finding_token = self._hint_token(report)
        self.assertEqual(run_token, report.run_id)

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp)
            store.save_report(report)
            finding = store.get_finding(run_token, finding_token)
        self.assertTrue(finding.fixable)
        self.assertIn(finding.code, {"TM001", "TM002", "TM003", "TM004"})

    def test_hint_avoids_an_ambiguous_bare_code(self) -> None:
        report = analyze_run(load_fixture(INEFFICIENT))
        codes = [finding.code for finding in report.findings]
        self.assertGreater(codes.count("TM003"), 1, "fixture should repeat TM003")
        _, finding_token = self._hint_token(report)
        if ":" not in finding_token:
            self.assertEqual(codes.count(finding_token), 1)

    def test_hint_never_points_at_an_unfixable_finding(self) -> None:
        report = analyze_run(load_fixture(INEFFICIENT))
        unfixable_codes = {f.code for f in report.findings if not f.fixable}
        _, finding_token = self._hint_token(report)
        self.assertNotIn(finding_token.split(":")[0], unfixable_codes)


class AnalyzeRunTests(unittest.TestCase):
    def test_partial_measurements_are_reported_as_observations(self):
        run = make_run([
            make_call("a", "bash", {"command": "x"}, status="success",
                      duration_ms=0, tokens={"input_tokens": 0}, cost=0),
            make_call("b", "bash", {"command": "y"}),
        ])
        report = analyze_run(run)
        self.assertEqual(report.metrics.duration_ms, 0)
        self.assertEqual(report.metrics.total_tokens, 0)
        self.assertEqual(report.metrics.total_cost, 0)
        for label in ("Duration", "Token usage", "Cost"):
            self.assertTrue(any(f"{label} coverage: 1/2" in note for note in report.notes))
        self.assertTrue(any("Outcomes are unknown for 1/2" in note for note in report.notes))

    def test_complete_measurements_have_no_partial_coverage_warning(self):
        run = make_run([make_call("a", "bash", status="success", duration_ms=1,
                                  tokens={"input_tokens": 2}, cost=0)])
        report = analyze_run(run)
        self.assertFalse(any("coverage:" in note for note in report.notes))
        self.assertEqual(report.metrics.duration_ms, 1)
        self.assertEqual(report.metrics.total_tokens, 2)

    def test_absent_measurements_remain_unavailable_with_zero_coverage(self):
        report = analyze_run(make_run([make_call("a", "bash")]))
        self.assertIsNone(report.metrics.duration_ms)
        self.assertIsNone(report.metrics.total_tokens)
        self.assertIsNone(report.metrics.total_cost)
        for label in ("Duration", "Token usage", "Cost"):
            self.assertTrue(any(
                f"{label} coverage: 0/1" in note and "unavailable" in note
                for note in report.notes
            ))

    def test_legitimate_reverification_counts_are_not_claimed_as_waste(self):
        run = make_run([
            make_call("a", "read", {"path": "a.py"}, status="success"),
            make_call("edit", "edit", {"path": "a.py"}, status="success"),
            make_call("b", "read", {"path": "a.py"}, status="success"),
        ])
        report = analyze_run(run)
        self.assertEqual(report.metrics.duplicate_calls, 1)
        self.assertFalse(any(finding.code == "TM003" for finding in report.findings))
        self.assertTrue(any("not proven waste" in note for note in report.notes))

    def test_comparison_labels_partial_measurement_deltas(self):
        before = make_run([make_call("a", "bash", duration_ms=10),
                           make_call("b", "read")])
        after = make_run([make_call("c", "bash", duration_ms=1)])
        report = compare_runs(before, after)
        self.assertEqual(report.delta_for("duration_ms").delta, -9)
        self.assertTrue(any("Before: Duration coverage: 1/2" in note for note in report.notes))
        self.assertTrue(any("cannot establish savings" in note for note in report.notes))

    def test_analyze_run_returns_sorted_findings_and_notes(self):
        run = make_run(
            [
                make_call("b1", "bash", {"command": "pytest -q"}),
                make_call("b2", "bash", {"command": "pytest -q"}),
                make_call("r1", "read", {"path": "src/a.py"}),
                make_call("r2", "read", {"path": "src/a.py"}),
            ]
        )
        report = analyze_run(run)
        self.assertEqual(report.run_id, run.run_id)
        self.assertEqual(report.metrics.total_calls, 4)
        self.assertTrue(report.findings)
        self.assertEqual(
            [finding.sort_key for finding in report.findings],
            sorted(finding.sort_key for finding in report.findings),
        )
        self.assertTrue(report.notes)
        self.assertTrue(
            any("not task correctness" in note for note in report.notes),
            report.notes,
        )
        for finding in report.findings:
            self.assertEqual(finding.run_id, run.run_id)

    def test_analyze_run_is_deterministic(self):
        first = analyze_run(load_fixture(INEFFICIENT))
        second = analyze_run(load_fixture(INEFFICIENT))
        self.assertEqual(
            [finding.id for finding in first.findings],
            [finding.id for finding in second.findings],
        )
        self.assertEqual(first.metrics.model_dump(), second.metrics.model_dump())

    def test_analyze_run_on_an_empty_run(self):
        report = analyze_run(TraceRun(run_id="run_empty"))
        self.assertEqual(report.findings, [])
        self.assertTrue(report.notes)

    def test_optimized_run_has_fewer_duplicate_calls(self):
        inefficient = compute_metrics(load_fixture(INEFFICIENT))
        optimized = compute_metrics(load_fixture(OPTIMIZED))
        self.assertLessEqual(optimized.duplicate_calls, inefficient.duplicate_calls)
        self.assertLess(optimized.duplicate_calls, inefficient.duplicate_calls)

    def test_fixture_metrics_are_plausible(self):
        metrics = compute_metrics(load_fixture(INEFFICIENT))
        self.assertEqual(metrics.total_calls, 29)
        self.assertEqual(metrics.failed_calls, 4)
        self.assertEqual(metrics.subagent_calls, 1)
        self.assertIsNotNone(metrics.duration_ms)


if __name__ == "__main__":
    unittest.main()
