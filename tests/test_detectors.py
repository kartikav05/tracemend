"""Tests for the deterministic detectors (TM001-TM005)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tracemend.detectors import (
    DETECTOR_CODES,
    detect_duplicate_tool_calls,
    detect_failed_retry_loops,
    detect_redundant_searches,
    detect_repeated_file_reads,
    detect_tool_hotspots,
    run_detectors,
)
from tracemend.models import TokenUsage, ToolCall, TraceRun, coerce_datetime

EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"
INEFFICIENT = EXAMPLES_DIR / "inefficient_run.json"


def make_call(call_id: str, tool: str, arguments: dict | None = None, **kwargs) -> ToolCall:
    """Build a ToolCall directly (the adapters module may not exist yet)."""
    payload: dict = {"id": call_id, "tool": tool, "arguments": arguments or {}}
    tokens = kwargs.pop("tokens", None)
    payload.update(kwargs)
    if tokens is not None:
        payload["token_usage"] = TokenUsage(**tokens)
    return ToolCall(**payload)


def make_run(events, run_id: str = "run_test", session_id: str = "session_test") -> TraceRun:
    return TraceRun(run_id=run_id, session_id=session_id, title="Test run", events=list(events))


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
                output_excerpt=raw.get("output"),
            )
        )
    return TraceRun(
        run_id="run_" + str(session.get("id") or Path(path).stem),
        session_id=str(session.get("id") or "session_unknown"),
        title=str(session.get("title") or "Fixture run"),
        model=session.get("model"),
        agent_name=session.get("agent"),
        events=events,
    )


def with_code(findings, code: str):
    return [finding for finding in findings if finding.code == code]


class DuplicateCallTests(unittest.TestCase):
    def test_identical_calls_are_flagged(self):
        run = make_run(
            [
                make_call("c1", "bash", {"command": "pytest -q"}),
                make_call("c2", "bash", {"command": "pytest -q"}),
            ]
        )
        findings = detect_duplicate_tool_calls(run)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.code, "TM001")
        self.assertEqual(finding.tool, "bash")
        self.assertEqual(finding.occurrences, 2)
        self.assertEqual(finding.evidence, ["c2"])
        self.assertEqual(finding.details["strategy"], "general_tool_efficiency")
        self.assertTrue(finding.fixable)

    def test_differing_arguments_are_not_flagged(self):
        run = make_run(
            [
                make_call("c1", "bash", {"command": "pytest -q"}),
                make_call("c2", "bash", {"command": "pytest -k payments"}),
            ]
        )
        self.assertEqual(detect_duplicate_tool_calls(run), [])

    def test_single_call_is_not_flagged(self):
        run = make_run([make_call("c1", "bash", {"command": "pytest -q"})])
        self.assertEqual(detect_duplicate_tool_calls(run), [])

    def test_reads_and_searches_are_left_to_tm003_and_tm004(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py"}),
                make_call("c2", "read", {"path": "src/a.py"}),
                make_call("c3", "grep", {"pattern": "a", "path": "src"}),
                make_call("c4", "grep", {"pattern": "a", "path": "src"}),
            ]
        )
        self.assertEqual(detect_duplicate_tool_calls(run), [])

    def test_failing_repeats_belong_to_tm002(self):
        run = make_run(
            [
                make_call("c1", "bash", {"command": "pytest -q"}, status="error"),
                make_call("c2", "bash", {"command": "pytest -q"}, status="error"),
            ]
        )
        self.assertEqual(detect_duplicate_tool_calls(run), [])

    def test_many_repeats_are_high_severity(self):
        run = make_run([make_call(f"c{i}", "bash", {"command": "ls"}) for i in range(6)])
        finding = detect_duplicate_tool_calls(run)[0]
        self.assertEqual(finding.occurrences, 6)
        self.assertEqual(len(finding.evidence), 5)
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.confidence, "high")

    def test_subagent_duplicate_lowers_confidence(self):
        same_agent = make_run(
            [
                make_call("p1", "bash", {"command": "ls"}),
                make_call("p2", "bash", {"command": "ls"}),
            ]
        )
        multi_agent = make_run(
            [
                make_call("p1", "bash", {"command": "ls"}),
                make_call("p2", "bash", {"command": "ls"}, agent_id="sub", parent_agent_id="main"),
            ]
        )
        baseline = detect_duplicate_tool_calls(same_agent)[0]
        lowered = detect_duplicate_tool_calls(multi_agent)[0]
        self.assertLess(
            ("low", "medium", "high").index(lowered.confidence),
            ("low", "medium", "high").index(baseline.confidence),
        )
        self.assertEqual(lowered.details["agents"], ["main", "sub"])
        self.assertTrue(lowered.details["mitigations"])

    def test_write_then_rerun_is_mitigated(self):
        run = make_run(
            [
                make_call("r1", "pytest", {"path": "src/a.py"}),
                make_call(
                    "e1",
                    "edit",
                    {"path": "src/a.py", "old": "a", "new": "b"},
                    status="success",
                    modified_files=["src/a.py"],
                ),
                make_call("r2", "pytest", {"path": "src/a.py"}),
                make_call("r3", "pytest", {"path": "src/a.py"}),
            ]
        )
        finding = detect_duplicate_tool_calls(run)[0]
        self.assertIn("mitigations", finding.details)
        self.assertEqual(finding.severity, "low")


class FailedRetryLoopTests(unittest.TestCase):
    def test_single_failure_is_not_flagged(self):
        run = make_run([make_call("c1", "bash", {"command": "pytest -q"}, status="error")])
        self.assertEqual(detect_failed_retry_loops(run), [])

    def test_two_identical_failures_are_flagged(self):
        run = make_run(
            [
                make_call("c1", "bash", {"command": "pytest -q"}, status="error", error="boom"),
                make_call("c2", "bash", {"command": "pytest -q"}, status="error", error="boom"),
            ]
        )
        finding = detect_failed_retry_loops(run)[0]
        self.assertEqual(finding.code, "TM002")
        self.assertEqual(finding.occurrences, 2)
        self.assertEqual(finding.evidence, ["c1", "c2"])
        self.assertEqual(finding.severity, "low")
        self.assertEqual(finding.confidence, "medium")
        self.assertEqual(finding.details["strategy"], "retry_discipline")
        self.assertTrue(finding.fixable)

    def test_three_identical_failures_are_high_severity(self):
        run = make_run(
            [
                make_call(f"c{i}", "bash", {"command": "pytest -q"}, status="error", error="boom")
                for i in range(3)
            ]
        )
        finding = detect_failed_retry_loops(run)[0]
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.confidence, "high")

    def test_transient_failures_are_acknowledged_in_the_description(self):
        run = make_run(
            [
                make_call("c1", "bash", {"command": "pytest -q"}, status="error"),
                make_call("c2", "bash", {"command": "pytest -q"}, status="error"),
            ]
        )
        finding = detect_failed_retry_loops(run)[0]
        self.assertIn("transient", finding.description)

    def test_differing_failing_calls_are_not_flagged(self):
        run = make_run(
            [
                make_call("c1", "bash", {"command": "pytest -q"}, status="error"),
                make_call("c2", "bash", {"command": "pytest -x"}, status="error"),
            ]
        )
        self.assertEqual(detect_failed_retry_loops(run), [])


class RepeatedReadTests(unittest.TestCase):
    def test_repeated_reads_are_flagged(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py"}),
                make_call("c2", "read", {"path": "src/a.py"}),
                make_call("c3", "read", {"path": "src/a.py"}),
            ]
        )
        finding = detect_repeated_file_reads(run)[0]
        self.assertEqual(finding.code, "TM003")
        self.assertEqual(finding.occurrences, 3)
        self.assertEqual(finding.evidence, ["c2", "c3"])
        self.assertEqual(finding.details["path"], "src/a.py")
        self.assertEqual(finding.details["strategy"], "file_read_reuse")

    def test_unknown_modification_data_lowers_confidence(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py"}),
                make_call("c2", "read", {"path": "src/a.py"}),
            ]
        )
        finding = detect_repeated_file_reads(run)[0]
        self.assertEqual(finding.confidence, "low")
        self.assertTrue(finding.details["limitations"])

    def test_reads_separated_by_an_observable_edit_are_not_redundant(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py"}),
                make_call(
                    "e1",
                    "edit",
                    {"path": "src/a.py", "old": "a", "new": "b"},
                    status="success",
                    modified_files=["src/a.py"],
                ),
                make_call("c2", "read", {"path": "src/a.py"}),
            ]
        )
        self.assertEqual(detect_repeated_file_reads(run), [])

    def test_window_after_an_edit_records_modification_evidence(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py"}),
                make_call("c2", "read", {"path": "src/a.py"}),
                make_call(
                    "e1",
                    "edit",
                    {"path": "src/a.py", "old": "a", "new": "b"},
                    status="success",
                    modified_files=["src/a.py"],
                ),
                make_call("c3", "read", {"path": "src/a.py"}),
            ]
        )
        findings = detect_repeated_file_reads(run)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence, ["c2"])
        self.assertEqual(findings[0].confidence, "medium")
        self.assertTrue(findings[0].details["modification_evidence"])

    def test_failed_reads_are_not_counted_as_redundant_reads(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py"}),
                make_call("c2", "read", {"path": "src/a.py"}, status="error", error="gone"),
            ]
        )
        self.assertEqual(detect_repeated_file_reads(run), [])

    def test_different_paths_are_not_flagged(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py"}),
                make_call("c2", "read", {"path": "src/b.py"}),
            ]
        )
        self.assertEqual(detect_repeated_file_reads(run), [])


class RedundantSearchTests(unittest.TestCase):
    def test_identical_searches_are_flagged(self):
        run = make_run(
            [
                make_call("c1", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="fp1"),
                make_call("c2", "grep", {"path": "src", "pattern": "payment"}, result_fingerprint="fp1"),
            ]
        )
        finding = detect_redundant_searches(run)[0]
        self.assertEqual(finding.code, "TM004")
        self.assertEqual(finding.occurrences, 2)
        self.assertEqual(finding.evidence, ["c2"])
        self.assertEqual(finding.confidence, "high")
        self.assertTrue(finding.details["identical_results"])
        self.assertEqual(finding.details["strategy"], "search_efficiency")

    def test_missing_result_fingerprints_lower_confidence(self):
        with_fp = make_run(
            [
                make_call("c1", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="fp1"),
                make_call("c2", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="fp1"),
            ]
        )
        without_fp = make_run(
            [
                make_call("c1", "grep", {"pattern": "payment", "path": "src"}),
                make_call("c2", "grep", {"pattern": "payment", "path": "src"}),
            ]
        )
        trusted = detect_redundant_searches(with_fp)[0]
        unknown = detect_redundant_searches(without_fp)[0]
        self.assertEqual(trusted.confidence, "high")
        self.assertEqual(unknown.confidence, "low")
        self.assertLess(
            ("low", "medium", "high").index(unknown.confidence),
            ("low", "medium", "high").index(trusted.confidence),
        )
        self.assertIsNone(unknown.details["identical_results"])

    def test_query_arguments_are_treated_as_searches(self):
        run = make_run(
            [
                make_call("c1", "mcp_search", {"query": "payment flow"}),
                make_call("c2", "mcp_search", {"query": "payment flow"}),
            ]
        )
        self.assertEqual(len(detect_redundant_searches(run)), 1)
        self.assertEqual(detect_duplicate_tool_calls(run), [])

    def test_overlapping_broad_search_with_identical_fingerprint_is_flagged(self):
        run = make_run(
            [
                make_call("c1", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="same"),
                make_call("c2", "grep", {"pattern": "payment_status", "path": "src"}, result_fingerprint="same"),
            ]
        )
        findings = detect_redundant_searches(run)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence, ["c1"])
        self.assertEqual(findings[0].details["narrow_pattern"], "payment_status")

    def test_overlapping_patterns_with_different_fingerprints_are_not_flagged(self):
        run = make_run(
            [
                make_call("c1", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="a"),
                make_call("c2", "grep", {"pattern": "payment_status", "path": "src"}, result_fingerprint="b"),
            ]
        )
        self.assertEqual(detect_redundant_searches(run), [])

    def test_different_scopes_are_not_identical(self):
        run = make_run(
            [
                make_call("c1", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="fp1"),
                make_call("c2", "grep", {"pattern": "payment", "path": "tests"}, result_fingerprint="fp1"),
            ]
        )
        self.assertEqual(detect_redundant_searches(run), [])

    def test_subagent_search_duplicate_lowers_confidence(self):
        run = make_run(
            [
                make_call("c1", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="fp1"),
                make_call(
                    "c2",
                    "grep",
                    {"pattern": "payment", "path": "src"},
                    result_fingerprint="fp1",
                    agent_id="sub",
                    parent_agent_id="main",
                ),
            ]
        )
        finding = detect_redundant_searches(run)[0]
        self.assertEqual(finding.confidence, "medium")
        self.assertEqual(finding.details["agents"], ["main", "sub"])


class ToolHotspotTests(unittest.TestCase):
    def test_busy_tool_is_reported_as_informational(self):
        run = make_run([make_call(f"c{i}", "bash", {"command": f"cmd {i}"}) for i in range(5)])
        finding = detect_tool_hotspots(run)[0]
        self.assertEqual(finding.code, "TM005")
        self.assertEqual(finding.severity, "info")
        self.assertEqual(finding.confidence, "medium")
        self.assertFalse(finding.fixable)
        self.assertEqual(finding.occurrences, 5)

    def test_quiet_tool_is_not_reported(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "a"}),
                make_call("c2", "read", {"path": "b"}),
            ]
        )
        self.assertEqual(detect_tool_hotspots(run), [])

    def test_duration_share_triggers_the_hotspot(self):
        run = make_run(
            [
                make_call("c1", "bash", {"command": "slow"}, duration_ms=900),
                make_call("c2", "read", {"path": "a"}, duration_ms=100),
            ]
        )
        findings = detect_tool_hotspots(run)
        self.assertEqual([finding.tool for finding in findings], ["bash"])
        self.assertGreaterEqual(findings[0].details["share_of_observed_duration"], 0.4)

    def test_missing_metadata_is_not_fabricated(self):
        run = make_run([make_call(f"c{i}", "bash", {"command": f"cmd {i}"}) for i in range(5)])
        finding = detect_tool_hotspots(run)[0]
        self.assertIsNone(finding.details["tokens"])
        self.assertIsNone(finding.details["cost"])
        self.assertIsNone(finding.details["duration_ms"])
        self.assertTrue(
            any("Token usage was not present" in note for note in finding.details["limitations"])
        )


class GeneralDetectorTests(unittest.TestCase):
    def test_empty_run_returns_nothing_from_every_detector(self):
        empty = TraceRun(run_id="run_empty")
        for detector in (
            detect_duplicate_tool_calls,
            detect_failed_retry_loops,
            detect_repeated_file_reads,
            detect_redundant_searches,
            detect_tool_hotspots,
        ):
            self.assertEqual(detector(empty), [])
        self.assertEqual(run_detectors(empty), [])

    def test_detector_codes_are_declared(self):
        self.assertEqual(DETECTOR_CODES, ("TM001", "TM002", "TM003", "TM004", "TM005"))

    def test_findings_are_sorted_and_ids_are_stable(self):
        first = load_fixture(INEFFICIENT)
        second = load_fixture(INEFFICIENT)
        first_findings = run_detectors(first)
        second_findings = run_detectors(second)
        self.assertTrue(first_findings)
        self.assertEqual(
            [finding.id for finding in first_findings],
            [finding.id for finding in second_findings],
        )
        keys = [finding.sort_key for finding in first_findings]
        self.assertEqual(keys, sorted(keys))

    def test_tm001_tm003_tm004_evidence_is_disjoint(self):
        run = make_run(
            [
                make_call("b1", "bash", {"command": "pytest -q"}),
                make_call("b2", "bash", {"command": "pytest -q"}),
                make_call("r1", "read", {"path": "src/a.py"}),
                make_call("r2", "read", {"path": "src/a.py"}),
                make_call("g1", "grep", {"pattern": "a", "path": "src"}, result_fingerprint="f"),
                make_call("g2", "grep", {"pattern": "a", "path": "src"}, result_fingerprint="f"),
            ]
        )
        findings = run_detectors(run)
        evidence = {
            code: {call_id for finding in with_code(findings, code) for call_id in finding.evidence}
            for code in ("TM001", "TM003", "TM004")
        }
        self.assertTrue(evidence["TM001"])
        self.assertTrue(evidence["TM003"])
        self.assertTrue(evidence["TM004"])
        self.assertFalse(evidence["TM001"] & evidence["TM003"])
        self.assertFalse(evidence["TM001"] & evidence["TM004"])
        self.assertFalse(evidence["TM003"] & evidence["TM004"])

    def test_fixture_produces_expected_finding_families(self):
        run = load_fixture(INEFFICIENT)
        findings = run_detectors(run)
        codes = {finding.code for finding in findings}
        self.assertTrue({"TM001", "TM004"} & codes, f"expected TM001 or TM004 in {sorted(codes)}")
        self.assertIn("TM002", codes)
        self.assertIn("TM003", codes)
        for finding in findings:
            self.assertEqual(finding.run_id, run.run_id)
            self.assertTrue(finding.title)
            self.assertTrue(finding.description)
            self.assertTrue(finding.details["strategy"])
            for call_id in finding.evidence:
                self.assertIn(call_id, run.event_by_id())

    def test_fixture_evidence_ids_exist_in_the_run(self):
        run = load_fixture(INEFFICIENT)
        known = run.event_by_id()
        for finding in run_detectors(run):
            self.assertLessEqual(len(finding.evidence), 8)
            self.assertTrue(set(finding.evidence) <= set(known))


if __name__ == "__main__":
    unittest.main()
