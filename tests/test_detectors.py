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
from tracemend.models import TokenUsage, ToolCall, TraceRun, coerce_datetime, make_finding_id

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

    def test_edit_before_the_group_does_not_mitigate_repeats(self):
        run = make_run(
            [
                make_call(
                    "e1",
                    "edit",
                    {"path": "src/a.py", "old": "a", "new": "b"},
                    status="success",
                    modified_files=["src/a.py"],
                )
            ]
            + [make_call(f"r{i}", "pytest", {"path": "src/a.py"}) for i in range(4)]
        )
        finding = detect_duplicate_tool_calls(run)[0]
        self.assertNotIn("mitigations", finding.details)
        self.assertEqual(finding.severity, "medium")


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
        finding = findings[0]
        self.assertEqual(finding.evidence, ["c2"])
        # Unknown page coverage lowers confidence even though the file is known
        # to have been modified elsewhere in the run.
        self.assertTrue(finding.details["modification_evidence"])
        self.assertEqual(finding.confidence, "low")
        self.assertIn("may have repeated content", finding.description)
        self.assertTrue(
            any("exact coverage is unknown" in note for note in finding.details["limitations"])
        )

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

    def test_identical_read_ranges_are_flagged_with_a_stable_id(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py", "offset": 10, "limit": 20}),
                make_call("c2", "read", {"path": "src/a.py", "offset": 10, "limit": 20}),
            ]
        )
        findings = detect_repeated_file_reads(run)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence, ["c2"])
        self.assertEqual(findings[0].details["range_status"], "offset_limit")
        self.assertEqual(findings[0].details["read_range"], "offset=10;limit=20")
        self.assertEqual(
            [finding.id for finding in detect_repeated_file_reads(run)],
            [finding.id for finding in findings],
        )

    def test_range_spellings_within_one_scheme_compare_equal(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py", "range": "0-20"}),
                make_call("c2", "read", {"path": "src/a.py", "range": [0, 20]}),
                make_call(
                    "c3", "read", {"path": "src/a.py", "range": {"start": 0, "end": 20}}
                ),
            ]
        )
        findings = detect_repeated_file_reads(run)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].occurrences, 3)
        self.assertEqual(findings[0].evidence, ["c2", "c3"])

    def test_offset_limit_and_range_are_not_assumed_equivalent(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py", "offset": 0, "limit": 20}),
                make_call("c2", "read", {"path": "src/a.py", "range": "0-20"}),
            ]
        )
        self.assertEqual(detect_repeated_file_reads(run), [])

    def test_limit_only_and_offset_only_pages_stay_distinct(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py", "limit": 20}),
                make_call("c2", "read", {"path": "src/a.py", "limit": 50}),
                make_call("c3", "read", {"path": "src/a.py", "offset": 10}),
                make_call("c4", "read", {"path": "src/a.py", "offset": 40}),
            ]
        )
        self.assertEqual(detect_repeated_file_reads(run), [])

    def test_repeated_limit_only_pages_are_flagged(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py", "limit": 20}),
                make_call("c2", "read", {"path": "src/a.py", "limit": 20}),
            ]
        )
        finding = detect_repeated_file_reads(run)[0]
        self.assertEqual(finding.details["read_range"], "limit=20")
        self.assertEqual(finding.evidence, ["c2"])

    def test_disjoint_or_different_read_pages_are_legitimate(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py", "offset": 0, "limit": 20}),
                make_call("c2", "read", {"path": "src/a.py", "offset": 20, "limit": 20}),
                make_call("c3", "read", {"path": "src/a.py", "range": "40-60"}),
                make_call("c4", "read", {"path": "src/a.py", "offset": 0, "limit": 40}),
            ]
        )
        self.assertEqual(detect_repeated_file_reads(run), [])

    def test_missing_range_metadata_is_conservative(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py"}),
                make_call("c2", "read", {"path": "src/a.py"}),
            ]
        )
        finding = detect_repeated_file_reads(run)[0]
        self.assertEqual(finding.details["range_status"], "absent")
        self.assertIsNone(finding.details["read_range"])
        self.assertTrue(
            any("No offset, limit or range" in note for note in finding.details["limitations"])
        )

    def test_malformed_ranges_are_never_asserted_as_repeats(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py", "range": "nonsense"}),
                make_call("c2", "read", {"path": "src/a.py", "range": "nonsense"}),
                make_call("c3", "read", {"path": "src/a.py", "range": "10"}),
                make_call("c4", "read", {"path": "src/a.py", "range": [1]}),
                make_call("c5", "read", {"path": "src/a.py", "range": "-5-10"}),
            ]
        )
        self.assertEqual(detect_repeated_file_reads(run), [])

    def test_conflicting_pagination_fields_are_skipped(self):
        run = make_run(
            [
                make_call(
                    "c1",
                    "read",
                    {"path": "src/a.py", "offset": 0, "range": "0-20"},
                ),
                make_call(
                    "c2",
                    "read",
                    {"path": "src/a.py", "limit": 20, "range": "0-20"},
                ),
                make_call("c3", "read", {"path": "src/a.py", "offset": 10, "limit": 20}),
                make_call("c4", "read", {"path": "src/a.py", "offset": 10, "limit": 20}),
            ]
        )
        findings = detect_repeated_file_reads(run)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence, ["c4"])

    def test_failed_write_does_not_assert_a_file_change(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py"}),
                make_call(
                    "e1",
                    "edit",
                    {"path": "src/a.py", "old": "a", "new": "b"},
                    status="error",
                    modified_files=["src/a.py"],
                ),
                make_call("c2", "read", {"path": "src/a.py"}),
            ]
        )
        finding = detect_repeated_file_reads(run)[0]
        self.assertEqual(finding.evidence, ["c2"])
        self.assertFalse(finding.details["modification_evidence"])
        self.assertFalse(finding.details["run_has_modification_data"])

    def test_unknown_write_conservatively_splits_the_read_window(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py"}),
                make_call("u1", "edit", {"path": "src/a.py"}),
                make_call("c2", "read", {"path": "src/a.py"}),
                make_call("c3", "read", {"path": "src/a.py"}),
            ]
        )
        findings = detect_repeated_file_reads(run)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence, ["c3"])
        self.assertTrue(
            any(
                "unknown outcomes" in note
                for note in findings[0].details["limitations"]
            )
        )

    def test_unpaginated_group_keeps_the_historical_id(self):
        run = make_run(
            [
                make_call("c1", "read", {"path": "src/a.py"}),
                make_call("c2", "read", {"path": "src/a.py"}),
                make_call("c3", "read", {"path": "src/a.py"}),
            ]
        )
        finding = detect_repeated_file_reads(run)[0]
        self.assertEqual(
            finding.id,
            make_finding_id("TM003", "read", "src/a.py|c1|c3|3"),
        )

    def test_multiagent_reads_lower_confidence(self):
        def build(second_agent):
            return make_run(
                [
                    make_call("c1", "read", {"path": "src/a.py", "offset": 0, "limit": 20}),
                    make_call(
                        "c2",
                        "read",
                        {"path": "src/a.py", "offset": 0, "limit": 20},
                        agent_id=second_agent,
                        parent_agent_id="main" if second_agent != "main" else None,
                    ),
                    make_call(
                        "e1",
                        "edit",
                        {"path": "src/a.py", "old": "a", "new": "b"},
                        status="success",
                        modified_files=["src/a.py"],
                    ),
                ]
            )

        baseline = detect_repeated_file_reads(build("main"))[0]
        multi_agent = detect_repeated_file_reads(build("sub"))[0]
        self.assertEqual(baseline.confidence, "medium")
        self.assertEqual(multi_agent.confidence, "low")
        self.assertEqual(multi_agent.details["agents"], ["main", "sub"])
        self.assertTrue(multi_agent.details["mitigations"])


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
                make_call("c1", "grep", {"pattern": "payment_status", "path": "src"}, result_fingerprint="same"),
                make_call("c2", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="same"),
            ]
        )
        findings = detect_redundant_searches(run)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence, ["c2"])
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

    def test_broad_coverage_rejects_a_relevant_write_between_the_pair(self):
        for status in ("success", "unknown"):
            with self.subTest(status=status):
                run = make_run(
                    [
                        make_call(
                            "c1",
                            "grep",
                            {"pattern": "payment_status", "path": "src"},
                            result_fingerprint="same",
                        ),
                        make_call(
                            "e1",
                            "edit",
                            {"path": "src/payments.py"},
                            status=status,
                            modified_files=["src/payments.py"],
                        ),
                        make_call(
                            "c2",
                            "grep",
                            {"pattern": "payment", "path": "src"},
                            result_fingerprint="same",
                        ),
                    ]
                )
                self.assertEqual(detect_redundant_searches(run), [])

    def test_repository_root_scope_covers_relative_paths(self):
        run = make_run(
            [
                make_call(
                    "s1", "grep", {"pattern": "payment", "path": "."}, result_fingerprint="f"
                ),
                make_call(
                    "e1",
                    "edit",
                    {"path": "src/payments.py"},
                    status="success",
                    modified_files=["src/payments.py"],
                ),
                make_call(
                    "s2", "grep", {"pattern": "payment", "path": "."}, result_fingerprint="f"
                ),
            ]
        )
        self.assertEqual(detect_redundant_searches(run), [])

    def test_cross_agent_broad_coverage_lowers_confidence(self):
        run = make_run(
            [
                make_call(
                    "c1", "grep", {"pattern": "payment_status", "path": "src"}, result_fingerprint="same"
                ),
                make_call(
                    "c2",
                    "grep",
                    {"pattern": "payment", "path": "src"},
                    result_fingerprint="same",
                    agent_id="sub",
                    parent_agent_id="main",
                ),
            ]
        )
        finding = detect_redundant_searches(run)[0]
        self.assertEqual(finding.confidence, "medium")
        self.assertEqual(finding.details["agents"], ["main", "sub"])
        self.assertTrue(finding.details["mitigations"])

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

    def test_later_narrow_search_does_not_justify_a_prior_broad_search(self):
        run = make_run(
            [
                make_call("c1", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="same"),
                make_call("c2", "grep", {"pattern": "payment_status", "path": "src"}, result_fingerprint="same"),
            ]
        )
        self.assertEqual(detect_redundant_searches(run), [])

    def test_repeated_failed_searches_are_left_to_tm002(self):
        run = make_run(
            [
                make_call("c1", "grep", {"pattern": "payment", "path": "src"}, status="error"),
                make_call("c2", "grep", {"pattern": "payment", "path": "src"}, status="error"),
            ]
        )
        self.assertEqual(detect_redundant_searches(run), [])
        retries = detect_failed_retry_loops(run)
        self.assertEqual(len(retries), 1)
        self.assertEqual(retries[0].evidence, ["c1", "c2"])

    def test_mixed_success_and_error_searches_do_not_double_report(self):
        run = make_run(
            [
                make_call("s1", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="f"),
                make_call("s2", "grep", {"pattern": "payment", "path": "src"}, status="error"),
                make_call("s3", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="f"),
                make_call("s4", "grep", {"pattern": "payment", "path": "src"}, status="error"),
            ]
        )
        searches = detect_redundant_searches(run)
        retries = detect_failed_retry_loops(run)
        self.assertEqual(len(searches), 1)
        self.assertEqual(searches[0].details["matched_ids"], ["s1", "s3"])
        self.assertEqual(searches[0].evidence, ["s3"])
        self.assertEqual(len(retries), 1)
        self.assertEqual(retries[0].evidence, ["s2", "s4"])
        self.assertFalse(set(searches[0].evidence) & set(retries[0].evidence))

    def test_successful_relevant_write_allows_researching(self):
        run = make_run(
            [
                make_call("s1", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="f"),
                make_call(
                    "e1",
                    "edit",
                    {"path": "src/payments.py", "old": "a", "new": "b"},
                    status="success",
                    modified_files=["src/payments.py"],
                ),
                make_call("s2", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="f"),
                make_call("s3", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="f"),
            ]
        )
        findings = detect_redundant_searches(run)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence, ["s3"])
        self.assertEqual(findings[0].occurrences, 2)

    def test_write_outside_the_search_scope_does_not_invalidate(self):
        run = make_run(
            [
                make_call("s1", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="f"),
                make_call(
                    "e1",
                    "edit",
                    {"path": "tests/test_payments.py"},
                    status="success",
                    modified_files=["tests/test_payments.py"],
                ),
                make_call("s2", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="f"),
            ]
        )
        self.assertEqual(len(detect_redundant_searches(run)), 1)

    def test_failed_write_does_not_invalidate_a_search(self):
        run = make_run(
            [
                make_call("s1", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="f"),
                make_call(
                    "e1",
                    "edit",
                    {"path": "src/payments.py"},
                    status="error",
                    modified_files=["src/payments.py"],
                ),
                make_call("s2", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="f"),
            ]
        )
        self.assertEqual(len(detect_redundant_searches(run)), 1)

    def test_unknown_write_conservatively_splits_the_search_window(self):
        run = make_run(
            [
                make_call("s1", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="f"),
                make_call("u1", "edit", {"path": "src/payments.py"}),
                make_call("s2", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="f"),
            ]
        )
        self.assertEqual(detect_redundant_searches(run), [])

    def test_identical_group_without_writes_keeps_the_historical_id(self):
        first = make_call(
            "s1", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="f"
        )
        second = make_call(
            "s2", "grep", {"pattern": "payment", "path": "src"}, result_fingerprint="f"
        )
        finding = detect_redundant_searches(make_run([first, second]))[0]
        self.assertEqual(
            finding.id,
            make_finding_id("TM004", "grep", f"{first.call_fingerprint}|2"),
        )


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

    def test_partial_duration_coverage_lowers_hotspot_confidence(self):
        run = make_run(
            [
                make_call("c1", "bash", {"command": "slow"}, duration_ms=900),
                make_call("c2", "read", {"path": "a"}, duration_ms=100),
                make_call("c3", "read", {"path": "b"}),
            ]
        )
        finding = detect_tool_hotspots(run)[0]
        self.assertEqual(finding.tool, "bash")
        self.assertEqual(finding.confidence, "low")
        coverage = finding.details["measurement_coverage"]
        self.assertEqual(coverage["durations_recorded"], 2)
        self.assertEqual(coverage["calls"], 3)
        self.assertTrue(
            any("Duration was recorded for only 2/3" in note for note in finding.details["limitations"])
        )

    def test_complete_duration_coverage_keeps_hotspot_confidence(self):
        run = make_run(
            [
                make_call("c1", "bash", {"command": "slow"}, duration_ms=900),
                make_call("c2", "read", {"path": "a"}, duration_ms=100),
            ]
        )
        finding = detect_tool_hotspots(run)[0]
        self.assertEqual(finding.confidence, "medium")
        self.assertEqual(finding.details["measurement_coverage"]["durations_recorded"], 2)

    def test_failure_hotspot_with_unknown_outcomes_lowers_confidence(self):
        run = make_run(
            [
                make_call(f"c{i}", "bash", {"command": "pytest -q"}, status="error")
                for i in range(3)
            ]
            + [make_call("c4", "bash", {"command": "pytest -q"})]
        )
        finding = detect_tool_hotspots(run)[0]
        self.assertEqual(finding.confidence, "low")
        self.assertEqual(finding.details["measurement_coverage"]["outcomes_recorded"], 3)
        self.assertTrue(
            any(
                "Outcomes are unknown for 1/4" in note
                for note in finding.details["limitations"]
            )
        )

    def test_partial_token_and_cost_coverage_is_reported(self):
        run = make_run(
            [
                make_call(
                    "c1",
                    "bash",
                    {"command": "cmd 0"},
                    tokens={"input_tokens": 10},
                    cost=0.01,
                )
            ]
            + [make_call(f"c{i}", "bash", {"command": f"cmd {i}"}) for i in range(1, 5)]
        )
        finding = detect_tool_hotspots(run)[0]
        coverage = finding.details["measurement_coverage"]
        self.assertEqual(coverage["tokens_recorded"], 1)
        self.assertEqual(coverage["costs_recorded"], 1)
        self.assertTrue(
            any("recorded for only 1/5 calls" in note for note in finding.details["limitations"])
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
