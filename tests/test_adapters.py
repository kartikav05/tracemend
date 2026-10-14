"""Tests for the trace ingestion engine (``tracemend.adapters``).

Run with ``python -m unittest tests.test_adapters`` (pytest is not required).
Every test writes to a ``tempfile.TemporaryDirectory``; nothing here touches the
network or a real agent configuration.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from tracemend.adapters import (
    detect_format,
    load_trace_file,
    load_trace_text,
    summarise,
)
from tracemend.adapters.generic import duration_from_time
from tracemend.errors import TraceParseError, TraceTooLargeError, UnsupportedFormatError

REPO_ROOT = Path(__file__).resolve().parents[1]

EPOCH_MS_A = 1_760_000_000_000
EPOCH_MS_B = 1_760_000_005_000


def generic_payload(**overrides) -> dict:
    """A valid generic trace with a session block and two ordered events."""
    payload = {
        "format": "tracemend.generic",
        "version": 1,
        "session": {
            "id": "session_demo",
            "title": "Demo session",
            "agent": "demo-agent",
            "model": "claude-sonnet-4",
            "created_at": "2026-01-01T00:00:00Z",
        },
        "events": [
            {
                "id": "call_001",
                "agent_id": "main",
                "tool": "grep",
                "arguments": {"pattern": "x", "path": "src"},
                "status": "success",
                "timestamp": "2026-01-01T00:00:01Z",
                "duration_ms": 120,
                "tokens": {"input_tokens": 10, "output_tokens": 2},
                "cost": 0.001,
                "result_fingerprint": "fp_grep_x",
            },
            {
                "id": "call_002",
                "agent_id": "main",
                "tool": "bash",
                "arguments": {"command": "pytest -q"},
                "status": "error",
                "timestamp": "2026-01-01T00:00:05Z",
                "duration_ms": 2000,
                "error": "1 failed",
                "output": "E   AssertionError",
            },
        ],
    }
    payload.update(overrides)
    return payload


class AdapterTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def write_trace(self, payload, name: str = "trace.json") -> Path:
        path = self.tmp / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path


class TestDetection(AdapterTestBase):
    def test_detect_declared_formats(self):
        self.assertEqual(detect_format({"format": "tracemend.generic"}), "generic")
        self.assertEqual(detect_format({"format": "opencode.session.v2"}), "opencode")

    def test_detect_by_shape(self):
        self.assertEqual(detect_format({"messages": []}), "opencode")
        self.assertEqual(detect_format({"info": {"id": "s"}}), "opencode")
        self.assertEqual(detect_format({"events": []}), "generic")

    def test_detect_tool_calls_alias_is_generic(self):
        payload = {"tool_calls": [{"tool": "grep", "arguments": {"pattern": "x"}, "agent_id": "main"}]}
        self.assertEqual(detect_format(payload), "generic")

    def test_detect_opencode_legacy_tool_calls(self):
        payload = {"tool_calls": [{"tool": "bash", "input": {"command": "ls"}, "state": {"status": "completed"}}]}
        self.assertEqual(detect_format(payload), "opencode")

    def test_detect_unknown_payload_raises(self):
        with self.assertRaises(UnsupportedFormatError) as ctx:
            detect_format({"hello": "world"})
        self.assertIn("generic", ctx.exception.hint or "")

    def test_undetectable_text_raises_unsupported_format(self):
        with self.assertRaises(UnsupportedFormatError):
            load_trace_text(json.dumps({"hello": "world"}))

    def test_unknown_declared_format_raises(self):
        with self.assertRaises(UnsupportedFormatError):
            load_trace_text(json.dumps({"format": "weird.export", "events": []}))

    def test_unknown_explicit_override_raises(self):
        path = self.write_trace(generic_payload())
        with self.assertRaises(UnsupportedFormatError):
            load_trace_file(path, format="bogus")
        with self.assertRaises(UnsupportedFormatError):
            load_trace_text(json.dumps(generic_payload()), format="bogus")


class TestGenericTrace(AdapterTestBase):
    def test_valid_generic_trace(self):
        path = self.write_trace(generic_payload())
        run = load_trace_file(path)

        self.assertEqual(run.source, "generic")
        self.assertEqual(run.session_id, "session_demo")
        self.assertEqual(run.title, "Demo session")
        self.assertEqual(run.model, "claude-sonnet-4")
        self.assertEqual(run.agent_name, "demo-agent")
        self.assertEqual(run.event_count, 2)
        self.assertTrue(run.run_id.startswith("run_"))
        self.assertEqual(run.source_path, str(path))
        self.assertIsNotNone(run.source_sha256)
        self.assertFalse(run.truncated)
        self.assertEqual(run.created_at, datetime(2026, 1, 1, tzinfo=UTC))

        first, second = run.events
        self.assertEqual([first.sequence, second.sequence], [0, 1])
        self.assertEqual(first.tool, "grep")
        self.assertEqual(first.arguments, {"pattern": "x", "path": "src"})
        self.assertEqual(first.status, "success")
        self.assertEqual(first.duration_ms, 120)
        self.assertEqual(first.token_usage.total, 12)
        self.assertAlmostEqual(first.cost or 0, 0.001)
        self.assertEqual(first.result_fingerprint, "fp_grep_x")

        self.assertEqual(second.status, "error")
        self.assertEqual(second.error, "1 failed")
        self.assertEqual(second.output_excerpt, "E   AssertionError")
        self.assertIsNone(second.token_usage)
        self.assertIsNone(second.cost)

    def test_tool_calls_key_alias(self):
        payload = generic_payload()
        payload["tool_calls"] = payload.pop("events")
        run = load_trace_text(json.dumps(payload))
        self.assertEqual(run.source, "generic")
        self.assertEqual(run.event_count, 2)
        self.assertEqual(run.metadata["event_key"], "tool_calls")

    def test_missing_session_block_uses_defaults(self):
        payload = {"format": "tracemend.generic", "events": generic_payload()["events"]}
        run = load_trace_text(json.dumps(payload))
        self.assertEqual(run.session_id, "session_unknown")
        self.assertEqual(run.title, "Untitled session")
        self.assertIsNone(run.model)
        self.assertIsNone(run.created_at)
        self.assertEqual(run.event_count, 2)

    def test_invalid_json_raises_with_hint(self):
        path = self.tmp / "broken.json"
        path.write_text('{"events": [ { "tool": "grep" ', encoding="utf-8")
        with self.assertRaises(TraceParseError) as ctx:
            load_trace_file(path)
        self.assertIsNotNone(ctx.exception.hint)
        self.assertIn("invalid JSON", ctx.exception.message)

    def test_empty_events_list_still_produces_a_run(self):
        run = load_trace_text(json.dumps(generic_payload(events=[])))
        self.assertEqual(run.event_count, 0)
        self.assertEqual(run.events, [])
        self.assertEqual(summarise(run).event_count, 0)
        self.assertTrue(run.run_id.startswith("run_"))

    def test_missing_measurements_stay_none(self):
        payload = generic_payload(
            events=[{"id": "call_1", "tool": "grep", "arguments": {"pattern": "x"}}]
        )
        run = load_trace_text(json.dumps(payload))
        event = run.events[0]
        self.assertIsNone(event.duration_ms)
        self.assertIsNone(event.token_usage)
        self.assertIsNone(event.cost)
        self.assertIsNone(event.timestamp)
        self.assertIsNone(event.error)
        self.assertEqual(event.status, "unknown")

    def test_token_usage_alias_and_top_level_tokens(self):
        payload = generic_payload(
            events=[
                {"id": "a", "tool": "read", "arguments": {}, "token_usage": {"input_tokens": 3, "output_tokens": 4}},
                {"id": "b", "tool": "read", "arguments": {}, "input_tokens": 7, "output_tokens": 8},
                {"id": "c", "tool": "read", "arguments": {}, "tokens": {"input": 5}},
            ]
        )
        run = load_trace_text(json.dumps(payload))
        self.assertEqual(run.events[0].token_usage.total, 7)
        self.assertEqual(run.events[1].token_usage.total, 15)
        self.assertEqual(run.events[2].token_usage.total, 5)
        self.assertIsNone(run.events[2].token_usage.output_tokens)

    def test_epoch_and_iso_timestamps(self):
        payload = generic_payload(
            events=[
                {"id": "iso", "tool": "grep", "arguments": {}, "timestamp": "2026-01-01T00:00:10Z"},
                {"id": "epoch", "tool": "read", "arguments": {}, "timestamp": EPOCH_MS_A},
            ]
        )
        run = load_trace_text(json.dumps(payload))
        iso, epoch = run.event_by_id()["iso"], run.event_by_id()["epoch"]
        self.assertEqual(iso.timestamp, datetime(2026, 1, 1, 0, 0, 10, tzinfo=UTC))
        self.assertEqual(epoch.timestamp, datetime.fromtimestamp(EPOCH_MS_A / 1000, tz=UTC))
        self.assertIsNotNone(iso.timestamp.tzinfo)
        self.assertIsNotNone(epoch.timestamp.tzinfo)

    def test_sequence_follows_timestamp_order_not_file_order(self):
        payload = generic_payload(
            events=[
                {"id": "late", "tool": "read", "arguments": {}, "timestamp": "2026-01-01T00:00:30Z"},
                {"id": "early", "tool": "grep", "arguments": {}, "timestamp": "2026-01-01T00:00:10Z"},
                {"id": "untimed", "tool": "ls", "arguments": {}},
                {"id": "mid", "tool": "bash", "arguments": {}, "timestamp": "2026-01-01T00:00:20Z"},
            ]
        )
        run = load_trace_text(json.dumps(payload))
        self.assertEqual([e.id for e in run.events], ["early", "mid", "late", "untimed"])
        self.assertEqual([e.sequence for e in run.events], [0, 1, 2, 3])

    def test_duplicate_event_ids_become_unique(self):
        payload = generic_payload(
            events=[
                {"id": "dup", "tool": "grep", "arguments": {}},
                {"id": "dup", "tool": "read", "arguments": {}},
                {"id": "dup", "tool": "bash", "arguments": {}},
            ]
        )
        run = load_trace_text(json.dumps(payload))
        ids = [event.id for event in run.events]
        self.assertEqual(ids, ["dup", "dup-2", "dup-3"])
        self.assertEqual(len(set(ids)), 3)

    def test_missing_event_id_is_derived_and_unique(self):
        payload = generic_payload(events=[{"tool": "grep", "arguments": {}}, {"tool": "read", "arguments": {}}])
        run = load_trace_text(json.dumps(payload))
        self.assertEqual([e.id for e in run.events], ["session_demo:0000", "session_demo:0001"])

    def test_non_object_events_are_skipped_and_counted(self):
        payload = generic_payload(events=["oops", {"id": "ok", "tool": "grep", "arguments": {}}])
        run = load_trace_text(json.dumps(payload))
        self.assertEqual(run.event_count, 1)
        summary = summarise(run)
        self.assertEqual(summary.skipped_records, 1)
        self.assertTrue(any("skipped non-object" in warning for warning in run.warnings))


class TestRedaction(AdapterTestBase):
    def test_output_secret_is_redacted_before_storing(self):
        payload = generic_payload(
            events=[
                {
                    "id": "call_1",
                    "tool": "read",
                    "arguments": {"path": "src/config.py"},
                    "status": "success",
                    "output": "OPENAI_API_KEY=sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
                }
            ]
        )
        run = load_trace_text(json.dumps(payload))
        excerpt = run.events[0].output_excerpt or ""
        self.assertIn("[REDACTED:", excerpt)
        self.assertNotIn("sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", excerpt)
        self.assertTrue(run.redactions)
        self.assertIn("openai_key", run.redactions)
        self.assertGreater(summarise(run).redactions_applied, 0)

    def test_arguments_and_error_are_redacted(self):
        payload = generic_payload(
            events=[
                {
                    "id": "call_1",
                    "tool": "bash",
                    "arguments": {"api_key": "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"},
                    "status": "error",
                    "error": "auth failed with sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
                }
            ]
        )
        run = load_trace_text(json.dumps(payload))
        event = run.events[0]
        self.assertIn("[REDACTED:", json.dumps(event.arguments))
        self.assertIn("[REDACTED:", event.error or "")


class TestDeterminism(AdapterTestBase):
    def test_same_bytes_same_run_id_and_different_bytes_different_run_id(self):
        path = self.write_trace(generic_payload())
        first = load_trace_file(path).run_id
        second = load_trace_file(path).run_id
        self.assertEqual(first, second)

        other = self.write_trace(generic_payload(events=[]), name="other.json")
        self.assertNotEqual(load_trace_file(other).run_id, first)

    def test_text_and_file_loads_agree_when_no_path_is_given(self):
        payload = generic_payload()
        text = json.dumps(payload)
        self.assertEqual(load_trace_text(text).run_id, load_trace_text(text).run_id)


class TestSizeLimit(AdapterTestBase):
    def test_oversize_file_raises_trace_too_large(self):
        path = self.write_trace(generic_payload())
        with self.assertRaises(TraceTooLargeError) as ctx:
            load_trace_file(path, max_bytes=64)
        self.assertIsNotNone(ctx.exception.hint)
        self.assertGreater(path.stat().st_size, 64)

    def test_size_limit_uses_max_trace_bytes_by_default(self):
        run = load_trace_file(self.write_trace(generic_payload()))
        self.assertEqual(run.event_count, 2)


class TestTimeBoxHelpers(unittest.TestCase):
    """`duration_from_time` must understand both time-box shapes."""

    def test_start_end_pair(self) -> None:
        self.assertEqual(duration_from_time({"start": EPOCH_MS_A, "end": EPOCH_MS_A + 2300}), 2300)

    def test_created_completed_pair(self) -> None:
        box = {"created": 1791768325193, "ran": 1791768326902, "completed": 1791768336125}
        self.assertEqual(duration_from_time(box), 10932)

    def test_epoch_seconds_are_scaled(self) -> None:
        self.assertEqual(duration_from_time({"start": 1_760_000_000, "end": 1_760_000_003}), 3000)

    def test_relative_delta_is_kept(self) -> None:
        self.assertEqual(duration_from_time({"start": 0, "end": 1500}), 1500)

    def test_missing_bound_is_unavailable(self) -> None:
        self.assertIsNone(duration_from_time({"created": EPOCH_MS_A}))
        self.assertIsNone(duration_from_time({"completed": EPOCH_MS_A}))
        self.assertIsNone(duration_from_time(None))
        self.assertIsNone(duration_from_time("nonsense"))

    def test_backwards_bounds_are_unavailable(self) -> None:
        self.assertIsNone(duration_from_time({"created": EPOCH_MS_A, "completed": EPOCH_MS_A - 5}))


class TestOpenCodeV2RealWorldShapes(AdapterTestBase):
    """Shapes taken from a real OpenCode v2.0.26 session database.

    The v2 tool record uses ``name`` for the tool, ``state.metadata.files`` with
    ``{"file", "patch"}`` objects, and a ``{"created", "ran", "completed"}`` time
    box. None of these may be invented or copied verbatim.
    """

    CREATED = 1791768325193
    RAN = 1791768326902
    COMPLETED = 1791768336125

    def _run(self, parts: list[dict]) -> object:
        payload = {
            "info": {"id": "ses_v2_real", "title": "V2 real-world shapes"},
            "messages": [
                {"info": {"id": "msg_1", "role": "assistant"}, "parts": parts}
            ],
        }
        return load_trace_text(json.dumps(payload))

    def test_v2_time_box_yields_a_duration(self) -> None:
        run = self._run(
            [
                {
                    "type": "tool",
                    "name": "shell",
                    "state": {"status": "completed", "input": {"command": "ls -la"}},
                    "time": {
                        "created": self.CREATED,
                        "ran": self.RAN,
                        "completed": self.COMPLETED,
                    },
                }
            ]
        )
        call = run.events[0]
        self.assertEqual(call.tool, "shell")
        self.assertEqual(call.duration_ms, self.COMPLETED - self.CREATED)
        self.assertEqual(
            call.timestamp, datetime.fromtimestamp(self.CREATED / 1000, tz=UTC)
        )

    def test_v2_error_status_is_normalised(self) -> None:
        run = self._run(
            [
                {
                    "type": "tool",
                    "name": "read",
                    "state": {
                        "status": "error",
                        "input": {"filePath": "src/payments.py"},
                        "error": "file not found",
                    },
                    "time": {"created": self.CREATED, "completed": self.COMPLETED},
                }
            ]
        )
        self.assertEqual(run.events[0].status, "error")
        self.assertEqual(run.events[0].error, "file not found")

    def test_files_entries_keep_only_paths(self) -> None:
        patch = "Index: src/payments.py\n@@ -1,3 +1,3 @@\n-secret-token\n+redacted\n" * 200
        run = self._run(
            [
                {
                    "type": "tool",
                    "name": "edit",
                    "state": {
                        "status": "completed",
                        "input": {"filePath": "src/payments.py"},
                        "metadata": {
                            "files": [
                                {"file": "src/payments.py", "patch": patch},
                                {"file": "src/config.py", "patch": patch},
                                {"file": "src/payments.py", "patch": patch},
                            ],
                            "exit": 0,
                            "truncated": False,
                        },
                    },
                    "time": {"created": self.CREATED, "completed": self.COMPLETED},
                }
            ]
        )
        call = run.events[0]
        self.assertEqual(call.modified_files, ["src/payments.py", "src/config.py"])
        serialised = json.dumps(call.modified_files)
        self.assertNotIn("Index:", serialised)
        self.assertNotIn("secret-token", serialised)
        self.assertLess(len(serialised), 500)

    def test_string_files_entries_still_work(self) -> None:
        run = self._run(
            [
                {
                    "type": "tool",
                    "name": "write",
                    "state": {
                        "status": "completed",
                        "input": {"filePath": "a.py"},
                        "metadata": {"files": ["a.py", "b.py"]},
                    },
                }
            ]
        )
        self.assertEqual(run.events[0].modified_files, ["a.py", "b.py"])


class TestOpenCode(AdapterTestBase):
    def test_v2_messages_parts_shape(self):
        payload = {
            "info": {"id": "ses_v2", "title": "V2 session", "agent": "build"},
            "messages": [
                {
                    "info": {"id": "msg_0001", "role": "assistant", "time": {"created": EPOCH_MS_A}},
                    "parts": [
                        {"type": "text", "text": "thinking out loud"},
                        {
                            "type": "tool",
                            "tool": "bash",
                            "state": {
                                "status": "completed",
                                "input": {"command": "pytest -q"},
                                "output": "6 passed in 1.68s",
                                "time": {"start": EPOCH_MS_A, "end": EPOCH_MS_A + 2_300},
                            },
                        },
                    ],
                },
                {
                    "info": {"id": "msg_0002", "role": "assistant", "agent": "explore-subagent"},
                    "parts": [
                        {
                            "type": "tool",
                            "tool": "read",
                            "state": {
                                "status": "error",
                                "input": {"filePath": "src/payments.py"},
                                "error": "file changed on disk",
                            },
                        }
                    ],
                },
            ],
        }
        run = load_trace_text(json.dumps(payload))

        self.assertEqual(run.source, "opencode")
        self.assertEqual(run.session_id, "ses_v2")
        self.assertEqual(run.title, "V2 session")
        self.assertEqual(run.event_count, 2)

        first, second = run.events
        self.assertEqual(first.id, "msg_0001:0001")
        self.assertEqual(first.tool, "bash")
        self.assertEqual(first.arguments, {"command": "pytest -q"})
        self.assertEqual(first.status, "success")
        self.assertEqual(first.duration_ms, 2300)
        self.assertEqual(first.output_excerpt, "6 passed in 1.68s")
        # message-level agent wins; a message without one inherits the session agent
        self.assertEqual(first.agent_id, "build")
        self.assertEqual(second.agent_id, "explore-subagent")
        self.assertEqual(first.timestamp, datetime.fromtimestamp(EPOCH_MS_A / 1000, tz=UTC))

        self.assertEqual(second.tool, "read")
        self.assertEqual(second.arguments, {"filePath": "src/payments.py"})
        self.assertEqual(second.status, "error")
        self.assertEqual(second.error, "file changed on disk")
        self.assertIsNone(second.duration_ms)

    def test_legacy_flat_tool_calls_shape(self):
        payload = {
            "tool_calls": [
                {
                    "id": "tc_1",
                    "tool": "bash",
                    "input": {"command": "ls -la"},
                    "state": {"status": "completed"},
                    "output": "total 8",
                },
                {
                    "id": "tc_2",
                    "tool": "read",
                    "input": {"filePath": "a.py"},
                    "status": "success",
                    "result_fingerprint": "fp_a",
                },
            ]
        }
        run = load_trace_text(json.dumps(payload))
        self.assertEqual(run.source, "opencode")
        self.assertEqual(run.metadata["shape"], "tool_calls")
        self.assertEqual([event.id for event in run.events], ["tc_1", "tc_2"])
        self.assertEqual(run.events[0].arguments, {"command": "ls -la"})
        self.assertEqual(run.events[0].output_excerpt, "total 8")
        self.assertEqual(run.events[1].result_fingerprint, "fp_a")

    def test_messages_without_tool_calls_raises(self):
        payload = {
            "info": {"id": "ses_empty"},
            "messages": [
                {
                    "info": {"id": "msg_1", "role": "assistant"},
                    "parts": [{"type": "text", "text": "no tools here"}],
                }
            ],
        }
        with self.assertRaises(TraceParseError) as ctx:
            load_trace_text(json.dumps(payload), format="opencode")
        self.assertIn("no tool calls", ctx.exception.message)
        self.assertIn("export", ctx.exception.hint or "")

    def test_empty_export_raises(self):
        with self.assertRaises(TraceParseError):
            load_trace_text(json.dumps({"info": {"id": "ses_1"}}), format="opencode")

    def test_sanitized_export_produces_warning(self):
        payload = {
            "format": "opencode.export",
            "sanitized": True,
            "info": {"id": "ses_sanitized"},
            "messages": [
                {
                    "info": {"id": "msg_1", "role": "assistant"},
                    "parts": [
                        {
                            "type": "tool",
                            "tool": "grep",
                            "state": {"status": "completed", "input": {"pattern": "x"}},
                        }
                    ],
                }
            ],
        }
        run = load_trace_text(json.dumps(payload))
        self.assertEqual(run.event_count, 1)
        self.assertTrue(
            any("sanitized export" in warning for warning in run.warnings),
            run.warnings,
        )
        self.assertIsNone(run.events[0].output_excerpt)
        self.assertIsNone(run.events[0].result_fingerprint)

    def test_detects_missing_results_without_inventing_them(self):
        payload = {
            "messages": [
                {
                    "role": "assistant",
                    "parts": [{"type": "tool", "tool": "bash", "state": {"status": "completed"}}],
                }
            ]
        }
        run = load_trace_text(json.dumps(payload))
        self.assertEqual(run.event_count, 1)
        self.assertIsNone(run.events[0].output_excerpt)
        self.assertTrue(any("tool results unavailable" in warning for warning in run.warnings))

    def test_user_message_parts_are_ignored(self):
        payload = {
            "messages": [
                {"role": "user", "parts": [{"type": "tool", "tool": "bash", "state": {"status": "completed"}}]},
                {
                    "role": "assistant",
                    "parts": [{"type": "tool", "tool": "grep", "state": {"status": "completed", "output": "ok"}}],
                },
            ]
        }
        run = load_trace_text(json.dumps(payload))
        self.assertEqual([event.tool for event in run.events], ["grep"])


class TestRepositoryFixtures(unittest.TestCase):
    """The shipped example traces must load with the real engine."""

    def test_example_traces_load(self):
        inefficient = REPO_ROOT / "examples" / "inefficient_run.json"
        optimized = REPO_ROOT / "examples" / "optimized_run.json"
        if not inefficient.exists() or not optimized.exists():
            self.skipTest("example fixtures are not present")

        before = load_trace_file(inefficient)
        after = load_trace_file(optimized)

        self.assertEqual(before.event_count, 29)
        self.assertEqual(after.event_count, 10)
        self.assertEqual(before.source, "generic")
        self.assertNotEqual(before.run_id, after.run_id)
        self.assertTrue(before.redactions)
        self.assertEqual(load_trace_file(inefficient).run_id, before.run_id)
        self.assertEqual(summarise(before).event_count, 29)


if __name__ == "__main__":
    unittest.main()
