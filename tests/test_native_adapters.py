"""Unit tests for the native Claude Code and Cursor adapters.

All fixtures are synthetic and sanitized: they contain a deliberately fake
credential (``sk-proj-EXAMPLENOTAREALKEY...``) that must never survive import.
Tests cover detection, record merging, incomplete pairs, mixed sessions,
line-numbered failures, bounds, redaction and the "never estimate" contract.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from tracemend.adapters import (
    SUPPORTED_FORMATS,
    detect_format,
    detect_jsonl_format,
    load_trace_file,
    load_trace_text,
    summarise,
)
from tracemend.adapters.claude_code import parse_claude_code
from tracemend.adapters.cursor import parse_cursor
from tracemend.adapters.jsonl import MAX_JSONL_LINE_BYTES, as_rows, parse_jsonl
from tracemend.errors import TraceParseError, TraceTooLargeError, UnsupportedFormatError

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CLAUDE = FIXTURES / "claude_code_session.jsonl"
CLAUDE_TEXT_ONLY = FIXTURES / "claude_code_text_only.jsonl"
CURSOR_CLI = FIXTURES / "cursor_cli_session.jsonl"
CURSOR_HOOKS = FIXTURES / "cursor_hooks_session.jsonl"

FAKE_SECRET = "sk-proj-EXAMPLENOTAREALKEY000000000000"


def rows_of(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def serialised(run) -> str:
    return json.dumps(
        {
            "events": [event.model_dump(mode="json") for event in run.events],
            "warnings": run.warnings,
            "metadata": run.metadata,
            "title": run.title,
            "model": run.model,
        },
        default=str,
    )


class TestJsonlReader(unittest.TestCase):
    def test_blank_lines_and_crlf_are_tolerated(self) -> None:
        text = '\r\n{"a": 1}\r\n\r\n{"b": 2}\r\n\r\n'
        self.assertEqual(parse_jsonl(text), [{"a": 1}, {"b": 2}])

    def test_one_record_jsonl(self) -> None:
        self.assertEqual(parse_jsonl('{"only": true}'), [{"only": True}])

    def test_final_newline_is_optional(self) -> None:
        self.assertEqual(parse_jsonl('{"a": 1}\n{"b": 2}'), [{"a": 1}, {"b": 2}])

    def test_truncated_final_record_is_an_error(self) -> None:
        with self.assertRaises(TraceParseError) as ctx:
            parse_jsonl('{"a": 1}\n{"b": 2')
        self.assertIn("line 2", ctx.exception.message)

    def test_invalid_line_reports_its_line_number(self) -> None:
        with self.assertRaises(TraceParseError) as ctx:
            parse_jsonl('{"a": 1}\n{"b": \n')
        self.assertIn("line 2", ctx.exception.message)

    def test_non_object_line_is_an_error(self) -> None:
        with self.assertRaises(TraceParseError) as ctx:
            parse_jsonl('{"a": 1}\n[1, 2]\n')
        self.assertIn("line 2", ctx.exception.message)

    def test_empty_input_is_an_error(self) -> None:
        with self.assertRaises(TraceParseError):
            parse_jsonl("\n\n")

    def test_line_byte_limit(self) -> None:
        with patch("tracemend.adapters.jsonl.MAX_JSONL_LINE_BYTES", 10), self.assertRaises(
            TraceParseError
        ) as ctx:
            parse_jsonl('{"a": "0123456789"}')
        self.assertIn("line 1", ctx.exception.message)
        self.assertLess(MAX_JSONL_LINE_BYTES, 10 * 1024 * 1024)

    def test_record_limit(self) -> None:
        with patch("tracemend.adapters.jsonl.MAX_JSONL_RECORDS", 1), self.assertRaises(
            TraceParseError
        ) as ctx:
            parse_jsonl('{"a": 1}\n{"b": 2}\n')
        self.assertIn("more than 1", ctx.exception.message)

    def test_list_payload_record_limit(self) -> None:
        with patch("tracemend.adapters.jsonl.MAX_JSONL_RECORDS", 1), self.assertRaises(
            TraceParseError
        ) as ctx:
            as_rows([{"a": 1}, {"b": 2}], source_label="Test")
        self.assertIn("exceed", ctx.exception.message)


class TestDetection(unittest.TestCase):
    def test_registry_lists_every_adapter(self) -> None:
        self.assertEqual(
            {"generic", "opencode", "claude-code", "cursor"}, set(SUPPORTED_FORMATS)
        )

    def test_claude_jsonl_is_detected(self) -> None:
        run = load_trace_file(CLAUDE)
        self.assertEqual(run.source, "claude-code")

    def test_cursor_shapes_are_detected(self) -> None:
        self.assertEqual(load_trace_file(CURSOR_CLI).source, "cursor")
        self.assertEqual(load_trace_file(CURSOR_HOOKS).source, "cursor")

    def test_single_record_dicts_are_detected(self) -> None:
        claude_row = rows_of(CLAUDE)[1]
        cursor_row = rows_of(CURSOR_CLI)[1]
        self.assertEqual(detect_format(claude_row), "claude-code")
        self.assertEqual(detect_format(cursor_row), "cursor")
        self.assertEqual(load_trace_text(json.dumps(claude_row)).source, "claude-code")

    def test_jsonl_detection_rejects_unknown_rows(self) -> None:
        with self.assertRaises(UnsupportedFormatError):
            detect_jsonl_format([{"foo": 1}, {"bar": 2}])
        with self.assertRaises(UnsupportedFormatError):
            load_trace_text('{"foo": 1}\n{"bar": 2}\n')

    def test_jsonl_detection_rejects_mixed_record_shapes(self) -> None:
        with self.assertRaises(UnsupportedFormatError):
            detect_jsonl_format([rows_of(CLAUDE)[1], rows_of(CURSOR_CLI)[1]])

    def test_generic_and_opencode_are_not_stolen(self) -> None:
        self.assertEqual(detect_format({"events": []}), "generic")
        self.assertEqual(detect_format({"messages": []}), "opencode")
        self.assertEqual(detect_format({"info": {"id": "s"}}), "opencode")


class TestClaudeCode(unittest.TestCase):
    def setUp(self) -> None:
        self.run = load_trace_file(CLAUDE)

    def test_session_metadata_and_events(self) -> None:
        run = self.run
        self.assertEqual(run.source, "claude-code")
        self.assertEqual(run.session_id, "cc-demo-session")
        self.assertEqual(run.model, "claude-sonnet-4-5")
        self.assertEqual(run.agent_name, "claude-code")
        self.assertEqual(run.event_count, 4)
        self.assertEqual([event.id for event in run.events],
                         ["toolu_read_001", "toolu_grep_001", "toolu_bash_001", "toolu_write_001"])
        self.assertEqual([event.sequence for event in run.events], [0, 1, 2, 3])
        self.assertIsNotNone(run.source_sha256)
        self.assertEqual(run.created_at.isoformat(), "2026-02-01T10:00:01+00:00")

    def test_streaming_snapshot_is_collapsed_by_tool_id(self) -> None:
        self.assertEqual(self.run.metadata["duplicate_snapshots"], 1)
        self.assertEqual(len([e for e in self.run.events if e.id == "toolu_read_001"]), 1)

    def test_result_is_joined_and_incomplete_stays_unknown(self) -> None:
        by_id = self.run.event_by_id()
        self.assertEqual(by_id["toolu_read_001"].status, "success")
        self.assertEqual(by_id["toolu_read_001"].output_excerpt, "1: print('hello')")
        self.assertEqual(by_id["toolu_write_001"].status, "error")
        self.assertEqual(by_id["toolu_write_001"].error, "permission denied")
        self.assertEqual(by_id["toolu_grep_001"].status, "unknown")
        self.assertIsNone(by_id["toolu_grep_001"].output_excerpt)
        self.assertEqual(self.run.metadata["incomplete_calls"], 1)
        self.assertTrue(any("no tool_result" in warning for warning in self.run.warnings))

    def test_measurements_are_never_estimated(self) -> None:
        for event in self.run.events:
            self.assertIsNone(event.duration_ms)
            self.assertIsNone(event.token_usage)
            self.assertIsNone(event.cost)
        self.assertTrue(any("per-call tokens are unavailable" in w for w in self.run.warnings))
        self.assertTrue(any("parentUuid" in w for w in self.run.warnings))

    def test_explicit_agent_ids_are_preserved_without_parent_uuid(self) -> None:
        grep = self.run.event_by_id()["toolu_grep_001"]
        self.assertEqual(grep.agent_id, "subagent-1")
        self.assertEqual(grep.parent_agent_id, "main")
        read = self.run.event_by_id()["toolu_read_001"]
        self.assertEqual(read.agent_id, "main")
        self.assertIsNone(read.parent_agent_id)

    def test_secrets_are_redacted_everywhere(self) -> None:
        bash = self.run.event_by_id()["toolu_bash_001"]
        self.assertNotIn(FAKE_SECRET, bash.output_excerpt or "")
        self.assertIn("[REDACTED:", bash.output_excerpt or "")
        self.assertIn("openai_key", self.run.redactions)
        self.assertNotIn(FAKE_SECRET, serialised(self.run))
        self.assertGreater(summarise(self.run).redactions_applied, 0)

    def test_message_prose_is_not_copied(self) -> None:
        self.assertNotIn("I will read the entry point", serialised(self.run))

    def test_import_is_deterministic(self) -> None:
        again = load_trace_file(CLAUDE)
        self.assertEqual(self.run.run_id, again.run_id)
        self.assertEqual([e.model_dump() for e in self.run.events],
                         [e.model_dump() for e in again.events])

    def test_mixed_sessions_are_rejected(self) -> None:
        rows = rows_of(CLAUDE)
        rows[1]["sessionId"] = "cc-other-session"
        with self.assertRaises(TraceParseError) as ctx:
            load_trace_text("\n".join(json.dumps(row) for row in rows))
        self.assertIn("mixes", ctx.exception.message)
        self.assertNotIn("cc-other-session", ctx.exception.message)

    def test_text_only_transcript_is_an_actionable_error(self) -> None:
        with self.assertRaises(TraceParseError) as ctx:
            load_trace_file(CLAUDE_TEXT_ONLY)
        self.assertIn("no tool_use", ctx.exception.message)
        self.assertIn("never infers", ctx.exception.hint or "")

    def test_invalid_jsonl_raises_with_line_number(self) -> None:
        text = "\n".join([json.dumps(rows_of(CLAUDE)[1]), '{"type": "assistant", '])
        with self.assertRaises(TraceParseError) as ctx:
            load_trace_text(text, format="claude-code")
        self.assertIn("line 2", ctx.exception.message)

    def test_file_size_ceiling_still_applies(self) -> None:
        with self.assertRaises(TraceTooLargeError):
            load_trace_file(CLAUDE, max_bytes=64)

    def test_missing_tool_result_before_use_still_joins(self) -> None:
        rows = [
            {
                "type": "user",
                "sessionId": "s",
                "message": {"content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": "done"}
                ]},
            },
            {
                "type": "assistant",
                "sessionId": "s",
                "message": {"content": [
                    {"type": "tool_use", "id": "t1", "name": "Read", "input": {}}
                ]},
            },
        ]
        run = load_trace_text("\n".join(json.dumps(row) for row in rows), format="claude-code")
        self.assertEqual(run.events[0].status, "success")
        self.assertEqual(run.events[0].output_excerpt, "done")


class TestCursorCli(unittest.TestCase):
    def setUp(self) -> None:
        self.run = load_trace_file(CURSOR_CLI)

    def test_start_and_complete_merge_once(self) -> None:
        self.assertEqual(self.run.source, "cursor")
        self.assertEqual(self.run.session_id, "cursor-demo-session")
        self.assertEqual(self.run.model, "cursor-small")
        self.assertEqual(self.run.event_count, 3)
        self.assertEqual([e.id for e in self.run.events],
                         ["call_read_1", "call_shell_1", "call_grep_1"])
        self.assertEqual(self.run.metadata["shape"], "cli")

    def test_tool_names_are_normalised_conservatively(self) -> None:
        self.assertEqual([e.tool for e in self.run.events], ["read", "bash", "grep"])

    def test_failure_and_exit_code_are_preserved(self) -> None:
        shell = self.run.event_by_id()["call_shell_1"]
        self.assertEqual(shell.status, "error")
        self.assertIn("exit code 1", shell.error or "")
        self.assertNotIn(FAKE_SECRET, shell.error or "")
        self.assertNotIn(FAKE_SECRET, serialised(self.run))

    def test_missing_completion_stays_unknown(self) -> None:
        grep = self.run.event_by_id()["call_grep_1"]
        self.assertEqual(grep.status, "unknown")
        self.assertIsNone(grep.output_excerpt)
        self.assertEqual(self.run.metadata["incomplete_calls"], 1)

    def test_session_duration_is_not_attributed_to_a_tool(self) -> None:
        for event in self.run.events:
            self.assertIsNone(event.duration_ms)
            self.assertIsNone(event.token_usage)
            self.assertIsNone(event.cost)

    def test_completion_without_start_is_kept_once(self) -> None:
        row = {
            "type": "tool_call",
            "subtype": "completed",
            "call_id": "only_completion",
            "session_id": "s",
            "tool_call": {"readToolCall": {"args": {"path": "a.py"},
                                           "result": {"success": {"content": "ok"}}}},
        }
        run = load_trace_text(json.dumps(row), format="cursor")
        self.assertEqual(run.event_count, 1)
        self.assertEqual(run.events[0].status, "success")
        self.assertEqual(run.metadata["merged_without_start"], 1)

    def test_unknown_tool_key_keeps_the_reported_name(self) -> None:
        row = {
            "type": "tool_call",
            "subtype": "completed",
            "call_id": "c1",
            "session_id": "s",
            "tool_call": {"specialToolCall": {"args": {"x": 1},
                                              "result": {"success": {"content": "ok"}}}},
        }
        run = load_trace_text(json.dumps(row), format="cursor")
        self.assertEqual(run.events[0].tool, "special")

    def test_duplicate_started_snapshot_is_collapsed(self) -> None:
        rows = rows_of(CURSOR_CLI)
        run = load_trace_text(
            "\n".join(json.dumps(row) for row in [rows[0], rows[1], rows[1], rows[2]]),
            format="cursor",
        )
        self.assertEqual(run.event_count, 1)
        self.assertEqual(run.metadata["duplicate_snapshots"], 1)

    def test_mixed_sessions_are_rejected(self) -> None:
        rows = rows_of(CURSOR_CLI)
        rows[2]["session_id"] = "another-session"
        with self.assertRaises(TraceParseError) as ctx:
            load_trace_text("\n".join(json.dumps(row) for row in rows), format="cursor")
        self.assertIn("mixes", ctx.exception.message)

    def test_mixed_shapes_are_rejected(self) -> None:
        rows = [rows_of(CURSOR_CLI)[1], rows_of(CURSOR_HOOKS)[0]]
        with self.assertRaises(TraceParseError) as ctx:
            load_trace_text("\n".join(json.dumps(row) for row in rows), format="cursor")
        self.assertIn("mixes", ctx.exception.message)

    def test_unknown_schema_is_a_clear_error(self) -> None:
        with self.assertRaises(TraceParseError):
            load_trace_text('{"type": "assistant", "text": "hello"}', format="cursor")


class TestCursorHooks(unittest.TestCase):
    def setUp(self) -> None:
        self.run = load_trace_file(CURSOR_HOOKS)

    def test_pairs_are_merged_and_orphans_kept(self) -> None:
        self.assertEqual(self.run.metadata["shape"], "hooks")
        self.assertEqual(self.run.event_count, 4)
        self.assertEqual([e.id for e in self.run.events],
                         ["hook_read_1", "hook_shell_1", "hook_grep_1", "hook_orphan_1"])
        self.assertEqual(self.run.metadata["merged_without_start"], 1)

    def test_json_stringified_output_is_decoded(self) -> None:
        read = self.run.event_by_id()["hook_read_1"]
        self.assertEqual(read.status, "success")
        self.assertEqual(read.output_excerpt, "1: print('hello')")
        self.assertEqual(read.duration_ms, 35)

    def test_failures_and_exit_codes_are_preserved_and_redacted(self) -> None:
        shell = self.run.event_by_id()["hook_shell_1"]
        self.assertEqual(shell.status, "error")
        self.assertIn("exit code 2", shell.error or "")
        self.assertNotIn(FAKE_SECRET, shell.error or "")
        self.assertNotIn(FAKE_SECRET, serialised(self.run))
        self.assertIn("openai_key", self.run.redactions)
        self.assertEqual(shell.duration_ms, 120)

    def test_unpaired_start_stays_unknown(self) -> None:
        self.assertEqual(self.run.event_by_id()["hook_grep_1"].status, "unknown")
        self.assertEqual(self.run.metadata["incomplete_calls"], 1)

    def test_hook_capture_limitation_is_reported(self) -> None:
        self.assertTrue(any("only record tool calls" in w for w in self.run.warnings))

    def test_arguments_are_redacted_and_bounded(self) -> None:
        shell = self.run.event_by_id()["hook_shell_1"]
        self.assertEqual(shell.arguments, {"command": "npm test"})


class TestAdapterParsersDirectly(unittest.TestCase):
    def test_parsers_accept_one_record_dicts(self) -> None:
        run = parse_claude_code(rows_of(CLAUDE)[1])
        self.assertEqual(run.event_count, 1)
        cursor = parse_cursor(rows_of(CURSOR_CLI)[1])
        self.assertEqual(cursor.event_count, 1)

    def test_rows_must_be_objects(self) -> None:
        with self.assertRaises(TraceParseError):
            parse_claude_code(["not-a-row"])
        with self.assertRaises(TraceParseError):
            parse_cursor([1, 2, 3])


if __name__ == "__main__":
    unittest.main()
