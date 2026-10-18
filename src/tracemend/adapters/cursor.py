"""Cursor adapter: CLI ``stream-json`` NDJSON and captured hook JSONL (preToolUse/postToolUse).

CLI: started/completed pairs merged by call_id; lone start keeps unknown status.
Hooks: pre/post pairs merged; failures preserve exit codes and errors.
Tool names normalized conservatively (readToolCall->read, shellToolCall->bash, etc.).
CLI result duration is session-level, not copied to tools. Hook tool_output JSON decoded.
No installation or execution — only reads the given file. Text-only transcripts rejected.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..errors import TraceParseError
from ..models import (
    ToolCall,
    TraceRun,
    canonical_json,
    coerce_datetime,
    normalize_tool_name,
    short_hash,
    utc_now,
)
from ..security import limit_preview, unique_preserving_order
from .generic import (
    IdAllocator,
    Redactor,
    coerce_int,
    coerce_text,
    finalise_events,
    first_present,
    make_run_id,
)
from .jsonl import as_rows, single_session_id

_HOOK_EVENTS = frozenset({"preToolUse", "postToolUse", "postToolUseFailure"})
_CLI_TYPES = frozenset({"system", "result", "tool_call"})

_NO_TOOLS_MESSAGE = "the Cursor input contained no tool calls"
_NO_TOOLS_HINT = (
    "Point TraceMend at Cursor `stream-json` output or at captured "
    "preToolUse/postToolUse hook records. A Cursor IDE chat transcript without "
    "hook events has no tool evidence, and TraceMend never infers tool calls from prose."
)
_MIXED_HINT = "Import one Cursor session in a single shape at a time."

#: Clear, documented synonyms only. Unknown ``*ToolCall`` names are preserved.
_CLI_TOOL_NAMES: dict[str, str] = {
    "readtoolcall": "read",
    "writetoolcall": "write",
    "edittoolcall": "edit",
    "deletetoolcall": "delete",
    "shelltoolcall": "bash",
    "greptoolcall": "grep",
    "globtoolcall": "glob",
    "listtoolcall": "ls",
    "lstoolcall": "ls",
}


def _is_hook_record(record: Any) -> bool:
    return isinstance(record, dict) and record.get("hook_event_name") in _HOOK_EVENTS


def _is_cli_record(record: Any) -> bool:
    if not isinstance(record, dict):
        return False
    if isinstance(record.get("tool_call"), dict):
        return True
    return record.get("type") in _CLI_TYPES and bool(
        record.get("session_id") or record.get("call_id")
    )


def matches_record(record: Any) -> bool:
    """True for a single Cursor CLI or hook record (used by detection)."""
    return _is_hook_record(record) or _is_cli_record(record)


def _decode_object(value: Any) -> dict[str, Any] | None:
    """Decode a JSON-stringified object, returning ``None`` when it is not one."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text.startswith("{"):
            return None
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            return None
        return decoded if isinstance(decoded, dict) else None
    return None


def _arguments(value: Any, redactor: Redactor) -> dict[str, Any]:
    decoded = _decode_object(value)
    if decoded is not None:
        return redactor.value(decoded)
    if isinstance(value, str) and value.strip():
        return redactor.value({"_raw": value})
    return {}


def _cli_tool_name(key: str) -> str:
    mapped = _CLI_TOOL_NAMES.get(key.strip().lower())
    if mapped:
        return mapped
    stem = re.sub(r"(ToolCall|Tool)$", "", key.strip(), flags=re.IGNORECASE) or key
    return re.sub(r"(?<!^)(?=[A-Z])", "_", stem).lower() or "unknown"


def _result_text(value: Any) -> str | None:
    """Pull human-readable text out of a Cursor success/failure object."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("content", "stdout", "output", "result", "message"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
            if isinstance(candidate, list):
                joined = "\n".join(
                    item for item in (coerce_text(entry) for entry in candidate) if item
                )
                if joined:
                    return joined
        return canonical_json(value)
    return coerce_text(value)


def _exit_code(value: Any) -> int | None:
    if isinstance(value, dict):
        value = first_present(value.get("exit_code"), value.get("exitCode"))
    return coerce_int(value)


def _error_with_code(text: str | None, code: int | None) -> str | None:
    if code is not None and code != 0:
        return f"exit code {code}: {text}" if text else f"exit code {code}"
    return text


def _apply_cli_result(call: ToolCall, result: Any, redactor: Redactor) -> bool:
    """Join a ``result`` object onto a CLI call. Returns True when it had evidence."""
    if not isinstance(result, dict) or not result:
        return False
    success = result.get("success")
    failure = result.get("failure")
    if failure is not None and failure is not False:
        code = _exit_code(failure) if isinstance(failure, dict) else None
        text = redactor.text(_result_text(failure))
        call.status = "error"
        call.error = _error_with_code(limit_preview(text or "") or None, code)
        call.output_excerpt = limit_preview(text or "") or None
        return True
    if success is not None and success is not False:
        code = _exit_code(success) if isinstance(success, dict) else None
        text = redactor.text(_result_text(success))
        failed = code not in (None, 0) or (
            isinstance(success, dict) and success.get("isError") is True
        )
        call.status = "error" if failed else "success"
        call.output_excerpt = limit_preview(text or "") or None
        if failed:
            call.error = _error_with_code(limit_preview(text or "") or None, code)
        return True
    return False


def _hook_output(record: dict[str, Any], redactor: Redactor) -> tuple[str | None, int | None, bool | None]:
    """Return ``(text, exit_code, success_flag)`` for a hook ``tool_output``."""
    raw = record.get("tool_output")
    if raw is None:
        return None, None, None
    decoded = _decode_object(raw)
    if decoded is None:
        text = redactor.text(coerce_text(raw))
        return limit_preview(text or "") or None, None, None
    code = _exit_code(decoded)
    success = decoded.get("success")
    failed = decoded.get("isError") is True or (code not in (None, 0))
    text_value = _result_text(decoded)
    text = limit_preview(redactor.text(text_value or "") or "") or None
    if success is False:
        failed = True
    return text, code, (not failed if (failed or success is not None or code is not None) else None)


def _hook_duration(record: dict[str, Any]) -> int | None:
    value = coerce_int(first_present(record.get("duration_ms"), record.get("duration")))
    if value is None or value < 0:
        return None
    return value


def _hook_apply(call: ToolCall, record: dict[str, Any], redactor: Redactor) -> None:
    text, code, success_flag = _hook_output(record, redactor)
    event = coerce_text(record.get("hook_event_name")) or ""
    failed = event == "postToolUseFailure" or success_flag is False
    call.status = "error" if failed else "success"
    if text is not None:
        call.output_excerpt = text
    if failed:
        call.error = _error_with_code(text, code)
    duration = _hook_duration(record)
    if duration is not None:
        call.duration_ms = duration


def parse_cursor(
    payload: Any,
    *,
    source_path: str | None = None,
    digest: str | None = None,
) -> TraceRun:
    """Parse Cursor CLI ``stream-json`` or captured hook JSONL."""
    rows = as_rows(payload, source_label="Cursor")
    hook_mode = any(_is_hook_record(row) for row in rows)
    cli_mode = any(_is_cli_record(row) for row in rows)
    if hook_mode and cli_mode:
        raise TraceParseError(
            "the Cursor input mixes stream-json and hook records",
            hint=_MIXED_HINT,
        )
    if not hook_mode and not cli_mode:
        raise TraceParseError(
            "the Cursor input has no recognised stream-json or hook records",
            hint=_NO_TOOLS_HINT,
        )

    session_id = single_session_id(
        (
            value
            for row in rows
            for value in (
                coerce_text(row.get("session_id")),
                coerce_text(row.get("conversation_id")),
            )
        ),
        source_label="Cursor",
    )

    redactor = Redactor()
    allocator = IdAllocator()
    warnings: list[str] = []
    staged: list[tuple[Any, int, ToolCall]] = []
    calls: dict[str, ToolCall] = {}
    stamps: list[Any] = []
    model: str | None = None
    tool_calls = 0
    results_joined = 0
    duplicate_snapshots = 0
    merged_without_start = 0
    incomplete_calls = 0
    ignored_records = 0
    derived_ids = 0

    for row_index, row in enumerate(rows):
        timestamp = coerce_datetime(first_present(row.get("timestamp"), row.get("ts")))
        if timestamp is not None:
            stamps.append(timestamp)

        if hook_mode:
            if not _is_hook_record(row):
                ignored_records += 1
                continue
            event = coerce_text(row.get("hook_event_name")) or ""
            source_id = (coerce_text(row.get("tool_use_id")) or "").strip()
            if not source_id:
                derived_ids += 1
                source_id = f"{session_id}:{row_index:04d}"
            call = calls.get(source_id)
            if event == "preToolUse":
                arguments = _arguments(row.get("tool_input"), redactor)
                if call is not None:
                    duplicate_snapshots += 1
                    if not call.arguments and arguments:
                        call.arguments = arguments
                    continue
                tool_calls += 1
                call = ToolCall(
                    id=allocator.allocate(source_id),
                    session_id=session_id,
                    tool=normalize_tool_name(coerce_text(row.get("tool_name")) or "unknown"),
                    arguments=arguments,
                    status="unknown",
                    timestamp=timestamp,
                    raw_index=row_index,
                )
                calls[source_id] = call
                staged.append((call.timestamp, row_index, call))
                continue

            if call is None:
                merged_without_start += 1
                tool_calls += 1
                call = ToolCall(
                    id=allocator.allocate(source_id),
                    session_id=session_id,
                    tool=normalize_tool_name(coerce_text(row.get("tool_name")) or "unknown"),
                    arguments=_arguments(row.get("tool_input"), redactor),
                    status="unknown",
                    timestamp=timestamp,
                    raw_index=row_index,
                )
                calls[source_id] = call
                staged.append((call.timestamp, row_index, call))
            elif call.status != "unknown":
                duplicate_snapshots += 1
                continue
            _hook_apply(call, row, redactor)
            results_joined += 1
            continue

        # ------------------------------------------------------------ CLI mode
        row_type = (coerce_text(row.get("type")) or "").strip().lower()
        if row_type == "system":
            model = model or coerce_text(row.get("model"))
            continue
        if row_type != "tool_call":
            ignored_records += 1
            continue

        inner = row.get("tool_call")
        if not isinstance(inner, dict) or not inner:
            raise TraceParseError(
                f"Cursor tool_call record {row_index} has no 'tool_call' object",
                hint=_NO_TOOLS_HINT,
            )
        tool_key = next(
            (key for key, value in inner.items() if isinstance(value, dict) and key.endswith("ToolCall")),
            None,
        ) or next(
            (key for key, value in inner.items() if isinstance(value, dict)),
            None,
        )
        if tool_key is None:
            raise TraceParseError(
                f"Cursor tool_call record {row_index} has no recognised tool payload",
                hint="Expected `tool_call: {\"readToolCall\": {...}}`.",
            )
        body = inner.get(tool_key) or {}
        source_id = (coerce_text(row.get("call_id")) or "").strip()
        if not source_id:
            derived_ids += 1
            source_id = f"{session_id}:{row_index:04d}"
        subtype = (coerce_text(row.get("subtype")) or "").strip().lower()
        arguments = _arguments(body.get("args"), redactor)

        call = calls.get(source_id)
        if subtype == "started":
            if call is not None:
                duplicate_snapshots += 1
                if not call.arguments and arguments:
                    call.arguments = arguments
                continue
            tool_calls += 1
            call = ToolCall(
                id=allocator.allocate(source_id),
                session_id=session_id,
                tool=_cli_tool_name(tool_key),
                arguments=arguments,
                status="unknown",
                timestamp=timestamp,
                raw_index=row_index,
            )
            calls[source_id] = call
            staged.append((call.timestamp, row_index, call))
            continue

        if call is None:
            tool_calls += 1
            merged_without_start += 1
            call = ToolCall(
                id=allocator.allocate(source_id),
                session_id=session_id,
                tool=_cli_tool_name(tool_key),
                arguments=arguments,
                status="unknown",
                timestamp=timestamp,
                raw_index=row_index,
            )
            calls[source_id] = call
            staged.append((call.timestamp, row_index, call))
        elif call.status != "unknown":
            duplicate_snapshots += 1
            continue
        if call.timestamp is None:
            call.timestamp = timestamp
        if _apply_cli_result(call, body.get("result"), redactor):
            results_joined += 1

    if tool_calls == 0:
        raise TraceParseError(_NO_TOOLS_MESSAGE, hint=_NO_TOOLS_HINT)

    incomplete_calls = sum(1 for _, _, call in staged if call.status == "unknown")
    if incomplete_calls:
        warnings.append(
            f"{incomplete_calls} tool call(s) had no completion record; status recorded as unknown"
        )
    if duplicate_snapshots:
        warnings.append(
            f"{duplicate_snapshots} duplicate Cursor record(s) were collapsed by call id"
        )
    if merged_without_start:
        warnings.append(
            f"{merged_without_start} completion record(s) had no start; the call was kept once"
        )
    if derived_ids:
        warnings.append(
            f"{derived_ids} Cursor record(s) had no tool id; deterministic ids were derived"
        )
    if hook_mode:
        warnings.append(
            "Cursor hooks only record tool calls they were configured to capture; "
            "unrecorded activity cannot be reconstructed"
        )

    events = finalise_events(staged)
    return TraceRun(
        run_id=make_run_id(
            source_path=source_path,
            session_id=session_id,
            event_count=len(events),
            payload={"records": len(rows), "sha256": short_hash(canonical_json(rows), 32)},
            digest=digest,
        ),
        session_id=session_id,
        title="Untitled session",
        source="cursor",
        model=model,
        agent_name="cursor",
        created_at=min(stamps) if stamps else None,
        imported_at=utc_now(),
        source_path=source_path,
        source_sha256=digest,
        events=events,
        warnings=unique_preserving_order(warnings),
        redactions=sorted(redactor.names),
        truncated=False,
        metadata={
            "adapter": "cursor",
            "shape": "hooks" if hook_mode else "cli",
            "records": len(rows),
            "tool_calls": tool_calls,
            "results_joined": results_joined,
            "incomplete_calls": incomplete_calls,
            "duplicate_snapshots": duplicate_snapshots,
            "merged_without_start": merged_without_start,
            "derived_ids": derived_ids,
            "ignored_records": ignored_records,
            "skipped_records": 0,
            "redaction_count": redactor.hits,
        },
    )
