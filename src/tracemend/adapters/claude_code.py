"""Claude Code local transcript (JSONL) adapter.

Parses documented assistant/user rows with tool_use/tool_result blocks.
Streaming snapshots deduplicated by tool id. Results joined by tool_use_id;
missing results keep status unknown. Message-level usage warned, not copied.
agentId/parentAgentId preserved; parentUuid is a message link, not an agent.
Prose never stored — only redacted args and bounded result previews.
"""

from __future__ import annotations

from typing import Any

from ..errors import TraceParseError
from ..models import ToolCall, TraceRun, canonical_json, coerce_datetime, short_hash, utc_now
from ..security import limit_preview, unique_preserving_order
from .generic import IdAllocator, Redactor, coerce_text, finalise_events, make_run_id
from .jsonl import as_rows, single_session_id

_NO_TOOLS_MESSAGE = "the Claude Code transcript contained no tool_use blocks"
_NO_TOOLS_HINT = (
    "Use a Claude Code transcript that ran tools (JSONL rows with "
    "'type': 'assistant'/'user' and tool_use/tool_result content). A plain chat "
    "transcript has no tool evidence, and TraceMend never infers tool calls from prose."
)

_USAGE_WARNING = (
    "Claude Code reports token usage per assistant message; per-call tokens are unavailable"
)
_PARENT_WARNING = (
    "parentUuid links messages rather than agents; parent agent ids were kept only "
    "when explicitly provided"
)


def matches_record(record: Any) -> bool:
    """True for a single Claude Code transcript row (used by format detection)."""
    if not isinstance(record, dict):
        return False
    message = record.get("message")
    if isinstance(record.get("sessionId"), str) and isinstance(message, dict):
        return True
    return (
        record.get("type") in {"assistant", "user"}
        and isinstance(message, dict)
        and isinstance(message.get("content"), list)
        and isinstance(record.get("uuid"), str)
    )


def _is_error_flag(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"true", "1", "yes", "error"}


def _content_text(value: Any) -> str | None:
    """Flatten tool_result content (string or text blocks) without message prose."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = [
            coerce_text(block.get("text"))
            for block in value
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        joined = "\n".join(part for part in parts if part)
        return joined or None
    if isinstance(value, dict):
        return coerce_text(value)
    return coerce_text(value)


def _clean_arguments(value: Any, redactor: Redactor) -> dict[str, Any]:
    """Redact a tool input and keep it a mapping without losing evidence."""
    if value is None:
        return {}
    cleaned = redactor.value(value)
    if isinstance(cleaned, dict):
        return cleaned
    return {"_value": cleaned}


def _apply_result(
    call: ToolCall,
    block: dict[str, Any],
    *,
    redactor: Redactor,
) -> None:
    """Join one tool_result block onto its call."""
    content = _content_text(block.get("content"))
    if content is not None:
        excerpt = limit_preview(redactor.text(content) or "") or None
        call.output_excerpt = excerpt
    else:
        excerpt = None
    call.status = "error" if _is_error_flag(block.get("is_error")) else "success"
    if call.status == "error":
        call.error = excerpt


def parse_claude_code(
    payload: Any,
    *,
    source_path: str | None = None,
    digest: str | None = None,
) -> TraceRun:
    """Parse a Claude Code JSONL transcript (one row or a row list)."""
    rows = as_rows(payload, source_label="Claude Code")
    session_id = single_session_id(
        (coerce_text(row.get("sessionId")) for row in rows),
        source_label="Claude Code",
    )

    redactor = Redactor()
    allocator = IdAllocator()
    warnings: list[str] = []
    staged: list[tuple[Any, int, ToolCall]] = []
    calls_by_id: dict[str, ToolCall] = {}
    pending_results: dict[str, dict[str, Any]] = {}
    stamps: list[Any] = []

    model: str | None = None
    saw_usage = False
    saw_parent_uuid = False
    duplicate_snapshots = 0
    results_joined = 0
    orphan_results = 0
    ignored_records = 0
    tool_uses = 0

    for row_index, row in enumerate(rows):
        row_type = (coerce_text(row.get("type")) or "").strip().lower()
        if row_type == "assistant":
            message = row.get("message") if isinstance(row.get("message"), dict) else {}
            model = model or coerce_text(message.get("model"))
            if isinstance(message.get("usage"), dict):
                saw_usage = True
            if coerce_text(row.get("parentUuid")):
                saw_parent_uuid = True

            agent_id = coerce_text(row.get("agentId")) or "main"
            parent_agent_id = coerce_text(row.get("parentAgentId"))
            timestamp = coerce_datetime(row.get("timestamp"))
            if timestamp is not None:
                stamps.append(timestamp)

            for block_index, block in enumerate(message.get("content") or []):
                if not isinstance(block, dict):
                    continue
                if (coerce_text(block.get("type")) or "").strip().lower() != "tool_use":
                    continue
                tool_uses += 1
                source_id = (coerce_text(block.get("id")) or "").strip()
                tool_name = (coerce_text(block.get("name")) or "").strip()
                if not tool_name:
                    tool_name = "unknown"
                    warnings.append("a tool_use block had no tool name; recorded as 'unknown'")
                raw_input = block.get("input")
                arguments = _clean_arguments(raw_input, redactor)

                if source_id:
                    existing = calls_by_id.get(source_id)
                    if existing is not None:
                        duplicate_snapshots += 1
                        if not existing.arguments and arguments:
                            existing.arguments = arguments
                        continue

                base_id = source_id or f"{session_id}:{row_index:04d}:{block_index:04d}"
                call = ToolCall(
                    id=allocator.allocate(base_id),
                    session_id=session_id,
                    agent_id=agent_id.strip() or "main",
                    parent_agent_id=parent_agent_id or None,
                    tool=tool_name,
                    arguments=arguments,
                    status="unknown",
                    timestamp=timestamp,
                    raw_index=len(staged),
                )
                pending = pending_results.pop(source_id, None) if source_id else None
                if pending is not None:
                    _apply_result(call, pending, redactor=redactor)
                    results_joined += 1
                if source_id:
                    calls_by_id[source_id] = call
                staged.append((call.timestamp, len(staged), call))

        elif row_type == "user":
            timestamp = coerce_datetime(row.get("timestamp"))
            if timestamp is not None:
                stamps.append(timestamp)
            message = row.get("message") if isinstance(row.get("message"), dict) else {}
            for block in message.get("content") or []:
                if not isinstance(block, dict):
                    continue
                if (coerce_text(block.get("type")) or "").strip().lower() != "tool_result":
                    continue
                tool_use_id = (coerce_text(block.get("tool_use_id")) or "").strip()
                call = calls_by_id.get(tool_use_id) if tool_use_id else None
                if call is None:
                    if tool_use_id:
                        pending_results.setdefault(tool_use_id, block)
                    else:
                        orphan_results += 1
                    continue
                _apply_result(call, block, redactor=redactor)
                results_joined += 1
        else:
            ignored_records += 1

    if tool_uses == 0:
        raise TraceParseError(_NO_TOOLS_MESSAGE, hint=_NO_TOOLS_HINT)

    orphan_results += len(pending_results)
    incomplete_calls = sum(1 for _, _, call in staged if call.status == "unknown")

    if duplicate_snapshots:
        warnings.append(
            f"{duplicate_snapshots} duplicate streaming snapshot(s) of tool_use blocks "
            "were collapsed by tool id"
        )
    if incomplete_calls:
        warnings.append(
            f"{incomplete_calls} tool call(s) had no tool_result; status recorded as unknown"
        )
    if orphan_results:
        warnings.append(
            f"{orphan_results} tool_result block(s) had no matching tool_use and were ignored"
        )
    if saw_usage:
        warnings.append(_USAGE_WARNING)
    if saw_parent_uuid:
        warnings.append(_PARENT_WARNING)

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
        source="claude-code",
        model=model,
        agent_name="claude-code",
        created_at=min(stamps) if stamps else None,
        imported_at=utc_now(),
        source_path=source_path,
        source_sha256=digest,
        events=events,
        warnings=unique_preserving_order(warnings),
        redactions=sorted(redactor.names),
        truncated=False,
        metadata={
            "adapter": "claude-code",
            "shape": "jsonl",
            "records": len(rows),
            "tool_uses": tool_uses,
            "results_joined": results_joined,
            "incomplete_calls": incomplete_calls,
            "duplicate_snapshots": duplicate_snapshots,
            "orphan_results": orphan_results,
            "ignored_records": ignored_records,
            "skipped_records": 0,
            "redaction_count": redactor.hits,
        },
    )
