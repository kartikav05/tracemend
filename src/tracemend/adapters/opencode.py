"""OpenCode session export adapter.

The OpenCode export command changed between releases, so both documented
invocations are handled defensively:

* legacy CLI: ``opencode export <session-id> --sanitize``
* V2 CLI:     ``opencode session export <session-id> --sanitize``

Recognised payload shapes
-------------------------
1. V2 session export::

       {"info": {"id": "ses_...", "title": "..."}, "messages": [ ... ]}

2. Message/part export (what ``session export`` writes)::

       {"messages": [
          {"role": "assistant",
           "parts": [{"type": "tool", "tool": "bash",
                      "state": {"status": "completed",
                                "input": {"command": "pytest -q"},
                                "output": "6 passed",
                                "time": {"start": 1730000000000, "end": 1730000002300}}}]}]}

3. Flat legacy export::

       {"tool_calls": [{"tool": "bash", "input": {...}, "state": {...}}]}

Only ``parts`` of ``type == "tool"`` on assistant/tool messages become events.
Fields a sanitized export removed are reported in ``run.warnings`` rather than
invented: TraceMend never fabricates tool results, timings or tokens.

Adapter notes
-------------
* Event ids are ``"<message id>:<part index>"`` so re-imports are stable and
  collisions across parts cannot happen.
* ``state.time.start``/``state.time.end`` are epoch values; OpenCode writes
  milliseconds, and a plain millisecond delta is used when the bounds look like
  epoch seconds or an already-relative delta (see :func:`duration_from_time`).
* OpenCode attaches token totals to whole messages, not to individual tool
  parts, so per-part ``token_usage`` stays ``None`` instead of double counting
  the message total.
* Anything unreadable is counted as a skipped record and surfaced in
  ``run.warnings``; unexpected shape errors are wrapped in ``TraceParseError``.
"""

from __future__ import annotations

from typing import Any

from ..errors import TraceParseError
from ..models import ToolCall, TraceRun, coerce_datetime, normalize_status, utc_now
from ..security import limit_preview, unique_preserving_order
from .generic import (
    IdAllocator,
    Redactor,
    build_event,
    coerce_float,
    coerce_text,
    duration_from_time,
    extract_token_usage,
    finalise_events,
    first_present,
    make_run_id,
    timestamp_from_time,
)

_NO_TOOLS_HINT = (
    "Export a session that actually ran tools: `opencode export <session-id> --sanitize` "
    "(legacy CLI) or `opencode session export <session-id> --sanitize` (V2 CLI)."
)
_NO_TOOLS_MESSAGE = "the OpenCode export contained no tool calls"
_SANITIZED_WARNING = (
    "sanitized export: tool results unavailable; result-fingerprint based detectors "
    "will be low confidence"
)


def _model_name(value: Any) -> str | None:
    """OpenCode stores the model as either a string or ``{"id": ...}``."""
    if isinstance(value, dict):
        return coerce_text(first_present(value.get("id"), value.get("modelID"), value.get("name")))
    return coerce_text(value)


def _as_list(value: Any) -> list[Any]:
    """Normalise a list, a single object, or ``None`` into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _declares_sanitized(payload: dict[str, Any], info: dict[str, Any]) -> bool:
    for source in (payload, info):
        if source.get("sanitized") is True or source.get("sanitize") is True:
            return True
    return False


#: Keys that carry a path inside an OpenCode ``files`` entry object.
_MODIFIED_FILE_KEYS = ("file", "filePath", "path", "filename", "name")
#: Longest value kept from a ``files`` entry; real paths are far shorter, so a
#: longer value means the entry is not a path.
_MAX_MODIFIED_PATH_CHARS = 4096


def _modified_files(state: dict[str, Any]) -> list[str]:
    """File paths a call is known to have written.

    OpenCode v2 stores ``{"file": ..., "patch": ...}`` objects in
    ``state.metadata.files``. Only the path is kept: the embedded patch text is
    unbounded and must never be copied verbatim onto the event, both because it
    would bloat the store and because it would make TM003, which compares reads
    against ``modified_files``, match on a blob instead of a path.
    """
    candidates = state.get("files")
    if candidates is None:
        metadata = state.get("metadata")
        if isinstance(metadata, dict):
            candidates = metadata.get("files")
    if isinstance(candidates, str):
        candidates = [candidates]
    if not isinstance(candidates, list):
        return []

    paths: list[str] = []
    for item in candidates:
        if isinstance(item, dict):
            raw_path = first_present(
                *(item.get(key) for key in _MODIFIED_FILE_KEYS)
            )
            text = coerce_text(raw_path)
        else:
            text = coerce_text(item)
        text = (text or "").strip()
        if text and len(text) <= _MAX_MODIFIED_PATH_CHARS:
            paths.append(text)
    return unique_preserving_order(paths)


def _build_tool_part(
    part: dict[str, Any],
    *,
    index: int,
    message_id: str,
    part_index: int,
    agent_id: str,
    session_id: str,
    message_timestamp: Any,
    allocator: IdAllocator,
    redactor: Redactor,
    warnings: list[str],
) -> tuple[ToolCall, bool]:
    """Map one ``type == "tool"`` message part to a :class:`ToolCall`."""
    state = part.get("state") if isinstance(part.get("state"), dict) else {}

    tool_name: str | None = None
    for candidate in (
        part.get("tool"),
        part.get("toolName"),
        part.get("name"),
        state.get("tool"),
    ):
        text = coerce_text(candidate)
        if text and text.strip():
            tool_name = text.strip()
            break
    if tool_name is None:
        tool_name = "unknown"
        warnings.append(f"{message_id}: part {part_index} has no tool name; recorded as 'unknown'")

    arguments = first_present(state.get("input"), part.get("input"), part.get("arguments"))
    if arguments is None:
        arguments = {}
    arguments = redactor.value(arguments)

    error_value = first_present(state.get("error"), part.get("error"))
    raw_status = state.get("status") if "status" in state else part.get("status")
    if raw_status is None and error_value:
        raw_status = "error"

    time_value = state.get("time") if isinstance(state.get("time"), dict) else part.get("time")
    timestamp = timestamp_from_time(time_value) or timestamp_from_time(message_timestamp)
    duration_ms = duration_from_time(time_value)

    raw_output = first_present(
        state.get("output"), part.get("output"), state.get("result"), part.get("result")
    )
    if raw_output is not None:
        excerpt = limit_preview(redactor.text(coerce_text(raw_output)) or "") or None
    else:
        explicit = part.get("output_excerpt")
        excerpt = limit_preview(redactor.text(coerce_text(explicit)) or "") or None

    fingerprint = coerce_text(
        first_present(part.get("result_fingerprint"), state.get("result_fingerprint"))
    )

    call = ToolCall(
        id=allocator.allocate(f"{message_id}:{part_index:04d}"),
        session_id=session_id,
        agent_id=(agent_id or "").strip() or "main",
        parent_agent_id=coerce_text(
            first_present(part.get("parent_agent_id"), state.get("parent_agent_id"))
        )
        or None,
        tool=tool_name,
        arguments=arguments,
        status=normalize_status(raw_status),
        timestamp=timestamp,
        duration_ms=duration_ms,
        error=redactor.text(error_value),
        token_usage=extract_token_usage(state) or extract_token_usage(part),
        cost=coerce_float(first_present(state.get("cost"), part.get("cost"))),
        result_fingerprint=fingerprint,
        modified_files=_modified_files(state),
        output_excerpt=excerpt,
        raw_index=index,
    )
    has_result = raw_output is not None or bool(fingerprint)
    return call, has_result


def parse_opencode(
    payload: dict[str, Any],
    *,
    source_path: str | None = None,
    digest: str | None = None,
) -> TraceRun:
    """Parse an OpenCode session export into a :class:`TraceRun`."""
    if not isinstance(payload, dict):
        raise TraceParseError(
            f"OpenCode export must be a JSON object, got {type(payload).__name__}",
            hint=_NO_TOOLS_HINT,
        )

    warnings: list[str] = []
    info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
    session_id = (
        coerce_text(first_present(info.get("id"), payload.get("session_id"), payload.get("id")))
        or ""
    ).strip() or "session_unknown"
    title = (
        coerce_text(first_present(info.get("title"), payload.get("title"))) or ""
    ).strip() or "Untitled session"
    model = _model_name(first_present(info.get("model"), payload.get("model")))
    agent_name = coerce_text(
        first_present(info.get("agent"), info.get("mode"), payload.get("agent"))
    )
    created_at = timestamp_from_time(info.get("time")) or coerce_datetime(
        first_present(info.get("created_at"), payload.get("created_at"))
    )

    redactor = Redactor()
    allocator = IdAllocator()
    staged: list[tuple[Any, int, ToolCall]] = []
    skipped = 0
    tool_parts = 0
    result_bearing = 0

    messages = payload.get("messages")
    tool_calls = payload.get("tool_calls")

    if messages is not None:
        shape = "messages"
        for message_index, message in enumerate(_as_list(messages)):
            if not isinstance(message, dict):
                skipped += 1
                warnings.append(f"message {message_index}: skipped non-object entry")
                continue
            message_info = message.get("info") if isinstance(message.get("info"), dict) else {}
            role = (
                coerce_text(first_present(message.get("role"), message_info.get("role"))) or ""
            ).strip().lower()
            if role and role not in ("assistant", "tool"):
                continue
            message_id = (
                coerce_text(first_present(message.get("id"), message_info.get("id"))) or ""
            ).strip() or f"msg-{message_index:04d}"
            agent_id = (
                coerce_text(
                    first_present(
                        message_info.get("agent"),
                        message_info.get("mode"),
                        message.get("agent"),
                        message.get("mode"),
                        agent_name,
                    )
                )
                or ""
            ).strip() or "main"
            message_timestamp = timestamp_from_time(message_info.get("time")) or coerce_datetime(
                first_present(message_info.get("created_at"), message.get("created_at"))
            )
            for part_index, part in enumerate(_as_list(message.get("parts"))):
                if not isinstance(part, dict):
                    skipped += 1
                    continue
                if (coerce_text(part.get("type")) or "").strip().lower() != "tool":
                    continue
                order_index = len(staged)
                try:
                    call, has_result = _build_tool_part(
                        part,
                        index=order_index,
                        message_id=message_id,
                        part_index=part_index,
                        agent_id=agent_id,
                        session_id=session_id,
                        message_timestamp=message_timestamp,
                        allocator=allocator,
                        redactor=redactor,
                        warnings=warnings,
                    )
                except TraceParseError:
                    raise
                except Exception as exc:  # pragma: no cover - defensive, shape-dependent
                    skipped += 1
                    warnings.append(
                        f"{message_id}: part {part_index} skipped ({exc.__class__.__name__})"
                    )
                    continue
                tool_parts += 1
                if has_result:
                    result_bearing += 1
                staged.append((call.timestamp, order_index, call))
    elif tool_calls is not None:
        shape = "tool_calls"
        for index, record in enumerate(_as_list(tool_calls)):
            if not isinstance(record, dict):
                skipped += 1
                continue
            try:
                call = build_event(
                    record,
                    index=index,
                    session_id=session_id,
                    allocator=allocator,
                    redactor=redactor,
                    warnings=warnings,
                )
            except TraceParseError:
                raise
            except Exception as exc:  # pragma: no cover - defensive, shape-dependent
                skipped += 1
                warnings.append(f"tool call {index}: skipped ({exc.__class__.__name__})")
                continue
            tool_parts += 1
            if call.output_excerpt or call.result_fingerprint:
                result_bearing += 1
            staged.append((call.timestamp, index, call))
    else:
        raise TraceParseError(_NO_TOOLS_MESSAGE, hint=_NO_TOOLS_HINT)

    if tool_parts == 0:
        raise TraceParseError(_NO_TOOLS_MESSAGE, hint=_NO_TOOLS_HINT)

    if _declares_sanitized(payload, info) or result_bearing == 0:
        warnings.append(_SANITIZED_WARNING)

    events = finalise_events(staged)
    return TraceRun(
        run_id=make_run_id(
            source_path=source_path,
            session_id=session_id,
            event_count=len(events),
            payload=payload,
            digest=digest,
        ),
        session_id=session_id,
        title=title,
        source="opencode",
        model=model,
        agent_name=agent_name,
        created_at=created_at,
        imported_at=utc_now(),
        source_path=source_path,
        source_sha256=digest,
        events=events,
        warnings=unique_preserving_order(warnings),
        redactions=sorted(redactor.names),
        truncated=False,
        metadata={
            "adapter": "opencode",
            "shape": shape,
            "tool_parts": tool_parts,
            "skipped_records": skipped,
            "redaction_count": redactor.hits,
        },
    )
