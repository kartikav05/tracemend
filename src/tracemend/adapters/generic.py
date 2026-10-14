"""Generic TraceMend JSON trace adapter.

This is TraceMend's canonical interchange shape: one JSON object describing an
agent session and the tool calls it made. Other adapters translate foreign
exports (OpenCode, etc.) into the same model.

.. code-block:: json

    {
      "format": "tracemend.generic",
      "version": 1,
      "session": {
        "id": "session_fix-payment-api-bug",
        "title": "Fix payment API bug",
        "agent": "opencode-coding-agent",
        "model": "claude-sonnet-4",
        "created_at": "2026-10-13T09:12:00Z"
      },
      "events": [
        {
          "id": "call_001",
          "agent_id": "main",
          "parent_agent_id": null,
          "tool": "grep",
          "arguments": {"pattern": "x"},
          "status": "success",
          "timestamp": "2026-10-13T09:12:04Z",
          "duration_ms": 120,
          "error": null,
          "tokens": {"input_tokens": 10, "output_tokens": 2},
          "cost": 0.001,
          "result_fingerprint": "fp_grep_x_a1",
          "modified_files": [],
          "output": "raw text",
          "output_excerpt": null
        }
      ]
    }

Tolerated variations (every one of them is optional):

* ``session`` may be omitted entirely; documented defaults are used.
* ``tokens`` and ``token_usage`` are accepted interchangeably, and
  ``input_tokens``/``output_tokens`` may also sit at the top level of an event.
* ``timestamp`` may be an ISO-8601 string or a numeric epoch (seconds or ms).
* ``events`` and ``tool_calls`` are both accepted as the event-array key.
* ``duration_ms``, ``tokens`` and ``cost`` stay ``None`` when absent - TraceMend
  never fabricates a measurement it did not observe.

Parsing is tolerant but never silent: records that cannot be read are counted
as skipped, and anything ambiguous is reported through ``run.warnings``.

The helpers below (``coerce_*``, ``Redactor``, ``IdAllocator``,
``build_event``, ``finalise_events``) are shared with the OpenCode adapter so
both adapters normalise identically.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..errors import TraceParseError
from ..models import (
    TokenUsage,
    ToolCall,
    TraceRun,
    canonical_json,
    coerce_datetime,
    normalize_status,
    short_hash,
    utc_now,
)
from ..security import limit_preview, redact_text, redact_value, unique_preserving_order

_MISSING = object()
_MIN_TS = datetime.min.replace(tzinfo=UTC)

#: Values above these thresholds are epoch timestamps rather than durations.
_EPOCH_MS = 1e11
_EPOCH_SECONDS = 1e6


def first_present(*values: Any) -> Any:
    """Return the first value that is not ``None``."""
    for value in values:
        if value is not None:
            return value
    return None


def coerce_text(value: Any) -> str | None:
    """Best-effort string coercion that never raises."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return canonical_json(value)
    if isinstance(value, float) and value != value:
        return None
    return str(value)


def coerce_int(value: Any) -> int | None:
    """Coerce a JSON scalar to ``int``; booleans and junk become ``None``."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return round(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            pass
        try:
            return round(float(text))
        except ValueError:
            return None
    return None


def coerce_float(value: Any) -> float | None:
    """Coerce a JSON scalar to ``float``; booleans and junk become ``None``."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except (OverflowError, ValueError):
            return None
        if number != number or number in (float("inf"), float("-inf")):
            return None
        return number
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return float(text)
        except ValueError:
            return None
    return None


class Redactor:
    """Applies TraceMend redaction rules and accounts for every hit."""

    def __init__(self) -> None:
        self.names: set[str] = set()
        self.hits = 0

    def text(self, value: Any) -> str | None:
        if value is None:
            return None
        raw = value if isinstance(value, str) else (coerce_text(value) or "")
        cleaned, hits = redact_text(raw)
        self._record(hits)
        return cleaned

    def value(self, value: Any) -> Any:
        cleaned, hits = redact_value(value)
        self._record(hits)
        return cleaned

    def _record(self, hits: list[str]) -> None:
        if hits:
            self.names.update(hits)
            self.hits += len(hits)


class IdAllocator:
    """Hands out unique event ids, suffixing collisions with ``-2``, ``-3`` ..."""

    def __init__(self) -> None:
        self._used: set[str] = set()

    def allocate(self, base: str) -> str:
        candidate = (base or "").strip() or "event"
        if candidate not in self._used:
            self._used.add(candidate)
            return candidate
        suffix = 2
        while f"{candidate}-{suffix}" in self._used:
            suffix += 1
        unique = f"{candidate}-{suffix}"
        self._used.add(unique)
        return unique


def timestamp_from_time(raw: Any) -> datetime | None:
    """Read a timestamp from either a ``{"start": ...}`` box or a bare value."""
    if isinstance(raw, dict):
        return coerce_datetime(first_present(raw.get("start"), raw.get("created"), raw.get("end")))
    return coerce_datetime(raw)


def duration_from_time(raw: Any) -> int | None:
    """Millisecond duration from a start/end style time box.

    Two shapes are understood:

    * the documented ``{"start": ..., "end": ...}`` pair, and
    * the ``{"created": ..., "ran": ..., "completed": ...}`` box written by
      current OpenCode v2 sessions, where ``ran`` is the moment execution began
      rather than a duration.

    OpenCode writes epoch milliseconds, but sanitized/older exports can carry
    epoch seconds or a plain millisecond delta, so the unit is inferred from the
    magnitude of the values. Returns ``None`` when either bound is missing.
    """
    if not isinstance(raw, dict):
        return None
    start = coerce_float(first_present(raw.get("start"), raw.get("created"), raw.get("ran")))
    end = coerce_float(first_present(raw.get("end"), raw.get("completed")))
    if start is None or end is None:
        return None
    delta = end - start
    if delta < 0:
        return None
    if start > _EPOCH_MS or end > _EPOCH_MS:
        return round(delta)
    if start > _EPOCH_SECONDS:
        return round(delta * 1000)
    return round(delta)


def extract_token_usage(record: dict[str, Any]) -> TokenUsage | None:
    """Read token usage from ``tokens``/``token_usage`` or top-level fields."""
    raw = first_present(record.get("tokens"), record.get("token_usage"))
    input_tokens: int | None = None
    output_tokens: int | None = None
    if isinstance(raw, dict):
        input_tokens = coerce_int(first_present(raw.get("input_tokens"), raw.get("input")))
        output_tokens = coerce_int(first_present(raw.get("output_tokens"), raw.get("output")))
    if input_tokens is None:
        input_tokens = coerce_int(record.get("input_tokens"))
    if output_tokens is None:
        output_tokens = coerce_int(record.get("output_tokens"))
    if input_tokens is None and output_tokens is None:
        return None
    return TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens)


def make_run_id(
    *,
    source_path: str | None,
    session_id: str,
    event_count: int,
    payload: dict[str, Any],
    digest: str | None = None,
) -> str:
    """Deterministic run id: same bytes -> same id (idempotent re-import)."""
    source = source_path or ""
    seed = digest or short_hash(canonical_json(payload), 32)
    return f"run_{short_hash(f'{source}|{session_id}|{event_count}|{seed}')}"


def finalise_events(staged: list[tuple[datetime | None, int, ToolCall]]) -> list[ToolCall]:
    """Sort by (timestamp, original index) and assign post-sort ``sequence``."""
    ordered = sorted(
        staged,
        key=lambda item: (0 if item[0] is not None else 1, item[0] or _MIN_TS, item[1]),
    )
    events: list[ToolCall] = []
    for sequence, (_timestamp, _index, call) in enumerate(ordered):
        call.sequence = sequence
        events.append(call)
    return events


def build_event(
    record: dict[str, Any],
    *,
    index: int,
    session_id: str,
    allocator: IdAllocator,
    redactor: Redactor,
    warnings: list[str],
) -> ToolCall:
    """Map one lenient mapping (generic event or OpenCode legacy tool call)."""
    source_id = coerce_text(record.get("id"))
    base_id = (source_id or "").strip() or f"{session_id}:{index:04d}"

    tool_name: str | None = None
    for candidate in (
        record.get("tool"),
        record.get("name"),
        record.get("tool_name"),
        record.get("toolName"),
    ):
        text = coerce_text(candidate)
        if text and text.strip():
            tool_name = text.strip()
            break
    if tool_name is None:
        tool_name = "unknown"
        warnings.append(f"event {index}: no tool name found; recorded as 'unknown'")

    arguments = first_present(record.get("arguments"), record.get("args"), record.get("input"))
    if arguments is None:
        arguments = {}
    arguments = redactor.value(arguments)

    error_value = first_present(record.get("error"), record.get("error_message"))
    raw_status = record.get("status")
    if raw_status is None and error_value:
        raw_status = "error"

    time_value = record.get("time")
    duration_ms = coerce_int(record.get("duration_ms"))
    if duration_ms is None:
        duration_ms = coerce_int(record.get("duration"))
    if duration_ms is None:
        duration_ms = duration_from_time(time_value)

    timestamp = coerce_datetime(first_present(record.get("timestamp"), record.get("ts")))
    if timestamp is None:
        timestamp = timestamp_from_time(time_value)

    raw_output = first_present(record.get("output"), record.get("result"))
    if raw_output is not None:
        excerpt = limit_preview(redactor.text(coerce_text(raw_output)) or "") or None
    else:
        explicit = record.get("output_excerpt")
        excerpt = limit_preview(redactor.text(coerce_text(explicit)) or "") or None

    raw_files = record.get("modified_files")
    if isinstance(raw_files, str):
        modified_files = [raw_files]
    elif isinstance(raw_files, list):
        modified_files = [text for text in (coerce_text(item) for item in raw_files) if text]
    else:
        modified_files = []

    agent_id = coerce_text(first_present(record.get("agent_id"), record.get("agent"))) or "main"
    parent_agent_id = coerce_text(record.get("parent_agent_id")) or None

    return ToolCall(
        id=allocator.allocate(base_id),
        session_id=session_id,
        agent_id=agent_id.strip() or "main",
        parent_agent_id=parent_agent_id,
        tool=tool_name,
        arguments=arguments,
        status=normalize_status(raw_status),
        timestamp=timestamp,
        duration_ms=duration_ms,
        error=redactor.text(error_value),
        token_usage=extract_token_usage(record),
        cost=coerce_float(record.get("cost")),
        result_fingerprint=coerce_text(
            first_present(record.get("result_fingerprint"), record.get("fingerprint"))
        ),
        modified_files=modified_files,
        output_excerpt=excerpt,
        raw_index=index,
    )


def parse_generic(
    payload: dict[str, Any],
    *,
    source_path: str | None = None,
    digest: str | None = None,
) -> TraceRun:
    """Parse a generic TraceMend JSON payload into a :class:`TraceRun`."""
    if not isinstance(payload, dict):
        raise TraceParseError(
            f"generic trace must be a JSON object, got {type(payload).__name__}",
            hint="TraceMend's generic format is a single JSON object with a 'session' and an 'events' array.",
        )

    warnings: list[str] = []
    raw_session = payload.get("session")
    if raw_session is None:
        session: dict[str, Any] = {}
    elif isinstance(raw_session, dict):
        session = raw_session
    else:
        session = {}
        warnings.append("session block is not a JSON object; defaults applied")

    session_id = (coerce_text(session.get("id")) or "").strip() or "session_unknown"
    title = (coerce_text(session.get("title")) or "").strip() or "Untitled session"
    model = coerce_text(session.get("model"))
    agent_name = coerce_text(first_present(session.get("agent"), session.get("agent_name")))
    created_at = coerce_datetime(first_present(session.get("created_at"), session.get("created")))

    events_key: str | None = None
    raw_events: Any = _MISSING
    for key in ("events", "tool_calls"):
        if payload.get(key) is not None:
            events_key = key
            raw_events = payload[key]
            break
    if raw_events is _MISSING:
        warnings.append("no 'events' or 'tool_calls' array found; imported with 0 events")
        raw_events = []
    elif not isinstance(raw_events, list):
        raise TraceParseError(
            f"'{events_key}' must be a JSON array, got {type(raw_events).__name__}",
            hint="Wrap the tool calls in a JSON array, e.g. \"events\": [ ... ].",
        )

    redactor = Redactor()
    allocator = IdAllocator()
    staged: list[tuple[datetime | None, int, ToolCall]] = []
    skipped = 0

    for index, record in enumerate(raw_events):
        if not isinstance(record, dict):
            skipped += 1
            warnings.append(f"event {index}: skipped non-object entry ({type(record).__name__})")
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
            warnings.append(f"event {index}: skipped unreadable record ({exc.__class__.__name__})")
            continue
        staged.append((call.timestamp, index, call))

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
        source="generic",
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
            "adapter": "generic",
            "event_key": events_key or "events",
            "version": payload.get("version"),
            "skipped_records": skipped,
            "redaction_count": redactor.hits,
        },
    )
