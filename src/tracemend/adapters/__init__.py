"""Trace ingestion engine: detect a trace format and normalise it into a run.

The public surface is deliberately tiny:

``detect_format(payload)``
    Decide whether a decoded JSON payload is ``"generic"`` (TraceMend's own
    format), ``"opencode"`` (an OpenCode session export), ``"claude-code"`` (a
    Claude Code transcript row) or ``"cursor"`` (a Cursor CLI/hook record).
    Raises :class:`UnsupportedFormatError` when nothing can be recognised.

``load_trace_file(path, format=None, *, max_bytes=MAX_TRACE_BYTES)``
    Read a trace from disk through :func:`security.read_text_limited` (so the
    size ceiling is enforced), hash the raw bytes, parse the JSON/JSONL and
    return a :class:`TraceRun`. Invalid input raises :class:`TraceParseError`
    with a hint (JSONL errors always carry a line number).

``load_trace_text(text, *, format=None, source_path=None)``
    Same, for text already in memory.

``summarise(run, *, skipped=0, redaction_count=0)``
    Build the :class:`ImportSummary` the CLI/MCP layer reports back.

JSON documents keep the original behaviour: a single object is decoded first
and routed by :func:`detect_format`. Only when that fails *and* the first line is
a self-contained JSON object does the loader treat the input as JSON Lines
(bounded by :data:`adapters.jsonl.MAX_JSONL_RECORDS` and
``MAX_JSONL_LINE_BYTES``). Existing generic/OpenCode payloads therefore can
never be re-interpreted as JSONL, and a broken JSONL row is an error rather than
a silently skipped record.

Guarantees shared by every adapter:

* ``run_id`` is deterministic - ``run_<hash>`` over source, session id, event
  count and (file sha256 | payload hash) - so re-importing the same bytes is
  idempotent.
* Event ids are unique: the source id is kept when present, otherwise
  ``"<session_id>:<index:04d>"``; collisions gain ``-2``, ``-3`` ... suffixes.
* ``sequence`` is the post-sort index; events are ordered by
  ``(timestamp, original index)`` and untimed events keep their relative order.
* Secrets are redacted *before* anything is stored, and the hit names land in
  ``run.redactions``.
* ``truncated`` stays ``False`` - an oversized input raises
  :class:`TraceTooLargeError` instead of being silently cut.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..errors import TraceParseError, UnsupportedFormatError
from ..models import ImportSummary, TraceRun
from ..security import MAX_TRACE_BYTES, read_text_limited, redact_text, sha256_file
from .claude_code import matches_record as _matches_claude
from .claude_code import parse_claude_code
from .cursor import matches_record as _matches_cursor
from .cursor import parse_cursor
from .generic import parse_generic
from .jsonl import looks_like_jsonl, parse_jsonl
from .opencode import parse_opencode

__all__ = [
    "JSONL_FORMATS",
    "SUPPORTED_FORMATS",
    "detect_format",
    "detect_jsonl_format",
    "load_trace_file",
    "load_trace_text",
    "parse_claude_code",
    "parse_cursor",
    "parse_generic",
    "parse_opencode",
    "summarise",
]

#: Trace formats this build can ingest.
SUPPORTED_FORMATS: tuple[str, ...] = ("generic", "opencode", "claude-code", "cursor")
#: Formats that are read as JSON Lines / NDJSON.
JSONL_FORMATS: frozenset[str] = frozenset({"claude-code", "cursor"})

_SUPPORTED_HINT = (
    "Supported formats: 'generic' (TraceMend generic JSON with an 'events' array), "
    "'opencode' (an OpenCode session export with 'messages'/'info'), 'claude-code' "
    "(a Claude Code JSONL transcript) and 'cursor' (Cursor CLI stream-json or hook "
    "JSONL). Pass format='generic', 'opencode', 'claude-code' or 'cursor' to force "
    "a parser."
)

_PARSERS = {
    "generic": parse_generic,
    "opencode": parse_opencode,
    "claude-code": parse_claude_code,
    "cursor": parse_cursor,
}

#: Tolerated spellings for an explicit/MCP format override.
_FORMAT_ALIASES = {
    "claude": "claude-code",
    "claude_code": "claude-code",
    "claudecode": "claude-code",
    "cursor_cli": "cursor",
    "cursor-cli": "cursor",
    "cursor_ide": "cursor",
    "cursor-ide": "cursor",
    "cursor_hooks": "cursor",
    "cursor-hooks": "cursor",
}

#: Keys that only show up in OpenCode-style tool call entries.
_OPENCODE_MARKERS = frozenset({"state", "input", "time", "parts", "tool_call"})
#: Keys that only show up in generic TraceMend events.
_GENERIC_MARKERS = frozenset(
    {"arguments", "args", "agent_id", "duration_ms", "result_fingerprint", "parent_agent_id",
     "sequence", "tokens"}
)


def _normalise_format_name(name: str) -> str:
    key = name.strip().lower()
    return _FORMAT_ALIASES.get(key, key)


def _format_from_declared(declared: str) -> str:
    key = _normalise_format_name(declared)
    if "opencode" in key:
        return "opencode"
    if "claude" in key:
        return "claude-code"
    if "cursor" in key:
        return "cursor"
    if key.startswith("tracemend") or key in {"generic", "tracemend", "tracemend.generic"}:
        return "generic"
    if key in SUPPORTED_FORMATS:
        return key
    raise UnsupportedFormatError(
        f"unsupported trace format: {declared!r}",
        hint=_SUPPORTED_HINT,
    )


def _resolve_explicit_format(format: str | None) -> str | None:
    """Validate a caller-supplied format override."""
    if format is None:
        return None
    if not isinstance(format, str) or not format.strip():
        raise UnsupportedFormatError(
            "format override must be a non-empty string",
            hint=_SUPPORTED_HINT,
        )
    key = _normalise_format_name(format)
    if key not in SUPPORTED_FORMATS:
        raise UnsupportedFormatError(
            f"unsupported trace format: {format!r}",
            hint=_SUPPORTED_HINT,
        )
    return key


def _classify_tool_calls(calls: list[Any]) -> str:
    """Disambiguate the ``tool_calls`` key shared by generic and OpenCode."""
    opencode_score = 0
    generic_score = 0
    for entry in calls[:25]:
        if not isinstance(entry, dict):
            continue
        keys = set(entry)
        opencode_score += len(keys & _OPENCODE_MARKERS)
        generic_score += len(keys & _GENERIC_MARKERS)
    return "opencode" if opencode_score > generic_score else "generic"


def detect_format(payload: dict) -> str:
    """Return the adapter id for a decoded JSON trace payload.

    An explicit ``format`` field wins outright; otherwise the top-level keys are
    inspected. Existing generic/OpenCode shapes are checked first so a native
    Claude Code or Cursor marker can never steal them. Raises
    :class:`UnsupportedFormatError` when nothing matches.
    """
    if not isinstance(payload, dict):
        raise UnsupportedFormatError(
            f"trace root must be a JSON object, got {type(payload).__name__}",
            hint=_SUPPORTED_HINT,
        )

    declared = payload.get("format")
    if isinstance(declared, str) and declared.strip():
        return _format_from_declared(declared)

    if isinstance(payload.get("messages"), (list, dict)):
        return "opencode"
    if isinstance(payload.get("info"), dict):
        return "opencode"
    if isinstance(payload.get("events"), list):
        return "generic"
    if isinstance(payload.get("tool_calls"), list):
        return _classify_tool_calls(payload["tool_calls"])
    if _matches_claude(payload):
        return "claude-code"
    if _matches_cursor(payload):
        return "cursor"

    raise UnsupportedFormatError(
        "could not detect the trace format: expected an 'events' or 'tool_calls' "
        "array, OpenCode 'messages'/'info' keys, a Claude Code transcript row or a "
        "Cursor stream-json/hook record",
        hint=_SUPPORTED_HINT,
    )


def detect_jsonl_format(rows: list[dict]) -> str:
    """Identify a native adapter from decoded JSONL rows.

    Only rows recognised by a native adapter count; mixed or absent markers are a
    clear error rather than a guess.
    """
    sample = [row for row in rows[:50] if isinstance(row, dict)]
    claude_score = sum(1 for row in sample if _matches_claude(row))
    cursor_score = sum(1 for row in sample if _matches_cursor(row))
    if claude_score and not cursor_score:
        return "claude-code"
    if cursor_score and not claude_score:
        return "cursor"
    if claude_score and cursor_score:
        raise UnsupportedFormatError(
            "could not detect the JSONL format: the input mixes Claude Code and Cursor records",
            hint=_SUPPORTED_HINT,
        )
    raise UnsupportedFormatError(
        "could not detect the JSONL format: no Claude Code or Cursor record markers found",
        hint=_SUPPORTED_HINT,
    )


def _run_parser(
    resolved: str,
    payload: Any,
    *,
    source_path: str | None,
    digest: str | None,
) -> TraceRun:
    parser = _PARSERS[resolved]
    try:
        return parser(payload, source_path=source_path, digest=digest)
    except TraceParseError:
        raise
    except Exception as exc:  # pragma: no cover - defensive, shape-dependent
        detail, _ = redact_text(str(exc))
        raise TraceParseError(
            f"could not parse {resolved} trace: {detail}",
            hint="The trace did not match the expected export shape; "
            "re-export it or open an issue with the payload.",
        ) from exc


def _load_text(
    text: str,
    *,
    format: str | None,
    source_path: str | None,
    digest: str | None,
) -> TraceRun:
    if not isinstance(text, str):
        raise TraceParseError(
            f"trace text must be a string, got {type(text).__name__}",
            hint=_SUPPORTED_HINT,
        )
    stripped = text.strip()
    if not stripped:
        raise TraceParseError(
            "trace input is empty",
            hint="Point TraceMend at a JSON trace file or paste a session export.",
        )

    if format in JSONL_FORMATS:
        # A single pretty-printed record (or a JSON array of rows) is a valid
        # one-record transcript; everything else is decoded line by line.
        try:
            document = json.loads(stripped)
        except json.JSONDecodeError:
            document = None
        payload: Any = document if isinstance(document, (dict, list)) else parse_jsonl(text)
        return _run_parser(format, payload, source_path=source_path, digest=digest)

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as exc:
        if format is None and looks_like_jsonl(stripped):
            rows = parse_jsonl(text)
            resolved = detect_jsonl_format(rows)
            return _run_parser(resolved, rows, source_path=source_path, digest=digest)
        raise TraceParseError(
            f"invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}",
            hint="TraceMend expects a JSON object with double-quoted keys; "
            "check the file is complete and not truncated.",
        ) from exc

    if not isinstance(payload, dict):
        raise TraceParseError(
            f"trace root must be a JSON object, got {type(payload).__name__}",
            hint=_SUPPORTED_HINT,
        )

    resolved = format or detect_format(payload)
    return _run_parser(resolved, payload, source_path=source_path, digest=digest)


def load_trace_file(
    path: str | Path,
    format: str | None = None,
    *,
    max_bytes: int = MAX_TRACE_BYTES,
) -> TraceRun:
    """Read and parse a trace file from disk.

    The size ceiling is enforced by :func:`security.read_text_limited` before any
    parsing happens, and the raw file sha256 is folded into the deterministic
    ``run_id``.
    """
    resolved = _resolve_explicit_format(format)
    target = Path(path)
    text = read_text_limited(target, max_bytes)
    digest = sha256_file(target)
    return _load_text(
        text,
        format=resolved,
        source_path=str(target),
        digest=digest,
    )


def load_trace_text(
    text: str,
    *,
    format: str | None = None,
    source_path: str | None = None,
) -> TraceRun:
    """Parse a trace already held in memory (no size limit applies here)."""
    resolved = _resolve_explicit_format(format)
    return _load_text(text, format=resolved, source_path=source_path, digest=None)


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def summarise(
    run: TraceRun,
    *,
    skipped: int = 0,
    redaction_count: int = 0,
) -> ImportSummary:
    """Build the import summary reported by the CLI and the MCP server.

    ``skipped`` and ``redaction_count`` default to the counters the adapters
    recorded in ``run.metadata``; pass an explicit value to override (a value of
    ``0`` means "use the recorded count").
    """
    skipped_records = skipped or _as_int(run.metadata.get("skipped_records"))
    redactions = redaction_count or _as_int(run.metadata.get("redaction_count"))
    return ImportSummary(
        run_id=run.run_id,
        source=run.source,
        session_id=run.session_id,
        title=run.title,
        event_count=run.event_count,
        skipped_records=skipped_records,
        warnings=list(run.warnings),
        redactions_applied=redactions,
        truncated=run.truncated,
        source_path=run.source_path,
    )
