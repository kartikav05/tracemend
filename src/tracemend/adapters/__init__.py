"""Trace ingestion engine: detect a trace format and normalise it into a run.

The public surface is deliberately tiny:

``detect_format(payload)``
    Decide whether a decoded JSON payload is ``"generic"`` (TraceMend's own
    format) or ``"opencode"`` (an OpenCode session export). Raises
    :class:`UnsupportedFormatError` when neither can be recognised.

``load_trace_file(path, format=None, *, max_bytes=MAX_TRACE_BYTES)``
    Read a trace from disk through :func:`security.read_text_limited` (so the
    size ceiling is enforced), hash the raw bytes, parse the JSON and return a
    :class:`TraceRun`. Invalid JSON raises :class:`TraceParseError` with a hint.

``load_trace_text(text, *, format=None, source_path=None)``
    Same, for text already in memory.

``summarise(run, *, skipped=0, redaction_count=0)``
    Build the :class:`ImportSummary` the CLI/MCP layer reports back.

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
from ..security import MAX_TRACE_BYTES, read_text_limited, sha256_file
from .generic import parse_generic
from .opencode import parse_opencode

__all__ = [
    "SUPPORTED_FORMATS",
    "detect_format",
    "load_trace_file",
    "load_trace_text",
    "parse_generic",
    "parse_opencode",
    "summarise",
]

#: Trace formats this build can ingest.
SUPPORTED_FORMATS: tuple[str, ...] = ("generic", "opencode")

_SUPPORTED_HINT = (
    "Supported formats: 'generic' (TraceMend generic JSON with an 'events' array) "
    "and 'opencode' (an OpenCode session export with 'messages'/'info'). "
    "Pass format='generic' or format='opencode' to force a parser."
)

_PARSERS = {"generic": parse_generic, "opencode": parse_opencode}

#: Keys that only show up in OpenCode-style tool call entries.
_OPENCODE_MARKERS = frozenset({"state", "input", "time", "parts", "tool_call"})
#: Keys that only show up in generic TraceMend events.
_GENERIC_MARKERS = frozenset(
    {"arguments", "args", "agent_id", "duration_ms", "result_fingerprint", "parent_agent_id",
     "sequence", "tokens"}
)


def _normalise_format_name(name: str) -> str:
    return name.strip().lower()


def _format_from_declared(declared: str) -> str:
    key = _normalise_format_name(declared)
    if "opencode" in key:
        return "opencode"
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
    """Return ``"generic"`` or ``"opencode"`` for a decoded trace payload.

    An explicit ``format`` field wins outright; otherwise the top-level keys are
    inspected. Raises :class:`UnsupportedFormatError` when nothing matches.
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

    raise UnsupportedFormatError(
        "could not detect the trace format: expected an 'events' or 'tool_calls' "
        "array, or OpenCode 'messages'/'info' keys",
        hint=_SUPPORTED_HINT,
    )


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

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as exc:
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
    parser = _PARSERS[resolved]
    try:
        return parser(payload, source_path=source_path, digest=digest)
    except TraceParseError:
        raise
    except Exception as exc:  # pragma: no cover - defensive, shape-dependent
        raise TraceParseError(
            f"could not parse {resolved} trace: {exc}",
            hint="The trace did not match the expected export shape; "
            "re-export it or open an issue with the payload.",
        ) from exc


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
