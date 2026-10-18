"""Bounded JSON Lines / NDJSON reader for native adapters.

Enforces record/line limits before decode. Blank lines ignored; CRLF handled.
Malformed lines raise with line number (no silent skips). Error messages
exclude the offending line content (may hold credentials).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from ..errors import TraceParseError
from ..security import unique_preserving_order

#: Maximum number of decoded JSONL records in one trace.
MAX_JSONL_RECORDS = 100_000
#: Maximum UTF-8 bytes allowed on a single JSONL line.
MAX_JSONL_LINE_BYTES = 1024 * 1024

JSONL_HINT = (
    "Expected one complete JSON object per line (JSON Lines / NDJSON). "
    "Re-export the session instead of editing the file by hand."
)


def looks_like_jsonl(text: str) -> bool:
    """True when the first non-blank line is a self-contained JSON object.

    The check is deliberately strict: pretty-printed JSON starts with a bare
    ``{`` which does not decode, so a truncated JSON document keeps its original
    error instead of being reported as a broken JSONL row.
    """
    first = _first_non_blank(text)
    if first is None:
        return False
    try:
        return isinstance(json.loads(first), dict)
    except json.JSONDecodeError:
        return False


def _first_non_blank(text: str) -> str | None:
    for line in text.splitlines():
        if line.strip():
            return line
    return None


def parse_jsonl(text: str) -> list[dict[str, Any]]:
    """Decode a JSONL document into a list of objects.

    Raises :class:`TraceParseError` with a line number for unreadable or
    non-object records, too many records, and oversized lines. It never skips a
    non-blank line.
    """
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if len(records) >= MAX_JSONL_RECORDS:
            raise TraceParseError(
                f"JSONL input has more than {MAX_JSONL_RECORDS} records",
                hint="Import a single, bounded session instead of a whole history.",
            )
        if len(line.encode("utf-8")) > MAX_JSONL_LINE_BYTES:
            raise TraceParseError(
                f"line {line_number} exceeds the {MAX_JSONL_LINE_BYTES} byte record limit",
                hint="One JSONL record per tool event; split the export before importing.",
            )
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TraceParseError(
                f"invalid JSON at line {line_number} column {exc.colno}: {exc.msg}",
                hint=JSONL_HINT,
            ) from exc
        if not isinstance(record, dict):
            raise TraceParseError(
                f"line {line_number}: each JSONL record must be a JSON object, "
                f"got {type(record).__name__}",
                hint=JSONL_HINT,
            )
        records.append(record)
    if not records:
        raise TraceParseError(
            "JSONL input contains no records",
            hint="Point TraceMend at a transcript that contains at least one event.",
        )
    return records


def _enforce_record_count(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(rows) > MAX_JSONL_RECORDS:
        raise TraceParseError(
            f"{len(rows)} records exceed the {MAX_JSONL_RECORDS} record limit",
            hint="One JSONL record per tool event; import a bounded session instead.",
        )
    return rows


def as_rows(payload: Any, *, source_label: str) -> list[dict[str, Any]]:
    """Normalize a parser payload (one object or a JSONL list) into rows."""
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        rows: list[dict[str, Any]] = []
        for index, record in enumerate(payload):
            if not isinstance(record, dict):
                raise TraceParseError(
                    f"{source_label} record {index} must be a JSON object, "
                    f"got {type(record).__name__}",
                    hint=JSONL_HINT,
                )
            rows.append(record)
        if not rows:
            raise TraceParseError(
                f"{source_label} input contains no records",
                hint="Point TraceMend at a transcript that contains at least one event.",
            )
        return _enforce_record_count(rows)
    raise TraceParseError(
        f"{source_label} transcript must be a JSON object or a JSONL row list, "
        f"got {type(payload).__name__}",
        hint=JSONL_HINT,
    )


def single_session_id(
    values: Iterable[str | None],
    *,
    source_label: str,
) -> str:
    """Return the one session id present, refusing to merge several sessions."""
    unique = unique_preserving_order(value for value in values if value)
    if len(unique) > 1:
        raise TraceParseError(
            f"{source_label} input mixes {len(unique)} sessions",
            hint="Import one session at a time; TraceMend never merges sessions silently.",
        )
    return unique[0] if unique else "session_unknown"
