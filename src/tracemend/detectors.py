"""Deterministic, rule-based inefficiency detectors.

Every detector is pure: it reads one normalized :class:`~tracemend.models.TraceRun`
and returns :class:`~tracemend.models.Finding` objects. There is no language
model, no network access, no filesystem access and no randomness, so the same
run always produces the same findings, in the same order, with the same ids.

Ownership rules (so the same wasted work is never reported twice)
-----------------------------------------------------------------
* ``TM001`` owns duplicate tool calls for every tool **except** read-like calls
  and search-like calls. It also leaves failing calls to ``TM002``: a repeated
  failure is a retry-discipline problem, not a general duplicate-call problem,
  and reporting it in both places would double-report the same waste.
* ``TM003`` owns repeated reads of the same file page that did not observably
  change. Reads with explicitly different ``offset``/``limit``/``range`` values
  are different pages and are legitimate; absent pagination lowers confidence
  and unparseable or conflicting pagination is skipped.
* ``TM004`` owns repeated and overlapping repository searches, including
  re-searching after a relevant recorded change.
* ``TM002`` owns repeated identical failures (retry discipline).
* ``TM005`` is informational only: a hotspot is never automatically wasteful
  and is never marked ``fixable``.

As a consequence ``TM001``, ``TM003`` and ``TM004`` never cite the same call
ids. Read-like means the normalized tool is ``read``; search-like means the
normalized tool is ``grep``/``glob`` or the call carries a ``pattern``/``query``
argument; everything else falls to ``TM001``.

Honesty rules
-------------
* Every finding cites real call ids from the run; a group without citable
  evidence is dropped instead of reported.
* Unavailable metadata stays ``None``: nothing is estimated or reported as zero
  when the trace simply does not contain it.
* Duplicate work that spans several agents is reported with ``details["agents"]``
  and one confidence step lower, because a subagent may legitimately repeat a
  parent's call.
* Only a write recorded as successful proves that a file changed. Failed writes
  prove nothing, and writes with unknown outcomes are treated as possible
  changes so a repeat is never asserted across them.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterable, Sequence

from .models import (
    Confidence,
    Finding,
    Severity,
    ToolCall,
    TraceRun,
    make_finding_id,
)
from .security import limit_preview

__all__ = [
    "DETECTOR_CODES",
    "detect_duplicate_tool_calls",
    "detect_failed_retry_loops",
    "detect_redundant_searches",
    "detect_repeated_file_reads",
    "detect_tool_hotspots",
    "is_read_call",
    "is_search_call",
    "is_write_call",
    "normalize_path",
    "path_of_call",
    "run_detectors",
    "sort_findings",
]

#: Detector codes emitted by this module, in evaluation order.
DETECTOR_CODES: tuple[str, ...] = ("TM001", "TM002", "TM003", "TM004", "TM005")

#: Hard cap on cited evidence ids per finding.
MAX_EVIDENCE = 8
#: A tool is a hotspot from this many calls onwards.
HOTSPOT_MIN_CALLS = 5
#: A tool is a hotspot from this many failures onwards.
HOTSPOT_MIN_FAILURES = 3
#: A tool is a hotspot from this share of observed tool time onwards.
HOTSPOT_MIN_DURATION_SHARE = 0.4

READ_TOOL_NAMES = frozenset({"read"})
SEARCH_TOOL_NAMES = frozenset({"grep", "glob"})
SEARCH_ARG_KEYS = ("pattern", "query")
WRITE_TOOL_NAMES = frozenset(
    {
        "edit",
        "write",
        "multiedit",
        "multi_edit",
        "apply_patch",
        "str_replace",
        "str_replace_editor",
        "create_file",
        "insert",
        "patch",
        "notebook_edit",
    }
)
PATH_ARG_KEYS = ("path", "file", "file_path", "filename", "notebook_path", "target")
SCOPE_ARG_KEYS = ("path", "scope", "cwd", "directory", "dir", "root", "glob")
#: Only the real pagination argument names; no invented ``line_start`` aliases.
READ_RANGE_ARG_KEYS = ("offset", "limit", "range")
_RANGE_PAIR_RE = re.compile(r"^\s*(\d+)\s*[-:]\s*(\d+)\s*$")

_CONFIDENCE_STEPS: tuple[Confidence, ...] = ("low", "medium", "high")


# --------------------------------------------------------------------------- #
# Shared classification helpers
# --------------------------------------------------------------------------- #
def normalize_path(value: str) -> str:
    """Normalize a path string so different spellings of one path compare equal."""
    cleaned = (value or "").strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.rstrip("/")


def _argument_string(call: ToolCall, keys: Sequence[str]) -> str | None:
    for key in keys:
        value = call.arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def is_read_call(call: ToolCall) -> bool:
    """True for read-like tools. Owned by ``TM003``."""
    return call.normalized_tool in READ_TOOL_NAMES


def is_search_call(call: ToolCall) -> bool:
    """True for search-like tools. Owned by ``TM004``."""
    if call.normalized_tool in SEARCH_TOOL_NAMES:
        return True
    return _argument_string(call, SEARCH_ARG_KEYS) is not None


def is_write_call(call: ToolCall) -> bool:
    """True for tools that may modify files (used to reset read windows)."""
    tool = call.normalized_tool
    if tool in WRITE_TOOL_NAMES:
        return True
    return "edit" in tool or "write" in tool or "patch" in tool


def path_of_call(call: ToolCall) -> str | None:
    """Best-effort primary target path of a call, or ``None`` when unknown."""
    explicit = _argument_string(call, PATH_ARG_KEYS)
    if explicit:
        return explicit
    return call.primary_target()


def search_pattern_of(call: ToolCall) -> str | None:
    return _argument_string(call, SEARCH_ARG_KEYS)


def search_scope_of(call: ToolCall) -> str:
    explicit = _argument_string(call, SCOPE_ARG_KEYS)
    return normalize_path(explicit) if explicit else ""


def _normalize_pattern(pattern: str) -> str:
    return " ".join(pattern.split())


def _range_int(value: object) -> int | None:
    """Parse a non-negative integer page argument, or ``None`` when unclear."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        return int(value) if value >= 0 and value.is_integer() else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _read_range(call: ToolCall) -> tuple[str, str | None]:
    """Classify the page a read covered: ``(scheme, signature)``.

    ``offset_limit`` and ``range`` are kept as distinct schemes: their
    inclusive/exclusive semantics are not established, so a ``range`` pair is
    never claimed to equal numerically similar ``offset``/``limit`` fields.
    The signature retains every explicitly recorded field, so ``limit=20`` and
    ``limit=50`` stay different pages. ``absent`` means no pagination was
    recorded; ``unsupported`` covers malformed values and conflicting mixed
    fields, which callers must not group as repeats.
    """
    arguments = call.arguments
    has_offset = "offset" in arguments
    has_limit = "limit" in arguments
    has_range = "range" in arguments
    if not (has_offset or has_limit or has_range):
        return "absent", None
    if has_range and (has_offset or has_limit):
        return "unsupported", None
    if has_offset or has_limit:
        parts: list[str] = []
        if has_offset:
            offset = _range_int(arguments["offset"])
            if offset is None:
                return "unsupported", None
            parts.append(f"offset={offset}")
        if has_limit:
            limit = _range_int(arguments["limit"])
            if limit is None:
                return "unsupported", None
            parts.append(f"limit={limit}")
        return "offset_limit", ";".join(parts)

    raw = arguments["range"]
    if isinstance(raw, str):
        match = _RANGE_PAIR_RE.match(raw)
        if not match:
            return "unsupported", None
        start, end = int(match.group(1)), int(match.group(2))
    elif isinstance(raw, (list, tuple)) and len(raw) == 2:
        start, end = _range_int(raw[0]), _range_int(raw[1])
        if start is None or end is None:
            return "unsupported", None
    elif isinstance(raw, dict):
        start, end = _range_int(raw.get("start")), _range_int(raw.get("end"))
        if start is None or end is None:
            return "unsupported", None
    else:
        return "unsupported", None
    if end < start:
        return "unsupported", None
    return "range", f"range={start}:{end}"


def _read_range_key(call: ToolCall) -> str:
    """Group key for reads: one scheme and one page signature per group."""
    status, signature = _read_range(call)
    return f"{status}|{signature or ''}"


def _path_within_scope(path: str, scope: str) -> bool:
    """True only when a path is provably covered by a search scope."""
    path_value = normalize_path(path)
    scope_value = normalize_path(scope)
    if not path_value:
        return False
    if scope_value in {"", "."}:
        # No scope, or the repository root: every relative path is covered.
        return True
    if path_value == scope_value or path_value.startswith(scope_value + "/"):
        return True
    if any(char in scope_value for char in "*?["):
        return fnmatch.fnmatchcase(path_value, scope_value)
    return False


def _ordered_groups(
    calls: Iterable[ToolCall], key_fn: Callable[[ToolCall], str]
) -> dict[str, list[ToolCall]]:
    """Group calls while preserving first-seen order (deterministic)."""
    groups: dict[str, list[ToolCall]] = {}
    for call in calls:
        groups.setdefault(key_fn(call), []).append(call)
    return groups


def _severity_for_redundant(redundant: int) -> tuple[Severity, Confidence]:
    """Shared severity/confidence ladder for ``TM001``/``TM003``/``TM004``."""
    if redundant >= 5:
        return "high", "high"
    if redundant >= 3:
        return "medium", "high"
    return "low", "medium"


def _lower_confidence(confidence: Confidence, steps: int = 1) -> Confidence:
    index = _CONFIDENCE_STEPS.index(confidence)
    return _CONFIDENCE_STEPS[max(0, index - steps)]


def _lower_severity(severity: Severity, floor: Severity = "info") -> Severity:
    """Step one severity level down, never below ``floor``."""
    order: tuple[Severity, ...] = ("info", "low", "medium", "high")
    index = max(order.index(severity) - 1, order.index(floor))
    return order[index]


def _agent_ids(calls: Sequence[ToolCall]) -> list[str]:
    return sorted({call.agent_id for call in calls})


def _evidence(calls: Sequence[ToolCall]) -> list[str]:
    return [call.id for call in calls][:MAX_EVIDENCE]


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Stable, deterministic finding order: severity, then size, then id."""
    return sorted(findings, key=lambda finding: finding.sort_key)


# --------------------------------------------------------------------------- #
# TM001 - duplicate tool calls
# --------------------------------------------------------------------------- #
def _declared_touched_paths(call: ToolCall) -> set[str]:
    """Paths a call declares it wrote, regardless of the recorded outcome."""
    touched = {normalize_path(path) for path in call.modified_files if path}
    if is_write_call(call):
        target = path_of_call(call)
        if target:
            touched.add(normalize_path(target))
    return {path for path in touched if path}


def _touched_paths(call: ToolCall) -> set[str]:
    """Paths a call is known to have changed: successful writes only.

    A failed write must not assert a file change, and a write with an unknown
    outcome is not proof that anything changed.
    """
    if call.status != "success":
        return set()
    return _declared_touched_paths(call)


def _possibly_touched_paths(call: ToolCall) -> set[str]:
    """Paths a write may have changed; unknown outcomes remain possible changes."""
    if call.status not in {"success", "unknown"}:
        return set()
    return _declared_touched_paths(call)


def _group_candidate_paths(run: TraceRun, calls: Sequence[ToolCall]) -> set[str]:
    """Paths that a duplicate group appears to operate on."""
    paths: set[str] = set()
    for call in calls:
        target = path_of_call(call)
        if target:
            paths.add(normalize_path(target))
    modified = {path for event in run.events for path in _touched_paths(event)}
    if modified:
        for call in calls:
            for value in call.arguments.values():
                if not isinstance(value, str) or not value:
                    continue
                for candidate in modified:
                    if candidate and candidate in value:
                        paths.add(candidate)
    return {path for path in paths if path}


def _mitigation_reason(run: TraceRun, calls: Sequence[ToolCall], paths: set[str]) -> str | None:
    """Explain why repeats of this group may be legitimate re-verification.

    A successful edit/write that landed *before* the last repeat and touched one
    of the group's paths means the repeats may be re-checking changed state
    rather than repeating identical work on unchanged state.
    """
    if not paths or is_write_call(calls[0]):
        return None
    positions = {event.id: index for index, event in enumerate(run.events)}
    first_position = positions.get(calls[0].id)
    repeat_positions = [positions[call.id] for call in calls[1:] if call.id in positions]
    if first_position is None or not repeat_positions:
        return None
    last_repeat = max(repeat_positions)
    for event in run.events:
        if not is_write_call(event) or event.status != "success":
            continue
        index = positions.get(event.id, len(run.events))
        # The edit has to land after the first call and before a later repeat;
        # an edit before the whole group cannot justify the repeats.
        if not first_position < index < last_repeat:
            continue
        hit = _touched_paths(event) & paths
        if not hit:
            continue
        return (
            f"{event.id} modified {sorted(hit)[0]} before the later repeats, so those repeats may "
            "be legitimate re-verification of changed state instead of duplicated work."
        )
    return None


def detect_duplicate_tool_calls(run: TraceRun) -> list[Finding]:
    """``TM001``: identical non-read, non-search calls repeated in one run."""
    eligible = [
        call
        for call in run.events
        if not is_read_call(call) and not is_search_call(call) and call.status != "error"
    ]
    findings: list[Finding] = []
    for fingerprint, calls in _ordered_groups(eligible, lambda call: call.call_fingerprint).items():
        total = len(calls)
        if total < 2:
            continue
        evidence = [call.id for call in calls[1:]]
        if not evidence:
            continue
        redundant = total - 1
        severity, confidence = _severity_for_redundant(redundant)
        tool = calls[0].normalized_tool
        details: dict[str, object] = {
            "strategy": "general_tool_efficiency",
            "call_fingerprint": fingerprint,
            "total_calls_in_group": total,
            "redundant_calls": redundant,
            "tool": tool,
        }
        agents = _agent_ids(calls)
        if len(agents) > 1:
            details["agents"] = agents
            confidence = _lower_confidence(confidence)
        paths = _group_candidate_paths(run, calls)
        mitigation = _mitigation_reason(run, calls, paths)
        mitigations: list[str] = []
        if mitigation:
            mitigations.append(mitigation)
            severity = _lower_severity(severity, floor="low")
            confidence = _lower_confidence(confidence)
        if len(agents) > 1:
            mitigations.append(
                "The group spans several agents ("
                + ", ".join(agents)
                + "); a subagent may legitimately repeat a parent agent's call."
            )
        if mitigations:
            details["mitigations"] = mitigations
        if paths:
            details["paths"] = sorted(paths)
        findings.append(
            Finding(
                id=make_finding_id("TM001", tool, fingerprint),
                code="TM001",
                run_id=run.run_id,
                severity=severity,
                confidence=confidence,
                title=f"Duplicate {tool} calls ({total}x)",
                description=(
                    f"{tool} was called {total} times with identical arguments, so {redundant} "
                    "of those calls repeated work that had already been done. The first call is "
                    "treated as legitimate; the remaining ones are the redundant repeats."
                ),
                tool=tool,
                occurrences=total,
                evidence=_evidence(calls[1:]),
                recommendation=(
                    f"Reuse the first {tool} result instead of repeating an identical call; if the "
                    "result is still needed, restate it from the earlier output or cache it in the "
                    "session instructions."
                ),
                fixable=True,
                details=details,
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# TM002 - failed retry loops
# --------------------------------------------------------------------------- #
def detect_failed_retry_loops(run: TraceRun) -> list[Finding]:
    """``TM002``: the same call failing two or more times."""
    failures = [call for call in run.events if call.status == "error"]
    findings: list[Finding] = []
    for fingerprint, calls in _ordered_groups(failures, lambda call: call.call_fingerprint).items():
        if len(calls) < 2:
            continue
        severity: Severity
        confidence: Confidence
        if len(calls) >= 3:
            severity, confidence = "high", "high"
        else:
            severity, confidence = "low", "medium"
        tool = calls[0].normalized_tool
        details: dict[str, object] = {
            "strategy": "retry_discipline",
            "call_fingerprint": fingerprint,
            "failure_count": len(calls),
        }
        agents = _agent_ids(calls)
        if len(agents) > 1:
            details["agents"] = agents
            confidence = _lower_confidence(confidence)
        excerpt = limit_preview(calls[-1].error, 200)
        if excerpt:
            details["last_error_excerpt"] = excerpt
        first = limit_preview(calls[0].error, 200)
        if first and first != excerpt:
            details["first_error_excerpt"] = first
        findings.append(
            Finding(
                id=make_finding_id("TM002", tool, fingerprint),
                code="TM002",
                run_id=run.run_id,
                severity=severity,
                confidence=confidence,
                title=f"Repeated failing {tool} call ({len(calls)}x)",
                description=(
                    f"The same {tool} invocation failed {len(calls)} times with identical "
                    "arguments and no change in between. This pattern is consistent with an "
                    "unguided retry loop; note that transient external failures can also cause "
                    "repeated errors, so this observation alone does not prove the agent handled "
                    "the failure incorrectly."
                ),
                tool=tool,
                occurrences=len(calls),
                evidence=_evidence(calls),
                recommendation=(
                    "Change the approach after the first failure: inspect the error, adjust the "
                    "arguments or the code, and only retry when something relevant has changed. "
                    "Otherwise stop and report the failure."
                ),
                fixable=True,
                details=details,
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# TM003 - repeated file reads
# --------------------------------------------------------------------------- #
def detect_repeated_file_reads(run: TraceRun) -> list[Finding]:
    """``TM003``: several reads of one file page with no observable change in between."""
    modified_paths: set[str] = set()
    uncertain_paths: set[str] = set()
    for event in run.events:
        modified_paths |= _touched_paths(event)
        if event.status == "unknown":
            uncertain_paths |= _possibly_touched_paths(event)
    run_has_modification_data = bool(modified_paths)
    uncertain_paths -= modified_paths

    windows: dict[str, list[list[ToolCall]]] = {}
    current: dict[str, list[ToolCall]] = {}
    for event in run.events:
        # Successful writes prove a change; writes with unknown outcomes are
        # treated as possible changes so a window never spans either.
        for path in _possibly_touched_paths(event):
            if current.get(path):
                windows.setdefault(path, []).append(current[path])
            current[path] = []
        if not is_read_call(event) or event.status == "error":
            continue
        target = path_of_call(event)
        if not target:
            continue
        path = normalize_path(target)
        current.setdefault(path, []).append(event)
    for path, window in current.items():
        if window:
            windows.setdefault(path, []).append(window)

    findings: list[Finding] = []
    for path, path_windows in windows.items():
        file_has_modification_data = path in modified_paths
        for window in path_windows:
            if len(window) < 2:
                continue
            supported = [
                call for call in window if _read_range(call)[0] != "unsupported"
            ]
            if len(supported) < 2:
                continue
            range_groups = _ordered_groups(supported, _read_range_key)
            for range_key, reads in range_groups.items():
                if len(reads) < 2:
                    continue
                range_status, signature = range_key.split("|", 1)
                signature = signature or None
                redundant = len(reads) - 1
                severity, confidence = _severity_for_redundant(redundant)
                if not run_has_modification_data:
                    confidence = "low"
                elif not file_has_modification_data:
                    confidence = _lower_confidence(confidence)
                if range_status == "absent":
                    # Unknown page coverage cannot support a high-confidence repeat.
                    confidence = _lower_confidence(confidence)
                tool = reads[0].normalized_tool
                details: dict[str, object] = {
                    "strategy": "file_read_reuse",
                    "path": path,
                    "reads_in_window": len(reads),
                    "redundant_reads": redundant,
                    "read_range": signature,
                    "range_status": range_status,
                    "modification_evidence": file_has_modification_data,
                    "run_has_modification_data": run_has_modification_data,
                }
                limitations: list[str] = []
                if not run_has_modification_data:
                    if uncertain_paths:
                        limitations.append(
                            "The trace contains no successful file-modification data, but writes "
                            "with unknown outcomes were recorded and may have changed file content; "
                            "repeated reads are reported with low confidence."
                        )
                    else:
                        limitations.append(
                            "The trace contains no file-modification data at all, so it cannot be "
                            "proven that the file content stayed the same between these reads; the "
                            "file may have changed on disk and just not been recorded."
                        )
                elif not file_has_modification_data:
                    limitations.append(
                        f"The trace records no modification of {path} itself, so the file is "
                        "treated as unchanged between these reads."
                    )
                if range_status == "absent":
                    limitations.append(
                        f"No offset, limit or range was recorded for these reads of {path}, so the "
                        "pages they covered cannot be compared; exact coverage is unknown."
                    )
                agents = _agent_ids(reads)
                if len(agents) > 1:
                    confidence = _lower_confidence(confidence)
                    details["agents"] = agents
                    details["mitigations"] = [
                        "The repeated reads span several agents ("
                        + ", ".join(agents)
                        + "); a subagent may legitimately re-read a file its parent already read."
                    ]
                if limitations:
                    details["limitations"] = limitations
                if range_status == "absent" and len(range_groups) == 1:
                    # Keep the historical id for runs without pagination data.
                    key = f"{path}|{reads[0].id}|{reads[-1].id}|{len(reads)}"
                else:
                    key = (
                        f"{path}|{range_key}|{reads[0].id}|{reads[-1].id}|{len(reads)}"
                    )
                if range_status == "absent":
                    description = (
                        f"{path} was read {len(reads)} times with no modification in between and "
                        "no recorded offset, limit or range, so exact page overlap cannot be "
                        f"confirmed; {redundant} of those reads may have repeated content that "
                        "was already available. The first read is treated as legitimate."
                    )
                else:
                    description = (
                        f"{path} was read {len(reads)} times with no modification in between, "
                        f"so {redundant} of those reads repeated content that was already "
                        "available. The first read is treated as legitimate."
                    )
                findings.append(
                    Finding(
                        id=make_finding_id("TM003", tool, key),
                        code="TM003",
                        run_id=run.run_id,
                        severity=severity,
                        confidence=confidence,
                        title=f"Repeated reads of {path} ({len(reads)}x)",
                        description=description,
                        tool=tool,
                        occurrences=len(reads),
                        evidence=_evidence(reads[1:]),
                        recommendation=(
                            "Keep the file content from the first read in context instead of "
                            f"reading {path} again; re-read only after something has changed it."
                        ),
                        fixable=True,
                        details=details,
                    )
                )
    return findings


# --------------------------------------------------------------------------- #
# TM004 - redundant search patterns
# --------------------------------------------------------------------------- #
def _relevant_write_positions(run: TraceRun, scope: str) -> list[int]:
    """Positions in ``run.events`` of writes that may change a search scope."""
    positions: list[int] = []
    for index, event in enumerate(run.events):
        touched = _possibly_touched_paths(event)
        if touched and any(_path_within_scope(path, scope) for path in touched):
            positions.append(index)
    return positions


def _search_windows(
    calls: Sequence[ToolCall], boundaries: Sequence[int], positions: dict[str, int]
) -> list[list[ToolCall]]:
    """Split a group at relevant writes so re-searching changed content is allowed."""
    windows: list[list[ToolCall]] = []
    current: list[ToolCall] = [calls[0]]
    for call in calls[1:]:
        start = positions[current[-1].id]
        end = positions[call.id]
        if any(start < boundary < end for boundary in boundaries):
            windows.append(current)
            current = [call]
        else:
            current.append(call)
    windows.append(current)
    return windows


def detect_redundant_searches(run: TraceRun) -> list[Finding]:
    """``TM004``: identical searches, and broad searches covered by narrower ones."""
    # Failed searches are retry discipline: TM002 owns them, TM004 must not
    # report the same error calls as wasted search work.
    searches = [
        call for call in run.events if is_search_call(call) and call.status != "error"
    ]
    if not searches:
        return []

    positions = {call.id: index for index, call in enumerate(run.events)}
    findings: list[Finding] = []
    claimed: set[str] = set()

    for fingerprint, calls in _ordered_groups(searches, lambda call: call.call_fingerprint).items():
        if len(calls) < 2:
            continue
        claimed.update(call.id for call in calls)
        # A successful (or unknown-outcome) write that may have changed the
        # searched content legitimizes searching again after it.
        scope = search_scope_of(calls[0])
        boundaries = _relevant_write_positions(run, scope)
        windows = _search_windows(calls, boundaries, positions)
        for window in windows:
            if len(window) < 2:
                continue
            redundant = len(window) - 1
            severity, confidence = _severity_for_redundant(redundant)
            fingerprints = [call.result_fingerprint for call in window]
            details: dict[str, object] = {
                "strategy": "search_efficiency",
                "call_fingerprint": fingerprint,
                "matched_ids": [call.id for call in window],
                "result_fingerprints": sorted({fp for fp in fingerprints if fp}),
                "redundant_searches": redundant,
            }
            if all(fp is not None for fp in fingerprints) and len(set(fingerprints)) == 1:
                # The strongest evidence available: identical arguments *and* identical results.
                confidence = "high"
                details["identical_results"] = True
            else:
                confidence = _lower_confidence(confidence)
                details["identical_results"] = None
                details["limitations"] = [
                    "Result fingerprints are missing or differ between these calls, so identical "
                    "results cannot be confirmed; only the repeated arguments are known."
                ]
            agent_ids = _agent_ids(window)
            if len(agent_ids) > 1:
                confidence = _lower_confidence(confidence)
                details["agents"] = agent_ids
                details.setdefault("mitigations", []).append(
                    "The repeated search spans several agents ("
                    + ", ".join(agent_ids)
                    + "); a subagent may legitimately repeat a parent agent's search."
                )
            pattern = search_pattern_of(window[0]) or ""
            tool = window[0].normalized_tool
            if len(windows) == 1:
                key = f"{fingerprint}|{len(window)}"
            else:
                key = f"{fingerprint}|{window[0].id}|{window[-1].id}|{len(window)}"
            findings.append(
                Finding(
                    id=make_finding_id("TM004", tool, key),
                    code="TM004",
                    run_id=run.run_id,
                    severity=severity,
                    confidence=confidence,
                    title=f"Repeated search ({len(window)}x): {pattern!r} in {scope or '.'}",
                    description=(
                        f"The search {pattern!r} over {scope or '.'} was issued {len(window)} times "
                        f"with identical arguments, so {redundant} of those searches repeated the "
                        "same lookup. The first search is treated as legitimate."
                    ),
                    tool=tool,
                    occurrences=len(window),
                    evidence=_evidence(window[1:]),
                    recommendation=(
                        "Reuse the results of the earlier search instead of issuing an identical "
                        "one; search again only when the searched content has changed."
                    ),
                    fixable=True,
                    details=details,
                )
            )

    findings.extend(_detect_broad_search_covered_by_narrower(run, searches, claimed))
    return findings


def _detect_broad_search_covered_by_narrower(
    run: TraceRun, searches: Sequence[ToolCall], claimed: set[str]
) -> list[Finding]:
    """A broad pattern whose results are already covered by a narrower pattern."""
    findings: list[Finding] = []
    positions = {call.id: index for index, call in enumerate(run.events)}
    for broader in searches:
        broad_pattern = search_pattern_of(broader)
        if not broad_pattern:
            continue
        broad_scope = search_scope_of(broader)
        norm_broad = _normalize_pattern(broad_pattern)
        boundaries = _relevant_write_positions(run, broad_scope)
        for narrower in searches:
            if narrower.id == broader.id or narrower.normalized_tool != broader.normalized_tool:
                continue
            # Only an earlier narrower search can have covered a later broad
            # search; a later narrow result cannot justify work already done.
            narrow_position = positions[narrower.id]
            broad_position = positions[broader.id]
            if narrow_position >= broad_position:
                continue
            if any(narrow_position < boundary < broad_position for boundary in boundaries):
                # A relevant recorded change justifies searching again.
                continue
            narrow_pattern = search_pattern_of(narrower)
            if not narrow_pattern:
                continue
            norm_narrow = _normalize_pattern(narrow_pattern)
            if norm_broad == norm_narrow or norm_broad not in norm_narrow:
                continue
            if search_scope_of(narrower) != broad_scope:
                continue
            broad_fp = broader.result_fingerprint
            narrow_fp = narrower.result_fingerprint
            if not broad_fp or not narrow_fp or broad_fp != narrow_fp:
                continue
            key = f"{broad_scope}|{norm_broad}|{norm_narrow}|{broader.id}"
            if any(
                finding.id == make_finding_id("TM004", broader.normalized_tool, key)
                for finding in findings
            ):
                continue
            evidence = [broader.id]
            details: dict[str, object] = {
                "strategy": "search_efficiency",
                "broad_pattern": broad_pattern,
                "narrow_pattern": narrow_pattern,
                "scope": broad_scope,
                "narrow_call_id": narrower.id,
                "result_fingerprint": broad_fp,
                "identical_results": True,
                "redundant_searches": 1,
            }
            confidence: Confidence = "high"
            agent_ids = _agent_ids([broader, narrower])
            if len(agent_ids) > 1:
                confidence = _lower_confidence(confidence)
                details["agents"] = agent_ids
                details["mitigations"] = [
                    "The coverage relies on searches from several agents ("
                    + ", ".join(agent_ids)
                    + "); a subagent may legitimately repeat a parent agent's search."
                ]
            if broader.id in claimed:
                continue
            claimed.add(broader.id)
            findings.append(
                Finding(
                    id=make_finding_id("TM004", broader.normalized_tool, key),
                    code="TM004",
                    run_id=run.run_id,
                    severity="low",
                    confidence=confidence,
                    title=f"Broad search {broad_pattern!r} already covered by {narrow_pattern!r}",
                    description=(
                        f"The search {broad_pattern!r} over {broad_scope or '.'} returned the same "
                        f"result fingerprint as the narrower search {narrow_pattern!r} over the same "
                        "scope, so its results were already covered by the narrower pattern."
                    ),
                    tool=broader.normalized_tool,
                    occurrences=1,
                    evidence=evidence,
                    recommendation=(
                        "Prefer the narrower pattern that already returned these results, or reuse "
                        "the results of the earlier broad search instead of searching again."
                    ),
                    fixable=True,
                    details=details,
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# TM005 - tool hotspots (informational)
# --------------------------------------------------------------------------- #
def detect_tool_hotspots(run: TraceRun) -> list[Finding]:
    """``TM005``: tools that dominate calls, failures or observed time."""
    if not run.events:
        return []
    known_durations = [event.duration_ms for event in run.events if event.duration_ms is not None]
    total_duration = sum(known_durations) if known_durations else None
    total_calls = len(run.events)
    duration_known = len(known_durations)
    token_known = sum(
        1
        for event in run.events
        if event.token_usage is not None and event.token_usage.total is not None
    )
    cost_known = sum(1 for event in run.events if event.cost is not None)
    outcome_known = sum(1 for event in run.events if event.status != "unknown")
    durations_available = duration_known > 0
    tokens_available = token_known > 0
    costs_available = cost_known > 0

    findings: list[Finding] = []
    for tool, calls in _ordered_groups(run.events, lambda call: call.normalized_tool).items():
        call_count = len(calls)
        failures = sum(1 for call in calls if call.status == "error")
        durations = [call.duration_ms for call in calls if call.duration_ms is not None]
        tool_duration = sum(durations) if durations else None
        share: float | None = None
        if durations_available and total_duration and tool_duration is not None:
            share = tool_duration / total_duration
        call_trigger = call_count >= HOTSPOT_MIN_CALLS
        failure_trigger = failures >= HOTSPOT_MIN_FAILURES
        duration_trigger = share is not None and share + 1e-9 >= HOTSPOT_MIN_DURATION_SHARE
        if not (call_trigger or failure_trigger or duration_trigger):
            continue
        confidence: Confidence = "medium"
        if duration_trigger and not call_trigger and not failure_trigger and duration_known < total_calls:
            # A duration share computed from a subset cannot prove a hotspot.
            confidence = "low"
        if failure_trigger and not call_trigger and outcome_known < total_calls:
            confidence = _lower_confidence(confidence)
        tokens = [
            call.token_usage.total
            for call in calls
            if call.token_usage is not None and call.token_usage.total is not None
        ]
        costs = [call.cost for call in calls if call.cost is not None]
        details: dict[str, object] = {
            "strategy": "tool_hotspot_observation",
            "calls": call_count,
            "failures": failures,
            "share_of_all_calls": round(call_count / total_calls, 4),
            "duration_ms": tool_duration,
            "share_of_observed_duration": round(share, 4) if share is not None else None,
            "tokens": sum(tokens) if tokens else None,
            "cost": sum(costs) if costs else None,
            "measurement_coverage": {
                "calls": total_calls,
                "durations_recorded": duration_known,
                "tokens_recorded": token_known,
                "costs_recorded": cost_known,
                "outcomes_recorded": outcome_known,
            },
            "informational_only": True,
        }
        limitations: list[str] = []
        if not tokens_available:
            limitations.append(
                "Token usage was not present anywhere in this trace, so no token figures are "
                "reported for this tool."
            )
        elif token_known < total_calls:
            limitations.append(
                f"Token usage was recorded for only {token_known}/{total_calls} calls; the "
                "reported token sum is partial."
            )
        if not costs_available:
            limitations.append(
                "Cost was not present anywhere in this trace, so no cost figures are reported."
            )
        elif cost_known < total_calls:
            limitations.append(
                f"Cost was recorded for only {cost_known}/{total_calls} calls; the reported cost "
                "sum is partial."
            )
        if not durations_available:
            limitations.append(
                "No durations were recorded in this trace, so this tool's share of tool time is "
                "unavailable."
            )
        elif duration_known < total_calls:
            limitations.append(
                f"Duration was recorded for only {duration_known}/{total_calls} calls; the "
                "observed-time share is based on recorded durations only."
            )
        if outcome_known < total_calls:
            limitations.append(
                f"Outcomes are unknown for {total_calls - outcome_known}/{total_calls} calls; the "
                "failure count includes only recorded errors and may undercount failures."
            )
        if limitations:
            details["limitations"] = limitations
        findings.append(
            Finding(
                id=make_finding_id("TM005", tool, f"hotspot|{tool}"),
                code="TM005",
                run_id=run.run_id,
                severity="info",
                confidence=confidence,
                title=f"Tool hotspot: {tool}",
                description=(
                    f"{tool} accounted for {call_count} of {total_calls} observed calls"
                    + (f" and {failures} failures" if failures else "")
                    + (
                        f", and {share:.0%} of the observed tool time"
                        if share is not None
                        else ""
                    )
                    + ". This is an observation about where the session spends its effort, not a "
                    "verdict that the tool use was wasteful."
                ),
                tool=tool,
                occurrences=call_count,
                evidence=_evidence(calls),
                recommendation=(
                    f"Review whether the {tool} calls were all necessary; a high call count is only "
                    "worth changing when the work itself was avoidable."
                ),
                fixable=False,
                details=details,
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def run_detectors(run: TraceRun) -> list[Finding]:
    """Run every detector and return a deterministic, ordered finding list."""
    findings: list[Finding] = []
    findings.extend(detect_duplicate_tool_calls(run))
    findings.extend(detect_failed_retry_loops(run))
    findings.extend(detect_repeated_file_reads(run))
    findings.extend(detect_redundant_searches(run))
    findings.extend(detect_tool_hotspots(run))
    return sort_findings(findings)
