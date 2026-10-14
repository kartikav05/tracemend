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
* ``TM003`` owns repeated reads of files that did not observably change.
* ``TM004`` owns repeated and overlapping repository searches.
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
"""

from __future__ import annotations

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
def _touched_paths(call: ToolCall) -> set[str]:
    """Paths a single call is known to have written."""
    touched = {normalize_path(path) for path in call.modified_files if path}
    if is_write_call(call):
        target = path_of_call(call)
        if target:
            touched.add(normalize_path(target))
    return {path for path in touched if path}


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
    repeat_positions = [positions[call.id] for call in calls[1:] if call.id in positions]
    if not repeat_positions:
        return None
    last_repeat = max(repeat_positions)
    for event in run.events:
        if not is_write_call(event) or event.status == "error":
            continue
        index = positions.get(event.id, len(run.events))
        if index >= last_repeat:
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
    """``TM003``: several reads of one file with no observable change in between."""
    modified_paths: set[str] = set()
    run_has_modification_data = False
    for event in run.events:
        touched = _touched_paths(event)
        if touched:
            run_has_modification_data = True
            modified_paths |= touched

    windows: dict[str, list[list[ToolCall]]] = {}
    current: dict[str, list[ToolCall]] = {}
    for event in run.events:
        for path in _touched_paths(event):
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
            redundant = len(window) - 1
            severity, confidence = _severity_for_redundant(redundant)
            if not run_has_modification_data:
                confidence = "low"
            elif not file_has_modification_data:
                confidence = _lower_confidence(confidence)
            tool = window[0].normalized_tool
            details: dict[str, object] = {
                "strategy": "file_read_reuse",
                "path": path,
                "reads_in_window": len(window),
                "redundant_reads": redundant,
                "modification_evidence": file_has_modification_data,
                "run_has_modification_data": run_has_modification_data,
            }
            if not run_has_modification_data:
                details["limitations"] = [
                    "The trace contains no file-modification data at all, so it cannot be proven "
                    "that the file content stayed the same between these reads; the file may have "
                    "changed on disk and just not been recorded."
                ]
            elif not file_has_modification_data:
                details["limitations"] = [
                    f"The trace records no modification of {path} itself, so the file is treated "
                    "as unchanged between these reads."
                ]
            key = f"{path}|{window[0].id}|{window[-1].id}|{len(window)}"
            findings.append(
                Finding(
                    id=make_finding_id("TM003", tool, key),
                    code="TM003",
                    run_id=run.run_id,
                    severity=severity,
                    confidence=confidence,
                    title=f"Repeated reads of {path} ({len(window)}x)",
                    description=(
                        f"{path} was read {len(window)} times with no modification in between, so "
                        f"{redundant} of those reads repeated content that was already available. "
                        "The first read is treated as legitimate."
                    ),
                    tool=tool,
                    occurrences=len(window),
                    evidence=_evidence(window[1:]),
                    recommendation=(
                        "Keep the file content from the first read in context instead of reading "
                        f"{path} again; re-read only after something has changed it."
                    ),
                    fixable=True,
                    details=details,
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# TM004 - redundant search patterns
# --------------------------------------------------------------------------- #
def detect_redundant_searches(run: TraceRun) -> list[Finding]:
    """``TM004``: identical searches, and broad searches covered by narrower ones."""
    searches = [call for call in run.events if is_search_call(call)]
    if not searches:
        return []

    findings: list[Finding] = []
    claimed: set[str] = set()

    for fingerprint, calls in _ordered_groups(searches, lambda call: call.call_fingerprint).items():
        if len(calls) < 2:
            continue
        redundant = len(calls) - 1
        severity, confidence = _severity_for_redundant(redundant)
        fingerprints = [call.result_fingerprint for call in calls]
        details: dict[str, object] = {
            "strategy": "search_efficiency",
            "call_fingerprint": fingerprint,
            "matched_ids": [call.id for call in calls],
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
        agent_ids = _agent_ids(calls)
        if len(agent_ids) > 1:
            confidence = _lower_confidence(confidence)
            details["agents"] = agent_ids
            details.setdefault("mitigations", []).append(
                "The repeated search spans several agents ("
                + ", ".join(agent_ids)
                + "); a subagent may legitimately repeat a parent agent's search."
            )
        pattern = search_pattern_of(calls[0]) or ""
        scope = search_scope_of(calls[0])
        tool = calls[0].normalized_tool
        key = f"{fingerprint}|{len(calls)}"
        claimed.update(call.id for call in calls)
        findings.append(
            Finding(
                id=make_finding_id("TM004", tool, key),
                code="TM004",
                run_id=run.run_id,
                severity=severity,
                confidence=confidence,
                title=f"Repeated search ({len(calls)}x): {pattern!r} in {scope or '.'}",
                description=(
                    f"The search {pattern!r} over {scope or '.'} was issued {len(calls)} times "
                    f"with identical arguments, so {redundant} of those searches repeated the same "
                    "lookup. The first search is treated as legitimate."
                ),
                tool=tool,
                occurrences=len(calls),
                evidence=_evidence(calls[1:]),
                recommendation=(
                    "Reuse the results of the earlier search instead of issuing an identical one; "
                    "search again only when the searched content has changed."
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
    for broader in searches:
        broad_pattern = search_pattern_of(broader)
        if not broad_pattern:
            continue
        broad_scope = search_scope_of(broader)
        norm_broad = _normalize_pattern(broad_pattern)
        for narrower in searches:
            if narrower.id == broader.id or narrower.normalized_tool != broader.normalized_tool:
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
            if broader.id in claimed:
                continue
            claimed.add(broader.id)
            findings.append(
                Finding(
                    id=make_finding_id("TM004", broader.normalized_tool, key),
                    code="TM004",
                    run_id=run.run_id,
                    severity="low",
                    confidence="high",
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
    durations_available = bool(known_durations)
    tokens_available = any(
        event.token_usage is not None and event.token_usage.total is not None for event in run.events
    )
    costs_available = any(event.cost is not None for event in run.events)
    total_calls = len(run.events)

    findings: list[Finding] = []
    for tool, calls in _ordered_groups(run.events, lambda call: call.normalized_tool).items():
        call_count = len(calls)
        failures = sum(1 for call in calls if call.status == "error")
        durations = [call.duration_ms for call in calls if call.duration_ms is not None]
        tool_duration = sum(durations) if durations else None
        share: float | None = None
        if durations_available and total_duration and tool_duration is not None:
            share = tool_duration / total_duration
        is_hotspot = (
            call_count >= HOTSPOT_MIN_CALLS
            or failures >= HOTSPOT_MIN_FAILURES
            or (share is not None and share + 1e-9 >= HOTSPOT_MIN_DURATION_SHARE)
        )
        if not is_hotspot:
            continue
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
            "informational_only": True,
        }
        limitations: list[str] = []
        if not tokens_available:
            limitations.append(
                "Token usage was not present anywhere in this trace, so no token figures are "
                "reported for this tool."
            )
        if not costs_available:
            limitations.append(
                "Cost was not present anywhere in this trace, so no cost figures are reported."
            )
        if not durations_available:
            limitations.append(
                "No durations were recorded in this trace, so this tool's share of tool time is "
                "unavailable."
            )
        if limitations:
            details["limitations"] = limitations
        findings.append(
            Finding(
                id=make_finding_id("TM005", tool, f"hotspot|{tool}"),
                code="TM005",
                run_id=run.run_id,
                severity="info",
                confidence="medium",
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
