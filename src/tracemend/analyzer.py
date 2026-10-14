"""Deterministic metrics, run comparison and report assembly.

The analyzer never estimates: a metric that the trace does not contain is
reported as ``None`` ("unavailable") and never as ``0``. ``0`` is a real
measurement and must stay distinguishable from "the trace did not say".
"""

from __future__ import annotations

from collections.abc import Sequence

from .detectors import run_detectors, sort_findings
from .models import (
    AnalysisReport,
    ComparisonReport,
    Finding,
    MetricDelta,
    RunMetrics,
    ToolCall,
    ToolStat,
    TraceRun,
)

__all__ = ["analyze_run", "compare_runs", "compute_metrics"]

#: Comparison metric name -> the :class:`RunMetrics` attribute behind it.
_METRIC_ATTRIBUTES: tuple[tuple[str, str], ...] = (
    ("tool_calls", "total_calls"),
    ("failed_calls", "failed_calls"),
    ("duplicate_calls", "duplicate_calls"),
    ("duration_ms", "duration_ms"),
    ("total_tokens", "total_tokens"),
)

#: Notes always attached to a comparison report.
_COMPARISON_NOTES: tuple[str, ...] = (
    "These metrics indicate behavioural changes, not necessarily improved task correctness.",
    "A lower number of calls, failures or duplicates is a behavioural signal; it does not by "
    "itself show that the task was completed more accurately.",
)

_METHODOLOGY_NOTES: tuple[str, ...] = (
    "Findings come from deterministic rules over normalized tool calls; no language model, "
    "network access or sampling is involved.",
    "TM001 owns duplicate non-read, non-search calls; TM002 owns repeated identical failures "
    "(retry discipline); TM003 owns repeated reads of unchanged files; TM004 owns repeated or "
    "overlapping searches; TM005 reports informational hotspots.",
    "TM001, TM003 and TM004 never report the same call ids: reads belong to TM003, "
    "grep/glob-style searches and calls carrying a pattern/query argument belong to TM004, and "
    "everything else falls to TM001.",
    "Instruction-level findings describe observed behaviour, not task correctness.",
    "Metadata the trace does not contain (duration, tokens, cost) is reported as unavailable "
    "(None) and is never estimated or replaced with zero.",
    "A tool hotspot (TM005) is an observation about where the session spent effort, not a "
    "verdict that the work was wasteful.",
)


def _sum_known(values: Sequence[int | float | None]) -> int | float | None:
    known = [value for value in values if value is not None]
    if not known:
        return None
    return sum(known)


def _known_tokens(call: ToolCall) -> int | None:
    if call.token_usage is None:
        return None
    return call.token_usage.total


def compute_metrics(run: TraceRun) -> RunMetrics:
    """Measure a run. Unavailable values stay ``None``."""
    events = run.events
    groups: dict[str, list[ToolCall]] = {}
    for call in events:
        groups.setdefault(call.call_fingerprint, []).append(call)

    tool_groups: dict[str, list[ToolCall]] = {}
    for call in events:
        tool_groups.setdefault(call.normalized_tool, []).append(call)

    tool_stats: dict[str, ToolStat] = {}
    for tool, calls in tool_groups.items():
        tool_fingerprints: dict[str, list[ToolCall]] = {}
        for call in calls:
            tool_fingerprints.setdefault(call.call_fingerprint, []).append(call)
        duplicate_calls = sum(len(group) - 1 for group in tool_fingerprints.values())
        tokens = [value for value in (_known_tokens(call) for call in calls) if value is not None]
        durations = [call.duration_ms for call in calls if call.duration_ms is not None]
        tool_stats[tool] = ToolStat(
            tool=tool,
            calls=len(calls),
            failures=sum(1 for call in calls if call.status == "error"),
            duplicate_calls=duplicate_calls,
            duration_ms=sum(durations) if durations else None,
            tokens=sum(tokens) if tokens else None,
        )

    return RunMetrics(
        total_calls=len(events),
        failed_calls=sum(1 for call in events if call.status == "error"),
        duplicate_calls=sum(len(group) - 1 for group in groups.values()),
        distinct_tools=len(tool_groups),
        duration_ms=_sum_known([call.duration_ms for call in events]),
        total_tokens=_sum_known([_known_tokens(call) for call in events]),
        total_cost=_sum_known([call.cost for call in events]),
        subagent_calls=sum(1 for call in events if call.parent_agent_id),
        tool_stats=tool_stats,
    )


def _metric_delta(name: str, before: int | float | None, after: int | float | None) -> MetricDelta:
    """Build one delta, keeping unavailable metrics unavailable."""
    if before is None or after is None:
        return MetricDelta(
            name=name,
            before=None,
            after=None,
            delta=None,
            percent_change=None,
            available=False,
        )
    delta = after - before
    percent_change: float | None = (
        None if before == 0 else round((float(delta) / float(before)) * 100.0, 4)
    )
    return MetricDelta(
        name=name,
        before=before,
        after=after,
        delta=delta,
        percent_change=percent_change,
        available=True,
    )


def compare_runs(before: TraceRun, after: TraceRun) -> ComparisonReport:
    """Compare the measured behaviour of two runs (correlation, not causation)."""
    before_metrics = compute_metrics(before)
    after_metrics = compute_metrics(after)

    deltas: list[MetricDelta] = []
    for name, attribute in _METRIC_ATTRIBUTES:
        deltas.append(
            _metric_delta(name, getattr(before_metrics, attribute), getattr(after_metrics, attribute))
        )

    notes = list(_COMPARISON_NOTES)
    if before_metrics.total_tokens is None or after_metrics.total_tokens is None:
        notes.append("Token usage was unavailable for at least one run.")
    if before_metrics.duration_ms is None or after_metrics.duration_ms is None:
        notes.append("Duration was unavailable for at least one run.")
    notes.append(
        "Unavailable metrics are marked available=False with all values None; they are never "
        "estimated."
    )

    return ComparisonReport(
        before_run_id=before.run_id,
        after_run_id=after.run_id,
        before_title=before.title,
        after_title=after.title,
        deltas=deltas,
        notes=notes,
    )


def analyze_run(run: TraceRun) -> AnalysisReport:
    """Metrics plus findings for one run, with the methodology recorded."""
    metrics = compute_metrics(run)
    findings: list[Finding] = sort_findings(run_detectors(run))
    notes = list(_METHODOLOGY_NOTES)
    if not findings:
        notes.append(
            "No inefficient tool-usage patterns matched the current rules for this run; this is "
            "not proof that the run was optimal."
        )
    return AnalysisReport(
        run_id=run.run_id,
        session_id=run.session_id,
        title=run.title,
        source=run.source,
        metrics=metrics,
        findings=findings,
        notes=notes,
    )
