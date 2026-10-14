"""Presentation layer shared by the CLI and the MCP resource endpoints.

Built for humans first (Rich), with a plain-text fallback used by
machine-readable and non-interactive modes. Nothing in this module writes to
disk or mutates state. Every human-readable string is passed through
``security.redact_text`` so trace evidence can never leak a secret into a
terminal, a report file or an AI client.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Group, RenderableType
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .errors import TraceMendError
from .models import (
    AnalysisReport,
    ComparisonReport,
    Finding,
    FixProposal,
    ImportSummary,
    MetricDelta,
    PatchRecord,
    RunMetrics,
    TraceRun,
)
from .security import limit_preview, redact_text

BRAND = "TraceMend"
TAGLINE = "Find the waste. Fix the agent."
RULE_WIDTH = 32

SEVERITY_STYLE: dict[str, str] = {
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold cyan",
    "info": "dim",
}

METRIC_LABELS: dict[str, str] = {
    "tool_calls": "Tool calls",
    "failed_calls": "Failed calls",
    "duplicate_calls": "Duplicate calls",
    "duration_ms": "Duration",
    "total_tokens": "Tokens",
    "findings": "Findings",
}

COMPARISON_ROWS: tuple[tuple[str, str], ...] = (
    ("Total tool calls", "tool_calls"),
    ("Failed calls", "failed_calls"),
    ("Duplicate calls", "duplicate_calls"),
    ("Duration", "duration_ms"),
    ("Tokens", "total_tokens"),
)


def sanitize(text: str | None) -> str:
    """Redact secrets from a human-readable string."""
    if not text:
        return ""
    return redact_text(text)[0]


def format_duration(value: int | None) -> str:
    if value is None:
        return "N/A"
    seconds, milliseconds = divmod(int(value), 1000)
    if seconds >= 60:
        minutes, seconds = divmod(seconds, 60)
        return f"{minutes}m {seconds:02d}s"
    if seconds:
        return f"{seconds}.{milliseconds // 100:01d}s"
    return f"{milliseconds}ms"


def format_number(value: int | float | None) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, float) and not value.is_integer():
        return f"{value:,.2f}"
    return f"{int(value):,}"


def format_percent(value: float | None) -> str:
    if value is None:
        return "N/A"
    sign = "+" if value > 0 else ""
    return f"{sign}{value:.1f}%"


def run_label(run: TraceRun) -> str:
    return f"{run.title} [{run.run_id}]"


# --------------------------------------------------------------------- banner
def build_banner(version: str = "0.1.0") -> RenderableType:
    header = Text()
    header.append(f"{BRAND} v{version}\n", style="bold")
    header.append(TAGLINE, style="italic dim")
    return header


def build_run_header(run: TraceRun) -> RenderableType:
    lines = Table.grid(padding=(0, 1))
    lines.add_column(style="dim", justify="right")
    lines.add_column()
    lines.add_row("Session:", Text(sanitize(run.title)))
    lines.add_row("Source:", Text(run.source))
    if run.model:
        lines.add_row("Model:", Text(run.model))
    lines.add_row("Run:", Text(run.run_id))
    return lines


# -------------------------------------------------------------------- summary
def build_summary(report: AnalysisReport) -> RenderableType:
    metrics = report.metrics
    table = Table.grid(padding=(0, 1))
    table.add_column(justify="left")
    table.add_column(justify="right", style="bold")
    table.add_row("Total tool calls", format_number(metrics.total_calls))
    table.add_row("Failed calls", format_number(metrics.failed_calls))
    table.add_row("Duplicate calls", format_number(metrics.duplicate_calls))
    table.add_row("Duration", format_duration(metrics.duration_ms))
    table.add_row("Tokens", format_number(metrics.total_tokens))
    table.add_row("Potential inefficiencies", format_number(len(report.findings)))
    return Group(Rule("EXECUTION SUMMARY", style="dim", characters="─"), table)


def build_metrics_table(metrics: RunMetrics) -> RenderableType:
    table = Table(title="Tool usage", title_style="bold", header_style="bold dim")
    table.add_column("Tool")
    table.add_column("Calls", justify="right")
    table.add_column("Failed", justify="right")
    table.add_column("Duplicate", justify="right")
    table.add_column("Duration", justify="right")
    for name, stat in sorted(
        metrics.tool_stats.items(), key=lambda item: (-item[1].calls, item[0])
    ):
        table.add_row(
            name,
            format_number(stat.calls),
            format_number(stat.failures),
            format_number(stat.duplicate_calls),
            format_duration(stat.duration_ms),
        )
    return table


# ------------------------------------------------------------------- findings
def find_evidences(run: TraceRun | None, ids: list[str], limit: int = 5) -> list[str]:
    """Render evidence call ids, with their tool/target when the run is known."""
    if run is None:
        return ids[:limit]
    by_id = run.event_by_id()
    rendered: list[str] = []
    for call_id in ids[:limit]:
        event = by_id.get(call_id)
        if event is None:
            rendered.append(call_id)
            continue
        target = event.primary_target()
        suffix = f" ({sanitize(target)})" if target else ""
        rendered.append(f"{call_id}  {event.normalized_tool}{suffix}")
    return rendered


def build_finding_panel(finding: Finding, run: TraceRun | None = None) -> RenderableType:
    style = SEVERITY_STYLE.get(finding.severity, "white")
    heading = Text()
    heading.append(f"[{finding.severity.upper()}] ", style=style)
    heading.append(f"{finding.code} — ", style="bold")
    heading.append(sanitize(finding.title), style="bold")

    body = Table.grid(padding=(0, 1))
    body.add_column(style="dim", justify="right")
    body.add_column()
    body.add_row("Tool:", Text(sanitize(finding.tool)))
    body.add_row("Occurrences:", Text(format_number(finding.occurrences)))
    body.add_row("Confidence:", Text(finding.confidence))
    if finding.evidence:
        body.add_row("Evidence:", Text("\n".join(find_evidences(run, finding.evidence))))
    body.add_row("Finding:", Text(sanitize(finding.description)))
    if finding.recommendation:
        body.add_row("Recommendation:", Text(sanitize(finding.recommendation)))

    return Panel(
        body,
        title=heading,
        title_align="left",
        border_style=style,
        padding=(0, 1),
    )


def build_findings_section(
    report: AnalysisReport, *, run: TraceRun | None = None, limit: int | None = None
) -> RenderableType:
    findings = report.findings if limit is None else report.findings[:limit]
    if not findings:
        return Group(
            Rule("FINDINGS", style="dim", characters="─"),
            Text("No inefficiencies detected in this run.", style="green"),
        )
    panels: list[RenderableType] = [
        build_finding_panel(finding, run) for finding in findings
    ]
    return Group(Rule("FINDINGS", style="dim", characters="─"), *panels)


def build_next_step(report: AnalysisReport) -> RenderableType:
    if not report.findings:
        return Group(
            Rule("NEXT STEP", style="dim", characters="─"),
            Text("Nothing to fix. Try comparing against another run:", style="dim"),
            Text("  tracemend compare <other.json> ", style="bold"),
        )
    fixable = [finding for finding in report.findings if finding.fixable]
    if not fixable:
        return Group(
            Rule("NEXT STEP", style="dim", characters="─"),
            Text("No auto-fixable finding in this run. Review the hotspots, or:", style="dim"),
            Text("  tracemend compare <other.json> ", style="bold"),
        )
    first = fixable[0]
    # Print a bare detector code only when it is unambiguous; otherwise the hint
    # would produce a command that the store cannot resolve.
    ambiguous = sum(1 for finding in report.findings if finding.code == first.code) > 1
    target = first.id if ambiguous else first.code
    hint = Text()
    hint.append("tracemend fix propose ", style="bold")
    hint.append(f"{report.run_id} {target}", style="bold")
    hint.append(" --workspace .", style="dim")
    detail = Text(f"tracemend explain {report.run_id} {first.id}", style="dim")
    return Group(Rule("NEXT STEP", style="dim", characters="─"), hint, detail)


def build_analysis_view(
    report: AnalysisReport, *, run: TraceRun | None = None, limit: int | None = None
) -> RenderableType:
    title = run.title if run is not None else report.title
    parts: list[RenderableType] = [build_banner()]
    header = Table.grid(padding=(0, 1))
    header.add_column(style="dim", justify="right")
    header.add_column()
    header.add_row("Session:", Text(sanitize(title)))
    header.add_row("Source:", Text(report.source))
    header.add_row("Run:", Text(report.run_id))
    parts.append(header)
    parts.append(build_summary(report))
    if limit is None:
        parts.append(build_metrics_table(report.metrics))
    parts.append(build_findings_section(report, run=run, limit=limit))
    if report.notes:
        notes = Group(*(Text(sanitize(note), style="dim") for note in report.notes))
        parts.append(Group(Rule("NOTES", style="dim", characters="─"), notes))
    parts.append(build_next_step(report))
    return Group(*parts)


# ------------------------------------------------------------------- proposals
def build_proposal_view(proposal: FixProposal) -> RenderableType:
    header = Table.grid(padding=(0, 1))
    header.add_column(style="dim", justify="right")
    header.add_column()
    header.add_row("Proposal:", Text(proposal.proposal_id))
    header.add_row("Run:", Text(proposal.run_id))
    header.add_row("Finding:", Text(f"{proposal.code} ({proposal.finding_id})"))
    header.add_row("Target:", Text(f"{proposal.target_file} in {proposal.workspace}"))
    header.add_row("Strategy:", Text(proposal.strategy))
    header.add_row("Status:", Text(proposal.status))
    header.add_row("Origin:", Text(proposal.origin))
    if proposal.evidence:
        header.add_row("Evidence:", Text(", ".join(proposal.evidence[:6])))

    rationale = Markdown(sanitize(proposal.rationale))
    limitation_lines = [sanitize(item) for item in proposal.limitations]
    limitations = Group(*(Text(f"- {line}", style="dim") for line in limitation_lines))

    parts: list[RenderableType] = [
        Rule("FIX PROPOSAL", style="dim", characters="─"),
        header,
        Group(Rule("WHY", style="dim", characters="─"), rationale),
        Group(Rule("PROPOSED CHANGE", style="dim", characters="─"), Markdown(sanitize(proposal.instruction_text))),
    ]
    if limitation_lines:
        parts.append(Group(Rule("LIMITATIONS", style="dim", characters="─"), limitations))
    parts.append(build_approval_hint(proposal))
    return Group(*parts)


def build_approval_hint(proposal: FixProposal) -> RenderableType:
    if proposal.status == "pending":
        lines = Group(
            Text("This change has NOT been applied and requires human approval:", style="dim"),
            Text(f"  tracemend fix diff {proposal.proposal_id}", style="bold"),
            Text(f"  tracemend fix approve {proposal.proposal_id}", style="bold"),
            Text(f"  tracemend fix apply {proposal.proposal_id}", style="bold"),
        )
    elif proposal.status == "approved":
        lines = Group(
            Text("Approved. Apply the exact patch with:", style="dim"),
            Text(f"  tracemend fix apply {proposal.proposal_id}", style="bold"),
        )
    else:
        lines = Group(Text(f"Proposal status: {proposal.status}", style="dim"))
    return Group(Rule("NEXT STEP", style="dim", characters="─"), lines)


def build_diff_view(proposal: FixProposal) -> RenderableType:
    diff_text = Text()
    for line in sanitize(proposal.patch).splitlines():
        if line.startswith("+++") or line.startswith("---"):
            diff_text.append(line + "\n", style="bold")
        elif line.startswith("+"):
            diff_text.append(line + "\n", style="green")
        elif line.startswith("-"):
            diff_text.append(line + "\n", style="red")
        elif line.startswith("@@"):
            diff_text.append(line + "\n", style="cyan")
        else:
            diff_text.append(line + "\n")
    header = Table.grid(padding=(0, 1))
    header.add_column(style="dim", justify="right")
    header.add_column()
    header.add_row("Proposal:", Text(proposal.proposal_id))
    header.add_row("Target:", Text(f"{proposal.workspace}/{proposal.target_file}"))
    header.add_row("Patch hash:", Text(proposal.patch_sha256[:16]))
    header.add_row("Base hash:", Text(proposal.original_sha256[:16]))
    return Group(
        Rule("PROPOSED DIFF", style="dim", characters="─"),
        header,
        diff_text,
        build_approval_hint(proposal),
    )


def build_patch_view(record: PatchRecord) -> RenderableType:
    table = Table.grid(padding=(0, 1))
    table.add_column(style="dim", justify="right")
    table.add_column()
    table.add_row("Patch:", Text(record.patch_id))
    table.add_row("Status:", Text(record.status))
    table.add_row("Target:", Text(f"{record.workspace}/{record.target_file}"))
    table.add_row("Applied:", Text(record.applied_at.isoformat()))
    table.add_row("Backup:", Text(record.backup_path))
    if record.undone_at:
        table.add_row("Undone:", Text(record.undone_at.isoformat()))
    return Group(Rule("APPLIED PATCH", style="dim", characters="─"), table)


# ------------------------------------------------------------------ comparison
def build_comparison_view(report: ComparisonReport) -> RenderableType:
    table = Table(header_style="bold dim", show_edge=False, pad_edge=False)
    table.add_column("Metric")
    table.add_column("Before", justify="right")
    table.add_column("After", justify="right")
    table.add_column("Change", justify="right")

    for label, key in COMPARISON_ROWS:
        delta = report.delta_for(key)
        if delta is None:
            continue
        before = delta.before
        after = delta.after
        if key == "duration_ms":
            before_text = format_duration(int(before) if before is not None else None)
            after_text = format_duration(int(after) if after is not None else None)
        else:
            before_text = format_number(before)
            after_text = format_number(after)
        change = format_percent(delta.percent_change)
        style = ""
        if delta.percent_change is not None:
            style = "green" if delta.percent_change < 0 else ("red" if delta.percent_change > 0 else "dim")
        table.add_row(label, before_text, after_text, Text(change, style=style))

    parts: list[RenderableType] = [
        build_banner(),
        Rule("EXECUTION COMPARISON", style="dim", characters="─"),
        table,
    ]
    duplicate = report.delta_for("duplicate_calls")
    if duplicate is not None and duplicate.percent_change is not None:
        line = Text()
        line.append("Duplicate calls: ", style="bold")
        line.append(format_percent(duplicate.percent_change), style="bold")
        parts.append(line)
    notes = Group(*(Text(sanitize(note), style="dim") for note in report.notes))
    parts.append(Group(Rule("NOTES", style="dim", characters="─"), notes))
    return Group(*parts)


def build_import_view(summary: ImportSummary, run: TraceRun | None = None) -> RenderableType:
    table = Table.grid(padding=(0, 1))
    table.add_column(style="dim", justify="right")
    table.add_column()
    table.add_row("Run:", Text(summary.run_id))
    table.add_row("Source:", Text(summary.source))
    table.add_row("Session:", Text(sanitize(summary.title)))
    table.add_row("Events:", Text(format_number(summary.event_count)))
    table.add_row("Redactions:", Text(format_number(summary.redactions_applied)))
    if summary.skipped_records:
        table.add_row("Skipped records:", Text(format_number(summary.skipped_records)))
    parts: list[RenderableType] = [
        Rule("IMPORTED TRACE", style="dim", characters="─"),
        table,
    ]
    if summary.warnings:
        warnings = Group(*(Text(f"- {sanitize(w)}", style="yellow") for w in summary.warnings))
        parts.append(Group(Rule("WARNINGS", style="dim", characters="─"), warnings))
    if run is not None:
        next_step = Group(
            Text("Analyze it with:", style="dim"),
            Text(f"  tracemend analyze {run.source_path or '<trace.json>'}", style="bold"),
        )
        parts.append(next_step)
    return Group(*parts)


def build_error_view(error: TraceMendError) -> RenderableType:
    body = Table.grid(padding=(0, 1))
    body.add_column(style="dim", justify="right")
    body.add_column()
    body.add_row("Error:", Text(sanitize(error.message), style="red"))
    if error.hint:
        body.add_row("Hint:", Text(sanitize(error.hint)))
    return Panel(body, title=f"[bold red]{error.code}", title_align="left", border_style="red")


def build_hint_view(message: str, command: str) -> RenderableType:
    return Group(Text(sanitize(message), style="dim"), Text(f"  {command}", style="bold"))


# ------------------------------------------------------------------------ json
def to_json_text(payload: Any) -> str:
    """Safe JSON serialization for machine-readable output."""
    return json.dumps(payload, indent=2, sort_keys=False, default=str)


def report_to_payload(report: AnalysisReport) -> dict[str, Any]:
    return json.loads(report.model_dump_json())


def finding_to_payload(finding: Finding) -> dict[str, Any]:
    return json.loads(finding.model_dump_json())


def proposal_to_payload(proposal: FixProposal) -> dict[str, Any]:
    payload = json.loads(proposal.model_dump_json())
    payload["patch_sha256"] = proposal.patch_sha256
    return payload


def run_to_payload(run: TraceRun, *, include_events: bool = False) -> dict[str, Any]:
    payload = json.loads(run.model_dump_json())
    if not include_events:
        payload.pop("events", None)
        payload["event_count"] = run.event_count
    return payload


def comparison_to_payload(report: ComparisonReport) -> dict[str, Any]:
    return json.loads(report.model_dump_json())


def metrics_to_payload(metrics: RunMetrics) -> dict[str, Any]:
    return json.loads(metrics.model_dump_json())


def delta_summary(delta: MetricDelta) -> str:
    """One-line textual summary of a metric delta."""
    return f"{delta.name}: {format_number(delta.before)} -> {format_number(delta.after)} ({format_percent(delta.percent_change)})"


def truncate(text: str, limit: int = 200) -> str:
    """Short, redacted preview helper for terminals."""
    return limit_preview(sanitize(text), limit) or ""
