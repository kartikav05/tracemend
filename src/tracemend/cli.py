"""TraceMend command line interface.

The CLI is the only place a human approval can be granted. It shares every
service with the MCP server (``adapters``, ``analyzer``, ``fixes``, ``storage``)
so behaviour can never diverge between the two front ends.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console

from . import __version__, fixes, reports
from .adapters import load_trace_file
from .analyzer import analyze_run
from .errors import ApprovalRequiredError, TraceMendError
from .models import AnalysisReport, TraceRun
from .storage import Store

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"], "max_content_width": 100}
OUTPUT_CHOICES = click.Choice(["text", "json"], case_sensitive=False)
SEVERITY_CHOICES = click.Choice(["info", "low", "medium", "high"], case_sensitive=False)


def _console() -> Console:
    return Console(highlight=False, soft_wrap=False)


def _dump(payload: dict[str, Any], *, output: str | None, as_json: bool) -> None:
    """Emit JSON either to stdout or to a file."""
    text = reports.to_json_text(payload)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        return
    click.echo(text)


def _fail(error: TraceMendError, *, as_json: bool, console: Console) -> None:
    if as_json:
        click.echo(reports.to_json_text(error.to_dict()))
    else:
        console.print(reports.build_error_view(error))
    raise SystemExit(error.exit_code)


def _require_report(store: Store, run_id: str) -> AnalysisReport:
    return store.get_report(run_id)


def _load_and_analyze(
    store: Store, trace: str, source_format: str | None
) -> tuple[TraceRun, AnalysisReport]:
    run = load_trace_file(trace, format=source_format)
    store.save_run(run)
    report = analyze_run(run)
    store.save_report(report)
    return run, report


# ---------------------------------------------------------------------- group
@click.group(context_settings=CONTEXT_SETTINGS)
@click.option(
    "--data-dir",
    type=click.Path(file_okay=False, dir_okay=True, path_type=str),
    default=None,
    envvar="TRACEMEND_DATA_DIR",
    help="Local state directory (defaults to the platform user data dir).",
)
@click.version_option(__version__, "-V", "--version", prog_name="TraceMend", message="%(prog)s %(version)s")
@click.pass_context
def cli(ctx: click.Context, data_dir: str | None) -> None:
    """TraceMend — Find the waste. Fix the agent.

    Analyze AI agent execution traces, detect inefficient tool usage and safely
    optimize agent instructions with evidence-backed fixes.
    """
    ctx.obj = {"store": Store(data_dir), "console": _console()}


# -------------------------------------------------------------------- analyze
@cli.command()
@click.argument("trace", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.option("--format", "output_format", type=OUTPUT_CHOICES, default="text", show_default=True,
              help="Report rendering format.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=str), default=None,
              help="Write the JSON report to this file instead of stdout.")
@click.option("--source-format", type=click.Choice(["generic", "opencode"]), default=None,
              help="Force the input trace format instead of auto-detecting it.")
@click.option("--limit", type=int, default=None, help="Show at most this many findings.")
@click.pass_context
def analyze(
    ctx: click.Context,
    trace: str,
    output_format: str,
    output: str | None,
    source_format: str | None,
    limit: int | None,
) -> None:
    """Import TRACE, run the deterministic analysis and report findings."""
    store: Store = ctx.obj["store"]
    console: Console = ctx.obj["console"]
    as_json = output_format.lower() == "json"
    if output and not as_json:
        as_json = True
    try:
        run, report = _load_and_analyze(store, trace, source_format)
    except TraceMendError as error:
        _fail(error, as_json=as_json, console=console)
        return

    if as_json:
        _dump(reports.report_to_payload(report), output=output, as_json=True)
        return
    console.print(reports.build_analysis_view(report, run=run, limit=limit))


# ------------------------------------------------------------------- findings
@cli.command()
@click.argument("run_id")
@click.option("--severity", type=SEVERITY_CHOICES, default=None, help="Only show this severity.")
@click.option("--limit", type=int, default=20, show_default=True, help="Maximum findings to show.")
@click.option("--format", "output_format", type=OUTPUT_CHOICES, default="text", show_default=True)
@click.pass_context
def findings(ctx: click.Context, run_id: str, severity: str | None, limit: int, output_format: str) -> None:
    """List findings recorded for RUN_ID."""
    store: Store = ctx.obj["store"]
    console: Console = ctx.obj["console"]
    as_json = output_format.lower() == "json"
    try:
        report = _require_report(store, run_id)
        items = store.get_findings(run_id, severity=severity, limit=limit)
    except TraceMendError as error:
        _fail(error, as_json=as_json, console=console)
        return

    if as_json:
        click.echo(
            reports.to_json_text(
                {
                    "run_id": run_id,
                    "count": len(items),
                    "findings": [reports.finding_to_payload(item) for item in items],
                }
            )
        )
        return

    if not items:
        console.print(reports.build_hint_view("No findings match this filter.", f"tracemend findings {run_id}"))
        return
    run = store.get_run(run_id)
    scoped = report.model_copy(update={"findings": items})
    console.print(reports.build_findings_section(scoped, run=run))


# -------------------------------------------------------------------- explain
@cli.command()
@click.argument("run_id")
@click.argument("finding_id")
@click.option("--format", "output_format", type=OUTPUT_CHOICES, default="text", show_default=True)
@click.pass_context
def explain(ctx: click.Context, run_id: str, finding_id: str, output_format: str) -> None:
    """Explain one finding with its evidence and recommendation."""
    store: Store = ctx.obj["store"]
    console: Console = ctx.obj["console"]
    as_json = output_format.lower() == "json"
    try:
        finding = store.get_finding(run_id, finding_id)
        run = store.get_run(run_id)
    except TraceMendError as error:
        _fail(error, as_json=as_json, console=console)
        return

    if as_json:
        payload = reports.finding_to_payload(finding)
        payload["evidence_detail"] = reports.find_evidences(run, finding.evidence, limit=25)
        click.echo(reports.to_json_text(payload))
        return
    console.print(reports.build_finding_panel(finding, run))


# ------------------------------------------------------------------------ fix
@cli.group()
def fix() -> None:
    """Propose, preview, approve, apply and undo AGENTS.md fixes."""


@fix.command("propose")
@click.argument("run_id")
@click.argument("finding_id")
@click.option("--workspace", type=click.Path(exists=True, file_okay=False, path_type=str), required=True,
              help="Workspace directory that owns AGENTS.md.")
@click.option("--target", "target_file", default="AGENTS.md", show_default=True,
              help="Relative target file (only AGENTS.md is supported).")
@click.option("--format", "output_format", type=OUTPUT_CHOICES, default="text", show_default=True)
@click.pass_context
def fix_propose(
    ctx: click.Context, run_id: str, finding_id: str, workspace: str, target_file: str, output_format: str
) -> None:
    """Create a pending, reviewable fix proposal for FINDING_ID."""
    store: Store = ctx.obj["store"]
    console: Console = ctx.obj["console"]
    as_json = output_format.lower() == "json"
    try:
        store.get_run(run_id)
        store.get_finding(run_id, finding_id)
        proposal = fixes.create_proposal(
            store=store,
            run_id=run_id,
            finding_id=finding_id,
            workspace=workspace,
            target_file=target_file,
        )
    except TraceMendError as error:
        _fail(error, as_json=as_json, console=console)
        return

    if as_json:
        _dump(reports.proposal_to_payload(proposal), output=None, as_json=True)
        return
    console.print(reports.build_proposal_view(proposal))


@fix.command("diff")
@click.argument("proposal_id")
@click.option("--format", "output_format", type=OUTPUT_CHOICES, default="text", show_default=True)
@click.pass_context
def fix_diff(ctx: click.Context, proposal_id: str, output_format: str) -> None:
    """Preview the exact unified diff of PROPOSAL_ID without modifying anything."""
    store: Store = ctx.obj["store"]
    console: Console = ctx.obj["console"]
    as_json = output_format.lower() == "json"
    try:
        proposal = store.get_proposal(proposal_id)
    except TraceMendError as error:
        _fail(error, as_json=as_json, console=console)
        return

    if as_json:
        payload = reports.proposal_to_payload(proposal)
        payload["diff"] = proposal.patch
        click.echo(reports.to_json_text(payload))
        return
    console.print(reports.build_diff_view(proposal))


@fix.command("approve")
@click.argument("proposal_id")
@click.option("--yes", is_flag=True, default=False,
              help="Confirm approval non-interactively (scripted local use only; never available over MCP).")
@click.pass_context
def fix_approve(ctx: click.Context, proposal_id: str, yes: bool) -> None:
    """Deliberately approve PROPOSAL_ID as a human.

    Approval is bound to the exact patch hash, workspace and original file hash.
    """
    store: Store = ctx.obj["store"]
    console: Console = ctx.obj["console"]
    try:
        proposal = store.get_proposal(proposal_id)
    except TraceMendError as error:
        _fail(error, as_json=False, console=console)
        return

    console.print(reports.build_diff_view(proposal))
    if not yes:
        if not sys.stdin.isatty():
            error = ApprovalRequiredError(
                "approval requires an interactive terminal",
                hint="Run this command in a terminal, or pass --yes for a deliberate local script.",
            )
            _fail(error, as_json=False, console=console)
            return
        typed = click.prompt(
            f"Type 'approve' to authorize this exact patch for {proposal.workspace}/{proposal.target_file}",
            default="",
            show_default=False,
        )
        yes = typed.strip() == "approve"
    try:
        record = fixes.approve_proposal(store, proposal_id, confirm=yes)
    except TraceMendError as error:
        _fail(error, as_json=False, console=console)
        return
    console.print(
        reports.build_hint_view(
            f"Approved {record.approval_id} for patch {record.patch_sha256[:16]}.",
            f"tracemend fix apply {proposal_id}",
        )
    )


@fix.command("apply")
@click.argument("proposal_id")
@click.option("--format", "output_format", type=OUTPUT_CHOICES, default="text", show_default=True)
@click.pass_context
def fix_apply(ctx: click.Context, proposal_id: str, output_format: str) -> None:
    """Apply an already approved patch atomically, after integrity checks."""
    store: Store = ctx.obj["store"]
    console: Console = ctx.obj["console"]
    as_json = output_format.lower() == "json"
    try:
        record = fixes.apply_proposal(store, proposal_id)
    except TraceMendError as error:
        _fail(error, as_json=as_json, console=console)
        return

    if as_json:
        click.echo(reports.to_json_text(_patch_payload(record)))
        return
    console.print(reports.build_patch_view(record))


@fix.command("undo")
@click.argument("patch_id")
@click.option("--format", "output_format", type=OUTPUT_CHOICES, default="text", show_default=True)
@click.pass_context
def fix_undo(ctx: click.Context, patch_id: str, output_format: str) -> None:
    """Revert a TraceMend patch, refusing to overwrite unrelated edits."""
    store: Store = ctx.obj["store"]
    console: Console = ctx.obj["console"]
    as_json = output_format.lower() == "json"
    try:
        record = fixes.undo_patch(store, patch_id)
    except TraceMendError as error:
        _fail(error, as_json=as_json, console=console)
        return

    if as_json:
        click.echo(reports.to_json_text(_patch_payload(record)))
        return
    console.print(reports.build_patch_view(record))


@fix.command("list")
@click.option("--run-id", default=None, help="Only proposals for this run.")
@click.option("--status", default=None, help="Only proposals with this status.")
@click.option("--format", "output_format", type=OUTPUT_CHOICES, default="text", show_default=True)
@click.pass_context
def fix_list(ctx: click.Context, run_id: str | None, status: str | None, output_format: str) -> None:
    """List stored fix proposals."""
    store: Store = ctx.obj["store"]
    console: Console = ctx.obj["console"]
    proposals = store.list_proposals(run_id=run_id, status=status)
    if output_format.lower() == "json":
        click.echo(
            reports.to_json_text({"count": len(proposals), "proposals": [reports.proposal_to_payload(p) for p in proposals]})
        )
        return
    if not proposals:
        console.print(reports.build_hint_view("No proposals stored yet.", "tracemend fix propose <run-id> <finding-id> --workspace ."))
        return
    table = reports.Table(header_style="bold dim")
    table.add_column("Proposal")
    table.add_column("Run")
    table.add_column("Finding")
    table.add_column("Status")
    table.add_column("Target")
    for proposal in proposals:
        table.add_row(
            proposal.proposal_id,
            proposal.run_id,
            proposal.code,
            proposal.status,
            f"{proposal.workspace}/{proposal.target_file}",
        )
    console.print(table)


def _patch_payload(record: Any) -> dict[str, Any]:
    import json

    return json.loads(record.model_dump_json())


# -------------------------------------------------------------------- compare
@cli.command()
@click.argument("before", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.argument("after", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.option("--format", "output_format", type=OUTPUT_CHOICES, default="text", show_default=True)
@click.option("--source-format", type=click.Choice(["generic", "opencode"]), default=None)
@click.pass_context
def compare(ctx: click.Context, before: str, after: str, output_format: str, source_format: str | None) -> None:
    """Compare two traces: BEFORE (baseline) against AFTER (follow-up)."""
    store: Store = ctx.obj["store"]
    console: Console = ctx.obj["console"]
    as_json = output_format.lower() == "json"
    try:
        from .analyzer import compare_runs as compare_service

        before_run = load_trace_file(before, format=source_format)
        after_run = load_trace_file(after, format=source_format)
        for run in (before_run, after_run):
            store.save_run(run)
            store.save_report(analyze_run(run))
        comparison = compare_service(before_run, after_run)
    except TraceMendError as error:
        _fail(error, as_json=as_json, console=console)
        return

    if as_json:
        click.echo(reports.to_json_text(reports.comparison_to_payload(comparison)))
        return
    console.print(reports.build_comparison_view(comparison))


# ------------------------------------------------------------------------ mcp
@cli.command()
def mcp() -> None:
    """Run the TraceMend MCP server over stdio."""
    from .mcp_server import main as run_server

    run_server()


def main() -> None:
    """Console-script entry point."""
    cli(prog_name="tracemend")


if __name__ == "__main__":
    main()
