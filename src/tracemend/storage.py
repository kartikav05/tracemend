"""SQLite persistence built on the standard library only.

Only derived, minimized data is stored: run metadata, normalized events,
analysis results, findings, fix proposals, approvals and applied patches.
Raw transcripts are never retained beyond the normalized events.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .errors import (
    FindingNotFoundError,
    PatchNotFoundError,
    ProposalNotFoundError,
    RunNotFoundError,
)
from .models import (
    AnalysisReport,
    ApprovalRecord,
    Finding,
    FixProposal,
    PatchRecord,
    TraceRun,
)

SCHEMA_VERSION = 1
DATA_DIR_ENV = "TRACEMEND_DATA_DIR"
DB_FILENAME = "tracemend.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    run_id TEXT PRIMARY KEY,
    generated_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    code TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    tool TEXT NOT NULL,
    occurrences INTEGER NOT NULL,
    payload TEXT NOT NULL,
    -- Finding ids are only guaranteed unique within a run, so the primary key
    -- must be composite: two different runs may legitimately produce the same
    -- per-run identifier (for example the tool-level hotspot finding).
    PRIMARY KEY (run_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(run_id, severity);

CREATE TABLE IF NOT EXISTS proposals (
    proposal_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    strategy TEXT NOT NULL,
    target_file TEXT NOT NULL,
    workspace TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_proposals_run ON proposals(run_id);
CREATE INDEX IF NOT EXISTS idx_proposals_identity
    ON proposals(run_id, finding_id, target_file, strategy);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL UNIQUE,
    approved_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS patches (
    patch_id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    status TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_patches_proposal ON patches(proposal_id);
"""


def default_data_dir() -> Path:
    """Platform-appropriate local state directory."""
    override = os.environ.get(DATA_DIR_ENV)
    if override:
        return Path(override).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "tracemend"
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg).expanduser() / "tracemend"
    return Path.home() / ".local" / "share" / "tracemend"


def resolve_data_dir(data_dir: str | Path | None = None) -> Path:
    """Resolve the state directory, honouring ``TRACEMEND_DATA_DIR``."""
    if data_dir is None:
        return default_data_dir()
    return Path(data_dir).expanduser()


class Store:
    """Thin, typed wrapper around a local SQLite database."""

    def __init__(self, data_dir: str | Path | None = None) -> None:
        self.data_dir = resolve_data_dir(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / DB_FILENAME
        self.backup_dir = self.data_dir / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self._initialise()

    @classmethod
    def from_env(cls) -> Store:
        return cls(default_data_dir())

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialise(self) -> None:
        with self._connect() as connection:
            self._drop_legacy_tables(connection)
            connection.executescript(_SCHEMA)
            connection.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    @staticmethod
    def _drop_legacy_tables(connection: sqlite3.Connection) -> None:
        """Drop pre-composite-key derived tables.

        Older databases keyed ``findings`` by ``finding_id`` alone, which breaks
        as soon as a second run produces the same per-run id. Findings and
        reports are derived data, so they are rebuilt on the next analyse.
        """
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'findings'"
        ).fetchone()
        if row is None:
            return
        definition = (row["sql"] or "").replace("\n", " ")
        if "finding_id TEXT PRIMARY KEY" in definition:
            connection.execute("DROP TABLE findings")
            connection.execute("DROP TABLE reports")

    # ------------------------------------------------------------------ runs
    def save_run(self, run: TraceRun) -> TraceRun:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO runs(run_id, session_id, source, title, imported_at, payload)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    session_id=excluded.session_id,
                    source=excluded.source,
                    title=excluded.title,
                    imported_at=excluded.imported_at,
                    payload=excluded.payload
                """,
                (
                    run.run_id,
                    run.session_id,
                    run.source,
                    run.title,
                    run.imported_at.isoformat(),
                    run.model_dump_json(),
                ),
            )
        return run

    def get_run(self, run_id: str) -> TraceRun:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise RunNotFoundError(
                f"run not found: {run_id}",
                hint="Import a trace first, e.g. `tracemend analyze <trace.json>`.",
            )
        return TraceRun.model_validate_json(row["payload"])

    def has_run(self, run_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM runs WHERE run_id = ? LIMIT 1", (run_id,)
            ).fetchone()
        return row is not None

    def list_runs(self, limit: int = 50) -> list[TraceRun]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM runs ORDER BY imported_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [TraceRun.model_validate_json(row["payload"]) for row in rows]

    def delete_run(self, run_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
            connection.execute("DELETE FROM reports WHERE run_id = ?", (run_id,))
            connection.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))

    # --------------------------------------------------------------- reports
    def save_report(self, report: AnalysisReport) -> AnalysisReport:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO reports(run_id, generated_at, payload) VALUES(?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    generated_at=excluded.generated_at,
                    payload=excluded.payload
                """,
                (report.run_id, report.generated_at.isoformat(), report.model_dump_json()),
            )
            connection.execute("DELETE FROM findings WHERE run_id = ?", (report.run_id,))
            connection.executemany(
                """
                INSERT INTO findings(
                    finding_id, run_id, code, severity, confidence, tool, occurrences, payload
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        finding.id,
                        finding.run_id,
                        finding.code,
                        finding.severity,
                        finding.confidence,
                        finding.tool,
                        finding.occurrences,
                        finding.model_dump_json(),
                    )
                    for finding in report.findings
                ],
            )
        return report

    def get_report(self, run_id: str) -> AnalysisReport:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM reports WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise RunNotFoundError(
                f"no analysis stored for run: {run_id}",
                hint="Run `tracemend analyze <trace.json>` for this run first.",
            )
        return AnalysisReport.model_validate_json(row["payload"])

    def has_report(self, run_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM reports WHERE run_id = ? LIMIT 1", (run_id,)
            ).fetchone()
        return row is not None

    # -------------------------------------------------------------- findings
    def get_findings(
        self, run_id: str, *, severity: str | None = None, limit: int | None = None
    ) -> list[Finding]:
        query = "SELECT payload FROM findings WHERE run_id = ?"
        params: list[object] = [run_id]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY severity, occurrences DESC, finding_id"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        findings = [Finding.model_validate_json(row["payload"]) for row in rows]
        return sorted(findings, key=lambda finding: finding.sort_key)

    def get_finding(self, run_id: str, finding_id: str) -> Finding:
        """Fetch one finding by instance id, or by an unambiguous detector code.

        Instance ids such as ``TM002:bash:532575068ce1`` are unique within a run.
        A bare code such as ``TM002`` is accepted only when exactly one finding in
        the run carries it, so an ambiguous code can never silently resolve to the
        wrong finding.
        """
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM findings WHERE run_id = ? AND finding_id = ?",
                (run_id, finding_id),
            ).fetchone()
        if row is None and not self.has_report(run_id):
            raise RunNotFoundError(f"no analysis stored for run: {run_id}")
        if row is not None:
            return Finding.model_validate_json(row["payload"])

        code = finding_id.strip().upper()
        candidates = [finding for finding in self.get_findings(run_id) if finding.code == code]
        if len(candidates) == 1:
            return candidates[0]
        if candidates:
            ids = ", ".join(candidate.id for candidate in candidates)
            raise FindingNotFoundError(
                f"{finding_id} matches {len(candidates)} findings in run {run_id}",
                hint=f"Use one full finding id: {ids}",
            )
        raise FindingNotFoundError(
            f"finding not found for run {run_id}: {finding_id}",
            hint="List findings with `tracemend findings <run-id>`.",
        )

    # ------------------------------------------------------------- proposals
    def save_proposal(self, proposal: FixProposal) -> FixProposal:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO proposals(
                    proposal_id, run_id, finding_id, strategy, target_file,
                    workspace, status, created_at, payload
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(proposal_id) DO UPDATE SET
                    status=excluded.status,
                    payload=excluded.payload
                """,
                (
                    proposal.proposal_id,
                    proposal.run_id,
                    proposal.finding_id,
                    proposal.strategy,
                    proposal.target_file,
                    proposal.workspace,
                    proposal.status,
                    proposal.created_at.isoformat(),
                    proposal.model_dump_json(),
                ),
            )
        return proposal

    def get_proposal(self, proposal_id: str) -> FixProposal:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
        if row is None:
            raise ProposalNotFoundError(
                f"proposal not found: {proposal_id}",
                hint="Create one with `tracemend fix propose <run-id> <finding-id>`.",
            )
        return FixProposal.model_validate_json(row["payload"])

    def list_proposals(
        self, *, run_id: str | None = None, status: str | None = None
    ) -> list[FixProposal]:
        query = "SELECT payload FROM proposals"
        clauses: list[str] = []
        params: list[object] = []
        if run_id:
            clauses.append("run_id = ?")
            params.append(run_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [FixProposal.model_validate_json(row["payload"]) for row in rows]

    def find_proposal_for(
        self, run_id: str, finding_id: str, target_file: str, strategy: str
    ) -> FixProposal | None:
        """Idempotency lookup so the same fix is never proposed twice."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload FROM proposals
                WHERE run_id = ? AND finding_id = ? AND target_file = ? AND strategy = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (run_id, finding_id, target_file, strategy),
            ).fetchone()
        if row is None:
            return None
        return FixProposal.model_validate_json(row["payload"])

    # -------------------------------------------------------------- approvals
    def save_approval(self, record: ApprovalRecord) -> ApprovalRecord:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO approvals(approval_id, proposal_id, approved_at, payload)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(proposal_id) DO UPDATE SET
                    approval_id=excluded.approval_id,
                    approved_at=excluded.approved_at,
                    payload=excluded.payload
                """,
                (
                    record.approval_id,
                    record.proposal_id,
                    record.approved_at.isoformat(),
                    record.model_dump_json(),
                ),
            )
        return record

    def get_approval(self, proposal_id: str) -> ApprovalRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM approvals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
        if row is None:
            return None
        return ApprovalRecord.model_validate_json(row["payload"])

    # ---------------------------------------------------------------- patches
    def save_patch(self, record: PatchRecord) -> PatchRecord:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO patches(patch_id, proposal_id, run_id, status, applied_at, payload)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(patch_id) DO UPDATE SET
                    status=excluded.status,
                    payload=excluded.payload
                """,
                (
                    record.patch_id,
                    record.proposal_id,
                    record.run_id,
                    record.status,
                    record.applied_at.isoformat(),
                    record.model_dump_json(),
                ),
            )
        return record

    def get_patch(self, patch_id: str) -> PatchRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM patches WHERE patch_id = ?", (patch_id,)
            ).fetchone()
        if row is None:
            raise PatchNotFoundError(
                f"patch not found: {patch_id}",
                hint="Applied patches are listed by `tracemend fix list`.",
            )
        return PatchRecord.model_validate_json(row["payload"])

    def list_patches(
        self, *, run_id: str | None = None, proposal_id: str | None = None
    ) -> list[PatchRecord]:
        query = "SELECT payload FROM patches"
        clauses: list[str] = []
        params: list[object] = []
        if run_id:
            clauses.append("run_id = ?")
            params.append(run_id)
        if proposal_id:
            clauses.append("proposal_id = ?")
            params.append(proposal_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY applied_at DESC"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [PatchRecord.model_validate_json(row["payload"]) for row in rows]
