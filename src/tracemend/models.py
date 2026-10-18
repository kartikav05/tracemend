"""Frozen data contracts shared by the CLI, the MCP server and the services.

Every other module imports its types from here. Keep the public surface stable:
``adapters``, ``detectors``, ``analyzer``, ``fixes``, ``reports``, ``storage``,
``cli`` and ``mcp_server`` all depend on the names defined in this module.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["info", "low", "medium", "high"]
Confidence = Literal["low", "medium", "high"]
CallStatus = Literal["success", "error", "unknown"]
RunSource = Literal["generic", "opencode", "claude-code", "cursor"]
ProposalStatus = Literal["pending", "approved", "rejected", "applied", "undone", "stale"]
PatchStatus = Literal["applied", "undone"]
ProposalOrigin = Literal["deterministic", "ai"]

#: Detector codes -> human readable category title.
FINDING_CODES: dict[str, str] = {
    "TM001": "Duplicate tool calls",
    "TM002": "Failed retry loop",
    "TM003": "Repeated file reads",
    "TM004": "Redundant search patterns",
    "TM005": "Tool execution hotspot",
}

SEVERITY_RANK: dict[str, int] = {"high": 0, "medium": 1, "low": 2, "info": 3}

#: Canonical tool aliases. Keys are what traces report, values are what
#: detectors compare on. Deliberately conservative: only clear synonyms.
TOOL_ALIASES: dict[str, str] = {
    "sh": "bash",
    "shell": "bash",
    "zsh": "bash",
    "execute": "bash",
    "exec": "bash",
    "terminal": "bash",
    "readfile": "read",
    "read_file": "read",
    "view": "read",
    "cat": "read",
    "open_file": "read",
    "readfiletool": "read",
    "ripgrep": "grep",
    "rg": "grep",
    "grep_search": "grep",
    "grepsearch": "grep",
    "search_text": "grep",
    "list": "ls",
    "listdir": "ls",
    "list_dir": "ls",
    "glob_search": "glob",
    "globsearch": "glob",
    "find_files": "glob",
}

_SUCCESS_TOKENS = {"ok", "success", "succeeded", "completed", "complete", "passed", "done", "0"}
_ERROR_TOKENS = {"error", "failed", "failure", "fail", "errored", "exception", "timeout"}

# Bounded vocabularies for prose statuses. Words are matched whole, never as
# substrings, so "broken" and "lookbook" cannot be read as "ok".
_SUCCESS_WORDS = frozenset(
    {
        "ok",
        "okay",
        "success",
        "successful",
        "successfully",
        "succeed",
        "succeeded",
        "succeeds",
        "complete",
        "completed",
        "done",
        "passed",
    }
)
_FAILURE_WORDS = frozenset(
    {
        "error",
        "errors",
        "errored",
        "fail",
        "fails",
        "failed",
        "failing",
        "failure",
        "failures",
        "exception",
        "exceptions",
        "timeout",
        "timeouts",
    }
)
# Bound negation so "no errors found" is neither a failure nor a success.
_NEGATION_WORDS = frozenset(
    {"no", "not", "without", "zero", "none", "never", "neither", "nor", "0"}
)
_NEGATION_FILLERS = frozenset({"a", "an", "the", "any", "more", "further", "single", "new"})
_WORD_RE = re.compile(r"[a-z0-9]+")


def utc_now() -> datetime:
    """Timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def canonical_json(value: Any) -> str:
    """Deterministic JSON encoding used for argument hashing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def short_hash(text: str, length: int = 12) -> str:
    """Stable short digest used for ids and fingerprints."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_tool_name(name: str) -> str:
    """Lower-case and de-alias a tool name so detectors can group calls."""
    cleaned = re.sub(r"[^a-z0-9_]+", "_", (name or "").strip().lower()).strip("_")
    if not cleaned:
        return "unknown"
    return TOOL_ALIASES.get(cleaned, cleaned)


def _classify_status_words(words: list[str]) -> CallStatus:
    """Classify pre-tokenised status prose; a genuine failure always wins."""
    has_failure = False
    has_success = False
    index = 0
    while index < len(words):
        word = words[index]
        if word in _NEGATION_WORDS:
            target = index + 1
            budget = 2
            while target < len(words) and budget and words[target] in _NEGATION_FILLERS:
                target += 1
                budget -= 1
            if target < len(words) and (
                words[target] in _FAILURE_WORDS or words[target] in _SUCCESS_WORDS
            ):
                # "no errors", "not failed", "not ok": consume the negated word.
                index = target + 1
                continue
        if word in _FAILURE_WORDS:
            has_failure = True
        elif word in _SUCCESS_WORDS:
            has_success = True
        elif word in {"timed", "time"} and index + 1 < len(words) and words[index + 1] == "out":
            has_failure = True
        index += 1
    if has_failure:
        return "error"
    if has_success:
        return "success"
    return "unknown"


def normalize_status(value: Any) -> CallStatus:
    """Map heterogeneous status values onto a three-state model.

    Booleans and numbers are explicit: ``True``/``0`` mean success, ``False``
    and any other number mean error. Text is matched on whole words, never on
    substrings, so ``broken`` is not ``ok`` and ``lookup failed`` is an error.
    A bounded negation (``no errors found``, ``not failed``, ``not ok``) is
    consumed and yields ``unknown`` unless another word is decisive.
    """
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "success" if value else "error"
    if isinstance(value, (int, float)):
        return "success" if value == 0 else "error"
    text = str(value).strip().lower()
    if text in _SUCCESS_TOKENS:
        return "success"
    if text in _ERROR_TOKENS:
        return "error"
    return _classify_status_words(_WORD_RE.findall(text.replace("n't", " not")))


def coerce_datetime(value: Any) -> datetime | None:
    """Best-effort timestamp coercion; never raises, returns ``None`` if unclear."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        seconds = value / 1000.0 if value > 1e11 else float(value)
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def make_finding_id(code: str, tool: str, key: str) -> str:
    """Deterministic, unique per-instance finding identifier."""
    return f"{code}:{normalize_tool_name(tool)}:{short_hash(key)}"


def new_id(prefix: str, length: int = 12) -> str:
    return f"{prefix}_{secrets.token_hex(length // 2)}"


class TokenUsage(BaseModel):
    model_config = ConfigDict(extra="ignore")

    input_tokens: int | None = None
    output_tokens: int | None = None

    @property
    def total(self) -> int | None:
        if self.input_tokens is None and self.output_tokens is None:
            return None
        return (self.input_tokens or 0) + (self.output_tokens or 0)


class ToolCall(BaseModel):
    """One normalized agent tool invocation."""

    model_config = ConfigDict(extra="ignore")

    id: str
    session_id: str = "session_unknown"
    agent_id: str = "main"
    parent_agent_id: str | None = None
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: CallStatus = "unknown"
    timestamp: datetime | None = None
    sequence: int = 0
    duration_ms: int | None = None
    error: str | None = None
    token_usage: TokenUsage | None = None
    cost: float | None = None
    result_fingerprint: str | None = None
    modified_files: list[str] = Field(default_factory=list)
    output_excerpt: str | None = None
    raw_index: int | None = None

    @field_validator("tool")
    @classmethod
    def _tool_not_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("tool name must not be empty")
        return value

    @field_validator("arguments", mode="before")
    @classmethod
    def _arguments_is_mapping(cls, value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                decoded = json.loads(value)
            except json.JSONDecodeError:
                return {"_raw": value}
            return decoded if isinstance(decoded, dict) else {"_value": decoded}
        if isinstance(value, (list, tuple)):
            return {"_items": list(value)}
        return {"_value": value}

    @property
    def normalized_tool(self) -> str:
        return normalize_tool_name(self.tool)

    @property
    def argument_fingerprint(self) -> str:
        """Hash of the canonicalized arguments (ignores tool name)."""
        return short_hash(canonical_json(self.arguments))

    @property
    def call_fingerprint(self) -> str:
        """Hash of tool + arguments, ignoring agent and timing information."""
        return short_hash(f"{self.normalized_tool}|{self.argument_fingerprint}")

    @property
    def is_failure(self) -> bool:
        return self.status == "error"

    def primary_target(self) -> str | None:
        """Best-effort target path/pattern, used to group related calls."""
        for key in ("path", "file", "file_path", "target", "filename", "notebook_path"):
            value = self.arguments.get(key)
            if isinstance(value, str) and value:
                return value
        for key in ("pattern", "query", "command", "cmd", "script"):
            value = self.arguments.get(key)
            if isinstance(value, str) and value:
                return value
        return None


class TraceRun(BaseModel):
    """A normalized, imported agent session."""

    model_config = ConfigDict(extra="ignore")

    run_id: str
    session_id: str = "session_unknown"
    title: str = "Untitled session"
    source: RunSource = "generic"
    model: str | None = None
    agent_name: str | None = None
    created_at: datetime | None = None
    imported_at: datetime = Field(default_factory=utc_now)
    source_path: str | None = None
    source_sha256: str | None = None
    events: list[ToolCall] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    redactions: list[str] = Field(default_factory=list)
    truncated: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def event_count(self) -> int:
        return len(self.events)

    def event_by_id(self) -> dict[str, ToolCall]:
        return {event.id: event for event in self.events}

    def events_for_tool(self, tool: str) -> list[ToolCall]:
        normalized = normalize_tool_name(tool)
        return [event for event in self.events if event.normalized_tool == normalized]


class ToolStat(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tool: str
    calls: int = 0
    failures: int = 0
    duplicate_calls: int = 0
    duration_ms: int | None = None
    tokens: int | None = None


class RunMetrics(BaseModel):
    """Measured facts about a run. ``None`` means genuinely unavailable."""

    model_config = ConfigDict(extra="ignore")

    total_calls: int = 0
    failed_calls: int = 0
    duplicate_calls: int = 0
    distinct_tools: int = 0
    duration_ms: int | None = None
    total_tokens: int | None = None
    total_cost: float | None = None
    subagent_calls: int = 0
    tool_stats: dict[str, ToolStat] = Field(default_factory=dict)


class Finding(BaseModel):
    """An evidence-backed inefficiency detected in a run."""

    model_config = ConfigDict(extra="ignore")

    id: str
    code: str
    run_id: str
    severity: Severity = "medium"
    confidence: Confidence = "medium"
    title: str
    description: str
    tool: str = "unknown"
    occurrences: int = 1
    evidence: list[str] = Field(default_factory=list)
    recommendation: str = ""
    fixable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("code")
    @classmethod
    def _known_code(cls, value: str) -> str:
        if value not in FINDING_CODES:
            raise ValueError(f"unknown finding code: {value}")
        return value

    @property
    def sort_key(self) -> tuple[int, int, str]:
        return (SEVERITY_RANK.get(self.severity, 9), -self.occurrences, self.id)


class AnalysisReport(BaseModel):
    """The full deterministic analysis of one run."""

    model_config = ConfigDict(extra="ignore")

    run_id: str
    session_id: str = "session_unknown"
    title: str = "Untitled session"
    source: RunSource = "generic"
    generated_at: datetime = Field(default_factory=utc_now)
    metrics: RunMetrics = Field(default_factory=RunMetrics)
    findings: list[Finding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    def findings_by_severity(self, severity: str) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity == severity]

    def find_finding(self, finding_id: str) -> Finding | None:
        for finding in self.findings:
            if finding.id == finding_id:
                return finding
        return None

    @property
    def fixable_count(self) -> int:
        return sum(1 for finding in self.findings if finding.fixable)


class ApprovalRecord(BaseModel):
    """A single-use human approval, bound to one exact patch."""

    model_config = ConfigDict(extra="ignore")

    approval_id: str
    proposal_id: str
    patch_sha256: str
    workspace: str
    target_file: str
    original_sha256: str
    approved_at: datetime = Field(default_factory=utc_now)
    approved_by: str = "local-cli"
    status: str = "granted"


class FixProposal(BaseModel):
    """A reviewable instruction patch, never applied without approval."""

    model_config = ConfigDict(extra="ignore")

    proposal_id: str
    run_id: str
    finding_id: str
    code: str
    strategy: str
    title: str
    rationale: str
    instruction_text: str
    workspace: str
    target_file: str = "AGENTS.md"
    original_sha256: str
    original_content: str
    proposed_sha256: str
    patch: str
    origin: ProposalOrigin = "deterministic"
    evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    status: ProposalStatus = "pending"
    applied_at: datetime | None = None
    applied_sha256: str | None = None
    patch_id: str | None = None
    approval_id: str | None = None

    @property
    def patch_sha256(self) -> str:
        return sha256_text(self.patch)

    @property
    def is_applicable(self) -> bool:
        return self.status == "approved"


class PatchRecord(BaseModel):
    """A TraceMend patch that was written to disk."""

    model_config = ConfigDict(extra="ignore")

    patch_id: str
    proposal_id: str
    run_id: str
    workspace: str
    target_file: str
    strategy: str
    applied_at: datetime = Field(default_factory=utc_now)
    original_sha256: str
    applied_sha256: str
    backup_path: str
    status: PatchStatus = "applied"
    undone_at: datetime | None = None


class MetricDelta(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    before: float | int | None = None
    after: float | int | None = None
    delta: float | int | None = None
    percent_change: float | None = None
    available: bool = True


class ComparisonReport(BaseModel):
    """Behavioural comparison of two runs. Correlation, not causation."""

    model_config = ConfigDict(extra="ignore")

    before_run_id: str
    after_run_id: str
    before_title: str = ""
    after_title: str = ""
    generated_at: datetime = Field(default_factory=utc_now)
    deltas: list[MetricDelta] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    def delta_for(self, name: str) -> MetricDelta | None:
        for delta in self.deltas:
            if delta.name == name:
                return delta
        return None


class ImportSummary(BaseModel):
    """What ``load_trace`` reports back to a caller."""

    model_config = ConfigDict(extra="ignore")

    run_id: str
    source: RunSource
    session_id: str
    title: str
    event_count: int
    skipped_records: int = 0
    warnings: list[str] = Field(default_factory=list)
    redactions_applied: int = 0
    truncated: bool = False
    source_path: str | None = None
