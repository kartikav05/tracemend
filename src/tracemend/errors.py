"""Exception hierarchy shared by the CLI, the MCP server and the services."""

from __future__ import annotations


class TraceMendError(Exception):
    """Base class for every error TraceMend raises deliberately."""

    code = "TRACEMEND_ERROR"
    exit_code = 1

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def to_dict(self) -> dict[str, str]:
        payload = {"error": self.code, "message": self.message}
        if self.hint:
            payload["hint"] = self.hint
        return payload


class TraceParseError(TraceMendError):
    """The trace file could not be parsed or failed validation."""

    code = "TRACE_PARSE_ERROR"
    exit_code = 2


class UnsupportedFormatError(TraceParseError):
    """The trace format is recognised but not supported."""

    code = "UNSUPPORTED_FORMAT"


class TraceTooLargeError(TraceParseError):
    """The trace file exceeds the configured size limit."""

    code = "TRACE_TOO_LARGE"


class RunNotFoundError(TraceMendError):
    """The requested run is not present in the local store."""

    code = "RUN_NOT_FOUND"
    exit_code = 3


class FindingNotFoundError(TraceMendError):
    """The requested finding does not exist for the given run."""

    code = "FINDING_NOT_FOUND"
    exit_code = 3


class ProposalNotFoundError(TraceMendError):
    """The requested fix proposal does not exist."""

    code = "PROPOSAL_NOT_FOUND"
    exit_code = 3


class PatchNotFoundError(TraceMendError):
    """The requested applied patch does not exist."""

    code = "PATCH_NOT_FOUND"
    exit_code = 3


class SecurityError(TraceMendError):
    """A safety invariant was violated (path escape, symlink, unsafe target)."""

    code = "SECURITY_ERROR"
    exit_code = 4


class ApprovalRequiredError(TraceMendError):
    """A write was attempted without a valid, matching human approval."""

    code = "APPROVAL_REQUIRED"
    exit_code = 5


class StaleFileError(TraceMendError):
    """The target file changed after the proposal was generated."""

    code = "STALE_FILE"
    exit_code = 5


class ProposalConflictError(TraceMendError):
    """The proposal is in a state that forbids the requested operation."""

    code = "PROPOSAL_CONFLICT"
    exit_code = 5


class UndoConflictError(TraceMendError):
    """The target file was modified after TraceMend applied its patch."""

    code = "UNDO_CONFLICT"
    exit_code = 5


class NotFixableError(TraceMendError):
    """The finding cannot be remediated automatically."""

    code = "NOT_FIXABLE"
    exit_code = 3
