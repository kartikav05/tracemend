"""Safety primitives: redaction, path guarding, hashing and atomic writes.

This module is the single place where TraceMend decides what is safe to read,
what is safe to write, and what must never leave the machine. Everything that
touches the filesystem or trace content goes through here.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any

from .errors import ProposalConflictError, SecurityError

try:  # POSIX only; Windows has no cooperative directory locking.
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

#: Hard ceiling for a single imported trace file (32 MiB).
MAX_TRACE_BYTES = 32 * 1024 * 1024
#: Maximum characters kept from a single tool output preview.
MAX_PREVIEW_CHARS = 400
#: Maximum characters allowed for an AI- or template-generated instruction.
MAX_INSTRUCTION_CHARS = 4000
#: The only file TraceMend is allowed to modify in a workspace.
ALLOWED_TARGET_NAME = "AGENTS.md"

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

#: Darwin ``copyfile(3)`` flags: ``COPYFILE_ACL | COPYFILE_STAT | COPYFILE_XATTR``.
#: ``shutil.copy2`` only asks for ``COPYFILE_DATA``, so it drops ACLs and xattrs.
_COPYFILE_METADATA = 0x00000007
#: BSD ``sys/stat.h`` immutable and append-only flags. The kernel rejects replacement
#: while any of them is set, so TraceMend refuses early with an actionable error.
_UNSAFE_FLAGS = 0x00000002 | 0x00000004 | 0x00020000 | 0x00040000
#: ``errno`` values ``flock(2)`` returns when a peer already holds the workspace lock.
_LOCK_BUSY_ERRNOS = frozenset({errno.EACCES, errno.EAGAIN})
_LOCK_POLL_SECONDS = 0.05

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|private[_-]?token)\b\s*[:=]\s*[\"']?([^\s\"',;]{6,})"
        ),
    ),
    ("connection_string", re.compile(r"(?i)\b(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^\s\"']+:[^\s\"'@]+@")),
)

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def redact_text(text: str) -> tuple[str, list[str]]:
    """Replace detected secrets in ``text``.

    Returns the redacted text plus the sorted list of pattern names that fired.
    """
    if not text:
        return text, []
    hits: set[str] = set()
    result = text
    for name, pattern in _SECRET_PATTERNS:
        if name == "credential_assignment":
            def _replace_assignment(match: re.Match[str]) -> str:
                return f"{match.group(1)}=[REDACTED:credential]"

            new_result, count = pattern.subn(_replace_assignment, result)
        else:
            new_result, count = pattern.subn(f"[REDACTED:{name}]", result)
        if count:
            hits.add(name)
            result = new_result
    return result, sorted(hits)


def redact_value(value: Any, *, depth: int = 0) -> tuple[Any, list[str]]:
    """Recursively redact strings inside JSON-compatible structures."""
    if depth > 12:
        return "[REDACTED:depth]", ["depth_limit"]
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        hits: set[str] = set()
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            new_key, key_hits = redact_text(str(key))
            new_value, value_hits = redact_value(item, depth=depth + 1)
            hits.update(key_hits)
            hits.update(value_hits)
            cleaned[new_key] = new_value
        return cleaned, sorted(hits)
    if isinstance(value, (list, tuple)):
        hits = set()
        cleaned_list = []
        for item in value:
            new_item, item_hits = redact_value(item, depth=depth + 1)
            hits.update(item_hits)
            cleaned_list.append(new_item)
        return cleaned_list, sorted(hits)
    return value, []


def limit_preview(text: str | None, limit: int = MAX_PREVIEW_CHARS) -> str | None:
    """Trim a tool output to a safe preview length."""
    if text is None:
        return None
    stripped = _CONTROL_CHARS.sub("", text).strip()
    if len(stripped) <= limit:
        return stripped
    return stripped[:limit] + "... [truncated]"


def validate_instruction_text(text: str) -> str:
    """Validate instruction text destined for an ``AGENTS.md`` patch."""
    if not isinstance(text, str):
        raise SecurityError("instruction text must be a string")
    cleaned = _CONTROL_CHARS.sub("", text)
    if not cleaned.strip():
        raise SecurityError("instruction text must not be empty")
    if len(cleaned) > MAX_INSTRUCTION_CHARS:
        raise SecurityError(
            f"instruction text exceeds {MAX_INSTRUCTION_CHARS} characters",
            hint="Keep the proposed instruction minimal and focused.",
        )
    if "```" in cleaned:
        raise SecurityError(
            "instruction text must not contain fenced code blocks",
            hint="TraceMend only writes Markdown prose into AGENTS.md.",
        )
    return cleaned


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    """Hash a file's bytes. Raises ``FileNotFoundError`` if it is missing."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_file_or_empty(path: str | Path) -> str:
    """Hash a file, treating a missing file as empty content."""
    try:
        return sha256_file(path)
    except FileNotFoundError:
        return EMPTY_SHA256


def read_text_limited(path: str | Path, limit: int = MAX_TRACE_BYTES) -> str:
    """Read UTF-8 text from ``path``, refusing oversized inputs."""
    target = Path(path)
    try:
        size = target.stat().st_size
    except FileNotFoundError as exc:
        raise SecurityError(f"file not found: {target}") from exc
    if size > limit:
        from .errors import TraceTooLargeError

        raise TraceTooLargeError(
            f"file is {size} bytes, limit is {limit} bytes",
            hint="Trim the trace or raise TraceMend's size limit deliberately.",
        )
    return target.read_text(encoding="utf-8", errors="replace")


def resolve_workspace(workspace: str | Path) -> Path:
    """Resolve a workspace directory, refusing anything that is not a real dir."""
    candidate = Path(workspace).expanduser()
    if not candidate.exists():
        raise SecurityError(f"workspace does not exist: {candidate}")
    if not candidate.is_dir():
        raise SecurityError(f"workspace is not a directory: {candidate}")
    return candidate.resolve(strict=True)


def is_within(base: Path, candidate: Path) -> bool:
    """True when ``candidate`` is ``base`` itself or lives underneath it."""
    base_resolved = base.resolve()
    candidate_resolved = candidate.resolve()
    if base_resolved == candidate_resolved:
        return True
    return base_resolved in candidate_resolved.parents


def validate_target_file(target_file: str) -> str:
    """Only a project-local ``AGENTS.md`` may ever be modified."""
    if not isinstance(target_file, str) or not target_file.strip():
        raise SecurityError("target file must be a non-empty string")
    raw = target_file.strip()
    if raw.startswith(("/", "~")) or re.match(r"^[A-Za-z]:[\\/]", raw):
        raise SecurityError(
            f"target file must be relative to the workspace: {target_file!r}",
            hint="TraceMend only edits a project-local AGENTS.md.",
        )
    parts = Path(raw).parts
    if ".." in parts:
        raise SecurityError(f"target file must not traverse upwards: {target_file!r}")
    if Path(raw).name != ALLOWED_TARGET_NAME:
        raise SecurityError(
            f"refusing to modify {target_file!r}: only {ALLOWED_TARGET_NAME} is supported",
            hint="TraceMend v0.1 intentionally edits agent instructions only.",
        )
    return str(Path(*parts))


def resolve_target_path(workspace: Path, target_file: str) -> Path:
    """Resolve a validated target path, rejecting symlink escapes."""
    relative = validate_target_file(target_file)
    workspace_resolved = workspace.resolve(strict=True)
    candidate = workspace_resolved / relative

    for parent in _iter_parents(candidate.parent, workspace_resolved):
        if parent.is_symlink():
            raise SecurityError(
                f"refusing to write through symlinked directory: {parent}",
                hint="TraceMend does not follow symlinks inside a workspace.",
            )

    if candidate.is_symlink():
        raise SecurityError(
            f"refusing to write to symlink: {candidate}",
            hint="Replace the symlink with a regular file if you want TraceMend to edit it.",
        )

    if candidate.exists():
        resolved = candidate.resolve()
        if not is_within(workspace_resolved, resolved):
            raise SecurityError(f"target escapes the workspace: {candidate}")
    elif not is_within(workspace_resolved, candidate):
        raise SecurityError(f"target escapes the workspace: {candidate}")

    return candidate


def _iter_parents(start: Path, stop: Path) -> Iterator[Path]:
    """Yield ``start`` and its parents up to (but excluding) ``stop``."""
    current = start
    stop_resolved = stop.resolve()
    while True:
        if current.resolve() == stop_resolved:
            return
        yield current
        if current.parent == current:
            return
        current = current.parent


def atomic_write_text(
    path: str | Path,
    text: str,
    *,
    encoding: str = "utf-8",
    metadata_source: str | Path | None = None,
) -> None:
    """Write text atomically: temp file in the same directory, then ``os.replace``.

    Mode, ownership, ACLs and xattrs are copied onto the temporary file *before* the
    replace, so the swap never exposes a file with the wrong metadata. ``metadata_source``
    defaults to the existing target; a missing target means "create", so there is no
    metadata to preserve. Callers own path containment and symlink checks.
    """
    target = Path(path)
    explicit = metadata_source is not None
    donor_path = target if metadata_source is None else Path(metadata_source)
    donor = _metadata_donor(donor_path, explicit=explicit)
    _raise_unsafe_flags(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    _atomic_replace(target, text.encode(encoding), donor=donor)


def _atomic_replace(target: Path, data: bytes, *, donor: Path | None) -> None:
    """Write ``data`` to a sibling temp file, seal it with ``donor`` metadata, replace."""
    temp_path: Path | None = None
    try:
        fd, temp_name = tempfile.mkstemp(
            dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
        )
        temp_path = Path(temp_name)
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        if donor is not None:
            _copy_metadata(donor, temp_path)
            _fsync_path(temp_path)
        _replace(temp_path, target)
        temp_path = None
        _fsync_directory(target.parent)
    finally:
        if temp_path is not None:
            _safe_unlink(temp_path)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


def _replace(source: Path, target: Path) -> None:
    try:
        os.replace(source, target)
    except OSError as exc:
        if exc.errno in {errno.EPERM, errno.EACCES, errno.EROFS}:
            raise SecurityError(
                f"refusing to replace {target}: {exc.strerror}",
                hint="The file or its directory is protected by permissions, ACLs or flags.",
            ) from exc
        raise


def _fsync_path(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> None:
    """Persist a directory-entry change (rename or unlink). POSIX only."""
    if os.name != "posix":  # pragma: no cover - Windows cannot fsync a directory
        return
    _fsync_path(path)


def _safe_unlink(path: Path) -> None:
    """Remove a temporary artefact, clearing flags we may have copied onto it."""
    if path.exists() and hasattr(os, "chflags"):
        with contextlib.suppress(OSError):
            os.chflags(path, 0)
    with contextlib.suppress(OSError):
        path.unlink()


def _metadata_donor(source: Path, *, explicit: bool) -> Path | None:
    """Return a regular, non-symlinked metadata source, or ``None`` when creating."""
    if source.is_symlink():
        raise SecurityError(
            f"refusing to copy metadata from symlink: {source}",
            hint="Replace the symlink with a regular file if you want TraceMend to edit it.",
        )
    if not source.exists():
        if explicit:
            raise SecurityError(f"metadata source does not exist: {source}")
        return None
    if not source.is_file():
        raise SecurityError(f"metadata source is not a regular file: {source}")
    return source


def _raise_unsafe_flags(path: Path) -> None:
    """Refuse files the kernel would not let us replace, with a clear error."""
    if not hasattr(os, "chflags") or not hasattr(os.stat_result, "st_flags"):
        return
    if not path.exists():
        return
    if path.stat().st_flags & _UNSAFE_FLAGS:
        raise SecurityError(
            f"refusing to modify {path}: immutable or append-only flags are set",
            hint="Clear the flags first (for example: chflags nouchg <file>).",
        )


def _copy_metadata(source: Path, target: Path) -> None:
    """Copy mode, ownership, ACLs and xattrs onto ``target``, or fail closed.

    ``shutil.copystat`` alone is not sufficient: on macOS it cannot copy ACLs (and this
    interpreter exposes no ``os.listxattr``), so metadata goes through ``copyfile(3)``.
    """
    try:
        if sys.platform == "darwin":
            _darwin_copy_metadata(source, target)
        elif sys.platform.startswith("linux"):
            shutil.copystat(source, target, follow_symlinks=False)
            _copy_xattrs(source, target)
        else:  # pragma: no cover - unsupported platforms only
            raise SecurityError(
                f"cannot preserve file metadata on {sys.platform}",
                hint="TraceMend will not replace a file when mode, owner or ACLs would be lost.",
            )
    except OSError as exc:
        raise SecurityError(
            f"could not preserve metadata from {source}: {exc}",
            hint="TraceMend will not replace a file when mode, owner, ACLs or xattrs would be lost.",
        ) from exc
    _verify_metadata(source, target)


def _darwin_copy_metadata(source: Path, target: Path) -> None:
    """Copy ACL, stat and xattr metadata with Darwin's ``fcopyfile(3)``."""
    import ctypes

    source_fd = os.open(source, os.O_RDONLY)
    try:
        target_fd = os.open(target, os.O_RDONLY)
    except BaseException:
        os.close(source_fd)
        raise
    try:
        libc = _darwin_libc()
        if libc.fcopyfile(source_fd, target_fd, None, _COPYFILE_METADATA) != 0:
            code = ctypes.get_errno()
            raise OSError(code, f"fcopyfile metadata: {os.strerror(code)}")
    finally:
        os.close(source_fd)
        os.close(target_fd)


@cache
def _darwin_libc() -> Any:
    import ctypes
    import ctypes.util

    libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    libc.fcopyfile.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    libc.fcopyfile.restype = ctypes.c_int
    return libc


def _copy_xattrs(source: Path, target: Path) -> None:
    if not hasattr(os, "listxattr"):  # pragma: no cover - Linux CPython always has it
        raise SecurityError(f"cannot enumerate extended attributes of {source}")
    for name in os.listxattr(source):
        try:
            os.setxattr(target, name, os.getxattr(source, name))
        except OSError as exc:
            raise SecurityError(
                f"could not preserve extended attribute {name!r} from {source}: {exc}"
            ) from exc


def _verify_metadata(source: Path, target: Path) -> None:
    expected = source.stat()
    actual = target.stat()
    lost = []
    if stat.S_IMODE(expected.st_mode) != stat.S_IMODE(actual.st_mode):
        lost.append("mode")
    if (expected.st_uid, expected.st_gid) != (actual.st_uid, actual.st_gid):
        lost.append("ownership")
    if lost:
        raise SecurityError(
            f"could not preserve {' and '.join(lost)} when copying {source}",
            hint="TraceMend refuses to change file permissions or ownership implicitly.",
        )


def make_backup(path: str | Path, backup_dir: str | Path) -> Path:
    """Snapshot ``path`` into ``backup_dir`` as an independent, durable copy.

    The snapshot holds the exact bytes *and* mode, ownership, ACLs and xattrs, in a
    separate inode, so later in-place edits to the original cannot mutate it. A missing
    source still produces an empty snapshot; whether the file existed is journal state,
    never inferred from the backup bytes. A failure leaves no partial snapshot behind.
    """
    source = Path(path)
    directory = Path(backup_dir)
    directory.mkdir(parents=True, exist_ok=True)
    exists = source.exists()
    if exists:
        if source.is_symlink():
            raise SecurityError(f"refusing to back up symlink: {source}")
        if not source.is_file():
            raise SecurityError(f"refusing to back up non-regular file: {source}")
    destination = _create_backup_file(directory, source.name)
    try:
        if exists:
            _copy_bytes(source, destination)
            _copy_metadata(source, destination)
        _fsync_path(destination)
        _fsync_directory(directory)
    except BaseException:
        _safe_unlink(destination)
        raise
    return destination


def _create_backup_file(directory: Path, name: str) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    for attempt in range(16):
        suffix = "" if attempt == 0 else f"-{attempt}"
        candidate = directory / f"{name}.{stamp}{suffix}.bak"
        try:
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        os.close(fd)
        return candidate
    raise SecurityError(f"could not allocate a unique backup name in {directory}")


def _copy_bytes(source: Path, destination: Path) -> None:
    with source.open("rb") as source_handle, destination.open("wb") as target_handle:
        shutil.copyfileobj(source_handle, target_handle)
        target_handle.flush()
        os.fsync(target_handle.fileno())


def verify_backup(backup_path: str | Path, expected_sha256: str) -> None:
    """Refuse a backup that is missing, not a regular file, a symlink, or tampered."""
    backup = Path(backup_path)
    if backup.is_symlink():
        raise SecurityError(f"refusing to trust symlinked backup: {backup}")
    if not backup.exists():
        raise ProposalConflictError(
            f"backup is missing: {backup}",
            hint="The pre-patch content cannot be restored automatically.",
        )
    if not backup.is_file():
        raise SecurityError(f"backup is not a regular file: {backup}")
    if sha256_file(backup) != expected_sha256:
        raise ProposalConflictError(
            f"backup {backup} no longer matches the recorded original content",
            hint="The snapshot was modified; undo cannot be trusted.",
        )


def atomic_restore(target_path: str | Path, backup_path: str | Path) -> None:
    """Atomically restore the bytes and metadata of ``backup_path`` onto ``target_path``.

    Callers must run :func:`verify_backup` and the target hash checks first; this helper
    only guarantees an atomic, metadata-faithful replacement (or recreation) of the target.
    """
    target = Path(target_path)
    backup = Path(backup_path)
    if backup.is_symlink():
        raise SecurityError(f"refusing to restore from symlinked backup: {backup}")
    if not backup.is_file():
        raise SecurityError(f"backup is not a regular file: {backup}")
    _raise_unsafe_flags(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    _atomic_replace(target, backup.read_bytes(), donor=backup)


@contextlib.contextmanager
def workspace_lock(workspace: str | Path, *, timeout: float = 10.0) -> Iterator[None]:
    """Hold an exclusive advisory ``flock`` on the workspace directory itself.

    The lock lives on the canonical directory's file descriptor, so no lock file is
    created inside the workspace and every store pointing at that directory serialises
    against the same lock. Advisory, non-reentrant, POSIX only.
    """
    if fcntl is None:  # pragma: no cover - Windows
        raise SecurityError(
            "cooperative workspace locking is not supported on this platform",
            hint="TraceMend needs POSIX flock(2) to serialise apply and undo.",
        )
    path = resolve_workspace(workspace)
    fd = os.open(path, os.O_RDONLY)
    deadline = time.monotonic() + max(timeout, 0.0)
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in _LOCK_BUSY_ERRNOS:
                    raise SecurityError(f"cannot lock workspace {path}: {exc}") from exc
                if time.monotonic() >= deadline:
                    raise ProposalConflictError(
                        f"workspace is busy: another TraceMend write holds {path}",
                        hint="Wait for the other apply or undo to finish, then retry.",
                    ) from exc
                time.sleep(_LOCK_POLL_SECONDS)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def ensure_within_workspace(workspace: Path, candidate: Path, *, what: str = "path") -> Path:
    """Guard for any path that will be read or written on behalf of a workspace."""
    resolved_workspace = workspace.resolve(strict=True)
    resolved = candidate.resolve()
    if not is_within(resolved_workspace, resolved):
        raise SecurityError(f"{what} escapes the workspace: {candidate}")
    return resolved


def unique_preserving_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered
