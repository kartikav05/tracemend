"""Safety primitives: redaction, path guarding, hashing and atomic writes.

This module is the single place where TraceMend decides what is safe to read,
what is safe to write, and what must never leave the machine. Everything that
touches the filesystem or trace content goes through here.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import SecurityError

#: Hard ceiling for a single imported trace file (32 MiB).
MAX_TRACE_BYTES = 32 * 1024 * 1024
#: Maximum characters kept from a single tool output preview.
MAX_PREVIEW_CHARS = 400
#: Maximum characters allowed for an AI- or template-generated instruction.
MAX_INSTRUCTION_CHARS = 4000
#: The only file TraceMend is allowed to modify in a workspace.
ALLOWED_TARGET_NAME = "AGENTS.md"

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

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


def atomic_write_text(path: str | Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write text atomically: temp file in the same directory, then ``os.replace``."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding=encoding,
            dir=str(target.parent),
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
            newline="\n",
        ) as handle:
            tmp_path = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
    except BaseException:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)
        raise


def make_backup(path: str | Path, backup_dir: str | Path) -> Path:
    """Copy ``path`` into ``backup_dir`` before it is modified.

    A missing source file still produces a backup marker, so undo can restore
    the "file did not exist" state.
    """
    source = Path(path)
    directory = Path(backup_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    destination = directory / f"{source.name}.{stamp}.bak"
    if source.exists():
        shutil.copy2(source, destination)
    else:
        destination.write_text("", encoding="utf-8")
    return destination


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
