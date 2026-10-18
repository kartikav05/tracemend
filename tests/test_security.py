"""Tests for the frozen safety primitives in :mod:`tracemend.security`."""

from __future__ import annotations

import errno
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tracemend import security
from tracemend.errors import ProposalConflictError, SecurityError, TraceTooLargeError

DARWIN = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")
POSIX = os.name == "posix"
#: macOS ``UF_IMMUTABLE`` from ``sys/stat.h``.
UF_IMMUTABLE = 0x00000002
ACL_ENTRY = "everyone allow read"


def _set_acl(path: Path) -> bool:
    """Attach a benign ACL entry; ``False`` when the filesystem cannot store one."""
    if shutil.which("chmod") is None:
        return False
    result = subprocess.run(
        ["chmod", "+a", ACL_ENTRY, str(path)], capture_output=True, check=False
    )
    return result.returncode == 0


def _acl_lines(path: Path) -> str:
    result = subprocess.run(
        ["ls", "-le", str(path)], capture_output=True, text=True, check=False
    )
    return result.stdout


def _set_xattr(path: Path) -> bool:
    if shutil.which("xattr") is None:
        return False
    result = subprocess.run(
        ["xattr", "-w", "user.tracemend_test", "probe", str(path)],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def _xattr_value(path: Path) -> str:
    result = subprocess.run(
        ["xattr", "-p", "user.tracemend_test", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip()

OPENAI_KEY = "sk-" + "A" * 32
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
JWT = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)
BEARER = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"
PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAsecretmaterial\n"
    "-----END RSA PRIVATE KEY-----"
)


class TestRedaction(unittest.TestCase):
    def test_openai_style_key(self) -> None:
        redacted, hits = security.redact_text(f"export KEY={OPENAI_KEY}")
        self.assertNotIn(OPENAI_KEY, redacted)
        self.assertIn("[REDACTED:openai_key]", redacted)
        self.assertIn("openai_key", hits)

    def test_aws_access_key(self) -> None:
        redacted, hits = security.redact_text(f"aws_access_key_id = {AWS_KEY}")
        self.assertNotIn(AWS_KEY, redacted)
        self.assertIn("[REDACTED:aws_access_key]", redacted)
        self.assertIn("aws_access_key", hits)

    def test_jwt(self) -> None:
        redacted, hits = security.redact_text(f"token: {JWT}")
        self.assertNotIn(JWT, redacted)
        self.assertIn("[REDACTED:jwt]", redacted)
        self.assertIn("jwt", hits)

    def test_bearer_token(self) -> None:
        redacted, hits = security.redact_text(BEARER)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz012345", redacted)
        self.assertIn("bearer_token", hits)

    def test_password_assignment(self) -> None:
        redacted, hits = security.redact_text("password=hunter2supersecret")
        self.assertNotIn("hunter2supersecret", redacted)
        self.assertEqual(redacted, "password=[REDACTED:credential]")
        self.assertIn("credential_assignment", hits)

    def test_private_key_block(self) -> None:
        redacted, hits = security.redact_text(PRIVATE_KEY)
        self.assertNotIn("MIIEowIBAAKCAQEAsecretmaterial", redacted)
        self.assertIn("[REDACTED:private_key]", redacted)
        self.assertIn("private_key", hits)

    def test_clean_text_is_untouched(self) -> None:
        redacted, hits = security.redact_text("nothing secret here")
        self.assertEqual(redacted, "nothing secret here")
        self.assertEqual(hits, [])

    def test_nested_dict_and_list_redaction(self) -> None:
        payload = {
            "auth": {"api_key": OPENAI_KEY, "note": "keep me"},
            "history": [{"token": JWT}, "plain", AWS_KEY],
        }
        cleaned, hits = security.redact_value(payload)
        self.assertIn("openai_key", hits)
        self.assertIn("jwt", hits)
        self.assertIn("aws_access_key", hits)
        self.assertEqual(cleaned["auth"]["note"], "keep me")
        self.assertEqual(cleaned["history"][1], "plain")
        self.assertNotIn(OPENAI_KEY, str(cleaned))
        self.assertNotIn(JWT, str(cleaned))
        self.assertNotIn(AWS_KEY, str(cleaned))


class TestInstructionValidation(unittest.TestCase):
    def test_rejects_empty(self) -> None:
        for value in ("", "   ", "\n\t"):
            with self.subTest(value=value), self.assertRaises(SecurityError):
                security.validate_instruction_text(value)

    def test_rejects_oversized(self) -> None:
        oversized = "a" * (security.MAX_INSTRUCTION_CHARS + 1)
        with self.assertRaises(SecurityError):
            security.validate_instruction_text(oversized)

    def test_rejects_fenced_code(self) -> None:
        with self.assertRaises(SecurityError):
            security.validate_instruction_text("do this:\n```\nrm -rf /\n```")

    def test_accepts_prose_and_strips_control_chars(self) -> None:
        cleaned = security.validate_instruction_text("Reuse\x00 reads when unchanged.")
        self.assertEqual(cleaned, "Reuse reads when unchanged.")


class TestTargetValidation(unittest.TestCase):
    def test_allows_agents_md(self) -> None:
        self.assertEqual(security.validate_target_file("AGENTS.md"), "AGENTS.md")

    def test_rejects_bad_targets(self) -> None:
        for target in (
            "/etc/AGENTS.md",
            "~/AGENTS.md",
            "../AGENTS.md",
            "sub/../../AGENTS.md",
            "CLAUDE.md",
            "notes.md",
            "AGENTS.md.bak",
            "",
        ):
            with self.subTest(target=target), self.assertRaises(SecurityError):
                security.validate_target_file(target)


class TestResolveTargetPath(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.outside = self.root / "outside"
        self.outside.mkdir()

    def test_plain_target(self) -> None:
        resolved = security.resolve_target_path(self.workspace, "AGENTS.md")
        self.assertEqual(resolved, self.workspace.resolve() / "AGENTS.md")

    def test_blocks_symlinked_directory_escape(self) -> None:
        (self.workspace / "link").symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(SecurityError):
            security.resolve_target_path(self.workspace, "link/AGENTS.md")

    def test_blocks_symlinked_file_escape(self) -> None:
        secret = self.outside / "secrets.md"
        secret.write_text("top secret\n", encoding="utf-8")
        (self.workspace / "AGENTS.md").symlink_to(secret)
        with self.assertRaises(SecurityError):
            security.resolve_target_path(self.workspace, "AGENTS.md")

    def test_blocks_workspace_escape(self) -> None:
        with self.assertRaises(SecurityError):
            security.resolve_target_path(self.workspace, "../AGENTS.md")


class TestFilesystemPrimitives(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_atomic_write_replaces_and_leaves_no_temp_files(self) -> None:
        target = self.root / "AGENTS.md"
        target.write_text("old content\n", encoding="utf-8")
        security.atomic_write_text(target, "new content\n")
        self.assertEqual(target.read_text(encoding="utf-8"), "new content\n")
        leftovers = [p.name for p in self.root.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["AGENTS.md"])

    def test_make_backup_copies_bytes(self) -> None:
        target = self.root / "AGENTS.md"
        target.write_text("original bytes\n", encoding="utf-8")
        backup_dir = self.root / "backups"
        backup = security.make_backup(target, backup_dir)
        self.assertTrue(backup.exists())
        self.assertEqual(backup.read_bytes(), target.read_bytes())
        self.assertTrue(backup.name.startswith("AGENTS.md."))
        self.assertTrue(backup.name.endswith(".bak"))

    def test_make_backup_marker_for_missing_file(self) -> None:
        backup = security.make_backup(self.root / "missing.md", self.root / "backups")
        self.assertTrue(backup.exists())
        self.assertEqual(backup.read_text(encoding="utf-8"), "")

    def test_read_text_limited_raises_above_limit(self) -> None:
        target = self.root / "trace.json"
        target.write_text("0123456789", encoding="utf-8")
        with self.assertRaises(TraceTooLargeError):
            security.read_text_limited(target, limit=4)
        self.assertEqual(security.read_text_limited(target, limit=100), "0123456789")

    def test_sha256_file_or_empty(self) -> None:
        self.assertEqual(
            security.sha256_file_or_empty(self.root / "nope.md"), security.EMPTY_SHA256
        )
        target = self.root / "empty.md"
        target.write_text("", encoding="utf-8")
        self.assertEqual(security.sha256_file_or_empty(target), security.EMPTY_SHA256)

    def test_limit_preview_truncates(self) -> None:
        self.assertIsNone(security.limit_preview(None))
        self.assertEqual(security.limit_preview("short", limit=10), "short")
        preview = security.limit_preview("x" * 50, limit=10)
        self.assertEqual(preview, "x" * 10 + "... [truncated]")

    def test_is_within_boundaries(self) -> None:
        base = self.root / "base"
        child = base / "nested" / "file.md"
        child.parent.mkdir(parents=True)
        child.write_text("x", encoding="utf-8")
        sibling = self.root / "base2" / "file.md"
        sibling.parent.mkdir(parents=True)
        sibling.write_text("x", encoding="utf-8")

        self.assertTrue(security.is_within(base, base))
        self.assertTrue(security.is_within(base, child))
        self.assertFalse(security.is_within(base, sibling))
        self.assertFalse(security.is_within(child, base))
        self.assertFalse(security.is_within(base, self.root))


class TestAtomicWriteMetadata(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root / "AGENTS.md"
        self.target.write_text("old content\n", encoding="utf-8")
        os.chmod(self.target, 0o640)

    def _temp_leftovers(self) -> list[str]:
        return [p.name for p in self.root.iterdir() if p.name.endswith(".tmp")]

    def test_preserves_mode_of_existing_target(self) -> None:
        security.atomic_write_text(self.target, "new content\n")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)
        self.assertEqual(self.target.read_text(encoding="utf-8"), "new content\n")

    def test_preserves_restrictive_mode(self) -> None:
        os.chmod(self.target, 0o600)
        security.atomic_write_text(self.target, "tight\n")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o600)

    def test_explicit_metadata_source_wins(self) -> None:
        donor = self.root / "donor.md"
        donor.write_text("donor\n", encoding="utf-8")
        os.chmod(donor, 0o644)
        security.atomic_write_text(self.target, "new\n", metadata_source=donor)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o644)
        self.assertEqual(donor.read_text(encoding="utf-8"), "donor\n")

    def test_missing_target_is_created(self) -> None:
        fresh = self.root / "fresh.md"
        security.atomic_write_text(fresh, "created\n")
        self.assertEqual(fresh.read_text(encoding="utf-8"), "created\n")
        # New instruction files stay private; only existing files donate permissions.
        self.assertEqual(stat.S_IMODE(fresh.stat().st_mode) & 0o077, 0)
        self.assertEqual(self._temp_leftovers(), [])

    def test_missing_metadata_source_is_rejected(self) -> None:
        with self.assertRaises(SecurityError):
            security.atomic_write_text(
                self.target, "new\n", metadata_source=self.root / "nope.md"
            )
        self.assertEqual(self.target.read_text(encoding="utf-8"), "old content\n")

    def test_symlinked_metadata_source_is_rejected(self) -> None:
        link = self.root / "link.md"
        link.symlink_to(self.target)
        with self.assertRaises(SecurityError):
            security.atomic_write_text(self.target, "new\n", metadata_source=link)

    def test_metadata_failure_leaves_original_intact(self) -> None:
        with (
            mock.patch.object(security, "_copy_metadata", side_effect=SecurityError("boom")),
            self.assertRaises(SecurityError),
        ):
            security.atomic_write_text(self.target, "new content\n")
        self.assertEqual(self.target.read_text(encoding="utf-8"), "old content\n")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)
        self.assertEqual(self._temp_leftovers(), [])

    def test_write_failure_leaves_original_intact(self) -> None:
        with (
            mock.patch.object(security, "_write_all", side_effect=OSError(28, "no space")),
            self.assertRaises(OSError),
        ):
            security.atomic_write_text(self.target, "new content\n")
        self.assertEqual(self.target.read_text(encoding="utf-8"), "old content\n")
        self.assertEqual(self._temp_leftovers(), [])

    def test_fsync_failure_leaves_original_intact(self) -> None:
        with (
            mock.patch.object(security.os, "fsync", side_effect=OSError(5, "io error")),
            self.assertRaises(OSError),
        ):
            security.atomic_write_text(self.target, "new content\n")
        self.assertEqual(self.target.read_text(encoding="utf-8"), "old content\n")
        self.assertEqual(self._temp_leftovers(), [])

    def test_replace_failure_leaves_original_intact(self) -> None:
        with (
            mock.patch.object(security.os, "replace", side_effect=OSError(errno.EIO, "io error")),
            self.assertRaises(OSError),
        ):
            security.atomic_write_text(self.target, "new content\n")
        self.assertEqual(self.target.read_text(encoding="utf-8"), "old content\n")
        self.assertEqual(self._temp_leftovers(), [])

    @unittest.skipUnless(DARWIN and hasattr(os, "chflags"), "BSD flags required")
    def test_immutable_target_is_refused(self) -> None:
        os.chflags(self.target, UF_IMMUTABLE)
        self.addCleanup(os.chflags, self.target, 0)
        with self.assertRaises(SecurityError):
            security.atomic_write_text(self.target, "new content\n")
        self.assertEqual(self.target.read_text(encoding="utf-8"), "old content\n")

    @unittest.skipUnless(DARWIN, "macOS ACLs only")
    def test_darwin_acl_and_xattrs_survive_replace(self) -> None:
        if not _set_acl(self.target) or not _set_xattr(self.target):
            self.skipTest("filesystem does not support ACLs or user xattrs")
        security.atomic_write_text(self.target, "new content\n")
        self.assertIn("everyone allow read", _acl_lines(self.target))
        self.assertEqual(_xattr_value(self.target), "probe")


class TestBackupSnapshot(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root / "AGENTS.md"
        self.target.write_text("original bytes\n", encoding="utf-8")
        os.chmod(self.target, 0o640)
        self.backup_dir = self.root / "backups"

    def test_backup_is_an_independent_snapshot(self) -> None:
        backup = security.make_backup(self.target, self.backup_dir)
        self.target.write_text("mutated in place\n", encoding="utf-8")
        self.assertEqual(backup.read_text(encoding="utf-8"), "original bytes\n")

    def test_backup_preserves_bytes_and_mode(self) -> None:
        backup = security.make_backup(self.target, self.backup_dir)
        self.assertEqual(backup.read_bytes(), self.target.read_bytes())
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o640)
        self.assertTrue(backup.name.startswith("AGENTS.md."))
        self.assertTrue(backup.name.endswith(".bak"))

    def test_empty_existing_file_snapshot(self) -> None:
        self.target.write_text("", encoding="utf-8")
        backup = security.make_backup(self.target, self.backup_dir)
        self.assertEqual(backup.read_bytes(), b"")
        security.verify_backup(backup, security.EMPTY_SHA256)

    def test_missing_source_snapshot_is_empty(self) -> None:
        backup = security.make_backup(self.root / "missing.md", self.backup_dir)
        self.assertTrue(backup.exists())
        self.assertEqual(backup.read_bytes(), b"")
        security.verify_backup(backup, security.EMPTY_SHA256)

    def test_verify_rejects_tampered_backup(self) -> None:
        backup = security.make_backup(self.target, self.backup_dir)
        backup.write_text("tampered\n", encoding="utf-8")
        with self.assertRaises(ProposalConflictError):
            security.verify_backup(backup, security.sha256_file(self.target))

    def test_verify_rejects_missing_backup(self) -> None:
        with self.assertRaises(ProposalConflictError):
            security.verify_backup(self.backup_dir / "gone.bak", security.EMPTY_SHA256)

    def test_verify_rejects_symlinked_backup(self) -> None:
        link = self.root / "link.bak"
        link.symlink_to(self.target)
        with self.assertRaises(SecurityError):
            security.verify_backup(link, security.sha256_file(self.target))

    def test_verify_rejects_directory(self) -> None:
        directory = self.root / "dir.bak"
        directory.mkdir()
        with self.assertRaises(SecurityError):
            security.verify_backup(directory, security.EMPTY_SHA256)

    def test_backup_failure_leaves_no_snapshot(self) -> None:
        with (
            mock.patch.object(security, "_copy_metadata", side_effect=SecurityError("boom")),
            self.assertRaises(SecurityError),
        ):
            security.make_backup(self.target, self.backup_dir)
        self.assertEqual(list(self.backup_dir.iterdir()), [])
        self.assertEqual(self.target.read_text(encoding="utf-8"), "original bytes\n")

    def test_restore_round_trip_keeps_bytes_and_mode(self) -> None:
        backup = security.make_backup(self.target, self.backup_dir)
        security.atomic_write_text(self.target, "patched\n")
        security.verify_backup(backup, security.sha256_file(backup))
        security.atomic_restore(self.target, backup)
        self.assertEqual(self.target.read_text(encoding="utf-8"), "original bytes\n")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)

    def test_restore_recreates_missing_target(self) -> None:
        security.atomic_write_text(self.target, "patched\n")
        backup = security.make_backup(self.target, self.backup_dir)
        self.target.unlink()
        security.atomic_restore(self.target, backup)
        self.assertEqual(self.target.read_text(encoding="utf-8"), "patched\n")

    @unittest.skipUnless(DARWIN, "macOS ACLs only")
    def test_darwin_backup_preserves_acl_and_xattrs(self) -> None:
        if not _set_acl(self.target) or not _set_xattr(self.target):
            self.skipTest("filesystem does not support ACLs or user xattrs")
        backup = security.make_backup(self.target, self.backup_dir)
        self.assertIn("everyone allow read", _acl_lines(backup))
        self.assertEqual(_xattr_value(backup), "probe")

    @unittest.skipUnless(LINUX and hasattr(os, "setxattr"), "Linux xattrs only")
    def test_linux_backup_preserves_xattrs(self) -> None:
        os.setxattr(self.target, "user.tracemend_test", b"probe")
        backup = security.make_backup(self.target, self.backup_dir)
        self.assertEqual(os.getxattr(backup, "user.tracemend_test"), b"probe")


class TestWorkspaceLock(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()

    def assert_lock_is_held(self, workspace: Path) -> None:
        with (
            self.assertRaises(ProposalConflictError),
            security.workspace_lock(workspace, timeout=0.05),
        ):
            self.fail("workspace lock was acquired concurrently")

    def test_lock_releases_on_exit(self) -> None:
        with security.workspace_lock(self.workspace, timeout=0.1):
            self.assert_lock_is_held(self.workspace)
        with security.workspace_lock(self.workspace, timeout=0.1):
            pass

    def test_lock_releases_after_exception(self) -> None:
        with (
            self.assertRaises(RuntimeError),
            security.workspace_lock(self.workspace, timeout=0.1),
        ):
            raise RuntimeError("boom")
        with security.workspace_lock(self.workspace, timeout=0.1):
            pass

    def test_equivalent_paths_share_one_lock(self) -> None:
        alias = self.root / "workspace" / ".." / "workspace"
        with security.workspace_lock(self.workspace, timeout=0.1):
            self.assert_lock_is_held(alias)

    @unittest.skipUnless(POSIX, "POSIX flock only")
    def test_cross_process_contention(self) -> None:
        script = (
            "import fcntl, os, sys\n"
            "fd = os.open(sys.argv[1], os.O_RDONLY)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "print('ready', flush=True)\n"
            "sys.stdin.readline()\n"
        )
        holder = subprocess.Popen(
            [sys.executable, "-c", script, str(self.workspace)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(holder.kill)
        self.assertEqual(holder.stdout.readline().strip(), "ready")
        self.assert_lock_is_held(self.workspace)
        holder.stdin.write("release\n")
        holder.stdin.flush()
        holder.wait(timeout=10)
        with security.workspace_lock(self.workspace, timeout=1.0):
            pass

    def test_unsupported_platform_raises(self) -> None:
        with (
            mock.patch.object(security, "fcntl", None),
            self.assertRaises(SecurityError),
            security.workspace_lock(self.workspace),
        ):
            pass


if __name__ == "__main__":
    unittest.main()
