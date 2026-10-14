"""Tests for the frozen safety primitives in :mod:`tracemend.security`."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tracemend import security
from tracemend.errors import SecurityError, TraceTooLargeError

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


if __name__ == "__main__":
    unittest.main()
