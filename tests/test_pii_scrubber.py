#!/usr/bin/env python3
"""Tests for git-history-pii-scrubber. All tests run against REAL git repos
created in temp dirs -- no mocks of the core logic."""

import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pii_scrubber as ps

FIXED_ENV = {
    "GIT_AUTHOR_NAME": "Test Dev",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test Dev",
    "GIT_COMMITTER_EMAIL": "test@example.com",
    "GIT_AUTHOR_DATE": "2026-02-01 12:00:00 +0000",
    "GIT_COMMITTER_DATE": "2026-02-01 12:00:00 +0000",
}


def make_repo():
    repo = tempfile.mkdtemp(prefix="pii-scrub-test-")
    ps._git(repo, "init", "-q", "-b", "main")
    ps._git(repo, "config", "user.name", "Test Dev")
    ps._git(repo, "config", "user.email", "test@example.com")
    return repo


def commit_file(repo, name, content, message):
    with open(os.path.join(repo, name), "w") as fh:
        fh.write(content)
    ps._git(repo, "add", name)
    ps._git(repo, "commit", "-q", "-m", message, env_extra=FIXED_ENV)


def plant_pii_repo():
    """Repo with PII across two commits. Card assembled by concatenation so no
    secret-looking literal appears in this source file."""
    repo = make_repo()
    commit_file(repo, "contacts.txt",
                "Support: support@example.com\nOn-call: +1-555-010-2030\n",
                "add contacts")
    card = "4111" + "1111" + "1111" + "1111"
    commit_file(repo, "billing.txt",
                "SSN on file: 078-05-1120\nCard on file: %s\n" % card,
                "add billing")
    return repo


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.repo = make_repo()
        self.addCleanup(shutil.rmtree, self.repo, True)

    def test_scan_finds_planted_pii(self):
        shutil.rmtree(self.repo, ignore_errors=True)
        self.repo = plant_pii_repo()
        findings = ps.scan_repo(self.repo)
        kinds = {f.kind for f in findings}
        self.assertEqual(kinds, {"email", "phone", "ssn", "credit_card"})
        self.assertEqual(len(findings), 4)
        by_kind = {f.kind: f for f in findings}
        self.assertEqual(by_kind["email"].path, "contacts.txt")
        self.assertEqual(by_kind["email"].match, "support@example.com")
        self.assertEqual(by_kind["phone"].match, "+1-555-010-2030")
        self.assertEqual(by_kind["ssn"].match, "078-05-1120")
        self.assertTrue(all(len(f.commit) == 40 for f in findings))
        # findings point at the right commits
        log = ps._git(self.repo, "log", "--format=%H %s").stdout.decode()
        first = [l.split()[0] for l in log.splitlines() if "add contacts" in l][0]
        self.assertEqual(by_kind["email"].commit, first)

    def test_scan_reports_file_commit_line(self):
        shutil.rmtree(self.repo, ignore_errors=True)
        self.repo = plant_pii_repo()
        findings = ps.scan_repo(self.repo)
        for f in findings:
            self.assertTrue(f.path)
            self.assertGreater(f.line_no, 0)

    def test_scan_clean_repo_no_findings(self):
        commit_file(self.repo, "notes.txt", "hello world\nnothing sensitive\n", "docs")
        self.assertEqual(ps.scan_repo(self.repo), [])

    def test_scan_empty_repo_no_findings(self):
        self.assertEqual(ps.scan_repo(self.repo), [])

    def test_credit_card_requires_luhn(self):
        # 13-19 digits that fail Luhn must NOT be flagged.
        commit_file(self.repo, "nums.txt", "ref: 4111111111111112\n", "nums")
        kinds = {f.kind for f in ps.scan_repo(self.repo)}
        self.assertNotIn("credit_card", kinds)

    def test_scan_json_output(self):
        shutil.rmtree(self.repo, ignore_errors=True)
        self.repo = plant_pii_repo()
        import json
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = ps.main(["scan", self.repo, "--json"])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 1)  # findings present -> exit 1
        data = json.loads(buf.getvalue())
        self.assertEqual(len(data), 4)
        self.assertIn("commit", data[0])


class TestSafeRewrite(unittest.TestCase):
    def setUp(self):
        self.repo = plant_pii_repo()
        self.addCleanup(shutil.rmtree, self.repo, True)

    def test_scrub_removes_pii_and_keeps_backup(self):
        backup = os.path.join(tempfile.gettempdir(), "pii-scrub-test-backup.bundle")
        if os.path.exists(backup):
            os.remove(backup)
        self.addCleanup(lambda: os.path.exists(backup) and os.remove(backup))

        before = ps.scan_repo(self.repo)
        self.assertEqual(len(before), 4)

        created = ps.create_backup(self.repo, backup)
        self.assertEqual(created, backup)
        self.assertTrue(os.path.getsize(backup) > 0)
        # bundle verify passes
        v = ps._git(self.repo, "bundle", "verify", backup, check=False)
        self.assertEqual(v.returncode, 0)

        commit_map = ps.rewrite_history(self.repo)
        self.assertEqual(len(commit_map), 2)

        after = ps.scan_repo(self.repo)
        self.assertEqual(after, [])

        # working tree content is actually redacted
        head = ps._git(self.repo, "show", "HEAD:billing.txt").stdout.decode()
        self.assertNotIn("078-05-1120", head)
        self.assertNotIn("4111111111111111", head)
        self.assertIn("[REDACTED-SSN]", head)
        self.assertIn("[REDACTED-CREDIT_CARD]", head)

        # backup still on disk and restorable
        self.assertTrue(os.path.exists(backup))
        restore = tempfile.mkdtemp(prefix="pii-scrub-restore-")
        self.addCleanup(shutil.rmtree, restore, True)
        subprocess.run(["git", "clone", "-q", backup, restore],
                       check=True, capture_output=True)
        restored = ps._git(restore, "show", "HEAD:billing.txt").stdout.decode()
        self.assertIn("078-05-1120", restored)  # original PII recoverable from backup

    def test_rewrite_preserves_history_shape(self):
        ps.rewrite_history(self.repo)
        log = ps._git(self.repo, "log", "--reverse",
                      "--format=%an|%ae|%s").stdout.decode().strip().splitlines()
        self.assertEqual(len(log), 2)
        self.assertIn("Test Dev|test@example.com|add contacts", log)
        self.assertIn("Test Dev|test@example.com|add billing", log)
        files = ps._git(self.repo, "ls-tree", "-r", "--name-only", "HEAD").stdout.decode().split()
        self.assertEqual(sorted(files), ["billing.txt", "contacts.txt"])

    def test_rewrite_preserves_merge_topology(self):
        repo = make_repo()
        self.addCleanup(shutil.rmtree, repo, True)
        commit_file(repo, "a.txt", "base\n", "base")
        ps._git(repo, "checkout", "-q", "-b", "feature")
        commit_file(repo, "b.txt", "call me at +1-555-010-9900\n", "feature work")
        ps._git(repo, "checkout", "-q", "main")
        commit_file(repo, "c.txt", "main work\n", "main work")
        ps._git(repo, "merge", "-q", "--no-ff", "-m", "merge feature", "feature",
                env_extra=FIXED_ENV)
        self.assertEqual(len(ps.scan_repo(repo)), 1)
        commit_map = ps.rewrite_history(repo)
        self.assertEqual(len(commit_map), 4)
        self.assertEqual(ps.scan_repo(repo), [])
        merge_sha = ps._git(repo, "rev-parse", "HEAD").stdout.decode().strip()
        parents = ps._git(repo, "log", "-1", "--format=%P", merge_sha).stdout.decode().split()
        self.assertEqual(len(parents), 2)  # merge topology preserved

    def test_scrub_aborts_when_backup_fails(self):
        # backup into a nonexistent directory -> GitError, repo untouched
        with self.assertRaises(ps.GitError):
            ps.create_backup(self.repo, "/nonexistent-dir-xyz/backup.bundle")
        self.assertEqual(len(ps.scan_repo(self.repo)), 4)

    def test_scrub_cli_requires_yes(self):
        rc = ps.main(["scrub", self.repo])
        self.assertEqual(rc, 2)
        self.assertEqual(len(ps.scan_repo(self.repo)), 4)  # untouched

    def test_scrub_cli_end_to_end(self):
        backup = os.path.join(tempfile.gettempdir(), "pii-scrub-cli-backup.bundle")
        if os.path.exists(backup):
            os.remove(backup)
        self.addCleanup(lambda: os.path.exists(backup) and os.remove(backup))
        rc = ps.main(["scrub", self.repo, "--yes", "--backup", backup])
        self.assertEqual(rc, 0)
        self.assertEqual(ps.scan_repo(self.repo), [])
        self.assertTrue(os.path.exists(backup))


class TestDemo(unittest.TestCase):
    def test_demo_runs_end_to_end(self):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = ps.main(["demo"])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("scan found 4 PII occurrence(s)", out)
        self.assertIn("VERIFIED CLEAN", out)

    def test_readme_example_output_matches_fresh_demo_run(self):
        """The README's Example output block is byte-for-byte the demo output."""
        readme = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "README.md")
        with open(readme) as fh:
            content = fh.read()
        m = re.search(r"<!-- DEMO-OUTPUT-START -->\n(.*?)<!-- DEMO-OUTPUT-END -->",
                      content, re.DOTALL)
        self.assertIsNotNone(m, "README missing DEMO-OUTPUT markers")
        block = m.group(1)
        self.assertTrue(block.startswith("```\n") and block.rstrip().endswith("```"),
                        "example output must be a fenced code block")
        readme_output = block[len("```\n"):].rstrip()
        if readme_output.endswith("```"):
            readme_output = readme_output[:-3].rstrip()

        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = ps.main(["demo"])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 0)
        fresh = buf.getvalue().rstrip()
        self.assertEqual(readme_output, fresh,
                         "README example output is stale -- re-run build_readme.py")


if __name__ == "__main__":
    unittest.main()
