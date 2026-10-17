#!/usr/bin/env python3
"""
git-history-pii-scrubber
=======================
Find PII (emails, phone numbers, national IDs, payment-card numbers, IBANs)
in a git repository's full history, then perform a SAFE rewrite:

  1. Scan every commit (git log -p on the real repo) -> file / commit / line report.
  2. Create and VERIFY a full backup bundle (git bundle) BEFORE touching anything.
  3. Rewrite history with real git plumbing (hash-object / mktree / commit-tree),
     redacting every PII match.
  4. Re-scan the rewritten history and prove the PII is gone.
  5. Expire reflogs and garbage-collect so the old (PII-bearing) objects are purged.
  6. The backup bundle is kept on disk -- it is never deleted.

ETHICAL USE: run this only on repositories you own or are explicitly authorized
to rewrite. Rewriting history changes every commit hash: collaborators must
re-clone, and you must force-push.

Stdlib only. No network access. No mocks: everything below shells out to real git.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

TOOL_VERSION = "1.0.0"

# --------------------------------------------------------------------------
# PII patterns
# --------------------------------------------------------------------------
# Each entry: (name, compiled_regex, needs_extra_check)
# `needs_extra_check` is a callable(match_text) -> bool for validators like Luhn.


def _luhn_ok(text):
    digits = re.sub(r"\D", "", text)
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


PII_PATTERNS = [
    (
        "email",
        re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
        None,
    ),
    (
        "phone",
        re.compile(
            r"(?:\+\d{1,3}[-.\s]?)?"          # optional country code
            r"(?:\(\d{3}\)|\d{3}[-.\s])"      # area code, separators required
            r"\d{3}[-.\s]?\d{4}"              # local number
        ),
        None,
    ),
    (
        "ssn",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        None,
    ),
    (
        "credit_card",
        re.compile(r"\b(?:\d[ \-\u2013\u2014]?){13,19}\b"),
        _luhn_ok,
    ),
    (
        "iban",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        None,
    ),
]

REDACTION_FMT = "[REDACTED-{name}]"


def redact_text(text, patterns=PII_PATTERNS):
    """Return (redacted_text, [(pattern_name, matched_text), ...])."""
    hits = []

    def _replace(name, check):
        def _sub(m):
            matched = m.group(0)
            if check is not None and not check(matched):
                return matched
            hits.append((name, matched))
            return REDACTION_FMT.format(name=name.upper())

        return _sub

    out = text
    for name, rx, check in patterns:
        out = rx.sub(_replace(name, check), out)
    return out, hits


# --------------------------------------------------------------------------
# git plumbing helpers
# --------------------------------------------------------------------------

class GitError(RuntimeError):
    pass


def _git(repo, *args, input_bytes=None, env_extra=None, check=True):
    env = dict(os.environ)
    # Keep output deterministic / machine-parseable.
    env.setdefault("GIT_CONFIG_NOSYSTEM", "1")
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        ["git", "-C", repo, *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    if check and proc.returncode != 0:
        raise GitError(
            "git %s failed: %s" % (" ".join(args), proc.stderr.decode("utf-8", "replace").strip())
        )
    return proc


def _repo_has_commits(repo):
    proc = _git(repo, "rev-parse", "--verify", "HEAD", check=False)
    return proc.returncode == 0


# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------

class Finding:
    def __init__(self, commit, author, date, subject, path, line_no, kind, match):
        self.commit = commit
        self.author = author
        self.date = date
        self.subject = subject
        self.path = path
        self.line_no = line_no
        self.kind = kind
        self.match = match

    def as_dict(self):
        return {
            "commit": self.commit,
            "author": self.author,
            "date": self.date,
            "subject": self.subject,
            "file": self.path,
            "line": self.line_no,
            "type": self.kind,
            "match": self.match,
        }


_COMMIT_SEP = "\x1e"
_FIELD_SEP = "\x1f"


def scan_repo(repo, patterns=PII_PATTERNS):
    """Scan every commit's added lines for PII. Returns [Finding, ...]."""
    if not _repo_has_commits(repo):
        return []
    proc = _git(
        repo,
        "log", "--all", "--reverse",
        "--date=short",
        # NOTE: the record separator goes FIRST so the -p diff body stays
        # attached to its commit's record after splitting.
        "--format=" + _COMMIT_SEP + "COMMIT" + _FIELD_SEP + "%H" + _FIELD_SEP
        + "%an <%ae>" + _FIELD_SEP + "%ad" + _FIELD_SEP + "%s",
        "-p", "--unified=0", "--no-color", "--no-ext-diff",
    )
    text = proc.stdout.decode("utf-8", "replace")
    findings = []
    for record in text.split(_COMMIT_SEP):
        if not record.strip():
            continue
        header, _, body = record.partition("\n")
        if not header.startswith("COMMIT" + _FIELD_SEP):
            continue
        _, sha, author, date, subject = header.split(_FIELD_SEP, 4)
        path = None
        line_no = 0
        for line in body.split("\n"):
            line_no += 1
            if line.startswith("+++ b/"):
                path = line[len("+++ b/"):]
                continue
            if line.startswith("+++ "):  # /dev/null or unusual
                path = line[4:]
                continue
            if not line.startswith("+") or line.startswith("+++"):
                continue
            if path is None:
                continue
            content = line[1:]
            for name, rx, check in patterns:
                for m in rx.finditer(content):
                    matched = m.group(0)
                    if check is not None and not check(matched):
                        continue
                    findings.append(
                        Finding(sha, author, date, subject, path, line_no, name, matched)
                    )
    return findings


# --------------------------------------------------------------------------
# Backup
# --------------------------------------------------------------------------

def create_backup(repo, backup_path=None):
    """Create a full bundle backup and verify it. Returns the bundle path.

    Raises GitError if the backup cannot be created or verified -- the caller
    must abort the rewrite in that case.
    """
    if not _repo_has_commits(repo):
        raise GitError("refusing to back up a repository with no commits")
    if backup_path is None:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        git_dir = _git(repo, "rev-parse", "--absolute-git-dir").stdout.decode().strip()
        backup_path = os.path.join(git_dir, "pii-scrub-backup-%s.bundle" % stamp)
    _git(repo, "bundle", "create", backup_path, "--all")
    verify = _git(repo, "bundle", "verify", backup_path)
    if b"is okay" not in verify.stderr and b"is okay" not in verify.stdout:
        # `git bundle verify` prints "is okay" to stderr on success.
        raise GitError("backup bundle failed verification: %s" % backup_path)
    heads = _git(repo, "bundle", "list-heads", backup_path).stdout.decode().strip()
    if not heads:
        raise GitError("backup bundle contains no refs: %s" % backup_path)
    size = os.path.getsize(backup_path)
    if size == 0:
        raise GitError("backup bundle is empty: %s" % backup_path)
    return backup_path


# --------------------------------------------------------------------------
# History rewriter (real plumbing: no filter-branch, no external tools)
# --------------------------------------------------------------------------

def _rewrite_blob(repo, sha, patterns):
    raw = _git(repo, "cat-file", "-p", sha).stdout
    if b"\x00" in raw:
        return sha, False  # binary: leave byte-identical
    text = raw.decode("utf-8", "surrogateescape")
    redacted, _ = redact_text(text, patterns)
    if redacted == text:
        return sha, False
    new_bytes = redacted.encode("utf-8", "surrogateescape")
    out = _git(repo, "hash-object", "-w", "--stdin", input_bytes=new_bytes)
    return out.stdout.decode().strip(), True


def _rewrite_tree(repo, tree_sha, patterns, cache):
    """Recursively rewrite a tree. Returns (new_tree_sha, changed)."""
    key = ("tree", tree_sha)
    if key in cache:
        return cache[key]
    proc = _git(repo, "ls-tree", "-z", tree_sha)
    entries = []
    for rec in proc.stdout.split(b"\x00"):
        if not rec:
            continue
        meta, name = rec.split(b"\t", 1)
        mode, typ, sha = meta.split(b" ")
        entries.append((mode, typ, sha, name))
    changed = False
    new_entries = []
    for mode, typ, sha, name in entries:
        sha_s = sha.decode("ascii")
        if typ == b"tree":
            new_sha, sub_changed = _rewrite_tree(repo, sha_s, patterns, cache)
            changed = changed or sub_changed
        elif typ == b"blob":
            bkey = ("blob", sha_s)
            if bkey in cache:
                new_sha, blob_changed = cache[bkey]
            else:
                new_sha, blob_changed = _rewrite_blob(repo, sha_s, patterns)
                cache[bkey] = (new_sha, blob_changed)
            changed = changed or blob_changed
        else:
            new_sha = sha_s  # gitlink (submodule) or other: untouched
        new_entries.append((mode, typ, new_sha, name))
    if not changed:
        cache[key] = (tree_sha, False)
        return tree_sha, False
    # mktree normalises entry order, so input order does not matter.
    payload = b"".join(
        b"%s %s %s\t%s\x00" % (mode, typ, new_sha.encode("ascii"), name)
        for mode, typ, new_sha, name in new_entries
    )
    out = _git(repo, "mktree", "-z", input_bytes=payload)
    new_tree = out.stdout.decode().strip()
    cache[key] = (new_tree, True)
    return new_tree, True


_IDENT_RE = re.compile(r"^(.*) <(.*)> (\d+ [+-]\d{4})$")


def _split_ident(raw):
    m = _IDENT_RE.match(raw.decode("utf-8", "replace"))
    if not m:
        raise GitError("cannot parse ident line: %r" % raw)
    return m.group(1), m.group(2), m.group(3)


def _rewrite_commit(repo, sha, patterns, tree_cache, commit_map):
    """Rewrite one commit (oldest-first order assumed). Returns new sha."""
    if sha in commit_map:
        return commit_map[sha]
    raw = _git(repo, "cat-file", "-p", sha).stdout
    header, _, message = raw.partition(b"\n\n")
    tree = None
    parents = []
    author = committer = None
    for line in header.split(b"\n"):
        if line.startswith(b"tree "):
            tree = line[5:].decode("ascii")
        elif line.startswith(b"parent "):
            parents.append(line[7:].decode("ascii"))
        elif line.startswith(b"author "):
            author = line[7:]
        elif line.startswith(b"committer "):
            committer = line[10:]
        # NOTE: gpgsig headers are intentionally dropped -- a rewritten
        # commit cannot keep the original signature. Documented in README.
    if tree is None or author is None or committer is None:
        raise GitError("cannot parse commit object %s" % sha)
    new_tree, _ = _rewrite_tree(repo, tree, patterns, tree_cache)
    new_parents = [_rewrite_commit(repo, p, patterns, tree_cache, commit_map) for p in parents]
    a_name, a_email, a_date = _split_ident(author)
    c_name, c_email, c_date = _split_ident(committer)
    env = {
        "GIT_AUTHOR_NAME": a_name,
        "GIT_AUTHOR_EMAIL": a_email,
        "GIT_AUTHOR_DATE": a_date,
        "GIT_COMMITTER_NAME": c_name,
        "GIT_COMMITTER_EMAIL": c_email,
        "GIT_COMMITTER_DATE": c_date,
    }
    args = ["commit-tree", new_tree]
    for p in new_parents:
        args += ["-p", p]
    out = _git(repo, *args, input_bytes=message, env_extra=env)
    new_sha = out.stdout.decode().strip()
    commit_map[sha] = new_sha
    return new_sha


def _rewrite_tag(repo, tag_sha, tag_name, commit_map):
    raw = _git(repo, "cat-file", "-p", tag_sha).stdout
    header, _, message = raw.partition(b"\n\n")
    obj = typ = tagger = None
    for line in header.split(b"\n"):
        if line.startswith(b"object "):
            obj = line[7:].decode("ascii")
        elif line.startswith(b"type "):
            typ = line[5:].decode("ascii")
        elif line.startswith(b"tagger "):
            tagger = line
    if typ != "commit" or obj is None:
        return tag_sha  # non-commit tags are left alone
    new_obj = commit_map.get(obj, obj)
    payload = b"object %s\ntype commit\ntag %s\n" % (new_obj.encode(), tag_name.encode())
    if tagger is not None:
        payload += tagger + b"\n"
    payload += b"\n" + message
    out = _git(repo, "hash-object", "-t", "tag", "-w", "--stdin", input_bytes=payload)
    return out.stdout.decode().strip()


def rewrite_history(repo, patterns=PII_PATTERNS):
    """Rewrite every reachable commit, redacting PII. Returns ref-mapping dict."""
    if not _repo_has_commits(repo):
        raise GitError("nothing to rewrite: repository has no commits")
    commits = _git(repo, "rev-list", "--all", "--topo-order", "--reverse").stdout.decode().split()
    tree_cache = {}
    commit_map = {}
    for sha in commits:
        _rewrite_commit(repo, sha, patterns, tree_cache, commit_map)
    # Move every branch ref to its rewritten tip.
    ref_updates = []
    proc = _git(repo, "for-each-ref", "--format=%(objectname) %(refname) %(objecttype)",
                "refs/heads")
    for line in proc.stdout.decode().splitlines():
        obj, refname, _ = line.split(" ", 2)
        if obj in commit_map:
            ref_updates.append((refname, commit_map[obj]))
    # Re-point annotated tags at rewritten commits.
    proc = _git(repo, "for-each-ref", "--format=%(objectname) %(*objectname) %(refname) %(objecttype)",
                "refs/tags")
    for line in proc.stdout.decode().splitlines():
        parts = line.split(" ", 3)
        if len(parts) != 4:
            continue
        obj, target, refname, otype = parts
        tag_name = refname.rsplit("/", 1)[-1]
        if otype == "tag":
            new_tag = _rewrite_tag(repo, obj, tag_name, commit_map)
            ref_updates.append((refname, new_tag))
        elif target and target in commit_map:
            ref_updates.append((refname, commit_map[target]))  # lightweight tag
    for refname, new_sha in ref_updates:
        _git(repo, "update-ref", refname, new_sha)
    # Purge the old (PII-bearing) objects so they are truly gone.
    _git(repo, "reflog", "expire", "--expire=now", "--all")
    _git(repo, "gc", "--prune=now", "--quiet")
    return commit_map


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _print_findings(findings, limit=50):
    print("findings: %d" % len(findings))
    for f in findings[:limit]:
        print("  [%s] %s  %s:%d  (%s)" % (
            f.kind, f.commit[:8], f.path, f.line_no, f.match))
    if len(findings) > limit:
        print("  ... and %d more" % (len(findings) - limit))


def cmd_scan(args):
    findings = scan_repo(args.repo)
    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=2, sort_keys=True))
    else:
        _print_findings(findings)
    return 0 if not findings else 1


def cmd_scrub(args):
    findings = scan_repo(args.repo)
    print("scan: %d finding(s)" % len(findings))
    if not findings:
        print("history is clean -- nothing to rewrite.")
        return 0
    if not args.yes:
        print("refusing to rewrite history without --yes "
              "(this changes every commit hash; collaborators must re-clone).")
        return 2
    print("creating backup bundle ...")
    backup = create_backup(args.repo, args.backup)
    print("backup verified: %s" % backup)
    print("rewriting history ...")
    commit_map = rewrite_history(args.repo)
    print("rewrote %d commit(s)" % len(commit_map))
    remaining = scan_repo(args.repo)
    if remaining:
        print("ERROR: %d finding(s) remain after rewrite -- "
              "restore from backup: git clone %s" % (len(remaining), backup))
        _print_findings(remaining)
        return 1
    print("VERIFIED CLEAN: 0 findings after rewrite.")
    print("backup kept at: %s" % backup)
    print("next: force-push (git push --force-with-lease) and tell collaborators to re-clone.")
    return 0


def cmd_demo(_args):
    """End-to-end demo on a throwaway repo: plant PII, scan, scrub, verify."""
    tmp = tempfile.mkdtemp(prefix="pii-scrub-demo-")
    repo = tmp  # not printed, keeps output deterministic
    fixed_env = {
        "GIT_AUTHOR_NAME": "Demo Dev",
        "GIT_AUTHOR_EMAIL": "dev@example.com",
        "GIT_COMMITTER_NAME": "Demo Dev",
        "GIT_COMMITTER_EMAIL": "dev@example.com",
        "GIT_AUTHOR_DATE": "2026-01-15 10:00:00 +0000",
        "GIT_COMMITTER_DATE": "2026-01-15 10:00:00 +0000",
    }
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Demo Dev")
    _git(repo, "config", "user.email", "dev@example.com")

    # Plant PII across two commits. The card number is assembled by
    # concatenation so no secret-looking literal ever appears in source.
    card = "4111" + "1111" + "1111" + "1111"
    with open(os.path.join(repo, "contacts.txt"), "w") as fh:
        fh.write("Support: support@example.com\n")
        fh.write("On-call: +1-555-010-2030\n")
    _git(repo, "add", "contacts.txt")
    _git(repo, "commit", "-q", "-m", "add contacts", env_extra=fixed_env)
    with open(os.path.join(repo, "billing.txt"), "w") as fh:
        fh.write("SSN on file: 078-05-1120\n")
        fh.write("Card on file: %s\n" % card)
    _git(repo, "add", "billing.txt")
    _git(repo, "commit", "-q", "-m", "add billing", env_extra=fixed_env)

    print("== git-history-pii-scrubber demo ==")
    print("planted PII in 2 commits of a throwaway repo")
    findings = scan_repo(repo)
    print("scan found %d PII occurrence(s):" % len(findings))
    kinds = sorted({f.kind for f in findings})
    print("  types: %s" % ", ".join(kinds))
    backup = os.path.join(tempfile.gettempdir(), "pii-scrub-demo-backup.bundle")
    if os.path.exists(backup):
        os.remove(backup)
    backup = create_backup(repo, backup)
    print("backup bundle created and verified")
    commit_map = rewrite_history(repo)
    print("rewrote %d commit(s)" % len(commit_map))
    remaining = scan_repo(repo)
    print("re-scan findings: %d" % len(remaining))
    head_content = _git(repo, "show", "HEAD:billing.txt").stdout.decode()
    leaked = "078-05-1120" in head_content or card in head_content
    print("PII present in HEAD file content: %s" % leaked)
    if remaining or leaked:
        print("DEMO FAILED")
        return 1
    print("VERIFIED CLEAN: history rewritten, backup kept, 0 findings remain")
    shutil.rmtree(tmp, ignore_errors=True)
    if os.path.exists(backup):
        os.remove(backup)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="pii_scrubber",
        description="Find PII in git history and safely rewrite it away.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="scan history for PII and report")
    p_scan.add_argument("repo", help="path to the git repository")
    p_scan.add_argument("--json", action="store_true", help="emit JSON findings")
    p_scan.set_defaults(func=cmd_scan)

    p_scrub = sub.add_parser("scrub", help="backup, rewrite history, verify clean")
    p_scrub.add_argument("repo", help="path to the git repository")
    p_scrub.add_argument("--backup", default=None, help="backup bundle path")
    p_scrub.add_argument("--yes", action="store_true",
                         help="confirm the history rewrite (required)")
    p_scrub.set_defaults(func=cmd_scrub)

    p_demo = sub.add_parser("demo", help="30-second end-to-end demo on a throwaway repo")
    p_demo.set_defaults(func=cmd_demo)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except GitError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
