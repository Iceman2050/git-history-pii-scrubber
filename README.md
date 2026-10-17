# git-history-pii-scrubber

**Someone pasted a customer's email, a phone number, and a credit-card number into a commit message in 2021. It's still in your git history today — and `git rm` won't touch it.**

Cloning the repo, forking it, or checking out an old tag brings the PII right back. Rewriting history with `git filter-branch` is terrifying: one wrong flag and you've destroyed the repo with no way back.

This tool makes history rewrites boring and safe:

1. **Scans** every commit (`git log -p` on the real repo) for emails, phone numbers, SSNs, credit-card numbers (Luhn-validated), and IBANs — reporting commit, file, and line.
2. **Backs up first**: creates a full `git bundle` and *verifies* it before touching anything. The rewrite refuses to start if the backup fails.
3. **Rewrites** history with real git plumbing (`hash-object` / `mktree` / `commit-tree`) — no `filter-branch`, no external dependencies — redacting every match to `[REDACTED-EMAIL]` etc.
4. **Re-verifies**: rescans the rewritten history and proves zero findings remain, then expires reflogs and garbage-collects so the old PII-bearing objects are actually purged.
5. **Keeps the backup.** It is never deleted.

## Quickstart

```bash
# Scan a repo (exit 1 if PII found, 0 if clean)
python3 pii_scrubber.py scan /path/to/repo
python3 pii_scrubber.py scan /path/to/repo --json

# Safe rewrite: backup -> rewrite -> verify (requires explicit --yes)
python3 pii_scrubber.py scrub /path/to/repo --yes
python3 pii_scrubber.py scrub /path/to/repo --yes --backup /safe/place/backup.bundle

# 30-second end-to-end demo on a throwaway repo
python3 pii_scrubber.py demo
```

## Example output

The block below is machine-verified: `build_readme.py` runs `pii_scrubber.py demo`
fresh and splices its stdout here byte-for-byte, and the test suite re-runs the
demo and diffs it against this block (a stale README fails CI).

<!-- DEMO-OUTPUT-START -->
```
== git-history-pii-scrubber demo ==
planted PII in 2 commits of a throwaway repo
scan found 4 PII occurrence(s):
  types: credit_card, email, phone, ssn
backup bundle created and verified
rewrote 2 commit(s)
re-scan findings: 0
PII present in HEAD file content: False
VERIFIED CLEAN: history rewritten, backup kept, 0 findings remain
```
<!-- DEMO-OUTPUT-END -->

## How the safe rewrite works

- **Backup gate**: `git bundle create --all` + `git bundle verify` + a non-empty
  ref check. Any failure raises before a single object is rewritten.
- **Plumbing rewrite**: commits are replayed oldest-first. Each tree is rebuilt
  recursively; text blobs are redacted; binary blobs are carried over
  byte-identical. Authors, dates, messages, merge topology, and tags are
  preserved (lightweight and annotated).
- **Purge**: `git reflog expire --expire=now --all && git gc --prune=now` removes
  the original objects, so the PII is gone from the object store, not just from
  the refs.
- After a successful run you still need to `git push --force-with-lease`, and
  every collaborator must re-clone — rewritten history means new commit hashes.

## What it does NOT do

- It does **not** detect PII in the *current working tree* beyond what is in
  history (run the `scan` — it covers all reachable commits, which includes HEAD).
- It does **not** preserve GPG commit signatures — a rewritten commit cannot
  keep the original signature. Signatures are dropped and this is reported, not
  hidden.
- It does **not** scan submodule contents (gitlinks are carried over untouched).
- It does **not** stop PII from being committed again — pair it with a
  pre-commit hook or secret scanner for prevention.
- It does **not** rewrite history on the remote for you — the force-push is
  yours, deliberately.

## Ethical use

Run this only on repositories you **own** or are explicitly authorized to
rewrite. History rewriting changes every commit hash: collaborators must
re-clone, open PRs must be rebased, and CI caches may need clearing. Never use
this tool to tamper with evidence, to falsify authorship, or on anyone else's
repository.

## Detectors

| Type | Pattern | Notes |
|------|---------|-------|
| `email` | RFC-ish email regex | — |
| `phone` | International/US phone shapes | separators required, avoids bare digit runs |
| `ssn` | `\d{3}-\d{2}-\d{4}` | US Social Security Number shape |
| `credit_card` | 13–19 digits | Luhn checksum required — kills false positives |
| `iban` | 2 letters + 2 digits + 11–30 alphanumerics | International bank account shape |

## Built by Ingenious AI
- DisclosureGuard — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DisclosureGuard.
- ModelMinder — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ModelMinder.
- TermsWatch — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20TermsWatch.
- Vibe-Code Audit — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.
- Rogue-Agent Defense — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.
- BreachHunter — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20BreachHunter.
- ChatBreaker — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ChatBreaker.
- Agent Flight Recorder — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.
- Agent Auth Gateway — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.
- DomainGuard — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DomainGuard.
- ContentCraft AI — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ContentCraft%20AI.
Built with Muse — try it free: invite code 2HCQH1
