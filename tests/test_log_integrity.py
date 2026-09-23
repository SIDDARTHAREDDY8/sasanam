"""Red-team tests: T6 (log tampering), T12 (secrets in logs), fail-closed logging.

Threat refs:
  T6  - Log tampering: unkeyed SHA-256 chain, truncate-and-rebuild,
        tail truncation, history rewrite.
  T12 - Secrets in logs: credential/PII material logged verbatim.
  R6  - Authenticated log: HMAC chain, checkpoints, fail-closed emission.
  R7  - Redact-before-log.

Every test here FAILS on the current code: each asserts a control that does
not exist, demonstrating the vulnerability as an assertion failure.
"""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # shared sibling harness (tests/harness.py)
from gov.log import (
    ActionLog,
    GENESIS,
    _canonical,
    _entry_hash,
    read_entries,
    verify_chain,
)


def forge_log(path, entries):
    """Attacker primitive: rewrite a log file with a freshly computed,
    self-consistent UNKEYED chain over attacker-chosen entry dicts.

    This is exactly what T6 says anyone holding the log file can do.
    """
    prev = GENESIS
    lines = []
    for i, e in enumerate(entries, start=1):
        e = dict(e)
        e["seq"] = i
        e.pop("hash", None)
        e["prev_hash"] = prev
        e["hash"] = _entry_hash(prev, _canonical(e))
        prev = e["hash"]
        lines.append(json.dumps(e, ensure_ascii=True, default=str))
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def benign_calls(executor, ident, n=5):
    for i in range(n):
        executor.call(ident, "write_file",
                      path="note-%d.txt" % i, content="benign %d" % i)


class TestTruncateAndRebuild(unittest.TestCase):
    """T6: drop the last 3 entries, re-append 3 forged entries with a
    recomputed unkeyed chain. verify_chain must detect it."""

    def test_truncate_and_rebuild_is_detected(self):
        run = make_run()
        ident = run["identities"]["support"]
        benign_calls(run["executor"], ident, 5)
        log_path = Path(run["run_dir"]) / "actions.jsonl"
        entries = read_entries(log_path)
        self.assertGreaterEqual(len(entries), 5)

        forged = []
        for i in range(3):
            f = dict(entries[len(entries) - 3 + i])
            f["args"] = dict(f.get("args") or {})
            f["args"]["content"] = "FORGED-CONTENT-%d" % i
            f["reason"] = "attacker rewrite"
            forged.append(f)
        forge_log(log_path, entries[:-3] + forged)

        ok, broken_seq, count = verify_chain(log_path)
        self.assertFalse(
            ok,
            "T6: truncate-and-rebuild with a recomputed unkeyed chain was NOT "
            "detected by verify_chain (returned ok=True over %d entries)" % count,
        )


class TestTailTruncation(unittest.TestCase):
    """T6: delete the last entry. R6 requires periodic checkpoints (STH-style)
    that defeat tail truncation; the log has none, so it is undetectable."""

    def test_tail_truncation_is_detected(self):
        run = make_run()
        ident = run["identities"]["support"]
        benign_calls(run["executor"], ident, 3)
        log_path = Path(run["run_dir"]) / "actions.jsonl"

        # No checkpoint mechanism exists on the log at all.
        log = run["log"]
        has_checkpoints = hasattr(log, "write_checkpoint") or hasattr(log, "checkpoints")
        self.assertTrue(
            has_checkpoints,
            "T6/R6: no checkpoint mechanism exists, so tail truncation "
            "cannot be detected by checkpoint comparison",
        )

        entries = read_entries(log_path)
        lines = log_path.read_text(encoding="utf-8").splitlines()
        log_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

        ok, broken_seq, count = verify_chain(log_path)
        self.assertFalse(
            ok,
            "T6: tail truncation (last of %d entries deleted) was NOT detected "
            "by verify_chain" % len(entries),
        )


class TestHistoryRewrite(unittest.TestCase):
    """T6: modify an early entry's args, recompute all subsequent hashes.
    verify_chain must detect it."""

    def test_history_rewrite_is_detected(self):
        run = make_run()
        ident = run["identities"]["support"]
        benign_calls(run["executor"], ident, 4)
        log_path = Path(run["run_dir"]) / "actions.jsonl"
        entries = read_entries(log_path)
        self.assertGreaterEqual(len(entries), 4)

        tampered = [dict(e) for e in entries]
        tampered[0]["args"] = dict(tampered[0].get("args") or {})
        tampered[0]["args"]["path"] = "pwned.txt"
        tampered[0]["args"]["content"] = "attacker-controlled content"
        forge_log(log_path, tampered)

        ok, broken_seq, count = verify_chain(log_path)
        self.assertFalse(
            ok,
            "T6: history rewrite (entry seq 1 args altered, chain recomputed) "
            "was NOT detected by verify_chain",
        )


class TestSecretsInLogs(unittest.TestCase):
    """T12/R7: credentials and PII must be redacted before logging, never
    stored verbatim; redactions_applied must be recorded."""

    FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
    FAKE_SSN = "078-05-1120"  # synthetic, clearly fake

    def test_no_credentials_logged_verbatim(self):
        run = make_run()
        ident = run["identities"]["support"]
        ex = run["executor"]
        ex.call(ident, "write_file", path="notes.txt",
                content="deploy key %s do not share" % self.FAKE_AWS_KEY)
        # send_email is require_approval under the default policy: the queued
        # tool_call entry still logs the full args verbatim today.
        ex.call(ident, "send_email", to="boss@example.com", subject="report",
                body="employee ssn %s attached" % self.FAKE_SSN)

        raw = (Path(run["run_dir"]) / "actions.jsonl").read_text(encoding="utf-8")
        self.assertNotIn(
            self.FAKE_AWS_KEY, raw,
            "T12: fake AWS key appears VERBATIM in the action log",
        )
        self.assertNotIn(
            self.FAKE_SSN, raw,
            "T12: fake SSN appears VERBATIM in the action log",
        )
        entries = read_entries(Path(run["run_dir"]) / "actions.jsonl")
        self.assertTrue(
            any(e.get("redactions_applied") for e in entries),
            "T12/R7: no log entry records redactions_applied",
        )


class TestFailClosedLogging(unittest.TestCase):
    """R6: log emission failure must abort BEFORE the tool executes.
    Currently the tool runs first and the log write raises afterwards."""

    def test_logging_failure_aborts_before_execution(self):
        run = make_run()
        ident = run["identities"]["support"]
        ex = run["executor"]

        # Make every log emission fail: point the log at a directory.
        logdir = Path(run["run_dir"]) / "log_as_dir"
        logdir.mkdir(parents=True, exist_ok=True)
        run["log"].path = logdir

        target = Path(run["run_dir"]) / "sandbox" / "must_not_exist.txt"
        with self.assertRaises(Exception):
            ex.call(ident, "write_file", path="must_not_exist.txt",
                    content="this must never be written")
        self.assertFalse(
            target.exists(),
            "T6/R6: log emission failed, yet the tool STILL EXECUTED "
            "(fail-open logging: write_file ran before append raised)",
        )


class TestF126RefreshSigAtomicity(unittest.TestCase):
    """F126: refresh() must capture the (size, mtime) signature BEFORE
    reading content, not after.

    The F22 cache assumes the signature describes the file version that
    produced _seq/_prev. Capturing it after the read lets a concurrent
    writer slip in between: _seq goes stale while the signature matches
    the current file, so the next _refresh_if_changed() skips the re-read
    and assigns a duplicate seq (chain fork). This test deterministically
    reproduces that interleaving: a writer appends during another
    instance's constructor refresh(), between its content read and its
    signature capture.
    """

    def test_concurrent_writer_during_refresh_no_duplicate_seq(self):
        from gov.log import verify_chain
        import tempfile

        d = Path(tempfile.mkdtemp(prefix="f126-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(str(d),
                                                            ignore_errors=True))
        p = str(d / "actions.jsonl")
        log_a = ActionLog(p)
        for i in range(3):
            log_a.append({"n": i})

        real_read_text = Path.read_text

        def interleaved_read_text(self, *args, **kwargs):
            text = real_read_text(self, *args, **kwargs)
            # The concurrent writer lands between the content read and
            # the signature capture inside refresh().
            if str(self) == p and text.strip().count("\n") == 2:
                log_a.append({"racer": True})
            return text

        with mock.patch.object(Path, "read_text", interleaved_read_text):
            log_b = ActionLog(p)  # constructor refresh, raced

        entry = log_b.append({"after": True})
        # File now holds 5 entries (3 + racer + this one); the new entry
        # must chain onto the racer's seq 4, not duplicate it.
        self.assertEqual(entry["seq"], 5,
                         "F126: stale _seq after raced refresh caused a "
                         "duplicate seq assignment (chain fork)")
        ok, _broken, count = verify_chain(p)
        self.assertTrue(ok)
        self.assertEqual(count, 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
