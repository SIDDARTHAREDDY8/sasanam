"""Hardening round-18 regression tests: F74 (+ F-RA1).

F74 (HIGH, Performance workstream): ``EgressLedger.append`` was an
    unlocked read-modify-write. Concurrent writers sharing one ledger
    (threads in one process, e.g. N agent threads sharing a run dir
    doing ``api_call`` bursts) read the same tail and appended the same
    next sequence number with divergent hashes -- the chain forked, and
    every later ``call()`` failed closed with
    ``LedgerUnverifiableError``. Safe direction, liveness bug.

    Fix: F25-style locking in ``gov/egress_ledger.py`` -- a reentrant
    per-path read/write lock (in-process RW guard + POSIX flock:
    LOCK_SH for readers, LOCK_EX for the append critical section).
    Appends linearize across threads AND processes; readers never see a
    torn append. Lock acquisition timeout fails closed (never writes /
    trusts unlocked).

F-RA1 (Real Agent workstream, independent confirmation): concurrent
    ``require_verified()`` torn-reads -- a reader's full-file verify
    racing a writer's append observes a partial trailing line and
    fail-closes, refusing legitimate calls. The read side of the same
    F74 lock fixes it: readers hold LOCK_SH while verifying/scanning.

Deterministic, stdlib only, no network, no real systems.
"""

import fcntl
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import gov.egress_ledger as ledger_mod  # noqa: E402
from gov.egress_ledger import (  # noqa: E402
    EgressLedger,
    LedgerLockError,
    LedgerUnverifiableError,
)

_F74_THREADS = 8
_F74_APPENDS_EACH = 25
_F74_TOTAL = _F74_THREADS * _F74_APPENDS_EACH


def _shape(tag):
    """Minimal api_call shape record, as the executor appends."""
    return {
        "ts": time.time(),
        "run_id": "r74-%s" % tag,
        "principal": "perf-org",
        "tool": "api_call",
        "endpoint": "https://collector.synthetic.local/x",
        "campaign_domain": "synthetic.local",
        "param_keys": ["q"],
        "n_params": 1,
        "str_bytes": 8,
        "max_entropy": 2.0,
        "fragment": False,
    }


def _f74_append_worker(path, barrier, n, tag, errors):
    """One writer thread with its own EgressLedger instance -- the
    shared-run shape: separate executors in one process, one ledger."""
    try:
        ledger = EgressLedger(path)
        barrier.wait(timeout=60)
        for _ in range(n):
            ledger.append(_shape(tag))
    except Exception as e:  # noqa: BLE001 -- collected, asserted below
        errors.append("%r" % (e,))


def _f74_read_worker(path, barrier, stop, errors):
    """F-RA1 shape: a reader verifying/scanning while writers append."""
    try:
        ledger = EgressLedger(path)
        barrier.wait(timeout=60)
        while not stop.is_set():
            ledger.require_verified()
            ledger.taint_active("perf-org")
            ledger.fragments("perf-org",
                             "https://collector.synthetic.local/x")
    except Exception as e:  # noqa: BLE001 -- collected, asserted below
        errors.append("%r" % (e,))


def _parse_ledger(path):
    with open(path, encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]


class TestF74ConcurrentLedgerAppends(unittest.TestCase):
    """F74: concurrent EgressLedger.append must linearize -- no duplicate
    sequence numbers, no forked chain, ledger verifies afterwards."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="r18f74-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_concurrent_thread_appends_linearize(self):
        """8 threads x 25 appends, one shared ledger, barrier-started.

        Pre-fix: the unlocked read-modify-write forks the chain --
        duplicate seq numbers and verify() False. Post-fix: seqs are
        exactly 1..200 and the ledger verifies.
        """
        path = os.path.join(self.dir, "egress.jsonl")
        barrier = threading.Barrier(_F74_THREADS)
        errors = []
        threads = [
            threading.Thread(
                target=_f74_append_worker,
                args=(path, barrier, _F74_APPENDS_EACH, t, errors),
            )
            for t in range(_F74_THREADS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(180)
            self.assertFalse(t.is_alive(), "append worker hung")
        self.assertEqual(errors, [], "writers raised: %r" % (errors[:3],))
        parsed = _parse_ledger(path)
        self.assertEqual(len(parsed), _F74_TOTAL,
                         "every append must land exactly once")
        seqs = [e["seq"] for e in parsed]
        self.assertEqual(len(set(seqs)), _F74_TOTAL,
                         "duplicate sequence numbers: chain forked")
        self.assertEqual(sorted(seqs), list(range(1, _F74_TOTAL + 1)))
        self.assertTrue(EgressLedger(path).verify(),
                        "forked chain must not verify")

    def test_concurrent_verified_reads_do_not_tear(self):
        """F-RA1: readers calling require_verified()/taint_active()/
        fragments() while writers append must not fail closed on torn
        reads. Pre-fix the reader can observe a partial trailing line
        and raise LedgerUnverifiableError on legitimate calls."""
        path = os.path.join(self.dir, "egress.jsonl")
        n_writers, n_readers = 4, 4
        barrier = threading.Barrier(n_writers + n_readers)
        stop = threading.Event()
        errors = []
        writers = [
            threading.Thread(
                target=_f74_append_worker,
                args=(path, barrier, 40, "w%d" % t, errors),
            )
            for t in range(n_writers)
        ]
        readers = [
            threading.Thread(
                target=_f74_read_worker,
                args=(path, barrier, stop, errors),
            )
            for _ in range(n_readers)
        ]
        for t in writers + readers:
            t.start()
        for t in writers:
            t.join(180)
            self.assertFalse(t.is_alive(), "writer hung")
        stop.set()
        for t in readers:
            t.join(180)
            self.assertFalse(t.is_alive(), "reader hung")
        self.assertEqual(errors, [], "torn read failed closed: %r"
                         % (errors[:3],))
        self.assertTrue(EgressLedger(path).verify())

    def test_write_lock_timeout_fails_closed_without_writing(self):
        """If the append lock cannot be acquired, append raises
        LedgerLockError and writes nothing -- never unlocked, mirroring
        the F25 ActionLog discipline."""
        path = os.path.join(self.dir, "egress.jsonl")
        ledger = EgressLedger(path)
        ledger.append(_shape("seed"))
        before = _parse_ledger(path)
        hold = open(path, "a", encoding="utf-8")
        self.addCleanup(hold.close)
        fcntl.flock(hold.fileno(), fcntl.LOCK_EX)  # hold it ourselves
        try:
            with mock.patch.object(ledger_mod, "LEDGER_LOCK_TIMEOUT_SECS",
                                   1, create=True):
                with self.assertRaises(LedgerLockError):
                    ledger.append(_shape("should-never-land"))
        finally:
            fcntl.flock(hold.fileno(), fcntl.LOCK_UN)
        after = _parse_ledger(path)
        self.assertEqual(after, before, "timed-out append must write nothing")
        self.assertTrue(EgressLedger(path).verify())

    def test_read_lock_timeout_fails_closed_as_unverifiable(self):
        """A reader that cannot acquire the read lock must fail closed
        as LedgerUnverifiableError (refuse to trust), never as 'clean'."""
        path = os.path.join(self.dir, "egress.jsonl")
        EgressLedger(path).append(_shape("seed"))
        hold = open(path, "a", encoding="utf-8")
        self.addCleanup(hold.close)
        fcntl.flock(hold.fileno(), fcntl.LOCK_EX)
        try:
            with mock.patch.object(ledger_mod, "LEDGER_LOCK_TIMEOUT_SECS",
                                   1, create=True):
                with self.assertRaises(LedgerUnverifiableError):
                    EgressLedger(path).require_verified()
        finally:
            fcntl.flock(hold.fileno(), fcntl.LOCK_UN)
        # After the holder releases, reads work again (liveness restored).
        EgressLedger(path).require_verified()

    def test_unusable_ledger_path_reads_as_missing_fail_open(self):
        """F74 must not break the F10 fail-open contract: readers on an
        unusable ledger path (parent missing, or a file in the way)
        behave exactly like a missing ledger -- vacuous verify, False
        taint, no campaign hit, never an exception."""
        for bad_path in ("/nonexistent-dir-xyz-f74/ledger.jsonl",
                         os.path.join(self.dir, "blocker", "l.jsonl")):
            if "blocker" in bad_path:
                Path(os.path.join(self.dir, "blocker")).write_text("x")
            ledger = EgressLedger(bad_path)
            ledger.require_verified()  # must not raise
            self.assertTrue(ledger.verify())
            self.assertFalse(ledger.taint_active("perf-org"))
            self.assertEqual(
                ledger.fragments("perf-org",
                                 "https://collector.synthetic.local/x"), [])
            self.assertFalse(ledger.campaign_hit(
                "perf-org", "https://collector.synthetic.local/x"))
            self.assertFalse(ledger.structural_campaign_hit(
                "perf-org", "synthetic.local", ["q"]))

    def test_sequential_appends_still_chain(self):
        """The lock must not change single-writer behavior: seqs chain
        1..N and every entry links prev_hash correctly."""
        path = os.path.join(self.dir, "egress.jsonl")
        ledger = EgressLedger(path)
        for i in range(10):
            ledger.append(_shape("s%d" % i))
        parsed = _parse_ledger(path)
        self.assertEqual([e["seq"] for e in parsed], list(range(1, 11)))
        prev = "0" * 64
        for e in parsed:
            self.assertEqual(e["prev_hash"], prev)
            prev = e["entry_hash"]
        self.assertTrue(ledger.verify())


if __name__ == "__main__":
    unittest.main()
