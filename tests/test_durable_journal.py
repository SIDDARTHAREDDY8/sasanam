"""Tests for gov.durable_journal: the hash-chained durable event journal.

Red-first: these tests were written BEFORE the production module was
trusted (the journal was written 2026-09-29 and these tests are its
first real exercise). Every corruption mode must FAIL CLOSED — the
loader raises, never silently repairs.

Convention: stdlib unittest only (repo standard; discovered by
tests/run_tests.py).
"""

import fcntl
import json
import multiprocessing
import os
import sys
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.durable_journal import (  # noqa: E402
    Journal,
    JournalCorrupted,
    JournalLockError,
    TornTailError,
    recover_torn_tail,
    verify_journal,
)


def _raw_lines(path):
    with open(path, "rb") as f:
        return [ln.decode("utf-8") for ln in f]


def _rewrite(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def _rec(line):
    return json.loads(line)


def _dump(rec):
    return json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"


def _concurrent_worker(path, n, queue):
    j = Journal(path)
    for i in range(n):
        j.append("W", {"worker": os.getpid(), "i": i})
    queue.put(True)


def _lock_holder(path, seconds):
    import time
    fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    fcntl.flock(fd, fcntl.LOCK_EX)
    time.sleep(seconds)
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


class JournalAppendTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dj-")
        self.jpath = os.path.join(self.tmp, "j.journal")

    def test_append_and_reload_ok(self):
        j = Journal(self.jpath)
        j.append("ApprovalRequested", {"approval_id": "a1"})
        j.append("TimerStarted", {"approval_id": "a1", "fire_at": 123})
        j2 = Journal(self.jpath)
        self.assertEqual(len(j2.records), 2)
        self.assertEqual([r["type"] for r in j2.records],
                         ["ApprovalRequested", "TimerStarted"])
        self.assertEqual([r["seq"] for r in j2.records], [0, 1])
        self.assertEqual(j2.tip, j.tip)

    def test_chain_binding_blocks_hash_tamper(self):
        j = Journal(self.jpath)
        j.append("ApprovalRequested", {"approval_id": "a1"})
        rec = _rec(_raw_lines(self.jpath)[0])
        rec["body"]["approval_id"] = "attacker"
        _rewrite(self.jpath, [_dump(rec)])
        with self.assertRaises(JournalCorrupted):
            Journal(self.jpath)
        self.assertEqual(verify_journal(self.jpath), (False, 0))

    def test_middle_record_deletion_fails_closed(self):
        j = Journal(self.jpath)
        for i in range(3):
            j.append("R%d" % i, {"n": i})
        lines = _raw_lines(self.jpath)
        del lines[1]
        _rewrite(self.jpath, lines)
        with self.assertRaises(JournalCorrupted):
            Journal(self.jpath)

    def test_prev_link_tamper_fails_closed(self):
        j = Journal(self.jpath)
        j.append("A", {})
        j.append("B", {})
        lines = _raw_lines(self.jpath)
        second = _rec(lines[1])
        second["prev"] = "0" * 64
        lines[1] = _dump(second)
        _rewrite(self.jpath, lines)
        with self.assertRaises(JournalCorrupted):
            Journal(self.jpath)

    def test_seq_reorder_fails_closed(self):
        j = Journal(self.jpath)
        for i in range(2):
            j.append("R%d" % i, {"n": i})
        lines = _raw_lines(self.jpath)
        lines[0], lines[1] = lines[1], lines[0]
        _rewrite(self.jpath, lines)
        with self.assertRaises(JournalCorrupted):
            Journal(self.jpath)

    def test_append_many_is_one_transaction(self):
        j = Journal(self.jpath)
        j.append_many([("A", {"n": 1}), ("B", {"n": 2}), ("C", {"n": 3})])
        txns = {r["txn"] for r in j.records}
        self.assertEqual(len(txns), 1)
        self.assertNotIn(None, txns)
        j2 = Journal(self.jpath)
        self.assertEqual(len(j2.records), 3)

    def test_append_if_check_and_append_is_atomic(self):
        j = Journal(self.jpath)
        ok, _ = j.append_if([("Claim", {"id": 1})],
                            lambda recs: not any(r["type"] == "Claim"
                                                 for r in recs))
        self.assertTrue(ok)
        ok, _ = j.append_if([("Claim", {"id": 2})],
                            lambda recs: not any(r["type"] == "Claim"
                                                 for r in recs))
        self.assertFalse(ok)
        self.assertEqual(len(j.records), 1)

    def test_record_body_types_are_checked(self):
        j = Journal(self.jpath)
        with self.assertRaises(ValueError):
            j.append("", {})
        with self.assertRaises(ValueError):
            j.append("A", "not-a-dict")
        with self.assertRaises(ValueError):
            j.append_if([], lambda recs: True)

    def test_empty_journal_loads(self):
        j = Journal(self.jpath)
        self.assertEqual(j.records, [])
        self.assertTrue(j.tip.startswith("GENESIS"))
        self.assertEqual(verify_journal(self.jpath), (True, 0))

    def test_journal_file_mode_is_private(self):
        j = Journal(self.jpath)
        j.append("A", {})
        mode = os.stat(self.jpath).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_verify_journal_ok_and_bad(self):
        j = Journal(self.jpath)
        j.append("A", {})
        self.assertEqual(verify_journal(self.jpath), (True, 1))
        with open(self.jpath, "ab") as f:
            f.write(b"\x00not json\x00\n")
        self.assertEqual(verify_journal(self.jpath), (False, 0))


class TornTailTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dj-")
        self.jpath = os.path.join(self.tmp, "j.journal")

    def test_torn_tail_raises_torn_tail_error(self):
        j = Journal(self.jpath)
        j.append("A", {"n": 1})
        j.append("B", {"n": 2})
        tip_before = j.tip
        with open(self.jpath, "ab") as f:
            f.write(b'{"seq": 2, "prev": "abc')
        with self.assertRaises(TornTailError) as ctx:
            Journal(self.jpath)
        self.assertEqual(ctx.exception.tip_hash, tip_before)

    def test_torn_tail_recovery_is_explicit(self):
        j = Journal(self.jpath)
        j.append("A", {"n": 1})
        tip_before = j.tip
        with open(self.jpath, "ab") as f:
            f.write(b'{"seq": 1, "prev": "abc')
        recovered = recover_torn_tail(self.jpath)
        self.assertEqual(recovered, tip_before)
        ok, count = verify_journal(self.jpath)
        self.assertTrue(ok)
        self.assertEqual(count, 1)
        # Recovery refuses when the journal is already clean.
        with self.assertRaises(ValueError):
            recover_torn_tail(self.jpath)

    def test_recovery_refuses_tampered_prefix(self):
        j = Journal(self.jpath)
        j.append("A", {"n": 1})
        j.append("B", {"n": 2})
        lines = _raw_lines(self.jpath)
        rec = _rec(lines[0])
        rec["body"]["n"] = 999
        lines[0] = _dump(rec)
        lines.append('{"seq": 2, "prev": "torn')
        _rewrite(self.jpath, lines)
        with self.assertRaises((JournalCorrupted, TornTailError)):
            Journal(self.jpath)
        # The prefix is tampered: recovery must refuse, never truncate
        # and bless a corrupted prefix.
        with self.assertRaises(JournalCorrupted):
            recover_torn_tail(self.jpath)


class ConcurrencyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dj-")
        self.jpath = os.path.join(self.tmp, "j.journal")

    def test_concurrent_appends_serialize(self):
        q = multiprocessing.Queue()
        procs = [multiprocessing.Process(target=_concurrent_worker,
                                         args=(self.jpath, 20, q))
                 for _ in range(4)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(60)
            self.assertEqual(p.exitcode, 0)
        j = Journal(self.jpath)
        self.assertEqual(len(j.records), 80)
        self.assertEqual([r["seq"] for r in j.records], list(range(80)))

    def test_exclusive_lock_blocks_while_held(self):
        import time
        j = Journal(self.jpath)
        j.append("A", {})
        p = multiprocessing.Process(target=_lock_holder,
                                    args=(self.jpath, 5))
        p.start()
        time.sleep(1.0)
        try:
            fd = os.open(self.jpath, os.O_WRONLY | os.O_APPEND)
            try:
                with self.assertRaises((OSError, BlockingIOError)):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
        finally:
            p.join(10)
        self.assertEqual(p.exitcode, 0)
        # After the holder releases, appends proceed.
        j2 = Journal(self.jpath)
        j2.append("B", {})
        self.assertEqual(len(j2.records), 2)
        self.assertTrue(issubclass(JournalLockError, OSError))


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dj-")
        self.jpath = os.path.join(self.tmp, "j.journal")

    def _sidecar(self, seq):
        return "%s.snapshot.%d" % (self.jpath, seq)

    def test_snapshot_and_compact(self):
        j = Journal(self.jpath)
        j.append("A", {"n": 1})
        j.take_snapshot({"folded": "state", "count": 1})
        j.append("B", {"n": 2})
        j.append("C", {"n": 3})
        before_bodies = [r["body"] for r in j.records[2:]]
        j.compact()
        j2 = Journal(self.jpath)
        self.assertEqual(j2.records[0]["type"], "SnapshotLoaded")
        self.assertTrue(j2.records[0]["body"]["snapshot_hash"])
        self.assertEqual([r["type"] for r in j2.records],
                         ["SnapshotLoaded", "B", "C"])
        self.assertEqual([r["seq"] for r in j2.records], [0, 1, 2])
        # The bodies after the snapshot survived compaction byte-identical.
        self.assertEqual([r["body"] for r in j2.records[1:]], before_bodies)
        # Post-compaction appends chain cleanly.
        j2.append("D", {"n": 4})
        self.assertTrue(verify_journal(self.jpath)[0])

    def test_compact_requires_snapshot(self):
        j = Journal(self.jpath)
        j.append("A", {})
        with self.assertRaises(ValueError):
            j.compact()

    def test_compact_from_stale_handle_keeps_concurrent_appends(self):
        # j_stale loaded before j_live appended: compact must re-read
        # under the mutation mutex, so the concurrent appends survive
        # the replace instead of being silently lost.
        j_stale = Journal(self.jpath)
        j_stale.append("A", {"n": 1})
        j_stale.take_snapshot({"folded": "state"})
        j_live = Journal(self.jpath)
        j_live.append("B", {"n": 2})
        j_live.append("C", {"n": 3})
        # j_stale's in-memory records do NOT include B/C.
        self.assertEqual([r["type"] for r in j_stale.records],
                         ["A", "SnapshotTaken"])
        j_stale.compact()
        j2 = Journal(self.jpath)
        self.assertEqual([r["type"] for r in j2.records],
                         ["SnapshotLoaded", "B", "C"])
        self.assertTrue(verify_journal(self.jpath)[0])

    def test_snapshot_sidecar_tamper_fails_closed(self):
        j = Journal(self.jpath)
        j.append("A", {"n": 1})
        j.take_snapshot({"s": 1})
        j.compact()
        with open(self._sidecar(1), "ab") as f:
            f.write(b"tampered")
        with self.assertRaises(JournalCorrupted):
            Journal(self.jpath)

    def test_snapshot_sidecar_missing_fails_closed(self):
        j = Journal(self.jpath)
        j.append("A", {"n": 1})
        j.take_snapshot({"s": 1})
        j.compact()
        os.unlink(self._sidecar(1))
        with self.assertRaises(JournalCorrupted):
            Journal(self.jpath)

    def test_snapshot_record_tamper_fails_closed(self):
        j = Journal(self.jpath)
        j.append("A", {"n": 1})
        j.take_snapshot({"s": 1})
        lines = _raw_lines(self.jpath)
        rec = _rec(lines[1])
        rec["body"]["snapshot_hash"] = "f" * 64
        lines[1] = _dump(rec)
        _rewrite(self.jpath, lines)
        with self.assertRaises(JournalCorrupted):
            Journal(self.jpath)


if __name__ == "__main__":
    unittest.main()
