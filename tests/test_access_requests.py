"""Unit tests for gov.access_requests (Teleport access-request ADAPT)."""

import os
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import access_requests as ar
from gov import ephemeral_grants as eg
from gov.log import ActionLog

_NOW = 1790907600.0
_GRANTS = [{"tool": "tool:db_query"}]


def _store():
    return ar.AccessRequestStore()


def _submit(store, **kw):
    kw.setdefault("requestor", "agent:alice")
    kw.setdefault("grants", _GRANTS)
    kw.setdefault("reason", "nightly report")
    kw.setdefault("max_duration_s", 3600)
    kw.setdefault("now", _NOW)
    return ar.submit(store, **kw)


def _log():
    d = tempfile.mkdtemp(prefix="ar_ut_",
                         dir=os.environ.get("TMPDIR") or "/tmp")
    return ActionLog(os.path.join(d, "audit.jsonl"))


class SubmitTests(unittest.TestCase):
    def test_submit_pending(self):
        rec = _submit(_store())
        self.assertEqual(rec["state"], "PENDING")
        self.assertTrue(rec["request_id"].startswith("ar_"))
        self.assertEqual(len(rec["request_digest"]), 64)

    def test_submit_requires_reason(self):
        with self.assertRaises(ValueError):
            _submit(_store(), reason="   ")

    def test_submit_requires_grants(self):
        with self.assertRaises(ValueError):
            _submit(_store(), grants=[])

    def test_submit_bad_tool_shape(self):
        with self.assertRaises(ValueError):
            _submit(_store(), grants=[{"tool": "db_query"}])

    def test_submit_duration_ceiling(self):
        with self.assertRaises(ValueError):
            _submit(_store(), max_duration_s=90000)

    def test_submit_bad_threshold(self):
        with self.assertRaises(ValueError):
            _submit(_store(), approve_threshold=0)


class ReviewTests(unittest.TestCase):
    def test_approve_single(self):
        store = _store()
        rec = _submit(store)
        st = ar.review(store, rec["request_id"], "agent:bob", True,
                       now=_NOW + 1)
        self.assertEqual(st, "APPROVED")

    def test_deny_terminal(self):
        store = _store()
        rec = _submit(store)
        ar.review(store, rec["request_id"], "agent:bob", False,
                  now=_NOW + 1)
        self.assertEqual(store.get(rec["request_id"])["state"], "DENIED")

    def test_self_review_refused(self):
        store = _store()
        rec = _submit(store)
        with self.assertRaises(ar.AccessRequestError) as ctx:
            ar.review(store, rec["request_id"], "agent:alice", True,
                      now=_NOW + 1)
        self.assertEqual(ctx.exception.code,
                         "access-request-self-review-refused")

    def test_unknown_request(self):
        with self.assertRaises(ValueError):
            ar.review(_store(), "ar_nope", "agent:bob", True, now=_NOW)

    def test_expiry_at_read_time(self):
        store = _store()
        rec = _submit(store, max_duration_s=100)
        with self.assertRaises(ar.AccessRequestError) as ctx:
            ar.review(store, rec["request_id"], "agent:bob", True,
                      now=_NOW + 1000)
        self.assertEqual(ctx.exception.code,
                         "access-request-terminal-refused")
        self.assertEqual(store.get(rec["request_id"])["state"], "EXPIRED")

    def test_resolve_expiry(self):
        store = _store()
        rec = _submit(store, max_duration_s=100)
        self.assertEqual(ar.resolve(store, rec["request_id"], _NOW + 1000),
                         "EXPIRED")

    def test_no_expiry_before_deadline(self):
        store = _store()
        rec = _submit(store, max_duration_s=3600)
        self.assertEqual(ar.resolve(store, rec["request_id"], _NOW + 10),
                         "PENDING")


class MintTests(unittest.TestCase):
    def _approved(self, **kw):
        store = _store()
        rec = _submit(store, **kw)
        ar.review(store, rec["request_id"], "agent:bob", True,
                  now=_NOW + 1)
        return store, rec

    def test_mint_composes_with_check_grant(self):
        store, rec = self._approved(max_duration_s=600)
        grant = ar.mint_grant(store, rec["request_id"], now=_NOW + 1)
        d = eg.check_grant(principal="agent:alice",
                           action="tool:db_query",
                           tuples=grant["tuples"],
                           check_conditions={"now": _NOW + 2})
        self.assertTrue(d["allowed"])

    def test_mint_ttl_is_max_duration_from_approval(self):
        store, rec = self._approved(max_duration_s=600)
        grant = ar.mint_grant(store, rec["request_id"], now=_NOW + 1)
        self.assertEqual(grant["expires_at"], _NOW + 1 + 600)
        d = eg.check_grant(principal="agent:alice",
                           action="tool:db_query",
                           tuples=grant["tuples"],
                           check_conditions={"now": _NOW + 1 + 601})
        self.assertFalse(d["allowed"])

    def test_mint_pending_refused(self):
        store = _store()
        rec = _submit(store)
        with self.assertRaises(ar.AccessRequestError) as ctx:
            ar.mint_grant(store, rec["request_id"], now=_NOW + 1)
        self.assertEqual(ctx.exception.code, "access-request-grant-refused")

    def test_mint_denied_refused(self):
        store = _store()
        rec = _submit(store)
        ar.review(store, rec["request_id"], "agent:bob", False,
                  now=_NOW + 1)
        with self.assertRaises(ar.AccessRequestError):
            ar.mint_grant(store, rec["request_id"], now=_NOW + 2)

    def test_mint_scoped_to_requested_tools(self):
        store, rec = self._approved(grants=[{"tool": "tool:db_query"}])
        grant = ar.mint_grant(store, rec["request_id"], now=_NOW + 1)
        tools = {t.object for t in grant["tuples"]}
        self.assertEqual(tools, {"tool:db_query"})


class WriterTests(unittest.TestCase):
    def test_events_and_replay(self):
        log = _log()
        writer = ar.AccessRequestWriter(log)
        store = _store()
        rec = _submit(store, writer=writer)
        ar.review(store, rec["request_id"], "agent:bob", True,
                  now=_NOW + 1, writer=writer)
        grant = ar.mint_grant(store, rec["request_id"], now=_NOW + 1,
                              writer=writer)
        events = ar.access_request_events(log, rec["request_id"])
        self.assertEqual([e["event"] for e in events],
                         ["submitted", "review", "approved", "grant-issued"])
        self.assertTrue(all(e["join_key"] == rec["request_id"]
                            for e in events))
        self.assertEqual(ar.replay_state(log, rec["request_id"]), "APPROVED")
        self.assertEqual(grant["join_key"], rec["request_id"])
        self.assertTrue(writer.verify(log))

    def test_replay_denied(self):
        log = _log()
        writer = ar.AccessRequestWriter(log)
        store = _store()
        rec = _submit(store, writer=writer)
        ar.review(store, rec["request_id"], "agent:bob", False,
                  now=_NOW + 1, writer=writer)
        self.assertEqual(ar.replay_state(log, rec["request_id"]), "DENIED")

    def test_unknown_join_key_replays_none(self):
        log = _log()
        self.assertIsNone(ar.replay_state(log, "ar_missing"))


class SnapshotTests(unittest.TestCase):
    def test_round_trip(self):
        store = _store()
        rec = _submit(store, approve_threshold=2)
        ar.review(store, rec["request_id"], "agent:bob", True,
                  now=_NOW + 1)
        store2 = ar.AccessRequestStore.restore(store.snapshot())
        r2 = store2.get(rec["request_id"])
        self.assertEqual(r2["state"], "PENDING")
        self.assertEqual(len(r2["reviews"]), 1)

    def test_restore_rejects_malformed(self):
        with self.assertRaises(ValueError):
            ar.AccessRequestStore.restore({"nope": 1})

    def test_get_returns_copy_not_live(self):
        store = _store()
        rec = _submit(store)
        got = store.get(rec["request_id"])
        got["state"] = "APPROVED"
        self.assertEqual(store.get(rec["request_id"])["state"], "PENDING")


if __name__ == "__main__":
    unittest.main()
