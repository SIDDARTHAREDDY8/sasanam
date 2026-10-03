"""Unit tests for gov/memory_store.py (wave-298 lane 2).

Bi-temporal agent memory store (graphiti/cognee pattern): immutable
episodes, supersession (never delete), signed tombstone retraction,
bi-temporal recall, Admiralty reliability grading, declared
retention schedules. Every refusal asserted by machine code (F351).
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519
from gov import memory_store as ms


def _seed(tag):
    return hashlib.sha256(("w298-test-%s" % tag).encode()).digest()


def _pub(seed):
    return ed25519.publickey(seed).hex()


class _World:
    """Test world: two agents with keys, one archivist, one store."""

    def __init__(self):
        self.sa = _seed("agent-a")
        self.sb = _seed("agent-b")
        self.arch = _seed("archivist")
        self.store = ms.MemoryStore(archivists={"chief": _pub(self.arch)})

    def episode(self, seed, principal, tag="e", at=1000):
        import json
        agent = "agent-%s" % tag
        digest = hashlib.sha256(("content-%s" % tag).encode()).hexdigest()
        body = {"agent_id": agent, "content_digest": digest,
                "source_principal": principal, "source_pubkey": _pub(seed),
                "recorded_at": at}
        sig = ed25519.sign(seed, json.dumps(
            body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode()).hex()
        return self.store.record_episode(agent, digest, principal,
                                         _pub(seed), sig, at)

    def fact(self, seed, principal, key, stmt_tag, episodes, valid_at=1000,
             recorded_at=1100, retain_until=None, reliability="C",
             credibility=3):
        import json
        digest = hashlib.sha256(("stmt-%s" % stmt_tag).encode()).hexdigest()
        body = {"statement_key": key, "statement_digest": digest,
                "source_episode_ids": sorted(episodes),
                "source_principal": principal, "source_pubkey": _pub(seed),
                "valid_at": valid_at, "retain_until": retain_until,
                "reliability": reliability, "credibility": credibility,
                "created_at": recorded_at}
        sig = ed25519.sign(seed, json.dumps(
            body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode()).hex()
        return self.store.record_fact(key, digest, episodes, principal,
                                      _pub(seed), sig, valid_at,
                                      recorded_at, retain_until=retain_until,
                                      reliability=reliability,
                                      credibility=credibility)


def _code_of(fn):
    try:
        fn()
    except ms.MemoryStoreError as e:
        return e.code
    raise AssertionError("expected MemoryStoreError, got none")


class EpisodeTests(unittest.TestCase):

    def test_episode_happy_path(self):
        w = _World()
        eid = w.episode(w.sa, "alice")
        self.assertRegex(eid, r"^[0-9a-f]{64}$")

    def test_episode_idempotent(self):
        w = _World()
        a = w.episode(w.sa, "alice")
        b = w.episode(w.sa, "alice")
        self.assertEqual(a, b)

    def test_episode_forged_signature(self):
        w = _World()
        code = _code_of(lambda: w.store.record_episode(
            "agent-x", "0" * 64, "mallory", _pub(w.sa),
            ed25519.sign(w.sb, b"nope").hex(), 1000))
        self.assertEqual(code, ms.MEM_INVALID)

    def test_episode_malformed_digest(self):
        w = _World()
        code = _code_of(lambda: w.store.record_episode(
            "agent-x", "not-a-digest", "alice", _pub(w.sa),
            "ab" * 64, 1000))
        self.assertEqual(code, ms.MEM_INVALID)


class FactTests(unittest.TestCase):

    def test_fact_happy_path_recall(self):
        w = _World()
        eid = w.episode(w.sa, "alice")
        w.fact(w.sa, "alice", "sky-color", "blue", [eid])
        got = w.store.recall("sky-color", 1200)
        self.assertEqual(got["reliability_grade"], "C3")
        self.assertEqual(got["corroboration_count"], 1)
        self.assertEqual(got["source_episode_ids"], [eid])
        self.assertEqual(got["source_principal"], "alice")
        self.assertIsNone(got["invalid_at"])
        self.assertFalse(got["tombstoned"])

    def test_fact_unknown_episode_ref(self):
        w = _World()
        code = _code_of(lambda: w.fact(w.sa, "alice", "k", "s", ["0" * 64]))
        self.assertEqual(code, ms.MEM_INVALID)

    def test_fact_forged_signature(self):
        w = _World()
        eid = w.episode(w.sa, "alice")
        import json
        digest = hashlib.sha256(b"stmt-x").hexdigest()
        body = {"statement_key": "k", "statement_digest": digest,
                "source_episode_ids": [eid], "source_principal": "alice",
                "source_pubkey": _pub(w.sa), "valid_at": 1000,
                "retain_until": None, "reliability": "C", "credibility": 3,
                "created_at": 1100}
        sig = ed25519.sign(w.sb, json.dumps(
            body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode()).hex()  # wrong key
        code = _code_of(lambda: w.store.record_fact(
            "k", digest, [eid], "alice", _pub(w.sa), sig, 1000, 1100))
        self.assertEqual(code, ms.MEM_INVALID)

    def test_fact_bad_grade(self):
        w = _World()
        eid = w.episode(w.sa, "alice")
        code = _code_of(lambda: w.fact(w.sa, "alice", "k", "s", [eid],
                                       reliability="G"))
        self.assertEqual(code, ms.MEM_INVALID)
        code = _code_of(lambda: w.fact(w.sa, "alice", "k", "s", [eid],
                                       credibility=7))
        self.assertEqual(code, ms.MEM_INVALID)

    def test_fact_lapsed_retention_at_write(self):
        w = _World()
        eid = w.episode(w.sa, "alice")
        code = _code_of(lambda: w.fact(w.sa, "alice", "k", "s", [eid],
                                       recorded_at=1100, retain_until=1000))
        self.assertEqual(code, ms.MEM_INVALID)

    def test_supersession_closes_old(self):
        w = _World()
        e1 = w.episode(w.sa, "alice")
        e2 = w.episode(w.sa, "alice", tag="e2", at=2000)
        w.fact(w.sa, "alice", "k", "v1", [e1], valid_at=1000,
               recorded_at=1100)
        w.fact(w.sa, "alice", "k", "v2", [e2], valid_at=2000,
               recorded_at=2100)
        hist = w.store.history("k", 2200)
        self.assertEqual(len(hist), 2)
        self.assertEqual(hist[0]["invalid_at"], 2000)
        self.assertEqual(hist[0]["expired_at"], 2100)
        self.assertIsNone(hist[1]["invalid_at"])
        # bi-temporal: old T still recalls the old claim
        old = w.store.recall("k", 1500)
        self.assertEqual(old["statement_digest"],
                         hashlib.sha256(b"stmt-v1").hexdigest())
        new = w.store.recall("k", 2150)
        self.assertEqual(new["statement_digest"],
                         hashlib.sha256(b"stmt-v2").hexdigest())

    def test_recall_boundaries(self):
        w = _World()
        eid = w.episode(w.sa, "alice")
        w.fact(w.sa, "alice", "k", "s", [eid], valid_at=1000,
               recorded_at=1100)
        # left-closed: at valid_at and created_at -> OK
        self.assertIsNotNone(w.store.recall("k", 1100))
        # before created -> expired
        code = _code_of(lambda: w.store.recall("k", 1050))
        self.assertEqual(code, ms.MEM_EXPIRED)

    def test_recall_after_supersede_window(self):
        w = _World()
        e1 = w.episode(w.sa, "alice")
        e2 = w.episode(w.sa, "alice", tag="e2", at=2000)
        w.fact(w.sa, "alice", "k", "v1", [e1], valid_at=1000,
               recorded_at=1100)
        w.fact(w.sa, "alice", "k", "v2", [e2], valid_at=2000,
               recorded_at=2100)
        # at invalid_at (half-open right) the old record is gone;
        # the new one becomes live at its created_at
        got = w.store.recall("k", 2100)
        self.assertEqual(got["statement_digest"],
                         hashlib.sha256(b"stmt-v2").hexdigest())
        code = _code_of(lambda: w.store.recall("k", 2050))
        self.assertEqual(code, ms.MEM_EXPIRED)

    def test_recall_unknown_key(self):
        w = _World()
        code = _code_of(lambda: w.store.recall("nope", 1000))
        self.assertEqual(code, ms.MEM_INVALID)


class RetractionTests(unittest.TestCase):

    def _retract(self, w, key, seed, principal, at=3000):
        import json
        body = {"statement_key": key, "retractor_principal": principal,
                "retractor_pubkey": _pub(seed), "retracted_at": at}
        sig = ed25519.sign(seed, json.dumps(
            body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode()).hex()
        return w.store.retract_fact(key, principal, _pub(seed), sig, at)

    def test_retract_source_key(self):
        w = _World()
        eid = w.episode(w.sa, "alice")
        w.fact(w.sa, "alice", "k", "s", [eid])
        tid = self._retract(w, "k", w.sa, "alice")
        self.assertRegex(tid, r"^[0-9a-f]{64}$")
        code = _code_of(lambda: w.store.recall("k", 1200))
        self.assertEqual(code, ms.MEM_TOMBSTONED)
        hist = w.store.history("k", 3100)
        self.assertEqual(len(hist), 2)
        self.assertTrue(hist[-1]["tombstoned"])
        self.assertEqual(hist[0]["invalid_at"], 3000)

    def test_retract_archivist(self):
        w = _World()
        eid = w.episode(w.sa, "alice")
        w.fact(w.sa, "alice", "k", "s", [eid])
        self._retract(w, "k", w.arch, "chief")
        code = _code_of(lambda: w.store.recall("k", 1200))
        self.assertEqual(code, ms.MEM_TOMBSTONED)

    def test_retract_wrong_key(self):
        w = _World()
        eid = w.episode(w.sa, "alice")
        w.fact(w.sa, "alice", "k", "s", [eid])
        code = _code_of(lambda: self._retract(w, "k", w.sb, "bob"))
        self.assertEqual(code, ms.MEM_UNSIGNED_RETRACTION)

    def test_retract_tampered_signature(self):
        w = _World()
        eid = w.episode(w.sa, "alice")
        w.fact(w.sa, "alice", "k", "s", [eid])
        import json
        body = {"statement_key": "k", "retractor_principal": "alice",
                "retractor_pubkey": _pub(w.sa), "retracted_at": 3000}
        sig = ed25519.sign(w.sa, json.dumps(
            body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode()).hex()
        bad = ("00" if sig[:2] != "00" else "ff") + sig[2:]
        code = _code_of(lambda: w.store.retract_fact(
            "k", "alice", _pub(w.sa), bad, 3000))
        self.assertEqual(code, ms.MEM_UNSIGNED_RETRACTION)

    def test_retract_unknown_key(self):
        w = _World()
        code = _code_of(lambda: self._retract(w, "nope", w.sa, "alice"))
        self.assertEqual(code, ms.MEM_INVALID)

    def test_double_retract(self):
        w = _World()
        eid = w.episode(w.sa, "alice")
        w.fact(w.sa, "alice", "k", "s", [eid])
        self._retract(w, "k", w.sa, "alice")
        code = _code_of(lambda: self._retract(w, "k", w.sa, "alice", at=3100))
        self.assertEqual(code, ms.MEM_TOMBSTONED)


class RetentionTests(unittest.TestCase):

    def test_retention_lapse_refuses_loud(self):
        w = _World()
        eid = w.episode(w.sa, "alice")
        w.fact(w.sa, "alice", "k", "s", [eid], recorded_at=1100,
               retain_until=2000)
        self.assertIsNotNone(w.store.recall("k", 1500))
        code = _code_of(lambda: w.store.recall("k", 2000))
        self.assertEqual(code, ms.MEM_RETENTION_LAPSED)
        code = _code_of(lambda: w.store.history("k", 2000))
        self.assertEqual(code, ms.MEM_RETENTION_LAPSED)


class NoDeleteTests(unittest.TestCase):

    def test_no_delete_api(self):
        w = _World()
        for name in ("delete_fact", "remove_fact", "delete", "remove",
                     "purge", "forget"):
            self.assertFalse(hasattr(w.store, name),
                             "store must not grow a %r method" % name)
        with self.assertRaises(AttributeError):
            w.store.delete_fact("k")


class CorroborationTests(unittest.TestCase):

    def test_corroboration_counts_distinct_principals(self):
        w = _World()
        e1 = w.episode(w.sa, "alice")
        e2 = w.episode(w.sb, "bob", tag="e2", at=2000)
        w.fact(w.sa, "alice", "k", "same", [e1], valid_at=1000,
               recorded_at=1100)
        w.fact(w.sb, "bob", "k", "same", [e2], valid_at=2000,
               recorded_at=2100)
        got = w.store.recall("k", 2200)
        self.assertEqual(got["corroboration_count"], 2)

    def test_corroboration_distinguishes_digests(self):
        w = _World()
        e1 = w.episode(w.sa, "alice")
        e2 = w.episode(w.sb, "bob", tag="e2", at=2000)
        w.fact(w.sa, "alice", "k", "v1", [e1], valid_at=1000,
               recorded_at=1100)
        w.fact(w.sb, "bob", "k", "v2", [e2], valid_at=2000,
               recorded_at=2100)
        got = w.store.recall("k", 2200)
        self.assertEqual(got["corroboration_count"], 1)


class Ed25519ContractTests(unittest.TestCase):

    def test_verify_contract(self):
        seed = _seed("contract")
        pub = ed25519.publickey(seed)
        msg = b"contract"
        sig = ed25519.sign(seed, msg)
        self.assertIs(ed25519.verify(pub, msg, sig), True)
        bad = bytearray(sig)
        bad[0] ^= 1
        self.assertIs(ed25519.verify(pub, msg, bytes(bad)), False)


if __name__ == "__main__":
    unittest.main()
