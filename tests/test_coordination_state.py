"""Unit tests for gov/coordination_state.py (wave-295 lane 4).

Signed CRDT shared state (automerge pattern): every change carries an
Ed25519 signature over (actor_id, seq, payload, parents, author key);
merge is union-only and deterministic; forks are first-class.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import coordination_state as cs
from gov import decision_codes
from gov import ed25519

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_EVE = bytes(range(97, 129))


def _pub(seed):
    return ed25519.publickey(seed).hex()


_PUB_A = _pub(_SEED_A)
_PUB_B = _pub(_SEED_B)
_PUB_C = _pub(_SEED_C)
_PUB_EVE = _pub(_SEED_EVE)


def _dag(trusted=(_PUB_A, _PUB_B, _PUB_C)):
    return cs.StateDag("test-registry", set(trusted))


def _set(key, value="v"):
    return {"op": "set", "key": key, "value": value}


class CoordinationStateTest(unittest.TestCase):
    # -- happy path --------------------------------------------------

    def test_sign_ingest_verify_roundtrip(self):
        d = _dag()
        ch = cs.sign_change(_SEED_A, "agent-a", 1, _set("k1", "v1"))
        out = d.ingest(ch)
        self.assertIs(out["applied"], True)
        self.assertIs(out["duplicate"], False)
        self.assertEqual(out["digest"], ch["digest"])
        self.assertEqual(len(d), 1)

    def test_materialize_folds_in_deterministic_order(self):
        d = _dag()
        d.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k", "from-a")))
        d.ingest(cs.sign_change(_SEED_B, "agent-b", 1, _set("k", "from-b")))
        # (seq, actor_id): (1, agent-a) < (1, agent-b) -> b wins.
        self.assertEqual(d.materialize(), {"k": "from-b"})

    def test_replay_is_idempotent_noop(self):
        d = _dag()
        ch = cs.sign_change(_SEED_A, "agent-a", 1, _set("k"))
        d.ingest(ch)
        out = d.ingest(ch)
        self.assertIs(out["applied"], False)
        self.assertIs(out["duplicate"], True)
        self.assertEqual(len(d), 1)

    def test_heads_and_missing_parents(self):
        d = _dag()
        self.assertEqual(d.heads(), [])
        a1 = d.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k"))
                      )["digest"]
        self.assertEqual(d.heads(), [a1])
        a2 = cs.sign_change(_SEED_A, "agent-a", 2, _set("k"),
                            parents=[a1])
        d.ingest(a2)
        self.assertEqual(d.heads(), [a2["digest"]])
        self.assertEqual(d.missing_parents(), [])

    def test_change_digest_is_content_addressed(self):
        c1 = cs.sign_change(_SEED_A, "agent-a", 1, _set("k", "v1"))
        c2 = cs.sign_change(_SEED_A, "agent-a", 1, _set("k", "v2"))
        self.assertNotEqual(c1["digest"], c2["digest"])
        self.assertEqual(len(c1["digest"]), 64)

    def test_all_changes_sorted_deterministically(self):
        d = _dag()
        d.ingest(cs.sign_change(_SEED_B, "agent-b", 1, _set("k")))
        d.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k")))
        order = [(c["seq"], c["actor_id"]) for c in d.all_changes()]
        self.assertEqual(order, [(1, "agent-a"), (1, "agent-b")])

    # -- forgery / invalid -------------------------------------------

    def test_forged_signature_refuses_coded(self):
        d = _dag()
        ch = cs.sign_change(_SEED_A, "agent-a", 1, _set("k"))
        ch["signature"] = "00" * 64  # valid hex, wrong signature
        with self.assertRaises(cs.CoordinationStateError) as cm:
            d.ingest(ch)
        self.assertEqual(cm.exception.code, "coord-state-forgery")

    def test_forged_signature_swapped_key_refuses(self):
        d = _dag()
        ch = cs.sign_change(_SEED_EVE, "agent-a", 1, _set("k"))
        # Eve signs with her own seed but claims to be A's key.
        ch["author_pubkey"] = _PUB_A
        with self.assertRaises(cs.CoordinationStateError) as cm:
            d.ingest(ch)
        self.assertEqual(cm.exception.code, "coord-state-forgery")

    def test_untrusted_author_refuses_invalid(self):
        d = _dag(trusted=(_PUB_A,))
        ch = cs.sign_change(_SEED_B, "agent-b", 1, _set("k"))
        with self.assertRaises(cs.CoordinationStateError) as cm:
            d.ingest(ch)
        self.assertEqual(cm.exception.code, "coord-state-invalid")

    def test_malformed_change_refuses_invalid(self):
        d = _dag()
        for bad in (None, [], "x", {"actor_id": "agent-a"}):
            with self.assertRaises(cs.CoordinationStateError) as cm:
                d.ingest(bad)
            self.assertEqual(cm.exception.code, "coord-state-invalid")

    def test_circular_payload_refuses_coded_not_bare(self):
        d = _dag()
        evil = {}
        evil["self"] = evil
        with self.assertRaises(cs.CoordinationStateError) as cm:
            cs.sign_change(_SEED_A, "agent-a", 1, evil)
        # F351-class: coded refusal, never a bare ValueError.
        self.assertEqual(cm.exception.code, "coord-state-invalid")

    def test_duplicate_parents_refuse(self):
        d = _dag()
        a1 = d.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k"))
                      )["digest"]
        with self.assertRaises(cs.CoordinationStateError) as cm:
            cs.sign_change(_SEED_A, "agent-a", 2, _set("k"),
                           parents=[a1, a1])
        self.assertEqual(cm.exception.code, "coord-state-invalid")

    def test_seq_gap_refuses_invalid(self):
        d = _dag()
        d.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k")))
        with self.assertRaises(cs.CoordinationStateError) as cm:
            d.ingest(cs.sign_change(_SEED_A, "agent-a", 3, _set("k")))
        self.assertEqual(cm.exception.code, "coord-state-invalid")

    def test_seq_reuse_overwrite_refuses_coded(self):
        d = _dag()
        d.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k", "v1")))
        other = cs.sign_change(_SEED_A, "agent-a", 1, _set("k", "v2"))
        with self.assertRaises(cs.CoordinationStateError) as cm:
            d.ingest(other)
        self.assertEqual(cm.exception.code, "coord-state-overwrite")

    def test_non_set_op_refuses(self):
        d = _dag()
        with self.assertRaises(cs.CoordinationStateError) as cm:
            cs.sign_change(_SEED_A, "agent-a", 1, {"op": "delete",
                                                  "key": "k"})
        self.assertEqual(cm.exception.code, "coord-state-invalid")

    def test_non_scalar_value_refuses(self):
        d = _dag()
        with self.assertRaises(cs.CoordinationStateError) as cm:
            cs.sign_change(_SEED_A, "agent-a", 1,
                           {"op": "set", "key": "k",
                            "value": {"nested": "object"}})
        self.assertEqual(cm.exception.code, "coord-state-invalid")

    # -- bounds -------------------------------------------------------

    def test_payload_over_bound_refuses(self):
        with self.assertRaises(cs.CoordinationStateError) as cm:
            cs.sign_change(_SEED_A, "agent-a", 1,
                           _set("k", "x" * 5000))
        self.assertEqual(cm.exception.code, "coord-state-bound")

    def test_too_many_changes_refuses(self):
        d = _dag()
        old_max = cs._MAX_CHANGES
        cs._MAX_CHANGES = 2
        try:
            d.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k1")))
            d.ingest(cs.sign_change(_SEED_B, "agent-b", 1, _set("k2")))
            with self.assertRaises(cs.CoordinationStateError) as cm:
                d.ingest(cs.sign_change(_SEED_C, "agent-c", 1, _set("k3")))
            self.assertEqual(cm.exception.code, "coord-state-bound")
        finally:
            cs._MAX_CHANGES = old_max

    def test_depth_bound_survives_reverse_ingest(self):
        # Evasion attempt: build a chain across 4 actors and ingest it
        # leaf-first, so every parent is unknown at ingest time. The
        # bound must still hold once the ancestry completes.
        old_max = cs._MAX_DEPTH
        cs._MAX_DEPTH = 2
        try:
            seeds = [_SEED_A, _SEED_B, _SEED_C,
                     bytes(range(129, 161))]
            pubs = {_pub(s) for s in seeds}
            d2 = cs.StateDag("r2", pubs)
            chain = []
            parent = None
            for i, seed in enumerate(seeds):
                actor = "actor-%d" % i
                ch = cs.sign_change(seed, actor, 1, _set("k"),
                                    parents=[parent] if parent else [])
                parent = ch["digest"]
                chain.append(ch)
            # Ingest leaf-first.
            d2.ingest(chain[3])
            d2.ingest(chain[2])
            d2.ingest(chain[1])
            with self.assertRaises(cs.CoordinationStateError) as cm:
                d2.ingest(chain[0])
            self.assertEqual(cm.exception.code, "coord-state-bound")
        finally:
            cs._MAX_DEPTH = old_max

    def test_depth_over_bound_refuses(self):
        d = _dag()
        old_max = cs._MAX_DEPTH
        cs._MAX_DEPTH = 2
        try:
            p = None
            for i in range(1, 4):
                ch = cs.sign_change(_SEED_A, "agent-a", i, _set("k"),
                                    parents=[p] if p else [])
                p = d.ingest(ch)["digest"]
            with self.assertRaises(cs.CoordinationStateError) as cm:
                d.ingest(cs.sign_change(_SEED_A, "agent-a", 4, _set("k"),
                                        parents=[p]))
            self.assertEqual(cm.exception.code, "coord-state-bound")
        finally:
            cs._MAX_DEPTH = old_max

    def test_bad_seed_refuses(self):
        with self.assertRaises(cs.CoordinationStateError) as cm:
            cs.sign_change(b"short", "agent-a", 1, _set("k"))
        self.assertEqual(cm.exception.code, "coord-state-invalid")

    # -- merge --------------------------------------------------------

    def _two_dags(self):
        da = _dag()
        db = _dag()
        a1 = da.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k"))
                       )["digest"]
        # db forks from the same root
        db.ingest(da.get(a1))
        da.ingest(cs.sign_change(_SEED_A, "agent-a", 2, _set("ka", "a"),
                                 parents=[a1]))
        db.ingest(cs.sign_change(_SEED_B, "agent-b", 1, _set("kb", "b"),
                                 parents=[a1]))
        return da, db

    def test_merge_union_and_fork_record(self):
        da, db = self._two_dags()
        head, forks = da.merge(db)
        self.assertEqual(len(da), 3)  # union: nothing lost
        self.assertEqual(len(forks), 1)
        fork = forks[0]
        self.assertIn("tip", fork)
        self.assertIn("base", fork)
        self.assertIn("changes", fork)
        self.assertIsNotNone(fork["base"])
        self.assertEqual(len(fork["changes"]), 1)

    def test_merge_is_order_independent(self):
        da, db = self._two_dags()
        h1, f1 = da.merge(db)
        da2, db2 = self._two_dags()
        h2, f2 = db2.merge(da2)
        self.assertEqual(h1, h2)
        self.assertEqual(f1, f2)

    def test_merge_single_head_no_forks(self):
        da = _dag()
        db = _dag()
        da.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k")))
        head, forks = db.merge(da)
        self.assertEqual(forks, [])
        self.assertEqual(head, db.heads()[0])

    def test_merge_never_deletes_signed_change(self):
        da, db = self._two_dags()
        before = {c["digest"] for c in da.all_changes()} | \
                 {c["digest"] for c in db.all_changes()}
        da.merge(db)
        after = {c["digest"] for c in da.all_changes()}
        self.assertEqual(before, after)

    def test_merge_forged_peer_change_refuses(self):
        da = _dag()
        db = _dag()
        da.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k")))
        forged = cs.sign_change(_SEED_EVE, "agent-b", 1, _set("evil"))
        forged["author_pubkey"] = _PUB_B
        db._changes[forged["digest"]] = dict(forged)
        db._changes[forged["digest"]]["digest"] = forged["digest"]
        db._last_seq["agent-b"] = 1
        with self.assertRaises(cs.CoordinationStateError) as cm:
            da.merge(db)
        self.assertEqual(cm.exception.code, "coord-state-forgery")

    def test_merge_non_dag_refuses(self):
        d = _dag()
        with self.assertRaises(cs.CoordinationStateError) as cm:
            d.merge({"not": "a dag"})
        self.assertEqual(cm.exception.code, "coord-state-invalid")

    def test_offline_fork_rejoin(self):
        # Actor B works offline from an old head; A advances the main
        # DAG; rejoin merges both branches as a first-class fork.
        main = _dag()
        root = main.ingest(cs.sign_change(_SEED_A, "agent-a", 1,
                                          _set("root")))["digest"]
        offline = _dag()
        offline.ingest(main.get(root))
        offline.ingest(cs.sign_change(_SEED_B, "agent-b", 1,
                                      _set("offline-key", "v"),
                                      parents=[root]))
        main.ingest(cs.sign_change(_SEED_A, "agent-a", 2,
                                   _set("main-key", "v"),
                                   parents=[root]))
        head, forks = main.merge(offline)
        self.assertEqual(len(main), 3)
        self.assertEqual(len(forks), 1)
        self.assertEqual(main.materialize(),
                         {"root": "v", "offline-key": "v",
                          "main-key": "v"})
        self.assertEqual(main.missing_parents(), [])

    def test_verify_change_stateless(self):
        ch = cs.sign_change(_SEED_A, "agent-a", 1, _set("k"))
        ok, detail = cs.verify_change(ch, {_PUB_A})
        self.assertIs(ok, True)
        self.assertEqual(detail["digest"], ch["digest"])

    def test_verify_change_rejects_untrusted(self):
        ch = cs.sign_change(_SEED_A, "agent-a", 1, _set("k"))
        with self.assertRaises(cs.CoordinationStateError) as cm:
            cs.verify_change(ch, {_PUB_B})
        self.assertEqual(cm.exception.code, "coord-state-invalid")

    def test_empty_trusted_set_refuses(self):
        with self.assertRaises(cs.CoordinationStateError) as cm:
            cs.StateDag("r", set())
        self.assertEqual(cm.exception.code, "coord-state-invalid")

    def test_codes_registered(self):
        for code in ("coord-state-overwrite", "coord-state-bound",
                     "coord-state-forgery", "coord-state-invalid"):
            self.assertIn(code, decision_codes.TAXONOMY)


if __name__ == "__main__":
    unittest.main()
