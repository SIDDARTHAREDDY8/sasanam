"""Unit tests for gov/memory_reconcile.py (wave-298 lane 3).

Red-first: written against the new module; every coded refusal is
asserted by code.
"""

import hashlib
import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519
from gov import memory_reconcile as mr


def _seed(tag):
    return hashlib.sha256(b"w298-unit:" + tag.encode()).digest()


def _prov(principal="agent-a", reliability="C3", corroborations=0):
    return {"source_principal": principal, "reliability": reliability,
            "corroborations": corroborations, "ingested_at": 1000}


class _Harness:
    def __init__(self, test):
        self.t = test
        self.r = mr.MemoryReconciler(_seed("reconciler"), "recon-1")
        self.owner_seed = _seed("owner-a")
        self.r.declare_namespace(
            "agent-a", ed25519.publickey(self.owner_seed).hex())

    def candidate(self, key="k", value="v", op="add", supersedes=None,
                  provenance=None, namespace="agent-a", written_at=1000,
                  expires_at=None, seed=None):
        vd = hashlib.sha256(value.encode()).hexdigest()
        cand = {"schema": "memory-record/v1", "namespace": namespace,
                "key": key, "value_digest": vd, "written_at": written_at,
                "supersedes": supersedes,
                "provenance": provenance or _prov(),
                "expires_at": expires_at, "op": op}
        body = {k: cand[k] for k in
                ("schema", "namespace", "key", "value_digest", "written_at",
                 "supersedes", "provenance", "expires_at", "op")}
        cand["signature"] = ed25519.sign(
            seed or self.owner_seed,
            json.dumps(body, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode()).hex()
        return cand


class TestMemoryReconcile(unittest.TestCase):
    def setUp(self):
        self.h = _Harness(self)

    def test_codes(self):
        self.assertEqual(mr.RC_INVALID, "memory-reconcile-invalid")
        self.assertEqual(mr.RC_SCOPE_MISSING, "memory-reconcile-scope-missing")
        self.assertEqual(mr.RC_UNAUTH_NS,
                         "memory-reconcile-unauthorized-namespace")
        self.assertEqual(mr.RC_POISON, "memory-reconcile-poison-refused")
        self.assertEqual(mr.RC_CONFLICT,
                         "memory-reconcile-conflict-unresolved")

    def test_decisions_vocabulary(self):
        self.assertEqual(
            (mr.RC_ADD, mr.RC_UPDATE, mr.RC_DELETE, mr.RC_NOOP),
            ("ADD", "UPDATE", "DELETE", "NOOP"))

    def test_add_verify_recall(self):
        h = self.h
        dec = h.r.reconcile(h.candidate(), [], {}, 1000)
        self.assertEqual(dec["decision"], "ADD")
        self.assertTrue(h.r.verify_decision(dec))
        rec = h.r.recall({"namespace": "agent-a", "key": "k"},
                         "agent-a", 1001)
        self.assertEqual(rec["state"], "active")
        self.assertIn("fact_id", rec)

    def test_noop_duplicate(self):
        h = self.h
        h.r.reconcile(h.candidate(), [], {}, 1000)
        latest = h.r.recall({"namespace": "agent-a", "key": "k"},
                            "agent-a", 1001)
        dec = h.r.reconcile(h.candidate(written_at=1002), [latest], {},
                            1002)
        self.assertEqual(dec["decision"], "NOOP")

    def test_update_with_snapshot(self):
        h = self.h
        h.r.reconcile(h.candidate(provenance=_prov(corroborations=3,
                                                  reliability="A1")),
                      [], {}, 1000)
        latest = h.r.recall({"namespace": "agent-a", "key": "k"},
                            "agent-a", 1001)
        upd = h.candidate(value="v2", op="update",
                          supersedes=latest["fact_id"],
                          provenance=_prov(corroborations=2),
                          written_at=1002)
        dec = h.r.reconcile(upd, [latest], {}, 1002)
        self.assertEqual(dec["decision"], "UPDATE")
        self.assertEqual(dec["supersedes"], latest["fact_id"])
        self.assertTrue(dec["snapshot_digest"])
        self.assertTrue(h.r.verify_decision(dec))

    def test_update_refuses_without_supersedes(self):
        h = self.h
        h.r.reconcile(h.candidate(), [], {}, 1000)
        latest = h.r.recall({"namespace": "agent-a", "key": "k"},
                            "agent-a", 1001)
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.reconcile(h.candidate(value="v2", op="update",
                                      written_at=1002),
                          [latest], {}, 1002)
        self.assertEqual(cm.exception.code, mr.RC_INVALID)

    def test_poison_refused(self):
        h = self.h
        h.r.reconcile(h.candidate(provenance=_prov(reliability="A1",
                                                  corroborations=3)),
                      [], {}, 1000)
        latest = h.r.recall({"namespace": "agent-a", "key": "k"},
                            "agent-a", 1001)
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.reconcile(h.candidate(value="evil", op="update",
                                      supersedes=latest["fact_id"],
                                      written_at=1002),
                          [latest], {}, 1002)
        self.assertEqual(cm.exception.code, mr.RC_POISON)

    def test_archivist_override_permits(self):
        from gov import ed25519 as ed
        h = self.h
        arch = _seed("archivist")
        h.r.declare_archivist(ed.publickey(arch).hex())
        h.r.reconcile(h.candidate(provenance=_prov(reliability="B2",
                                                  corroborations=3)),
                      [], {}, 1000)
        latest = h.r.recall({"namespace": "agent-a", "key": "k"},
                            "agent-a", 1001)
        upd = h.candidate(value="v2", op="update",
                          supersedes=latest["fact_id"], written_at=1002)
        body = {k: upd[k] for k in
                ("schema", "namespace", "key", "value_digest", "written_at",
                 "supersedes", "provenance", "expires_at", "op")}
        override = ed.sign(
            arch, json.dumps(body, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode()).hex()
        dec = h.r.reconcile(upd, [latest],
                            {"archivist_override": override}, 1002)
        self.assertEqual(dec["decision"], "UPDATE")

    def test_add_conflict_code(self):
        h = self.h
        h.r.reconcile(h.candidate(), [], {}, 1000)
        latest = h.r.recall({"namespace": "agent-a", "key": "k"},
                            "agent-a", 1001)
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.reconcile(h.candidate(value="other", op="add",
                                      written_at=1002),
                          [latest], {}, 1002)
        self.assertEqual(cm.exception.code, mr.RC_CONFLICT)

    def test_delete_tombstones(self):
        h = self.h
        h.r.reconcile(h.candidate(), [], {}, 1000)
        latest = h.r.recall({"namespace": "agent-a", "key": "k"},
                            "agent-a", 1001)
        dec = h.r.reconcile(h.candidate(op="delete",
                                        supersedes=latest["fact_id"],
                                        written_at=1002),
                            [latest], {}, 1002)
        self.assertEqual(dec["decision"], "DELETE")
        hist = h.r._facts[("agent-a", "k")]
        self.assertEqual(len(hist), 2)
        self.assertEqual(hist[0]["fact_id"], latest["fact_id"])
        self.assertEqual(hist[1]["state"], "tombstoned")

    def test_recall_tombstoned_refused(self):
        h = self.h
        h.r.reconcile(h.candidate(), [], {}, 1000)
        latest = h.r.recall({"namespace": "agent-a", "key": "k"},
                            "agent-a", 1001)
        h.r.reconcile(h.candidate(op="delete",
                                  supersedes=latest["fact_id"],
                                  written_at=1002),
                      [latest], {}, 1002)
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.recall({"namespace": "agent-a", "key": "k"}, "agent-a",
                       1003)
        self.assertEqual(cm.exception.code, mr.RC_INVALID)

    def test_recall_requires_scope(self):
        h = self.h
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.recall({}, "agent-a", 1000)
        self.assertEqual(cm.exception.code, mr.RC_SCOPE_MISSING)
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.recall(None, "agent-a", 1000)
        self.assertEqual(cm.exception.code, mr.RC_SCOPE_MISSING)

    def test_cross_namespace_needs_grant(self):
        h = self.h
        h.r.declare_namespace(
            "agent-b", ed25519.publickey(_seed("owner-b")).hex())
        h.r.reconcile(h.candidate(), [], {}, 1000)
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.recall({"namespace": "agent-a", "key": "k"}, "agent-b",
                       1001)
        self.assertEqual(cm.exception.code, mr.RC_UNAUTH_NS)
        grant = h.r.grant_sharing("agent-a", "agent-b", 900, 2000,
                                 h.owner_seed)
        # F376 (wave-300): bearer-grant model -- the signed grant must be
        # presented; a bare namespace string never authorizes.
        rec = h.r.recall({"namespace": "agent-a", "key": "k"}, "agent-b",
                         1500, grant=grant)
        self.assertEqual(rec["state"], "active")
        h.r.revoke_grant(grant["grant_id"], h.owner_seed)
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.recall({"namespace": "agent-a", "key": "k"}, "agent-b",
                       1500, grant=grant)
        self.assertEqual(cm.exception.code, mr.RC_UNAUTH_NS)

    def test_forged_candidate_refused(self):
        h = self.h
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.reconcile(h.candidate(seed=_seed("attacker")), [], {},
                          1000)
        self.assertEqual(cm.exception.code, mr.RC_UNAUTH_NS)

    def test_forged_decision_refused(self):
        h = self.h
        dec = h.r.reconcile(h.candidate(), [], {}, 1000)
        tampered = dict(dec)
        tampered["decision"] = "UPDATE"
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.verify_decision(tampered)
        self.assertEqual(cm.exception.code, mr.RC_INVALID)

    def test_ed25519_contract(self):
        seed = _seed("contract")
        pub = ed25519.publickey(seed)
        sig = ed25519.sign(seed, b"x")
        self.assertIs(ed25519.verify(pub, b"x", sig), True)
        bad = bytearray(sig)
        bad[0] ^= 1
        self.assertIs(ed25519.verify(pub, b"x", bytes(bad)), False)

    def test_rate_bound(self):
        r = mr.MemoryReconciler(_seed("reconciler"), "recon-1",
                                max_writes_per_principal=1,
                                write_window_seconds=60)
        owner_seed = _seed("owner-a")
        r.declare_namespace("agent-a",
                            ed25519.publickey(owner_seed).hex())
        hh = _Harness(self)
        hh.r = r
        hh.owner_seed = owner_seed
        r.reconcile(hh.candidate(key="one"), [], {}, 1000)
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            r.reconcile(hh.candidate(key="two"), [], {}, 1001)
        self.assertEqual(cm.exception.code, mr.RC_INVALID)

    def test_store_divergence_refused(self):
        h = self.h
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.reconcile(h.candidate(), [{"schema": "memory-record/v1",
                                           "fact_id": "00" * 32}],
                          {}, 1000)
        self.assertEqual(cm.exception.code, mr.RC_INVALID)

    def test_grant_ttl_bounded(self):
        h = self.h
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.grant_sharing("agent-a", "agent-a", 0, 31 * 86400,
                             h.owner_seed)
        self.assertEqual(cm.exception.code, mr.RC_INVALID)


class TestF375F376Closures(unittest.TestCase):
    """Regression pins for the wave-299 findings closed in wave-300."""

    def test_f375_principal_rotation_no_longer_evades_bound(self):
        # F375: rotating provenance.source_principal used to evade the
        # bound; the bound is now keyed on the authenticated owner key
        # as well, so the 3rd rotated write refuses.
        r = mr.MemoryReconciler(_seed("reconciler"), "recon-1",
                                max_writes_per_principal=2,
                                write_window_seconds=3600)
        owner_seed = _seed("owner-a")
        r.declare_namespace("agent-a",
                            ed25519.publickey(owner_seed).hex())
        hh = _Harness(self)
        hh.r = r
        hh.owner_seed = owner_seed
        accepted = 0
        for i in range(6):
            try:
                r.reconcile(hh.candidate(
                    key="k%d" % i, value="v%d" % i,
                    provenance=_prov(principal="principal-%d" % i),
                    written_at=1000 + i), [], {}, 1000 + i)
                accepted += 1
            except mr.MemoryReconcileError:
                pass
        self.assertEqual(accepted, 2)

    def test_f375_distinct_owners_keep_independent_budgets(self):
        # Two different namespace owners are not charged against each
        # other's budget.
        r = mr.MemoryReconciler(_seed("reconciler"), "recon-1",
                                max_writes_per_principal=1,
                                write_window_seconds=3600)
        seed_a = _seed("owner-a")
        seed_b = _seed("owner-b")
        r.declare_namespace("agent-a", ed25519.publickey(seed_a).hex())
        r.declare_namespace("agent-b", ed25519.publickey(seed_b).hex())
        hh = _Harness(self)
        hh.r = r
        r.reconcile(hh.candidate(namespace="agent-a", seed=seed_a,
                                 provenance=_prov(principal="owner-a-writer")),
                    [], {}, 1000)
        dec = r.reconcile(hh.candidate(namespace="agent-b", seed=seed_b,
                                       provenance=_prov(
                                           principal="owner-b-writer")),
                          [], {}, 1001)
        self.assertEqual(dec["decision"], "ADD")

    def test_f376_grant_must_be_presented(self):
        # F376: a self-asserted grantee name no longer authorizes;
        # the signed grant must be presented and must verify against
        # the owner's declared key.
        h = _Harness(self)
        h.r.declare_namespace(
            "agent-b", ed25519.publickey(_seed("owner-b")).hex())
        h.r.reconcile(h.candidate(), [], {}, 1000)
        h.r.grant_sharing("agent-a", "agent-b", 900, 2000, h.owner_seed)
        # bare assertion, no grant presented
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.recall({"namespace": "agent-a", "key": "k"}, "agent-b",
                       1500)
        self.assertEqual(cm.exception.code, mr.RC_UNAUTH_NS)

    def test_f376_presented_grant_verifies(self):
        # An honestly presented grant still authorizes; a forged one
        # (wrong owner key) refuses.
        h = _Harness(self)
        h.r.declare_namespace(
            "agent-b", ed25519.publickey(_seed("owner-b")).hex())
        h.r.reconcile(h.candidate(), [], {}, 1000)
        grant = h.r.grant_sharing("agent-a", "agent-b", 900, 2000,
                                  h.owner_seed)
        rec = h.r.recall({"namespace": "agent-a", "key": "k"}, "agent-b",
                         1500, grant=grant)
        self.assertEqual(rec["state"], "active")
        forged = dict(grant)
        forged["signature"] = "00" * 64
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.recall({"namespace": "agent-a", "key": "k"}, "agent-b",
                       1500, grant=forged)
        self.assertEqual(cm.exception.code, mr.RC_UNAUTH_NS)

    def test_f376_wrong_grantee_name_refused(self):
        # Presenting alice->bob's grant while asserting "carol" refuses.
        h = _Harness(self)
        h.r.declare_namespace(
            "agent-b", ed25519.publickey(_seed("owner-b")).hex())
        h.r.declare_namespace(
            "carol", ed25519.publickey(_seed("owner-carol")).hex())
        h.r.reconcile(h.candidate(), [], {}, 1000)
        grant = h.r.grant_sharing("agent-a", "agent-b", 900, 2000,
                                  h.owner_seed)
        with self.assertRaises(mr.MemoryReconcileError) as cm:
            h.r.recall({"namespace": "agent-a", "key": "k"}, "carol",
                       1500, grant=grant)
        self.assertEqual(cm.exception.code, mr.RC_UNAUTH_NS)


if __name__ == "__main__":
    unittest.main()
