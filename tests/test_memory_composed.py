"""Unit tests for gov.memory_composed (wave-300 lane 3).

Contracts pinned here:
- every coded refusal carries a machine ``code`` (F351);
- gov.ed25519.verify is bool-returning: assert ``is True`` / ``is False``,
  never truthiness (wave-243 lesson);
- the composer adapts the two modules without changing their semantics.
"""

import hashlib
import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519
from gov import memory_reconcile as mr
from gov import memory_store as ms
from gov import memory_composed as mc
from gov.memory_composed import MemoryComposer, MemoryComposedError


def _seed(tag):
    return hashlib.sha256(b"w300-unit:" + tag.encode()).digest()


def _provenance(**kw):
    base = {"source_principal": "agent-a", "reliability": "C3",
            "corroborations": 0, "ingested_at": 1000}
    base.update(kw)
    return base


def _candidate(owner_seed, key="user-preference-theme", value="dark",
               op="add", supersedes=None, provenance=None,
               namespace="agent-a", written_at=1000, expires_at=None):
    vd = hashlib.sha256(value.encode()).hexdigest()
    cand = {"schema": "memory-record/v1", "namespace": namespace,
            "key": key, "value_digest": vd, "written_at": written_at,
            "supersedes": supersedes,
            "provenance": provenance or _provenance(),
            "expires_at": expires_at, "op": op}
    body = {k: cand[k] for k in
            ("schema", "namespace", "key", "value_digest", "written_at",
             "supersedes", "provenance", "expires_at", "op")}
    cand["signature"] = ed25519.sign(
        owner_seed, json.dumps(body, sort_keys=True,
                               separators=(",", ":"),
                               ensure_ascii=True).encode()).hex()
    return cand


def _setup():
    r = mr.MemoryReconciler(_seed("reconciler"), "recon-1",
                            max_writes_per_principal=10000,
                            write_window_seconds=3600)
    owner_seed = _seed("owner-a")
    r.declare_namespace("agent-a",
                        ed25519.publickey(owner_seed).hex())
    store = ms.MemoryStore()
    comp = MemoryComposer(r, {"agent-a": owner_seed})
    comp.bind_store("agent-a", store)
    return r, comp, owner_seed, store


class MemoryComposedContractTests(unittest.TestCase):
    def test_add_recall_roundtrip(self):
        r, comp, owner_seed, store = _setup()
        out = comp.composed_write("agent-a", _candidate(owner_seed),
                                  store, {}, 1000)
        self.assertEqual(out["decision"]["decision"], "ADD")
        self.assertEqual(out["generation"], 0)
        view = comp.composed_recall(
            "agent-a",
            {"namespace": "agent-a", "key": "user-preference-theme"},
            "agent-a", 1001)
        self.assertEqual(view["value_digest"],
                         hashlib.sha256(b"dark").hexdigest())
        self.assertEqual(view["reliability_grade"], "C3")

    def test_fact_id_is_reconcile_derivation(self):
        r, comp, owner_seed, store = _setup()
        cand = _candidate(owner_seed, written_at=1000)
        out = comp.composed_write("agent-a", cand, store, {}, 1000)
        body = {"namespace": "agent-a", "key": "user-preference-theme",
                "value_digest": cand["value_digest"], "written_at": 1000,
                "supersedes": None}
        want = hashlib.sha256(json.dumps(
            body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode()).hexdigest()
        self.assertEqual(out["decision"]["fact_id"], want)

    def test_undelcared_namespace_write_refused_coded(self):
        r, comp, owner_seed, store = _setup()
        with self.assertRaises(Exception) as ctx:
            comp.composed_write(
                "agent-b", _candidate(owner_seed, namespace="agent-b"),
                store, {}, 1000)
        self.assertEqual(ctx.exception.code,
                         "memory-reconcile-unauthorized-namespace")

    def test_key_too_long_refused_coded(self):
        r, comp, owner_seed, store = _setup()
        with self.assertRaises(MemoryComposedError) as ctx:
            comp.composed_write("agent-a",
                                _candidate(owner_seed, key="k" * 100),
                                store, {}, 1000)
        self.assertEqual(ctx.exception.code, mc.MC_KEY_TOO_LONG)
        self.assertEqual(ctx.exception.code, "memory-composed-key-too-long")

    def test_tombstone_then_readmit(self):
        r, comp, owner_seed, store = _setup()
        d1 = comp.composed_write(
            "agent-a", _candidate(owner_seed, value="v1"), store, {},
            1000)["decision"]
        comp.composed_write(
            "agent-a", _candidate(owner_seed, value="v1", op="delete",
                                  supersedes=d1["fact_id"],
                                  written_at=1001),
            store, {}, 1001)
        with self.assertRaises(Exception) as ctx:
            comp.composed_recall(
                "agent-a",
                {"namespace": "agent-a", "key": "user-preference-theme"},
                "agent-a", 1002)
        self.assertEqual(ctx.exception.code, "memory-reconcile-invalid")
        out = comp.composed_write(
            "agent-a", _candidate(owner_seed, value="v2", written_at=1003),
            store, {}, 1003)
        self.assertEqual(out["generation"], 1)
        view = comp.composed_recall(
            "agent-a",
            {"namespace": "agent-a", "key": "user-preference-theme"},
            "agent-a", 1004)
        self.assertEqual(view["value_digest"],
                         hashlib.sha256(b"v2").hexdigest())

    def test_grade_closed_vocabulary(self):
        r, comp, owner_seed, store = _setup()
        for token, letter, num in (("A1", "A", 1), ("D4", "D", 4),
                                   ("C3", "C", 3)):
            # fresh setup per token to keep keys unique
            r2, c2, os2, st2 = _setup()
            c2.composed_write(
                "agent-a",
                _candidate(os2, key="k-" + token.lower(),
                           provenance=_provenance(reliability=token)),
                st2, {}, 1000)
            view = c2.composed_recall(
                "agent-a", {"namespace": "agent-a",
                            "key": "k-" + token.lower()},
                "agent-a", 1001)
            self.assertEqual(view["reliability_grade"], token)
        with self.assertRaises(Exception) as ctx:
            comp.composed_write(
                "agent-a",
                _candidate(owner_seed, key="bad",
                           provenance=_provenance(reliability="Z9")),
                store, {}, 1000)
        self.assertEqual(ctx.exception.code, "memory-reconcile-invalid")

    def test_temporal_mapping_and_store_authority(self):
        r, comp, owner_seed, store = _setup()
        comp.composed_write(
            "agent-a",
            _candidate(owner_seed, written_at=100, expires_at=200),
            store, {}, 100)
        view = comp.composed_recall(
            "agent-a",
            {"namespace": "agent-a", "key": "user-preference-theme"},
            "agent-a", 150)
        self.assertEqual(view["valid_at"], 100)
        self.assertEqual(view["created_at"], 100)
        self.assertEqual(view["retain_until"], 200)
        with self.assertRaises(Exception) as ctx:
            comp.composed_recall(
                "agent-a",
                {"namespace": "agent-a", "key": "user-preference-theme"},
                "agent-a", 50)
        self.assertEqual(ctx.exception.code, "memory-store-expired")
        with self.assertRaises(Exception) as ctx:
            comp.composed_recall(
                "agent-a",
                {"namespace": "agent-a", "key": "user-preference-theme"},
                "agent-a", 250)
        self.assertEqual(ctx.exception.code,
                         "memory-store-retention-lapsed")

    def test_divergent_store_refused(self):
        r, comp, owner_seed, store = _setup()
        comp.composed_write("agent-a", _candidate(owner_seed), store,
                            {}, 1000)
        other = ms.MemoryStore()
        with self.assertRaises(MemoryComposedError) as ctx:
            comp.composed_write(
                "agent-a", _candidate(owner_seed, value="x",
                                      written_at=1001),
                other, {}, 1001)
        self.assertEqual(ctx.exception.code, "memory-composed-divergent")

    def test_key_grammar_narrowed_fail_closed(self):
        r, comp, owner_seed, store = _setup()
        with self.assertRaises(MemoryComposedError) as ctx:
            comp.composed_write(
                "agent-a",
                _candidate(owner_seed, key="user/preference/theme"),
                store, {}, 1000)
        self.assertEqual(ctx.exception.code, mc.MC_KEY_INVALID)
        # No wedge: the reconciler inventory was not advanced.
        out = comp.composed_write(
            "agent-a", _candidate(owner_seed, key="ok-key"), store, {},
            1000)
        self.assertEqual(out["decision"]["decision"], "ADD")

    def test_ed25519_contract_is_true_is_false(self):
        # wave-243 lesson: verify() is bool-returning, never raises.
        seed = _seed("contract")
        msg = b"contract probe"
        sig = ed25519.sign(seed, msg)
        self.assertIs(ed25519.verify(
            ed25519.publickey(seed), msg, sig), True)
        bad = bytearray(sig)
        bad[0] ^= 0x01
        self.assertIs(ed25519.verify(
            ed25519.publickey(seed), msg, bytes(bad)), False)


if __name__ == "__main__":
    unittest.main()
