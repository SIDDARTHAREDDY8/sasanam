"""Unit tests: F382/F383 closures in gov/workflow.py (wave-303 lane 3).

F382: WorkflowStore._load() populates in-memory indexes without
re-appending to the journal file -- reload is a fixed point.
F383: the step-level idempotency-key replay path applies the same
name/inputs-digest drift checks as the seq-slot path, refusing
workflow-step-unauthorized on mismatch; no new decision codes were
needed (pin stays 1820).

Every coded refusal is asserted by code. These tests are the red-first
closure pins; break-first behavior was confirmed on the pristine
wave-302 base (reload doubled the journal; key path replayed stale
outputs) before the fix.
"""

import hashlib
import os
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import delegation as dg
from gov import delegation_revocation as drv
from gov import ed25519
from gov import workflow as wf


def _seed(tag):
    return hashlib.sha256(("w303-f382f383-" + tag).encode()).digest()


class F382F383Base(unittest.TestCase):
    def setUp(self):
        self.seed_a = _seed("a")
        self.seed_b = _seed("b")
        self.pub_a = ed25519.publickey(self.seed_a).hex()
        self.pub_b = ed25519.publickey(self.seed_b).hex()
        self.at = 1_700_000_000
        self.tmp = tempfile.mkdtemp(prefix="wf-f382f383-")

    def tearDown(self):
        for f in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, f))
        os.rmdir(self.tmp)

    def _chain(self, delegatee="agent-b"):
        cons = {"expires_at": self.at + 3600, "max_depth": 4,
                "allowed_targets": [delegatee]}
        return dg.issue(self.seed_a, "agent-a", delegatee, self.pub_b,
                        ["tool.invoke"], issued_at=self.at,
                        constraints=cons)

    def _auth(self, chain=None, actor="agent-b"):
        return {"actor_id": actor, "action": "tool.invoke",
                "chain": [chain] if chain is None else chain,
                "trust_roots": [self.pub_a],
                "revocation_ledger": drv.DelegationRevoker(
                    self.seed_a, "agent-a")}

    def _code_of(self, fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 -- probe harness
            self.assertIsNotNone(getattr(e, "code", None),
                                 "refusal without code: %r" % (e,))
            return e.code
        self.fail("expected coded refusal, call succeeded")

    def _path(self, name="wf.jsonl"):
        return os.path.join(self.tmp, name)

    def _line_count(self, path):
        with open(path, encoding="utf-8") as fh:
            return len(fh.read().splitlines())


class F382JournalFixedPointTests(F382F383Base):
    def _seeded_store(self, path):
        auth = self._auth([self._chain()])
        store = wf.WorkflowStore(path=path)
        store.start_run("etl", run_id="j1", authority=auth, at=self.at)
        store.run_step("j1", 0, "s0", lambda i: {"x": 1},
                       authority=auth, at=self.at)
        return store

    def test_reload_does_not_grow_journal(self):
        path = self._path()
        self._seeded_store(path)
        n1 = self._line_count(path)
        wf.WorkflowStore(path=path)
        self.assertEqual(self._line_count(path), n1)

    def test_repeated_reloads_are_fixed_point(self):
        path = self._path()
        self._seeded_store(path)
        n1 = self._line_count(path)
        for _ in range(3):
            wf.WorkflowStore(path=path)
        self.assertEqual(self._line_count(path), n1)

    def test_load_rebuilds_indexes(self):
        path = self._path()
        live = self._seeded_store(path)
        loaded = wf.WorkflowStore(path=path)
        self.assertEqual(live._steps.keys(), loaded._steps.keys())
        self.assertEqual(live._run_idem, loaded._run_idem)
        self.assertEqual(live._step_idem, loaded._step_idem)
        self.assertEqual(live._run_status, loaded._run_status)

    def test_loaded_store_replays_and_resumes(self):
        path = self._path()
        self._seeded_store(path)
        auth = self._auth([self._chain()])
        loaded = wf.WorkflowStore(path=path)
        out, replayed = loaded.run_step(
            "j1", 0, "s0", lambda i: {"x": 999},
            authority=auth, at=self.at)
        self.assertEqual((out, replayed), ({"x": 1}, True))
        out2, replayed2 = loaded.run_step(
            "j1", 1, "s1", lambda i: {"x": 2},
            authority=auth, at=self.at)
        self.assertEqual((out2, replayed2), ({"x": 2}, False))
        # replay wrote nothing; the new step appended exactly one record
        self.assertEqual(self._line_count(path), 3)

    def test_tampered_record_refuses_on_load(self):
        path = self._path()
        self._seeded_store(path)
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        lines[0] = lines[0][:-2] + "ff"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        self.assertEqual(
            self._code_of(wf.WorkflowStore, path=path),
            "workflow-checkpoint-tampered")

    def test_crash_tear_tolerated(self):
        path = self._path()
        self._seeded_store(path)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write('{"type": "step", "half-writ')
        loaded = wf.WorkflowStore(path=path)
        self.assertEqual(loaded.run_status("j1"), "running")
        # two complete records + the unreadable tear; a second load
        # must not change the file (fixed point still holds).
        self.assertEqual(self._line_count(path), 3)
        wf.WorkflowStore(path=path)
        self.assertEqual(self._line_count(path), 3)


class F383KeyPathDriftTests(F382F383Base):
    def setUp(self):
        super().setUp()
        self.auth = self._auth([self._chain()])
        self.store = wf.WorkflowStore()

    def _completed(self, run_id="k1", seq=0, name="step-a",
                   inputs=None, key="K"):
        self.store.start_run("etl", run_id=run_id, authority=self.auth,
                             at=self.at)
        return self.store.run_step(
            run_id, seq, name, lambda i: {"v": "A"},
            inputs=inputs if inputs is not None else {"in": 1},
            idempotency_key=key, authority=self.auth, at=self.at)

    def test_key_hit_same_name_inputs_replays(self):
        self._completed()
        out, replayed = self.store.run_step(
            "k1", 7, "step-a", lambda i: {"v": "B"},
            inputs={"in": 1}, idempotency_key="K",
            authority=self.auth, at=self.at)
        self.assertEqual((out, replayed), ({"v": "A"}, True))

    def test_key_hit_different_name_refuses(self):
        self._completed()
        self.assertEqual(
            self._code_of(
                self.store.run_step, "k1", 5, "step-B-DIFFERENT",
                lambda i: {"v": "B"}, inputs={"in": 1},
                idempotency_key="K", authority=self.auth, at=self.at),
            "workflow-step-unauthorized")

    def test_key_hit_different_inputs_refuses(self):
        self._completed()
        self.assertEqual(
            self._code_of(
                self.store.run_step, "k1", 5, "step-a",
                lambda i: {"v": "B"}, inputs={"in": 999},
                idempotency_key="K", authority=self.auth, at=self.at),
            "workflow-step-unauthorized")

    def test_key_hit_both_drift_refuses(self):
        self._completed()
        self.assertEqual(
            self._code_of(
                self.store.run_step, "k1", 5, "step-B-DIFFERENT",
                lambda i: {"v": "B"}, inputs={"in": 999},
                idempotency_key="K", authority=self.auth, at=self.at),
            "workflow-step-unauthorized")

    def test_refusal_is_sticky(self):
        # A refused drift attempt does not consume or corrupt the
        # binding: a later correct replay still returns the record.
        self._completed()
        self._code_of(
            self.store.run_step, "k1", 5, "step-B-DIFFERENT",
            lambda i: {"v": "B"}, inputs={"in": 999},
            idempotency_key="K", authority=self.auth, at=self.at)
        out, replayed = self.store.run_step(
            "k1", 7, "step-a", lambda i: {"v": "B"},
            inputs={"in": 1}, idempotency_key="K",
            authority=self.auth, at=self.at)
        self.assertEqual((out, replayed), ({"v": "A"}, True))

    def test_seq_slot_drift_still_refuses(self):
        self._completed(run_id="k2", key=None)
        self.assertEqual(
            self._code_of(
                self.store.run_step, "k2", 0, "step-a",
                lambda i: {"v": "B"}, inputs={"in": 999},
                authority=self.auth, at=self.at),
            "workflow-step-unauthorized")

    def test_unknown_key_executes(self):
        self._completed()
        out, replayed = self.store.run_step(
            "k1", 3, "step-c", lambda i: {"v": "C"},
            inputs={"in": 3}, idempotency_key="FRESH",
            authority=self.auth, at=self.at)
        self.assertEqual((out, replayed), ({"v": "C"}, False))


if __name__ == "__main__":
    unittest.main()
