"""Unit tests for the F387 closure (wave-305 lane A).

F387 (LOW, filed 2026-10-03 by the wave-304 independent red team):
``gov/workflow.py::recv_step``/``sleep_step`` completed paths skip the
inputs-drift refusal ``run_step`` enforces. Both record an
``inputs_digest`` (``{"event": event}`` / ``{"wake_at": wake_at}``) yet
the completed-path replay checks only ``rec["name"] != name``:
- a slot completed for event "settled" replayed
  ``({"amount": 100}, True)`` for a "refunded" subscription;
- a slot completed with ``wake_at=T1`` returned ``(True, True)`` for
  ``wake_at=T2``.

The closure: the completed paths apply the same name AND inputs-digest
drift checks as ``run_step``'s sequence-slot path, refusing coded
``workflow-step-unauthorized`` (F383 defect class). The module docstring
already promises drift refusal "for an already-completed step slot".

The break-first battery is evals/w303_f387_probes.py; these tests pin
the contract at the unit level.
"""

import hashlib
import unittest

from gov import delegation as dg
from gov import delegation_revocation as drv
from gov import ed25519
from gov import workflow as wf

AT = 1_700_000_000


class F387ClosureFixture(unittest.TestCase):
    def setUp(self):
        self.sa = hashlib.sha256(b"w305f387-a").digest()
        self.sb = hashlib.sha256(b"w305f387-b").digest()
        self.pa = ed25519.publickey(self.sa).hex()
        self.pb = ed25519.publickey(self.sb).hex()
        cons = {"expires_at": AT + 3600, "max_depth": 4,
                "allowed_targets": ["agent-b"]}
        self.root = dg.issue(self.sa, "agent-a", "agent-b", self.pb,
                             ("tool.invoke",), issued_at=AT,
                             constraints=dict(cons))
        self.chain = [self.root]
        self.store = wf.WorkflowStore()

    def _ledger(self):
        return drv.DelegationRevoker(self.sa, "agent-a")

    def _auth(self, ledger="default", actor="agent-b"):
        d = {"actor_id": actor, "action": "tool.invoke",
             "chain": self.chain, "trust_roots": [self.pa]}
        if ledger == "default":
            d["revocation_ledger"] = self._ledger()
        elif ledger is not None:
            d["revocation_ledger"] = ledger
        return d

    def _revoked(self):
        ledger = self._ledger()
        ledger.revoke(self.root["receipt_id"], AT + 5)
        return ledger

    def _code_of(self, fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 -- probe harness
            self.assertIsNotNone(getattr(e, "code", None),
                                 "refusal without code: %r" % (e,))
            return e.code
        return None

    # -- recv_step: event drift refuses -------------------------------

    def _recv_completed(self, run_id="r1", seq=1, name="wait",
                        event="settled", payload=None):
        payload = {"amount": 100} if payload is None else payload
        self.store.start_run("wf", run_id=run_id,
                             authority=self._auth(), at=AT)
        self.store.notify(run_id, event, payload,
                          authority=self._auth(), at=AT)
        out, replayed = self.store.recv_step(
            run_id, seq, name, event, authority=self._auth(), at=AT)
        self.assertEqual((out, replayed), (payload, False))
        return payload

    def test_recv_event_drift_refuses_coded(self):
        self._recv_completed()
        code = self._code_of(
            self.store.recv_step, "r1", 1, "wait", "refunded",
            authority=self._auth(), at=AT + 5)
        self.assertEqual(code, "workflow-step-unauthorized")

    def test_recv_same_event_still_replays(self):
        self._recv_completed()
        out, replayed = self.store.recv_step(
            "r1", 1, "wait", "settled", authority=self._auth(),
            at=AT + 5)
        self.assertEqual((out, replayed), ({"amount": 100}, True))

    def test_recv_name_drift_still_refuses(self):
        self._recv_completed()
        code = self._code_of(
            self.store.recv_step, "r1", 1, "other-name", "settled",
            authority=self._auth(), at=AT + 5)
        self.assertEqual(code, "workflow-step-unauthorized")

    def test_recv_timeout_output_still_replays(self):
        # A slot completed via the timeout path has inputs_digest over
        # {"event": event}; the same event still replays the timeout
        # output, a different event still refuses.
        self.store.start_run("wf", run_id="r2",
                             authority=self._auth(), at=AT)
        out, replayed = self.store.recv_step(
            "r2", 1, "wait", "never-arrives", authority=self._auth(),
            at=AT, now=AT + 50, timeout_at=AT + 10)
        self.assertEqual((out, replayed), ({"timeout": True}, False))
        out2, rep2 = self.store.recv_step(
            "r2", 1, "wait", "never-arrives", authority=self._auth(),
            at=AT + 5)
        self.assertEqual((out2, rep2), ({"timeout": True}, True))
        code = self._code_of(
            self.store.recv_step, "r2", 1, "wait", "other-event",
            authority=self._auth(), at=AT + 6)
        self.assertEqual(code, "workflow-step-unauthorized")

    # -- sleep_step: wake_at drift refuses ------------------------------

    def _sleep_completed(self, run_id="r3", seq=1, name="nap",
                         wake_at=AT + 100, now=AT + 200):
        self.store.start_run("wf", run_id=run_id,
                             authority=self._auth(), at=AT)
        awake, replayed = self.store.sleep_step(
            run_id, seq, name, wake_at, authority=self._auth(),
            at=AT, now=now)
        self.assertEqual((awake, replayed), (True, False))

    def test_sleep_wakeat_drift_refuses_coded(self):
        self._sleep_completed()
        code = self._code_of(
            self.store.sleep_step, "r3", 1, "nap", AT + 999999,
            authority=self._auth(), at=AT + 5, now=AT + 200)
        self.assertEqual(code, "workflow-step-unauthorized")

    def test_sleep_same_wakeat_still_replays(self):
        self._sleep_completed()
        awake, replayed = self.store.sleep_step(
            "r3", 1, "nap", AT + 100, authority=self._auth(),
            at=AT + 5, now=AT + 200)
        self.assertEqual((awake, replayed), (True, True))

    def test_sleep_name_drift_still_refuses(self):
        self._sleep_completed()
        code = self._code_of(
            self.store.sleep_step, "r3", 1, "other-name", AT + 100,
            authority=self._auth(), at=AT + 5, now=AT + 200)
        self.assertEqual(code, "workflow-step-unauthorized")

    # -- ordering: authority re-proof (F380) stays first -----------------

    def test_authority_reproof_before_drift_check(self):
        # A revoked ledger must refuse coded workflow-authority-revoked
        # even when the inputs also drift -- authority is re-proved
        # before the completed-path replay checks run.
        self._recv_completed()
        code = self._code_of(
            self.store.recv_step, "r1", 1, "wait", "refunded",
            authority=self._auth(ledger=self._revoked()), at=AT + 5)
        self.assertEqual(code, "workflow-authority-revoked")


if __name__ == "__main__":
    unittest.main()
