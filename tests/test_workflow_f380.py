"""Unit tests for the F380 closure (wave-303 lane 1).

F380 (MEDIUM, filed 2026-10-03 by the wave-302 independent red team):
``gov/workflow.py`` treated the revocation ledger as optional in
``_verify_authority``, and the completed-step replay path in
``run_step`` returned recorded outputs before ``_verify_authority`` --
so ``replay()`` performed no authority check at all.

The closure: the ledger is REQUIRED on every verification (fail
closed, coded ``workflow-authority-revoked`` -- the F378 precedent);
``run_step`` re-proves authority on every entry, before the
completed-step replay paths; ``sleep_step``/``recv_step`` completed
paths do the same (same defect class).

The break-first battery is evals/w303_f380_probes.py; these tests pin
the contract at the unit level.
"""

import hashlib
import unittest

from gov import delegation as dg
from gov import delegation_revocation as drv
from gov import ed25519
from gov import workflow as wf

AT = 1_700_000_000


class F380ClosureFixture(unittest.TestCase):
    def setUp(self):
        self.sa = hashlib.sha256(b"w303f380-a").digest()
        self.sb = hashlib.sha256(b"w303f380-b").digest()
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

    # -- the ledger is required on every verification -----------------

    def test_start_run_without_ledger_refuses(self):
        self.assertEqual(
            self._code_of(self.store.start_run, "etl", run_id="r1",
                          authority=self._auth(ledger=None), at=AT),
            "workflow-authority-revoked")

    def test_run_step_without_ledger_refuses(self):
        self.store.start_run("etl", run_id="r2",
                             authority=self._auth(), at=AT)
        self.assertEqual(
            self._code_of(self.store.run_step, "r2", 0, "s0",
                          lambda i: {"ok": 1},
                          authority=self._auth(ledger=None), at=AT + 10),
            "workflow-authority-revoked")

    def test_revoked_chain_without_ledger_refuses(self):
        # The original F380 break: omitting the ledger let a REVOKED
        # chain authorize. Now it fails closed.
        self._revoked()
        self.store.start_run("etl", run_id="r3",
                             authority=self._auth(), at=AT)
        self.assertEqual(
            self._code_of(self.store.run_step, "r3", 0, "s0",
                          lambda i: {"ok": 1},
                          authority=self._auth(ledger=None), at=AT + 10),
            "workflow-authority-revoked")

    def test_revoked_chain_with_ledger_refuses(self):
        ledger = self._revoked()
        self.store.start_run("etl", run_id="r4",
                             authority=self._auth(), at=AT)
        self.assertEqual(
            self._code_of(self.store.run_step, "r4", 0, "s0",
                          lambda i: {"ok": 1},
                          authority=self._auth(ledger=ledger), at=AT + 10),
            "workflow-authority-revoked")

    def test_notify_without_ledger_refuses(self):
        self.store.start_run("etl", run_id="r5",
                             authority=self._auth(), at=AT)
        self.assertEqual(
            self._code_of(self.store.notify, "r5", "ev", {"k": 1},
                          authority=self._auth(ledger=None), at=AT + 10),
            "workflow-authority-revoked")

    def test_complete_run_without_ledger_refuses(self):
        self.store.start_run("etl", run_id="r6",
                             authority=self._auth(), at=AT)
        self.assertEqual(
            self._code_of(self.store.complete_run, "r6",
                          authority=self._auth(ledger=None), at=AT + 10),
            "workflow-authority-revoked")

    # -- replay paths re-verify authority ------------------------------

    def test_replay_reverifies_revoked_chain(self):
        self._revoked()
        auth = self._auth()
        self.store.start_run("etl", run_id="r7", authority=auth, at=AT)
        self.store.run_step("r7", 0, "s0", lambda i: {"v": 1},
                            authority=auth, at=AT)
        self.assertEqual(
            self._code_of(self.store.replay, "r7",
                          [{"seq": 0, "name": "s0",
                            "fn": lambda i: {"evil": 1}, "inputs": {}}],
                          authority=self._auth(ledger=None), at=AT + 10),
            "workflow-authority-revoked")

    def test_replay_enforces_actor_binding(self):
        auth = self._auth()
        self.store.start_run("etl", run_id="r8", authority=auth, at=AT)
        self.store.run_step("r8", 0, "s0", lambda i: {"secret": "A"},
                            authority=auth, at=AT)
        garbage = {"actor_id": "mallory", "action": "tool.invoke",
                   "chain": [], "trust_roots": [],
                   "revocation_ledger": self._ledger()}
        self.assertEqual(
            self._code_of(self.store.replay, "r8",
                          [{"seq": 0, "name": "s0",
                            "fn": lambda i: {"evil": 1}, "inputs": {}}],
                          authority=garbage, at=AT + 10),
            "workflow-step-unauthorized")

    def test_sleep_completed_path_reverifies(self):
        auth = self._auth()
        self.store.start_run("etl", run_id="r9", authority=auth, at=AT)
        self.store.sleep_step("r9", 0, "wait", wake_at=AT,
                              authority=auth, at=AT)
        self.assertEqual(
            self._code_of(self.store.sleep_step, "r9", 0, "wait",
                          wake_at=AT,
                          authority=self._auth(ledger=None), at=AT + 10),
            "workflow-authority-revoked")

    def test_recv_completed_path_reverifies(self):
        auth = self._auth()
        self.store.start_run("etl", run_id="r10", authority=auth, at=AT)
        self.store.notify("r10", "ev", {"p": 1}, authority=auth, at=AT)
        self.store.recv_step("r10", 0, "w", "ev", authority=auth, at=AT)
        self.assertEqual(
            self._code_of(self.store.recv_step, "r10", 0, "w", "ev",
                          authority=self._auth(ledger=None), at=AT + 10),
            "workflow-authority-revoked")

    # -- honest path unaffected ---------------------------------------

    def test_honest_execute_replay_resume(self):
        auth = self._auth()
        self.store.start_run("etl", run_id="r11", authority=auth, at=AT)
        out, replayed = self.store.run_step(
            "r11", 0, "s0", lambda i: {"ok": 1}, authority=auth, at=AT)
        self.assertEqual(out, {"ok": 1})
        self.assertFalse(replayed)
        out2, replayed2 = self.store.run_step(
            "r11", 0, "s0", lambda i: {"evil": 2}, authority=auth,
            at=AT + 10)
        self.assertEqual(out2, {"ok": 1})
        self.assertTrue(replayed2)
        res = self.store.replay(
            "r11", [{"seq": 0, "name": "s0", "fn": lambda i: {"e": 3},
                     "inputs": {}}], authority=auth, at=AT + 20)
        self.assertEqual(res[0][4], {"ok": 1})
        self.assertTrue(res[0][3])

    def test_ed25519_contract_pinned(self):
        msg = b"workflow-f380-authority"
        sig = ed25519.sign(self.sa, msg)
        self.assertIs(ed25519.verify(bytes.fromhex(self.pa), msg, sig),
                      True)
        bad = bytearray(sig)
        bad[0] ^= 1
        self.assertIs(ed25519.verify(bytes.fromhex(self.pa), msg,
                                     bytes(bad)), False)


if __name__ == "__main__":
    unittest.main()
