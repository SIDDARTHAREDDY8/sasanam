"""Unit tests for gov/workflow_approval.py: approval-gated workflow steps.

Every coded refusal is asserted by code (F351 contract); the ed25519
True/False contract is pinned on the paths this module touches
(delegation_approval's own tests pin the signature path); the two new
decision codes are pinned as raw source literals.
"""

import hashlib
import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import approval_request as ar
from gov import delegation as dg
from gov import delegation_approval as da
from gov import delegation_revocation as rv
from gov import ed25519
from gov import workflow as wf
from gov import workflow_approval as wa


def _seed(tag):
    return hashlib.sha256(("w302wa-" + tag).encode()).digest()


AT = 1_700_000_000


class GatedStepFixture(unittest.TestCase):
    def setUp(self):
        self.sa, self.sb, self.sc = _seed("a"), _seed("b"), _seed("c")
        self.pa = ed25519.publickey(self.sa).hex()
        self.pb = ed25519.publickey(self.sb).hex()
        self.pc = ed25519.publickey(self.sc).hex()
        self.trust_roots = [self.pa]
        cons = {"expires_at": AT + 3600, "max_depth": 4,
                "allowed_targets": ["agent-b"]}
        self.root = dg.issue(self.sa, "agent-a", "agent-b", self.pb,
                             ("tool.invoke",), issued_at=AT,
                             constraints=dict(cons))
        self.chain = [self.root]

    def _authority(self, chain=None, actor="agent-b", revoker=None):
        # F380 closure re-pin: the workflow store requires a revocation
        # ledger on every authority verification (fail closed when
        # absent). Mint a fresh (empty) revoker when the caller passes
        # none.
        if revoker is None:
            revoker = rv.DelegationRevoker(self.sa, "agent-a")
        return {"actor_id": actor, "action": "tool.invoke",
                "chain": chain or self.chain,
                "trust_roots": self.trust_roots,
                "revocation_ledger": revoker}

    def _store(self, run_id="run1", authority=None):
        store = wf.WorkflowStore()
        store.start_run("wf", run_id=run_id,
                        authority=authority or self._authority(), at=AT)
        return store

    def _pkg(self, run_id="run1", seq=0, name="step0", inputs=None,
             issued_at=AT, ttl=3600, chain=None, rid="agent-b", seed=None):
        seed = seed or (self.sb if rid == "agent-b" else self.sc)
        return wa.request_approval(
            chain=chain or self.chain, delegation_right="tool.invoke",
            run_id=run_id, seq=seq, name=name,
            inputs={"x": 1} if inputs is None else inputs,
            requester_agent_id=rid,
            requester_principal="principal-" + rid,
            requester_pubkey_hex=ed25519.publickey(seed).hex(),
            requester_seed=seed, approver_schema=[],
            ttl_seconds=ttl, issued_at=issued_at)

    def _runner(self, store, revoker=None):
        return wa.ApprovalGatedWorkflow(store, trust_roots=self.trust_roots,
                                        revoker=revoker)

    def _code_of(self, fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001
            self.assertIsNotNone(getattr(e, "code", None),
                                 "refusal without code: %r" % (e,))
            return e.code
        self.fail("expected coded refusal, call succeeded")

    # -- request ----------------------------------------------------------

    def test_request_binds_step_digest(self):
        pkg = self._pkg()
        ctx = pkg["envelope"]["request"]["context_digests"]
        self.assertEqual(ctx["workflow_step_digest"],
                         wa.step_digest_for("run1", 0, "step0", {"x": 1}))
        # The delegation bindings ride along (digests, never raw chains).
        for k in ("delegation_chain_digest", "delegator_id_digest",
                  "delegation_right_digest"):
            self.assertEqual(len(ctx[k]), 64)

    def test_request_action_binds_step(self):
        pkg = self._pkg()
        body = pkg["envelope"]["request"]
        args = {"run_id": "run1", "seq": 0, "name": "step0",
                "input_digest": wa.input_digest_for({"x": 1})}
        self.assertEqual(body["action_digest"],
                         ar.action_digest_for({"tool": "workflow.step",
                                               "args": args}))

    def test_request_refuses_non_dict_inputs(self):
        self.assertEqual(
            self._code_of(wa.request_approval, chain=self.chain,
                          delegation_right="tool.invoke",
                          run_id="run1", seq=0, name="step0",
                          inputs=[1, 2],
                          requester_agent_id="agent-b",
                          requester_principal="principal-agent-b",
                          requester_pubkey_hex=self.pb,
                          requester_seed=self.sb, approver_schema=[],
                          ttl_seconds=3600, issued_at=AT),
            "workflow-approval-binding-invalid")

    def test_request_refuses_reserved_key(self):
        self.assertEqual(
            self._code_of(wa.request_approval, chain=self.chain,
                          delegation_right="tool.invoke",
                          run_id="run1", seq=0, name="step0",
                          inputs={"x": 1, "_gated_step": "smuggled"},
                          requester_agent_id="agent-b",
                          requester_principal="principal-agent-b",
                          requester_pubkey_hex=self.pb,
                          requester_seed=self.sb, approver_schema=[],
                          ttl_seconds=3600, issued_at=AT),
            "workflow-approval-binding-invalid")

    # -- execution --------------------------------------------------------

    def test_gated_step_executes_and_replays(self):
        store = self._store()
        auth = self._authority()
        pkg = self._pkg()
        r = self._runner(store)
        out = r.run_gated_step("run1", 0, "step0",
                               lambda i: {"y": i["x"] + 1}, {"x": 1},
                               approval_package=pkg, authority=auth, at=AT)
        self.assertEqual(out["outputs"], {"y": 2})
        self.assertFalse(out["replayed"])
        self.assertEqual(len(out["approval_digest"]), 64)
        # fn sees the original inputs, not the augmented binding.
        seen = []
        out2 = r.run_gated_step("run1", 0, "step0",
                                lambda i: seen.append(dict(i)) or {"y": 0},
                                {"x": 1}, approval_package=pkg,
                                authority=auth, at=AT + 5)
        self.assertTrue(out2["replayed"])
        self.assertEqual(out2["outputs"], {"y": 2})
        self.assertEqual(seen, [])

    def test_approval_digest_in_checkpoint_record(self):
        store = self._store()
        auth = self._authority()
        pkg = self._pkg()
        r = self._runner(store)
        out = r.run_gated_step("run1", 0, "step0", lambda i: {"y": 1},
                               {"x": 1}, approval_package=pkg,
                               authority=auth, at=AT)
        step = store.get_step("run1", 0)
        aug = {"x": 1, "_gated_step":
               {"step_digest": out["step_digest"],
                "approval_digest": out["approval_digest"]}}
        want = hashlib.sha256(json.dumps(
            aug, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(step["inputs_digest"], want)

    def test_wrong_step_digests_refuse(self):
        store = self._store()
        auth = self._authority()
        pkg = self._pkg(inputs={"x": 1})
        r = self._runner(store)
        self.assertEqual(
            self._code_of(r.run_gated_step, "run1", 0, "step0",
                          lambda i: {"y": 1}, {"x": 2},
                          approval_package=pkg, authority=auth, at=AT),
            "workflow-approval-digest-mismatch")

    def test_cross_step_replay_refuses(self):
        store = self._store()
        auth = self._authority()
        pkg = self._pkg(seq=0)
        r = self._runner(store)
        self.assertEqual(
            self._code_of(r.run_gated_step, "run1", 1, "step1",
                          lambda i: {"y": 1}, {"x": 1},
                          approval_package=pkg, authority=auth, at=AT),
            "workflow-approval-digest-mismatch")

    def test_non_gated_approval_refuses(self):
        store = self._store()
        auth = self._authority()
        pkg = da.issue_delegated_request(
            chain=self.chain, delegation_right="tool.invoke",
            action={"tool": "shell", "args": {"cmd": "ls"}},
            requester_agent_id="agent-b",
            requester_principal="principal-agent-b",
            requester_pubkey_hex=self.pb, requester_seed=self.sb,
            approver_schema=[], ttl_seconds=3600, issued_at=AT)
        r = self._runner(store)
        self.assertEqual(
            self._code_of(r.run_gated_step, "run1", 0, "step0",
                          lambda i: {"y": 1}, {"x": 1},
                          approval_package=pkg, authority=auth, at=AT),
            "workflow-approval-digest-mismatch")

    def test_revocation_beats_approval(self):
        store = self._store()
        auth = self._authority()
        pkg = self._pkg()
        revoker = rv.DelegationRevoker(self.sa, "agent-a")
        revoker.revoke(self.root["receipt_id"], AT + 5)
        r = self._runner(store, revoker=revoker)
        self.assertEqual(
            self._code_of(r.run_gated_step, "run1", 0, "step0",
                          lambda i: {"y": 1}, {"x": 1},
                          approval_package=pkg, authority=auth, at=AT + 10),
            "delegation-revoked")

    def test_expired_approval_refuses_at_execution(self):
        store = self._store()
        auth = self._authority()
        pkg = self._pkg(issued_at=AT - 3600, ttl=60)
        r = self._runner(store)
        self.assertEqual(
            self._code_of(r.run_gated_step, "run1", 0, "step0",
                          lambda i: {"y": 1}, {"x": 1},
                          approval_package=pkg, authority=auth, at=AT),
            "approval-request-expired")

    def test_requester_must_be_actor(self):
        # Approval requested by agent-b, but the run belongs to agent-c.
        cons = {"expires_at": AT + 3600, "max_depth": 4,
                "allowed_targets": ["agent-c"]}
        root_c = dg.issue(self.sa, "agent-a", "agent-c", self.pc,
                          ("tool.invoke",), issued_at=AT,
                          constraints=dict(cons))
        store = wf.WorkflowStore()
        auth_c = self._authority(chain=[root_c], actor="agent-c")
        store.start_run("wf", run_id="run1", authority=auth_c, at=AT)
        pkg = self._pkg()  # requested by agent-b
        r = self._runner(store)
        self.assertEqual(
            self._code_of(r.run_gated_step, "run1", 0, "step0",
                          lambda i: {"y": 1}, {"x": 1},
                          approval_package=pkg, authority=auth_c, at=AT),
            "workflow-approval-digest-mismatch")

    def test_authority_chain_must_match_approval(self):
        store = self._store()
        auth = self._authority()
        pkg = self._pkg()
        # Same actor, different (wider-rights) chain than approved.
        cons = {"expires_at": AT + 3600, "max_depth": 4,
                "allowed_targets": ["agent-b"]}
        root2 = dg.issue(self.sa, "agent-a", "agent-b", self.pb,
                         ("tool.invoke", "memory.read"), issued_at=AT,
                         constraints=dict(cons))
        auth2 = dict(auth, chain=[root2])
        r = self._runner(store)
        self.assertEqual(
            self._code_of(r.run_gated_step, "run1", 0, "step0",
                          lambda i: {"y": 1}, {"x": 1},
                          approval_package=pkg, authority=auth2, at=AT),
            "workflow-approval-digest-mismatch")

    def test_resume_reverifies_approval(self):
        store = self._store()
        auth = self._authority()
        pkg = self._pkg(ttl=3600)
        r = self._runner(store)
        r.run_gated_step("run1", 0, "step0", lambda i: {"y": i["x"] + 1},
                         {"x": 1}, approval_package=pkg,
                         authority=auth, at=AT)
        r2 = wa.ApprovalGatedWorkflow(store, trust_roots=self.trust_roots)
        out = r2.run_gated_step("run1", 0, "step0", lambda i: {"y": 999},
                                {"x": 1}, approval_package=pkg,
                                authority=auth, at=AT + 100)
        self.assertTrue(out["replayed"])
        self.assertEqual(out["outputs"], {"y": 2})
        # After the approval's time box: refuses, never executes.
        self.assertEqual(
            self._code_of(r2.run_gated_step, "run1", 0, "step0",
                          lambda i: {"y": 1}, {"x": 1},
                          approval_package=pkg, authority=auth, at=AT + 4000),
            "approval-request-expired")

    def test_different_approval_for_recorded_slot_is_drift(self):
        # One step, one approval: a second approval for the same step
        # digests is a different packet digest -> the recorded slot
        # keeps its original binding (definition drift, fail closed).
        store = self._store()
        auth = self._authority()
        pkg1 = self._pkg(issued_at=AT)
        pkg2 = self._pkg(issued_at=AT + 1)
        r = self._runner(store)
        r.run_gated_step("run1", 0, "step0", lambda i: {"y": 1},
                         {"x": 1}, approval_package=pkg1,
                         authority=auth, at=AT)
        self.assertEqual(
            self._code_of(r.run_gated_step, "run1", 0, "step0",
                          lambda i: {"y": 1}, {"x": 1},
                          approval_package=pkg2, authority=auth, at=AT + 2),
            "workflow-step-unauthorized")

    def test_step_digest_helpers(self):
        d1 = wa.step_digest_for("run1", 0, "s", {"x": 1})
        self.assertEqual(len(d1), 64)
        self.assertNotEqual(d1, wa.step_digest_for("run1", 1, "s", {"x": 1}))
        self.assertNotEqual(d1, wa.step_digest_for("run1", 0, "s", {"x": 2}))
        self.assertEqual(wa.input_digest_for({"x": 1}),
                         wa.input_digest_for({"x": 1}))

    def test_new_codes_in_taxonomy(self):
        import re
        with open("gov/decision_codes.py", encoding="utf-8") as fh:
            src = fh.read()
        for code in ("workflow-approval-digest-mismatch",
                     "workflow-approval-binding-invalid"):
            self.assertEqual(len(re.findall(
                r'"code":\s*\'%s\'' % re.escape(code), src)), 1,
                "code literal %r not exactly once" % code)


if __name__ == "__main__":
    unittest.main()
