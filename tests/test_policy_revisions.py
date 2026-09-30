"""Unit tests for gov/policy_revisions.py (wave-229 lane C).

Public-seam tests: the registry, the replay, the evidence seal, and
the additive PolicyDecision stamping. No implementation internals.
"""

import copy
import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import policy_revisions as pr
from gov import policy as policy_mod


POLICY_V1 = """\
version: "1"
policies:
  - id: allow-send
    effect: allow
    match:
      tool: send_email
"""

POLICY_V2 = """\
version: "2"
policies:
  - id: deny-send
    effect: deny
    match:
      tool: send_email
"""

ACTION = {"tool": "send_email", "agent": "agent-1", "role": "member",
          "args": {"to": "bob@example.com"}}
CONTEXT = {"counters": {"send_email": 1}}


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class RegisterTest(unittest.TestCase):
    def test_digest_recomputed_from_bytes(self):
        reg = pr.RevisionRegistry()
        rev = reg.register("policy:1", POLICY_V1.encode("utf-8"))
        self.assertEqual(rev.digest, _digest(POLICY_V1))

    def test_correct_claimed_digest_accepted(self):
        reg = pr.RevisionRegistry()
        rev = reg.register("policy:1", POLICY_V1.encode("utf-8"),
                           claimed_digest=_digest(POLICY_V1))
        self.assertEqual(rev.digest, _digest(POLICY_V1))

    def test_false_claimed_digest_refused(self):
        reg = pr.RevisionRegistry()
        with self.assertRaises(pr.ReplayError) as ctx:
            reg.register("policy:1", POLICY_V1.encode("utf-8"),
                         claimed_digest="00" * 32)
        self.assertEqual(ctx.exception.code, "replay-policy-digest-mismatch")

    def test_duplicate_bytes_idempotent(self):
        reg = pr.RevisionRegistry()
        r1 = reg.register("policy:1", POLICY_V1.encode("utf-8"))
        r2 = reg.register("policy:1", POLICY_V1.encode("utf-8"))
        self.assertIs(r1, r2)

    def test_duplicate_bytes_conflict_refused(self):
        reg = pr.RevisionRegistry()
        reg.register("policy:1", POLICY_V1.encode("utf-8"))
        with self.assertRaises(pr.ReplayError) as ctx:
            reg.register("policy:1", POLICY_V2.encode("utf-8"))
        self.assertEqual(ctx.exception.code,
                         "replay-policy-revision-conflict")

    def test_unknown_supersedes_refused(self):
        reg = pr.RevisionRegistry()
        with self.assertRaises(pr.ReplayError) as ctx:
            reg.register("policy:2", POLICY_V2.encode("utf-8"),
                         supersedes="policy:ghost")
        self.assertEqual(ctx.exception.code,
                         "replay-policy-revision-unknown")

    def test_chain_oldest_first(self):
        reg = pr.RevisionRegistry()
        reg.register("policy:1", POLICY_V1.encode("utf-8"))
        reg.register("policy:2", POLICY_V2.encode("utf-8"),
                     supersedes="policy:1")
        self.assertEqual(reg.chain("policy:2"), ["policy:1", "policy:2"])

    def test_empty_inputs_malformed(self):
        reg = pr.RevisionRegistry()
        for rev_id, blob in (("", b"x"), (None, b"x"),
                             ("policy:1", b""),
                             ("policy:1", "not-bytes")):
            with self.assertRaises(pr.ReplayError) as ctx:
                reg.register(rev_id, blob)
            self.assertEqual(ctx.exception.code, "replay-policy-malformed")


class EvaluateStampTest(unittest.TestCase):
    def test_evaluate_stamps_revision(self):
        engine = policy_mod.PolicyEngine.from_text(
            POLICY_V1, source_label="t")
        d = engine.evaluate(dict(ACTION), dict(CONTEXT))
        self.assertEqual(d.effect, "allow")
        self.assertEqual(d.policy_rev_id, "policy:1")
        self.assertEqual(d.policy_digest, _digest(POLICY_V1))
        self.assertEqual(d.policy_digest, engine.policy_hash)

    def test_serialization_additive(self):
        engine = policy_mod.PolicyEngine.from_text(
            POLICY_V1, source_label="t")
        d = engine.evaluate(dict(ACTION), dict(CONTEXT))
        ser = d.to_dict()
        self.assertEqual(ser["policy_rev_id"], "policy:1")
        self.assertEqual(ser["policy_digest"], _digest(POLICY_V1))

    def test_half_pinned_refused(self):
        with self.assertRaises(ValueError):
            policy_mod.PolicyDecision("allow", "ok", policy_id="x",
                                      policy_rev_id="policy:1")
        with self.assertRaises(ValueError):
            policy_mod.PolicyDecision("allow", "ok", policy_id="x",
                                      policy_digest="ab" * 32)

    def test_legacy_decision_byte_identical(self):
        # A hand-built decision without the stamp serializes exactly
        # as before the wave-229 fields existed.
        d = policy_mod.PolicyDecision("allow", "ok", policy_id="x")
        ser = d.to_dict()
        self.assertNotIn("policy_rev_id", ser)
        self.assertNotIn("policy_digest", ser)


class ReplayTest(unittest.TestCase):
    def _wired(self):
        engine = policy_mod.PolicyEngine.from_text(
            POLICY_V1, source_label="t")
        reg = pr.RevisionRegistry()
        pr.pin_engine_bytes(reg, "policy:1", POLICY_V1.encode("utf-8"))
        return engine, reg

    def test_replay_reproduces(self):
        engine, reg = self._wired()
        ev = pr.capture_evidence(ACTION, CONTEXT)
        res = pr.replay(ev, "policy:1", reg)
        live = engine.evaluate(dict(ACTION), dict(CONTEXT))
        self.assertTrue(res["replayed"])
        self.assertEqual(res["verdict"]["effect"], live.effect)
        self.assertEqual(res["verdict"]["reason"], live.reason)

    def test_replay_does_not_pollute_ledger(self):
        engine, reg = self._wired()
        ev = pr.capture_evidence(ACTION, CONTEXT)
        before = engine.mode_ledger.entries() \
            if hasattr(engine.mode_ledger, "entries") else None
        pr.replay(ev, "policy:1", reg)
        after = engine.mode_ledger.entries() \
            if hasattr(engine.mode_ledger, "entries") else None
        self.assertEqual(before, after)

    def test_unknown_revision(self):
        _engine, reg = self._wired()
        ev = pr.capture_evidence(ACTION, CONTEXT)
        with self.assertRaises(pr.ReplayError) as ctx:
            pr.replay(ev, "policy:999", reg)
        self.assertEqual(ctx.exception.code,
                         "replay-policy-revision-unknown")

    def test_drift_refused(self):
        engine, reg = self._wired()
        mutated = policy_mod.PolicyEngine.from_text(
            POLICY_V2, source_label="t2")
        pr.pin_engine_bytes(reg, "policy:2", POLICY_V2.encode("utf-8"),
                            supersedes="policy:1")
        ev = pr.capture_evidence(ACTION, CONTEXT)
        # The live policy now denies; the pinned revision still
        # allows -- drift must be explicit, not silent.
        cur = mutated.evaluate(dict(ACTION), dict(CONTEXT))
        self.assertEqual(cur.effect, "deny")
        with self.assertRaises(pr.ReplayError) as ctx:
            pr.replay(ev, "policy:1", reg, current_engine=mutated)
        self.assertEqual(ctx.exception.code, "replay-policy-drift")
        # Without the live comparison the pinned replay is stable.
        res = pr.replay(ev, "policy:1", reg)
        self.assertEqual(res["verdict"]["effect"], "allow")

    def test_no_drift_when_live_agrees(self):
        _engine, reg = self._wired()
        same = policy_mod.PolicyEngine.from_text(
            POLICY_V1, source_label="t-same")
        ev = pr.capture_evidence(ACTION, CONTEXT)
        res = pr.replay(ev, "policy:1", reg, current_engine=same)
        self.assertTrue(res["replayed"])
        self.assertTrue(res["drift_checked"])

    def test_tampered_evidence(self):
        _engine, reg = self._wired()
        ev = pr.capture_evidence(ACTION, CONTEXT)
        ev2 = copy.deepcopy(ev)
        ev2["action"]["tool"] = "delete_everything"
        with self.assertRaises(pr.ReplayError) as ctx:
            pr.replay(ev2, "policy:1", reg)
        self.assertEqual(ctx.exception.code, "replay-evidence-tampered")

    def test_unknown_evidence_fields_malformed(self):
        _engine, reg = self._wired()
        ev = pr.capture_evidence(ACTION, CONTEXT)
        ev["smuggled"] = True
        with self.assertRaises(pr.ReplayError) as ctx:
            pr.replay(ev, "policy:1", reg)
        self.assertEqual(ctx.exception.code, "replay-policy-malformed")

    def test_malformed_policy_bytes(self):
        reg = pr.RevisionRegistry()
        reg.register("policy:bad", b"::: not yaml :::")
        ev = pr.capture_evidence(ACTION, CONTEXT)
        with self.assertRaises(pr.ReplayError) as ctx:
            pr.replay(ev, "policy:bad", reg)
        self.assertEqual(ctx.exception.code, "replay-policy-malformed")

    def test_replay_result_never_authority(self):
        _engine, reg = self._wired()
        ev = pr.capture_evidence(ACTION, CONTEXT)
        res = pr.replay(ev, "policy:1", reg)
        with self.assertRaises(pr.ReplayError) as ctx:
            pr.deny_authority_use(res)
        self.assertEqual(ctx.exception.code,
                         "replay-policy-not-authorization")


if __name__ == "__main__":
    unittest.main()
