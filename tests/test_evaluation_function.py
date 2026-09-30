"""Unit tests for gov/evaluation_function.py.

Expected values are computed inline from stdlib primitives (hashlib +
json with the canonical shape documented in the module docstring), not
from the module's own digest helpers -- the digest values are not
trusted from the code under test.
"""

import hashlib
import json
import unittest

import sys
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import evaluation_function as ev
from gov import policy_revisions as pr

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

POLICY_RA = """\
version: "3"
policies:
  - id: approval-send
    effect: require_approval
    match:
      tool: send_email
"""

EK = "evidence-key-1"
AK = "adjudication-key-1"
INSTANT = "2026-09-30T10:00:00Z"


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")


def _entry(tool="send_email", agent="agent-1"):
    return {"action": {"tool": tool, "agent": agent, "role": "member",
                       "args": {"to": "bob@example.com"}},
            "context": {"counters": {tool: 1}}}


def _registry(*texts):
    reg = pr.RevisionRegistry()
    for i, text in enumerate(texts, 1):
        reg.register("policy:%d" % i, text.encode("utf-8"))
    return reg


class TestFreezeCall(unittest.TestCase):

    def test_freeze_digest_matches_documented_formula(self):
        details = [_entry()]
        frozen = ev.freeze_call(details, evidence_key_id=EK,
                                policy_rev_id="policy:1",
                                policy_digest="0" * 64,
                                instant=INSTANT, nonce=7)
        expected = hashlib.sha256(
            _canon({"instant": INSTANT, "nonce": 7,
                    "authorization_details": details})).hexdigest()
        self.assertEqual(frozen["call_digest"], expected)
        self.assertEqual(frozen["v"], 1)
        self.assertEqual(frozen["evidence_key_id"], EK)

    def test_different_inputs_different_digests(self):
        kw = dict(evidence_key_id=EK, policy_rev_id="policy:1",
                  policy_digest="0" * 64, instant=INSTANT)
        a = ev.freeze_call([_entry("send_email")], nonce=1, **kw)
        b = ev.freeze_call([_entry("send_sms")], nonce=2, **kw)
        self.assertNotEqual(a["call_digest"], b["call_digest"])

    def test_half_pinned_refused(self):
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.freeze_call([_entry()], evidence_key_id=EK,
                           policy_rev_id="policy:1", policy_digest=None,
                           instant=INSTANT)
        self.assertEqual(ctx.exception.code, "evaluation-malformed")

    def test_unpinned_refused(self):
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.freeze_call([_entry()], evidence_key_id=EK,
                           policy_rev_id=None, policy_digest=None,
                           instant=INSTANT)
        self.assertEqual(ctx.exception.code, "evaluation-malformed")

    def test_empty_details_refused(self):
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.freeze_call([], evidence_key_id=EK,
                           policy_rev_id="policy:1",
                           policy_digest="0" * 64, instant=INSTANT)
        self.assertEqual(ctx.exception.code, "evaluation-malformed")

    def test_non_utc_instant_refused(self):
        for bad in ("2026-09-30T10:00:00", "not-a-date", "",
                    "2026-09-30T10:00:00+05:00"):
            with self.assertRaises(ev.EvaluationError) as ctx:
                ev.freeze_call([_entry()], evidence_key_id=EK,
                               policy_rev_id="policy:1",
                               policy_digest="0" * 64, instant=bad)
            self.assertEqual(ctx.exception.code, "evaluation-malformed",
                             bad)

    def test_nonce_is_per_process_monotonic(self):
        kw = dict(evidence_key_id=EK, policy_rev_id="policy:1",
                  policy_digest="0" * 64, instant=INSTANT)
        a = ev.freeze_call([_entry()], **kw)
        b = ev.freeze_call([_entry()], **kw)
        self.assertGreater(b["nonce"], a["nonce"])

    def test_freeze_is_a_deepcopy(self):
        details = [_entry()]
        frozen = ev.freeze_call(details, evidence_key_id=EK,
                                policy_rev_id="policy:1",
                                policy_digest="0" * 64, instant=INSTANT)
        details[0]["action"]["args"]["to"] = "mallory@example.com"
        self.assertEqual(
            frozen["authorization_details"][0]["action"]["args"]["to"],
            "bob@example.com")


class TestEvaluateCall(unittest.TestCase):

    def test_role_conflation_refused(self):
        reg = _registry(POLICY_V1)
        digest = reg.get("policy:1").digest
        frozen = ev.freeze_call([_entry()], evidence_key_id=EK,
                                policy_rev_id="policy:1",
                                policy_digest=digest, instant=INSTANT)
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.evaluate_call(frozen, reg, adjudication_key_id=EK)
        self.assertEqual(ctx.exception.code,
                         "evaluation-key-role-conflation")

    def test_unknown_revision_refused(self):
        reg = _registry(POLICY_V1)
        frozen = ev.freeze_call([_entry()], evidence_key_id=EK,
                                policy_rev_id="policy:9",
                                policy_digest="0" * 64, instant=INSTANT)
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.evaluate_call(frozen, reg, adjudication_key_id=AK)
        self.assertEqual(ctx.exception.code,
                         "evaluation-revision-unknown")

    def test_digest_mismatch_refused(self):
        reg = _registry(POLICY_V1)
        frozen = ev.freeze_call([_entry()], evidence_key_id=EK,
                                policy_rev_id="policy:1",
                                policy_digest="f" * 64, instant=INSTANT)
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.evaluate_call(frozen, reg, adjudication_key_id=AK)
        self.assertEqual(ctx.exception.code,
                         "evaluation-policy-digest-mismatch")

    def test_swapped_input_refused_at_evaluate(self):
        reg = _registry(POLICY_V1)
        digest = reg.get("policy:1").digest
        frozen = ev.freeze_call([_entry()], evidence_key_id=EK,
                                policy_rev_id="policy:1",
                                policy_digest=digest, instant=INSTANT)
        frozen["authorization_details"][0]["action"]["args"]["to"] = \
            "mallory@example.com"
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.evaluate_call(frozen, reg, adjudication_key_id=AK)
        self.assertEqual(ctx.exception.code, "evaluation-input-swapped")

    def test_deny_dominates(self):
        reg = _registry(POLICY_V1)
        digest = reg.get("policy:1").digest
        frozen = ev.freeze_call([_entry("send_email"), _entry("send_sms")],
                                evidence_key_id=EK, policy_rev_id="policy:1",
                                policy_digest=digest, instant=INSTANT)
        rec = ev.evaluate_call(frozen, reg, adjudication_key_id=AK)
        self.assertEqual(rec["verdict"], "deny")
        self.assertEqual([e["effect"] for e in rec["entry_verdicts"]],
                         ["allow", "deny"])

    def test_require_approval_dominates_allow(self):
        reg = _registry(POLICY_RA)
        digest = reg.get("policy:1").digest
        frozen = ev.freeze_call([_entry("send_email"), _entry("send_sms")],
                                evidence_key_id=EK, policy_rev_id="policy:1",
                                policy_digest=digest, instant=INSTANT)
        rec = ev.evaluate_call(frozen, reg, adjudication_key_id=AK)
        # send_sms hits no rule -> default_deny dominates require_approval
        self.assertEqual(rec["verdict"], "deny")
        frozen2 = ev.freeze_call([_entry("send_email")],
                                 evidence_key_id=EK, policy_rev_id="policy:1",
                                 policy_digest=digest, instant=INSTANT)
        rec2 = ev.evaluate_call(frozen2, reg, adjudication_key_id=AK)
        self.assertEqual(rec2["verdict"], "require_approval")

    def test_unevaluable_entry_refused_not_skipped(self):
        reg = _registry(POLICY_V1)
        digest = reg.get("policy:1").digest
        bad = _entry()
        bad["action"]["args"] = "not-a-mapping"  # fails Request contract
        frozen = ev.freeze_call([_entry(), bad], evidence_key_id=EK,
                                policy_rev_id="policy:1",
                                policy_digest=digest, instant=INSTANT)
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.evaluate_call(frozen, reg, adjudication_key_id=AK)
        self.assertEqual(ctx.exception.code,
                         "evaluation-incomplete-details")

    def test_verdict_digest_covers_verdict(self):
        reg = _registry(POLICY_V1)
        digest = reg.get("policy:1").digest
        frozen = ev.freeze_call([_entry()], evidence_key_id=EK,
                                policy_rev_id="policy:1",
                                policy_digest=digest, instant=INSTANT)
        rec = ev.evaluate_call(frozen, reg, adjudication_key_id=AK)
        expected = hashlib.sha256(_canon({
            "call_digest": rec["call_digest"],
            "verdict": rec["verdict"],
            "entry_digests": [e["entry_digest"]
                              for e in rec["entry_verdicts"]],
            "policy_rev_id": "policy:1",
            "policy_digest": digest})).hexdigest()
        self.assertEqual(rec["verdict_digest"], expected)


class TestVerifyAndReplay(unittest.TestCase):

    def _record(self, tools=("send_email",)):
        reg = _registry(POLICY_V1)
        digest = reg.get("policy:1").digest
        frozen = ev.freeze_call([_entry(t) for t in tools],
                                evidence_key_id=EK, policy_rev_id="policy:1",
                                policy_digest=digest, instant=INSTANT)
        return reg, ev.evaluate_call(frozen, reg,
                                     adjudication_key_id=AK)

    def test_verify_round_trip(self):
        reg, rec = self._record()
        self.assertIs(ev.verify_call(rec, reg), rec)

    def test_verify_rejects_truncated_entry_verdicts(self):
        reg, rec = self._record(("send_email", "send_sms"))
        rec["entry_verdicts"] = rec["entry_verdicts"][:1]
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.verify_call(rec, reg)
        self.assertEqual(ctx.exception.code,
                         "evaluation-incomplete-details")

    def test_verify_rejects_flipped_verdict(self):
        reg, rec = self._record()
        rec["verdict"] = "allow" if rec["verdict"] == "deny" else "deny"
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.verify_call(rec, reg)
        self.assertEqual(ctx.exception.code, "evaluation-input-swapped")

    def test_replay_reproduces(self):
        reg, rec = self._record(("send_email", "send_sms"))
        out = ev.replay_evaluation(rec, reg)
        self.assertTrue(out["replayed"])
        self.assertEqual(out["verdict"], "deny")
        self.assertFalse(out["drift_checked"])

    def test_replay_detects_non_reproducible_verdict(self):
        from copy import deepcopy
        reg, rec = self._record(("send_sms",))  # pinned verdict: deny
        self.assertEqual(rec["verdict"], "deny")
        forged = deepcopy(rec)
        forged["verdict"] = "allow"
        forged["verdict_digest"] = ev.verdict_digest_of(forged)
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.replay_evaluation(forged, reg)
        self.assertEqual(ctx.exception.code,
                         "evaluation-non-reproducible")

    def test_replay_detects_policy_drift(self):
        from gov import policy as pol
        reg, rec = self._record(("send_email",))  # pinned: allow
        self.assertEqual(rec["verdict"], "allow")
        current = pol.PolicyEngine.from_text(POLICY_V2,
                                             source_label="<probe>")
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.replay_evaluation(rec, reg, current_engine=current)
        self.assertEqual(ctx.exception.code, "evaluation-policy-drift")

    def test_replay_same_revision_no_drift(self):
        from gov import policy as pol
        reg, rec = self._record(("send_email",))
        current = pol.PolicyEngine.from_text(POLICY_V1,
                                             source_label="<probe>")
        out = ev.replay_evaluation(rec, reg, current_engine=current)
        self.assertTrue(out["drift_checked"])
        self.assertEqual(out["verdict"], "allow")

    def test_replay_refuses_tampered_input(self):
        from copy import deepcopy
        reg, rec = self._record()
        rec["authorization_details"][0]["action"]["args"]["to"] = \
            "mallory@example.com"
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.replay_evaluation(rec, reg)
        self.assertEqual(ctx.exception.code, "evaluation-input-swapped")


class TestDenyAuthorityUse(unittest.TestCase):

    def test_record_is_not_authority(self):
        reg, rec = TestVerifyAndReplay()._record()
        with self.assertRaises(ev.EvaluationError) as ctx:
            ev.deny_authority_use(rec)
        self.assertEqual(ctx.exception.code,
                         "evaluation-not-authorization")

    def test_non_record_passes(self):
        self.assertTrue(ev.deny_authority_use({"foo": "bar"}))
        self.assertTrue(ev.deny_authority_use(None))


if __name__ == "__main__":
    unittest.main()
