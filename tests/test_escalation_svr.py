#!/usr/bin/env python3
"""Unit tests for gov/escalation_bind.py and gov/svr.py.

Independent spec-vector literals (not recomputed through the
modules under test where the module's own digest math is the
subject): digests are recomputed here only as the checker's
independent oracle for the escalation/SVR link fields.
"""

import hashlib
import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import escalation_bind as eb
from gov import svr as svr_mod
from gov import action_capsule as ac


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


_DIGEST_A = "aa" * 32
_DIGEST_B = "bb" * 32
_APPROVAL_BODY = {"approver": "oncall-lead", "decision": "escalate-approve",
                  "rationale": "incident-7782",
                  "issued_at": "2026-09-30T00:00:00+00:00"}
_APPROVAL_DIGEST = hashlib.sha256(_canon(_APPROVAL_BODY)).hexdigest()


def _escalated_capsule():
    return ac.seal_capsule({
        "attempt": {"action": "restart_database",
                    "args_digest": _DIGEST_A,
                    "escalation_required": True},
        "effect": {"status": "admitted",
                   "evidence": "db restarted; pid log line"},
    })


def _approval_for(capsule):
    return {"v": 1,
            "approval_body": dict(_APPROVAL_BODY),
            "approval_digest": _APPROVAL_DIGEST,
            "action_digest": capsule["verdict_digest"]}


def _svr():
    return svr_mod.build_svr(
        artifact_digest=_DIGEST_A,
        build_instructions_digest=_DIGEST_B,
        reproduction_pointers=["oci://registry.example.com/img",
                               "git+https://git.example.com/r@abc123"],
        verifier_results={"reproduced": True})


class EscalationBindTest(unittest.TestCase):
    def test_bound_capsule_verifies_to_approval_digest(self):
        capsule = _escalated_capsule()
        bound = eb.bind_escalation(_approval_for(capsule), capsule)
        self.assertEqual(eb.verify_escalation_bound(bound),
                         _APPROVAL_DIGEST)

    def test_binding_survives_capsule_replay(self):
        capsule = _escalated_capsule()
        bound = eb.bind_escalation(_approval_for(capsule), capsule)
        body = ac.verify_capsule(bound)
        self.assertEqual(body["effect"]["escalation_digest"],
                         _APPROVAL_DIGEST)
        self.assertEqual(body["attempt"]["escalation"]
                         ["approval_digest"], _APPROVAL_DIGEST)

    def test_unbound_escalated_action_refuses(self):
        with self.assertRaises(eb.EscalationBindError) as ctx:
            eb.verify_escalation_bound(_escalated_capsule())
        self.assertEqual(ctx.exception.code, "escalation-not-bound")

    def test_non_escalated_capsule_returns_none(self):
        plain = ac.seal_capsule({
            "attempt": {"action": "read_file",
                        "args_digest": _DIGEST_A},
            "effect": {"status": "admitted", "evidence": "bytes read"},
        })
        self.assertIsNone(eb.verify_escalation_bound(plain))

    def test_approval_digest_mismatch_refuses_at_bind(self):
        capsule = _escalated_capsule()
        approval = _approval_for(capsule)
        approval["approval_digest"] = "00" * 32
        with self.assertRaises(eb.EscalationBindError) as ctx:
            eb.bind_escalation(approval, capsule)
        self.assertEqual(ctx.exception.code,
                         "escalation-approval-digest-mismatch")

    def test_approval_for_other_action_refuses(self):
        capsule = _escalated_capsule()
        other = ac.seal_capsule({
            "attempt": {"action": "delete_database",
                        "args_digest": _DIGEST_B,
                        "escalation_required": True},
            "effect": {"status": "admitted",
                       "evidence": "db deleted; log line"},
        })
        with self.assertRaises(eb.EscalationBindError) as ctx:
            eb.bind_escalation(_approval_for(other), capsule)
        self.assertEqual(ctx.exception.code,
                         "escalation-action-mismatch")

    def test_double_bind_refuses(self):
        capsule = _escalated_capsule()
        bound = eb.bind_escalation(_approval_for(capsule), capsule)
        with self.assertRaises(eb.EscalationBindError) as ctx:
            eb.bind_escalation(_approval_for(bound), bound)
        self.assertEqual(ctx.exception.code, "escalation-already-bound")

    def test_tampered_approval_body_breaks_digest(self):
        capsule = _escalated_capsule()
        bound = eb.bind_escalation(_approval_for(capsule), capsule)
        body = ac.verify_capsule(bound)
        # Re-seal the same attempt/effect with a swapped approval
        # body: the recomputed approval digest must differ.
        swapped = dict(body["attempt"])
        esc = dict(swapped["escalation"])
        esc["approval_body"] = {"approver": "attacker"}
        swapped["escalation"] = esc
        tampered = ac.seal_capsule({"attempt": swapped,
                                    "effect": dict(body["effect"])})
        with self.assertRaises(eb.EscalationBindError) as ctx:
            eb.verify_escalation_bound(tampered)
        self.assertEqual(ctx.exception.code,
                         "escalation-approval-digest-mismatch")

    def test_malformed_approval_refuses(self):
        capsule = _escalated_capsule()
        with self.assertRaises(eb.EscalationBindError) as ctx:
            eb.bind_escalation({"approval_body": {}}, capsule)
        self.assertEqual(ctx.exception.code, "escalation-malformed")

    def test_action_digest_binds_original_attempt(self):
        capsule = _escalated_capsule()
        bound = eb.bind_escalation(_approval_for(capsule), capsule)
        body = ac.verify_capsule(bound)
        attempt_minus = {k: v for k, v in body["attempt"].items()
                         if k != "escalation"}
        want = hashlib.sha256(_canon(attempt_minus)).hexdigest()
        self.assertEqual(body["attempt"]["escalation"]
                         ["action_digest"], want)
        self.assertEqual(want, capsule["verdict_digest"])


class SVRTest(unittest.TestCase):
    def test_build_verify_roundtrip(self):
        rec = _svr()
        verified = svr_mod.verify_svr(rec)
        self.assertEqual(verified["svr_digest"], rec["svr_digest"])
        self.assertEqual(len(rec["reproduction_pointers"]), 2)

    def test_digest_pinned(self):
        rec = _svr()
        body = {"v": 1, "artifact_digest": _DIGEST_A,
                "build_instructions_digest": _DIGEST_B,
                "reproduction_pointers": rec["reproduction_pointers"],
                "verifier_results": rec["verifier_results"]}
        want = hashlib.sha256(_canon(body)).hexdigest()
        self.assertEqual(rec["svr_digest"], want)

    def test_empty_pointers_refuse(self):
        with self.assertRaises(svr_mod.SVRError) as ctx:
            svr_mod.build_svr(_DIGEST_A, _DIGEST_B, [],
                              verifier_results={})
        self.assertEqual(ctx.exception.code,
                         "svr-no-reproduction-pointer")

    def test_malformed_pointers_refuse(self):
        for pointer in ("no-scheme", "has space://x", "", 42,
                        "x" * 3000):
            with self.assertRaises(svr_mod.SVRError) as ctx:
                svr_mod.build_svr(_DIGEST_A, _DIGEST_B, [pointer])
            self.assertEqual(ctx.exception.code,
                             "svr-pointer-malformed")

    def test_malformed_digest_refuses(self):
        with self.assertRaises(svr_mod.SVRError) as ctx:
            svr_mod.build_svr("nope", _DIGEST_B,
                              ["oci://x.example.com/i"])
        self.assertEqual(ctx.exception.code, "svr-digest-malformed")

    def test_authority_field_refuses(self):
        with self.assertRaises(svr_mod.SVRError) as ctx:
            svr_mod.svr_carries_no_authority(
                {"artifact_digest": _DIGEST_A, "grant": "all"})
        self.assertEqual(ctx.exception.code, "svr-not-authorization")

    def test_tampered_record_refuses(self):
        rec = _svr()
        tampered = dict(rec)
        tampered["verifier_results"] = {"reproduced": False}
        with self.assertRaises(svr_mod.SVRError) as ctx:
            svr_mod.verify_svr(tampered)
        self.assertEqual(ctx.exception.code, "svr-digest-mismatch")

    def test_attach_and_verify_link(self):
        capsule = _escalated_capsule()
        rec = _svr()
        linked = svr_mod.attach_svr_to_capsule(capsule, rec)
        ac.verify_capsule(linked)  # capsule replay still green
        self.assertEqual(svr_mod.verify_capsule_svr(linked, rec),
                         rec["svr_digest"])

    def test_tampered_svr_breaks_link(self):
        capsule = _escalated_capsule()
        rec = _svr()
        linked = svr_mod.attach_svr_to_capsule(capsule, rec)
        tampered = dict(rec)
        tampered["artifact_digest"] = _DIGEST_B
        with self.assertRaises(svr_mod.SVRError) as ctx:
            svr_mod.verify_capsule_svr(linked, tampered)
        self.assertEqual(ctx.exception.code, "svr-digest-mismatch")

    def test_capsule_without_link_refuses(self):
        capsule = _escalated_capsule()
        with self.assertRaises(svr_mod.SVRError) as ctx:
            svr_mod.verify_capsule_svr(capsule, _svr())
        self.assertEqual(ctx.exception.code, "svr-malformed")

    def test_verifier_results_none_defaults_empty(self):
        rec = svr_mod.build_svr(_DIGEST_A, _DIGEST_B,
                                ["oci://x.example.com/i"])
        self.assertEqual(rec["verifier_results"], {})


if __name__ == "__main__":
    unittest.main()
