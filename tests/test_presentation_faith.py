"""Unit tests for gov/presentation.py and gov/approval_render.py
(wave-220 lane A: presentation-faithfulness + mission-bound ARAP).

Tests at the public seams: render/seal/verify/guard and the mission
permit registry. Expected values are independent literals (hand-
computed digests), never recomputed the way the code computes them.
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import approval_render as ar  # noqa: E402
from gov import presentation as pres  # noqa: E402


def _record(**over):
    rec = {
        "id": "appr-0001",
        "tool": "write_file",
        "args": {"path": "/etc/app/config.yaml", "mode": "overwrite"},
        "preview": "write /etc/app/config.yaml (overwrite)",
        "agent_id": "agent-7",
        "role": "executor",
        "principal": "principal:agent-7",
        "policy_id": "pol-9",
        "policy_version": 3,
        "matched_rules": ["rule-write"],
        "policy_flag": None,
        "packet_risk_score": 55,
        "packet_risk_factors": ["writes-outside-sandbox"],
        "shield_tier": "standard",
        "persuasion_score": 0,
        "persuasion_markers": [],
        "policy_context": {"path_resolved": "/etc/app/config.yaml",
                           "memory_provenance": [],
                           "attachment_carriers": []},
        "deferred_effect": None,
    }
    rec.update(over)
    return rec


class TestPresentationDigest(unittest.TestCase):
    def test_digest_format(self):
        d = pres.presentation_digest("hello")
        self.assertTrue(d.startswith("sha256:"))
        self.assertEqual(len(d), len("sha256:") + 64)

    def test_digest_known_value(self):
        # Independent literal: sha256("abc") from the spec vector.
        self.assertEqual(
            pres.presentation_digest("abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_digest_rejects_non_string(self):
        with self.assertRaises(TypeError):
            pres.presentation_digest(b"bytes")

    def test_artifact_digest_stable(self):
        rec = _record()
        self.assertEqual(pres.artifact_digest(rec),
                         pres.artifact_digest(_record()))

    def test_artifact_digest_sensitive_to_record(self):
        rec = _record()
        tampered = _record(args={"path": "/etc/passwd"})
        self.assertNotEqual(pres.artifact_digest(rec),
                            pres.artifact_digest(tampered))


class TestCheckPresentationIntegrity(unittest.TestCase):
    def test_intact_returns_true(self):
        self.assertTrue(pres.check_presentation_integrity(
            {"text": "shown", "digest": pres.presentation_digest("shown")}))

    def test_missing_presentation(self):
        for bad in (None, "x", {}, {"text": "x"}):
            with self.assertRaises(pres.PresentationMissingError) as ctx:
                pres.check_presentation_integrity(bad)
            self.assertEqual(ctx.exception.code, "presentation-missing")

    def test_tampered_digest(self):
        with self.assertRaises(pres.DisplayHashMismatchError) as ctx:
            pres.check_presentation_integrity(
                {"text": "shown",
                 "digest": pres.presentation_digest("other")})
        self.assertEqual(ctx.exception.code, "display-hash-mismatch")


class TestRenderSealVerify(unittest.TestCase):
    def test_render_digest_covers_text(self):
        p = ar.render_approval(_record())
        self.assertEqual(p["digest"], pres.presentation_digest(p["text"]))

    def test_render_is_deterministic(self):
        self.assertEqual(ar.render_approval(_record())["digest"],
                         ar.render_approval(_record())["digest"])

    def test_render_reflects_record(self):
        a = ar.render_approval(_record())["digest"]
        b = ar.render_approval(_record(tool="delete_file"))["digest"]
        self.assertNotEqual(a, b)

    def test_seal_binds_artifact_and_presentation(self):
        rec = _record()
        p = ar.render_approval(rec)
        sealed = ar.seal_approval(rec, p, signer="op-1")
        self.assertEqual(sealed["artifact_digest"],
                         pres.artifact_digest(rec))
        self.assertEqual(sealed["presentation_digest"], p["digest"])
        self.assertEqual(sealed["presentation_text"], p["text"])
        self.assertEqual(sealed["signer"], "op-1")
        self.assertTrue(ar.verify_seal(rec, sealed))

    def test_seal_refuses_tampered_presentation(self):
        rec = _record()
        p = dict(ar.render_approval(rec))
        p["text"] = p["text"] + " extra line"
        with self.assertRaises(pres.DisplayHashMismatchError):
            ar.seal_approval(rec, p, signer="op-1")

    def test_verify_seal_swapped_record(self):
        rec_a = _record(id="appr-A", tool="read_file")
        rec_b = _record(id="appr-B", tool="delete_file")
        sealed = ar.seal_approval(rec_a, ar.render_approval(rec_a),
                                  signer="op-1")
        with self.assertRaises(pres.DisplayHashMismatchError) as ctx:
            ar.verify_seal(rec_b, sealed)
        self.assertEqual(ctx.exception.code, "display-hash-mismatch")

    def test_verify_seal_stale_display(self):
        rec = _record()
        sealed = ar.seal_approval(rec, ar.render_approval(rec), signer="op-1")
        rec["packet_risk_score"] = 99  # record drifts after rendering
        with self.assertRaises(pres.DisplayHashMismatchError):
            ar.verify_seal(rec, sealed)

    def test_verify_seal_malformed(self):
        rec = _record()
        for bad in (None, {}, {"presentation_text": "t"}):
            with self.assertRaises(pres.PresentationMissingError) as ctx:
                ar.verify_seal(rec, bad)
            self.assertEqual(ctx.exception.code, "presentation-missing")

    def test_seal_does_not_mutate_presentation(self):
        rec = _record()
        p = ar.render_approval(rec)
        before = dict(p)
        ar.seal_approval(rec, p, signer="op-1")
        self.assertEqual(p, before)


class TestGuardedDecide(unittest.TestCase):
    class StubQueue:
        def __init__(self, record):
            self._record = record
            self.calls = []

        def get(self, approval_id):
            if approval_id != self._record["id"]:
                raise KeyError(approval_id)
            return self._record

        def decide(self, approval_id, approved, reason, **kw):
            self.calls.append((approval_id, approved, reason, kw))
            return ("decided", approval_id, approved, reason)

    def test_legacy_passthrough(self):
        rec = _record()
        stub = self.StubQueue(rec)
        got = ar.guarded_decide(stub, "appr-0001", True, "ok", sealed=None)
        self.assertEqual(got, ("decided", "appr-0001", True, "ok"))
        self.assertEqual(stub.calls, [("appr-0001", True, "ok", {})])

    def test_guarded_with_valid_seal_decides(self):
        rec = _record()
        stub = self.StubQueue(rec)
        sealed = ar.seal_approval(rec, ar.render_approval(rec), signer="op-1")
        got = ar.guarded_decide(stub, "appr-0001", True, "ok", sealed=sealed)
        self.assertEqual(got, ("decided", "appr-0001", True, "ok"))

    def test_guarded_with_bad_seal_never_decides(self):
        rec = _record()
        stub = self.StubQueue(rec)
        sealed = ar.seal_approval(rec, ar.render_approval(rec), signer="op-1")
        rec["tool"] = "delete_file"  # tamper the live record after sealing
        with self.assertRaises(pres.DisplayHashMismatchError):
            ar.guarded_decide(stub, "appr-0001", True, "ok", sealed=sealed)
        self.assertEqual(stub.calls, [])


class TestSealMissionBinding(unittest.TestCase):
    def _digest(self):
        return pres.parameter_digest({"subject": "agent-7",
                                      "resource": "/etc/app/config.yaml",
                                      "action": "write_file"})

    def test_seal_stamps_parameter_digest(self):
        rec = _record()
        sealed = ar.seal_approval(rec, ar.render_approval(rec),
                                 signer="op-1",
                                 parameter_digest=self._digest())
        self.assertEqual(sealed["parameter_digest"], self._digest())

    def test_seal_without_digest_carries_none(self):
        rec = _record()
        sealed = ar.seal_approval(rec, ar.render_approval(rec), signer="op-1")
        self.assertNotIn("parameter_digest", sealed)

    def test_verify_seal_accepts_matching_binding(self):
        rec = _record()
        d = self._digest()
        sealed = ar.seal_approval(rec, ar.render_approval(rec),
                                 signer="op-1", parameter_digest=d)
        self.assertTrue(ar.verify_seal(rec, sealed, parameter_digest=d))

    def test_verify_seal_refuses_retargeted_binding(self):
        rec = _record()
        sealed = ar.seal_approval(rec, ar.render_approval(rec),
                                 signer="op-1",
                                 parameter_digest=self._digest())
        other = pres.parameter_digest({"subject": "other"})
        with self.assertRaises(pres.MissionBindingMismatchError) as ctx:
            ar.verify_seal(rec, sealed, parameter_digest=other)
        self.assertEqual(ctx.exception.code, "mission-binding-mismatch")

    def test_verify_seal_refuses_unbound_when_binding_required(self):
        rec = _record()
        sealed = ar.seal_approval(rec, ar.render_approval(rec), signer="op-1")
        with self.assertRaises(pres.MissionBindingMismatchError):
            ar.verify_seal(rec, sealed, parameter_digest=self._digest())

    def test_guarded_decide_enforces_binding_before_decide(self):
        rec = _record()
        d = self._digest()
        sealed = ar.seal_approval(rec, ar.render_approval(rec),
                                 signer="op-1", parameter_digest=d)
        stub = TestGuardedDecide.StubQueue(rec)
        with self.assertRaises(pres.MissionBindingMismatchError):
            ar.guarded_decide(stub, rec["id"], True, "ok", sealed=sealed,
                              parameter_digest=pres.parameter_digest(
                                  {"subject": "other"}))
        self.assertEqual(stub.calls, [])
        # Matching binding proceeds.
        ar.guarded_decide(stub, rec["id"], True, "ok", sealed=sealed,
                          parameter_digest=d)
        self.assertEqual(len(stub.calls), 1)
        self.assertEqual(stub.calls[0][0], rec["id"])


class TestMissionBinding(unittest.TestCase):
    def _digest(self):
        return pres.parameter_digest({"subject": "agent-7",
                                      "resource": "/etc/app/config.yaml",
                                      "action": "write_file"})

    def test_parameter_digest_format_and_stability(self):
        d = self._digest()
        self.assertTrue(d.startswith("sha256:"))
        self.assertEqual(d, self._digest())

    def test_parameter_digest_sensitive(self):
        other = pres.parameter_digest({"subject": "agent-7",
                                       "resource": "/etc/app/config.yaml",
                                       "action": "write_file",
                                       "args": {"x": 1}})
        self.assertNotEqual(self._digest(), other)

    def test_bind_and_verify(self):
        rec = _record()
        sealed = ar.seal_approval(rec, ar.render_approval(rec), signer="op-1")
        d = self._digest()
        bound = pres.mission_bind_approval(sealed, d)
        self.assertNotIn("parameter_digest", sealed)  # no mutation
        self.assertEqual(bound["parameter_digest"], d)
        self.assertTrue(pres.verify_mission_binding(bound, d))

    def test_binding_mismatch_refused(self):
        rec = _record()
        sealed = ar.seal_approval(rec, ar.render_approval(rec), signer="op-1")
        bound = pres.mission_bind_approval(sealed, self._digest())
        other = pres.parameter_digest({"subject": "other"})
        with self.assertRaises(pres.MissionBindingMismatchError) as ctx:
            pres.verify_mission_binding(bound, other)
        self.assertEqual(ctx.exception.code, "mission-binding-mismatch")

    def test_unbound_seal_refused(self):
        rec = _record()
        sealed = ar.seal_approval(rec, ar.render_approval(rec), signer="op-1")
        with self.assertRaises(pres.MissionBindingMismatchError):
            pres.verify_mission_binding(sealed, self._digest())


class TestMissionPermitRegistry(unittest.TestCase):
    def _issue(self, reg, digest="sha256:deadbeef"):
        return reg.issue("appr-0001", digest)

    def test_issue_consume_once(self):
        reg = pres.MissionPermitRegistry()
        lease = self._issue(reg)
        self.assertTrue(reg.consume(lease["lease_id"], "sha256:deadbeef"))

    def test_replay_refused(self):
        reg = pres.MissionPermitRegistry()
        lease = self._issue(reg)
        reg.consume(lease["lease_id"], "sha256:deadbeef")
        with self.assertRaises(pres.PermitReusedError) as ctx:
            reg.consume(lease["lease_id"], "sha256:deadbeef")
        self.assertEqual(ctx.exception.code, "permit-reused")

    def test_digest_change_refused(self):
        reg = pres.MissionPermitRegistry()
        lease = self._issue(reg)
        with self.assertRaises(pres.MissionBindingMismatchError) as ctx:
            reg.consume(lease["lease_id"], "sha256:feedface")
        self.assertEqual(ctx.exception.code, "mission-binding-mismatch")

    def test_relaxed_match_refused(self):
        reg = pres.MissionPermitRegistry()
        lease = self._issue(reg)
        with self.assertRaises(pres.DowngradeRefusedError) as ctx:
            reg.consume(lease["lease_id"], "sha256:deadbeef", match="prefix")
        self.assertEqual(ctx.exception.code, "downgrade-refused")

    def test_refused_attempt_does_not_burn_lease(self):
        reg = pres.MissionPermitRegistry()
        lease = self._issue(reg)
        with self.assertRaises(pres.MissionBindingMismatchError):
            reg.consume(lease["lease_id"], "sha256:wrong")
        self.assertTrue(reg.consume(lease["lease_id"], "sha256:deadbeef"))

    def test_unknown_lease_refused(self):
        reg = pres.MissionPermitRegistry()
        with self.assertRaises(pres.MissionBindingMismatchError):
            reg.consume("mission-permit-nope", "sha256:deadbeef")

    def test_audit_callback_fires(self):
        reg = pres.MissionPermitRegistry()
        lease = self._issue(reg)
        events = []
        reg.consume(lease["lease_id"], "sha256:deadbeef",
                    audit=events.append)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "mission_permit_consumed")

    def test_authoring_misuse_is_valueerror(self):
        reg = pres.MissionPermitRegistry()
        with self.assertRaises(ValueError):
            reg.issue("", "sha256:x")
        with self.assertRaises(ValueError):
            reg.issue("appr-1", "")


if __name__ == "__main__":
    unittest.main()
