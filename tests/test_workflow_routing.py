"""Unit tests for gov/workflow_routing.py: routing-slip authority.

Wave-301 lane 5 (MassTransit Courier ADAPT): the routing slip is a signed
itinerary that travels WITH the work. Authority rides along: every leg
re-verifies the full chain before executing, legs cannot be skipped,
reordered, or widened, and per-leg receipts chain the auditable path.

Every coded refusal is asserted by code (F351 contract); the ed25519
True/False contract is pinned (wave-243); the two new decision codes
are pinned as raw source literals.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519
from gov import workflow_routing as wr


def _seed(tag):
    return hashlib.sha256(tag.encode()).digest()


def _hex64(s):
    return hashlib.sha256(s.encode()).hexdigest()


class RoutingSlipContractTest(unittest.TestCase):
    def setUp(self):
        self.seed_issuer = _seed("w301rs-issuer")
        self.seed_b = _seed("w301rs-b")
        self.seed_c = _seed("w301rs-c")
        self.seed_d = _seed("w301rs-d")
        self.seed_evil = _seed("w301rs-evil")
        self.pub_issuer = ed25519.publickey(self.seed_issuer).hex()
        self.pub_b = ed25519.publickey(self.seed_b).hex()
        self.pub_c = ed25519.publickey(self.seed_c).hex()
        self.pub_d = ed25519.publickey(self.seed_d).hex()
        self.at = 1_700_000_000
        self.trust = [self.pub_issuer]

    def _leg(self, hid, pub, rights=("tool.invoke",)):
        return {"handler_id": hid, "handler_pubkey_hex": pub,
                "rights": list(rights),
                "input_digest": _hex64("in-" + hid),
                "output_digest": _hex64("out-" + hid)}

    def _slip(self, rights_b=("tool.invoke",), rights_c=("tool.invoke",)):
        return wr.issue_slip(
            self.seed_issuer, "issuer",
            [self._leg("agent-b", self.pub_b, rights_b),
             self._leg("agent-c", self.pub_c, rights_c),
             self._leg("agent-d", self.pub_d, ("tool.invoke",))],
            issued_at=self.at, expires_at=self.at + 3600)

    def _code_of(self, fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 -- probe harness
            self.assertIsNotNone(getattr(e, "code", None),
                                 "refusal without code: %r" % (e,))
            return e.code
        self.fail("expected coded refusal, call succeeded")

    # -- happy path ----------------------------------------------------

    def test_issue_and_verify_control(self):
        slip = self._slip()
        self.assertTrue(wr.verify_slip(slip, self.trust, self.at) is True)
        self.assertEqual(slip["next_leg"], 0)

    def test_complete_leg_advances_and_chains_receipt(self):
        slip = self._slip()
        leg = wr.accept_leg(slip, 0, self.seed_b, self.at, self.trust)
        self.assertEqual(leg["handler_id"], "agent-b")
        slip2 = wr.complete_leg(slip, 0, self.seed_b, _hex64("res-b"),
                               self.at, self.trust)
        self.assertEqual(slip2["next_leg"], 1)
        self.assertEqual(len(slip2["receipts"]), 1)
        self.assertEqual(slip["next_leg"], 0)  # input slip not mutated
        self.assertTrue(wr.verify_slip(slip2, self.trust, self.at) is True)

    def test_full_three_leg_workflow_auditable(self):
        slip = self._slip()
        for i, seed in enumerate((self.seed_b, self.seed_c, self.seed_d)):
            slip = wr.complete_leg(slip, i, seed, _hex64("res-%d" % i),
                                   self.at, self.trust)
        self.assertEqual(slip["next_leg"], 3)
        self.assertTrue(wr.verify_slip(slip, self.trust, self.at) is True)
        digests = [r["receipt_digest"] for r in slip["receipts"]]
        self.assertEqual(len(set(digests)), 3)

    def test_attenuation_allowed(self):
        # A leg may narrow what it forwards, never widen.
        slip = self._slip(rights_b=("tool.invoke", "memory.read"))
        slip2 = wr.complete_leg(slip, 0, self.seed_b, _hex64("res-b"),
                                self.at, self.trust,
                                forwarded_rights=["tool.invoke"])
        self.assertTrue(wr.verify_slip(slip2, self.trust, self.at) is True)

    # -- attacks --------------------------------------------------------

    def test_leg_skip_refused(self):
        slip = self._slip()
        code = self._code_of(wr.complete_leg, slip, 1, self.seed_c,
                             _hex64("res-c"), self.at, self.trust)
        self.assertEqual(code, "workflow-routing-slip-tampered")

    def test_leg_reorder_refused(self):
        slip = self._slip()
        slip2 = wr.complete_leg(slip, 0, self.seed_b, _hex64("res-b"),
                                self.at, self.trust)
        # Attacker forges a receipt claiming leg 0 again is the "next" one.
        forged = dict(slip2)
        forged["next_leg"] = 0
        code = self._code_of(wr.verify_slip, forged, self.trust, self.at)
        self.assertEqual(code, "workflow-routing-slip-tampered")

    def test_rights_widening_at_forward_refused(self):
        slip = self._slip(rights_b=("tool.invoke",))
        code = self._code_of(
            wr.complete_leg, slip, 0, self.seed_b, _hex64("res-b"),
            self.at, self.trust,
            forwarded_rights=["tool.invoke", "memory.read"])
        self.assertEqual(code, "workflow-routing-rights-widened")

    def test_downstream_grant_exceeds_forwarded_refused(self):
        # Itinerary grants leg c a right that leg b never forwarded:
        # complete leg 0 (it can only forward its own rights), then leg 1
        # cannot be accepted under the widened grant.
        slip = self._slip(rights_b=("tool.invoke",),
                          rights_c=("tool.invoke", "memory.read"))
        slip2 = wr.complete_leg(slip, 0, self.seed_b, _hex64("res-b"),
                                self.at, self.trust)
        code = self._code_of(wr.accept_leg, slip2, 1, self.seed_c,
                             self.at, self.trust)
        self.assertEqual(code, "workflow-routing-rights-widened")

    def test_forged_slip_signature_refused(self):
        slip = self._slip()
        tampered = dict(slip)
        tampered["legs"] = [dict(l) for l in slip["legs"]]
        tampered["legs"][1] = dict(slip["legs"][1])
        tampered["legs"][1]["rights"] = ["tool.invoke", "admin.all"]
        code = self._code_of(wr.verify_slip, tampered, self.trust, self.at)
        self.assertEqual(code, "workflow-routing-slip-tampered")

    def test_truncated_receipt_chain_refused(self):
        slip = self._slip()
        slip2 = wr.complete_leg(slip, 0, self.seed_b, _hex64("res-b"),
                                self.at, self.trust)
        slip3 = wr.complete_leg(slip2, 1, self.seed_c, _hex64("res-c"),
                                self.at, self.trust)
        truncated = dict(slip3)
        truncated["receipts"] = slip3["receipts"][:1]  # drop leg-1 receipt
        code = self._code_of(wr.verify_slip, truncated, self.trust, self.at)
        self.assertEqual(code, "workflow-routing-slip-tampered")

    def test_wrong_handler_key_refused(self):
        slip = self._slip()
        code = self._code_of(wr.accept_leg, slip, 0, self.seed_evil,
                             self.at, self.trust)
        self.assertEqual(code, "workflow-routing-slip-tampered")

    def test_untrusted_issuer_refused(self):
        slip = self._slip()
        code = self._code_of(wr.verify_slip, slip,
                             [ed25519.publickey(self.seed_evil).hex()],
                             self.at)
        self.assertEqual(code, "workflow-routing-slip-tampered")

    def test_expired_slip_refused(self):
        slip = self._slip()
        code = self._code_of(wr.verify_slip, slip, self.trust,
                             self.at + 7200)
        self.assertEqual(code, "approval-request-expired")

    def test_malformed_slip_shape_refused(self):
        code = self._code_of(wr.verify_slip, {"not": "a slip"},
                             self.trust, self.at)
        self.assertEqual(code, "decision-code-malformed")

    # -- contracts -------------------------------------------------------

    def test_ed25519_contract_pinned(self):
        pub_b = ed25519.publickey(self.seed_b)
        self.assertIs(ed25519.verify(pub_b, b"m",
                                     ed25519.sign(self.seed_b, b"m")), True)
        self.assertIs(ed25519.verify(pub_b, b"m",
                                     ed25519.sign(self.seed_evil, b"m")),
                      False)

    def test_new_codes_pinned_as_literals(self):
        import gov.decision_codes as dc
        src = open(dc.__file__, encoding="utf-8").read()
        self.assertIn('"code": \'workflow-routing-slip-tampered\'', src)
        self.assertIn('"code": \'workflow-routing-rights-widened\'', src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
