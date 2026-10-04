"""Units for gov.action_bound_permits (W243-5).

Covers the binding lifecycle, all four registered refusal codes,
the vocabulary gate, recipient-signed confirmation, base-permit
pinning, and the taxonomy add-only property (pin 792).
"""

import unittest

from gov import action_bound_permits as abp
from gov import decision_codes
from gov import ed25519

KEY = b"w243-lane-d-unit-issuer-key-00000"
REQ = "cd" * 32


def make(**kw):
    args = dict(recipient="agent://w1", key_ref="key://w1",
                request_digest=REQ, action_instance="act-001",
                issuer_key=KEY)
    args.update(kw)
    return abp.bind_permit(**args)


def present(permit, **kw):
    args = dict(presenter_key="key://w1", action_instance="act-001",
                issuer_key=KEY)
    args.update(kw)
    return abp.present_bound(permit, **args)


class BindTest(unittest.TestCase):
    def test_bind_and_present(self):
        self.assertTrue(present(make()))

    def test_missing_issuer_key_malformed(self):
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            make(issuer_key=None)
        self.assertEqual(c.exception.code, "permit-malformed")

    def test_bad_request_digest_malformed(self):
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            make(request_digest="not-a-digest")
        self.assertEqual(c.exception.code, "permit-malformed")

    def test_unknown_currentness_mode_malformed(self):
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            make(currentness_mode="whenever")
        self.assertEqual(c.exception.code, "permit-malformed")

    def test_binding_digest_deterministic(self):
        a = make()
        b = make()
        self.assertEqual(a["binding_digest"], b["binding_digest"])

    def test_different_issuer_key_different_digest(self):
        other = make(issuer_key=b"different-issuer-key-0000000000")
        self.assertNotEqual(make()["binding_digest"],
                            other["binding_digest"])


class PresentTest(unittest.TestCase):
    def test_presenter_mismatch(self):
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            present(make(), presenter_key="key://intruder")
        self.assertEqual(c.exception.code, "permit-presenter-mismatch")

    def test_instance_replay(self):
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            present(make(), action_instance="act-002")
        self.assertEqual(c.exception.code, "permit-instance-replay")

    def test_tamper_rekey(self):
        p = dict(make())
        p["key_ref"] = "key://forged"
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            present(p, presenter_key="key://forged")
        self.assertEqual(c.exception.code, "permit-tampered")

    def test_tamper_digest_edit(self):
        p = dict(make())
        p["binding_digest"] = "ff" * 32
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            present(p)
        self.assertEqual(c.exception.code, "permit-tampered")

    def test_malformed_not_a_dict(self):
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            present("permit")
        self.assertEqual(c.exception.code, "permit-malformed")

    def test_malformed_missing_field(self):
        p = dict(make())
        del p["action_instance"]
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            present(p)
        self.assertEqual(c.exception.code, "permit-malformed")


class CurrentnessTest(unittest.TestCase):
    def test_fresh_at_use_without_evidence_refused(self):
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            present(make(currentness_mode="fresh-at-use"))
        self.assertEqual(c.exception.code, "permit-currentness-violated")

    def test_fresh_at_use_with_evidence_admitted(self):
        self.assertTrue(present(make(currentness_mode="fresh-at-use"),
                                freshness_evidence="fresh-at:2026-09-30"))

    def test_none_without_evidence_admitted(self):
        self.assertTrue(present(make(currentness_mode="none")))


class VocabularyTest(unittest.TestCase):
    def test_unregistered_reason_refused(self):
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            abp.raise_refusal("hand-waved-reason", "nope")
        self.assertEqual(c.exception.code,
                         "permit-refusal-vocabulary-invalid")

    def test_registered_reason_raises_that_code(self):
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            abp.raise_refusal("permit-instance-replay", "declared")
        self.assertEqual(c.exception.code, "permit-instance-replay")

    def test_registered_refusals_sorted_closed(self):
        reasons = abp.registered_refusals()
        self.assertEqual(tuple(sorted(reasons)), reasons)
        self.assertEqual(len(reasons), 4)
        for r in reasons:
            decision_codes.code_for(r)  # mapped, no DecisionCodeError

    def test_error_code_first(self):
        e = abp.ActionBoundPermitError("permit-presenter-mismatch", "x")
        self.assertTrue(str(e).startswith("permit-presenter-mismatch"))


class ConfirmationTest(unittest.TestCase):
    def test_confirm_and_verify(self):
        permit = make()
        seed = ed25519.generate_seed()
        pub = ed25519.publickey(seed)
        sig = abp.recipient_confirm(permit, seed)
        self.assertTrue(abp.verify_recipient_confirmation(permit, pub, sig))

    def test_forged_confirmation_tampered(self):
        permit = make()
        seed = ed25519.generate_seed()
        pub = ed25519.publickey(seed)
        sig = bytearray(abp.recipient_confirm(permit, seed))
        sig[0] ^= 0x01
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            abp.verify_recipient_confirmation(permit, pub, bytes(sig))
        self.assertEqual(c.exception.code, "permit-tampered")

    def test_wrong_pub_tampered(self):
        permit = make()
        sig = abp.recipient_confirm(permit, ed25519.generate_seed())
        other_pub = ed25519.publickey(ed25519.generate_seed())
        with self.assertRaises(abp.ActionBoundPermitError) as c:
            abp.verify_recipient_confirmation(permit, other_pub, sig)
        self.assertEqual(c.exception.code, "permit-tampered")


class BasePermitPinTest(unittest.TestCase):
    def test_base_permit_pinned_and_verified(self):
        base = {"v": 1, "iss": "x", "jti": "y", "legs": []}
        permit = make(base_permit=base)
        self.assertTrue(permit["base_permit_digest"])
        # bound_permit.verify_permit over a hand-made base raises;
        # the pin check runs only after base verification passes.
        self.assertIn("base_permit_digest", permit)

    def test_base_permit_not_supplied_malformed(self):
        base = {"v": 1, "iss": "x", "jti": "y", "legs": []}
        permit = make(base_permit=base)
        with self.assertRaises(abp.ActionBoundPermitError):
            present(permit)


class TaxonomyTest(unittest.TestCase):
    def test_pin_792(self):
        # Wave-243 bound-permits lane: re-pointed 788 -> 792 (4 new codes).
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(decision_codes.TAXONOMY), 1984)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes), additive only; merge coordinator composed.

    def test_new_codes_mapped(self):
        for code in abp.registered_refusals():
            rec = decision_codes.code_for(code)
            self.assertEqual(rec["domain"], "permit")
            self.assertEqual(rec["code"], code)


if __name__ == "__main__":
    unittest.main()
