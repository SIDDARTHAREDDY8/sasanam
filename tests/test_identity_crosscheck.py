"""Unit tests for gov.identity_crosscheck (wave-246 lane 10, W246-10).

PTV attested-agent-identity cross-check: a peer's claimed identity is
graded against an attestation and a deployment-supplied anchor.
Unverified anchor yields asserted-only, never attested.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import identity_crosscheck as ic
from gov import decision_codes as dc
from gov import ed25519 as _ed25519


def _anchor(key_id="anchor-1", principal="agent-7"):
    seed = _ed25519.generate_seed()
    pub = _ed25519.publickey(seed)
    anchor = {"keys": {key_id: pub}}
    att = ic.make_attestation(seed, key_id=key_id,
                              attested_principal=principal)
    return anchor, att


class VerdictTest(unittest.TestCase):
    def test_attested(self):
        anchor, att = _anchor()
        r = ic.check({"principal": "agent-7"}, att, anchor)
        self.assertEqual(r["verdict"], "attested")
        self.assertIsNone(r["code"])

    def test_no_attestation_asserted_only(self):
        anchor, _att = _anchor()
        r = ic.check({"principal": "agent-7"}, None, anchor)
        self.assertEqual(r["verdict"], "asserted-only")
        self.assertIsNone(r["code"])

    def test_no_anchor_asserted_only_never_attested(self):
        _anchor_map, att = _anchor()
        for anchor in (None, {}, {"keys": {}}, {"keys": "nope"},
                       "blob"):
            r = ic.check({"principal": "agent-7"}, att, anchor)
            self.assertEqual(r["verdict"], "asserted-only",
                             "anchor %r must never attest" % (anchor,))

    def test_claim_mismatch_refused(self):
        anchor, att = _anchor(principal="agent-7")
        r = ic.check({"principal": "agent-9"}, att, anchor)
        self.assertEqual(r["verdict"], "refused")
        self.assertEqual(r["code"], "identity-claim-mismatch")

    def test_unknown_key_id_refused(self):
        anchor, _att = _anchor()
        seed = _ed25519.generate_seed()
        att = ic.make_attestation(seed, key_id="anchor-9",
                                  attested_principal="agent-7")
        r = ic.check({"principal": "agent-7"}, att, anchor)
        self.assertEqual(r["verdict"], "refused")
        self.assertEqual(r["code"], "identity-anchor-unknown")

    def test_forged_signature_refused(self):
        anchor, att = _anchor()
        bad = dict(att)
        sig = bytearray(bad["signature"])
        sig[-1] ^= 0xFF
        bad["signature"] = bytes(sig)
        r = ic.check({"principal": "agent-7"}, bad, anchor)
        self.assertEqual(r["verdict"], "refused")
        self.assertEqual(r["code"], "identity-attestation-unverifiable")

    def test_malformed_attestation_refused(self):
        anchor, _att = _anchor()
        for bad in ({}, {"attested_principal": "agent-7"},
                    {"attested_principal": "agent-7", "key_id": "a",
                     "signature": b"\x00"},
                    "blob", 42):
            r = ic.check({"principal": "agent-7"}, bad, anchor)
            self.assertEqual(r["verdict"], "refused", "input %r" % (bad,))
            self.assertEqual(r["code"], "identity-attestation-malformed")

    def test_malformed_claim_refused(self):
        anchor, att = _anchor()
        for bad_claim in (None, "agent-7", {}, {"principal": ""},
                          {"principal": 7}):
            r = ic.check(bad_claim, att, anchor)
            self.assertEqual(r["verdict"], "refused",
                             "claim %r" % (bad_claim,))

    def test_malformed_anchor_key_refused(self):
        _anchor_map, att = _anchor()
        anchor = {"keys": {"anchor-1": b"short"}}
        r = ic.check({"principal": "agent-7"}, att, anchor)
        self.assertEqual(r["verdict"], "refused")
        self.assertEqual(r["code"], "identity-anchor-unknown")

    def test_verify_contract_pinned(self):
        # gov.ed25519.verify returns True/False and never raises; the
        # check requires ``is True`` (wave-243 lesson). Pin the contract
        # at this seam: good sig True, forged sig False.
        seed = _ed25519.generate_seed()
        pub = _ed25519.publickey(seed)
        msg = b"contract-pin"
        sig = _ed25519.sign(seed, msg)
        self.assertIs(_ed25519.verify(pub, msg, sig), True)
        bad = bytearray(sig)
        bad[0] ^= 0x01
        self.assertIs(_ed25519.verify(pub, msg, bytes(bad)), False)

    def test_make_attestation_rejects_bad_inputs(self):
        seed = _ed25519.generate_seed()
        for args in ((b"short", "k", "p"),
                     (seed, "", "p"),
                     (seed, "k", "")):
            with self.assertRaises(ValueError):
                ic.make_attestation(*args)

    def test_result_shape(self):
        anchor, att = _anchor()
        r = ic.check({"principal": "agent-7"}, att, anchor)
        self.assertEqual(set(r), {"verdict", "code", "detail"})
        self.assertIsInstance(r["detail"], str)


class TaxonomyTest(unittest.TestCase):
    def test_pin_899(self):
        # Wave-246 lane 10: 895 + 4 identity-crosscheck codes, additive
        # only, comment + assert.
        # Wave-246 merge: re-pointed lane-local pin to the composed 936 (was lane-local 899); additive only.
        # Wave-248 merge: re-pointed to 979 (938 + 41 wave-248 codes), additive only.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 2020)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.

    def test_codes_mapped(self):
        for code in ("identity-attestation-malformed",
                     "identity-anchor-unknown",
                     "identity-attestation-unverifiable",
                     "identity-claim-mismatch"):
            rec = dc.code_for(code)
            self.assertEqual(rec["code"], code)


if __name__ == "__main__":
    unittest.main()
