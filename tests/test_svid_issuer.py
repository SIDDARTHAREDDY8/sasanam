"""Unit tests for gov.svid_issuer (wave-259 lane 3, identity-mesh).

Short-lived SPIFFE-style workload identity documents from a local TEST
issuer: issuance profiles as data, profile-capped TTLs in minutes,
pinned trust roots (parallel roots for rotation), default-deny mesh
admission over verified SVIDs, and the F224 _validate_now contract on
the verify read path.

Pin test discipline (wave-145 lesson): sentences with raw similarity
inside the derived band are flaky through record_intent -- here the
analogue is expiry boundaries: the boundary pin uses
similarity_countermand-style exact-now assertions, not fuzzy windows.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes as dc
from gov import ed25519 as ed
from gov import svid_issuer as sv

_SEED = bytes(range(32))
_OTHER_SEED = bytes([255 - b for b in range(32)])
_PUBKEY = "ab" * 32
_TD = "example.org"
NOW = 1700000000.0


def _issuer(**kw):
    kw.setdefault("issuer_seed", _SEED)
    return sv.TestSvidIssuer(**kw)


def _verifier(**kw):
    kw.setdefault("trust_roots", {"test-issuer-1": ed.publickey(_SEED)})
    kw.setdefault("trust_domain", _TD)
    return sv.SvidVerifier(**kw)


def _doc(**over):
    doc = _issuer().issue("spiffe://example.org/agent/a", _PUBKEY,
                          ttl_minutes=5, now=NOW)
    doc.update(over)
    return doc


class IssueTests(unittest.TestCase):
    def test_round_trip(self):
        doc = _issuer().issue("spiffe://example.org/agent/a", _PUBKEY,
                              ttl_minutes=5, now=NOW)
        claims = _verifier().verify(doc, now=NOW)
        self.assertEqual(claims["spiffe_id"], "spiffe://example.org/agent/a")
        self.assertEqual(claims["trust_domain"], "example.org")
        self.assertEqual(claims["public_key"], _PUBKEY)
        self.assertEqual(claims["issued_at"], int(NOW))
        self.assertEqual(claims["expires_at"], int(NOW) + 300)

    def test_ttl_is_minutes_and_capped(self):
        # workload profile max is 30 minutes: 30 OK, 31 refused.
        doc = _issuer().issue("spiffe://example.org/agent/a", _PUBKEY,
                              ttl_minutes=30, now=NOW)
        self.assertEqual(doc["expires_at"] - doc["issued_at"], 1800)
        with self.assertRaises(sv.SvidError) as ctx:
            _issuer().issue("spiffe://example.org/agent/a", _PUBKEY,
                            ttl_minutes=31, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-ttl-stretched")

    def test_ttl_unbounded_refused(self):
        for bad in (None, 0, -5, True, "30", 5.0):
            with self.assertRaises(sv.SvidError) as ctx:
                _issuer().issue("spiffe://example.org/agent/a", _PUBKEY,
                                ttl_minutes=bad, now=NOW)
            self.assertEqual(ctx.exception.code, "svid-ttl-unbounded",
                             "ttl=%r" % (bad,))

    def test_profiles_are_data(self):
        policy = {"tiny": {"max_ttl_minutes": 2,
                           "usages": ("workload-auth",)}}
        iss = _issuer(policy=policy)
        doc = iss.issue("spiffe://example.org/agent/a", _PUBKEY,
                        ttl_minutes=2, profile="tiny", now=NOW)
        self.assertEqual(doc["usage"], ["workload-auth"])
        with self.assertRaises(sv.SvidError) as ctx:
            iss.issue("spiffe://example.org/agent/a", _PUBKEY,
                      ttl_minutes=3, profile="tiny", now=NOW)
        self.assertEqual(ctx.exception.code, "svid-ttl-stretched")
        with self.assertRaises(sv.SvidError) as ctx:
            iss.issue("spiffe://example.org/agent/a", _PUBKEY,
                      ttl_minutes=1, profile="nope", now=NOW)
        self.assertEqual(ctx.exception.code, "svid-malformed")

    def test_malformed_identity_refused(self):
        for bad_id in ("", "not-a-uri", "spiffe://", "spiffe:///p",
                       "https://example.org/a", "spiffe://ex ample/a"):
            with self.assertRaises(sv.SvidError) as ctx:
                _issuer().issue(bad_id, _PUBKEY, ttl_minutes=5, now=NOW)
            self.assertEqual(ctx.exception.code,
                             "svid-identity-malformed", bad_id)
        for bad_key in ("", "zz" * 32, "AB" * 32, "ab" * 31):
            with self.assertRaises(sv.SvidError) as ctx:
                _issuer().issue("spiffe://example.org/agent/a", bad_key,
                                ttl_minutes=5, now=NOW)
            self.assertEqual(ctx.exception.code,
                             "svid-identity-malformed", bad_key)

    def test_id_normalized_lowercase(self):
        doc = _issuer().issue("spiffe://EXAMPLE.ORG/Agent/A", _PUBKEY,
                              ttl_minutes=5, now=NOW)
        self.assertEqual(doc["spiffe_id"], "spiffe://example.org/agent/a")
        claims = _verifier().verify(doc, now=NOW)
        self.assertEqual(claims["spiffe_id"], "spiffe://example.org/agent/a")

    def test_now_validated_first(self):
        # F234 (F228 shape): a non-numeric `now` refuses svid-malformed
        # before any identity/profile/TTL refusal decision.
        with self.assertRaises(sv.SvidError) as ctx:
            _issuer().issue("not-a-spiffe-id", _PUBKEY, ttl_minutes=5,
                            now="yesterday")
        self.assertEqual(ctx.exception.code, "svid-malformed")
        with self.assertRaises(sv.SvidError) as ctx:
            _issuer().issue("spiffe://example.org/agent/a", _PUBKEY,
                            ttl_minutes=0, now="yesterday")
        self.assertEqual(ctx.exception.code, "svid-malformed")
        with self.assertRaises(sv.SvidError) as ctx:
            _issuer().issue("spiffe://example.org/agent/a", _PUBKEY,
                            ttl_minutes=5, profile="nope",
                            now="yesterday")
        self.assertEqual(ctx.exception.code, "svid-malformed")


class VerifyTests(unittest.TestCase):
    def test_expired(self):
        doc = _doc()
        with self.assertRaises(sv.SvidError) as ctx:
            _verifier().verify(doc, now=NOW + 300.0)
        self.assertEqual(ctx.exception.code, "svid-expired")
        # Just before expiry still verifies (exact boundary pin).
        _verifier().verify(doc, now=NOW + 299.0)

    def test_cross_trust_domain(self):
        doc = _issuer().issue("spiffe://other.example/agent/a", _PUBKEY,
                              ttl_minutes=5, now=NOW)
        with self.assertRaises(sv.SvidError) as ctx:
            _verifier().verify(doc, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-trust-domain-mismatch")

    def test_lookalike_domain_refused(self):
        doc = _issuer().issue("spiffe://example.org.evil/agent/a",
                              _PUBKEY, ttl_minutes=5, now=NOW)
        with self.assertRaises(sv.SvidError) as ctx:
            _verifier().verify(doc, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-trust-domain-mismatch")

    def test_forged_signature(self):
        doc = _doc()
        sig = bytearray(bytes.fromhex(doc["issuer_signature"]))
        sig[7] ^= 0x01
        doc["issuer_signature"] = bytes(sig).hex()
        with self.assertRaises(sv.SvidError) as ctx:
            _verifier().verify(doc, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-signature-invalid")

    def test_signature_transplant(self):
        a = _doc()
        b = _issuer().issue("spiffe://example.org/agent/b", "cd" * 32,
                            ttl_minutes=5, now=NOW)
        b["issuer_signature"] = a["issuer_signature"]
        with self.assertRaises(sv.SvidError) as ctx:
            _verifier().verify(b, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-signature-invalid")

    def test_field_tamper(self):
        doc = _doc()
        doc["public_key"] = "00" * 32
        with self.assertRaises(sv.SvidError) as ctx:
            _verifier().verify(doc, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-signature-invalid")

    def test_issuer_not_pinned(self):
        rogue = _issuer(issuer_seed=_OTHER_SEED, key_id="rogue")
        doc = rogue.issue("spiffe://example.org/agent/a", _PUBKEY,
                          ttl_minutes=5, now=NOW)
        with self.assertRaises(sv.SvidError) as ctx:
            _verifier().verify(doc, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-issuer-unknown")

    def test_wrong_trust_root_key(self):
        doc = _doc()
        v = sv.SvidVerifier({"test-issuer-1": ed.publickey(_OTHER_SEED)},
                            trust_domain=_TD)
        with self.assertRaises(sv.SvidError) as ctx:
            v.verify(doc, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-signature-invalid")

    def test_missing(self):
        with self.assertRaises(sv.SvidError) as ctx:
            _verifier().verify(None, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-missing")

    def test_malformed(self):
        for bad in ("nope", 42, {"spiffe_id": "x"}):
            with self.assertRaises(sv.SvidError) as ctx:
                _verifier().verify(bad, now=NOW)
            self.assertEqual(ctx.exception.code, "svid-malformed",
                             repr(bad)[:40])

    def test_validate_now_contract(self):
        # F224 contract: None -> wall clock; bool/non-numeric/NaN/inf
        # refuse svid-malformed; a past numeric now is honored.
        import math
        doc = _doc()
        for bad_now in (True, "now", float("nan"), float("inf"), [1]):
            with self.assertRaises(sv.SvidError) as ctx:
                _verifier().verify(doc, now=bad_now)
            self.assertEqual(ctx.exception.code, "svid-malformed",
                             repr(bad_now))
        # Past now honored: a doc issued at NOW verifies at NOW - 10.
        claims = _verifier().verify(doc, now=NOW - 10.0)
        self.assertEqual(claims["spiffe_id"], "spiffe://example.org/agent/a")

    def test_now_validated_first(self):
        # F234 (F228 shape): `now` is validated before ANY refusal
        # decision in verify() -- a non-numeric `now` refuses
        # svid-malformed regardless of SVID validity.
        good = _doc()
        bad_sig = dict(good)
        bad_sig["issuer_signature"] = "00" * 64
        for bad_svid in (None, bad_sig, {"spiffe_id": "x"}):
            with self.assertRaises(sv.SvidError) as ctx:
                _verifier().verify(bad_svid, now="yesterday")
            self.assertEqual(ctx.exception.code, "svid-malformed",
                             repr(bad_svid)[:40])
        with self.assertRaises(sv.SvidError) as ctx:
            _verifier().verify(good, now="yesterday")
        self.assertEqual(ctx.exception.code, "svid-malformed")

    def test_expected_usage_enforced(self):
        # F233: the SVID's SIGNED usage list must cover expected_usage.
        mesh = _issuer().issue("spiffe://example.org/agent/a", _PUBKEY,
                               ttl_minutes=5, profile="mesh-control",
                               now=NOW)
        self.assertEqual(mesh["usage"], ["mesh-control"])
        with self.assertRaises(sv.SvidError) as ctx:
            _verifier().verify(mesh, now=NOW,
                               expected_usage="workload-auth")
        self.assertEqual(ctx.exception.code, "svid-usage-mismatch")
        # Matching usage verifies; omitted expected_usage keeps the
        # old behavior (usage returned in claims, unenforced).
        claims = _verifier().verify(mesh, now=NOW,
                                    expected_usage="mesh-control")
        self.assertEqual(claims["usage"], ["mesh-control"])
        claims = _verifier().verify(mesh, now=NOW)
        self.assertEqual(claims["usage"], ["mesh-control"])
        # A malformed expected_usage is a caller error.
        for bad in (123, "", ["mesh-control"]):
            with self.assertRaises(sv.SvidError) as ctx:
                _verifier().verify(mesh, now=NOW, expected_usage=bad)
            self.assertEqual(ctx.exception.code, "svid-malformed",
                             repr(bad))

    def test_usage_tamper_dies_at_signature(self):
        # F233: the usage check runs over the signed body only -- a
        # tampered usage never reaches the usage comparison as a pass.
        doc = _doc()
        doc["usage"] = ["mesh-control"]
        with self.assertRaises(sv.SvidError) as ctx:
            _verifier().verify(doc, now=NOW,
                               expected_usage="mesh-control")
        self.assertEqual(ctx.exception.code, "svid-signature-invalid")

    def test_multi_root_rotation(self):
        doc = _issuer(issuer_seed=_OTHER_SEED,
                      key_id="test-issuer-2").issue(
            "spiffe://example.org/agent/a", _PUBKEY, ttl_minutes=5,
            now=NOW)
        v = sv.SvidVerifier(
            {"test-issuer-1": ed.publickey(_SEED),
             "test-issuer-2": ed.publickey(_OTHER_SEED)},
            trust_domain=_TD)
        claims = v.verify(doc, now=NOW)
        self.assertEqual(claims["issuer_key_id"], "test-issuer-2")


class MeshControlTests(unittest.TestCase):
    def _gate(self, allow):
        return sv.MeshControl(_verifier(), {"allow": allow})

    def test_default_deny(self):
        gate = self._gate(["spiffe://example.org/ops/"])
        with self.assertRaises(sv.SvidError) as ctx:
            gate.admit(_doc(), now=NOW)
        self.assertEqual(ctx.exception.code, "svid-acl-denied")

    def test_allowlist_prefix_admits(self):
        gate = self._gate(["spiffe://example.org/agent/"])
        self.assertEqual(gate.admit(_doc(), now=NOW),
                         "spiffe://example.org/agent/a")

    def test_empty_allow_denies_all(self):
        gate = self._gate([])
        with self.assertRaises(sv.SvidError) as ctx:
            gate.admit(_doc(), now=NOW)
        self.assertEqual(ctx.exception.code, "svid-acl-denied")

    def test_verify_runs_before_acl(self):
        gate = self._gate(["spiffe://example.org/agent/"])
        with self.assertRaises(sv.SvidError) as ctx:
            gate.admit(_doc(), now=NOW + 900.0)
        self.assertEqual(ctx.exception.code, "svid-expired")
        with self.assertRaises(sv.SvidError) as ctx:
            gate.admit(None, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-missing")

    def test_no_downgrade_seam(self):
        gate = self._gate(["spiffe://example.org/agent/"])
        suspicious = [a for a in dir(gate)
                      if "skip" in a.lower() or "bypass" in a.lower()
                      or "insecure" in a.lower() or "downgrade" in a.lower()]
        self.assertEqual(suspicious, [])

    def test_prefix_confusion_refused(self):
        # "spiffe://example.org/agent" must not admit
        # "spiffe://example.org/agents-evil/x": segment-boundary
        # matching, not raw startswith.
        gate = self._gate(["spiffe://example.org/agent"])
        evil = _issuer().issue("spiffe://example.org/agents-evil/x",
                               _PUBKEY, ttl_minutes=5, now=NOW)
        with self.assertRaises(sv.SvidError) as ctx:
            gate.admit(evil, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-acl-denied")
        # Exact-ID entry and bare-domain entry still behave.
        exact = sv.MeshControl(_verifier(),
                               {"allow": ["spiffe://example.org/agent/a"]})
        self.assertEqual(exact.admit(_doc(), now=NOW),
                         "spiffe://example.org/agent/a")
        with self.assertRaises(sv.SvidError):
            exact.admit(_issuer().issue("spiffe://example.org/agent/b",
                                        _PUBKEY, ttl_minutes=5, now=NOW),
                        now=NOW)

    def test_bad_policy_refused(self):
        for bad_policy in ({"allow": "spiffe://x/"}, {"allow": [""]},
                           {"allow": ["http://example.org/"]}, [],
                           {"allow": [None]}):
            with self.assertRaises(sv.SvidError):
                sv.MeshControl(_verifier(), bad_policy)
        # An absent allowlist is not malformed: it is default-deny.
        gate = sv.MeshControl(_verifier(), {})
        with self.assertRaises(sv.SvidError) as ctx:
            gate.admit(_doc(), now=NOW)
        self.assertEqual(ctx.exception.code, "svid-acl-denied")

    def test_policy_usages_binding(self):
        # F233 (admit seam): a policy-bound usage list refuses a
        # verified SVID whose signed usage is outside it, with
        # svid-acl-denied; a covered usage still admits.
        gate = sv.MeshControl(
            _verifier(),
            {"allow": ["spiffe://example.org/agent/"],
             "usages": ["workload-auth"]})
        mesh = _issuer().issue("spiffe://example.org/agent/a", _PUBKEY,
                               ttl_minutes=5, profile="mesh-control",
                               now=NOW)
        with self.assertRaises(sv.SvidError) as ctx:
            gate.admit(mesh, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-acl-denied")
        self.assertEqual(gate.admit(_doc(), now=NOW),
                         "spiffe://example.org/agent/a")

    def test_admit_expected_usage_passthrough(self):
        # F233: per-call expected_usage threads through admit() to the
        # verifier seam (svid-usage-mismatch on mismatch).
        gate = self._gate(["spiffe://example.org/agent/"])
        mesh = _issuer().issue("spiffe://example.org/agent/a", _PUBKEY,
                               ttl_minutes=5, profile="mesh-control",
                               now=NOW)
        with self.assertRaises(sv.SvidError) as ctx:
            gate.admit(mesh, now=NOW, expected_usage="workload-auth")
        self.assertEqual(ctx.exception.code, "svid-usage-mismatch")
        self.assertEqual(
            gate.admit(mesh, now=NOW, expected_usage="mesh-control"),
            "spiffe://example.org/agent/a")

    def test_bad_usages_policy_refused(self):
        for bad_usages in ("workload-auth", [], [""], [None],
                           ["workload-auth", 42]):
            with self.assertRaises(sv.SvidError):
                sv.MeshControl(_verifier(),
                               {"allow": ["spiffe://example.org/"],
                                "usages": bad_usages})

    def test_now_validated_first_at_admit(self):
        # F234: admit() validates `now` via verify() before any
        # refusal decision.
        gate = self._gate(["spiffe://example.org/agent/"])
        bad_sig = _doc()
        bad_sig["issuer_signature"] = "00" * 64
        with self.assertRaises(sv.SvidError) as ctx:
            gate.admit(bad_sig, now="yesterday")
        self.assertEqual(ctx.exception.code, "svid-malformed")


class TaxonomyPinTests(unittest.TestCase):
    def test_pin(self):
        # Wave-259 lane 3: pin 1080 -> 1074 (+10 svid-* codes).
        # Wave-261 lane B (F233): pin 1092 -> 1093 (+1 svid-usage-mismatch).
        self.assertEqual(len(dc.TAXONOMY), 1621)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).
        for code in ("svid-missing", "svid-malformed",
                     "svid-identity-malformed", "svid-ttl-unbounded",
                     "svid-ttl-stretched", "svid-trust-domain-mismatch",
                     "svid-usage-mismatch", "svid-issuer-unknown",
                     "svid-signature-invalid",
                     "svid-expired", "svid-acl-denied"):
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "svid")
            self.assertEqual(dc.TAXONOMY[code]["code"], code)


if __name__ == "__main__":
    unittest.main()
