"""Unit tests for gov/session_binding.py (wave-269 session-bound
presentation lane).

Covers the EHD/bind_body primitives, transcript hashing, the Session
present/verify round trip, every refusal code, the verifier-provider
indirection (including the key-remote skip-with-attribution path), and
the lane-local taxonomy pin. Deterministic; explicit ``now`` only.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import session_binding as sb  # noqa: E402
from gov import signing  # noqa: E402
from gov import decision_codes  # noqa: E402

NOW = 1780000000.0
TTL = 600.0
NONCE = b"unit-test-nonce"
ARTIFACT = hashlib.sha256(b"artifact").hexdigest()

TAXONOMY_PIN = 2035 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)




def _keys(n=2):
    return [signing.Ed25519Signer(bytes([i] * 32)) for i in range(n)]


def _provider(signer):
    return sb.StaticVerifierProvider(
        {signer.key_id: signing.Ed25519Verifier(signer.public_key)})


def _pair(signer, sid="s1"):
    provider = _provider(signer)
    kw = dict(signer=signer, ephemeral_pubkey=signer.public_key,
              verifier_provider=provider)
    presenter = sb.Session(session_id=sid, **kw)
    verifier = sb.Session(session_id=sid, **kw)
    for role, payload in (("agent", b"m1"), ("tool", b"m2")):
        presenter.append_record(role, payload)
        verifier.append_record(role, payload)
    return presenter, verifier


class PrimitivesTest(unittest.TestCase):
    def test_ehd_is_sha256(self):
        expect = hashlib.sha256(NONCE + _keys(1)[0].public_key).hexdigest()
        self.assertEqual(sb.ehd(NONCE, _keys(1)[0].public_key), expect)

    def test_ehd_rejects_bad_inputs(self):
        with self.assertRaises(sb.SessionBindingError):
            sb.ehd(b"", _keys(1)[0].public_key)
        with self.assertRaises(sb.SessionBindingError):
            sb.ehd(NONCE, b"short")

    def test_bind_body_domain_separation(self):
        b1 = sb.bind_body(sb.INFO_RECEIPT_PRESENT, b"X", b"Y")
        b2 = sb.bind_body(sb.INFO_APPROVAL_PRESENT, b"X", b"Y")
        self.assertNotEqual(b1, b2)
        self.assertEqual(b1, sb.bind_body(sb.INFO_RECEIPT_PRESENT,
                                         b"X", b"Y"))

    def test_bind_body_framing_unambiguous(self):
        # ("AB","C") vs ("A","BC") must differ: length prefixes.
        self.assertNotEqual(sb.bind_body(sb.INFO_RECEIPT_PRESENT,
                                         b"AB", b"C"),
                            sb.bind_body(sb.INFO_RECEIPT_PRESENT,
                                         b"A", b"BC"))

    def test_bind_body_rejects_unknown_info(self):
        with self.assertRaises(sb.SessionBindingError) as ctx:
            sb.bind_body("evil.v1", b"X", b"Y")
        self.assertEqual(ctx.exception.code,
                         "sessbind-domain-mismatch")

    def test_transcript_order_matters(self):
        t1, t2 = sb.Transcript(), sb.Transcript()
        t1.append("a", b"1")
        t1.append("b", b"2")
        t2.append("b", b"2")
        t2.append("a", b"1")
        self.assertNotEqual(t1.digest(), t2.digest())

    def test_transcript_rejects_bad_records(self):
        t = sb.Transcript()
        with self.assertRaises(sb.SessionBindingError):
            t.append("", b"x")
        with self.assertRaises(sb.SessionBindingError):
            t.append("a", "not-bytes")


class RoundTripTest(unittest.TestCase):
    def test_valid_presentation_verifies(self):
        signer = _keys(1)[0]
        presenter, verifier = _pair(signer)
        pres = presenter.present(ARTIFACT, NOW, TTL, NONCE)
        v = verifier.verify_presentation(pres, ARTIFACT, NOW)
        self.assertTrue(v["ok"])
        self.assertEqual(v["code"], "sessbind-ok")

    def test_each_info_domain_round_trips(self):
        signer = _keys(1)[0]
        for info in (sb.INFO_RECEIPT_PRESENT, sb.INFO_APPROVAL_PRESENT,
                     sb.INFO_DECISION_PRESENT):
            presenter, verifier = _pair(signer)
            pres = presenter.present(ARTIFACT, NOW, TTL, NONCE, info=info)
            v = verifier.verify_presentation(pres, ARTIFACT, NOW,
                                             info=info)
            self.assertTrue(v["ok"], info)

    def test_deterministic(self):
        signer = _keys(1)[0]
        p1, _ = _pair(signer)
        p2, _ = _pair(signer)
        self.assertEqual(p1.present(ARTIFACT, NOW, TTL, NONCE),
                         p2.present(ARTIFACT, NOW, TTL, NONCE))

    def test_verify_never_raises(self):
        signer = _keys(1)[0]
        _, verifier = _pair(signer)
        for bad in (None, "str", [], {"format": "nope"}):
            v = verifier.verify_presentation(bad, ARTIFACT, NOW)
            self.assertFalse(v["ok"])


class RefusalCodesTest(unittest.TestCase):
    def _v(self, mutate=None, **kw):
        signer = _keys(1)[0]
        presenter, verifier = _pair(signer)
        pres = presenter.present(ARTIFACT, NOW, TTL, NONCE)
        if mutate:
            mutate(pres)
        info = kw.get("info", sb.INFO_RECEIPT_PRESENT)
        return verifier.verify_presentation(pres, ARTIFACT,
                                            kw.get("now", NOW), info=info)

    def test_cross_session_replay_refused(self):
        signer = _keys(1)[0]
        provider = _provider(signer)
        kw = dict(signer=signer, ephemeral_pubkey=signer.public_key,
                  verifier_provider=provider)
        presenter = sb.Session(session_id="s", **kw)
        verifier = sb.Session(session_id="s", **kw)
        presenter.append_record("a", b"1")
        verifier.append_record("a", b"2")
        pres = presenter.present(ARTIFACT, NOW, TTL, NONCE)
        v = verifier.verify_presentation(pres, ARTIFACT, NOW)
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "sessbind-transcript-mismatch")

    def test_domain_confusion_refused(self):
        v = self._v(info=sb.INFO_APPROVAL_PRESENT)
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "sessbind-domain-mismatch")

    def test_expired_refused(self):
        v = self._v(now=NOW + TTL + 1)
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "sessbind-token-expired")

    def test_not_yet_valid_refused(self):
        v = self._v(now=NOW - 1)
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "sessbind-token-expired")

    def test_signature_tamper_refused(self):
        def mutate(pres):
            sig = bytearray(bytes.fromhex(pres["signature"]))
            sig[0] ^= 0xFF
            pres["signature"] = bytes(sig).hex()
        v = self._v(mutate=mutate)
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "sessbind-signature-invalid")

    def test_ehd_transplant_refused(self):
        keys = _keys(2)
        provider = _provider(keys[0])
        presenter = sb.Session(session_id="s", signer=keys[0],
                               ephemeral_pubkey=keys[1].public_key,
                               verifier_provider=provider)
        verifier = sb.Session(session_id="s", signer=keys[0],
                              ephemeral_pubkey=keys[0].public_key,
                              verifier_provider=provider)
        presenter.append_record("a", b"1")
        verifier.append_record("a", b"1")
        pres = presenter.present(ARTIFACT, NOW, TTL, NONCE)
        v = verifier.verify_presentation(pres, ARTIFACT, NOW)
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "sessbind-ehd-mismatch")

    def test_unknown_key_fails_closed(self):
        signer = _keys(1)[0]
        empty = sb.StaticVerifierProvider({})
        kw = dict(signer=signer, ephemeral_pubkey=signer.public_key,
                  verifier_provider=empty)
        presenter = sb.Session(session_id="s", **kw)
        verifier = sb.Session(session_id="s", **kw)
        presenter.append_record("a", b"1")
        verifier.append_record("a", b"1")
        pres = presenter.present(ARTIFACT, NOW, TTL, NONCE)
        v = verifier.verify_presentation(pres, ARTIFACT, NOW)
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "sessbind-verifier-misconfigured")

    def test_malformed_never_raises(self):
        signer = _keys(1)[0]
        _, verifier = _pair(signer)
        for bad in (None, 42, "x", {"format": "wrong"}, {}):
            v = verifier.verify_presentation(bad, ARTIFACT, NOW)
            self.assertFalse(v["ok"])
            self.assertEqual(v["code"], "sessbind-malformed")

    def test_present_rejects_bad_inputs(self):
        signer = _keys(1)[0]
        presenter, _ = _pair(signer)
        with self.assertRaises(sb.SessionBindingError):
            presenter.present("not-hex", NOW, TTL, NONCE)
        with self.assertRaises(sb.SessionBindingError):
            presenter.present(ARTIFACT, NOW, 0, NONCE)
        with self.assertRaises(sb.SessionBindingError):
            presenter.present(ARTIFACT, NOW, TTL, b"")
        with self.assertRaises(sb.SessionBindingError):
            presenter.present(ARTIFACT, NOW, TTL, NONCE,
                              info="evil.v1")


class KeyRemoteVerifierTest(unittest.TestCase):
    def test_ehd_skipped_with_attribution(self):
        signer = _keys(1)[0]

        class RemoteVerifier(signing.Verifier):
            def __init__(self, inner):
                self._inner = inner

            @property
            def key_id(self):
                return self._inner.key_id

            def verify(self, data, sig):
                return self._inner.verify(data, sig)

        inner = signing.Ed25519Verifier(signer.public_key)
        self.assertFalse(hasattr(RemoteVerifier(inner), "public_key"))
        provider = sb.StaticVerifierProvider(
            {signer.key_id: RemoteVerifier(inner)})
        kw = dict(signer=signer, ephemeral_pubkey=signer.public_key,
                  verifier_provider=provider)
        presenter = sb.Session(session_id="s", **kw)
        verifier = sb.Session(session_id="s", **kw)
        presenter.append_record("a", b"1")
        verifier.append_record("a", b"1")
        pres = presenter.present(ARTIFACT, NOW, TTL, NONCE)
        v = verifier.verify_presentation(pres, ARTIFACT, NOW)
        self.assertTrue(v["ok"])
        self.assertTrue(any("ehd-check-skipped" in c
                            for c in v["checked"]))


class RegistryTest(unittest.TestCase):
    def test_lane_pin(self):
        self.assertEqual(len(decision_codes.TAXONOMY), TAXONOMY_PIN)

    def test_codes_registered(self):
        for code in sb.CODES:
            self.assertIn(code, decision_codes.TAXONOMY)

    def test_no_duplicate_literals(self):
        import re
        with open(os.path.join(os.path.dirname(__file__), "..",
                               "gov", "decision_codes.py")) as fh:
            src = fh.read()
        codes = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]',
                           src)
        self.assertEqual(len(codes), len(set(codes)))
        self.assertEqual(len(codes), TAXONOMY_PIN)


if __name__ == "__main__":
    unittest.main()
