"""Unit tests for the W245-4 adversarial-registry extension of
gov.registry_acceptance (additive; accept_package contract unchanged).
"""

import base64
import hashlib
import unittest

from gov import decision_codes
from gov import ed25519 as ed
from gov import registry_acceptance as ra

_SEEDS = [bytes([0xD0 + i]) * 32 for i in range(3)]
_PUBS = [ed.publickey(s) for s in _SEEDS]
_NOW = 1727731200 + 900


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _manifest(payload, seed=0):
    body = ra.canonical_manifest_bytes(payload)
    return {"payload": payload,
            "signatures": [{"key": _b64(_PUBS[seed]),
                            "sig": _b64(ed.sign(_SEEDS[seed], body))}]}


def _payload(name, version, data, **extra):
    p = {"name": name, "version": version,
         "digest": hashlib.sha256(data).hexdigest(),
         "issued_at": _NOW - 100, "valid_until": _NOW + 3600}
    p.update(extra)
    return p


def _policy(**over):
    policy = {"threshold": 1,
              "trusted_keys": [_b64(p) for p in _PUBS]}
    policy.update(over)
    return policy


def _revoke(*pubs):
    return {"revoked_keys": [_b64(p) for p in pubs]}


class CompromisedKeyTest(unittest.TestCase):
    def test_compromised_signer_refused_despite_valid_signature(self):
        data = b"unit-pkg"
        manifest = _manifest(_payload("u", "1", data))
        with self.assertRaises(ra.RegistryAcceptanceError) as ctx:
            ra.accept_from_adversarial_registry(
                manifest, data, _policy(), _NOW, _revoke(_PUBS[0]))
        self.assertEqual(ctx.exception.code, "package-signer-compromised")

    def test_unrevoked_signer_accepted(self):
        data = b"unit-pkg"
        manifest = _manifest(_payload("u", "1", data))
        res = ra.accept_from_adversarial_registry(
            manifest, data, _policy(), _NOW, _revoke())
        self.assertEqual(res["verdict"], "accept")
        self.assertIn("revocation", res["adversarial_checks"])

    def test_multi_sig_one_compromised_refuses(self):
        # threshold 2, both keys trusted, one revoked: the good
        # signature cannot carry the compromised one.
        data = b"unit-pkg"
        payload = _payload("u", "1", data)
        body = ra.canonical_manifest_bytes(payload)
        sigs = [{"key": _b64(_PUBS[i]),
                 "sig": _b64(ed.sign(_SEEDS[i], body))} for i in (0, 1)]
        manifest = {"payload": payload, "signatures": sigs}
        with self.assertRaises(ra.RegistryAcceptanceError) as ctx:
            ra.accept_from_adversarial_registry(
                manifest, data, _policy(threshold=2), _NOW,
                _revoke(_PUBS[1]))
        self.assertEqual(ctx.exception.code, "package-signer-compromised")


class NameTrustTest(unittest.TestCase):
    def test_name_trust_policy_refused_before_signature_work(self):
        # Even a manifest whose signature is garbage must refuse on
        # the POLICY first: name trust is a configuration error, not
        # a package verdict.
        manifest = {"payload": _payload("u", "1", b"x"),
                    "signatures": []}
        with self.assertRaises(ra.RegistryAcceptanceError) as ctx:
            ra.accept_from_adversarial_registry(
                manifest, b"x", _policy(trusted_accounts=["admin"]),
                _NOW, _revoke())
        self.assertEqual(ctx.exception.code,
                         "package-identity-name-untrusted")

    def test_publisher_field_is_display_only(self):
        data = b"unit-pkg"
        payload = _payload("u", "1", data, publisher="admin")
        res = ra.accept_from_adversarial_registry(
            _manifest(payload), data, _policy(), _NOW, _revoke())
        self.assertEqual(res["verdict"], "accept")


class FirstSeenTest(unittest.TestCase):
    def test_pin_recorded_then_substitution_refused(self):
        store = {}
        data1 = b"unit-pkg-v1"
        m1 = _manifest(_payload("u", "1", data1))
        ra.accept_from_adversarial_registry(
            m1, data1, _policy(), _NOW, _revoke(), first_seen=store)
        self.assertEqual(store[("u", "1")],
                         hashlib.sha256(data1).hexdigest())
        data2 = b"unit-pkg-v1-changed"
        m2 = _manifest(_payload("u", "1", data2))
        with self.assertRaises(ra.RegistryAcceptanceError) as ctx:
            ra.accept_from_adversarial_registry(
                m2, data2, _policy(), _NOW, _revoke(), first_seen=store)
        self.assertEqual(ctx.exception.code,
                         "package-digest-first-seen-mismatch")
        # The refusal pins nothing: the original digest still stands.
        self.assertEqual(store[("u", "1")],
                         hashlib.sha256(data1).hexdigest())

    def test_none_store_skips_pinning(self):
        data = b"unit-pkg"
        manifest = _manifest(_payload("u", "1", data))
        res = ra.accept_from_adversarial_registry(
            manifest, data, _policy(), _NOW, _revoke(), first_seen=None)
        self.assertEqual(res["verdict"], "accept")

    def test_non_dict_store_malformed(self):
        data = b"unit-pkg"
        manifest = _manifest(_payload("u", "1", data))
        with self.assertRaises(ra.RegistryAcceptanceError) as ctx:
            ra.accept_from_adversarial_registry(
                manifest, data, _policy(), _NOW, _revoke(),
                first_seen=[("u", "1")])
        self.assertEqual(ctx.exception.code, "verifier-input-malformed")


class BaseContractRegressionTest(unittest.TestCase):
    def test_accept_package_unchanged(self):
        # The lane must not alter the base entry point: valid package
        # accepts, bad signature still refuses package-signature-invalid.
        data = b"unit-pkg"
        manifest = _manifest(_payload("u", "1", data))
        res = ra.accept_package(manifest, data, _policy(), _NOW)
        self.assertEqual(res["verdict"], "accept")
        self.assertNotIn("adversarial_checks", res)
        rogue = bytes([0xFE]) * 32
        rogue_pub = ed.publickey(rogue)
        payload = _payload("u", "1", data)
        body = ra.canonical_manifest_bytes(payload)
        bad = {"payload": payload,
               "signatures": [{"key": _b64(rogue_pub),
                               "sig": _b64(ed.sign(rogue, body))}]}
        with self.assertRaises(ra.RegistryAcceptanceError) as ctx:
            ra.accept_package(bad, data, _policy(), _NOW)
        self.assertEqual(ctx.exception.code, "package-signature-invalid")


class TaxonomyMappingTest(unittest.TestCase):
    def test_new_codes_mapped(self):
        for code, domain in (("package-signer-compromised",
                              "registry-acceptance"),
                             ("package-identity-name-untrusted",
                              "registry-acceptance"),
                             ("package-digest-first-seen-mismatch",
                              "registry-acceptance")):
            rec = decision_codes.code_for(code)
            self.assertEqual(rec["domain"], domain)
            self.assertEqual(rec["code"], code)

    def test_taxonomy_pin(self):
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes),
        # additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(decision_codes.TAXONOMY), 2058)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
