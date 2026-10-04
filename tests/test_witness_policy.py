"""Unit tests for gov/witness_policy.py (wave-322 lane 2).

Covers the signed witness-policy artifact: seal/verify round trip,
threshold enforcement, unknown-field refusal (shape drift), version
monotonicity (TUF N+1), validity-window filtering, verifier_inputs
shape, vkey keyID recomputation, seal-time fail-closed, canonical
bytes, MUST-ignore rotation composition, known-signer forgery refusal,
and trust-anchor authority. Deterministic (fixed seeds); stdlib only.
"""

import copy
import unittest

from gov import witness_policy as WP
from gov import checkpoint_note as CN
from gov.signing import Ed25519Signer

_SEED_OP = bytes(range(32))
_SEED_W1 = bytes([255 - i for i in range(32)])
_SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
_SEED_W3 = bytes([(i * 13 + 5) % 256 for i in range(32)])
_SEED_P1 = bytes([(i * 3 + 11) % 256 for i in range(32)])
_SEED_P2 = bytes([(i * 5 + 17) % 256 for i in range(32)])

_NOW = 1798765432


def _signer(seed):
    return Ed25519Signer(seed)


def _vkey(name, signer):
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519,
                               signer.public_key),
        CN.SIG_TYPE_ED25519, signer.public_key)


def _wit(name, seed, **kw):
    d = {"name": name, "vkey": _vkey(name, _signer(seed)),
         "operator": "%s-op" % name, "contact": "%s@x.org" % name,
         "not_before": _NOW - 100000, "not_after": _NOW + 100000,
         "status": "usable"}
    d.update(kw)
    return d


def _signer_entry(signer):
    pub = signer.public_key
    return {"key_id": pub.hex(), "public_key": pub.hex()}


def _body(**kw):
    d = {
        "schema": "witness-policy/v1",
        "policy_id": "sasanam-witness-policy",
        "version": 1,
        "issued_at": _NOW - 1000,
        "expires_at": _NOW + 86400,
        "threshold": 2,
        "log": {"name": "op", "vkey": _vkey("op", _signer(_SEED_OP))},
        "witnesses": [_wit("w1", _SEED_W1), _wit("w2", _SEED_W2),
                      _wit("w3", _SEED_W3)],
        "policy_signers": [_signer_entry(_signer(_SEED_P1)),
                           _signer_entry(_signer(_SEED_P2))],
        "policy_threshold": 2,
        "max_checkpoint_staleness_seconds": 10800,
    }
    d.update(kw)
    return d


def _anchor():
    return {"policy_signers": [_signer_entry(_signer(_SEED_P1)),
                               _signer_entry(_signer(_SEED_P2))],
            "policy_threshold": 2}


def _seal(body, seeds=(_SEED_P1, _SEED_P2)):
    return WP.seal_policy(body, [_signer(s) for s in seeds])


class TestSealVerify(unittest.TestCase):
    def test_roundtrip_returns_verified_values(self):
        doc = _seal(_body())
        got = WP.verify_policy_document(doc, _anchor(), _NOW)
        self.assertIsInstance(got, dict)
        self.assertEqual(got["version"], 1)
        self.assertEqual(got["threshold"], 2)
        self.assertEqual(len(got["witnesses"]), 3)
        # No parse internals leak into the verified values.
        self.assertNotIn("parsed", got["witnesses"][0])

    def test_seal_refuses_malformed_body(self):
        body = _body()
        body["threshold"] = 0
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            _seal(body)
        self.assertEqual(ctx.exception.code,
                         "witness-policy-threshold-invalid")

    def test_seal_dedupes_repeat_signer(self):
        doc = _seal(_body(), seeds=(_SEED_P1, _SEED_P1))
        self.assertEqual(len(doc["signatures"]), 1)

    def test_canonical_bytes_stable(self):
        b1 = WP.canonical_policy_bytes({"b": 2, "a": 1})
        b2 = WP.canonical_policy_bytes({"a": 1, "b": 2})
        self.assertEqual(b1, b2)
        self.assertEqual(b1, b'{"a":1,"b":2}')

    def test_future_issued_at_accepted(self):
        # Pre-provisioned successor: not refused as not-yet-valid.
        body = _body(issued_at=_NOW + 3600, expires_at=_NOW + 90000)
        doc = _seal(body)
        got = WP.verify_policy_document(doc, _anchor(), _NOW)
        self.assertEqual(got["version"], 1)

    def test_bool_version_refused(self):
        doc = _seal(_body())
        doc["policy"]["version"] = True
        with self.assertRaises(WP.WitnessPolicyError):
            WP.verify_policy_document(doc, _anchor(), _NOW)


class TestThresholds(unittest.TestCase):
    def test_below_threshold_unmet(self):
        doc = _seal(_body(), seeds=(_SEED_P1,))
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.verify_policy_document(doc, _anchor(), _NOW)
        self.assertEqual(ctx.exception.code,
                         "witness-policy-threshold-unmet")

    def test_anchor_threshold_rules_not_document(self):
        # Document claims threshold 1, anchor demands 2: 1 signature
        # must NOT verify.
        body = _body(policy_threshold=1)
        doc = _seal(body, seeds=(_SEED_P1,))
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.verify_policy_document(doc, _anchor(), _NOW)
        self.assertEqual(ctx.exception.code,
                         "witness-policy-threshold-unmet")


class TestShapeDrift(unittest.TestCase):
    def test_unknown_top_level_field(self):
        doc = _seal(_body())
        doc["policy"]["zzz"] = 1
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.verify_policy_document(doc, _anchor(), _NOW)
        self.assertEqual(ctx.exception.code,
                         "witness-policy-unknown-field")

    def test_unknown_envelope_field(self):
        doc = _seal(_body())
        doc["extra"] = []
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.verify_policy_document(doc, _anchor(), _NOW)
        self.assertEqual(ctx.exception.code,
                         "witness-policy-unknown-field")

    def test_unknown_witness_field(self):
        doc = _seal(_body())
        doc["policy"]["witnesses"][0]["zzz"] = 1
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.verify_policy_document(doc, _anchor(), _NOW)
        self.assertEqual(ctx.exception.code,
                         "witness-policy-unknown-field")

    def test_vkey_name_mismatch(self):
        doc = _seal(_body())
        doc["policy"]["witnesses"][0]["name"] = "renamed"
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.verify_policy_document(doc, _anchor(), _NOW)
        self.assertEqual(ctx.exception.code, "witness-policy-malformed")


class TestUpdates(unittest.TestCase):
    def _v(self, version):
        return WP.verify_policy_document(_seal(_body(version=version)),
                                         _anchor(), _NOW)

    def test_monotonic_update_ok(self):
        old = self._v(1)
        new_doc = _seal(_body(version=2))
        new = WP.check_policy_update(old, new_doc, _anchor(), _NOW)
        self.assertEqual(new["version"], 2)

    def test_same_version_rollback(self):
        old = self._v(2)
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.check_policy_update(old, _seal(_body(version=2)),
                                   _anchor(), _NOW)
        self.assertEqual(ctx.exception.code,
                         "witness-policy-version-rollback")

    def test_older_version_rollback(self):
        old = self._v(5)
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.check_policy_update(old, _seal(_body(version=4)),
                                   _anchor(), _NOW)
        self.assertEqual(ctx.exception.code,
                         "witness-policy-version-rollback")

    def test_policy_id_mismatch(self):
        old = self._v(1)
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.check_policy_update(old, _seal(_body(version=2,
                                                    policy_id="other")),
                                   _anchor(), _NOW)
        self.assertEqual(ctx.exception.code, "witness-policy-id-mismatch")

    def test_authorized_key_drop(self):
        old = self._v(1)
        witnesses = [_wit("w1", _SEED_W1), _wit("w2", _SEED_W2)]
        new = WP.check_policy_update(old, _seal(_body(version=2,
                                                      witnesses=witnesses)),
                                     _anchor(), _NOW)
        self.assertEqual({w["name"] for w in new["witnesses"]},
                         {"w1", "w2"})

    def test_drop_below_threshold_refused(self):
        old = self._v(1)
        witnesses = [_wit("w1", _SEED_W1)]
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.check_policy_update(old, _seal(_body(version=2,
                                                      witnesses=witnesses)),
                                   _anchor(), _NOW)
        # The new document's own shape check fires (k=2 > n=1).
        self.assertEqual(ctx.exception.code,
                         "witness-policy-threshold-invalid")


class TestActiveWitnesses(unittest.TestCase):
    def test_window_and_status_filtering(self):
        policy = WP.verify_policy_document(_seal(_body()), _anchor(), _NOW)
        act = WP.active_witnesses(policy, _NOW)
        self.assertEqual(set(act), {"w1", "w2", "w3"})

        body = _body(witnesses=[
            _wit("w1", _SEED_W1),
            _wit("w2", _SEED_W2, not_after=_NOW - 10),  # expired window
            _wit("w3", _SEED_W3, status="retired"),      # retired
        ])
        policy = WP.verify_policy_document(_seal(body), _anchor(), _NOW)
        act = WP.active_witnesses(policy, _NOW)
        self.assertEqual(set(act), {"w1"})

    def test_readonly_not_counted(self):
        body = _body(witnesses=[
            _wit("w1", _SEED_W1, status="readonly"),
            _wit("w2", _SEED_W2),
            _wit("w3", _SEED_W3),
        ])
        policy = WP.verify_policy_document(_seal(body), _anchor(), _NOW)
        self.assertEqual(set(WP.active_witnesses(policy, _NOW)),
                         {"w2", "w3"})


class TestVerifierInputs(unittest.TestCase):
    def test_shape(self):
        policy = WP.verify_policy_document(_seal(_body()), _anchor(), _NOW)
        vin = WP.verifier_inputs(policy, _NOW)
        self.assertEqual(set(vin),
                         {"operator_vkeys", "witness_vkeys", "quorum_k",
                          "policy_id", "policy_version"})
        self.assertEqual(vin["quorum_k"], 2)
        self.assertEqual(vin["policy_version"], 1)
        self.assertEqual(len(vin["operator_vkeys"]), 1)
        self.assertEqual(set(vin["witness_vkeys"]), {"w1", "w2", "w3"})


class TestUntrustedInput(unittest.TestCase):
    """verifier_inputs / active_witnesses must raise CODED refusals on
    junk input -- never a raw KeyError/TypeError (standards review)."""

    def test_verifier_inputs_junk_dict(self):
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.verifier_inputs({"log": {"vkey": "x"}, "witnesses": []},
                               _NOW)
        self.assertEqual(ctx.exception.code, "witness-policy-malformed")

    def test_verifier_inputs_not_a_dict(self):
        with self.assertRaises(WP.WitnessPolicyError):
            WP.verifier_inputs(["not", "a", "dict"], _NOW)

    def test_active_witnesses_unhashable_name(self):
        policy = {"witnesses": [{"name": ["unhashable"], "vkey": "v",
                                 "status": "usable",
                                 "not_before": _NOW - 1,
                                 "not_after": _NOW + 1}]}
        # Must not raise TypeError: unhashable name is skipped, coded
        # path stays clean.
        self.assertEqual(WP.active_witnesses(policy, _NOW), {})

    def test_active_witnesses_not_a_dict(self):
        with self.assertRaises(WP.WitnessPolicyError):
            WP.active_witnesses(None, _NOW)


class TestRotationComposition(unittest.TestCase):
    def test_unknown_keyid_ignored(self):
        doc = _seal(_body())
        doc["signatures"].append({"keyid": "ff" * 32, "sig": "00" * 64})
        got = WP.verify_policy_document(doc, _anchor(), _NOW)
        self.assertEqual(got["version"], 1)

    def test_known_signer_bad_sig_is_forgery_signal(self):
        doc = _seal(_body())
        raw = bytearray(bytes.fromhex(doc["signatures"][0]["sig"]))
        raw[0] ^= 1
        doc["signatures"][0]["sig"] = bytes(raw).hex()
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.verify_policy_document(doc, _anchor(), _NOW)
        self.assertEqual(ctx.exception.code,
                         "witness-policy-signature-invalid")

    def test_duplicate_key_material_refused(self):
        # Same 32-byte key, two names, consistent vkey names.
        doc = _seal(_body())
        doc["policy"]["witnesses"][1] = {
            "name": "w1b",
            "vkey": _vkey("w1b", _signer(_SEED_W1)),
            "operator": "op", "contact": "c@x.org",
            "not_before": _NOW - 100000, "not_after": _NOW + 100000,
            "status": "usable"}
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.verify_policy_document(doc, _anchor(), _NOW)
        self.assertEqual(ctx.exception.code,
                         "witness-policy-duplicate-witness")


class TestTrustAnchorUnknownField(unittest.TestCase):
    """Wave-325 residual 3: the trust anchor fails closed on unknown
    fields, consistent with every other policy level."""

    def test_unknown_field_refused(self):
        doc = _seal(_body())
        bad = _anchor()
        bad["note"] = "a stray field that must not be silently ignored"
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.verify_policy_document(doc, bad, _NOW)
        self.assertEqual(ctx.exception.code,
                         "witness-policy-unknown-field")

    def test_clean_anchor_still_verifies(self):
        doc = _seal(_body())
        got = WP.verify_policy_document(doc, _anchor(), _NOW)
        self.assertEqual(got["version"], 1)
        self.assertEqual(len(got["policy_signers"]), 2)


if __name__ == "__main__":
    unittest.main()
