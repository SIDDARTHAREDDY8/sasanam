"""Unit tests for gov/measurement_policy.py (wave-214 lane C)."""

import unittest

from gov import measurement_policy as mp
from gov import ed25519 as _ed

NOW = 1785000000
DA = "a" * 64
DB = "b" * 64


def _issuer():
    seed = _ed.generate_seed()
    return seed, _ed.publickey(seed)


def _body(**over):
    kw = dict(policy_name="gpu-fleet", version=1,
              required_measurements=[("launch_image", DA)],
              not_before=NOW - 3600, not_after=NOW + 3600,
              signer_kid="policy-ops")
    kw.update(over)
    return mp.make_policy_body(**kw)


def _registry_for(body, seed, pub, now=NOW):
    reg = mp.MeasurementPolicyRegistry(pub)
    reg.activate(body, mp.sign_policy(seed, body), now=now)
    return reg


class TestShape(unittest.TestCase):
    def test_unknown_fields_refused(self):
        body = _body()
        body["extra"] = "nope"
        with self.assertRaises(mp.MeasurementPolicyError) as cm:
            mp.validate_policy_body(body)
        self.assertEqual(cm.exception.code, "policy-body-malformed")

    def test_empty_measurements_refused(self):
        with self.assertRaises(mp.MeasurementPolicyError):
            _body(required_measurements=[])

    def test_duplicate_components_refused(self):
        with self.assertRaises(mp.MeasurementPolicyError):
            _body(required_measurements=[("c", DA), ("c", DB)])

    def test_bad_digest_refused(self):
        with self.assertRaises(mp.MeasurementPolicyError):
            _body(required_measurements=[("c", "zz")])

    def test_inverted_window_refused(self):
        with self.assertRaises(mp.MeasurementPolicyError):
            _body(not_before=NOW + 100, not_after=NOW)

    def test_bad_version_refused(self):
        for bad in (0, -1, True, "1"):
            with self.assertRaises(mp.MeasurementPolicyError):
                _body(version=bad)

    def test_wide_digest_accepted(self):
        # 48-byte measurements (SEV-SNP MEASUREMENT) are 96 hex.
        body = _body(required_measurements=[("measurement", "f" * 96)])
        self.assertEqual(body["required_measurements"][0]["expected_digest"],
                         "f" * 96)

    def test_canonical_bytes_stable(self):
        a = _body()
        b = mp.make_policy_body(policy_name="gpu-fleet", version=1,
                                required_measurements=[("launch_image", DA)],
                                not_before=NOW - 3600, not_after=NOW + 3600,
                                signer_kid="policy-ops")
        self.assertEqual(mp.canonical_policy_json(a),
                         mp.canonical_policy_json(b))


class TestRegistry(unittest.TestCase):
    def test_activate_and_evaluate_ok(self):
        seed, pub = _issuer()
        reg = _registry_for(_body(), seed, pub)
        self.assertEqual(reg.evaluate("gpu-fleet", 1,
                                      {"launch_image": DA}, now=NOW),
                         ("gpu-fleet", 1))
        self.assertEqual(reg.known_policies(), [("gpu-fleet", 1)])

    def test_unknown_policy(self):
        _, pub = _issuer()
        reg = mp.MeasurementPolicyRegistry(pub)
        with self.assertRaises(mp.MeasurementPolicyError) as cm:
            reg.evaluate("nope", 1, {}, now=NOW)
        self.assertEqual(cm.exception.code, "policy-unknown")

    def test_downgrade_refused(self):
        seed, pub = _issuer()
        reg = mp.MeasurementPolicyRegistry(pub)
        reg.activate(_body(version=2), mp.sign_policy(seed, _body(version=2)),
                     now=NOW)
        with self.assertRaises(mp.MeasurementPolicyError) as cm:
            reg.activate(_body(version=1),
                         mp.sign_policy(seed, _body(version=1)), now=NOW)
        self.assertEqual(cm.exception.code, "policy-version-downgrade")

    def test_stale_eval_refused(self):
        seed, pub = _issuer()
        body = _body(not_after=NOW + 10)
        reg = _registry_for(body, seed, pub)
        with self.assertRaises(mp.MeasurementPolicyError) as cm:
            reg.evaluate("gpu-fleet", 1, {"launch_image": DA},
                         now=NOW + 11)
        self.assertEqual(cm.exception.code, "policy-stale")

    def test_future_activation_refused(self):
        seed, pub = _issuer()
        body = _body(not_before=NOW + 100, not_after=NOW + 7200)
        reg = mp.MeasurementPolicyRegistry(pub)
        with self.assertRaises(mp.MeasurementPolicyError) as cm:
            reg.activate(body, mp.sign_policy(seed, body), now=NOW)
        self.assertEqual(cm.exception.code, "policy-not-yet-valid")

    def test_expired_activation_refused(self):
        seed, pub = _issuer()
        body = _body(not_before=NOW - 7200, not_after=NOW - 1)
        reg = mp.MeasurementPolicyRegistry(pub)
        with self.assertRaises(mp.MeasurementPolicyError) as cm:
            reg.activate(body, mp.sign_policy(seed, body), now=NOW)
        self.assertEqual(cm.exception.code, "policy-stale")

    def test_wrong_key_activation_refused(self):
        rogue, _ = _issuer()
        _, pub = _issuer()
        reg = mp.MeasurementPolicyRegistry(pub)
        with self.assertRaises(mp.MeasurementPolicyError) as cm:
            reg.activate(_body(), mp.sign_policy(rogue, _body()), now=NOW)
        self.assertEqual(cm.exception.code, "policy-signature-invalid")

    def test_bad_issuer_key_rejected(self):
        with self.assertRaises(mp.MeasurementPolicyError):
            mp.MeasurementPolicyRegistry(b"short")

    def test_swap_after_activation_refused(self):
        seed, pub = _issuer()
        reg = _registry_for(_body(), seed, pub)
        reg._policies[("gpu-fleet", 1)]["body"]["version"] = 99
        with self.assertRaises(mp.MeasurementPolicyError) as cm:
            reg.evaluate("gpu-fleet", 1, {"launch_image": DA}, now=NOW)
        self.assertEqual(cm.exception.code, "policy-signature-invalid")

    def test_multi_policy_names_independent(self):
        seed, pub = _issuer()
        reg = mp.MeasurementPolicyRegistry(pub)
        b1 = _body(policy_name="a", version=1)
        b2 = _body(policy_name="b", version=5)
        reg.activate(b1, mp.sign_policy(seed, b1), now=NOW)
        reg.activate(b2, mp.sign_policy(seed, b2), now=NOW)
        self.assertEqual(reg.known_policies(), [("a", 1), ("b", 5)])

    def test_activation_failures_bounded(self):
        _, pub = _issuer()
        reg = mp.MeasurementPolicyRegistry(pub)
        for _ in range(70):
            try:
                reg.activate(_body(), b"short-sig", now=NOW)
            except mp.MeasurementPolicyError:
                pass
        self.assertEqual(len(reg.activation_failures), 64)


if __name__ == "__main__":
    unittest.main()
