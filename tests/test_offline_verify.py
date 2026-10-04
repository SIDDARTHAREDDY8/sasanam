"""Unit tests for gov/offline_verify (wave-324 lane 2).

Focused unit tests for the auditor's offline evidence verifier:
report shape, code constants, digest determinism, package parsing,
trust-root validation, the policy-window check, and the
crash-never-succeeds contract. Attack coverage lives in
evals/w324_offver_probes.py.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import offline_verify as OV  # noqa: E402


class TestCodes(unittest.TestCase):
    def test_all_codes_registered(self):
        from gov import decision_codes as DC
        codes = [
            OV.OFFLINE_VERIFY_MALFORMED,
            OV.OFFLINE_VERIFY_VERSION_SKEW,
            OV.OFFLINE_VERIFY_TRUST_ROOT_INVALID,
            OV.OFFLINE_VERIFY_BUNDLE_DIGEST_MISMATCH,
            OV.OFFLINE_VERIFY_WITNESS_LAYER_MISSING,
            OV.OFFLINE_VERIFY_CHAIN_BROKEN,
            OV.OFFLINE_VERIFY_MONOTONICITY,
            OV.OFFLINE_VERIFY_CONTAINMENT,
            OV.OFFLINE_VERIFY_ENTRY_SIGNATURE_INVALID,
            OV.OFFLINE_VERIFY_REDACTION_UNDISCLOSED,
            OV.OFFLINE_VERIFY_ANCHOR_INVALID,
            OV.OFFLINE_VERIFY_ANCHOR_UNSUPPORTED,
            OV.OFFLINE_VERIFY_ANCHOR_KEY_MISMATCH,
            OV.OFFLINE_VERIFY_WITNESS_LAYER_INVALID,
            OV.OFFLINE_VERIFY_POLICY_WINDOW,
            OV.OFFLINE_VERIFY_INTERNAL,
        ]
        self.assertEqual(len(codes), 16)
        self.assertEqual(len(set(codes)), 16)
        for c in codes:
            self.assertIn(c, DC.TAXONOMY, "unregistered: %s" % c)
            self.assertTrue(c.startswith("offline-verify-"), c)

    def test_error_carries_code_and_checks(self):
        err = OV.OfflineVerifyError("offline-verify-malformed", "x",
                                    checks=[{"step": "s"}])
        self.assertEqual(err.code, "offline-verify-malformed")
        self.assertEqual(err.checks, [{"step": "s"}])
        self.assertIn("[offline-verify-malformed]", str(err))


class TestDigest(unittest.TestCase):
    def test_digest_deterministic_and_excludes_attachments(self):
        d = tempfile.mkdtemp(prefix="offver-ut-")
        with open(os.path.join(d, "a.json"), "w") as f:
            f.write('{"a":1}')
        with open(os.path.join(d, "b.json"), "w") as f:
            f.write('{"b":2}')
        d1 = OV.bundle_digest_for_dir(d)
        # Post-export attachments must not move the digest.
        with open(os.path.join(d, "witness_layer.json"), "w") as f:
            f.write('{"x":1}')
        with open(os.path.join(d, "BUNDLE_DIGEST.sha256"), "w") as f:
            f.write(d1 + "\n")
        with open(os.path.join(d, "small_carrier.bin"), "wb") as f:
            f.write(b"\x00\x01")
        d2 = OV.bundle_digest_for_dir(d)
        self.assertEqual(d1, d2)
        self.assertRegex(d1, r"^[0-9a-f]{64}$")

    def test_digest_order_independent(self):
        d1 = tempfile.mkdtemp(prefix="offver-ut1-")
        d2 = tempfile.mkdtemp(prefix="offver-ut2-")
        for d, names in ((d1, ["a", "b", "c"]), (d2, ["c", "a", "b"])):
            for n in names:
                with open(os.path.join(d, n), "w") as f:
                    f.write(n)
        self.assertEqual(OV.bundle_digest_for_dir(d1),
                         OV.bundle_digest_for_dir(d2))

    def test_digest_missing_dir(self):
        # Pure function: a missing/empty dir digests as empty input
        # (no crash). The verifier's package-parse step rejects missing
        # directories separately.
        d = OV.bundle_digest_for_dir("/nonexistent/offver-dir")
        self.assertEqual(d, hashlib.sha256().hexdigest())


class TestTrustRoot(unittest.TestCase):
    def _root(self, **kw):
        r = {"policy_signers": [
                {"key_id": "ab" * 32, "public_key": "cd" * 32}],
             "policy_threshold": 1,
             "anchor_log_pubkey_hex": "ef" * 32}
        r.update(kw)
        return r

    def _expect(self, root, code):
        v = OV._Verifier(root, 1)
        with self.assertRaises(OV.OfflineVerifyError) as cm:
            v.pin_trust_root()
        self.assertEqual(cm.exception.code, code)

    def test_rejects_non_mapping(self):
        self._expect(None, "offline-verify-trust-root-invalid")

    def test_rejects_empty_signers(self):
        self._expect(self._root(policy_signers=[]),
                     "offline-verify-trust-root-invalid")

    def test_rejects_bad_threshold(self):
        self._expect(self._root(policy_threshold=0),
                     "offline-verify-trust-root-invalid")
        self._expect(self._root(policy_threshold=5),
                     "offline-verify-trust-root-invalid")

    def test_rejects_missing_anchor_key(self):
        r = self._root()
        del r["anchor_log_pubkey_hex"]
        self._expect(r, "offline-verify-trust-root-invalid")

    def test_rejects_malformed_anchor_key(self):
        self._expect(self._root(anchor_log_pubkey_hex="zzz"),
                     "offline-verify-trust-root-invalid")

    def test_accepts_and_records_digest(self):
        v = OV._Verifier(self._root(), 1)
        v.pin_trust_root()
        self.assertRegex(v.facts["trust_root_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(v.checks[0]["step"], "trust-root-pin")
        self.assertEqual(v.checks[0]["result"], "pass")


class TestPackageParse(unittest.TestCase):
    def _root(self):
        return {"policy_signers": [
                    {"key_id": "ab" * 32, "public_key": "cd" * 32}],
                "policy_threshold": 1,
                "anchor_log_pubkey_hex": "ef" * 32}

    def _expect_code(self, pkg, code, **kw):
        with self.assertRaises(OV.OfflineVerifyError) as cm:
            OV.verify_evidence_bundle(pkg, self._root(), **kw)
        self.assertEqual(cm.exception.code, code)

    def test_rejects_none_input(self):
        self._expect_code(None, "offline-verify-malformed", now=1)

    def test_rejects_truncated_json(self):
        self._expect_code(b'{"format": "sasanam', "offline-verify-malformed",
                          now=1)

    def test_rejects_version_skew(self):
        pkg = {"format": "sasanam-offline-evidence-package/v2",
               "files": {}, "witness_layer": {}}
        self._expect_code(json.dumps(pkg).encode(),
                          "offline-verify-version-skew", now=1)

    def test_rejects_unknown_field(self):
        pkg = {"format": "sasanam-offline-evidence-package/v1",
               "files": {"a": "b"}, "witness_layer": {}, "evil": 1}
        self._expect_code(json.dumps(pkg).encode(),
                          "offline-verify-malformed", now=1)

    def test_rejects_missing_now(self):
        with self.assertRaises(OV.OfflineVerifyError) as cm:
            OV.verify_evidence_bundle(b"{}", self._root())
        self.assertEqual(cm.exception.code, "offline-verify-malformed")

    def test_rejects_bad_carrier_b64(self):
        pkg = {"format": "sasanam-offline-evidence-package/v1",
               "files": {"a": "b"}, "witness_layer": {},
               "small_carrier_b64": "!!!"}
        self._expect_code(json.dumps(pkg).encode(),
                          "offline-verify-malformed", now=1)

    def test_never_returns_bare_bool(self):
        # Even the narrowest failure is a typed exception, never False.
        try:
            OV.verify_evidence_bundle(b"nope", self._root(), now=1)
        except OV.OfflineVerifyError as exc:
            self.assertTrue(exc.code.startswith("offline-verify-"))
            self.assertIsInstance(exc.checks, list)
        else:
            self.fail("expected OfflineVerifyError")


class TestReportShape(unittest.TestCase):
    def test_report_keys(self):
        v = OV._Verifier({}, 123)
        v._pass("demo-step", "ok")
        r = v._report("pass")
        self.assertEqual(r["format"],
                         "sasanam-offline-verification-report/v1")
        self.assertEqual(r["verdict"], "pass")
        self.assertEqual(r["now"], 123)
        self.assertEqual(r["checks"],
                         [{"step": "demo-step", "result": "pass",
                           "detail": "ok"}])
        self.assertIn("facts", r)

    def test_fail_report_attached_to_error(self):
        v = OV._Verifier({}, 1)
        v._pass("a", "ok")
        with self.assertRaises(OV.OfflineVerifyError) as cm:
            v._fail("offline-verify-malformed", "b-step", "bad")
        err = cm.exception
        self.assertEqual(len(err.checks), 2)
        self.assertEqual(err.checks[1]["result"], "fail")
        self.assertEqual(err.checks[1]["code"], "offline-verify-malformed")
        self.assertEqual(err.report["verdict"], "fail")


if __name__ == "__main__":
    unittest.main()
