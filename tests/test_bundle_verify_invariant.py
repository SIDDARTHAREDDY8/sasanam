#!/usr/bin/env python3
"""Unit tests for gov/bundle_verify_invariant.py (wave-238 lane B).

Pins the witness GHSA-2v4r invariant: any failed verify sub-step
hard-fails the whole bundle verification, naming the failing check.
"""

import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import bundle_verify_invariant as bvi


def _att(**kw):
    base = {
        "policy_signatures": [
            {"identity_ok": True, "sig_ok": True, "error": None}],
        "artifacts": [
            {"path": "build/out.bin", "is_symlink": False,
             "target": None}],
        "attestation_root": "/attest",
        "edges": [
            {"edge": "build->publish",
             "shared_digests": {"sha256": "ab" * 32}}],
        "timestamps": [
            {"eku": ["1.3.6.1.5.5.7.3.8"],
             "critical": ["1.3.6.1.5.5.7.3.8"]}],
        "attestors": [
            {"type": "file",
             "instances": [{"id": "file-1", "evaluated": True}]}],
        "steps": [{"collection": "build"}],
        "collection": "build",
        "hash_comparisons": [
            {"digests_a": {"sha256": "ab" * 32},
             "digests_b": {"sha256": "ab" * 32},
             "compared_with": "sha256"}],
    }
    base.update(kw)
    return base


def _code_of(fn, *args):
    try:
        fn(*args)
    except bvi.BundleInvariantError as exc:
        return exc.code
    return None


class PolicySignatureTests(unittest.TestCase):
    def test_forged_policy_shape_refused(self):
        # GHSA-2v4r: identity matched, signature never verified.
        code = _code_of(bvi.verify_policy_signature, [
            {"identity_ok": True, "sig_ok": False,
             "error": "sig bytes garbage"},
            {"identity_ok": False, "sig_ok": True, "error": None},
        ])
        self.assertEqual(code, "verify-signature-failed")

    def test_forged_shape_refused_even_without_error_text(self):
        code = _code_of(bvi.verify_policy_signature, [
            {"identity_ok": True, "sig_ok": False, "error": None},
        ])
        self.assertEqual(code, "verify-signature-failed")

    def test_no_clean_verifier(self):
        code = _code_of(bvi.verify_policy_signature, [
            {"identity_ok": False, "sig_ok": True, "error": None},
        ])
        self.assertEqual(code, "verify-no-clean-verifier")

    def test_all_errored_attempts(self):
        code = _code_of(bvi.verify_policy_signature, [
            {"identity_ok": False, "sig_ok": False, "error": "boom"},
        ])
        self.assertEqual(code, "verify-no-clean-verifier")

    def test_clean_pass(self):
        ok, detail = bvi.verify_policy_signature(
            [{"identity_ok": True, "sig_ok": True, "error": None}])
        self.assertTrue(ok)

    def test_absent_claims_pass(self):
        ok, _ = bvi.verify_policy_signature(None)
        self.assertTrue(ok)

    def test_malformed_fails_closed(self):
        code = _code_of(bvi.verify_policy_signature, "not-a-list")
        self.assertEqual(code, "verify-signature-failed")


class SymlinkTests(unittest.TestCase):
    def test_escape_refused(self):
        code = _code_of(bvi.verify_symlink_safety, [
            {"path": "build/x", "is_symlink": True,
             "target": "../../etc/passwd"}],
            "/attest")
        self.assertEqual(code, "verify-symlink-escape")

    def test_absolute_escape_refused(self):
        code = _code_of(bvi.verify_symlink_safety, [
            {"path": "build/x", "is_symlink": True,
             "target": "/etc/passwd"}],
            "/attest")
        self.assertEqual(code, "verify-symlink-escape")

    def test_internal_symlink_passes(self):
        ok, _ = bvi.verify_symlink_safety(
            [{"path": "build/x", "is_symlink": True,
              "target": "../lib/y"}], "/attest")
        self.assertTrue(ok)

    def test_non_symlink_ignored(self):
        ok, _ = bvi.verify_symlink_safety(
            [{"path": "build/x", "is_symlink": False, "target": None}],
            "/attest")
        self.assertTrue(ok)


class FlowTests(unittest.TestCase):
    def test_empty_edge_refused(self):
        code = _code_of(bvi.verify_artifact_flow, [
            {"edge": "build->publish", "shared_digests": {}}])
        self.assertEqual(code, "verify-artifactsfrom-empty")

    def test_missing_digests_refused(self):
        code = _code_of(bvi.verify_artifact_flow,
                        [{"edge": "build->publish"}])
        self.assertEqual(code, "verify-artifactsfrom-empty")

    def test_flowing_edge_passes(self):
        ok, _ = bvi.verify_artifact_flow(
            [{"edge": "a->b", "shared_digests": {"sha256": "ab" * 32}}])
        self.assertTrue(ok)


class TimestampTests(unittest.TestCase):
    def test_noncritical_eku_refused(self):
        code = _code_of(bvi.verify_timestamp_eku, [
            {"eku": ["1.3.6.1.5.5.7.3.8"],
             "critical": []}])
        self.assertEqual(code, "verify-timestamp-eku-missing")

    def test_extra_eku_refused(self):
        code = _code_of(bvi.verify_timestamp_eku, [
            {"eku": ["1.3.6.1.5.5.7.3.8", "1.3.6.1.5.5.7.3.3"],
             "critical": ["1.3.6.1.5.5.7.3.8"]}])
        self.assertEqual(code, "verify-timestamp-eku-missing")

    def test_sole_critical_passes(self):
        ok, _ = bvi.verify_timestamp_eku([
            {"eku": ["1.3.6.1.5.5.7.3.8"],
             "critical": ["1.3.6.1.5.5.7.3.8"]}])
        self.assertTrue(ok)


class AttestorTests(unittest.TestCase):
    def test_shadowed_instance_refused(self):
        code = _code_of(bvi.verify_attestor_completeness, [
            {"type": "file",
             "instances": [{"id": "file-malicious", "evaluated": False},
                           {"id": "file-benign", "evaluated": True}]}])
        self.assertEqual(code, "verify-attestor-shadowed")

    def test_all_evaluated_passes(self):
        ok, _ = bvi.verify_attestor_completeness([
            {"type": "file",
             "instances": [{"id": "a", "evaluated": True},
                           {"id": "b", "evaluated": True}]}])
        self.assertTrue(ok)


class CollectionTests(unittest.TestCase):
    def test_empty_collection_match_refused(self):
        code = _code_of(bvi.verify_collection_binding,
                        [{"collection": ""}], "")
        self.assertEqual(code, "verify-collection-empty-match")

    def test_exact_match_passes(self):
        ok, _ = bvi.verify_collection_binding(
            [{"collection": "build"}], "build")
        self.assertTrue(ok)

    def test_mismatch_refused(self):
        code = _code_of(bvi.verify_collection_binding,
                        [{"collection": "other"}], "build")
        self.assertEqual(code, "verify-collection-empty-match")


class HashStrengthTests(unittest.TestCase):
    def test_downgrade_refused(self):
        code = _code_of(bvi.verify_hash_strength, [
            {"digests_a": {"sha1": "cd" * 20, "sha256": "ab" * 32},
             "digests_b": {"sha1": "cd" * 20, "sha256": "ab" * 32},
             "compared_with": "sha1"}])
        self.assertEqual(code, "verify-hash-downgrade")

    def test_no_stronger_available_passes(self):
        ok, _ = bvi.verify_hash_strength([
            {"digests_a": {"sha1": "cd" * 20},
             "digests_b": {"sha1": "cd" * 20},
             "compared_with": "sha1"}])
        self.assertTrue(ok)

    def test_strong_comparison_passes(self):
        ok, _ = bvi.verify_hash_strength([
            {"digests_a": {"sha256": "ab" * 32},
             "digests_b": {"sha256": "ab" * 32},
             "compared_with": "sha256"}])
        self.assertTrue(ok)


class RegistryTests(unittest.TestCase):
    def test_registry_order_and_codes(self):
        codes = [code for _name, code, _fn in bvi.INVARIANT_CHECKS]
        self.assertEqual(codes, [
            "verify-signature-failed",
            "verify-symlink-escape",
            "verify-artifactsfrom-empty",
            "verify-timestamp-eku-missing",
            "verify-attestor-shadowed",
            "verify-collection-empty-match",
            "verify-hash-downgrade",
        ])
        # Policy-signature check runs first: it is the trust root.
        self.assertEqual(bvi.INVARIANT_CHECKS[0][0], "policy-signature")

    def test_first_failure_named(self):
        evil = _att(
            artifacts=[{"path": "x", "is_symlink": True,
                        "target": "/etc/passwd"}],
            edges=[{"edge": "a->b", "shared_digests": {}}])
        ok, code, detail = bvi.run_bundle_invariants(evil)
        self.assertFalse(ok)
        # Symlink check precedes the flow check in registry order.
        self.assertEqual(code, "verify-symlink-escape")
        self.assertIn("symlink-escape", detail)

    def test_verify_raises_named_error(self):
        with self.assertRaises(bvi.BundleInvariantError) as cm:
            bvi.verify_bundle_invariants(_att(edges=[
                {"edge": "a->b", "shared_digests": {}}]))
        self.assertEqual(cm.exception.code, "verify-artifactsfrom-empty")

    def test_clean_bundle_passes(self):
        ok, code, detail = bvi.run_bundle_invariants(_att())
        self.assertTrue(ok)
        self.assertIsNone(code)

    def test_absent_section_passes(self):
        ok, code, _ = bvi.run_bundle_invariants(None)
        self.assertTrue(ok)
        self.assertIsNone(code)

    def test_malformed_section_fails_closed(self):
        ok, code, _ = bvi.run_bundle_invariants("not-a-dict")
        self.assertFalse(ok)
        self.assertIsNotNone(code)

    def test_error_carries_code_and_detail(self):
        err = bvi.BundleInvariantError("verify-symlink-escape", "d")
        self.assertEqual(err.code, "verify-symlink-escape")
        self.assertIn("verify-symlink-escape", str(err))


class V20WiringTests(unittest.TestCase):
    """V20 in gov/evidence_verify.py: appended only when the manifest
    carries an attestation section; a corrupted sub-check fails the
    bundle naming the check."""

    def _ctx(self, attestations):
        from gov import evidence_verify as ev
        class Ctx:
            pass
        c = Ctx()
        c.manifest = {"attestations": attestations} \
            if attestations is not None else {}
        return ev, c

    def test_v20_refuses_forged_policy_signature(self):
        ev, c = self._ctx(_att(policy_signatures=[
            {"identity_ok": True, "sig_ok": False,
             "error": "sig bytes garbage"}]))
        check = ev.v20_bundle_invariants(c)
        self.assertEqual(check.id, "V20")
        self.assertEqual(check.status, "fail")
        self.assertIn("verify-signature-failed", check.detail)

    def test_v20_passes_clean_attestations(self):
        ev, c = self._ctx(_att())
        check = ev.v20_bundle_invariants(c)
        self.assertEqual(check.status, "pass")

    def test_v20_runs_only_with_attestation_section(self):
        from gov import evidence_verify as ev
        import inspect
        src = inspect.getsource(ev._run_checks_v4_v18)
        self.assertIn("attestations", src)
        self.assertIn("v20_bundle_invariants", src)


if __name__ == "__main__":
    unittest.main()
