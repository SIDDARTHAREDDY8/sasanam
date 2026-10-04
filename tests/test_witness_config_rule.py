"""Unit tests for gov/witness_config_rule.py (wave-240 lane D).

W240-7 (GHSA-ggg4): .witness.yaml auto-load rule + upload-destination
confirmation gating + tighten-only sensitive filtering.
W240-8 (GHSA-6xq9/GHSA-88v8): intermediate-CA completeness at every
chain-verify entry point.
"""

import unittest

from gov import witness_config_rule as wr
from gov import decision_codes as dc


class ConfigLoadTest(unittest.TestCase):
    def test_cwd_autoload_refused_in_ci(self):
        with self.assertRaises(wr.WitnessConfigError) as cm:
            wr.load_config({"a": 1}, source="cwd/.witness.yaml",
                           context=wr.CONTEXT_CI, auto_discovered=True)
        self.assertEqual(cm.exception.code, "witness-config-cwd-autoload")

    def test_cwd_autoload_refused_in_untrusted_repo(self):
        with self.assertRaises(wr.WitnessConfigError) as cm:
            wr.load_config({"a": 1}, source="cwd/.witness.yaml",
                           context=wr.CONTEXT_UNTRUSTED, auto_discovered=True)
        self.assertEqual(cm.exception.code, "witness-config-cwd-autoload")

    def test_explicit_path_trusted_loads(self):
        cfg = wr.load_config({"a": 1}, source="/etc/sasanam/witness.yaml",
                             context=wr.CONTEXT_TRUSTED,
                             auto_discovered=False)
        self.assertEqual(cfg, {"a": 1})

    def test_explicit_path_in_ci_loads(self):
        # An explicit path is not auto-load; CI refusal applies to
        # discovery, not to the context alone.
        cfg = wr.load_config({"a": 1}, source="/etc/sasanam/witness.yaml",
                             context=wr.CONTEXT_CI, auto_discovered=False)
        self.assertEqual(cfg, {"a": 1})

    def test_unknown_context_fails_closed(self):
        with self.assertRaises(wr.WitnessConfigError):
            wr.load_config({"a": 1}, source="x",
                           context="somewhere-else", auto_discovered=False)

    def test_non_mapping_fails_closed(self):
        with self.assertRaises(wr.WitnessConfigError):
            wr.load_config(["not", "a", "mapping"], source="x",
                           context=wr.CONTEXT_TRUSTED, auto_discovered=False)


class UploadDestinationTest(unittest.TestCase):
    def test_ungated_change_refused(self):
        with self.assertRaises(wr.WitnessConfigError) as cm:
            wr.apply_upload_destination("s3://a", "s3://b", confirmed=False)
        self.assertEqual(cm.exception.code, "witness-config-upload-ungated")

    def test_confirmed_change_applies(self):
        self.assertEqual(
            wr.apply_upload_destination("s3://a", "s3://b", confirmed=True),
            "s3://b")

    def test_unchanged_is_noop(self):
        self.assertEqual(
            wr.apply_upload_destination("s3://a", "s3://a", confirmed=False),
            "s3://a")


class SensitiveFilterTest(unittest.TestCase):
    def test_downgrade_refused(self):
        with self.assertRaises(wr.WitnessConfigError) as cm:
            wr.set_sensitive_filter(["AKIA", "token="], ["token="])
        self.assertEqual(cm.exception.code, "witness-config-filter-downgrade")

    def test_disable_refused(self):
        with self.assertRaises(wr.WitnessConfigError):
            wr.set_sensitive_filter(["AKIA"], [])

    def test_tighten_applies(self):
        self.assertEqual(
            wr.set_sensitive_filter(["a"], ["a", "b"]), ["a", "b"])

    def test_unchanged_applies(self):
        self.assertEqual(
            wr.set_sensitive_filter(["a"], ["a"]), ["a"])


class IntermediateCompletenessTest(unittest.TestCase):
    def _fragment(self):
        return [
            {"subject": "leaf", "issuer": "intermediate"},
            {"subject": "root", "issuer": "root"},
        ]

    def test_fragment_without_intermediates_refused(self):
        for inter in (None, []):
            with self.assertRaises(wr.WitnessConfigError) as cm:
                wr.assert_intermediates_loaded(self._fragment(),
                                               intermediates=inter)
            self.assertEqual(cm.exception.code,
                             "witness-intermediates-missing")
            self.assertIn("completeness", cm.exception.detail)

    def test_fragment_with_intermediates_ok(self):
        inter = [{"subject": "intermediate", "issuer": "root"}]
        self.assertTrue(
            wr.assert_intermediates_loaded(self._fragment(),
                                           intermediates=inter))

    def test_self_contained_chain_needs_no_intermediates(self):
        # A complete in-chain hierarchy needs no loaded intermediates.
        chain = [
            {"subject": "leaf", "issuer": "intermediate"},
            {"subject": "intermediate", "issuer": "root"},
            {"subject": "root", "issuer": "root"},
        ]
        self.assertTrue(
            wr.assert_intermediates_loaded(chain, intermediates=None))

    def test_single_self_signed_ok(self):
        chain = [{"subject": "root", "issuer": "root"}]
        self.assertTrue(
            wr.assert_intermediates_loaded(chain, intermediates=None))

    def test_empty_chain_fails_closed(self):
        with self.assertRaises(wr.WitnessConfigError) as cm:
            wr.assert_intermediates_loaded([], intermediates=None)
        self.assertEqual(cm.exception.code, "witness-intermediates-missing")

    def test_every_entry_point_enforces(self):
        points = wr.chain_entry_points()
        self.assertGreaterEqual(len(points), 1)
        fragment = self._fragment()
        for entry in points:
            with self.assertRaises(wr.WitnessConfigError) as cm:
                wr.verify_chain_entry(fragment, intermediates=None,
                                      entry_point=entry)
            self.assertEqual(cm.exception.code,
                             "witness-intermediates-missing")

    def test_entry_point_with_intermediates_verifies(self):
        fragment = self._fragment()
        inter = [{"subject": "intermediate", "issuer": "root"}]
        for entry in wr.chain_entry_points():
            v = wr.verify_chain_entry(fragment, intermediates=inter,
                                      entry_point=entry)
            self.assertTrue(v["ok"])
            self.assertEqual(v["completeness"], "intermediates-loaded")
            self.assertIn("deployment-owned", v["note"])

    def test_unknown_entry_point_fails_closed(self):
        fragment = self._fragment()
        inter = [{"subject": "intermediate", "issuer": "root"}]
        with self.assertRaises(wr.WitnessConfigError):
            wr.verify_chain_entry(fragment, intermediates=inter,
                                  entry_point="bogus")


class TaxonomyTest(unittest.TestCase):
    def test_witness_codes_mapped(self):
        for code in ("witness-config-cwd-autoload",
                     "witness-config-upload-ungated",
                     "witness-config-filter-downgrade",
                     "witness-intermediates-missing"):
            self.assertIsNotNone(dc.code_for(code), code)
        # Wave-242 merge: re-pointed 766 -> 788 (22 new codes: 5
        # aggregate-budget/no-effect + 6 stale-authority/containment
        # + 1 exception-TTL + 10 absence-epoch), additive only, composed
        # from the five lane commits by direct byte-verification.
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 2021)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
