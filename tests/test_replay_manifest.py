"""Unit tests: replay manifest v1 (wave-271).

White-box contract pins for gov.replay_manifest. The adversarial
behavior is covered break-first by evals/w271_replay_probes.py; these
tests pin contracts the battery exercises end to end:

  - raise-vs-return contract of verify_manifest (raise on failure,
    {"verified": True} dict on success -- never a bare bool)
  - chain shape (genesis prev_hash, link_hash coverage, seal coverage)
  - fail-closed pin block at seal (dirty / missing / malformed)
  - code_pins live at manifest level; link bodies are immutable once
    appended
  - negative-evidence links carry tool_dispatched False
  - terminology: "replay manifest", never "replay" unqualified

TAXONOMY_PIN = 1588  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).
"""

import json
import unittest

from gov import decision_codes
from gov import replay_manifest as rm

TAXONOMY_PIN = 2070 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2070 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*). # Wave-333 lane 4: pin 2062 -> 2070 (+8 revocation-push-*).



NOW = 1790960000


def _builder(**kw):
    kw.setdefault("now", lambda: NOW)
    return rm.ReplayManifestBuilder("spiffe://prod/agent-7", **kw)


def _benign_manifest():
    b = _builder()
    b.record_environment_snapshot({"python": "3.12"})
    b.record_tool_call(tool_id="fs.read", input_digest="a1" * 32,
                       output_digest="b2" * 32,
                       tool_digest_pin="c3" * 32, seed=42)
    b.record_presentation(presented_bytes=b"shown-bytes",
                          purpose="approval-prompt")
    b.record_approval_received(approval_id="appr-1",
                               approval_receipt_ref="d4" * 32,
                               decision_digest="e5" * 32)
    b.record_gate_consult(gate="egress", decision_code="deny",
                          reason="unlisted host")
    return b.seal()


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


class TaxonomyPinTests(unittest.TestCase):
    def test_pin(self):
        self.assertEqual(len(decision_codes.TAXONOMY), TAXONOMY_PIN)

    def test_new_codes_registered(self):
        for code in ("replay-approval-receipt-invalid",
                     "replay-broken-chain",
                     "replay-dirty-codebase-seal",
                     "replay-malformed",
                     "replay-missing-approval-receipt",
                     "replay-presentation-mismatch",
                     "replay-unverifiable-tool-digest"):
            self.assertIn(code, decision_codes.TAXONOMY)
            self.assertEqual(decision_codes.TAXONOMY[code]["domain"],
                             "replay")


class VerifyContractTests(unittest.TestCase):
    def test_success_returns_verified_dict(self):
        r = rm.verify_manifest(_benign_manifest())
        self.assertIsInstance(r, dict)
        self.assertIs(r["verified"], True)
        self.assertTrue(r["receipts_unverified"])  # no checker supplied
        self.assertTrue(r["presentations_unverified"])

    def test_failure_raises_coded_error(self):
        m = _benign_manifest()
        m["links"][1]["output_digest"] = "99" * 32
        with self.assertRaises(rm.ReplayManifestError) as ctx:
            rm.verify_manifest(m)
        self.assertEqual(ctx.exception.code, "replay-broken-chain")
        # And the error str carries the code first (code-first shape).
        self.assertTrue(str(ctx.exception).startswith(
            "replay-broken-chain: "))

    def test_genesis_prev_hash(self):
        m = _benign_manifest()
        self.assertEqual(m["links"][0]["prev_hash"], rm.GENESIS_HASH)

    def test_link_hash_covers_body(self):
        m = _benign_manifest()
        link = m["links"][1]
        body = {k: v for k, v in link.items() if k != "link_hash"}
        import hashlib
        self.assertEqual(
            hashlib.sha256(_canonical(body)).hexdigest(),
            link["link_hash"])

    def test_seal_covers_links_and_pins(self):
        m = _benign_manifest()
        import hashlib
        expect = hashlib.sha256(_canonical(
            {"format": rm.MANIFEST_FORMAT, "links": m["links"],
             "code_pins": m["code_pins"]})).hexdigest()
        self.assertEqual(m["manifest_digest"], expect)

    def test_code_pins_at_manifest_level_not_in_links(self):
        m = _benign_manifest()
        self.assertIn("1", m["code_pins"])
        self.assertNotIn("code_pin", m["links"][1])

    def test_wrong_format_refused(self):
        with self.assertRaises(rm.ReplayManifestError) as ctx:
            rm.verify_manifest({"format": "nope", "links": []})
        self.assertEqual(ctx.exception.code, "replay-malformed")


class SealFailClosedTests(unittest.TestCase):
    def test_dirty_refused_at_seal(self):
        b = _builder()
        b.record_tool_call(tool_id="t", input_digest="a1" * 32,
                           output_digest="b2" * 32,
                           tool_digest_pin="c3" * 32, seed=1, dirty=True)
        with self.assertRaises(rm.ReplayManifestError) as ctx:
            b.seal()
        self.assertEqual(ctx.exception.code, "replay-dirty-codebase-seal")

    def test_missing_pin_refused_at_seal(self):
        b = _builder()
        b.record_tool_call(tool_id="t", input_digest="a1" * 32,
                           output_digest="b2" * 32,
                           tool_digest_pin=None, seed=1)
        with self.assertRaises(rm.ReplayManifestError) as ctx:
            b.seal()
        self.assertEqual(ctx.exception.code,
                         "replay-unverifiable-tool-digest")

    def test_malformed_pin_refused_at_seal(self):
        b = _builder()
        b.record_tool_call(tool_id="t", input_digest="a1" * 32,
                           output_digest="b2" * 32,
                           tool_digest_pin="not-a-digest", seed=1)
        with self.assertRaises(rm.ReplayManifestError) as ctx:
            b.seal()
        self.assertEqual(ctx.exception.code,
                         "replay-unverifiable-tool-digest")

    def test_registry_mismatch_refused_at_seal(self):
        reg = rm.InMemoryPinRegistry()
        reg.register("t", "c3" * 32)
        b = _builder(code_pin_policy=reg)
        b.record_tool_call(tool_id="t", input_digest="a1" * 32,
                           output_digest="b2" * 32,
                           tool_digest_pin="ff" * 32, seed=1)
        with self.assertRaises(rm.ReplayManifestError) as ctx:
            b.seal()
        self.assertEqual(ctx.exception.code,
                         "replay-unverifiable-tool-digest")

    def test_record_after_seal_refused(self):
        b = _builder()
        b.record_gate_consult(gate="g", decision_code="deny",
                              reason="r")
        b.seal()
        with self.assertRaises(rm.ReplayManifestError):
            b.record_gate_consult(gate="g", decision_code="deny",
                                  reason="r")

    def test_double_seal_refused(self):
        b = _builder()
        b.seal()
        with self.assertRaises(rm.ReplayManifestError):
            b.seal()


class NegativeEvidenceTests(unittest.TestCase):
    def test_negative_evidence_first_class(self):
        b = _builder()
        b.record_gate_consult(gate="egress", decision_code="deny",
                              reason="unlisted host")
        m = b.seal()
        link = m["links"][0]
        self.assertEqual(link["action"], "gate_consult")
        self.assertEqual(link["negative_evidence"]["tool_dispatched"],
                         False)
        self.assertEqual(link["negative_evidence"]["decision"], "deny")
        r = rm.verify_manifest(m)
        self.assertIs(r["verified"], True)

    def test_dispatched_tool_not_negative(self):
        b = _builder()
        b.record_gate_consult(gate="egress", decision_code="allow",
                              reason="listed", dispatched_tool="fs.read")
        m = b.seal()
        self.assertNotIn("negative_evidence", m["links"][0])
        self.assertEqual(m["links"][0]["dispatched_tool"], "fs.read")


class DeterminismTests(unittest.TestCase):
    def test_same_inputs_same_bytes(self):
        a = _canonical(_benign_manifest())
        b = _canonical(_benign_manifest())
        self.assertEqual(a, b)

    def test_different_now_different_ts(self):
        b1 = rm.ReplayManifestBuilder("a", now=lambda: NOW)
        b2 = rm.ReplayManifestBuilder("a", now=lambda: NOW + 1)
        b1.record_gate_consult(gate="g", decision_code="deny", reason="r")
        b2.record_gate_consult(gate="g", decision_code="deny", reason="r")
        self.assertNotEqual(b1.seal()["links"][0]["ts"],
                            b2.seal()["links"][0]["ts"])


class TerminologyTests(unittest.TestCase):
    def test_module_says_replay_manifest(self):
        self.assertIn("replay manifest", rm.__doc__.lower())
        self.assertEqual(rm.MANIFEST_FORMAT,
                         "sasanam-replay-manifest/v1")


if __name__ == "__main__":
    unittest.main()
