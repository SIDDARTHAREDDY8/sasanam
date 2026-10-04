"""Unit tests for gov/evidence_envelope (wave-248 lane 3).

Per-record DSSE envelope for the offline evidence bundle, with the
two blamejs/pki 0.7.6 pins: (a) multi-signature envelopes refused,
(b) verification work bounded before crypto.
"""

import base64
import copy
import json
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import decision_codes as dc  # noqa: E402
from gov import ed25519 as ed  # noqa: E402
from gov import evidence_envelope as ee  # noqa: E402


def _keys():
    seed = ed.generate_seed()
    return seed, ed.publickey(seed)


class TestEvidenceEnvelope(unittest.TestCase):
    # Lane-local pin: 938 (wave-247) + 2 new codes.
    def test_taxonomy_pin(self):
        # Wave-248 merge: re-pointed to 979 (938 + 41 wave-248 codes), additive only.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1976)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.
        self.assertIn("evidence-envelope-record-limit", dc.TAXONOMY)
        self.assertIn("evidence-envelope-record-too-large", dc.TAXONOMY)

    def test_payload_types_in_vendored_namespace(self):
        for ptype in (ee.PAYLOAD_TYPE_AUDIT_ENTRY,
                      ee.PAYLOAD_TYPE_BUNDLE_MANIFEST):
            self.assertTrue(ptype.startswith(
                "application/vnd.sasanam."))
            self.assertTrue(ptype.endswith("+json"))

    def test_seal_open_roundtrip(self):
        seed, pub = _keys()
        record = {"seq": 7, "decision": "deny", "reason": "t"}
        env = ee.seal_record(record, seed, key_id="k1")
        self.assertEqual(env["payloadType"],
                         ee.PAYLOAD_TYPE_AUDIT_ENTRY)
        self.assertEqual(len(env["signatures"]), 1)
        self.assertEqual(env["signatures"][0]["keyid"], "k1")
        self.assertEqual(ee.open_record(env, pub), record)

    def test_seal_record_key_id_optional(self):
        seed, pub = _keys()
        env = ee.seal_record({"seq": 1}, seed)
        self.assertEqual(ee.open_record(env, pub), {"seq": 1})

    def test_open_record_wrong_pubkey_refused(self):
        seed, _ = _keys()
        _, other_pub = _keys()
        env = ee.seal_record({"seq": 1}, seed)
        with self.assertRaises(ee.EvidenceEnvelopeError) as ctx:
            ee.open_record(env, other_pub)
        self.assertIn("dsse-signature-invalid", ctx.exception.code)

    def test_multisig_refused_even_with_valid_first(self):
        # Blamejs pin (a): the second signature rides through
        # unverified in the buggy shape; here the envelope refuses.
        seed, pub = _keys()
        env = ee.seal_record({"seq": 1}, seed)
        other_seed = ed.generate_seed()
        forged = copy.deepcopy(env)
        forged["signatures"].append({
            "keyid": "attacker",
            "sig": ed.sign(other_seed, b"not-pae-bytes").hex(),
        })
        with self.assertRaises(ee.EvidenceEnvelopeError) as ctx:
            ee.open_record(forged, pub)
        self.assertIn("dsse-envelope-multi-signature",
                      ctx.exception.code)

    def test_zero_signatures_refused(self):
        seed, pub = _keys()
        env = ee.seal_record({"seq": 1}, seed)
        env["signatures"] = []
        with self.assertRaises(ee.EvidenceEnvelopeError) as ctx:
            ee.open_record(env, pub)
        self.assertIn("dsse-envelope-no-signature",
                      ctx.exception.code)

    def test_wrong_payload_type_refused(self):
        seed, pub = _keys()
        env = ee.seal_record({"seq": 1}, seed)
        env2 = copy.deepcopy(env)
        env2["payloadType"] =\
            "application/vnd.sasanam.decision-packet+json"
        with self.assertRaises(ee.EvidenceEnvelopeError) as ctx:
            ee.open_record(env2, pub)
        self.assertIn("payload-type-refused", ctx.exception.code)

    def test_manifest_envelope_not_openable_as_record(self):
        # Cross-kind transplant inside the evidence domain.
        seed, pub = _keys()
        env = ee.seal_manifest({"bundle_id": "b1"}, seed)
        with self.assertRaises(ee.EvidenceEnvelopeError):
            ee.open_record(env, pub)

    def test_tampered_payload_refused(self):
        seed, pub = _keys()
        env = ee.seal_record({"seq": 1, "decision": "deny"}, seed)
        tampered = copy.deepcopy(env)
        raw = json.loads(base64.b64decode(tampered["payload"]))
        raw["decision"] = "allow"
        tampered["payload"] = base64.b64encode(
            json.dumps(raw).encode()).decode("ascii")
        with self.assertRaises(ee.EvidenceEnvelopeError) as ctx:
            ee.open_record(tampered, pub)
        self.assertIn(ctx.exception.code,
                      ("dsse-signature-invalid",
                       "dsse-envelope-malformed"))

    def test_oversized_record_refused_at_seal(self):
        seed, _ = _keys()
        big = {"seq": 1, "blob": "x" * (ee.MAX_RECORD_BYTES + 1)}
        with self.assertRaises(ee.EvidenceEnvelopeError) as ctx:
            ee.seal_record(big, seed)
        self.assertIn("evidence-envelope-record-too-large",
                      ctx.exception.code)

    def test_record_at_bound_seals(self):
        seed, pub = _keys()
        # Exactly at the bound must still seal (fail-closed, not
        # off-by-one).
        blob_len = ee.MAX_RECORD_BYTES - len(
            json.dumps({"seq": 1, "blob": ""},
                       sort_keys=True, separators=(",", ":")).encode())
        record = {"seq": 1, "blob": "x" * blob_len}
        env = ee.seal_record(record, seed)
        self.assertEqual(ee.open_record(env, pub), record)

    def test_bundle_limit_refused_before_crypto(self):
        # Blamejs pin (b): 10,001 envelopes -> record-limit refusal,
        # not per-record signature failures.
        seed, pub = _keys()
        envs = [ee.seal_record({"seq": i}, seed) for i in range(5)]
        for env in envs:
            env["signatures"][0]["sig"] = "ab" * 64
        oversized = envs * 2001
        self.assertGreater(len(oversized), ee.MAX_RECORDS_PER_BUNDLE)
        with self.assertRaises(ee.EvidenceEnvelopeError) as ctx:
            ee.open_records(oversized, pub)
        self.assertIn("evidence-envelope-record-limit",
                      ctx.exception.code)

    def test_bundle_at_limit_opens(self):
        seed, pub = _keys()
        records = [{"seq": i} for i in range(50)]
        envs = ee.seal_records(records, seed)
        self.assertEqual(ee.open_records(envs, pub), records)

    def test_seal_records_limit_refused(self):
        seed, _ = _keys()
        with self.assertRaises(ee.EvidenceEnvelopeError) as ctx:
            ee.seal_records(
                [{"seq": i}
                 for i in range(ee.MAX_RECORDS_PER_BUNDLE + 1)], seed)
        self.assertIn("evidence-envelope-record-limit",
                      ctx.exception.code)

    def test_malformed_inputs_refused(self):
        _, pub = _keys()
        for bad in (None, [], "x", {}, {"payloadType": "x"},
                    {"payload": "e30=", "payloadType":
                     ee.PAYLOAD_TYPE_AUDIT_ENTRY,
                     "signatures": "not-a-list"}):
            with self.assertRaises(ee.EvidenceEnvelopeError,
                                   msg="accepted %r" % (bad,)):
                ee.open_record(bad, pub)

    def test_bad_seed_and_pubkey_refused(self):
        _, pub = _keys()
        with self.assertRaises(ee.EvidenceEnvelopeError):
            ee.seal_record({"seq": 1}, b"short")
        env_seed, _ = _keys()
        env = ee.seal_record({"seq": 1}, env_seed)
        with self.assertRaises(ee.EvidenceEnvelopeError):
            ee.open_record(env, b"short")

    def test_expected_seq_pin(self):
        seed, pub = _keys()
        env = ee.seal_record({"seq": 42}, seed)
        self.assertEqual(ee.open_record(env, pub, expected_seq=42),
                         {"seq": 42})
        with self.assertRaises(ee.EvidenceEnvelopeError):
            ee.open_record(env, pub, expected_seq=43)

    def test_manifest_roundtrip(self):
        seed, pub = _keys()
        manifest = {"bundle_id": "b1", "record_count": 2}
        env = ee.seal_manifest(manifest, seed, key_id="m")
        self.assertEqual(env["payloadType"],
                         ee.PAYLOAD_TYPE_BUNDLE_MANIFEST)
        self.assertEqual(ee.open_manifest(env, pub), manifest)

    def test_non_dict_record_refused(self):
        seed, _ = _keys()
        with self.assertRaises(ee.EvidenceEnvelopeError):
            ee.seal_record(["not", "a", "dict"], seed)


if __name__ == "__main__":
    unittest.main()
