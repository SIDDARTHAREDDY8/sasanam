#!/usr/bin/env python3
"""Unit tests for gov/evidence_ingest_gate.py.

Module discipline, policy freezing, freshness-annotation contract,
revision-binding contract, scan-report ephemerality, and the
lane-local taxonomy pin. Adversarial behavior lives in
evals/w272_ingest_probes.py (red-first); these tests pin the API
contract the merge coordinator relies on.
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from gov import ed25519 as ed
from gov import evidence_ingest_gate as ig

NOW = 1790960000
ISSUER_SEED = bytes([0xA5]) * 32
ISSUER_PUB = ed.publickey(ISSUER_SEED)
REV = "ab" * 32
DIGEST = "cd" * 32


def _policy(**over):
    kw = dict(mode="enforce", max_staleness_seconds=3600,
              force_rescan_interval_s=60,
              freshness_annotation_ttl_s=600,
              freshness_issuer_pub=ISSUER_PUB,
              policy_version="ingest-policy/test-v1")
    kw.update(over)
    return ig.IngestPolicy(**kw)


class TestPolicy(unittest.TestCase):
    def test_mode_fixed_at_construction(self):
        p = _policy(mode="audit")
        self.assertEqual(p.mode, "audit")
        # No ambient downgrade: a second construction cannot flip an
        # existing policy object; mode is a constructor argument only.
        with self.assertRaises(ig.EvidenceIngestGateError):
            ig.IngestPolicy(mode="ignore",
                            freshness_issuer_pub=ISSUER_PUB)

    def test_issuer_pub_shape_enforced(self):
        with self.assertRaises(ig.EvidenceIngestGateError):
            ig.IngestPolicy(freshness_issuer_pub=b"short")

    def test_describe(self):
        d = _policy().describe()
        self.assertEqual(d["mode"], "enforce")
        self.assertEqual(d["policy_version"], "ingest-policy/test-v1")


class TestRevisionBinding(unittest.TestCase):
    def test_register_and_bind(self):
        b = ig.InMemoryRevisionBinding(now=lambda: NOW)
        b.register_revision(REV, [DIGEST], registered_time=NOW - 10)
        self.assertTrue(b.is_bound(REV, DIGEST))
        self.assertFalse(b.is_bound(REV, "00" * 32))
        self.assertFalse(b.is_bound("00" * 32, DIGEST))
        self.assertEqual(b.revision_time(REV), NOW - 10)

    def test_unknown_revision_raises_unbound(self):
        b = ig.InMemoryRevisionBinding(now=lambda: NOW)
        with self.assertRaises(ig.EvidenceIngestGateError) as ctx:
            b.revision_time("ff" * 32)
        self.assertEqual(ctx.exception.code, "ingest-revision-unbound")

    def test_malformed_registration_refused(self):
        b = ig.InMemoryRevisionBinding(now=lambda: NOW)
        with self.assertRaises(ig.EvidenceIngestGateError):
            b.register_revision("not-hex", [DIGEST])
        with self.assertRaises(ig.EvidenceIngestGateError):
            b.register_revision(REV, ["not-hex"])


class TestFreshnessAnnotation(unittest.TestCase):
    def test_roundtrip(self):
        ann = ig.make_freshness_annotation(
            revision_digest=REV, bundle_id="b1", issuer_seed=ISSUER_SEED,
            annotated_time=NOW - 100)
        self.assertEqual(ann["format"], ig.FRESHNESS_FORMAT)
        # A valid annotation verifies (no raise).
        ig._verify_freshness_annotation(
            ann, revision_digest=REV, bundle_id="b1",
            issuer_pub=ISSUER_PUB, now=NOW, ttl_s=600)

    def test_wrong_issuer_refused(self):
        ann = ig.make_freshness_annotation(
            revision_digest=REV, bundle_id="b1",
            issuer_seed=bytes([0x5A]) * 32, annotated_time=NOW - 100)
        with self.assertRaises(ig.EvidenceIngestGateError) as ctx:
            ig._verify_freshness_annotation(
                ann, revision_digest=REV, bundle_id="b1",
                issuer_pub=ISSUER_PUB, now=NOW, ttl_s=600)
        self.assertEqual(ctx.exception.code, "ingest-freshness-invalid")

    def test_future_annotation_refused(self):
        ann = ig.make_freshness_annotation(
            revision_digest=REV, bundle_id="b1", issuer_seed=ISSUER_SEED,
            annotated_time=NOW + 100)
        with self.assertRaises(ig.EvidenceIngestGateError) as ctx:
            ig._verify_freshness_annotation(
                ann, revision_digest=REV, bundle_id="b1",
                issuer_pub=ISSUER_PUB, now=NOW, ttl_s=600)
        self.assertEqual(ctx.exception.code, "ingest-freshness-invalid")

    def test_expired_annotation_refused(self):
        ann = ig.make_freshness_annotation(
            revision_digest=REV, bundle_id="b1", issuer_seed=ISSUER_SEED,
            annotated_time=NOW - 1200)
        with self.assertRaises(ig.EvidenceIngestGateError) as ctx:
            ig._verify_freshness_annotation(
                ann, revision_digest=REV, bundle_id="b1",
                issuer_pub=ISSUER_PUB, now=NOW, ttl_s=600)
        self.assertEqual(ctx.exception.code, "ingest-freshness-invalid")

    def test_wrong_bundle_refused(self):
        ann = ig.make_freshness_annotation(
            revision_digest=REV, bundle_id="b1", issuer_seed=ISSUER_SEED,
            annotated_time=NOW - 100)
        with self.assertRaises(ig.EvidenceIngestGateError):
            ig._verify_freshness_annotation(
                ann, revision_digest=REV, bundle_id="b2",
                issuer_pub=ISSUER_PUB, now=NOW, ttl_s=600)

    def test_tampered_body_refused(self):
        ann = ig.make_freshness_annotation(
            revision_digest=REV, bundle_id="b1", issuer_seed=ISSUER_SEED,
            annotated_time=NOW - 100)
        ann["body"]["annotated_time"] = NOW - 50  # post-sign tamper
        with self.assertRaises(ig.EvidenceIngestGateError) as ctx:
            ig._verify_freshness_annotation(
                ann, revision_digest=REV, bundle_id="b1",
                issuer_pub=ISSUER_PUB, now=NOW, ttl_s=600)
        self.assertEqual(ctx.exception.code, "ingest-freshness-invalid")

    def test_malformed_seed_refused(self):
        with self.assertRaises(ig.EvidenceIngestGateError):
            ig.make_freshness_annotation(
                revision_digest=REV, bundle_id="b1",
                issuer_seed=b"short", annotated_time=NOW)


class TestGateDiscipline(unittest.TestCase):
    def _gate(self, **over):
        kw = dict(policy=_policy(), transparency_log=object(),
                  audit_log_path="/nonexistent/audit.jsonl",
                  ca_public_key=b"\x00" * 32,
                  revision_binding=ig.InMemoryRevisionBinding(
                      now=lambda: NOW),
                  now=lambda: NOW)
        kw.update(over)
        return ig.IngestGate(**kw)

    def test_evaluate_is_pure(self):
        g = self._gate()
        v1 = g.evaluate(bundle_id="x", submission={"garbage": 1},
                       verify_time=NOW)
        v2 = g.evaluate(bundle_id="x", submission={"garbage": 1},
                       verify_time=NOW)
        self.assertEqual(v1["code"], "ingest-malformed")
        self.assertEqual(v1, v2)
        self.assertIsNone(g.scan_report("x"))

    def test_evaluate_never_raises(self):
        g = self._gate()
        for bad in (None, [], "str", {"kind": "wrong"}, {"sealed": {}}):
            v = g.evaluate(bundle_id="x", submission=bad,
                           verify_time=NOW)
            self.assertEqual(v["verdict"], "deny")
            self.assertTrue(v["blocked"])

    def test_set_policy_is_explicit_event(self):
        g = self._gate()
        rec = g.set_policy(_policy(policy_version="ingest-policy/test-v2"))
        self.assertEqual(rec["event"], "ingest-policy-switched")
        self.assertEqual(rec["from"], "ingest-policy/test-v1")
        self.assertEqual(rec["to"], "ingest-policy/test-v2")
        self.assertEqual(g.policy.policy_version, "ingest-policy/test-v2")

    def test_drift_events_start_empty(self):
        self.assertEqual(self._gate().drift_events(), [])

    def test_unknown_mode_rejected(self):
        # Unknown mode fails closed at construction.
        with self.assertRaises(ig.EvidenceIngestGateError):
            ig.IngestGate(
                policy=object(), transparency_log=object(),
                audit_log_path="/x", ca_public_key=b"\x00" * 32,
                revision_binding=ig.InMemoryRevisionBinding(),
                now=lambda: NOW)

    def test_scan_report_ephemeral_note(self):
        # The ephemeral-report contract is documented on the record.
        g = self._gate()
        rec = {"bundle_id": "b", "submission_digest": "00" * 32,
               "verdict": {"verdict": "admit", "code": "ingest-admit",
                           "evaluated_at": NOW,
                           "policy_version": "ingest-policy/test-v1"},
               "admitted_at": NOW,
               "policy_version": "ingest-policy/test-v1"}
        rep = g._make_report("b", rec, rescan_due=False)
        self.assertIn("never audit evidence", rep["note"])
        self.assertFalse(rep["drift"])


class TestTaxonomyPin(unittest.TestCase):
    def test_pin_1482_on_raw_literals(self):
        # Wave-275 merge pin: 1485 = 1477 (wave-274 merge) + 5 codes (coverage-*)
        # (3 provlabel-* + 8 rail-* + 3 decodetrust-* + 5 attestor-*).
        # Counted on quoted source literals per the wave-260 lesson.
        import re
        from collections import Counter
        with open(os.path.join(
                _REPO, "gov", "decision_codes.py")) as fh:
            src = fh.read()
        codes = re.findall(
            r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
        dups = [c for c, n in Counter(codes).items() if n > 1]
        self.assertEqual(len(codes), 2124) # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*). # Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*)
        self.assertEqual(len(set(codes)), 2124) # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*). # Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*)
        self.assertEqual(dups, [])
        ingest = sorted(c for c in codes if c.startswith("ingest-"))
        self.assertEqual(len(ingest), 9)
        self.assertEqual(ingest, sorted(ingest))  # alphabetical


if __name__ == "__main__":
    unittest.main()
