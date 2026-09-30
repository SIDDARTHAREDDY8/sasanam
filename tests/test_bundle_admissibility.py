"""Unit tests for gov/bundle_admissibility.py (wave-218 lane C).

Seams: AdmissibilityPolicy construction/decision, classify()
outcome mapping, replay-digest bind/check. Deterministic, synthetic,
$0 spend. Bundles are built with the real evidence_bundle pipeline
(fixed signer seed + fixed exported_at -> deterministic).
"""

import json
import os
import secrets
import shutil
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.keyfixture import provision_test_key, scrub_key_env

EXPORTED_AT = "2026-09-26T00:00:00+00:00"


def _signer(seed_byte="7c"):
    from gov.signing import Ed25519Signer
    return Ed25519Signer(bytes.fromhex(seed_byte * 32))


class _BundleBase(unittest.TestCase):
    def setUp(self):
        self._restore = scrub_key_env()
        provision_test_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.signer = _signer()

    def tearDown(self):
        self.tmp.cleanup()
        self._restore()

    def _log(self, path, hmac_only=False):
        from gov.log import ActionLog
        log = ActionLog(path, signer=None if hmac_only else self.signer,
                        deployment_mode="staging")
        log.append({"event": "policy_loaded", "policy_version": "p1",
                    "policy_hash": "h" * 16,
                    "policy_path": "policies/p1.yaml", "pinned": True})
        for i in range(3):
            log.append({"event": "tool_call", "decision": "allow",
                        "tool": "tool-%d" % i})
        return log

    def _assemble(self, name, mutate_payload=None, hmac_only=False):
        from gov.evidence_bundle import (
            EvidenceBundle, log_evidence_bundle_receipt, canonical)
        from gov.log import ActionLog
        import hashlib
        d = os.path.join(self.tmp.name, name)
        os.mkdir(d)
        lp = os.path.join(d, "audit.log")
        self._log(lp, hmac_only=hmac_only)
        eb = EvidenceBundle(lp, exported_at=EXPORTED_AT,
                            operator_id="admiss-unit")
        payload = eb.build()
        if mutate_payload is not None:
            mutate_payload(payload)
            payload["bundle_meta"]["bundle_id"] = None
            payload["bundle_meta"]["bundle_id"] = (
                "EVB-" + hashlib.sha256(canonical(payload)).hexdigest()
                [:16])
        manifest = eb.seal(payload, signer=self.signer)
        log_evidence_bundle_receipt(
            manifest,
            ActionLog(lp, signer=None if hmac_only else self.signer,
                      deployment_mode="staging"),
            signer=self.signer)
        op = {"key_id": self.signer.key_id,
              "public_key_hex": self.signer.public_key.hex()}
        out = os.path.join(d, "bundle")
        eb.assemble(payload, manifest, operator_key=op,
                    checkpoint_keys=[dict(op)], out_dir=out)
        return out

    def _redigest(self, bundle_dir):
        from gov.safeguard_bundle import compute_bundle_digest
        digest = compute_bundle_digest(bundle_dir)
        with open(os.path.join(bundle_dir, "BUNDLE_DIGEST.sha256"),
                  "w") as f:
            f.write(digest + "\n")

    def _rewrite(self, bundle_dir, rel, obj):
        from gov.evidence_bundle import canonical
        with open(os.path.join(bundle_dir, rel), "w",
                  encoding="utf-8") as f:
            f.write(canonical(obj).decode("utf-8") + "\n")


class TestPolicyConstruction(_BundleBase):
    def test_unknown_class_rejected(self):
        from gov.bundle_admissibility import (
            AdmissibilityPolicy, PolicyAuthoringError)
        with self.assertRaises(PolicyAuthoringError):
            AdmissibilityPolicy(accept=("bogus",))

    def test_warn_must_be_subset_of_accept(self):
        from gov.bundle_admissibility import (
            AdmissibilityPolicy, PolicyAuthoringError)
        with self.assertRaises(PolicyAuthoringError):
            AdmissibilityPolicy(accept=("admissible",), warn=("stale",))

    def test_risky_classes_need_acknowledge(self):
        from gov.bundle_admissibility import (
            AdmissibilityPolicy, PolicyAuthoringError)
        for risky in ("conflicted", "missing_evidence"):
            with self.assertRaises(PolicyAuthoringError):
                AdmissibilityPolicy(accept=(risky,))
        p = AdmissibilityPolicy(accept=("conflicted", "missing_evidence"),
                                warn=("conflicted", "missing_evidence"),
                                acknowledge_risk=True)
        self.assertIn("conflicted", p.accept)

    def test_bad_max_age_rejected(self):
        from gov.bundle_admissibility import (
            AdmissibilityPolicy, PolicyAuthoringError)
        for bad in (0, -5, "hour", True, None.__class__):
            if bad is None.__class__:
                continue
            with self.assertRaises(PolicyAuthoringError):
                AdmissibilityPolicy(max_age_seconds=bad)

    def test_fingerprint_stable_and_covers_config(self):
        from gov.bundle_admissibility import AdmissibilityPolicy
        a = AdmissibilityPolicy.auditor_strict()
        b = AdmissibilityPolicy.auditor_strict()
        self.assertEqual(a.fingerprint(), b.fingerprint())
        c = AdmissibilityPolicy.monitor_lax()
        self.assertNotEqual(a.fingerprint(), c.fingerprint())

    def test_decide_codes(self):
        from gov.bundle_admissibility import AdmissibilityPolicy
        strict = AdmissibilityPolicy.auditor_strict()
        d = strict.decide("admissible")
        self.assertTrue(d["accepted"])
        self.assertEqual(d["code"], "admissible")
        self.assertIsNone(d["warning"])
        d = strict.decide("unverifiable")
        self.assertFalse(d["accepted"])
        self.assertEqual(d["code"], "rejected_unverifiable")
        lax = AdmissibilityPolicy.monitor_lax()
        d = lax.decide("stale")
        self.assertTrue(d["accepted"])
        self.assertEqual(d["code"], "tolerated_stale")
        self.assertEqual(d["warning"], "bundle_stale_accepted")
        d = lax.decide("conflicted")
        self.assertFalse(d["accepted"])
        self.assertEqual(d["code"], "rejected_conflicted")
        with self.assertRaises(Exception):
            strict.decide("bogus-class")


class TestClassify(_BundleBase):
    def test_happy_bundle_admissible(self):
        from gov.bundle_admissibility import (
            AdmissibilityPolicy, classify)
        bdir = self._assemble("b1")
        res = classify(bdir, as_of="2026-09-26T01:00:00+00:00")
        self.assertEqual(res["outcome"], "admissible")
        self.assertEqual(res["verifier_verdict"], "SELF_CONSISTENT")
        self.assertTrue(res["bundle_digest"])
        self.assertTrue(res["bundle_id"].startswith("EVB-"))

    def test_stale(self):
        from gov.bundle_admissibility import classify
        bdir = self._assemble("b1")
        res = classify(bdir, as_of="2026-09-28T00:00:00+00:00",
                       max_age_seconds=3600)
        self.assertEqual(res["outcome"], "stale")

    def test_degraded_coverage_is_missing_evidence(self):
        from gov.bundle_admissibility import classify
        bdir = self._assemble("b1", hmac_only=True)
        res = classify(bdir, as_of="2026-09-26T01:00:00+00:00")
        self.assertEqual(res["outcome"], "missing_evidence")
        self.assertTrue(any("inclusion coverage" in r
                            for r in res["reasons"]))

    def test_missing_required_file(self):
        from gov.bundle_admissibility import classify
        bdir = self._assemble("b1")
        os.remove(os.path.join(bdir, "checkpoints.jsonl"))
        self._redigest(bdir)
        res = classify(bdir, as_of="2026-09-26T01:00:00+00:00")
        self.assertEqual(res["outcome"], "missing_evidence")

    def test_policy_disagreement_is_conflicted(self):
        from gov.bundle_admissibility import classify
        def mutate(payload):
            payload["policy"]["policy_version"]["value"] = "p999"
        bdir = self._assemble("b1", mutate_payload=mutate)
        res = classify(bdir, as_of="2026-09-26T01:00:00+00:00")
        self.assertEqual(res["outcome"], "conflicted")

    def test_tampered_payload_unverifiable(self):
        from gov.bundle_admissibility import classify
        bdir = self._assemble("b1")
        p = os.path.join(bdir, "evidence.json")
        payload = json.loads(open(p, encoding="utf-8").read())
        payload["decisions"]["by_event"]["tool_call"] = 999
        self._rewrite(bdir, "evidence.json", payload)
        self._redigest(bdir)
        res = classify(bdir, as_of="2026-09-26T01:00:00+00:00")
        self.assertEqual(res["outcome"], "unverifiable")

    def test_not_a_bundle_is_unverifiable(self):
        from gov.bundle_admissibility import classify
        d = os.path.join(self.tmp.name, "empty")
        os.mkdir(d)
        res = classify(d)
        self.assertEqual(res["outcome"], "unverifiable")

    def test_future_exported_at_unverifiable(self):
        from gov.bundle_admissibility import classify
        bdir = self._assemble("b1")
        res = classify(bdir, as_of="2026-09-25T00:00:00+00:00")
        self.assertEqual(res["outcome"], "unverifiable")

    def test_admit_pipeline(self):
        from gov.bundle_admissibility import (
            AdmissibilityPolicy, admit)
        bdir = self._assemble("b1")
        res = admit(bdir, AdmissibilityPolicy.auditor_strict(),
                    as_of="2026-09-26T01:00:00+00:00")
        self.assertTrue(res["accepted"])
        self.assertEqual(res["code"], "admissible")
        self.assertEqual(res["policy"], "auditor-strict")
        with self.assertRaises(Exception):
            admit(bdir, "not-a-policy")


class TestReplayBinding(_BundleBase):
    def test_bind_and_replay_happy(self):
        from gov.bundle_admissibility import (
            AdmissibilityPolicy, bind_verification, check_replay)
        bdir = self._assemble("b1")
        pol = AdmissibilityPolicy.auditor_strict()
        rec = bind_verification(bdir, pol,
                                as_of="2026-09-26T01:00:00+00:00")
        self.assertEqual(rec["format"],
                         "bundle-admissibility-verification/1")
        self.assertEqual(rec["policy_fingerprint"], pol.fingerprint())
        chk = check_replay(rec, policy=pol,
                           now="2026-09-26T02:00:00+00:00")
        self.assertEqual(chk["outcome"], "admissible")
        self.assertEqual(chk["code"], "replay_ok")

    def test_rotated_policy_mismatch(self):
        from gov.bundle_admissibility import (
            AdmissibilityPolicy, bind_verification, check_replay)
        bdir = self._assemble("b1")
        rec = bind_verification(
            bdir, AdmissibilityPolicy.auditor_strict(),
            as_of="2026-09-26T01:00:00+00:00")
        chk = check_replay(rec,
                           policy=AdmissibilityPolicy.monitor_lax(),
                           now="2026-09-26T02:00:00+00:00")
        self.assertEqual(chk["outcome"], "unverifiable")
        self.assertEqual(chk["code"], "replay_binding_mismatch")

    def test_altered_facts_mismatch(self):
        from gov.bundle_admissibility import (
            AdmissibilityPolicy, bind_verification, check_replay)
        bdir = self._assemble("b1")
        pol = AdmissibilityPolicy.auditor_strict()
        rec = bind_verification(bdir, pol,
                                as_of="2026-09-26T01:00:00+00:00")
        facts = dict(rec["facts"])
        facts["outcome"] = "admissible-but-lying"
        chk = check_replay(rec, policy=pol, facts=facts,
                           now="2026-09-26T02:00:00+00:00")
        self.assertEqual(chk["outcome"], "unverifiable")
        self.assertEqual(chk["code"], "replay_binding_mismatch")

    def test_asof_mismatch(self):
        from gov.bundle_admissibility import (
            AdmissibilityPolicy, bind_verification, check_replay)
        bdir = self._assemble("b1")
        pol = AdmissibilityPolicy.auditor_strict()
        rec = bind_verification(bdir, pol,
                                as_of="2026-09-26T01:00:00+00:00")
        chk = check_replay(rec, policy=pol,
                           as_of="2026-09-27T01:00:00+00:00",
                           now="2026-09-27T02:00:00+00:00")
        self.assertEqual(chk["outcome"], "unverifiable")
        self.assertEqual(chk["code"], "replay_binding_mismatch")

    def test_stale_record(self):
        from gov.bundle_admissibility import (
            AdmissibilityPolicy, bind_verification, check_replay)
        bdir = self._assemble("b1")
        pol = AdmissibilityPolicy(
            accept=("admissible", "stale"), warn=("stale",),
            max_age_seconds=3600, name="hourly")
        rec = bind_verification(bdir, pol,
                                as_of="2026-09-26T01:00:00+00:00")
        chk = check_replay(rec, policy=pol,
                           now="2026-09-28T01:00:00+00:00")
        self.assertEqual(chk["outcome"], "stale")
        self.assertEqual(chk["code"], "verification_record_stale")

    def test_malformed_record(self):
        from gov.bundle_admissibility import (
            AdmissibilityPolicy, check_replay)
        pol = AdmissibilityPolicy.auditor_strict()
        for bad in ({"format": "bogus"}, "not-a-dict", None):
            chk = check_replay(bad, policy=pol)
            self.assertEqual(chk["outcome"], "unverifiable")
            self.assertEqual(chk["code"], "malformed_record")

    def test_replay_digest_domain_separated(self):
        from gov.bundle_admissibility import replay_digest
        d1, _ = replay_digest(policy_fingerprint="abc",
                             facts={"x": 1},
                             as_of="2026-09-26T01:00:00+00:00")
        d2, _ = replay_digest(policy_fingerprint="abc",
                             facts={"x": 2},
                             as_of="2026-09-26T01:00:00+00:00")
        self.assertNotEqual(d1, d2)
        with self.assertRaises(Exception):
            replay_digest(policy_fingerprint="", facts={},
                          as_of="2026-09-26T01:00:00+00:00")
        with self.assertRaises(Exception):
            replay_digest(policy_fingerprint="abc", facts="nope",
                          as_of="2026-09-26T01:00:00+00:00")
        with self.assertRaises(Exception):
            replay_digest(policy_fingerprint="abc", facts={},
                          as_of="not-a-time")


if __name__ == "__main__":
    unittest.main()
