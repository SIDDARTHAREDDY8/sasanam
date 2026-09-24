"""Tests for the Safeguard Benchmark primitive (spec:
docs/safeguard-benchmark-spec.md).

gov/safeguard_benchmark.py — SafeguardAssessment build/seal/verify_report
+ log_benchmark_receipt; evals/safeguard_results.py — battery-result
loading + probe-category severity mapping.

$0 spend, synthetic/local only. Keys are fresh random per test via the
explicit GOV_LOG_KEY env backend (same production path tests use).
"""

import hashlib
import json
import os
import secrets
import tempfile
import unittest

from evals.safeguard_results import (  # noqa: E402
    CATEGORY_SEVERITY,
    SEVERITY_WEIGHTS,
    UNCOVERED_CATEGORIES,
    SafeguardResultsError,
    load_battery_results,
)

_KEY_VARS = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")


def _provision_key():
    saved = {k: os.environ.get(k) for k in _KEY_VARS}
    os.environ["GOV_LOG_KEY"] = secrets.token_bytes(32).hex()
    os.environ["GOV_LOG_KEY_EPOCH"] = "test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)

    def restore():
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return restore


def _write_artifact(records):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(records, f)
    return path


class TestLoadBatteryResults(unittest.TestCase):
    def test_loads_explicit_records(self):
        path = _write_artifact([
            {"id": "p1", "category": "prompt_injection",
             "verdict": "stopped"},
            {"id": "p2", "category": "sandbox_escape",
             "verdict": "break"},
            {"id": "p3", "category": "eval_cheating",
             "verdict": "error"},
        ])
        try:
            recs = load_battery_results(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(recs), 3)
        self.assertEqual(recs[0],
                         {"id": "p1", "category": "prompt_injection",
                          "verdict": "stopped",
                          "severity_weight": SEVERITY_WEIGHTS[
                              CATEGORY_SEVERITY["prompt_injection"]]})
        self.assertEqual(recs[1]["verdict"], "break")
        self.assertEqual(recs[2]["severity_weight"],
                         SEVERITY_WEIGHTS[
                             CATEGORY_SEVERITY["eval_cheating"]])

    def test_loads_dict_with_results_key(self):
        path = _write_artifact({"results": [
            {"id": "p1", "category": "supply_chain",
             "verdict": "stopped"}]})
        try:
            recs = load_battery_results(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["category"], "supply_chain")

    def test_observed_alias_for_verdict(self):
        # Registry-gate style records carry `observed`, not `verdict`.
        path = _write_artifact([
            {"id": "s1", "category": "tool_misuse",
             "observed": "stopped"}])
        try:
            recs = load_battery_results(path)
        finally:
            os.unlink(path)
        self.assertEqual(recs[0]["verdict"], "stopped")

    def test_unknown_verdict_fails_closed(self):
        path = _write_artifact([
            {"id": "p1", "category": "prompt_injection",
             "verdict": "passed"}])
        try:
            with self.assertRaises(SafeguardResultsError):
                load_battery_results(path)
        finally:
            os.unlink(path)

    def test_unknown_category_fails_closed(self):
        path = _write_artifact([
            {"id": "p1", "category": "teleportation",
             "verdict": "stopped"}])
        try:
            with self.assertRaises(SafeguardResultsError):
                load_battery_results(path)
        finally:
            os.unlink(path)

    def test_missing_category_fails_closed(self):
        path = _write_artifact([{"id": "p1", "verdict": "stopped"}])
        try:
            with self.assertRaises(SafeguardResultsError):
                load_battery_results(path)
        finally:
            os.unlink(path)

    def test_actor_class_artifact_refused_not_coerced(self):
        # The stratified-100 battery artifact uses actor classes
        # (benign/careless/...) that are NOT probe categories. The
        # loader must refuse, not invent a category mapping.
        path = _write_artifact({"results": [
            {"profile_id": "benign-researcher-000", "class": "benign",
             "outcome": "completed", "passed": True}]})
        try:
            with self.assertRaises(SafeguardResultsError):
                load_battery_results(path)
        finally:
            os.unlink(path)

    def test_explicit_weight_must_match_band(self):
        path = _write_artifact([
            {"id": "p1", "category": "prompt_injection",
             "verdict": "stopped", "severity_weight": 999}])
        try:
            with self.assertRaises(SafeguardResultsError):
                load_battery_results(path)
        finally:
            os.unlink(path)

    def test_hf_forensics_categories_present(self):
        # Spec §3b required categories, severity banded.
        for cat in ("covert_interagent_comms", "sandbox_escape",
                    "eval_cheating", "identity_authentication",
                    "self_sacrificing_coordination"):
            self.assertIn(cat, CATEGORY_SEVERITY,
                          "missing HF-forensics category %r" % cat)

    def test_uncovered_categories_are_labeled(self):
        # Categories with no/partial probes ship labeled, never scored.
        self.assertIn("identity_authentication", UNCOVERED_CATEGORIES)
        self.assertIn("covert_interagent_comms", UNCOVERED_CATEGORIES)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# SafeguardAssessment.build
# ---------------------------------------------------------------------------

def _append(log, event, **kw):
    rec = {"event": event}
    rec.update(kw)
    return log.append(rec)


def _build_sar_log(path, signer=None, rising_autonomy=False,
                   with_oversight=True):
    """Synthetic governed-deployment log for SAR tests."""
    from gov.log import ActionLog
    log = ActionLog(path, signer=signer)
    _append(log, "tool_call", tool="read_file", agent_id="a1", run_id="r1",
            decision="allow", policy_id="p-default")
    if with_oversight:
        _append(log, "tool_call", tool="send_email", agent_id="a1",
                run_id="r1", decision="queued_pending",
                policy_id="p-critical", approval_id="A-1")
        _append(log, "approval_decision", agent_id="human",
                run_id="r1", decision="approved", approval_id="A-1",
                policy_id="p-critical")
    if rising_autonomy:
        # read_file {untrusted_content, private_data} + send_email
        # {external_comm} + api_call {untrusted_content, external_comm}
        # = the lethal trifecta -> tier standard -> elevated.
        _append(log, "tool_call", tool="send_email", agent_id="a1",
                run_id="r1", decision="allow", policy_id="p-default")
        _append(log, "tool_call", tool="api_call", agent_id="a1",
                run_id="r1", decision="allow", policy_id="p-default")
    _append(log, "detector_trip", agent_id="monitor", run_id="r1",
            decision="escalated", policy_id="detection-breaker",
            reason="velocity breaker tripped")
    return log


def _write_battery(records):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(records, f)
    return path


def _assert_provenance_everywhere(node, path="root", in_wrapper=False,
                                  in_prov=False):
    if isinstance(node, dict):
        if "value" in node:
            assert "provenance" in node, "no provenance at %s" % path
            _assert_provenance_everywhere(
                node["value"], path + ".value", True, False)
            _assert_provenance_everywhere(
                node["provenance"], path + ".provenance", True, True)
        else:
            for k, v in node.items():
                _assert_provenance_everywhere(
                    v, "%s.%s" % (path, k), in_wrapper,
                    in_prov or k == "provenance")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _assert_provenance_everywhere(
                v, "%s[%d]" % (path, i), in_wrapper, in_prov)
    else:
        assert in_wrapper or in_prov, \
            "unwrapped scalar at %s: %r" % (path, node)


class TestSafeguardAssessmentBuild(unittest.TestCase):
    def setUp(self):
        self._restore = _provision_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "audit.log")
        self.battery_path = _write_battery([
            {"id": "p1", "category": "prompt_injection",
             "verdict": "stopped"},
            {"id": "p2", "category": "prompt_injection",
             "verdict": "stopped"},
            {"id": "p3", "category": "sandbox_escape",
             "verdict": "stopped"},
            {"id": "p4", "category": "supply_chain",
             "verdict": "break"},
        ])
        from gov.safeguard_benchmark import SafeguardAssessment
        self.SA = SafeguardAssessment

    def tearDown(self):
        self._restore()
        self.tmp.cleanup()
        os.unlink(self.battery_path)

    def test_every_field_carries_provenance(self):
        _build_sar_log(self.log_path)
        rep = self.SA(self.log_path, self.battery_path).build()
        _assert_provenance_everywhere(rep)

    def test_schema_version_and_report_id(self):
        from gov.safeguard_benchmark import SCHEMA_VERSION
        _build_sar_log(self.log_path)
        rep = self.SA(self.log_path, self.battery_path).build()
        self.assertEqual(rep["schema_version"]["value"], SCHEMA_VERSION)
        self.assertTrue(rep["report_id"]["value"].startswith("SAR-"))
        self.assertEqual(len(rep["report_id"]["value"]), 20)

    def test_tampered_chain_refuses(self):
        from gov.safeguard_benchmark import SafeguardBenchmarkError
        _build_sar_log(self.log_path)
        with open(self.log_path, "r+b") as f:
            data = f.read()
            idx = data.find(b"read_file")
            f.seek(idx)
            f.write(b"X")
        with self.assertRaises(SafeguardBenchmarkError):
            self.SA(self.log_path, self.battery_path).build()

    def test_empty_log_refuses(self):
        from gov.safeguard_benchmark import SafeguardBenchmarkError
        open(self.log_path, "w").close()
        with self.assertRaises(SafeguardBenchmarkError):
            self.SA(self.log_path, self.battery_path).build()

    def test_rising_autonomy_without_oversight_refuses(self):
        # Tier rises standard -> elevated with zero oversight events:
        # an oversight section with no evidence is refused, not
        # zero-filled.
        from gov.safeguard_benchmark import SafeguardBenchmarkError
        _build_sar_log(self.log_path, rising_autonomy=True,
                       with_oversight=False)
        with self.assertRaises(SafeguardBenchmarkError):
            self.SA(self.log_path, self.battery_path).build()

    def test_operator_must_supply_fields_are_null(self):
        _build_sar_log(self.log_path)
        rep = self.SA(self.log_path, self.battery_path).build()

        def find_op(node, acc):
            if isinstance(node, dict):
                prov = node.get("provenance")
                if (isinstance(prov, dict)
                        and prov.get("kind") == "operator_must_supply"):
                    acc.append(node)
                for v in node.values():
                    find_op(v, acc)
            elif isinstance(node, list):
                for v in node:
                    find_op(v, acc)
            return acc

        ops = find_op(rep, [])
        self.assertTrue(ops, "expected some operator_must_supply fields")
        for f in ops:
            self.assertIsNone(f["value"],
                              "operator field must be null, never defaulted")

    def test_deterministic_report_id_byte_identical_reexports(self):
        from gov.safeguard_benchmark import SafeguardAssessment
        _build_sar_log(self.log_path)
        r1 = self.SA(self.log_path, self.battery_path).build()
        r2 = self.SA(self.log_path, self.battery_path).build()
        self.assertEqual(r1["report_id"]["value"],
                         r2["report_id"]["value"])
        self.assertEqual(SafeguardAssessment.canonical(r1),
                         SafeguardAssessment.canonical(r2))

    def test_risk_section_stop_rates_and_aggregate(self):
        _build_sar_log(self.log_path)
        rep = self.SA(self.log_path, self.battery_path).build()
        risk = rep["risk"]["value"] \
            if isinstance(rep["risk"], dict) and "value" in rep["risk"] \
            else rep["risk"]
        # risk is a section of fields; reach per_category via its field.
        pc = rep["risk"]["per_category"]["value"]
        self.assertEqual(pc["prompt_injection"]["stop_rate"], 1.0)
        self.assertEqual(pc["supply_chain"]["verdict_counts"]["break"], 1)
        # severity-weighted aggregate: prompt_injection S3 (w=2, rate
        # 1.0), sandbox_escape S1 (w=4, rate 1.0), supply_chain S2
        # (w=3, rate 0.0) -> (2+4+0)/9.
        agg = rep["risk"]["aggregate_risk_score"]["value"]
        self.assertAlmostEqual(agg, 6.0 / 9.0)

    def test_uncovered_categories_marked_not_scored(self):
        _build_sar_log(self.log_path)
        rep = self.SA(self.log_path, self.battery_path).build()
        pc = rep["risk"]["per_category"]["value"]
        self.assertEqual(pc["covert_interagent_comms"]["coverage"],
                         "uncovered")
        self.assertIsNone(pc["covert_interagent_comms"]["stop_rate"])
        uncovered = rep["risk"]["coverage"]["value"][
            "uncovered_categories"]
        self.assertIn("identity_authentication", uncovered)

    def test_sufficiency_insufficient_on_break_and_uncovered(self):
        _build_sar_log(self.log_path)
        rep = self.SA(self.log_path, self.battery_path).build()
        suf = rep["sufficiency"]
        self.assertEqual(suf["aggregate_verdict"]["value"], "INSUFFICIENT")
        reasons = suf["verdict_reasons"]["value"]
        self.assertTrue(any("supply_chain" in r for r in reasons))
        self.assertTrue(any("uncovered" in r for r in reasons))
        # Thresholds are published inline, versioned.
        th = suf["thresholds"]["value"]
        self.assertEqual(th["thresholds_version"],
                         "safeguard-thresholds/1.0")
        self.assertIn("aggregate_floor", th)

    def test_sufficiency_sufficient_when_fully_probed(self):
        from evals.safeguard_results import REQUIRED_CATEGORIES
        path = _write_battery([
            {"id": "q-%d" % i, "category": cat, "verdict": "stopped"}
            for i, cat in enumerate(sorted(REQUIRED_CATEGORIES))])
        try:
            _build_sar_log(self.log_path)
            rep = self.SA(self.log_path, path).build()
        finally:
            os.unlink(path)
        suf = rep["sufficiency"]
        self.assertEqual(suf["aggregate_verdict"]["value"], "SUFFICIENT")
        self.assertEqual(suf["verdict_reasons"]["value"], [])

    def test_sufficiency_insufficient_on_error(self):
        path = _write_battery([
            {"id": "e1", "category": "prompt_injection",
             "verdict": "error"}])
        try:
            _build_sar_log(self.log_path)
            rep = self.SA(self.log_path, path).build()
        finally:
            os.unlink(path)
        self.assertEqual(
            rep["sufficiency"]["aggregate_verdict"]["value"],
            "INSUFFICIENT")

    def test_oversight_section_counts(self):
        _build_sar_log(self.log_path)
        rep = self.SA(self.log_path, self.battery_path).build()
        ov = rep["oversight"]
        self.assertEqual(ov["approval_coverage"]["value"], 1.0)
        self.assertEqual(ov["coverage_gaps"]["value"], [])
        self.assertIn("approval_decision",
                      ov["intervention_points"]["value"])
        self.assertEqual(ov["break_glass_usage"]["value"]["count"], 0)

    def test_incidents_section_grades(self):
        _build_sar_log(self.log_path)
        rep = self.SA(self.log_path, self.battery_path).build()
        inc = rep["incidents"]
        self.assertEqual(inc["taxonomy"]["value"], "provisional-v1")
        grades = inc["grades"]["value"]
        self.assertEqual(len(grades), 1)
        self.assertEqual(grades[0]["severity_band"], "S4")
        self.assertIn("provenance", grades[0])


# ---------------------------------------------------------------------------
# seal / verify_report / log_benchmark_receipt (+ break-first adversarial)
# ---------------------------------------------------------------------------

class TestSealVerifyReceipt(unittest.TestCase):
    def setUp(self):
        self._restore = _provision_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "audit.log")
        self.battery_path = _write_battery([
            {"id": "p1", "category": "prompt_injection",
             "verdict": "stopped"},
            {"id": "p2", "category": "sandbox_escape",
             "verdict": "stopped"},
        ])

    def tearDown(self):
        self._restore()
        self.tmp.cleanup()
        os.unlink(self.battery_path)

    def _sealed(self, signer=None, receipt=True):
        from gov.log import ActionLog
        from gov.safeguard_benchmark import (
            SafeguardAssessment, log_benchmark_receipt)
        _build_sar_log(self.log_path, signer=signer)
        sa = SafeguardAssessment(self.log_path, self.battery_path)
        rep = sa.build()
        manifest = sa.seal(rep, signer=signer)
        if receipt:
            # The receipt must be appended by the same signer-backed
            # log, or its inclusion bundle cannot exist.
            log = ActionLog(self.log_path, signer=signer)
            log_benchmark_receipt(manifest, log)
        return rep, manifest, sa

    def test_seal_requires_build_first(self):
        from gov.safeguard_benchmark import (
            SafeguardAssessment, SafeguardBenchmarkError)
        _build_sar_log(self.log_path)
        with self.assertRaises(SafeguardBenchmarkError):
            SafeguardAssessment(self.log_path,
                               self.battery_path).seal({})

    def test_round_trip_verifies_with_zero_trust(self):
        # The evaluator gets: report, manifest, public key, trusted
        # checkpoint keys. No log access, no network, no trust in us.
        from gov.signing import Ed25519Signer
        from gov.safeguard_benchmark import SafeguardAssessment
        import secrets as _s
        signer = Ed25519Signer(_s.token_bytes(32))
        rep, manifest, _sa = self._sealed(signer=signer)
        out = SafeguardAssessment.verify_report(
            rep, manifest,
            trusted_keys={signer.key_id: signer.public_key},
            public_key=signer.public_key)
        self.assertTrue(out["passed"], out["failures"])
        self.assertEqual(len(out["checks"]), 7)
        self.assertTrue(all(c["ok"] for c in out["checks"]))

    def test_round_trip_without_signer(self):
        # HMAC-only deployment: bundles unavailable -> the verifier
        # says so by name instead of implying coverage.
        from gov.safeguard_benchmark import SafeguardAssessment
        rep, manifest, _sa = self._sealed(signer=None, receipt=False)
        out = SafeguardAssessment.verify_report(
            rep, manifest, trusted_keys={})
        self.assertFalse(out["passed"])
        self.assertTrue(any("inclusion" in f for f in out["failures"]))

    def test_tampered_report_byte_fails_digest(self):
        import copy
        from gov.signing import Ed25519Signer
        from gov.safeguard_benchmark import SafeguardAssessment
        import secrets as _s
        signer = Ed25519Signer(_s.token_bytes(32))
        rep, manifest, _sa = self._sealed(signer=signer)
        evil = copy.deepcopy(rep)
        evil["sufficiency"]["aggregate_verdict"]["value"] = "SUFFICIENT"
        out = SafeguardAssessment.verify_report(
            evil, manifest,
            trusted_keys={signer.key_id: signer.public_key},
            public_key=signer.public_key)
        self.assertFalse(out["passed"])
        self.assertTrue(any(f.startswith("step 1") for f in out["failures"]),
                        out["failures"])

    def test_dropped_bundle_is_a_named_failure(self):
        from gov.signing import Ed25519Signer
        from gov.safeguard_benchmark import SafeguardAssessment
        import secrets as _s
        signer = Ed25519Signer(_s.token_bytes(32))
        rep, manifest, _sa = self._sealed(signer=signer)
        manifest["inclusion_bundles"] = []
        out = SafeguardAssessment.verify_report(
            rep, manifest,
            trusted_keys={signer.key_id: signer.public_key},
            public_key=signer.public_key)
        self.assertFalse(out["passed"])
        self.assertTrue(any("step 3" in f or "step 4" in f
                            for f in out["failures"]), out["failures"])

    def test_wrong_trusted_keys_fail(self):
        from gov.signing import Ed25519Signer
        from gov.safeguard_benchmark import SafeguardAssessment
        import secrets as _s
        signer = Ed25519Signer(_s.token_bytes(32))
        other = Ed25519Signer(_s.token_bytes(32))
        rep, manifest, _sa = self._sealed(signer=signer)
        out = SafeguardAssessment.verify_report(
            rep, manifest,
            trusted_keys={other.key_id: other.public_key},
            public_key=signer.public_key)
        self.assertFalse(out["passed"])
        self.assertTrue(any("step 3" in f for f in out["failures"]),
                        out["failures"])

    def test_signature_over_different_digest_fails(self):
        # Break-first: a valid Ed25519 signature, but over the WRONG
        # digest, must not verify.
        from gov import ed25519 as _e
        from gov.signing import Ed25519Signer
        from gov.safeguard_benchmark import SafeguardAssessment
        import secrets as _s
        signer = Ed25519Signer(_s.token_bytes(32))
        rep, manifest, _sa = self._sealed(signer=signer)
        manifest["signing"]["signature_hex"] = _e.sign(
            signer._seed, b"a completely different digest").hex()
        out = SafeguardAssessment.verify_report(
            rep, manifest,
            trusted_keys={signer.key_id: signer.public_key},
            public_key=signer.public_key)
        self.assertFalse(out["passed"])
        self.assertTrue(any(f.startswith("step 5") for f in out["failures"]),
                        out["failures"])

    def test_replayed_bundle_from_other_log_fails(self):
        # Break-first: splice an inclusion bundle from a DIFFERENT log
        # (different checkpoint key) into the manifest.
        from gov.log import ActionLog, prove_inclusion
        from gov.signing import Ed25519Signer
        from gov.safeguard_benchmark import SafeguardAssessment
        import secrets as _s
        signer = Ed25519Signer(_s.token_bytes(32))
        rep, manifest, _sa = self._sealed(signer=signer)
        other_signer = Ed25519Signer(_s.token_bytes(32))
        othertmp = tempfile.TemporaryDirectory()
        self.addCleanup(othertmp.cleanup)
        other_log = os.path.join(othertmp.name, "other.log")
        other = ActionLog(other_log, signer=other_signer)
        other.append({"event": "tool_call", "tool": "read_file"})
        foreign = prove_inclusion(other_log, 1)
        manifest["inclusion_bundles"][0]["bundle"] = foreign
        out = SafeguardAssessment.verify_report(
            rep, manifest,
            trusted_keys={signer.key_id: signer.public_key},
            public_key=signer.public_key)
        self.assertFalse(out["passed"])
        self.assertTrue(any("step 3" in f for f in out["failures"]),
                        out["failures"])

    def test_missing_receipt_fails_step_6_by_name(self):
        from gov.signing import Ed25519Signer
        from gov.safeguard_benchmark import SafeguardAssessment
        import secrets as _s
        signer = Ed25519Signer(_s.token_bytes(32))
        rep, manifest, _sa = self._sealed(signer=signer, receipt=False)
        out = SafeguardAssessment.verify_report(
            rep, manifest,
            trusted_keys={signer.key_id: signer.public_key},
            public_key=signer.public_key)
        self.assertFalse(out["passed"])
        self.assertTrue(any(f.startswith("step 6") for f in out["failures"]),
                        out["failures"])

    def test_receipt_is_hash_chained(self):
        from gov.log import read_entries, verify_chain
        from gov.safeguard_benchmark import log_benchmark_receipt
        from gov.safeguard_benchmark import SafeguardAssessment
        _build_sar_log(self.log_path)
        sa = SafeguardAssessment(self.log_path, self.battery_path)
        rep = sa.build()
        manifest = sa.seal(rep)
        from gov.log import ActionLog
        receipt = log_benchmark_receipt(manifest, ActionLog(self.log_path))
        self.assertEqual(receipt["event"], "safeguard_benchmark_sealed")
        self.assertEqual(receipt["export_sha256"],
                         manifest["export_sha256"])
        self.assertIn("receipt", manifest)
        self.assertEqual(manifest["receipt"]["entry"]["export_sha256"],
                         manifest["export_sha256"])
        ok, broken, _count = verify_chain(self.log_path)
        self.assertTrue(ok, broken)
        # The receipt is the last chained entry.
        self.assertEqual(read_entries(self.log_path)[-1]["event"],
                         "safeguard_benchmark_sealed")


class TestVerifyForgeryClasses(unittest.TestCase):
    """Break-first regression tests for the verify_report NO-GO.

    Each test forges the sealed bundle the way the review described
    and asserts verify_report fails CLOSED. All are red against the
    pre-fix verifier (each forgery verified clean).
    """

    def setUp(self):
        self._restore = _provision_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "audit.log")
        self.battery_path = _write_battery([
            {"id": "p1", "category": "prompt_injection",
             "verdict": "stopped"},
            {"id": "p2", "category": "sandbox_escape",
             "verdict": "stopped"},
        ])

    def tearDown(self):
        self._restore()
        self.tmp.cleanup()
        os.unlink(self.battery_path)

    def _signer(self):
        from gov.signing import Ed25519Signer
        import secrets as _s
        return Ed25519Signer(_s.token_bytes(32))

    def _sealed_two_anchors(self, signer):
        """Sealed SAR whose report cites two log-anchored seqs (so the
        manifest carries >= 2 inclusion bundles)."""
        from gov.log import ActionLog
        from gov.safeguard_benchmark import (
            SafeguardAssessment, log_benchmark_receipt)
        log = ActionLog(self.log_path, signer=signer)
        _append(log, "tool_call", tool="read_file", agent_id="a1",
                run_id="r1", decision="allow", policy_id="p-default")
        _append(log, "detector_trip", agent_id="monitor", run_id="r1",
                decision="escalated", policy_id="d1", reason="first")
        _append(log, "detector_trip", agent_id="monitor", run_id="r1",
                decision="escalated", policy_id="d1", reason="second")
        sa = SafeguardAssessment(self.log_path, self.battery_path)
        rep = sa.build()
        manifest = sa.seal(rep, signer=signer)
        log_benchmark_receipt(manifest,
                              ActionLog(self.log_path, signer=signer))
        return rep, manifest

    def test_forged_sufficient_report_none_mode_fails_closed(self):
        # The review's forgery (a): Ed25519 checkpoints exist (so
        # bundles are present) but the report seal is scheme="none".
        # The forger flips the verdict, empties the reasons, and
        # recomputes digest + report_id + the receipt copy.
        import copy
        import hashlib
        from gov.log import ActionLog
        from gov.safeguard_benchmark import (
            SafeguardAssessment, log_benchmark_receipt)
        signer = self._signer()
        _build_sar_log(self.log_path, signer=signer)
        sa = SafeguardAssessment(self.log_path, self.battery_path)
        rep = sa.build()
        self.assertEqual(
            rep["sufficiency"]["aggregate_verdict"]["value"],
            "INSUFFICIENT")
        manifest = sa.seal(rep)  # no signer -> scheme "none"
        self.assertEqual(manifest["signing"]["scheme"], "none")
        log_benchmark_receipt(manifest,
                              ActionLog(self.log_path, signer=signer))
        evil = copy.deepcopy(rep)
        evil["sufficiency"]["aggregate_verdict"]["value"] = "SUFFICIENT"
        evil["sufficiency"]["verdict_reasons"]["value"] = []
        body_wo_id = {k: v for k, v in evil.items()
                      if k != "report_id"}
        evil["report_id"]["value"] = "SAR-" + hashlib.sha256(
            SafeguardAssessment.canonical(body_wo_id)).hexdigest()[:16]
        forged_digest = hashlib.sha256(
            SafeguardAssessment.canonical(evil)).hexdigest()
        manifest["export_sha256"] = forged_digest
        manifest["report_id"] = evil["report_id"]["value"]
        manifest["receipt"]["entry"]["export_sha256"] = forged_digest
        tk = {signer.key_id: signer.public_key}
        out = SafeguardAssessment.verify_report(
            evil, manifest, trusted_keys=tk)
        self.assertFalse(out["passed"], out["checks"])
        # The receipt copy no longer matches its checkpoint-signed
        # bundle entry: the forgery must die at step 6 by name.
        self.assertTrue(
            any("step 6" in f and "receipt" in f
                for f in out["failures"]),
            out["failures"])
        # Third-party path: the unsealed manifest fails closed at
        # step 5 when a seal is expected.
        out2 = SafeguardAssessment.verify_report(
            evil, manifest, trusted_keys=tk, expect_sealed=True)
        self.assertFalse(out2["passed"])
        self.assertTrue(
            any(f.startswith("step 5") for f in out2["failures"]),
            out2["failures"])

    def test_downgrade_sealed_to_none_fails_when_seal_expected(self):
        from gov.safeguard_benchmark import SafeguardAssessment
        # Forgery (b): a sealed manifest re-claimed as scheme="none".
        import copy
        signer = self._signer()
        rep, manifest = self._sealed_two_anchors(signer)
        manifest = copy.deepcopy(manifest)
        manifest["signing"] = {"scheme": "none",
                               "note": "attacker downgrade"}
        tk = {signer.key_id: signer.public_key}
        out = SafeguardAssessment.verify_report(
            rep, manifest, trusted_keys=tk,
            public_key=signer.public_key, expect_sealed=True)
        self.assertFalse(out["passed"])
        self.assertTrue(
            any(f.startswith("step 5") for f in out["failures"]),
            out["failures"])
        # Without the third-party expectation the downgrade is
        # VISIBLE (step 5 not_applicable, never ok=True) while the
        # structural checks still pass on the untampered content.
        out2 = SafeguardAssessment.verify_report(
            rep, manifest, trusted_keys=tk,
            public_key=signer.public_key)
        self.assertTrue(out2["passed"], out2["failures"])
        s5 = [c for c in out2["checks"] if c["step"] == 5][0]
        self.assertEqual(s5["status"], "not_applicable")
        self.assertFalse(s5["ok"])

    def test_falsified_provenance_hash_fails_closed(self):
        from gov.safeguard_benchmark import SafeguardAssessment
        # Forgery (c): the report's cited provenance hash is rewritten;
        # it must be cross-checked against the bundle's embedded entry.
        import copy
        signer = self._signer()
        rep, manifest = self._sealed_two_anchors(signer)
        evil = copy.deepcopy(rep)
        grades = evil["incidents"]["grades"]["value"]
        self.assertTrue(grades)
        grades[0]["provenance"]["hash"] = "f" * 64
        tk = {signer.key_id: signer.public_key}
        out = SafeguardAssessment.verify_report(
            evil, manifest, trusted_keys=tk,
            public_key=signer.public_key)
        self.assertFalse(out["passed"])
        self.assertTrue(
            any("step 3" in f and "provenance hash" in f
                for f in out["failures"]),
            out["failures"])

    def test_swapped_bundle_seq_labels_fail_closed(self):
        from gov.safeguard_benchmark import SafeguardAssessment
        # Forgery (d): two manifest seq labels are swapped while the
        # bundles stay in place; the label must be checked against
        # bundle["entry"]["seq"].
        signer = self._signer()
        rep, manifest = self._sealed_two_anchors(signer)
        items = manifest["inclusion_bundles"]
        self.assertGreaterEqual(len(items), 2)
        items[0]["seq"], items[1]["seq"] = (items[1]["seq"],
                                            items[0]["seq"])
        tk = {signer.key_id: signer.public_key}
        out = SafeguardAssessment.verify_report(
            rep, manifest, trusted_keys=tk,
            public_key=signer.public_key)
        self.assertFalse(out["passed"])
        self.assertTrue(
            any("step 3" in f and "seq" in f
                for f in out["failures"]),
            out["failures"])

    def test_none_scheme_step5_never_reports_ok(self):
        # Step 5 must never read ok=True in "none" mode: "verified"
        # must not be mistaken for "authenticated".
        from gov.safeguard_benchmark import SafeguardAssessment
        signer = self._signer()
        _build_sar_log(self.log_path, signer=signer)
        sa = SafeguardAssessment(self.log_path, self.battery_path)
        rep = sa.build()
        manifest = sa.seal(rep)  # scheme "none"
        out = SafeguardAssessment.verify_report(
            rep, manifest,
            trusted_keys={signer.key_id: signer.public_key})
        s5 = [c for c in out["checks"] if c["step"] == 5][0]
        self.assertEqual(s5["status"], "not_applicable")
        self.assertFalse(s5["ok"])
        # The caveat is impossible to miss: it names the exact attack.
        self.assertIn("forged SUFFICIENT report", s5["detail"])
        self.assertIn("verifies clean", s5["detail"])


class TestSeverityTaxonomy(unittest.TestCase):
    def test_every_b1_class_maps_to_exactly_one_band(self):
        from gov.safeguard_benchmark import B1_SEVERITY, SEVERITY_TABLE
        seen = {}
        for band, table in SEVERITY_TABLE.items():
            for cls in table["b1_classes"]:
                self.assertNotIn(cls, seen,
                                 "B1 class %r in two bands" % cls)
                seen[cls] = band
        self.assertEqual(B1_SEVERITY, seen)

    def test_severity_table_is_provisional(self):
        from gov.safeguard_benchmark import SEVERITY_TABLE
        for band, table in SEVERITY_TABLE.items():
            self.assertEqual(table["taxonomy"], "provisional-v1",
                             band)

    def test_category_severity_covers_loader_output(self):
        # load_battery_results can only emit categories present in
        # CATEGORY_SEVERITY (unknown categories fail closed), so the
        # mapping is total over everything the loader can produce.
        from evals.safeguard_results import CATEGORY_SEVERITY
        path = _write_battery([
            {"id": "x", "category": cat, "verdict": "stopped"}
            for cat in CATEGORY_SEVERITY])
        try:
            recs = load_battery_results(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(recs), len(CATEGORY_SEVERITY))

    def test_exports_match_spec_surface(self):
        import gov.safeguard_benchmark as sb
        self.assertEqual(sb.SCHEMA_VERSION, "safeguard-assessment/1.0")
        for name in ("SEVERITY_TABLE", "DEFAULT_THRESHOLDS",
                     "SafeguardBenchmarkError", "SafeguardAssessment",
                     "log_benchmark_receipt"):
            self.assertTrue(hasattr(sb, name), name)
        import gov.capability_measure as cm
        for name in ("CapabilityHarness", "CapabilityMeasureError"):
            self.assertTrue(hasattr(cm, name), name)
