"""Unit tests for gov.drift: fingerprints, store, statistics, detection."""

import json
import math
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
# Keyed Row-9 chains: the drift store's HMAC chain needs a configured
# key (keyprovider idiom — the keyfixture test hook only fires when
# GOV_LOG_KEY is absent, i.e. test contexts).
sys.path.insert(0, os.path.dirname(__file__))
from keyfixture import provision_test_key  # noqa: E402
provision_test_key()

from gov import drift  # noqa: E402


def _fp(tools, egress_bytes=0, denies=0, run_seq=0):
    return drift.RunFingerprint(
        tool_counts=dict(tools),
        decisions={"allow": sum(tools.values()), "require_approval": 0,
                   "deny": denies},
        egress_bytes=egress_bytes,
        run_seq=run_seq,
        run_id="r%d" % run_seq,
    )


def _store():
    tmp = tempfile.mkdtemp(prefix="drift_ut_")
    return drift.DriftStore(Path(tmp) / "profiles")


class FingerprintValidationTest(unittest.TestCase):
    def test_negative_tool_count_refused(self):
        with self.assertRaises(ValueError):
            drift.RunFingerprint({"a": -1}, {"allow": 1})

    def test_unknown_decision_key_refused(self):
        with self.assertRaises(ValueError):
            drift.RunFingerprint({"a": 1}, {"allow": 1, "maybe": 2})

    def test_negative_egress_refused(self):
        with self.assertRaises(ValueError):
            drift.RunFingerprint({"a": 1}, {"allow": 1}, egress_bytes=-5)

    def test_roundtrip(self):
        fp = _fp({"search": 3}, egress_bytes=100, run_seq=7)
        fp2 = drift.RunFingerprint.from_dict(fp.to_dict())
        self.assertEqual(fp2.to_dict(), fp.to_dict())


class FingerprintFromEntriesTest(unittest.TestCase):
    def test_folds_known_shapes(self):
        entries = [
            {"event": "tool_call", "tool": "search"},
            {"event": "tool_call", "tool": "search"},
            {"event": "action", "tool": "email"},
            {"decision": "allow"},
            {"decision": "deny"},
            {"event": "approval_requested"},
            {"event": "approval_denied"},
            {"event": "egress", "bytes": 500},
            {"event": "egress", "bytes": "not-a-number"},
            {"event": "something_else", "tool": "search"},  # ignored shape
            "not-a-dict",  # ignored
        ]
        fp = drift.fingerprint_from_entries(entries)
        self.assertEqual(fp.tool_counts, {"search": 2, "email": 1})
        self.assertEqual(fp.decisions["allow"], 1)
        self.assertEqual(fp.decisions["deny"], 1)
        self.assertEqual(fp.approvals_requested, 1)
        self.assertEqual(fp.approvals_denied, 1)
        self.assertEqual(fp.egress_events, 2)
        self.assertEqual(fp.egress_bytes, 500)


class ChiSquareTest(unittest.TestCase):
    def test_zero_stat_gives_p_one(self):
        self.assertEqual(drift.chi_square_sf(0.0, 3), 1.0)

    def test_known_value_strong(self):
        # Worked example: observed [90, 10] vs expected [50, 50]:
        # chi2 = 1600/50 + 1600/50 = 64, df = 1.
        # P(|Z| > 8) = 2*(1 - Phi(8)) ~= 1.24e-15 (independent bound).
        p = drift.chi_square_sf(64.0, 1)
        self.assertLess(p, 1e-12)
        self.assertGreater(p, 0.0)

    def test_known_value_weak(self):
        # chi2 = 4.0, df = 1 -> p ~= 0.0455 (between 0.01 and 0.05).
        p = drift.chi_square_sf(4.0, 1)
        self.assertGreater(p, 0.01)
        self.assertLess(p, 0.05)

    def test_no_signal_at_exact_match(self):
        p = drift.chi_square_sf(0.001, 5)
        self.assertGreater(p, 0.99)

    def test_bad_df_refused(self):
        with self.assertRaises(ValueError):
            drift.chi_square_sf(1.0, 0)


class MannKendallTest(unittest.TestCase):
    def test_strictly_increasing(self):
        # n=5, S=10, var=16.67 -> z = 9/4.082 ~= 2.204.
        z = drift.mann_kendall_z([1, 2, 3, 4, 5])
        self.assertGreater(z, 2.20)
        self.assertLess(z, 2.21)

    def test_constant_series_zero(self):
        self.assertEqual(drift.mann_kendall_z([5, 5, 5, 5, 5]), 0.0)

    def test_decreasing_negative(self):
        self.assertLess(drift.mann_kendall_z([5, 4, 3, 2, 1]), 0.0)

    def test_too_few_points_zero(self):
        self.assertEqual(drift.mann_kendall_z([1, 2, 3]), 0.0)


class StoreChainTest(unittest.TestCase):
    def test_record_and_verify(self):
        s = _store()
        s.record_run("a1", "p", _fp({"x": 1}))
        s.record_run("a1", "p", _fp({"x": 2}))
        self.assertTrue(s.verify_chain("a1"))
        self.assertEqual(len(s.runs("a1")), 2)

    def test_tamper_breaks_chain(self):
        s = _store()
        s.record_run("a1", "p", _fp({"x": 1}))
        p = s._path("a1")
        lines = p.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["fingerprint"]["egress_bytes"] = 999999
        p.write_text(json.dumps(rec) + "\n", encoding="utf-8")
        self.assertFalse(s.verify_chain("a1"))

    def test_dropped_record_breaks_linkage(self):
        s = _store()
        s.record_run("a1", "p", _fp({"x": 1}))
        s.record_run("a1", "p", _fp({"x": 2}))
        p = s._path("a1")
        lines = p.read_text(encoding="utf-8").splitlines()
        p.write_text(lines[1] + "\n", encoding="utf-8")  # drop first
        self.assertFalse(s.verify_chain("a1"))

    def test_audit_before_mutation(self):
        # F167: a failing audit aborts the record -- nothing is written.
        def bad_audit(event):
            raise RuntimeError("audit down")
        s = _store()
        with self.assertRaises(RuntimeError):
            s.record_run("a1", "p", _fp({"x": 1}), audit=bad_audit)
        self.assertEqual(s.runs("a1"), [])

    def test_agent_id_sanitized(self):
        s = _store()
        s.record_run("agent/../../evil", "p", _fp({"x": 1}))
        self.assertTrue(s.verify_chain("agent/../../evil"))
        self.assertNotIn("..", s._path("agent/../../evil").name)

    def test_wrong_type_refused(self):
        s = _store()
        with self.assertRaises(TypeError):
            s.record_run("a1", "p", {"not": "a fingerprint"})


class KeyedChainTest(unittest.TestCase):
    """Row-9 keyed chains: HMAC-SHA256 appends, legacy compatibility.

    New records carry ``chain_keyed: true`` and a MAC under the
    deployment key (resolved through gov.keyprovider, the audit log's
    idiom). Pre-upgrade records carry the legacy unkeyed digest and
    verify without migration.
    """

    def _legacy_records(self, n=2):
        # Hand-built pre-upgrade chain: unkeyed SHA-256 digests, no
        # chain_keyed marker — what the pre-keyed store wrote.
        from gov.chained_store import canonical, sha256_hex
        recs, prev = [], ""
        for i in range(n):
            rec = {
                "agent_id": "a1",
                "principal": "p",
                "fingerprint": _fp({"x": i}).to_dict(),
                "drift_version": 1,
                "recorded_at": "2026-01-01T00:00:0%d+00:00" % i,
                "run_seq": i,
                "prev_digest": prev,
            }
            rec["digest"] = sha256_hex(canonical(rec))
            prev = rec["digest"]
            recs.append(rec)
        return recs

    @staticmethod
    def _write(store, recs):
        store._path("a1").write_text(
            "".join(json.dumps(r, sort_keys=True,
                               separators=(",", ":")) + "\n"
                    for r in recs),
            encoding="utf-8")

    def test_new_records_are_keyed(self):
        s = _store()
        rec = s.record_run("a1", "p", _fp({"x": 1}))
        self.assertTrue(rec.get("chain_keyed"))
        self.assertIn("key_epoch", rec)
        self.assertTrue(s.verify_chain("a1"))

    def test_legacy_chain_verifies(self):
        s = _store()
        self._write(s, self._legacy_records(3))
        self.assertTrue(s.verify_chain("a1"))

    def test_keyed_append_onto_legacy_chain(self):
        s = _store()
        self._write(s, self._legacy_records(2))
        s.record_run("a1", "p", _fp({"x": 9}))
        self.assertTrue(s.verify_chain("a1"))

    def test_history_rewrite_recompute_fails(self):
        # The off-band attacker rewrites history and recomputes every
        # digest with the PUBLIC unkeyed scheme: without the key the
        # forged chain must not verify.
        from gov.chained_store import canonical, sha256_hex
        s = _store()
        s.record_run("a1", "p", _fp({"x": 1}))
        s.record_run("a1", "p", _fp({"x": 2}))
        recs = [json.loads(line)
                for line in s._path("a1").read_text(
                    encoding="utf-8").splitlines()]
        recs[0]["fingerprint"]["tool_counts"]["x"] = 999
        prev = ""
        for rec in recs:
            rec.pop("digest", None)
            rec["prev_digest"] = prev
            rec["digest"] = sha256_hex(canonical(rec))
            prev = rec["digest"]
        self._write(s, recs)
        self.assertFalse(s.verify_chain("a1"))

    def test_wrong_key_rejected(self):
        s = _store()
        s.record_run("a1", "p", _fp({"x": 1}))
        old = os.environ.get("GOV_LOG_KEY")
        os.environ["GOV_LOG_KEY"] = "ff" * 32
        try:
            self.assertFalse(s.verify_chain("a1"))
        finally:
            os.environ["GOV_LOG_KEY"] = old
        self.assertTrue(s.verify_chain("a1"))

    def test_no_key_refuses_append_and_verify(self):
        from gov.keys import NoKeyConfiguredError
        old_key = os.environ.pop("GOV_LOG_KEY", None)
        old_ring = os.environ.pop("GOV_KEYRING_PATH", None)
        try:
            s = _store()
            with self.assertRaises(NoKeyConfiguredError):
                s.record_run("a1", "p", _fp({"x": 1}))
            self.assertEqual(s.runs("a1"), [])  # fail-closed: unwritten
        finally:
            if old_key is not None:
                os.environ["GOV_LOG_KEY"] = old_key
            if old_ring is not None:
                os.environ["GOV_KEYRING_PATH"] = old_ring
        # Keyed history with no key configured: cannot verify, not
        # silently treated as intact.
        s = _store()
        s.record_run("a1", "p", _fp({"x": 1}))
        old_key = os.environ.pop("GOV_LOG_KEY", None)
        old_ring = os.environ.pop("GOV_KEYRING_PATH", None)
        try:
            self.assertFalse(s.verify_chain("a1"))
        finally:
            if old_key is not None:
                os.environ["GOV_LOG_KEY"] = old_key
            if old_ring is not None:
                os.environ["GOV_KEYRING_PATH"] = old_ring
        self.assertTrue(s.verify_chain("a1"))


class DetectDriftTest(unittest.TestCase):
    def _benign_store(self, n=10, agent="a"):
        s = _store()
        for i in range(n):
            s.record_run(agent, "p",
                         _fp({"search": 20, "summarize": 10,
                              "http_post": 2, "email": 3},
                             egress_bytes=4000, run_seq=i))
        return s

    def test_insufficient_data_silent(self):
        s = self._benign_store(n=5)
        res = drift.detect_drift(s, "a")
        self.assertEqual(res.level, "silent")
        self.assertEqual(res.reason, "insufficient_data")

    def test_stable_silent(self):
        s = self._benign_store(n=12)
        res = drift.detect_drift(s, "a")
        self.assertEqual(res.level, "silent")
        self.assertEqual(res.signals, [])

    def test_ramp_reaches_hold(self):
        s = self._benign_store(n=5)
        for i in range(5, 15):
            n = 4 + 4 * (i - 5)
            s.record_run("a", "p",
                         _fp({"search": 20, "summarize": 10,
                              "http_post": n, "email": 3},
                             egress_bytes=8000 + 8000 * (i - 5),
                             run_seq=i))
        res = drift.detect_drift(s, "a")
        self.assertEqual(res.level, "hold")
        kinds = {sg.kind for sg in res.signals}
        self.assertIn("egress_trend", kinds)
        self.assertIn("tool_distribution", kinds)

    def test_novel_tool_capped_at_weak(self):
        s = self._benign_store(n=5)
        for i in range(5, 10):
            tools = {"search": 20, "summarize": 10, "http_post": 2,
                     "email": 3, "translate": 30}
            s.record_run("a", "p", _fp(tools, egress_bytes=4000,
                                       run_seq=i))
        res = drift.detect_drift(s, "a")
        # Novelty is benign evolution until corroborated: at most warn.
        self.assertNotEqual(res.level, "hold")
        dist = [sg for sg in res.signals
                if sg.kind == "tool_distribution"]
        if dist:
            self.assertEqual(dist[0].strength, "weak")
            self.assertTrue(dist[0].detail["novel_capped"])

    def test_deny_rate_spike_warns(self):
        s = _store()
        for i in range(5):
            s.record_run("a", "p", _fp({"search": 30}, run_seq=i))
        for i in range(5, 13):
            s.record_run("a", "p",
                         _fp({"search": 30}, denies=20, run_seq=i))
        res = drift.detect_drift(s, "a")
        kinds = {sg.kind for sg in res.signals}
        self.assertIn("deny_rate", kinds)
        # One strong signal alone -> warn, not hold.
        self.assertEqual(res.level, "warn")

    def test_poisoned_baseline_silent_ceiling(self):
        # Honest ceiling: from-birth badness has no clean baseline, so
        # no change is measured. Documented, not hidden.
        s = _store()
        for i in range(10):
            s.record_run("a", "p",
                         _fp({"http_post": 60}, egress_bytes=200000,
                             run_seq=i))
        res = drift.detect_drift(s, "a")
        self.assertEqual(res.level, "silent")

    def test_tiny_denominators_no_rate_signal(self):
        # 2 decisions per run: rates are noise, must not fire.
        s = _store()
        for i in range(10):
            s.record_run("a", "p", _fp({"x": 2}, run_seq=i))
        res = drift.detect_drift(s, "a")
        self.assertEqual(res.level, "silent")

    def test_wrong_store_type_refused(self):
        with self.assertRaises(TypeError):
            drift.detect_drift(object(), "a")


class ExecutorWiringTest(unittest.TestCase):
    def _executor(self, drift_store):
        from gov.log import ActionLog
        from gov.approvals import ApprovalQueue
        from gov.executor import ToolExecutor
        from gov.policy import PolicyEngine
        repo = Path(__file__).resolve().parent.parent
        run_dir = Path(tempfile.mkdtemp(prefix="drift_ex_"))
        policy = PolicyEngine(str(repo / "policies" / "default.yaml"))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        ex = ToolExecutor(
            run_dir, policy, log, approvals,
            ledger_path=run_dir / "egress_ledger.jsonl",
            ungoverned_ack=("I acknowledge this run is ungoverned and "
                            "I accept the risk."),
            drift_store=drift_store,
        )
        return ex, log, approvals

    def test_no_store_zero_behavior_change(self):
        ex, log, approvals = self._executor(None)
        res = ex.check_run_drift("a")
        self.assertEqual(res.level, "silent")
        self.assertEqual(res.reason, "no_drift_store")

    def test_hold_queues_drift_review(self):
        store = _store()
        for i in range(5):
            store.record_run("a", "p",
                             _fp({"search": 20, "http_post": 2},
                                 egress_bytes=4000, run_seq=i))
        ex, log, approvals = self._executor(store)
        ident = ex.mint_identity("a", "worker", "user-1")
        held = False
        for i in range(5, 15):
            n = 4 + 4 * (i - 5)
            res = ex.check_run_drift(
                "a",
                fingerprint=_fp({"search": 20, "http_post": n},
                                egress_bytes=8000 + 8000 * (i - 5),
                                run_seq=i),
                identity=ident)
            if res.level == "hold":
                held = True
        self.assertTrue(held)
        flags = [r.get("policy_flag") for r in approvals.all()]
        self.assertIn("drift_hold", flags)

    def test_hold_requires_identity(self):
        store = _store()
        for i in range(5):
            store.record_run("a", "p",
                             _fp({"search": 20, "http_post": 2},
                                 egress_bytes=4000, run_seq=i))
        ex, log, approvals = self._executor(store)
        with self.assertRaises(TypeError):
            for i in range(5, 15):
                n = 4 + 4 * (i - 5)
                ex.check_run_drift(
                    "a",
                    fingerprint=_fp({"search": 20, "http_post": n},
                                    egress_bytes=8000 + 8000 * (i - 5),
                                    run_seq=i),
                    identity=None)

    def test_watch_only_audits_no_approval(self):
        store = _store()
        for i in range(5):
            store.record_run("a", "p",
                             _fp({"search": 20, "summarize": 10},
                                 egress_bytes=4000, run_seq=i))
        ex, log, approvals = self._executor(store)
        ident = ex.mint_identity("a", "worker", "user-1")
        # Novel tool at moderate volume: distribution signal only.
        for i in range(5, 10):
            res = ex.check_run_drift(
                "a",
                fingerprint=_fp({"search": 20, "summarize": 10,
                                 "translate": 30},
                                egress_bytes=4000, run_seq=i),
                identity=ident)
        self.assertIn(res.level, ("silent", "watch", "warn"))
        self.assertNotEqual(res.level, "hold")
        flags = [r.get("policy_flag") for r in approvals.all()]
        self.assertNotIn("drift_hold", flags)


if __name__ == "__main__":
    unittest.main()
