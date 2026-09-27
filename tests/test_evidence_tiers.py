"""Unit tests for gov.evidence_tiers (hot/warm/cold evidence retention).

Red-first: these tests were written against the probe battery's
break-first findings (10/10 BREAK pre-seam) and assert the controls
that closed them. They run hermetically: explicit test key via
tests/keyfixture, unique tmpdirs, injectable ``now`` for TTL.
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import evidence_tiers as et
from gov import log as _log
from gov.log import ActionLog

_ENV_VARS = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")


def _policy(ttl=10, warm_ttl=3600):
    return et.RetentionPolicy(
        policy_id="test-pol",
        hot_ttl_by_event={"*": ttl},
        warm_fields_by_event={"*": ["event", "ts", "i"]},
        warm_ttl_seconds=warm_ttl)


class EvidenceTierBase(unittest.TestCase):
    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in _ENV_VARS}
        os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
        try:
            from tests.keyfixture import provision_test_key
        except ImportError:
            from keyfixture import provision_test_key
        provision_test_key(epoch="test")
        self.tmp = Path(tempfile.mkdtemp(prefix="test-evtiers-"))
        self.log_path = str(self.tmp / "actions.jsonl")
        self.now = datetime.now(timezone.utc)

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def make_log(self, n, event="probe"):
        log = ActionLog(self.log_path)
        for i in range(n):
            log.append({"event": event, "i": i})
        return log

    def read_hot(self):
        with open(self.log_path, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def read_warm(self):
        p = self.tmp / "warm.jsonl"
        if not p.exists():
            return []
        with open(p, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def retire(self, policy=None, now=None):
        return et.retire_hot(
            self.log_path, policy or _policy(),
            now=now or (self.now + timedelta(seconds=3600)))


class PolicyValidationTests(EvidenceTierBase):
    def test_rejects_missing_star_ttl(self):
        with self.assertRaises(ValueError):
            et.RetentionPolicy(policy_id="x",
                               hot_ttl_by_event={"probe": 10},
                               warm_fields_by_event={"*": ["event", "ts"]},
                               warm_ttl_seconds=3600)

    def test_rejects_nonpositive_ttl(self):
        with self.assertRaises(ValueError):
            et.RetentionPolicy(policy_id="x",
                               hot_ttl_by_event={"*": 0},
                               warm_fields_by_event={"*": ["event", "ts"]},
                               warm_ttl_seconds=3600)

    def test_rejects_secretish_fields(self):
        for bad in ("api_key", "secret", "password", "token", "ssn"):
            with self.assertRaises(ValueError):
                et.RetentionPolicy(
                    policy_id="x", hot_ttl_by_event={"*": 10},
                    warm_fields_by_event={"*": ["event", "ts", bad]},
                    warm_ttl_seconds=3600)

    def test_rejects_chain_fields(self):
        for bad in ("hash", "prev_hash"):
            with self.assertRaises(ValueError):
                et.RetentionPolicy(
                    policy_id="x", hot_ttl_by_event={"*": 10},
                    warm_fields_by_event={"*": ["event", "ts", bad]},
                    warm_ttl_seconds=3600)

    def test_requires_event_and_ts_fields(self):
        # TTL re-audit needs the event class + timestamp in every
        # projection; a policy that drops either is refused fail-fast.
        with self.assertRaises(ValueError):
            et.RetentionPolicy(policy_id="x",
                               hot_ttl_by_event={"*": 10},
                               warm_fields_by_event={"*": ["ts"]},
                               warm_ttl_seconds=3600)
        with self.assertRaises(ValueError):
            et.RetentionPolicy(policy_id="x",
                               hot_ttl_by_event={"*": 10},
                               warm_fields_by_event={"*": ["event"]},
                               warm_ttl_seconds=3600)


class RetireHotTests(EvidenceTierBase):
    def test_basic_retire_and_verify(self):
        self.make_log(6)
        res = self.retire()
        self.assertEqual(res["retired"], 6)
        hot = self.read_hot()
        # Only the retirement marker survives in hot.
        self.assertEqual(len(hot), 1)
        self.assertTrue(et._is_hot_marker(hot[0]))
        self.assertEqual(
            (hot[0]["first_seq"], hot[0]["last_seq"]), (1, 6))
        warm = self.read_warm()
        self.assertEqual(len(warm), 1)
        self.assertEqual(warm[0]["kind"], "retirement_summary")
        v = et.verify_tiered(self.log_path, _policy())
        self.assertTrue(v["ok"], v["error"])
        self.assertEqual(v["retirements"][0]["range"], [1, 6])

    def test_ttl_prefix_only(self):
        self.make_log(4)
        # 4 old entries expire; 2 fresh ones must survive.
        t1 = datetime.now(timezone.utc)
        res = et.retire_hot(self.log_path, _policy(ttl=10),
                            now=self.now + timedelta(seconds=11))
        self.assertEqual(res["retired"], 4)
        log2 = ActionLog(self.log_path)
        log2.append({"event": "probe", "i": "new-1"})
        log2.append({"event": "probe", "i": "new-2"})
        # Retire "now" is before the fresh entries' TTL expires.
        res2 = et.retire_hot(self.log_path, _policy(ttl=10),
                             now=t1 + timedelta(seconds=5))
        self.assertEqual(res2["retired"], 0)  # fresh ones untouched
        hot = self.read_hot()
        n_markers = sum(1 for e in hot if et._is_hot_marker(e))
        n_live = sum(1 for e in hot if not et._is_hot_marker(e))
        self.assertEqual(n_markers, 1)
        self.assertEqual(n_live, 2)

    def test_noop_when_nothing_expired(self):
        self.make_log(3)
        res = et.retire_hot(self.log_path, _policy(ttl=3600),
                            now=self.now)
        self.assertEqual(res["retired"], 0)
        self.assertFalse(res["truncated"])
        self.assertEqual(len(self.read_hot()), 3)

    def test_markers_are_permanent(self):
        # Two retirements: both markers stay; ranges tile from 1.
        self.make_log(4)
        self.retire()
        ActionLog(self.log_path).append({"event": "probe", "i": "x"})
        ActionLog(self.log_path).append({"event": "probe", "i": "y"})
        res = self.retire()
        self.assertEqual(res["retired"], 3)  # old marker + 2 live
        hot = self.read_hot()
        markers = [e for e in hot if et._is_hot_marker(e)]
        self.assertEqual(len(markers), 2)
        self.assertEqual(
            (markers[0]["first_seq"], markers[0]["last_seq"]), (1, 4))
        self.assertEqual(
            (markers[1]["first_seq"], markers[1]["last_seq"]), (5, 7))
        v = et.verify_tiered(self.log_path, _policy())
        self.assertTrue(v["ok"], v["error"])

    def test_second_summary_embeds_old_marker(self):
        self.make_log(2)
        self.retire()
        ActionLog(self.log_path).append({"event": "probe", "i": "z"})
        self.retire()
        warm = self.read_warm()
        s2 = [s for s in warm
              if s["kind"] == "retirement_summary"][-1]
        # The old marker is embedded in the new summary's projections
        # (audit-visible chain of custody).
        marker_projs = [p for p in s2["projections"]
                        if p.get("event") == et.RETIRE_EVENT]
        self.assertEqual(len(marker_projs), 1)

    def test_idempotent_rerun_is_noop(self):
        self.make_log(3)
        self.retire()
        res = self.retire()
        self.assertEqual(res["retired"], 0)
        self.assertFalse(res["truncated"])
        v = et.verify_tiered(self.log_path, _policy())
        self.assertTrue(v["ok"], v["error"])

    def test_refuses_unverifiable_log(self):
        self.make_log(3)
        lines = open(self.log_path, encoding="utf-8").read().splitlines()
        # Delete a middle entry without any covering summary.
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(lines[0] + "\n" + lines[2] + "\n")
        with self.assertRaises(et.TierError):
            self.retire()


class SummaryCommitmentTests(EvidenceTierBase):
    def test_commitment_recomputes(self):
        self.make_log(5)
        self.retire()
        s = self.read_warm()[0]
        self.assertEqual(et._summary_commitment(s),
                         s["summary_digest"])
        # Range and count bind the exact retired set.
        self.assertEqual((s["first_seq"], s["last_seq"]), (1, 5))
        self.assertEqual(s["count"], 5)
        self.assertEqual(len(s["projections"]), 5)

    def test_inclusion_proof_roundtrip(self):
        self.make_log(5)
        originals = self.read_hot()  # operator backup of retired set
        self.retire()
        s = self.read_warm()[0]
        for idx, entry in enumerate(originals):
            proof = et.prove_inclusion_in_summary(entry, idx, originals)
            self.assertTrue(
                et.verify_inclusion_in_summary(entry, idx, proof, s))
            tampered = dict(entry)
            tampered["i"] = "forged"
            self.assertFalse(
                et.verify_inclusion_in_summary(tampered, idx, proof, s))

    def test_tampered_summary_rejected(self):
        self.make_log(4)
        self.retire()
        wp = self.tmp / "warm.jsonl"
        lines = open(wp, encoding="utf-8").read().splitlines()
        obj = json.loads(lines[0])
        obj["projections"][0]["i"] = "tampered"
        lines[0] = json.dumps(obj, sort_keys=True)
        with open(wp, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        # Tampering is loud (here the warm MAC catches it first; the
        # summary commitment recompute is the second layer).
        v = et.verify_tiered(self.log_path, _policy())
        self.assertFalse(v["ok"])


class VerificationTests(EvidenceTierBase):
    def _retire_and_grow(self):
        self.make_log(6)
        self.retire()
        log = ActionLog(self.log_path)
        for i in range(4):
            log.append({"event": "probe", "i": "live-%d" % i})

    def test_hot_deletion_without_summary_loud(self):
        self._retire_and_grow()
        lines = open(self.log_path, encoding="utf-8").read().splitlines()
        # lines[0] = marker, lines[1..4] = live. Drop 2 middles.
        evil = [lines[0], lines[1], lines[4]]
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(evil) + "\n")
        v = et.verify_tiered(self.log_path, _policy())
        self.assertFalse(v["ok"])
        self.assertIn("no covering retirement", v["error"])

    def test_marker_deletion_loud(self):
        self.make_log(4)
        self.retire()
        ActionLog(self.log_path).append({"event": "probe", "i": "q"})
        hot = self.read_hot()
        # Delete the marker: the retired head loses its anchor.
        live_only = [e for e in hot if not et._is_hot_marker(e)]
        with open(self.log_path, "w", encoding="utf-8") as f:
            for e in live_only:
                f.write(json.dumps(e, sort_keys=True) + "\n")
        v = et.verify_tiered(self.log_path, _policy())
        self.assertFalse(v["ok"])

    def test_warm_tamper_loud(self):
        self.make_log(4)
        self.retire()
        wp = self.tmp / "warm.jsonl"
        data = open(wp, encoding="utf-8").read()
        with open(wp, "w", encoding="utf-8") as f:
            f.write(data[:-2] + ("0" if data[-2] != "0" else "1") + "\n")
        v = et.verify_tiered(self.log_path, _policy())
        self.assertFalse(v["ok"])

    def test_cold_tamper_loud(self):
        self.make_log(4)
        self.retire()
        et.retire_warm(self.log_path, _policy(),
                       now=self.now + timedelta(seconds=7200))
        cp = self.tmp / "cold.jsonl"
        data = open(cp, encoding="utf-8").read()
        with open(cp, "w", encoding="utf-8") as f:
            f.write(data[:-2] + ("0" if data[-2] != "0" else "1") + "\n")
        v = et.verify_tiered(self.log_path, _policy())
        self.assertFalse(v["ok"])

    def test_cold_anchor_transitive_resolution(self):
        # After warm->cold, the hot marker resolves through the anchor.
        self.make_log(4)
        self.retire()
        r = et.retire_warm(self.log_path, _policy(),
                           now=self.now + timedelta(seconds=7200))
        self.assertEqual(r["anchored"], 1)
        self.assertEqual(len(self.read_warm()), 1)  # only the marker
        v = et.verify_tiered(self.log_path, _policy())
        self.assertTrue(v["ok"], v["error"])
        self.assertEqual(v["retirements"][0]["via"], "cold")

    def test_passthrough_unretired_log(self):
        self.make_log(3)
        v = et.verify_tiered(self.log_path, _policy())
        self.assertTrue(v["ok"], v["error"])
        self.assertEqual(v["retirements"], [])
        # And it agrees with the base verifier.
        ok, _, _ = _log.verify_chain(self.log_path)
        self.assertTrue(ok)

    def test_hook_verify_tiered(self):
        self.make_log(3)
        v = _log.verify_tiered(self.log_path, _policy())
        self.assertTrue(v["ok"], v["error"])

    def test_hook_retire_evidence(self):
        self.make_log(3)
        log = ActionLog(self.log_path)
        res = log.retire_evidence(
            _policy(), now=self.now + timedelta(seconds=3600))
        self.assertEqual(res["retired"], 3)
        v = _log.verify_tiered(self.log_path, _policy())
        self.assertTrue(v["ok"], v["error"])


class WarmSubsetTests(EvidenceTierBase):
    def test_projections_strict_subset(self):
        log = ActionLog(self.log_path)
        log.append({"event": "probe", "i": 1, "extra": "must-not-carry",
                    "detail": "nope"})
        et.retire_hot(self.log_path, _policy(),
                      now=self.now + timedelta(seconds=3600))
        s = self.read_warm()[0]
        for p in s["projections"]:
            self.assertLess(len(p), 6)  # entry had 6+ fields
            self.assertNotIn("extra", p)
            self.assertNotIn("detail", p)
            self.assertNotIn("hash", p)
            self.assertNotIn("prev_hash", p)

    def test_no_secret_material_in_warm(self):
        log = ActionLog(self.log_path)
        log.append({"event": "probe", "i": 1,
                    "note": "api_key=AKIAIOSFODNN7EXAMPLE"})
        et.retire_hot(self.log_path, _policy(),
                      now=self.now + timedelta(seconds=3600))
        blob = open(self.tmp / "warm.jsonl",
                    encoding="utf-8").read().lower()
        self.assertNotIn("akiaiosfodnn7example", blob)


class CrashRecoveryTests(EvidenceTierBase):
    def test_orphan_summary_reused_no_dup(self):
        self.make_log(4)
        policy = _policy()
        now = self.now + timedelta(seconds=3600)
        # Crash between summary append and marker append: craft the
        # summary the way retire_hot would, without the marker.
        prefix = et._eligible_prefix_for_retire(self.log_path, policy,
                                                now)
        summary = et._build_warm_summary(prefix, policy, now)
        et._append_warm_summary(str(self.tmp / "warm.jsonl"), summary)
        # Recovery run must reuse the orphan, not duplicate it.
        res = et.retire_hot(self.log_path, policy, now=now)
        self.assertTrue(res["recovered"])
        warm = self.read_warm()
        summaries = [e for e in warm
                     if e.get("kind") == "retirement_summary"]
        self.assertEqual(len(summaries), 1)
        v = et.verify_tiered(self.log_path, policy)
        self.assertTrue(v["ok"], v["error"])

    def test_marker_crash_completes_truncation(self):
        self.make_log(4)
        policy = _policy()
        now = self.now + timedelta(seconds=3600)
        prefix = et._eligible_prefix_for_retire(self.log_path, policy,
                                                now)
        summary = et._build_warm_summary(prefix, policy, now)
        warm_entry = et._append_warm_summary(
            str(self.tmp / "warm.jsonl"), summary)
        et._append_retirement_marker(self.log_path, policy, prefix,
                                    warm_entry, now)
        # Crash before truncation: rerun must finish the job.
        res = et.retire_hot(self.log_path, policy, now=now)
        self.assertTrue(res["truncated"])
        hot = self.read_hot()
        self.assertEqual(len(hot), 1)
        self.assertTrue(et._is_hot_marker(hot[0]))
        v = et.verify_tiered(self.log_path, policy)
        self.assertTrue(v["ok"], v["error"])


if __name__ == "__main__":
    unittest.main()
