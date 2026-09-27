#!/usr/bin/env python3
"""Unit tests for gov/taint_ledger.py (wave-139 lane 1).

Seams: TaintLedger.observe / taint_for / blinded_token / sweep /
purge / save+load / verify_chain, the no-token-strings privacy
invariant, and the RareTokenTracker cross-run wiring (ledger attached
vs not). TTL tests inject observed_at/now — no sleeping, fully
deterministic.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import taint_ledger as tl  # noqa: E402
from gov import rare_token as rt  # noqa: E402
from gov.keys import NoKeyConfiguredError  # noqa: E402

TEST_KEY = b"wave139-test-hmac-key-32bytes!!"

DOC_TOKENS = ["zephyrcorp", "industries", "88142", "22901", "marlowe",
              "finch", "brigadier", "oswald", "thornberry",
              "hartlepool", "480000"]


def _old(hours):
    return (datetime.now(timezone.utc)
            - timedelta(hours=hours)).isoformat()


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="taint-ledger-test-")
        self.path = os.path.join(self.tmp, "taint.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _ledger(self, **kw):
        kw.setdefault("hmac_key", TEST_KEY)
        return tl.TaintLedger(self.path, **kw)


class PersistenceFormatTest(_Base):
    def test_round_trip_preserves_counts_ids_commitments(self):
        led = self._ledger()
        led.observe("agent-a", "doc-1", DOC_TOKENS)
        led.observe("agent-a", "doc-2", ["zephyrcorp"])
        led2 = self._ledger()
        recs = led2.taint_for("agent-a")
        by_src = {r["source_id"]: r for r in recs}
        self.assertEqual(set(by_src), {"doc-1", "doc-2"})
        self.assertEqual(by_src["doc-1"]["rare_token_count"],
                         len(DOC_TOKENS))
        self.assertEqual(len(by_src["doc-1"]["commitments"]),
                         len(DOC_TOKENS))
        self.assertEqual(by_src["doc-2"]["rare_token_count"], 1)

    def test_header_record_footer_present(self):
        led = self._ledger()
        led.observe("agent-a", "doc-1", DOC_TOKENS)
        with open(self.path, encoding="utf-8") as fh:
            lines = [ln for ln in (l.strip() for l in fh) if ln]
        kinds = [json.loads(ln)["record"] for ln in lines]
        self.assertEqual(kinds[0], "header")
        self.assertEqual(kinds[-1], "footer")
        self.assertTrue(all(k == "taint" for k in kinds[1:-1]))
        header = json.loads(lines[0])
        self.assertEqual(header["taint_ledger"], tl.TAINT_LEDGER_VERSION)

    def test_reobserve_replaces_and_refreshes_ttl(self):
        led = self._ledger(ttl_seconds=3600)
        led.observe("agent-a", "doc-1", ["zephyrcorp"],
                    observed_at=_old(2))
        # Expired before the re-read...
        self.assertEqual(led.taint_for("agent-a"), [])
        led.observe("agent-a", "doc-1", ["zephyrcorp", "marlowe"])
        recs = led.taint_for("agent-a")
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["rare_token_count"], 2)

    def test_zero_token_read_not_recorded(self):
        led = self._ledger()
        res = led.observe("agent-a", "doc-1", [])
        self.assertFalse(res["ledger_recorded"])
        self.assertEqual(led.taint_for("agent-a"), [])

    def test_commitment_cap_is_deterministic(self):
        led = self._ledger()
        many = ["tok%04d" % i for i in range(600)]
        res = led.observe("agent-a", "doc-1", many)
        self.assertEqual(res["rare_token_count"], rt.MAX_TOKENS_PER_DOC)
        recs = self._ledger().taint_for("agent-a")
        self.assertEqual(len(recs[0]["commitments"]),
                         rt.MAX_TOKENS_PER_DOC)


class TTLTest(_Base):
    def test_expired_taint_invisible(self):
        led = self._ledger(ttl_seconds=3600)
        led.observe("agent-a", "doc-1", DOC_TOKENS,
                    observed_at=_old(2))
        self.assertEqual(led.taint_for("agent-a"), [])

    def test_live_taint_visible(self):
        led = self._ledger(ttl_seconds=3600)
        led.observe("agent-a", "doc-1", DOC_TOKENS,
                    observed_at=_old(0.5))
        self.assertEqual(len(led.taint_for("agent-a")), 1)

    def test_now_injection_is_deterministic(self):
        led = self._ledger(ttl_seconds=3600)
        at = _old(2)
        led.observe("agent-a", "doc-1", DOC_TOKENS, observed_at=at)
        then = (datetime.fromisoformat(at)
                + timedelta(hours=2, minutes=30))
        # 2h30m after observation with a 1h TTL: expired.
        self.assertEqual(led.taint_for("agent-a", now=then), [])
        led2 = self._ledger(ttl_seconds=3 * 3600)
        soon = datetime.fromisoformat(at) + timedelta(minutes=30)
        self.assertEqual(len(led2.taint_for("agent-a", now=soon)), 1)

    def test_sweep_reaps_only_expired(self):
        led = self._ledger(ttl_seconds=3600)
        led.observe("agent-a", "old-doc", DOC_TOKENS,
                    observed_at=_old(2))
        # Expired records are invisible to taint_for immediately...
        self.assertEqual(led.taint_for("agent-a"), [])
        # ...and reaped from the file by sweep.
        self.assertEqual(led.sweep(), 1)
        led.observe("agent-a", "new-doc", DOC_TOKENS,
                    observed_at=_old(0.5))
        self.assertEqual(led.sweep(), 0)
        self.assertEqual(led.live_source_ids("agent-a"), ["new-doc"])
        # Sweep persisted: a fresh load agrees.
        self.assertEqual(self._ledger().live_source_ids("agent-a"),
                         ["new-doc"])

    def test_bad_ttl_rejected(self):
        with self.assertRaises(ValueError):
            self._ledger(ttl_seconds=0)
        with self.assertRaises(ValueError):
            self._ledger(ttl_seconds=-5)


class PurgeTest(_Base):
    def test_purge_one_agent_keeps_other(self):
        led = self._ledger()
        led.observe("agent-a", "doc-1", DOC_TOKENS)
        led.observe("agent-b", "doc-9", DOC_TOKENS)
        removed = led.purge("agent-a")
        self.assertEqual(removed, 1)
        self.assertEqual(led.taint_for("agent-a"), [])
        self.assertEqual(len(led.taint_for("agent-b")), 1)
        # Persisted across a reload.
        self.assertEqual(self._ledger().taint_for("agent-a"), [])

    def test_purge_all(self):
        led = self._ledger()
        led.observe("agent-a", "doc-1", DOC_TOKENS)
        led.observe("agent-b", "doc-9", DOC_TOKENS)
        removed = led.purge()
        self.assertEqual(removed, 2)
        self.assertEqual(self._ledger().taint_for("agent-b"), [])

    def test_purge_unknown_agent_is_noop(self):
        led = self._ledger()
        led.observe("agent-a", "doc-1", DOC_TOKENS)
        self.assertEqual(led.purge("agent-nobody"), 0)
        self.assertEqual(len(led.taint_for("agent-a")), 1)


class IdentityKeyingTest(_Base):
    def test_records_isolated_per_agent(self):
        led = self._ledger()
        led.observe("agent-a", "doc-1", DOC_TOKENS)
        led.observe("agent-b", "doc-1", ["zephyrcorp"])
        recs_a = {r["source_id"]: r
                  for r in self._ledger().taint_for("agent-a")}
        recs_b = {r["source_id"]: r
                  for r in self._ledger().taint_for("agent-b")}
        self.assertEqual(recs_a["doc-1"]["rare_token_count"],
                         len(DOC_TOKENS))
        self.assertEqual(recs_b["doc-1"]["rare_token_count"], 1)
        # Commitments are agent-bound: same source+token differs.
        self.assertNotEqual(recs_a["doc-1"]["commitments"],
                            recs_b["doc-1"]["commitments"])


class PrivacyInvariantTest(_Base):
    """The wave-136 privacy contract, extended to durable storage:
    token strings appear NOWHERE in the ledger file."""

    def test_file_contains_no_token_strings(self):
        led = self._ledger()
        led.observe("agent-a", "doc-1", DOC_TOKENS)
        raw = open(self.path, encoding="utf-8").read().lower()
        leaked = [t for t in DOC_TOKENS if t in raw]
        self.assertEqual(leaked, [])

    def test_query_results_contain_no_token_strings(self):
        led = self._ledger()
        led.observe("agent-a", "doc-1", DOC_TOKENS)
        blob = str(led.taint_for("agent-a")).lower()
        leaked = [t for t in DOC_TOKENS if t in blob]
        self.assertEqual(leaked, [])
        # Commitments are opaque hex digests, not tokens.
        for rec in led.taint_for("agent-a"):
            for c in rec["commitments"]:
                self.assertRegex(c, r"^[0-9a-f]{64}$")

    def test_commitments_deterministic_across_instances(self):
        led1 = self._ledger()
        led2 = self._ledger()
        self.assertEqual(led1.blinded_token("a", "d", "marlowe"),
                         led2.blinded_token("a", "d", "marlowe"))
        self.assertNotEqual(led1.blinded_token("a", "d", "marlowe"),
                            led1.blinded_token("a", "d", "finch"))

    def test_different_keys_give_different_commitments(self):
        led1 = tl.TaintLedger(self.path, hmac_key=b"key-one-32bytes-padded!!!!!!")
        other = os.path.join(self.tmp, "other.jsonl")
        led2 = tl.TaintLedger(other, hmac_key=b"key-two-32bytes-padded!!!!!!")
        self.assertNotEqual(led1.blinded_token("a", "d", "marlowe"),
                            led2.blinded_token("a", "d", "marlowe"))


class TamperEvidenceTest(_Base):
    def test_verify_chain_clean(self):
        led = self._ledger()
        led.observe("agent-a", "doc-1", DOC_TOKENS)
        self.assertTrue(led.verify_chain())

    def _corrupt_line(self, idx, fn):
        with open(self.path, encoding="utf-8") as fh:
            lines = fh.readlines()
        lines[idx] = fn(lines[idx])
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)

    def test_corrupt_record_fails_closed(self):
        led = self._ledger()
        led.observe("agent-a", "doc-1", DOC_TOKENS)
        self._corrupt_line(1, lambda ln: ln.replace("doc-1", "doc-X"))
        with self.assertRaises(tl.TaintPersistenceError):
            self._ledger()

    def test_dropped_record_fails_closed(self):
        led = self._ledger()
        led.observe("agent-a", "doc-1", DOC_TOKENS)
        led.observe("agent-a", "doc-2", ["marlowe"])
        with open(self.path, encoding="utf-8") as fh:
            lines = fh.readlines()
        # Drop the first taint record (line 1); chain linkage breaks.
        del lines[1]
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        with self.assertRaises(tl.TaintPersistenceError):
            self._ledger()

    def test_missing_footer_fails_closed(self):
        led = self._ledger()
        led.observe("agent-a", "doc-1", DOC_TOKENS)
        with open(self.path, encoding="utf-8") as fh:
            lines = fh.readlines()
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines[:-1])
        with self.assertRaises(tl.TaintPersistenceError):
            self._ledger()

    def test_empty_file_fails_closed(self):
        open(self.path, "w").close()
        with self.assertRaises(tl.TaintPersistenceError):
            self._ledger()


class KeyProvisioningTest(_Base):
    def test_unprovisioned_key_fails_closed(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("GOV_LOG_KEY", "GOV_KEYRING_FILE")}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(NoKeyConfiguredError):
                tl.TaintLedger(self.path)

    def test_explicit_key_bypasses_provider(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("GOV_LOG_KEY", "GOV_KEYRING_FILE")}
        with mock.patch.dict(os.environ, env, clear=True):
            led = tl.TaintLedger(self.path, hmac_key=TEST_KEY)
            led.observe("agent-a", "doc-1", DOC_TOKENS)
            self.assertEqual(len(led.taint_for("agent-a")), 1)

    def test_env_key_used_when_no_explicit_key(self):
        # The suite provisions GOV_LOG_KEY (tests/__init__.py); the
        # ledger resolves through the same provider production uses.
        led = tl.TaintLedger(self.path)
        led.observe("agent-a", "doc-1", DOC_TOKENS)
        led2 = tl.TaintLedger(self.path)
        self.assertEqual(len(led2.taint_for("agent-a")), 1)


class TrackerWiringTest(_Base):
    DOC = ("Customer account review \u2014 Zephyrcorp Industries.\n"
           "Account reference ZX-88142, renewal code QX-22901.\n"
           "Primary contact: Marlowe Finch.\n"
           "Contract value 480000, renewal due Q3.")
    PARAPHRASE = ("Process the renewal for Zephyrcorp Industries "
                  "(account ZX-88142). Marlowe Finch confirmed renewal "
                  "code QX-22901; contract value 480000.")
    REWRITE = ("The client account is due for renewal. Please reach "
               "out to the primary contact to confirm the details.")
    DEST = "https://collector.synthetic.local/intake"

    def _run2_tracker(self):
        return rt.RareTokenTracker(
            taint_ledger=tl.TaintLedger(self.path, hmac_key=TEST_KEY))

    def test_cross_run_content_tier_same_ladder(self):
        t1 = rt.RareTokenTracker(
            taint_ledger=tl.TaintLedger(self.path, hmac_key=TEST_KEY))
        t1.observe_read("agent-a", "doc-1", self.DOC)
        t2 = self._run2_tracker()
        r = t2.check_egress("agent-a", "http_post",
                            {"url": self.DEST, "data": self.PARAPHRASE},
                            payload_text=self.PARAPHRASE)
        self.assertEqual(r["verdict"], "require_approval")
        self.assertGreaterEqual(r["overlap"], 3)
        self.assertEqual(r["source_id"], "doc-1")

    def test_cross_run_behavioral_tier_fires(self):
        t1 = rt.RareTokenTracker(
            taint_ledger=tl.TaintLedger(self.path, hmac_key=TEST_KEY))
        t1.observe_read("agent-a", "doc-1", self.DOC)
        t2 = self._run2_tracker()
        r = t2.check_egress("agent-a", "http_post",
                            {"url": self.DEST, "data": self.REWRITE},
                            payload_text=self.REWRITE)
        self.assertEqual(r["verdict"], "behavioral_flag")
        self.assertEqual(r["overlap"], 0)
        self.assertGreaterEqual(r["docs_read"], 1)

    def test_no_ledger_zero_behavior_change(self):
        t1 = rt.RareTokenTracker()
        t1.observe_read("agent-a", "doc-1", self.DOC)
        t2 = rt.RareTokenTracker()
        r = t2.check_egress("agent-a", "http_post",
                            {"url": self.DEST, "data": self.REWRITE},
                            payload_text=self.REWRITE)
        self.assertEqual(r["verdict"], "allow")

    def test_in_run_source_takes_precedence_no_double_count(self):
        t1 = rt.RareTokenTracker(
            taint_ledger=tl.TaintLedger(self.path, hmac_key=TEST_KEY))
        t1.observe_read("agent-a", "doc-1", self.DOC)
        t2 = self._run2_tracker()
        # Re-read in run 2: the in-run full token set wins; the
        # ledger record for the same source is not double-counted.
        t2.observe_read("agent-a", "doc-1", self.DOC)
        r = t2.check_egress("agent-a", "http_post",
                            {"url": self.DEST, "data": self.PARAPHRASE},
                            payload_text=self.PARAPHRASE)
        self.assertEqual(r["verdict"], "require_approval")
        in_run_overlap = len(
            set(rt.extract_rare_tokens(self.PARAPHRASE))
            & set(rt.extract_rare_tokens(self.DOC)))
        self.assertEqual(r["overlap"], in_run_overlap)

    def test_observe_read_reports_ledger(self):
        t = rt.RareTokenTracker(
            taint_ledger=tl.TaintLedger(self.path, hmac_key=TEST_KEY))
        res = t.observe_read("agent-a", "doc-1", self.DOC)
        self.assertTrue(res["ledger_recorded"])
        t_plain = rt.RareTokenTracker()
        res2 = t_plain.observe_read("agent-a", "doc-1", self.DOC)
        self.assertFalse(res2["ledger_recorded"])


if __name__ == "__main__":
    unittest.main()
