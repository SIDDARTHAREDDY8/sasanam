"""Unit tests for gov/framing.py.

Contract under test: per-tool argument-distribution fingerprints
(hosts, recipient domains, path prefixes -- routing metadata only),
chi-square shift detection with the substitutive/additive
discriminator, graduated SILENT/WATCH/WARN/HOLD levels, and the
hash-chained FramingStore.
"""
import os
import tempfile
import unittest
from pathlib import Path

# Keyed Row-9 chains: the framing store's HMAC chain needs a configured
# key (keyprovider idiom — the keyfixture test hook only fires when
# GOV_LOG_KEY is absent, i.e. test contexts).
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from keyfixture import provision_test_key  # noqa: E402
provision_test_key()

from gov import framing as F
from gov.framing import (
    FramingFingerprint, FramingStore, FramingSignal, FramingResult,
    detect_framing, framing_fingerprint_from_entries,
    _norm_host, _norm_domain, _norm_prefix, _signal_argument_distribution,
)


def _fp(tool, cats, seq=0):
    return {"fingerprint": FramingFingerprint({tool: cats},
                                              run_seq=seq).to_dict()}


class NormHost(unittest.TestCase):
    def test_full_url(self):
        self.assertEqual(_norm_host("https://vendor.example:8443/api/v1?x=1"),
                         "vendor.example")

    def test_case_and_www(self):
        self.assertEqual(_norm_host("HTTPS://WWW.Vendor.EXAMPLE/"),
                         "vendor.example")

    def test_userinfo(self):
        self.assertEqual(_norm_host("https://user:pw@api.example/hook"),
                         "api.example")

    def test_bare_host(self):
        self.assertEqual(_norm_host("printer3"), "printer3")

    def test_missing(self):
        self.assertIsNone(_norm_host(None))
        self.assertIsNone(_norm_host(""))
        self.assertIsNone(_norm_host("   "))
        self.assertIsNone(_norm_host(42))


class NormDomain(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(_norm_domain("Ops@Corp.EXAMPLE"), "corp.example")

    def test_list_takes_first(self):
        self.assertEqual(_norm_domain(["a@x.example", "b@y.example"]),
                         "x.example")

    def test_missing(self):
        self.assertIsNone(_norm_domain(None))
        self.assertIsNone(_norm_domain("not-an-email"))
        self.assertIsNone(_norm_domain(""))


class NormPrefix(unittest.TestCase):
    def test_nested(self):
        self.assertEqual(_norm_prefix("staging/note.txt"), "staging")

    def test_leading_slash(self):
        self.assertEqual(_norm_prefix("/var/log/x"), "var")

    def test_bare_filename(self):
        self.assertEqual(_norm_prefix("note.txt"), "note.txt")

    def test_missing(self):
        self.assertIsNone(_norm_prefix(None))
        self.assertIsNone(_norm_prefix(""))
        self.assertIsNone(_norm_prefix("/"))


class FingerprintValidation(unittest.TestCase):
    def test_negative_count_rejected(self):
        with self.assertRaises(ValueError):
            FramingFingerprint({"http_post": {"a.example": -1}})

    def test_untracked_tool_rejected(self):
        with self.assertRaises(ValueError):
            FramingFingerprint({"nmap": {"x": 1}})

    def test_zero_counts_dropped(self):
        fp = FramingFingerprint({"http_post": {"a.example": 0,
                                               "b.example": 2}})
        self.assertEqual(fp.arg_counts,
                         {"http_post": {"b.example": 2}})

    def test_roundtrip(self):
        fp = FramingFingerprint({"http_post": {"a.example": 3}},
                                run_seq=7, run_id="r7")
        back = FramingFingerprint.from_dict(fp.to_dict())
        self.assertEqual(back.to_dict(), fp.to_dict())


class FromEntries(unittest.TestCase):
    def test_extracts_routing_fields(self):
        entries = [
            {"event": "tool_call", "tool": "http_post",
             "decision": "allowed_executed",
             "args": {"url": "https://vendor.example/api"}},
            {"event": "tool_call", "tool": "send_email",
             "decision": "approved_executed",
             "args": {"to": "ops@corp.example"}},
            {"event": "tool_call", "tool": "write_file",
             "decision": "allowed_executed",
             "args": {"path": "logs/run.txt"}},
        ]
        fp = framing_fingerprint_from_entries(entries)
        self.assertEqual(fp.arg_counts["http_post"], {"vendor.example": 1})
        self.assertEqual(fp.arg_counts["send_email"], {"corp.example": 1})
        self.assertEqual(fp.arg_counts["write_file"], {"logs": 1})

    def test_denied_calls_excluded(self):
        entries = [
            {"event": "tool_call", "tool": "http_post", "decision": "denied",
             "args": {"url": "https://evil.example/"}},
            {"event": "tool_call", "tool": "http_post",
             "decision": "allowed_executed",
             "args": {"url": "https://vendor.example/"}},
        ]
        fp = framing_fingerprint_from_entries(entries)
        self.assertEqual(fp.arg_counts["http_post"], {"vendor.example": 1})

    def test_missing_routing_field_skipped_not_guessed(self):
        entries = [
            {"event": "tool_call", "tool": "http_post",
             "decision": "allowed_executed", "args": {"payload": "x"}},
            {"event": "tool_call", "tool": "http_post",
             "decision": "allowed_executed"},  # no args at all
        ]
        fp = framing_fingerprint_from_entries(entries)
        self.assertEqual(fp.arg_counts, {})

    def test_untracked_tools_ignored(self):
        entries = [{"event": "tool_call", "tool": "search",
                    "decision": "allowed_executed",
                    "args": {"query": "x"}}]
        fp = framing_fingerprint_from_entries(entries)
        self.assertEqual(fp.arg_counts, {})

    def test_non_dict_entries_ignored(self):
        fp = framing_fingerprint_from_entries([None, "x", 42])
        self.assertEqual(fp.arg_counts, {})


class SignalMath(unittest.TestCase):
    def _runs(self, tool, specs):
        return [_fp(tool, s, i) for i, s in enumerate(specs)]

    def test_identical_is_none(self):
        runs = self._runs("http_post", [{"a.example": 20}] * 13)
        self.assertIsNone(_signal_argument_distribution(
            "http_post", runs[:5], runs[5:]))

    def test_single_category_is_none(self):
        # Only one category ever seen: nothing to compare.
        runs = self._runs("http_post", [{"a.example": 20}] * 13)
        self.assertIsNone(_signal_argument_distribution(
            "http_post", runs[:5], runs[5:]))

    def test_insufficient_mass_is_none(self):
        runs = self._runs("http_post", [{"a.example": 3}] * 13)
        self.assertIsNone(_signal_argument_distribution(
            "http_post", runs[:5], runs[5:]))

    def test_substitutive_is_strong(self):
        base = self._runs("http_post", [{"vendor.example": 20}] * 5)
        win = self._runs("http_post", [{"personal.example": 20}] * 8,
                         )
        sig = _signal_argument_distribution("http_post", base, win)
        self.assertIsNotNone(sig)
        self.assertEqual(sig.strength, "strong")
        self.assertTrue(sig.detail["substitutive"])
        self.assertFalse(sig.detail["additive_capped"])

    def test_additive_is_capped_weak(self):
        base = self._runs("http_post", [{"vendor-a.example": 20}] * 5)
        win = self._runs(
            "http_post",
            [{"vendor-a.example": 16, "vendor-b.example": 4}] * 8)
        sig = _signal_argument_distribution("http_post", base, win)
        self.assertIsNotNone(sig)
        self.assertEqual(sig.strength, "weak")
        self.assertTrue(sig.detail["additive_capped"])
        self.assertFalse(sig.detail["substitutive"])

    def test_trickle_remnant_still_substitutive(self):
        # 5% remnant to the old destination does not launder the
        # shift into "additive".
        base = self._runs("http_post", [{"vendor.example": 20}] * 5)
        win = self._runs(
            "http_post",
            [{"vendor.example": 1, "personal.example": 19}] * 8)
        sig = _signal_argument_distribution("http_post", base, win)
        self.assertIsNotNone(sig)
        self.assertEqual(sig.strength, "strong")
        self.assertTrue(sig.detail["substitutive"])

    def test_redistribution_without_novelty_is_strong(self):
        base = self._runs(
            "http_post",
            [{"vendor-a.example": 18, "vendor-b.example": 2}] * 5)
        win = self._runs(
            "http_post",
            [{"vendor-a.example": 2, "vendor-b.example": 18}] * 8)
        sig = _signal_argument_distribution("http_post", base, win)
        self.assertIsNotNone(sig)
        self.assertEqual(sig.strength, "strong")

    def test_new_tool_in_window_without_baseline_is_none(self):
        # No baseline mass for the tool: nothing to compare against
        # (novel-tool appearance is gov.drift's signal, not this one's).
        base = self._runs("http_post", [{"vendor.example": 20}] * 5)
        win = self._runs("send_email", [{"corp.example": 5}] * 8)
        self.assertIsNone(_signal_argument_distribution(
            "send_email", base, win))

    def test_signal_validation(self):
        with self.assertRaises(ValueError):
            FramingSignal("tool_distribution", "strong", {}, "x")
        with self.assertRaises(ValueError):
            FramingSignal("argument_distribution", "medium", {}, "x")
        with self.assertRaises(ValueError):
            FramingResult("severe")


class StoreChain(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="framing_ut_"))
        self.store = FramingStore(self.tmp / "profiles")

    def test_record_and_verify(self):
        self.store.record_run("a1", "p1",
                              FramingFingerprint(
                                  {"http_post": {"a.example": 5}}))
        self.assertTrue(self.store.verify_chain("a1"))
        self.assertEqual(len(self.store.runs("a1")), 1)

    def test_tamper_detected(self):
        import json
        self.store.record_run("a1", "p1",
                              FramingFingerprint(
                                  {"http_post": {"a.example": 5}}))
        self.store.record_run("a1", "p1",
                              FramingFingerprint(
                                  {"http_post": {"b.example": 5}}))
        p = self.tmp / "profiles" / "a1.jsonl"
        lines = p.read_text().splitlines()
        rec = json.loads(lines[1])
        rec["fingerprint"]["arg_counts"]["http_post"] = {"evil.example": 99}
        lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        p.write_text("\n".join(lines) + "\n")
        self.assertFalse(self.store.verify_chain("a1"))

    def test_wrong_type_rejected(self):
        with self.assertRaises(TypeError):
            self.store.record_run("a1", "p1", {"not": "a fingerprint"})


class KeyedChain(unittest.TestCase):
    """Row-9 keyed chains for the framing store: HMAC-SHA256 appends,
    legacy compatibility (same contract as the drift store)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="framingkey_ut_"))
        self.store = FramingStore(self.tmp / "profiles")

    def _fp(self, i):
        return FramingFingerprint({"http_post": {"a.example": 5 + i}})

    def _legacy_records(self, n=2):
        from gov.chained_store import canonical, sha256_hex
        recs, prev = [], ""
        for i in range(n):
            rec = {
                "agent_id": "a1",
                "principal": "p1",
                "fingerprint": self._fp(i).to_dict(),
                "framing_version": 1,
                "recorded_at": "2026-01-01T00:00:0%d+00:00" % i,
                "run_seq": i,
                "prev_digest": prev,
            }
            rec["digest"] = sha256_hex(canonical(rec))
            prev = rec["digest"]
            recs.append(rec)
        return recs

    def _write(self, recs):
        import json
        (self.tmp / "profiles" / "a1.jsonl").write_text(
            "".join(json.dumps(r, sort_keys=True,
                               separators=(",", ":")) + "\n"
                    for r in recs),
            encoding="utf-8")

    def test_new_records_are_keyed(self):
        rec = self.store.record_run("a1", "p1", self._fp(0))
        self.assertTrue(rec.get("chain_keyed"))
        self.assertIn("key_epoch", rec)
        self.assertTrue(self.store.verify_chain("a1"))

    def test_legacy_chain_verifies(self):
        self._write(self._legacy_records(3))
        self.assertTrue(self.store.verify_chain("a1"))

    def test_keyed_append_onto_legacy_chain(self):
        self._write(self._legacy_records(2))
        self.store.record_run("a1", "p1", self._fp(9))
        self.assertTrue(self.store.verify_chain("a1"))

    def test_history_rewrite_recompute_fails(self):
        import json
        from gov.chained_store import canonical, sha256_hex
        self.store.record_run("a1", "p1", self._fp(0))
        self.store.record_run("a1", "p1", self._fp(1))
        p = self.tmp / "profiles" / "a1.jsonl"
        recs = [json.loads(line)
                for line in p.read_text(encoding="utf-8").splitlines()]
        recs[0]["fingerprint"]["arg_counts"]["http_post"] = {
            "evil.example": 99}
        prev = ""
        for rec in recs:
            rec.pop("digest", None)
            rec["prev_digest"] = prev
            rec["digest"] = sha256_hex(canonical(rec))
            prev = rec["digest"]
        self._write(recs)
        self.assertFalse(self.store.verify_chain("a1"))

    def test_wrong_key_rejected(self):
        import os
        self.store.record_run("a1", "p1", self._fp(0))
        old = os.environ.get("GOV_LOG_KEY")
        os.environ["GOV_LOG_KEY"] = "ff" * 32
        try:
            self.assertFalse(self.store.verify_chain("a1"))
        finally:
            os.environ["GOV_LOG_KEY"] = old
        self.assertTrue(self.store.verify_chain("a1"))


class DetectLevels(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="framing_ut_"))

    def _store_with(self, agent, specs):
        store = FramingStore(self.tmp / ("s_" + agent))
        for i, spec in enumerate(specs):
            store.record_run(agent, "p1",
                             FramingFingerprint(spec, run_seq=i,
                                                run_id="r%d" % i))
        return store

    def test_insufficient_data_silent(self):
        store = self._store_with(
            "a", [{"http_post": {"a.example": 20}}] * 3)
        res = detect_framing(store, "a")
        self.assertEqual(res.level, "silent")
        self.assertEqual(res.reason, "insufficient_data")

    def test_stable_silent(self):
        store = self._store_with(
            "a", [{"http_post": {"a.example": 20}}] * 13)
        self.assertEqual(detect_framing(store, "a").level, "silent")

    def test_single_shift_warn(self):
        store = self._store_with(
            "a", [{"http_post": {"vendor.example": 20}}] * 5
            + [{"http_post": {"personal.example": 20}}] * 8)
        res = detect_framing(store, "a")
        self.assertEqual(res.level, "warn")
        self.assertEqual(len(res.signals), 1)
        self.assertEqual(res.signals[0].strength, "strong")

    def test_triple_shift_hold(self):
        base = {"http_post": {"vendor.example": 20},
                "write_file": {"logs": 10},
                "send_email": {"corp.example": 5}}
        shifted = {"http_post": {"personal.example": 20},
                   "write_file": {"secrets": 10},
                   "send_email": {"gmail.example": 5}}
        store = self._store_with("a", [base] * 5 + [shifted] * 8)
        res = detect_framing(store, "a")
        self.assertEqual(res.level, "hold")
        self.assertEqual(len(res.signals), 3)

    def test_additive_watch(self):
        store = self._store_with(
            "a", [{"http_post": {"vendor-a.example": 20}}] * 5
            + [{"http_post": {"vendor-a.example": 16,
                              "vendor-b.example": 4}}] * 8)
        res = detect_framing(store, "a")
        self.assertEqual(res.level, "watch")

    def test_wrong_store_type(self):
        with self.assertRaises(TypeError):
            detect_framing(object(), "a")

    def test_result_serializes(self):
        store = self._store_with(
            "a", [{"http_post": {"vendor.example": 20}}] * 5
            + [{"http_post": {"personal.example": 20}}] * 8)
        d = detect_framing(store, "a").to_dict()
        self.assertEqual(d["level"], "warn")
        self.assertEqual(d["signals"][0]["kind"], "argument_distribution")


if __name__ == "__main__":
    unittest.main()
