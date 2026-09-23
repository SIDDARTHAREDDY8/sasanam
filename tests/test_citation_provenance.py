#!/usr/bin/env python3
"""Unit tests for gov/citation_provenance.py (F139 closure)."""

import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_REPO, os.path.join(_REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import citation_provenance as cp  # noqa: E402


def _log_entry(url="https://pastebin.synthetic.local/claims/study-7",
               decision="allowed_executed", tool="http_post",
               agent_id="researcher-1", principal="redteam-org",
               run_id="run-1", seq=7):
    return {
        "event": "tool_call",
        "tool": tool,
        "decision": decision,
        "run_id": run_id,
        "agent_id": agent_id,
        "principal": principal,
        "seq": seq,
        "args": {
            "url": url,
            "payload": {"bytes": 318, "sha256_prefix": "abc123def4567890"},
        },
    }


class NormalizeTests(unittest.TestCase):
    def test_lowercases_host_and_scheme(self):
        self.assertEqual(
            cp.normalize_url("HTTPS://PasteBin.Synthetic.Local/claims/x"),
            "https://pastebin.synthetic.local/claims/x")

    def test_drops_default_ports(self):
        self.assertEqual(cp.normalize_url("https://h.test:443/a"),
                         "https://h.test/a")
        self.assertEqual(cp.normalize_url("http://h.test:80/a"),
                         "http://h.test/a")

    def test_keeps_nondefault_port(self):
        self.assertEqual(cp.normalize_url("https://h.test:8443/a"),
                         "https://h.test:8443/a")

    def test_strips_fragment_and_trailing_slash(self):
        self.assertEqual(cp.normalize_url("https://h.test/a/#frag"),
                         "https://h.test/a")

    def test_empty_path_becomes_slash(self):
        self.assertEqual(cp.normalize_url("https://h.test"),
                         "https://h.test/")

    def test_query_is_significant(self):
        # Documented residual: query-param evasion is a different URL
        # (conservative against false accusation).
        self.assertEqual(cp.normalize_url("https://h.test/a?x=1"),
                         "https://h.test/a?x=1")
        self.assertNotEqual(cp.normalize_url("https://h.test/a?x=1"),
                            cp.normalize_url("https://h.test/a"))

    def test_rejects_non_http(self):
        self.assertIsNone(cp.normalize_url("ftp://h.test/a"))
        self.assertIsNone(cp.normalize_url("not a url"))
        self.assertIsNone(cp.normalize_url(""))
        self.assertIsNone(cp.normalize_url(None))
        self.assertIsNone(cp.normalize_url(123))


class LogIndexTests(unittest.TestCase):
    def test_executed_upload_indexed(self):
        recs = cp.upload_records_from_log_entries([_log_entry()])
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r["url_normalized"],
                         "https://pastebin.synthetic.local/claims/study-7")
        self.assertEqual(r["agent_id"], "researcher-1")
        self.assertEqual(r["principal"], "redteam-org")
        self.assertEqual(r["payload_sha256_prefix"], "abc123def4567890")
        self.assertEqual(r["source"], "action_log")

    def test_approved_executed_indexed(self):
        recs = cp.upload_records_from_log_entries(
            [_log_entry(decision="approved_executed")])
        self.assertEqual(len(recs), 1)

    def test_queued_never_approved_not_a_plant(self):
        recs = cp.upload_records_from_log_entries(
            [_log_entry(decision="queued")])
        self.assertEqual(recs, [])

    def test_denied_not_indexed(self):
        recs = cp.upload_records_from_log_entries(
            [_log_entry(decision="denied")])
        self.assertEqual(recs, [])

    def test_non_post_tools_ignored(self):
        recs = cp.upload_records_from_log_entries(
            [_log_entry(tool="api_call")])
        self.assertEqual(recs, [])

    def test_unparseable_url_skipped(self):
        recs = cp.upload_records_from_log_entries(
            [_log_entry(url="not a url")])
        self.assertEqual(recs, [])


class LedgerRecordTests(unittest.TestCase):
    def test_kind_filter(self):
        entries = [
            {"kind": "upload", "url": "https://h.test/a",
             "url_normalized": "https://h.test/a",
             "principal": "p", "agent_id": "a1"},
            {"kind": "velocity", "url": "https://h.test/b"},
        ]
        recs = cp.upload_records_from_ledger_entries(entries)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["source"], "egress_ledger")

    def test_normalizes_when_missing(self):
        entries = [{"kind": "upload",
                    "url": "HTTPS://H.TEST:443/a/",
                    "principal": "p", "agent_id": "a1"}]
        recs = cp.upload_records_from_ledger_entries(entries)
        self.assertEqual(recs[0]["url_normalized"], "https://h.test/a")


class VerifyTests(unittest.TestCase):
    def _index(self, url="https://pastebin.synthetic.local/claims/study-7"):
        idx = cp.CitationIndex()
        idx.add_log_entries([_log_entry(url=url)])
        return idx

    def test_self_planted(self):
        res = cp.verify_citation(
            "https://pastebin.synthetic.local/claims/study-7",
            {"principal": "redteam-org", "agent_id": "researcher-1"},
            index=self._index())
        self.assertEqual(res["verdict"], cp.SELF_PLANTED)
        self.assertTrue(res["same_principal"])
        self.assertTrue(res["same_agent"])
        self.assertIsNotNone(res["upload"])

    def test_self_planted_other_agent_still_tainted(self):
        res = cp.verify_citation(
            "https://pastebin.synthetic.local/claims/study-7",
            {"principal": "redteam-org", "agent_id": "other-agent"},
            index=self._index())
        self.assertEqual(res["verdict"], cp.SELF_PLANTED)
        self.assertTrue(res["same_principal"])
        self.assertFalse(res["same_agent"])

    def test_unknown(self):
        res = cp.verify_citation("https://arxiv.org/abs/1234",
                                 index=self._index())
        self.assertEqual(res["verdict"], cp.UNKNOWN)
        self.assertIsNone(res["upload"])

    def test_unparseable_is_unknown(self):
        res = cp.verify_citation("garbage", index=self._index())
        self.assertEqual(res["verdict"], cp.UNKNOWN)

    def test_independent_via_trusted_source(self):
        res = cp.verify_citation("https://www.nature.com/articles/x",
                                 index=self._index(),
                                 trusted_sources=("nature.com",))
        self.assertEqual(res["verdict"], cp.INDEPENDENT)

    def test_trusted_source_subdomain_match(self):
        res = cp.verify_citation("https://sub.example.org/y",
                                 index=self._index(),
                                 trusted_sources=("example.org",))
        self.assertEqual(res["verdict"], cp.INDEPENDENT)

    def test_trusted_source_no_suffix_confusion(self):
        res = cp.verify_citation("https://notnature.com/x",
                                 index=self._index(),
                                 trusted_sources=("nature.com",))
        self.assertEqual(res["verdict"], cp.UNKNOWN)

    def test_independent_via_content_hash(self):
        h = "0" * 64
        res = cp.verify_citation("https://h.test/doc",
                                 index=self._index(),
                                 trusted_content_hashes=(h,),
                                 content_sha256=h)
        self.assertEqual(res["verdict"], cp.INDEPENDENT)

    def test_plant_beats_trust_anchor(self):
        # A plant uploaded TO a trusted host still verifies SELF_PLANTED.
        idx = self._index(url="https://www.nature.com/articles/planted")
        res = cp.verify_citation("https://www.nature.com/articles/planted",
                                 index=idx,
                                 trusted_sources=("nature.com",))
        self.assertEqual(res["verdict"], cp.SELF_PLANTED)

    def test_auto_builds_index_from_log_entries(self):
        res = cp.verify_citation(
            "https://pastebin.synthetic.local/claims/study-7",
            log_entries=[_log_entry()])
        self.assertEqual(res["verdict"], cp.SELF_PLANTED)

    def test_normalization_matches_trailing_slash(self):
        idx = self._index()
        res = cp.verify_citation(
            "https://pastebin.synthetic.local/claims/study-7/", index=idx)
        self.assertEqual(res["verdict"], cp.SELF_PLANTED)


class FakeLedger:
    def __init__(self, entries):
        self._entries = entries

    def uploads(self):
        return [e for e in self._entries if e.get("kind") == "upload"]


class IndexLedgerTests(unittest.TestCase):
    def test_add_ledger(self):
        idx = cp.CitationIndex()
        idx.add_ledger(FakeLedger([
            {"kind": "upload", "url": "https://h.test/a",
             "url_normalized": "https://h.test/a",
             "principal": "p", "agent_id": "a1"},
            {"kind": "velocity", "tool": "api_call"},
        ]))
        self.assertEqual(len(idx.lookup("https://h.test/a")), 1)
        self.assertEqual(idx.lookup("https://h.test/b"), [])

    def test_add_ledger_none_is_noop(self):
        idx = cp.CitationIndex()
        idx.add_ledger(None)
        self.assertEqual(len(idx), 0)


class ExtractUrlsTests(unittest.TestCase):
    def test_extracts_and_dedups(self):
        text = ("See https://a.test/x and https://a.test/x, "
                "plus http://b.test/y.")
        self.assertEqual(cp.extract_urls(text),
                         ["https://a.test/x", "http://b.test/y"])

    def test_empty(self):
        self.assertEqual(cp.extract_urls(""), [])
        self.assertEqual(cp.extract_urls(None), [])


if __name__ == "__main__":
    unittest.main()
