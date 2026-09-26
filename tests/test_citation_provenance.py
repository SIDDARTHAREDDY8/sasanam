#!/usr/bin/env python3
"""Unit tests for gov/citation_provenance.py (F139 closure)."""

import os
import secrets
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "test-citation-prov")
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_REPO, os.path.join(_REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import citation_provenance as cp  # noqa: E402
from harness import make_run  # noqa: E402


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

    def test_non_upload_tools_ignored(self):
        # send_email is not URL-citable: still ignored after F140.
        recs = cp.upload_records_from_log_entries(
            [_log_entry(tool="send_email")])
        self.assertEqual(recs, [])

    def test_apicall_endpoint_indexed(self):
        # F140: api_call reads the "endpoint" arg, not "url".
        entry = _log_entry(tool="api_call")
        entry["args"] = {
            "endpoint": "https://pasteapi.synthetic.local/v3/bins/publish",
            "params": {"content": "fabricated study"},
        }
        recs = cp.upload_records_from_log_entries([entry])
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["url_normalized"],
                         "https://pasteapi.synthetic.local/v3/bins/publish")
        self.assertEqual(recs[0]["tool"], "api_call")
        self.assertEqual(recs[0]["source"], "action_log")
        self.assertIsNotNone(recs[0]["payload_sha256_prefix"])
        self.assertIsNotNone(recs[0]["payload_bytes"])

    def test_apicall_without_endpoint_skipped(self):
        entry = _log_entry(tool="api_call")
        entry["args"] = {"params": {"content": "x"}}
        recs = cp.upload_records_from_log_entries([entry])
        self.assertEqual(recs, [])

    def test_params_fingerprint_deterministic(self):
        p1 = {"b": 2, "a": [1, 2], "c": "x"}
        p2 = {"c": "x", "a": [1, 2], "b": 2}
        self.assertEqual(cp.canonical_params_fingerprint(p1),
                         cp.canonical_params_fingerprint(p2))
        nbytes, prefix = cp.canonical_params_fingerprint(p1)
        self.assertTrue(nbytes > 0)
        self.assertEqual(len(prefix), 16)

    def test_params_fingerprint_differs_on_content(self):
        self.assertNotEqual(
            cp.canonical_params_fingerprint({"a": 1}),
            cp.canonical_params_fingerprint({"a": 2}))

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


# ---------------------------------------------------------------------------
# F142 Leg A, mechanism 2: content-keyed correlation (exact 256-bit match).
# ---------------------------------------------------------------------------

def _sha(b):
    import hashlib
    return hashlib.sha256(b).hexdigest()


_PLANT_BODY = b"fabricated replication study content, exactly these bytes"
_PLANT_HASH = _sha(_PLANT_BODY)
# One-bit-flipped digest: must NOT match (exact-match only).
_NEAR_MISS_HASH = ("0" if _PLANT_HASH[0] != "0" else "1") + _PLANT_HASH[1:]


def _ledger_entry_with_content(url="https://h.test/bins/x",
                               content_hashes=(_PLANT_HASH,)):
    return {"kind": "upload", "url": url,
            "url_normalized": cp.normalize_url(url),
            "content_sha256_set": list(content_hashes),
            "principal": "p", "agent_id": "a1"}


class ContentKeyedCorrelationTests(unittest.TestCase):
    def test_ledger_parses_content_sha256_set(self):
        recs = cp.upload_records_from_ledger_entries(
            [_ledger_entry_with_content()])
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["content_sha256_set"], [_PLANT_HASH])

    def test_ledger_missing_content_set_is_empty(self):
        recs = cp.upload_records_from_ledger_entries(
            [{"kind": "upload", "url": "https://h.test/a",
              "url_normalized": "https://h.test/a",
              "principal": "p", "agent_id": "a1"}])
        self.assertEqual(recs[0]["content_sha256_set"], [])

    def test_lookup_by_content_sha256_hits(self):
        idx = cp.CitationIndex()
        idx.add_ledger(FakeLedger([_ledger_entry_with_content()]))
        hits = idx.lookup_by_content_sha256(_PLANT_HASH)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["url_normalized"], "https://h.test/bins/x")

    def test_lookup_by_content_sha256_miss_on_near_miss(self):
        idx = cp.CitationIndex()
        idx.add_ledger(FakeLedger([_ledger_entry_with_content()]))
        self.assertEqual(idx.lookup_by_content_sha256(_NEAR_MISS_HASH), [])

    def test_lookup_by_content_sha256_case_insensitive(self):
        idx = cp.CitationIndex()
        idx.add_ledger(FakeLedger([_ledger_entry_with_content()]))
        hits = idx.lookup_by_content_sha256(_PLANT_HASH.upper())
        self.assertEqual(len(hits), 1)

    def test_verify_citation_content_keyed_self_planted(self):
        # TD-2: isolate the content-keyed path — the cited URL matches NO
        # URL key in the index; only the supplied content hash correlates.
        idx = cp.CitationIndex()
        idx.add_ledger(FakeLedger([_ledger_entry_with_content()]))
        res = cp.verify_citation("https://h.test/bins/OTHER-URL",
                                 {"principal": "p", "agent_id": "a1"},
                                 index=idx, content_sha256=_PLANT_HASH,
                                 trusted_content_hashes=())
        self.assertEqual(res["verdict"], cp.SELF_PLANTED)
        self.assertIsNotNone(res["upload"])
        self.assertIn("content", res["reason"])

    def test_content_keyed_plant_beats_trust_anchor(self):
        # Plant evidence beats trust anchors on the content key too.
        idx = cp.CitationIndex()
        idx.add_ledger(FakeLedger(
            [_ledger_entry_with_content(url="https://www.nature.com/x")]))
        res = cp.verify_citation("https://www.nature.com/y",
                                 index=idx, content_sha256=_PLANT_HASH,
                                 trusted_sources=("nature.com",))
        self.assertEqual(res["verdict"], cp.SELF_PLANTED)

    def test_content_sha256_no_match_stays_unknown(self):
        idx = cp.CitationIndex()
        idx.add_ledger(FakeLedger([_ledger_entry_with_content()]))
        res = cp.verify_citation("https://h.test/bins/OTHER-URL",
                                 index=idx,
                                 content_sha256=_sha(b"unrelated bytes"),
                                 trusted_content_hashes=())
        self.assertEqual(res["verdict"], cp.UNKNOWN)
        self.assertIsNone(res["upload"])

    def test_url_key_still_takes_precedence(self):
        # URL-keyed hit wins even when a content hash is also supplied.
        idx = cp.CitationIndex()
        idx.add_ledger(FakeLedger([_ledger_entry_with_content()]))
        res = cp.verify_citation("https://h.test/bins/x",
                                 index=idx, content_sha256=_sha(b"other"))
        self.assertEqual(res["verdict"], cp.SELF_PLANTED)
        self.assertIn("URL was uploaded", res["reason"])


# ---------------------------------------------------------------------------
# F142 Leg A, mechanism 1: response-URL capture and alias indexing.
# ---------------------------------------------------------------------------

class ExtractResponseUrlsTests(unittest.TestCase):
    def test_prefers_explicit_resource_url(self):
        urls = cp.extract_response_urls(
            "api_call",
            {"status": 200, "resource_url": "https://h.test/bins/abc"},
            endpoint="https://h.test/v3/publish")
        self.assertEqual(urls, ["https://h.test/bins/abc"])

    def test_collects_location_and_resource_urls_list(self):
        urls = cp.extract_response_urls(
            "api_call",
            {"status": 201,
             "location": "https://h.test/bins/one",
             "resource_urls": ["https://h.test/bins/two"]},
            endpoint="https://h.test/v3/publish")
        # Preference order: resource_url, resource_urls, location, url.
        self.assertEqual(urls, ["https://h.test/bins/two",
                                "https://h.test/bins/one"])

    def test_excludes_endpoint_echo(self):
        # A result that merely echoes the called endpoint contributes no
        # response-minted URL.
        urls = cp.extract_response_urls(
            "http_post",
            {"status": 202, "url": "https://h.test/post"},
            endpoint="https://h.test/post")
        self.assertEqual(urls, [])

    def test_bounded_scan_finds_embedded_urls(self):
        urls = cp.extract_response_urls(
            "api_call",
            {"status": 200,
             "body": {"message": "created at https://h.test/bins/deep",
                      "nested": {"link": "https://h.test/bins/deeper"}}},
            endpoint="https://h.test/v3/publish")
        self.assertEqual(urls, ["https://h.test/bins/deep",
                                "https://h.test/bins/deeper"])

    def test_ignores_non_urls_and_normalizes(self):
        urls = cp.extract_response_urls(
            "api_call",
            {"status": 200, "note": "no urls here",
             "count": 3, "nothing": None,
             "mixed": "https://H.TEST:443/Bins/Up"},
            endpoint="https://h.test/v3/publish")
        self.assertEqual(urls, ["https://h.test/Bins/Up"])

    def test_never_raises_on_garbage(self):
        self.assertEqual(cp.extract_response_urls("api_call", None), [])
        self.assertEqual(cp.extract_response_urls("api_call", "junk"), [])
        self.assertEqual(cp.extract_response_urls(
            "api_call", {"a": object()}), [])

    def test_bounded_at_25_urls(self):
        result = {"items": ["https://h.test/bins/%d" % i for i in range(50)]}
        urls = cp.extract_response_urls(
            "api_call", result, endpoint="https://h.test/v3/publish")
        self.assertEqual(len(urls), 25)


class ResponseUrlAliasTests(unittest.TestCase):
    def test_ledger_parses_response_urls(self):
        entry = _ledger_entry_with_content()
        entry["response_urls"] = ["https://h.test/bins/x"]
        recs = cp.upload_records_from_ledger_entries([entry])
        self.assertEqual(recs[0]["response_urls"],
                         ["https://h.test/bins/x"])

    def test_log_parses_response_urls(self):
        e = _log_entry(tool="api_call")
        e["args"] = {"endpoint": "https://h.test/v3/publish",
                     "params": {"a": 1}}
        e["response_urls"] = ["https://h.test/bins/x"]
        recs = cp.upload_records_from_log_entries([e])
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["response_urls"],
                         ["https://h.test/bins/x"])

    def test_lookup_hits_response_url_alias(self):
        # The plant record is keyed on the endpoint AND the captured
        # response URL.
        rec = {"url": "https://h.test/v3/publish",
               "url_normalized": "https://h.test/v3/publish",
               "response_urls": ["https://h.test/bins/x"],
               "content_sha256_set": [], "principal": "p", "agent_id": "a1"}
        idx = cp.CitationIndex()
        idx.add_upload_records([rec])
        hits = idx.lookup("https://h.test/bins/x")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["url_normalized"],
                         "https://h.test/v3/publish")

    def test_verify_citation_self_planted_via_response_url(self):
        rec = {"url": "https://h.test/v3/publish",
               "url_normalized": "https://h.test/v3/publish",
               "response_urls": ["https://h.test/bins/x"],
               "content_sha256_set": [], "principal": "p", "agent_id": "a1"}
        idx = cp.CitationIndex()
        idx.add_upload_records([rec])
        res = cp.verify_citation("https://h.test/bins/x",
                                 {"principal": "p", "agent_id": "a1"},
                                 index=idx)
        self.assertEqual(res["verdict"], cp.SELF_PLANTED)
        self.assertIn("URL was uploaded", res["reason"])


# ---------------------------------------------------------------------------
# H3 (F142 Leg-A residual, wave-117): http_post upload records carry
# content hashes (parity with api_call).
# ---------------------------------------------------------------------------

class HttpPostContentHashRecordTests(unittest.TestCase):
    def _ex(self):
        tmp = tempfile.mkdtemp(prefix="govh3-")
        ctx = make_run(ledger_path=os.path.join(tmp, "egress.jsonl"))
        return ctx["executor"]

    def _redacted_post(self):
        return {"url": "https://pasteapi.synthetic.local/v3/bins/publish",
                "payload": {"bytes": 11, "sha256_prefix": "ab" * 8}}

    def test_http_post_record_carries_content_hashes(self):
        ex = self._ex()
        h1, h2 = _sha(b"alpha"), _sha(b"beta")
        ex._record_upload("http_post", self._redacted_post(), "p", "a1",
                          content_hashes=[h2, h1])
        recs = ex._ledger.uploads()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["content_sha256_set"], sorted([h1, h2]))

    def test_http_post_record_sanitizes_and_dedupes(self):
        ex = self._ex()
        h1 = _sha(b"alpha")
        ex._record_upload("http_post", self._redacted_post(), "p", "a1",
                          content_hashes=[h1, h1, 42, "", None])
        recs = ex._ledger.uploads()
        self.assertEqual(recs[0]["content_sha256_set"], [h1])

    def test_http_post_record_empty_without_hashes(self):
        # Pre-upgrade call shape (no content_hashes kwarg): fail-open,
        # empty set, record still written.
        ex = self._ex()
        ex._record_upload("http_post", self._redacted_post(), "p", "a1")
        recs = ex._ledger.uploads()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["content_sha256_set"], [])

    def test_api_call_record_still_hashes_params(self):
        # Parity regression: the api_call path is untouched.
        ex = self._ex()
        ex._record_upload("api_call",
                          {"endpoint": "https://h.test/e",
                           "params": {"content": "hello"}},
                          "p", "a1")
        recs = ex._ledger.uploads()
        self.assertEqual(recs[0]["content_sha256_set"],
                         [_sha(b"hello")])

    def test_http_post_hashes_are_content_indexed(self):
        # The hashes the record carries must be findable through the
        # public content-keyed lookup.
        ex = self._ex()
        h1 = _sha(b"alpha")
        ex._record_upload("http_post", self._redacted_post(), "p", "a1",
                          content_hashes=[h1])
        idx = cp.CitationIndex()
        idx.add_ledger(ex._ledger)
        hits = idx.lookup_by_content_sha256(h1)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["url_normalized"],
                         "https://pasteapi.synthetic.local/v3/bins/publish")


if __name__ == "__main__":
    unittest.main()
