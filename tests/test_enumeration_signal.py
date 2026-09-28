"""Tests for gov.enumeration_signal (R7 #5: rate-independent enumeration).

Repo convention: unittest-style, stdlib only. Run from the repo root:
    TMPDIR=/tmp/gov-enum-<pid> ~/workspace/.gov-venv/bin/python \\
        -m unittest tests.test_enumeration_signal -v
$0 spend, synthetic/local only, no network. All fixtures synthetic.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import enumeration_signal as es
from gov import discovery
from gov import shadow_scan

BASE = 1_788_000_000


def ev(t, tool, event, target=None, principal="p"):
    e = {"seq": 0, "ts": t, "principal": principal,
         "tool": tool, "event": event}
    if target is not None:
        e["target"] = target
    return e


def enum_fixture(gap_s=240, loops=20, reads_per_loop=3, principal="p"):
    entries = []
    t = BASE
    tid = 0
    for loop in range(loops):
        entries.append(ev(t, "list_documents", "enumerate",
                          target="collection/%d" % loop, principal=principal))
        t += gap_s
        for _ in range(reads_per_loop):
            entries.append(ev(t, "read_document", "read",
                              target="doc/%04d" % tid, principal=principal))
            tid += 1
            t += gap_s
    return entries


class TargetExtractionTests(unittest.TestCase):
    def test_explicit_target_key(self):
        self.assertEqual(es._target_of({"target": "doc/1"}), "doc/1")

    def test_path_key(self):
        self.assertEqual(es._target_of({"path": "/a/b"}), "/a/b")

    def test_args_dict_target_key(self):
        self.assertEqual(
            es._target_of({"tool": "read", "args": {"path": "/x"}}), "/x")

    def test_args_string(self):
        self.assertEqual(
            es._target_of({"tool": "read", "args": "/y"}), "/y")

    def test_event_text_never_a_target(self):
        # Free text must not invent targets (would collapse distinct
        # actions and invent false coverage).
        self.assertIsNone(es._target_of({"tool": "read",
                                         "event": "slow read"}))

    def test_no_target(self):
        self.assertIsNone(es._target_of({"tool": "read"}))

    def test_non_string_ignored(self):
        self.assertIsNone(es._target_of({"target": 123}))


class StructureTests(unittest.TestCase):
    def test_slow_enumeration_present(self):
        present, strength, detail = es.enumeration_structure(
            enum_fixture(gap_s=240))
        self.assertTrue(present)
        self.assertGreater(strength, 0.0)
        self.assertLessEqual(strength, 1.0)
        self.assertEqual(detail["enumeration_runs"], 20)
        self.assertEqual(detail["distinct_targets"], 80)
        self.assertFalse(detail["target_cap_hit"])

    def test_rate_independent_identical_structure(self):
        # 1/min and 1/hour produce the same verdict: no timing
        # criterion anywhere in the signal.
        fast = es.enumeration_structure(enum_fixture(gap_s=60))
        slow = es.enumeration_structure(enum_fixture(gap_s=3600))
        self.assertEqual(fast[0], slow[0])
        self.assertEqual(fast[1], slow[1])
        self.assertTrue(slow[0])

    def test_two_reads_not_a_run(self):
        entries = enum_fixture(loops=5, reads_per_loop=2)
        present, _, _ = es.enumeration_structure(entries)
        self.assertFalse(present)

    def test_min_actions_floor(self):
        entries = enum_fixture(loops=4, reads_per_loop=3)  # 16 actions
        present, _, detail = es.enumeration_structure(entries)
        self.assertFalse(present)
        self.assertLess(detail["actions"], es.ENUM_MIN_ACTIONS)

    def test_min_runs_floor(self):
        entries = enum_fixture(loops=2, reads_per_loop=3)  # 2 runs
        present, _, _ = es.enumeration_structure(entries)
        self.assertFalse(present)

    def test_organic_repetition_not_flagged(self):
        # List->read loops exist, but the same 5 targets repeat:
        # coverage does the discrimination.
        entries = []
        t = BASE
        for loop in range(6):
            entries.append(ev(t, "list_documents", "enumerate",
                              target="collection/shared"))
            t += 300
            for k in range(3):
                entries.append(ev(t, "read_document", "read",
                                  target="notes/fav%d" % (k % 5)))
                t += 300
        present, _, detail = es.enumeration_structure(entries)
        self.assertFalse(present)
        self.assertLess(detail["coverage"], es.ENUM_MIN_COVERAGE)

    def test_target_blind_log_stays_silent(self):
        entries = [ev(BASE + i * 240, "list_documents", "enumerate")
                   for i in range(5)]
        entries += [ev(BASE + 2000 + i * 240, "read_document", "read")
                    for i in range(20)]
        present, _, detail = es.enumeration_structure(entries)
        self.assertFalse(present)
        self.assertLess(detail["targeted_fraction"],
                        es.ENUM_MIN_TARGETED_FRACTION)

    def test_reads_before_first_list_unattributed(self):
        entries = [ev(BASE + i, "read_document", "read",
                      target="doc/%d" % i) for i in range(10)]
        entries += enum_fixture(gap_s=240, loops=1, reads_per_loop=3)
        present, _, detail = es.enumeration_structure(entries)
        # 1 run only (the 10 unattributed reads form no run).
        self.assertEqual(detail["enumeration_runs"], 1)
        self.assertFalse(present)

    def test_never_raises_on_garbage(self):
        entries = [None, "x", 42, {}, {"ts": "not-a-time"},
                   {"tool": None, "event": None, "ts": BASE},
                   {"target": None, "ts": BASE, "tool": "read"}]
        present, strength, detail = es.enumeration_structure(entries)
        self.assertFalse(present)
        self.assertEqual(strength, 0.0)
        self.assertGreater(detail["skipped"], 0)

    def test_deterministic(self):
        a = es.enumeration_structure(enum_fixture())
        b = es.enumeration_structure(enum_fixture())
        self.assertEqual(a, b)

    def test_distinct_target_cap(self):
        entries = []
        t = BASE
        entries.append(ev(t, "list_documents", "enumerate", target="c/0"))
        t += 1
        for i in range(es.ENUM_MAX_DISTINCT_TARGETS + 100):
            if i % 4 == 0 and i:
                entries.append(ev(t, "list_documents", "enumerate",
                                  target="c/%d" % i))
            else:
                entries.append(ev(t, "read_document", "read",
                                  target="doc/%d" % i))
            t += 1
        present, strength, detail = es.enumeration_structure(entries)
        self.assertTrue(detail["target_cap_hit"])
        self.assertEqual(detail["distinct_targets"],
                         es.ENUM_MAX_DISTINCT_TARGETS)
        # Fail-open: the signal still fires on what was seen.
        self.assertTrue(present)
        self.assertGreater(strength, 0.0)


class IntegrationTests(unittest.TestCase):
    def test_signal_kind_registered(self):
        self.assertIn(es.SIGNAL_KIND, discovery.SIGNAL_WEIGHTS)

    def test_fingerprint_emits_signal(self):
        fp = shadow_scan.fingerprint_principal("svc-slow-enum",
                                               enum_fixture(gap_s=240))
        kinds = {s["kind"]: s for s in fp["signals"]}
        self.assertIn(es.SIGNAL_KIND, kinds)
        self.assertTrue(kinds[es.SIGNAL_KIND]["present"])
        # Independent sighting: agent_like even though the weighted
        # score (rate-gated signatures) is far below 0.5.
        self.assertLess(fp["score"], 0.5)
        self.assertTrue(fp["agent_like"])

    def test_fingerprint_quiet_for_organic(self):
        entries = [ev(BASE + i * 300, "read_file", "operator action",
                      target="notes/fav%d" % (i % 5)) for i in range(38)]
        fp = shadow_scan.fingerprint_principal("human-op", entries)
        kinds = {s["kind"]: s for s in fp["signals"]}
        self.assertFalse(kinds[es.SIGNAL_KIND]["present"])
        self.assertFalse(fp["agent_like"])

    def test_scan_action_log_surfaces_candidate(self):
        from gov import discovery as d
        sigs = d.scan_action_log(enum_fixture(gap_s=240, principal="s"), set())
        self.assertTrue(any(s["kind"] == es.SIGNAL_KIND for s in sigs))
        self.assertTrue(all(s["source"] == "principal:s" for s in sigs))


if __name__ == "__main__":
    unittest.main()
