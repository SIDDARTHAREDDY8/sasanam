"""Unit tests for gov/supervision.py (wave-297 lane 4).

Declared agent lifecycle supervision (erlang/otp pattern): closed
child inventory, one_for_one / one_for_all / rest_for_one restart
strategies, bounded intensity, signed crash reports with
digest-only reason storage, crash-loop detection, and signed,
audit-logged escalation.
"""

import hashlib
import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes as dc
from gov import ed25519
from gov import supervision as sup


def _seed(tag):
    return hashlib.sha256(("w297-test-%s" % tag).encode()).digest()


def _pub(seed):
    return ed25519.publickey(seed).hex()


def _child(i, strategy="one_for_one", max_restarts=100, window_seconds=3600):
    cid = "child-%s" % chr(ord("a") + i)
    cs = _seed("c%d" % i)
    return sup.ChildSpec(cid, _pub(cs), strategy, max_restarts,
                         window_seconds), cs


def _make(strategy="one_for_one", max_restarts=100, window_seconds=3600,
          n=3):
    specs = []
    seeds = {}
    for i in range(n):
        spec, cs = _child(i, strategy, max_restarts, window_seconds)
        specs.append(spec)
        seeds[spec.child_id] = cs
    s = sup.Supervisor("sup-ut", specs, _seed("sup"))
    s.start(at=0)
    return s, seeds


def _report(child_seed, child_id, reason, crashed_at):
    body = {"child_id": child_id, "reason_kind": "exit",
            "reason_bytes": reason, "crashed_at": crashed_at}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode()
    rep = dict(body)
    rep["signature"] = ed25519.sign(child_seed, raw).hex()
    return rep


class TestSupervisionDecisions(unittest.TestCase):
    def test_codes_registered(self):
        for code in ("supervision-crash-loop",
                     "supervision-intensity-exceeded",
                     "supervision-invalid",
                     "supervision-undeclared-child"):
            self.assertIn(code, dc.TAXONOMY)
        self.assertEqual(len(dc.TAXONOMY), 1841)

    def test_code_literals_sorted_unique(self):
        lits = [c for c in dc.TAXONOMY]
        self.assertEqual(lits, sorted(lits))
        self.assertEqual(len(lits), len(set(lits)))

    def test_one_for_one_restarts_only_crashed(self):
        s, seeds = _make("one_for_one")
        d = s.report_crash("child-b", _report(seeds["child-b"], "child-b",
                                             "boom", 5), at=5)
        self.assertEqual(d["action"], "restart")
        self.assertEqual(d["restart_set"], ["child-b"])
        self.assertIsNone(d["code"])

    def test_one_for_all_restarts_all(self):
        s, seeds = _make("one_for_all")
        d = s.report_crash("child-c", _report(seeds["child-c"], "child-c",
                                             "boom", 5), at=5)
        self.assertEqual(sorted(d["restart_set"]),
                         ["child-a", "child-b", "child-c"])

    def test_rest_for_one_restarts_crashed_and_later(self):
        s, seeds = _make("rest_for_one")
        d = s.report_crash("child-b", _report(seeds["child-b"], "child-b",
                                             "boom", 5), at=5)
        self.assertEqual(d["restart_set"], ["child-b", "child-c"])
        d2 = s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                              "boom", 6), at=6)
        self.assertEqual(sorted(d2["restart_set"]),
                         ["child-a", "child-b", "child-c"])

    def test_rest_for_one_reorder(self):
        s, seeds = _make("rest_for_one")
        s.report_crash("child-b", _report(seeds["child-b"], "child-b",
                                         "boom", 5), at=5)
        # b restarted: order becomes [a, b, c] (b re-appended after a)
        d = s.report_crash("child-c", _report(seeds["child-c"], "child-c",
                                             "boom2", 6), at=6)
        self.assertEqual(d["restart_set"], ["child-c"])

    def test_undeclared_child_refuses_coded(self):
        s, seeds = _make()
        with self.assertRaises(sup.SupervisionError) as cm:
            s.report_crash("child-z", _report(_seed("x"), "child-z",
                                              "boom", 5), at=5)
        self.assertEqual(cm.exception.code, "supervision-undeclared-child")

    def test_forged_report_refuses_coded(self):
        s, seeds = _make()
        rep = _report(_seed("attacker"), "child-a", "boom", 5)
        with self.assertRaises(sup.SupervisionError) as cm:
            s.report_crash("child-a", rep, at=5)
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_missing_signature_refuses(self):
        s, seeds = _make()
        rep = _report(seeds["child-a"], "child-a", "boom", 5)
        del rep["signature"]
        with self.assertRaises(sup.SupervisionError) as cm:
            s.report_crash("child-a", rep, at=5)
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_extra_field_refuses(self):
        s, seeds = _make()
        rep = _report(seeds["child-a"], "child-a", "boom", 5)
        rep["note"] = "extra"
        with self.assertRaises(sup.SupervisionError) as cm:
            s.report_crash("child-a", rep, at=5)
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_oversized_reason_refuses(self):
        s, seeds = _make()
        rep = _report(seeds["child-a"], "child-a", "x" * 4097, 5)
        with self.assertRaises(sup.SupervisionError) as cm:
            s.report_crash("child-a", rep, at=5)
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_reason_at_bound_ok(self):
        s, seeds = _make()
        rep = _report(seeds["child-a"], "child-a", "x" * 4096, 5)
        d = s.report_crash("child-a", rep, at=5)
        self.assertEqual(d["action"], "restart")

    def test_reason_digest_only(self):
        # The stored escalation/decision records carry digests, never
        # the raw reason payload.
        s, seeds = _make()
        secret = "top-secret-payload-%d" % 7
        d = s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                             secret, 5), at=5)
        self.assertEqual(d["reason_digest"],
                         hashlib.sha256(secret.encode()).hexdigest())
        self.assertNotIn(secret, json.dumps(d))

    def test_intensity_exhaustion_refuses_and_escalates(self):
        s, seeds = _make(max_restarts=2, window_seconds=3600)
        s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                         "r1", 0), at=0)
        s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                         "r2", 1), at=1)
        with self.assertRaises(sup.SupervisionError) as cm:
            s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                             "r3", 2), at=2)
        self.assertEqual(cm.exception.code,
                         "supervision-intensity-exceeded")
        escs = s.escalations
        self.assertEqual(len(escs), 1)
        self.assertEqual(escs[0]["code"], "supervision-intensity-exceeded")
        self.assertTrue(s.verify_escalation(escs[0]))

    def test_intensity_window_slides(self):
        s, seeds = _make(max_restarts=1, window_seconds=100)
        s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                         "r1", 0), at=0)
        d = s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                             "r2", 150), at=150)
        self.assertEqual(d["action"], "restart")

    def test_crash_loop_refuses_and_escalates(self):
        s, seeds = _make(max_restarts=100)
        s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                         "same", 0), at=0)
        s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                         "same", 1), at=1)
        with self.assertRaises(sup.SupervisionError) as cm:
            s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                             "same", 2), at=2)
        self.assertEqual(cm.exception.code, "supervision-crash-loop")
        escs = s.escalations
        self.assertEqual(escs[-1]["code"], "supervision-crash-loop")
        self.assertTrue(s.verify_escalation(escs[-1]))

    def test_loop_streak_resets_on_new_reason(self):
        s, seeds = _make(max_restarts=100)
        for t, r in ((0, "x"), (1, "y"), (2, "x"), (3, "x")):
            d = s.report_crash("child-a", _report(seeds["child-a"],
                                                  "child-a", r, t), at=t)
            self.assertEqual(d["action"], "restart")

    def test_escalation_tamper_fails_verify(self):
        s, seeds = _make(max_restarts=1)
        s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                         "r1", 0), at=0)
        try:
            s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                             "r2", 1), at=1)
        except sup.SupervisionError:
            pass
        forged = dict(s.escalations[0])
        forged["code"] = "supervision-invalid"
        self.assertFalse(s.verify_escalation(forged))
        forged["signature"] = "00" * 64
        self.assertFalse(s.verify_escalation(forged))

    def test_child_spec_frozen(self):
        spec, _ = _child(0)
        with self.assertRaises(sup.SupervisionError) as cm:
            spec.max_restarts = 9999
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_duplicate_child_id_refuses(self):
        spec1, _ = _child(0)
        spec2, _ = _child(0)
        with self.assertRaises(sup.SupervisionError) as cm:
            sup.Supervisor("s", [spec1, spec2], _seed("s"))
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_bad_strategy_refuses(self):
        with self.assertRaises(sup.SupervisionError) as cm:
            sup.ChildSpec("child-a", _pub(_seed("x")), "nope", 3, 60)
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_unbounded_intensity_refuses(self):
        with self.assertRaises(sup.SupervisionError):
            sup.ChildSpec("child-a", _pub(_seed("x")), "one_for_one", 0, 60)
        with self.assertRaises(sup.SupervisionError):
            sup.ChildSpec("child-a", _pub(_seed("x")), "one_for_one", 3, 0)
        with self.assertRaises(sup.SupervisionError):
            sup.ChildSpec("child-a", _pub(_seed("x")), "one_for_one",
                          1001, 60)

    def test_empty_inventory_refuses(self):
        with self.assertRaises(sup.SupervisionError) as cm:
            sup.Supervisor("s", [], _seed("s"))
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_circular_material_refuses_coded(self):
        evil = {}
        evil["self"] = evil
        with self.assertRaises(sup.SupervisionError) as cm:
            sup._canonical(evil)
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_restarts_in_window_accounting(self):
        s, seeds = _make(max_restarts=10, window_seconds=100)
        s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                         "r1", 0), at=0)
        s.report_crash("child-a", _report(seeds["child-a"], "child-a",
                                         "r2", 50), at=50)
        self.assertEqual(s.restarts_in_window("child-a", 60), 2)
        self.assertEqual(s.restarts_in_window("child-a", 200), 0)

    def test_audit_sink_never_breaks(self):
        # A broken sink must not break supervision (F345-class).
        old = sup._EMIT
        sup._EMIT = lambda e, f: 1 / 0  # noqa: E731
        try:
            s, seeds = _make()
            d = s.report_crash("child-a", _report(seeds["child-a"],
                                                  "child-a", "boom", 5),
                               at=5)
            self.assertEqual(d["action"], "restart")
        finally:
            sup._EMIT = old


if __name__ == "__main__":
    unittest.main()
