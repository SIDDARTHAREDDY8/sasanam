#!/usr/bin/env python3
"""Unit tests for gov.gate_hardening (wave-271 enforcement-path hardening).

Covers the module contract at the unit level: compilation, mode
discipline, deadline inversion, callback allowlist, error/timeout
fail-closed, signed exceptions, break-glass, promotion, and the
audit-scanner analog. The adversarial falsifiable tests live in
evals/w271_gatehard_probes.py; these pin the exact contract points.
"""

import os
import re
import sys
import time
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from gov import gate_hardening as gh
from gov import ed25519 as _ed

NOW = 1791000000


def _gate(**kw):
    kw.setdefault("mode", "protect")
    kw.setdefault("global_deadline_s", 5.0)
    kw.setdefault("now", lambda: NOW)
    return gh.Gate(**kw)


def _policy(predicate, policy_id="p", deadline_s=None, callbacks=()):
    return gh.compile_policy({
        "policy_id": policy_id,
        "predicate_name": getattr(predicate, "__name__", "p"),
        "predicate": predicate,
        "deadline_s": deadline_s,
        "host_callbacks": list(callbacks),
    })


class TestCompilation(unittest.TestCase):
    def test_digest_deterministic(self):
        a = _policy(lambda rt: True)
        b = _policy(lambda rt: True)
        self.assertEqual(a.digest, b.digest)

    def test_digest_keyed(self):
        g = _gate()
        d = g.register_policy(_policy(lambda rt: True))
        self.assertEqual(d, g._policies[d].digest)

    def test_malformed_spec_refused(self):
        with self.assertRaises(gh.GateConfigError) as cm:
            gh.compile_policy({"policy_id": "x"})
        self.assertEqual(cm.exception.code, "gatehard-policy-malformed")


class TestModeDiscipline(unittest.TestCase):
    def test_unknown_mode_refused(self):
        with self.assertRaises(gh.GateConfigError) as cm:
            gh.Gate(mode="observe", global_deadline_s=5.0)
        self.assertEqual(cm.exception.code, "gatehard-unknown-mode")

    def test_monitor_allows_but_records(self):
        g = _gate(mode="monitor")
        g.register_policy(_policy(lambda rt: False))
        v = g.evaluate({"request_id": "r1"})
        self.assertTrue(v["allowed"])
        self.assertEqual(v["code"], "gatehard-monitor-would-deny")
        self.assertTrue(any(e["event"] == "monitor-would-deny"
                            for e in g.audit_log()))

    def test_protect_denies_with_policy_code(self):
        g = _gate(mode="protect")
        g.register_policy(_policy(lambda rt: False))
        v = g.evaluate({"request_id": "r1"})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-policy-denied")

    def test_promotion_recorded(self):
        g = _gate(mode="monitor")
        g.promote_to_protect(now=NOW, reason="rollout done")
        self.assertEqual(g.mode, "protect")
        self.assertTrue(any(e["event"] == "mode-promoted"
                            and e["reason"] == "rollout done"
                            for e in g.audit_log()))

    def test_demotion_recorded(self):
        g = _gate(mode="protect")
        g.demote_to_monitor(now=NOW, reason="regression")
        self.assertEqual(g.mode, "monitor")
        self.assertTrue(any(e["event"] == "mode-demoted"
                            for e in g.audit_log()))


class TestDeadlineInversion(unittest.TestCase):
    def test_unset_global_deadline_refused(self):
        with self.assertRaises(gh.GateConfigError) as cm:
            gh.Gate(mode="protect", global_deadline_s=None)
        self.assertEqual(cm.exception.code,
                         "gatehard-global-deadline-unset")

    def test_zero_global_deadline_refused(self):
        with self.assertRaises(gh.GateConfigError) as cm:
            gh.Gate(mode="protect", global_deadline_s=0)
        self.assertEqual(cm.exception.code,
                         "gatehard-global-deadline-unset")

    def test_per_policy_tighter_ok(self):
        g = _gate()
        g.register_policy(_policy(lambda rt: True, deadline_s=1.0))
        self.assertEqual(len(g._policies), 1)

    def test_per_policy_looser_refused(self):
        g = _gate()
        with self.assertRaises(gh.GateConfigError) as cm:
            g.register_policy(_policy(lambda rt: True, deadline_s=60.0))
        self.assertEqual(
            cm.exception.code,
            "gatehard-per-policy-deadline-exceeds-global")

    def test_timeout_denies(self):
        def slow(rt):
            time.sleep(0.05)
            return True
        g = _gate()
        g.register_policy(_policy(slow, deadline_s=0.005))
        v = g.evaluate({"request_id": "r1"})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-gate-timeout")


class TestCallbackAllowlist(unittest.TestCase):
    def test_wildcard_refused(self):
        with self.assertRaises(gh.GateConfigError) as cm:
            gh.Gate(mode="protect", global_deadline_s=5.0,
                    host_allowlist=frozenset(["*"]))
        self.assertEqual(cm.exception.code,
                         "gatehard-host-callback-wildcard")

    def test_unlisted_callback_denies(self):
        def uses(rt):
            rt.host_callback("pwn", "x")
            return True
        g = _gate(host_allowlist=frozenset())
        g.register_policy(_policy(uses, callbacks=["pwn"]))
        v = g.evaluate({"request_id": "r1"})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-host-callback-denied")

    def test_listed_callback_works(self):
        seen = []

        def uses(rt):
            seen.append(rt.host_callback("metrics", "tick"))
            return True
        g = _gate(host_allowlist=frozenset(["metrics"]))
        g.register_policy(_policy(uses, callbacks=["metrics"]))
        v = g.evaluate({"request_id": "r1"})
        self.assertTrue(v["allowed"])
        self.assertEqual(seen, ["cb:metrics:tick"])


class TestErrorFailClosed(unittest.TestCase):
    def test_crash_denies(self):
        def boom(rt):
            raise RuntimeError("x")
        g = _gate()
        g.register_policy(_policy(boom))
        v = g.evaluate({"request_id": "r1"})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-gate-error")

    def test_f291_undeepcopyable_request_denies_no_raise(self):
        # F291: deepcopy failure becomes a coded fail-closed deny, not
        # a raw raise.
        import threading
        g = _gate()
        g.register_policy(_policy(lambda rt: True))
        v = g.evaluate({"request_id": "r1",
                        "lock": threading.Lock()})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-gate-error")
        self.assertEqual(v["request_id"], "r1")

    def test_f291_undeepcopyable_request_monitor_would_deny(self):
        import threading
        g = _gate(mode="monitor")
        g.register_policy(_policy(lambda rt: True))
        v = g.evaluate({"request_id": "r1",
                        "lock": threading.Lock()})
        self.assertTrue(v["allowed"])
        self.assertEqual(v["code"], "gatehard-monitor-would-deny")
        self.assertEqual(v["would_deny_code"], "gatehard-gate-error")

    def test_f291_deep_nesting_denies_no_raise(self):
        # F291: pathological nesting -> RecursionError inside deepcopy,
        # converted to a coded deny.
        deep = cur = {}
        for _ in range(200000):
            cur["n"] = {}
            cur = cur["n"]
        g = _gate()
        g.register_policy(_policy(lambda rt: True))
        v = g.evaluate({"request_id": "r1", "deep": deep})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-gate-error")

    def test_f291_scan_row_denies_no_raise(self):
        # F291, scan() leg: hostile copy yields a fail-closed row.
        import threading
        g = _gate()
        g.register_policy(_policy(lambda rt: True))
        rows = g.scan([{"request_id": "r1",
                        "lock": threading.Lock()}])
        self.assertEqual(rows, [{"request_id": "r1", "would": "deny",
                                 "code": "gatehard-gate-error"}])

    def test_f291_non_dict_request_denies_no_raise(self):
        # F291: a hostile non-dict request cannot raise via request_id
        # extraction on the early-deny path.
        import threading
        class Weird(object):
            def __init__(self):
                self.lock = threading.Lock()
            def __bool__(self):
                return True
            def get(self, *a, **k):
                raise TypeError("no get for you")
        g = _gate()
        g.register_policy(_policy(lambda rt: True))
        v = g.evaluate(Weird())
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-gate-error")
        self.assertEqual(v["request_id"], "?")

    def test_valid_ignore_exception_allows_audited(self):
        def boom(rt):
            raise RuntimeError("x")
        seed = bytes([0x43]) * 32
        g = _gate(exception_issuer_pub=_ed.publickey(seed))
        g.register_policy(_policy(boom, policy_id="boom"))
        body = gh.failure_ignore_body("boom", NOW - 10, NOW + 60,
                                       "flaky")
        exc = gh.FailureIgnore("boom", NOW - 10, NOW + 60, "flaky",
                               _ed.sign(seed, body))
        v = g.evaluate({"request_id": "r1"}, failure_ignore=exc)
        self.assertTrue(v["allowed"])
        self.assertEqual(v["code"], "gatehard-ignore-exception-used")
        self.assertTrue(any(e["event"] == "ignore-exception-used"
                            for e in g.audit_log()))

    def test_expired_ignore_exception_denies(self):
        def boom(rt):
            raise RuntimeError("x")
        seed = bytes([0x43]) * 32
        g = _gate(exception_issuer_pub=_ed.publickey(seed))
        g.register_policy(_policy(boom, policy_id="boom"))
        body = gh.failure_ignore_body("boom", NOW - 100, NOW - 10,
                                       "flaky")
        exc = gh.FailureIgnore("boom", NOW - 100, NOW - 10, "flaky",
                               _ed.sign(seed, body))
        v = g.evaluate({"request_id": "r1"}, failure_ignore=exc)
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-ignore-exception-invalid")

    def test_wrong_policy_ignore_exception_denies(self):
        def boom(rt):
            raise RuntimeError("x")
        seed = bytes([0x43]) * 32
        g = _gate(exception_issuer_pub=_ed.publickey(seed))
        g.register_policy(_policy(boom, policy_id="boom"))
        body = gh.failure_ignore_body("other", NOW - 10, NOW + 60,
                                       "flaky")
        exc = gh.FailureIgnore("other", NOW - 10, NOW + 60, "flaky",
                               _ed.sign(seed, body))
        v = g.evaluate({"request_id": "r1"}, failure_ignore=exc)
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-ignore-exception-invalid")


class TestBreakGlass(unittest.TestCase):
    def _gate_with_issuer(self):
        seed = bytes([0x42]) * 32
        g = _gate(breakglass_issuer_pub=_ed.publickey(seed))
        g.register_policy(_policy(lambda rt: False))
        return g, seed

    def _token(self, seed, request_class="deny-all", not_before=NOW - 10,
               expires_at=NOW + 60, reason="incident"):
        body = gh.breakglass_body(request_class, not_before, expires_at,
                                  reason)
        return gh.BreakGlassToken(request_class, not_before, expires_at,
                                  reason, _ed.sign(seed, body))

    def test_valid_breakglass_allows_audited(self):
        g, seed = self._gate_with_issuer()
        v = g.evaluate({"request_id": "r1", "class": "deny-all"},
                       break_glass=self._token(seed))
        self.assertTrue(v["allowed"])
        self.assertEqual(v["code"], "gatehard-breakglass-used")
        self.assertTrue(any(e["event"] == "breakglass-used"
                            for e in g.audit_log()))

    def test_forged_breakglass_denies(self):
        g, _seed = self._gate_with_issuer()
        tok = gh.BreakGlassToken("deny-all", NOW - 10, NOW + 60,
                                 "forged", b"bogus", namespace="trusted")
        v = g.evaluate({"request_id": "r1", "class": "deny-all"},
                       break_glass=tok)
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-breakglass-invalid")

    def test_wrong_class_breakglass_denies(self):
        g, seed = self._gate_with_issuer()
        v = g.evaluate({"request_id": "r1", "class": "deny-all"},
                       break_glass=self._token(seed, request_class="other"))
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-breakglass-invalid")


class TestFreshRuntime(unittest.TestCase):
    def test_runtime_not_retained(self):
        g = _gate()
        g.register_policy(_policy(lambda rt: True))
        g.evaluate({"request_id": "r1"})
        self.assertTrue(g._runtime_after_eval_is_none())

    def test_each_request_gets_fresh_ctx(self):
        seen = []
        residue = []

        def grab(rt):
            residue.append("n" in rt.ctx)  # residue from a prior request?
            seen.append(rt.ctx)
            rt.ctx["n"] = 1
            return True
        g = _gate()
        g.register_policy(_policy(grab))
        g.evaluate({"request_id": "r1"})
        g.evaluate({"request_id": "r2"})
        self.assertEqual(len(seen), 2)
        self.assertIsNot(seen[0], seen[1])
        self.assertEqual(residue, [False, False])


class TestAuditScanner(unittest.TestCase):
    def test_deterministic_order(self):
        g = _gate()
        g.register_policy(_policy(lambda rt: True))
        reqs = [{"request_id": "r%d" % i} for i in (3, 1, 2)]
        rep = g.scan(reqs)
        self.assertEqual([r["request_id"] for r in rep],
                         ["r1", "r2", "r3"])

    def test_flags_new_denials(self):
        g1 = _gate()
        g1.register_policy(_policy(lambda rt: True))
        g2 = _gate()
        g2.register_policy(_policy(
            lambda rt: rt.request.get("request_id") != "r2"))
        reqs = [{"request_id": "r1"}, {"request_id": "r2"}]
        rep1 = {r["request_id"]: r["would"] for r in g1.scan(reqs)}
        rep2 = {r["request_id"]: r["would"] for r in g2.scan(reqs)}
        self.assertEqual(rep1, {"r1": "allow", "r2": "allow"})
        self.assertEqual(rep2, {"r1": "allow", "r2": "deny"})

    def test_scan_is_read_only(self):
        g = _gate()
        g.register_policy(_policy(lambda rt: True))
        n = len(g.audit_log())
        g.scan([{"request_id": "r1"}])
        self.assertEqual(len(g.audit_log()), n)


class TestTaxonomy(unittest.TestCase):
    def test_literals_unique_and_sorted(self):
        path = os.path.join(_REPO, "gov", "decision_codes.py")
        src = open(path).read()
        lits = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]',
                          src)
        self.assertEqual(len(lits), 1802)  # Wave-279 lane 2: pin 1493 -> 1494 (+1 evbundle-contract-refused); prior Wave-275 lane D: pin 1485 -> 1485.; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)
        self.assertEqual(len(set(lits)), len(lits))
        gh = sorted(c for c in set(lits) if c.startswith("gatehard-"))
        self.assertEqual(len(gh), 14)
        self.assertEqual(gh, sorted(gh))

    def test_new_codes_registered(self):
        from gov import decision_codes
        for code in ("gatehard-breakglass-invalid",
                     "gatehard-breakglass-used",
                     "gatehard-gate-error",
                     "gatehard-gate-timeout",
                     "gatehard-global-deadline-unset",
                     "gatehard-host-callback-denied",
                     "gatehard-host-callback-wildcard",
                     "gatehard-ignore-exception-invalid",
                     "gatehard-ignore-exception-used",
                     "gatehard-monitor-would-deny",
                     "gatehard-per-policy-deadline-exceeds-global",
                     "gatehard-policy-denied",
                     "gatehard-policy-malformed",
                     "gatehard-unknown-mode"):
            self.assertIn(code, decision_codes.TAXONOMY)
            self.assertEqual(decision_codes.TAXONOMY[code]["domain"],
                             "gatehard")


if __name__ == "__main__":
    unittest.main(verbosity=2)
