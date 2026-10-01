#!/usr/bin/env python3
"""Unit tests for wave-273 gate_hardening closures (F256/F257/F258/F276/
F280/F281) and the tool_grant F286 fix.

These pin the exact contract points of the closures; the adversarial
falsifiable tests live in evals/w272_isolation_probes.py and
evals/w272_redteam_probes.py.
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from gov import gate_hardening as gh
from gov import tool_grant
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


# ---------------------------------------------------------------------------
# F256: BaseException is fail-closed; GeneratorExit is re-raised
# ---------------------------------------------------------------------------

class TestF256BaseException(unittest.TestCase):
    def test_systemexit_becomes_deny(self):
        def boom(rt):
            raise SystemExit(3)
        g = _gate()
        g.register_policy(_policy(boom))
        v = g.evaluate({"request_id": "r"})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-gate-error")

    def test_keyboardinterrupt_becomes_deny(self):
        def boom(rt):
            raise KeyboardInterrupt()
        g = _gate()
        g.register_policy(_policy(boom))
        v = g.evaluate({"request_id": "r"})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-gate-error")

    def test_generatorexit_is_not_swallowed(self):
        # F256(3): GeneratorExit must not be converted into a deny;
        # it is re-raised so generator cleanup semantics stay intact.
        def boom(rt):
            raise GeneratorExit()
        g = _gate()
        g.register_policy(_policy(boom))
        with self.assertRaises(GeneratorExit):
            g.evaluate({"request_id": "r"})

    def test_runtime_discarded_on_baseexception(self):
        def boom(rt):
            raise SystemExit(1)
        g = _gate()
        g.register_policy(_policy(boom))
        g.evaluate({"request_id": "r"})
        self.assertIsNone(g._last_runtime)


# ---------------------------------------------------------------------------
# F257: bounded audit store with counted eviction
# ---------------------------------------------------------------------------

class TestF257BoundedAudit(unittest.TestCase):
    def test_default_bound(self):
        g = _gate()
        g.register_policy(_policy(lambda rt: True))
        for i in range(5000):
            g.evaluate({"request_id": "r%d" % i})
        self.assertLessEqual(len(g.audit_log()), 1024)
        self.assertEqual(g.audit_maxlen, 1024)

    def test_eviction_is_counted_not_silent(self):
        g = _gate(audit_maxlen=5)
        g.register_policy(_policy(lambda rt: True))
        for i in range(10):
            g.evaluate({"request_id": "r%d" % i})
        self.assertEqual(len(g.audit_log()), 5)
        self.assertGreater(g.audit_dropped, 0)
        # The surviving entries are the NEWEST (oldest evicted first).
        last = g.audit_log()[-1]
        self.assertEqual(last["request_id"], "r9")

    def test_custom_bound(self):
        g = _gate(audit_maxlen=10)
        self.assertEqual(g.audit_maxlen, 10)

    def test_invalid_bound_refused(self):
        # bool, non-int, and non-positive values are refused loudly.
        for bad in (0, -3, 1.5, "100", True):
            with self.assertRaises(gh.GateConfigError):
                _gate(audit_maxlen=bad)


# ---------------------------------------------------------------------------
# F258: deep-copied request; predicate cannot touch caller state
# ---------------------------------------------------------------------------

class TestF258DeepCopy(unittest.TestCase):
    def test_nested_mutation_does_not_touch_caller(self):
        def evil(rt):
            rt.request["nested"]["k"] = "pwned"
            rt.request["new"] = 1
            return True
        g = _gate()
        g.register_policy(_policy(evil))
        caller = {"request_id": "r", "nested": {"k": "v"}}
        v = g.evaluate(caller)
        self.assertTrue(v["allowed"])
        self.assertEqual(caller, {"request_id": "r",
                                  "nested": {"k": "v"}})

    def test_predicate_still_reads_nested_fields(self):
        def reader(rt):
            return rt.request["nested"]["k"] == "v"
        g = _gate()
        g.register_policy(_policy(reader))
        v = g.evaluate({"request_id": "r", "nested": {"k": "v"}})
        self.assertTrue(v["allowed"])

    def test_scan_also_deep_copies(self):
        def evil(rt):
            rt.request["nested"]["k"] = "pwned"
            return True
        g = _gate()
        g.register_policy(_policy(evil))
        reqs = [{"request_id": "r", "nested": {"k": "v"}}]
        out = g.scan(reqs)
        self.assertEqual(out[0]["would"], "allow")
        self.assertEqual(reqs[0]["nested"]["k"], "v")


# ---------------------------------------------------------------------------
# F276: loud config refusal
# ---------------------------------------------------------------------------

class TestF276LoudConfig(unittest.TestCase):
    def _spec(self, **kw):
        spec = {"policy_id": "p", "predicate_name": "p",
                "predicate": lambda rt: True,
                "host_callbacks": []}
        spec.update(kw)
        return spec

    def test_str_host_callbacks_refused(self):
        with self.assertRaises(gh.GateConfigError) as ctx:
            gh.compile_policy(self._spec(host_callbacks="exec"))
        self.assertEqual(ctx.exception.code, "gatehard-policy-malformed")

    def test_non_list_host_callbacks_refused(self):
        for bad in (None, 42, {"a": 1}):
            with self.assertRaises(gh.GateConfigError):
                gh.compile_policy(self._spec(host_callbacks=bad))

    def test_non_str_callback_entry_refused(self):
        with self.assertRaises(gh.GateConfigError):
            gh.compile_policy(self._spec(host_callbacks=["ok", 42]))

    def test_tuple_still_accepted(self):
        cp = gh.compile_policy(self._spec(host_callbacks=("a", "b")))
        self.assertEqual(cp.host_callbacks, ("a", "b"))

    def test_nonnumeric_deadline_refused(self):
        cp = gh.compile_policy(self._spec(deadline_s="not-a-number"))
        g = _gate()
        with self.assertRaises(gh.GateConfigError) as ctx:
            g.register_policy(cp)
        self.assertEqual(ctx.exception.code, "gatehard-policy-malformed")

    def test_bool_deadline_refused(self):
        cp = gh.compile_policy(self._spec(deadline_s=True))
        with self.assertRaises(gh.GateConfigError):
            _gate().register_policy(cp)

    def test_numeric_deadline_still_accepted(self):
        cp = gh.compile_policy(self._spec(deadline_s=2.0))
        g = _gate()
        self.assertIsNotNone(g.register_policy(cp))


# ---------------------------------------------------------------------------
# F280: FailureIgnore is per-policy
# ---------------------------------------------------------------------------

def _exc_seed():
    return bytes(bytearray(range(32)))


class TestF280PerPolicyIgnore(unittest.TestCase):
    def _gate2(self):
        seed = _exc_seed()
        return _gate(exception_issuer_pub=_ed.publickey(seed)), seed

    def _exc(self, seed, policy_id):
        body = gh.failure_ignore_body(policy_id, NOW - 10, NOW + 60, "r")
        return gh.FailureIgnore(policy_id, NOW - 10, NOW + 60, "r",
                                _ed.sign(seed, body))

    def test_ignore_does_not_skip_later_deny(self):
        def boom(rt):
            raise RuntimeError("x")
        g, seed = self._gate2()
        g.register_policy(_policy(boom, policy_id="aaa-boom"))
        g.register_policy(_policy(lambda rt: False, policy_id="zzz-deny"))
        v = g.evaluate({"request_id": "r"},
                       failure_ignore=self._exc(seed, "aaa-boom"))
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-policy-denied")

    def test_ignore_allows_when_rest_allow(self):
        def boom(rt):
            raise RuntimeError("x")
        g, seed = self._gate2()
        g.register_policy(_policy(boom, policy_id="aaa-boom"))
        g.register_policy(_policy(lambda rt: True, policy_id="zzz-ok"))
        v = g.evaluate({"request_id": "r"},
                       failure_ignore=self._exc(seed, "aaa-boom"))
        self.assertTrue(v["allowed"])
        self.assertEqual(v["code"], "gatehard-ignore-exception-used")

    def test_single_policy_ignore_unchanged(self):
        def boom(rt):
            raise RuntimeError("x")
        g, seed = self._gate2()
        g.register_policy(_policy(boom, policy_id="only"))
        v = g.evaluate({"request_id": "r"},
                       failure_ignore=self._exc(seed, "only"))
        self.assertTrue(v["allowed"])
        self.assertEqual(v["code"], "gatehard-ignore-exception-used")

    def test_invalid_ignore_still_denies(self):
        def boom(rt):
            raise RuntimeError("x")
        g, seed = self._gate2()
        g.register_policy(_policy(boom, policy_id="only"))
        bad = self._exc(seed, "other-policy")
        v = g.evaluate({"request_id": "r"}, failure_ignore=bad)
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-ignore-exception-invalid")


# ---------------------------------------------------------------------------
# F281: break-glass class matching
# ---------------------------------------------------------------------------

class TestF281BreakGlassClass(unittest.TestCase):
    def _setup(self):
        seed = bytes(bytearray(range(1, 33)))
        g = _gate(breakglass_issuer_pub=_ed.publickey(seed))
        g.register_policy(_policy(lambda rt: False, policy_id="p"))
        return g, seed

    def _tok(self, seed, cls):
        body = gh.breakglass_body(cls, NOW - 10, NOW + 60, "r")
        return gh.BreakGlassToken(cls, NOW - 10, NOW + 60, "r",
                                  _ed.sign(seed, body))

    def test_class_does_not_match_request_id(self):
        g, seed = self._setup()
        v = g.evaluate({"request_id": "r-victim"},
                       break_glass=self._tok(seed, "r-victim"))
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "gatehard-breakglass-invalid")

    def test_none_never_matches(self):
        g, seed = self._setup()
        v = g.evaluate({}, break_glass=self._tok(seed, None))
        self.assertFalse(v["allowed"])

    def test_request_without_class_key_does_not_match(self):
        g, seed = self._setup()
        v = g.evaluate({"request_id": "r"},
                       break_glass=self._tok(seed, "k"))
        self.assertFalse(v["allowed"])

    def test_legitimate_class_match_still_works(self):
        g, seed = self._setup()
        v = g.evaluate({"request_id": "r", "class": "k"},
                       break_glass=self._tok(seed, "k"))
        self.assertTrue(v["allowed"])
        self.assertEqual(v["code"], "gatehard-breakglass-used")

    def test_class_mismatch_still_denied(self):
        g, seed = self._setup()
        v = g.evaluate({"request_id": "r", "class": "other"},
                       break_glass=self._tok(seed, "k"))
        self.assertFalse(v["allowed"])


# ---------------------------------------------------------------------------
# F286: tool_grant enforce() never raises on store failure
# ---------------------------------------------------------------------------

_ISS_SEED = bytes(bytearray(range(64, 96)))
_HOLDER_SEED = bytes(bytearray(range(96, 128)))
_AUD = "https://mcp.example.internal/fileserver"
_LINK = "sha256:" + "ab" * 32


def _f286_details(tool="read_file"):
    return {
        "type": "https://sasanam.dev/mcp_tool_call",
        "locations": [_AUD],
        "actions": ["call"],
        "identifier": "fileserver::" + tool,
        "arg_bounds": {"path": {"predicate": "prefix",
                                "params": {"prefix": "/data/shared/"}}},
        "supply_chain": {"link_digest": _LINK, "delegation_ok": True},
        "max_calls": 3,
    }


def _f286_grant():
    iss = tool_grant.Issuer(iss="sasanam-tool-as", issuer_seed=_ISS_SEED,
                            mandate_lookup=lambda m: {"version": 7})
    return iss.issue(sub="spiffe://trust-domain/ns/prod/sa/agent-7",
                     aud=_AUD, proof_pub=_ed.publickey(_HOLDER_SEED),
                     mandate_id="mnd_1", mandate_version=7,
                     details=[_f286_details()], lifetime_s=600, now=NOW)


def _f286_proof(g, nonce):
    return tool_grant.make_pop_proof(_HOLDER_SEED, g, method="tools/call",
                                     uri=_AUD + "/tools/call", now=NOW,
                                     nonce=nonce)


def _f286_call(g, nonce, provider):
    env = dict(issuer_pub=_ed.publickey(_ISS_SEED),
               server_name="fileserver", server_uri=_AUD, now=NOW,
               usage_store=tool_grant.UsageStore(),
               mandate_version_provider=provider,
               link_verifier=lambda t: _LINK)
    return tool_grant.enforce(g, proof=_f286_proof(g, nonce), tool="read_file",
                              args={"path": "/data/shared/a.txt"}, **env)


class TestF286MandateStoreFailClosed(unittest.TestCase):
    def test_raising_provider_becomes_unreachable_verdict(self):
        def raising(mid):
            raise ConnectionError("store down")
        v = _f286_call(_f286_grant(), "n1", raising)
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-mandate-unreachable")

    def test_returning_none_provider_is_still_fail_closed(self):
        # A None return is "no version known": mandate-drift, still
        # fail-closed (a distinct code from unreachable-by-exception).
        v = _f286_call(_f286_grant(), "n1", lambda mid: None)
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-mandate-drift")

    def test_healthy_provider_unchanged(self):
        v = _f286_call(_f286_grant(), "n2", lambda mid: 7)
        self.assertTrue(v["ok"])


# ---------------------------------------------------------------------------
# Monitor-but-count verdict accounting (wave-273 phase 2)
# ---------------------------------------------------------------------------

class TestMonitorAccounting(unittest.TestCase):
    def _mon(self, **kw):
        kw.setdefault("mode", "monitor")
        return _gate(**kw)

    def test_would_deny_counted_per_code(self):
        g = self._mon()
        g.register_policy(_policy(lambda rt: False, policy_id="p"))
        v = g.evaluate({"request_id": "r"})
        self.assertTrue(v["allowed"])
        self.assertEqual(v["code"], "gatehard-monitor-would-deny")
        self.assertEqual(v["would_deny_code"], "gatehard-policy-denied")
        self.assertEqual(g.monitor_deny_counts["gatehard-policy-denied"], 1)

    def test_all_enforcement_points_mirrored(self):
        # host-callback-denied, gate-timeout, gate-error are each
        # mirrored by a monitor-path counter.
        g = self._mon(host_allowlist=frozenset({"ok"}))
        def evil_cb(rt):
            rt.host_callback("evil")
            return True
        def boom(rt):
            raise RuntimeError("x")
        g.register_policy(_policy(evil_cb, policy_id="a-cb"))
        g.register_policy(_policy(boom, policy_id="z-boom"))
        g.evaluate({"request_id": "r1"})  # first policy trips first
        self.assertEqual(
            g.monitor_deny_counts["gatehard-host-callback-denied"], 1)

        g2 = self._mon()
        g2.register_policy(_policy(boom, policy_id="p"))
        g2.evaluate({"request_id": "r"})
        self.assertEqual(g2.monitor_deny_counts["gatehard-gate-error"], 1)

    def test_would_allow_counted(self):
        g = self._mon()
        g.register_policy(_policy(lambda rt: True, policy_id="p"))
        g.evaluate({"request_id": "r"})
        self.assertEqual(g.monitor_allow_count, 1)
        self.assertEqual(len(g.monitor_deny_counts), 0)

    def test_protect_mode_does_not_touch_counters(self):
        g = _gate(mode="protect")
        g.register_policy(_policy(lambda rt: False, policy_id="p"))
        v = g.evaluate({"request_id": "r"})
        self.assertFalse(v["allowed"])
        self.assertEqual(len(g.monitor_deny_counts), 0)
        self.assertEqual(g.monitor_allow_count, 0)

    def test_monitor_report(self):
        g = self._mon()
        g.register_policy(_policy(lambda rt: rt.request["k"] == "ok",
                                  policy_id="p"))
        for i in range(3):
            g.evaluate({"request_id": "a%d" % i, "k": "ok"})
        for i in range(2):
            g.evaluate({"request_id": "d%d" % i, "k": "nope"})
        r = g.monitor_report()
        self.assertEqual(r["monitor_would_allow"], 3)
        self.assertEqual(r["monitor_would_deny"],
                         {"gatehard-policy-denied": 2})
        self.assertEqual(r["monitor_would_deny_total"], 2)
        self.assertEqual(r["monitor_evaluations"], 5)

    def test_scan_summary(self):
        g = _gate(mode="protect")
        g.register_policy(_policy(lambda rt: rt.request["k"] == "ok",
                                  policy_id="deny-p"))
        reqs = [{"request_id": "a1", "k": "ok"},
                {"request_id": "a2", "k": "ok"},
                {"request_id": "d1", "k": "nope"}]
        s = g.scan_summary(reqs)
        self.assertEqual(s["would_allow"], 2)
        self.assertEqual(s["would_deny"],
                         {"gatehard-policy-denied": 1})

    def test_scan_summary_does_not_mutate_counters(self):
        g = self._mon()
        g.register_policy(_policy(lambda rt: False, policy_id="p"))
        g.evaluate({"request_id": "r"})
        before = dict(g.monitor_deny_counts)
        g.scan_summary([{"request_id": "s", "k": "v"}])
        self.assertEqual(dict(g.monitor_deny_counts), before)

    def test_fresh_gate_starts_zero(self):
        g = self._mon()
        self.assertEqual(g.monitor_allow_count, 0)
        self.assertEqual(len(g.monitor_deny_counts), 0)

    def test_ignore_allow_path_counts_as_would_allow(self):
        # A valid FailureIgnore whose remaining policies all allow is
        # an allowed verdict: it must increment monitor_allow_count,
        # not slip past the accounting on the early return.
        seed = bytes(bytearray(range(32)))
        g = _gate(mode="monitor", exception_issuer_pub=_ed.publickey(seed))

        def boom(rt):
            raise RuntimeError("x")
        g.register_policy(_policy(boom, policy_id="only"))
        body = gh.failure_ignore_body("only", NOW - 10, NOW + 60, "r")
        exc = gh.FailureIgnore("only", NOW - 10, NOW + 60, "r",
                               _ed.sign(seed, body))
        v = g.evaluate({"request_id": "r"}, failure_ignore=exc)
        self.assertTrue(v["allowed"])
        self.assertEqual(v["code"], "gatehard-ignore-exception-used")
        self.assertEqual(g.monitor_allow_count, 1)
        self.assertEqual(len(g.monitor_deny_counts), 0)


if __name__ == "__main__":
    unittest.main()
