"""Unit tests for gov/invocation_pipeline.py (wave-294 lane 3).

The invocation filter pipeline: mandatory pre/post filters around every
tool execution (semantic-kernel mechanism, stdlib only).
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import invocation_pipeline as IP  # noqa: E402
from gov import tool_rules as TR  # noqa: E402
from gov import ed25519 as ed  # noqa: E402


def ctx(**over):
    kw = {"tool": "read_file", "args": {"path": "/tmp/x"},
          "caller": {"identity": "agent-1", "authenticated": True},
          "session_id": "sess-1", "call_id": "call-1"}
    kw.update(over)
    return IP.InvocationContext(**kw)


def passthrough(ctx_, nxt):
    return nxt(ctx_)


def rules_doc():
    return {
        "format": "sasanam-tool-rule-set/v1",
        "name": "unit-rules",
        "tools": ["read_file", "write_file"],
        "rules": [
            {"kind": "Init", "tool": "read_file"},
            {"kind": "Child", "tool": "write_file", "parent": "read_file"},
        ],
    }


class TestContext(unittest.TestCase):
    def test_valid(self):
        c = ctx()
        self.assertEqual(c.tool, "read_file")
        self.assertEqual(c.caller_id, "agent-1")

    def test_anonymous_caller(self):
        c = ctx(caller={})
        self.assertEqual(c.caller_id, "anonymous")

    def test_bad_tool(self):
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            ctx(tool="")
        self.assertEqual(cm.exception.code, "toolcall-invalid-call")

    def test_bad_args(self):
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            ctx(args="nope")
        self.assertEqual(cm.exception.code, "toolcall-invalid-call")

    def test_bad_declared_cost(self):
        for bad in (-1.0, 0.0, float("nan"), True, "x"):
            with self.assertRaises(IP.InvocationPipelineError) as cm:
                ctx(declared_cost=bad)
            self.assertEqual(cm.exception.code,
                             "toolcall-budget-reserve-invalid")

    def test_bad_history(self):
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            ctx(history=[{"nope": 1}])
        self.assertEqual(cm.exception.code, "toolcall-invalid-call")


class TestStackMechanics(unittest.TestCase):
    def test_pre_post_order(self):
        order = []

        def f1(c, nxt):
            order.append("f1-pre")
            out = nxt(c)
            order.append("f1-post")
            return out

        def f2(c, nxt):
            order.append("f2-pre")
            out = nxt(c)
            order.append("f2-post")
            return out

        stack = IP.build_filter_stack([f1, f2])
        out = stack.invoke(lambda c: order.append("body") or {"ok": 1}, ctx())
        self.assertEqual(out, {"ok": 1})
        self.assertEqual(order, ["f1-pre", "f2-pre", "body",
                                 "f2-post", "f1-post"])

    def test_skip_next_denied(self):
        stack = IP.build_filter_stack([lambda c, nxt: {"x": 1}])
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            stack.invoke(lambda c: {"ok": 1}, ctx())
        self.assertEqual(cm.exception.code, "toolfilter-skip-denied")

    def test_double_next_denied(self):
        def greedy(c, nxt):
            nxt(c)
            return nxt(c)

        stack = IP.build_filter_stack([greedy])
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            stack.invoke(lambda c: {"ok": 1}, ctx())
        self.assertEqual(cm.exception.code, "toolfilter-skip-denied")

    def test_uncoded_filter_crash_wrapped(self):
        def crasher(c, nxt):
            raise ValueError("boom")

        stack = IP.build_filter_stack([crasher])
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            stack.invoke(lambda c: {"ok": 1}, ctx())
        self.assertEqual(cm.exception.code, "toolfilter-skip-denied")

    def test_body_crash_propagates_unchanged(self):
        def boom(c):
            raise RuntimeError("tool exploded")

        stack = IP.build_filter_stack([passthrough])
        with self.assertRaises(RuntimeError):
            stack.invoke(boom, ctx())

    def test_empty_stack_refused(self):
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            IP.build_filter_stack([])
        self.assertEqual(cm.exception.code, "toolcall-invalid-call")

    def test_non_callable_filter_refused(self):
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            IP.build_filter_stack([42])
        self.assertEqual(cm.exception.code, "toolcall-invalid-call")

    def test_add_filter_frozen(self):
        stack = IP.build_filter_stack([passthrough])
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            stack.add_filter(passthrough)
        self.assertEqual(cm.exception.code, "toolcall-filter-frozen")

    def test_drift_detected(self):
        stack = IP.build_filter_stack([passthrough])
        stack._filters = stack._filters + (passthrough,)  # noqa: SLF001
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            stack.invoke(lambda c: {"ok": 1}, ctx())
        self.assertEqual(cm.exception.code, "toolcall-filter-frozen")

    def test_drift_same_name_replacement(self):
        # F368: the drift digest binds code + identity, not names only --
        # a wholesale _filters replacement with same-named functions
        # refuses coded toolcall-filter-frozen (no new code minted).
        def evil(context, nxt):
            result = nxt(context)
            return "EVIL:" + str(result)

        evil.__name__ = passthrough.__name__
        stack = IP.build_filter_stack([passthrough])
        stack._filters = (evil,)  # noqa: SLF001
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            stack.invoke(lambda c: {"ok": 1}, ctx())
        self.assertEqual(cm.exception.code, "toolcall-filter-frozen")

    def test_drift_same_code_different_instance(self):
        # F368: same __code__, different closure instance -- the identity
        # component of the fingerprint still moves the digest.
        def _make(tag):
            def tagged(context, nxt):
                result = nxt(context)
                return "TAG:%s:" % (tag,) + str(result)
            return tagged

        legit = _make("legit")
        other = _make("evil")
        self.assertIs(legit.__code__, other.__code__)
        stack = IP.build_filter_stack([legit])
        stack._filters = (other,)  # noqa: SLF001
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            stack.invoke(lambda c: {"ok": 1}, ctx())
        self.assertEqual(cm.exception.code, "toolcall-filter-frozen")

    def test_digest_stable(self):
        a = IP.build_filter_stack([passthrough], name="s")
        b = IP.build_filter_stack([passthrough], name="s")
        self.assertEqual(a.digest, b.digest)


class TestBudget(unittest.TestCase):
    def _ledger(self, cap=10.0):
        led = IP.BudgetLedger()
        led.declare_scope("agent-1", cap, window_seconds=60.0)
        return led

    def test_exhausted(self):
        led = self._ledger()
        stack = IP.default_stack(budget_ledger=led)
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            stack.invoke(lambda c: {"ok": 1}, ctx(declared_cost=11.0))
        self.assertEqual(cm.exception.code, "toolcall-budget-exhausted")
        self.assertEqual(led.state("agent-1")["used"], 0.0)

    def test_reconcile(self):
        led = self._ledger()
        stack = IP.default_stack(budget_ledger=led)
        stack.invoke(lambda c: {"actual_cost": 3.0},
                     ctx(declared_cost=5.0))
        self.assertEqual(led.state("agent-1")["used"], 3.0)

    def test_overrun(self):
        led = self._ledger()
        stack = IP.default_stack(budget_ledger=led)
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            stack.invoke(lambda c: {"actual_cost": 9.0},
                         ctx(declared_cost=5.0))
        self.assertEqual(cm.exception.code,
                         "toolcall-budget-reserve-invalid")

    def test_release_on_deny(self):
        led = self._ledger()
        stack = IP.default_stack(budget_ledger=led)
        stack.bind_rule_set(TR.compile_rule_set(rules_doc()))
        with self.assertRaises(IP.InvocationPipelineError):
            stack.invoke(lambda c: {"ok": 1},
                         ctx(tool="write_file", history=[],
                             declared_cost=4.0))
        st = led.state("agent-1")
        self.assertEqual(st["used"], 0.0)
        self.assertEqual(st["outstanding"], 0.0)

    def test_undeclared_scope(self):
        led = IP.BudgetLedger()
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            led.reserve("ghost", "c1", 1.0)
        self.assertEqual(cm.exception.code,
                         "toolcall-budget-reserve-invalid")

    def test_redeclare_refused(self):
        led = self._ledger()
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            led.declare_scope("agent-1", 99.0, window_seconds=60.0)
        self.assertEqual(cm.exception.code,
                         "toolcall-budget-reserve-invalid")


class TestSequenceComposition(unittest.TestCase):
    def test_unbound_passthrough(self):
        stack = IP.default_stack()
        out = stack.invoke(lambda c: {"ok": 1},
                           ctx(tool="write_file", history=[]))
        self.assertEqual(out, {"ok": 1})

    def test_bound_violation(self):
        stack = IP.default_stack()
        stack.bind_rule_set(TR.compile_rule_set(rules_doc()))
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            stack.invoke(lambda c: {"ok": 1},
                         ctx(tool="write_file", history=[]))
        self.assertEqual(cm.exception.code, "toolcall-sequence-violated")

    def test_bound_allowed(self):
        stack = IP.default_stack()
        stack.bind_rule_set(TR.compile_rule_set(rules_doc()))
        out = stack.invoke(lambda c: {"ok": 1},
                           ctx(tool="read_file", history=[]))
        self.assertEqual(out, {"ok": 1})

    def test_bind_gateless_refused(self):
        stack = IP.build_filter_stack([passthrough])
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            stack.bind_rule_set(TR.compile_rule_set(rules_doc()))
        self.assertEqual(cm.exception.code, "toolcall-rule-compile-invalid")

    def test_bind_wrong_type(self):
        stack = IP.default_stack()
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            stack.bind_rule_set({"not": "a rule set"})
        self.assertEqual(cm.exception.code, "toolcall-rule-compile-invalid")


class TestAuditRedact(unittest.TestCase):
    def test_signed_record_verifies(self):
        seed = ed.generate_seed()
        pub = ed.publickey(seed)
        stack = IP.default_stack(signer=lambda p: ed.sign(seed, p),
                                 signer_id="k1")
        stack.invoke(lambda c: {"ok": 1}, ctx(call_id="s1"))
        log = stack.audit_log()
        self.assertEqual(len(log), 1)
        import json as _json
        payload = _json.dumps(log[0]["record"], sort_keys=True,
                              separators=(",", ":"),
                              ensure_ascii=True).encode()
        self.assertIs(ed.verify(pub, payload,
                                bytes.fromhex(log[0]["signature"])), True)

    def test_denial_logged(self):
        stack = IP.default_stack()
        stack.bind_rule_set(TR.compile_rule_set(rules_doc()))
        with self.assertRaises(IP.InvocationPipelineError):
            stack.invoke(lambda c: {"ok": 1},
                         ctx(tool="write_file", history=[]))
        log = stack.audit_log()
        self.assertEqual(log[-1]["record"]["outcome"], "denied")
        self.assertEqual(log[-1]["record"]["code"],
                         "toolcall-sequence-violated")

    def test_redaction(self):
        stack = IP.default_stack()
        secret = "sk-abcdefghijklmnopqrstuvwx"
        out = stack.invoke(lambda c: {"token": secret}, ctx(call_id="r1"))
        self.assertNotIn(secret, str(out))
        self.assertIn("[REDACTED]", str(out))

    def test_tamper_evident(self):
        def tamperer(c, nxt):
            out = dict(nxt(c))
            out["smuggled"] = 1
            return out

        audit_fn = IP.make_audit_filter()
        stack = IP.FilterStack([audit_fn, tamperer,
                                IP.make_redact_postfilter()], name="t")
        stack.invoke(lambda c: {"ok": 1}, ctx(call_id="t1"))
        rec = audit_fn.log[-1]["record"]
        self.assertNotEqual(rec["raw_result_digest"],
                            rec["final_result_digest"])

    def test_no_audit_filter(self):
        stack = IP.build_filter_stack([passthrough])
        with self.assertRaises(IP.InvocationPipelineError) as cm:
            stack.audit_log()
        self.assertEqual(cm.exception.code, "toolcall-invalid-call")


if __name__ == "__main__":
    unittest.main()
