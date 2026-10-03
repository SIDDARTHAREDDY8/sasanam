"""Unit tests for immediate escalation on coded refusals in saga compensation.

Wave-308 lane E (residual 1 from wave-307 lane B): ``_compensate_step``
retried deterministic coded refusals ``_max_comp`` times as if transient.
A coded refusal is a verdict -- retrying cannot change it -- so
compensation now escalates immediately on the first coded refusal while
still retrying genuinely transient (uncoded) failures.

Coded-vs-transient boundary (documented, pinned below):
  coded     = the exception carries a non-empty-string ``code`` attribute
              (the code-first convention shared by SagaError,
              ComposedError, and the IdempotencyError subclasses). A code
              IS the decision; retrying a decision is incoherent.
  transient = any other Exception (timeouts, transport, resource
              exhaustion, non-code-first bugs): a later attempt may
              succeed, so the attempt budget still applies.
  crash     = BaseException: still propagates untouched; the step stays
              'compensating' for a later resume().

Red-first: test_coded_refusal_escalates_immediately FAILS on the
pre-fix tree (3 attempts) and passes after the fix (1 attempt).
"""

import unittest

from gov import workflow_saga as saga


def _scaffold(tag, comp_fn, maxc=3):
    """s1 succeeds, s2's action fails -> s1 is compensated with comp_fn."""
    saga.clear_ops()
    saga.register_op("e-a-%s" % tag, lambda p: ({"ok": 1}, []))
    saga.register_op("e-c-%s" % tag, comp_fn)
    saga.register_op("e-f-%s" % tag, lambda p: 1 / 0)
    mgr = saga.SagaManager(max_compensation_attempts=maxc)
    d = mgr.define([
        saga.SagaStepDef("s1", "e-a-%s" % tag, {}, "e-c-%s" % tag, {}),
        saga.SagaStepDef("s2", "e-f-%s" % tag, {}, "e-c-%s" % tag, {}),
    ])
    inst = mgr.start(d, saga_id="e-%s" % tag)
    try:
        mgr.run(inst)
    except saga.SagaError:
        pass
    return mgr, inst


def _attempt_events(inst):
    return [e for e in inst.history
            if e.get("type") == "compensation_attempt_failed"]


class CodedRefusalTests(unittest.TestCase):
    def test_coded_refusal_escalates_immediately(self):
        """A coded refusal is a verdict: exactly ONE attempt, then the
        saga escalates under its designed escalation code."""
        def _coded(p):
            raise saga.SagaError(
                "idempotency replay references step 'x': foreign pair "
                "refused",
                code="workflow-composed-replay-foreign")

        mgr, inst = _scaffold("coded", _coded)
        self.assertEqual(inst.status, "escalated")
        self.assertEqual(inst.escalation_code,
                         "workflow-saga-compensation-failed")
        attempts = _attempt_events(inst)
        self.assertEqual(len(attempts), 1,
                         "coded refusal must not be retried; saw %d "
                         "attempt(s)" % len(attempts))
        # The audit trail keeps the full refusal for the operator.
        self.assertIn("foreign pair refused", attempts[0]["detail"])
        st = [s for s in inst.steps if s["step_id"] == "s1"][0]
        self.assertEqual(st["state"], "compensation_failed")
        self.assertEqual(st["comp_attempts"], 1)

    def test_escalation_error_surfaces_saga_code(self):
        """The raised escalation error carries the saga's designed code
        (Decision 7), not the refusal's code."""
        def _coded(p):
            raise saga.SagaError("verdict", code="some-decision-code")

        saga.clear_ops()
        saga.register_op("e-a-x", lambda p: ({"ok": 1}, []))
        saga.register_op("e-c-x", _coded)
        saga.register_op("e-f-x", lambda p: 1 / 0)
        mgr = saga.SagaManager()
        d = mgr.define([
            saga.SagaStepDef("s1", "e-a-x", {}, "e-c-x", {}),
            saga.SagaStepDef("s2", "e-f-x", {}, "e-c-x", {}),
        ])
        inst = mgr.start(d, saga_id="e-x")
        with self.assertRaises(saga.SagaError) as ctx:
            mgr.run(inst)
        self.assertEqual(ctx.exception.code,
                         "workflow-saga-compensation-failed")

    def test_composed_error_code_counts_as_coded(self):
        """ComposedError is code-first too: its refusals escalate
        immediately, not after _max_comp retries."""
        from gov import workflow_composed as wc

        def _coded(p):
            raise wc.ComposedError("foreign pair refused",
                                   code="workflow-composed-replay-foreign")

        mgr, inst = _scaffold("composed", _coded)
        self.assertEqual(inst.status, "escalated")
        self.assertEqual(len(_attempt_events(inst)), 1)

    def test_idempotency_subclass_code_counts_as_coded(self):
        """IdempotencyError subclasses carry a class-level code: also
        deterministic, also not retried."""
        from gov import workflow_idempotency as wi

        def _coded(p):
            raise wi.IdempotencyConflict("same key, different digest")

        mgr, inst = _scaffold("idem", _coded)
        self.assertEqual(inst.status, "escalated")
        self.assertEqual(len(_attempt_events(inst)), 1)

    def test_uncoded_saga_error_still_retried(self):
        """A SagaError WITHOUT a code is not a verdict: the attempt
        budget still applies (fail-safe default)."""
        def _uncoded(p):
            raise saga.SagaError("no code attached")

        mgr, inst = _scaffold("uncoded", _uncoded)
        self.assertEqual(inst.status, "escalated")
        self.assertEqual(len(_attempt_events(inst)), 3)


class TransientRetryTests(unittest.TestCase):
    def test_transient_failure_still_retried_then_escalates(self):
        """Uncoded failures keep the old behavior: _max_comp attempts,
        then escalation under the saga code."""
        def _flaky(p):
            raise RuntimeError("downstream still down")

        mgr, inst = _scaffold("transient", _flaky)
        self.assertEqual(inst.status, "escalated")
        self.assertEqual(inst.escalation_code,
                         "workflow-saga-compensation-failed")
        self.assertEqual(len(_attempt_events(inst)), 3)

    def test_transient_then_success_compensates(self):
        """A transient failure followed by success still compensates --
        the retry budget is not skipped for uncoded errors."""
        calls = []

        def _flaky_once(p):
            calls.append(1)
            if len(calls) == 1:
                raise TimeoutError("timed out once")
            return {"compensated": True}

        mgr, inst = _scaffold("once", _flaky_once)
        self.assertEqual(inst.status, "compensated")
        self.assertEqual(len(_attempt_events(inst)), 1)
        st = [s for s in inst.steps if s["step_id"] == "s1"][0]
        self.assertEqual(st["state"], "compensated")

    def test_base_exception_still_propagates(self):
        """Crash semantics unchanged: BaseException propagates, the step
        stays 'compensating' for a later resume()."""
        def _crash(p):
            raise KeyboardInterrupt("simulated crash")

        saga.clear_ops()
        saga.register_op("e-a-crash", lambda p: ({"ok": 1}, []))
        saga.register_op("e-c-crash", _crash)
        saga.register_op("e-f-crash", lambda p: 1 / 0)
        mgr = saga.SagaManager()
        d = mgr.define([
            saga.SagaStepDef("s1", "e-a-crash", {}, "e-c-crash", {}),
            saga.SagaStepDef("s2", "e-f-crash", {}, "e-c-crash", {}),
        ])
        inst = mgr.start(d, saga_id="e-crash")
        with self.assertRaises(KeyboardInterrupt):
            mgr.run(inst)
        st = [s for s in inst.steps if s["step_id"] == "s1"][0]
        self.assertEqual(st["state"], "compensating")
        self.assertEqual(len(_attempt_events(inst)), 0)


if __name__ == "__main__":
    unittest.main()
