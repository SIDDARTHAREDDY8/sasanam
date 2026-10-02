"""Unit tests for the deterministic approval remediation taxonomy
(wave-279 lane 6): ``gov/remediation.py`` in isolation (taxonomy
dispatch, bounded re-ask-repair loop, harness driver, declared
filter primitive) plus the ``ElicitationError.remediation`` carrier.
The behavioral battery lives in
``evals/w279_remediation_probes.py``; these tests pin the primitives
so regressions surface at the smallest scope.
"""

import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# tests/__init__ provisions an explicit test key on import.
from gov import remediation as rem
from gov import elicitation_contract as ec


class TaxonomyConstantsTest(unittest.TestCase):
    def test_eight_actions(self):
        self.assertEqual(
            set(rem.ACTIONS),
            {"reask", "fix", "filter", "refrain", "noop",
             "exception", "fix-reask", "custom"})

    def test_nine_failure_classes(self):
        self.assertEqual(len(rem.FAILURE_CLASSES), 9)
        self.assertEqual(len(set(rem.FAILURE_CLASSES)), 9)

    def test_default_policy_covers_every_class(self):
        for fc in rem.FAILURE_CLASSES:
            self.assertIn(fc, rem.DEFAULT_POLICY)
            self.assertIn(rem.DEFAULT_POLICY[fc], rem.ACTIONS)

    def test_default_policy_is_fail_closed(self):
        # Only the fixable validation failures permit a re-ask; the
        # default policy never maps anything to NOOP.
        for fc, act in rem.DEFAULT_POLICY.items():
            if fc in (rem.FAILURE_RATIONALE_MISSING,
                      rem.FAILURE_SCHEMA_INVALID):
                self.assertEqual(act, rem.REASK)
            else:
                self.assertNotEqual(act, rem.NOOP, fc)


class ClassifyTest(unittest.TestCase):
    def test_schema_invalid_reasks_with_budget(self):
        out = rem.classify(rem.FAILURE_SCHEMA_INVALID,
                           budget_remaining=2)
        self.assertEqual(out["action"], "reask")
        self.assertTrue(out["retry_permitted"])
        self.assertFalse(out["proceed"])
        self.assertEqual(out["budget_remaining"], 2)

    def test_reask_escalates_to_refrain_on_empty_budget(self):
        out = rem.classify(rem.FAILURE_SCHEMA_INVALID,
                           budget_remaining=0)
        self.assertEqual(out["action"], "refrain")
        self.assertFalse(out["retry_permitted"])

    def test_secret_detected_refrains(self):
        out = rem.classify(rem.FAILURE_SECRET_DETECTED,
                           budget_remaining=3)
        self.assertEqual(out["action"], "refrain")
        self.assertFalse(out["retry_permitted"])

    def test_unknown_class_fails_closed(self):
        out = rem.classify("not-a-real-class")
        self.assertEqual(out["action"], "refrain")
        self.assertFalse(out["retry_permitted"])

    def test_unknown_action_fails_closed(self):
        out = rem.classify(rem.FAILURE_SCHEMA_INVALID,
                           action="teleport")
        self.assertEqual(out["action"], "refrain")

    def test_repair_action_without_primitives_fails_closed(self):
        for act in (rem.FIX, rem.FILTER, rem.FIX_REASK):
            out = rem.classify(rem.FAILURE_SCHEMA_INVALID, action=act)
            self.assertEqual(out["action"], "refrain", act)
            self.assertFalse(out["retry_permitted"], act)

    def test_noop_only_by_explicit_policy(self):
        out = rem.classify(rem.FAILURE_CUSTOM, action=rem.NOOP)
        self.assertEqual(out["action"], "noop")
        self.assertTrue(out["proceed"])

    def test_custom_callback_concrete_result(self):
        out = rem.classify(rem.FAILURE_CUSTOM,
                           custom=lambda value, info: rem.REFRAIN)
        self.assertEqual(out["action"], "refrain")
        self.assertIn("custom remediation chose", out["note"])

    def test_custom_callback_misbehaves_fails_closed(self):
        out = rem.classify(rem.FAILURE_CUSTOM,
                           custom=lambda value, info: "teleport")
        self.assertEqual(out["action"], "refrain")

    def test_custom_callback_raises_fails_closed(self):
        def bad(value, info):
            raise RuntimeError("boom")
        out = rem.classify(rem.FAILURE_CUSTOM, custom=bad)
        self.assertEqual(out["action"], "refrain")
        self.assertIn("RuntimeError", out["note"])

    def test_custom_without_callback_fails_closed(self):
        out = rem.classify(rem.FAILURE_CUSTOM)
        self.assertEqual(out["action"], "refrain")

    def test_classify_never_raises(self):
        # Total by contract: garbage in, refrain out.
        out = rem.classify(None, action=None, policy="nope",
                           budget_remaining="lots",
                           custom="not-callable",
                           context="not-a-dict")
        self.assertEqual(out["action"], "refrain")

    def test_outcome_shape(self):
        out = rem.classify(rem.FAILURE_PRECHECK)
        for key in ("failure_class", "action", "retry_permitted",
                    "proceed", "repaired_value", "budget_remaining",
                    "steps", "note"):
            self.assertIn(key, out)


class ReaskRepairTest(unittest.TestCase):
    def test_clean_first_attempt_noop(self):
        out = rem.reask_repair(lambda: "fine",
                               lambda v: (True, None))
        self.assertEqual(out["action"], "noop")
        self.assertTrue(out["proceed"])
        self.assertEqual(out["repaired_value"], "fine")
        self.assertEqual(len(out["steps"]), 1)

    def test_always_failing_terminates_fail_closed(self):
        calls = []
        out = rem.reask_repair(
            lambda: calls.append(1) or "bad",
            lambda v: (False, "invalid"),
            max_rounds=2)
        self.assertEqual(len(calls), 3)  # initial + 2 re-asks
        self.assertEqual(out["action"], "refrain")
        self.assertFalse(out["retry_permitted"])
        self.assertFalse(out["proceed"])
        self.assertEqual(len(out["steps"]), 3)

    def test_zero_rounds_single_attempt(self):
        calls = []
        out = rem.reask_repair(
            lambda: calls.append(1) or "bad",
            lambda v: (False, "invalid"),
            max_rounds=0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(out["action"], "refrain")

    def test_declared_fix_reverified(self):
        out = rem.reask_repair(
            lambda: {"a": 1, "junk": 2},
            lambda v: (True, None) if set(v) == {"a"}
            else (False, "undeclared"),
            fix=lambda v: {"a": v["a"]})
        self.assertEqual(out["action"], "fix")
        self.assertTrue(out["proceed"])
        self.assertEqual(out["repaired_value"], {"a": 1})
        self.assertTrue(any(s.get("fix_applied") for s in
                            out["steps"]))

    def test_fix_failing_verification_falls_back_to_reask(self):
        attempts = []
        out = rem.reask_repair(
            lambda: attempts.append(1) or "bad",
            lambda v: (True, None) if v == "good" else (False, "bad"),
            max_rounds=1,
            fix=lambda v: "still-bad")
        self.assertEqual(out["action"], "refrain")  # exhausted
        self.assertEqual(len(attempts), 2)

    def test_reask_then_clean(self):
        vals = iter(["bad", "good"])
        out = rem.reask_repair(
            lambda: next(vals),
            lambda v: (True, None) if v == "good" else (False, "bad"),
            max_rounds=3)
        self.assertEqual(out["action"], "reask")
        self.assertTrue(out["proceed"])
        self.assertEqual(out["repaired_value"], "good")

    def test_producer_raising_fails_closed(self):
        def boom():
            raise RuntimeError("producer down")
        out = rem.reask_repair(boom, lambda v: (True, None))
        self.assertEqual(out["action"], "refrain")
        self.assertFalse(out["proceed"])

    def test_validator_raising_fails_closed(self):
        def boom(v):
            raise RuntimeError("validator down")
        out = rem.reask_repair(lambda: "v", boom, max_rounds=0)
        self.assertEqual(out["action"], "refrain")

    def test_fix_raising_does_not_break_loop(self):
        def bad_fix(v):
            raise RuntimeError("fix down")
        out = rem.reask_repair(
            lambda: "bad",
            lambda v: (True, None) if v == "good" else (False, "bad"),
            max_rounds=0, fix=bad_fix)
        self.assertEqual(out["action"], "refrain")

    def test_never_raises_on_garbage_args(self):
        out = rem.reask_repair(None, None, max_rounds="lots")
        self.assertEqual(out["action"], "refrain")


class DropUndeclaredTest(unittest.TestCase):
    def test_drops_undeclared_keys(self):
        schema = {"properties": {"reason": {"type": "string"}}}
        self.assertEqual(
            rem.drop_undeclared({"reason": "x", "junk": 1}, schema),
            {"reason": "x"})

    def test_non_dict_passthrough(self):
        self.assertEqual(rem.drop_undeclared("s", {}), "s")
        self.assertEqual(rem.drop_undeclared(None, None), None)


class ElicitationErrorCarrierTest(unittest.TestCase):
    def test_remediation_defaults_none(self):
        err = ec.ElicitationError("nope")
        self.assertIsNone(err.remediation)
        self.assertIsInstance(err, ValueError)
        self.assertEqual(str(err), "nope")

    def test_remediation_carried(self):
        outcome = rem.classify(rem.FAILURE_SCHEMA_INVALID)
        err = ec.ElicitationError("nope", remediation=outcome)
        self.assertEqual(err.remediation, outcome)


class DriverTest(unittest.TestCase):
    def _queue(self, status="pending", attempts=0):
        class Q(object):
            def get(self, approval_id):
                return {"id": approval_id, "status": status,
                        "elicitation_attempts": attempts}

            def elicit_decision(self, approval_id, response,
                                rationale=None, decided_by=None,
                                rationale_schema=None):
                raise ec.ElicitationError(
                    "refused",
                    remediation=rem.classify(
                        rem.FAILURE_SCHEMA_INVALID,
                        budget_remaining=ec.MAX_ELICITATIONS
                        - attempts))
        return Q()

    def test_driver_stops_when_record_not_pending(self):
        ok, outcome = rem.elicit_with_remediation(
            self._queue(status="approved"), "aid",
            lambda r, o: ("accept", None))
        self.assertFalse(ok)
        self.assertEqual(outcome["action"], "refrain")

    def test_driver_stops_on_exhausted_shared_budget(self):
        calls = []
        q = self._queue(attempts=ec.MAX_ELICITATIONS)
        ok, outcome = rem.elicit_with_remediation(
            q, "aid",
            lambda r, o: calls.append(r) or ("decline",
                                            {"reason": "x"}),
            max_rounds=5)
        self.assertFalse(ok)
        self.assertEqual(calls, [])
        self.assertEqual(outcome["action"], "refrain")
        self.assertEqual(outcome["budget_remaining"], 0)

    def test_driver_bounded_by_max_rounds(self):
        calls = []
        q = self._queue()
        ok, outcome = rem.elicit_with_remediation(
            q, "aid",
            lambda r, o: calls.append(r) or ("decline",
                                            {"reason": 123}),
            max_rounds=2)
        self.assertFalse(ok)
        self.assertEqual(len(calls), 2)
        self.assertEqual(outcome["action"], "refrain")

    def test_driver_returns_decision_on_success(self):
        class Q(object):
            def get(self, approval_id):
                return {"id": approval_id, "status": "pending",
                        "elicitation_attempts": 0}

            def elicit_decision(self, approval_id, response,
                                rationale=None, decided_by=None,
                                rationale_schema=None):
                return ({"id": approval_id}, {"event": "ok"})
        ok, result = rem.elicit_with_remediation(
            Q(), "aid", lambda r, o: ("accept", None))
        self.assertTrue(ok)
        self.assertEqual(result[0]["id"], "aid")

    def test_driver_never_raises(self):
        class Q(object):
            def get(self, approval_id):
                raise RuntimeError("queue down")
        ok, outcome = rem.elicit_with_remediation(
            Q(), "aid", lambda r, o: ("accept", None))
        self.assertFalse(ok)
        self.assertEqual(outcome["action"], "refrain")


if __name__ == "__main__":
    unittest.main()
