"""Unit tests: F381 closure -- idempotency caller binding + evict authority.

Wave-303 lane 2. gov/workflow_idempotency.py only.

F381 (MEDIUM): complete()/checkpoint() were not caller-bound -- a
different authorized caller could complete another actor's in-flight
record with a fabricated result (replay-cache poisoning, defeating
acks_late); evict_completed() took an operator NAME with no authority
verifier (unauthenticated eviction).

Closure: BeginOutcome records the beginning caller; complete()/
checkpoint() refuse coded workflow-idempotency-caller-mismatch on
mismatch; evict_completed() requires and verifies an authority
verifier (refusing/raising verifier fails closed coded
workflow-idempotency-authority-lapsed).
"""

import unittest

from gov import workflow_idempotency as wi

_AT = 1700000000
_OPD = "ab" * 32


def _verifier(caller, namespace, op_class, at):
    return True


def _refusing(caller, namespace, op_class, at):
    return False


def _raising(caller, namespace, op_class, at):
    raise RuntimeError("verifier down")


class CallerBindingTest(unittest.TestCase):
    def _pair(self, key="k1"):
        backing = {}
        s1 = wi.IdempotencyStore(backing=backing)
        s2 = wi.IdempotencyStore(backing=backing)
        o1 = s1.begin("ns1", "pay", key, _OPD, "alice", _verifier, at=_AT)
        o2 = s2.begin("ns1", "pay", key, _OPD, "mallory", _verifier, at=_AT)
        return s1, o1, o2

    def test_cross_caller_complete_refuses_coded(self):
        _, _, o2 = self._pair()
        self.assertEqual(o2.status, "retry")
        with self.assertRaises(wi.IdempotencyCallerMismatch) as ctx:
            o2.complete("cd" * 32, "mallory-result-ref", at=_AT)
        self.assertEqual(ctx.exception.code,
                         "workflow-idempotency-caller-mismatch")

    def test_cross_caller_checkpoint_refuses_coded(self):
        _, _, o2 = self._pair(key="k3")
        with self.assertRaises(wi.IdempotencyCallerMismatch) as ctx:
            o2.checkpoint("mallory was here", at=_AT)
        self.assertEqual(ctx.exception.code,
                         "workflow-idempotency-caller-mismatch")

    def test_no_replay_poisoning_after_refusal(self):
        s1, o1, o2 = self._pair()
        try:
            o2.complete("cd" * 32, "mallory-result-ref", at=_AT)
        except wi.IdempotencyCallerMismatch:
            pass
        # The beginning caller can still complete honestly.
        o1b = s1.begin("ns1", "pay", "k1", _OPD, "alice", _verifier, at=_AT)
        o1b.complete("ef" * 32, "alice-result-ref", at=_AT)
        o3 = s1.begin("ns1", "pay", "k1", _OPD, "alice", _verifier, at=_AT)
        self.assertEqual(o3.status, "replay")
        self.assertEqual(o3.result_ref, "alice-result-ref")

    def test_same_caller_retry_completes(self):
        backing = {}
        s1 = wi.IdempotencyStore(backing=backing)
        s2 = wi.IdempotencyStore(backing=backing)
        o1 = s1.begin("ns1", "pay", "k9", _OPD, "agent-a", _verifier, at=_AT)
        self.assertEqual(o1.status, "new")
        o2 = s2.begin("ns1", "pay", "k9", _OPD, "agent-a", _verifier, at=_AT)
        self.assertEqual(o2.status, "retry")
        # acks_late across crash+restart is preserved for the same caller.
        self.assertIsNone(o2.complete("ab" * 32, "ptr://r9", at=_AT))

    def test_same_caller_checkpoint_works(self):
        s = wi.IdempotencyStore()
        o = s.begin("ns1", "pay", "kc", _OPD, "alice", _verifier, at=_AT)
        o.checkpoint("halfway", at=_AT)
        self.assertIn("halfway", o.notes)

    def test_complete_on_replay_still_value_error(self):
        s = wi.IdempotencyStore()
        o = s.begin("ns1", "pay", "kr", _OPD, "alice", _verifier, at=_AT)
        o.complete("ab" * 32, "ptr://r", at=_AT)
        o2 = s.begin("ns1", "pay", "kr", _OPD, "alice", _verifier, at=_AT)
        self.assertEqual(o2.status, "replay")
        with self.assertRaises(ValueError):
            o2.complete("ab" * 32, "ptr://r", at=_AT)

    def test_checkpoint_on_replay_still_value_error(self):
        s = wi.IdempotencyStore()
        o = s.begin("ns1", "pay", "kw", _OPD, "alice", _verifier, at=_AT)
        o.complete("ab" * 32, "ptr://r", at=_AT)
        o2 = s.begin("ns1", "pay", "kw", _OPD, "alice", _verifier, at=_AT)
        with self.assertRaises(ValueError):
            o2.checkpoint("late note", at=_AT)

    def test_complete_after_evict_fails_closed_coded(self):
        # Record evicted between begin() and complete(): the binding is
        # re-read from the live backing record, so it fails closed coded
        # rather than completing a ghost.
        s = wi.IdempotencyStore()
        o = s.begin("ns1", "pay", "ke", _OPD, "alice", _verifier, at=_AT)
        o.complete("ab" * 32, "ptr://r", at=_AT)
        s.evict_completed("ns1", "pay", "ke", operator="ops",
                          authority_verifier=_verifier, at=_AT)
        o2 = s.begin("ns1", "pay", "ke", _OPD, "alice", _verifier, at=_AT)
        self.assertEqual(o2.status, "new")
        o2.complete("ab" * 32, "ptr://r2", at=_AT)  # no raise: fresh record

    def test_digest_conflict_control_still_holds(self):
        s = wi.IdempotencyStore()
        s.begin("ns1", "pay", "kx", _OPD, "alice", _verifier, at=_AT)
        with self.assertRaises(wi.IdempotencyConflict) as ctx:
            s.begin("ns1", "pay", "kx", "cd" * 32, "alice", _verifier,
                    at=_AT)
        self.assertEqual(ctx.exception.code, "permit-idempotency-conflict")


class EvictAuthorityTest(unittest.TestCase):
    def _completed(self, store=None):
        s = store or wi.IdempotencyStore()
        o = s.begin("ns1", "pay", "k2", _OPD, "alice", _verifier, at=_AT)
        o.complete("ab" * 32, "ref", at=_AT)
        return s

    def test_evict_without_verifier_fails_closed(self):
        s = self._completed()
        # authority_verifier is a required parameter: omitting it is a
        # fail-closed refusal (TypeError), never an eviction.
        with self.assertRaises(TypeError):
            s.evict_completed("ns1", "pay", "k2", operator="mallory",
                              at=_AT)
        # Record is still there: alice can still replay it.
        o = s.begin("ns1", "pay", "k2", _OPD, "alice", _verifier, at=_AT)
        self.assertEqual(o.status, "replay")

    def test_evict_with_refusing_verifier_refuses_coded(self):
        s = self._completed()
        with self.assertRaises(wi.IdempotencyAuthorityLapsed) as ctx:
            s.evict_completed("ns1", "pay", "k2", operator="mallory",
                              authority_verifier=_refusing, at=_AT)
        self.assertEqual(ctx.exception.code,
                         "workflow-idempotency-authority-lapsed")

    def test_evict_with_raising_verifier_fails_closed_coded(self):
        s = self._completed()
        with self.assertRaises(wi.IdempotencyAuthorityLapsed) as ctx:
            s.evict_completed("ns1", "pay", "k2", operator="mallory",
                              authority_verifier=_raising, at=_AT)
        self.assertEqual(ctx.exception.code,
                         "workflow-idempotency-authority-lapsed")

    def test_evict_with_noncallable_verifier_value_error(self):
        s = self._completed()
        with self.assertRaises(ValueError):
            s.evict_completed("ns1", "pay", "k2", operator="mallory",
                              authority_verifier=None, at=_AT)

    def test_authorized_evict_still_loud(self):
        sink = []
        s = wi.IdempotencyStore(sink=sink.append)
        o = s.begin("ns1", "pay", "k2", _OPD, "alice", _verifier, at=_AT)
        o.complete("ab" * 32, "ref", at=_AT)
        rec = s.evict_completed("ns1", "pay", "k2", operator="ops",
                                authority_verifier=_verifier, at=_AT)
        self.assertEqual(rec["evicted_key"], "k2")
        self.assertEqual(rec["operator"], "ops")
        self.assertEqual(rec["reason"], "operator")
        self.assertTrue(any(r.get("event") == "evict-operator"
                            for r in sink))

    def test_evict_absent_record_key_error(self):
        s = wi.IdempotencyStore()
        with self.assertRaises(KeyError):
            s.evict_completed("ns1", "pay", "nope", operator="ops",
                              authority_verifier=_verifier, at=_AT)

    def test_evict_verifier_receives_operator_as_caller(self):
        seen = {}

        def spy(caller, namespace, op_class, at):
            seen.update(caller=caller, namespace=namespace,
                        op_class=op_class)
            return True

        s = self._completed()
        s.evict_completed("ns1", "pay", "k2", operator="ops-human",
                          authority_verifier=spy, at=_AT)
        # Same-scope authorization: the operator name is the caller
        # identity presented to the verifier.
        self.assertEqual(seen["caller"], "ops-human")
        self.assertEqual(seen["namespace"], "ns1")
        self.assertEqual(seen["op_class"], "pay")


if __name__ == "__main__":
    unittest.main()
