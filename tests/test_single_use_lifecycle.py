#!/usr/bin/env python3
"""Unit tests for gov/single_use_lifecycle.py.

Tests sit at the public seam (LifecycleRegistry methods); expected
values are literals from the spec, never recomputed by the module.
"""

import os
import sys
import threading
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import single_use_lifecycle as lc  # noqa: E402

A = "a" * 64
B = "b" * 64
IN_A = "c" * 64
IN_B = "d" * 64
RC_A = "e" * 64


def _reg(*approvals):
    reg = lc.LifecycleRegistry()
    for digest in approvals:
        reg.register_approval(digest)
    return reg


def _code(exc):
    return getattr(exc, "code", None)


class ReserveTest(unittest.TestCase):
    def test_reserve_returns_bound_record(self):
        reg = _reg(A)
        r = reg.reserve(A, "step-1", IN_A)
        self.assertEqual(r["kind"], "single-use-reservation")
        self.assertEqual(r["approval_digest"], A)
        self.assertEqual(r["step_id"], "step-1")
        self.assertEqual(r["input_digest"], IN_A)
        self.assertEqual(r["status"], "reserved")
        self.assertEqual(len(r["reservation_id"]), 64)

    def test_reservation_id_domain_separated_and_stable(self):
        # 64 hex, deterministic across instances; distinct from a raw
        # sha256 of the same bytes (domain separation).
        r1 = _reg(A).reserve(A, "step-1", IN_A)
        r2 = _reg(A).reserve(A, "step-1", IN_A)
        self.assertEqual(r1["reservation_id"], r2["reservation_id"])
        import hashlib
        raw = hashlib.sha256((A + "step-1" + IN_A).encode()).hexdigest()
        self.assertNotEqual(r1["reservation_id"], raw)

    def test_double_reserve_same_triple_refuses_distinct_code(self):
        reg = _reg(A)
        reg.reserve(A, "step-1", IN_A)
        with self.assertRaises(lc.LifecycleError) as ctx:
            reg.reserve(A, "step-1", IN_A)
        self.assertEqual(_code(ctx.exception),
                         "single-use-reserve-conflict")

    def test_different_triples_independent(self):
        reg = _reg(A)
        reg.reserve(A, "step-1", IN_A)
        r = reg.reserve(A, "step-2", IN_A)
        self.assertEqual(r["step_id"], "step-2")

    def test_unknown_approval_fails_closed(self):
        reg = _reg(A)
        with self.assertRaises(lc.LifecycleError) as ctx:
            reg.reserve(B, "step-1", IN_A)
        self.assertEqual(_code(ctx.exception),
                         "single-use-reservation-unknown")

    def test_malformed_inputs(self):
        reg = _reg(A)
        for args in (("nope", "s", IN_A), (A, "", IN_A), (A, "s", "ZZ"),
                     (None, "s", IN_A)):
            with self.assertRaises(lc.LifecycleError) as ctx:
                reg.reserve(*args)
            self.assertEqual(_code(ctx.exception),
                             "single-use-malformed", args)


class AdmitTest(unittest.TestCase):
    def test_admit_happy_path(self):
        reg = _reg(A)
        r = reg.reserve(A, "step-1", IN_A)
        a = reg.admit(r, "step-1", IN_A)
        self.assertEqual(a["reservation_id"], r["reservation_id"])
        self.assertEqual(a["status"], "admitted")
        self.assertEqual(len(a["admission_id"]), 64)

    def test_admit_wrong_step_refuses(self):
        reg = _reg(A)
        r = reg.reserve(A, "step-1", IN_A)
        with self.assertRaises(lc.LifecycleError) as ctx:
            reg.admit(r, "step-2", IN_A)
        self.assertEqual(_code(ctx.exception),
                         "single-use-reservation-mismatch")

    def test_admit_wrong_input_refuses(self):
        reg = _reg(A)
        r = reg.reserve(A, "step-1", IN_A)
        with self.assertRaises(lc.LifecycleError) as ctx:
            reg.admit(r, "step-1", IN_B)
        self.assertEqual(_code(ctx.exception),
                         "single-use-reservation-mismatch")

    def test_admit_forged_reservation_refuses(self):
        reg = _reg(A)
        r = reg.reserve(A, "step-1", IN_A)
        forged = dict(r)
        forged["reservation_id"] = "0" * 64
        with self.assertRaises(lc.LifecycleError) as ctx:
            reg.admit(forged, "step-1", IN_A)
        self.assertEqual(_code(ctx.exception),
                         "single-use-reservation-unknown")

    def test_admit_idempotent(self):
        reg = _reg(A)
        r = reg.reserve(A, "step-1", IN_A)
        a1 = reg.admit(r, "step-1", IN_A)
        a2 = reg.admit(r, "step-1", IN_A)
        self.assertEqual(a1["admission_id"], a2["admission_id"])


class ReconcileTest(unittest.TestCase):
    def _admitted(self, reg):
        r = reg.reserve(A, "step-1", IN_A)
        return reg.admit(r, "step-1", IN_A)

    def test_reconcile_emits_consumption_record(self):
        reg = _reg(A)
        a = self._admitted(reg)
        c = reg.reconcile(a, RC_A)
        self.assertEqual(c["kind"], "single-use-consumption")
        self.assertEqual(c["execution_receipt_digest"], RC_A)
        self.assertEqual(len(c["consumption_digest"]), 64)
        # Re-derivation is stable and excludes the digest field.
        self.assertEqual(lc.LifecycleRegistry.consumption_digest(c),
                         c["consumption_digest"])
        tampered = dict(c)
        tampered["step_id"] = "step-2"
        self.assertNotEqual(lc.LifecycleRegistry.consumption_digest(
            tampered), c["consumption_digest"])

    def test_double_reconcile_replayed(self):
        reg = _reg(A)
        a = self._admitted(reg)
        reg.reconcile(a, RC_A)
        with self.assertRaises(lc.LifecycleError) as ctx:
            reg.reconcile(a, RC_A)
        self.assertEqual(_code(ctx.exception),
                         "single-use-reconcile-replayed")

    def test_reconcile_without_admit_refuses(self):
        reg = _reg(A)
        r = reg.reserve(A, "step-1", IN_A)
        # A hand-built admission bypasses admit; the admission id will
        # not recompute -> forged admission fails closed.
        with self.assertRaises(lc.LifecycleError):
            reg.reconcile({"reservation_id": r["reservation_id"]}, RC_A)

    def test_reconcile_closes_the_execution_gate(self):
        reg = _reg(A)
        a = self._admitted(reg)
        reg.reconcile(a, RC_A)
        with self.assertRaises(lc.LifecycleError) as ctx:
            reg.require_reserved(A, "step-1", IN_A)
        self.assertEqual(_code(ctx.exception), "single-use-not-reserved")


class ExecutionGateTest(unittest.TestCase):
    def test_no_reservation_refuses(self):
        reg = _reg(A)
        with self.assertRaises(lc.LifecycleError) as ctx:
            reg.require_reserved(A, "step-1", IN_A)
        self.assertEqual(_code(ctx.exception), "single-use-not-reserved")

    def test_live_reservation_passes(self):
        reg = _reg(A)
        r = reg.reserve(A, "step-1", IN_A)
        self.assertEqual(reg.require_reserved(A, "step-1", IN_A),
                         r["reservation_id"])


class BindingTest(unittest.TestCase):
    def test_binding_verifies_and_tampering_refuses(self):
        reg = _reg(A)
        r = reg.reserve(A, "step-1", IN_A)
        a = reg.admit(r, "step-1", IN_A)
        c = reg.reconcile(a, RC_A)
        receipt = {"observation": {"consumption_digest":
                                  c["consumption_digest"]}}
        self.assertTrue(reg.verify_consumption_binding(receipt, c))
        receipt["observation"]["consumption_digest"] = "0" * 64
        with self.assertRaises(lc.LifecycleError) as ctx:
            reg.verify_consumption_binding(receipt, c)
        self.assertEqual(_code(ctx.exception),
                         "single-use-reservation-mismatch")


class ConcurrencyTest(unittest.TestCase):
    def test_concurrent_reserve_exactly_one_wins(self):
        for _ in range(3):  # repeat: the race must be deterministic
            reg = _reg(A)
            wins, codes = [], []
            barrier = threading.Barrier(8)

            def racer():
                barrier.wait()
                try:
                    wins.append(reg.reserve(A, "step-race", IN_A))
                except lc.LifecycleError as exc:  # noqa: BLE001
                    codes.append(_code(exc))

            threads = [threading.Thread(target=racer) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(len(wins), 1)
            self.assertEqual(len(codes), 7)
            self.assertTrue(all(c == "single-use-reserve-conflict"
                                for c in codes))


class DecisionCodesTest(unittest.TestCase):
    def test_new_codes_mapped(self):
        from gov import decision_codes as dc
        for code in ("single-use-reserve-conflict", "single-use-not-reserved",
                     "single-use-reservation-mismatch",
                     "single-use-reservation-unknown",
                     "single-use-reconcile-replayed",
                     "single-use-lifecycle-refused"):
            rec = dc.code_for(code)
            self.assertEqual(rec["code"], code)
            self.assertEqual(rec["domain"], "single_use")
            self.assertFalse(dc.emit(code, (A,))["authority"])


if __name__ == "__main__":
    unittest.main()


class CapsuleCompositionTest(unittest.TestCase):
    def _linked(self):
        from gov import action_capsule as ac
        reg = _reg(A)
        r = reg.reserve(A, "step-1", IN_A)
        a = reg.admit(r, "step-1", IN_A)
        c = reg.reconcile(a, RC_A)
        capsule = ac.seal_capsule({
            "attempt": {"action": "wire", "initiator": "agent-1"},
            "effect": {"status": "admitted",
                       "evidence": "executor-receipt-001"},
        })
        return reg, r, c, capsule

    def test_attach_and_verify(self):
        from gov import action_capsule as ac
        reg, r, c, capsule = self._linked()
        linked = lc.attach_consumption(capsule, c)
        self.assertEqual(lc.verify_capsule_consumption(linked, c),
                         c["consumption_digest"])
        effect = ac.verify_capsule(linked)["effect"]
        self.assertEqual(effect["consumption_digest"],
                         c["consumption_digest"])
        self.assertEqual(effect["reservation_id"], r["reservation_id"])

    def test_tampered_record_refuses(self):
        reg, r, c, capsule = self._linked()
        linked = lc.attach_consumption(capsule, c)
        tampered = dict(c)
        tampered["step_id"] = "step-2"
        with self.assertRaises(lc.LifecycleError) as ctx:
            lc.verify_capsule_consumption(linked, tampered)
        self.assertEqual(_code(ctx.exception),
                         "single-use-reservation-mismatch")

    def test_unlinked_capsule_refuses(self):
        reg, r, c, capsule = self._linked()
        with self.assertRaises(lc.LifecycleError) as ctx:
            lc.verify_capsule_consumption(capsule, c)
        self.assertEqual(_code(ctx.exception), "single-use-malformed")
