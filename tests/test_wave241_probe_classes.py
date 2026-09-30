"""Unit tests for wave-241 lane D: obligation binding (ND-038),
parameter canonicalization (ND-048), expected-participants audit.

Stdlib unittest only. Deterministic.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import obligation_binding as ob
from gov import parameter_canonicalization as pc
from gov import expected_participants as ep


class ObligationBindingTest(unittest.TestCase):
    def test_unfulfilled_refuses_naming_missing(self):
        permit = ob.declare_obligations("p1", ["notify", "receipt"])
        with self.assertRaises(ob.ObligationError) as ctx:
            ob.verify_obligations(permit, ob.evidence_fulfilled({"receipt"}))
        self.assertEqual(ctx.exception.code, "obligation-unfulfilled")
        self.assertIn("notify", ctx.exception.detail)

    def test_fulfilled_verifies_and_settles(self):
        permit = ob.declare_obligations("p1", ["notify"])
        receipt = ob.settle_permit(permit, ob.evidence_fulfilled({"notify"}))
        self.assertTrue(receipt["settled"])
        self.assertEqual(receipt["obligations_fulfilled"], ["notify"])

    def test_no_obligations_trivially_verifies(self):
        permit = ob.declare_obligations("p1", [])
        receipt = ob.settle_permit(permit, ob.evidence_fulfilled(set()))
        self.assertTrue(receipt["settled"])

    def test_duplicate_obligation_refuses_malformed(self):
        with self.assertRaises(ob.ObligationError) as ctx:
            ob.declare_obligations("p1", ["a", "a"])
        self.assertEqual(ctx.exception.code, "obligation-malformed")

    def test_empty_permit_id_refuses_malformed(self):
        with self.assertRaises(ob.ObligationError) as ctx:
            ob.declare_obligations("", ["a"])
        self.assertEqual(ctx.exception.code, "obligation-malformed")

    def test_evidence_is_a_frozenset(self):
        ev = ob.evidence_fulfilled(["a"])
        self.assertIsInstance(ev, frozenset)

    def test_verify_requires_proper_records(self):
        permit = ob.declare_obligations("p1", ["a"])
        with self.assertRaises(ob.ObligationError) as ctx:
            ob.verify_obligations(permit, {"a"})
        self.assertEqual(ctx.exception.code, "obligation-malformed")


class ParameterCanonicalizationTest(unittest.TestCase):
    def test_spliced_literal_collapses(self):
        self.assertEqual(pc.canonicalize('"ec"ho hi'), "echo hi")

    def test_sh_c_wrapper_unwrapped(self):
        self.assertEqual(pc.canonicalize('sh -c "echo hi"'), "echo hi")

    def test_nested_wrappers_unwrapped(self):
        self.assertEqual(
            pc.canonicalize("bash -c 'sh -c \"echo hi\"'"), "echo hi")

    def test_base64_payload_embedded(self):
        # "cat /etc/passwd" is Y2F0IC9ldGMvcGFzc3dk
        canon = pc.canonicalize(
            "echo Y2F0IC9ldGMvcGFzc3dk | base64 -d")
        self.assertIn("cat /etc/passwd", canon)

    def test_denied_after_canonicalization_refuses_obfuscation(self):
        with self.assertRaises(pc.ParameterError) as ctx:
            pc.check_parameters(
                'sh -c "ec"ho /etc/passwd',
                allowed_prefixes=("echo",),
                denied_substrings=("/etc/passwd",))
        self.assertEqual(ctx.exception.code, "parameter-obfuscation")

    def test_plain_allowed_command_passes(self):
        verdict = pc.check_parameters(
            "echo hello", ("echo",), ("/etc/passwd",))
        self.assertTrue(verdict["allowed"])
        self.assertEqual(verdict["canonical"], "echo hello")

    def test_not_allowed_returns_false(self):
        verdict = pc.check_parameters(
            "ls /tmp", ("echo",), ())
        self.assertFalse(verdict["allowed"])

    def test_empty_command_refuses_malformed(self):
        with self.assertRaises(pc.ParameterError) as ctx:
            pc.canonicalize("   ")
        self.assertEqual(ctx.exception.code, "parameter-malformed")

    def test_string_allowlist_refuses_malformed(self):
        with self.assertRaises(pc.ParameterError) as ctx:
            pc.check_parameters("echo hi", "echo", ())
        self.assertEqual(ctx.exception.code, "parameter-malformed")


class ExpectedParticipantsTest(unittest.TestCase):
    def _policy(self):
        return ep.ExpectedParticipantsPolicy(
            {"billing-run": ("orchestrator", "tool-runner", "auditor")})

    def test_missing_expected_participant_refuses(self):
        chain = [{"participant_id": "orchestrator",
                  "signature_present": True},
                 {"participant_id": "auditor",
                  "signature_present": True}]
        with self.assertRaises(ep.ExpectedParticipantsError) as ctx:
            ep.verify_delegation_chain(chain, self._policy(), "billing-run")
        self.assertEqual(ctx.exception.code,
                         "expected-participant-missing")
        self.assertIn("tool-runner", ctx.exception.detail)

    def test_unexpected_signed_participant_refuses(self):
        chain = [{"participant_id": "orchestrator",
                  "signature_present": True},
                 {"participant_id": "tool-runner",
                  "signature_present": True},
                 {"participant_id": "auditor",
                  "signature_present": True},
                 {"participant_id": "sidecar",
                  "signature_present": True}]
        with self.assertRaises(ep.ExpectedParticipantsError) as ctx:
            ep.verify_delegation_chain(chain, self._policy(), "billing-run")
        self.assertEqual(ctx.exception.code,
                         "unexpected-participant-signed")
        self.assertIn("sidecar", ctx.exception.detail)

    def test_full_chain_verifies(self):
        chain = [{"participant_id": "orchestrator",
                  "signature_present": True},
                 {"participant_id": "tool-runner",
                  "signature_present": True},
                 {"participant_id": "auditor",
                  "signature_present": True}]
        verdict = ep.verify_delegation_chain(chain, self._policy(),
                                             "billing-run")
        self.assertTrue(verdict["ok"])
        self.assertEqual(verdict["verified_participants"],
                         ("orchestrator", "tool-runner", "auditor"))

    def test_undeclared_workload_refuses(self):
        with self.assertRaises(ep.ExpectedParticipantsError) as ctx:
            ep.verify_delegation_chain([], self._policy(), "unknown")
        self.assertEqual(ctx.exception.code,
                         "expected-participants-undeclared")

    def test_truthy_non_true_does_not_count(self):
        chain = [{"participant_id": "orchestrator",
                  "signature_present": True},
                 {"participant_id": "tool-runner",
                  "signature_present": 1},  # truthy, not True
                 {"participant_id": "auditor",
                  "signature_present": True}]
        with self.assertRaises(ep.ExpectedParticipantsError) as ctx:
            ep.verify_delegation_chain(chain, self._policy(), "billing-run")
        self.assertEqual(ctx.exception.code,
                         "expected-participant-missing")

    def test_duplicate_participant_in_policy_refuses(self):
        with self.assertRaises(ep.ExpectedParticipantsError) as ctx:
            ep.ExpectedParticipantsPolicy({"w": ("a", "a")})
        self.assertEqual(ctx.exception.code,
                         "expected-participants-malformed")

    def test_empty_expected_set_refuses(self):
        with self.assertRaises(ep.ExpectedParticipantsError) as ctx:
            ep.ExpectedParticipantsPolicy({"w": ()})
        self.assertEqual(ctx.exception.code,
                         "expected-participants-malformed")

    def test_hop_without_participant_id_refuses(self):
        with self.assertRaises(ep.ExpectedParticipantsError) as ctx:
            ep.verify_delegation_chain([{"signature_present": True}],
                                       self._policy(), "billing-run")
        self.assertEqual(ctx.exception.code,
                         "expected-participants-malformed")


if __name__ == "__main__":
    unittest.main()
