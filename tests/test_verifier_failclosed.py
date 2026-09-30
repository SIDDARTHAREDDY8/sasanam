"""Unit tests for gov.verifier_failclosed (W243-7 + W243-8).

The battery proves the attack-shape behavior; these tests pin the
deterministic seams: lapse-first ordering, verdict structure, and the
fail-closed boundaries.
"""

import unittest
from datetime import datetime, timezone

from gov import verifier_failclosed as vf


def _ts(iso):
    return datetime.fromisoformat(iso.replace("+00:00", "")).replace(
        tzinfo=timezone.utc)


class TestOrdering(unittest.TestCase):
    def test_lapse_check_beats_store_unavailable(self):
        """A lapse-registered draft citation is refused stale-authority
        even when the authority store does not know the id (the store
        never gets to say 'unavailable' about a lapsed draft)."""
        hop = {"participant_id": "a", "signature_present": True,
               "authority_id": "draft-emirdag-scitt-ai-agent-execution-00",
               "authority_minted_at": _ts("2026-10-14T00:00:00")}
        policy = {"verifier_policy_input": "pin:t1",
                  "authority_store": {}}
        with self.assertRaises(vf.VerifierFailclosedError) as ctx:
            vf.evaluate_delegation_chain([hop], policy)
        self.assertEqual(ctx.exception.code, "stale-authority")

    def test_lapse_check_beats_store_valid(self):
        """A store calling a lapsed draft 'valid' is the
        green-on-lapsed defect: the lapse registry wins."""
        hop = {"participant_id": "a", "signature_present": True,
               "authority_id": "draft-emirdag-scitt-ai-agent-execution-00",
               "authority_minted_at": _ts("2026-10-14T00:00:00")}
        policy = {"verifier_policy_input": "pin:t1",
                  "authority_store": {
                      "draft-emirdag-scitt-ai-agent-execution-00":
                          {"status": "valid"}}}
        with self.assertRaises(vf.VerifierFailclosedError) as ctx:
            vf.evaluate_delegation_chain([hop], policy)
        self.assertEqual(ctx.exception.code, "stale-authority")

    def test_lapse_citation_without_timestamp_is_stale(self):
        hop = {"participant_id": "a", "signature_present": True,
               "authority_id": "draft-emirdag-scitt-ai-agent-execution-00"}
        policy = {"verifier_policy_input": "pin:t1"}
        with self.assertRaises(vf.VerifierFailclosedError) as ctx:
            vf.evaluate_delegation_chain([hop], policy)
        self.assertEqual(ctx.exception.code, "authority-stale")


class TestVerdict(unittest.TestCase):
    def test_allow_verdict_names_policy_input(self):
        verdict = vf.evaluate_delegation_chain(
            [{"participant_id": "a", "signature_present": True}],
            {"verifier_policy_input": "pin:allow-1"})
        self.assertEqual(verdict["verdict"], "allow")
        self.assertEqual(verdict["verifier_policy_input"], "pin:allow-1")
        self.assertEqual(len(verdict["hops"]), 1)
        self.assertEqual(verdict["hops"][0]["authority_status"], "valid")

    def test_stale_source_verdict_shape(self):
        verdict = vf.evaluate_delegation_chain(
            [{"participant_id": "a", "signature_present": True}],
            {"verifier_policy_input": "pin:s1",
             "chain_source": {"stale": True}})
        self.assertEqual(verdict["verdict"], "stale")
        self.assertEqual(verdict["code"], "chain-source-stale")
        self.assertEqual(verdict["verifier_policy_input"], "pin:s1")

    def test_expected_audit_ok(self):
        verdict = vf.evaluate_delegation_chain(
            [{"participant_id": "a", "signature_present": True},
             {"participant_id": "b", "signature_present": True}],
            {"verifier_policy_input": "pin:e1",
             "expected_workload": "wl",
             "expected_declarations": {"wl": ("a", "b")}})
        self.assertEqual(verdict["verdict"], "allow")
        self.assertEqual(verdict["expected_participants"], ["a", "b"])


class TestMalformed(unittest.TestCase):
    def test_truthy_signature_does_not_count(self):
        """Only exactly True counts as signature_present; a truthy
        non-True value is recorded as False (not a signed hop) and the
        expected-participant audit sees it as missing."""
        verdict = vf.evaluate_delegation_chain(
            [{"participant_id": "a", "signature_present": 1}],
            {"verifier_policy_input": "pin:m1"})
        self.assertFalse(verdict["hops"][0]["signature_present"])

    def test_string_chain_refused(self):
        with self.assertRaises(vf.VerifierFailclosedError) as ctx:
            vf.evaluate_delegation_chain("not-a-chain",
                                         {"verifier_policy_input": "p"})
        self.assertEqual(ctx.exception.code, "verifier-input-malformed")

    def test_bad_store_status_refused(self):
        with self.assertRaises(vf.VerifierFailclosedError) as ctx:
            vf.evaluate_delegation_chain(
                [{"participant_id": "a", "authority_id": "x"}],
                {"verifier_policy_input": "p",
                 "authority_store": {"x": {"status": "maybe"}}})
        self.assertEqual(ctx.exception.code, "verifier-input-malformed")


if __name__ == "__main__":
    unittest.main()
