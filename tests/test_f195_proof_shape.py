#!/usr/bin/env python3
"""Regression tests for F195: the decision-packet proof validator must
accept the producer's own legitimate proof shapes.

Counterexample.to_dict() emits nearest_rule=None for `unsupported`
verdicts (and for `exceeds` when no boundary entry is close); the
packet seam's shape check used to demand str and spuriously refused
those genuine proofs at build and at verify time.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import authority_proof as ap  # noqa: E402
from gov import decision_packet as dp  # noqa: E402

SEED = bytes.fromhex("11" * 32)


def _gql_boundary():
    return ap.boundary_from_dict({
        "boundary_id": "f195-boundary", "version": "1",
        "graphql_max_depth": 4, "graphql_allow_mutations": True,
        "graphql_mutation_allowlist": ["updateProfile"],
        "graphql_allow_introspection": False,
        "egress_hosts": ["api.internal"],
    })


def _genuine_unsupported_proof_dict():
    # Multi-operation GraphQL document: the checker cannot attribute
    # which operation the caller will run -> fails closed as
    # unsupported, with counterexample.nearest_rule=None.
    q = ("query GetUser { user { name } } "
         "mutation Sneaky { deleteUser(id: 1) }")
    proof = ap.check({"tool": "graphql", "args": {"query": q}},
                     {}, _gql_boundary())
    assert proof.verdict == ap.UNSUPPORTED, proof.verdict
    pd = proof.to_dict()
    assert pd["counterexample"]["nearest_rule"] is None
    return pd


def _build(**over):
    kw = dict(decision="deny", boundary_declared=True,
              evidence_head_digest="GENESIS",
              issued_at="2026-09-28T00:00:00+00:00")
    kw.update(over)
    return dp.build_decision_packet(**kw)


def _fs_boundary():
    return ap.boundary_from_dict({
        "boundary_id": "f195-boundary", "version": "1",
        "fs_read_prefixes": ["/allowed"],
        "fs_write_prefixes": ["/allowed"],
    })


def _mcp_boundary():
    return ap.boundary_from_dict({
        "boundary_id": "f195-mcp", "version": "1",
        "mcp_servers": ["files"], "mcp_tools": ["files::read"],
        "mcp_max_arg_bytes": 64,
    })


def _round_trip(proof_dict, decision):
    body = _build(decision=decision, authority_proof=proof_dict)
    return dp.verify_decision_packet(dp.sign_packet(body, SEED))


class F195ProofShape(unittest.TestCase):
    def test_unsupported_with_null_nearest_rule_round_trips(self):
        # The F195 close-when: build+sign+verify on a genuine
        # `unsupported` proof -> ok.
        body = _build(authority_proof=_genuine_unsupported_proof_dict())
        packet = dp.sign_packet(body, SEED)
        ok, reason = dp.verify_decision_packet(packet)
        self.assertTrue(ok, reason)

    def test_nearest_rule_string_still_accepted(self):
        pd = _genuine_unsupported_proof_dict()
        pd["counterexample"] = dict(pd["counterexample"],
                                    nearest_rule="/data/allowed")
        body = _build(authority_proof=pd)
        ok, reason = dp.verify_decision_packet(dp.sign_packet(body, SEED))
        self.assertTrue(ok, reason)

    def test_nearest_rule_wrong_type_still_rejected(self):
        # Fail-closed for genuinely malformed shapes: nearest_rule
        # must be str or null, never int/list/dict.
        for bad in (123, ["x"], {"rule": "x"}):
            pd = _genuine_unsupported_proof_dict()
            pd["counterexample"] = dict(pd["counterexample"],
                                        nearest_rule=bad)
            with self.assertRaises(dp.PacketError, msg="bad=%r" % (bad,)):
                _build(authority_proof=pd)

    def test_counterexample_other_fields_still_strict(self):
        # domain/access/reason remain str-required.
        for key in ("domain", "access", "reason"):
            pd = _genuine_unsupported_proof_dict()
            ce = dict(pd["counterexample"])
            ce[key] = None
            pd["counterexample"] = ce
            with self.assertRaises(dp.PacketError, msg="key=%s" % key):
                _build(authority_proof=pd)

    def test_non_dict_counterexample_still_rejected(self):
        pd = _genuine_unsupported_proof_dict()
        pd["counterexample"] = "not-a-dict"
        with self.assertRaises(dp.PacketError):
            _build(authority_proof=pd)


class F195TotalityOverVerdicts(unittest.TestCase):
    """DSSE-envelope discipline: the shape validator is total over the
    outcome enum -- every verdict the producer legitimately emits must
    have a defined accept/reject answer at the packet seam, with no
    outcome falling through a crack. All proofs below are genuine
    producer output from the public ap.check() seam."""

    def _assert_round_trip_ok(self, proof, decision):
        pd = proof.to_dict()
        ok, reason = _round_trip(pd, decision)
        self.assertTrue(ok, "verdict=%s: %s" % (proof.verdict, reason))

    def test_within_boundary_no_counterexample(self):
        proof = ap.check(
            {"tool": "write_file", "args": {"path": "/allowed/ok.txt"}},
            {"path_resolved": "/allowed/ok.txt"}, _fs_boundary())
        self.assertEqual(proof.verdict, ap.WITHIN)
        self.assertIsNone(proof.counterexample)
        self._assert_round_trip_ok(proof, "allow")

    def test_exceeds_boundary_with_str_nearest_rule(self):
        proof = ap.check(
            {"tool": "write_file", "args": {"path": "/etc/cron.d/evil"}},
            {"path_resolved": "/etc/cron.d/evil"}, _fs_boundary())
        self.assertEqual(proof.verdict, ap.EXCEEDS)
        self.assertIsInstance(proof.counterexample.nearest_rule, str)
        self._assert_round_trip_ok(proof, "deny")

    def test_exceeds_boundary_with_null_nearest_rule(self):
        # MCP arg-budget exceedance emits nearest_rule=None (no rule
        # is "close" to a byte budget) -- same producer shape as
        # unsupported, must be accepted.
        big = {"blob": "x" * 1000}
        proof = ap.check(
            {"tool": "mcp_call",
             "args": {"server": "files", "name": "read",
                      "arguments": big}},
            {}, _mcp_boundary())
        self.assertEqual(proof.verdict, ap.EXCEEDS)
        self.assertIsNone(proof.counterexample.nearest_rule)
        self._assert_round_trip_ok(proof, "deny")

    def test_unsupported_with_null_nearest_rule(self):
        proof = ap.check(
            {"tool": "graphql", "args": {"query":
             "query GetUser { user { name } } "
             "mutation Sneaky { deleteUser(id: 1) }"}},
            {}, _gql_boundary())
        self.assertEqual(proof.verdict, ap.UNSUPPORTED)
        self.assertIsNone(proof.counterexample.nearest_rule)
        self._assert_round_trip_ok(proof, "deny")

    def test_inconclusive_no_counterexample(self):
        proof = ap.check({"tool": "write_file",
                          "args": {"path": "/allowed/ok.txt"}}, {}, None)
        self.assertEqual(proof.verdict, ap.INCONCLUSIVE)
        self.assertIsNone(proof.counterexample)
        self._assert_round_trip_ok(proof, "deny")


if __name__ == "__main__":
    unittest.main()
