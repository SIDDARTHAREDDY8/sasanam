"""Unit tests for gov/ephemeral_grants.py (wave-280 lane 3).

Behavioral contracts only: tuple validation, check semantics,
condition evaluation, spent-lease replay, batch vectors, expand trees,
and the audit-log writer chain.
"""

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import ephemeral_grants as eg

_NOW = 1790907600.0


def _hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class TupleValidationTest(unittest.TestCase):
    def test_bad_user_shape(self):
        with self.assertRaises(ValueError):
            eg.ContextualTuple(user="alice", relation="can_invoke",
                               obj="tool:t")

    def test_bad_relation(self):
        with self.assertRaises(ValueError):
            eg.ContextualTuple(user="agent:a", relation="may_invoke",
                               obj="tool:t")

    def test_unknown_condition_key_refused(self):
        with self.assertRaises(ValueError):
            eg.ContextualTuple(user="agent:a", relation="can_invoke",
                               obj="tool:t",
                               conditions={"grant_duration": 60})

    def test_non_hex_arg_digest_refused(self):
        with self.assertRaises(ValueError):
            eg.ContextualTuple(user="agent:a", relation="can_invoke",
                               obj="tool:t",
                               conditions={"arg_digest": "zzz"})

    def test_uppercase_hex_refused(self):
        with self.assertRaises(ValueError):
            eg.ContextualTuple(user="agent:a", relation="can_invoke",
                               obj="tool:t",
                               conditions={"arg_digest": "A" * 64})

    def test_nonfinite_valid_until_refused(self):
        with self.assertRaises(ValueError):
            eg.ContextualTuple(user="agent:a", relation="can_invoke",
                               obj="tool:t",
                               conditions={"valid_until": float("inf")})

    def test_bool_budget_refused(self):
        with self.assertRaises(ValueError):
            eg.ContextualTuple(user="agent:a", relation="can_invoke",
                               obj="tool:t",
                               conditions={"max_budget": True})

    def test_negative_budget_refused(self):
        with self.assertRaises(ValueError):
            eg.ContextualTuple(user="agent:a", relation="can_invoke",
                               obj="tool:t",
                               conditions={"max_budget": -1.0})


class CheckSemanticsTest(unittest.TestCase):
    def _t(self, **kw):
        kw.setdefault("user", "agent:alice")
        kw.setdefault("relation", "can_invoke")
        kw.setdefault("obj", "tool:db_query")
        return eg.ContextualTuple(**kw)

    def test_plain_tuple_allows(self):
        d = eg.check_grant("agent:alice", "tool:db_query", [self._t()],
                           {"now": _NOW})
        self.assertTrue(d["allowed"])
        self.assertIsNone(d["code"])

    def test_wrong_principal_refused(self):
        d = eg.check_grant("agent:bob", "tool:db_query", [self._t()],
                           {"now": _NOW})
        self.assertFalse(d["allowed"])
        self.assertEqual(d["code"], "delegation-ephemeral-grant-refused")

    def test_wrong_tool_refused(self):
        d = eg.check_grant("agent:alice", "tool:rm", [self._t()],
                           {"now": _NOW})
        self.assertFalse(d["allowed"])

    def test_malformed_action_is_programming_error(self):
        with self.assertRaises(ValueError):
            eg.check_grant("agent:alice", "db_query", [self._t()], {})

    def test_readonly_refuses_consequential(self):
        t = self._t(relation="can_invoke_readonly")
        d = eg.check_grant("agent:alice", "tool:db_query", [t],
                           {"now": _NOW}, consequential=True)
        self.assertFalse(d["allowed"])

    def test_readonly_allows_read(self):
        t = self._t(relation="can_invoke_readonly")
        d = eg.check_grant("agent:alice", "tool:db_query", [t],
                           {"now": _NOW}, consequential=False)
        self.assertTrue(d["allowed"])

    def test_missing_actual_for_declared_condition_fails_closed(self):
        t = self._t(conditions={"arg_digest": _hex("x")})
        d = eg.check_grant("agent:alice", "tool:db_query", [t], {"now": _NOW})
        self.assertFalse(d["allowed"])


class SpentLeaseTest(unittest.TestCase):
    def test_double_spend_refused(self):
        reg = eg.SpentLeaseRegistry()
        self.assertTrue(reg.spend("lease-1", "inv-1"))
        with self.assertRaises(eg.EphemeralGrantError) as cm:
            reg.spend("lease-1", "inv-2")
        self.assertEqual(cm.exception.code,
                         "delegation-ephemeral-grant-refused")
        self.assertTrue(reg.is_spent("lease-1"))
        self.assertFalse(reg.is_spent("lease-2"))

    def test_lease_bound_check_spends_once(self):
        t = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                               obj="tool:db_query", lease_ref="L1")
        reg = eg.SpentLeaseRegistry()
        d1 = eg.check_grant("agent:alice", "tool:db_query", [t],
                            {"now": _NOW, "invocation_id": "i1"},
                            lease_ref="L1", spent_ledger=reg)
        self.assertTrue(d1["allowed"])
        d2 = eg.check_grant("agent:alice", "tool:db_query", [t],
                            {"now": _NOW, "invocation_id": "i2"},
                            lease_ref="L1", spent_ledger=reg)
        self.assertFalse(d2["allowed"])
        self.assertEqual(d2["code"], "delegation-ephemeral-grant-refused")

    def test_lease_requires_naming_tuple(self):
        t = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                               obj="tool:db_query", lease_ref="L-other")
        d = eg.check_grant("agent:alice", "tool:db_query", [t],
                           {"now": _NOW}, lease_ref="L1",
                           spent_ledger=eg.SpentLeaseRegistry())
        self.assertFalse(d["allowed"])


def _seam_ctx(lease="single-use"):
    from gov import delegation_tokens as dt
    h_s, h_p = dt.generate_test_keypair()
    a_s, a_p = dt.generate_test_keypair()
    trust = dt.DelegationTrust(
        human_keys={h_s.key_id: h_p}, authority_keys={a_s.key_id: a_p},
        user_issuer_keys={h_s.key_id: h_p})
    u = dt.issue_user_token(h_s, "u1", ["tool:t"], "s1")
    ag = dt.issue_agent_token(a_s, "alice", "worker", "alice", ["tool:t"],
                              "s1")
    kw = {} if lease is None else {"lease": lease}
    d = dt.issue_delegation(h_s, "u1", u, ag, ["tool:t"], "s1",
                            "https://r.example/x", **kw)
    ctx = dt.DelegationContext(user_token=u, agent_token=ag,
                               delegation_token=d, parent_chain=[],
                               trust=trust, session_id="s1")
    ctx.bind()
    return dt, ctx


class SeamHardeningTest(unittest.TestCase):
    """Wave-280 review findings: seam-raised refusals are DelegationError-
    catchable, single-use without a registry fails closed, and a wired
    decision writer records at decision time."""

    def test_seam_error_is_delegation_error(self):
        dt, ctx = _seam_ctx()
        self.assertTrue(issubclass(dt.EphemeralGrantError,
                                   dt.DelegationError))
        self.assertTrue(issubclass(dt.EphemeralGrantError,
                                   eg.EphemeralGrantError))
        with self.assertRaises(dt.DelegationError) as cm:
            dt.authorize_action(ctx, "tool:t")
        self.assertEqual(cm.exception.code,
                         "delegation-ephemeral-grant-refused")

    def test_single_use_without_registry_refused(self):
        dt, ctx = _seam_ctx()
        ref = dt.token_ref(ctx.delegation_token)
        t = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                               obj="tool:t", lease_ref=ref)
        with self.assertRaises(dt.EphemeralGrantError) as cm:
            dt.authorize_action(ctx, "tool:t",
                                contextual_tuples=[t],
                                check_conditions={"now": _NOW,
                                                  "invocation_id": "i1"})
        self.assertEqual(cm.exception.code,
                         "delegation-ephemeral-grant-refused")

    def test_decision_writer_records_allow_and_refuse(self):
        os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
        os.environ.setdefault("GOV_LOG_KEY", "00" * 32)
        os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w280-fga-seam-unit")
        from gov.log import ActionLog
        dt, ctx = _seam_ctx()
        ref = dt.token_ref(ctx.delegation_token)
        d = tempfile.mkdtemp(prefix="g280su_",
                             dir=os.environ.get("TMPDIR") or "/tmp")
        writer = eg.GrantDecisionWriter(
            ActionLog(os.path.join(d, "audit.jsonl")))
        reg = eg.SpentLeaseRegistry()
        t = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                               obj="tool:t", lease_ref=ref)
        dt.authorize_action(ctx, "tool:t", contextual_tuples=[t],
                            check_conditions={"now": _NOW,
                                              "invocation_id": "w1"},
                            spent_ledger=reg, decision_writer=writer)
        with self.assertRaises(dt.EphemeralGrantError):
            dt.authorize_action(ctx, "tool:t", contextual_tuples=[t],
                                check_conditions={"now": _NOW,
                                                  "invocation_id": "w2"},
                                spent_ledger=reg, decision_writer=writer)
        recs = eg.grant_decision_records(writer._log)
        self.assertEqual([r["allowed"] for r in recs], [True, False])
        self.assertEqual(recs[1]["code"],
                         "delegation-ephemeral-grant-refused")


class BatchExpandTest(unittest.TestCase):
    def test_batch_vector_complete(self):
        t = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                               obj="tool:a")
        vec = eg.batch_check(
            [{"principal": "agent:alice", "action": "tool:a"},
             {"principal": "agent:alice", "action": "tool:b"},
             {"principal": "agent:alice", "action": "tool:a"}],
            [t], {"now": _NOW})
        self.assertEqual([v["allowed"] for v in vec], [True, False, True])

    def test_expand_tree_digest_binds(self):
        t = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                               obj="tool:a")
        tree = eg.expand_decision(user="agent:alice", relation="can_invoke",
                                  obj="tool:a", tuples=[t])
        self.assertTrue(tree["matched"])
        import json as _json
        body = {k: v for k, v in tree.items() if k != "tree_digest"}
        canon = _json.dumps(body, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True, default=str).encode()
        self.assertEqual(hashlib.sha256(canon).hexdigest(),
                         tree["tree_digest"])


class WriterTest(unittest.TestCase):
    def test_record_chains(self):
        os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
        os.environ.setdefault("GOV_LOG_KEY", "00" * 32)
        os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w280-fga-unit")
        from gov.log import ActionLog, read_entries
        d = tempfile.mkdtemp(prefix="g280u_", dir=os.environ.get("TMPDIR") or "/tmp")
        log = ActionLog(os.path.join(d, "audit.jsonl"))
        w = eg.GrantDecisionWriter(log)
        t = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                               obj="tool:a")
        w.record(eg.check_grant("agent:alice", "tool:a", [t], {"now": _NOW}),
                 "agent:alice")
        w.record(eg.check_grant("agent:bob", "tool:a", [t], {"now": _NOW}),
                 "agent:bob")
        recs = eg.grant_decision_records(log)
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[1]["prev_grant_decision_digest"],
                         recs[0]["record_digest"])
        self.assertTrue(recs[0]["allowed"])
        self.assertFalse(recs[1]["allowed"])


if __name__ == "__main__":
    unittest.main()
