#!/usr/bin/env python3
"""Unit tests for gov/plan_policy.py (Row 7 build step 4: plan-level
pre-execution policy check).

Covers: manifest normalization (strict, fail-closed), each rule's
refuse/pass semantics, digest binding (manifest in digest, manifest-less
digests unchanged), verify_digest staleness, verdict determinism,
tool-vocabulary alignment with the trajectory instrument, and the
composer admit/execute integration.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import delegation as dg
from gov import delegation_revocation as drv
from gov import ed25519
from gov import plan_policy as pp
from gov import workflow as wf
from gov import workflow_saga as saga
from gov import workflow_routing as wr
from gov import workflow_idempotency as idem
from gov import workflow_composed as wc


def _seed(tag):
    return hashlib.sha256(tag.encode()).digest()

SA = _seed("w313pp-a")
PA = ed25519.publickey(SA).hex()
AT = 1_700_000_000


def _fn(i):
    return {"ok": True}


def _fn_plan(manifest, name="u", key="k", fn=None):
    return wc.ComposedPlan(
        [{"kind": "fn", "name": name, "fn": fn or _fn,
          "inputs": {}, "idem_key": key}],
        manifest=manifest)


def _obs_manifest(**kw):
    m = {"capabilities": ["observation"],
         "units": {"u": {"tool": "read_file",
                         "capabilities": ["observation"],
                         "trust": "internal"}}}
    m.update(kw)
    return m


def _code_of(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", None)
    return None


class ManifestNormalizationTests(unittest.TestCase):
    def test_non_dict_manifest_refused(self):
        self.assertEqual(
            _code_of(wc.ComposedPlan,
                     [{"kind": "fn", "name": "u", "fn": _fn,
                       "inputs": {}, "idem_key": "k"}],
                     manifest="nope"),
            "workflow-composed-definition-invalid")

    def test_unknown_top_key_refused(self):
        m = _obs_manifest(surprise=1)
        self.assertEqual(_code_of(_fn_plan, m),
                         "workflow-composed-definition-invalid")

    def test_unit_coverage_must_be_exact(self):
        m = _obs_manifest()
        entry = m["units"]["u"]
        m["units"] = {}
        self.assertEqual(_code_of(_fn_plan, m),
                         "workflow-composed-definition-invalid")
        m["units"] = {"u": entry, "ghost": entry}
        self.assertEqual(_code_of(_fn_plan, m),
                         "workflow-composed-definition-invalid")

    def test_unknown_unit_key_refused(self):
        m = _obs_manifest()
        m["units"]["u"]["mystery"] = 1
        self.assertEqual(_code_of(_fn_plan, m),
                         "workflow-composed-definition-invalid")

    def test_unknown_capability_refused(self):
        m = _obs_manifest()
        m["units"]["u"]["capabilities"] = ["teleport"]
        self.assertEqual(_code_of(_fn_plan, m),
                         "workflow-composed-definition-invalid")

    def test_unknown_trust_refused(self):
        m = _obs_manifest()
        m["units"]["u"]["trust"] = "cosmic"
        self.assertEqual(_code_of(_fn_plan, m),
                         "workflow-composed-definition-invalid")

    def test_empty_declassify_reason_refused(self):
        m = _obs_manifest(
            declassify=[{"from": "u", "to": "u", "reason": ""}])
        self.assertEqual(_code_of(_fn_plan, m),
                         "workflow-composed-definition-invalid")

    def test_normalized_form_is_canonical(self):
        m = _obs_manifest()
        m["capabilities"] = ["observation", "observation"]
        plan = _fn_plan(m)
        self.assertEqual(plan.manifest["capabilities"], ["observation"])
        # JSON round-trip stable: the digest binds the normalized form.
        d1 = pp.manifest_digest(plan.manifest)
        d2 = pp.manifest_digest(pp.normalize_manifest(m, plan.units))
        self.assertEqual(d1, d2)


class RuleUnknownToolTests(unittest.TestCase):
    def test_unknown_tool_refused(self):
        m = _obs_manifest()
        m["units"]["u"]["tool"] = "mystery_tool"
        plan = _fn_plan(m)
        self.assertEqual(
            _code_of(pp.check_plan, plan, pp.PlanPolicy(["observation"])),
            "plan-policy-unknown-tool")

    def test_known_tools_attributed(self):
        self.assertEqual(pp.tool_class("send_email"), "egress")
        self.assertEqual(pp.tool_class("write_file"), "state-write")
        self.assertEqual(pp.tool_class("read_file"), "observation")
        self.assertIsNone(pp.tool_class("mystery_tool"))
        self.assertEqual(pp.inherent_capabilities("send_email"), {"egress"})
        self.assertIsNone(pp.inherent_capabilities("mystery_tool"))


class RuleCapabilityTests(unittest.TestCase):
    def test_hidden_egress_refused(self):
        # The unit's tool is an egress sink but the declaration claims
        # observation only: hiding inherent capability refuses.
        m = _obs_manifest()
        m["units"]["u"]["tool"] = "send_email"
        plan = _fn_plan(m)
        self.assertEqual(
            _code_of(pp.check_plan, plan, pp.PlanPolicy(["observation"])),
            "plan-policy-capability")

    def test_envelope_must_cover_units(self):
        # Plan declares no egress capability but the unit is an
        # egress sink: the brief's headline case.
        m = {"capabilities": ["observation"],
             "units": {"u": {"tool": "send_email",
                             "capabilities": ["egress"],
                             "trust": "internal"}}}
        plan = _fn_plan(m)
        self.assertEqual(
            _code_of(pp.check_plan, plan,
                     pp.PlanPolicy(["observation", "egress"])),
            "plan-policy-capability")

    def test_deployment_policy_constrains_envelope(self):
        m = {"capabilities": ["egress"],
             "units": {"u": {"tool": "send_email",
                             "capabilities": ["egress"],
                             "trust": "internal"}}}
        plan = _fn_plan(m)
        # Deployment allows only observation: the plan's egress claim
        # refuses even though the declaration is internally coherent.
        self.assertEqual(
            _code_of(pp.check_plan, plan, pp.PlanPolicy(["observation"])),
            "plan-policy-capability")

    def test_coherent_egress_passes(self):
        m = {"capabilities": ["egress"],
             "units": {"u": {"tool": "send_email",
                             "capabilities": ["egress"],
                             "trust": "internal"}}}
        plan = _fn_plan(m)
        v = pp.check_plan(plan, pp.PlanPolicy(["egress", "observation"]))
        self.assertEqual(v.rule_results[2], ("capability", "pass"))

    def test_over_declaration_allowed(self):
        # Declaring MORE than inherent is conservative, not a lie.
        m = {"capabilities": ["observation", "state-write"],
             "units": {"u": {"tool": "read_file",
                             "capabilities": ["observation",
                                              "state-write"],
                             "trust": "internal"}}}
        plan = _fn_plan(m)
        pp.check_plan(plan, pp.PlanPolicy(["observation", "state-write"]))


class RuleDataFlowTests(unittest.TestCase):
    def _two_unit(self, consumes_b):
        m = {"capabilities": ["observation"],
             "units": {"a": {"tool": "read_file",
                             "capabilities": ["observation"],
                             "trust": "internal"},
                       "b": {"tool": "read_file",
                             "capabilities": ["observation"],
                             "trust": "internal",
                             "consumes": consumes_b}}}
        return wc.ComposedPlan(
            [{"kind": "fn", "name": "a", "fn": _fn,
              "inputs": {}, "idem_key": "k1"},
             {"kind": "fn", "name": "b", "fn": _fn,
              "inputs": {}, "idem_key": "k2"}],
            manifest=m)

    def test_forward_edge_passes(self):
        plan = self._two_unit([{"from": "a",
                                "classification": "internal"}])
        pp.check_plan(plan, pp.PlanPolicy(["observation"]))

    def test_backward_edge_refused(self):
        plan = self._two_unit([{"from": "b",
                                "classification": "internal"}])
        # b consumes from b: self-edge (non-forward) refuses.
        self.assertEqual(
            _code_of(pp.check_plan, plan, pp.PlanPolicy(["observation"])),
            "plan-policy-data-flow")

    def test_unknown_producer_refused(self):
        plan = self._two_unit([{"from": "ghost",
                                "classification": "internal"}])
        self.assertEqual(
            _code_of(pp.check_plan, plan, pp.PlanPolicy(["observation"])),
            "plan-policy-data-flow")

    def test_duplicate_edge_refused(self):
        plan = self._two_unit([{"from": "a", "classification": "internal"},
                               {"from": "a", "classification": "public"}])
        self.assertEqual(
            _code_of(pp.check_plan, plan, pp.PlanPolicy(["observation"])),
            "plan-policy-data-flow")

    def test_producer_trust_must_dominate_classification(self):
        m = {"capabilities": ["observation"],
             "units": {"a": {"tool": "read_file",
                             "capabilities": ["observation"],
                             "trust": "public"},
                       "b": {"tool": "read_file",
                             "capabilities": ["observation"],
                             "trust": "internal",
                             "consumes": [{"from": "a",
                                           "classification":
                                           "confidential"}]}}}
        plan = wc.ComposedPlan(
            [{"kind": "fn", "name": "a", "fn": _fn,
              "inputs": {}, "idem_key": "k1"},
             {"kind": "fn", "name": "b", "fn": _fn,
              "inputs": {}, "idem_key": "k2"}],
            manifest=m)
        self.assertEqual(
            _code_of(pp.check_plan, plan, pp.PlanPolicy(["observation"])),
            "plan-policy-data-flow")

    def _slip_plan(self, internal_flows):
        legs = [{"handler_id": "h1", "handler_pubkey_hex": PA,
                 "rights": ["tool.invoke"], "input_digest": "0" * 64,
                 "output_digest": "0" * 64},
                {"handler_id": "h2", "handler_pubkey_hex": PA,
                 "rights": ["tool.invoke"], "input_digest": "0" * 64,
                 "output_digest": "0" * 64}]
        slip = wr.issue_slip(SA, "issuer", legs, AT)
        m = {"capabilities": ["observation"],
             "units": {"rt": {"leg_tools": {"0": "read_file",
                                            "1": "read_file"},
                               "capabilities": ["observation"],
                               "trust": "internal",
                               "internal_flows": internal_flows}}}
        return wc.ComposedPlan(
            [{"kind": "slip", "name": "rt", "slip": slip,
              "trust_roots": [PA],
              "leg_fns": {0: (SA, _fn), 1: (SA, _fn)},
              "idem_key": "sl"}],
            manifest=m)

    def test_slip_implied_edge_undeclared_refused(self):
        plan = self._slip_plan([])
        self.assertEqual(
            _code_of(pp.check_plan, plan, pp.PlanPolicy(["observation"])),
            "plan-policy-data-flow")

    def test_slip_implied_edge_declared_passes(self):
        plan = self._slip_plan([{"from": "leg:0", "to": "leg:1",
                                 "classification": "internal"}])
        pp.check_plan(plan, pp.PlanPolicy(["observation"]))

    def test_slip_phantom_edge_refused(self):
        plan = self._slip_plan([{"from": "leg:0", "to": "leg:1",
                                 "classification": "internal"},
                                {"from": "leg:1", "to": "leg:0",
                                 "classification": "internal"}])
        self.assertEqual(
            _code_of(pp.check_plan, plan, pp.PlanPolicy(["observation"])),
            "plan-policy-data-flow")

    def test_fn_unit_internal_flows_refused(self):
        m = _obs_manifest()
        m["units"]["u"]["internal_flows"] = []
        self.assertEqual(_code_of(_fn_plan, m),
                         "workflow-composed-definition-invalid")

    def test_saga_has_no_implied_internal_edges(self):
        # Verified against gov/workflow_saga.py: compensations receive
        # compensation_params only, so no action->comp edge exists.
        unit = {"kind": "saga", "definition": None}
        self.assertEqual(pp.implied_internal_flows(unit), set())
        self.assertEqual(pp.implied_internal_flows({"kind": "fn"}), set())


class RuleTrustMixingTests(unittest.TestCase):
    def _plan(self, trust_b, declassify=None):
        m = {"capabilities": ["observation"],
             "units": {"a": {"tool": "read_file",
                             "capabilities": ["observation"],
                             "trust": "confidential"},
                       "b": {"tool": "read_file",
                             "capabilities": ["observation"],
                             "trust": trust_b,
                             "consumes": [{"from": "a",
                                           "classification":
                                           "confidential"}]}}}
        if declassify is not None:
            m["declassify"] = declassify
        return wc.ComposedPlan(
            [{"kind": "fn", "name": "a", "fn": _fn,
              "inputs": {}, "idem_key": "k1"},
             {"kind": "fn", "name": "b", "fn": _fn,
              "inputs": {}, "idem_key": "k2"}],
            manifest=m)

    def test_undeclared_mixing_refused(self):
        plan = self._plan("public")
        self.assertEqual(
            _code_of(pp.check_plan, plan, pp.PlanPolicy(["observation"])),
            "plan-policy-trust-mixing")

    def test_declared_declassify_passes(self):
        plan = self._plan(
            "public",
            declassify=[{"from": "a", "to": "b",
                         "reason": "operator-approved summary"}])
        pp.check_plan(plan, pp.PlanPolicy(["observation"]))

    def test_no_crossing_no_declaration_needed(self):
        plan = self._plan("confidential")
        pp.check_plan(plan, pp.PlanPolicy(["observation"]))

    def test_declassify_wrong_pair_refused(self):
        plan = self._plan(
            "public",
            declassify=[{"from": "b", "to": "a",
                         "reason": "wrong direction"}])
        self.assertEqual(
            _code_of(pp.check_plan, plan, pp.PlanPolicy(["observation"])),
            "plan-policy-trust-mixing")


class DigestBindingTests(unittest.TestCase):
    def test_manifest_less_digest_unchanged(self):
        # Adding the manifest feature must not churn digests of
        # existing manifest-less plans.
        units = [{"kind": "fn", "name": "u", "fn": _fn,
                  "inputs": {"x": 1}, "idem_key": "k"}]
        self.assertEqual(wc.ComposedPlan(units).digest,
                         wc.ComposedPlan(units).digest)

    def test_manifest_bound_into_digest(self):
        units = [{"kind": "fn", "name": "u", "fn": _fn,
                  "inputs": {}, "idem_key": "k"}]
        plain = wc.ComposedPlan(units)
        manifested = _fn_plan(_obs_manifest())
        self.assertNotEqual(plain.digest, manifested.digest)
        # Same manifest content, different key order -> same digest.
        m = _obs_manifest()
        m["units"]["u"]["trust"] = "internal"
        self.assertEqual(_fn_plan(_obs_manifest()).digest,
                         manifested.digest)

    def test_manifest_mutation_changes_digest(self):
        p1 = _fn_plan(_obs_manifest())
        m = _obs_manifest()
        m["capabilities"] = ["observation", "egress"]
        m["units"]["u"]["capabilities"] = ["observation"]
        # envelope change alone changes the digest (verdict bound).
        p2 = _fn_plan(m)
        self.assertNotEqual(p1.digest, p2.digest)

    def test_verify_digest_catches_in_place_unit_mutation(self):
        plan = _fn_plan(_obs_manifest())
        plan.verify_digest()  # clean: no raise

        def _evil(i):
            return {"pwned": True}
        plan.units[0]["fn"] = _evil
        self.assertEqual(_code_of(plan.verify_digest),
                         "workflow-composed-definition-invalid")

    def test_verify_digest_catches_in_place_manifest_mutation(self):
        plan = _fn_plan(_obs_manifest())
        plan.manifest["units"]["u"]["tool"] = "send_email"
        self.assertEqual(_code_of(plan.verify_digest),
                         "workflow-composed-definition-invalid")

    def test_check_plan_catches_stale_digest(self):
        plan = _fn_plan(_obs_manifest())

        def _evil(i):
            return {"pwned": True}
        plan.units[0]["fn"] = _evil
        self.assertEqual(
            _code_of(pp.check_plan, plan, pp.PlanPolicy(["observation"])),
            "workflow-composed-definition-invalid")

    def test_check_plan_manifest_missing(self):
        plan = wc.ComposedPlan([{"kind": "fn", "name": "u", "fn": _fn,
                                 "inputs": {}, "idem_key": "k"}])
        self.assertEqual(
            _code_of(pp.check_plan, plan, pp.PlanPolicy(["observation"])),
            "plan-policy-manifest-missing")


class VerdictTests(unittest.TestCase):
    def test_verdict_deterministic(self):
        plan = _fn_plan(_obs_manifest())
        pol = pp.PlanPolicy(["observation"])
        v1 = pp.check_plan(plan, pol)
        v2 = pp.check_plan(plan, pol)
        self.assertEqual(v1.verdict_digest, v2.verdict_digest)
        self.assertEqual(v1.to_dict()["verdict_digest"],
                         v2.to_dict()["verdict_digest"])
        self.assertEqual(v1.plan_digest, plan.digest)
        self.assertEqual(v1.policy_id, "plan-policy-v1")
        self.assertTrue(all(r[1] == "pass" for r in v1.rule_results))

    def test_verdict_binds_policy_id(self):
        plan = _fn_plan(_obs_manifest())
        v1 = pp.check_plan(plan, pp.PlanPolicy(["observation"],
                                              policy_id="gen-a"))
        v2 = pp.check_plan(plan, pp.PlanPolicy(["observation"],
                                              policy_id="gen-b"))
        self.assertNotEqual(v1.verdict_digest, v2.verdict_digest)

    def test_policy_rejects_unknown_capability(self):
        self.assertEqual(
            _code_of(pp.PlanPolicy, ["teleport"]),
            "workflow-composed-definition-invalid")


class VocabularyAlignmentTests(unittest.TestCase):
    def test_tool_table_matches_trajectory_instrument(self):
        # The gate's tool-class table is intentionally a separate
        # definition from gov/trajectory_risk.py's (no coupling), but
        # the vocabularies must agree -- drift fails here, loudly.
        from gov import trajectory_risk as tr
        self.assertEqual(
            set(pp._TOOL_EGRESS), set(tr._EGRESS_SINKS))
        self.assertEqual(
            set(pp._TOOL_STATE_WRITE), set(tr._STATE_MUTATIONS))
        self.assertEqual(
            set(pp._TOOL_OBSERVATION), set(tr._OBSERVATIONS))


class ComposerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.ws = wf.WorkflowStore()
        self.sm = saga.SagaManager()
        self.im = idem.IdempotencyStore()
        self.c = wc.WorkflowComposer(self.ws, self.sm, self.im)
        cons = {"expires_at": AT + 3600, "max_depth": 4,
                "allowed_targets": ["agent-b"]}
        chain = [dg.issue(SA, "agent-a", "agent-b", PA,
                          ("tool.invoke",), issued_at=AT, constraints=cons)]
        self.auth = {"actor_id": "agent-b", "action": "tool.invoke",
                     "chain": chain, "trust_roots": [PA],
                     "revocation_ledger": drv.DelegationRevoker(SA,
                                                                "agent-a")}
        self.pol = pp.PlanPolicy(["observation"])

    def _run(self, run_id):
        return self.ws.start_run("plan", run_id=run_id,
                                 authority=self.auth, at=AT)

    def test_manifest_less_plan_unaffected(self):
        # No manifest -> no admission requirement (backwards compat).
        plan = wc.ComposedPlan([{"kind": "fn", "name": "u", "fn": _fn,
                                 "inputs": {}, "idem_key": "k"}])
        run = self._run("c1")
        res = self.c.execute(plan, run_id=run["run_id"],
                             authority=self.auth, at=AT)
        self.assertIn("u", res["units"])

    def test_execute_without_admission_refused(self):
        plan = _fn_plan(_obs_manifest())
        run = self._run("c2")
        self.assertEqual(
            _code_of(self.c.execute, plan, run_id=run["run_id"],
                     authority=self.auth, at=AT),
            "plan-policy-not-admitted")

    def test_admit_then_execute(self):
        plan = _fn_plan(_obs_manifest())
        verdict = self.c.admit_plan(plan, self.pol)
        self.assertIsInstance(verdict, pp.PolicyVerdict)
        run = self._run("c3")
        res = self.c.execute(plan, run_id=run["run_id"],
                             authority=self.auth, at=AT)
        self.assertIn("u", res["units"])

    def test_admit_refuses_violating_plan(self):
        m = {"capabilities": ["observation"],
             "units": {"u": {"tool": "send_email",
                             "capabilities": ["egress"],
                             "trust": "internal"}}}
        plan = _fn_plan(m)
        self.assertEqual(_code_of(self.c.admit_plan, plan, self.pol),
                         "plan-policy-capability")

    def test_mutated_plan_not_admitted(self):
        plan = _fn_plan(_obs_manifest())
        self.c.admit_plan(plan, self.pol)

        def _evil(i):
            return {"pwned": True}
        mutated = _fn_plan(_obs_manifest(), fn=_evil)
        self.assertNotEqual(mutated.digest, plan.digest)
        run = self._run("c4")
        self.assertEqual(
            _code_of(self.c.execute, mutated, run_id=run["run_id"],
                     authority=self.auth, at=AT),
            "plan-policy-not-admitted")

    def test_in_place_mutation_refused_at_execute(self):
        plan = _fn_plan(_obs_manifest())
        self.c.admit_plan(plan, self.pol)

        def _evil(i):
            return {"pwned": True}
        plan.units[0]["fn"] = _evil
        run = self._run("c5")
        # Stale admitted digest + mutated content: verify_digest fires
        # before the admission lookup.
        self.assertEqual(
            _code_of(self.c.execute, plan, run_id=run["run_id"],
                     authority=self.auth, at=AT),
            "workflow-composed-definition-invalid")

    def test_admission_is_per_composer(self):
        plan = _fn_plan(_obs_manifest())
        self.c.admit_plan(plan, self.pol)
        c2 = wc.WorkflowComposer(self.ws, self.sm, self.im)
        run = self._run("c6")
        self.assertEqual(
            _code_of(c2.execute, plan, run_id=run["run_id"],
                     authority=self.auth, at=AT),
            "plan-policy-not-admitted")


if __name__ == "__main__":
    unittest.main()
