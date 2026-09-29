"""Unit tests for gov/decision_diagnostics.py + perm_loader hardening
(wave-206 lane C).

Public seams only: decide_with_diagnostics / build_decision_record /
verify_decision_record / no_decision_record / build_diagnostic_event /
verify_diagnostic_event, PermModel.decide_traced, the constant-fold
load refusal in gov/perm_loader.py, and the additive diagnostics key
in gov/decision_log_v2.py. Deterministic. Stdlib unittest.
"""

import copy
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_diagnostics as dd  # noqa: E402
from gov import decision_log_v2 as dlv  # noqa: E402
from gov import perm_loader as pl  # noqa: E402

_MODEL_YML = """\
perm_model: sasanam-perm/v1
model_version: 1
description: "Two-screen unit fixture."
request_schema:
  agent_id: str
  tool_name: str
policy_schema:
  tool_pat: str
  eft: eft
matchers:
  toolMatch: glob
screens:
  -
    name: deny
    description: "Deny screen."
    effect: "!some(where (p_eft == deny))"
    matcher:
      call:
        - toolMatch
        -
          req: tool_name
        -
          pol: tool_pat
  -
    name: allow
    description: "Allow screen."
    effect: "some(where (p_eft == allow))"
    matcher:
      call:
        - toolMatch
        -
          req: tool_name
        -
          pol: tool_pat
composition:
  default_verdict: deny
  order:
    -
      screen: deny
      verdict: deny
      invert: true
    -
      screen: allow
      verdict: allow
      invert: false
"""

_POLICY_YML = """\
perm_policy: sasanam-perm/v1
description: "Two-row unit fixture."
policies:
  deny:
    -
      tool_pat: "db_*"
      eft: deny
  allow:
    -
      tool_pat: "read_*"
      eft: allow
"""

_NO_MATCH_POLICY_YML = """\
perm_policy: sasanam-perm/v1
description: "No row matches read_file."
policies:
  deny:
    -
      tool_pat: "db_*"
      eft: deny
  allow:
    -
      tool_pat: "write_*"
      eft: allow
"""

def _model(policy=_POLICY_YML):
    return pl.compile_perm_model(_MODEL_YML.encode(), policy.encode())


def _request(tool="read_file"):
    return {"agent_id": "agent-a", "tool_name": tool}


class TestDecideWithDiagnostics(unittest.TestCase):
    def test_record_shape(self):
        rec = dd.decide_with_diagnostics(_model(), _request())
        # Exactly the five spec'd top-level keys -- no more, no fewer.
        self.assertEqual(set(rec),
                         {"decision", "decision_id",
                          "determining_policies", "errors", "residuals"})
        self.assertEqual(rec["decision"], "allow")
        self.assertEqual(rec["errors"], [])
        bindings = rec["residuals"]["bindings"]
        self.assertEqual(bindings["record_version"], 1)
        self.assertEqual(len(bindings["request_digest"]), 64)
        self.assertEqual(set(bindings["perm"]),
                         {"model_digest", "policy_digest",
                          "composition_digest", "function_set_digest"})

    def test_determining_policies_name_rows(self):
        rec = dd.decide_with_diagnostics(_model(), _request())
        det = rec["determining_policies"]
        self.assertEqual(len(det), 1)
        row = det[0]
        self.assertEqual(row["screen"], "allow")
        self.assertEqual(row["policy_index"], 0)
        self.assertEqual(row["policy_id"], "allow[0]")
        self.assertEqual(row["effect"], "allow")
        self.assertFalse(rec["residuals"]["default_used"])

    def test_deny_decision_determines_deny_row(self):
        model = _model()
        rec = dd.decide_with_diagnostics(model, _request(tool="db_x"))
        self.assertEqual(rec["decision"], "deny")
        det = rec["determining_policies"]
        self.assertEqual(len(det), 1)
        self.assertEqual(det[0]["screen"], "deny")
        self.assertEqual(det[0]["policy_index"], 0)
        self.assertEqual(det[0]["policy_id"], "deny[0]")
        self.assertEqual(det[0]["effect"], "deny")

    def test_malformed_request_fails_closed(self):
        bad = _request()
        del bad["tool_name"]
        with self.assertRaises(pl.PermError):
            dd.decide_with_diagnostics(_model(), bad)

    def test_unknown_decision_refused(self):
        model = _model()
        request = _request()
        perm = model.bom_perm_section()
        req_digest = dd._request_digest_for(request)
        det = [{"screen": "allow", "policy_index": 0,
                "policy_id": "allow[0]", "effect": "allow"}]
        with self.assertRaises(dd.RecordBuildError):
            dd.build_decision_record(decision="explode",
                                     determining_policies=det,
                                     request_digest=req_digest,
                                     perm=perm)

    def test_verify_round_trip(self):
        model = _model()
        request = _request()
        rec = dd.decide_with_diagnostics(model, request)
        dd.verify_decision_record(rec)  # self-contained
        dd.verify_decision_record(rec, request=request,
                                  perm_model=model)  # rebound

    def test_forged_determiner_breaks_id(self):
        model = _model()
        rec = dd.decide_with_diagnostics(model, _request())
        forged = copy.deepcopy(rec)
        forged["determining_policies"][0]["policy_id"] = "allow[7]"
        with self.assertRaises(dd.RecordVerifyError):
            dd.verify_decision_record(forged)

    def test_forged_decision_breaks_id(self):
        rec = dd.decide_with_diagnostics(_model(), _request())
        forged = copy.deepcopy(rec)
        forged["decision"] = "deny"
        with self.assertRaises(dd.RecordVerifyError):
            dd.verify_decision_record(forged)

    def test_cross_request_swap_refused(self):
        model = _model()
        rec = dd.decide_with_diagnostics(model, _request())
        other = {"agent_id": "agent-a", "tool_name": "read_other"}
        with self.assertRaises(dd.RecordVerifyError):
            dd.verify_decision_record(rec, request=other)

    def test_cross_pack_swap_refused(self):
        model = _model()
        rec = dd.decide_with_diagnostics(model, _request())
        model2 = _model(policy=_NO_MATCH_POLICY_YML)
        with self.assertRaises(dd.RecordVerifyError):
            dd.verify_decision_record(rec, perm_model=model2)

    def test_no_decision_path_explicit(self):
        model = _model(policy=_NO_MATCH_POLICY_YML)
        request = _request()
        rec = dd.decide_with_diagnostics(model, request,
                                         default_as_no_decision=True)
        self.assertEqual(rec["decision"], "no-decision")
        self.assertEqual(rec["determining_policies"], [])
        self.assertTrue(rec["residuals"]["unknown_entities"])
        self.assertIn("decision_holds_iff", rec["residuals"])
        self.assertFalse(rec["residuals"]["default_used"])
        dd.verify_decision_record(rec, request=request,
                                  perm_model=model)

    def test_default_path_labeled(self):
        model = _model(policy=_NO_MATCH_POLICY_YML)
        rec = dd.decide_with_diagnostics(model, _request())
        self.assertEqual(rec["decision"], "deny")
        self.assertTrue(rec["residuals"]["default_used"])
        self.assertEqual(rec["determining_policies"], [])

    def test_no_decision_record_ctor(self):
        model = _model(policy=_NO_MATCH_POLICY_YML)
        request = _request()
        rec = dd.no_decision_record(model=model, request=request,
                                    reason="partial: velocity pending")
        self.assertEqual(rec["decision"], "no-decision")
        self.assertEqual(rec["residuals"]["decision_holds_iff"],
                         "partial: velocity pending")
        self.assertEqual(
            {u["name"] for u in rec["residuals"]["unknown_entities"]},
            set(request))
        dd.verify_decision_record(rec, request=request,
                                  perm_model=model)

    def test_decision_ids_stable_and_distinct(self):
        model = _model()
        request = _request()
        r1 = dd.decide_with_diagnostics(model, request)
        r2 = dd.decide_with_diagnostics(model, request)
        self.assertEqual(r1["decision_id"], r2["decision_id"])
        other = dd.decide_with_diagnostics(
            model, {"agent_id": "agent-a", "tool_name": "read_x"})
        self.assertNotEqual(r1["decision_id"], other["decision_id"])


class TestConstantFoldRefusal(unittest.TestCase):
    # A whole-screen matcher that constant-folds is the
    # silently-never-matching pack shape (dead rows, honest-looking
    # pack). The probes use a dedicated single-screen model so the
    # constant applies to the entire matcher, not one branch of an or.
    _MINI_MODEL_TMPL = """\
perm_model: sasanam-perm/v1
model_version: 1
description: "Single-screen constant-fold fixture."
request_schema:
  agent_id: str
policy_schema:
  agent_pat: str
  eft: eft
matchers:
  toolMatch: glob
screens:
  -
    name: deny
    description: "Screen under test."
    effect: "!some(where (p_eft == deny))"
    matcher:
%s
composition:
  default_verdict: deny
  order:
    -
      screen: deny
      verdict: deny
      invert: true
"""
    _MINI_POLICY_YML = """\
perm_policy: sasanam-perm/v1
description: "Single deny row."
policies:
  deny:
    -
      agent_pat: "*"
      eft: deny
"""

    def _mini(self, matcher_block):
        return (self._MINI_MODEL_TMPL % matcher_block).encode()

    def test_constant_false_matcher_refused(self):
        bad = self._mini("      eq:\n        - \"never\"\n"
                         "        - \"matches\"")
        with self.assertRaises(pl.PermError) as ctx:
            pl.compile_perm_model(bad, self._MINI_POLICY_YML.encode())
        self.assertIn("never-true", str(ctx.exception))

    def test_constant_false_nested_refused(self):
        bad = self._mini("      and:\n        -\n"
                         "          eq:\n"
                         "            - \"a\"\n"
                         "            - \"b\"")
        with self.assertRaises(pl.PermError):
            pl.compile_perm_model(bad, self._MINI_POLICY_YML.encode())

    def test_constant_true_matcher_allowed(self):
        # Constant-TRUE is the pack author's explicit, digest-visible
        # "match all" -- allowed (documented asymmetry).
        doc = self._mini("      eq:\n        - 1\n        - 1")
        model = pl.compile_perm_model(
            doc, self._MINI_POLICY_YML.encode())
        verdict, screen, _ = model.decide({"agent_id": "agent-a"})
        self.assertEqual((verdict, screen), ("deny", "deny"))

    def test_decide_traced_carries_rows(self):
        model = _model()
        verdict, screen, trace = model.decide_traced(_request())
        self.assertEqual((verdict, screen), ("allow", "allow"))
        fired = [t for t in trace if t["decided"]]
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0]["matched"],
                         [{"index": 0, "effect": "allow"}])
        self.assertTrue(fired[0]["effect_value"])

    def test_decide_traced_marks_default(self):
        model = _model(policy=_NO_MATCH_POLICY_YML)
        verdict, screen, trace = model.decide_traced(_request())
        self.assertEqual((verdict, screen), ("deny", "default"))
        self.assertTrue(all(not t["decided"] for t in trace))
        self.assertEqual(len(trace), 2)


class TestV2DiagnosticsWiring(unittest.TestCase):
    def _parts(self):
        model = _model()
        request = _request()
        rec = dd.decide_with_diagnostics(model, request)
        raw_body = {"agent_id": "agent-a", "tool_name": "read_file"}
        inputs = {"rules": [{"id": "r1", "effect": "allow",
                             "match": {"tool": "read_file"}}],
                  "request": {"tool": "read_file"}}
        verdict = {"effect": "allow", "matched_rule": "r1",
                   "reason": "rule r1 matched"}
        return model, request, rec, raw_body, inputs, verdict

    def test_round_trip(self):
        model, request, rec, raw_body, inputs, verdict = self._parts()
        event = dd.build_diagnostic_event(
            record=rec, raw_body=raw_body, replay_fn="deny_first_rules",
            replay_inputs=inputs, replay_verdict=verdict)
        self.assertEqual(event["diagnostics"], rec)
        dd.verify_diagnostic_event(event, request=request,
                                   perm_model=model)

    def test_tampered_diagnostics_break_v2_id(self):
        model, request, rec, raw_body, inputs, verdict = self._parts()
        event = dd.build_diagnostic_event(
            record=rec, raw_body=raw_body, replay_fn="deny_first_rules",
            replay_inputs=inputs, replay_verdict=verdict)
        tampered = copy.deepcopy(event)
        tampered["diagnostics"]["determining_policies"][0][
            "effect"] = "deny"
        with self.assertRaises(dlv.EventVerifyError):
            dlv.verify_event(tampered)

    def test_legacy_event_bytes_unchanged(self):
        _, _, _, raw_body, inputs, verdict = self._parts()
        decision = {"kind": "tool_call", "effect": "allow",
                    "policy_id": "p1", "reason": "rule r1 matched"}
        event = dlv.build_event(decision=decision, raw_body=raw_body,
                                replay_fn="deny_first_rules",
                                replay_inputs=inputs,
                                replay_verdict=verdict)
        self.assertNotIn("diagnostics", event)
        dlv.verify_event(event)  # still verifies without the block

    def test_malformed_diagnostics_refused_at_build(self):
        _, _, rec, raw_body, inputs, verdict = self._parts()
        bad = copy.deepcopy(rec)
        del bad["decision_id"]
        decision = {"kind": "tool_call", "effect": "allow",
                    "policy_id": "p1", "reason": "rule r1 matched"}
        with self.assertRaises(dlv.EventBuildError):
            dlv.build_event(decision=decision, raw_body=raw_body,
                            replay_fn="deny_first_rules",
                            replay_inputs=inputs, replay_verdict=verdict,
                            diagnostics=bad)

    def test_malformed_diagnostics_refused_at_verify(self):
        model, request, rec, raw_body, inputs, verdict = self._parts()
        event = dd.build_diagnostic_event(
            record=rec, raw_body=raw_body, replay_fn="deny_first_rules",
            replay_inputs=inputs, replay_verdict=verdict)
        event["diagnostics"]["decision"] = "explode"
        # Rebind the id so only the shape check is under test. This
        # reaches into a private seam deliberately: build_event
        # refuses malformed diagnostics by design, so there is no
        # public seam for "malformed block, valid id".
        event["decision_id"] = dlv._decision_id_for(
            {k: v for k, v in event.items() if k != "decision_id"})
        with self.assertRaises(dlv.EventVerifyError):
            dlv.verify_event(event)


if __name__ == "__main__":
    unittest.main()
