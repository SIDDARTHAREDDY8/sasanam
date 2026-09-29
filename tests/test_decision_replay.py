"""Tests for the decision-trace replay verifier (gov/decision_replay.py).

Covers: the differential pin between the replayer and the live engine
(verdict + every per-rule outcome), tamper/drift/version loud
failures, the no-raw-secrets scrub (unit + end-to-end through the
executor's capture hook), determinism, standalone importability, and
post-verdict monotonicity.
"""

import copy
import importlib.util
import json
import os
import sys
import tempfile
import secrets
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov.policy import PolicyEngine
from gov.decision_contract import Request
from gov import decision_replay as dr


_RICH_POLICY = """\
version: 3
roles:
  analyst: [read_file, send_email]
  ops: [read_file, write_file, api_call]
policies:
  - id: deny-outside-sandbox
    effect: deny
    match:
      tool: [read_file, write_file]
      path_outside_sandbox: true
    reason: no outside reads.
  - id: deny-many-sends
    effect: deny
    match:
      tool: [send_email]
      when:
        - path: counters.send_email
          gte: 3
    reason: too many sends.
  - effect: deny
    match:
      tool: [api_call]
      high_entropy_payload: true
    reason: id-less deny rule.
  - id: queue-secret-write
    effect: require_approval
    match:
      tool: [write_file]
      path_contains_any: [secret]
    reason: queue secret writes.
  - id: allow-analyst-reads
    effect: allow
    match:
      tool: [read_file]
      role: [analyst]
    reason: allow analyst reads.
  - id: allow-ops
    effect: allow
    match:
      role: [ops]
    reason: allow ops tools.
"""

_SECRET_VALUES = ("s3cr3t-p@ssw0rd-9f2c", "tok_live_4a1b7e9f2c",
                  "bearer-abc-123-xyz", "raw payload bytes here",
                  "victim@allowed.example")


def _engine():
    return PolicyEngine.from_text(_RICH_POLICY, source_label="<test>")


def _trace_for(policy, action, ctx, **kw):
    decision = policy.decide(Request.from_action(action, ctx))
    return dr.build_trace(decision=decision, action=action,
                          context=ctx, policy=policy, **kw)


def _synth():
    policy = _engine()
    action = {"tool": "send_email", "role": "analyst",
              "agent_id": "a9", "args": {"to": "x@y.z"}}
    ctx = {"counters": {"send_email": 9}, "domain_allowlisted": True}
    trace = _trace_for(policy, action, ctx)
    bundle = dr.policy_bundle_from_policy(policy)
    return trace, bundle


def _repair_digests(trace):
    trace["integrity"]["sections"] = {
        n: dr.sha256_hex(dr.canonical(trace[n]))
        for n in ("policy", "request", "verdict", "evaluation",
                  "post_verdict")}
    trace["integrity"]["trace_digest"] = dr.sha256_hex(dr.canonical(
        {"trace_version": dr.TRACE_VERSION,
         "sections": trace["integrity"]["sections"]}))


class DifferentialTest(unittest.TestCase):
    """The replayer must agree with the live engine, rule by rule."""

    def test_sweep_matches_engine(self):
        policy = _engine()
        bundle = dr.policy_bundle_from_policy(policy)
        tools = ["read_file", "write_file", "send_email", "api_call",
                 "unknown_tool"]
        roles = ["analyst", "ops", "support", None]
        agents = ["agent-1", "agent-2"]
        paths = ["notes.txt", "secret/plan.txt", None]
        contexts = [
            {},
            {"path_outside_sandbox": True},
            {"path_outside_sandbox": False},
            {"path_resolved": "other/secret/x.txt"},
            {"counters": {"send_email": 0}},
            {"counters": {"send_email": 5}},
            {"counters": {"http_post": 2, "send_email": 2}},
            {"high_entropy_payload": True},
            {"high_entropy_payload": False},
            {"domain_allowlisted": True, "counters": {"api_call": 9}},
        ]
        n = 0
        for tool in tools:
            for role in roles:
                for agent in agents:
                    for path in paths:
                        for ctx in contexts:
                            args = {}
                            if path is not None:
                                args["path"] = path
                            action = {"tool": tool, "role": role,
                                      "agent_id": agent, "args": args}
                            trace = _trace_for(policy, action, ctx)
                            result = dr.replay(trace, bundle)
                            decision = policy.decide(
                                Request.from_action(action, ctx))
                            self.assertEqual(result["verdict"],
                                             decision.effect,
                                             (tool, role, agent, path,
                                              ctx))
                            self.assertEqual(result["policy_id"],
                                             decision.policy_id,
                                             (tool, role, agent, path,
                                              ctx))
                            n += 1
        self.assertEqual(n, 5 * 4 * 2 * 3 * 10)

    def test_interleaved_effects_pass_order(self):
        # Rules declared allow-before-deny: the engine evaluates in
        # PASS order (deny first). The trace must carry true
        # declaration indices and the replayer must follow the same
        # order -- otherwise replay falsely reports divergence.
        pol = ("version: 1\n"
               "roles:\n"
               "  r: [read_file]\n"
               "policies:\n"
               "  - id: allow-first\n"
               "    effect: allow\n"
               "    match:\n"
               "      tool: [read_file]\n"
               "    reason: allow declared first.\n"
               "  - id: deny-second\n"
               "    effect: deny\n"
               "    match:\n"
               "      tool: [read_file]\n"
               "    reason: deny declared second.\n")
        policy = PolicyEngine.from_text(pol, source_label="<interleaved>")
        bundle = dr.policy_bundle_from_policy(policy)
        action = {"tool": "read_file", "role": "r", "agent_id": "a",
                  "args": {}}
        trace = _trace_for(policy, action, {})
        order = [(t["rule_id"], t["declaration_index"])
                 for t in trace["evaluation"]["trace"]]
        self.assertEqual(order, [("deny-second", 1),
                                 ("allow-first", 0)])
        result = dr.replay(trace, bundle)
        self.assertEqual(result["verdict"], "deny")
        self.assertEqual(result["policy_id"], "deny-second")

    def test_id_less_rule_display_id(self):
        policy = _engine()
        bundle = dr.policy_bundle_from_policy(policy)
        action = {"tool": "api_call", "role": "ops", "agent_id": "a",
                  "args": {}}
        ctx = {"high_entropy_payload": True}
        trace = _trace_for(policy, action, ctx)
        ids = [t["rule_id"] for t in trace["evaluation"]["trace"]]
        self.assertIn("rule-2", ids)
        result = dr.replay(trace, bundle)
        self.assertEqual(result["verdict"], "deny")

    def test_default_deny(self):
        policy = _engine()
        bundle = dr.policy_bundle_from_policy(policy)
        action = {"tool": "unknown_tool", "role": "support",
                  "agent_id": "a", "args": {}}
        trace = _trace_for(policy, action, {})
        self.assertEqual(trace["verdict"]["effect"], "deny")
        self.assertIsNone(trace["verdict"]["policy_id"])
        self.assertEqual(trace["verdict"]["flag"], "default_deny")
        self.assertEqual(trace["verdict"]["matched_rules"],
                         ["default_deny"])
        self.assertIsNone(trace["evaluation"]["deciding_rule"])
        result = dr.replay(trace, bundle)
        self.assertEqual(result["verdict"], "deny")
        self.assertIsNone(result["policy_id"])


_LADDER_REPLAY_POLICY = """\
version: 1
approvals:
  quorum:
    min_approvals: 2
    eligible_principals: [op1, op2]
policies:
  - id: obs-cand
    effect: deny
    mode: observe
    match:
      tool: http_post
    reason: candidate
  - id: warn-cand
    effect: deny
    mode: warn
    match:
      tool: delete_file
    reason: warning
  - id: plain-allow
    effect: allow
    match:
      tool: read_file
    reason: reads ok
"""


class LadderReplayTest(unittest.TestCase):
    """Wave-198: replay routes by the RECORDED decision-time mode,
    not the bundle's load-time mode (runtime graduation moves the
    ledger; the bundle only carries load-time modes)."""

    def _ladder_engine(self):
        return PolicyEngine.from_text(_LADDER_REPLAY_POLICY,
                                      source_label="<test-ladder>")

    def _action(self, tool):
        return {"tool": tool, "agent_id": "a", "args": {}}

    def test_deny_mode_routes_ahead_of_warn_in_replay(self):
        # Wave-198 (review catch): replay must mirror decide()'s
        # decider routing -- a deny-mode deny declared AFTER a
        # warn-mode forbid still decides deny, never allow.
        policy = PolicyEngine.from_text(
            "version: 1\n"
            "policies:\n"
            "  - id: warn-first\n"
            "    effect: deny\n"
            "    mode: warn\n"
            "    match:\n"
            "      tool: delete_file\n"
            "    reason: warn candidate\n"
            "  - id: deny-second\n"
            "    effect: deny\n"
            "    mode: deny\n"
            "    match:\n"
            "      tool: delete_file\n"
            "    reason: real deny\n",
            source_label="<test-ladder>")
        action = self._action("delete_file")
        decision = policy.decide(Request.from_action(action, {}))
        self.assertEqual(decision.effect, "deny")
        trace = dr.build_trace(decision=decision, action=action,
                               context={}, policy=policy)
        bundle = dr.policy_bundle_from_policy(policy)
        result = dr.replay(trace, bundle)
        self.assertEqual(result["verdict"], "deny")
        self.assertEqual(result["deciding_mode"], "deny")
        self.assertEqual(result["policy_id"], "deny-second")

    def test_warn_decision_replays(self):
        policy = self._ladder_engine()
        action = self._action("delete_file")
        decision = policy.decide(Request.from_action(action, {}))
        self.assertEqual((decision.effect, decision.nominal_effect,
                          decision.mode),
                         ("allow", "deny", "warn"))
        trace = dr.build_trace(decision=decision, action=action,
                               context={}, policy=policy)
        self.assertEqual(trace["verdict"]["mode"], "warn")
        self.assertEqual(trace["verdict"]["nominal_effect"], "deny")
        hit = trace["evaluation"]["forbid_hits"][0]
        self.assertEqual(hit["mode"], "warn")
        bundle = dr.policy_bundle_from_policy(policy)
        result = dr.replay(trace, bundle)
        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(result["nominal_verdict"], "deny")
        self.assertEqual(result["deciding_mode"], "warn")
        self.assertEqual(result["policy_id"], "warn-cand")

    def test_observe_only_match_replays_as_default_deny(self):
        # The observe hit has no authority: the decider is the
        # implicit default deny, and the mirror must not crown the
        # observe rule.
        policy = self._ladder_engine()
        action = self._action("http_post")
        decision = policy.decide(Request.from_action(action, {}))
        self.assertEqual(decision.effect, "deny")
        self.assertIsNone(decision.policy_id)
        self.assertEqual(len(decision.diagnostics.observed_hits), 1)
        trace = dr.build_trace(decision=decision, action=action,
                               context={}, policy=policy)
        bundle = dr.policy_bundle_from_policy(policy)
        result = dr.replay(trace, bundle)
        self.assertEqual(result["verdict"], "deny")
        self.assertIsNone(result["policy_id"])

    def test_runtime_graduation_replays_by_recorded_mode(self):
        # The bundle still says observe (load-time); the ledger moved
        # the rule to warn at runtime. Replay must honor the trace,
        # not the bundle.
        policy = self._ladder_engine()
        ledger = policy.mode_ledger
        for _ in range(120):
            policy.decide(Request.from_action(
                self._action("http_post"), {}))
        for _ in range(30):
            ledger.record_review("obs-cand", correct=True,
                                 reviewer="op1")
        ok, reasons = policy.apply_graduation(
            "obs-cand", "warn", approvers=["op1", "op2"])
        self.assertTrue(ok, reasons)
        action = self._action("http_post")
        decision = policy.decide(Request.from_action(action, {}))
        self.assertEqual(decision.mode, "warn")
        self.assertEqual(decision.effect, "allow")
        trace = dr.build_trace(decision=decision, action=action,
                               context={}, policy=policy)
        bundle = dr.policy_bundle_from_policy(policy)
        bundle_mode = [r for r in bundle["rules"]
                       if r["id"] == "obs-cand"][0].get("mode")
        self.assertEqual(bundle_mode, "observe")  # load-time, stale
        self.assertEqual(trace["verdict"]["mode"], "warn")  # recorded
        result = dr.replay(trace, bundle)
        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(result["nominal_verdict"], "deny")

    def test_tampered_recorded_mode_fails_replay(self):
        policy = self._ladder_engine()
        action = self._action("delete_file")
        decision = policy.decide(Request.from_action(action, {}))
        trace = dr.build_trace(decision=decision, action=action,
                               context={}, policy=policy)
        bundle = dr.policy_bundle_from_policy(policy)
        trace["verdict"]["mode"] = "deny"  # tamper, digests not repaired
        with self.assertRaises(dr.TraceTamperedError):
            dr.replay(trace, bundle)


class LoudFailureTest(unittest.TestCase):
    """Tamper / drift / version failures are named, never silent."""

    def test_tampered_input_names_section(self):
        trace, bundle = _synth()
        bad = copy.deepcopy(trace)
        bad["request"]["context"]["counters"]["send_email"] = 0
        with self.assertRaises(dr.TraceTamperedError) as cm:
            dr.replay(bad, bundle)
        self.assertEqual(cm.exception.section, "request")

    def test_tampered_envelope_names_section(self):
        trace, bundle = _synth()
        bad = copy.deepcopy(trace)
        bad["integrity"]["sections"]["verdict"] = "0" * 64
        with self.assertRaises(dr.TraceTamperedError) as cm:
            dr.replay(bad, bundle)
        self.assertEqual(cm.exception.section, "verdict")

    def test_rewritten_verdict_names_section(self):
        trace, bundle = _synth()
        self.assertEqual(trace["verdict"]["effect"], "deny")
        bad = copy.deepcopy(trace)
        bad["verdict"]["effect"] = "allow"
        with self.assertRaises(dr.TraceTamperedError) as cm:
            dr.replay(bad, bundle)
        self.assertEqual(cm.exception.section, "verdict")

    def test_policy_rule_drift(self):
        trace, bundle = _synth()
        drifted = copy.deepcopy(bundle)
        drifted["rules"][1]["match"]["when"][0]["gte"] = 9999
        with self.assertRaises(dr.PolicyDriftError):
            dr.replay(trace, drifted)

    def test_policy_version_drift(self):
        trace, bundle = _synth()
        drifted = copy.deepcopy(bundle)
        drifted["policy_version"] = "4"
        with self.assertRaises(dr.PolicyDriftError):
            dr.replay(trace, drifted)

    def test_policy_rule_reorder_is_drift(self):
        trace, bundle = _synth()
        reordered = copy.deepcopy(bundle)
        reordered["rules"] = list(reversed(reordered["rules"]))
        with self.assertRaises(dr.PolicyDriftError):
            dr.replay(trace, reordered)

    def test_future_trace_version_refused(self):
        trace, bundle = _synth()
        bad = copy.deepcopy(trace)
        bad["trace_version"] = 2
        with self.assertRaises(dr.TraceVersionError) as cm:
            dr.replay(bad, bundle)
        self.assertEqual(cm.exception.trace_version, 2)

    def test_per_rule_divergence_caught(self):
        # Flip a recorded per-rule outcome but repair the digests, so
        # only the recomputation comparison can catch it.
        trace, bundle = _synth()
        bad = copy.deepcopy(trace)
        for t in bad["evaluation"]["trace"]:
            t["matched"] = not t["matched"]
            break
        _repair_digests(bad)
        with self.assertRaises(dr.ReplayMismatchError) as cm:
            dr.replay(bad, bundle)
        self.assertIn("matched", str(cm.exception))

    def test_post_verdict_loosening_refused(self):
        trace, bundle = _synth()
        self.assertEqual(trace["verdict"]["effect"], "deny")
        bad = copy.deepcopy(trace)
        bad["post_verdict"]["final_effect"] = "allow"
        bad["post_verdict"]["modified"] = True
        _repair_digests(bad)
        with self.assertRaises(dr.ReplayMismatchError) as cm:
            dr.replay(bad, bundle)
        self.assertIn("loosened", str(cm.exception))

    def test_post_verdict_tightening_accepted(self):
        policy = _engine()
        action = {"tool": "read_file", "role": "analyst",
                  "agent_id": "a", "args": {"path": "notes.txt"}}
        trace = _trace_for(policy, action, {},
                           final_effect="require_approval",
                           final_policy_id="tool-rating-default",
                           final_flag="unrated_mutating_tool")
        bundle = dr.policy_bundle_from_policy(policy)
        result = dr.replay(trace, bundle)
        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(result["final_effect"], "require_approval")
        self.assertTrue(result["post_verdict_modified"])


class NoSecretsTest(unittest.TestCase):
    """Digests and IDs only -- never raw secrets, key material, PII,
    or raw payload bytes."""

    def test_no_raw_secrets_in_trace(self):
        policy = _engine()
        action = {"tool": "api_call", "role": "ops", "agent_id": "a",
                  "args": {"endpoint": "https://x.example/hook",
                           "password": _SECRET_VALUES[0],
                           "api_key": _SECRET_VALUES[1],
                           "headers": {"Authorization": _SECRET_VALUES[2]},
                           "payload": _SECRET_VALUES[3],
                           "to": _SECRET_VALUES[4],
                           "path": "hook/log.txt"}}
        ctx = {"high_entropy_payload": False}
        trace = _trace_for(policy, action, ctx)
        blob = dr.canonical(trace)
        for secret in _SECRET_VALUES:
            self.assertNotIn(secret, blob, secret)
        # path stays verbatim (match-relevant); the rest are digests.
        self.assertEqual(trace["request"]["args"]["path"],
                         "hook/log.txt")
        self.assertEqual(trace["request"]["args"]["password"],
                         {"$digest": dr.sha256_hex(
                             dr.canonical(_SECRET_VALUES[0]))})
        # resource derived from a non-path key is digested, not raw.
        self.assertNotEqual(trace["request"]["resource"],
                            "https://x.example/hook")

    def test_executor_hook_trace_has_no_raw_secrets(self):
        """End-to-end: the capture hook's trace carries digests only."""
        from gov.log import ActionLog, read_entries
        from gov.approvals import ApprovalQueue
        from gov.executor import ToolExecutor

        os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
        tmp = os.environ.get("TMPDIR") or tempfile.gettempdir()
        Path(tmp).mkdir(parents=True, exist_ok=True)
        run_dir = Path(tempfile.mkdtemp(prefix="drt-", dir=tmp))
        pol_text = ("version: 1\n"
                    "egress:\n"
                    "  domain_allowlist: [allowed.example]\n"
                    "roles:\n"
                    "  ops: [api_call]\n"
                    "policies:\n"
                    "  - id: allow-api\n"
                    "    effect: allow\n"
                    "    match:\n"
                    "      tool: [api_call]\n"
                    "    reason: allow.\n")
        policy = PolicyEngine.from_text(pol_text,
                                        source_label="<test-hook>")
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        ex = ToolExecutor(run_dir, policy, log, approvals,
                          ledger_path=run_dir / "egress_ledger.jsonl",
                          ungoverned_ack="decision-replay test: synthetic")
        ident = ex.mint_identity("agent-1", "ops", "user-1")
        ex.call(ident, "api_call",
                endpoint="https://allowed.example/hook",
                password=_SECRET_VALUES[0], payload=_SECRET_VALUES[3])
        traces = [e.get("decision_trace") for e in
                  read_entries(run_dir / "actions.jsonl")
                  if isinstance(e, dict) and "decision_trace" in e]
        self.assertTrue(traces, "capture hook wrote no decision_trace")
        for trace in traces:
            self.assertNotIn("capture_error", trace)
            blob = dr.canonical(trace)
            for secret in _SECRET_VALUES:
                self.assertNotIn(secret, blob, secret)
            result = dr.replay(
                trace, dr.policy_bundle_from_policy(policy))
            self.assertEqual(result["verdict"], "allow")


class HygieneTest(unittest.TestCase):
    """Determinism, schema versioning, standalone importability."""

    def test_build_trace_deterministic(self):
        policy = _engine()
        action = {"tool": "write_file", "role": "ops", "agent_id": "a",
                  "args": {"path": "secret/x.txt", "content": "zzz"}}
        ctx = {"path_outside_sandbox": False,
               "counters": {"write_file": 2}}
        t1 = dr.canonical(_trace_for(policy, action, ctx))
        t2 = dr.canonical(_trace_for(policy, action, ctx))
        self.assertEqual(t1, t2)

    def test_trace_schema_versioned(self):
        trace, _ = _synth()
        self.assertEqual(trace["trace_version"], 1)
        self.assertEqual(set(trace["integrity"]["sections"]),
                         {"policy", "request", "verdict", "evaluation",
                          "post_verdict"})
        self.assertEqual(trace["policy"]["rule_count"],
                         len(_engine().policies))

    def test_module_is_stdlib_only_and_standalone(self):
        src = Path(dr.__file__).read_text()
        for line in src.splitlines():
            s = line.strip()
            if s.startswith("import ") or s.startswith("from "):
                self.assertNotIn("gov", s, s)
                self.assertIn(s.split()[1].split(".")[0],
                              ("hashlib", "json", "math"), s)
        # Importable from a bare file path without the repo importable.
        spec = importlib.util.spec_from_file_location(
            "decision_replay_standalone", dr.__file__)
        mod = importlib.util.module_from_spec(spec)
        saved_modules = dict(sys.modules)
        saved_path = list(sys.path)
        try:
            for name in list(sys.modules):
                if name == "gov" or name.startswith("gov."):
                    del sys.modules[name]
            sys.path = [p for p in sys.path
                        if os.path.abspath(p) != os.path.abspath(
                            os.path.dirname(os.path.dirname(dr.__file__)))]
            spec.loader.exec_module(mod)
        finally:
            sys.path = saved_path
            sys.modules.update(saved_modules)
        self.assertEqual(mod.TRACE_VERSION, 1)
        self.assertTrue(issubclass(mod.TraceTamperedError,
                                   mod.ReplayError))


if __name__ == "__main__":
    unittest.main()
