"""Unit tests: Cedar-style Request/Decision+Diagnostics contract.

Target: gov/decision_contract.py + PolicyEngine.decide() (interface
ideas adapted from cedar-policy/cedar, Apache-2.0 — credited, not
cloned).

Pinned properties (red-first, 2026-09-28, wave-180 lane B):

  1. forbid-overrides-permit — a matching deny rule denies no matter
     how many permit rules match or where the rules are declared, and
     the diagnostics NAME the forbid rule as the decider.
  2. diagnostics list every evaluated rule in order — the trace
     covers every rule (match/no-match), forbid/approval/permit hit
     buckets name every matched rule, shadowed hits are named rather
     than hidden.
  3. fail-closed — an empty policy denies with diagnostics saying why
     (implicit default_deny); a malformed policy refuses at load.

Plus the lane-B closure: every policy evaluation returns
{decision, diagnostics} — PolicyEngine.evaluate() (the path every
enforcement call site uses) carries the full Diagnostics on the
returned PolicyDecision, so the why is never dropped at the seam.
"""

import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import tests  # noqa: F401  (provisions an explicit key for the harness)
from gov.policy import PolicyEngine, PolicyDecision
from gov.decision_contract import (
    ContractError,
    Decision,
    Diagnostics,
    Request,
    DEFAULT_DENY_ID,
)


def _engine(policy_text):
    return PolicyEngine.from_text(policy_text, source_label="<test policy>")


def _req(tool="read_file", agent_id="agent-1", role="analyst",
         args=None, context=None):
    action = {"tool": tool, "agent_id": agent_id, "role": role,
              "args": args or {"path": "/tmp/x.txt"}}
    return Request.from_action(action, context or {})


_PERMIT_FIRST = """\
version: 2
roles:
  analyst: [read_file]
policies:
  - id: permit-reads
    effect: allow
    match:
      tool: [read_file]
    reason: permit declared FIRST.
  - id: forbid-secret-reads
    effect: deny
    match:
      tool: [read_file]
    reason: forbid declared second still wins.
"""

_FORBID_FIRST = """\
version: 2
roles:
  analyst: [read_file]
policies:
  - id: forbid-secret-reads
    effect: deny
    match:
      tool: [read_file]
    reason: forbid declared first wins.
  - id: permit-reads
    effect: allow
    match:
      tool: [read_file]
    reason: permit declared second loses.
"""

_MANY_PERMITS = """\
version: 2
roles:
  analyst: [read_file]
policies:
  - id: permit-a
    effect: allow
    match:
      tool: [read_file]
    reason: permit a.
  - id: permit-b
    effect: allow
    match:
      tool: [read_file]
    reason: permit b.
  - id: permit-c
    effect: allow
    match:
      tool: [read_file]
    reason: permit c.
  - id: forbid-all-reads
    effect: deny
    match:
      tool: [read_file]
    reason: one forbid beats three permits.
"""

_MIXED = """\
version: 2
roles:
  analyst: [read_file, send_email]
policies:
  - id: forbid-secret-reads
    effect: deny
    match:
      tool: [read_file]
    reason: forbid.
  - id: approval-sends
    effect: require_approval
    match:
      tool: [send_email]
    reason: approval.
  - id: permit-reads
    effect: allow
    match:
      tool: [read_file]
    reason: permit.
"""

_EMPTY = """\
version: 2
roles:
  analyst: [read_file]
policies: []
"""


class TestForbidOverridesPermit(unittest.TestCase):
    """Property 1: forbid wins regardless of declaration order/count."""

    def test_forbid_beats_permit_declared_first(self):
        d = _engine(_PERMIT_FIRST).decide(_req())
        self.assertEqual(d.effect, "deny")
        self.assertFalse(d.allowed)
        # The diagnostics NAME the forbid rule as the decider.
        self.assertIsNotNone(d.diagnostics.deciding_rule)
        self.assertEqual(d.diagnostics.deciding_rule.rule_id,
                         "forbid-secret-reads")
        self.assertEqual(d.diagnostics.deciding_rule.effect, "deny")
        self.assertIn("forbid-secret-reads",
                      d.diagnostics.forbid_policy_ids)
        # The losing permit is named as shadowed, not hidden.
        shadowed = {h.rule_id for h in d.diagnostics.shadowed_hits}
        self.assertIn("permit-reads", shadowed)

    def test_forbid_beats_permit_declared_second(self):
        d = _engine(_FORBID_FIRST).decide(_req())
        self.assertEqual(d.effect, "deny")
        self.assertEqual(d.diagnostics.deciding_rule.rule_id,
                         "forbid-secret-reads")

    def test_one_forbid_beats_many_permits(self):
        d = _engine(_MANY_PERMITS).decide(_req())
        self.assertEqual(d.effect, "deny")
        self.assertEqual(d.diagnostics.deciding_rule.rule_id,
                         "forbid-all-reads")
        shadowed = {h.rule_id for h in d.diagnostics.shadowed_hits}
        self.assertEqual(shadowed, {"permit-a", "permit-b", "permit-c"})

    def test_no_match_is_implicit_deny(self):
        d = _engine(_PERMIT_FIRST).decide(_req(tool="send_email"))
        self.assertEqual(d.effect, "deny")
        self.assertFalse(d.allowed)
        self.assertIsNone(d.diagnostics.deciding_rule)
        self.assertEqual(d.flag, DEFAULT_DENY_ID)

    def test_permit_wins_when_no_forbid_matches(self):
        # A policy where only the permit matches this request.
        eng = _engine("""\
version: 2
roles:
  analyst: [read_file]
policies:
  - id: forbid-sends
    effect: deny
    match:
      tool: [send_email]
    reason: forbid.
  - id: permit-reads
    effect: allow
    match:
      tool: [read_file]
    reason: permit.
""")
        d = eng.decide(_req())
        self.assertEqual(d.effect, "allow")
        self.assertTrue(d.allowed)
        self.assertEqual(d.diagnostics.deciding_rule.rule_id,
                         "permit-reads")
        self.assertEqual(d.diagnostics.forbid_hits, ())


class TestDiagnosticsCompleteness(unittest.TestCase):
    """Property 2: diagnostics list every evaluated rule, in order."""

    def test_trace_covers_every_rule_in_evaluation_order(self):
        d = _engine(_MIXED).decide(_req())
        trace = d.diagnostics.trace
        # Every rule appears exactly once, in evaluation order:
        # deny pass, then require_approval pass, then allow pass.
        self.assertEqual([(t.effect, t.rule_id) for t in trace], [
            ("deny", "forbid-secret-reads"),
            ("require_approval", "approval-sends"),
            ("allow", "permit-reads"),
        ])
        # Match flags are honest for this read_file request.
        self.assertEqual([t.matched for t in trace],
                         [True, False, True])

    def test_policy_ids_name_everything_that_fired(self):
        d = _engine(_MIXED).decide(_req())
        self.assertEqual(d.diagnostics.policy_ids,
                         frozenset({"forbid-secret-reads", "permit-reads"}))
        self.assertEqual(
            [h.rule_id for h in d.diagnostics.forbid_hits],
            ["forbid-secret-reads"])
        self.assertEqual(
            [h.rule_id for h in d.diagnostics.permit_hits],
            ["permit-reads"])
        self.assertEqual(d.diagnostics.approval_hits, ())

    def test_deciding_flag_marks_exactly_one_hit(self):
        d = _engine(_MIXED).decide(_req())
        deciding = [h for h in (d.diagnostics.forbid_hits
                                + d.diagnostics.approval_hits
                                + d.diagnostics.permit_hits)
                    if h.deciding]
        self.assertEqual(len(deciding), 1)
        self.assertEqual(deciding[0].rule_id, "forbid-secret-reads")
        self.assertIs(d.diagnostics.deciding_rule, deciding[0])

    def test_diagnostics_serialize(self):
        d = _engine(_MIXED).decide(_req())
        blob = d.diagnostics.to_dict()
        self.assertEqual(blob["deciding_rule"]["rule_id"],
                         "forbid-secret-reads")
        self.assertEqual(len(blob["trace"]), 3)
        self.assertIn("permit-reads", blob["policy_ids"])
        top = d.to_dict()
        self.assertEqual(top["effect"], "deny")
        self.assertEqual(top["request"]["principal"], "agent-1")
        self.assertEqual(top["request"]["action"], "read_file")


class TestFailClosed(unittest.TestCase):
    """Property 3: empty policy denies; malformed policy refuses."""

    def test_empty_policy_denies_with_diagnostics_saying_why(self):
        d = _engine(_EMPTY).decide(_req())
        self.assertEqual(d.effect, "deny")
        self.assertFalse(d.allowed)
        self.assertIsNone(d.diagnostics.deciding_rule)
        self.assertEqual(d.diagnostics.trace, ())
        self.assertEqual(d.diagnostics.policy_ids, frozenset())
        self.assertIn("default", d.reason.lower())
        self.assertIn("fail-closed", d.reason.lower())
        self.assertEqual(d.flag, DEFAULT_DENY_ID)

    def test_unknown_effect_refused_at_load(self):
        with self.assertRaises(ValueError):
            _engine("""\
version: 2
roles:
  analyst: [read_file]
policies:
  - id: bad
    effect: sometimes
    match:
      tool: [read_file]
""")

    def test_unknown_match_key_refused_at_load(self):
        with self.assertRaises(ValueError):
            _engine("""\
version: 2
roles:
  analyst: [read_file]
policies:
  - id: bad
    effect: allow
    match:
      macht:
        tool: [read_file]
""")

    def test_non_mapping_rule_refused_at_load(self):
        with self.assertRaises(ValueError):
            _engine("""\
version: 2
roles:
  analyst: [read_file]
policies:
  - just-a-string
""")


class TestRequestShape(unittest.TestCase):
    """The contract is typed: malformed requests fail loud."""

    def test_empty_principal_refused(self):
        with self.assertRaises(ContractError):
            Request(principal="", action="read_file", resource=None,
                    role=None, args={}, context={})

    def test_non_mapping_context_refused(self):
        with self.assertRaises(ContractError):
            Request(principal="a", action="read_file", resource=None,
                    role=None, args={}, context=[("x", 1)])

    def test_decide_rejects_untyped_request(self):
        eng = _engine(_EMPTY)
        with self.assertRaises(TypeError):
            eng.decide({"tool": "read_file"})

    def test_from_action_principal_fallback_is_explicit(self):
        r = Request.from_action({"tool": None, "args": {}})
        self.assertEqual(r.principal, "unknown")
        self.assertIsNone(r.action)

    def test_decision_invariants_enforced(self):
        r = _req()
        with self.assertRaises(ContractError):
            Decision(effect="maybe", allowed=False, reason="x",
                     policy_id=None, flag=None,
                     diagnostics=Diagnostics(deciding_rule=None), request=r)
        with self.assertRaises(ContractError):
            Decision(effect="allow", allowed=False, reason="x",
                     policy_id=None, flag=None,
                     diagnostics=Diagnostics(deciding_rule=None), request=r)


class TestRequireApprovalPreserved(unittest.TestCase):
    """require_approval stays first-class (not collapsed to deny)."""

    def test_approval_effect_allowed_false(self):
        eng = _engine("""\
version: 2
roles:
  analyst: [send_email]
policies:
  - id: approval-sends
    effect: require_approval
    match:
      tool: [send_email]
    reason: needs a human.
""")
        d = eng.decide(_req(tool="send_email",
                            args={"to": "x@y.z"}))
        self.assertEqual(d.effect, "require_approval")
        self.assertFalse(d.allowed)
        self.assertEqual(d.diagnostics.deciding_rule.rule_id,
                         "approval-sends")

    def test_forbid_beats_approval(self):
        eng = _engine("""\
version: 2
roles:
  analyst: [send_email]
policies:
  - id: approval-sends
    effect: require_approval
    match:
      tool: [send_email]
    reason: needs a human.
  - id: forbid-sends
    effect: deny
    match:
      tool: [send_email]
    reason: never.
""")
        d = eng.decide(_req(tool="send_email",
                            args={"to": "x@y.z"}))
        self.assertEqual(d.effect, "deny")
        self.assertEqual(d.diagnostics.deciding_rule.rule_id,
                         "forbid-sends")


class TestEvaluateCarriesDiagnostics(unittest.TestCase):
    """Lane-B closure: every evaluation returns {decision, diagnostics}.

    evaluate() is the path every enforcement call site uses; the
    full Diagnostics must ride along on the returned PolicyDecision
    so the why is never dropped at the seam.
    """

    def test_evaluate_returns_policy_decision_with_diagnostics(self):
        eng = _engine(_PERMIT_FIRST)
        pd = eng.evaluate({"tool": "read_file", "agent_id": "agent-1",
                           "role": "analyst",
                           "args": {"path": "/tmp/x.txt"}}, {})
        self.assertIsInstance(pd, PolicyDecision)
        self.assertEqual(pd.effect, "deny")
        # The diagnostics ride along.
        self.assertIsInstance(pd.diagnostics, Diagnostics)
        self.assertEqual(pd.diagnostics.deciding_rule.rule_id,
                         "forbid-secret-reads")
        self.assertIn("permit-reads",
                      {h.rule_id for h in pd.diagnostics.shadowed_hits})

    def test_evaluate_diagnostics_for_implicit_deny(self):
        eng = _engine(_EMPTY)
        pd = eng.evaluate({"tool": "read_file", "agent_id": "agent-1",
                           "role": "analyst", "args": {}}, {})
        self.assertEqual(pd.effect, "deny")
        self.assertEqual(pd.matched_rules, ["default_deny"])
        self.assertIsNone(pd.diagnostics.deciding_rule)

    def test_policy_decision_to_dict_includes_diagnostics(self):
        eng = _engine(_PERMIT_FIRST)
        pd = eng.evaluate({"tool": "read_file", "agent_id": "agent-1",
                           "role": "analyst",
                           "args": {"path": "/tmp/x.txt"}}, {})
        blob = pd.to_dict()
        self.assertEqual(
            blob["diagnostics"]["deciding_rule"]["rule_id"],
            "forbid-secret-reads")

    def test_to_policy_decision_keeps_legacy_semantics(self):
        eng = _engine(_PERMIT_FIRST)
        d = eng.decide(_req())
        pd = d.to_policy_decision()
        self.assertEqual(pd.effect, "deny")
        self.assertEqual(pd.matched_rules, ["forbid-secret-reads"])
        self.assertIs(pd.diagnostics, d.diagnostics)


if __name__ == "__main__":
    unittest.main()
