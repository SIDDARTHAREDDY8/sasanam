"""Break-first probes: Cedar-style Request/Decision+Diagnostics contract.

Target: gov/decision_contract.py + PolicyEngine.decide() (adapted from
the interface ideas of cedar-policy/cedar, Apache-2.0 — credited, not
cloned; see the module docstring).

The two properties under test:

  1. forbid-overrides-permit — a matching deny rule denies no matter
     how many permits match or where the rules are declared. The
     engine evaluates all deny rules before any permit is consulted,
     so a permit can never shadow a forbid by declaration order.
  2. diagnostics honesty — every Decision names the exact policy ids
     that fired (deciding + shadowed) and carries the evaluation
     trace. There is no API path by which the diagnostics can lie
     about which rule decided.

Verdicts: HELD = property holds (attack shape defeated), BREAK =
property violated (file a finding — never silently patch).

Standalone: python evals/cedar_contract_probes.py
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov.policy import PolicyEngine
from gov.decision_contract import Request, ContractError

RESULTS = []


def _report(name, verdict, detail):
    RESULTS.append({"verdict": verdict, "detail": {"probe": name,
                                                  "note": detail}})
    print("  %-34s %s  %s" % (name, verdict, detail))


def _engine(policy_text):
    return PolicyEngine.from_text(policy_text, source_label="<probe policy>")


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
      path_contains_any: [secret]
    reason: forbid declared SECOND.
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
      path_contains_any: [secret]
    reason: forbid declared FIRST.
  - id: permit-reads
    effect: allow
    match:
      tool: [read_file]
    reason: permit declared SECOND.
"""

_TWO_FORBIDS = """\
version: 2
roles:
  analyst: [read_file]
policies:
  - id: forbid-secret-reads
    effect: deny
    match:
      tool: [read_file]
      path_contains_any: [secret]
    reason: first forbid.
  - id: forbid-classified-reads
    effect: deny
    match:
      tool: [read_file]
      path_contains_any: [secret]
    reason: second forbid, same scope.
  - id: permit-reads
    effect: allow
    match:
      tool: [read_file]
    reason: permit.
"""

_NARROW_FORBID = """\
version: 2
roles:
  analyst: [read_file, write_file]
policies:
  - id: permit-all-files
    effect: allow
    match:
      tool: [read_file, write_file]
    reason: broad permit.
  - id: forbid-prod-config
    effect: deny
    match:
      tool: [write_file]
      path_contains_any: [/prod/config]
    reason: narrow forbid on prod config.
"""

_THREE_TIER = """\
version: 2
roles:
  analyst: [send_email]
policies:
  - id: permit-sends
    effect: allow
    match:
      tool: [send_email]
    reason: permit declared first.
  - id: approval-bulk-sends
    effect: require_approval
    match:
      tool: [send_email]
      min_sends: 3
    reason: approval declared second.
  - id: forbid-external-sends
    effect: deny
    match:
      tool: [send_email]
    reason: forbid declared last.
"""

_TWO_PERMITS = """\
version: 2
roles:
  analyst: [read_file]
policies:
  - id: permit-reads-general
    effect: allow
    match:
      tool: [read_file]
    reason: first permit.
  - id: permit-reads-specific
    effect: allow
    match:
      tool: [read_file]
      path_contains_any: [docs]
    reason: second permit, narrower.
"""


def _req(tool, agent="probe-agent", role="analyst", args=None, ctx=None):
    return Request.from_action(
        {"tool": tool, "role": role, "agent_id": agent, "args": args or {}},
        ctx or {})


def p1_forbid_beats_permit_permit_first():
    """Adversarial ordering: permit declared BEFORE forbid. Forbid wins."""
    d = _engine(_PERMIT_FIRST).decide(
        _req("read_file", args={"path": "/data/secret.txt"}))
    ok = (d.effect == "deny" and not d.allowed
          and d.policy_id == "forbid-secret-reads"
          and d.diagnostics.deciding_rule.rule_id == "forbid-secret-reads"
          and d.diagnostics.forbid_policy_ids == ("forbid-secret-reads",)
          and any(h.rule_id == "permit-reads" and not h.deciding
                  for h in d.diagnostics.permit_hits))
    _report("p1_permit_declared_first", "HELD" if ok else "BREAK",
            "forbid wins despite permit-first declaration; permit named as shadowed"
            if ok else "ORDERING BYPASS: %r" % (d.to_dict(),))


def p2_forbid_beats_permit_forbid_first():
    """Same verdict when the forbid is declared first (order-independent)."""
    d = _engine(_FORBID_FIRST).decide(
        _req("read_file", args={"path": "/data/secret.txt"}))
    ok = (d.effect == "deny" and d.policy_id == "forbid-secret-reads"
          and d.diagnostics.deciding_rule.deciding)
    _report("p2_forbid_declared_first", "HELD" if ok else "BREAK",
            "verdict identical under reversed declaration order"
            if ok else "ORDERING DIVERGENCE: %r" % (d.to_dict(),))


def p3_multiple_forbids_all_named():
    """Two forbids match: decider is first in declaration order; BOTH named."""
    d = _engine(_TWO_FORBIDS).decide(
        _req("read_file", args={"path": "/data/secret.txt"}))
    ok = (d.effect == "deny"
          and d.policy_id == "forbid-secret-reads"
          and d.diagnostics.forbid_policy_ids
          == ("forbid-secret-reads", "forbid-classified-reads"))
    _report("p3_multiple_forbids_named", "HELD" if ok else "BREAK",
            "decider=forbid-secret-reads; both forbids in forbid_hits"
            if ok else "FORBID SUPPRESSED: %r" % (d.to_dict(),))


def p4_narrow_forbid_beats_broad_permit():
    """A narrowly-scoped forbid beats a broad permit on a disjoint match key."""
    eng = _engine(_NARROW_FORBID)
    d_hit = eng.decide(_req("write_file", args={"path": "/prod/config/app.yaml"}))
    d_miss = eng.decide(_req("write_file", args={"path": "/tmp/notes.txt"}))
    ok = (d_hit.effect == "deny"
          and d_hit.policy_id == "forbid-prod-config"
          and d_miss.effect == "allow"
          and d_miss.policy_id == "permit-all-files")
    _report("p4_narrow_forbid_scope", "HELD" if ok else "BREAK",
            "narrow forbid denies its scope; broad permit still allows outside it"
            if ok else "SCOPE FAILURE: hit=%r miss=%r"
            % (d_hit.to_dict(), d_miss.to_dict()))


def p5_forbid_no_match_permit_wins():
    """Forbid whose conditions do NOT match must not deny (no false forbid)."""
    d = _engine(_PERMIT_FIRST).decide(
        _req("read_file", args={"path": "/data/public.txt"}))
    ok = (d.effect == "allow" and d.allowed
          and d.policy_id == "permit-reads"
          and d.diagnostics.forbid_hits == ())
    _report("p5_forbid_no_match", "HELD" if ok else "BREAK",
            "non-matching forbid is silent; permit decides"
            if ok else "FALSE FORBID: %r" % (d.to_dict(),))


def p6_implicit_deny():
    """No rule matches -> implicit deny; diagnostics say so explicitly."""
    d = _engine(_PERMIT_FIRST).decide(_req("delete_file"))
    dg = d.diagnostics
    ok = (d.effect == "deny" and not d.allowed and d.policy_id is None
          and d.flag == "default_deny" and dg.deciding_rule is None
          and dg.policy_ids == frozenset()
          and len(dg.trace) == 2)  # both rules evaluated, none matched
    _report("p6_implicit_deny", "HELD" if ok else "BREAK",
            "default deny is an explicit, traceable verdict — not a silent hole"
            if ok else "IMPLICIT DENY OPAQUE: %r" % (d.to_dict(),))


def p7_tier_ordering():
    """deny > require_approval > allow regardless of declaration order."""
    eng = _engine(_THREE_TIER)
    d_all = eng.decide(_req("send_email", ctx={"counters": {"send_email": 5}}))
    # A request matching approval+permit but no deny: strip the deny rule.
    eng2 = _engine(_THREE_TIER.replace(
        "  - id: forbid-external-sends\n    effect: deny\n"
        "    match:\n      tool: [send_email]\n"
        "    reason: forbid declared last.\n", ""))
    d_noforbid = eng2.decide(_req("send_email",
                                 ctx={"counters": {"send_email": 5}}))
    ok = (d_all.effect == "deny" and d_all.policy_id == "forbid-external-sends"
          and d_noforbid.effect == "require_approval"
          and d_noforbid.policy_id == "approval-bulk-sends"
          and not d_noforbid.allowed)
    _report("p7_tier_ordering", "HELD" if ok else "BREAK",
            "deny>approval>allow holds with hostile declaration order"
            if ok else "TIER INVERSION: %r / %r"
            % (d_all.to_dict(), d_noforbid.to_dict()))


def p8_diagnostics_cannot_lie():
    """Adversarial: try to make the diagnostics misattribute the decider.

    Shapes attempted: (a) legacy to_policy_decision() must agree with
    the contract's deciding rule; (b) the Cedar-style policy_ids set
    must contain exactly the fired ids; (c) no shadowed permit may
    ever be flagged deciding; (d) the trace must show the deny pass
    was evaluated before any permit.
    """
    eng = _engine(_PERMIT_FIRST)
    req = _req("read_file", args={"path": "/data/secret.txt"})
    d = eng.decide(req)
    legacy = eng.evaluate(req.to_action(), dict(req.context))
    dg = d.diagnostics
    trace_effects = [t.effect for t in dg.trace]
    first_deny = trace_effects.index("deny")
    first_allow = trace_effects.index("allow")
    ok = (
        # (a) legacy surface agrees with the contract
        legacy.policy_id == dg.deciding_rule.rule_id == "forbid-secret-reads"
        and legacy.effect == d.effect == "deny"
        # (b) policy_ids is exactly the fired set
        and dg.policy_ids == frozenset({"forbid-secret-reads",
                                        "permit-reads"})
        # (c) shadowed permits never flagged deciding
        and all(not h.deciding for h in dg.permit_hits)
        and dg.shadowed_hits
        and all(h.rule_id == "permit-reads" for h in dg.shadowed_hits)
        # (d) deny pass evaluated before any permit
        and first_deny < first_allow
    )
    _report("p8_diagnostics_honest", "HELD" if ok else "BREAK",
            "decider=forbid-secret-reads on every surface; permit shadowed, not hidden"
            if ok else "DIAGNOSTIC LIE: %r" % (d.to_dict(),))


def p9_shadowed_permit_named():
    """Two permits match: first declared decides; loser is named, not hidden."""
    d = _engine(_TWO_PERMITS).decide(
        _req("read_file", args={"path": "/docs/guide.txt"}))
    dg = d.diagnostics
    ok = (d.effect == "allow" and d.policy_id == "permit-reads-general"
          and [h.rule_id for h in dg.permit_hits]
          == ["permit-reads-general", "permit-reads-specific"]
          and [h.rule_id for h in dg.shadowed_hits]
          == ["permit-reads-specific"])
    _report("p9_shadowed_permit_named", "HELD" if ok else "BREAK",
            "first-declared permit decides; narrower loser listed as shadowed"
            if ok else "SHADOW SUPPRESSED: %r" % (d.to_dict(),))


def p10_contract_strictness():
    """Untyped requests fail loud at construction — never silent evaluation."""
    holes = []
    for kwargs in ({"principal": "", "action": "read_file"},
                   {"principal": "a", "action": "read_file",
                    "context": ["not", "a", "mapping"]},
                   {"principal": "a", "action": "read_file",
                    "args": "not-a-mapping"}):
        base = {"principal": "a", "action": "read_file", "resource": None,
                "role": None, "args": {}, "context": {}}
        base.update(kwargs)
        try:
            Request(**base)
            holes.append(kwargs)
        except (ContractError, TypeError):
            pass
    try:
        PolicyEngine.from_text(_PERMIT_FIRST).decide(
            {"tool": "read_file"})  # raw dict, not a Request
        holes.append("raw-dict-decide")
    except TypeError:
        pass
    ok = not holes
    _report("p10_contract_strict", "HELD" if ok else "BREAK",
            "untyped requests rejected at the seam"
            if ok else "CONTRACT HOLES: %r" % (holes,))


def p11_differential_evaluate_vs_decide():
    """Differential: decide() verdict fields == evaluate() on both the
    default policy (27 rules) and adversarial-ordering synthetic
    policies. The refactor must not move a single verdict."""
    mismatches = []
    engines = [PolicyEngine("policies/default.yaml"),
               _engine(_PERMIT_FIRST), _engine(_THREE_TIER)]
    cases = [
        ({"tool": "read_file", "role": "analyst", "agent_id": "a",
          "args": {"path": "/data/secret.txt"}}, {}),
        ({"tool": "read_file", "role": "analyst", "agent_id": "a",
          "args": {"path": "/tmp/x.txt"}}, {}),
        ({"tool": "send_email", "role": "analyst", "agent_id": "a",
          "args": {}}, {"domain_allowlisted": True}),
        ({"tool": "send_email", "role": "analyst", "agent_id": "a",
          "args": {}}, {"domain_allowlisted": False}),
        ({"tool": "delete_file", "role": "coder", "agent_id": "a",
          "args": {"path": "/tmp/x"}}, {"path_outside_sandbox": True}),
        ({"tool": None, "args": {"destination": "x"}},  # platform-egress shape
         {"platform_egress": True, "domain_allowlisted": True}),
        ({"tool": "api_call", "role": "coder", "agent_id": "a",
          "args": {}}, {"counters": {"send_email": 9}}),
    ]
    for eng in engines:
        for action, ctx in cases:
            req = Request.from_action(action, ctx)
            d = eng.decide(req)
            pd = eng.evaluate(action, ctx)
            if not (pd.effect == d.effect and pd.policy_id == d.policy_id
                    and pd.flag == d.flag and pd.reason == d.reason
                    and pd.matched_rules
                    == ([d.policy_id] if d.policy_id else ["default_deny"])):
                mismatches.append((action.get("tool"), d.effect, pd.effect))
    ok = not mismatches
    _report("p11_differential", "HELD" if ok else "BREAK",
            "%d engine/case pairs: decide() == evaluate() on every verdict field"
            % (len(engines) * len(cases))
            if ok else "VERDICT DRIFT: %r" % (mismatches,))


def p12_deny_pass_precedes_permits():
    """Structural: no allow-pass trace entry precedes a deny-pass entry."""
    d = _engine(_PERMIT_FIRST).decide(
        _req("read_file", args={"path": "/data/public.txt"}))
    seen_allow = False
    ok = True
    for t in d.diagnostics.trace:
        if t.effect == "allow":
            seen_allow = True
        if t.effect == "deny" and seen_allow:
            ok = False
            break
    _report("p12_pass_order", "HELD" if ok else "BREAK",
            "deny pass is structurally evaluated before any permit"
            if ok else "PASS INTERLEAVED")


def main():
    print("== cedar-contract probes (break-first) ==")
    p1_forbid_beats_permit_permit_first()
    p2_forbid_beats_permit_forbid_first()
    p3_multiple_forbids_all_named()
    p4_narrow_forbid_beats_broad_permit()
    p5_forbid_no_match_permit_wins()
    p6_implicit_deny()
    p7_tier_ordering()
    p8_diagnostics_cannot_lie()
    p9_shadowed_permit_named()
    p10_contract_strictness()
    p11_differential_evaluate_vs_decide()
    p12_deny_pass_precedes_permits()
    held = sum(1 for r in RESULTS if r["verdict"] == "HELD")
    brk = sum(1 for r in RESULTS if r["verdict"] == "BREAK")
    err = len(RESULTS) - held - brk
    print("----")
    print("%d/%d HELD, %d BREAK, %d ERROR" % (held, len(RESULTS), brk, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
