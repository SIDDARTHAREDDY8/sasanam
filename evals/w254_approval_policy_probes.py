"""Break-first red battery: declarative approval rules (wave-254 lane 2;
palantir/policy-bot ADAPT -- pattern only, no policy-bot code).

The gap under test: the human approval queue has no declarative rule
layer. There is no and/or-composed rule set that routes requests to
require-approval / auto-approve / disapproval-opt-in, no guarantee that
auto-approval is auditable, no guarantee that disapproval is explicit
opt-in (never the default), and no read-only simulation API.

Break shapes pinned here:
  (a) auto-approve without an audit sink -> silent auto-approval
      (must refuse approval-policy-no-audit-sink);
  (b) auto-approve that touches the human queue (must never happen);
  (c) disapproval as the default outcome (must be require-approval);
  (d) disapproval-opt-in without explicit "disapproval": true
      (must refuse approval-policy-malformed at compile);
  (e) simulation with side effects (must be structurally read-only);
  (f) malformed rules (unknown op/action, bad shapes) compiling
      silently (must refuse approval-policy-malformed);
  (g) require-approval with no queue seam (must refuse
      approval-policy-seam-unavailable, never drop the request);
  (h) audit-sink failure during auto-approve (must refuse
      approval-policy-audit-failed, never silently approve).

On the pristine wave-253 base every probe reports GAP (the module does
not exist). After the build, every probe must report HELD under both
staging and a clean environment.

Synthetic/local only. Deterministic: fixed fixtures, canonical-JSON
comparisons, no wall clock in asserted values. Stdlib only, no
in-repo git subprocesses. Fresh TMPDIR per process is the caller's
concern; this battery writes nothing outside the stdlib tempdir.
"""

import inspect
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# Repo root (this file lives in evals/) so `gov` is importable when the
# battery is run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# ------------------------------------------------------------------
# probe harness
# ------------------------------------------------------------------

RESULTS = []


def _record(name, verdict, detail=""):
    RESULTS.append({"probe": name, "verdict": verdict, "detail": detail})
    return verdict


def load_policy_module():
    """Return (gov.approval_policy, None) or (None, reason)."""
    try:
        from gov import approval_policy
        return approval_policy, None
    except ImportError as exc:  # noqa: BLE001 - importability is the gap
        return None, str(exc)


def _gap(name, reason):
    return _record(name, "GAP", "module missing: %s" % reason)


# --- rule fixtures ----------------------------------------------------

AUTO_RULES = {
    "version": 1,
    "rules": [
        {"id": "low-risk-reads",
         "when": {"and": [
             {"field": "tool", "op": "eq", "value": "fs.read"},
             {"field": "risk_score", "op": "lt", "value": 0.3},
         ]},
         "action": "auto-approve",
         "note": "low risk reads need no human"},
        {"id": "catch-all",
         "when": {"field": "tool", "op": "exists"},
         "action": "require-approval"},
    ],
}

DISAPPROVAL_RULES = {
    "version": 1,
    "rules": [
        {"id": "deny-exfil",
         "when": {"field": "tool", "op": "eq",
                  "value": "network.egress"},
         "action": "disapproval-opt-in",
         "disapproval": True},
        {"id": "catch-all",
         "when": {"field": "tool", "op": "exists"},
         "action": "require-approval"},
    ],
}

AUTO_REQUEST = {"tool": "fs.read", "risk_score": 0.1,
                "agent_id": "agent-1"}
CATCHALL_REQUEST = {"tool": "shell.exec", "risk_score": 0.9,
                    "agent_id": "agent-1"}
EGRESS_REQUEST = {"tool": "network.egress", "risk_score": 0.9}


class RecordingQueue(object):
    """Fake approval-queue seam: records .queue() calls."""

    def __init__(self):
        self.calls = []

    def queue(self, action, decision, **kwargs):
        self.calls.append({"action": action, "decision": decision,
                           "kwargs": kwargs})
        return "approval-%d" % len(self.calls)


class ExplodingQueue(object):
    """Queue seam that must never be called (simulation / auto paths)."""

    def queue(self, *args, **kwargs):
        raise AssertionError("queue seam touched on a non-queue path")


# --- probes ------------------------------------------------------------


def probe_module_exists():
    mod, reason = load_policy_module()
    if mod is None:
        return _gap("approval-policy/module-exists", reason)
    for name in ("compile_rules", "route", "simulate",
                 "ApprovalPolicyError"):
        if not hasattr(mod, name):
            return _record("approval-policy/module-exists", "BREAK",
                           "missing public name %s" % name)
    return _record("approval-policy/module-exists", "HELD",
                   "public surface present")


def probe_auto_approve_without_sink_refused():
    mod, reason = load_policy_module()
    if mod is None:
        return _gap("approval-policy/auto-approve-no-sink", reason)
    rs = mod.compile_rules(AUTO_RULES)
    try:
        mod.route(rs, AUTO_REQUEST, queue=RecordingQueue(),
                  audit_sink=None)
    except mod.ApprovalPolicyError as exc:
        if exc.code == "approval-policy-no-audit-sink":
            return _record("approval-policy/auto-approve-no-sink",
                           "HELD", "refused with code")
        return _record("approval-policy/auto-approve-no-sink", "BREAK",
                       "wrong code %r" % (exc.code,))
    return _record("approval-policy/auto-approve-no-sink", "BREAK",
                   "silent auto-approval without audit sink")


def probe_auto_approve_records_rule_and_evidence():
    mod, reason = load_policy_module()
    if mod is None:
        return _gap("approval-policy/auto-approve-audited", reason)
    rs = mod.compile_rules(AUTO_RULES)
    sunk = []
    queue = RecordingQueue()
    result = mod.route(rs, AUTO_REQUEST, queue=queue,
                       audit_sink=sunk.append)
    if result.get("action") != "auto-approve":
        return _record("approval-policy/auto-approve-audited", "BREAK",
                       "expected auto-approve, got %r"
                       % (result.get("action"),))
    if queue.calls:
        return _record("approval-policy/auto-approve-audited", "BREAK",
                       "auto-approve touched the human queue")
    if len(sunk) != 1:
        return _record("approval-policy/auto-approve-audited", "BREAK",
                       "expected exactly one audit entry, got %d"
                       % len(sunk))
    entry = sunk[0]
    missing = [k for k in ("rule_id", "request_digest",
                           "matched_evidence", "decision")
               if k not in entry]
    if missing:
        return _record("approval-policy/auto-approve-audited", "BREAK",
                       "audit entry missing %s" % (missing,))
    if entry["rule_id"] != "low-risk-reads":
        return _record("approval-policy/auto-approve-audited", "BREAK",
                       "wrong rule fired: %r" % (entry["rule_id"],))
    digest = entry["request_digest"]
    if not (isinstance(digest, str) and len(digest) == 64 and
            all(c in "0123456789abcdef" for c in digest)):
        return _record("approval-policy/auto-approve-audited", "BREAK",
                       "request_digest not 64-hex")
    if entry["decision"] != "auto-approved":
        return _record("approval-policy/auto-approve-audited", "BREAK",
                       "decision not auto-approved: %r"
                       % (entry["decision"],))
    return _record("approval-policy/auto-approve-audited", "HELD",
                   "rule + evidence recorded, queue untouched")


def probe_disapproval_never_default():
    mod, reason = load_policy_module()
    if mod is None:
        return _gap("approval-policy/disapproval-never-default", reason)
    # No rule matches this request: the default must be
    # require-approval, never disapproval.
    rs = mod.compile_rules(AUTO_RULES)
    outcome = rs.evaluate({"tool": "unknown.tool", "risk_score": 0.99})
    if outcome.action == "disapproval-opt-in":
        return _record("approval-policy/disapproval-never-default",
                       "BREAK", "disapproval is the default outcome")
    if outcome.action != "require-approval":
        return _record("approval-policy/disapproval-never-default",
                       "BREAK", "default is %r, not require-approval"
                       % (outcome.action,))
    return _record("approval-policy/disapproval-never-default", "HELD",
                   "default is require-approval")


def probe_disapproval_opt_in_compile_refused():
    mod, reason = load_policy_module()
    if mod is None:
        return _gap("approval-policy/disapproval-opt-in", reason)
    bad = {"version": 1, "rules": [
        {"id": "sneaky",
         "when": {"field": "tool", "op": "eq", "value": "x"},
         # disapproval-opt-in WITHOUT the explicit opt-in flag.
         "action": "disapproval-opt-in"}]}
    try:
        mod.compile_rules(bad)
    except mod.ApprovalPolicyError as exc:
        if exc.code == "approval-policy-malformed":
            return _record("approval-policy/disapproval-opt-in", "HELD",
                           "refused at compile")
        return _record("approval-policy/disapproval-opt-in", "BREAK",
                       "wrong code %r" % (exc.code,))
    return _record("approval-policy/disapproval-opt-in", "BREAK",
                   "disapproval-opt-in compiled without opt-in flag")


def probe_disapproval_opt_in_routes():
    mod, reason = load_policy_module()
    if mod is None:
        return _gap("approval-policy/disapproval-routes", reason)
    rs = mod.compile_rules(DISAPPROVAL_RULES)
    sunk = []
    result = mod.route(rs, EGRESS_REQUEST, queue=ExplodingQueue(),
                       audit_sink=sunk.append)
    if result.get("action") != "disapproval-opt-in":
        return _record("approval-policy/disapproval-routes", "BREAK",
                       "expected disapproval-opt-in, got %r"
                       % (result.get("action"),))
    if len(sunk) != 1 or sunk[0].get("decision") != "disapproved":
        return _record("approval-policy/disapproval-routes", "BREAK",
                       "disapproval not audited")
    if sunk[0].get("rule_id") != "deny-exfil":
        return _record("approval-policy/disapproval-routes", "BREAK",
                       "wrong rule fired")
    return _record("approval-policy/disapproval-routes", "HELD",
                   "explicit opt-in disapproval audited, queue untouched")


def probe_simulate_no_side_effects():
    mod, reason = load_policy_module()
    if mod is None:
        return _gap("approval-policy/simulate-pure", reason)
    rs = mod.compile_rules(AUTO_RULES)
    requests = [AUTO_REQUEST, CATCHALL_REQUEST, EGRESS_REQUEST]
    sig = inspect.signature(mod.simulate)
    params = set(sig.parameters)
    if params & {"queue", "audit_sink"}:
        return _record("approval-policy/simulate-pure", "BREAK",
                       "simulate accepts a write seam")
    first = mod.simulate(rs, requests)
    second = mod.simulate(rs, requests)
    if json.dumps(first, sort_keys=True) != json.dumps(
            second, sort_keys=True):
        return _record("approval-policy/simulate-pure", "BREAK",
                       "non-deterministic simulation")
    actions = {r["action"] for r in first}
    if actions != {"auto-approve", "require-approval"}:
        return _record("approval-policy/simulate-pure", "BREAK",
                       "unexpected simulated actions %r" % (actions,))
    for row in first:
        if "rule_id" not in row or "matched" not in row:
            return _record("approval-policy/simulate-pure", "BREAK",
                           "preview row missing rule_id/matched")
    return _record("approval-policy/simulate-pure", "HELD",
                   "read-only, deterministic, rule-attributed")


def probe_unknown_op_refused():
    mod, reason = load_policy_module()
    if mod is None:
        return _gap("approval-policy/unknown-op", reason)
    bad = {"version": 1, "rules": [
        {"id": "bad-op",
         "when": {"field": "tool", "op": "frobnicates",
                  "value": "x"},
         "action": "require-approval"}]}
    try:
        mod.compile_rules(bad)
    except mod.ApprovalPolicyError as exc:
        if exc.code == "approval-policy-malformed":
            return _record("approval-policy/unknown-op", "HELD",
                           "refused at compile")
        return _record("approval-policy/unknown-op", "BREAK",
                       "wrong code %r" % (exc.code,))
    return _record("approval-policy/unknown-op", "BREAK",
                   "unknown op compiled silently")


def probe_unknown_action_refused():
    mod, reason = load_policy_module()
    if mod is None:
        return _gap("approval-policy/unknown-action", reason)
    bad = {"version": 1, "rules": [
        {"id": "bad-action",
         "when": {"field": "tool", "op": "exists"},
         "action": "auto-disapprove"}]}
    try:
        mod.compile_rules(bad)
    except mod.ApprovalPolicyError as exc:
        if exc.code == "approval-policy-malformed":
            return _record("approval-policy/unknown-action", "HELD",
                           "refused at compile")
        return _record("approval-policy/unknown-action", "BREAK",
                       "wrong code %r" % (exc.code,))
    return _record("approval-policy/unknown-action", "BREAK",
                   "unknown action compiled silently")


def probe_queue_seam_unavailable_refused():
    mod, reason = load_policy_module()
    if mod is None:
        return _gap("approval-policy/seam-unavailable", reason)
    rs = mod.compile_rules(AUTO_RULES)
    for queue in (None, object()):
        try:
            mod.route(rs, CATCHALL_REQUEST, queue=queue,
                      audit_sink=lambda e: None,
                      queue_action={"tool": "shell.exec"},
                      queue_decision={"flag": "test"})
        except mod.ApprovalPolicyError as exc:
            if exc.code != "approval-policy-seam-unavailable":
                return _record("approval-policy/seam-unavailable",
                               "BREAK", "wrong code %r" % (exc.code,))
            continue
        return _record("approval-policy/seam-unavailable", "BREAK",
                       "request dropped with no queue seam")
    return _record("approval-policy/seam-unavailable", "HELD",
                   "fail-closed on missing seam")


def probe_first_match_wins():
    mod, reason = load_policy_module()
    if mod is None:
        return _gap("approval-policy/first-match-wins", reason)
    rules = {"version": 1, "rules": [
        {"id": "first",
         "when": {"field": "tool", "op": "exists"},
         "action": "require-approval"},
        {"id": "second",
         "when": {"field": "tool", "op": "exists"},
         "action": "auto-approve"}]}
    rs = mod.compile_rules(rules)
    outcome = rs.evaluate({"tool": "fs.read"})
    if outcome.rule_id != "first" or \
            outcome.action != "require-approval":
        return _record("approval-policy/first-match-wins", "BREAK",
                       "non-deterministic or wrong winner: %r/%r"
                       % (outcome.rule_id, outcome.action))
    return _record("approval-policy/first-match-wins", "HELD",
                   "declaration order wins deterministically")


def probe_audit_sink_failure_refuses():
    mod, reason = load_policy_module()
    if mod is None:
        return _gap("approval-policy/audit-failed", reason)
    rs = mod.compile_rules(AUTO_RULES)

    def bad_sink(entry):
        raise RuntimeError("sink down")

    try:
        mod.route(rs, AUTO_REQUEST, queue=RecordingQueue(),
                  audit_sink=bad_sink)
    except mod.ApprovalPolicyError as exc:
        if exc.code == "approval-policy-audit-failed":
            return _record("approval-policy/audit-failed", "HELD",
                           "refused with code")
        return _record("approval-policy/audit-failed", "BREAK",
                       "wrong code %r" % (exc.code,))
    except RuntimeError:
        return _record("approval-policy/audit-failed", "BREAK",
                       "raw sink error escapes the machine-code contract")
    return _record("approval-policy/audit-failed", "BREAK",
                   "silently approved despite sink failure")


def probe_and_or_not_composition():
    mod, reason = load_policy_module()
    if mod is None:
        return _gap("approval-policy/composition", reason)
    rules = {"version": 1, "rules": [
        {"id": "composed",
         "when": {"and": [
             {"or": [
                 {"field": "tool", "op": "eq", "value": "a"},
                 {"field": "tool", "op": "eq", "value": "b"},
             ]},
             {"not": {"field": "blocked", "op": "eq",
                      "value": True}},
         ]},
         "action": "auto-approve"},
        {"id": "catch-all",
         "when": {"field": "tool", "op": "exists"},
         "action": "require-approval"}]}
    rs = mod.compile_rules(rules)
    cases = [
        ({"tool": "a"}, "auto-approve"),
        ({"tool": "b"}, "auto-approve"),
        ({"tool": "a", "blocked": True}, "require-approval"),
        ({"tool": "c"}, "require-approval"),
    ]
    for request, want in cases:
        got = rs.evaluate(request).action
        if got != want:
            return _record("approval-policy/composition", "BREAK",
                           "%r -> %r, want %r" % (request, got, want))
    return _record("approval-policy/composition", "HELD",
                   "and/or/not evaluate correctly")


# ------------------------------------------------- green checks (depth-1)

def _green():
    """Depth-1: run adjacent batteries with GOV_SKIP_GREEN=1 and
    require zero BREAK/ERROR. Honors GOV_SKIP_GREEN itself (records
    skip, never spawns)."""
    import subprocess
    import tempfile
    if SKIP_GREEN:
        return ["green checks skipped (GOV_SKIP_GREEN=1)"]
    here = os.path.dirname(os.path.abspath(__file__))
    batteries = ["w251_posture_probes.py"]
    notes = []
    for bat in batteries:
        path = os.path.join(here, bat)
        if not os.path.exists(path):
            notes.append("%s: missing, skipped" % bat)
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        tmpd = tempfile.mkdtemp(prefix="w254-approval-")
        env["TMPDIR"] = tmpd
        try:
            proc = subprocess.run(
                [sys.executable, path], env=env, capture_output=True,
                text=True, timeout=600, cwd=os.path.join(here, ".."))
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("%s green check failed: %r" % (bat,
                                                                exc))
        out = (proc.stdout or "") + (proc.stderr or "")
        bad = ("BREAK" in out and "0 BREAK" not in out) or \
              ("ERROR" in out and "0 ERROR" not in out)
        if proc.returncode != 0 or bad:
            raise AssertionError(
                "%s green check failed (rc=%d): %s"
                % (bat, proc.returncode, out[-2000:]))
        notes.append("%s: green" % bat)
    return notes


# --- main ---------------------------------------------------------------

def main():
    probes = [
        probe_module_exists,
        probe_auto_approve_without_sink_refused,
        probe_auto_approve_records_rule_and_evidence,
        probe_disapproval_never_default,
        probe_disapproval_opt_in_compile_refused,
        probe_disapproval_opt_in_routes,
        probe_simulate_no_side_effects,
        probe_unknown_op_refused,
        probe_unknown_action_refused,
        probe_queue_seam_unavailable_refused,
        probe_first_match_wins,
        probe_audit_sink_failure_refuses,
        probe_and_or_not_composition,
    ]
    for probe in probes:
        try:
            probe()
        except Exception as exc:  # noqa: BLE001 - one bad probe
            # must not mask the rest.
            _record(probe.__name__, "ERROR", "%r" % (exc,))
    try:
        notes = _green()
    except Exception as exc:  # noqa: BLE001
        _record("green-checks", "ERROR", "%r" % (exc,))
        notes = []
    held = sum(1 for r in RESULTS if r["verdict"] == "HELD")
    gap = sum(1 for r in RESULTS if r["verdict"] == "GAP")
    err = sum(1 for r in RESULTS if r["verdict"] == "ERROR")
    print("w254_approval_policy_probes: %d/%d HELD (%d GAP, %d ERROR)"
          % (held, len(RESULTS), gap, err))
    for r in RESULTS:
        print("  [%s] %s %s" % (r["verdict"], r["probe"], r["detail"]))
    if notes:
        print("  green checks: %s" % ("; ".join(notes),))
    return 0 if (gap == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
