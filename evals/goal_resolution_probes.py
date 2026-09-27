#!/usr/bin/env python3
"""Row-11 approval-decision -> goal-resolution wiring probes (wave-134 lane).

Row 11's pinned residual: approving a ``goal_conflict_review`` item did
not itself update goal status; ``resolve_goal`` was a separate manual
step. A human could approve the review thinking the conflict was
resolved while both goals stayed active and the conflict re-fired.

This battery exercises the wiring that closes the *mechanics* half of
that gap: a DECIDED ``goal_conflict_review`` item now resolves the
underlying conflict automatically --

  p1_allow_resolves: conflict fires, human allows -> the new goal
     stands (active), the conflicting existing goal is superseded via
     the set_status path; the goal_status_changed events carry the
     approval_id and the approval_decision event carries the goal ids
     (cross-referenced both ways).
  p2_deny_supersedes_new: conflict fires, human denies -> the new goal
     is superseded; the existing goal stands untouched.
  p3_already_resolved_noop: the conflict is resolved separately first
     (resolve_goal), THEN the human decides the review -> the decision
     still records, a LOUD goal_resolution_noop fires, no crash, no
     silent skip, no status re-application.
  p4_unrelated_isolation: an unrelated (non-goal) approval decision
     touches no goal and emits no goal-resolution events.
  p5_unknown_goal_noop: apply_approval_resolution at the goals seam
     with goal ids unknown to the registry -> LOUD
     goal_resolution_noop for each, no raise, no phantom transitions.
  p6_hook_failure_safe: a raising post-decision hook never breaks
     decide() -- the decision records and a LOUD decision_hook_failed
     event is chained.

Honest ceiling (measured, not hidden): the wiring automates the
mechanics, not the judgment -- a human who allows without reading
still allows. Nothing here second-guesses the human.

Verdicts:
- HELD  = the expected signal fired (or correctly did not fire).
- BREAK = the expected wiring did not fire (a miss the feature
          claims to close).
- ERROR = probe/instrumentation problem.

$0 spend, synthetic/local, deterministic. Stdlib only.

Run:
  mkdir -p /tmp/gov-goalres
  TMPDIR=/tmp/gov-goalres ~/workspace/.gov-venv/bin/python evals/goal_resolution_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-goalresb ~/workspace/.gov-venv/bin/python evals/goal_resolution_probes.py
"""

import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "goal-resolution-break")
os.environ.setdefault("TMPDIR", "/tmp/gov-goalres")
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import goals as _goals  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.policy import PolicyEngine, PolicyDecision  # noqa: E402
from gov.identity import AgentIdentity  # noqa: E402

DEFAULT_POLICY = Path(REPO_ROOT) / "policies" / "default.yaml"
PRINCIPAL = "user-1"
POST_URL = "https://vendor.synthetic.local/sync"

_UNGOVERNED_ACK = (
    "row11 goal-resolution eval: synthetic red-team harness; raw "
    "pre-wave-74/75 pipeline by design, declared and chained")


# ---------------------------------------------------------------------------
# Session plumbing
# ---------------------------------------------------------------------------

def _session():
    run_dir = Path(tempfile.mkdtemp(prefix="govgoalres-",
                                    dir=os.environ["TMPDIR"]))
    policy = PolicyEngine(str(DEFAULT_POLICY))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(run_dir, policy, log, approvals,
                      ledger_path=run_dir / "egress_ledger.jsonl",
                      ungoverned_ack=_UNGOVERNED_ACK)
    return {"run_dir": run_dir, "executor": ex, "log": log,
            "approvals": approvals}


def _events(ctx, *names):
    hits = []
    for ev in read_entries(ctx["run_dir"] / "actions.jsonl"):
        if isinstance(ev, dict) and ev.get("event") in names:
            hits.append(ev)
    return hits


def _conflict_approvals(ctx):
    return [r for r in ctx["approvals"].all()
            if r.get("policy_flag") == "goal_conflict"
            or r.get("tool") == "goal_conflict_review"]


def _register_conflict(ctx):
    """Register A:preserve / B:delete(temp files); return (g_new, g_old, aid)."""
    ex = ctx["executor"]
    ident_a = ex.mint_identity("agent-a", "worker", PRINCIPAL)
    ident_b = ex.mint_identity("agent-b", "worker", PRINCIPAL)
    g_old, c1 = ex.register_goal(
        "agent-a", "preserve temp files for audit",
        effects=[("preserve", "temp files")], identity=ident_a)
    assert not c1, "first registration unexpectedly conflicted: %r" % (c1,)
    g_new, c2 = ex.register_goal(
        "agent-b", "delete all temp files",
        effects=[("delete", "temp files")], identity=ident_b)
    if not c2:
        raise AssertionError("conflict did not fire")
    queued = _conflict_approvals(ctx)
    if not queued:
        raise AssertionError("goal_conflict_review not queued")
    return g_new, g_old, queued[0]["id"], ident_a, ident_b


def _decide(ctx, aid, approved):
    return ctx["approvals"].decide(
        aid, approved,
        "probe: human %s the conflict review" % ("allows" if approved
                                                 else "denies"),
        decided_by="human-operator")


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def p1_allow_resolves():
    """Conflict -> human allows: new goal active, old superseded,
    events cross-reference both ways."""
    ctx = _session()
    ex = ctx["executor"]
    g_new, g_old, aid, _ia, _ib = _register_conflict(ctx)
    new_id, old_id = g_new["goal_id"], g_old["goal_id"]

    rec, _entry = _decide(ctx, aid, True)

    # New goal stands, old goal superseded.
    st_new = ex._goal_registry.get_goal(new_id)["status"]
    st_old = ex._goal_registry.get_goal(old_id)["status"]
    if st_new != "active":
        return ("BREAK", "allow: new goal status %r, expected 'active'"
                % (st_new,))
    if st_old != "superseded":
        return ("BREAK", "allow: old goal status %r, expected 'superseded'"
                % (st_old,))

    # goal_status_changed events carry the approval id.
    changed = _events(ctx, "goal_status_changed")
    old_changed = [e for e in changed if e.get("goal_id") == old_id]
    if not old_changed:
        return ("BREAK", "allow: no goal_status_changed for the old goal")
    if old_changed[-1].get("approval_id") != aid:
        return ("BREAK", "allow: status event missing approval_id %r "
                "(got %r)" % (aid, old_changed[-1].get("approval_id")))

    # The approval_decision event carries the goal ids.
    decisions = _events(ctx, "approval_decision")
    dec = [e for e in decisions if e.get("approval_id") == aid]
    if not dec:
        return ("BREAK", "allow: no approval_decision event for %r" % (aid,))
    gids = dec[-1].get("goal_ids") or []
    if new_id not in gids or old_id not in gids:
        return ("BREAK", "allow: decision event goal_ids %r missing %r/%r"
                % (gids, new_id, old_id))

    # Summary event present.
    if not _events(ctx, "goal_resolution"):
        return ("BREAK", "allow: no goal_resolution summary event")
    return ("HELD", "allow: new active, old superseded, approval_id on "
            "status events, goal_ids on the decision event")


def p2_deny_supersedes_new():
    """Conflict -> human denies: the new goal is superseded, the
    existing goal stands untouched."""
    ctx = _session()
    ex = ctx["executor"]
    g_new, g_old, aid, _ia, _ib = _register_conflict(ctx)
    new_id, old_id = g_new["goal_id"], g_old["goal_id"]

    _decide(ctx, aid, False)

    st_new = ex._goal_registry.get_goal(new_id)["status"]
    st_old = ex._goal_registry.get_goal(old_id)["status"]
    if st_new != "superseded":
        return ("BREAK", "deny: new goal status %r, expected 'superseded'"
                % (st_new,))
    if st_old != "active":
        return ("BREAK", "deny: old goal status %r, expected untouched "
                "'active'" % (st_old,))
    changed = _events(ctx, "goal_status_changed")
    new_changed = [e for e in changed if e.get("goal_id") == new_id]
    if not new_changed or new_changed[-1].get("approval_id") != aid:
        return ("BREAK", "deny: new-goal status event missing approval_id")
    if [e for e in changed if e.get("goal_id") == old_id]:
        return ("BREAK", "deny: old goal got a status change it should not "
                "have")
    return ("HELD", "deny: new goal superseded with approval_id on the "
            "status event; old goal untouched")


def p3_already_resolved_noop():
    """Conflict resolved separately first (resolve_goal), THEN the
    human decides the review: the decision still records, a LOUD
    goal_resolution_noop fires, nothing crashes, no status is
    re-applied."""
    ctx = _session()
    ex = ctx["executor"]
    g_new, g_old, aid, _ia, _ib = _register_conflict(ctx)
    new_id, old_id = g_new["goal_id"], g_old["goal_id"]

    # Human (or operator tooling) resolves the old goal separately.
    ex.resolve_goal(old_id, "superseded", note="resolved before deciding")

    n_changed_before = len(_events(ctx, "goal_status_changed"))
    _decide(ctx, aid, True)  # allow: would supersede the old goal again
    n_changed_after = len(_events(ctx, "goal_status_changed"))
    if n_changed_after != n_changed_before:
        return ("BREAK", "already-resolved: decide() re-applied a status "
                "change (%d -> %d)" % (n_changed_before, n_changed_after))

    noops = _events(ctx, "goal_resolution_noop")
    if not noops:
        return ("BREAK", "already-resolved: no goal_resolution_noop event "
                "-- the skip was silent")
    if not any(e.get("flag") == "goal_resolution_noop" for e in noops):
        return ("BREAK", "already-resolved: noop event not LOUD")
    if not any(e.get("approval_id") == aid and e.get("goal_id") == old_id
               for e in noops):
        return ("BREAK", "already-resolved: noop event does not name the "
                "approval and goal")
    # The decision itself still recorded.
    dec = [e for e in _events(ctx, "approval_decision")
           if e.get("approval_id") == aid]
    if not dec:
        return ("BREAK", "already-resolved: the decision was not recorded")
    if ex._goal_registry.get_goal(new_id)["status"] != "active":
        return ("BREAK", "already-resolved: new goal no longer active")
    return ("HELD", "already-resolved: decision recorded, LOUD "
            "goal_resolution_noop, no re-application")


def p4_unrelated_isolation():
    """Deciding a non-goal approval touches no goal and emits no
    goal-resolution events."""
    ctx = _session()
    ex = ctx["executor"]
    ident = ex.mint_identity("agent-c", "researcher", PRINCIPAL)
    g_new, g_old, gaid, _ia, _ib = _register_conflict(ctx)
    new_id, old_id = g_new["goal_id"], g_old["goal_id"]

    res = ex.call(ident, "http_post", url=POST_URL, payload={"k": "v"})
    if res.get("status") != "queued":
        return ("ERROR", "http_post did not queue: %r" % (res,))
    aid = res["approval_id"]
    ctx["approvals"].decide(aid, True, "probe: unrelated approve",
                            decided_by="human-operator")

    if _events(ctx, "goal_status_changed", "goal_resolution",
               "goal_resolution_noop"):
        return ("BREAK", "unrelated decision emitted goal-resolution "
                "events")
    if (ex._goal_registry.get_goal(new_id)["status"] != "active"
            or ex._goal_registry.get_goal(old_id)["status"] != "active"):
        return ("BREAK", "unrelated decision changed a goal status")
    if not _conflict_approvals(ctx):
        return ("BREAK", "the conflict review vanished")
    return ("HELD", "unrelated approval decided: no goal touched, no "
            "resolution events")


def p5_unknown_goal_noop():
    """apply_approval_resolution at the goals seam with goal ids the
    registry never saw: LOUD noop per id, no raise, no transitions."""
    run_dir = Path(tempfile.mkdtemp(prefix="govgoalres-seam-",
                                    dir=os.environ["TMPDIR"]))
    log = ActionLog(run_dir / "actions.jsonl")
    reg = _goals.GoalRegistry(audit=log.append)
    g, _c = reg.register("agent-z", "run-z", "preserve temp files",
                         effects=[("preserve", "temp files")])
    real_id = g["goal_id"]

    summary = _goals.apply_approval_resolution(
        reg, new_goal_id="goal-does-not-exist",
        existing_goal_ids=["goal-also-missing"],
        approved=True, approval_id="appr-bogus", audit=log.append)

    evs = list(read_entries(run_dir / "actions.jsonl"))
    noops = [e for e in evs
             if isinstance(e, dict)
             and e.get("event") == "goal_resolution_noop"]
    if len(noops) < 2:
        return ("BREAK", "unknown ids: expected >=2 noops, saw %d"
                % len(noops))
    if not all(e.get("flag") == "goal_resolution_noop" for e in noops):
        return ("BREAK", "unknown ids: noop events not LOUD")
    if reg.get_goal(real_id)["status"] != "active":
        return ("BREAK", "unknown ids: the REAL existing goal got "
                "superseded anyway")
    if [e for e in evs
            if isinstance(e, dict)
            and e.get("event") == "goal_status_changed"]:
        return ("BREAK", "unknown ids: a status change was chained")
    if len(summary["noop"]) < 2:
        return ("BREAK", "unknown ids: summary missing noop entries")
    return ("HELD", "unknown goal ids: LOUD noop per id, no raise, no "
            "phantom transitions")


def p6_hook_failure_safe():
    """A raising post-decision hook never breaks decide(): the decision
    records and a LOUD decision_hook_failed event is chained."""
    run_dir = Path(tempfile.mkdtemp(prefix="govgoalres-hook-",
                                    dir=os.environ["TMPDIR"]))
    log = ActionLog(run_dir / "actions.jsonl")
    q = ApprovalQueue(run_dir, log)
    # Bare queue: simulate the deployment wiring (the executor normally
    # installs its minted-identity verifier at construction) so queue()
    # accepts the test identity.
    q.set_identity_verifier(lambda _ident: True)

    def _boom(*_a):
        raise RuntimeError("synthetic hook failure")

    q.set_decision_hook(_boom)
    ident = AgentIdentity(agent_id="hook-test", role="worker",
                         run_id=run_dir.name, principal=PRINCIPAL)
    aid = q.queue(
        {"tool": "http_post", "args": {"url": POST_URL},
         "redactions": []},
        PolicyDecision("require_approval", "hook failure test"),
        "agent_direct", "preview", caller_identity=ident)

    try:
        rec, _entry = q.decide(aid, True, "probe: hook must not break",
                               decided_by="human-operator")
    except Exception as e:  # noqa: BLE001 - the point is it must not raise
        return ("BREAK", "decide() raised through a failing hook: %s: %s"
                % (type(e).__name__, e))
    if rec.get("status") != "approved":
        return ("BREAK", "decision did not record as approved")
    evs = list(read_entries(run_dir / "actions.jsonl"))
    fails = [e for e in evs
             if isinstance(e, dict)
             and e.get("event") == "decision_hook_failed"]
    if not fails:
        return ("BREAK", "hook failure not audited (silent swallow)")
    if not any(e.get("flag") == "decision_hook_failed" for e in fails):
        return ("BREAK", "decision_hook_failed not LOUD")
    return ("HELD", "raising hook: decision recorded, LOUD "
            "decision_hook_failed, decide() returned normally")


_PROBES = [
    ("p1_allow_resolves", p1_allow_resolves),
    ("p2_deny_supersedes_new", p2_deny_supersedes_new),
    ("p3_already_resolved_noop", p3_already_resolved_noop),
    ("p4_unrelated_isolation", p4_unrelated_isolation),
    ("p5_unknown_goal_noop", p5_unknown_goal_noop),
    ("p6_hook_failure_safe", p6_hook_failure_safe),
]


def main():
    n_break = n_held = n_err = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 - battery must not crash
            verdict, detail = ("ERROR", "%s: %s"
                               % (type(e).__name__, e))
        mark = {"HELD": "HELD", "BREAK": "BREAK",
                "ERROR": "ERROR"}.get(verdict, "NOTE")
        print("  %-38s %-6s %s" % (name, mark, detail))
        if verdict == "BREAK":
            n_break += 1
        elif verdict == "HELD":
            n_held += 1
        elif verdict == "ERROR":
            n_err += 1
    print("----")
    print("%d/%d HELD, %d BREAK, %d ERROR"
          % (n_held, len(_PROBES), n_break, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
