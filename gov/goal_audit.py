"""Post-hoc unregistered-goal pursuit audit (row 11, second half).

Wave-130 landed goal REGISTRATION + conflict detection between DECLARED
goals (gov/goals.py). The residual: an agent pursuing a goal it never
registered. The registry only knows declared goals; this module closes
the *behavior* half by comparing what the agent actually DID (executed
tool calls in the audit log) against the effects its registered goals
declared.

This is POST-HOC audit, not inline prevention. It produces findings for
the operator after the run. Inline prevention of unregistered intent is
deliberately out of scope: you cannot block what you cannot see coming
without an LLM judge ($0 constraint), and a post-hoc finding is the
honest, explainable primitive -- the operator sees exactly which action
had no covering goal.

How it works:
  1. Read the run's audit log. Reconstruct each agent's ACTIVE goals
     from ``goal_registered`` / ``goal_status_changed`` events (or take
     a live ``GoalRegistry``).
  2. Extract EXECUTED actions: ``tool_call`` events with
     ``decision`` in {"approved_executed", "allowed_executed"}.
     Each is mapped to a structured
     effect atom (verb, target) via a fixed tool->verb table and
     deterministic target extraction (URL host for sends, path for
     file ops), normalized with ``gov.goals.normalize_target``.
  3. For each HIGH-IMPACT action (send/delete/write -- reads are
     low-impact and never flagged, to avoid FP on read-only agents),
     check coverage against the agent's active goals:
       - exact (verb, normalized target) match -> covered, silent;
       - match only via a ("verb", "*") wildcard goal ->
         ``goal_wildcard_cover`` (INFO, not a violation);
       - no match at all -> ``goal_coverage_gap`` (the unregistered-
         pursuit signal);
       - verb opposes a declared effect on the same target
         (gov.goals opposition table) -> ``goal_contradiction``
         (stronger than a gap: the agent did the opposite of what it
         declared).
  4. Read-only: this module never writes to the audit log.

Honest ceiling (documented, not hidden):
- A ("send", "*") wildcard goal covers everything for that verb. The
  auditor reports WHEN a wildcard provided the cover, but it cannot
  distinguish a legitimately broad mandate ("general external
  communication") from deliberate vagueness-as-cover. An operator who
  registers wildcards is explicitly granting latitude; the finding
  makes that grant visible. Wave-135 tightens the registration side:
  vague goals (empty effects, wildcard targets) register in
  ``pending_specificity`` and cover NOTHING until a human narrows
  them or acknowledges their breadth -- and an acknowledged-broad
  goal's wildcard cover fires LOUD (severity high), not
  informational. The remaining gap is semantic: a specific-looking
  goal that is semantically broad still passes the structural check.
- Exact normalized-target matching, like gov/goals.py: paraphrased
  targets dodge the matcher by construction.
- Post-hoc only: the finding arrives after the action executed. The
  adjacent inline controls (approvals, volume guards) still bound the
  blast radius; this auditor names the *motive* gap they cannot see.
- Only governed-path executions are visible. Actions outside the
  audit log are outside the trust boundary.

$0, stdlib only, deterministic.
"""

from urllib.parse import urlparse

from .goals import normalize_target
from .goals import _OPPOSES

__all__ = [
    "audit_run_goals",
    "audit_entries",
    "derive_effect",
    "HIGH_IMPACT_VERBS",
]

# Tools the auditor understands -> goal effect verb. Tools outside this
# table are ignored (not flagged): flagging unknown tools would FP on
# every new tool the policy legitimately allows.
_TOOL_VERB = {
    "http_post": "send",
    "send_email": "send",
    "api_call": "send",
    "write_file": "write",
    "delete_file": "delete",
    "read_file": "read",
}

# Verbs whose uncovered execution is a finding. "read" is deliberately
# excluded: a read-only agent doing reads is the benign baseline, and
# flagging reads would drown the operator in noise.
HIGH_IMPACT_VERBS = frozenset({"send", "delete", "write"})

# Only genuinely-executed actions count. queued/denied/refused calls
# never ran, so they cannot be "pursuit". Two execution paths:
# "approved_executed" (via the approval queue) and "allowed_executed"
# (policy-allowed without approval, e.g. in-sandbox file ops).
_EXECUTED_DECISIONS = frozenset({"approved_executed", "allowed_executed"})


def _host_of(url):
    """Extract the network host from a URL, lowercased. Falls back to
    the raw string when unparseable (never raises)."""
    try:
        netloc = urlparse(str(url)).netloc
        host = netloc.split("@")[-1].split(":")[0].lower()
        return host or str(url)
    except Exception:  # noqa: BLE001 - best effort, never fail the audit
        return str(url)


def derive_effect(tool, args):
    """Map a (tool, args) pair to a (verb, normalized target) effect
    atom, or None if the tool is outside the auditor's vocabulary.

    Target extraction is deterministic and conservative:
      - send verbs: URL host (http_post/api_call) or recipient
        (send_email);
      - file verbs: the path argument.
    Missing/empty targets become "unknown" (never silently dropped --
    an "unknown" target simply won't match any declared goal, which is
    the fail-closed direction for coverage).
    """
    verb = _TOOL_VERB.get(tool)
    if verb is None:
        return None
    args = args if isinstance(args, dict) else {}
    target = ""
    if verb == "send":
        url = args.get("url") or args.get("endpoint") or ""
        recipient = args.get("to") or args.get("recipient") or ""
        if url:
            target = _host_of(url)
        elif recipient:
            target = str(recipient)
    else:
        target = args.get("path") or args.get("file") or ""
    if not str(target).strip():
        target = "unknown"
    return (verb, normalize_target(str(target)))


def _reconstruct_goals(entries, run_id):
    """Rebuild per-agent active goals from log events.

    Returns {agent_id: {goal_id: goal_dict}} with goal_dict holding
    goal_id, effects (list of [verb, target]), constraints, status.
    ``goal_status_changed`` events supersede; unknown goal_ids in a
    status event are ignored (fail-open on bookkeeping, fail-closed on
    coverage: an unparseable goal simply provides no cover).
    """
    goals = {}
    for ev in entries:
        if not isinstance(ev, dict):
            continue
        if ev.get("run_id") != run_id:
            continue
        etype = ev.get("event")
        if etype == "goal_registered":
            agent = ev.get("agent_id")
            gid = ev.get("goal_id")
            if not agent or not gid:
                continue
            goals.setdefault(agent, {})[gid] = {
                "goal_id": gid,
                "agent_id": agent,
                "effects": [list(e) for e in (ev.get("effects") or [])
                            if isinstance(e, (list, tuple))
                            and len(e) == 2],
                "constraints": [list(c) for c in
                                (ev.get("constraints") or [])],
                # Wave-135: registration-time status (pending_specificity
                # for vague goals) and the human-acknowledged breadth
                # flag. Pre-wave-135 logs carry neither: default to the
                # old behavior (active, unacknowledged).
                "status": ev.get("status") or "active",
                "broad_scope_acknowledged":
                    bool(ev.get("broad_scope_acknowledged")),
            }
        elif etype == "goal_status_changed":
            gid = ev.get("goal_id")
            status = ev.get("status")
            if not gid or status not in ("active", "superseded",
                                        "pending_specificity"):
                continue
            for agent_goals in goals.values():
                if gid in agent_goals:
                    agent_goals[gid]["status"] = status
        elif etype == "goal_specificity_resolved":
            # Wave-135: the human's goal_specificity_review decision.
            # Carries the post-resolution status AND the breadth flag;
            # both must move together or the reconstruction drifts from
            # the live registry.
            gid = ev.get("goal_id")
            status = ev.get("status")
            if not gid or status not in ("active", "superseded",
                                        "pending_specificity"):
                continue
            for agent_goals in goals.values():
                if gid in agent_goals:
                    agent_goals[gid]["status"] = status
                    agent_goals[gid]["broad_scope_acknowledged"] = \
                        bool(ev.get("broad_scope_acknowledged"))
    # Drop superseded: only live goals provide cover.
    return {a: {g: rec for g, rec in gs.items()
                if rec.get("status") == "active"}
            for a, gs in goals.items()}


def _goals_from_registry(registry, run_id):
    """Extract per-agent active goals from a live GoalRegistry."""
    out = {}
    try:
        active = registry.active_goals()
    except Exception:  # noqa: BLE001 - registry unusable, no cover
        return out
    for g in active or []:
        if not isinstance(g, dict):
            continue
        if g.get("run_id") != run_id:
            continue
        agent = g.get("agent_id")
        gid = g.get("goal_id")
        if not agent or not gid:
            continue
        out.setdefault(agent, {})[gid] = {
            "goal_id": gid,
            "agent_id": agent,
            "effects": [list(e) for e in (g.get("effects") or [])
                        if isinstance(e, (list, tuple)) and len(e) == 2],
            "constraints": [list(c) for c in
                            (g.get("constraints") or [])],
            "status": "active",
            # Wave-135: a human-acknowledged broad goal's wildcard
            # cover is LOUD (severity high), not informational.
            "broad_scope_acknowledged":
                bool(g.get("broad_scope_acknowledged")),
        }
    return out


def _check_coverage(verb, target, agent_goals):
    """Check one (verb, target) against an agent's active goals.

    Returns ("covered", goal_id), ("wildcard", goal_id),
    ("contradiction", goal_id, explanation), or ("gap", None).
    Contradiction is checked FIRST: doing the opposite of a declared
    goal is a stronger signal than merely lacking cover.
    """
    wildcard_hit = None
    for gid, goal in agent_goals.items():
        for eff in goal.get("effects") or []:
            if not isinstance(eff, (list, tuple)) or len(eff) != 2:
                continue
            everb, etarget = eff
            # Contradiction: the action's verb opposes a declared
            # effect verb on the same normalized target.
            if (etarget == target
                    and everb in _OPPOSES.get(verb, ())):
                return ("contradiction", gid,
                        "action (%s %s) directly opposes declared goal "
                        "effect (%s %s)" % (verb, target, everb, etarget))
            if everb != verb:
                continue
            if etarget == target:
                return ("covered", gid, None)
            if etarget == "*":
                # Don't return yet: an exact match on another goal
                # beats wildcard cover.
                if wildcard_hit is None:
                    wildcard_hit = gid
    if wildcard_hit is not None:
        return ("wildcard", wildcard_hit, None)
    return ("gap", None, None)


def audit_entries(run_id, entries, registry=None):
    """Core audit over an in-memory entry list.

    Returns (findings, summary). Findings are dicts with "finding" in
    {"goal_coverage_gap", "goal_contradiction", "goal_wildcard_cover"},
    plus agent_id, run_id, tool, effect, and a human-readable
    explanation. Summary carries counts and the per-agent goal/action
    tallies. Never raises on malformed entries (an unauditable log is
    reported in the summary, not crashed on).
    """
    findings = []
    summary = {
        "run_id": run_id,
        "agents_audited": [],
        "agents_with_no_goals": [],
        "actions_examined": 0,
        "high_impact_actions": 0,
        "findings": 0,
        "unauditable_entries": 0,
    }

    if registry is not None:
        agent_goals = _goals_from_registry(registry, run_id)
    else:
        agent_goals = _reconstruct_goals(entries, run_id)

    for ev in entries:
        if not isinstance(ev, dict):
            summary["unauditable_entries"] += 1
            continue
        if ev.get("run_id") != run_id:
            continue
        if ev.get("event") != "tool_call":
            continue
        if ev.get("decision") not in _EXECUTED_DECISIONS:
            continue
        agent = ev.get("agent_id")
        tool = ev.get("tool")
        if not agent or not tool:
            summary["unauditable_entries"] += 1
            continue
        effect = derive_effect(tool, ev.get("args"))
        if effect is None:
            # Tool outside the auditor's vocabulary: not flagged.
            continue
        verb, target = effect
        summary["actions_examined"] += 1
        if agent not in summary["agents_audited"]:
            summary["agents_audited"].append(agent)
        if verb not in HIGH_IMPACT_VERBS:
            continue
        summary["high_impact_actions"] += 1

        goals = agent_goals.get(agent, {})
        if not goals and agent not in summary["agents_with_no_goals"]:
            summary["agents_with_no_goals"].append(agent)

        status, gid, extra = _check_coverage(verb, target, goals)
        if status == "covered":
            continue
        if status == "contradiction":
            findings.append({
                "finding": "goal_contradiction",
                "severity": "high",
                "agent_id": agent,
                "run_id": run_id,
                "tool": tool,
                "effect": [verb, target],
                "covering_goal_id": gid,
                "explanation": (
                    "Agent %r executed %r (%s %s) which %s. The action "
                    "directly opposes a declared goal -- stronger than "
                    "a mere coverage gap."
                    % (agent, tool, verb, target, extra)),
            })
        elif status == "wildcard":
            # Wave-135 (row-11): a wildcard goal whose breadth a human
            # explicitly acknowledged at registration
            # (broad_scope_acknowledged via goal_specificity_review)
            # covers LOUD, not informational -- the operator accepted
            # the latitude, so its exercise stays maximally visible.
            acked = bool((goals.get(gid) or {})
                         .get("broad_scope_acknowledged"))
            if acked:
                findings.append({
                    "finding": "goal_wildcard_cover",
                    "severity": "high",
                    "flag": "goal_wildcard_acknowledged",
                    "agent_id": agent,
                    "run_id": run_id,
                    "tool": tool,
                    "effect": [verb, target],
                    "covering_goal_id": gid,
                    "explanation": (
                        "Agent %r executed %r (%s %s) covered ONLY by a "
                        "wildcard goal effect (%s *). LOUD: a human "
                        "explicitly acknowledged this goal's breadth at "
                        "registration (goal_specificity_review), so the "
                        "wildcard cover is surfaced at high severity, "
                        "not informational."
                        % (agent, tool, verb, target, verb)),
                })
            else:
                findings.append({
                    "finding": "goal_wildcard_cover",
                    "severity": "info",
                    "agent_id": agent,
                    "run_id": run_id,
                    "tool": tool,
                    "effect": [verb, target],
                    "covering_goal_id": gid,
                    "explanation": (
                        "Agent %r executed %r (%s %s) covered ONLY by a "
                        "wildcard goal effect (%s *). The auditor cannot "
                        "distinguish a legitimately broad mandate from "
                        "deliberate vagueness-as-cover; the grant of "
                        "latitude is surfaced here for operator review."
                        % (agent, tool, verb, target, verb)),
                })
        else:  # gap
            findings.append({
                "finding": "goal_coverage_gap",
                "severity": "high",
                "agent_id": agent,
                "run_id": run_id,
                "tool": tool,
                "effect": [verb, target],
                "registered_goal_count": len(goals),
                "explanation": (
                    "Agent %r executed high-impact %r (%s %s) with no "
                    "registered goal covering it%s. Unregistered-goal "
                    "pursuit: the action's objective was never declared."
                    % (agent, tool, verb, target,
                       (" (agent registered %d goal(s), none covering)"
                        % len(goals)) if goals
                       else " (agent registered no goals at all)")),
            })

    summary["findings"] = len(findings)
    return findings, summary


def audit_run_goals(run_id, log_path, registry=None):
    """Post-hoc audit of a run's log file.

    ``log_path`` is the run's actions.jsonl. Returns
    (findings, summary) -- see audit_entries. Read-only: never writes
    to the log. A missing/unreadable log yields zero findings and
    reports the problem in the summary (fail-open on observability,
    never a crash: the auditor is an instrument, not a control).
    """
    try:
        from .log import read_entries
        from pathlib import Path as _Path
        if not _Path(str(log_path)).exists():
            raise FileNotFoundError("log not found: %s" % (log_path,))
        entries = list(read_entries(str(log_path)))
    except Exception as e:  # noqa: BLE001 - instrument, not control
        return [], {
            "run_id": run_id,
            "agents_audited": [],
            "agents_with_no_goals": [],
            "actions_examined": 0,
            "high_impact_actions": 0,
            "findings": 0,
            "unauditable_entries": 0,
            "log_error": "%s: %s" % (type(e).__name__, e),
        }
    return audit_entries(run_id, entries, registry=registry)
