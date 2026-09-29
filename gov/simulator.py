"""Policy simulator: replay a policy file against recorded run logs.

"What would this policy have decided for each historical action?" The
simulator reads ``actions.jsonl`` from one or more run directories and
re-evaluates every recorded tool call against a (possibly new) policy
file, then reports which decisions would have changed, grouped by
severity. This is the "what would have been denied last week" tool:
run it before deploying a policy change to see the blast radius.

The design mirrors OPA/Styra decision-log replay (each stored decision
keeps its input; replay re-evaluates the input under the current
policy) and decizense's policy_drift_report (batch replay -> drift
rate + examples).

    python -m gov.simulator <policy.yaml> --rundir <run dir>
    python -m gov.simulator <policy.yaml> --latest
    python -m gov.simulator <policy.yaml> --all

Fail-closed properties:

* READ-ONLY. The simulator opens logs with plain reads and never calls
  ``log.append`` or writes to a run directory. Report files go to
  ``reports/`` (or ``--out``).
* Never executes anything: it only calls ``PolicyEngine.evaluate``.
* Actions whose evaluation context cannot be reconstructed (older logs
  predate the ``policy_context`` snapshot; e.g. ``carries_read_content``
  depends on run-time read fingerprints) are reported as
  ``indeterminate`` and EXCLUDED from the diff counts. A missing input
  is never silently defaulted.
* Entries rejected BEFORE policy evaluation (identity/role/DLP/
  rate-guard rejections) log ``policy_context: None`` by design: the
  evaluation context did not exist yet (see ``gov/executor.py`` — the
  snapshot is only built immediately before ``policy.evaluate``).
  These go into a separate ``pre_policy`` bucket: counted in
  ``totals``/``run_summary`` and listed as info diffs, but EXCLUDED
  from ``actions``/``indeterminate``/``changed``. That is the honest
  bucketing — the policy never adjudicated these actions and never
  would, since the pre-policy gates run before policy evaluation under
  any policy version. Entries whose log predates the ``policy_context``
  key entirely (key absent) stay ``indeterminate``.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from .log import read_entries
from .policy import PolicyEngine
from .dlp import api_call_high_entropy_payload

# Recorded log decision -> coarse policy effect.
_OLD_EFFECT = {
    "execution_authorized": "allow",
    "allowed_executed": "allow",
    "approved_executed": "allow",
    "denied": "deny",
    "queued_pending": "require_approval",
}

# (old_effect, new_effect) -> (severity, label). Ordered by importance.
_DIFF_KIND = {
    ("deny", "allow"): ("critical", "weakened_deny",
                        "previously DENIED action would now be ALLOWED"),
    ("allow", "deny"): ("high", "breaking_change",
                        "previously allowed action would now be DENIED"),
    ("allow", "require_approval"): ("medium", "new_approval_required",
                                    "previously allowed action would now "
                                    "need approval"),
    ("deny", "require_approval"): ("medium", "deny_relaxed_to_approval",
                                   "previously denied action would now be "
                                   "queued for approval"),
    ("require_approval", "deny"): ("medium", "approval_tightened_to_deny",
                                   "previously queued action would now be "
                                   "DENIED"),
    ("require_approval", "allow"): ("low", "approval_removed",
                                    "previously queued action would now be "
                                    "allowed outright"),
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                   "info": 4}


def _reconstruct_context(entry, counters, policy):
    """Rebuild the evaluation context for one recorded tool call.

    Returns (action, context, indeterminate_reason). When a match key the
    new policy uses cannot be reconstructed, indeterminate_reason names
    it and the action must not be counted in the diff.
    """
    snap = entry.get("policy_context") or {}
    action = {
        "tool": entry.get("tool"),
        "args": entry.get("args") or {},
        "role": entry.get("role"),
        "agent_id": entry.get("agent_id"),
    }
    # Which context keys does the NEW policy actually consult? Only those
    # can make the replay indeterminate. Role/agent/tool are always on the
    # entry; the rest need the snapshot or a deterministic recomputation.
    #
    # Some match keys are DERIVED by the engine, not looked up in the
    # evaluation context (see gov/policy.py::_matches): ``path_contains_any``
    # is computed from action["args"]["path"] plus context["path_resolved"]
    # (F146: the symlink-resolved target, passed through from the
    # snapshot below), and the ``min_*`` keys are
    # thresholds over context["counters"], which the simulator already
    # supplies. They must not count as needed context — only the true
    # context lookups belong here.
    _DERIVED_MATCH_KEYS = {
        "path_contains_any",
        "min_external_calls",
        "min_sends",
        "min_writes",
        "min_deletes",
    }
    needed = set()
    for rule in policy.policies:
        for key in (rule.get("match") or {}):
            if key not in ("tool", "role", "agent", "when",
                           *_DERIVED_MATCH_KEYS):
                needed.add(key)
    unknown = []

    def _val(key):
        # A legitimate None snapshot value (e.g. path_outside_sandbox=None,
        # "inside the sandbox") is real input, not missing input: the engine
        # consults these keys via bool(context.get(...)), and bool(None)
        # == bool(False). Passing None straight through reproduces the
        # engine's semantics exactly; only a key ABSENT from the snapshot
        # is unreconstructible.
        if key in snap:
            return snap[key], None
        if key == "domain_allowlisted":
            # Deterministic from the NEW policy's egress allowlist +
            # the recorded args: no run-time state involved.
            return _domain_allowlisted_new_policy(policy, action), None
        if key == "source_untrusted":
            return (entry.get("provenance") == "untrusted_influenced"), None
        if key == "high_entropy_payload":
            # F99/F106: deterministic from the recorded args — the same
            # composed scan the executor runs
            # (dlp.api_call_high_entropy_payload: params strings
            # recursive + endpoint URL query values / path segments).
            # No run-time state is involved, so entries recorded before
            # the key existed stay reconstructible (unlike taint keys
            # such as carries_read_content, which honestly go
            # indeterminate). The snapshot, when present, is
            # authoritative (checked first above).
            return api_call_high_entropy_payload(
                action.get("args") or {}), None
        if key == "platform_egress":
            # F110 (wave-34): deterministic from the record shape. The
            # executor never sets platform_egress on tool calls — only
            # gov/platform_egress.py sets it on its own direct policy
            # calls, which create no action-log entry. Every replayed
            # action-log entry is a tool call, so the honest value is
            # None (bool(None)==False, the engine's semantics). No
            # run-time state involved; old entries stay reconstructible.
            return None, None
        if key == "read_classified":
            # Row-13 (2026-09-26): the classification taint did not exist
            # before this feature. The snapshot (checked first above) is
            # authoritative for new entries; an old entry whose snapshot
            # lacks the key predates the registry and hook, so the taint
            # could not have been set — honestly False, not indeterminate.
            # (Unlike carries_read_content, where absence means the capture
            # predates the snapshot contract but the taint mechanism
            # existed.)
            return False, None
        if key in ("artifact_unknown", "artifact_tampered",
                   "artifact_restricted"):
            # Row-12 (wave-130): the artifact inventory did not exist
            # before this feature. An old entry whose snapshot lacks
            # the key predates the inventory and the egress check, so
            # no artifact signal could have been set — honestly False.
            return False, None
        if key == "credential_identity_mismatch":
            # F111 (wave-34): deterministic False when the recorded args
            # carry nothing the identity check could trip on. The
            # executor's check_egress returns bound (False) whenever
            # there is no credential_id arg, no credential_owner arg,
            # and no DLP credential-shaped string among the TOP-LEVEL
            # string args (it does not recurse into nested dicts —
            # mirrored exactly here) — regardless of whether a session
            # identity was provisioned or what the manifest held.
            # Anything credential-bearing in the args honestly goes
            # indeterminate: the verdict then depended on
            # manifest/session state the entry does not record. The
            # snapshot, when present, is authoritative (checked first
            # above).
            args = action.get("args") or {}
            if ("credential_id" in args or "credential_owner" in args):
                return None, key
            from gov import dlp as _dlp_mod
            for value in args.values():
                if isinstance(value, str) and _dlp_mod.find_credential(
                        value):
                    return None, key
            return False, None
        return None, key

    context = {"role": action["role"], "agent": action["agent_id"]}
    # The replayed per-tool attempt counters approximate the engine's own
    # counters; the snapshot (when present) is authoritative — it is the
    # exact counter state the engine saw at decision time (the engine
    # counts every attempt, including pre-policy rejections, before any
    # gate runs).
    context["counters"] = dict(snap.get("counters") or counters)
    # F146: the symlink-resolved path target rides the snapshot so replay
    # evaluates path_contains_any exactly as the engine did. Entries
    # recorded before the key existed evaluate declared-only — which is
    # exactly what the pre-F146 engine did — so absence is not
    # indeterminacy.
    if "path_resolved" in snap:
        context["path_resolved"] = snap["path_resolved"]
    for key in needed:
        value, missing = _val(key)
        if missing:
            unknown.append(missing)
        else:
            context[key] = value
    reason = ("cannot reconstruct evaluation context: %s"
              % ", ".join(sorted(set(unknown)))) if unknown else None
    return action, context, reason


def _domain_allowlisted_new_policy(policy, action):
    """Recompute domain allowlisting under the NEW policy's egress config."""
    from urllib.parse import urlparse
    tool, args = action["tool"], action["args"] or {}
    allow = (policy.egress or {}).get("domain_allowlist") or []
    host = None
    try:
        if tool == "http_post":
            host = (urlparse(args.get("url") or "").hostname or "").lower()
        elif tool == "send_email":
            to = args.get("to") or ""
            host = to.rsplit("@", 1)[-1].lower() if "@" in to else None
        elif tool == "api_call":
            # F94: api_call destinations are allowlisted by policy —
            # evaluate its ``endpoint`` like http_post's ``url``.
            host = (urlparse(args.get("endpoint") or "").hostname
                    or "").lower()
    except Exception:
        host = None
    if not host:
        return False
    return any(host == d.lower() or host.endswith("." + d.lower())
               for d in allow)


def _old_effect(entry):
    return _OLD_EFFECT.get(entry.get("decision"))


def simulate_policy(policy_path, run_dirs):
    """Replay *policy_path* over the recorded logs of *run_dirs*.

    Returns a report dict; never mutates a log.
    """
    policy = PolicyEngine(str(policy_path))
    report = {
        "policy": str(policy_path),
        "policy_hash": policy.policy_hash,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "runs": [],
        "totals": {"actions": 0, "unchanged": 0, "changed": 0,
                   "indeterminate": 0, "rule_changed_only": 0,
                   "pre_policy": 0},
        "diffs": [],  # every changed action, grouped by severity at print time
    }
    for run_dir in run_dirs:
        run_dir = Path(run_dir)
        entries = read_entries(run_dir / "actions.jsonl")
        counters = {}
        run_summary = {"run_dir": str(run_dir), "actions": 0, "unchanged": 0,
                       "changed": 0, "indeterminate": 0, "rule_changed_only": 0,
                       "pre_policy": 0}
        for entry in entries:
            if entry.get("event") != "tool_call":
                continue
            old = _old_effect(entry)
            if old is None:
                continue  # not a policy decision entry (e.g. refusals)
            tool = entry.get("tool")
            counters[tool] = counters.get(tool, 0) + 1  # engine counts first
            if "policy_context" in entry and entry["policy_context"] is None:
                # Rejected BEFORE policy evaluation (identity/role/DLP/
                # rate-guard). The policy never adjudicated this action and
                # never would — the pre-policy gates run before the policy
                # under any policy version — so it is bucketed separately:
                # counted, listed as an info diff, and EXCLUDED from
                # actions/indeterminate/changed. (A log that predates the
                # policy_context key entirely still goes "indeterminate".)
                run_summary["pre_policy"] += 1
                report["totals"]["pre_policy"] += 1
                report["diffs"].append({
                    "severity": "info", "kind": "pre_policy",
                    "label": "rejected before policy evaluation "
                             "(policy never adjudicated); excluded from "
                             "diff counts",
                    "run_dir": str(run_dir), "seq": entry.get("seq"),
                    "agent_id": entry.get("agent_id"), "role": entry.get("role"),
                    "tool": tool, "old_effect": old, "new_effect": None,
                    "new_policy_id": None, "old_policy_id": entry.get("policy_id"),
                    "detail": entry.get("reason"),
                })
                continue
            run_summary["actions"] += 1
            report["totals"]["actions"] += 1
            action, context, indeterminate = _reconstruct_context(
                entry, counters, policy)
            if indeterminate:
                run_summary["indeterminate"] += 1
                report["totals"]["indeterminate"] += 1
                report["diffs"].append({
                    "severity": "info", "kind": "indeterminate",
                    "label": "context incomplete; excluded from diff counts",
                    "run_dir": str(run_dir), "seq": entry.get("seq"),
                    "agent_id": entry.get("agent_id"), "role": entry.get("role"),
                    "tool": tool, "old_effect": old, "new_effect": None,
                    "new_policy_id": None, "old_policy_id": entry.get("policy_id"),
                    "detail": indeterminate,
                })
                continue
            # Wave-198: a what-if simulation is hypothetical, not
            # enforcement -- its matches must never enter the mode
            # ledger's violation telemetry as graduation evidence.
            new = policy.evaluate(action, context, record_telemetry=False)
            if new.effect == old:
                if new.policy_id != entry.get("policy_id"):
                    run_summary["rule_changed_only"] += 1
                    report["totals"]["rule_changed_only"] += 1
                    report["diffs"].append({
                        "severity": "info", "kind": "rule_changed",
                        "label": "same effect, matched by a different rule",
                        "run_dir": str(run_dir), "seq": entry.get("seq"),
                        "agent_id": entry.get("agent_id"),
                        "role": entry.get("role"), "tool": tool,
                        "old_effect": old, "new_effect": new.effect,
                        "new_policy_id": new.policy_id,
                        "old_policy_id": entry.get("policy_id"),
                        "detail": "old rule %s -> new rule %s"
                                  % (entry.get("policy_id"), new.policy_id),
                    })
                else:
                    run_summary["unchanged"] += 1
                    report["totals"]["unchanged"] += 1
                continue
            severity, kind, label = _DIFF_KIND.get(
                (old, new.effect), ("medium", "effect_changed",
                                    "decision effect changed"))
            run_summary["changed"] += 1
            report["totals"]["changed"] += 1
            report["diffs"].append({
                "severity": severity, "kind": kind, "label": label,
                "run_dir": str(run_dir), "seq": entry.get("seq"),
                "agent_id": entry.get("agent_id"), "role": entry.get("role"),
                "tool": tool,
                "args_summary": {k: (str(v)[:60] if k != "content" else "<redacted>")
                                 for k, v in (action["args"] or {}).items()},
                "old_effect": old, "new_effect": new.effect,
                "old_policy_id": entry.get("policy_id"),
                "new_policy_id": new.policy_id,
                "new_reason": new.reason,
            })
        report["runs"].append(run_summary)
    report["diffs"].sort(key=lambda d: (_SEVERITY_ORDER[d["severity"]],
                                        d.get("seq") or 0))
    return report


def _print_report(report):
    t = report["totals"]
    print("Policy simulation: %s" % report["policy"])
    print("  policy hash: %s" % report["policy_hash"][:16])
    for r in report["runs"]:
        print("  run %s: %d actions (%d unchanged, %d changed, "
              "%d indeterminate, %d rule-changed-only, %d pre-policy)"
              % (Path(r["run_dir"]).name, r["actions"], r["unchanged"],
                 r["changed"], r["indeterminate"], r["rule_changed_only"],
                 r.get("pre_policy", 0)))
    print("TOTAL: %d actions, %d unchanged, %d changed, %d indeterminate, "
          "%d pre-policy"
          % (t["actions"], t["unchanged"], t["changed"],
             t["indeterminate"], t.get("pre_policy", 0)))
    last_sev = None
    for d in report["diffs"]:
        if d["severity"] != last_sev:
            last_sev = d["severity"]
            print("\n== %s ==" % last_sev.upper())
        print("  [%s] run=%s seq=%s %s/%s %s: %s -> %s (%s)"
              % (d["kind"], Path(d["run_dir"]).name, d.get("seq"),
                 d.get("agent_id"), d.get("role"), d.get("tool"),
                 d.get("old_effect"), d.get("new_effect"),
                 d.get("new_policy_id") or d.get("detail") or ""))
        if d.get("new_reason"):
            print("      new reason: %s" % d["new_reason"])


def _write_reports(report, out_dir, tag):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = out_dir / ("simulate-%s-%s" % (tag, ts))
    json_path = base.with_suffix(".json")
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=True,
                                    default=str), encoding="utf-8")
    lines = ["# Policy simulation report", "",
             "- policy: `%s`" % report["policy"],
             "- policy hash: `%s`" % report["policy_hash"],
             "- generated: %s" % report["generated_at"], ""]
    t = report["totals"]
    lines.append("## Totals")
    lines.append("")
    lines.append("| actions | unchanged | changed | indeterminate | "
                 "rule-changed-only | pre-policy |")
    lines.append("|---|---|---|---|---|---|")
    lines.append("| %d | %d | %d | %d | %d | %d |"
                 % (t["actions"], t["unchanged"], t["changed"],
                    t["indeterminate"], t["rule_changed_only"],
                    t.get("pre_policy", 0)))
    lines.append("")
    for sev in ("critical", "high", "medium", "low", "info"):
        group = [d for d in report["diffs"] if d["severity"] == sev]
        if not group:
            continue
        lines.append("## %s" % sev.upper())
        lines.append("")
        for d in group:
            lines.append("- **[%s]** run `%s` seq %s — %s/%s `%s`: "
                         "**%s** -> **%s** (%s). %s"
                         % (d["kind"], Path(d["run_dir"]).name, d.get("seq"),
                            d.get("agent_id"), d.get("role"), d.get("tool"),
                            d.get("old_effect"), d.get("new_effect"),
                            d.get("new_policy_id") or d.get("detail") or "",
                            d.get("label", "")))
            if d.get("new_reason"):
                lines.append("  - new reason: %s" % d["new_reason"])
        lines.append("")
    md_path = base.with_suffix(".md")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def _resolve_run_dirs(args, root):
    runs = root / "runs"
    if args.rundir:
        return [Path(a) for a in args.rundir]
    cands = [d for d in runs.iterdir()] if runs.exists() else []
    cands = [d for d in cands if d.is_dir() and (d / "actions.jsonl").exists()]
    if args.all:
        if not cands:
            raise SystemExit("no runs with actions.jsonl found")
        return sorted(cands, key=lambda d: d.name)
    if not cands:
        raise SystemExit("no runs found; run python demo/run_demo.py first")
    return [max(cands, key=lambda d: d.stat().st_mtime)]


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="gov.simulator",
        description="Replay a policy file against recorded run logs: "
                    "what would this policy have decided for each "
                    "historical action?",
    )
    parser.add_argument("policy", help="policy YAML file to simulate")
    parser.add_argument("--rundir", action="append", default=None,
                        help="run directory (repeatable; default: --latest)")
    parser.add_argument("--latest", action="store_true",
                        help="use the most recent run")
    parser.add_argument("--all", action="store_true",
                        help="simulate every run in runs/")
    parser.add_argument("--out", default=None,
                        help="directory for the JSON/Markdown diff report "
                             "(default: reports/)")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    policy_path = Path(args.policy)
    if not policy_path.is_absolute():
        policy_path = root / policy_path
    if not policy_path.exists():
        raise SystemExit("policy file not found: %s" % args.policy)
    run_dirs = _resolve_run_dirs(args, root)
    report = simulate_policy(str(policy_path), run_dirs)
    _print_report(report)
    tag = "multi" if len(run_dirs) > 1 else Path(run_dirs[0]).name
    out_dir = Path(args.out) if args.out else root / "reports"
    json_path, md_path = _write_reports(report, out_dir, tag)
    print("\nreport written: %s" % json_path)
    print("report written: %s" % md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
