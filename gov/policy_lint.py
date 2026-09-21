"""Policy linter: catch dead, shadowed, and contradictory rules before deploy.

Run ``python -m gov.policy_lint policies/default.yaml`` (or the
``gov-policy-lint`` console script). Exits 0 when no findings, 1 otherwise.

Findings kinds:
  unknown_tool       match.tool names a tool that does not exist
  unknown_match_key  match uses a key the engine does not understand
  invalid_effect     effect is not allow/deny/require_approval
  shadowed_rule      a higher-precedence rule (deny > require_approval >
                     allow; same effect + earlier in file) matches a superset
                     of this rule's conditions, so this rule never fires
  contradictory_rule two rules with identical conditions but different effects
"""

import json
import sys
from pathlib import Path

from .policy import (KNOWN_MATCH_KEYS, KNOWN_TOOLS, VALID_EFFECTS,
                     _EFFECT_RANK, _as_list)
from .yamlmini import load as yaml_load


def _covers(sup, sub):
    """Conservative superset check: does *sup*'s match cover *sub*'s?"""
    for key, sub_val in sub.items():
        if key not in KNOWN_MATCH_KEYS:
            return False  # unknown semantics: do not claim coverage
        if key == "tool":
            sup_tools = set(_as_list(sup.get("tool"))) if "tool" in sup else None
            sub_tools = set(_as_list(sub_val))
            if sup_tools is not None and not sub_tools <= sup_tools:
                return False
        elif key in ("role", "agent"):
            sup_v = set(_as_list(sup.get(key))) if key in sup else None
            sub_v = set(_as_list(sub_val))
            if sup_v is not None and not sub_v <= sup_v:
                return False
        elif key == "path_contains_any":
            if "path_contains_any" in sup and set(_as_list(sup["path_contains_any"])) != set(_as_list(sub_val)):
                return False
        elif key in ("min_external_calls", "min_sends", "min_writes", "min_deletes"):
            if key in sup and int(sup[key]) > int(sub_val):
                return False  # higher threshold fires less often
        elif key in ("path_outside_sandbox", "domain_allowlisted",
                     "carries_read_content", "source_untrusted"):
            if key in sup and bool(sup[key]) != bool(sub_val):
                return False
        elif key == "when":
            if "when" in sup and sup["when"] != sub_val:
                return False
    return True


def _precedes(a, b, ia, ib):
    ra, rb = _EFFECT_RANK[a.get("effect")], _EFFECT_RANK[b.get("effect")]
    return ra > rb or (ra == rb and ia < ib)


def lint_file(path):
    """Return a list of finding dicts for the policy file at *path*."""
    cfg = yaml_load(str(Path(path))) or {}
    rules = cfg.get("policies") or []
    findings = []

    for i, rule in enumerate(rules):
        rid = rule.get("id", "rule-%d" % i)
        effect = rule.get("effect")
        if effect not in VALID_EFFECTS:
            findings.append({"kind": "invalid_effect", "rule_id": rid,
                             "detail": "effect %r is not one of %s"
                                       % (effect, sorted(VALID_EFFECTS))})
        match = rule.get("match") or {}
        for tool in _as_list(match.get("tool")):
            if tool not in KNOWN_TOOLS:
                findings.append({"kind": "unknown_tool", "rule_id": rid,
                                 "detail": "tool %r does not exist" % tool})
        for key in match:
            if key not in KNOWN_MATCH_KEYS:
                findings.append({"kind": "unknown_match_key", "rule_id": rid,
                                 "detail": "match key %r is not understood "
                                           "by the engine" % key})

    for i, rule in enumerate(rules):
        rid = rule.get("id", "rule-%d" % i)
        match = rule.get("match") or {}
        for j, other in enumerate(rules):
            if i == j:
                continue
            oid = other.get("id", "rule-%d" % j)
            if not _precedes(other, rule, j, i):
                continue
            if _covers(other.get("match") or {}, match):
                findings.append({"kind": "shadowed_rule", "rule_id": rid,
                                 "detail": "never fires: %s (effect %s) "
                                           "matches a superset of its "
                                           "conditions"
                                           % (oid, other.get("effect"))})
                break

    seen = {}
    for i, rule in enumerate(rules):
        rid = rule.get("id", "rule-%d" % i)
        key = json.dumps(rule.get("match") or {}, sort_keys=True, default=str)
        if key in seen and seen[key][1] != rule.get("effect"):
            findings.append({"kind": "contradictory_rule", "rule_id": rid,
                             "detail": "identical conditions to %s (%s) but "
                                       "a different effect (%s)"
                                       % (seen[key][0], seen[key][1],
                                          rule.get("effect"))})
        elif key not in seen:
            seen[key] = (rid, rule.get("effect"))
    return findings


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: python -m gov.policy_lint <policy.yaml>")
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    findings = lint_file(argv[0])
    for f in findings:
        print("%-18s %-28s %s" % (f["kind"], f["rule_id"], f["detail"]))
    if findings:
        print("%d finding(s)" % len(findings))
        return 1
    print("no findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
