"""Policy-delta risk gate (wave-246 lane 1, W246-1).

``gov/policy_change.py`` governs the policy-change CEREMONY (two-person
rule, authorship chaining, break-glass) and computes a structural diff,
but nothing in the tree asks whether the DELTA itself is risky: a
change that clears ceremony -- or arrives via break-glass -- can still
silently widen what agents may do. This module closes that seam.

``analyze_policy_delta(old_text, new_text)`` compares two policy texts
(parsed with the SAME parser the engine uses, via
``policy_change.canonical_policy_bytes``) and reports every risky
change with a risk class, severity, and before/after evidence:

* capability widening (roles gain tools, budgets grow, the egress
  allowlist gains domains, approval delegation is enabled)
  -> ``policy-delta-widening`` (high, refuse);
* a deny (forbid) rule removed outright
  -> ``policy-delta-forbid-removed`` (high, refuse);
* a deny rule's match provably narrowed (a list-valued match key lost
  members, so previously-covered actions escape the forbid)
  -> ``policy-delta-forbid-narrowed`` (high, refuse);
* a rule's effect moved up the deny < require_approval < allow ladder
  -> ``policy-delta-effect-weakened`` (high, refuse);
* a new allow rule no deny rule covers (tool-overlap heuristic; forbid
  priority is what guards allows, so an unguarded allow is a hole)
  -> ``policy-delta-allow-unforbidden`` (medium, flagged, verdict pass);
* a deny rule's match changed without provable narrowing
  -> ``policy-delta-forbid-modified`` (medium, flagged);
* an allow rule's match changed without provable widening
  -> ``policy-delta-allow-modified`` (medium, flagged);
* a require_approval rule removed (a human check disappears)
  -> ``policy-delta-check-removed`` (medium, flagged);
* a brand-new role carrying tools (a new capability surface)
  -> ``policy-delta-role-added`` (medium, flagged);
* an unclassified section changed (cannot assess direction)
  -> ``policy-delta-section-changed`` (medium, flagged).

Tighten-only deltas (new deny rules, shrunken roles/budgets/allowlists,
weakened effects) pass with zero findings. A semantic no-op (comments or
formatting only) passes: the comparison runs on canonical policy bytes,
so enforced meaning is what is judged.

Fail-closed: anything malformed -- unparseable text, a non-mapping
policy, duplicate rule ids, a rule that is not a mapping, an unknown
effect, a non-mapping match block -- raises ``PolicyDeltaError`` with
code ``policy-delta-malformed``. Never returns "pass" on input it could
not understand.

Deterministic: findings are sorted by (severity, section, rule, class)
and the report carries a SHA-256 digest over the canonical findings, so
two runs over the same pair agree byte-for-byte. Stdlib only. No
network, no subprocesses, no clock reads.

Decision codes are EVIDENCE, never authority.
"""

import hashlib
import json

from .policy_change import canonical_policy_bytes, PolicyChangeError

# ---------------------------------------------------------------------------
# Decision codes (also registered in gov/decision_codes.py TAXONOMY)
# ---------------------------------------------------------------------------

MALFORMED = "policy-delta-malformed"
WIDENING = "policy-delta-widening"
FORBID_REMOVED = "policy-delta-forbid-removed"
FORBID_NARROWED = "policy-delta-forbid-narrowed"
EFFECT_WEAKENED = "policy-delta-effect-weakened"
ALLOW_UNFORBIDDEN = "policy-delta-allow-unforbidden"
FORBID_MODIFIED = "policy-delta-forbid-modified"
ALLOW_MODIFIED = "policy-delta-allow-modified"
CHECK_REMOVED = "policy-delta-check-removed"
ROLE_ADDED = "policy-delta-role-added"
SECTION_CHANGED = "policy-delta-section-changed"

_PERMISSIVENESS = {"deny": 0, "require_approval": 1, "allow": 2}

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


class PolicyDeltaError(Exception):
    """A policy delta was refused (fail-closed)."""

    def __init__(self, code, detail=""):
        super(PolicyDeltaError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Loading / validation (fail-closed)
# ---------------------------------------------------------------------------

def _load(which, text):
    if not isinstance(text, str):
        raise PolicyDeltaError(
            MALFORMED, "%s policy must be str, got %s"
            % (which, type(text).__name__))
    try:
        parsed = json.loads(canonical_policy_bytes(text).decode("utf-8"))
    except PolicyChangeError as exc:
        raise PolicyDeltaError(
            MALFORMED, "%s policy malformed: %s" % (which, exc))
    if not isinstance(parsed, dict):
        raise PolicyDeltaError(
            MALFORMED, "%s policy must be a mapping" % which)
    return parsed


def _rules(which, policy):
    raw = policy.get("policies", [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise PolicyDeltaError(
            MALFORMED, "%s policies section must be a list" % which)
    rules = {}
    for i, rule in enumerate(raw):
        if not isinstance(rule, dict):
            raise PolicyDeltaError(
                MALFORMED, "%s rule %d is not a mapping" % (which, i))
        rid = rule.get("id", "rule-%d" % i)
        if not isinstance(rid, str):
            raise PolicyDeltaError(
                MALFORMED, "%s rule %d id is not a string" % (which, i))
        if rid in rules:
            raise PolicyDeltaError(
                MALFORMED, "%s duplicate rule id %r" % (which, rid))
        effect = rule.get("effect")
        if effect not in _PERMISSIVENESS:
            raise PolicyDeltaError(
                MALFORMED, "%s rule %r has unknown effect %r"
                % (which, rid, effect))
        match = rule.get("match", {})
        if match is None:
            match = {}
        if not isinstance(match, dict):
            raise PolicyDeltaError(
                MALFORMED, "%s rule %r match is not a mapping"
                % (which, rid))
        rules[rid] = rule
    return rules


def _as_str_set(value):
    if isinstance(value, list):
        return set(str(v) for v in value)
    return None


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _finding(risk_class, severity, section, rule_id, detail,
             before=None, after=None):
    return {
        "risk_class": risk_class,
        "severity": severity,
        "section": section,
        "rule_id": rule_id,
        "detail": detail,
        "before": before,
        "after": after,
    }


def _match_delta(old_match, new_match):
    """Classify per-key changes between two match mappings.

    Returns (widened, narrowed, changed_other): keys whose list value
    strictly grew, strictly shrank, or changed in a way whose coverage
    direction cannot be proven (non-list values, incomparable lists,
    added/removed keys).
    """
    widened, narrowed, changed = [], [], []
    for key in sorted(set(old_match) | set(new_match)):
        old_v, new_v = old_match.get(key), new_match.get(key)
        if key not in old_match or key not in new_match:
            changed.append(key)
            continue
        old_s, new_s = _as_str_set(old_v), _as_str_set(new_v)
        if old_s is None or new_s is None:
            if old_v != new_v:
                changed.append(key)
            continue
        if new_s > old_s:
            widened.append(key)
        elif new_s < old_s:
            narrowed.append(key)
        elif new_s != old_s:
            changed.append(key)
    return widened, narrowed, changed


def _deny_covers(deny_rule, allow_rule):
    """Heuristic: a deny rule guards an allow rule when their ``tool``
    match lists overlap. Forbid priority is what makes allows safe, so
    tool overlap is the coverage test we can prove from the text.

    Documented limitation: an allow rule with no ``tool`` key, or a
    deny whose guard works through a non-tool match key, is treated as
    uncovered (flagged, never silently passed).
    """
    deny_tools = _as_str_set(deny_rule.get("match", {}).get("tool"))
    allow_tools = _as_str_set(allow_rule.get("match", {}).get("tool"))
    if not deny_tools or not allow_tools:
        return False
    return bool(deny_tools & allow_tools)


def _analyze_rules(old_rules, new_rules):
    findings = []
    old_ids, new_ids = set(old_rules), set(new_rules)
    for rid in sorted(old_ids - new_ids):
        effect = old_rules[rid]["effect"]
        if effect == "deny":
            findings.append(_finding(
                FORBID_REMOVED, "high", "policies", rid,
                "deny rule removed outright; actions it forbade are now "
                "unguarded",
                before=old_rules[rid].get("match"),
                after=None))
        elif effect == "require_approval":
            findings.append(_finding(
                CHECK_REMOVED, "medium", "policies", rid,
                "require_approval rule removed; the human check it "
                "imposed no longer applies",
                before=old_rules[rid].get("match"),
                after=None))
        # removed allow rules only tighten: no finding.
    for rid in sorted(new_ids - old_ids):
        rule = new_rules[rid]
        effect = rule["effect"]
        if effect == "deny":
            continue  # new forbid: pure tightening.
        if effect == "allow":
            covered = any(
                _deny_covers(new_rules[d], rule)
                for d in new_rules if new_rules[d]["effect"] == "deny")
            if not covered:
                findings.append(_finding(
                    ALLOW_UNFORBIDDEN, "medium", "policies", rid,
                    "new allow rule is not covered by any deny rule "
                    "(no tool overlap); forbid priority cannot guard it",
                    before=None,
                    after=rule.get("match")))
        # new require_approval rules keep a human in the loop: no finding.
    for rid in sorted(old_ids & new_ids):
        old_r, new_r = old_rules[rid], new_rules[rid]
        old_e, new_e = old_r["effect"], new_r["effect"]
        if _PERMISSIVENESS[new_e] > _PERMISSIVENESS[old_e]:
            findings.append(_finding(
                EFFECT_WEAKENED, "high", "policies", rid,
                "rule effect moved %s -> %s (up the deny < "
                "require_approval < allow ladder)" % (old_e, new_e),
                before=old_e, after=new_e))
            continue
        old_m, new_m = old_r.get("match") or {}, new_r.get("match") or {}
        if old_m == new_m:
            continue
        widened, narrowed, changed = _match_delta(old_m, new_m)
        if new_e == "deny":
            if narrowed:
                findings.append(_finding(
                    FORBID_NARROWED, "high", "policies", rid,
                    "deny rule match provably narrowed on keys %s; "
                    "previously-forbidden actions escape the forbid"
                    % (sorted(narrowed),),
                    before=old_m, after=new_m))
            elif changed:
                findings.append(_finding(
                    FORBID_MODIFIED, "medium", "policies", rid,
                    "deny rule match changed on keys %s; coverage "
                    "direction unprovable, needs review"
                    % (sorted(changed),),
                    before=old_m, after=new_m))
            # widened-only deny match: tightening, no finding.
        elif new_e == "allow":
            if widened:
                findings.append(_finding(
                    WIDENING, "high", "policies", rid,
                    "allow rule match widened on keys %s"
                    % (sorted(widened),),
                    before=old_m, after=new_m))
            elif changed:
                findings.append(_finding(
                    ALLOW_MODIFIED, "medium", "policies", rid,
                    "allow rule match changed on keys %s; widening "
                    "unprovable, needs review" % (sorted(changed),),
                    before=old_m, after=new_m))
            # narrowed-only allow match: tightening, no finding.
        else:  # require_approval
            if widened:
                findings.append(_finding(
                    WIDENING, "medium", "policies", rid,
                    "require_approval rule match widened on keys %s; "
                    "more actions can reach the human queue"
                    % (sorted(widened),),
                    before=old_m, after=new_m))
            elif changed:
                findings.append(_finding(
                    ALLOW_MODIFIED, "medium", "policies", rid,
                    "require_approval rule match changed on keys %s; "
                    "direction unprovable, needs review"
                    % (sorted(changed),),
                    before=old_m, after=new_m))
    return findings


def _analyze_roles(old, new):
    findings = []
    old_roles = old.get("roles") or {}
    new_roles = new.get("roles") or {}
    if not isinstance(old_roles, dict) or not isinstance(new_roles, dict):
        raise PolicyDeltaError(MALFORMED, "roles section must be a mapping")
    for role in sorted(set(new_roles) - set(old_roles)):
        tools = new_roles[role]
        if not isinstance(tools, list):
            raise PolicyDeltaError(
                MALFORMED, "role %r tools must be a list" % role)
        if tools:
            findings.append(_finding(
                ROLE_ADDED, "medium", "roles", None,
                "new role %r carries tools %s: a new capability surface"
                % (role, sorted(str(t) for t in tools)),
                before=None, after=sorted(str(t) for t in tools)))
    for role in sorted(set(old_roles) & set(new_roles)):
        old_t, new_t = old_roles[role], new_roles[role]
        if not isinstance(old_t, list) or not isinstance(new_t, list):
            raise PolicyDeltaError(
                MALFORMED, "role %r tools must be a list" % role)
        gained = sorted(set(str(t) for t in new_t)
                        - set(str(t) for t in old_t))
        if gained:
            findings.append(_finding(
                WIDENING, "high", "roles", None,
                "role %r gained tools %s" % (role, gained),
                before=sorted(str(t) for t in old_t),
                after=sorted(str(t) for t in new_t)))
        # lost tools: tightening, no finding. Removed roles: no finding.
    return findings


def _analyze_rate_limit(old, new):
    findings = []
    old_rl = old.get("rate_limit") or {}
    new_rl = new.get("rate_limit") or {}
    if not isinstance(old_rl, dict) or not isinstance(new_rl, dict):
        raise PolicyDeltaError(
            MALFORMED, "rate_limit section must be a mapping")
    for key in sorted(set(old_rl) - set(new_rl)):
        findings.append(_finding(
            WIDENING, "high", "rate_limit", None,
            "budget %r removed; the constraint it imposed is gone" % key,
            before=old_rl[key], after=None))
    for key in sorted(set(old_rl) & set(new_rl)):
        old_v, new_v = old_rl[key], new_rl[key]
        if old_v == new_v:
            continue
        if isinstance(old_v, (int, float)) and isinstance(new_v, (int, float)) \
                and not isinstance(old_v, bool) and not isinstance(new_v, bool):
            if new_v > old_v:
                findings.append(_finding(
                    WIDENING, "high", "rate_limit", None,
                    "budget %r increased %s -> %s" % (key, old_v, new_v),
                    before=old_v, after=new_v))
            # decreased: tightening, no finding.
        else:
            findings.append(_finding(
                SECTION_CHANGED, "medium", "rate_limit", None,
                "budget %r changed in an unclassifiable way" % key,
                before=old_v, after=new_v))
    # added budget keys constrain something new: tightening, no finding.
    return findings


def _analyze_egress(old, new):
    findings = []
    old_e = old.get("egress") or {}
    new_e = new.get("egress") or {}
    if not isinstance(old_e, dict) or not isinstance(new_e, dict):
        raise PolicyDeltaError(
            MALFORMED, "egress section must be a mapping")
    old_al = _as_str_set(old_e.get("domain_allowlist") or [])
    new_al = _as_str_set(new_e.get("domain_allowlist") or [])
    gained = sorted(new_al - old_al)
    if gained:
        findings.append(_finding(
            WIDENING, "high", "egress", None,
            "domain allowlist gained %s" % (gained,),
            before=sorted(old_al), after=sorted(new_al)))
    # lost domains: tightening, no finding.
    for key in sorted(set(old_e) | set(new_e)):
        if key == "domain_allowlist":
            continue
        if old_e.get(key) != new_e.get(key):
            findings.append(_finding(
                SECTION_CHANGED, "medium", "egress", None,
                "egress key %r changed" % key,
                before=old_e.get(key), after=new_e.get(key)))
    return findings


def _bool(value):
    return value is True


def _analyze_approvals(old, new):
    findings = []
    old_a = old.get("approvals") or {}
    new_a = new.get("approvals") or {}
    if not isinstance(old_a, dict) or not isinstance(new_a, dict):
        raise PolicyDeltaError(
            MALFORMED, "approvals section must be a mapping")
    old_ex = _as_str_set(old_a.get("batch_excluded_queue_reasons") or [])
    new_ex = _as_str_set(new_a.get("batch_excluded_queue_reasons") or [])
    lost = sorted(old_ex - new_ex)
    if lost:
        findings.append(_finding(
            WIDENING, "high", "approvals", None,
            "batch-excluded queue reasons lost %s; more records become "
            "batch-approvable" % (lost,),
            before=sorted(old_ex), after=sorted(new_ex)))
    # gained exclusions: tightening, no finding.
    old_ttl, new_ttl = old_a.get("ttl_hours"), new_a.get("ttl_hours")
    if old_ttl != new_ttl and old_ttl is not None and new_ttl is not None:
        if isinstance(new_ttl, (int, float)) and isinstance(
                old_ttl, (int, float)) and new_ttl > old_ttl:
            findings.append(_finding(
                WIDENING, "medium", "approvals", None,
                "approval ttl_hours increased %s -> %s" % (old_ttl,
                                                           new_ttl),
                before=old_ttl, after=new_ttl))
        elif new_ttl != old_ttl:
            findings.append(_finding(
                SECTION_CHANGED, "medium", "approvals", None,
                "approval ttl_hours changed", before=old_ttl,
                after=new_ttl))
    old_d = old_a.get("delegation") or {}
    new_d = new_a.get("delegation") or {}
    if not isinstance(old_d, dict) or not isinstance(new_d, dict):
        raise PolicyDeltaError(
            MALFORMED, "approvals.delegation must be a mapping")
    if not _bool(old_d.get("enabled")) and _bool(new_d.get("enabled")):
        findings.append(_finding(
            WIDENING, "high", "approvals", None,
            "approval delegation enabled (was disabled)",
            before=False, after=True))
    old_hops, new_hops = old_d.get("max_hops"), new_d.get("max_hops")
    if old_hops != new_hops and old_hops is not None \
            and new_hops is not None:
        if isinstance(new_hops, (int, float)) and isinstance(
                old_hops, (int, float)) and new_hops > old_hops:
            findings.append(_finding(
                WIDENING, "high", "approvals", None,
                "delegation max_hops increased %s -> %s"
                % (old_hops, new_hops),
                before=old_hops, after=new_hops))
    for key in sorted(set(old_a) | set(new_a)):
        if key in ("batch_excluded_queue_reasons", "ttl_hours",
                   "delegation"):
            continue
        if old_a.get(key) != new_a.get(key):
            findings.append(_finding(
                SECTION_CHANGED, "medium", "approvals", None,
                "approvals key %r changed" % key,
                before=old_a.get(key), after=new_a.get(key)))
    return findings


_KNOWN_SECTIONS = ("version", "roles", "rate_limit", "egress", "approvals",
                   "policies")


def _analyze_other_sections(old, new):
    findings = []
    for key in sorted(set(old) | set(new)):
        if key in _KNOWN_SECTIONS:
            continue
        if old.get(key) != new.get(key):
            findings.append(_finding(
                SECTION_CHANGED, "medium", key, None,
                "unclassified top-level section changed; direction "
                "cannot be assessed from policy text alone",
                before=old.get(key), after=new.get(key)))
    # version bumps are routine metadata: noted in the summary, no finding.
    return findings


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


# ---------------------------------------------------------------------------
# Public seam
# ---------------------------------------------------------------------------

def analyze_policy_delta(old_text, new_text):
    """Analyze the risk of a policy change. Returns a report dict::

        {"verdict": "pass" | "refuse",
         "risk_findings": [ {risk_class, severity, section, rule_id,
                             detail, before, after}, ... ],
         "summary": {"refusals": int, "flags": int,
                     "sections_changed": [...]},
         "delta_digest": sha256 hex over the canonical findings,
         "old_digest": sha256 hex of canonical old policy,
         "new_digest": sha256 hex of canonical new policy}

    Raises :class:`PolicyDeltaError` (``policy-delta-malformed``) on any
    malformed input. Never returns "pass" for input it could not parse.
    """
    old = _load("old", old_text)
    new = _load("new", new_text)
    old_rules = _rules("old", old)
    new_rules = _rules("new", new)

    findings = []
    findings.extend(_analyze_rules(old_rules, new_rules))
    findings.extend(_analyze_roles(old, new))
    findings.extend(_analyze_rate_limit(old, new))
    findings.extend(_analyze_egress(old, new))
    findings.extend(_analyze_approvals(old, new))
    findings.extend(_analyze_other_sections(old, new))
    findings.sort(key=lambda f: (
        _SEVERITY_RANK[f["severity"]], f["section"],
        f["rule_id"] or "", f["risk_class"]))

    refusals = sum(1 for f in findings if f["severity"] == "high")
    flags = len(findings) - refusals
    verdict = "refuse" if refusals else "pass"
    digest = hashlib.sha256(_canonical(findings)).hexdigest()
    sections = sorted({f["section"] for f in findings})
    return {
        "verdict": verdict,
        "risk_findings": findings,
        "summary": {"verdict": verdict,
                    "refusals": refusals,
                    "flags": flags,
                    "sections_changed": sections},
        "delta_digest": digest,
        "old_digest": hashlib.sha256(
            canonical_policy_bytes(old_text)).hexdigest(),
        "new_digest": hashlib.sha256(
            canonical_policy_bytes(new_text)).hexdigest(),
    }


def check_policy_delta(old_text, new_text):
    """Like :func:`analyze_policy_delta`, but raises
    :class:`PolicyDeltaError` carrying the first high-severity finding's
    decision code when the verdict is "refuse". Returns the report on
    "pass".
    """
    report = analyze_policy_delta(old_text, new_text)
    if report["verdict"] == "refuse":
        first = next(f for f in report["risk_findings"]
                     if f["severity"] == "high")
        raise PolicyDeltaError(first["risk_class"], first["detail"])
    return report
