"""Four-bucket ordered authorization combine.

ADAPT (pattern only, no code vendored): the composition algebra of
Istio's ``AuthorizationPolicy`` (istio/istio, SHA
``db6e1182defcca9177dc74b4210804a1689d4299``, Apache-2.0, verified from
the actual LICENSE file). Istio's attributes are network/identity
centric (source principals, request headers, SNI, ports); the
``from``/``to``/``when`` vocabulary here is agent-native --
(principal, action, resource, context) tuples -- which is our design
work. The algebra ports; the Envoy filter mechanics do not.

The algebra
-----------
Policies are partitioned by action into ordered buckets evaluated as::

    AUDIT -> DENY -> CUSTOM -> ALLOW

Deny-before-allow is structural, never a named operator: a DENY match
short-circuits to deny before ALLOW (or CUSTOM) is ever consulted. No
special-case code is needed -- evaluation order plus short-circuit.

* Within a bucket, rules are OR'd (any match applies the bucket).
* Within a rule, clauses are AND'd: ``from`` (who) AND ``to`` (what)
  AND ``when`` (under what conditions). Multiple values inside one
  clause are OR'd.
* Every rule carries a name; the verdict attributes the exact rules
  that decided (the decision-trail analogue of Istio's
  ``namespace/name/rule-index`` rule keys).
* Default semantics: no ALLOW policies => default-allow; >=1 ALLOW
  policy => default-deny. (Shadow/dry-run rules are not policies for
  this purpose -- they are never enforced.)
* Dry-run / shadow mode: a rule marked ``shadow: true`` is evaluated
  and reported (``shadow_results`` + journal) but never enforced -- it
  can neither deny nor grant.
* CUSTOM (external authorizer): a matching custom rule consults a
  deployment-supplied ``authorizer`` callable. A misconfigured provider
  (not configured in the bundle, or no hook supplied) fails closed to
  deny-everything with ``authz-provider-misconfigured`` and a loud
  journal entry. The hook has a timeout (``timeout_ms`` per provider);
  a timeout or provider error fails closed to deny. Timeout is a
  duration bound -- no wall-clock decisions are made anywhere.
* Partial enforcement: when a rule's ``from``/``to`` match but its
  ``when`` conditions cannot be evaluated (attributes missing at the
  enforcement point), that fidelity loss is LOUD, never silent -- the
  ambient/waypoint lesson. A DENY rule in this state fails toward
  deny; an ALLOW rule in this state never grants; when nothing clean
  decides and decision-path rules were unevaluable, the verdict is the
  loud ``authz-partial-attributes`` refuse naming every affected rule
  and missing key.

Composition (never duplicated here): ``gov/policy_delta.py`` gates
policy *changes* (counterexamples, forbid-hard-override);
``gov/policy_change_containment.py`` bounds blast radius of changes.
This module evaluates a *loaded bundle* against a request -- the
run-time combine. Verdicts carry decision codes from the ``authz``
domain (see ``gov/decision_codes.py``) and can be attached to decision
packets via ``gov.decision_packet`` / ``gov.decision_codes``.

Determinism: stdlib only, no ambient clock, no randomness, no network.
``evaluate`` never raises -- every failure is a coded fail-closed
verdict.

Honest limits (see ``out_of_scope`` on every verdict): external
authorizer latency/availability is deployment-owned (the timeout only
bounds the wait); rule authorship and bundle integrity must be pinned
by the deployment; context attribute values are caller-supplied --
attribute-source integrity is the caller's job; transport security to
the external authorizer is out of scope here.
"""

import concurrent.futures
import hashlib
import json

__all__ = [
    "AuthorizationCombineError",
    "AUTHZ_BUNDLE_VERSION",
    "BUCKET_ORDER",
    "load_bundle",
    "evaluate",
    "request_digest",
]

#: Exact bundle format tag (exact match at load).
AUTHZ_BUNDLE_VERSION = "sasanam-authz-bundle/v1"

#: Bucket evaluation order. Structural -- never reordered.
BUCKET_ORDER = ("audit", "deny", "custom", "allow")

_MALFORMED_BUNDLE = "authz-malformed-bundle"
_MALFORMED_RULE = "authz-malformed-rule"
_UNCHECKABLE = "authz-uncheckable"
_AUDIT_HIT = "authz-audit-hit"
_ALLOW = "authz-allow"
_DENY = "authz-deny"
_DEFAULT_DENY = "authz-default-deny"
_SHADOW_EVALUATED = "authz-shadow-evaluated"
_PROVIDER_MISCONFIGURED = "authz-provider-misconfigured"
_PARTIAL_ATTRIBUTES = "authz-partial-attributes"

_VALID_ACTIONS = ("audit", "deny", "custom", "allow")
_VALID_OPS = ("eq", "ne", "in", "startswith", "present")
_VALID_SCALAR = (str, int, float, bool)

#: Honest boundary: what this module does NOT cover.
_OUT_OF_SCOPE = [
    "external-authorizer latency and availability (deployment-owned; "
    "timeout_ms only bounds the wait)",
    "rule authorship and bundle integrity (deployment must pin who "
    "may author bundles)",
    "attribute-source integrity (context values are caller-supplied; "
    "enrichment is the caller's job)",
    "transport security to the external authorizer",
]


class AuthorizationCombineError(Exception):
    """Fail-closed authorization-combine violation. ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        super(AuthorizationCombineError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


class _ProviderFailed(Exception):
    """Internal: the external authorizer errored or timed out."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def request_digest(request):
    """Content-addressed digest of a request (never a mutable ref)."""
    if not isinstance(request, dict):
        raise AuthorizationCombineError(
            _UNCHECKABLE, "request is not a dict")
    return _sha256_hex(_canonical(request))


# ----------------------------------------------------------------------
# Loading -- strict, fail-closed, machine-coded.
# ----------------------------------------------------------------------

def _refuse_load(code, detail):
    raise AuthorizationCombineError(code, detail)


def _load_str_list(value, what, rule_name):
    if (not isinstance(value, list) or not value
            or any(not isinstance(v, str) or not v for v in value)):
        _refuse_load(_MALFORMED_RULE,
                     "%s of rule %r must be a non-empty list of "
                     "non-empty strings" % (what, rule_name))
    return list(value)


def _load_from(doc, rule_name):
    if doc is None:
        return {"any": True, "principals": []}
    if not isinstance(doc, dict) or not doc:
        _refuse_load(_MALFORMED_RULE,
                     "from of rule %r must be a non-empty dict"
                     % (rule_name,))
    unknown = set(doc) - {"principals", "any"}
    if unknown:
        _refuse_load(_MALFORMED_RULE,
                     "from of rule %r has unknown keys %s"
                     % (rule_name, sorted(unknown)))
    if doc.get("any") is True:
        return {"any": True, "principals": []}
    if "any" in doc and doc["any"] is not True:
        _refuse_load(_MALFORMED_RULE,
                     "from.any of rule %r must be true when present"
                     % (rule_name,))
    return {"any": False,
            "principals": _load_str_list(doc.get("principals", []),
                                         "from.principals", rule_name)}


def _load_to(doc, rule_name):
    if doc is None:
        return {"any": True, "actions": [], "resources": []}
    if not isinstance(doc, dict) or not doc:
        _refuse_load(_MALFORMED_RULE,
                     "to of rule %r must be a non-empty dict"
                     % (rule_name,))
    unknown = set(doc) - {"actions", "resources", "any"}
    if unknown:
        _refuse_load(_MALFORMED_RULE,
                     "to of rule %r has unknown keys %s"
                     % (rule_name, sorted(unknown)))
    if doc.get("any") is True:
        return {"any": True, "actions": [], "resources": []}
    if "any" in doc and doc["any"] is not True:
        _refuse_load(_MALFORMED_RULE,
                     "to.any of rule %r must be true when present"
                     % (rule_name,))
    actions = (_load_str_list(doc["actions"], "to.actions", rule_name)
               if "actions" in doc else [])
    resources = (_load_str_list(doc["resources"], "to.resources",
                                rule_name)
                 if "resources" in doc else [])
    if not actions and not resources:
        _refuse_load(_MALFORMED_RULE,
                     "to of rule %r needs actions and/or resources"
                     % (rule_name,))
    return {"any": False, "actions": actions, "resources": resources}


def _load_condition(doc, rule_name, idx):
    if not isinstance(doc, dict):
        _refuse_load(_MALFORMED_RULE,
                     "when[%d] of rule %r must be a dict"
                     % (idx, rule_name))
    unknown = set(doc) - {"key", "op", "value"}
    if unknown:
        _refuse_load(_MALFORMED_RULE,
                     "when[%d] of rule %r has unknown keys %s"
                     % (idx, rule_name, sorted(unknown)))
    key = doc.get("key")
    op = doc.get("op")
    if not isinstance(key, str) or not key:
        _refuse_load(_MALFORMED_RULE,
                     "when[%d] of rule %r needs a non-empty key"
                     % (idx, rule_name))
    if op not in _VALID_OPS:
        _refuse_load(_MALFORMED_RULE,
                     "when[%d] of rule %r has unknown op %r"
                     % (idx, rule_name, op))
    if op == "in":
        value = doc.get("value")
        if (not isinstance(value, list) or not value
                or any(not isinstance(v, _VALID_SCALAR)
                       for v in value)):
            _refuse_load(_MALFORMED_RULE,
                         "when[%d] of rule %r: op 'in' needs a "
                         "non-empty list of scalars"
                         % (idx, rule_name))
        return {"key": key, "op": op, "value": list(value)}
    if op == "startswith":
        if not isinstance(doc.get("value"), str):
            _refuse_load(_MALFORMED_RULE,
                         "when[%d] of rule %r: op 'startswith' needs "
                         "a string value" % (idx, rule_name))
        return {"key": key, "op": op, "value": doc["value"]}
    if op == "present":
        return {"key": key, "op": op}
    value = doc.get("value", None)
    if "value" not in doc or not isinstance(value, _VALID_SCALAR):
        _refuse_load(_MALFORMED_RULE,
                     "when[%d] of rule %r: op %r needs a scalar value"
                     % (idx, rule_name, op))
    return {"key": key, "op": op, "value": value}


def _load_rule(doc, idx):
    where = "rule[%d]" % (idx,)
    if not isinstance(doc, dict):
        _refuse_load(_MALFORMED_RULE, "%s must be a dict" % (where,))
    name = doc.get("name")
    if not isinstance(name, str) or not name:
        _refuse_load(_MALFORMED_RULE,
                     "%s needs a non-empty string name" % (where,))
    action = doc.get("action")
    if action not in _VALID_ACTIONS:
        _refuse_load(_MALFORMED_RULE,
                     "rule %r has unknown action %r (closed set: %s)"
                     % (name, action, ", ".join(_VALID_ACTIONS)))
    unknown = set(doc) - {"name", "action", "shadow", "from", "to",
                          "when", "provider"}
    if unknown:
        _refuse_load(_MALFORMED_RULE,
                     "rule %r has unknown keys %s"
                     % (name, sorted(unknown)))
    shadow = doc.get("shadow", False)
    if not isinstance(shadow, bool):
        _refuse_load(_MALFORMED_RULE,
                     "rule %r: shadow must be a bool" % (name,))
    when = doc.get("when", [])
    if not isinstance(when, list):
        _refuse_load(_MALFORMED_RULE,
                     "rule %r: when must be a list" % (name,))
    rule = {"name": name, "action": action, "shadow": shadow,
            "from": _load_from(doc.get("from"), name),
            "to": _load_to(doc.get("to"), name),
            "when": [_load_condition(c, name, i)
                     for i, c in enumerate(when)]}
    provider = doc.get("provider")
    if action == "custom":
        if not isinstance(provider, str) or not provider:
            _refuse_load(_MALFORMED_RULE,
                         "rule %r: custom action needs a non-empty "
                         "provider id" % (name,))
        rule["provider"] = provider
    elif provider is not None:
        _refuse_load(_MALFORMED_RULE,
                     "rule %r: provider is only valid on custom "
                     "rules" % (name,))
    return rule


def _load_authorizers(doc):
    if not isinstance(doc, dict):
        _refuse_load(_MALFORMED_BUNDLE,
                     "external_authorizers must be a dict")
    out = {}
    for pid, cfg in doc.items():
        if not isinstance(pid, str) or not pid:
            _refuse_load(_MALFORMED_BUNDLE,
                         "external_authorizers needs string ids")
        if not isinstance(cfg, dict):
            _refuse_load(_MALFORMED_BUNDLE,
                         "provider %r config must be a dict" % (pid,))
        unknown = set(cfg) - {"timeout_ms"}
        if unknown:
            _refuse_load(_MALFORMED_BUNDLE,
                         "provider %r has unknown config keys %s"
                         % (pid, sorted(unknown)))
        timeout = cfg.get("timeout_ms", 1000)
        if (isinstance(timeout, bool) or not isinstance(timeout, int)
                or timeout <= 0):
            _refuse_load(_MALFORMED_BUNDLE,
                         "provider %r: timeout_ms must be a positive "
                         "int" % (pid,))
        out[pid] = {"timeout_ms": timeout}
    return out


def load_bundle(doc):
    """Load and strictly validate an authorization bundle.

    Raises :class:`AuthorizationCombineError` with a machine-readable
    ``code`` on any malformed input. Returns a normalized bundle dict.
    """
    if not isinstance(doc, dict):
        _refuse_load(_MALFORMED_BUNDLE, "bundle must be a dict")
    if doc.get("version") != AUTHZ_BUNDLE_VERSION:
        _refuse_load(_MALFORMED_BUNDLE,
                     "version must be %r" % (AUTHZ_BUNDLE_VERSION,))
    unknown = set(doc) - {"version", "rules", "external_authorizers"}
    if unknown:
        _refuse_load(_MALFORMED_BUNDLE,
                     "bundle has unknown keys %s" % (sorted(unknown),))
    rules = doc.get("rules", [])
    if not isinstance(rules, list):
        _refuse_load(_MALFORMED_BUNDLE, "rules must be a list")
    loaded = [_load_rule(r, i) for i, r in enumerate(rules)]
    names = [r["name"] for r in loaded]
    if len(set(names)) != len(names):
        dupes = sorted(n for n in set(names) if names.count(n) > 1)
        _refuse_load(_MALFORMED_BUNDLE,
                     "duplicate rule names: %s" % (dupes,))
    return {"version": AUTHZ_BUNDLE_VERSION, "rules": loaded,
            "external_authorizers": _load_authorizers(
                doc.get("external_authorizers", {}))}


# ----------------------------------------------------------------------
# Matching -- pure functions over loaded rules and requests.
# ----------------------------------------------------------------------

def _match_from(frm, principal):
    if frm["any"]:
        return True
    return principal in frm["principals"]


def _match_to(to, action, resource):
    if to["any"]:
        return True
    if to["actions"] and action not in to["actions"]:
        return False
    for pat in to["resources"]:
        if pat.startswith("prefix:"):
            if resource.startswith(pat[len("prefix:"):]):
                break
        elif resource == pat:
            break
    else:
        if to["resources"]:
            return False
    return True


def _eval_condition(cond, context):
    """Return (decided, matched, missing_keys)."""
    key = cond["key"]
    op = cond["op"]
    if key not in context:
        if op == "present":
            return (True, False, [])
        return (False, False, [key])
    value = context[key]
    if op == "eq":
        return (True, value == cond["value"], [])
    if op == "ne":
        return (True, value != cond["value"], [])
    if op == "in":
        try:
            hit = value in cond["value"]
        except TypeError:  # unhashable / uncomparable -- no match
            hit = False
        return (True, hit, [])
    if op == "startswith":
        return (True, isinstance(value, str)
                and value.startswith(cond["value"]), [])
    return (True, True, [])  # op == "present"


def _rule_outcome(rule, request):
    """Classify a rule against a request.

    Returns ``(outcome, missing)`` where outcome is ``"match"``,
    ``"no-match"``, or ``"partial"`` (from/to matched but ``when``
    could not be evaluated on missing attributes).
    """
    if not _match_from(rule["from"], request["principal"]):
        return ("no-match", [])
    if not _match_to(rule["to"], request["action"],
                     request["resource"]):
        return ("no-match", [])
    missing = []
    for cond in rule["when"]:
        decided, matched, miss = _eval_condition(
            cond, request["context"])
        if not decided:
            missing.extend(miss)
        elif not matched:
            return ("no-match", [])
    if missing:
        return ("partial", sorted(set(missing)))
    return ("match", [])


def _valid_request(request):
    return (isinstance(request, dict)
            and isinstance(request.get("principal"), str)
            and request.get("principal")
            and isinstance(request.get("action"), str)
            and request.get("action")
            and isinstance(request.get("resource"), str)
            and request.get("resource")
            and isinstance(request.get("context", {}), dict))


# ----------------------------------------------------------------------
# Evaluation -- ordered buckets, short-circuit, never raises.
# ----------------------------------------------------------------------

def _verdict(decision, code, reason, digest, matched_rules, audit_hits,
             shadow_results, partials, checked, detail=None):
    body = {"code": code, "request_digest": digest,
            "decision": decision, "matched_rules": matched_rules}
    return {
        "decision": decision,
        "admitted": decision == "allow",
        "code": code,
        "reason": reason,
        "request_digest": digest,
        "matched_rules": list(matched_rules),
        "audit_hits": list(audit_hits),
        "shadow_results": [dict(s) for s in shadow_results],
        "partial_attributes": [dict(p) for p in partials],
        "checked": list(checked),
        "out_of_scope": list(_OUT_OF_SCOPE),
        "evidence_digest": _sha256_hex(_canonical(body)),
        "detail": dict(detail) if detail else {},
    }


def _fail_closed(code, reason, request):
    try:
        digest = request_digest(request)
    except AuthorizationCombineError:
        digest = None
    return (_verdict("deny", code, reason, digest, [], [], [], [],
                     ["fail-closed"], None), [])


def _call_with_timeout(authorizer, pid, request, timeout_ms):
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        future = pool.submit(authorizer, pid, request)
        try:
            return future.result(timeout=timeout_ms / 1000.0)
        except concurrent.futures.TimeoutError:
            raise _ProviderFailed(
                "provider %r exceeded timeout_ms=%d" % (pid,
                                                        timeout_ms))
    except _ProviderFailed:
        raise
    except Exception as exc:  # noqa: BLE001 -- fail closed
        raise _ProviderFailed("provider %r raised %s: %s"
                              % (pid, type(exc).__name__, exc))
    finally:
        pool.shutdown(wait=False)


def _journal_event(events, event, rule, digest, extra=None):
    entry = {"event": event, "rule": rule,
             "request_digest": digest}
    if extra:
        entry.update(extra)
    events.append(entry)


def _evaluate(bundle, request, authorizer):
    if not isinstance(bundle, dict) or not isinstance(
            bundle.get("rules"), list):
        return _fail_closed(_UNCHECKABLE,
                            "bundle is not a loaded bundle", request)
    if not _valid_request(request):
        return _fail_closed(
            _UNCHECKABLE,
            "request must carry principal/action/resource as "
            "non-empty strings and context as a dict", request)
    request = {"principal": request["principal"],
               "action": request["action"],
               "resource": request["resource"],
               "context": dict(request.get("context", {}))}
    digest = request_digest(request)
    events = []
    checked = []
    audit_hits = []
    shadow_results = []
    partials = []          # all buckets; LOUD in the verdict + journal
    blocking_partials = []  # deny/custom/allow only; force the refuse
    matched_rules = []
    by_bucket = {"audit": [], "deny": [], "custom": [], "allow": []}
    for rule in bundle["rules"]:
        by_bucket[rule["action"]].append(rule)

    def note_partial(bucket, rule, missing):
        entry = {"bucket": bucket, "rule": rule["name"],
                 "missing": list(missing)}
        partials.append(entry)
        if bucket != "audit":
            blocking_partials.append(entry)
        _journal_event(events, _PARTIAL_ATTRIBUTES, rule["name"],
                       digest, {"bucket": bucket,
                                "missing": list(missing)})

    # AUDIT: evaluate every rule, log every hit, never enforce.
    for rule in by_bucket["audit"]:
        outcome, missing = _rule_outcome(rule, request)
        checked.append("audit:%s:%s" % (rule["name"], outcome))
        if rule["shadow"]:
            if outcome != "no-match":
                shadow_results.append({"rule": rule["name"],
                                       "would": "audit"})
                _journal_event(events, _SHADOW_EVALUATED,
                               rule["name"], digest,
                               {"would": "audit"})
            continue
        if outcome == "match":
            audit_hits.append(rule["name"])
            _journal_event(events, _AUDIT_HIT, rule["name"], digest)
        elif outcome == "partial":
            note_partial("audit", rule, missing)

    # DENY: any match short-circuits to deny before CUSTOM/ALLOW.
    for rule in by_bucket["deny"]:
        outcome, missing = _rule_outcome(rule, request)
        tag = "shadow-" if rule["shadow"] else ""
        checked.append("deny:%s:%s%s"
                       % (rule["name"], tag, outcome))
        if rule["shadow"]:
            if outcome != "no-match":
                shadow_results.append({"rule": rule["name"],
                                       "would": "deny"})
                _journal_event(events, _SHADOW_EVALUATED,
                               rule["name"], digest,
                               {"would": "deny"})
            continue
        if outcome == "match":
            matched_rules.append(rule["name"])
            return (_verdict("deny", _DENY,
                             "deny rule %r matched" % (rule["name"],),
                             digest, matched_rules, audit_hits,
                             shadow_results, partials, checked),
                    events)
        if outcome == "partial":
            # Fail toward deny on ambiguity -- never fail open.
            note_partial("deny", rule, missing)
            matched_rules.append(rule["name"])
            return (_verdict(
                "deny", _DENY,
                "deny rule %r matched on from/to; when[] unevaluable "
                "on missing attributes %s (fail-closed toward deny)"
                % (rule["name"], missing),
                digest, matched_rules, audit_hits, shadow_results,
                partials, checked),
                events)

    # CUSTOM: a matching rule consults the external authorizer. A
    # provider deny decides immediately; a provider allow continues to
    # the ALLOW bucket (it is not itself a grant).
    for rule in by_bucket["custom"]:
        outcome, missing = _rule_outcome(rule, request)
        tag = "shadow-" if rule["shadow"] else ""
        checked.append("custom:%s:%s%s"
                       % (rule["name"], tag, outcome))
        if rule["shadow"]:
            if outcome != "no-match":
                shadow_results.append({"rule": rule["name"],
                                       "would": "custom"})
                _journal_event(events, _SHADOW_EVALUATED,
                               rule["name"], digest,
                               {"would": "custom"})
            continue
        if outcome == "no-match":
            continue
        if outcome == "partial":
            # Ambiguity escalates to the external judgment, loudly.
            note_partial("custom", rule, missing)
        pid = rule["provider"]
        cfg = bundle.get("external_authorizers", {}).get(pid)
        if cfg is None or authorizer is None:
            _journal_event(events, _PROVIDER_MISCONFIGURED,
                           rule["name"], digest,
                           {"provider": pid,
                            "reason": "not configured" if cfg is None
                            else "no authorizer hook supplied"})
            return (_verdict(
                "deny", _PROVIDER_MISCONFIGURED,
                "custom rule %r matched but provider %r is "
                "misconfigured (fail-closed deny-everything)"
                % (rule["name"], pid),
                digest, matched_rules, audit_hits, shadow_results,
                partials, checked),
                events)
        try:
            result = _call_with_timeout(authorizer, pid, request,
                                        cfg["timeout_ms"])
        except _ProviderFailed as exc:
            _journal_event(events, _PROVIDER_MISCONFIGURED,
                           rule["name"], digest,
                           {"provider": pid, "reason": str(exc)})
            return (_verdict(
                "deny", _PROVIDER_MISCONFIGURED,
                "custom rule %r matched; provider %r failed: %s "
                "(fail-closed)" % (rule["name"], pid, exc),
                digest, matched_rules, audit_hits, shadow_results,
                partials, checked),
                events)
        if (not isinstance(result, (tuple, list)) or len(result) != 2
                or not isinstance(result[0], bool)):
            _journal_event(events, _PROVIDER_MISCONFIGURED,
                           rule["name"], digest,
                           {"provider": pid,
                            "reason": "malformed provider verdict"})
            return (_verdict(
                "deny", _PROVIDER_MISCONFIGURED,
                "custom rule %r matched; provider %r returned a "
                "malformed verdict (fail-closed)"
                % (rule["name"], pid),
                digest, matched_rules, audit_hits, shadow_results,
                partials, checked),
                events)
        allowed, provider_reason = result
        if not allowed:
            matched_rules.append(rule["name"])
            return (_verdict(
                "deny", _DENY,
                "custom rule %r matched; external authorizer %r "
                "denied: %s" % (rule["name"], pid, provider_reason),
                digest, matched_rules, audit_hits, shadow_results,
                partials, checked),
                events)
        matched_rules.append(rule["name"])
        checked.append("custom:%s:provider-allowed" % (rule["name"],))

    # ALLOW: any clean match admits. A partial match never grants.
    for rule in by_bucket["allow"]:
        outcome, missing = _rule_outcome(rule, request)
        tag = "shadow-" if rule["shadow"] else ""
        checked.append("allow:%s:%s%s"
                       % (rule["name"], tag, outcome))
        if rule["shadow"]:
            if outcome != "no-match":
                shadow_results.append({"rule": rule["name"],
                                       "would": "allow"})
                _journal_event(events, _SHADOW_EVALUATED,
                               rule["name"], digest,
                               {"would": "allow"})
            continue
        if outcome == "partial":
            note_partial("allow", rule, missing)
            continue
        if outcome == "match":
            matched_rules.append(rule["name"])
            return (_verdict("allow", _ALLOW,
                             "allow rule %r matched" % (rule["name"],),
                             digest, matched_rules, audit_hits,
                             shadow_results, partials, checked),
                    events)

    # Defaults: nothing decided.
    if blocking_partials:
        names = sorted(p["rule"] for p in blocking_partials)
        return (_verdict(
            "deny", _PARTIAL_ATTRIBUTES,
            "no rule cleanly decided and %d rule(s) unevaluable on "
            "missing attributes (fail-closed): %s"
            % (len(blocking_partials), ", ".join(names)),
            digest, matched_rules, audit_hits, shadow_results,
            partials, checked),
            events)
    has_allow = any(r["action"] == "allow" and not r["shadow"]
                    for r in bundle["rules"])
    if has_allow:
        return (_verdict("deny", _DEFAULT_DENY,
                         "no allow rule matched and >=1 allow rule "
                         "is configured (default-deny)",
                         digest, matched_rules, audit_hits,
                         shadow_results, partials, checked),
                events)
    return (_verdict("allow", _ALLOW,
                     "default-allow: no allow rules configured",
                     digest, matched_rules, audit_hits,
                     shadow_results, partials, checked),
            events)


def evaluate(bundle, request, *, authorizer=None, journal=None):
    """Evaluate a loaded bundle against a request.

    ``bundle``: :func:`load_bundle` output. ``request``: dict with
    ``principal`` / ``action`` / ``resource`` (non-empty strings) and
    ``context`` (dict of attributes). ``authorizer``: optional callable
    ``(provider_id, request) -> (bool, reason)`` consulted by matching
    CUSTOM rules. ``journal``: optional callable receiving event dicts
    (audit hits, shadow evaluations, provider misconfiguration,
    partial-attribute fidelity loss).

    Never raises: every failure is a coded fail-closed verdict.
    Deterministic; stdlib only; no ambient clock.
    """
    try:
        verdict, events = _evaluate(bundle, request, authorizer)
    except AuthorizationCombineError as exc:
        verdict, events = _fail_closed(exc.code,
                                       exc.detail or str(exc), request)
    except Exception:  # noqa: BLE001 -- evaluators never raise
        verdict, events = _fail_closed(_UNCHECKABLE,
                                       "evaluation error "
                                       "(fail-closed)", request)
    if journal is not None:
        journal_errors = []
        for event in events:
            try:
                journal(event)
            except Exception as exc:  # noqa: BLE001
                journal_errors.append("%s: %s"
                                      % (type(exc).__name__, exc))
        if journal_errors:
            detail = dict(verdict.get("detail") or {})
            detail["journal_errors"] = journal_errors
            verdict["detail"] = detail
    return verdict
