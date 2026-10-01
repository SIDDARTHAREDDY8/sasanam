"""Policy-delta counterexamples (wave-267 feature lane).

ADAPT of two Cedar patterns (Apache-2.0, verified in-repo by the
wave-266 prospecting lane; patterns only, no Cedar code vendored):

1. Cedar SymCC ``check_implies_with_counterexample`` -- a concrete
   violating request as the review artifact. The wave-266
   ``gov/policy_change_containment.py`` answers "does this widen
   authority?" with a verdict plus count-level detail; this module
   emits the REVIEW ARTIFACT: per expansion atom, the exact
   (subject, action, resource) grant, the boundary verdict for that
   grant, and which risk check(s) fired on it.
2. Cedar forbid semantics (authorizer.rs / partial_response.rs):
   hard-override forbid; default-deny in the ENGINE (no policy can
   express "allow everything"); any residual (unevaluable) forbid
   => decision-UNKNOWN, never fail-open; error-skip fail-closed --
   errors can only move toward deny.

Composition (never duplication):

* :func:`counterexamples` composes the public
  :func:`gov.policy_change_containment.check_policy_change` for the
  gate verdict, and reuses that module's private predicates for
  per-atom attribution, so the review artifacts can never drift
  from the verdicts (pinned by the battery's no-drift probe).
* :func:`evaluate` is a small request-evaluation engine with the
  Cedar combine: deny rules hard-override allows; default-deny;
  residual deny => Unknown; errors skip toward deny.
* :func:`request_review` queues the counterexamples on a
  :class:`gov.agent_callbacks.HumanApprovalGate` as digest-only
  review evidence; the concrete artifacts go back to the caller,
  never into the journal.

What this module provides, stdlib-only:

* :func:`counterexamples`: compare candidate vs current vs the
  declared damage boundary. Returns a record with one concrete
  counterexample per expansion grant. Raises
  :class:`PolicyDeltaError` only on malformed (authoring-error)
  input, never on a checkable-but-failing change.
* :func:`evaluate`: authorize a single request against a policy.
  Returns a decision record; "Unknown" must be treated as Deny by
  the deployment (never fail-open).
* :func:`request_review`: wire counterexamples into the
  human-approval queue (digest-only journal, artifacts to caller).

Fail-closed: a surviving deny/forbid rule in the candidate vetoes
the delta (``policy-delta-forbid-residual``) -- the check cannot
model deny semantics, so the delta is uncheckable, never a vacuous
pass. Unmodeled shapes, evaluation errors, and malformed requests
all move toward deny/unknown. Nothing is approved on a partial
check.

Honest boundaries (stated, not absorbed):

* Deterministic over-approximation, not an SMT proof: the
  containment question is answered by the same static check as
  wave-266; counterexamples are concrete only within the modeled
  rule language.
* Deny rules are vetoes, not modeled semantics: the engine treats
  a deny rule as a hard override on COVERED requests, but the
  delta check cannot prove what a deny rule removes -- hence the
  veto.
* Default-deny lives in the engine: a wildcard allow rule
  (``hosts: ["*"]``) is a deployment choice the engine will honor;
  the containment/boundary checks are what audit it.
* The approval queue gets digests only; the concrete artifacts are
  caller-held. A receipt proves a keyholder queued a scope-bound
  review, not that the review was independent.

Stdlib only. Deterministic: no clock, no I/O, no network, no
in-repo git subprocesses.
"""

import hashlib
import json
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov.policy_change_containment import (
    # Same-package reuse is deliberate: per-atom attribution MUST
    # use the exact predicates the gate verdict uses, so the
    # review artifacts can never drift from the verdicts. The
    # battery's no-drift probe pins this invariant.
    BOUNDARY_EXCEEDED,
    CAPABILITY_EXPANSION,
    CREDENTIAL_REACH_EXPANSION,
    L7_BYPASS,
    LINK_LOCAL_REACH,
    POLICY_VERSION,
    PolicyChangeError,
    _CHECKED,
    _OUT_OF_SCOPE,
    _Uncheckable,
    _atoms,
    _could_reach_credentialed,
    _covered_by,
    _covers,
    _host_covers,
    _is_link_local,
    _load_policy,
    _parse_host,
    _parse_method,
    _parse_path,
    _parse_port,
    _port_covers,
    check_policy_change,
)

__all__ = [
    "CODES",
    "POLICY_VERSION",
    "PolicyDeltaError",
    "counterexamples",
    "evaluate",
    "request_review",
]

# New decision codes introduced by this module (see
# gov/decision_codes.py). Sorted; the taxonomy merge asserts raw
# literal uniqueness. ``policy-delta-malformed`` already exists
# (owned by gov/policy_delta_gate.py) and is reused for this
# seam's loud malformed refusal instead of minting a duplicate.
CODES = (
    "policy-delta-counterexample-raised",
    "policy-delta-default-deny",
    "policy-delta-evaluation-error",
    "policy-delta-forbid",
    "policy-delta-forbid-residual",
    "policy-delta-unknown",
)

COUNTEREXAMPLE_RAISED = "policy-delta-counterexample-raised"
DEFAULT_DENY = "policy-delta-default-deny"
EVALUATION_ERROR = "policy-delta-evaluation-error"
FORBID = "policy-delta-forbid"
FORBID_RESIDUAL = "policy-delta-forbid-residual"
MALFORMED = "policy-delta-malformed"  # existing; reused, not minted
UNKNOWN = "policy-delta-unknown"

#: Fixed check order shared with the containment module.
_CHECK_ORDER = (BOUNDARY_EXCEEDED, LINK_LOCAL_REACH, L7_BYPASS,
                CREDENTIAL_REACH_EXPANSION, CAPABILITY_EXPANSION)

_DELTA_CHECKED = _CHECKED + (
    "counterexample-attribution",
    "forbid-residual-scan",
    "request-engine-default-deny",
)

_DELTA_OUT_OF_SCOPE = _OUT_OF_SCOPE + (
    "SMT-grade proof (deterministic over-approximation only; "
    "counterexamples are concrete within the modeled rule "
    "language)",
)


class PolicyDeltaError(Exception):
    """Loud policy-delta failure. ``code`` is a closed vocabulary
    member of :data:`CODES`."""

    def __init__(self, code, detail=""):
        super(PolicyDeltaError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _refuse(code, detail=""):
    raise PolicyDeltaError(code, detail)


def _malformed(what, detail):
    _refuse(MALFORMED, "%s: %s" % (what, detail))


def _deny_rule_ids(candidate):
    """Raw scan for surviving deny/forbid rules. Runs on the raw
    document BEFORE the allow-only loader rejects them: a deny
    rule the check cannot model must veto, never slip through."""
    if not isinstance(candidate, dict):
        return []
    rules = candidate.get("rules")
    if not isinstance(rules, list):
        return []
    return [r.get("id") if isinstance(r.get("id"), str) else
            "rules[%d]" % i
            for i, r in enumerate(rules)
            if isinstance(r, dict) and r.get("effect") == "deny"]


def _allow_only(candidate):
    """Rebuild the candidate with deny rules removed, so the
    allow-expansion can still be attributed for the reviewer even
    when a forbid vetoes the delta."""
    rules = candidate.get("rules", [])
    kept = [r for r in rules
            if not (isinstance(r, dict)
                    and r.get("effect") == "deny")]
    doc = dict(candidate)
    doc["rules"] = kept
    return doc


def _cred_hosts(credentialed_hosts):
    try:
        if isinstance(credentialed_hosts, str):
            raise TypeError("bare string")
        return frozenset(h.lower() for h in credentialed_hosts)
    except TypeError:
        _malformed("credentialed_hosts",
                   "must be an iterable of host strings")


def _atom_failed_checks(atom, bound_atoms, curr_atoms, cred_hosts):
    """Per-atom attribution: the exact expansion classification
    the containment gate uses, verbatim. Any drift between this
    and check_policy_change is a defect the battery pins."""
    fired = []
    if not _covered_by(atom, bound_atoms):
        fired.append(BOUNDARY_EXCEEDED)
    if atom[1] == "egress" and _is_link_local(atom[2]):
        fired.append(LINK_LOCAL_REACH)
    if atom[1] == "egress" \
            and _could_reach_credentialed(atom[2], cred_hosts):
        fired.append(L7_BYPASS)
    if atom[6] is not None and not any(
            m[0] == atom[0] and m[6] == atom[6]
            for m in curr_atoms):
        fired.append(CREDENTIAL_REACH_EXPANSION)
    if atom[1] == "egress" and atom[6] is None \
            and not _is_link_local(atom[2]) \
            and not _could_reach_credentialed(atom[2], cred_hosts) \
            and any(m[1] == "egress" and m[0] == atom[0]
                    and _host_covers(m[2], atom[2])
                    and _port_covers(m[3], atom[3])
                    for m in curr_atoms):
        fired.append(CAPABILITY_EXPANSION)
    return [c for c in _CHECK_ORDER if c in fired]


def _render_shape(shape):
    """Render a parsed shape back to its concrete surface form.
    Never raises: the fallback is the raw repr, because a review
    artifact must not die on display."""
    if shape == ("any",):
        return "*"
    if shape == ("none",):
        return "-"
    kind = shape[0]
    if kind in ("exact", "ip", "cidr", "method"):
        return str(shape[1])
    if kind == "suffix":
        return "*." + str(shape[1])
    if kind == "port":
        return str(shape[1])
    if kind == "range":
        return "%d-%d" % (shape[1], shape[2])
    if kind == "prefix":
        return str(shape[1]) + "*"
    return repr(shape)


def _render_resource(atom):
    (_sub, _act, host, port, method, path, credential) = atom
    return {"host": _render_shape(host),
            "port": _render_shape(port),
            "method": _render_shape(method),
            "path": _render_shape(path),
            "credential": credential if credential is not None
            else "-"}


def _digest_record(obj):
    """Canonical SHA-256 digest of a JSON record (evidence link)."""
    canonical = json.dumps(obj, sort_keys=True,
                           separators=(",", ":"),
                           default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _counterexample(subject, action, resource, within_boundary,
                    failed_checks):
    artifact = {"code": COUNTEREXAMPLE_RAISED,
                "subject": subject,
                "action": action,
                "resource": resource,
                "within_boundary": bool(within_boundary),
                "failed_checks": list(failed_checks)}
    artifact["evidence_digest"] = _digest_record(artifact)
    return artifact


def _record(verdict, delta_class, failed, cxs, detail=""):
    record = {"verdict": verdict,
              "delta_class": delta_class,
              "failed_checks": list(failed),
              "counterexamples": list(cxs),
              "checked": list(_DELTA_CHECKED),
              "out_of_scope": list(_DELTA_OUT_OF_SCOPE),
              "detail": detail}
    record["evidence_digest"] = _digest_record(record)
    return record


def counterexamples(candidate, current, boundary,
                    credentialed_hosts=()):
    """Emit one concrete counterexample per expansion grant.

    Returns a record: gate ``verdict``/``delta_class`` (composed
    from :func:`check_policy_change`), ``failed_checks``, and the
    ``counterexamples`` list. A surviving deny rule vetoes the
    delta (``policy-delta-forbid-residual``): the allow-expansion
    is still attributed for the reviewer, but the verdict is
    ``uncheckable`` -- never a vacuous pass. Raises
    :class:`PolicyDeltaError` only on malformed input."""
    deny_ids = _deny_rule_ids(candidate)
    try:
        report = check_policy_change(candidate, current, boundary,
                                     credentialed_hosts)
    except PolicyChangeError as e:
        _refuse(MALFORMED, e.detail)
    cred_hosts = _cred_hosts(credentialed_hosts)

    # Attribute the allow-expansion even under a forbid veto, so
    # the reviewer sees what else the candidate would do.
    attr_candidate = _allow_only(candidate) if deny_ids \
        else candidate
    try:
        cand_rules = _load_policy(attr_candidate, "candidate")
        curr_rules = _load_policy(current, "current")
        bound_rules = _load_policy(boundary, "boundary")
    except _Uncheckable:
        # Cannot attribute: mirror the gate verdict honestly.
        failed = list(report["failed_checks"])
        if UNKNOWN not in failed:
            failed.append(UNKNOWN)
        return _record("uncheckable", report["delta_class"], failed,
                       [], "delta not attributable: unmodeled shape")
    cand_atoms = _atoms(cand_rules)
    curr_atoms = _atoms(curr_rules)
    bound_atoms = _atoms(bound_rules)

    expansion = sorted(
        (a for a in cand_atoms if not _covered_by(a, curr_atoms)),
        key=lambda a: json.dumps(a, sort_keys=True, default=str))

    cxs = []
    errored = False
    for atom in expansion:
        try:
            fired = _atom_failed_checks(atom, bound_atoms,
                                        curr_atoms, cred_hosts)
            resource = _render_resource(atom)
        except Exception:
            # Error-skip fail-closed: an unattributable atom is
            # never silently dropped; it poisons the verdict.
            errored = True
            fired = [EVALUATION_ERROR]
            resource = _render_resource(atom)
        cxs.append(_counterexample(atom[0], atom[1], resource,
                                   BOUNDARY_EXCEEDED not in fired,
                                   fired))

    failed = list(report["failed_checks"])
    if deny_ids and FORBID_RESIDUAL not in failed:
        failed.insert(0, FORBID_RESIDUAL)
    if errored:
        verdict = "uncheckable"
        if EVALUATION_ERROR not in failed:
            failed.append(EVALUATION_ERROR)
        detail = "per-atom attribution failed; delta uncheckable"
    else:
        verdict = "uncheckable" if deny_ids else report["verdict"]
        detail = ("forbid veto: deny rule(s) %s survive in the "
                  "candidate" % (", ".join(deny_ids),)) if deny_ids \
            else report["detail"]
    return _record(verdict, report["delta_class"], failed, cxs,
                   detail)


# ------------------------------------------------------------------
# Request engine: Cedar combine (hard forbid, default-deny,
# residual-forbid => Unknown, error-skip fail-closed).
# ------------------------------------------------------------------

def _parse_rule_engine(rule, idx):
    """Deny-aware rule parse for the request engine. Mirrors
    ``_parse_rule`` but models ``effect: deny`` as a hard
    override instead of rejecting it as uncheckable. Unmodeled
    SHAPES raise _Uncheckable (the caller turns deny-rule
    residuals into Unknown); malformed input raises loudly."""
    what = "rules[%d]" % idx
    if not isinstance(rule, dict):
        _malformed(what, "rule must be a dict")
    rid = rule.get("id")
    if not isinstance(rid, str) or not rid:
        _malformed(what, "id must be a non-empty string")
    subject = rule.get("subject")
    if not isinstance(subject, str) or not subject:
        _malformed(what, "subject must be a non-empty string")
    effect = rule.get("effect", "allow")
    if effect not in ("allow", "deny"):
        _malformed(what, "effect must be 'allow' or 'deny', got %r"
                   % (effect,))
    action = rule.get("action")
    if action not in ("egress", "credential-use"):
        _malformed(what, "action must be 'egress' or "
                   "'credential-use', got %r" % (action,))
    credential = rule.get("credential")
    if credential is not None and \
            (not isinstance(credential, str) or not credential):
        _malformed(what, "credential must be a string or null")
    parsed = {"id": rid, "subject": subject, "effect": effect,
              "action": action, "credential": credential}
    if action == "egress":
        for key, parser in (("hosts", _parse_host),
                            ("ports", _parse_port),
                            ("methods", _parse_method),
                            ("paths", _parse_path)):
            values = rule.get(key)
            if not isinstance(values, list) or not values:
                _malformed(what, "%s must be a non-empty list" % key)
            parsed[key] = [parser(v, "%s.%s" % (what, key))
                           for v in values]
    else:
        if credential is None:
            _malformed(what, "credential-use needs a credential")
        for key in ("hosts", "ports", "methods", "paths"):
            parsed[key] = [("none",)]
    return parsed


def _load_policy_engine(doc, what):
    """Deny-aware load. Returns (rules, residual_deny_ids).
    Malformed raises PolicyDeltaError; per-rule unmodeled shapes
    in DENY rules become residuals (Unknown), never skips; in
    ALLOW rules they skip toward deny."""
    if not isinstance(doc, dict):
        _malformed(what, "policy must be a dict, got %s"
                   % type(doc).__name__)
    if doc.get("version") != POLICY_VERSION:
        _malformed(what, "version must be %d, got %r"
                   % (POLICY_VERSION, doc.get("version")))
    rules = doc.get("rules")
    if not isinstance(rules, list):
        _malformed(what, "rules must be a list")
    parsed = []
    residual = []
    skipped = []
    for i, raw in enumerate(rules):
        try:
            parsed.append(_parse_rule_engine(raw, i))
        except _Uncheckable:
            if isinstance(raw, dict) and \
                    raw.get("effect") == "deny":
                rid = raw.get("id")
                residual.append(rid if isinstance(rid, str)
                                else "rules[%d]" % i)
            else:
                rid = raw.get("id") if isinstance(raw, dict) \
                    else None
                skipped.append(rid if isinstance(rid, str)
                               else "rules[%d]" % i)
    ids = [r["id"] for r in parsed]
    if len(set(ids)) != len(ids):
        _malformed(what, "duplicate rule ids")
    return parsed, residual, skipped


def _parse_request(req):
    """Parse a request to a concrete atom. Malformed raises
    PolicyDeltaError; unmodeled shapes raise _Uncheckable. The
    caller fails both closed (Deny)."""
    if not isinstance(req, dict):
        _malformed("request", "request must be a dict")
    subject = req.get("subject")
    if not isinstance(subject, str) or not subject:
        _malformed("request", "subject must be a non-empty string")
    action = req.get("action")
    if action not in ("egress", "credential-use"):
        _malformed("request", "action must be 'egress' or "
                   "'credential-use', got %r" % (action,))
    credential = req.get("credential")
    if credential is not None and \
            (not isinstance(credential, str) or not credential):
        _malformed("request", "credential must be a string or null")
    if action == "credential-use":
        if credential is None:
            _malformed("request", "credential-use needs a "
                       "credential")
        return (subject, "credential-use", ("none",), ("none",),
                ("none",), ("none",), credential)
    host = _parse_host(req.get("host"), "request.host")
    port = _parse_port(req.get("port"), "request.port")
    method = _parse_method(req.get("method"), "request.method")
    path = _parse_path(req.get("path"), "request.path")
    return (subject, "egress", host, port, method, path, credential)


def evaluate(policy, request):
    """Authorize one request. Returns a decision record:
    ``decision`` in ("Allow", "Deny", "Unknown"), ``reason`` (a
    machine code for Deny/Unknown), ``matched_rule``.

    The combine: a covering deny rule hard-overrides any allow;
    no covering allow => Deny (default-deny lives in the engine);
    a residual (unevaluable) deny rule => Unknown -- the
    deployment MUST treat Unknown as Deny, never fail-open;
    evaluation errors skip toward deny, never toward allow.
    Malformed policy raises loudly; a malformed request Denies."""
    try:
        rules, residual, _skipped = _load_policy_engine(
            policy, "policy")
    except PolicyDeltaError:
        raise
    except PolicyChangeError as e:
        _refuse(MALFORMED, e.detail)
    try:
        req_atom = _parse_request(request)
    except (_Uncheckable, PolicyDeltaError, PolicyChangeError):
        return {"decision": "Deny", "reason": EVALUATION_ERROR,
                "matched_rule": None}
    if residual:
        # Residual forbid: we cannot prove the deny does NOT
        # cover the request => Unknown, never fail-open.
        return {"decision": "Unknown", "reason": FORBID_RESIDUAL,
                "matched_rule": residual[0]}
    for rule in rules:
        if rule["effect"] != "deny":
            continue
        try:
            covered = any(_covers(a, req_atom)
                          for a in _atoms([rule]))
        except Exception:
            # Cannot confirm the deny does not cover => Unknown.
            return {"decision": "Unknown",
                    "reason": FORBID_RESIDUAL,
                    "matched_rule": rule["id"]}
        if covered:
            return {"decision": "Deny", "reason": FORBID,
                    "matched_rule": rule["id"]}
    for rule in rules:
        if rule["effect"] != "allow":
            continue
        try:
            covered = any(_covers(a, req_atom)
                          for a in _atoms([rule]))
        except Exception:
            # Error-skip fail-closed: skip toward deny.
            continue
        if covered:
            return {"decision": "Allow", "reason": "allow",
                    "matched_rule": rule["id"]}
    return {"decision": "Deny", "reason": DEFAULT_DENY,
            "matched_rule": None}


def request_review(gate, record, policy_id):
    """Queue counterexamples on a HumanApprovalGate as digest-only
    review evidence. Returns (approval_id, artifacts): the journal
    gets digests only; the concrete artifacts go back to the
    caller and are never journaled raw."""
    if gate is None or not hasattr(gate, "request"):
        _malformed("gate", "needs a HumanApprovalGate-like object "
                   "with .request()")
    if not isinstance(record, dict) or \
            "counterexamples" not in record:
        _malformed("record", "needs a counterexamples() record")
    if not isinstance(policy_id, str) or not policy_id:
        _malformed("policy_id", "must be a non-empty string")
    cxs = record["counterexamples"]
    args = {"policy_id": policy_id,
            "verdict": record.get("verdict"),
            "failed_checks": list(record.get("failed_checks", [])),
            "n_counterexamples": len(cxs),
            "counterexamples_digest": _digest_record(cxs)}
    approval_id = gate.request("policy-delta-review", args)
    return approval_id, cxs
