"""CheckResources contract + NDJSON decision records (Cerbos ADAPT).

PATTERN LINEAGE: cerbos/cerbos (Apache-2.0, LICENSE bytes verified by
the wave-279 prospecting lane) -- the CheckResources request/response
contract (``{principal, resource, actions}`` -> per-action effect +
matched policy + requestId), derived roles (request-time
condition-derived roles imported into policies), compile-error-on-shadow
(no silent dead rules; default deny), and the NDJSON decision-log
record schema. This is a clean-room stdlib re-implementation of the
*mechanisms*; no Cerbos code is vendored here, and there is no Go
sidecar in-tree (a network PDP hop would invert our fail-closed posture
on PDP-down -- the prospectus's explicit non-goal).

What this module is:
  - ``compile_bundle``: load-time validation of a rule bundle, including
    the shadow analysis. A rule fully shadowed by an earlier rule is a
    ``BundleCompileError``, not a silent dead rule. Duplicate rule ids
    and unknown condition ops refuse the same way.
  - ``CheckResources``: the PDP. Request (principal, resource, action,
    context) -> response (per-action decision + matched-policy
    provenance: WHICH rule decided and why). Default deny. Derived roles
    resolve at request time from condition rules (the
    "agent-that-created-this-session owns it" shape); the record carries
    the granted role NAMES plus the bundle/policy version, so an
    auditor holding the versioned bundle can re-derive exactly which
    condition granted each role (the Cerbos discipline: the decision
    log + the policy version are the derivation evidence -- no
    separate grant store to trust). Every decision is emitted as a
    hash-chained ``decision-record`` into the HMAC audit log AT
    DECISION TIME (never batched) via ``gov.log.ActionLog.append`` --
    the same wire ``gov/guardrail_evidence.py`` uses (composition, not
    duplication).
  - ``verify_decision_records``: offline verification of the per-writer
    record chain (digests + continuity), so dropped/tampered records
    refuse.

Traps NOT imported from Cerbos:
  - Audit is never opt-in here: ``CheckResources`` requires the audit
    sink at construction (a PDP that cannot write evidence cannot
    decide). This inverts Cerbos's audit-disabled-by-default.
  - Secrets never land in records: resource attributes are bound by
    digest only (Cerbos's ``excludeMetadataKeys`` lesson, applied by
    default rather than opt-in).
  - ``eq`` is type-strict (``1`` is not ``True`` -- the F295 lesson):
    a condition on ``resource.attr.flag == 1`` does not match
    ``flag=True``.
  - A missing/unresolvable operand makes a predicate False for every
    op (fail-closed), never an exception.

The restricted predicate language is deliberately NOT full CEL: ops
``eq/neq/gt/gte/lt/lte/in/not_in`` over subject paths
(``principal.id``, ``principal.attr.X``, ``resource.kind``,
``resource.id``, ``resource.attr.X``, ``context.X``). A condition
carries either ``"value"`` (a literal) or ``"ref"`` (a subject path for
cross-references -- the ``resource.attr.owner == principal.id`` shape
that derived roles need).

Stdlib only. Deterministic: no clock reads, no randomness; ordering is
bundle order and request order.
"""

import hashlib
import json

SCHEMA_VERSION = "1.0"
RECORD_TYPE = "decision-record"

OPS = ("eq", "neq", "gt", "gte", "lt", "lte", "in", "not_in")

_GENESIS = "genesis"
_DEFAULT_DENY_ID = "default_deny"


class CheckResourcesError(Exception):
    """Base: something refused at the CheckResources seam."""


class BundleCompileError(CheckResourcesError):
    """The rule bundle is invalid (shadow, duplicate id, bad shape).

    ``rule_id`` names the offending rule when the fault is rule-local
    (None for bundle-level faults).
    """

    def __init__(self, message, rule_id=None):
        super().__init__(message)
        self.rule_id = rule_id


class CheckRequestError(CheckResourcesError):
    """The check request is malformed (loud, fail-closed, typed)."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Predicate language
# ---------------------------------------------------------------------------

def _resolve_subject(subject, principal, resource, context):
    """Resolve a subject path to a value, or None when unresolvable."""
    if subject == "principal.id":
        return principal.get("id")
    if subject == "resource.kind":
        return resource.get("kind")
    if subject == "resource.id":
        return resource.get("id")
    if subject.startswith("principal.attr."):
        attrs = principal.get("attrs")
        if isinstance(attrs, dict):
            return attrs.get(subject[len("principal.attr."):])
        return None
    if subject.startswith("resource.attr."):
        attrs = resource.get("attrs")
        if isinstance(attrs, dict):
            return attrs.get(subject[len("resource.attr."):])
        return None
    if subject.startswith("context."):
        if isinstance(context, dict):
            return context.get(subject[len("context."):])
        return None
    return None


def _pred_key(cond):
    """Hashable identity of a compiled condition (for shadow analysis)."""
    if cond["is_ref"]:
        op_repr = ("ref", cond["operand_subject"])
    else:
        op_repr = ("lit", type(cond["operand"]).__name__,
                   _digest(_canonical(cond["operand"])))
    return (cond["subject"], cond["op"], op_repr)


def _compile_condition(raw, where):
    if not isinstance(raw, dict):
        raise BundleCompileError("condition must be a dict in %s" % where)
    subject = raw.get("subject")
    op = raw.get("op")
    if not isinstance(subject, str) or not subject:
        raise BundleCompileError(
            "condition subject must be a non-empty string in %s" % where)
    if op not in OPS:
        raise BundleCompileError(
            "unknown condition op %r in %s (allowed: %s)"
            % (op, where, ", ".join(OPS)))
    if "value" in raw and "ref" in raw:
        raise BundleCompileError(
            "condition has both value and ref in %s" % where)
    if "ref" in raw:
        ref = raw["ref"]
        if not isinstance(ref, str) or not ref:
            raise BundleCompileError(
                "condition ref must be a non-empty subject path in %s"
                % where)
        return {"subject": subject, "op": op, "operand": None,
                "is_ref": True, "operand_subject": ref}
    if "value" not in raw:
        raise BundleCompileError(
            "condition needs a value or a ref in %s" % where)
    return {"subject": subject, "op": op, "operand": raw["value"],
            "is_ref": False, "operand_subject": None}


def _eval_condition(cond, principal, resource, context):
    left = _resolve_subject(cond["subject"], principal, resource, context)
    if cond["is_ref"]:
        right = _resolve_subject(cond["operand_subject"], principal,
                                 resource, context)
    else:
        right = cond["operand"]
    # Fail-closed on missing/unresolvable operands: a predicate that
    # cannot be evaluated is False, never an exception.
    if left is None or right is None:
        return False
    op = cond["op"]
    try:
        if op == "eq":
            # Type-strict (F295): 1 is not True, "1" is not 1.
            return type(left) is type(right) and left == right
        if op == "neq":
            return not (type(left) is type(right) and left == right)
        if op == "gt":
            return left > right
        if op == "gte":
            return left >= right
        if op == "lt":
            return left < right
        if op == "lte":
            return left <= right
        if op == "in":
            return isinstance(right, (list, tuple)) and any(
                type(left) is type(x) and left == x for x in right)
        if op == "not_in":
            return isinstance(right, (list, tuple)) and not any(
                type(left) is type(x) and left == x for x in right)
    except TypeError:
        # Incomparable types (e.g. str > int): predicate is False.
        return False
    return False  # unreachable; the op vocabulary is closed at compile


# ---------------------------------------------------------------------------
# Bundle compilation (with shadow analysis)
# ---------------------------------------------------------------------------

_EFFECTS = ("allow", "deny")


def _compile_rule(raw):
    if not isinstance(raw, dict):
        raise BundleCompileError("rule must be a dict, got %r" % (raw,))
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise BundleCompileError("rule id must be a non-empty string")
    kind = raw.get("resource_kind")
    if not isinstance(kind, str) or not kind:
        raise BundleCompileError(
            "rule %r: resource_kind must be a non-empty string" % (rule_id,))
    actions = raw.get("actions", [])
    if not isinstance(actions, list) or not actions \
            or not all(isinstance(a, str) and a for a in actions):
        raise BundleCompileError(
            "rule %r: actions must be a non-empty list of strings"
            % (rule_id,))
    roles = raw.get("roles", [])
    if not isinstance(roles, list) \
            or not all(isinstance(r, str) and r for r in roles):
        raise BundleCompileError(
            "rule %r: roles must be a list of strings" % (rule_id,))
    principal_id = raw.get("principal_id")
    if principal_id is not None and \
            (not isinstance(principal_id, str) or not principal_id):
        raise BundleCompileError(
            "rule %r: principal_id must be a non-empty string or absent"
            % (rule_id,))
    effect = raw.get("effect")
    if effect not in _EFFECTS:
        raise BundleCompileError(
            "rule %r: effect must be allow/deny, got %r" % (rule_id, effect))
    reason = raw.get("reason", "")
    if not isinstance(reason, str):
        raise BundleCompileError(
            "rule %r: reason must be a string" % (rule_id,))
    conds = [_compile_condition(c, "rule %r" % (rule_id,))
             for c in raw.get("conditions", []) or []]
    return {
        "id": rule_id, "resource_kind": kind, "actions": list(actions),
        "roles": list(roles), "principal_id": principal_id,
        "effect": effect, "reason": reason, "conditions": conds,
        "condition_keys": frozenset(_pred_key(c) for c in conds),
    }


def _compile_derived_role(raw):
    if not isinstance(raw, dict):
        raise BundleCompileError("derived_role must be a dict")
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise BundleCompileError(
            "derived_role name must be a non-empty string")
    when = raw.get("when", [])
    if not isinstance(when, list) or not when:
        raise BundleCompileError(
            "derived_role %r: when must be a non-empty condition list"
            % (name,))
    conds = [_compile_condition(c, "derived_role %r" % (name,))
             for c in when]
    return {"name": name, "conditions": conds}


def _shadows(earlier, later):
    """True when `later` can never fire because `earlier` precedes it.

    Every request matching later's selector also matches earlier's:
    same kind; earlier's actions cover later's; earlier's roles cover
    later's (an empty roles list matches any role); earlier's
    principal constraint covers later's; every one of earlier's
    conditions is implied by later's (exact-predicate subset -- sound
    but incomplete; a missed implication just means no flag, never a
    false flag).
    """
    if earlier["resource_kind"] != later["resource_kind"]:
        return False
    if "*" not in earlier["actions"]:
        if "*" in later["actions"]:
            return False
        if not set(later["actions"]) <= set(earlier["actions"]):
            return False
    if earlier["roles"]:
        if not later["roles"]:
            return False
        if not set(later["roles"]) <= set(earlier["roles"]):
            return False
    if earlier["principal_id"] is not None \
            and earlier["principal_id"] != later["principal_id"]:
        return False
    return earlier["condition_keys"] <= later["condition_keys"]


def compile_bundle(bundle):
    """Validate a rule bundle and return the compiled form.

    The returned dict holds tuples of compiled rules and derived
    roles; treat it as read-only (the module never mutates it after
    return, but the container types are plain dicts/tuples, not
    frozen).

    Raises BundleCompileError on: non-dict bundle, duplicate rule ids,
    malformed rules/conditions, or any rule fully shadowed by an
    earlier rule (dead rules are load-time errors, never silent).
    """
    if not isinstance(bundle, dict):
        raise BundleCompileError("bundle must be a dict")
    bundle_version = bundle.get("bundle_version", "")
    policy_version = bundle.get("policy_version", "")
    if not isinstance(bundle_version, str) or not isinstance(policy_version, str):
        raise BundleCompileError(
            "bundle_version/policy_version must be strings")
    raw_rules = bundle.get("rules", [])
    if not isinstance(raw_rules, list):
        raise BundleCompileError("bundle rules must be a list")
    seen = set()
    rules = []
    for raw in raw_rules:
        rule = _compile_rule(raw)
        if rule["id"] in seen:
            raise BundleCompileError(
                "duplicate rule id %r" % (rule["id"],))
        seen.add(rule["id"])
        for earlier in rules:
            if _shadows(earlier, rule):
                raise BundleCompileError(
                    "rule %r is fully shadowed by earlier rule %r: "
                    "it can never fire" % (rule["id"], earlier["id"]),
                    rule_id=rule["id"])
        rules.append(rule)
    raw_roles = bundle.get("derived_roles", [])
    if not isinstance(raw_roles, list):
        raise BundleCompileError("derived_roles must be a list")
    derived = [_compile_derived_role(r) for r in raw_roles]
    role_names = [d["name"] for d in derived]
    if len(set(role_names)) != len(role_names):
        raise BundleCompileError("duplicate derived role name")
    return {
        "bundle_version": bundle_version,
        "policy_version": policy_version,
        "rules": tuple(rules),
        "derived_roles": tuple(derived),
    }


# ---------------------------------------------------------------------------
# Request checking
# ---------------------------------------------------------------------------

#: Fields owned by this module on a decision record. The audit log adds
#: reserved chain metadata (seq, ts, prev_hash, MACs, ...) around them;
#: digest verification only covers these fields so log bookkeeping never
#: breaks it.
RECORD_FIELDS = (
    "record_type", "schema_version",
    "request_id",
    "principal_id", "principal_roles", "derived_roles",
    "resource_kind", "resource_id", "resource_attrs_digest",
    "action", "effect", "matched_rule_id", "rule_reason",
    "action_index", "action_count",
    "policy_version", "bundle_version",
    "prev_decision_record_digest", "record_digest",
)


class ActionDecision:
    """One per-action decision: effect + matched-policy provenance."""

    def __init__(self, effect, matched_rule_id, reason, derived_roles):
        self.effect = effect
        self.matched_rule_id = matched_rule_id
        self.reason = reason
        self.derived_roles = list(derived_roles)


class CheckResponse:
    """The per-request response: request_id + per-action decisions."""

    def __init__(self, request_id, results):
        self.request_id = request_id
        self.results = dict(results)


def _validate_request(request):
    if not isinstance(request, dict):
        raise CheckRequestError("request must be a dict")
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        raise CheckRequestError("request_id must be a non-empty string")
    principal = request.get("principal")
    if not isinstance(principal, dict):
        raise CheckRequestError("principal must be a dict")
    if not isinstance(principal.get("id"), str) or not principal.get("id"):
        raise CheckRequestError("principal.id must be a non-empty string")
    roles = principal.get("roles", [])
    if not isinstance(roles, list) \
            or not all(isinstance(r, str) for r in roles):
        raise CheckRequestError("principal.roles must be a list of strings")
    if not isinstance(principal.get("attrs", {}), dict):
        raise CheckRequestError("principal.attrs must be a dict")
    resource = request.get("resource")
    if not isinstance(resource, dict):
        raise CheckRequestError("resource must be a dict")
    for key in ("kind", "id"):
        if not isinstance(resource.get(key), str) or not resource.get(key):
            raise CheckRequestError(
                "resource.%s must be a non-empty string" % (key,))
    if not isinstance(resource.get("attrs", {}), dict):
        raise CheckRequestError("resource.attrs must be a dict")
    actions = request.get("actions")
    if not isinstance(actions, list) or not actions \
            or not all(isinstance(a, str) and a for a in actions):
        raise CheckRequestError(
            "actions must be a non-empty list of non-empty strings")
    if len(set(actions)) != len(actions):
        # Duplicate actions would collapse in CheckResponse.results
        # while emitting two chained records -- the response would
        # silently under-report a decision the log holds. Refuse.
        raise CheckRequestError("actions must not contain duplicates")
    context = request.get("context", {})
    if not isinstance(context, dict):
        raise CheckRequestError("context must be a dict")
    return request_id, principal, resource, actions, context


def _resolve_derived_roles(derived, principal, resource, context):
    granted = []
    for role in derived:
        if all(_eval_condition(c, principal, resource, context)
               for c in role["conditions"]):
            granted.append(role["name"])
    return granted


def _rule_matches(rule, action, effective_roles, principal, resource,
                  context):
    if rule["resource_kind"] != resource.get("kind"):
        return False
    if "*" not in rule["actions"] and action not in rule["actions"]:
        return False
    if rule["roles"] and not (set(rule["roles"]) & set(effective_roles)):
        return False
    if rule["principal_id"] is not None \
            and rule["principal_id"] != principal.get("id"):
        return False
    return all(_eval_condition(c, principal, resource, context)
               for c in rule["conditions"])


class _RequestScope:
    """Internal: the per-request values that travel together.

    (Fixes the 9-parameter positional cascade the review flagged: the
    request_id/principal/resource/action/context clump is one object
    now, not five positional args.)
    """

    def __init__(self, request_id, principal, resource, context,
                 derived, effective_roles, action_count):
        self.request_id = request_id
        self.principal = principal
        self.resource = resource
        self.context = context
        self.derived = derived
        self.effective_roles = effective_roles
        self.action_count = action_count


class CheckResources:
    """The CheckResources PDP: request -> per-action decisions + records.

    ``log`` is REQUIRED (an object with ``.append(dict)`` -- the HMAC
    ``ActionLog``): a PDP that cannot write evidence cannot decide
    (the Cerbos audit-disabled-by-default trap, inverted). Each
    action's decision is appended as a ``decision-record`` at decision
    time, never batched; a failing append propagates and the caller
    must not treat the decision as evidenced.

    One instance chains its own records via
    ``prev_decision_record_digest`` (per-writer chain, the
    guardrail_evidence pattern); the enclosing HMAC log gives global
    ordering.
    """

    def __init__(self, compiled, log):
        if not isinstance(compiled, dict) or "rules" not in compiled:
            raise CheckResourcesError(
                "compiled must come from compile_bundle()")
        if log is None or not hasattr(log, "append"):
            raise CheckResourcesError(
                "an audit sink is required: CheckResources cannot decide "
                "without writing decision records (no silent unaudited "
                "decisions)")
        self._compiled = compiled
        self._log = log
        self._last_digest = _GENESIS

    def check(self, request):
        """Check one request; returns CheckResponse.

        Request shape: {"request_id", "principal": {"id", "roles",
        "attrs"}, "resource": {"kind", "id", "attrs"}, "actions": [...],
        "context": {...}} -- the caller supplies ALL attributes (the
        PIP is the integrator's job, per the Cerbos discipline); the
        PDP evaluates, it does not look anything up.
        """
        request_id, principal, resource, actions, context = \
            _validate_request(request)
        derived = _resolve_derived_roles(self._compiled["derived_roles"],
                                         principal, resource, context)
        effective_roles = list(principal.get("roles", [])) + derived
        scope = _RequestScope(request_id, principal, resource, context,
                              derived, effective_roles, len(actions))
        results = {}
        for idx, action in enumerate(actions):
            decision = self._decide_one(scope, action, idx)
            results[action] = decision
        return CheckResponse(request_id, results)

    def _decide_one(self, scope, action, action_index):
        matched = None
        for rule in self._compiled["rules"]:
            if _rule_matches(rule, action, scope.effective_roles,
                             scope.principal, scope.resource,
                             scope.context):
                matched = rule
                break
        if matched is None:
            effect = "deny"
            matched_rule_id = _DEFAULT_DENY_ID
            reason = "no rule matched: default deny"
        else:
            effect = matched["effect"]
            matched_rule_id = matched["id"]
            reason = matched["reason"]
        record = {
            "record_type": RECORD_TYPE,
            "schema_version": SCHEMA_VERSION,
            "request_id": scope.request_id,
            "principal_id": scope.principal["id"],
            "principal_roles": list(scope.principal.get("roles", [])),
            "derived_roles": list(scope.derived),
            "resource_kind": scope.resource["kind"],
            "resource_id": scope.resource["id"],
            # Attrs bound by digest only: secret-shaped values must
            # never land raw in the record (the excludeMetadataKeys
            # lesson, applied by default).
            "resource_attrs_digest": _digest(
                _canonical(scope.resource.get("attrs", {}))),
            "action": action,
            "effect": effect,
            "matched_rule_id": matched_rule_id,
            "rule_reason": reason,
            # Completeness is checkable per request: a verifier that
            # knows the request expects indices 0..action_count-1, so
            # a dropped suffix is detectable (a chain alone cannot
            # attest to its own completeness -- the index/count pair
            # closes that).
            "action_index": action_index,
            "action_count": scope.action_count,
            "policy_version": self._compiled["policy_version"],
            "bundle_version": self._compiled["bundle_version"],
            "prev_decision_record_digest": self._last_digest,
        }
        record["record_digest"] = _digest(_canonical(record))
        # Fail-closed: a write failure propagates; the decision is not
        # evidenced and the caller must not treat it as made.
        self._log.append(record)
        self._last_digest = record["record_digest"]
        return ActionDecision(effect, matched_rule_id, reason,
                              scope.derived)


def decision_records(log):
    """All decision-record entries in ``log``, in stored order."""
    from gov.log import read_entries
    return [e for e in read_entries(log.path)
            if e.get("record_type") == RECORD_TYPE]


def request_records_complete(records, *, request_id):
    """True iff every action decision of a request is present.

    Collects records for ``request_id`` and requires the
    ``action_index`` set to equal ``range(action_count)`` with a single
    consistent ``action_count``. This is the completeness half that a
    chain alone cannot provide: a dropped suffix still chain-verifies,
    but it cannot fake the missing indices.
    """
    mine = [r for r in records if r.get("request_id") == request_id]
    if not mine:
        return False
    counts = {r.get("action_count") for r in mine}
    if len(counts) != 1:
        return False
    count = counts.pop()
    if not isinstance(count, int) or count <= 0:
        return False
    indices = {r.get("action_index") for r in mine}
    return indices == set(range(count))


def verify_decision_records(records):
    """Verify record digests and per-writer chain continuity.

    Returns True when every record's ``record_digest`` recomputes over
    this module's fields and each record's
    ``prev_decision_record_digest`` links the previous record (the
    first must link ``genesis``). Returns False on any mismatch --
    tampered effects, reordered records, injected samples.

    NOTE: a list mixing records from interleaved writers fails the
    continuity check honestly; verify each writer's subsequence
    separately (the guardrail_evidence discipline). The HMAC chain of
    the enclosing audit log is verified separately by the log reader --
    that is what makes the records evidence rather than claims.
    """
    prev = _GENESIS
    for rec in records:
        if rec.get("record_type") != RECORD_TYPE:
            return False
        if rec.get("prev_decision_record_digest") != prev:
            return False
        body = {k: rec.get(k) for k in RECORD_FIELDS
                if k != "record_digest"}
        if rec.get("record_digest") != _digest(_canonical(body)):
            return False
        prev = rec["record_digest"]
    return True
