"""First-class policy exceptions (wave-268).

Shape stolen from Kyverno ``PolicyException`` (wave-267 prospectus,
``kyverno/kyverno`` @ ``210d42a089415e46ef5889cb5d022e0113f8def3``,
Apache-2.0): the tuple ``{policyName, ruleNames[], match.any/all,
conditions, expiresAt, compensatingValidations[]}`` with the two ideas
that make it governance rather than a bypass list:

1. **Skip-attached-to-decision.** An exception never silently swallows
   a rule: a match produces a ``RuleSkip`` carrying the exception
   identities, which flows into the decision trail. Auditable by
   construction.
2. **Compensating controls.** An exception is granted only if its own
   validations still pass -- stronger than a pure exemption.

Adaptations for Sasanam (the Kyverno mechanism does not port):
- ``match`` is over agent ``(principal, action, resource, context)``
  tuples instead of Kubernetes objects/clusterRoles.
- Authorship gating is key-based, not Kubernetes RBAC: exceptions are
  sealed by deployment-authorized Ed25519 keys (write-gated by whoever
  holds the author keys; the engine path is read-only and is handed
  the trust material up front). Unprivileged authorship is refused
  loudly -- there is no unsigned path.
- ``expiresAt`` is REQUIRED on the single exception type (Kyverno has
  it only on the CEL flavor). Expired exceptions are skipped
  fail-closed toward enforcement: they grant nothing.
- The expression language is one small documented SUBSET (predicates
  below), not CEL/JMESPath: deterministic, no arithmetic, no function
  calls, no ambient time.

Time discipline: there is no ``now()`` anywhere in this module. Every
time comparison runs against a pinned ``eval_start`` supplied by the
caller (ISO-8601 UTC ``...Z`` or finite epoch seconds). Expiry is
evaluated against the pinned time, never the wall clock.

Structural composition (Kyverno's ``EngineResponse.IsSuccessful``):
any rule fail is unsuccessful; an exception converts the rule outcome
to ``skip`` (with identities attached); ``skip`` counts against
enforcement wherever the consuming seam requires a pass.
"""

import datetime
import hashlib
import json

from . import ed25519 as _ed25519

# ------------------------------------------------------------------
# Wire format.
# ------------------------------------------------------------------

EXCEPTION_KIND = "sasanam.policy-exception/v1"
SKIP_RECORD_KIND = "sasanam.policy-exception-skip/v1"

_WIRE_KEYS = frozenset({
    "kind", "id", "policyName", "ruleNames", "match", "conditions",
    "expiresAt", "compensatingValidations", "signature",
})
_SIG_KEYS = frozenset({"keyId", "sig"})
_OPS = frozenset({
    "eq", "ne", "in", "nin", "gt", "gte", "lt", "lte",
    "startswith", "present", "absent",
})
_NEEDS_VALUE = frozenset({
    "eq", "ne", "in", "nin", "gt", "gte", "lt", "lte", "startswith",
})


class PolicyExceptionError(Exception):
    """Loud, machine-coded exception refusal."""

    def __init__(self, code, human):
        super().__init__("%s: %s" % (code, human))
        self.code = code
        self.human = human


class _Missing(object):
    pass


_MISSING = _Missing()


# ------------------------------------------------------------------
# Canonical bytes / digests.
# ------------------------------------------------------------------

def canonical_bytes(obj):
    """Deterministic canonical bytes (JSON, sorted keys, tight)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _digest(obj):
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


# ------------------------------------------------------------------
# Pinned time.
# ------------------------------------------------------------------

def _parse_time(value, where):
    """Strictly parse ISO-8601 UTC '...Z' or finite epoch seconds.

    Returns epoch float. Anything else is ``exception-malformed`` --
    an unparseable expiry is never 'valid forever'.
    """
    if isinstance(value, bool):
        raise PolicyExceptionError(
            "exception-malformed", "%s must be an ISO-8601 UTC string "
            "or epoch seconds, got bool" % where)
    if isinstance(value, (int, float)):
        epoch = float(value)
        if epoch != epoch or epoch in (float("inf"), float("-inf")):
            raise PolicyExceptionError(
                "exception-malformed",
                "%s is not a finite epoch: %r" % (where, value))
        return epoch
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
            try:
                dt = datetime.datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
        else:
            raise PolicyExceptionError(
                "exception-malformed",
                "%s is not a strict ISO-8601 UTC timestamp: %r"
                % (where, value))
        return dt.replace(tzinfo=datetime.timezone.utc).timestamp()
    raise PolicyExceptionError(
        "exception-malformed",
        "%s must be an ISO-8601 UTC string or epoch seconds, got %s"
        % (where, type(value).__name__))


def _iso_of(epoch):
    return datetime.datetime.fromtimestamp(
        epoch, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------
# Subset predicate DSL (documented subset -- NOT CEL, NOT JMESPath).
#
# A condition is {"path": "a.b.c", "op": <op>, "value": <scalar>}:
#   eq / ne / in / nin / gt / gte / lt / lte / startswith
#   present / absent  (no value)
#
# "in"/"nin" take a LIST value; everything else takes a scalar.
# Comparisons against a MISSING path never hold (fail closed), except
# "absent" (holds exactly when missing) and "present" (the reverse).
# Type-mismatched comparisons are False, never errors.
# ------------------------------------------------------------------

def _resolve_path(context, path):
    cur = context
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


def _is_number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _eval_condition(cond, context):
    actual = _resolve_path(context, cond["path"])
    op = cond["op"]
    if op == "present":
        return actual is not _MISSING
    if op == "absent":
        return actual is _MISSING
    if actual is _MISSING:
        return False
    value = cond.get("value")
    if op == "eq":
        return actual == value
    if op == "ne":
        return actual != value
    if op == "in":
        return actual in value
    if op == "nin":
        return actual not in value
    if op in ("gt", "gte", "lt", "lte"):
        if not (_is_number(actual) and _is_number(value)):
            return False
        if op == "gt":
            return actual > value
        if op == "gte":
            return actual >= value
        if op == "lt":
            return actual < value
        return actual <= value
    if op == "startswith":
        return isinstance(actual, str) and isinstance(value, str) \
            and actual.startswith(value)
    return False  # unreachable: ops are closed at load


def _check_condition(cond, where):
    if not isinstance(cond, dict):
        raise PolicyExceptionError(
            "exception-malformed", "%s must be an object" % where)
    if set(cond.keys()) - {"path", "op", "value"}:
        raise PolicyExceptionError(
            "exception-malformed",
            "%s has unknown keys: %r" % (where, sorted(cond.keys())))
    path = cond.get("path")
    op = cond.get("op")
    if not isinstance(path, str) or not path or \
            any(not p for p in path.split(".")):
        raise PolicyExceptionError(
            "exception-malformed",
            "%s.path must be a non-empty dotted path" % where)
    if op not in _OPS:
        raise PolicyExceptionError(
            "exception-malformed",
            "%s.op %r is not in the documented subset %r"
            % (where, op, sorted(_OPS)))
    if op in _NEEDS_VALUE:
        if "value" not in cond:
            raise PolicyExceptionError(
                "exception-malformed",
                "%s needs a 'value' for op %r" % (where, op))
        value = cond["value"]
        if op in ("in", "nin"):
            if not isinstance(value, list) or not value or \
                    any(not _is_scalar(v) for v in value):
                raise PolicyExceptionError(
                    "exception-malformed",
                    "%s.value for op %r must be a non-empty list of "
                    "scalars" % (where, op))
        elif not _is_scalar(value):
            raise PolicyExceptionError(
                "exception-malformed",
                "%s.value must be a scalar for op %r" % (where, op))
    elif "value" in cond:
        raise PolicyExceptionError(
            "exception-malformed",
            "%s takes no 'value' for op %r" % (where, op))
    return {"path": path, "op": op,
            **({"value": cond["value"]} if op in _NEEDS_VALUE else {})}


def _is_scalar(v):
    return v is None or isinstance(v, (str, int, float, bool))


# ------------------------------------------------------------------
# Loaded exception objects.
# ------------------------------------------------------------------

class PolicyException(object):
    """A loaded, authorship-verified exception."""

    __slots__ = ("id", "policy_name", "rule_names", "match",
                 "conditions", "expires_at", "validations",
                 "author_key_id")

    def __init__(self, exc_id, policy_name, rule_names, match,
                 conditions, expires_at, validations, author_key_id):
        self.id = exc_id
        self.policy_name = policy_name
        self.rule_names = rule_names
        self.match = match            # ("any"/"all", [conditions])
        self.conditions = conditions  # [condition]
        self.expires_at = expires_at  # epoch float
        self.validations = validations  # [{"name", "check"}]
        self.author_key_id = author_key_id


class LoadReport(object):
    """Load outcome: exceptions + checked[] + out_of_scope[] + refused[]."""

    __slots__ = ("exceptions", "checked", "out_of_scope", "refused")

    def __init__(self, exceptions, checked, out_of_scope, refused):
        self.exceptions = exceptions
        self.checked = checked
        self.out_of_scope = out_of_scope
        self.refused = refused


class SkipDecision(object):
    """Outcome of ``apply``: 'skip' with identities, or 'no-skip'.

    ``detail`` is [(machine_code, exception_id)] for exceptions that
    were considered but did not grant (expired, validation failed).
    """

    __slots__ = ("kind", "exception_ids", "detail")

    def __init__(self, kind, exception_ids, detail):
        self.kind = kind
        self.exception_ids = list(exception_ids)
        self.detail = list(detail)


# ------------------------------------------------------------------
# Wire validation (closed shape, fail closed).
# ------------------------------------------------------------------

def _check_match(match, where):
    if not isinstance(match, dict) or set(match.keys()) != {"any"} and \
            set(match.keys()) != {"all"}:
        raise PolicyExceptionError(
            "exception-malformed",
            "%s.match must be exactly {'any': [...]} or {'all': [...]}"
            % where)
    mode = "any" if "any" in match else "all"
    filters = match[mode]
    if not isinstance(filters, list) or not filters:
        raise PolicyExceptionError(
            "exception-malformed",
            "%s.match.%s must be a non-empty filter list" % (where, mode))
    return (mode, [_check_condition(f, "%s.match.%s[%d]"
                                    % (where, mode, i))
                   for i, f in enumerate(filters)])


def _check_wire(wire, index):
    where = "exceptions[%d]" % index
    if not isinstance(wire, dict):
        raise PolicyExceptionError(
            "exception-malformed", "%s must be a JSON object" % where)
    unknown = set(wire.keys()) - _WIRE_KEYS
    if unknown:
        raise PolicyExceptionError(
            "exception-malformed",
            "%s has unknown keys: %r" % (where, sorted(unknown)))
    if wire.get("kind") != EXCEPTION_KIND:
        raise PolicyExceptionError(
            "exception-malformed",
            "%s.kind must be %r" % (where, EXCEPTION_KIND))
    exc_id = wire.get("id")
    if not isinstance(exc_id, str) or not exc_id:
        raise PolicyExceptionError(
            "exception-malformed", "%s.id must be a non-empty string"
            % where)
    policy_name = wire.get("policyName")
    if not isinstance(policy_name, str) or not policy_name:
        raise PolicyExceptionError(
            "exception-malformed",
            "%s.policyName must be a non-empty string" % where)
    rule_names = wire.get("ruleNames")
    if not isinstance(rule_names, list) or not rule_names or \
            any(not isinstance(r, str) or not r for r in rule_names) or \
            len(set(rule_names)) != len(rule_names):
        raise PolicyExceptionError(
            "exception-malformed",
            "%s.ruleNames must be a non-empty list of unique non-empty "
            "strings" % where)
    if "match" not in wire:
        raise PolicyExceptionError(
            "exception-malformed", "%s.match is required" % where)
    match = _check_match(wire["match"], where)
    conditions = wire.get("conditions", [])
    if not isinstance(conditions, list):
        raise PolicyExceptionError(
            "exception-malformed", "%s.conditions must be a list" % where)
    conditions = [_check_condition(c, "%s.conditions[%d]" % (where, i))
                  for i, c in enumerate(conditions)]
    if "expiresAt" not in wire:
        raise PolicyExceptionError(
            "exception-malformed", "%s.expiresAt is required" % where)
    expires_at = _parse_time(wire["expiresAt"], "%s.expiresAt" % where)
    validations = wire.get("compensatingValidations", [])
    if not isinstance(validations, list):
        raise PolicyExceptionError(
            "exception-malformed",
            "%s.compensatingValidations must be a list" % where)
    checked_validations = []
    names = set()
    for i, v in enumerate(validations):
        vwhere = "%s.compensatingValidations[%d]" % (where, i)
        if not isinstance(v, dict) or set(v.keys()) != {"name", "check"}:
            raise PolicyExceptionError(
                "exception-malformed",
                "%s must be {'name': ..., 'check': ...}" % vwhere)
        name = v["name"]
        if not isinstance(name, str) or not name or name in names:
            raise PolicyExceptionError(
                "exception-malformed",
                "%s.name must be a unique non-empty string" % vwhere)
        names.add(name)
        checked_validations.append(
            {"name": name,
             "check": _check_condition(v["check"], vwhere + ".check")})
    sig = wire.get("signature")
    if not isinstance(sig, dict) or set(sig.keys()) != _SIG_KEYS:
        raise PolicyExceptionError(
            "exception-malformed",
            "%s.signature must be {'keyId': ..., 'sig': ...}" % where)
    key_id = sig["keyId"]
    if not isinstance(key_id, str) or not key_id:
        raise PolicyExceptionError(
            "exception-malformed",
            "%s.signature.keyId must be a non-empty string" % where)
    sig_hex = sig["sig"]
    if not isinstance(sig_hex, str) or len(sig_hex) % 2 or not sig_hex:
        raise PolicyExceptionError(
            "exception-malformed",
            "%s.signature.sig must be non-empty hex" % where)
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        raise PolicyExceptionError(
            "exception-malformed",
            "%s.signature.sig is not valid hex" % where)
    return {
        "id": exc_id, "policy_name": policy_name,
        "rule_names": list(rule_names), "match": match,
        "conditions": conditions, "expires_at": expires_at,
        "validations": checked_validations,
        "author_key_id": key_id, "sig_bytes": sig_bytes,
        "body": {k: v for k, v in wire.items() if k != "signature"},
    }


def seal_exception(body, seed, key_id):
    """Producer-side helper: seal an exception body with an author key.

    Returns the body plus ``{"signature": {"keyId", "sig"}}`` where the
    signature covers ``canonical_bytes(body)`` (domain-separated by the
    kind string inside the body). Producer-side only; the engine never
    signs.
    """
    if not isinstance(body, dict):
        raise PolicyExceptionError(
            "exception-malformed", "seal_exception needs a body object")
    sig = _ed25519.sign(seed, canonical_bytes(body))
    wire = dict(body)
    wire["signature"] = {"keyId": key_id, "sig": sig.hex()}
    return wire


# ------------------------------------------------------------------
# Loading: closed-shape validation + authorship verification.
# ------------------------------------------------------------------

def load_exceptions(wires, trusted_authors, eval_start):
    """Load and verify exception wires.

    ``trusted_authors`` maps key id -> verifier with
    ``verify(data, sig)`` returning True/False (deployment-owned trust
    material; the engine path is read-only). ``eval_start`` is the
    pinned evaluation time (ISO-8601 UTC or epoch).

    Raises ``PolicyExceptionError`` (``exception-malformed`` /
    ``exception-unauthorized-authorship``) on the first bad wire --
    there is no unsigned or half-loaded path.
    """
    eval_epoch = _parse_time(eval_start, "eval_start")
    if not isinstance(wires, list):
        raise PolicyExceptionError(
            "exception-malformed", "wires must be a list")
    if not isinstance(trusted_authors, dict):
        raise PolicyExceptionError(
            "exception-malformed", "trusted_authors must be a dict")
    seen = set()
    exceptions = []
    for i, wire in enumerate(wires):
        checked = _check_wire(wire, i)
        if checked["id"] in seen:
            raise PolicyExceptionError(
                "exception-malformed",
                "duplicate exception id %r" % checked["id"])
        seen.add(checked["id"])
        verifier = trusted_authors.get(checked["author_key_id"])
        if verifier is None:
            raise PolicyExceptionError(
                "exception-unauthorized-authorship",
                "author key %r is not in the deployment trust set; "
                "unprivileged authorship refused"
                % checked["author_key_id"])
        try:
            ok = verifier.verify(canonical_bytes(checked["body"]),
                                 checked["sig_bytes"])
        except Exception:
            ok = False
        if ok is not True:
            raise PolicyExceptionError(
                "exception-unauthorized-authorship",
                "signature verification failed for exception %r "
                "(author %r)" % (checked["id"],
                                 checked["author_key_id"]))
        exceptions.append(PolicyException(
            checked["id"], checked["policy_name"], checked["rule_names"],
            checked["match"], checked["conditions"], checked["expires_at"],
            checked["validations"], checked["author_key_id"]))
    checked_ids = [e.id for e in exceptions]
    out_of_scope = [e.id for e in exceptions
                    if e.expires_at <= eval_epoch]
    return LoadReport(exceptions, checked_ids, out_of_scope, [])


# ------------------------------------------------------------------
# Evaluation.
# ------------------------------------------------------------------

def _eval_match(match, context):
    mode, filters = match
    results = [_eval_condition(f, context) for f in filters]
    return any(results) if mode == "any" else all(results)


def apply(policy_name, rule_name, context, eval_start, exceptions):
    """Evaluate loaded exceptions for one (policy, rule) hit.

    Returns a ``SkipDecision``. Never raises on well-formed input:
    expired exceptions are excluded (fail closed toward enforcement),
    failed compensating validations refuse the grant, and everything
    considered-but-not-granted is recorded in ``detail`` with its
    machine code. A granted skip ALWAYS carries the exception
    identities -- there is no silent bypass.
    """
    eval_epoch = _parse_time(eval_start, "eval_start")
    if not isinstance(context, dict):
        raise PolicyExceptionError(
            "exception-malformed", "context must be a mapping")
    granted = []
    detail = []
    for exc in exceptions:
        if exc.policy_name != policy_name:
            continue
        if rule_name not in exc.rule_names:
            continue
        if exc.expires_at <= eval_epoch:
            detail.append(("exception-expired", exc.id))
            continue
        if not _eval_match(exc.match, context):
            continue
        if not all(_eval_condition(c, context)
                   for c in exc.conditions):
            continue
        failed = [v["name"] for v in exc.validations
                  if not _eval_condition(v["check"], context)]
        if failed:
            detail.append(("exception-compensating-validation-failed",
                           exc.id))
            continue
        granted.append(exc.id)
    kind = "skip" if granted else "no-skip"
    return SkipDecision(kind, sorted(granted), detail)


def match_for_rule(policy_name, rule_name, context, eval_start,
                   exceptions):
    """Granted exception ids for one (policy, rule) hit (sorted)."""
    return apply(policy_name, rule_name, context, eval_start,
                 exceptions).exception_ids


def rule_outcome(rule_failed, decision):
    """Structural composition: any rule fail is unsuccessful.

    An exception converts the outcome to ``skip`` (identities
    attached); ``skip`` counts against enforcement wherever the
    consuming seam requires a pass.
    """
    if not isinstance(decision, SkipDecision):
        raise PolicyExceptionError(
            "exception-malformed",
            "rule_outcome needs a SkipDecision from apply()")
    if decision.kind == "skip" and rule_failed:
        return {"outcome": "skip",
                "code": "exception-granted-with-attribution",
                "exception_ids": list(decision.exception_ids)}
    if rule_failed:
        return {"outcome": "fail"}
    return {"outcome": "pass"}


def to_skip_record(decision, policy_name, rule_name, context, eval_start):
    """Digest-linked skip record for the decision trail.

    The record names every exception that caused the skip -- the
    PolicyReport analogue entry. Raises (loud) if the decision is not
    a skip: a non-skip has no business being recorded as one.
    """
    if not isinstance(decision, SkipDecision) or \
            decision.kind != "skip":
        raise PolicyExceptionError(
            "exception-malformed",
            "to_skip_record requires a granted skip decision")
    eval_epoch = _parse_time(eval_start, "eval_start")
    context_digest = _digest(context)
    record = {
        "kind": SKIP_RECORD_KIND,
        "code": "exception-granted-with-attribution",
        "policy": policy_name,
        "rule": rule_name,
        "exception_ids": sorted(decision.exception_ids),
        "context_digest": context_digest,
        "eval_start": _iso_of(eval_epoch),
    }
    record["digest"] = _digest(record)
    return record
