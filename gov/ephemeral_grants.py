"""Ephemeral grants: per-invocation contextual tuples (OpenFGA pattern STEAL).

Wave-280 lane 3. Stdlib only. $0 spend, synthetic/local only.

Pattern lineage: openfga/openfga (Apache-2.0) -- contextual tuples,
CEL conditions, BatchCheck, Expand. Mechanism only: no OpenFGA code,
text, or DSL copied; no Go sidecar in-tree (a network PDP hop inverts
fail-closed on PDP-down -- the prospectus enforcement note). The
condition vocabulary is deliberately CLOSED (no CEL): ``valid_until``,
``max_budget``, ``arg_digest``.

Problem (see ~/workspace/teams/wave280-fga/SPEC.md): the three-token
delegation grant is a *standing* grant for its whole TTL. This module
adds the per-invocation enforcement input:

* :class:`ContextualTuple` -- an ephemeral fact
  ``(user, relation, object, conditions)`` that exists only for the
  check request it is attached to. Users are ``agent:<id>`` /
  ``session:<id>``; objects are ``tool:<name>`` / ``resource:<uri>``;
  relations are ``can_invoke`` / ``can_invoke_readonly`` /
  ``delegated_to``.
* :func:`check_grant` -- fail-closed evaluation of one
  ``(principal, action)`` request against a tuple set. Every condition
  is evaluated at check time against the invocation actuals; a missing
  or mismatched actual fails closed; hostile condition shapes are
  refused at tuple construction.
* Single-use leases: a delegation token minted with ``lease="single-use"``
  requires contextual tuples at the check seam, and
  :class:`SpentLeaseRegistry` refuses the second presentation of the
  same lease ref. Cross-process replay is a STATED BOUNDARY (same
  class as the revocation seam's boundary in
  ``gov/delegation_tokens.py``), not a hidden gap.
* :func:`batch_check` -- one decision vector for N planned calls; never
  short-circuits (a failing check does not hide the rest).
* :func:`expand_decision` -- the resolution tree (decision provenance):
  which tuples and hops resolved the decision, digest-bound, directly
  usable as evidence-bundle material.
* :class:`GrantDecisionWriter` -- chains decision records into the HMAC
  audit log AT DECISION TIME (never batched later -- the prospectus
  enforcement note).

``EphemeralGrantError`` carries the machine code
``delegation-ephemeral-grant-refused`` (registered in
``gov/decision_codes.py``); the pure check functions return decision
dicts instead of raising. The delegation seam raises
``delegation_tokens.EphemeralGrantError``, a multiple-inheritance
bridge over this class AND the seam's ``DelegationError`` — so the
executor's ``except DelegationError`` refusal path audit-logs the
denial instead of crashing on a raw exception.
"""

import hashlib
import json
import math

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

RELATIONS = frozenset({"can_invoke", "can_invoke_readonly", "delegated_to"})
CONDITION_KEYS = frozenset({"valid_until", "max_budget", "arg_digest"})

RECORD_TYPE = "grant-decision"
SCHEMA_VERSION = 1

_GENESIS = "0" * 64
_HEX = set("0123456789abcdef")


class EphemeralGrantError(Exception):
    """Fail-closed: the ephemeral-grant check refused the request.

    Raised by the delegation seam (``gov/delegation_tokens.py``) when a
    single-use lease is presented without contextual tuples, when the
    tuples fail, or when a lease ref is replayed. The pure check
    functions (:func:`check_grant`, :func:`batch_check`) return decision
    dicts instead of raising.
    """

    code = "delegation-ephemeral-grant-refused"

    def __init__(self, detail=""):
        msg = self.code + (": " + detail if detail else "")
        super().__init__(msg)
        self.detail = detail


# ---------------------------------------------------------------------------
# Canonical form + digests
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Tuple construction (fail-fast)
# ---------------------------------------------------------------------------

def _check_user(value, what="user"):
    if not isinstance(value, str) or not value:
        raise ValueError("%s must be a non-empty string" % (what,))
    kind, sep, ident = value.partition(":")
    if not sep or not ident or kind not in ("agent", "session"):
        raise ValueError(
            "%s must be 'agent:<id>' or 'session:<id>', got %r"
            % (what, value))
    if any(ch.isspace() for ch in value):
        raise ValueError("%s must not contain whitespace: %r"
                         % (what, value))
    return value


def _check_object(value, what="object"):
    if not isinstance(value, str) or not value:
        raise ValueError("%s must be a non-empty string" % (what,))
    kind, sep, ident = value.partition(":")
    if not sep or not ident or kind not in ("tool", "resource"):
        raise ValueError(
            "%s must be 'tool:<name>' or 'resource:<uri>', got %r"
            % (what, value))
    if any(ch.isspace() for ch in value):
        raise ValueError("%s must not contain whitespace: %r"
                         % (what, value))
    return value


def _check_finite_number(value, what):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("%s must be a finite number, got %r"
                         % (what, value))
    if not math.isfinite(value):
        raise ValueError("%s must be finite, got %r" % (what, value))
    return float(value)


def _check_hex64(value, what):
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("%s must be 64 lowercase hex chars, got %r"
                         % (what, value))
    low = value.lower()
    if any(c not in _HEX for c in low) or low != value:
        raise ValueError("%s must be 64 lowercase hex chars, got %r"
                         % (what, value))
    return value


def _check_conditions(conditions):
    if conditions is None:
        return {}
    if not isinstance(conditions, dict):
        raise ValueError("conditions must be a dict, got %r" % (conditions,))
    out = {}
    for key, value in conditions.items():
        if key not in CONDITION_KEYS:
            # Closed vocabulary (no CEL): an unknown condition key is a
            # programming/hostile shape, refused at construction rather
            # than silently ignored (an ignored condition would be a
            # pass-by-omission).
            raise ValueError("unknown condition %r: vocabulary is %s"
                             % (key, sorted(CONDITION_KEYS)))
        if key == "valid_until":
            out[key] = _check_finite_number(value, "valid_until")
        elif key == "max_budget":
            v = _check_finite_number(value, "max_budget")
            if v < 0:
                raise ValueError("max_budget must be non-negative")
            out[key] = v
        elif key == "arg_digest":
            out[key] = _check_hex64(value, "arg_digest")
    return out


class ContextualTuple(object):
    """One ephemeral grant fact, valid only for its check request.

    ``lease_ref`` (optional): binds the tuple to a single-use lease --
    the tuple authorizes only when presented alongside the lease whose
    ref it names (see :class:`SpentLeaseRegistry`).
    """

    __slots__ = ("user", "relation", "object", "conditions", "lease_ref")

    def __init__(self, user, relation, obj, conditions=None,
                 lease_ref=None):
        if relation not in RELATIONS:
            raise ValueError("relation must be one of %s, got %r"
                             % (sorted(RELATIONS), relation))
        if relation == "delegated_to":
            # A userset hop: user delegates INTO the object userset.
            _check_user(user)
            _check_user(obj, "object")
        else:
            _check_user(user)
            _check_object(obj)
        if lease_ref is not None and (
                not isinstance(lease_ref, str) or not lease_ref):
            raise ValueError("lease_ref must be a non-empty string or None")
        self.user = user
        self.relation = relation
        self.object = obj
        self.conditions = _check_conditions(conditions)
        self.lease_ref = lease_ref

    def public(self):
        """The canonical public form (what evidence records carry)."""
        return {
            "user": self.user,
            "relation": self.relation,
            "object": self.object,
            "conditions": dict(self.conditions),
            "lease_ref": self.lease_ref,
        }

    def digest(self):
        return _digest(_canonical(self.public()))

    def __repr__(self):
        return "ContextualTuple(%r, %r, %r)" % (
            self.user, self.relation, self.object)


# ---------------------------------------------------------------------------
# Spent-lease registry (in-process; cross-process replay is a stated
# boundary -- same class as the RevocationLedger boundary)
# ---------------------------------------------------------------------------

class SpentLeaseRegistry(object):
    """Records consumed single-use lease refs, in-process.

    ``spend`` is idempotent-check-then-record: the second spend of the
    same ref raises :class:`EphemeralGrantError` fail-closed.
    """

    def __init__(self):
        self._spent = {}

    def is_spent(self, lease_ref):
        return lease_ref in self._spent

    def spend(self, lease_ref, invocation_id=""):
        if not isinstance(lease_ref, str) or not lease_ref:
            raise ValueError("lease_ref must be a non-empty string")
        if lease_ref in self._spent:
            raise EphemeralGrantError(
                "single-use lease %r already spent by invocation %r: "
                "replay refused" % (lease_ref,
                                    self._spent[lease_ref]))
        self._spent[lease_ref] = str(invocation_id or "")
        return True


# ---------------------------------------------------------------------------
# Check semantics
# ---------------------------------------------------------------------------

def _resolve_users(principal, tuples):
    """Transitive userset resolution via ``delegated_to`` hops.

    Returns (effective_user_set, hop_tuples_in_resolution_order).
    """
    _check_user(principal, "principal")
    effective = {principal}
    hops = []
    changed = True
    while changed:
        changed = False
        for t in tuples:
            if t.relation != "delegated_to":
                continue
            if t.user in effective and t.object not in effective:
                effective.add(t.object)
                hops.append(t)
                changed = True
    return effective, hops


def _check_principal_action(principal, action):
    _check_user(principal, "principal")
    if not isinstance(action, str) or not action.startswith("tool:") \
            or len(action) <= len("tool:"):
        raise ValueError("action must be 'tool:<name>', got %r" % (action,))
    if any(ch.isspace() for ch in action):
        raise ValueError("action must not contain whitespace: %r" % (action,))


def _eval_conditions(t, actuals):
    """Evaluate one tuple's conditions against the invocation actuals.

    Returns (ok, reason). A declared condition with a missing actual
    fails closed: the actuals are the caller's claim about the
    invocation, and an absent claim cannot satisfy a bound.
    """
    if not isinstance(actuals, dict):
        return False, "check_conditions must be a dict"
    for key, bound in t.conditions.items():
        if key == "valid_until":
            now = actuals.get("now")
            if now is None:
                return False, "condition valid_until declared but no 'now' actual"
            try:
                now_f = _check_finite_number(now, "now")
            except ValueError:
                return False, "actual 'now' is not a finite number"
            if now_f > bound:
                return False, "tuple expired at %r (now %r)" % (bound, now_f)
        elif key == "max_budget":
            budget = actuals.get("budget")
            if budget is None:
                return False, "condition max_budget declared but no 'budget' actual"
            try:
                budget_f = _check_finite_number(budget, "budget")
            except ValueError:
                return False, "actual 'budget' is not a finite number"
            if budget_f > bound:
                return False, "budget %r exceeds max_budget %r" % (budget_f, bound)
        elif key == "arg_digest":
            digest = actuals.get("args_digest")
            if digest is None:
                return False, "condition arg_digest declared but no 'args_digest' actual"
            if not isinstance(digest, str) or digest != bound:
                return False, "args_digest does not match the bound digest"
    return True, ""


def _refusal(detail):
    return {
        "allowed": False,
        "code": EphemeralGrantError.code,
        "code_detail": detail,
        "matched_tuples": [],
        "expand_tree": None,
        "decision_digest": None,
        "lease_ref": None,
    }


def check_grant(principal, action, tuples, check_conditions=None, *,
                consequential=False, lease_ref=None, spent_ledger=None):
    """Evaluate one authorization request against contextual tuples.

    Returns a decision dict (never raises for auth failures):
    ``{"allowed", "code", "code_detail", "matched_tuples",
    "expand_tree", "decision_digest", "lease_ref"}``. ``code`` is None
    on allow, ``delegation-ephemeral-grant-refused`` on refuse.
    Malformed *inputs* (bad principal/action shapes) raise ValueError:
    those are programming errors, not authorization outcomes.

    ``lease_ref``: when the caller binds a single-use lease, a tuple
    naming that lease ref is required and the ref is spent through
    ``spent_ledger`` (replay refuses coded).

    Note: conditions are evaluated only for the matched
    ``can_invoke``/``can_invoke_readonly`` tuples. ``delegated_to`` hop
    tuples extend the userset only — conditions attached to a hop tuple
    are NOT evaluated (documented spec gap, wave-280 review).
    """
    _check_principal_action(principal, action)
    tuples = list(tuples or [])
    for t in tuples:
        if not isinstance(t, ContextualTuple):
            raise ValueError("tuples must be ContextualTuple instances")
    actuals = check_conditions if check_conditions is not None else {}

    effective, hops = _resolve_users(principal, tuples)

    # Lease binding: a bound lease requires a tuple naming it.
    if lease_ref is not None:
        named = [t for t in tuples if t.lease_ref == lease_ref
                 and t.user in effective]
        if not named:
            return _refusal(
                "single-use lease %r: no contextual tuple names the lease"
                % (lease_ref,))
        if spent_ledger is not None:
            if spent_ledger.is_spent(lease_ref):
                return _refusal(
                    "single-use lease %r already spent: replay refused"
                    % (lease_ref,))

    matched = []
    for t in tuples:
        if t.relation not in ("can_invoke", "can_invoke_readonly"):
            continue
        if t.user not in effective:
            continue
        if t.object != action:
            continue
        if t.relation == "can_invoke_readonly" and consequential:
            # A readonly grant never authorizes a consequential action.
            continue
        if lease_ref is not None and t.lease_ref != lease_ref:
            continue
        ok, reason = _eval_conditions(t, actuals)
        if ok:
            matched.append(t)

    if not matched:
        return _refusal("no contextual tuple authorizes %r for %r"
                        % (action, principal))

    if lease_ref is not None and spent_ledger is not None:
        invocation_id = ""
        if isinstance(actuals, dict):
            invocation_id = actuals.get("invocation_id", "")
        try:
            spent_ledger.spend(lease_ref, invocation_id)
        except EphemeralGrantError as e:
            return _refusal(str(e))

    tree = expand_decision(principal, "can_invoke", action, tuples)
    decision = {
        "allowed": True,
        "code": None,
        "code_detail": "",
        "matched_tuples": [t.public() for t in matched],
        "expand_tree": tree,
        "decision_digest": None,
        "lease_ref": lease_ref,
    }
    decision["decision_digest"] = _digest(_canonical({
        k: v for k, v in decision.items() if k != "decision_digest"}))
    return decision


def batch_check(checks, tuples, check_conditions=None, **kwargs):
    """One decision vector for N planned calls. Never short-circuits:
    every check gets its own decision even when an earlier one fails,
    so the vector is complete evidence of the plan's auth surface.
    """
    return [check_grant(c["principal"], c["action"], tuples,
                        check_conditions,
                        consequential=c.get("consequential", False),
                        lease_ref=c.get("lease_ref"),
                        spent_ledger=kwargs.get("spent_ledger"))
            for c in checks]


def expand_decision(user, relation, obj, tuples):
    """The resolution tree: decision provenance as evidence material.

    Digest-bound (``tree_digest`` = sha256 of the canonical tree without
    the digest field) so a third party can recompute it without the
    engine.
    """
    _check_user(user, "subject")
    if relation not in ("can_invoke", "can_invoke_readonly"):
        raise ValueError("expand relation must be can_invoke or "
                         "can_invoke_readonly, got %r" % (relation,))
    _check_object(obj, "object")
    tuples = list(tuples or [])
    effective, hops = _resolve_users(user, tuples)
    matched = [t for t in tuples
               if t.relation in ("can_invoke", "can_invoke_readonly")
               and t.user in effective and t.object == obj]
    tree = {
        "subject": user,
        "relation": relation,
        "object": obj,
        "matched": bool(matched),
        "matched_tuples": [t.public() for t in matched],
        "children": [
            {
                "subject": t.user,
                "relation": "delegated_to",
                "object": t.object,
                "matched": True,
                "tuple_digest": t.digest(),
                "children": [],
            }
            for t in hops if t.user == user
        ],
    }
    tree["tree_digest"] = _digest(_canonical(tree))
    return tree


# ---------------------------------------------------------------------------
# Decision records, chained into the audit log at decision time
# ---------------------------------------------------------------------------

class GrantDecisionWriter(object):
    """Chains grant-decision records into the HMAC audit log.

    One writer instance chains its own records via
    ``prev_grant_decision_digest`` (the wave-279 guardrail-evidence
    precedent). Records are appended AT DECISION TIME, never batched
    later. Fail-closed: if ``log.append`` raises, the exception
    propagates and the caller must not treat the action as evidenced.
    """

    def __init__(self, log):
        self._log = log
        self._last_digest = _GENESIS

    def record(self, decision, principal):
        """Build, digest, chain, and append one grant-decision record."""
        if not isinstance(decision, dict) or "allowed" not in decision:
            raise EphemeralGrantError("decision must be a check_grant "
                                     "decision dict")
        _check_user(principal, "principal")
        record = {
            "record_type": RECORD_TYPE,
            "schema_version": SCHEMA_VERSION,
            "principal": principal,
            "allowed": bool(decision["allowed"]),
            "code": decision.get("code"),
            "decision_digest": decision.get("decision_digest"),
            "matched_tuples": decision.get("matched_tuples") or [],
            "expand_tree": decision.get("expand_tree"),
            "lease_ref": decision.get("lease_ref"),
            "prev_grant_decision_digest": self._last_digest,
        }
        record["record_digest"] = _digest(_canonical(record))
        entry = self._log.append(record)
        self._last_digest = record["record_digest"]
        return entry


def grant_decision_records(log):
    """All grant-decision records in ``log``, in stored order."""
    from gov.log import read_entries
    return [e for e in read_entries(log.path)
            if e.get("record_type") == RECORD_TYPE]
