"""Declarative approval rules with and/or composition (wave-254 lane 2).

palantir/policy-bot ADAPT (pattern only; no policy-bot code): rules are
declared in YAML/JSON, predicates compose with and/or/not, and each
rule carries one closed-vocabulary action:

    require-approval   -- route the request to the human approval queue
                          (the fail-closed default when nothing matches;
                          disapproval is NEVER the default)
    auto-approve       -- decide without a human, but ONLY with a
                          deployment-supplied audit sink: the fired
                          rule id, matched evidence, and a digest of the
                          request are recorded. The human queue is
                          never touched on this path.
    disapproval-opt-in -- disapprove the request; the rule must declare
                          "disapproval": true explicitly (explicit
                          opt-in, enforced at compile time and
                          re-checked at route time).

Public surface:
    compile_rules(doc) -> RuleSet            (fail-closed compile)
    RuleSet.evaluate(request) -> Outcome    (pure, first match wins)
    route(rule_set, request, queue=None, audit_sink=None,
          queue_action=None, queue_decision=None) -> dict
    simulate(rule_set, requests) -> [preview dicts]   (read-only)

Machine codes (domain 'approval-policy'):
    approval-policy-malformed            -- rule doc / request malformed
    approval-policy-no-audit-sink        -- auto-approve or disapproval
                                            refused: no audit sink
    approval-policy-seam-unavailable     -- require-approval refused:
                                            the queue's public seam is
                                            missing; the request is
                                            dropped, never auto-passed
    approval-policy-disapproval-defaulted -- runtime defense-in-depth:
                                            a disapproval outcome was
                                            about to fire without an
                                            explicit opt-in rule
    approval-policy-audit-failed         -- the audit sink raised during
                                            an auto/disapproval record;
                                            the decision is refused,
                                            never silently taken

Integration seam: the human queue is gov.approvals.ApprovalQueue; this
module touches ONLY its public queue(action, decision, ...) method.
If the seam is absent, require-approval refuses closed rather than
dropping the request onto any weaker path.
"""

import hashlib
import json

# ------------------------------------------------------------------
# machine codes (additive; also registered in gov/decision_codes.py)
# ------------------------------------------------------------------

MALFORMED = "approval-policy-malformed"
NO_AUDIT_SINK = "approval-policy-no-audit-sink"
SEAM_UNAVAILABLE = "approval-policy-seam-unavailable"
DISAPPROVAL_DEFAULTED = "approval-policy-disapproval-defaulted"
AUDIT_FAILED = "approval-policy-audit-failed"

ACTIONS = ("require-approval", "auto-approve", "disapproval-opt-in")

REQUIRE_APPROVAL = "require-approval"
AUTO_APPROVE = "auto-approve"
DISAPPROVAL_OPT_IN = "disapproval-opt-in"

# Leaf predicate ops. Type mismatches evaluate to False (the rule does
# not match); the default outcome is require-approval, so a False is
# the fail-closed direction.
_OPS = ("eq", "ne", "lt", "lte", "gt", "gte", "in", "not-in",
        "contains", "startswith", "exists")

_RULE_KEYS = frozenset(
    ("id", "when", "action", "disapproval", "note"))


class ApprovalPolicyError(Exception):
    """Loud approval-policy failure. ``code`` is the machine-readable
    failure mode (first positional arg = machine code, per the repo's
    code-first constructor idiom)."""

    def __init__(self, code, detail=""):
        super(ApprovalPolicyError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


# ------------------------------------------------------------------
# predicate evaluation (pure)
# ------------------------------------------------------------------

def _read_field(request, field):
    """Dotted-path read. Returns (present, value)."""
    current = request
    for part in field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return False, None
    return True, current


def _eval_leaf(predicate, request):
    field = predicate["field"]
    op = predicate["op"]
    present, value = _read_field(request, field)
    if op == "exists":
        return present
    if not present:
        return False
    want = predicate.get("value")
    try:
        if op == "eq":
            return value == want
        if op == "ne":
            return value != want
        if op == "lt":
            return value < want
        if op == "lte":
            return value <= want
        if op == "gt":
            return value > want
        if op == "gte":
            return value >= want
        if op == "in":
            return value in want
        if op == "not-in":
            return value not in want
        if op == "contains":
            return want in value
        if op == "startswith":
            return (isinstance(value, str) and
                    isinstance(want, str) and
                    value.startswith(want))
    except TypeError:
        # Incomparable types: the predicate does not match (fail
        # closed toward require-approval).
        return False
    return False  # unreachable: op validated at compile


def _eval_predicate(predicate, request):
    if "and" in predicate:
        return all(_eval_predicate(p, request)
                   for p in predicate["and"])
    if "or" in predicate:
        return any(_eval_predicate(p, request)
                   for p in predicate["or"])
    if "not" in predicate:
        return not _eval_predicate(predicate["not"], request)
    return _eval_leaf(predicate, request)


# ------------------------------------------------------------------
# compile (fail-closed)
# ------------------------------------------------------------------

def _refuse(detail):
    raise ApprovalPolicyError(MALFORMED, detail)


def _check_leaf(predicate, where):
    if not isinstance(predicate, dict):
        _refuse("%s: leaf predicate must be a dict" % where)
    field = predicate.get("field")
    op = predicate.get("op")
    if not isinstance(field, str) or not field:
        _refuse("%s: leaf needs a non-empty string 'field'" % where)
    if op not in _OPS:
        _refuse("%s: unknown op %r" % (where, op))
    if op == "exists":
        return
    if "value" not in predicate:
        _refuse("%s: op %r needs a 'value'" % (where, op))
    if op in ("in", "not-in") and not isinstance(
            predicate["value"], list):
        _refuse("%s: op %r needs a list 'value'" % (where, op))


def _check_predicate(predicate, where):
    if not isinstance(predicate, dict) or not predicate:
        _refuse("%s: predicate must be a non-empty dict" % where)
    keys = set(predicate)
    if keys == {"and"}:
        branches = predicate["and"]
        if not isinstance(branches, list) or not branches:
            _refuse("%s: 'and' needs a non-empty list" % where)
        for i, branch in enumerate(branches):
            _check_predicate(branch, "%s.and[%d]" % (where, i))
        return
    if keys == {"or"}:
        branches = predicate["or"]
        if not isinstance(branches, list) or not branches:
            _refuse("%s: 'or' needs a non-empty list" % where)
        for i, branch in enumerate(branches):
            _check_predicate(branch, "%s.or[%d]" % (where, i))
        return
    if keys == {"not"}:
        _check_predicate(predicate["not"], "%s.not" % where)
        return
    if set(predicate) <= {"field", "op", "value"} and \
            "field" in predicate and "op" in predicate:
        _check_leaf(predicate, where)
        return
    _refuse("%s: malformed predicate shape %r" % (where, sorted(keys)))


def _check_rule(rule, index):
    where = "rules[%d]" % index
    if not isinstance(rule, dict):
        _refuse("%s: rule must be a dict" % where)
    unknown = set(rule) - _RULE_KEYS
    if unknown:
        _refuse("%s: unknown rule keys %r" % (where, sorted(unknown)))
    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        _refuse("%s: rule needs a non-empty string 'id'" % where)
    action = rule.get("action")
    if action not in ACTIONS:
        _refuse("%s: unknown action %r" % (where, action))
    if "when" not in rule:
        _refuse("%s: rule needs a 'when' predicate" % where)
    _check_predicate(rule["when"], "%s.when" % where)
    if action == DISAPPROVAL_OPT_IN and rule.get("disapproval") \
            is not True:
        # Disapproval is explicit opt-in: the rule must name it.
        _refuse("%s: action %r requires 'disapproval': true" %
                (where, action))
    if action != DISAPPROVAL_OPT_IN and rule.get("disapproval") \
            is True:
        # The flag is meaningless (and misleading) on other actions.
        _refuse("%s: 'disapproval': true only belongs on %r rules" %
                (where, DISAPPROVAL_OPT_IN))


class Outcome(object):
    """The result of RuleSet.evaluate: action, winning rule_id (None
    when nothing matched), whether a rule matched, and the matched
    evidence."""

    def __init__(self, action, rule_id, matched, evidence):
        self.action = action
        self.rule_id = rule_id
        self.matched = matched
        self.evidence = evidence

    def to_dict(self):
        return {"action": self.action, "rule_id": self.rule_id,
                "matched": self.matched, "evidence": self.evidence}


class RuleSet(object):
    """Compiled, immutable rule set. evaluate() is pure."""

    def __init__(self, rules):
        # rules: list of (id, when, action, disapproval) tuples.
        self._rules = tuple(rules)

    def evaluate(self, request):
        """First matching rule wins. No match -> require-approval
        (fail closed to a human; disapproval is NEVER the default)."""
        if not isinstance(request, dict):
            raise ApprovalPolicyError(
                MALFORMED, "request must be a dict")
        for rule_id, when, action, _disapproval in self._rules:
            if _eval_predicate(when, request):
                return Outcome(action, rule_id, True, [{
                    "rule_id": rule_id,
                    "predicate": when,
                    "action": action,
                }])
        return Outcome(REQUIRE_APPROVAL, None, False, [])


def compile_rules(doc):
    """Compile a rule document (parsed YAML/JSON dict) into a RuleSet.

    Refuses approval-policy-malformed on any malformed shape: the
    author fixes the rules, they never compile into something weaker.
    """
    if not isinstance(doc, dict):
        _refuse("rule document must be a dict")
    if doc.get("version") != 1:
        _refuse("unsupported rule document version %r" %
                (doc.get("version"),))
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        _refuse("'rules' must be a non-empty list")
    seen = set()
    compiled = []
    for i, rule in enumerate(rules):
        _check_rule(rule, i)
        if rule["id"] in seen:
            _refuse("duplicate rule id %r" % (rule["id"],))
        seen.add(rule["id"])
        compiled.append((rule["id"], rule["when"], rule["action"],
                         rule.get("disapproval") is True))
    return RuleSet(compiled)


# ------------------------------------------------------------------
# routing (side-effecting; fail-closed seams)
# ------------------------------------------------------------------

def _utcnow_iso():
    import datetime
    return datetime.datetime.now(
        datetime.timezone.utc).isoformat()


def _canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _request_digest(request):
    try:
        canonical = _canonical_json(request)
    except (TypeError, ValueError) as exc:
        raise ApprovalPolicyError(
            MALFORMED, "request is not JSON-canonicalizable: %s"
            % (exc,))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _auto_entry(decision, outcome, request):
    return {
        "event": "approval_auto_decision",
        "decision": decision,
        "rule_id": outcome.rule_id,
        "rule_action": outcome.action,
        "request_digest": _request_digest(request),
        "matched_evidence": outcome.evidence,
        "issued_at": _utcnow_iso(),
    }


def _record_auto(outcome, request, audit_sink, decision):
    """Record an auto/disapproval decision via the audit sink. The
    decision is REFUSED (never silently taken) when there is no sink
    or the sink fails."""
    if audit_sink is None or not callable(audit_sink):
        raise ApprovalPolicyError(
            NO_AUDIT_SINK,
            "%s has no audit sink: silent %s is never allowed"
            % (outcome.action, decision))
    entry = _auto_entry(decision, outcome, request)
    try:
        audit_sink(entry)
    except ApprovalPolicyError:
        raise
    except Exception as exc:  # noqa: BLE001 - sink outage must not
        # turn into a silent approval; the machine-code contract holds.
        raise ApprovalPolicyError(
            AUDIT_FAILED, "audit sink failed: %r" % (exc,))
    return entry


def route(rule_set, request, queue=None, audit_sink=None,
          queue_action=None, queue_decision=None):
    """Route one request through the compiled rule set.

    require-approval -> the queue's public queue(action, decision,
        ...) seam; a missing seam refuses approval-policy-seam-
        unavailable (the request is dropped, never auto-passed).
    auto-approve     -> audit sink ONLY; the human queue is never
        touched.
    disapproval-opt-in -> audited disapproval; the winning rule must
        carry the explicit opt-in (re-checked here: compile-time
        enforcement is not the only line).
    """
    outcome = rule_set.evaluate(request)
    action = outcome.action
    if action == REQUIRE_APPROVAL:
        seam = getattr(queue, "queue", None)
        if queue is None or not callable(seam):
            raise ApprovalPolicyError(
                SEAM_UNAVAILABLE,
                "require-approval with no queue seam: request dropped")
        if queue_action is None or queue_decision is None:
            raise ApprovalPolicyError(
                MALFORMED,
                "require-approval needs queue_action and "
                "queue_decision")
        approval_id = seam(queue_action, queue_decision)
        return {"action": action, "rule_id": outcome.rule_id,
                "matched": outcome.matched,
                "approval_id": approval_id, "queued": True}
    if action == AUTO_APPROVE:
        entry = _record_auto(outcome, request, audit_sink,
                             "auto-approved")
        return {"action": action, "rule_id": outcome.rule_id,
                "matched": outcome.matched, "audited": True,
                "entry": entry}
    if action == DISAPPROVAL_OPT_IN:
        # Defense in depth: compile_rules already enforces the
        # explicit opt-in; a hand-built RuleSet must not smuggle a
        # default disapproval past it.
        opted_in = any(rule_id == outcome.rule_id and disapproval
                       for rule_id, _w, _a, disapproval
                       in rule_set._rules)
        if not opted_in:
            raise ApprovalPolicyError(
                DISAPPROVAL_DEFAULTED,
                "disapproval without an explicit opt-in rule")
        entry = _record_auto(outcome, request, audit_sink,
                             "disapproved")
        return {"action": action, "rule_id": outcome.rule_id,
                "matched": outcome.matched, "audited": True,
                "entry": entry}
    raise ApprovalPolicyError(  # unreachable: closed vocabulary
        MALFORMED, "unknown routed action %r" % (action,))


# ------------------------------------------------------------------
# simulation (read-only by construction)
# ------------------------------------------------------------------

def simulate(rule_set, requests):
    """Preview outcomes for a list of requests WITHOUT touching the
    queue or any audit sink: this function takes no write seam at
    all, so side effects are structurally impossible. Deterministic:
    identical inputs give byte-identical previews."""
    if not isinstance(requests, list):
        raise ApprovalPolicyError(
            MALFORMED, "requests must be a list")
    previews = []
    for request in requests:
        outcome = rule_set.evaluate(request)
        previews.append({
            "request_digest": _request_digest(request),
            "action": outcome.action,
            "rule_id": outcome.rule_id,
            "matched": outcome.matched,
        })
    return previews
