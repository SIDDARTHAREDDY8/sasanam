"""Declarative tool-call policy-as-data (wave-286 lane 8, KubeArmor+Istio ADAPT).

PATTERN LINEAGE: kubearmor/KubeArmor (Apache-2.0 root license -- the
GPL-2.0 BPF tree ``KubeArmor/BPF/*`` is EXCLUDED: no enforcer C code, no
protobuf, nothing from the copyleft tree is vendored or paraphrased here)
and istio/istio (Apache-2.0, verified on the ``master`` branch -- the
branch name itself is a small automation trap). This is a clean-room
stdlib-only reimplementation of the *mechanisms*; no upstream code,
protos, or prose are vendored.

Mechanisms adapted:
* KubeArmor ``fromSource`` caller binding -- a rule binds to the *calling*
  identity ("only this agent may invoke this tool"), exactly the shape of
  agent->tool authorization;
* KubeArmor "one policy schema, N enforcement backends" -- one declarative
  document compiled to a deterministic decision procedure; the deployment
  chooses the backend (this Python decision function, an nsjail profile
  via ``gov/sandbox_policy.py``, a future eBPF hook);
* KubeArmor ``Audit`` action as pre-enforcement verification -- policies
  ship in audit (evidence-only) mode, evidence is gathered, then the mode
  is flipped to enforce. Istio's experimental dry-run annotation is the
  same pattern; note Istio documents its dry-run telemetry as "for manual
  troubleshooting purposes and should not be used as an API because it may
  change anytime without prior notice" -- Sasanam's audit-mode evidence is
  therefore our own stable ``Alert``-shaped schema, not a copy of Istio's
  metric names (istio.io docs are CC-BY-4.0 and are not bulk-copied);
* KubeArmor ``Alert`` evidence -- every decision is a structured record
  carrying policy name, rule index, severity, tags, message, source,
  operation, resource, action, result, plus a hash-bound runtime identity
  (the invocation hash), not just names;
* Istio ``CUSTOM -> DENY -> ALLOW`` deterministic rule-combining order --
  the conflict-resolution algorithm for overlapping rules. One deliberate
  divergence: Istio's rule 3 is "no ALLOW policies => allow"; Sasanam is
  fail-closed, so no matching rule => DENY (documented, not hidden);
* Istio identity-before-authorization layering -- the caller's identity is
  authenticated *before* authorization is evaluated, and the evidence
  records which layer (authn / authz / custom) rejected a call;
* Istio DENY-rules treat missing attributes as matches (fail-closed on
  under-specification) -- adapted: a DENY rule matches an under-specified
  call, while an ALLOW rule requires its constrained args to be present.

Composition, not duplication:
* This module decides AUTHORIZATION (may this caller invoke this tool with
  these args). ``gov/sandbox_policy.py`` decides CONTAINMENT (namespaces,
  rlimits, syscall policy) -- this layer sits ABOVE it and never spawns
  processes or re-creates the executor.
* Policy violations route through ``gov/governed_exceptions.py``: a DENY
  verdict can be suppressed only via a live, governed exception (scope
  kind ``tool`` or ``policy``); suppression reports SKIPPED with the
  exception digest, never PASSED, and the verdict stays DENY -- an
  exception is accepted-risk evidence, not a bypass. There is no ad-hoc
  skip parameter on :meth:`CompiledToolPolicy.decide`.

Honest boundary (documented, not hidden): the policy decides on DECLARED
call shapes (caller identity claim, tool name, operation, args). It does
not observe whether the tool actually executed what was declared --
actual-vs-claimed enforcement is post-v1 (Tetragon-class observation).
The trust anchor for the caller identity is whatever authenticated the
claim before it reaches :meth:`decide`; an unauthenticated caller is
refused LOUD at the authn layer.

All refusals are LOUD: coded :class:`ToolCallPolicyError`, never silent.
"""

import copy
import fnmatch
import hashlib
import json
import re
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

POLICY_FORMAT = "sasanam-tool-call-policy/v1"

SCHEMA_VERSION = 1

#: Closed rule-action vocabulary (KubeArmor Allow/Audit/Block + Istio
#: ALLOW/DENY/CUSTOM/AUDIT, unified).
ACTIONS = frozenset({"ALLOW", "DENY", "AUDIT", "CUSTOM"})

#: Closed rollout modes (KubeArmor Audit-before-Block / Istio dry-run).
MODES = frozenset({"enforce", "audit"})

#: Closed arg-matcher vocabulary. Unknown matchers are refused at compile.
ARG_MATCHERS = frozenset({"equals", "prefix", "regex", "any_of"})

#: Maximum regex length at compile (F325 lesson: validate at schema time;
#: catastrophic backtracking remains a documented residual -- keep patterns
#: small and anchored).
MAX_REGEX_LEN = 256

#: Closed verdict vocabulary.
VERDICTS = frozenset({"ALLOW", "DENY"})

#: Closed rejection-layer vocabulary (Istio identity-first layering).
REJECTION_LAYERS = frozenset({"authn", "authz", "custom"})

#: Record type for per-decision alert evidence.
ALERT_RECORD_TYPE = "toolcall-policy-alert"

# Decision-code vocabulary (registered in gov/decision_codes.py).
UNAUTHENTICATED_CALLER = "toolcall-unauthenticated-caller"
POLICY_INVALID = "toolcall-policy-invalid"
POLICY_UNPINNED = "toolcall-policy-unpinned"
POLICY_DRIFT = "toolcall-policy-drift"
CALLER_OUT_OF_SCOPE = "toolcall-caller-out-of-scope"
CALL_DENIED = "toolcall-call-denied"
CUSTOM_DENIED = "toolcall-custom-denied"
NO_ALLOW = "toolcall-no-allow"
AUDIT_WOULD_DENY = "toolcall-audit-would-deny"
EXCEPTION_SUPPRESSED = "toolcall-exception-suppressed"
NO_COVERING_EXCEPTION = "toolcall-no-covering-exception"

__all__ = [
    "POLICY_FORMAT",
    "SCHEMA_VERSION",
    "ACTIONS",
    "MODES",
    "ARG_MATCHERS",
    "VERDICTS",
    "REJECTION_LAYERS",
    "ALERT_RECORD_TYPE",
    "ToolCallPolicyError",
    "CallDecision",
    "CompiledToolPolicy",
    "PolicyBinding",
    "compile_policy",
    "policy_digest",
    "set_mode",
    "bind",
    "register_authorizer",
    "suppress_with_exception",
    "set_emit",
    "sink_errors",
]


class ToolCallPolicyError(ValueError):
    """LOUD coded refusal for the tool-call-policy seam."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Canonical digest (same shape as the governed-exceptions seam)
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _digest(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


def policy_digest(doc):
    """Content digest of a tool-call-policy document (the pin)."""
    return _digest(doc)


# ---------------------------------------------------------------------------
# Opt-in audit sink (deployment wires the HMAC audit log here)
# ---------------------------------------------------------------------------

_emit_sinks = []
_sink_errors = []


def set_emit(fn):
    """Register an audit-event sink. Returns an unregister closure."""
    _emit_sinks.append(fn)

    def _unregister():
        try:
            _emit_sinks.remove(fn)
        except ValueError:
            pass

    return _unregister


def sink_errors():
    """Broken-sink records: recorded, never failed silently."""
    return list(_sink_errors)


def _emit(event):
    for fn in list(_emit_sinks):
        try:
            fn(event)
        except Exception as e:  # noqa: BLE001
            _sink_errors.append({"event": event, "error": repr(e)})


# ---------------------------------------------------------------------------
# CUSTOM authorizer registry (Istio CUSTOM: a named external decision point
# that can only tighten, never loosen)
# ---------------------------------------------------------------------------

_authorizers = {}


def register_authorizer(name, fn):
    """Register a named external authorizer for CUSTOM rules.

    The authorizer receives a context dict and returns "allow" or "deny".
    Any other return value, or any exception, is treated as "deny"
    (fail-closed); the contract is tighten-only.
    """
    if not isinstance(name, str) or not name:
        raise ToolCallPolicyError(
            "authorizer name must be a non-empty string",
            code=POLICY_INVALID)
    if not callable(fn):
        raise ToolCallPolicyError(
            "authorizer %r is not callable" % (name,), code=POLICY_INVALID)
    _authorizers[name] = fn


def _authorizer_verdict(name, ctx):
    fn = _authorizers.get(name)
    if fn is None:
        # Unregistered at decide time (was registered at compile, removed
        # since): fail closed, do not silently allow.
        return "deny", "authorizer %r not registered at decide time" % (name,)
    try:
        verdict = fn(ctx)
    except Exception as e:  # noqa: BLE001
        return "deny", "authorizer %r raised: %r" % (name, e)
    if verdict == "allow":
        return "allow", None
    if verdict == "deny":
        return "deny", None
    return "deny", "authorizer %r returned %r (not allow/deny)" % (name,
                                                                   verdict)


# ---------------------------------------------------------------------------
# Schema validation (fail-closed at compile)
# ---------------------------------------------------------------------------

def _refuse(message, code=POLICY_INVALID):
    raise ToolCallPolicyError(message, code=code)


def _check_str(value, what):
    if not isinstance(value, str) or not value:
        _refuse("%s must be a non-empty string; got %r" % (what, value))


def _validate_arg_matchers(args, rule_idx):
    if not isinstance(args, dict):
        _refuse("rule %d: args must be a dict; got %r" % (rule_idx, args))
    for arg_name, spec in args.items():
        if not isinstance(spec, dict) or len(spec) != 1:
            _refuse("rule %d: arg %r must be a single-matcher dict; got %r"
                    % (rule_idx, arg_name, spec))
        matcher, operand = next(iter(spec.items()))
        if matcher not in ARG_MATCHERS:
            _refuse("rule %d: arg %r: unknown matcher %r (closed: %s)"
                    % (rule_idx, arg_name, matcher,
                       ",".join(sorted(ARG_MATCHERS))))
        if matcher == "regex":
            if not isinstance(operand, str) or len(operand) > MAX_REGEX_LEN:
                _refuse("rule %d: arg %r: regex must be a string of at most "
                        "%d chars" % (rule_idx, arg_name, MAX_REGEX_LEN))
            try:
                re.compile(operand)
            except re.error as e:
                _refuse("rule %d: arg %r: regex does not compile: %s"
                        % (rule_idx, arg_name, e))
        elif matcher == "any_of":
            if (not isinstance(operand, (list, tuple)) or not operand
                    or not all(isinstance(v, (str, int, float, bool))
                               for v in operand)):
                _refuse("rule %d: arg %r: any_of must be a non-empty list "
                        "of scalars" % (rule_idx, arg_name))
        elif matcher in ("equals", "prefix"):
            if not isinstance(operand, str):
                _refuse("rule %d: arg %r: %s operand must be a string"
                        % (rule_idx, arg_name, matcher))


def _validate_doc(doc):
    if not isinstance(doc, dict):
        _refuse("policy document must be a dict; got %r" % (type(doc),))
    if doc.get("format") != POLICY_FORMAT:
        _refuse("policy format must be %r; got %r"
                % (POLICY_FORMAT, doc.get("format")))
    _check_str(doc.get("name"), "policy name")
    selector = doc.get("selector")
    if not isinstance(selector, dict):
        _refuse("policy selector must be a dict; got %r" % (selector,))
    agents = selector.get("agents", [])
    agent_tags = selector.get("agent_tags", [])
    if not agents and not agent_tags:
        _refuse("policy selector must name agents or agent_tags")
    if not isinstance(agents, list) or not all(
            isinstance(a, str) and a for a in agents):
        _refuse("selector agents must be a list of non-empty strings")
    if not isinstance(agent_tags, list) or not all(
            isinstance(t, str) and t for t in agent_tags):
        _refuse("selector agent_tags must be a list of non-empty strings")
    mode = doc.get("mode")
    if mode not in MODES:
        _refuse("policy mode must be one of %s; got %r"
                % (sorted(MODES), mode))
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        _refuse("policy rules must be a non-empty list")
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            _refuse("rule %d: must be a dict" % i)
        action = rule.get("action")
        if action not in ACTIONS:
            _refuse("rule %d: action must be one of %s; got %r"
                    % (i, sorted(ACTIONS), action))
        _check_str(rule.get("tool"), "rule %d tool" % i)
        _check_str(rule.get("operation"), "rule %d operation" % i)
        from_source = rule.get("from_source")
        if from_source is not None and not (
                isinstance(from_source, str) and from_source):
            _refuse("rule %d: from_source must be a non-empty string or "
                    "null" % i)
        if action == "CUSTOM":
            _check_str(rule.get("custom_authorizer"),
                       "rule %d custom_authorizer" % i)
            if rule["custom_authorizer"] not in _authorizers:
                _refuse("rule %d: custom_authorizer %r is not registered"
                        % (i, rule["custom_authorizer"]))
        severity = rule.get("severity", 5)
        if not isinstance(severity, int) or not 1 <= severity <= 10:
            _refuse("rule %d: severity must be an int in 1..10" % i)
        tags = rule.get("tags", [])
        if not isinstance(tags, list) or not all(
                isinstance(t, str) for t in tags):
            _refuse("rule %d: tags must be a list of strings" % i)
        if "args" in rule:
            _validate_arg_matchers(rule["args"], i)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _match_value(spec, present, value):
    """Single arg-matcher evaluation.

    Returns True/False. ``present`` is False when the call omitted the arg.
    """
    matcher, operand = next(iter(spec.items()))
    if matcher == "equals":
        return present and value == operand
    if matcher == "prefix":
        return present and isinstance(value, str) and \
            value.startswith(operand)
    if matcher == "regex":
        return present and isinstance(value, str) and \
            re.fullmatch(operand, value) is not None
    if matcher == "any_of":
        return present and value in operand
    return False  # unreachable: validated at compile


def _rule_matches_shape(rule, caller_identity, tool, operation):
    """Tool/operation/from_source shape match (no args involved)."""
    if not fnmatch.fnmatchcase(tool, rule["tool"]):
        return False
    if operation != rule["operation"]:
        return False
    from_source = rule.get("from_source")
    if from_source is not None and caller_identity != from_source:
        return False
    return True


def _args_satisfy(rule, args, deny_semantics):
    """Arg-constraint evaluation.

    deny_semantics=True (DENY rules): a missing arg counts as a MATCH
    (fail-closed on under-specification -- the Istio TCP lesson).
    deny_semantics=False (ALLOW/AUDIT/CUSTOM rules): every constrained arg
    must be present and satisfy its matcher.
    """
    constraints = rule.get("args", {})
    for arg_name, spec in constraints.items():
        present = arg_name in args
        if deny_semantics and not present:
            continue  # missing attr matches for DENY: fail closed
        if not _match_value(spec, present,
                            args.get(arg_name)):
            return False
    return True


def _rule_matches(rule, caller_identity, tool, operation, args):
    if not _rule_matches_shape(rule, caller_identity, tool, operation):
        return False
    return _args_satisfy(rule, args,
                         deny_semantics=(rule["action"] == "DENY"))


def _selector_covers(selector, caller):
    identity = caller.get("identity")
    if identity in selector.get("agents", []):
        return True
    want_tags = set(selector.get("agent_tags", []))
    if want_tags and want_tags & set(caller.get("tags", [])):
        return True
    return False


# ---------------------------------------------------------------------------
# Alert evidence (KubeArmor Alert-shaped, our own stable schema)
# ---------------------------------------------------------------------------

def _alert(policy_name, policy_digest, rule, rule_index, caller_identity,
           tool, operation, args, action, result, code, rejection_layer,
           message=None, would_have=None, extra=None):
    args_digest = _digest(args if isinstance(args, dict) else {})
    runtime_identity_hash = _digest({
        "policy_digest": policy_digest,
        "source": caller_identity,
        "tool": tool,
        "operation": operation,
        "args_digest": args_digest,
    })
    alert = {
        "record_type": ALERT_RECORD_TYPE,
        "timestamp": time.time(),
        "policy_name": policy_name,
        "policy_digest": policy_digest,
        "rule_index": rule_index,
        "rule_action": rule["action"] if rule is not None else None,
        "severity": rule.get("severity", 5) if rule is not None else 5,
        "tags": list(rule.get("tags", [])) if rule is not None else [],
        "message": message if message is not None else (
            rule.get("message") if rule is not None else ""),
        "source": caller_identity,
        "operation": operation,
        "tool": tool,
        "args_digest": args_digest,
        "runtime_identity_hash": runtime_identity_hash,
        "action": action,
        "result": result,
        "code": code,
        "rejection_layer": rejection_layer,
    }
    if would_have is not None:
        alert["would_have"] = would_have
    if extra:
        alert.update(extra)
    return alert


# ---------------------------------------------------------------------------
# Compiled policy
# ---------------------------------------------------------------------------

class CallDecision:
    """The outcome of one decide() call."""

    def __init__(self, verdict, rule_index, rejection_layer, alert, code,
                 near_misses):
        self.verdict = verdict
        self.rule_index = rule_index
        self.rejection_layer = rejection_layer
        self.alert = alert
        self.code = code
        self.near_misses = near_misses

    def to_dict(self):
        return {"verdict": self.verdict, "rule_index": self.rule_index,
                "rejection_layer": self.rejection_layer,
                "code": self.code, "near_misses": list(self.near_misses),
                "alert": dict(self.alert)}


class CompiledToolPolicy:
    """One compiled tool-call policy: the enforceable decision procedure."""

    def __init__(self, doc):
        # Deep copy: later mutation of the caller's dict cannot silently
        # change the compiled policy; _doc is the compiled record and the
        # pin covers it (drift detection compares against it).
        self._doc = copy.deepcopy(doc)
        self.digest = _digest(self._doc)
        self._alerts = []

    @property
    def name(self):
        return self._doc["name"]

    @property
    def mode(self):
        return self._doc["mode"]

    def alerts(self):
        return list(self._alerts)

    def _record(self, alert):
        self._alerts.append(alert)
        _emit(alert)
        return alert

    def _audit_rules(self, caller_identity, tool, operation, args):
        for i, rule in enumerate(self._doc["rules"]):
            if rule["action"] != "AUDIT":
                continue
            if _rule_matches(rule, caller_identity, tool, operation, args):
                self._record(_alert(
                    self._doc["name"], self.digest, rule, i,
                    caller_identity, tool, operation, args,
                    action="AUDIT", result="observed",
                    code=None, rejection_layer=None))

    def _check_caller(self, caller):
        if not isinstance(caller, dict):
            _refuse("caller must be a dict; got %r" % (type(caller),),
                    code=UNAUTHENTICATED_CALLER)
        identity = caller.get("identity")
        if not caller.get("authenticated") or not (
                isinstance(identity, str) and identity):
            alert = self._record(_alert(
                self._doc["name"], self.digest, None, None, identity,
                None, None, {}, action="DENY", result="denied",
                code=UNAUTHENTICATED_CALLER, rejection_layer="authn",
                message="caller identity not authenticated; authorization "
                        "is never evaluated without identity"))
            raise ToolCallPolicyError(
                "unauthenticated caller: identity must be established "
                "before tool-call authorization (authn layer)",
                code=UNAUTHENTICATED_CALLER)
        if not _selector_covers(self._doc["selector"], caller):
            raise ToolCallPolicyError(
                "caller %r is not covered by policy %r selector; no "
                "decision is available from this policy"
                % (identity, self._doc["name"]),
                code=CALLER_OUT_OF_SCOPE)
        return identity

    def _deny(self, rule, rule_index, caller_identity, tool, operation,
              args, code, rejection_layer, message=None, extra=None):
        if self._doc["mode"] == "audit":
            # Audit-before-Block rollout: record the would-be denial as
            # prospective evidence; do NOT enforce and do NOT emit a
            # misleading "denied" alert -- the verdict is ALLOW.
            audit_alert = self._record(_alert(
                self._doc["name"], self.digest, rule, rule_index,
                caller_identity, tool, operation, args,
                action="AUDIT", result="would-deny",
                code=AUDIT_WOULD_DENY, rejection_layer=rejection_layer,
                message="audit mode: the call would have been denied; "
                        "not enforced",
                would_have="deny"))
            return CallDecision("ALLOW", rule_index, rejection_layer,
                                audit_alert, AUDIT_WOULD_DENY, [])
        alert = self._record(_alert(
            self._doc["name"], self.digest, rule, rule_index,
            caller_identity, tool, operation, args,
            action="DENY", result="denied", code=code,
            rejection_layer=rejection_layer, message=message,
            extra=extra))
        return CallDecision("DENY", rule_index, rejection_layer, alert,
                            code, [])

    def decide(self, caller, tool, operation, args=None, now=None):
        """Decide one tool call. No ad-hoc skip: suppression routes only
        through :func:`suppress_with_exception` with a governed exception.

        Combining order (Istio): AUDIT (evidence only) -> CUSTOM -> DENY
        -> ALLOW. Deliberate divergence from Istio: no matching rule means
        DENY (Sasanam is fail-closed; Istio's "no ALLOW policies => allow"
        optimizes for traffic flow, not containment).
        """
        if args is not None and not isinstance(args, dict):
            _refuse("decide args must be a dict; got %r" % (type(args),))
        args = dict(args) if args else {}
        identity = self._check_caller(caller)
        self._audit_rules(identity, tool, operation, args)

        near_misses = []
        indexed = list(enumerate(self._doc["rules"]))

        # 1. CUSTOM: named external authorizers, evaluated first. A custom
        #    denial tightens; a custom allow never loosens a native denial.
        for i, rule in indexed:
            if rule["action"] != "CUSTOM":
                continue
            if not _rule_matches_shape(rule, identity, tool, operation):
                continue
            if not _args_satisfy(rule, args, deny_semantics=False):
                near_misses.append({"rule_index": i,
                                    "reason": "custom-arg-mismatch"})
                continue
            verdict, note = _authorizer_verdict(
                rule["custom_authorizer"],
                {"caller": identity, "tool": tool,
                 "operation": operation, "args": dict(args),
                 "rule_index": i, "policy_name": self._doc["name"]})
            if verdict == "deny":
                return self._deny(rule, i, identity, tool, operation,
                                  args, CUSTOM_DENIED, "custom",
                                  message=note)

        # 2. DENY: missing attributes count as matches (fail-closed).
        for i, rule in indexed:
            if rule["action"] != "DENY":
                continue
            if _rule_matches(rule, identity, tool, operation, args):
                return self._deny(rule, i, identity, tool, operation,
                                  args, CALL_DENIED, "authz")

        # 3. ALLOW: constrained args must be present and satisfied.
        for i, rule in indexed:
            if rule["action"] != "ALLOW":
                continue
            if _rule_matches_shape(rule, identity, tool, operation):
                if _args_satisfy(rule, args, deny_semantics=False):
                    alert = self._record(_alert(
                        self._doc["name"], self.digest, rule, i,
                        identity, tool, operation, args,
                        action="ALLOW", result="allowed",
                        code=None, rejection_layer=None))
                    return CallDecision("ALLOW", i, None, alert, None,
                                        near_misses)
                near_misses.append({"rule_index": i,
                                    "reason": "allow-arg-mismatch"})

        # 4. Default deny (documented Istio divergence: fail closed).
        decision = self._deny(None, None, identity, tool, operation, args,
                              NO_ALLOW, "authz",
                              message="no rule allowed the call; default "
                                      "deny")
        decision.near_misses = near_misses
        return decision


def compile_policy(doc):
    """Validate a policy document fail-closed and compile it to the
    deterministic decision procedure."""
    _validate_doc(doc)
    return CompiledToolPolicy(doc)


def set_mode(doc, mode):
    """Return a NEW document with the rollout mode changed.

    The rollout path: ship in "audit", gather would-deny evidence, review,
    then flip to "enforce" as a new pinned document version. The compiled
    policy's digest changes with the mode, so a flip is always a
    re-pinned, reviewable artifact -- never a silent in-place mutation.
    """
    if mode not in MODES:
        _refuse("mode must be one of %s; got %r" % (sorted(MODES), mode))
    new_doc = copy.deepcopy(doc)
    new_doc["mode"] = mode
    return new_doc


class PolicyBinding:
    """A compiled policy bound to a pin: decide() audits every decision."""

    def __init__(self, compiled, pin):
        self._compiled = compiled
        self.pin = pin
        self._decisions = []

    def decide(self, caller, tool, operation, args=None, now=None):
        decision = self._compiled.decide(caller, tool, operation, args,
                                         now=now)
        self._decisions.append(decision.to_dict())
        return decision

    def decisions(self):
        return list(self._decisions)


def bind(compiled, pin):
    """Bind a compiled policy to its pin. Refuses LOUD when unpinned or
    drifted -- a tool-call policy never decides under an unreviewed
    document (the sandbox-policy layer's pin-and-diff guarantee, one
    layer up)."""
    if not isinstance(compiled, CompiledToolPolicy):
        _refuse("bind needs a CompiledToolPolicy; got %r"
                % (type(compiled),))
    if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin):
        raise ToolCallPolicyError(
            "tool-call policy binding requires a 64-hex content pin; "
            "unpinned policies never decide",
            code=POLICY_UNPINNED)
    current = _digest(compiled._doc)
    if current != pin or current != compiled.digest:
        raise ToolCallPolicyError(
            "tool-call policy drift: the document no longer matches its "
            "pin; re-review and re-pin before deciding",
            code=POLICY_DRIFT)
    return PolicyBinding(compiled, pin)


def suppress_with_exception(compiled, alert_identity_hash, store,
                            check_id, scope, now=None):
    """Suppress a DENY alert through a governed exception.

    The covering exception must be live in ``store`` (a
    ``gov.governed_exceptions.ExceptionStore``); the scope kind must be
    ``tool`` or ``policy`` and its value must name the denied tool or the
    policy. The alert is re-recorded with Action=SKIPPED and the exception
    digest attached -- never PASSED, and the verdict stays DENY: an
    exception is accepted-risk evidence, not a bypass. A covering but
    expired/revoked exception refuses LOUD via the store's own contract.
    """
    from gov import governed_exceptions as ge
    if not isinstance(compiled, CompiledToolPolicy):
        _refuse("suppress_with_exception needs a CompiledToolPolicy",
                code=POLICY_INVALID)
    if not isinstance(scope, (tuple, list)) or len(scope) != 2 or \
            scope[0] not in ("tool", "policy"):
        raise ToolCallPolicyError(
            "exception scope for tool-call suppression must be "
            "(kind, value) with kind in ('tool', 'policy')",
            code=POLICY_INVALID)
    outcome = store.evaluate(check_id, tuple(scope), lambda: True,
                             now=now)
    if outcome.get("status") != "SKIPPED":
        # No live exception covers this scope: the store ran the
        # predicate, which means nothing was suppressed.
        raise ToolCallPolicyError(
            "no live governed exception covers %r for check %r; a DENY "
            "verdict cannot be suppressed ad-hoc" % (scope, check_id),
            code=NO_COVERING_EXCEPTION)
    exc_digest = outcome["exception_digest"]
    # Find the alert being suppressed (best effort: match by identity
    # hash; the suppression record carries the hash either way).
    target = None
    for alert in compiled.alerts():
        if alert.get("runtime_identity_hash") == alert_identity_hash:
            target = alert
            break
    record = {
        "record_type": ALERT_RECORD_TYPE,
        "timestamp": time.time(),
        "policy_name": compiled.name,
        "policy_digest": compiled.digest,
        "suppressed_alert_identity": alert_identity_hash,
        "check_id": check_id,
        "scope": list(scope),
        "action": "SKIPPED",
        "result": "suppressed",
        "verdict": "DENY",
        "code": EXCEPTION_SUPPRESSED,
        "exception_digest": exc_digest,
        "message": "DENY verdict stands; the violation alert is "
                   "suppressed under a live governed exception "
                   "(SKIPPED, never PASSED)",
    }
    if target is not None:
        record["suppressed_alert"] = dict(target)
    compiled._record(record)  # _record emits; no second _emit here
    return record
