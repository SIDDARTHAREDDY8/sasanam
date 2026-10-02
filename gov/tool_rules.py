"""Declared tool-call sequence rules (wave-293 lane 2, letta-ai/letta ADAPT).

PATTERN LINEAGE: letta-ai/letta (Apache-2.0) -- declarative tool rules
(Init/Child/Terminal/Conditional) as a runtime-checked sequence grammar,
and the "secrets never as tool arguments" pitfall rule. This is a
clean-room stdlib-only reimplementation of the *mechanisms*; no upstream
code is vendored.

Mechanisms adapted:
* Sequence grammar -- every tool call is checked against a declared,
  compiled rule set BEFORE it executes. A tool declared ``Init`` may only
  be called first in a session; a ``Child`` tool only directly after its
  named parent; after a ``Terminal`` tool nothing may follow; a
  ``Conditional`` tool only when its named predicate holds over
  (history, context flags).
* Closed inventory -- binding a rule set closes the tool inventory:
  undeclared tools do not exist; a call to an undeclared tool refuses
  coded ``toolcall-sequence-violated``.
* Compile-time freeze -- the rule set is validated and deep-frozen at
  compile (the F330/F340 pattern used by gov/tool_call_policy.py); a
  post-compile in-process mutation fails at the source instead of
  silently changing decisions under a still-valid digest.
* Secret-shape gate -- secret-looking arg VALUES (bounded pattern set)
  and secret-shaped arg NAMES carrying non-empty values refuse coded
  ``toolcall-secret-in-args``; args whose secret scan cannot complete
  within the declared bounds (nesting depth 4 / 64KB scan budget)
  refuse coded ``toolcall-secret-scan-incomplete`` (F365) -- the bounds
  are fail-closed, never silently allow. Secrets travel via typed
  context, never tool args.

Composition, not duplication:
* This module decides SEQUENCE (may this call happen now, in this
  session). ``gov/tool_call_policy.py`` decides AUTHORIZATION (may this
  caller invoke this tool with these args). The sequence checker runs
  inside ``CompiledToolPolicy.decide`` when a rule set is bound (opt-in
  via ``bind_rule_set``), right after the authn layer, surfacing
  violations as coded ``toolcall-sequence-violated`` /
  ``toolcall-secret-in-args`` DENY decisions at the same decide seam.
  With no rule set bound, ``decide`` behaves exactly as before.

Honest boundary (documented, not hidden): the checker decides on the
DECLARED session history handed to :meth:`check_call` (or derived from
a binding's ALLOW decisions). It does not observe whether the tool
actually executed what was declared -- actual-vs-claimed enforcement is
post-v1 (Tetragon-class observation), same as the policy layer.

All refusals are LOUD: coded :class:`ToolRuleError`, never silent.
"""

import hashlib
import json
import re
from types import MappingProxyType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RULE_SET_FORMAT = "sasanam-tool-rule-set/v1"

#: Closed rule-kind vocabulary (letta Init/Child/Terminal/Conditional).
RULE_KINDS = frozenset({"Init", "Child", "Terminal", "Conditional"})

#: Closed predicate-kind vocabulary. Predicates are declarative and
#: evaluable without executing code: ``flag`` reads a context flag,
#: ``history`` counts prior calls of a tool in the session history.
PREDICATE_KINDS = frozenset({"flag", "history"})

#: Compile-time bounds (bounded documents only).
MAX_TOOLS = 256
MAX_RULES = 256
MAX_NAME_LEN = 128
MAX_PREDICATES = 64

#: Runtime bounds.
MAX_HISTORY_SCAN = 4096
MAX_SECRET_SCAN_BYTES = 65536
MAX_SECRET_DEPTH = 4

#: Decision-code vocabulary (registered in gov/decision_codes.py).
SEQUENCE_VIOLATED = "toolcall-sequence-violated"
SECRET_IN_ARGS = "toolcall-secret-in-args"
SCAN_INCOMPLETE = "toolcall-secret-scan-incomplete"
RULE_COMPILE_INVALID = "toolcall-rule-compile-invalid"

__all__ = [
    "RULE_SET_FORMAT",
    "RULE_KINDS",
    "PREDICATE_KINDS",
    "ToolRuleError",
    "CompiledToolRuleSet",
    "compile_rule_set",
    "rule_set_digest",
]


class ToolRuleError(ValueError):
    """LOUD coded refusal for the tool-rules seam."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Canonical digest + deep freeze (the F330/F340 pattern)
# ---------------------------------------------------------------------------

def _json_default(obj):
    if isinstance(obj, MappingProxyType):
        return dict(obj)
    raise TypeError("object of type %s is not JSON serializable"
                    % type(obj).__name__)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=_json_default).encode("utf-8")


def _digest(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


def _freeze(obj):
    """Deep-freeze a validated rule-set document.

    dict -> MappingProxyType, list/tuple -> tuple, set -> frozenset.
    Post-compile in-process mutation then fails at the source instead of
    silently changing decisions under a still-valid digest. Digest-
    transparent: the frozen shape serializes back to the plain JSON form.
    """
    if isinstance(obj, dict):
        return MappingProxyType(
            {key: _freeze(value) for key, value in obj.items()})
    if isinstance(obj, (list, tuple)):
        return tuple(_freeze(value) for value in obj)
    if isinstance(obj, (set, frozenset)):
        return frozenset(_freeze(value) for value in obj)
    return obj


def rule_set_digest(doc):
    """Content digest of a tool-rule-set document (the pin)."""
    return _digest(doc)


# ---------------------------------------------------------------------------
# Secret-shape gate (bounded pattern set; fail-closed on match)
# ---------------------------------------------------------------------------

_SECRET_VALUE_PATTERNS = (
    r"sk-[A-Za-z0-9]{16,}",              # OpenAI-style keys
    r"gh[pousr]_[A-Za-z0-9]{16,}",      # GitHub tokens
    r"xox[baprs]-[A-Za-z0-9-]{8,}",     # Slack tokens
    r"AKIA[0-9A-Z]{16}",                # AWS access key IDs
    r"AIza[0-9A-Za-z\-_]{20,}",         # Google API keys
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",  # PEM private keys
)
_SECRET_VALUE_RE = re.compile("|".join("(?:%s)" % p
                                       for p in _SECRET_VALUE_PATTERNS))

#: Secret-shaped ARG NAMES: a non-empty value under one of these names is
#: treated as a secret even without a recognizable value shape.
_SECRET_NAME_RE = re.compile(
    r"(?i)^[\w-]*?(?:api[_-]?key|secret|passwd|password|client[_-]?secret"
    r"|access[_-]?token|refresh[_-]?token|private[_-]?key|auth[_-]?token"
    r"|session[_-]?token)$")


def _scan_value(value, depth, budget):
    """Scan value for secret-shaped strings (bounded walk).

    Returns True if a secret-shaped string is found, False if the value
    was FULLY scanned and is clean, and None if the scan could not
    complete within the declared bounds (nesting deeper than
    MAX_SECRET_DEPTH, or bytes left to scan after the 64KB budget is
    exhausted). A None outcome is never treated as clean: the caller
    refuses fail-closed, because unevaluatable input must not be
    silently allowed (F365).
    """
    if depth > MAX_SECRET_DEPTH:
        # Structure continues beyond the scan bound: its content is
        # unevaluatable, not clean.
        return None
    if isinstance(value, str):
        if budget[0] <= 0:
            # Bytes remain to scan but no budget: unevaluatable.
            return None
        truncated = len(value) > budget[0]
        chunk = value[:budget[0]]
        budget[0] -= len(chunk)
        if _SECRET_VALUE_RE.search(chunk) is not None:
            return True
        return None if truncated else False
    if isinstance(value, dict):
        incomplete = False
        for key, item in value.items():
            if isinstance(key, str) and _SECRET_NAME_RE.match(key):
                if item is None:
                    continue
                if isinstance(item, str):
                    if item:
                        return True
                    continue
                # A present non-empty non-string under a secret-shaped
                # name is still secret-shaped (fail-closed).
                if item != [] and item != {} and item != ():
                    return True
            sub = _scan_value(item, depth + 1, budget)
            if sub is True:
                return True
            if sub is None:
                incomplete = True
        return None if incomplete else False
    if isinstance(value, (list, tuple)):
        incomplete = False
        for item in value:
            sub = _scan_value(item, depth + 1, budget)
            if sub is True:
                return True
            if sub is None:
                incomplete = True
        return None if incomplete else False
    return False


def _args_carry_secret(args):
    """Tristate secret scan of args: True = secret found, False = fully
    scanned and clean, None = scan incomplete within the declared bounds
    (fail-closed at the caller)."""
    return _scan_value(args, 0, [MAX_SECRET_SCAN_BYTES])


# ---------------------------------------------------------------------------
# Compile-time validation (fail-closed)
# ---------------------------------------------------------------------------

_NAME_RE = re.compile(r"[A-Za-z0-9_.:-]+")


def _refuse_compile(message):
    raise ToolRuleError("tool-rule-set compile refused: %s" % (message,),
                        code=RULE_COMPILE_INVALID)


def _check_name(value, what):
    if not isinstance(value, str) or not value \
            or len(value) > MAX_NAME_LEN \
            or _NAME_RE.fullmatch(value) is None:
        _refuse_compile("%s must be a non-empty string of [A-Za-z0-9_.:-] "
                        "(<= %d chars); got %r"
                        % (what, MAX_NAME_LEN, value))
    return value


def _compile_predicates(predicates, inventory):
    if not isinstance(predicates, dict):
        _refuse_compile("predicates must be a dict; got %r"
                        % (type(predicates),))
    if len(predicates) > MAX_PREDICATES:
        _refuse_compile("too many predicates (%d > %d)"
                        % (len(predicates), MAX_PREDICATES))
    compiled = {}
    for pname, pspec in predicates.items():
        _check_name(pname, "predicate name")
        if pname in compiled:
            _refuse_compile("duplicate predicate %r" % (pname,))
        if not isinstance(pspec, dict):
            _refuse_compile("predicate %r must be a dict" % (pname,))
        kind = pspec.get("kind")
        if kind == "flag":
            flag = pspec.get("flag")
            _check_name(flag, "predicate %r flag" % (pname,))
            allowed = {"kind", "flag"}
            compiled[pname] = {"kind": "flag", "flag": flag}
        elif kind == "history":
            tool = pspec.get("tool")
            if tool not in inventory:
                _refuse_compile("predicate %r references undeclared tool %r"
                                % (pname, tool))
            min_calls = pspec.get("min_calls", 1)
            if not isinstance(min_calls, int) \
                    or isinstance(min_calls, bool) or min_calls < 1:
                _refuse_compile("predicate %r min_calls must be an int >= 1"
                                % (pname,))
            allowed = {"kind", "tool", "min_calls"}
            compiled[pname] = {"kind": "history", "tool": tool,
                               "min_calls": min_calls}
        else:
            _refuse_compile("predicate %r has unknown kind %r"
                            % (pname, kind))
        for key in pspec:
            if key not in allowed:
                _refuse_compile("predicate %r has unknown key %r"
                                % (pname, key))
    return compiled


def _compile_rules(rules, inventory, predicates):
    if not isinstance(rules, list):
        _refuse_compile("rules must be a list; got %r" % (type(rules),))
    if len(rules) > MAX_RULES:
        _refuse_compile("too many rules (%d > %d)"
                        % (len(rules), MAX_RULES))
    compiled = []
    for i, rule in enumerate(rules):
        where = "rule %d" % (i,)
        if not isinstance(rule, dict):
            _refuse_compile("%s must be a dict" % (where,))
        kind = rule.get("kind")
        if kind not in RULE_KINDS:
            _refuse_compile("%s has unknown kind %r" % (where, kind))
        tool = rule.get("tool")
        if tool not in inventory:
            _refuse_compile("%s references undeclared tool %r"
                            % (where, tool))
        if kind == "Init":
            allowed = {"kind", "tool"}
            entry = {"kind": kind, "tool": tool}
        elif kind == "Terminal":
            allowed = {"kind", "tool"}
            entry = {"kind": kind, "tool": tool}
        elif kind == "Child":
            parent = rule.get("parent")
            if parent not in inventory:
                _refuse_compile("%s references undeclared parent %r"
                                % (where, parent))
            if parent == tool:
                _refuse_compile("%s: a tool cannot be its own parent"
                                % (where,))
            allowed = {"kind", "tool", "parent"}
            entry = {"kind": kind, "tool": tool, "parent": parent}
        else:  # Conditional
            when = rule.get("when")
            if when not in predicates:
                _refuse_compile("%s references undeclared predicate %r"
                                % (where, when))
            allowed = {"kind", "tool", "when"}
            entry = {"kind": kind, "tool": tool, "when": when}
        for key in rule:
            if key not in allowed:
                _refuse_compile("%s has unknown key %r" % (where, key))
        compiled.append(entry)
    return compiled


def compile_rule_set(doc):
    """Validate a rule-set document fail-closed and compile it.

    Returns a frozen :class:`CompiledToolRuleSet`. Any shape violation
    refuses LOUD with coded ``toolcall-rule-compile-invalid``.
    """
    if not isinstance(doc, dict):
        _refuse_compile("rule set must be a dict; got %r"
                        % (type(doc),))
    for key in doc:
        if key not in ("format", "name", "tools", "rules", "predicates"):
            _refuse_compile("unknown top-level key %r" % (key,))
    if doc.get("format") != RULE_SET_FORMAT:
        _refuse_compile("format must be %r; got %r"
                        % (RULE_SET_FORMAT, doc.get("format")))
    name = _check_name(doc.get("name"), "name")
    tools = doc.get("tools")
    if not isinstance(tools, list) or not tools \
            or len(tools) > MAX_TOOLS:
        _refuse_compile("tools must be a non-empty list (<= %d)"
                        % (MAX_TOOLS,))
    inventory = []
    for tool in tools:
        _check_name(tool, "tool")
        if tool in inventory:
            _refuse_compile("duplicate tool %r" % (tool,))
        inventory.append(tool)
    inventory = frozenset(inventory)
    predicates = _compile_predicates(doc.get("predicates", {}), inventory)
    rules = _compile_rules(doc.get("rules", []), inventory, predicates)
    frozen = _freeze({
        "name": name,
        "tools": tuple(sorted(inventory)),
        "predicates": predicates,
        "rules": tuple(rules),
    })
    return CompiledToolRuleSet(frozen)


class CompiledToolRuleSet:
    """One compiled tool-rule set: the enforceable sequence checker.

    IMMUTABLE after compilation (the F330/F340 pattern): ``_doc`` is
    deep-frozen, so post-compile in-process mutation fails at the source.
    """

    def __init__(self, frozen_doc):
        # The document arrives frozen from compile_rule_set; _freeze is
        # idempotent over frozen structures, so direct construction with
        # an unfrozen dict is frozen here too. (No deepcopy: the frozen
        # MappingProxyType cannot be pickled/copied, and freezing already
        # severs every mutable alias.)
        self._doc = _freeze(frozen_doc)
        self.digest = _digest(self._doc)

    @property
    def name(self):
        return self._doc["name"]

    @property
    def tools(self):
        """The closed tool inventory: undeclared tools do not exist."""
        return tuple(self._doc["tools"])

    # -- evaluation ----------------------------------------------------

    def _refuse_sequence(self, message):
        raise ToolRuleError("tool-call sequence refused: %s" % (message,),
                            code=SEQUENCE_VIOLATED)

    def _check_history_shape(self, history):
        if not isinstance(history, (list, tuple)):
            self._refuse_sequence(
                "session history must be a list; got %r" % (type(history),))
        if len(history) > MAX_HISTORY_SCAN:
            self._refuse_sequence(
                "session history exceeds the %d-entry scan bound"
                % (MAX_HISTORY_SCAN,))
        for i, entry in enumerate(history):
            if not isinstance(entry, dict) \
                    or not isinstance(entry.get("tool"), str) \
                    or not entry.get("tool"):
                self._refuse_sequence(
                    "history entry %d must be a dict with a non-empty "
                    "string 'tool'; got %r" % (i, entry))

    def _predicate_holds(self, pname, history, context_flags):
        pred = self._doc["predicates"][pname]
        kind = pred["kind"]
        if kind == "flag":
            return bool(context_flags.get(pred["flag"]))
        # kind == "history"
        count = sum(1 for entry in history
                    if entry["tool"] == pred["tool"])
        return count >= pred["min_calls"]

    def _rule_satisfied(self, rule, history, context_flags):
        kind = rule["kind"]
        if kind == "Init":
            return not history
        if kind == "Child":
            return bool(history) and history[-1]["tool"] == rule["parent"]
        if kind == "Terminal":
            # The terminating call itself is always allowed; the session
            # closes AFTER it (checked below).
            return True
        # Conditional
        return self._predicate_holds(rule["when"], history, context_flags)

    def _terminal_tools(self):
        return frozenset(rule["tool"] for rule in self._doc["rules"]
                         if rule["kind"] == "Terminal")

    def check_call(self, tool, args=None, history=(), context_flags=None):
        """Check one tool call against the declared sequence.

        Returns an ``allowed`` record dict. Any violation -- undeclared
        tool, secret-shaped args, sequence violation, or an input the
        grammar cannot evaluate (fail-closed: the declaration is
        closed-world) -- raises coded :class:`ToolRuleError`
        (``toolcall-sequence-violated`` / ``toolcall-secret-in-args`` /
        ``toolcall-secret-scan-incomplete``).
        """
        # 1. Input shape (fail-closed: unevaluatable input violates the
        #    closed declaration).
        if not isinstance(tool, str) or not tool:
            self._refuse_sequence("tool must be a non-empty string; "
                                  "got %r" % (tool,))
        if args is None:
            args = {}
        if not isinstance(args, dict):
            self._refuse_sequence("args must be a dict; got %r"
                                  % (type(args),))
        for key in args:
            if not isinstance(key, str):
                self._refuse_sequence("args keys must be strings; got %r"
                                      % (key,))
        if history is None:
            history = ()
        self._check_history_shape(history)
        if context_flags is None:
            context_flags = {}
        if not isinstance(context_flags, dict):
            self._refuse_sequence("context_flags must be a dict; got %r"
                                  % (type(context_flags),))

        # 2. Secret-shape gate (before sequence: data-leak prevention is
        #    the tighter bound; order is deterministic and documented).
        #    The scan is tristate: a secret FOUND refuses coded
        #    toolcall-secret-in-args; a scan that could NOT COMPLETE
        #    within the declared bounds (depth 4 / 64KB budget) refuses
        #    coded toolcall-secret-scan-incomplete -- unevaluatable input
        #    is fail-closed, never silently allowed (F365).
        scan = _args_carry_secret(args)
        if scan is True:
            raise ToolRuleError(
                "tool-call refused: secret-shaped value in args for tool "
                "%r; secrets travel via typed context, never tool args"
                % (tool,), code=SECRET_IN_ARGS)
        if scan is None:
            raise ToolRuleError(
                "tool-call refused: the secret-shape scan of the args for "
                "tool %r could not complete within its declared bounds "
                "(nesting depth %d / %d-byte scan budget); unevaluatable "
                "input is refused fail-closed"
                % (tool, MAX_SECRET_DEPTH, MAX_SECRET_SCAN_BYTES),
                code=SCAN_INCOMPLETE)

        # 3. Closed inventory: undeclared tools do not exist.
        if tool not in self._doc["tools"]:
            self._refuse_sequence("undeclared tool %r; the bound rule set "
                                  "closes the tool inventory" % (tool,))

        # 4. Terminal closure: after a Terminal tool, nothing may follow.
        if history and history[-1]["tool"] in self._terminal_tools():
            self._refuse_sequence(
                "session closed by terminal tool %r; no calls may follow"
                % (history[-1]["tool"],))

        # 5. Per-tool rules (OR across rules of the same tool; a declared
        #    tool with no rules is unconstrained beyond the inventory).
        tool_rules = [rule for rule in self._doc["rules"]
                      if rule["tool"] == tool]
        if tool_rules and not any(self._rule_satisfied(rule, history,
                                                        context_flags)
                                  for rule in tool_rules):
            kinds = sorted(set(rule["kind"] for rule in tool_rules))
            self._refuse_sequence(
                "tool %r violates its declared rules %s at history "
                "length %d" % (tool, kinds, len(history)))

        return {"allowed": True, "tool": tool, "rule_set": self._doc["name"],
                "digest": self.digest, "history_len": len(history)}
