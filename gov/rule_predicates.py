"""Bounded predicate language for ``Conditional`` tool rules (wave-295 lane 3).

PATTERN LINEAGE: expr-lang/expr (MIT) and cel-expr/cel-go (Apache-2.0) --
compile-once, evaluate-many expression languages with a declared,
typed environment and a cost/memory budget on evaluation. This is a
clean-room stdlib-only reimplementation of the *disciplines*; no upstream
code is vendored.

The discipline, stated as Sasanam rules:

* TWO PHASES (cel-go compile/check): CHECK validates the predicate AST
  against a DECLARED environment of allowed session-history fields --
  unknown fields refuse coded ``toolcall-predicate-undeclared-field``
  AT COMPILE TIME. Nothing undeclared is ever evaluable.
* COST GATE (expr MemoryBudget): evaluation is pure, synchronous and
  bounded -- max AST nodes, max evaluation steps, max string lengths.
  Budget exhaustion refuses coded ``toolcall-predicate-budget``; the
  predicate can never DoS the decision path, and evaluation never
  silently truncates.
* PURE BY CONSTRUCTION (expr): no attribute access beyond declared
  fields, no function calls except a bounded builtin set, no imports,
  no loops, no I/O, no wall-clock, no exceptions escaping uncoded.
* RESULT PINNED (expr ``AsBool``): a predicate must evaluate to ``bool``;
  anything else refuses at compile time.

Language (AST as bounded JSON):

* ``{"const": <bool|int|str>}`` -- scalar literal. Lists are allowed only
  as homogeneous scalar lists of bounded length (for ``in``).
* ``{"field": "<name>"}`` -- a declared session-history field.
* ``{"op": "<op>", "args": [<node>, ...]}`` -- builtin application.

Builtins (closed vocabulary):

* comparisons: ``eq``, ``neq`` (same-type scalars), ``gt``, ``gte``,
  ``lt``, ``lte`` (ints only -- type confusion refuses at compile time);
* logic: ``and``, ``or`` (2+ bool args), ``not`` (1 bool arg);
* membership: ``in`` (scalar in homogeneous list), ``contains``
  (substring: str in str);
* ``len`` (str -> int).

The standard session-history environment (the only fields a predicate
can ever observe -- the predicate sees AGGREGATES, never raw history
entries, args, or tool outputs; the side channel is closed by
construction):

* ``calls`` (int): number of completed tool calls in the session history.
* ``last_tool`` (str): tool name of the most recent call ("" if none).
* ``distinct_tools`` (int): number of distinct tools used so far.
* ``started`` (bool): whether the session history is non-empty.

A rule-set document may declare ``predicate_env`` -- a SUBSET of the
standard environment with matching types -- to restrict what a
predicate may observe. It can never widen the environment.

Composition: ``gov/tool_rules.py`` compiles a ``Conditional`` rule's
``predicate`` spec at rule-set compile time (fail-closed); at check
time the compiled predicate is evaluated against the session history
and a false result refuses coded ``toolcall-sequence-violated``.

All refusals are LOUD: coded :class:`PredicateError`, never silent.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from types import MappingProxyType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Decision-code vocabulary (registered in gov/decision_codes.py).
PREDICATE_INVALID = "toolcall-predicate-invalid"
PREDICATE_BUDGET = "toolcall-predicate-budget"
PREDICATE_UNDECLARED_FIELD = "toolcall-predicate-undeclared-field"

#: The standard session-history environment: field name -> declared type.
#: Predicates observe aggregates only -- never raw history, args, or
#: tool outputs.
STANDARD_ENV = MappingProxyType({
    "calls": "int",
    "last_tool": "str",
    "distinct_tools": "int",
    "started": "bool",
})

#: Compile-time bounds.
MAX_AST_NODES = 256
MAX_CONST_STR_LEN = 256
MAX_CONST_LIST_LEN = 64
MAX_FIELD_NAME_LEN = 128

#: Evaluation budget (expr MemoryBudget discipline).
MAX_EVAL_STEPS = 4096
MAX_EVAL_STR_LEN = 1024

#: Closed builtin vocabulary: op -> (min_args, max_args).
_BUILTINS = MappingProxyType({
    "eq": (2, 2), "neq": (2, 2),
    "gt": (2, 2), "gte": (2, 2), "lt": (2, 2), "lte": (2, 2),
    "and": (2, None), "or": (2, None), "not": (1, 1),
    "in": (2, 2), "contains": (2, 2), "len": (1, 1),
})


class PredicateError(ValueError):
    """LOUD coded refusal for the predicate seam."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Freeze (the F330/F340 pattern, local so this module stays dependency-free)
# ---------------------------------------------------------------------------

def _freeze(obj):
    if isinstance(obj, dict):
        return MappingProxyType({k: _freeze(v) for k, v in obj.items()})
    if isinstance(obj, (list, tuple)):
        return tuple(_freeze(v) for v in obj)
    return obj


# ---------------------------------------------------------------------------
# CHECK phase: compile + validate
# ---------------------------------------------------------------------------

def _refuse_invalid(message):
    raise PredicateError("predicate refused: %s" % (message,),
                         code=PREDICATE_INVALID)


def _refuse_undeclared(field):
    raise PredicateError(
        "predicate refused: field %r is not in the declared predicate "
        "environment; undeclared fields do not exist" % (field,),
        code=PREDICATE_UNDECLARED_FIELD)


def _scalar_type(value, where):
    """Declared type of a scalar const; bool is NOT int here (strict)."""
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, str):
        return "str"
    _refuse_invalid("%s: const must be bool/int/str; got %r"
                    % (where, type(value)))


def _check_const(value, where, counter):
    if isinstance(value, list):
        if len(value) > MAX_CONST_LIST_LEN:
            _refuse_invalid(
                "%s: const list exceeds the %d-item bound"
                % (where, MAX_CONST_LIST_LEN))
        if not value:
            _refuse_invalid("%s: const list must be non-empty" % (where,))
        item_type = _scalar_type(value[0], where)
        for item in value:
            if _scalar_type(item, where) != item_type:
                _refuse_invalid(
                    "%s: const list must be homogeneous; mixed types"
                    % (where,))
            if isinstance(item, str) and len(item) > MAX_CONST_STR_LEN:
                _refuse_invalid(
                    "%s: const string exceeds the %d-char bound"
                    % (where, MAX_CONST_STR_LEN))
        return "list[%s]" % (item_type,)
    if isinstance(value, str) and len(value) > MAX_CONST_STR_LEN:
        _refuse_invalid("%s: const string exceeds the %d-char bound"
                        % (where, MAX_CONST_STR_LEN))
    return _scalar_type(value, where)


def _check_node(node, env, where, counter):
    """Recursively validate one AST node; returns its static type."""
    counter[0] += 1
    if counter[0] > MAX_AST_NODES:
        # Node-count is a compile-time bound: the expression is too big to
        # ever evaluate within budget, so it never compiles.
        raise PredicateError(
            "predicate refused: AST exceeds the %d-node compile bound"
            % (MAX_AST_NODES,), code=PREDICATE_BUDGET)
    if not isinstance(node, dict):
        _refuse_invalid("%s: node must be a dict; got %r"
                        % (where, type(node)))
    keys = set(node)
    if keys == {"const"}:
        if "const" not in node:  # pragma: no cover - defensive
            _refuse_invalid("%s: malformed const node" % (where,))
        return _check_const(node["const"], where, counter)
    if keys == {"field"}:
        name = node["field"]
        if not isinstance(name, str) or not name \
                or len(name) > MAX_FIELD_NAME_LEN:
            _refuse_invalid("%s: field name must be a non-empty string "
                            "(<= %d chars)" % (where, MAX_FIELD_NAME_LEN))
        if name not in env:
            _refuse_undeclared(name)
        return env[name]
    if keys == {"op", "args"}:
        op = node["op"]
        args = node["args"]
        if op not in _BUILTINS:
            _refuse_invalid("%s: unknown builtin %r; the builtin set is "
                            "closed" % (where, op))
        if not isinstance(args, list):
            _refuse_invalid("%s: op args must be a list" % (where,))
        lo, hi = _BUILTINS[op]
        if len(args) < lo or (hi is not None and len(args) > hi):
            _refuse_invalid("%s: builtin %r takes %s args; got %d"
                            % (where, op,
                               ("%d..%d" % (lo, hi)) if hi else ("%d+" % lo),
                               len(args)))
        arg_types = [_check_node(a, env, "%s.%s[%d]" % (where, op, i),
                                 counter)
                     for i, a in enumerate(args)]
        return _check_op_types(op, arg_types, where)
    _refuse_invalid("%s: node must be exactly one of {const}, {field}, "
                    "{op, args}; got keys %r" % (where, sorted(keys)))


def _check_op_types(op, arg_types, where):
    """Static type discipline for builtins. Returns the result type."""
    def need(types, why):
        if arg_types != types and not (
                len(types) == 1 and all(t == types[0] for t in arg_types)):
            _refuse_invalid(
                "%s: builtin %r requires %s; got %s"
                % (where, op, why, arg_types))

    if op in ("eq", "neq"):
        if len(set(arg_types)) != 1 or arg_types[0].startswith("list"):
            _refuse_invalid(
                "%s: builtin %r compares same-type scalars only; got %s"
                % (where, op, arg_types))
        return "bool"
    if op in ("gt", "gte", "lt", "lte"):
        # Ints only: type confusion (str vs int, bool vs int) refuses at
        # COMPILE time -- never a silent False at runtime.
        if arg_types != ["int", "int"]:
            _refuse_invalid(
                "%s: builtin %r compares ints only; got %s -- type "
                "confusion refuses at compile time" % (where, op, arg_types))
        return "bool"
    if op in ("and", "or"):
        if any(t != "bool" for t in arg_types):
            _refuse_invalid("%s: builtin %r takes bools; got %s"
                            % (where, op, arg_types))
        return "bool"
    if op == "not":
        if arg_types != ["bool"]:
            _refuse_invalid("%s: builtin 'not' takes a bool; got %s"
                            % (where, arg_types))
        return "bool"
    if op == "in":
        scalar, lst = arg_types
        if scalar in ("bool", "int", "str") and lst == "list[%s]" % (scalar,):
            return "bool"
        _refuse_invalid(
            "%s: builtin 'in' takes (scalar, homogeneous list of the same "
            "scalar type); got %s" % (where, arg_types))
    if op == "contains":
        if arg_types != ["str", "str"]:
            _refuse_invalid("%s: builtin 'contains' takes (str, str); got %s"
                            % (where, arg_types))
        return "bool"
    if op == "len":
        if arg_types != ["str"]:
            _refuse_invalid("%s: builtin 'len' takes a str; got %s"
                            % (where, arg_types))
        return "int"
    _refuse_invalid("%s: unreachable builtin %r" % (where, op))  # pragma: no cover


def compile_predicate_env(declared):
    """Validate a rule-set ``predicate_env`` declaration.

    It must be a SUBSET of the standard environment with matching types --
    the environment can be narrowed, never widened. ``None`` selects the
    full standard environment.
    """
    if declared is None:
        return dict(STANDARD_ENV)
    if not isinstance(declared, dict) or not declared:
        _refuse_invalid("predicate_env must be a non-empty dict or absent")
    env = {}
    for name, typ in declared.items():
        if not isinstance(name, str) or not isinstance(typ, str):
            _refuse_invalid("predicate_env entries must be str->str")
        if name not in STANDARD_ENV:
            _refuse_undeclared(name)
        if STANDARD_ENV[name] != typ:
            _refuse_invalid(
                "predicate_env field %r must keep its standard type %r; "
                "got %r" % (name, STANDARD_ENV[name], typ))
        env[name] = typ
    return env


def _thaw(obj):
    """MappingProxy/tuple -> dict/list (for re-compiling frozen ASTs)."""
    if isinstance(obj, MappingProxyType):
        return {key: _thaw(value) for key, value in obj.items()}
    if isinstance(obj, tuple):
        return [_thaw(value) for value in obj]
    if isinstance(obj, list):
        return [_thaw(value) for value in obj]
    if isinstance(obj, dict):
        return {key: _thaw(value) for key, value in obj.items()}
    return obj


def compile_predicate(spec, environment=None):
    """CHECK phase: compile a predicate spec against a declared environment.

    Returns an immutable :class:`CompiledPredicate`. Any violation refuses
    LOUD: ``toolcall-predicate-undeclared-field`` for unknown fields,
    ``toolcall-predicate-invalid`` for malformed/ill-typed specs,
    ``toolcall-predicate-budget`` for over-bound ASTs.
    """
    env = compile_predicate_env(environment)
    if not isinstance(spec, (dict, MappingProxyType)):
        _refuse_invalid("predicate spec must be a dict; got %r"
                        % (type(spec),))
    # Deep-copy through canonical JSON so the caller's spec cannot be
    # aliased (and frozen ASTs re-compile identically), then validate
    # the copy.
    import json as _json
    try:
        spec_copy = _json.loads(_json.dumps(_thaw(spec), sort_keys=True))
    except (TypeError, ValueError):
        _refuse_invalid("predicate spec must be JSON-serializable")
    result_type = _check_node(spec_copy, env, "predicate", [0])
    if result_type != "bool":
        _refuse_invalid("predicate must evaluate to bool; got %s"
                        % (result_type,))
    return CompiledPredicate(_freeze(spec_copy), _freeze(env))


class CompiledPredicate:
    """One compiled predicate: immutable, evaluatable, budget-guarded.

    IMMUTABLE after compilation (the F330/F340 pattern): the AST and the
    environment are deep-frozen, so post-compile in-process mutation of
    the caller's spec -- or of this object -- fails at the source.
    """

    __slots__ = ("_ast", "_env")

    def __init__(self, frozen_ast, frozen_env):
        object.__setattr__(self, "_ast", frozen_ast)
        object.__setattr__(self, "_env", frozen_env)

    def __setattr__(self, name, value):
        raise PredicateError(
            "predicate refused: CompiledPredicate is immutable",
            code=PREDICATE_INVALID)

    @property
    def environment(self):
        """The declared environment this predicate was checked against."""
        return dict(self._env)

    @property
    def ast(self):
        """The frozen canonical AST (plain JSON shapes)."""
        import json as _json
        return _json.loads(_json.dumps(_thaw(self._ast)))

    # -- EVALUATE phase -------------------------------------------------

    def _refuse_budget(self, message):
        raise PredicateError(
            "predicate refused: evaluation budget exhausted: %s "
            "(max %d steps; the predicate never silently truncates)"
            % (message, MAX_EVAL_STEPS), code=PREDICATE_BUDGET)

    def _refuse_eval(self, message):
        raise PredicateError("predicate refused: evaluation failed: %s"
                             % (message,), code=PREDICATE_INVALID)

    def evaluate(self, env_values):
        """EVALUATE phase: pure, synchronous, budget-guarded evaluation.

        ``env_values`` maps declared field names to runtime values. Every
        value is re-checked against its declared type (defense in depth:
        the compiler already proved the types, but the runtime never
        trusts the caller). Budget exhaustion refuses coded
        ``toolcall-predicate-budget``; any other evaluation failure
        refuses coded ``toolcall-predicate-invalid``. Returns a bool.
        """
        if not isinstance(env_values, dict):
            self._refuse_eval("env values must be a dict")
        values = {}
        for name, typ in self._env.items():
            if name not in env_values:
                self._refuse_eval("missing value for declared field %r"
                                  % (name,))
            values[name] = self._check_runtime_value(name, typ,
                                                     env_values[name])
        state = {"steps": 0}
        result = self._eval(self._ast, values, state)
        if not isinstance(result, bool):
            self._refuse_eval("predicate evaluated to non-bool %r"
                              % (type(result),))
        return result

    def _check_runtime_value(self, name, typ, value):
        if typ == "int":
            if isinstance(value, bool) or not isinstance(value, int):
                self._refuse_eval("field %r must be int; got %r"
                                  % (name, type(value)))
            return value
        if typ == "str":
            if not isinstance(value, str):
                self._refuse_eval("field %r must be str; got %r"
                                  % (name, type(value)))
            if len(value) > MAX_EVAL_STR_LEN:
                self._refuse_budget("field %r value exceeds the %d-char "
                                    "runtime bound" % (name, MAX_EVAL_STR_LEN))
            return value
        if typ == "bool":
            if not isinstance(value, bool):
                self._refuse_eval("field %r must be bool; got %r"
                                  % (name, type(value)))
            return value
        self._refuse_eval("unknown declared type %r" % (typ,))  # pragma: no cover

    def _step(self, state, cost=1):
        state["steps"] += cost
        if state["steps"] > MAX_EVAL_STEPS:
            self._refuse_budget("step limit exceeded")

    def _eval(self, node, values, state):
        self._step(state)
        keys = set(node)
        if keys == {"const"}:
            return node["const"]
        if keys == {"field"}:
            return values[node["field"]]
        op = node["op"]
        args = [self._eval(a, values, state) for a in node["args"]]
        return self._apply(op, args, state)

    def _apply(self, op, args, state):
        # All operand shapes were proven at compile time; the checks here
        # are defense in depth so no Python-level exception can ever
        # escape uncoded (the F351 contract).
        try:
            if op == "eq":
                return args[0] == args[1]
            if op == "neq":
                return args[0] != args[1]
            if op == "gt":
                return args[0] > args[1]
            if op == "gte":
                return args[0] >= args[1]
            if op == "lt":
                return args[0] < args[1]
            if op == "lte":
                return args[0] <= args[1]
            if op == "and":
                return all(args)
            if op == "or":
                return any(args)
            if op == "not":
                return not args[0]
            if op == "in":
                self._step(state, min(len(args[1]), MAX_CONST_LIST_LEN))
                return args[0] in args[1]
            if op == "contains":
                self._step(state, min(len(args[0]) + len(args[1]), 512))
                return args[1] in args[0]
            if op == "len":
                self._step(state, min(len(args[0]), 512))
                return len(args[0])
        except PredicateError:
            raise
        except Exception as exc:  # never uncoded (F351 contract)
            self._refuse_eval("builtin %r failed: %s" % (op, exc))
        self._refuse_eval("unknown builtin %r" % (op,))  # pragma: no cover


def session_fields(history):
    """Derive the declared session-history environment from a history.

    The predicate sees AGGREGATES only -- never raw history entries, tool
    args, or tool outputs. The side channel is closed by construction:
    no predicate field can smuggle a runtime value the environment does
    not declare.
    """
    if not isinstance(history, (list, tuple)):
        raise PredicateError("predicate refused: session history must be "
                             "a list or tuple",
                             code=PREDICATE_INVALID)
    tools = []
    for entry in history:
        if not isinstance(entry, dict) or not isinstance(
                entry.get("tool"), str):
            raise PredicateError("predicate refused: history entry must be "
                                 "a dict with a string 'tool'",
                                 code=PREDICATE_INVALID)
        tools.append(entry["tool"])
    return {
        "calls": len(tools),
        "last_tool": tools[-1] if tools else "",
        "distinct_tools": len(set(tools)),
        "started": bool(tools),
    }
