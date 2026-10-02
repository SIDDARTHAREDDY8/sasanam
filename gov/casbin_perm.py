"""Casbin PERM DSL for declarative agent->tool authorization (wave-281).

ADAPT of the casbin/casbin PERM metamodel mechanisms (Apache-2.0; shapes
only -- no casbin code vendored, no pycasbin dependency: the wave-280
prospectus rejects pycasbin on supply-chain grounds and the PERM model is
small enough to port clean-room in stdlib).

A policy is a CONF text with the PERM sections::

    [request_definition]   r = agent, tool, action
    [policy_definition]    p = agent, tool, action, eft
    [role_definition]      g = _, _
    [policy_effect]        e = !some(where (p.eft == deny))
    [matchers]             m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action
    [policy]               p, admin, shell, exec, allow
    [role_policy]          g, alice, admin

``[policy_effect]`` is a closed vocabulary (deny-override, allow-override,
priority) -- policy-combination stops being special cases in product code.
``[matchers]`` is a small audited expression language (never ``eval()``):
``&&`` / ``||`` / ``!`` / ``==`` / ``!=``, string literals, ``r.*`` / ``p.*``
attribute references, and the audited builtins ``g`` (role inheritance),
``keyMatch``, ``keyMatch2``, ``regexMatch``, ``ipMatch``. Unknown functions,
unknown operators, and malformed CONF refuse at compile time
(fail-closed); runtime matcher errors fail the whole enforcement closed
to deny (never raise, never allow).

``enforce_ex`` is the explain API: it returns the decision PLUS the
matched rule rows, so every denied tool call can name the rule that denied
it. ``packet_evidence`` hashes those rows (sha256 over canonical JSON)
into digest-bound records that feed ``decision_packet.build``'s existing
``matched_rules`` section -- Casbin-shaped evaluation feeding
packet-shaped evidence (composition, not duplication). ``batch_enforce``
authorizes N planned tool calls in one pass.

``*`` is the any-wildcard in policy-row fields: it matches any value
under ``==`` and keyMatch-style builtins. It is NOT special inside
``g()`` (role lookup) or ``regexMatch`` (regex syntax there), and under
``!=`` a ``*`` operand makes the comparison always False (fail-closed).

Compile-time shadow analysis is sound-but-incomplete: a missed
implication is never flagged, a false flag is never raised. Exact
duplicates and contradictory identical-pattern rows always refuse;
pattern-subset shadowing is analyzed only when the matcher is monotone
equality-shaped (no ``!=``/``!``, no ``g()`` role calls), because
non-monotone operators and role expansion make field-pattern subset
analysis unsound. Unknown ``r.*``/``p.*`` attribute references are
refused at compile (``row_id``/``lineno`` are evidence metadata, never
matcher-visible).

Stdlib only. Deterministic: no clock, no randomness, no I/O in the
evaluate path.
"""

import hashlib
import ipaddress
import json
import re

# ---------------------------------------------------------------------------
# Refusal vocabulary (registered in gov/decision_codes.py, domain "policy").
# ---------------------------------------------------------------------------


class CasbinError(ValueError):
    """Base for Casbin PERM declaration/enforcement refusals.

    Machine-readable ``.code`` on every refusal (repo convention: callers
    branch on ``code``, never on message text). Subclassing ValueError
    keeps declaration-time refusals catchable as programming errors too.
    """

    code = "casbin-conf-invalid"

    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


class CasbinConfError(CasbinError):
    """The CONF text is malformed (fail-closed at compile)."""

    def __init__(self, detail):
        super().__init__("casbin-conf-invalid", detail)


class CasbinUnknownFunctionError(CasbinError):
    """The matcher names a builtin outside the audited set."""

    def __init__(self, name):
        super().__init__(
            "casbin-unknown-matcher-function",
            "matcher function %r is not in the audited builtin set "
            "{g, keyMatch, keyMatch2, regexMatch, ipMatch}: refusing "
            "rather than evaluating an unknown predicate" % (name,))


class CasbinShadowError(CasbinError):
    """A policy row can never decide (duplicate/shadowed/contradictory)."""

    def __init__(self, row_id, reason):
        super().__init__(
            "casbin-policy-shadowed",
            "policy row %s %s: refusing rather than loading a "
            "dead rule" % (row_id, reason))


# Emitted (not raised) when a runtime matcher error fails an enforcement
# closed to deny; attached as the packet decision_code by the caller.
ENFORCE_ERROR_CODE = "casbin-enforce-error-fail-closed"

_RECORD_TYPE = "casbin-decision"

_BUILTINS = ("g", "keyMatch", "keyMatch2", "regexMatch", "ipMatch")

_EFFECT_FORMS = {
    "some(where (p.eft == allow))": "allow-override",
    "!some(where (p.eft == deny))": "deny-override",
    "priority(p.eft)": "priority",
}


class _MatchError(Exception):
    """Internal: a matcher evaluation step failed (fail-closed to deny)."""


# ---------------------------------------------------------------------------
# CONF parsing (strict, line-based -- never configparser's loose grammar).
# ---------------------------------------------------------------------------

_SECTION_RE = re.compile(r"^\[([a-z_]+)\]$")
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_KNOWN_SECTIONS = (
    "request_definition", "policy_definition", "role_definition",
    "policy_effect", "matchers", "policy", "role_policy",
)
_REQUIRED_SECTIONS = (
    "request_definition", "policy_definition", "policy_effect",
    "matchers", "policy",
)


def _parse_conf(text):
    if not isinstance(text, str):
        raise CasbinConfError("CONF must be str, got %s" % type(text).__name__)
    sections = {}
    current = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _SECTION_RE.match(line)
        if m:
            name = m.group(1)
            if name not in _KNOWN_SECTIONS:
                raise CasbinConfError(
                    "line %d: unknown section [%s]" % (lineno, name))
            if name in sections:
                raise CasbinConfError(
                    "line %d: duplicate section [%s]" % (lineno, name))
            sections[name] = []
            current = name
            continue
        if current is None:
            raise CasbinConfError("line %d: content before any section" % lineno)
        sections[current].append((lineno, line))
    missing = [s for s in _REQUIRED_SECTIONS if s not in sections]
    if missing:
        raise CasbinConfError("missing required sections: %s" % ", ".join(missing))
    return sections


def _parse_definition(lines, var, section):
    if len(lines) != 1:
        raise CasbinConfError(
            "[%s] must declare exactly one %s = ... line" % (section, var))
    lineno, line = lines[0]
    if "=" not in line:
        raise CasbinConfError("line %d: expected '%s = ...'" % (lineno, var))
    left, right = line.split("=", 1)
    if left.strip() != var:
        raise CasbinConfError(
            "line %d: expected '%s = ...', got %r" % (lineno, var, line))
    names = [n.strip() for n in right.split(",")]
    if not names or any(not _NAME_RE.match(n) for n in names):
        raise CasbinConfError("line %d: bad attribute list %r" % (lineno, line))
    return names


def _parse_policy_rows(lines):
    rows = []
    for lineno, line in lines:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 5 or parts[0] != "p":
            raise CasbinConfError(
                "line %d: policy rows are 'p, agent, tool, action, eft'" % lineno)
        _, agent, tool, action, eft = parts
        if eft not in ("allow", "deny"):
            raise CasbinConfError(
                "line %d: eft must be allow|deny, got %r" % (lineno, eft))
        if not agent or not tool or not action:
            raise CasbinConfError("line %d: empty policy field" % lineno)
        rows.append({"row_id": "p:%d" % len(rows), "agent": agent,
                     "tool": tool, "action": action, "eft": eft,
                     "lineno": lineno})
    return rows


def _parse_role_rows(lines):
    edges = []
    for lineno, line in lines:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 3 or parts[0] != "g":
            raise CasbinConfError(
                "line %d: role rows are 'g, child, parent'" % lineno)
        _, child, parent = parts
        if not child or not parent:
            raise CasbinConfError("line %d: empty role field" % lineno)
        edges.append((child, parent))
    return edges


# ---------------------------------------------------------------------------
# Matcher language: tokenizer + recursive-descent parser + evaluator.
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<op>&&|\|\||==|!=|!|\(|\)|,|\.)
  | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<bad>.)
""", re.VERBOSE)


def _tokenize(expr):
    tokens = []
    for m in _TOKEN_RE.finditer(expr):
        kind = m.lastgroup
        if kind == "ws":
            continue
        if kind == "bad":
            raise CasbinConfError("matcher: bad character %r" % m.group(0))
        tokens.append((kind, m.group(0)))
    return tokens


class _Parser:
    def __init__(self, tokens):
        self._toks = tokens
        self._pos = 0

    def _peek(self):
        return self._toks[self._pos] if self._pos < len(self._toks) else (None, None)

    def _next(self):
        tok = self._peek()
        self._pos += 1
        return tok

    def _expect_op(self, op):
        kind, val = self._next()
        if kind != "op" or val != op:
            raise CasbinConfError("matcher: expected %r" % op)
        return val

    def parse(self):
        node = self._parse_or()
        kind, val = self._peek()
        if kind is not None:
            raise CasbinConfError("matcher: trailing input %r" % (val,))
        return node

    def _parse_or(self):
        node = self._parse_and()
        while self._peek() == ("op", "||"):
            self._next()
            node = ("or", node, self._parse_and())
        return node

    def _parse_and(self):
        node = self._parse_unary()
        while self._peek() == ("op", "&&"):
            self._next()
            node = ("and", node, self._parse_unary())
        return node

    def _parse_unary(self):
        if self._peek() == ("op", "!"):
            self._next()
            return ("not", self._parse_unary())
        if self._peek() == ("op", "("):
            self._next()
            node = self._parse_or()
            self._expect_op(")")
            return node
        return self._parse_cmp()

    def _parse_cmp(self):
        left = self._parse_operand()
        if self._peek() in (("op", "=="), ("op", "!=")):
            _, op = self._next()
            right = self._parse_operand()
            return ("eq" if op == "==" else "ne", left, right)
        return left

    def _parse_operand(self):
        kind, val = self._next()
        if kind == "str":
            return ("str", _unquote(val))
        if kind == "name":
            if self._peek() == ("op", "("):
                return self._parse_call(val)
            if self._peek() == ("op", "."):
                self._next()
                k2, v2 = self._next()
                if k2 != "name":
                    raise CasbinConfError("matcher: expected attribute name")
                if val not in ("r", "p"):
                    raise CasbinConfError(
                        "matcher: unknown reference root %r (want r.* or p.*)"
                        % (val,))
                return ("ref", val, v2)
            raise CasbinConfError(
                "matcher: bare name %r is not a call, reference, or string"
                % (val,))
        raise CasbinConfError("matcher: expected operand, got %r" % (val,))

    def _parse_call(self, name):
        if name not in _BUILTINS:
            raise CasbinUnknownFunctionError(name)
        self._expect_op("(")
        args = []
        if self._peek() != ("op", ")"):
            args.append(self._parse_operand())
            while self._peek() == ("op", ","):
                self._next()
                args.append(self._parse_operand())
        self._expect_op(")")
        if len(args) != 2:
            raise CasbinConfError(
                "matcher: builtin %s takes exactly 2 args" % (name,))
        return ("call", name, tuple(args))


def _unquote(token):
    quote = token[0]
    body = token[1:-1]
    out = []
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body) and body[i + 1] in (quote, "\\"):
            out.append(body[i + 1])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _ast_uses_roles(node):
    tag = node[0]
    if tag == "call":
        return node[1] == "g" or any(_ast_uses_roles(a) for a in node[2])
    if tag in ("or", "and", "eq", "ne"):
        return _ast_uses_roles(node[1]) or _ast_uses_roles(node[2])
    if tag == "not":
        return _ast_uses_roles(node[1])
    return False


def _ast_is_monotone(node):
    """True iff the matcher uses policy fields only monotonically.

    ``*``-subsumption reasoning ("earlier pattern covers later") is valid
    only for monotone uses of a field: ``==`` and the keyMatch-style
    builtins. Under ``!=`` or ``!`` a ``*`` operand matches nothing (the
    comparison is defined False when either side is ``*``), so an
    earlier-field ``*`` does NOT subsume a later literal there — the
    subset branch must stay silent, or it false-flags live rows (S1).
    """
    tag = node[0]
    if tag in ("ne", "not"):
        return False
    if tag == "call":
        return all(_ast_is_monotone(a) for a in node[2])
    if tag in ("or", "and", "eq"):
        return _ast_is_monotone(node[1]) and _ast_is_monotone(node[2])
    return True


# Pinned shapes: requests are exactly (agent, tool, action); policy rows are
# exactly (agent, tool, action, eft). ``row_id``/``lineno`` are evidence
# metadata and are NOT matcher-visible (S2: keeping the identical-row
# shadow fast path sound).
_REQUEST_ATTRS = ("agent", "tool", "action")
_POLICY_ATTRS = ("agent", "tool", "action", "eft")


def _check_matcher_attrs(node):
    """Compile-time refusal of unknown r.*/p.* attribute references.

    Request shape is pinned to (agent, tool, action) and policy rows to
    (agent, tool, action, eft), so an unknown attribute can never be
    valid — refusing at compile is friendlier and keeps the identical-row
    shadow fast path sound (S2: row_id/lineno are not matcher-visible).
    """
    tag = node[0]
    if tag == "ref":
        side, attr = node[1], node[2]
        ok = (attr in _REQUEST_ATTRS) if side == "r" else (attr in _POLICY_ATTRS)
        if not ok:
            raise CasbinConfError(
                "matcher: unknown %s attribute %r" % (side, attr))
        return
    if tag == "call":
        for a in node[2]:
            _check_matcher_attrs(a)
        return
    if tag in ("or", "and", "eq", "ne"):
        _check_matcher_attrs(node[1])
        _check_matcher_attrs(node[2])
        return
    if tag == "not":
        _check_matcher_attrs(node[1])


def _key_match(value, pattern):
    if not isinstance(value, str) or not isinstance(pattern, str):
        raise _MatchError("keyMatch needs strings")
    if "*" not in pattern:
        return value == pattern
    rx = "".join(".*" if c == "*" else re.escape(c) for c in pattern)
    return re.fullmatch(rx, value) is not None


def _key_match2(value, pattern):
    if not isinstance(value, str) or not isinstance(pattern, str):
        raise _MatchError("keyMatch2 needs strings")
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == ":":
            j = i + 1
            while j < len(pattern) and (pattern[j].isalnum() or pattern[j] == "_"):
                j += 1
            if j == i + 1:
                raise _MatchError("keyMatch2: empty :param")
            out.append("[^/]+")
            i = j
        elif c == "*":
            out.append(".*")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.fullmatch("".join(out), value) is not None


def _regex_match(value, compiled):
    if not isinstance(value, str):
        raise _MatchError("regexMatch needs a string subject")
    return compiled.search(value) is not None


def _ip_match(value, cidr):
    if not isinstance(value, str) or not isinstance(cidr, str):
        raise _MatchError("ipMatch needs strings")
    try:
        return ipaddress.ip_address(value) in ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise _MatchError("ipMatch: %s" % (e,))


class _Roles:
    def __init__(self, edges):
        self._children = {}
        for child, parent in edges:
            self._children.setdefault(child, set()).add(parent)

    def inherits(self, child, parent):
        """True iff child == parent or child transitively inherits parent.

        Cycle-safe: visited set bounds the walk.
        """
        if child == parent:
            return True
        seen = {child}
        stack = [child]
        while stack:
            node = stack.pop()
            for nxt in self._children.get(node, ()):
                if nxt == parent:
                    return True
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return False


def _eval(node, request, row, roles, regex_cache):
    tag = node[0]
    if tag == "str":
        return node[1]
    if tag == "ref":
        _, root, attr = node
        if root == "r":
            source, allowed = request, _REQUEST_ATTRS
        else:
            source, allowed = row, _POLICY_ATTRS
        if attr not in allowed:
            raise _MatchError("unknown attribute %s.%s" % (root, attr))
        return source[attr]
    if tag == "eq":
        lval, rval = _eval(node[1], request, row, roles, regex_cache), \
            _eval(node[2], request, row, roles, regex_cache)
        if lval == "*" or rval == "*":
            return True
        return lval == rval
    if tag == "ne":
        lval, rval = _eval(node[1], request, row, roles, regex_cache), \
            _eval(node[2], request, row, roles, regex_cache)
        if lval == "*" or rval == "*":
            return False
        return lval != rval
    if tag == "not":
        val = _eval(node[1], request, row, roles, regex_cache)
        if not isinstance(val, bool):
            raise _MatchError("! needs a boolean")
        return not val
    if tag == "and":
        lval = _eval(node[1], request, row, roles, regex_cache)
        if not isinstance(lval, bool):
            raise _MatchError("&& needs booleans")
        if not lval:
            return False
        rval = _eval(node[2], request, row, roles, regex_cache)
        if not isinstance(rval, bool):
            raise _MatchError("&& needs booleans")
        return rval
    if tag == "or":
        lval = _eval(node[1], request, row, roles, regex_cache)
        if not isinstance(lval, bool):
            raise _MatchError("|| needs booleans")
        if lval:
            return True
        rval = _eval(node[2], request, row, roles, regex_cache)
        if not isinstance(rval, bool):
            raise _MatchError("|| needs booleans")
        return rval
    if tag == "call":
        _, name, args = node
        aval = _eval(args[0], request, row, roles, regex_cache)
        bval = _eval(args[1], request, row, roles, regex_cache)
        if name == "g":
            if not isinstance(aval, str) or not isinstance(bval, str):
                raise _MatchError("g needs strings")
            return roles.inherits(aval, bval)
        if name == "keyMatch":
            return _key_match(aval, bval)
        if name == "keyMatch2":
            return _key_match2(aval, bval)
        if name == "regexMatch":
            pat_node = args[1]
            if pat_node[0] == "ref" and pat_node[1] == "p":
                compiled = regex_cache.get((row["row_id"], pat_node[2]))
            elif pat_node[0] == "str":
                compiled = regex_cache.get(("literal", pat_node[1]))
            else:
                compiled = None
            if compiled is None:
                if not isinstance(bval, str):
                    raise _MatchError("regexMatch needs a string pattern")
                try:
                    compiled = re.compile(bval)
                except re.error as e:
                    raise _MatchError("regexMatch: bad pattern: %s" % (e,))
            return _regex_match(aval, compiled)
        if name == "ipMatch":
            return _ip_match(aval, bval)
    raise _MatchError("unknown AST node %r" % (tag,))


def _precompile_regexes(ast, rows):
    """Compile every regexMatch pattern statically at load.

    Patterns drawn from policy-row fields are compiled once per row;
    an invalid pattern refuses at compile time (fail-closed), never at
    enforce time. Returns {(row_id, field): compiled}.
    """
    found = []

    def walk(node):
        if node[0] == "call" and node[1] == "regexMatch":
            found.append(node[2][1])
        for child in node[1:]:
            if isinstance(child, tuple):
                walk(child)
            elif isinstance(child, (list, tuple)):
                for c in child:
                    if isinstance(c, tuple):
                        walk(c)

    walk(ast)
    compiled = {}
    for pat_node in found:
        if pat_node[0] == "ref" and pat_node[1] == "p":
            field = pat_node[2]
            for row in rows:
                try:
                    compiled[(row["row_id"], field)] = re.compile(row[field])
                except re.error as e:
                    raise CasbinConfError(
                        "row %s: invalid regexMatch pattern in field %r: %s"
                        % (row["row_id"], field, e))
        elif pat_node[0] == "str":
            try:
                compiled[("literal", pat_node[1])] = re.compile(pat_node[1])
            except re.error as e:
                raise CasbinConfError("invalid regexMatch literal: %s" % (e,))
    return compiled


# ---------------------------------------------------------------------------
# Compile: parse, validate, shadow-analyze.
# ---------------------------------------------------------------------------

def compile_model(conf_text):
    """Compile a PERM CONF text into an immutable model dict.

    Refuses fail-closed (CasbinError with a machine .code) on malformed
    CONF, unknown matcher functions, invalid regex patterns, duplicate
    rows, and rows that can never decide (shadowed/contradictory).
    """
    sections = _parse_conf(conf_text)
    req_attrs = _parse_definition(sections["request_definition"], "r",
                                 "request_definition")
    if req_attrs != ["agent", "tool", "action"]:
        raise CasbinConfError(
            "request_definition must be exactly 'r = agent, tool, action' "
            "(the agent->tool contract)")
    pol_attrs = _parse_definition(sections["policy_definition"], "p",
                                 "policy_definition")
    if pol_attrs != ["agent", "tool", "action", "eft"]:
        raise CasbinConfError(
            "policy_definition must be exactly 'p = agent, tool, action, eft'")
    role_attrs = _parse_definition(sections.get("role_definition", []), "g",
                                   "role_definition") if "role_definition" in sections else []
    if role_attrs and role_attrs != ["_", "_"]:
        raise CasbinConfError("role_definition must be exactly 'g = _, _'")
    effect_lines = sections["policy_effect"]
    if len(effect_lines) != 1:
        raise CasbinConfError("[policy_effect] declares exactly one e = ... line")
    _, effect_line = effect_lines[0]
    if "=" not in effect_line or effect_line.split("=", 1)[0].strip() != "e":
        raise CasbinConfError("[policy_effect] must be 'e = <form>'")
    effect_form = effect_line.split("=", 1)[1].strip()
    if effect_form not in _EFFECT_FORMS:
        raise CasbinConfError(
            "unknown policy_effect %r (want one of: %s)"
            % (effect_form, ", ".join(sorted(_EFFECT_FORMS))))
    effect = _EFFECT_FORMS[effect_form]
    matcher_lines = sections["matchers"]
    if len(matcher_lines) != 1:
        raise CasbinConfError("[matchers] declares exactly one m = ... line")
    _, matcher_line = matcher_lines[0]
    if "=" not in matcher_line or matcher_line.split("=", 1)[0].strip() != "m":
        raise CasbinConfError("[matchers] must be 'm = <expr>'")
    try:
        matcher_ast = _Parser(
            _tokenize(matcher_line.split("=", 1)[1].strip())).parse()
    except RecursionError:
        # A pathologically nested matcher (S3): fail-closed at compile with
        # a coded refusal rather than leaking a bare RecursionError.
        raise CasbinConfError("matcher: expression too deeply nested")
    _check_matcher_attrs(matcher_ast)

    rows = _parse_policy_rows(sections["policy"])
    edges = _parse_role_rows(sections.get("role_policy", []))
    roles = _Roles(edges)
    regex_cache = _precompile_regexes(matcher_ast, rows)
    _reject_shadowed(rows, effect, _ast_uses_roles(matcher_ast),
                     _ast_is_monotone(matcher_ast))

    return {
        "effect": effect,
        "effect_form": effect_form,
        "matcher_ast": matcher_ast,
        "policy": rows,
        "roles": roles,
        "regex_cache": regex_cache,
        "conf_bytes": conf_text.encode("utf-8"),
    }


def _pattern_subset(later, earlier):
    """True iff later's field pattern is covered by earlier's.

    Per field: equal literals, or earlier is the any-wildcard '*'.
    """
    for field in ("agent", "tool", "action"):
        if later[field] != earlier[field] and earlier[field] != "*":
            return False
    return True


def _reject_shadowed(rows, effect, uses_roles, monotone):
    for i, earlier in enumerate(rows):
        for later in rows[i + 1:]:
            same_pattern = all(later[f] == earlier[f]
                               for f in ("agent", "tool", "action"))
            if same_pattern and later["eft"] == earlier["eft"]:
                raise CasbinShadowError(later["row_id"], "is an exact duplicate")
            if same_pattern and later["eft"] != earlier["eft"]:
                # Identical rows match identically under every matcher
                # (row_id/lineno are not matcher-visible), so the
                # combinator decides which one is dead.
                dead = (
                    (effect == "deny-override" and earlier["eft"] == "deny")
                    or (effect == "allow-override" and earlier["eft"] == "allow")
                    or effect == "priority")
                if dead:
                    raise CasbinShadowError(
                        later["row_id"],
                        "contradicts identical earlier row %s (%s wins under %s)"
                        % (earlier["row_id"], earlier["eft"], effect))
                continue
            if uses_roles or not monotone or not _pattern_subset(later, earlier):
                continue
            # Monotone equality-shaped matcher: later's requests are a subset
            # of earlier's, so check whether later can ever change the outcome.
            if effect == "priority":
                raise CasbinShadowError(
                    later["row_id"],
                    "is fully covered by earlier row %s (priority: earlier decides first)"
                    % (earlier["row_id"],))
            if effect == "deny-override" and (
                    earlier["eft"] == "deny"
                    or (earlier["eft"] == "allow" and later["eft"] == "allow")):
                raise CasbinShadowError(
                    later["row_id"],
                    "is fully covered by earlier row %s (can never decide under deny-override)"
                    % (earlier["row_id"],))
            if effect == "allow-override" and (
                    earlier["eft"] == "allow"
                    or (earlier["eft"] == "deny" and later["eft"] == "deny")):
                raise CasbinShadowError(
                    later["row_id"],
                    "is fully covered by earlier row %s (can never decide under allow-override)"
                    % (earlier["row_id"],))


# ---------------------------------------------------------------------------
# Enforcement.
# ---------------------------------------------------------------------------

def _public_row(row):
    return {"row_id": row["row_id"], "agent": row["agent"],
            "tool": row["tool"], "action": row["action"], "eft": row["eft"]}


def _combine(effect, matched):
    if effect == "deny-override":
        if any(r["eft"] == "deny" for r in matched):
            return False
        return any(r["eft"] == "allow" for r in matched)
    if effect == "allow-override":
        if any(r["eft"] == "allow" for r in matched):
            return True
        return False
    # priority
    if matched:
        return matched[0]["eft"] == "allow"
    return False


def evaluate(model, agent, tool, action):
    """Full evaluation: ``{"decision", "matched_rows", "error"}``.

    ``decision`` is bool. ``matched_rows`` are the public row records whose
    matcher held, in policy order (empty on default-deny). ``error`` is
    None, or ``casbin-enforce-error-fail-closed`` when a matcher or
    request-shape problem failed the whole enforcement closed to deny.
    Never raises on authorization input; malformed *model* use (non-dict)
    is a programming error and raises TypeError.
    """
    request = {"agent": agent, "tool": tool, "action": action}
    if not all(isinstance(v, str) for v in request.values()):
        return {"decision": False, "matched_rows": [],
                "error": ENFORCE_ERROR_CODE}
    matched = []
    try:
        for row in model["policy"]:
            verdict = _eval(model["matcher_ast"], request, row, model["roles"],
                            model["regex_cache"])
            # The matcher is a boolean expression: a non-boolean top-level
            # value (e.g. `m = r.tool`) is a malformed policy, not a match.
            if not isinstance(verdict, bool):
                raise _MatchError("matcher did not evaluate to a boolean")
            if verdict:
                matched.append(_public_row(row))
    except (_MatchError, RecursionError):
        # RecursionError at eval time (pathologically deep role-free
        # expression): fail the whole enforcement closed, never raise.
        return {"decision": False, "matched_rows": [],
                "error": ENFORCE_ERROR_CODE}
    return {"decision": _combine(model["effect"], matched),
            "matched_rows": matched, "error": None}


def enforce(model, agent, tool, action):
    """Pure allow/deny. Errors fail closed to deny."""
    return evaluate(model, agent, tool, action)["decision"]


def enforce_ex(model, agent, tool, action):
    """Explain API: ``(decision, matched_rows)``.

    ``matched_rows`` names the rule rows that decided, so every denied
    tool call can say which rule denied it.
    """
    result = evaluate(model, agent, tool, action)
    return result["decision"], result["matched_rows"]


def batch_enforce(model, requests):
    """Authorize N planned tool calls in one pass.

    ``requests`` is an iterable of ``(agent, tool, action)`` triples;
    returns the decision list in order. A malformed triple is a
    programming error and raises ValueError (fail-fast, never a silent
    mis-authorization).
    """
    decisions = []
    for req in requests:
        # A str is iterable and would unpack into chars: reject it (and
        # bytes) explicitly so a malformed triple can never silently
        # mis-authorize as a fail-fast contract violation (S4).
        if isinstance(req, (str, bytes)) or not isinstance(req, (tuple, list)):
            raise ValueError(
                "each batch request must be an (agent, tool, action) "
                "triple, got %r" % (req,))
        try:
            agent, tool, action = req
        except (TypeError, ValueError):
            raise ValueError(
                "each batch request must be an (agent, tool, action) "
                "triple, got %r" % (req,))
        decisions.append(enforce(model, agent, tool, action))
    return decisions


# ---------------------------------------------------------------------------
# Evidence: row digests -> decision packet; audit-log records.
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def row_digest(row):
    """sha256 over the canonical matched-row record (third-party recomputable)."""
    return hashlib.sha256(_canonical(row)).hexdigest()


def policy_bundle_digest(model):
    """sha256 over the exact CONF bytes the model was compiled from."""
    return hashlib.sha256(model["conf_bytes"]).hexdigest()


def packet_evidence(result):
    """Digest-bound matched-row evidence for the decision packet.

    Takes the ``evaluate`` result dict; returns the row records that feed
    ``decision_packet.build(..., matched_rules=...)`` -- each carrying its
    row id, its recomputable digest, and its effect. On an errored
    evaluation the evidence is empty (fail-closed decisions carry no
    matched-row claims).
    """
    if result.get("error"):
        return []
    return [{"row_id": r["row_id"], "row_digest": row_digest(r),
             "eft": r["eft"]} for r in result["matched_rows"]]


def packet_decision_code(result):
    """The packet decision_code for this evaluation, or None.

    Only an errored (fail-closed) evaluation carries a code; clean
    allow/deny decisions are evidence-complete via matched_rows.
    """
    return result.get("error")


def record_decision(log, model, agent, tool, action, result):
    """Chain a casbin-decision record into the HMAC audit log at decision time.

    Never batched later: the record lands when the decision is made. A
    write failure propagates -- the decision is then not evidenced and the
    caller must not treat it as made (the log's own fail-closed contract).
    """
    record = {
        "record_type": _RECORD_TYPE,
        "agent": agent,
        "tool": tool,
        "action": action,
        "decision": "allow" if result["decision"] else "deny",
        "matched_row_digests": [row_digest(r) for r in result["matched_rows"]],
        "policy_bundle_digest": policy_bundle_digest(model),
        "error": result.get("error"),
    }
    record["record_digest"] = hashlib.sha256(_canonical(record)).hexdigest()
    return log.append(record)
