"""Nuclei-pattern attack-manifest DSL: templates, selection, and trust.

Mechanism provenance: projectdiscovery/nuclei (MIT -- LICENSE.md
bytes verified by the wave-283 prospecting lane; Copyright (c)
ProjectDiscovery, Inc.). This is a clean-room stdlib-only
reimplementation of four nuclei MECHANISMS only -- no nuclei code,
docs, or prose are vendored here:

1. the template skeleton: ``id`` + ``info`` block (name, author,
   severity, description, reference, tags, metadata) + typed
   ``matchers`` + typed ``extractors``;
2. the fixed 5-level severity taxonomy
   (info/low/medium/high/critical);
3. the ``-tc`` selection grammar (field comparisons over id, name,
   severity, author, tags, matcher/extractor types, and metadata keys,
   with ``&&`` / ``||`` / ``!`` composition);
4. the unsigned-template verification posture: templates are
   untrusted-by-default declarations; an unsigned template runs only
   against isolated fixtures unless the caller records an explicit
   loud opt-out (nuclei's ``-nmhe`` analog), and signed templates bind
   id+version+content-digest under Ed25519 (``gov.ed25519``).

Deliberately NOT stolen: the active network-probing engine (out of
scope -- this module evaluates declarative templates against recorded
trajectory segments, never probes a live target), the ``-ai`` flag
(paid cloud key), and community-template execution (third-party
templates are inert declarations here, never code).

Composition, not duplication: templates evaluate against trajectory
segments whose observations live in the wave-281 attack ledger
(``gov.attack_ledger``); ``bind_template_run`` records a template run
as a ledger piece + score with full referential integrity instead of
inventing a second evidence store, and ``templates_from_atomics``
derives a selectable template population from the wave-283 campaign
planners' atomic registries (the template-source direction).
Atomic-execution chaining stays in ``gov.campaign``.

$0: stdlib-only, no network, no randomness (signing keys are
caller-supplied; ``gov.ed25519.generate_seed`` is the caller's
business).

Determinism: template validation, matching, selection, and run
records are fully deterministic. Only Ed25519 key generation (done
by the caller) involves randomness.
"""

import hashlib
import json
import re

from gov import ed25519 as _ed

#: The pinned 5-level severity taxonomy (the nuclei contract). A tuple
#: so order is part of the pin.
SEVERITIES = ("info", "low", "medium", "high", "critical")

SCHEMA_VERSION = "1.0"

#: Trust targets. "isolated" = synthetic fixtures; "production" = any
#: target whose compromise matters (real agent trajectories, the live
#: ledger, deployment evidence).
TARGETS = ("isolated", "production")

#: Template id shape (nuclei ids are lowercase slug-ish).
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_MATCHER_TYPES = ("word", "regex", "binary", "dsl")
_EXTRACTOR_TYPES = ("regex", "kval", "dsl")
_MATCHER_CONDITIONS = ("and", "or")

# ---------------------------------------------------------------------------
# Coded refusals. The machine codes are registered in
# gov/decision_codes.py (domain "manifest"); the class-level ``code``
# attributes keep the taxonomy inventory (item 1) honest.
# ---------------------------------------------------------------------------


class ManifestError(ValueError):
    """Base for attack-manifest refusals. Every refusal carries a
    machine-readable ``code`` (repo convention: callers branch on
    ``code``, never on message text)."""


class TemplateMalformed(ManifestError):
    """A template failed schema validation. Fail-closed at load."""

    code = "manifest-template-malformed"


class TemplateUnsigned(ManifestError):
    """An unsigned template was aimed at a production trust target
    without a recorded explicit opt-out. Fail-closed."""

    code = "manifest-template-unsigned"


class SelectionInvalid(ManifestError):
    """A -tc selection expression failed to parse or named an unknown
    field. Fail-closed."""

    code = "manifest-selection-invalid"


class RegexUnsafe(ManifestError):
    """A matcher/extractor regex was refused at load: static analysis
    found nested-quantifier ambiguity (a ReDoS shape). Fail-closed at
    load -- the pattern never reaches the matching engine."""

    code = "manifest-regex-unsafe"


class SignatureInvalid(ManifestError):
    """An Ed25519 template signature failed verification (tamper or
    wrong key). Fail-closed."""

    code = "manifest-signature-invalid"


# ---------------------------------------------------------------------------
# Closed-vocabulary DSL (matcher + extractor expressions).
#
# Grammar (hand-written tokenizer + recursive descent; no eval()):
#
#   expr    := or_expr
#   or_expr := and_expr ("||" and_expr)*
#   and_expr:= unary ("&&" unary)*
#   unary   := "!" unary | primary
#   primary := "(" expr ")"
#            | "contains" "(" string ")"
#            | "len" "(" "observation" ")"
#            | operand (cmp_op operand)?
#   operand := "len" "(" "observation" ")" | "verdict" | "segment_id"
#            | string | integer
#   cmp_op  := "==" | "!=" | ">" | ">=" | "<" | "<="
#
# ``len(observation)`` is the BYTE length of the raw observation.
# Evaluation context: observation (decoded text), observation_bytes,
# verdict, segment_id. Type mismatches evaluate to False (fail-closed:
# a matcher that cannot decide does not fire).
# ---------------------------------------------------------------------------

_DSL_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<str>"(?:[^"\\]|\\["\\])*")
  | (?P<num>\d+)
  | (?P<op>&&|\|\||==|!=|>=|<=|>|<|!|\(|\)|,)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
""", re.VERBOSE)


def _dsl_tokenize(expr):
    toks = []
    pos = 0
    while pos < len(expr):
        m = _DSL_TOKEN_RE.match(expr, pos)
        if not m:
            raise TemplateMalformed(
                "dsl: cannot tokenize at %r" % (expr[pos:pos + 12],))
        pos = m.end()
        kind = m.lastgroup
        if kind == "ws":
            continue
        toks.append((kind, m.group()))
    return toks


# Maximum nesting depth for the hand-written parsers. Pathological
# nesting must surface as the coded malformed/selection refusal,
# never as an uncaught RecursionError (a template that cannot parse
# at load is malformed -- a crash is not a refusal).
_MAX_NEST_DEPTH = 64


class _DslParser(object):
    def __init__(self, toks):
        self._toks = toks
        self._pos = 0
        self._depth = 0

    def _nested(self):
        self._depth += 1
        if self._depth > _MAX_NEST_DEPTH:
            raise TemplateMalformed("dsl: expression nested too deeply")

    def _peek(self):
        return self._toks[self._pos] if self._pos < len(self._toks) else (None, None)

    def _next(self):
        tok = self._peek()
        if tok[0] is None:
            raise TemplateMalformed("dsl: unexpected end of expression")
        self._pos += 1
        return tok

    def _expect_op(self, want):
        kind, val = self._next()
        if kind != "op" or val != want:
            raise TemplateMalformed(
                "dsl: expected %r, got %r" % (want, val))
        return val

    def parse(self):
        node = self._parse_or()
        if self._peek()[0] is not None:
            raise TemplateMalformed(
                "dsl: trailing tokens %r" % (self._toks[self._pos:],))
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
            self._nested()
            try:
                return ("not", self._parse_unary())
            finally:
                self._depth -= 1
        return self._parse_primary()

    def _parse_primary(self):
        kind, val = self._peek()
        if (kind, val) == ("op", "("):
            self._next()
            self._nested()
            try:
                node = self._parse_or()
            finally:
                self._depth -= 1
            self._expect_op(")")
            return node
        if kind == "ident" and val == "contains":
            self._next()
            self._expect_op("(")
            skind, sval = self._next()
            if skind != "str":
                raise TemplateMalformed(
                    "dsl: contains() needs a string literal")
            self._expect_op(")")
            return ("contains", _dsl_unquote(sval))
        operand = self._parse_operand()
        kind2, val2 = self._peek()
        if kind2 == "op" and val2 in ("==", "!=", ">", ">=", "<", "<="):
            self._next()
            rhs = self._parse_operand()
            return ("cmp", val2, operand, rhs)
        # A bare operand is truthy only if it is a boolean call result;
        # anything else is a shape error (no silent truthiness).
        if operand[0] == "contains":
            return operand
        raise TemplateMalformed(
            "dsl: bare operand %r is not a boolean expression"
            % (operand,))

    def _parse_operand(self):
        kind, val = self._next()
        if kind == "ident" and val == "len":
            self._expect_op("(")
            ikind, ival = self._next()
            if ikind != "ident" or ival != "observation":
                raise TemplateMalformed(
                    "dsl: len() only applies to observation")
            self._expect_op(")")
            return ("len-observation",)
        if kind == "ident" and val in ("verdict", "segment_id"):
            return ("var", val)
        if kind == "str":
            return ("lit", _dsl_unquote(val))
        if kind == "num":
            return ("lit", int(val))
        if kind == "ident" and val == "contains":
            # contains() used as an operand inside a comparison is a
            # shape error -- contains() is boolean, not comparable.
            raise TemplateMalformed(
                "dsl: contains() is boolean, not a comparison operand")
        raise TemplateMalformed("dsl: bad operand %r" % (val,))


def _dsl_unquote(sval):
    inner = sval[1:-1]
    out = []
    i = 0
    while i < len(inner):
        c = inner[i]
        if c == "\\" and i + 1 < len(inner) and inner[i + 1] in ('"', "\\"):
            out.append(inner[i + 1])
            i += 2
        elif c == "\\":
            raise TemplateMalformed("dsl: bad escape in string literal")
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _parse_dsl(expr):
    if not isinstance(expr, str) or not expr.strip():
        raise TemplateMalformed("dsl: expression must be a non-empty string")
    return _DslParser(_dsl_tokenize(expr)).parse()


def _eval_dsl(node, ctx):
    """Evaluate a parsed DSL node. Returns a Python value; any type
    error inside yields False at the boolean level (fail-closed)."""
    tag = node[0]
    if tag == "or":
        return bool(_eval_dsl(node[1], ctx)) or bool(_eval_dsl(node[2], ctx))
    if tag == "and":
        return bool(_eval_dsl(node[1], ctx)) and bool(_eval_dsl(node[2], ctx))
    if tag == "not":
        return not bool(_eval_dsl(node[1], ctx))
    if tag == "contains":
        return node[1] in ctx["observation"]
    if tag == "len-observation":
        return len(ctx["observation_bytes"])
    if tag == "var":
        return ctx[node[1]]
    if tag == "lit":
        return node[1]
    if tag == "cmp":
        _, op, left, right = node
        lv = _eval_dsl(left, ctx)
        rv = _eval_dsl(right, ctx)
        try:
            if op == "==":
                return lv == rv and type(lv) is type(rv)
            if op == "!=":
                return not (lv == rv and type(lv) is type(rv))
            if not isinstance(lv, int) or not isinstance(rv, int):
                return False
            if op == ">":
                return lv > rv
            if op == ">=":
                return lv >= rv
            if op == "<":
                return lv < rv
            if op == "<=":
                return lv <= rv
        except TypeError:
            return False
    return False


# ---------------------------------------------------------------------------
# Regex safety gate (F325). Load-time refusal of backtracking-prone
# patterns.
#
# Maximum group-nesting depth for the pattern parser, mirroring the
# DSL parser's _MAX_NEST_DEPTH: deeper nesting is refused with the
# coded RegexUnsafe error rather than risking an uncaught
# RecursionError.
_RX_MAX_NEST = 64
# ``re.compile`` accepts any syntactically valid pattern, including
# nested-quantifier shapes like ``^(a+)+$`` whose backtracking is
# exponential in the input length (17.34 s on 29 bytes, ~1.85x/byte).
# Unsigned templates run freely at target="isolated", so the attacker
# model is real and availability of the template-evaluation worker is
# at stake. This gate parses each regex into a small AST and refuses
# -- with the coded manifest-regex-unsafe refusal -- any pattern
# where a repetition is applied to a nullable, ambiguous, or
# self-overlapping operand:
#
#   * nullable operand: ``(a*)*`` -- empty iterations repartition.
#   * ambiguous operand: ``(a|a)+`` -- the operand itself matches one
#     string two ways.
#   * self-overlapping operand: ``(a+)+`` -- the operand matches
#     strings of different lengths whose cut points overlap
#     (mid(X) ∩ first(X) != {}), so X·X repartitions; fixed-length
#     operands (``(\d{4})+``) are exempt because their iteration
#     boundaries are forced.
#
# The analysis is deliberately conservative (True-biased): exotic but
# safe shapes such as ``(a|ab)+`` or ``(ab|ac)+`` are refused too. The
# module docstring tells template authors to restructure (flatten the
# nesting or pin the repetition); a refused pattern is a loud,
# actionable load-time error, never a silent behavior change. What the
# gate does NOT do: bound run-time matching (patterns that pass the
# gate are at most polynomial in the input length, which the isolated
# target's fixture sizes already bound).
#
# Nodes: ("lit", ch) | ("any",) | ("class", frozenset) | ("eps",) |
# ("opaque",) | ("look", inner) | ("seq", [...]) | ("alt", [...]) |
# ("rep", node, lo, hi) with hi=None for unbounded. Character sets use
# None as the ANY sentinel (".", \D, \S, \W, [^...]).
# ---------------------------------------------------------------------------

_RX_SIMPLE_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v",
    "a": "\a", "0": "\0",
}
_RX_DIGITS = frozenset("0123456789")
_RX_SPACE = frozenset(" \t\n\r\f\v")
_RX_WORD = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


class _RegexParser(object):
    """Minimal regex parser: just enough of the pattern language to
    find repetition-over-ambiguous-operand shapes. The pattern already
    passed re.compile, so malformed input cannot arrive here."""

    def __init__(self, pattern):
        self.s = pattern
        self.n = len(pattern)
        self.pos = 0
        self._depth = 0

    def parse(self):
        node = self._alt()
        # re.compile accepted the pattern, so the whole string parses.
        return node

    def _peek(self):
        return self.s[self.pos] if self.pos < self.n else ""

    def _alt(self):
        branches = [self._seq()]
        while self._peek() == "|":
            self.pos += 1
            branches.append(self._seq())
        return branches[0] if len(branches) == 1 else ("alt", branches)

    def _seq(self):
        items = []
        while self.pos < self.n and self._peek() not in "|)":
            items.append(self._quant())
        if not items:
            return ("eps",)
        return items[0] if len(items) == 1 else ("seq", items)

    def _quant(self):
        node = self._atom()
        c = self._peek()
        if c == "*":
            lo, hi = 0, None
            self.pos += 1
        elif c == "+":
            lo, hi = 1, None
            self.pos += 1
        elif c == "?":
            lo, hi = 0, 1
            self.pos += 1
        elif c == "{":
            m = re.match(r"\{(\d+)(?:,(\d*)?)?\}", self.s[self.pos:])
            if not m:
                return node  # a literal brace, not a quantifier
            self.pos += m.end()
            lo = int(m.group(1))
            if "," not in m.group(0):
                hi = lo
            elif m.group(2):
                hi = int(m.group(2))
            else:
                hi = None
        else:
            return node
        if self._peek() in "?+":
            # Lazy "?" or possessive "+" (3.11+): neither changes the
            # worst-case shape materially; consume and ignore.
            self.pos += 1
        return ("rep", node, lo, hi)

    def _atom(self):
        c = self._peek()
        if c == "(":
            return self._group()
        if c == "[":
            return self._class()
        if c == ".":
            self.pos += 1
            return ("any",)
        if c == "\\":
            return self._escape()
        if c in "^$":
            self.pos += 1
            return ("eps",)
        self.pos += 1
        return ("lit", c)

    def _expect(self, want):
        if self._peek() != want:
            # Unreachable for re.compile-accepted patterns; fail
            # closed rather than mis-parse.
            raise RegexUnsafe("regex: unexpected %r, wanted %r"
                              % (self._peek(), want))
        self.pos += 1

    def _group(self):
        # Depth-capped like the DSL parser's _MAX_NEST_DEPTH: a
        # pattern that nests too deeply is refused with the coded
        # RegexUnsafe error, never an uncaught RecursionError (the
        # re module itself accepts deeper nesting than this parser
        # can recurse).
        self._depth += 1
        if self._depth > _RX_MAX_NEST:
            raise RegexUnsafe("regex: groups nested too deeply")
        try:
            return self._group_inner()
        finally:
            self._depth -= 1

    def _group_inner(self):
        self.pos += 1  # (
        if self._peek() == "?":
            self.pos += 1
            c = self._peek()
            if c == ":":
                self.pos += 1
                node = self._alt()
                self._expect(")")
                return node
            if c == "P":
                self.pos += 1
                if self._peek() == "<":
                    self.pos += 1
                    while self._peek() != ">":
                        self.pos += 1
                    self.pos += 1
                    node = self._alt()
                    self._expect(")")
                    return node
                # (?P=name): a backreference -- opaque.
                while self._peek() != ")":
                    self.pos += 1
                self.pos += 1
                return ("opaque",)
            if c in "=!":
                # (?=...) / (?!...): zero-width; the walk still
                # descends into the body for nested repeats.
                self.pos += 1
                inner = self._alt()
                self._expect(")")
                return ("look", inner)
            if c == "<":
                # (?<=...) / (?<!...)
                self.pos += 1
                self._expect(self._peek())  # = or !
                inner = self._alt()
                self._expect(")")
                return ("look", inner)
            # (?i), (?i-m), (?i:...) -- flag groups.
            while self._peek() not in ":)":
                self.pos += 1
            if self._peek() == ":":
                self.pos += 1
                node = self._alt()
                self._expect(")")
                return node
            self.pos += 1
            return ("eps",)
        node = self._alt()
        self._expect(")")
        return node

    def _escape(self):
        self.pos += 1  # \
        e = self._peek()
        self.pos += 1
        if e == "d":
            return ("class", _RX_DIGITS)
        if e == "s":
            return ("class", _RX_SPACE)
        if e == "w":
            return ("class", _RX_WORD)
        if e in "DSW":
            return ("any",)
        if e in "bB":
            return ("eps",)  # word boundary (outside classes)
        if e in "AZ":
            return ("eps",)
        if e.isdigit():
            return ("opaque",)  # backreference
        if e in _RX_SIMPLE_ESCAPES:
            return ("lit", _RX_SIMPLE_ESCAPES[e])
        return ("lit", e)  # escaped punctuation

    def _class(self):
        self.pos += 1  # [
        if self._peek() == "^":
            # A negated class matches (almost) anything: ANY.
            while self._peek() != "]":
                self.pos += 1
            self.pos += 1
            return ("any",)
        chars = set()
        first = True
        while True:
            c = self._peek()
            if c == "]" and not first:
                self.pos += 1
                break
            first = False
            if c == "\\":
                self.pos += 1
                e = self._peek()
                self.pos += 1
                if e == "d":
                    chars |= _RX_DIGITS
                elif e == "s":
                    chars |= _RX_SPACE
                elif e == "w":
                    chars |= _RX_WORD
                elif e in "DSW":
                    return ("any",)
                elif e in _RX_SIMPLE_ESCAPES:
                    chars.add(_RX_SIMPLE_ESCAPES[e])
                else:
                    chars.add(e)
                continue
            self.pos += 1
            nxt = self.s[self.pos:self.pos + 2]
            if nxt.startswith("-") and len(nxt) == 2 and nxt[1] != "]":
                self.pos += 1
                d = self._peek()
                self.pos += 1
                for o in range(ord(c), ord(d) + 1):
                    chars.add(chr(o))
            else:
                chars.add(c)
        return ("class", frozenset(chars))


def _rx_overlap(a, b):
    """Do two first/mid sets share a character? None (ANY) overlaps
    everything -- True-biased."""
    if a is None or b is None:
        return True
    return not a.isdisjoint(b)


def _rx_nullable(n):
    t = n[0]
    if t in ("lit", "any", "class"):
        return False
    if t in ("eps", "look", "opaque"):
        return True
    if t == "seq":
        return all(_rx_nullable(c) for c in n[1])
    if t == "alt":
        return any(_rx_nullable(c) for c in n[1])
    if t == "rep":
        return n[2] == 0 or _rx_nullable(n[1])
    raise AssertionError("bad regex node %r" % (t,))  # pragma: no cover


def _rx_first(n):
    """Possible first characters (None = ANY)."""
    t = n[0]
    if t == "lit":
        return frozenset([n[1]])
    if t in ("any", "opaque"):
        return None
    if t == "class":
        return n[1]
    if t in ("eps", "look"):
        return frozenset()
    if t == "seq":
        out = set()
        for c in n[1]:
            f = _rx_first(c)
            if f is None:
                return None
            out |= f
            if not _rx_nullable(c):
                break
        return frozenset(out)
    if t == "alt":
        out = set()
        for c in n[1]:
            f = _rx_first(c)
            if f is None:
                return None
            out |= f
        return frozenset(out)
    if t == "rep":
        return _rx_first(n[1])
    raise AssertionError("bad regex node %r" % (t,))  # pragma: no cover


def _rx_minlen(n):
    t = n[0]
    if t in ("lit", "any", "class"):
        return 1
    if t in ("eps", "look", "opaque"):
        return 0
    if t == "seq":
        return sum(_rx_minlen(c) for c in n[1])
    if t == "alt":
        return min(_rx_minlen(c) for c in n[1])
    if t == "rep":
        return n[2] * _rx_minlen(n[1])
    raise AssertionError("bad regex node %r" % (t,))  # pragma: no cover


def _rx_maxlen(n):
    """None = unbounded."""
    t = n[0]
    if t in ("lit", "any", "class"):
        return 1
    if t in ("eps", "look"):
        return 0
    if t == "opaque":
        return None
    if t == "seq":
        total = 0
        for c in n[1]:
            m = _rx_maxlen(c)
            if m is None:
                return None
            total += m
        return total
    if t == "alt":
        ms = [_rx_maxlen(c) for c in n[1]]
        return None if any(m is None for m in ms) else max(ms)
    if t == "rep":
        _, x, lo, hi = n
        if hi == 0:
            return 0
        m = _rx_maxlen(x)
        if hi is None or m is None:
            return None
        return hi * m
    raise AssertionError("bad regex node %r" % (t,))  # pragma: no cover


def _rx_fixed_len(n):
    mn, mx = _rx_minlen(n), _rx_maxlen(n)
    return mx is not None and mn == mx


def _rx_can_nonempty(n):
    m = _rx_maxlen(n)
    return m is None or m >= 1


def _rx_mid(n):
    """Characters that can appear at match position >= 1 (None = ANY).
    The repartition detector: a repeated operand X is dangerous when
    mid(X) overlaps first(X)."""
    t = n[0]
    if t in ("lit", "any", "class", "eps", "look"):
        return frozenset()
    if t == "opaque":
        return None
    if t == "alt":
        out = set()
        for c in n[1]:
            m = _rx_mid(c)
            if m is None:
                return None
            out |= m
        return frozenset(out)
    if t == "seq":
        cs = n[1]
        out = set()
        for i, c in enumerate(cs):
            m = _rx_mid(c)
            if m is None:
                return None
            out |= m
            if i + 1 < len(cs) and any(_rx_can_nonempty(p)
                                      for p in cs[:i + 1]):
                f = _rx_first(cs[i + 1])
                if f is None:
                    return None
                out |= f
        return frozenset(out)
    if t == "rep":
        _, x, lo, hi = n
        m = _rx_mid(x)
        if m is None:
            return None
        out = set(m)
        if hi is None or hi >= 2:
            f = _rx_first(x)
            if f is None:
                return None
            out |= f
        return frozenset(out)
    raise AssertionError("bad regex node %r" % (t,))  # pragma: no cover


def _rx_branch_overlap(a, b):
    """Can two alternation branches match a common string?
    True-biased over-approximation."""
    if _rx_nullable(a) and _rx_nullable(b):
        return True
    if not _rx_overlap(_rx_first(a), _rx_first(b)):
        return False
    if _rx_fixed_len(a) and _rx_fixed_len(b):
        return _rx_minlen(a) == _rx_minlen(b)
    return True


def _rx_repeat_dangerous(x):
    """Is repeating x (>= 2 iterations possible) backtracking-prone?"""
    if _rx_nullable(x):
        # (a*)* -- empty iterations repartition arbitrarily.
        return True
    if _rx_ambiguous(x):
        return True
    if _rx_fixed_len(x):
        # Fixed-length iterations have forced boundaries: linear.
        return False
    # Variable-length operand whose cut points overlap its starts:
    # X.X repartitions (the (a+)+ shape).
    return _rx_overlap(_rx_mid(x), _rx_first(x))


def _rx_ambiguous(n):
    t = n[0]
    if t in ("lit", "any", "class", "eps"):
        return False
    if t == "opaque":
        return True
    if t == "look":
        return _rx_ambiguous(n[1])
    if t == "alt":
        bs = n[1]
        if any(_rx_ambiguous(b) for b in bs):
            return True
        if sum(1 for b in bs if _rx_nullable(b)) >= 2:
            return True
        for i in range(len(bs)):
            for j in range(i + 1, len(bs)):
                if _rx_branch_overlap(bs[i], bs[j]):
                    return True
        return False
    if t == "seq":
        cs = n[1]
        if any(_rx_ambiguous(c) for c in cs):
            return True
        for i in range(len(cs) - 1):
            a, b = cs[i], cs[i + 1]
            if not _rx_can_nonempty(b):
                continue
            if _rx_nullable(a) and _rx_overlap(_rx_first(a),
                                              _rx_first(b)):
                # (a*)(a*): the empty match shifts the boundary.
                return True
            if (not _rx_fixed_len(a) and not _rx_fixed_len(b)
                    and _rx_overlap(_rx_mid(a), _rx_first(b))):
                # a+a: the boundary between a+ and a repartitions.
                return True
        return False
    if t == "rep":
        _, x, lo, hi = n
        if hi == 0:
            return False
        if hi == 1:
            # "?" / "{1}": no repetition, ambiguity of the operand.
            return _rx_ambiguous(x)
        return _rx_repeat_dangerous(x)
    raise AssertionError("bad regex node %r" % (t,))  # pragma: no cover


def _rx_check(n):
    """Walk the pattern AST; raise RegexUnsafe on the first
    backtracking-prone repetition."""
    t = n[0]
    if t == "rep":
        _, x, lo, hi = n
        _rx_check(x)
        if hi == 0 or hi == 1:
            return
        if _rx_repeat_dangerous(x):
            raise RegexUnsafe(
                "regex has a backtracking-prone repetition "
                "(nested/overlapping quantifiers): restructure the "
                "pattern (flatten the nesting or pin the repetition)")
        return
    if t in ("seq", "alt"):
        for c in n[1]:
            _rx_check(c)
    elif t == "look":
        _rx_check(n[1])
    # Leaves ("lit", "any", "class", "eps", "opaque") carry nothing.


def _check_regex_safety(pattern, where):
    """Parse ``pattern`` and refuse backtracking-prone shapes with the
    coded manifest-regex-unsafe refusal. Called at load, after the
    re.compile syntax check."""
    try:
        _rx_check(_RegexParser(pattern).parse())
    except RegexUnsafe as e:
        raise RegexUnsafe("%s: pattern %r refused: %s" % (where, pattern, e))


def check_regex_safety(pattern, where):
    """Public seam for the backtracking-safety gate (F325 mechanism).

    Other modules route caller-triggerable regexes through this instead
    of duplicating the analysis (F339: ``gov/tool_call_policy.py``).
    Raises :class:`RegexUnsafe` (a coded manifest-regex-unsafe
    ManifestError); callers translate it to their own coded refusal --
    never let it escape raw across module seams.
    """
    return _check_regex_safety(pattern, where)


# ---------------------------------------------------------------------------
# Template validation + normalization
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _require_str_list(value, what):
    if (not isinstance(value, list) or not value
            or any(not isinstance(v, str) for v in value)):
        raise TemplateMalformed("%s must be a non-empty list of str"
                                % (what,))
    return list(value)


def _validate_matcher(m, index):
    if not isinstance(m, dict):
        raise TemplateMalformed("matcher %d must be a dict" % (index,))
    mtype = m.get("type")
    if mtype not in _MATCHER_TYPES:
        raise TemplateMalformed(
            "matcher %d: unknown type %r (expected one of %s)"
            % (index, mtype, "/".join(_MATCHER_TYPES)))
    out = {"type": mtype}
    negative = m.get("negative", False)
    if not isinstance(negative, bool):
        raise TemplateMalformed("matcher %d: negative must be bool"
                                % (index,))
    out["negative"] = negative
    part = m.get("part", "observation")
    if part not in ("observation", "segment_id"):
        raise TemplateMalformed("matcher %d: unknown part %r" % (index, part))
    out["part"] = part
    if mtype == "word":
        out["words"] = _require_str_list(m.get("words"),
                                         "matcher %d words" % (index,))
        if any(not w for w in out["words"]):
            raise TemplateMalformed("matcher %d: empty word" % (index,))
        ci = m.get("case-insensitive", False)
        if not isinstance(ci, bool):
            raise TemplateMalformed(
                "matcher %d: case-insensitive must be bool" % (index,))
        out["case-insensitive"] = ci
    elif mtype == "regex":
        pattern = m.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise TemplateMalformed("matcher %d: regex needs a pattern"
                                    % (index,))
        try:
            re.compile(pattern)
        except re.error as e:
            raise TemplateMalformed("matcher %d: bad regex: %s"
                                    % (index, e))
        # F325: a compilable pattern can still be exponentially slow
        # (nested quantifiers). Refuse the ReDoS shape at load.
        _check_regex_safety(pattern, "matcher %d" % (index,))
        out["pattern"] = pattern
    elif mtype == "binary":
        sig = m.get("signature")
        if not isinstance(sig, str) or len(sig) % 2 or not sig:
            raise TemplateMalformed(
                "matcher %d: binary signature must be non-empty even-length "
                "hex" % (index,))
        try:
            bytes.fromhex(sig)
        except ValueError:
            raise TemplateMalformed(
                "matcher %d: binary signature is not hex" % (index,))
        out["signature"] = sig.lower()
        offset = m.get("offset")
        if offset is not None:
            if (not isinstance(offset, int) or isinstance(offset, bool)
                    or offset < 0):
                raise TemplateMalformed(
                    "matcher %d: offset must be a non-negative int"
                    % (index,))
            out["offset"] = offset
    elif mtype == "dsl":
        out["expr"] = m.get("expr")
        # Parse now: a template whose dsl cannot parse is malformed at
        # load, never at run. The AST is stashed so run-time
        # evaluation never re-parses.
        out["_ast"] = _parse_dsl(out["expr"])
    return out


def _validate_extractor(e, index):
    if not isinstance(e, dict):
        raise TemplateMalformed("extractor %d must be a dict" % (index,))
    etype = e.get("type")
    if etype not in _EXTRACTOR_TYPES:
        raise TemplateMalformed(
            "extractor %d: unknown type %r (expected one of %s)"
            % (index, etype, "/".join(_EXTRACTOR_TYPES)))
    name = e.get("name")
    if not isinstance(name, str) or not name:
        raise TemplateMalformed("extractor %d: name must be a non-empty "
                                "str" % (index,))
    out = {"type": etype, "name": name}
    if etype == "regex":
        pattern = e.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise TemplateMalformed("extractor %d: regex needs a pattern"
                                    % (index,))
        try:
            compiled = re.compile(pattern)
        except re.error as err:
            raise TemplateMalformed("extractor %d: bad regex: %s"
                                    % (index, err))
        # F325: same ReDoS gate as matchers (finditer is equally
        # exposed to nested-quantifier backtracking).
        _check_regex_safety(pattern, "extractor %d" % (index,))
        group = e.get("group", 0)
        if (not isinstance(group, int) or isinstance(group, bool)
                or group < 0 or group > compiled.groups):
            raise TemplateMalformed(
                "extractor %d: group %r out of range for %d group(s)"
                % (index, group, compiled.groups))
        out["pattern"] = pattern
        out["group"] = group
    elif etype == "kval":
        key = e.get("key")
        if not isinstance(key, str) or not key:
            raise TemplateMalformed("extractor %d: kval needs a key"
                                    % (index,))
        out["key"] = key
    elif etype == "dsl":
        out["expr"] = e.get("expr")
        out["_ast"] = _parse_dsl(out["expr"])
    return out


def _check_jsonable(obj, what):
    try:
        _canonical(obj)
    except (TypeError, ValueError) as e:
        raise TemplateMalformed("%s is not JSON-canonicalizable: %s"
                                % (what, e))


def validate_template(t):
    """Validate a template declaration; return the normalized dict.

    Normalization: defaults filled (matchers-condition "or",
    negative False, extractor group 0), derived ``matcher_types`` /
    ``extractor_types`` lists attached (for the selection grammar),
    and the input is verified JSON-canonicalizable so the template
    digest is stable. Raises TemplateMalformed (code
    manifest-template-malformed) fail-closed.
    """
    if not isinstance(t, dict):
        raise TemplateMalformed("template must be a dict")
    tid = t.get("id")
    if not isinstance(tid, str) or not _ID_RE.match(tid):
        raise TemplateMalformed(
            "template id must match %r" % (_ID_RE.pattern,))
    version = t.get("version")
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        raise TemplateMalformed("template version must be X.Y.Z")
    info = t.get("info")
    if not isinstance(info, dict):
        raise TemplateMalformed("template info must be a dict")
    name = info.get("name")
    if not isinstance(name, str) or not name.strip():
        raise TemplateMalformed("info.name must be a non-empty str")
    author = _require_str_list(info.get("author"), "info.author")
    severity = info.get("severity")
    if severity not in SEVERITIES:
        raise TemplateMalformed(
            "info.severity must be one of %s, got %r"
            % ("/".join(SEVERITIES), severity))
    description = info.get("description")
    if not isinstance(description, str) or not description.strip():
        raise TemplateMalformed("info.description must be a non-empty str")
    reference = info.get("reference", [])
    if (not isinstance(reference, list)
            or any(not isinstance(r, str) for r in reference)):
        raise TemplateMalformed("info.reference must be a list of str")
    tags = _require_str_list(info.get("tags"), "info.tags")
    protocol = info.get("protocol")
    if protocol is not None:
        if not isinstance(protocol, str) or not _ID_RE.match(protocol):
            raise TemplateMalformed(
                "info.protocol must be a lowercase slug like the template id")
    metadata = info.get("metadata", {})
    if not isinstance(metadata, dict):
        raise TemplateMalformed("info.metadata must be a dict")
    for k, v in metadata.items():
        if not isinstance(k, str):
            raise TemplateMalformed("info.metadata keys must be str")
        if not isinstance(v, (str, int, float, bool)):
            # bool is a JSON scalar and is allowed; anything else
            # (lists, dicts, None) would make the digest unstable.
            raise TemplateMalformed(
                "info.metadata values must be JSON scalars")
    cond = t.get("matchers-condition", "or")
    if cond not in _MATCHER_CONDITIONS:
        raise TemplateMalformed("matchers-condition must be and/or")
    matchers = t.get("matchers")
    if not isinstance(matchers, list) or not matchers:
        raise TemplateMalformed("template needs a non-empty matchers list")
    extractors = t.get("extractors", [])
    if not isinstance(extractors, list):
        raise TemplateMalformed("extractors must be a list")
    norm = {
        "id": tid,
        "version": version,
        "info": {
            "name": name,
            "author": author,
            "severity": severity,
            "description": description,
            "reference": list(reference),
            "tags": tags,
            "protocol": protocol,
            "metadata": dict(metadata),
        },
        "matchers-condition": cond,
        "matchers": [_validate_matcher(m, i)
                     for i, m in enumerate(matchers)],
        "extractors": [_validate_extractor(e, i)
                       for i, e in enumerate(extractors)],
    }
    norm["matcher_types"] = sorted({m["type"] for m in norm["matchers"]})
    norm["extractor_types"] = sorted({e["type"]
                                      for e in norm["extractors"]})
    _check_jsonable(norm, "normalized template")
    return norm


def template_digest(template):
    """sha256 over the canonical normalized template (the content
    identity the signature binds)."""
    return hashlib.sha256(_canonical(template).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Matching + extraction
# ---------------------------------------------------------------------------

def _matcher_fires(matcher, segment):
    if matcher["part"] == "observation":
        raw = segment["observation"]
        text = bytes(raw).decode("utf-8", errors="replace")
    else:
        raw = segment["segment_id"].encode("utf-8")
        text = segment["segment_id"]
    mtype = matcher["type"]
    if mtype == "word":
        words = matcher["words"]
        if matcher["case-insensitive"]:
            hay = text.lower()
            hit = any(w.lower() in hay for w in words)
        else:
            hit = any(w in text for w in words)
    elif mtype == "regex":
        hit = re.search(matcher["pattern"], text) is not None
    elif mtype == "binary":
        sig = bytes.fromhex(matcher["signature"])
        data = bytes(raw)
        offset = matcher.get("offset")
        if offset is not None:
            hit = data[offset:offset + len(sig)] == sig
        else:
            hit = sig in data
    elif mtype == "dsl":
        ctx = {
            "observation": text,
            "observation_bytes": bytes(raw),
            "verdict": str(segment.get("verdict", "")),
            "segment_id": str(segment.get("segment_id", "")),
        }
        try:
            # The AST was parsed and depth-capped at load; fall back to
            # a fresh parse only for hand-built matcher dicts that
            # skipped validation (still coded-refusal on failure).
            node = matcher.get("_ast") or _parse_dsl(matcher["expr"])
            hit = bool(_eval_dsl(node, ctx))
        except ManifestError:
            # The expression parsed at load; an eval-time shape error
            # cannot fire (fail-closed at the matcher level).
            hit = False
    else:  # pragma: no cover - validated at load
        hit = False
    return (not hit) if matcher["negative"] else hit


_KVAL_RE_TMPL = r"(?:^|[;\s,])%s=([^\s;,]+)"


def _extractor_values(extractor, segment):
    text = bytes(segment["observation"]).decode("utf-8", errors="replace")
    etype = extractor["type"]
    if etype == "regex":
        return [m.group(extractor["group"])
                for m in re.finditer(extractor["pattern"], text)]
    if etype == "kval":
        pat = _KVAL_RE_TMPL % (re.escape(extractor["key"]),)
        return [m.group(1) for m in re.finditer(pat, text)]
    if etype == "dsl":
        ctx = {"observation": text,
               "observation_bytes": bytes(segment["observation"]),
               "verdict": str(segment.get("verdict", "")),
               "segment_id": str(segment.get("segment_id", ""))}
        try:
            node = extractor.get("_ast") or _parse_dsl(extractor["expr"])
            val = _eval_dsl(node, ctx)
        except ManifestError:
            return []
        if isinstance(val, bool):
            return [str(val)]
        if isinstance(val, (str, int)):
            return [str(val)]
        return []
    return []  # pragma: no cover - validated at load


def _check_segment(segment, index):
    if not isinstance(segment, dict):
        raise TemplateMalformed("segment %d must be a dict" % (index,))
    sid = segment.get("segment_id")
    if not isinstance(sid, str) or not sid:
        raise TemplateMalformed("segment %d needs a segment_id str"
                                % (index,))
    obs = segment.get("observation")
    if not isinstance(obs, (bytes, bytearray)):
        raise TemplateMalformed("segment %d observation must be bytes"
                                % (index,))


# ---------------------------------------------------------------------------
# -tc selection grammar.
#
#   sel    := or_sel
#   or_sel := and_sel ("||" and_sel)*
#   and_sel:= unary ("&&" unary)*
#   unary  := "!" unary | "(" sel ")" | predicate
#   predicate := field ("==" | "!=") string
#              | string "in" field
#
# Fields: id, name, severity (scalars); author, tags, matcher_types,
# extractor_types (lists); metadata.<key> (scalar or absent).
# String literals are single-quoted. Unknown top-level fields or
# malformed expressions refuse with manifest-selection-invalid.
# ---------------------------------------------------------------------------

_SEL_FIELDS_SCALAR = ("id", "name", "severity", "version", "protocol")
_SEL_FIELDS_LIST = ("author", "tags", "matcher_types", "extractor_types")
_SEL_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<str>'(?:[^'\\]|\\['\\])*')
  | (?P<in>\bin\b)
  | (?P<op>&&|\|\||==|!=|!|\(|\))
  | (?P<word>[A-Za-z_][A-Za-z0-9_.]*)
""", re.VERBOSE)


def _sel_tokenize(expr):
    toks = []
    pos = 0
    while pos < len(expr):
        m = _SEL_TOKEN_RE.match(expr, pos)
        if not m:
            raise SelectionInvalid(
                "selection: cannot tokenize at %r" % (expr[pos:pos + 12],))
        pos = m.end()
        kind = m.lastgroup
        if kind == "ws":
            continue
        toks.append((kind, m.group()))
    return toks


def _sel_unquote(sval):
    inner = sval[1:-1]
    out = []
    i = 0
    while i < len(inner):
        c = inner[i]
        if c == "\\" and i + 1 < len(inner) and inner[i + 1] in ("'", "\\"):
            out.append(inner[i + 1])
            i += 2
        elif c == "\\":
            raise SelectionInvalid("selection: bad escape in string")
        else:
            out.append(c)
            i += 1
    return "".join(out)


class _SelParser(object):
    def __init__(self, toks):
        self._toks = toks
        self._pos = 0
        self._depth = 0

    def _nested(self):
        self._depth += 1
        if self._depth > _MAX_NEST_DEPTH:
            raise SelectionInvalid("selection: nested too deeply")

    def _peek(self):
        return self._toks[self._pos] if self._pos < len(self._toks) else (None, None)

    def _next(self):
        tok = self._peek()
        if tok[0] is None:
            raise SelectionInvalid("selection: unexpected end")
        self._pos += 1
        return tok

    def parse(self):
        node = self._parse_or()
        if self._peek()[0] is not None:
            raise SelectionInvalid("selection: trailing tokens")
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
            self._nested()
            try:
                return ("not", self._parse_unary())
            finally:
                self._depth -= 1
        if self._peek() == ("op", "("):
            self._next()
            self._nested()
            try:
                node = self._parse_or()
            finally:
                self._depth -= 1
            kind, val = self._next()
            if (kind, val) != ("op", ")"):
                raise SelectionInvalid("selection: expected )")
            return node
        return self._parse_predicate()

    def _field(self):
        kind, val = self._next()
        if kind != "word":
            raise SelectionInvalid("selection: expected a field name")
        if val in _SEL_FIELDS_SCALAR or val in _SEL_FIELDS_LIST:
            return ("field", val)
        if val == "metadata" or val.startswith("metadata."):
            key = val[len("metadata."):] if val.startswith("metadata.") else None
            if key is None:
                raise SelectionInvalid(
                    "selection: metadata needs a key (metadata.<key>)")
            if not re.match(r"^[A-Za-z0-9_]+$", key):
                raise SelectionInvalid(
                    "selection: bad metadata key %r" % (key,))
            return ("metadata", key)
        raise SelectionInvalid("selection: unknown field %r" % (val,))

    def _parse_predicate(self):
        kind, val = self._peek()
        if kind == "str":
            # 'value' in list_field
            self._next()
            ikind, ival = self._next()
            if ikind != "in":
                raise SelectionInvalid(
                    "selection: expected 'in' after string literal")
            field = self._field()
            if field[0] != "field" or field[1] not in _SEL_FIELDS_LIST:
                raise SelectionInvalid(
                    "selection: 'in' needs a list field")
            return ("in", _sel_unquote(val), field[1])
        field = self._field()
        okind, oval = self._next()
        if okind != "op" or oval not in ("==", "!="):
            raise SelectionInvalid(
                "selection: expected == or != after field")
        skind, sval = self._next()
        if skind != "str":
            raise SelectionInvalid(
                "selection: comparison needs a string literal")
        lit = _sel_unquote(sval)
        if field[0] == "metadata":
            return ("meta-cmp", oval, field[1], lit)
        return ("cmp", oval, field[1], lit)


def _parse_selection(expr):
    if not isinstance(expr, str) or not expr.strip():
        raise SelectionInvalid("selection: expression must be non-empty str")
    return _SelParser(_sel_tokenize(expr)).parse()


def _template_field(template, name):
    if name in ("id", "version"):
        return template[name]
    if name == "name":
        return template["info"]["name"]
    if name == "severity":
        return template["info"]["severity"]
    if name == "protocol":
        # First-class protocol-family field (the -tc `protocol`
        # analog); absent protocol selects as the empty string, so a
        # protocol predicate never silently matches a template that
        # declares none.
        return template["info"].get("protocol") or ""
    if name in ("author", "tags"):
        return list(template["info"][name])
    if name in ("matcher_types", "extractor_types"):
        return list(template[name])
    raise SelectionInvalid("selection: unknown field %r" % (name,))  # pragma: no cover


def _eval_selection(node, template):
    tag = node[0]
    if tag == "or":
        return _eval_selection(node[1], template) or \
            _eval_selection(node[2], template)
    if tag == "and":
        return _eval_selection(node[1], template) and \
            _eval_selection(node[2], template)
    if tag == "not":
        return not _eval_selection(node[1], template)
    if tag == "cmp":
        _, op, field, lit = node
        val = _template_field(template, field)
        if not isinstance(val, str):
            return False
        return (val == lit) if op == "==" else (val != lit)
    if tag == "in":
        _, lit, field = node
        return lit in _template_field(template, field)
    if tag == "meta-cmp":
        _, op, key, lit = node
        meta = template["info"]["metadata"]
        if key is None:
            return False
        val = meta.get(key)
        if not isinstance(val, str):
            return False
        return (val == lit) if op == "==" else (val != lit)
    return False  # pragma: no cover


def select(templates, condition):
    """The -tc analog: return the templates matching ``condition``.

    ``templates`` must already be normalized (validate_template).
    ``condition`` is a selection expression over id, name, severity,
    author, tags, matcher_types, extractor_types, and
    metadata.<key>. Malformed expressions or unknown fields refuse
    with manifest-selection-invalid (fail-closed: never silently
    select everything, never silently select nothing).
    """
    if not isinstance(templates, list):
        raise SelectionInvalid("selection: templates must be a list")
    ast = _parse_selection(condition)
    out = []
    for t in templates:
        if not isinstance(t, dict) or "id" not in t:
            raise SelectionInvalid(
                "selection: templates must be normalized template dicts")
        if _eval_selection(ast, t):
            out.append(t)
    return out


# ---------------------------------------------------------------------------
# Trust: signing, verification, and the unsigned-template posture.
# ---------------------------------------------------------------------------

def sign_template(seed, template):
    """Sign a normalized template with an Ed25519 seed.

    The signed message is the canonical JSON of
    {id, version, content_digest}: the signature binds the template's
    identity, its pinned version, and its exact content. Returns the
    envelope {"template", "signature" (hex), "pubkey" (hex)}.
    """
    norm = validate_template(template)
    msg = _canonical({
        "id": norm["id"],
        "version": norm["version"],
        "content_digest": template_digest(norm),
    }).encode("utf-8")
    sig = _ed.sign(bytes(seed), msg)
    pub = _ed.publickey(bytes(seed))
    return {
        "template": norm,
        "signature": bytes(sig).hex(),
        "pubkey": bytes(pub).hex(),
    }


def verify_signed_template(envelope):
    """Verify a signed template envelope. Returns True; raises
    SignatureInvalid (code manifest-signature-invalid) on ANY failure:
    bad shape, bad hex, digest mismatch, or a False from
    ``gov.ed25519.verify`` (the wave-243 lesson: check the exact
    return, never truthiness).
    """
    if not isinstance(envelope, dict):
        raise SignatureInvalid("envelope must be a dict")
    template = envelope.get("template")
    signature = envelope.get("signature")
    pubkey = envelope.get("pubkey")
    try:
        norm = validate_template(template)
        sig = bytes.fromhex(signature)
        pub = bytes.fromhex(pubkey)
    except (ValueError, TypeError, AttributeError):
        raise SignatureInvalid("envelope has bad shape or bad hex")
    except TemplateMalformed as e:
        raise SignatureInvalid("envelope template malformed: %s" % (e,))
    msg = _canonical({
        "id": norm["id"],
        "version": norm["version"],
        "content_digest": template_digest(norm),
    }).encode("utf-8")
    # Wave-243: verify() returns exact True/False and never raises.
    if _ed.verify(pub, msg, sig) is not True:
        raise SignatureInvalid(
            "Ed25519 verification failed for template %r v%s"
            % (norm["id"], norm["version"]))
    return True


def _check_target(target):
    if target not in TARGETS:
        raise TemplateMalformed(
            "target must be one of %s, got %r" % ("/".join(TARGETS), target))
    return target


def run_template(template, segments, *, target="isolated",
                 allow_unsigned=False, optout_reason=None):
    """Evaluate an (unsigned) template against trajectory segments.

    ``segments``: [{"segment_id": str, "observation": bytes,
    "verdict": str}]. Returns the run record: template identity,
    trust ("unsigned"), target, per-segment fired flags, extracted
    evidence, and the template digest.

    Trust posture (the nuclei unsigned-template rule): an unsigned
    template runs against ``target="isolated"`` freely; against
    ``target="production"`` it refuses LOUD with
    manifest-template-unsigned unless ``allow_unsigned=True`` with a
    non-empty ``optout_reason`` -- and then the opt-out is recorded in
    the run record (never silent, the ``-nmhe`` analog).
    """
    norm = validate_template(template)
    _check_target(target)
    if not isinstance(segments, list):
        raise TemplateMalformed("segments must be a list")
    for i, s in enumerate(segments):
        _check_segment(s, i)
    unsigned_optout = False
    if target == "production" and not allow_unsigned:
        raise TemplateUnsigned(
            "unsigned template %r refused at production target: sign it "
            "or record an explicit opt-out" % (norm["id"],))
    if allow_unsigned:
        if target != "production":
            raise TemplateMalformed(
                "allow_unsigned is only meaningful at the production target")
        if not isinstance(optout_reason, str) or not optout_reason.strip():
            raise TemplateMalformed(
                "allow_unsigned requires a non-empty optout_reason")
        unsigned_optout = True
    return _execute(norm, segments, target, "unsigned",
                    unsigned_optout, optout_reason)


def _execute(norm, segments, target, trust, unsigned_optout, optout_reason):
    """The matcher/extractor evaluation core shared by run_template
    and run_signed_template (the trust decision happens above)."""
    cond = norm["matchers-condition"]
    per_segment = []
    extracted = {}
    any_fired = False
    for s in segments:
        fires = [_matcher_fires(m, s) for m in norm["matchers"]]
        fired = all(fires) if cond == "and" else any(fires)
        any_fired = any_fired or fired
        per_segment.append({"segment_id": s["segment_id"],
                            "fired": fired,
                            "verdict": str(s.get("verdict", ""))})
        if fired:
            for e in norm["extractors"]:
                vals = _extractor_values(e, s)
                if vals:
                    extracted.setdefault(e["name"], []).extend(vals)
    return {
        "schema_version": SCHEMA_VERSION,
        "template_id": norm["id"],
        "template_version": norm["version"],
        "severity": norm["info"]["severity"],
        "trust": trust,
        "target": target,
        "unsigned_optout": unsigned_optout,
        "optout_reason": optout_reason if unsigned_optout else None,
        "template_digest": template_digest(norm),
        "fired": any_fired,
        "per_segment": per_segment,
        "extracted": extracted,
    }


def run_signed_template(envelope, pubkey, segments, *, target="isolated"):
    """Verify a signed envelope, then run it at the given target.

    A valid signature is the trust upgrade: signed templates run at
    the production target with no opt-out. Any verification failure
    refuses LOUD before a single matcher evaluates.
    """
    verify_signed_template(envelope)
    if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
        raise SignatureInvalid("pubkey must be 32 bytes")
    if bytes(pubkey).hex() != envelope["pubkey"]:
        raise SignatureInvalid("envelope pubkey does not match the "
                               "presented pubkey")
    norm = envelope["template"]
    _check_target(target)
    rec = _execute(norm, segments, target, "signed", False, None)
    return rec


def bind_template_run(ledger, template, run_record):
    """Record a template run in the attack ledger (composition).

    The run record becomes a content-addressed ``manifest-run`` piece;
    a score links it with scorer ``manifest:<id>`` and the fired
    verdict. The ledger's referential integrity and hash chain do the
    tamper-evidence work -- this function invents no second store.
    Returns {"piece_id", "score_id"}.
    """
    norm = validate_template(template)
    if not isinstance(run_record, dict) or \
            run_record.get("template_id") != norm["id"]:
        raise TemplateMalformed("run_record does not belong to template %r"
                                % (norm["id"],))
    body = _canonical(run_record).encode("utf-8")
    piece_id = ledger.record_piece("manifest-run", body)
    rationale = "template %s %s (%d/%d segments fired)" % (
        norm["id"], "FIRED" if run_record.get("fired") else "no-fire",
        sum(1 for s in run_record.get("per_segment", []) if s["fired"]),
        len(run_record.get("per_segment", [])))
    score_id = ledger.record_score(piece_id, "manifest:" + norm["id"],
                                   bool(run_record.get("fired")), rationale)
    return {"piece_id": piece_id, "score_id": score_id}


# ---------------------------------------------------------------------------
# Source-side composition: campaign atomics as a template population.
# ---------------------------------------------------------------------------

def _slugify(name):
    slug = re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")
    if not slug or not _ID_RE.match(slug):
        raise TemplateMalformed(
            "atomic name %r does not slugify to a template id" % (name,))
    return slug


def templates_from_atomics(atomics, default_severity="info"):
    """Derive templates from campaign-registered atomic specs.

    The source-side composition with ``gov.campaign`` /
    ``gov.battery_lang`` (the sink side is ``bind_template_run``):
    a campaign's atomic registry becomes a template population the
    ``-tc`` selection grammar can subset, so planners select
    template-declared probes instead of raw atomic dicts.

    Each atomic's break assertion becomes a ``dsl`` matcher on
    ``verdict == "BREAK"`` (the nuclei matchers-as-break-conditions
    mapping). Severity comes from the atomic's declared ``"severity"``
    or ``default_severity``. Every derived template is
    ``validate_template``-checked fail-closed. Atomic specs are
    duck-typed (``name``/``description`` required; ``severity`` /
    ``tags`` optional) so this module does not import
    ``gov.battery_lang``.
    """
    if default_severity not in SEVERITIES:
        raise TemplateMalformed(
            "default_severity must be one of %s" % ("/".join(SEVERITIES),))
    if not isinstance(atomics, list):
        raise TemplateMalformed("atomics must be a list")
    out = []
    for i, atomic in enumerate(atomics):
        if not isinstance(atomic, dict):
            raise TemplateMalformed("atomic %d must be a dict" % (i,))
        name = atomic.get("name")
        if not isinstance(name, str) or not name.strip():
            raise TemplateMalformed("atomic %d needs a name str" % (i,))
        description = atomic.get("description")
        if not isinstance(description, str) or not description.strip():
            raise TemplateMalformed("atomic %d needs a description str"
                                    % (i,))
        severity = atomic.get("severity", default_severity)
        if severity not in SEVERITIES:
            raise TemplateMalformed(
                "atomic %r severity %r not in %s"
                % (name, severity, "/".join(SEVERITIES)))
        extra_tags = atomic.get("tags", [])
        if (not isinstance(extra_tags, list)
                or any(not isinstance(t, str) for t in extra_tags)):
            raise TemplateMalformed("atomic %r tags must be a list of str"
                                    % (name,))
        slug = _slugify(name)
        out.append(validate_template({
            "id": slug,
            "version": "1.0.0",
            "info": {
                "name": name,
                "author": ["campaign-registry"],
                "severity": severity,
                "description": description,
                "reference": [],
                "tags": ["atomic"] + extra_tags,
                "protocol": None,
                "metadata": {"source": "campaign-registry",
                             "atomic": name},
            },
            "matchers": [{"type": "dsl",
                          "expr": 'verdict == "BREAK"'}],
            "extractors": [],
        }))
    return out
