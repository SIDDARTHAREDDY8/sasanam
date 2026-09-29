"""gov.pack_lint: a symcc-style red-team linter for policy packs.

This module ADAPTS Cedar's ``symcc`` acceptance triple (wave-205
prospecting, section 2) to Sasanam's two policy-pack domains:

* safety    -- no vacuously-bypassable policy: no never-matching
  rules, no unreachable branches, no shadowed grants.
* liveness  -- the pack is not trivially-deny-all / never-fires: at
  least one reachable allow path (PERM) or firing rule (detection)
  per pack.
* sanity    -- no self-contradicting rule pairs, no fail-open
  defaults, no uncompilable packs.

Every violation names the offending rule (or pack member) and the
check that fired, in the form ``family/check`` (for example
``safety/shadowed-row``).

HONEST RESIDUAL -- bounded approximation, no SMT solver. Reachability
is decided by a bounded witness search: small candidate inputs are
synthesised from rule/matcher structure and VERIFIED against the real
evaluation engines (``capability_rules.evaluate_module`` /
``evaluate_bundle`` and ``perm_loader``'s matcher evaluator). A rule
with no verified witness is reported unsatisfiable. The search is
deliberately incomplete: exotic regex constructs (backreferences,
lookarounds with data-dependent context), very deep boolean trees,
and matcher expressions outside the supported constraint language
may yield "no witness found" for a rule that is in fact satisfiable.
Such reports are false positives of the linter, not proofs of a
vacuous rule -- the check names and this docstring say so, and the
battery pins the constructs the search DOES cover. Never present a
lint report as a proof; it is a red-team finding aid.

The linter is pure: it never activates, signs, or evaluates anything
with side effects. ``PackLintError`` is raised only for API misuse
(wrong argument types); policy problems are always returned as
violations inside a :class:`LintReport`.
"""

import re

try:
    import sre_parse as _sre_parse
    import sre_constants as _sre_constants
except ImportError:  # pragma: no cover -- stdlib always ships these
    _sre_parse = None
    _sre_constants = None

__all__ = [
    "PackLintError",
    "LintViolation",
    "LintReport",
    "lint_capability_rule_files",
    "lint_perm_pack",
    "require_clean",
]


class PackLintError(Exception):
    """API misuse of the pack linter (wrong types, empty pack, ...)."""


class LintViolation(object):
    """One fired check: the offending rule/member, the check, detail."""

    __slots__ = ("rule", "check", "detail")

    def __init__(self, rule, check, detail):
        if not isinstance(rule, str) or not rule:
            raise PackLintError("violation rule must be a non-empty str")
        if not isinstance(check, str) or not check:
            raise PackLintError("violation check must be a non-empty str")
        self.rule = rule
        self.check = check
        self.detail = str(detail)

    def __repr__(self):
        return "LintViolation(rule=%r, check=%r)" % (self.rule, self.check)

    def __eq__(self, other):
        return (isinstance(other, LintViolation)
                and (self.rule, self.check, self.detail)
                == (other.rule, other.check, other.detail))

    def __hash__(self):
        return hash((self.rule, self.check, self.detail))


class LintReport(object):
    """The immutable result of linting one pack."""

    __slots__ = ("violations", "checks", "note")

    def __init__(self, violations=(), checks=(), note=""):
        self.violations = tuple(violations)
        self.checks = tuple(checks)
        self.note = str(note or "")

    @property
    def clean(self):
        """True when no check fired."""
        return not self.violations

    def for_check(self, check):
        """Violations fired by one check name."""
        return tuple(v for v in self.violations if v.check == check)

    def summary(self):
        """One-line-per-violation human summary (stable ordering)."""
        if self.clean:
            return "pack-lint: clean (%d checks)" % len(self.checks)
        lines = ["pack-lint: %d violation(s) across %d check(s):"
                 % (len(self.violations), len(self.checks))]
        for v in sorted(self.violations,
                        key=lambda v: (v.check, v.rule)):
            lines.append("  [%s] %s: %s" % (v.check, v.rule, v.detail))
        return "\n".join(lines)

    def __repr__(self):
        return "LintReport(violations=%d, checks=%d, clean=%s)" % (
            len(self.violations), len(self.checks), self.clean)


def require_clean(report):
    """Raise :class:`PackLintError` unless ``report`` is clean."""
    if not isinstance(report, LintReport):
        raise PackLintError("require_clean needs a LintReport")
    if not report.clean:
        raise PackLintError(
            "pack failed lint:\n%s" % report.summary())


# ---------------------------------------------------------------------------
# Regex witness synthesis (bounded; verified against the real engine)
# ---------------------------------------------------------------------------

# Caps keep the search terminating on hostile patterns.
_RX_MAX_REPEAT = 3
_RX_MAX_CANDIDATES = 8


def _rx_literal_charset(ops):
    """Pick one character matching an sre_parse IN charset, or None."""
    negate = False
    candidates = []
    for op, arg in ops:
        if op is _sre_constants.NEGATE:
            negate = True
        elif op is _sre_constants.LITERAL:
            candidates.append(chr(arg))
        elif op is _sre_constants.RANGE:
            lo, hi = arg
            candidates.append(chr(lo))
        elif op is _sre_constants.CATEGORY:
            cat = arg
            name = str(cat)
            if "DIGIT" in name:
                candidates.append("0" if "NOT" not in name else "a")
            elif "SPACE" in name:
                candidates.append(" " if "NOT" not in name else "a")
            elif "WORD" in name:
                candidates.append("a" if "NOT" not in name else "-")
            else:
                candidates.append("a")
        else:
            candidates.append("a")
    if not candidates:
        candidates = ["a"]
    if not negate:
        return candidates[0]
    excluded = set(candidates)
    for probe in ("a", "0", " ", "!", "~", "Z", "_", "-"):
        if probe not in excluded:
            return probe
    return None


def _rx_build(parsed, groups):
    """Build one witness string from parsed sre_parse tokens.

    ``groups`` maps group index -> witness (for backreferences).
    Returns (text, boundary_positions); may raise on exotic opcodes.
    """
    out = []
    boundaries = []

    def emit(sub, gidx=None):
        text, bpos = _rx_build(sub, groups)
        base = sum(len(p) for p in out)
        out.append(text)
        boundaries.extend(base + p for p in bpos)
        if gidx is not None:
            groups[gidx] = text

    for op, arg in parsed:
        if op is _sre_constants.LITERAL:
            out.append(chr(arg))
        elif op is _sre_constants.NOT_LITERAL:
            out.append("a" if arg != ord("a") else "b")
        elif op is _sre_constants.ANY:
            out.append("a")
        elif op is _sre_constants.IN:
            ch = _rx_literal_charset(arg)
            if ch is None:
                raise ValueError("empty charset")
            out.append(ch)
        elif op is _sre_constants.BRANCH:
            _nothing, branches = arg
            text, bpos = _rx_build(branches[0], groups)
            base = sum(len(p) for p in out)
            out.append(text)
            boundaries.extend(base + p for p in bpos)
        elif op is _sre_constants.SUBPATTERN:
            _gid, _add, _del, sub = arg
            emit(sub)
        elif op is _sre_constants.GROUPREF:
            text = groups.get(arg, "a")
            out.append(text)
        elif op in (_sre_constants.MAX_REPEAT, _sre_constants.MIN_REPEAT):
            lo, hi, sub = arg
            if lo == hi:
                # Exact counted repetition ({16}): honor it, bounded.
                n = min(lo, 64)
            else:
                n = lo if lo > 0 else 1
                n = min(n, _RX_MAX_REPEAT)
            for _ in range(n):
                emit(sub)
        elif op is _sre_constants.AT:
            if arg is _sre_constants.AT_BOUNDARY:
                boundaries.append(sum(len(p) for p in out))
            # Other anchors (^ $ \A \Z) need no characters.
        elif op is _sre_constants.ASSERT:
            direction, sub = arg
            text, _b = _rx_build(sub, groups)
            if direction < 0:  # lookbehind: the text precedes
                out.insert(0, text)
            else:  # lookahead: the text follows
                out.append(text)
        elif op is _sre_constants.ASSERT_NOT:
            pass  # negative lookarounds usually hold at a fresh position
        else:
            raise ValueError("unsupported regex opcode %r" % (op,))
    return "".join(out), boundaries


def _regex_witness_candidates(pattern):
    """Yield candidate witness strings for ``pattern`` (a str).

    Candidates are verified by the caller against the real engine;
    this generator only proposes. Yields at most
    ``_RX_MAX_CANDIDATES`` strings.
    """
    if _sre_parse is None:
        return
    try:
        parsed = _sre_parse.parse(pattern)
    except Exception:
        return
    groups = {}
    try:
        text, boundaries = _rx_build(parsed, groups)
    except Exception:
        return
    seen = set()
    cands = [text]
    # Word-boundary assertions are the common reason the naive
    # witness fails: retry with a space at each recorded boundary.
    for pos in boundaries:
        if len(cands) >= _RX_MAX_CANDIDATES:
            break
        variant = text[:pos] + " " + text[pos:]
        cands.append(variant)
    # A trailing space helps patterns ending at a boundary; a
    # leading space helps patterns starting at one.
    if len(cands) < _RX_MAX_CANDIDATES:
        cands.append(" " + text)
    if len(cands) < _RX_MAX_CANDIDATES:
        cands.append(text + " ")
    for cand in cands:
        if cand not in seen:
            seen.add(cand)
            yield cand


def _glob_to_regex_source(glob_pattern):
    """Translate a glob to an equivalent regex source string."""
    out = []
    for ch in glob_pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "".join(out)


def _glob_witness(glob_pattern):
    """One string fully matched by the glob, or None."""
    src = _glob_to_regex_source(glob_pattern)
    try:
        rx = re.compile(r"\A(?:%s)\Z" % src)
    except re.error:
        return None
    for cand in _regex_witness_candidates(src):
        if rx.match(cand):
            return cand
    return None


# ---------------------------------------------------------------------------
# Detection-rule domain (capability_rules)
# ---------------------------------------------------------------------------

# Bounds for the witness search. Small on purpose: this is a red-team
# approximation, not a solver.
_STMT_MAX_CANDIDATES = 6
_STMT_MAX_PRODUCT = 16

# Leaf kinds in compiled capability_rules statements (see _eval_leaf).
_LEAF_PATTERN = "pattern"
_LEAF_IMPORT = "import"
_LEAF_IMPORT_RE = "import-re"
_LEAF_ENV_NAME = "env-name"
_LEAF_TOOL_DEF = "tool-def"


def _sanitize_name_witness(text, for_tool=False):
    """Strip characters the feature extractors cannot capture.

    env names come from ``os.environ["NAME"]`` captures (no quotes,
    backslashes, or whitespace); tool names from ``def tool_\\w+``
    captures (word characters only).
    """
    if for_tool:
        return "".join(ch for ch in text
                       if ch.isalnum() or ch == "_")
    return "".join(ch for ch in text
                   if ch not in "\"'\\" and not ch.isspace())


def _leaf_text_candidates(leaf):
    """Candidate module-text strings satisfying one compiled leaf.

    ``leaf`` is the ``(kind, value, source)`` triple from
    ``_eval_leaf``. Candidates are verified by the caller with the
    real evaluator; this function only proposes.
    """
    kind, value = leaf[0], leaf[1]
    cands = []
    if kind == _LEAF_PATTERN:
        cands = list(_regex_witness_candidates(value.pattern))
    elif kind == _LEAF_IMPORT:
        cands = ["import " + value]
    elif kind == _LEAF_IMPORT_RE:
        for w in _regex_witness_candidates(value.pattern):
            cands.append("import " + w)
    elif kind == _LEAF_ENV_NAME:
        for w in _regex_witness_candidates(value.pattern):
            name = _sanitize_name_witness(w)
            if name:
                cands.append('os.environ["%s"]' % name)
    elif kind == _LEAF_TOOL_DEF:
        for w in _regex_witness_candidates(value.pattern):
            name = _sanitize_name_witness(w, for_tool=True)
            if name:
                cands.append("def tool_%s(" % name)
    return cands[:_STMT_MAX_CANDIDATES]


def _walk_match_refs(stmt):
    """Yield every ``match:`` reference string in a statement."""
    kind = stmt[0]
    if kind == "match":
        yield stmt[1]
    elif kind in ("and", "or"):
        for sub in stmt[1]:
            for ref in _walk_match_refs(sub):
                yield ref
    elif kind == "not":
        for ref in _walk_match_refs(stmt[1]):
            yield ref
    elif kind == "some":
        for sub in stmt[2]:
            for ref in _walk_match_refs(sub):
                yield ref
    elif kind == "count":
        pass  # count wraps a leaf, never a match
    elif kind == "subscope":
        for ref in _walk_match_refs(stmt[1]):
            yield ref
    elif kind == "leaf":
        pass
    else:  # pragma: no cover -- compiler owns the opcode set
        raise PackLintError("unknown statement opcode %r" % (kind,))


def _walk_leaves(stmt):
    """Yield ``(leaf_triple, position)`` for every leaf in a statement."""
    kind = stmt[0]
    if kind == "leaf":
        yield (stmt[1], "leaf")
    elif kind in ("and", "or"):
        for i, sub in enumerate(stmt[1]):
            for leaf, _pos in _walk_leaves(sub):
                yield (leaf, "%s/branch[%d]" % (kind, i))
    elif kind == "not":
        for leaf, _pos in _walk_leaves(stmt[1]):
            yield (leaf, "not")
    elif kind == "some":
        for i, sub in enumerate(stmt[2]):
            for leaf, _pos in _walk_leaves(sub):
                yield (leaf, "some/branch[%d]" % i)
    elif kind == "count":
        yield (stmt[1], "count")
    elif kind == "subscope":
        for leaf, pos in _walk_leaves(stmt[1]):
            yield (leaf, "subscope/" + pos)
    elif kind == "match":
        pass
    else:  # pragma: no cover -- compiler owns the opcode set
        raise PackLintError("unknown statement opcode %r" % (kind,))


def _stmt_text_candidates(stmt, witnesses):
    """Candidate module texts satisfying ``stmt`` (bounded).

    ``witnesses`` maps namespace -> verified module text (or None).
    ``match:`` refs resolve through it; every candidate is verified
    by the caller with the real evaluator.

    ``None`` inside a candidate list means "this sub-statement needs
    no positive text" (a bare ``not``); the empty list means the
    sub-statement is unsatisfiable within the search bounds.
    """
    kind = stmt[0]
    if kind == "leaf":
        return _leaf_text_candidates(stmt[1])
    if kind == "match":
        return _match_text_candidates(stmt[1], witnesses)
    if kind == "not":
        return [None]
    if kind == "and":
        parts = [_stmt_text_candidates(s, witnesses) for s in stmt[1]]
        if any(part == [] for part in parts):
            return []
        out = [""]
        for part in parts:
            part = [c for c in part if c is not None]
            if not part:
                continue
            nxt = []
            for base in out:
                for cand in part[:_STMT_MAX_CANDIDATES]:
                    joined = cand if not base else base + "\n" + cand
                    nxt.append(joined)
                    if len(nxt) >= _STMT_MAX_PRODUCT:
                        break
                if len(nxt) >= _STMT_MAX_PRODUCT:
                    break
            out = nxt
        return out
    if kind == "or":
        out = []
        for sub in stmt[1]:
            for cand in _stmt_text_candidates(sub, witnesses):
                cand = "" if cand is None else cand
                if cand not in out:
                    out.append(cand)
                if len(out) >= _STMT_MAX_PRODUCT:
                    return out
        return out
    if kind == "some":
        _k, n, subs = stmt
        per_sub = [_stmt_text_candidates(s, witnesses) for s in subs]
        per_sub = [p for p in per_sub if p != []]
        if len(per_sub) < n:
            return []
        # Concatenate one candidate from n distinct branches (bounded).
        chosen = per_sub[:n]
        out = [""]
        for part in chosen:
            part = ["" if c is None else c for c in part]
            nxt = []
            for base in out:
                for cand in part[:2]:
                    joined = cand if not base else base + "\n" + cand
                    nxt.append(joined)
                    if len(nxt) >= _STMT_MAX_PRODUCT:
                        break
                if len(nxt) >= _STMT_MAX_PRODUCT:
                    break
            out = nxt
        return out
    if kind == "count":
        _k, leaf, _n = stmt
        return _leaf_text_candidates(leaf)
    if kind == "subscope":
        return []
    raise PackLintError("unknown statement opcode %r" % (kind,))


def _match_text_candidates(ref, witnesses):
    """Candidate texts satisfying one ``match:`` reference.

    Bundle-scope witnesses are shape dicts, not module text; they
    cannot be inlined into a module candidate, so they resolve to no
    candidates here (a documented bound of the search).
    """
    from .capability_rules import SAME_MODULE_NAMESPACE
    if ref == SAME_MODULE_NAMESPACE:
        secrets_w = [t for ns, t in witnesses.items()
                     if ns.startswith("capability/secrets/")
                     and isinstance(t, str) and t]
        egress_w = [t for ns, t in witnesses.items()
                    if ns.startswith("capability/egress/")
                    and isinstance(t, str) and t]
        if secrets_w and egress_w:
            return [secrets_w[0] + "\n" + egress_w[0]]
        return []
    if ref.endswith("/*"):
        prefix = ref[:-2]
        hits = [t for ns, t in witnesses.items()
                if (ns == prefix or ns.startswith(prefix + "/"))
                and isinstance(t, str) and t]
        return hits[:2]
    text = witnesses.get(ref)
    if isinstance(text, dict):
        return []
    return [text] if text else []


def _verify_module_text(pack, text, namespace):
    """True iff ``text`` makes ``namespace`` match (real evaluator)."""
    from . import capability_rules as _cr
    try:
        matched, _evidence = _cr.evaluate_module(pack, text)
    except Exception:
        return False
    return namespace in matched


def _bundle_candidate_shapes(stmt, witnesses):
    """Candidate ``{module_id: text}`` bundles for a bundle sub-statement.

    Tries both the all-in-one-module shape and the split shape (each
    positive contributor in its own module): composition rules like
    "signals in DIFFERENT modules" only fire in the split shape,
    because the all-in-one shape triggers the synthetic
    ``capability/composition/same-module`` namespace.
    """
    pieces = []
    kind = stmt[0]
    branches = stmt[1] if kind == "and" else [stmt]
    for branch in branches:
        cands = _stmt_text_candidates(branch, witnesses)
        cands = [c for c in cands if c]
        if cands:
            pieces.append(cands[0])
    shapes = []
    if pieces:
        shapes.append({"m0": "\n".join(pieces)})
        if len(pieces) > 1:
            shapes.append({"m%d" % i: piece
                           for i, piece in enumerate(pieces)})
    # Fall back to the plain candidate list (single module each).
    for cand in _stmt_text_candidates(stmt, witnesses):
        if cand:
            shapes.append({"m0": cand})
        if len(shapes) >= _STMT_MAX_PRODUCT:
            break
    # Deduplicate while keeping order.
    seen = set()
    out = []
    for shape in shapes:
        key = tuple(sorted(shape.items()))
        if key not in seen:
            seen.add(key)
            out.append(shape)
    return out[:_STMT_MAX_PRODUCT]


def _verify_bundle_text(pack, modules, namespace):
    """True iff the ``{module_id: text}`` bundle matches ``namespace``."""
    from . import capability_rules as _cr
    try:
        bundle_ns, _per = _cr.evaluate_bundle(pack, modules)
    except Exception:
        return False
    return namespace in bundle_ns


def _compute_witnesses(pack):
    """Map namespace -> verified witness text (or None), pack order.

    Module-scope rules are witnessed with ``evaluate_module``;
    bundle-scope rules with a single-module ``evaluate_bundle``.
    Rules are processed in the pack's topological order so ``match:``
    refs resolve against already-verified witnesses.
    """
    witnesses = {}
    for rule in pack.rules:
        text = None
        try:
            if rule.scope == "module":
                for cand in _stmt_text_candidates(
                        rule.statement, witnesses)[:_STMT_MAX_PRODUCT]:
                    cand = "" if cand is None else cand
                    if _verify_module_text(pack, cand, rule.namespace):
                        text = cand
                        break
            elif rule.scope == "bundle":
                # Bundle rules wrap their statement in subscope; the
                # sub-statement is witnessed per module, trying both
                # single-module and split-module bundle shapes. The
                # stored witness is the shape dict (truthy = fires).
                stmt = rule.statement
                sub = stmt[1] if stmt[0] == "subscope" else stmt
                for shape in _bundle_candidate_shapes(sub, witnesses):
                    if _verify_bundle_text(pack, shape, rule.namespace):
                        text = dict(shape)
                        break
            else:  # pragma: no cover -- compiler owns the scope set
                pass
        except Exception:
            text = None
        witnesses[rule.namespace] = text
    return witnesses


def _is_prefix_ref(ref):
    return ref.endswith("/*")


def _lint_detection_pack(pack):
    """Run the safety/liveness/sanity checks over a compiled pack."""
    from .capability_rules import SAME_MODULE_NAMESPACE
    violations = []
    checks = []
    namespaces = set()
    for rule in pack.rules:
        namespaces.add(rule.namespace)

    def check(name):
        checks.append(name)

    witnesses = _compute_witnesses(pack)

    # -- safety: dead match refs (prefix refs with no in-pack target) --
    check("safety/dead-match-ref")
    for rule in pack.rules:
        for ref in _walk_match_refs(rule.statement):
            if ref == SAME_MODULE_NAMESPACE:
                has_s = any(ns.startswith("capability/secrets/")
                            for ns in namespaces)
                has_e = any(ns.startswith("capability/egress/")
                            for ns in namespaces)
                if not (has_s and has_e):
                    violations.append(LintViolation(
                        rule.name, "safety/dead-match-ref",
                        "match: %s can never resolve: pack has no "
                        "capability/secrets/* and capability/egress/* "
                        "namespaces" % (ref,)))
            elif _is_prefix_ref(ref):
                prefix = ref[:-2]
                if not any(ns == prefix or
                           ns.startswith(prefix + "/")
                           for ns in namespaces):
                    violations.append(LintViolation(
                        rule.name, "safety/dead-match-ref",
                        "match: %s has no target namespace in this pack; "
                        "the branch can never fire" % (ref,)))

    # -- safety: vacuous leaves (a leaf the search cannot satisfy) --
    check("safety/vacuous-leaf")
    for rule in pack.rules:
        for leaf, pos in _walk_leaves(rule.statement):
            if not _leaf_text_candidates(leaf):
                violations.append(LintViolation(
                    rule.name, "safety/vacuous-leaf",
                    "%s leaf %r (%s) admits no witness within the "
                    "search bounds; the leaf can never match"
                    % (pos, leaf[0], leaf[2])))

    # -- safety: unsatisfiable rules --
    check("safety/unsatisfiable-rule")
    for rule in pack.rules:
        if witnesses[rule.namespace] is None:
            violations.append(LintViolation(
                rule.name, "safety/unsatisfiable-rule",
                "no input makes this rule fire within the search "
                "bounds (scope=%s); the rule is dead policy text"
                % (rule.scope,)))

    # -- sanity: structural self-contradiction (and[X, not X]) --
    check("sanity/self-contradiction")
    for rule in pack.rules:
        if _has_self_contradiction(rule.statement):
            violations.append(LintViolation(
                rule.name, "sanity/self-contradiction",
                "the statement conjoins a sub-statement with its own "
                "negation; it can never hold"))

    # -- liveness: at least one rule in the pack can fire --
    check("liveness/pack-never-fires")
    if not any(t is not None for t in witnesses.values()):
        violations.append(LintViolation(
            "pack", "liveness/pack-never-fires",
            "no rule in this pack can fire within the search bounds; "
            "the pack is inert"))

    return violations, checks


def _canon_stmt(stmt):
    """Canonical form of a statement for structural comparison."""
    kind = stmt[0]
    if kind == "leaf":
        lkind, value, _src = stmt[1]
        v = value.pattern if hasattr(value, "pattern") else value
        return ("leaf", lkind, v)
    if kind == "match":
        return ("match", stmt[1])
    if kind == "not":
        return ("not", _canon_stmt(stmt[1]))
    if kind in ("and", "or"):
        return (kind, tuple(sorted(_canon_stmt(s) for s in stmt[1])))
    if kind == "some":
        _k, n, subs = stmt
        return ("some", n, tuple(sorted(_canon_stmt(s) for s in subs)))
    if kind == "count":
        _k, leaf, n = stmt
        lk, lkind, value = leaf[0], leaf[1], leaf[2]
        v = value.pattern if hasattr(value, "pattern") else value
        return ("count", lkind, v, n)
    if kind == "subscope":
        return ("subscope", _canon_stmt(stmt[1]))
    raise PackLintError("unknown statement opcode %r" % (kind,))


def _has_self_contradiction(stmt):
    """True iff an ``and`` conjoins X with ``not`` X (structurally)."""
    kind = stmt[0]
    if kind == "and":
        canon = [_canon_stmt(s) for s in stmt[1]]
        negs = set()
        poss = set()
        for s, c in zip(stmt[1], canon):
            if s[0] == "not":
                negs.add(c[1])
            else:
                poss.add(c)
        if negs & poss:
            return True
    if kind in ("and", "or"):
        return any(_has_self_contradiction(s) for s in stmt[1])
    if kind == "not":
        return _has_self_contradiction(stmt[1])
    if kind == "some":
        return any(_has_self_contradiction(s) for s in stmt[2])
    if kind == "subscope":
        return _has_self_contradiction(stmt[1])
    return False


def lint_capability_rule_files(files):
    """Lint a detection rule pack: ``{member_id: bytes}``.

    Returns a :class:`LintReport`. A pack that does not compile
    yields ``sanity/uncompilable-pack`` (a pack that cannot load
    cannot be meaningfully enforced).
    """
    from . import capability_rules as _cr
    if not isinstance(files, dict) or not files:
        raise PackLintError("files must be a non-empty dict")
    for member_id, data in files.items():
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise PackLintError(
                "member %r must be bytes" % (member_id,))
    checks = ["sanity/uncompilable-pack"]
    try:
        pack = _cr.load_pack_files(
            {mid: bytes(d) for mid, d in files.items()})
    except Exception as exc:
        return LintReport(
            violations=(LintViolation(
                "pack", "sanity/uncompilable-pack",
                "pack does not compile: %s: %s"
                % (type(exc).__name__, exc)),),
            checks=tuple(checks),
            note="compile refused; deeper checks not run")
    violations, deeper = _lint_detection_pack(pack)
    return LintReport(violations=violations,
                      checks=tuple(checks + deeper),
                      note="bounded witness search, no SMT solver")


# ---------------------------------------------------------------------------
# PERM domain (perm_loader)
# ---------------------------------------------------------------------------

# Bounds for the PERM witness search.
_PERM_MAX_SETS = 16
_PERM_MAX_REQUESTS = 8

_COMPARE_OPS = ("eq", "neq", "gt", "gte", "lt", "lte")


def _perm_operand_value(operand, row):
    """Resolve a compiled operand against a policy row.

    Returns ``("column", name, type)`` for request columns, otherwise
    ``("value", python_value)``.
    """
    kind = operand[0]
    if kind == "req":
        return ("column", operand[1], operand[2])
    if kind == "pol":
        return ("value", row[operand[1]])
    if kind == "lit":
        return ("value", operand[1])
    raise PackLintError("unknown operand %r" % (kind,))


def _perm_constraint_sets(node, row):
    """Bounded DNF-ish constraint sets for a compiled matcher.

    Each set maps request column -> constraint tuple. ``and``
    merges (cartesian, capped); ``or`` unions branch sets; ``not``
    and unhandled shapes contribute the empty set (the verifier
    filters wrong guesses).
    """
    kind = node[0]
    if kind == "and":
        sets = [{}]
        for child in node[1]:
            child_sets = _perm_constraint_sets(child, row)
            merged = []
            for base in sets:
                for add in child_sets:
                    combo = dict(base)
                    ok = True
                    for col, con in add.items():
                        if col in combo and combo[col] != con:
                            # Two different constraints on one
                            # column: keep both only if identical.
                            ok = False
                            break
                        combo[col] = con
                    if ok:
                        merged.append(combo)
                    if len(merged) >= _PERM_MAX_SETS:
                        break
                if len(merged) >= _PERM_MAX_SETS:
                    break
            sets = merged or [{}]
        return sets[:_PERM_MAX_SETS]
    if kind == "or":
        out = []
        for child in node[1]:
            for s in _perm_constraint_sets(child, row):
                if s not in out:
                    out.append(s)
                if len(out) >= _PERM_MAX_SETS:
                    return out
        return out or [{}]
    if kind == "not":
        return [{}]
    if kind in _COMPARE_OPS:
        left = _perm_operand_value(node[1], row)
        right = _perm_operand_value(node[2], row)
        col = val = None
        if left[0] == "column" and right[0] == "value":
            col, val = left[1], right[1]
        elif right[0] == "column" and left[0] == "value":
            # Reverse the operator for (value OP column).
            col, val = right[1], left[1]
            flip = {"gt": "lt", "gte": "lte", "lt": "gt", "lte": "gte"}
            kind = flip.get(kind, kind)
        if col is None:
            return [{}]
        return [{col: (kind, val)}]
    if kind == "call":
        _k, impl_name, args = node
        if impl_name not in ("glob", "regex") or len(args) != 2:
            return [{}]
        first = _perm_operand_value(args[0], row)
        second = _perm_operand_value(args[1], row)
        if first[0] == "column" and second[0] == "value" \
                and isinstance(second[1], str):
            return [{first[1]: (impl_name, second[1])}]
        return [{}]
    return [{}]


def _perm_build_request(cset, req_schema):
    """Build one request satisfying a constraint set, or None."""
    request = {}
    for col, typ in req_schema.items():
        cons = [c for c, co in cset.items() if c == col]
        if typ == "str":
            val = "x"
            for c in cons:
                op, arg = cset[c]
                if op == "eq":
                    val = arg
                elif op == "glob":
                    w = _glob_witness(arg)
                    if w is None:
                        return None
                    val = w
                elif op == "regex":
                    w = None
                    for cand in _regex_witness_candidates(
                            arg.pattern if hasattr(arg, "pattern")
                            else str(arg)):
                        w = cand
                        break
                    if w is None:
                        return None
                    val = w
            for c in cons:
                if cset[c][0] == "neq" and val == cset[c][1]:
                    val = val + "_"
            request[col] = val
        elif typ == "int":
            exact = None
            lo = hi = None
            for c in cons:
                op, arg = cset[c]
                if op == "eq":
                    exact = arg
                elif op == "gt":
                    lo = arg + 1 if lo is None else max(lo, arg + 1)
                elif op == "gte":
                    lo = arg if lo is None else max(lo, arg)
                elif op == "lt":
                    hi = arg - 1 if hi is None else min(hi, arg - 1)
                elif op == "lte":
                    hi = arg if hi is None else min(hi, arg)
            if exact is not None:
                if not isinstance(exact, int) \
                        or isinstance(exact, bool):
                    return None
                if (lo is not None and exact < lo) or \
                        (hi is not None and exact > hi):
                    return None
                val = exact
            else:
                if lo is not None and hi is not None and lo > hi:
                    return None
                # Prefer the neutral 0 over an extreme bound: a
                # witness at the edge of the allowed range is more
                # likely to trip unrelated screens/rows and prove
                # nothing about THIS row.
                if lo is not None:
                    val = lo
                elif hi is not None and 0 > hi:
                    val = hi
                else:
                    val = 0
            for c in cons:
                if cset[c][0] == "neq" and val == cset[c][1]:
                    val += 1
                    if hi is not None and val > hi:
                        return None
            request[col] = val
        elif typ == "bool":
            val = True
            for c in cons:
                op, arg = cset[c]
                if op == "eq":
                    val = bool(arg)
                elif op == "neq":
                    val = not bool(arg)
            request[col] = val
        else:  # pragma: no cover -- schema validation owns the types
            return None
    return request


def _perm_row_requests(model, screen_name, row):
    """Verified requests where ``row`` matches ``screen_name``.

    Every returned request satisfies the screen's matcher for the
    row under the REAL matcher evaluator -- the constraint solver
    only proposes.
    """
    from .perm_loader import _eval_matcher
    matcher = model._screens[screen_name]["matcher"]
    req_schema = model._model["request_schema"]
    sets = _perm_constraint_sets(matcher, row)[:_PERM_MAX_SETS]
    constrained = set()
    for s in sets:
        constrained.update(s)
    out = []
    for cset in sets:
        request = _perm_build_request(cset, req_schema)
        if request is None:
            continue
        try:
            holds = _eval_matcher(matcher, request, row)
        except Exception:
            holds = False
        if holds and request not in out:
            out.append(request)
        if len(out) >= _PERM_MAX_REQUESTS:
            break
    # Diversity: vary unconstrained columns so shadowing verdicts do
    # not rest on a single hand-picked request.
    diverse = list(out)
    for base in out:
        for col, typ in req_schema.items():
            if col in constrained:
                continue
            alt = dict(base)
            if typ == "str":
                alt[col] = "other" if base[col] != "other" else "x2"
            elif typ == "int":
                alt[col] = base[col] + 100
            elif typ == "bool":
                alt[col] = not base[col]
            try:
                holds = _eval_matcher(matcher, alt, row)
            except Exception:
                holds = False
            if holds and alt not in diverse:
                diverse.append(alt)
            if len(diverse) >= _PERM_MAX_REQUESTS:
                break
        if len(diverse) >= _PERM_MAX_REQUESTS:
            break
    return diverse


def _perm_canon_matcher(node, row):
    """Canonical matcher with policy columns substituted.

    Two rows whose canonical matchers are equal behave identically;
    structural equality is sound (no false positives), though not
    complete (semantically equal but structurally different matchers
    are missed -- an honest residual).
    """
    kind = node[0]
    if kind in ("and", "or"):
        return (kind, tuple(sorted(_perm_canon_matcher(c, row)
                                   for c in node[1])))
    if kind == "not":
        return ("not", _perm_canon_matcher(node[1], row))
    if kind in _COMPARE_OPS:
        return (kind, _perm_canon_operand(node[1], row),
                _perm_canon_operand(node[2], row))
    if kind == "call":
        _k, impl_name, args = node
        return ("call", impl_name,
                tuple(_perm_canon_operand(a, row) for a in args))
    raise PackLintError("unknown matcher node %r" % (kind,))


def _perm_canon_operand(operand, row):
    kind = operand[0]
    if kind == "req":
        return ("req", operand[1])
    if kind == "pol":
        return ("lit", row[operand[1]])
    if kind == "lit":
        value = operand[1]
        if hasattr(value, "pattern"):
            value = ("regex", value.pattern)
        return ("lit", value)
    raise PackLintError("unknown operand %r" % (kind,))


def _lint_perm_model(model):
    """Run the safety/liveness/sanity checks over a compiled PERM model."""
    from .perm_loader import _eval_matcher, _apply_effect, PermModel
    from .perm_loader import (EFFECT_ALLOW_AND_DENY, EFFECT_PRIORITY)
    violations = []
    checks = []
    req_schema = model._model["request_schema"]
    composition = model._model["composition"]
    screens = model._screens
    policies = model._policies

    def check(name):
        checks.append(name)

    # -- per-row witnesses (shared by several checks) --
    check("safety/vacuous-row")
    row_requests = {}
    for sname in screens:
        for idx, row in enumerate(policies.get(sname, [])):
            reqs = _perm_row_requests(model, sname, row)
            row_requests[(sname, idx)] = reqs
            if not reqs:
                violations.append(LintViolation(
                    "%s row[%d]" % (sname, idx),
                    "safety/vacuous-row",
                    "no request satisfies this row's matcher within the "
                    "search bounds; the row is an unreachable branch"))

    # -- safety: shadowed rows (removal changes no verdict) --
    check("safety/shadowed-row")
    for sname in screens:
        rows = policies.get(sname, [])
        for idx, row in enumerate(rows):
            reqs = row_requests[(sname, idx)]
            if not reqs:
                continue  # already flagged vacuous
            # Only witnesses that actually reach this row's screen
            # can distinguish it; witnesses intercepted by an
            # earlier screen prove nothing either way.
            screen_reqs = []
            for req in reqs:
                try:
                    if model.decide(req)[1] == sname:
                        screen_reqs.append(req)
                except Exception:
                    continue
            if not screen_reqs:
                continue
            minus_policies = {
                s: ([r for j, r in enumerate(rs) if not (s == sname
                                                         and j == idx)])
                for s, rs in policies.items()
            }
            minus = PermModel(model._model, minus_policies,
                              model_digest=model.model_digest,
                              policy_digest=model.policy_digest)
            shadowed = True
            for req in screen_reqs:
                try:
                    full = model.decide(req)[:2]
                    reduced = minus.decide(req)[:2]
                except Exception:
                    shadowed = False
                    break
                if full != reduced:
                    shadowed = False
                    break
            if shadowed:
                violations.append(LintViolation(
                    "%s row[%d]" % (sname, idx),
                    "safety/shadowed-row",
                    "every request matching this row decides identically "
                    "without it (verdict+screen unchanged over %d "
                    "witness request(s)); the grant is dead policy text"
                    % len(screen_reqs)))

    # -- safety: contradictory pairs (same matcher, different eft) --
    check("safety/contradictory-pair")
    for sname, screen in screens.items():
        rows = policies.get(sname, [])
        effect = screen["effect"]
        # The conflict only bites for effects where both efts
        # participate; under allow/deny-override the minority row is
        # inert and the shadowed-row check already covers it.
        if effect not in (EFFECT_ALLOW_AND_DENY, EFFECT_PRIORITY):
            continue
        seen = {}
        for idx, row in enumerate(rows):
            canon = _perm_canon_matcher(screen["matcher"], row)
            for other_idx, other_eft in seen.get(canon, []):
                if other_eft != row["eft"]:
                    violations.append(LintViolation(
                        "%s row[%d]" % (sname, idx),
                        "safety/contradictory-pair",
                        "row[%d] has a structurally identical matcher but "
                        "eft %r vs %r under effect %r; the pair cancels "
                        "instead of deciding" % (other_idx, row["eft"],
                                                 other_eft, effect)))
                    break
            seen.setdefault(canon, []).append((idx, row["eft"]))

    # -- safety: dead composition entries (a screen that never fires) --
    check("safety/dead-screen-entry")
    for entry in composition["order"]:
        sname = entry["screen"]
        screen = screens[sname]
        fired = False
        for idx, row in enumerate(policies.get(sname, [])):
            for req in row_requests[(sname, idx)]:
                try:
                    matched = [r for r in policies[sname]
                               if _eval_matcher(screen["matcher"],
                                                req, r)]
                    effect_value = _apply_effect(screen["effect"],
                                                 matched)
                except Exception:
                    continue
                if effect_value != entry["invert"]:
                    fired = True
                    break
            if fired:
                break
        if not fired:
            violations.append(LintViolation(
                sname, "safety/dead-screen-entry",
                "composition entry (verdict=%r) never fires within the "
                "search bounds; the screen is an unreachable branch"
                % (entry["verdict"],)))

    # -- liveness: the pack can allow something --
    check("liveness/trivially-denies-all")
    verdicts = set()
    for reqs in row_requests.values():
        for req in reqs:
            try:
                verdicts.add(model.decide(req)[0])
            except Exception:
                continue
    if not (verdicts & {"allow", "require_approval"}) \
            and composition["default_verdict"] not in (
                "allow", "require_approval"):
        violations.append(LintViolation(
            "pack", "liveness/trivially-denies-all",
            "no witness request reaches allow/require_approval; the "
            "pack denies everything it can express"))

    # -- sanity: no fail-open default --
    check("sanity/default-allow")
    if composition["default_verdict"] == "allow":
        violations.append(LintViolation(
            "pack", "sanity/default-allow",
            "composition default_verdict is allow: anything the "
            "screens do not catch is permitted"))

    return violations, checks


def lint_perm_pack(model_data, policy_data):
    """Lint a PERM model + policy document pair.

    ``model_data`` / ``policy_data``: bytes or str of the YAML
    documents (the same inputs as ``compile_perm_model``). Returns a
    :class:`LintReport`. A pair that does not compile yields
    ``sanity/uncompilable-pack``.
    """
    from . import perm_loader as _pl
    checks = ["sanity/uncompilable-pack"]
    try:
        model = _pl.compile_perm_model(model_data, policy_data)
    except Exception as exc:
        return LintReport(
            violations=(LintViolation(
                "pack", "sanity/uncompilable-pack",
                "PERM model/policy does not compile: %s: %s"
                % (type(exc).__name__, exc)),),
            checks=tuple(checks),
            note="compile refused; deeper checks not run")
    violations, deeper = _lint_perm_model(model)
    return LintReport(violations=violations,
                      checks=tuple(checks + deeper),
                      note="bounded witness search, no SMT solver")
