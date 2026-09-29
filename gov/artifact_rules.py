"""General-purpose artifact-rule verifier: in-toto-style CREATE /
MODIFY / DELETE / REQUIRE / MATCH / DISALLOW rules over plain
(name -> digest) material/product maps.

UPSTREAM PIN: the rule grammar is adapted from in-toto's
specification, ``in-toto-spec.md`` section 4.3.3 ("Artifact Rules")
(in-toto/docs @ 6459afd8e94a332e423ba05c2862b534acbe741d, verified
2026-09-29). The specification is under the Community Specification
License; NO spec text is copied here and NO in-toto code is vendored
-- the semantics below are re-described in our own words and the code
lineage is ours. Only the public rule-kind names and the ordered
consumptive-queue discipline are carried over.

Why this module exists alongside ``gov.provenance_verifier``: that
module's rule engine is deliberately NARROW -- REQUIRE/MATCH/
DISALLOW over digest-bound SEALED ProvenanceStatement records (the
name->statement binding is its anti-swap authority). This module is
GENERAL -- the full six-rule grammar over raw (name -> sha256 digest)
material and product maps, for any caller that knows what a step
consumed and produced but does not have sealed statements (e.g. a
promotion gate comparing declared materials against declared
products). The two engines share the fail-closed discipline, never
the seam.

Rule grammar (each rule is a tuple; ``parse_rule`` normalizes)::

    ("CREATE", pattern)
        Every UNCONSUMED product whose name fnmatch-matches ``pattern``
        must NOT be present in materials: the step genuinely created
        it. Consumes the matching product records. A pattern matching
        nothing is a no-op (it claims nothing).

    ("MODIFY", pattern)
        Every name matched by ``pattern`` (in either materials or
        products) must be present in BOTH, with DIFFERENT digests: the
        step changed it, it did not rename or re-emit it. Consumes the
        matching material AND product records together. A same-digest
        pair, a materials-only name, or a products-only name under a
        MODIFY rule is refused.

    ("DELETE", pattern)
        Every UNCONSUMED material whose name fnmatch-matches
        ``pattern`` must NOT be present in products: the step dropped
        it. Consumes the matching material records.

    ("REQUIRE", name)
        An unconsumed record with exactly this name must exist
        (materials or products). Consumes every unconsumed record with
        that name (a material record and a product record with the
        same name are the same artifact at two points in the step, so
        REQUIRE accounting for the name must account for both).

    ("MATCH", name, expected_digest_hex)
        REQUIRE, plus every unconsumed record with this name must
        carry EXACTLY the caller-pinned digest -- the digest binding
        for step chaining. The pinned value is caller-supplied policy,
        never read from the artifact being checked. Consumes every
        record with that name.

    ("DISALLOW",)
        Terminal only. Refuses every artifact still unconsumed, naming
        them. It must appear EXACTLY once, as the LAST rule.

Two fail-closed disciplines (same as the sibling engine):

1. Rules apply in order; each rule CONSUMES the artifacts it
   accounts for. An artifact consumed by one rule is gone from the
   queue -- a later rule naming it finds nothing and refuses (an
   artifact is accounted for exactly once).
2. Every rule set MUST end with a terminal ``DISALLOW``. Anything
   left unconsumed is refused -- there is NO implicit ALLOW *. A rule
   set without a terminal DISALLOW, or with DISALLOW anywhere but
   last, is refused at load time, before any artifact is examined.

Strictness: the public seam ``verify_artifacts`` raises
``ArtifactRuleError`` loudly on every violation (a ``ValueError``,
matching the sibling modules), because a silent False on an
artifact-accounting check is an invitation to skip it. Unknown rule
kinds, malformed tuples, empty patterns, path-confusing names, and
non-sha256-hex digests are all refused.

Patterns are fnmatch (``*``, ``?``, ``[seq]``), matched against the
FULL artifact name, case-sensitively. This is a documented
approximation of path-pattern matching, not a regex engine: patterns
are data, never executed.

Honest residuals:
- The (materials, products) maps are caller-supplied claims; this
  module verifies that the RULES account for the CLAIMED artifacts,
  not that the step really consumed/emitted them. Artifact reality is
  the caller's responsibility (same posture as the sibling engine's
  named_statements binding).
- Pattern matching is fnmatch on names; there is no directory-walk
  semantics. Name hygiene (no ``..``, no absolute paths, no
  backslashes) is enforced at the queue boundary so a pattern cannot
  be confused across a path seam.
- Digests are sha256 hex only; other digest types are refused rather
  than coerced.
- The module is intentionally UNINTEGRATED: no other gov module
  produces raw (name -> digest) material/product maps yet, and the
  sealed-statement path already has its own narrower engine. Wiring
  this into ``verify_provenance_chain`` would mix the two seams.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import fnmatch
import hashlib
import json

__all__ = [
    "ArtifactRuleError",
    "load_rules",
    "parse_rule",
    "verify_artifacts",
]

_RULE_KINDS = ("CREATE", "MODIFY", "DELETE", "REQUIRE", "MATCH", "DISALLOW")


class ArtifactRuleError(ValueError):
    """Raised loudly on any artifact-rule violation."""


def _check_hex_digest(value, where):
    if not isinstance(value, str):
        raise ArtifactRuleError(
            "%s: digest must be str, got %s"
            % (where, type(value).__name__))
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ArtifactRuleError(
            "%s: not a sha256 hex digest: %r" % (where, value))
    return value


def _check_name(name, where):
    """Artifact-name hygiene: non-empty str, no NUL, not absolute, no
    ``..`` path segment, no backslashes (a backslash in a name invites
    cross-OS path confusion in a Linux evaluator)."""
    if not isinstance(name, str) or not name:
        raise ArtifactRuleError(
            "%s: artifact name must be a non-empty str" % where)
    if "\x00" in name:
        raise ArtifactRuleError("%s: artifact name has NUL: %r" % (where, name))
    if name.startswith("/"):
        raise ArtifactRuleError(
            "%s: artifact name must not be absolute: %r" % (where, name))
    if "\\" in name:
        raise ArtifactRuleError(
            "%s: artifact name must not contain backslash: %r"
            % (where, name))
    if ".." in name.split("/"):
        raise ArtifactRuleError(
            "%s: artifact name must not contain '..': %r" % (where, name))
    return name


def _check_pattern(pattern, where):
    if not isinstance(pattern, str) or not pattern:
        raise ArtifactRuleError(
            "%s: rule pattern must be a non-empty str" % where)
    if "\x00" in pattern:
        raise ArtifactRuleError(
            "%s: rule pattern has NUL: %r" % (where, pattern))
    return pattern


def parse_rule(spec):
    """Normalize one rule tuple; refuse unknown kinds and malformed
    tuples loudly.

    Accepted forms: ("CREATE", pattern), ("MODIFY", pattern),
    ("DELETE", pattern), ("REQUIRE", name), ("MATCH", name, digest),
    ("DISALLOW",). Anything else is refused.
    """
    if not isinstance(spec, (tuple, list)) or not spec:
        raise ArtifactRuleError("rule must be a non-empty tuple, got %r"
                                % (spec,))
    kind = spec[0]
    if kind not in _RULE_KINDS:
        raise ArtifactRuleError(
            "unknown rule kind %r (expected one of %s)"
            % (kind, ", ".join(_RULE_KINDS)))
    if kind in ("CREATE", "MODIFY", "DELETE"):
        if len(spec) != 2:
            raise ArtifactRuleError(
                "%s takes exactly one pattern, got %r" % (kind, spec))
        return (kind, _check_pattern(spec[1], kind))
    if kind == "REQUIRE":
        if len(spec) != 2:
            raise ArtifactRuleError(
                "REQUIRE takes exactly one artifact name, got %r" % (spec,))
        return ("REQUIRE", _check_name(spec[1], "REQUIRE"))
    if kind == "MATCH":
        if len(spec) != 3:
            raise ArtifactRuleError(
                "MATCH takes an artifact name and a digest, got %r"
                % (spec,))
        return ("MATCH", _check_name(spec[1], "MATCH"),
                _check_hex_digest(spec[2], "MATCH expected digest"))
    # DISALLOW
    if len(spec) != 1:
        raise ArtifactRuleError(
            "DISALLOW takes no arguments, got %r" % (spec,))
    return ("DISALLOW",)


def load_rules(specs):
    """Strict-validate a rule set; enforces the terminal-DISALLOW
    discipline fail-closed. Returns the normalized rules as a tuple.

    Refused: an empty set; a set with no DISALLOW; a DISALLOW in any
    position but last; more than one DISALLOW. The terminal DISALLOW
    is not optional and it is not defaulted -- a rule set that does
    not say what to do with leftovers is refused before evaluation.
    """
    if not isinstance(specs, (tuple, list)) or not specs:
        raise ArtifactRuleError("rule set must be a non-empty sequence")
    normalized = tuple(parse_rule(spec) for spec in specs)
    disallow_positions = [i for i, rule in enumerate(normalized)
                          if rule[0] == "DISALLOW"]
    if not disallow_positions:
        raise ArtifactRuleError(
            "rule set must end with a terminal DISALLOW (fail-closed "
            "lint discipline: no implicit ALLOW *)")
    if disallow_positions != [len(normalized) - 1]:
        raise ArtifactRuleError(
            "DISALLOW is terminal: it may only appear as the last rule, "
            "got positions %r" % (disallow_positions,))
    return normalized


def _rule_set_digest(rules):
    canonical = json.dumps([list(rule) for rule in rules],
                           separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _check_artifact_map(mapping, where):
    if not isinstance(mapping, dict):
        raise ArtifactRuleError(
            "%s must be a dict of name -> sha256 hex digest, got %s"
            % (where, type(mapping).__name__))
    checked = {}
    for name, digest in mapping.items():
        _check_name(name, "%s key" % where)
        _check_hex_digest(digest, "%s[%r]" % (where, name))
        checked[name] = digest
    return checked


def _build_queue(materials, products):
    """The artifact queue: one record per (name, side) pair. A name in
    both maps yields TWO records (material and product) -- CREATE /
    MODIFY / DELETE semantics need the sides separate, and REQUIRE /
    MATCH accounting consumes a name's records together. Deterministic
    order: sorted names, material record before product record."""
    queue = []
    for name in sorted(materials):
        queue.append({"name": name, "side": "material",
                      "digest": materials[name], "consumed": False})
    for name in sorted(products):
        queue.append({"name": name, "side": "product",
                      "digest": products[name], "consumed": False})
    return queue


def _unconsumed(records):
    return [r for r in records if not r["consumed"]]


def _names_matching(records, pattern, side=None):
    names = set()
    for record in records:
        if record["consumed"]:
            continue
        if side is not None and record["side"] != side:
            continue
        if fnmatch.fnmatchcase(record["name"], pattern):
            names.add(record["name"])
    return sorted(names)


def _records_named(records, name):
    return [r for r in records
            if not r["consumed"] and r["name"] == name]


def _consume(records, names, audit):
    for record in records:
        if not record["consumed"] and record["name"] in names:
            record["consumed"] = True
            audit.append("%s:%s" % (record["side"], record["name"]))


def verify_artifacts(materials, products, rule_specs, context=""):
    """Verify (materials, products) against the rule set, consumptive
    and in order. Returns an audit report dict on success; raises
    ``ArtifactRuleError`` loudly on any violation.

    ``materials`` / ``products``: dicts mapping artifact name ->
    sha256 hex digest. ``rule_specs``: rule tuples (or the output of
    ``load_rules``). ``context``: optional label echoed in the report
    and in error messages (which step / promotion this check is for).
    """
    ctx = ("[%s] " % context) if context else ""
    materials = _check_artifact_map(materials, "materials")
    products = _check_artifact_map(products, "products")
    rules = load_rules(rule_specs)
    queue = _build_queue(materials, products)
    per_rule = []

    for rule in rules:
        kind = rule[0]
        consumed_here = []
        if kind == "CREATE":
            pattern = rule[1]
            for name in _names_matching(queue, pattern, side="product"):
                if name in materials:
                    raise ArtifactRuleError(
                        "%sCREATE %r: product %r already exists in "
                        "materials -- not created by this step"
                        % (ctx, pattern, name))
                _consume(queue, {name}, consumed_here)
        elif kind == "DELETE":
            pattern = rule[1]
            for name in _names_matching(queue, pattern, side="material"):
                if name in products:
                    raise ArtifactRuleError(
                        "%sDELETE %r: material %r still present in "
                        "products -- not deleted by this step"
                        % (ctx, pattern, name))
                _consume(queue, {name}, consumed_here)
        elif kind == "MODIFY":
            pattern = rule[1]
            for name in _names_matching(queue, pattern):
                in_m = name in materials
                in_p = name in products
                if not (in_m and in_p):
                    raise ArtifactRuleError(
                        "%sMODIFY %r: artifact %r must be in BOTH "
                        "materials and products (in materials: %s, in "
                        "products: %s)" % (ctx, pattern, name, in_m, in_p))
                if materials[name] == products[name]:
                    raise ArtifactRuleError(
                        "%sMODIFY %r: artifact %r has identical digests "
                        "in materials and products -- nothing was "
                        "modified" % (ctx, pattern, name))
                _consume(queue, {name}, consumed_here)
        elif kind == "REQUIRE":
            name = rule[1]
            hits = _records_named(queue, name)
            if not hits:
                raise ArtifactRuleError(
                    "%sREQUIRE %r: artifact not in the queue (absent or "
                    "already consumed)" % (ctx, name))
            _consume(queue, {name}, consumed_here)
        elif kind == "MATCH":
            name, pinned = rule[1], rule[2]
            hits = _records_named(queue, name)
            if not hits:
                raise ArtifactRuleError(
                    "%sMATCH %r: artifact not in the queue (absent or "
                    "already consumed)" % (ctx, name))
            for record in hits:
                if record["digest"] != pinned:
                    raise ArtifactRuleError(
                        "%sMATCH %r: %s record digest %s != pinned "
                        "digest %s" % (ctx, name, record["side"],
                                       record["digest"], pinned))
            _consume(queue, {name}, consumed_here)
        else:  # DISALLOW -- terminal by load_rules
            leftover = _unconsumed(queue)
            if leftover:
                names = sorted("%s:%s" % (r["side"], r["name"])
                               for r in leftover)
                raise ArtifactRuleError(
                    "%sDISALLOW: %d artifact(s) unconsumed by any rule "
                    "(no implicit ALLOW *): %s"
                    % (ctx, len(names), ", ".join(names)))
        per_rule.append({"rule": list(rule),
                         "consumed": sorted(consumed_here)})

    return {
        "ok": True,
        "context": context,
        "materials": len(materials),
        "products": len(products),
        "rule_set_digest": _rule_set_digest(rules),
        "per_rule": per_rule,
        "consumed_count": sum(len(entry["consumed"]) for entry in per_rule),
    }
