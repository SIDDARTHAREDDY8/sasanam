"""Build-provenance verifier: in-toto-pattern artifact rules over
``ProvenanceStatement`` records.

PATTERN LINEAGE: in-toto's artifact-rule grammar (re-implemented in
stdlib Python -- no in-toto code is vendored here, only the pattern)
and Nix's reproducibility-verification techniques (double-build
check, input-closure hash as identity, signed binary substitution --
docs-level steal, no daemon).

Two fail-closed disciplines, stolen from in-toto's verifylib:

1. Rules apply in order and each rule *consumes* artifacts from the
   queue. An artifact is "accounted for" only when a rule consumes it.
2. Every rule set MUST end with a terminal ``DISALLOW``. Any artifact
   left in the queue at the terminal DISALLOW is refused. A rule set
   without a terminal DISALLOW is refused outright (lint discipline,
   fail-closed) -- even if every artifact was consumed.

Rule grammar::

    ("REQUIRE", name)
        The provenance record for artifact ``name`` must exist and
        verify: the trusted name -> statement binding selects the
        sealed statement for ``name``, and its pinned artifact digest
        must equal the claimed digest, with a valid signature from a
        trusted key. Consumes ``name`` from the queue.

    ("MATCH", name, expected_digest_hex)
        REQUIRE, plus the claimed digest must equal
        ``expected_digest_hex`` -- the digest-bound step chaining
        (in-toto MATCH). The expected digest is pinned by an earlier
        step's verified statement or a deployment manifest; it is a
        caller-supplied value, never read from the artifact being
        checked. Consumes ``name`` from the queue.

    ("DISALLOW",)
        Terminal only. Refuses every artifact still in the queue.

The name -> statement binding (``named_statements``) is the analog of
in-toto's signed layout: it must come from the deployment manifest /
policy, never from the receipts being verified. Without it, a receipt
swap between two artifacts with valid statements would be invisible
(the wave-178 falsifiable probe) -- the binding is what makes the
swap fail closed.

The falsifiable receipt-swap probe: swap two digest receipts between
steps and the chain fails -- the statement bound to name A pins A's
digest, not B's, so the binding check refuses the swapped receipt.

Reproducibility verification (Nix ADAPT):

* ``verify_double_build`` -- the Nix ``--check`` discipline: each
  deterministic input is rebuilt TWICE. A deterministic claim whose
  rebuilds disagree is a lie; a rebuild disagreeing with the recorded
  digest is a lie. Non-deterministic inputs are reported as unchecked,
  never re-derived (same honesty as
  ``build_provenance.verify_reproducibility``).
* ``input_closure_digest`` / ``verify_input_closure`` -- the
  input-closure hash as identity: hash drift always means an input
  change. The caller supplies the observed (name, digest) closure; the
  verifier compares it against the statement's declared inputs.
* ``verify_prebuilt`` -- signed binary substitution: a prebuilt
  artifact is accepted only under a verified sealed statement.
  Unsigned prebuilts are refused loudly.

Strictness: the Verifier interface returns True/False internally but
the public seams here raise ``ProvenanceVerifierError`` loudly,
because a silent False on a provenance check is an invitation to skip
it. Unknown rule kinds, malformed rules, and non-terminal DISALLOW
placements are refused.

Honest residuals: the artifact NAME binding lives in the caller's
``named_statements`` mapping (layout analog); the statement format
itself carries only the digest, so a caller that builds the mapping
from the receipts defeats the swap detection -- the mapping's own
provenance is the caller's responsibility. Double-build and closure
checks trust the caller's rebuilder / observed inputs to be honest
(they detect lies in the statement, not lies in the rebuilder).
Non-deterministic inputs are evidence, not promises, by design.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import hashlib
import json

from . import build_provenance as _bp
from .signing import Verifier

__all__ = [
    "ProvenanceVerifierError",
    "check_rule_set",
    "input_closure_digest",
    "parse_rule",
    "verify_double_build",
    "verify_input_closure",
    "verify_prebuilt",
    "verify_provenance_chain",
]


class ProvenanceVerifierError(ValueError):
    """Raised loudly on any provenance-verification failure."""


def _check_hex_digest(value, where):
    if not isinstance(value, str):
        raise ProvenanceVerifierError(
            "%s: digest must be str, got %s" % (where, type(value).__name__))
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ProvenanceVerifierError(
            "%s: not a sha256 hex digest: %r" % (where, value))
    return value


def _check_name(name, where):
    if not isinstance(name, str) or not name:
        raise ProvenanceVerifierError(
            "%s: artifact name must be a non-empty str" % where)
    return name


def parse_rule(spec):
    """Strict-parse one rule spec into a normalized tuple.

    Accepted forms: ("REQUIRE", name), ("MATCH", name, digest),
    ("DISALLOW",). Anything else is refused.
    """
    if not isinstance(spec, (tuple, list)) or not spec:
        raise ProvenanceVerifierError("rule must be a non-empty "
                                      "tuple/list, got %r" % (spec,))
    kind = spec[0]
    if kind == "REQUIRE":
        if len(spec) != 2:
            raise ProvenanceVerifierError(
                "REQUIRE takes exactly one artifact name, got %r" % (spec,))
        return ("REQUIRE", _check_name(spec[1], "REQUIRE"))
    if kind == "MATCH":
        if len(spec) != 3:
            raise ProvenanceVerifierError(
                "MATCH takes an artifact name and a digest, got %r"
                % (spec,))
        return ("MATCH", _check_name(spec[1], "MATCH"),
                _check_hex_digest(spec[2], "MATCH expected digest"))
    if kind == "DISALLOW":
        if len(spec) != 1:
            raise ProvenanceVerifierError(
                "DISALLOW takes no arguments, got %r" % (spec,))
        return ("DISALLOW",)
    raise ProvenanceVerifierError("unknown rule kind: %r" % (kind,))


def check_rule_set(rules):
    """Strict-validate a rule set; enforces the terminal-DISALLOW
    discipline. Returns the normalized rule list."""
    if not isinstance(rules, (list, tuple)) or not rules:
        raise ProvenanceVerifierError("rule set must be a non-empty list")
    normalized = [parse_rule(r) for r in rules]
    for i, rule in enumerate(normalized[:-1]):
        if rule[0] == "DISALLOW":
            raise ProvenanceVerifierError(
                "DISALLOW is terminal: it may only appear as the last "
                "rule (found at position %d)" % i)
    if normalized[-1][0] != "DISALLOW":
        raise ProvenanceVerifierError(
            "rule set must end with a terminal DISALLOW (fail-closed "
            "lint discipline); got %r as the last rule"
            % (normalized[-1],))
    return normalized


def _strict_artifacts(artifacts):
    if not isinstance(artifacts, dict):
        raise ProvenanceVerifierError("artifacts must be a dict of "
                                      "name -> sha256 hex digest")
    for name, digest in artifacts.items():
        _check_name(name, "artifacts")
        _check_hex_digest(digest, "artifacts[%r]" % name)
    return dict(artifacts)


def _strict_named_statements(named_statements, verifiers):
    """Strict-validate the trusted name -> sealed-statement binding.

    ``named_statements`` is the analog of in-toto's signed layout: it
    binds artifact NAMES to their provenance statements and must come
    from the deployment manifest / policy -- never from the receipts
    being verified. (The statement format itself carries only the
    digest; a future statement format could bind the name inside the
    signed body. Until then, this mapping is the name binding, and its
    provenance is the caller's responsibility -- documented as a
    residual.)
    """
    if not isinstance(named_statements, dict) or not named_statements:
        raise ProvenanceVerifierError("named_statements must be a "
                                      "non-empty dict of artifact name "
                                      "-> sealed statement")
    if not isinstance(verifiers, dict) or not verifiers:
        raise ProvenanceVerifierError("verifiers must be a non-empty dict "
                                      "of key_id -> Verifier")
    for key_id, verifier in verifiers.items():
        if not isinstance(verifier, Verifier):
            raise ProvenanceVerifierError(
                "verifier for key_id %r is not a gov.signing.Verifier"
                % key_id)
    bound = {}
    for name, sealed in named_statements.items():
        _check_name(name, "named_statements")
        try:
            _stmt, _sig, key_id = _bp.parse_statement(sealed)
        except _bp.ProvenanceError as exc:
            raise ProvenanceVerifierError(
                "named_statements %r: sealed statement is malformed: %s"
                % (name, exc))
        if key_id not in verifiers:
            raise ProvenanceVerifierError(
                "no trusted verifier for statement key_id %r "
                "(artifact %r)" % (key_id, name))
        bound[name] = (key_id, sealed)
    return bound


def _use_statement(bound, verifiers, name, claimed_digest,
                   rule_kind):
    """Verify the statement bound to ``name`` against the receipt.

    The trusted name -> statement binding selects the statement; then
    ``verify_sealed_statement`` checks the signature AND that the
    statement pins exactly the receipt's claimed digest. A swapped
    receipt (name A claiming artifact B's digest) fails the binding
    because A's statement pins A's digest, not B's.
    """
    sealed_entry = bound.get(name)
    if sealed_entry is None:
        raise ProvenanceVerifierError(
            "%s %r: no provenance record bound to this artifact name"
            % (rule_kind, name))
    key_id, sealed = sealed_entry
    try:
        return _bp.verify_sealed_statement(
            sealed, expected_artifact_hex=claimed_digest,
            verifier=verifiers[key_id])
    except _bp.ProvenanceError as exc:
        raise ProvenanceVerifierError(
            "%s %r: provenance record failed verification: %s"
            % (rule_kind, name, exc))


def verify_provenance_chain(named_statements, artifacts, rules,
                            verifiers):
    """Verify a provenance chain under in-toto-pattern artifact rules.

    ``named_statements``: dict of artifact name -> sealed statement
    (as produced by ``ProvenanceStatement.seal``). This is the trusted
    name binding -- the analog of in-toto's signed layout -- and must
    come from the deployment manifest / policy, never from the
    receipts being verified.
    ``artifacts``: dict of artifact name -> claimed sha256 hex digest
    (the receipts).
    ``rules``: rule specs; must end with ("DISALLOW",).
    ``verifiers``: dict key_id -> gov.signing.Verifier.

    Returns {"consumed": [...], "rules_applied": n}. Raises
    ProvenanceVerifierError loudly on any failure.
    """
    queue = _strict_artifacts(artifacts)
    normalized = check_rule_set(rules)

    # Strict-validate the trusted name binding up front. Signature
    # verification happens per use (see _use_statement): the name
    # selects the statement, and verify_sealed_statement then checks
    # the signature AND that the statement pins exactly the receipt's
    # claimed digest -- a non-vacuous binding.
    named = _strict_named_statements(named_statements, verifiers)

    consumed = []
    for rule in normalized:
        kind = rule[0]
        if kind == "REQUIRE":
            name = rule[1]
            if name not in queue:
                raise ProvenanceVerifierError(
                    "REQUIRE %r: artifact not in the queue (absent or "
                    "already consumed)" % name)
            # The non-vacuous artifact binding: the trusted name
            # binding selects the statement, and the statement must pin
            # exactly the receipt's claimed digest. A swapped receipt
            # fails here because the statement for name A pins A's
            # digest, not B's.
            _use_statement(named, verifiers, name, queue[name], "REQUIRE")
            del queue[name]
            consumed.append(name)
        elif kind == "MATCH":
            name, expected = rule[1], rule[2]
            if name not in queue:
                raise ProvenanceVerifierError(
                    "MATCH %r: artifact not in the queue (absent or "
                    "already consumed)" % name)
            _use_statement(named, verifiers, name, queue[name], "MATCH")
            if queue[name] != expected:
                raise ProvenanceVerifierError(
                    "MATCH %r: digest %s != expected %s"
                    % (name, queue[name], expected))
            del queue[name]
            consumed.append(name)
        else:  # terminal DISALLOW
            if queue:
                raise ProvenanceVerifierError(
                    "terminal DISALLOW: unaccounted artifacts refused: %s"
                    % sorted(queue))
    return {"consumed": consumed, "rules_applied": len(normalized)}


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def input_closure_digest(sealed_or_statement):
    """The input-closure hash: sha256 over the canonical list of
    (name, digest) pairs. Hash drift always means an input change."""
    if isinstance(sealed_or_statement, _bp.ProvenanceStatement):
        stmt = sealed_or_statement
    else:
        try:
            stmt, _, _ = _bp.parse_statement(sealed_or_statement)
        except _bp.ProvenanceError as exc:
            raise ProvenanceVerifierError(
                "input_closure_digest: sealed statement is malformed: %s"
                % exc)
    pairs = sorted((i.name, i.digest_hex) for i in stmt.inputs)
    return hashlib.sha256(_canonical(
        {"closure": [[n, d] for n, d in pairs]})).hexdigest()


def verify_input_closure(sealed, observed_inputs, verifier,
                         expected_artifact_hex):
    """Verify the input closure against independently observed inputs.

    ``observed_inputs``: list of (name, digest_hex) the caller actually
    saw at build time. Must exactly equal the statement's declared
    inputs (no additions, no omissions, no digest changes). The
    statement signature is verified first, bound to the caller's
    ``expected_artifact_hex`` (never read from the statement itself).

    Returns {"closure": <input-closure digest>}.
    """
    if not isinstance(verifier, Verifier):
        raise ProvenanceVerifierError("verifier must be a "
                                      "gov.signing.Verifier")
    _check_hex_digest(expected_artifact_hex, "expected_artifact")
    try:
        stmt = _bp.verify_sealed_statement(
            sealed, expected_artifact_hex=expected_artifact_hex,
            verifier=verifier)
    except _bp.ProvenanceError as exc:
        raise ProvenanceVerifierError(
            "input-closure statement failed verification: %s" % exc)
    if not isinstance(observed_inputs, (list, tuple)):
        raise ProvenanceVerifierError("observed_inputs must be a list of "
                                      "(name, digest) pairs")
    observed = {}
    for pair in observed_inputs:
        if (not isinstance(pair, (tuple, list)) or len(pair) != 2):
            raise ProvenanceVerifierError(
                "observed input must be a (name, digest) pair, got %r"
                % (pair,))
        name, digest = pair
        _check_name(name, "observed input")
        _check_hex_digest(digest, "observed input %r" % name)
        if name in observed:
            raise ProvenanceVerifierError(
                "duplicate observed input %r" % name)
        observed[name] = digest
    declared = {i.name: i.digest_hex for i in stmt.inputs}
    if observed != declared:
        only_observed = sorted(set(observed) - set(declared))
        only_declared = sorted(set(declared) - set(observed))
        drifted = sorted(n for n in observed
                         if n in declared and observed[n] != declared[n])
        raise ProvenanceVerifierError(
            "input-closure drift: undeclared=%s missing=%s drifted=%s"
            % (only_observed, only_declared, drifted))
    return {"closure": input_closure_digest(stmt)}


def verify_double_build(sealed, rebuilder, verifier,
                        expected_artifact_hex):
    """The Nix --check discipline: compare, don't trust.

    Verifies the statement signature and the artifact binding, then
    rebuilds every deterministic input TWICE. A deterministic claim
    whose two rebuilds disagree is a lie; a rebuild disagreeing with
    the recorded digest is a lie. Non-deterministic inputs are
    reported as unchecked, never re-derived.

    The expected artifact digest is a parameter, not read from the
    statement (a self-read binding would be vacuous).
    """
    if not isinstance(verifier, Verifier):
        raise ProvenanceVerifierError("verifier must be a "
                                      "gov.signing.Verifier")
    try:
        stmt = _bp.verify_sealed_statement(
            sealed, expected_artifact_hex=expected_artifact_hex,
            verifier=verifier)
    except _bp.ProvenanceError as exc:
        raise ProvenanceVerifierError(
            "double-build statement failed verification: %s" % exc)
    if not callable(rebuilder):
        raise ProvenanceVerifierError("rebuilder must be callable")
    checked, unchecked = [], []
    for inp in stmt.inputs:
        if not inp.deterministic:
            unchecked.append(inp.name)
            continue
        first = rebuilder(inp.name)
        second = rebuilder(inp.name)
        for got in (first, second):
            if not isinstance(got, str):
                raise ProvenanceVerifierError(
                    "rebuilder must return hex digests")
        if first != second:
            raise ProvenanceVerifierError(
                "double-build lie: input %r claimed deterministic but "
                "two rebuilds disagree (%s vs %s)"
                % (inp.name, first, second))
        if first != inp.digest_hex:
            raise ProvenanceVerifierError(
                "reproducibility lie: input %r claimed digest %s, "
                "rebuild produced %s"
                % (inp.name, inp.digest_hex, first))
        checked.append(inp.name)
    return {"checked": checked, "unchecked": unchecked}


def verify_prebuilt(name, digest_hex, sealed, verifier):
    """Signed binary substitution: a prebuilt artifact is accepted only
    under a verified sealed statement. Unsigned prebuilts (sealed is
    None) and digest mismatches are refused loudly."""
    _check_name(name, "prebuilt")
    _check_hex_digest(digest_hex, "prebuilt %r" % name)
    if sealed is None:
        raise ProvenanceVerifierError(
            "prebuilt %r: no provenance statement -- unsigned prebuilts "
            "are refused" % name)
    if not isinstance(verifier, Verifier):
        raise ProvenanceVerifierError("verifier must be a "
                                      "gov.signing.Verifier")
    # verify_sealed_statement enforces the signature AND the artifact
    # binding (statement pins exactly the claimed digest).
    try:
        return _bp.verify_sealed_statement(
            sealed, expected_artifact_hex=digest_hex, verifier=verifier)
    except _bp.ProvenanceError as exc:
        raise ProvenanceVerifierError(
            "prebuilt %r failed verification: %s" % (name, exc))
