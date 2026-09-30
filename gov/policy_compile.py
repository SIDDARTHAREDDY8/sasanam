"""Compile-policy-once front gate for the policy stack.

STEAL (idea only, Apache-2.0, no upstream source vendored) from
sigstore/policy-controller (read 2026-09-29, wave-216 prospecting):
the **compile-policy-once** discipline -- AUTHORING ERRORS fail at
compile time, and one compiled verifier serves many artifacts. Two
concrete rules:

1. ``compile_policy(spec)`` validates the WHOLE policy ONCE and
   returns a compiled verifier object. Unknown keys, empty
   combinators, malformed predicates, and unresolvable references
   all raise at compile. Evaluation against many artifacts/claims
   uses the compiled form with zero re-parsing.
2. Evaluation can never raise an authoring-error class. This is
   true BY CONSTRUCTION: the compiled objects' evaluation paths
   contain no authoring validation at all -- they operate only on
   the pre-validated, normalized form. Garbage *data* at evaluation
   time is still refused loudly (a ``ValueError``), but it is a data
   error, never an authoring error.

Coverage: ``gov.identity_policy`` (wave-215, per-certificate
identity-policy DSL) and ``gov.artifact_rules`` (wave-212, in-toto
style CREATE/MODIFY/DELETE/REQUIRE/MATCH/DISALLOW). ``identity_policy``
already parses at load time; ``artifact_rules`` re-ran ``load_rules``
on every ``verify_artifacts`` call -- this module closes that gap via
``gov.artifact_rules._evaluate`` (extracted, behavior-identical; see
that module's docstring).

The compile step is a FRONT GATE, never a re-interpretation: a
compiled ruleset's report is byte-identical to the legacy
``verify_artifacts`` report on the same inputs (pinned by battery),
and a compiled identity policy delegates to the same ``verify()``.

``fingerprint()`` gives the deployment a stable sha256 pin over the
compiled form (canonical rules / canonical policy description), so
an operator can assert "the exact policy I audited" before serving
traffic.

Stdlib only. $0 spend. Synthetic/local testing.
"""

from __future__ import annotations

import hashlib
import json

from gov import artifact_rules as _ar
from gov import identity_policy as _ip

__all__ = [
    "CompiledArtifactRuleset",
    "CompiledIdentityPolicy",
    "CompiledPolicy",
    "compile_policy",
]

def _digest_canonical(obj):
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class CompiledPolicy(object):
    """Base: a compiled policy. ``fingerprint()`` is the deployment
    pin; ``evaluate`` can never raise an authoring-error class."""

    def fingerprint(self):
        raise NotImplementedError

    def evaluate(self, *args, **kwargs):
        raise NotImplementedError


class CompiledIdentityPolicy(CompiledPolicy):
    """A compiled identity-policy DSL policy.

    ``spec`` is either a plain-data spec dict (exactly one predicate
    key -- see ``gov.identity_policy.parse_policy``) or an already
    constructed ``identity_policy.Policy`` (whose constructors refused
    every authoring error at build time). All authoring validation is
    DONE -- ``verify(claims)`` and ``admit(claims)`` evaluate only.
    """

    def __init__(self, policy):
        if not isinstance(policy, _ip.Policy):
            raise _ip.PolicyAuthoringError(
                "compiled identity policy requires an "
                "identity_policy.Policy instance")
        self._policy = policy

    def fingerprint(self):
        return _digest_canonical({"identity_policy": self._policy.describe()})

    def verify(self, claims):
        """Evaluate identity claims. Returns a PolicyVerdict; never
        raises PolicyAuthoringError -- the policy was fully validated
        at compile."""
        return self._policy.verify(claims)

    def admit(self, claims):
        """Fail-closed admission: report dict on pass, PolicyViolation
        on fail/error -- same contract as
        ``identity_policy.check_admission``."""
        verdict = self.verify(claims)
        if verdict.verdict == "pass":
            return {"verdict": "pass", "code": verdict.code,
                    "vacuous": verdict.vacuous,
                    "policy": self._policy.describe(),
                    "fingerprint": self.fingerprint()}
        raise _ip.PolicyViolation(verdict.code, verdict.detail)

    # The evaluation path has no spec/predicate parameter: there is no
    # way to smuggle an unvalidated policy shape through verify/admit.
    # ``policy`` is intentionally NOT exposed as a settable attribute.


class CompiledArtifactRuleset(CompiledPolicy):
    """A compiled artifact ruleset.

    ``rules`` are the normalized output of ``artifact_rules.load_rules``
    (or raw rule-spec tuples -- compiled once here). ``evaluate``
    takes ONLY artifact maps: there is no rule_specs parameter, so a
    caller cannot re-introduce unvalidated rule shapes at evaluation
    time. Evaluation is ``_evaluate`` -- the exact core
    ``verify_artifacts`` uses -- so reports are identical to legacy.
    """

    def __init__(self, rules):
        if isinstance(rules, (list, tuple)) and rules and \
                isinstance(rules[0], tuple):
            # Raw specs: validate once, here, at compile.
            self._rules = _ar.load_rules(rules)
        elif isinstance(rules, tuple) and all(
                isinstance(r, tuple) and r and r[0] in _ar._RULE_KINDS
                for r in rules):
            # Already-normalized output of load_rules: re-validating is
            # free and keeps the invariant total -- malformed input
            # that merely LOOKS normalized is still refused here.
            self._rules = _ar.load_rules(rules)
        else:
            raise _ar.ArtifactRuleError(
                "compiled ruleset requires rule-spec tuples")
        self._fingerprint = _digest_canonical(
            {"artifact_rules": [list(r) for r in self._rules]})

    def fingerprint(self):
        return self._fingerprint

    def evaluate(self, materials, products, context=""):
        """Evaluate artifact maps against the compiled ruleset. Raises
        ArtifactRuleError only on artifact DATA problems or rule
        violations -- never on a rule authoring problem (those were
        refused at compile)."""
        materials = _ar._check_artifact_map(materials, "materials")
        products = _ar._check_artifact_map(products, "products")
        return _ar._evaluate(materials, products, self._rules, context)


def compile_policy(spec):
    """Validate a policy ONCE and return a compiled verifier.

    Dispatch (all authoring errors raised HERE, never at evaluation):
    * plain-data dict with exactly one predicate key, or an
      ``identity_policy.Policy`` instance
      -> :class:`CompiledIdentityPolicy`
    * sequence of artifact rule-spec tuples (or normalized
      ``load_rules`` output)
      -> :class:`CompiledArtifactRuleset`
    * anything else -> ``PolicyAuthoringError``
    """
    if isinstance(spec, _ip.Policy):
        return CompiledIdentityPolicy(spec)
    if isinstance(spec, dict) and not isinstance(spec, bool) \
            and len(spec) == 1:
        return CompiledIdentityPolicy(_ip.parse_policy(spec))
    if isinstance(spec, (list, tuple)) and spec:
        return CompiledArtifactRuleset(spec)
    raise _ip.PolicyAuthoringError(
        "compile_policy: unrecognized policy spec %r -- expected an "
        "identity-policy spec dict / Policy, or artifact rule tuples"
        % (type(spec).__name__,))
