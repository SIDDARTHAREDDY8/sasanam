"""Promotion-gate wiring for ``gov.artifact_rules`` (wave-213 lane B).

``gov/artifact_rules.py`` landed in wave-212 as an intentionally
UNINTEGRATED verifier: it checks raw (name -> sha256 digest)
material/product maps against an in-toto-style six-rule grammar
(CREATE / MODIFY / DELETE / REQUIRE / MATCH / terminal DISALLOW).
This module wires that verifier into the one admission decision whose
seam already produces (materials, products) claims: the
staging -> enforced **promotion ceremony** in
``gov.sign_deploy_namespaces.NamespaceRegistry.promote()``.

Seam discipline (do not mix):
- ``gov.provenance_verifier`` stays NARROW -- REQUIRE/MATCH/DISALLOW
  over digest-bound SEALED ProvenanceStatement records. Its
  anti-swap authority is the name->statement binding, not raw maps.
- This gate stays GENERAL -- the full six-rule grammar over raw
  caller-supplied (materials, products) maps. The two engines share
  the fail-closed discipline, never the seam.

Tighten-only contract:
- The gate can only DENY a promotion the legacy path would have
  admitted. Every check the legacy path performed (bundle known,
  two-operator ceremony, fresh signature at threshold) runs FIRST,
  unchanged; the artifact gate runs only after all of them passed.
- Without a configured ruleset the legacy path is byte-identical:
  no new kwargs are required, no audit detail changes.
- With a configured ruleset, a missing or malformed
  (materials, products) map DENIES (fail closed) rather than silently
  skipping the gate -- skipping would widen the admit path back to
  legacy.
- A ruleset is validated at POLICY-LOAD time by
  ``load_promotion_rules`` (the terminal-DISALLOW lint from
  ``artifact_rules.load_rules``: no terminal DISALLOW, no implicit
  ALLOW * -- the set is refused before any artifact is examined).

Denial surfacing: ``check_promotion_artifacts`` raises
``ArtifactRuleError`` loudly (a ValueError, matching the sibling
modules); the caller (``NamespaceRegistry.promote``) converts it to a
``NamespaceError`` with code ``artifact-gate-refused`` and writes a
``promotion-denied`` entry carrying the violation into the
hash-chained audit log.

Honest residuals:
- The (materials, products) maps are caller-supplied claims; the gate
  verifies that the RULES account for the CLAIMED artifacts, not that
  the build step really consumed/emitted them. Artifact reality is
  the caller's responsibility (the same posture the unintegrated
  module documents).
- Digests are sha256 hex only; other digest types are refused rather
  than coerced.

Stdlib only. $0 spend. Synthetic/local testing.
"""

from .artifact_rules import (
    ArtifactRuleError,
    load_rules,
    verify_artifacts,
)

__all__ = [
    "ArtifactRuleError",
    "load_promotion_rules",
    "check_promotion_artifacts",
]


def load_promotion_rules(rule_specs):
    """Validate a promotion ruleset at policy-load time, fail-closed.

    Delegates to ``artifact_rules.load_rules``: the set is refused
    unless it ends with EXACTLY one terminal DISALLOW (the
    "DISALLOW *" discipline -- anything left unconsumed is refused,
    there is NO implicit ALLOW *). Returns the normalized rules as a
    tuple, ready to hand to ``check_promotion_artifacts`` or to
    ``NamespaceRegistry(artifact_ruleset=...)``.
    """
    return load_rules(rule_specs)


def check_promotion_artifacts(name, materials, products, rules):
    """Evaluate the promotion artifact gate for one bundle.

    ``name``: the bundle name being promoted (context label).
    ``materials`` / ``products``: dicts mapping artifact name ->
    sha256 hex digest, supplied by the caller promoting the bundle.
    ``rules``: a ruleset already validated by
    ``load_promotion_rules`` (re-validation is cheap and harmless if
    raw specs are passed).

    Returns the ``verify_artifacts`` audit report dict on success
    (``rule_set_digest`` is the pinned evidence of what was
    enforced). Raises ``ArtifactRuleError`` loudly on any violation,
    including absent maps when the gate is active (fail closed).
    """
    if materials is None or products is None:
        raise ArtifactRuleError(
            "promotion gate: materials and products maps are required "
            "when a ruleset is configured (fail closed -- refusing to "
            "skip the gate for bundle %r)" % (name,))
    return verify_artifacts(materials, products, rules,
                            context="promotion:%s" % name)
