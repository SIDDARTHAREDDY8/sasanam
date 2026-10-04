"""Mandatory claim-bounds schema for evidence bundles.

The narrow-claims discipline appears independently in three sources
prospected in wave-207:

- W3C Verifiable Credentials Data Model 2.0: "verifiability of a
  credential does not imply the truth of claims encoded therein";
- IETF SCITT (RFC 9943): receipts prove action / principal / policy /
  verdict -- explicitly NOT that the content is "correct, safe, or
  wise";
- TEE attestation (SEV-SNP / TDX): a report proves platform + image,
  never workload behavior.

This module makes that discipline a MANDATORY primitive: every
evidence bundle must declare claim bounds, and the offline verifier
refuses boundless or overstated bundles. Overstating a claim is a
closure-level violation -- cf. F205, where an uncheckable inclusion
proof silently failed on every promoted leaf: the receipt *looked*
like proof and was not. A bound that is not checked is decoration;
a claim that is not bounded is an overstatement.

Schema (exact four keys; unknown keys are refused):
    {"proves": [...], "does_not_prove": [...],
     "verifier_assumptions": [...], "scope_limits": [...]}

All four are non-empty lists of non-empty strings. ``does_not_prove``
may never be empty: a bundle claiming nothing is outside its proof is
a degenerate honesty dodge, not humility. ``proves`` and
``does_not_prove`` must be disjoint: a bundle that both proves and
disproves the same claim is incoherent. No list may contain
duplicates.

The overlap check (``claims_within_bounds``) is a simple explicit
token-membership test, not NLP: every claim token asserted by a piece
of evidence must be an exact member of ``proves``. A token outside
``proves`` is refused with the token named.

For the offline evidence bundle, the "evidence" is the payload
sections themselves. The per-section assignment
(``{section_name: [claim tokens]}``) is validated by
``validate_claim_assignment``: its keys must be EXACTLY the payload's
evidence sections (no missing section, no extra section -- a claim
surface with no assignment is a smuggled claim), and every token must
be in ``proves``.

Bridges: ``from_vc_bounds`` maps W3C-VC-shaped ``claimBounds``
(``proves`` / ``doesNotProve``) onto the canonical schema and validates
it through ``validate_bounds`` -- one primitive, every evidence shape.
A consistently dishonest issuer (declaring broad ``proves`` AND broad
per-section claims) is NOT detectable by the overlap check: token
membership cannot catch an issuer that lies consistently. The defense
is the auditor reading the declared bounds -- which is why boundless
bundles are refused and ``does_not_prove`` may never be empty.

stdlib-only. Fail closed: the single error vocabulary is
``ClaimBoundsError``; nothing is defaulted silently.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

#: Exact schema keys. A bounds dict with any other top-level key is
#: refused -- an auditor must never silently ignore a bound it does
#: not understand.
REQUIRED_FIELDS = ("proves", "does_not_prove", "verifier_assumptions",
                   "scope_limits")


class ClaimBoundsError(Exception):
    """Single fail-closed vocabulary for claim-bounds violations."""


def _check_token_list(value, where):
    if not isinstance(value, list) or not value:
        raise ClaimBoundsError(
            "%s: must be a non-empty list of non-empty str" % where)
    for i, tok in enumerate(value):
        if not isinstance(tok, str) or not tok:
            raise ClaimBoundsError(
                "%s[%d]: must be a non-empty str" % (where, i))
    if len(set(value)) != len(value):
        dupes = sorted({t for t in value if value.count(t) > 1})
        raise ClaimBoundsError(
            "%s: duplicate claim token(s) refused: %s" % (where, dupes))
    return list(value)


def validate_bounds(bounds, where="claim_bounds"):
    """Validate a claim-bounds dict. Returns a normalized deep copy.

    Raises ClaimBoundsError naming the offending field when the dict
    is missing, misshapen, has an empty ``does_not_prove``, lists a
    token in both ``proves`` and ``does_not_prove``, carries duplicates,
    or carries unknown keys.
    """
    if not isinstance(bounds, dict):
        raise ClaimBoundsError(
            "%s: must be a dict, got %s" % (where, type(bounds).__name__))
    extra = sorted(set(bounds) - set(REQUIRED_FIELDS))
    if extra:
        raise ClaimBoundsError(
            "%s: unknown field(s) refused: %s" % (where, extra))
    missing = [f for f in REQUIRED_FIELDS if f not in bounds]
    if missing:
        raise ClaimBoundsError(
            "%s: missing required field(s): %s" % (where, missing))
    proves = _check_token_list(bounds["proves"], where + ".proves")
    does_not = _check_token_list(bounds["does_not_prove"],
                                 where + ".does_not_prove")
    assumptions = _check_token_list(bounds["verifier_assumptions"],
                                    where + ".verifier_assumptions")
    scope = _check_token_list(bounds["scope_limits"], where + ".scope_limits")
    incoherent = sorted(set(proves) & set(does_not))
    if incoherent:
        raise ClaimBoundsError(
            "%s: token(s) in both proves and does_not_prove (incoherent): "
            "%s" % (where, incoherent))
    return {"proves": proves, "does_not_prove": does_not,
            "verifier_assumptions": assumptions, "scope_limits": scope}


def claims_within_bounds(where, claims, proves):
    """Overlap check: every claim token must be an exact member of
    ``proves``. Raises ClaimBoundsError naming the stray token(s).
    This is token membership, not NLP -- the issuer declares its
    claims in the shared vocabulary; the verifier does not interpret
    prose.
    """
    if not isinstance(claims, list):
        raise ClaimBoundsError(
            "%s: claims must be a list, got %s"
            % (where, type(claims).__name__))
    allowed = set(proves)
    stray = [c for c in claims if c not in allowed]
    if stray:
        raise ClaimBoundsError(
            "%s: evidence claim(s) broader than proves refused: %s"
            % (where, sorted(set(stray))))
    return None


def validate_claim_assignment(assignment, section_names, proves,
                              where="claim_assignment"):
    """Validate the per-section claim assignment.

    ``assignment`` maps section name -> list of claim tokens.
    Keys must be EXACTLY ``section_names``: a missing section hides a
    claim surface; an extra section smuggles one. Every token must be
    in ``proves`` (via ``claims_within_bounds``).
    """
    if not isinstance(assignment, dict):
        raise ClaimBoundsError(
            "%s: must be a dict, got %s"
            % (where, type(assignment).__name__))
    expected = set(section_names)
    got = set(assignment)
    if got != expected:
        missing = sorted(expected - got)
        extra = sorted(got - expected)
        raise ClaimBoundsError(
            "%s: section set mismatch: missing %s, extra %s"
            % (where, missing, extra))
    for section in sorted(assignment):
        claims = assignment[section]
        if not isinstance(claims, list) or not claims:
            raise ClaimBoundsError(
                "%s.%s: must be a non-empty list of claim tokens"
                % (where, section))
        for i, tok in enumerate(claims):
            if not isinstance(tok, str) or not tok:
                raise ClaimBoundsError(
                    "%s.%s[%d]: must be a non-empty str" % (where, section, i))
        claims_within_bounds("%s.%s" % (where, section), claims, proves)
    return None


# ---------------------------------------------------------------- defaults
# The canonical v1 honesty statement for offline evidence bundles,
# derived from the verifier's normative HONESTY_FOOTER
# (docs/evidence-bundle-spec.md section 7): recorded events only,
# integrity is not truth, key custody is claimed not proven,
# timestamps are operator wall-clock, unpinned bundles prove
# self-consistency only.

_DEFAULT_PROVES = [
    "bundle-digest-integrity",
    "bundle-identity-deterministic",
    "recorded-events-integrity",
    "event-inclusion",
    "sequence-continuity",
    "policy-consistency",
    "decision-record-integrity",
    "approval-consistency",
    "citation-consistency",
    "benchmark-verdict-integrity",
    "kms-attestation-integrity",
    "retention-schema-validity",
    "discovery-snapshot-integrity",
    "discovery-absence-recorded",
    "operator-authorship-pinned",
    "receipt-chain-integrity",
]

_DEFAULT_DOES_NOT_PROVE = [
    "truth-of-recorded-events",
    "unrecorded-actions",
    "key-custody",
    "wall-clock-accuracy",
    "authorship-without-pin",
    "citation-truth",
    "operator-assertion-truth",
    "live-transparency-anchoring",
    "regulator-acceptance",
]

_DEFAULT_ASSUMPTIONS = [
    "operator-key-pin-supplied-out-of-band",
    "verifier-executes-in-trusted-environment",
    "stdlib-crypto-implementation-correct",
]

_DEFAULT_SCOPE = [
    "single-tenant",
    "window-limited-to-transported-seq-range",
    "v1-extension-checks-are-non-normative",
]

#: Per-section claim assignment for the nine evidence-bundle payload
#: sections. ``discovery`` takes one of two tokens depending on whether
#: a discovery ledger was supplied.
_DEFAULT_SECTION_CLAIMS = {
    "bundle_meta": ["bundle-identity-deterministic",
                    "operator-authorship-pinned",
                    "receipt-chain-integrity",
                    "bundle-digest-integrity"],
    "log_slice": ["recorded-events-integrity", "event-inclusion",
                  "sequence-continuity"],
    "policy": ["policy-consistency"],
    "decisions": ["decision-record-integrity"],
    "approvals": ["approval-consistency"],
    "citations": ["citation-consistency"],
    "benchmark": ["benchmark-verdict-integrity"],
    "kms_attestation": ["kms-attestation-integrity"],
    "retention_manifest": ["retention-schema-validity"],
}


def default_bundle_bounds(where="claim_bounds"):
    """The canonical v1 honesty statement. The four bound lists are
    fixed by the v1 honesty contract, not by the window contents."""
    bounds = {"proves": list(_DEFAULT_PROVES),
              "does_not_prove": list(_DEFAULT_DOES_NOT_PROVE),
              "verifier_assumptions": list(_DEFAULT_ASSUMPTIONS),
              "scope_limits": list(_DEFAULT_SCOPE)}
    return validate_bounds(bounds, where=where)


def default_claim_assignment(section_names, proves, *, discovery_present,
                             extra_section_claims=None,
                             where="claim_assignment"):
    """Per-section claim tokens for the given payload sections. Every
    returned token is drawn from ``proves`` by construction; the
    verifier re-checks membership anyway (never trust the generator).
    Unknown sections are refused -- the assignment vocabulary is
    closed: a new section needs an explicit token allocation, not a
    silent pass. ``extra_section_claims`` (wave-318 lane 2) extends the
    allocation map additively for schema extensions; the v1 map is
    untouched when it is None.
    """
    section_claims = dict(_DEFAULT_SECTION_CLAIMS)
    if extra_section_claims:
        for section, tokens in extra_section_claims.items():
            if section in section_claims:
                raise ClaimBoundsError(
                    "%s: extra allocation for known section %r refused "
                    "(the v1 contract is immutable)" % (where, section))
            section_claims[section] = list(tokens)
    assignment = {}
    for section in section_names:
        if section == "discovery":
            token = ("discovery-snapshot-integrity" if discovery_present
                     else "discovery-absence-recorded")
            assignment[section] = [token]
        elif section in section_claims:
            assignment[section] = list(section_claims[section])
        else:
            raise ClaimBoundsError(
                "%s: no claim allocation for section %r -- allocate "
                "tokens explicitly before issuing" % (where, section))
    # Defense in depth: the generator's own output must satisfy the
    # verifier's rule.
    validate_claim_assignment(assignment, section_names, proves, where=where)
    return assignment


# ---------------------------------------------------------------- bridges

#: Canonical assumptions/scope inherited by VC-shaped credentials: the
#: VC profile reuses the bundle-level verifier contract.
_VC_INHERITED_ASSUMPTIONS = list(_DEFAULT_ASSUMPTIONS)
_VC_INHERITED_SCOPE = list(_DEFAULT_SCOPE)


def from_vc_bounds(vc_bounds, where="claim_bounds"):
    """Bridge a W3C-VC-shaped ``claimBounds`` (``proves`` /
    ``doesNotProve``) onto the canonical schema. The VC profile does
    not carry verifier assumptions or scope limits of its own; it
    inherits the canonical ones -- stated explicitly in the returned
    dict, never silently. Validates through ``validate_bounds``.
    """
    if not isinstance(vc_bounds, dict):
        raise ClaimBoundsError(
            "%s: VC claimBounds must be a dict, got %s"
            % (where, type(vc_bounds).__name__))
    proves = vc_bounds.get("proves")
    does_not = vc_bounds.get("doesNotProve")
    canon = {"proves": proves, "does_not_prove": does_not,
             "verifier_assumptions": list(_VC_INHERITED_ASSUMPTIONS),
             "scope_limits": list(_VC_INHERITED_SCOPE)}
    return validate_bounds(canon, where=where)
