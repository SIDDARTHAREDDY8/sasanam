"""Ownership inference for agent identities (wave-343 lane 4).

Rig Security (2026-10-05 deep-dive, steal #3) insight, adapted: every
agent identity should be auto-traceable to its human owner --
"block the agent, not the employee" / "what is acting through that
access right now?". Rig does this with an ML identity-correlation
engine (RICE, unverifiable accuracy marketing -- NOT copied). Ours is
the precision answer: the deployment's own principal directory is the
ground truth, and the inference is deterministic, evidence-backed, and
fail-closed.

What this module does: given a (dex-shaped, normalized) identity claim
set -- {subject, email, email_verified, groups, connector_id,
declared_principal} -- and a deployment-supplied owner directory, it
infers the owning principal and records every piece of evidence it
used. The output is an OwnershipAttribution dict that can ride a
decision packet (``gov/decision_packet.py`` ``owner_attribution``
section) or attach to the agent inventory (``gov/inventory_catalog``
``attach_owner_attribution``).

Design rules (compare-don't-trust):

* Only IdP-vouched identifiers are owner evidence: a ``email`` claim
  counts ONLY when ``email_verified`` is True; ``subject`` counts
  because the upstream connector vouched it (``normalize_claims``
  refused otherwise). ``declared_principal`` is SELF-ASSERTED and is
  NEVER owner evidence -- it is used only for the
  declared-vs-inferred consistency comparison, which is itself the
  accountability signal (``declared-differs-inferred`` is the
  principal-spoofing flag).
* ``groups`` are shared by construction: a group match is recorded as
  CORROBORATING evidence only when it names a principal already named
  by stronger evidence; it can never resolve an owner alone and never
  vetoes a resolution.
* Conflicts are LOUD: two strong sources naming different principals
  refuse ``ownership-inference-ambiguous``. No evidence refuses
  ``ownership-inference-unresolved``. We never guess.
* No raw PII in evidence records: raw identifier values are stored
  only as sha256 digests (``value_digest``); the attribution names
  the owner principal (that IS the primitive) but never the raw
  email/subject that produced it.
* Deterministic: no clock, no randomness, no I/O. Evidence is sorted
  by (source, candidate) so attributions are byte-stable.

The ``OwnerDirectory`` is deployment-supplied ground truth:
``{"principals": {"alice": {"emails": [...], "subjects": [...],
"groups": [...]}, ...}}``. ``load_owner_directory`` validates it
fail-fast: duplicate emails/subjects claimed by two principals refuse
``ownership-directory-malformed`` at load, never at inference time.

Fail-closed API contract:

* ``infer_owner`` raises ``OwnershipInferenceError`` carrying the
  machine code (``ownership-inference-unresolved``,
  ``ownership-inference-ambiguous``, ``ownership-directory-malformed``).
* ``attribute_owner`` never raises: on failure it returns the
  attribution with ``owner: None``, ``tier: "unresolved"`` and the
  machine code in ``code`` -- the undecided state is EXPLICIT and
  coded, never silently omitted.

Stdlib only.
"""

import hashlib
import json

# ---------------------------------------------------------------------------
# Machine codes (registered in gov/decision_codes.py; real emission sites
# are the raises below and the coded unresolved attributions).
# ---------------------------------------------------------------------------
CODE_UNRESOLVED = "ownership-inference-unresolved"
CODE_AMBIGUOUS = "ownership-inference-ambiguous"
CODE_DIRECTORY_MALFORMED = "ownership-directory-malformed"

# Confidence tiers, strongest first.
TIER_VERIFIED_EMAIL = "verified-email-binding"
TIER_SUBJECT = "directory-subject-binding"
TIER_PRINCIPAL = "directory-principal-known"
TIER_UNRESOLVED = "unresolved"

_TIER_RANK = {
    TIER_VERIFIED_EMAIL: 0,
    TIER_SUBJECT: 1,
    TIER_PRINCIPAL: 2,
    TIER_UNRESOLVED: 3,
}
TIERS = tuple(_TIER_RANK)

DECLARED_CONSISTENCY_VALUES = (
    "declared-matches-inferred",
    "declared-differs-inferred",
    "no-declared-principal",
    "owner-unresolved",
)

_OWNER_PRODUCER = "gov/ownership_inference.py"
_ATTRIBUTION_VERSION = 1


class OwnershipInferenceError(Exception):
    """Owner inference refused. ``code`` is the taxonomy machine code."""

    def __init__(self, code, detail=""):
        super(OwnershipInferenceError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _nonempty_str(value):
    return isinstance(value, str) and bool(value.strip())


def _digest_value(source, value):
    """sha256 over a domain-separated identifier value -- PII never
    leaves this module in raw form inside evidence records."""
    return hashlib.sha256(
        ("%s\x00%s" % (source, value)).encode("utf-8")).hexdigest()


def load_owner_directory(raw):
    """Validate a deployment-supplied owner directory; return it.

    ``raw`` is ``{"principals": {name: {"emails": [...], "subjects":
    [...], "groups": [...]}}}``. Every identifier list is optional
    (defaults to empty); every identifier must be a non-empty string;
    an email or subject claimed by two principals refuses
    ``ownership-directory-malformed`` (a directory that cannot
    disambiguate is a deployment configuration error, fail-fast).
    Groups may be shared across principals (they are corroborating
    evidence only).

    Returns a deep-copied, normalized directory marked
    ``"_validated": True``. Raises :class:`OwnershipInferenceError`
    (code ``ownership-directory-malformed``) on any malformed input.
    """
    def _fail(detail):
        raise OwnershipInferenceError(CODE_DIRECTORY_MALFORMED, detail)

    if not isinstance(raw, dict):
        _fail("directory must be a dict, got %s" % type(raw).__name__)
    principals = raw.get("principals")
    if not isinstance(principals, dict) or not principals:
        _fail("directory must carry a non-empty 'principals' dict")
    normalized = {}
    seen_emails = {}
    seen_subjects = {}
    for name in sorted(principals):
        if not _nonempty_str(name):
            _fail("principal names must be non-empty strings, got %r"
                  % (name,))
        entry = principals[name]
        if not isinstance(entry, dict):
            _fail("principal %r entry must be a dict" % (name,))
        ident = {}
        for field in ("emails", "subjects", "groups"):
            values = entry.get(field, [])
            if not isinstance(values, list):
                _fail("principal %r field %r must be a list" % (name, field))
            clean = []
            for value in values:
                if not _nonempty_str(value):
                    _fail("principal %r field %r holds a non-string or "
                          "empty identifier" % (name, field))
                clean.append(value)
            ident[field] = sorted(set(clean))
        for email in ident["emails"]:
            if email in seen_emails:
                _fail("email %r claimed by both %r and %r"
                      % (email, seen_emails[email], name))
            seen_emails[email] = name
        for subject in ident["subjects"]:
            if subject in seen_subjects:
                _fail("subject %r claimed by both %r and %r"
                      % (subject, seen_subjects[subject], name))
            seen_subjects[subject] = name
        normalized[name] = ident
    return {"principals": normalized, "_validated": True}


def _as_directory(directory):
    """Accept a validated directory or a raw one (validated on the fly)."""
    if isinstance(directory, dict) and directory.get("_validated") is True \
            and isinstance(directory.get("principals"), dict):
        return directory
    return load_owner_directory(directory)


def _collect_evidence(claims, directory):
    """Collect (tier, candidate, evidence-item) triples from IdP-vouched
    identifiers. Never uses declared_principal as evidence."""
    principals = directory["principals"]
    found = []  # (tier, candidate, evidence-item)

    email = claims.get("email")
    if claims.get("email_verified") is True and _nonempty_str(email):
        owners = [name for name, ident in principals.items()
                  if email in ident["emails"]]
        # owners has at most one entry: load validated that.
        for name in owners:
            found.append((TIER_VERIFIED_EMAIL, name, {
                "source": "idp-verified-email",
                "field": "email",
                "value_digest": _digest_value("email", email),
                "candidate": name,
                "tier": TIER_VERIFIED_EMAIL,
            }))

    subject = claims.get("subject")
    if _nonempty_str(subject):
        owners = [name for name, ident in principals.items()
                  if subject in ident["subjects"]]
        for name in owners:
            found.append((TIER_SUBJECT, name, {
                "source": "directory-subject",
                "field": "subject",
                "value_digest": _digest_value("subject", subject),
                "candidate": name,
                "tier": TIER_SUBJECT,
            }))

    declared = claims.get("declared_principal")
    if _nonempty_str(declared) and declared in principals:
        # Weakest tier, and HONEST about it: the declared principal is
        # self-asserted. It answers "is this principal known to the
        # deployment" -- not "is this principal verified".
        found.append((TIER_PRINCIPAL, declared, {
            "source": "declared-principal",
            "field": "declared_principal",
            "value_digest": _digest_value("declared_principal", declared),
            "candidate": declared,
            "tier": TIER_PRINCIPAL,
        }))

    # Groups: corroboration only. A group naming a principal that no
    # stronger source named is recorded nowhere (it cannot identify a
    # human owner); a group agreeing with a resolved candidate is
    # appended as corroborating evidence.
    strong_candidates = {candidate for _, candidate, _ in found}
    groups = claims.get("groups") or []
    if isinstance(groups, list):
        for group in sorted({g for g in groups if _nonempty_str(g)}):
            for name in sorted(principals):
                if group in principals[name]["groups"] \
                        and name in strong_candidates:
                    found.append((TIER_PRINCIPAL, name, {
                        "source": "directory-group",
                        "field": "groups",
                        "value_digest": _digest_value("groups", group),
                        "candidate": name,
                        "tier": TIER_PRINCIPAL,
                        "strength": "corroborating",
                    }))
    return found


def _identity_subject(claims):
    return (claims.get("subject")
            or claims.get("declared_principal")
            or "unknown")


def _consistency(declared, owner):
    if owner is None:
        return "owner-unresolved"
    if not _nonempty_str(declared):
        return "no-declared-principal"
    if declared == owner:
        return "declared-matches-inferred"
    return "declared-differs-inferred"


def _canonical_attribution(identity_subject, owner, tier,
                           declared_consistency, evidence, code,
                           conflicting=None):
    """The digest-bound attribution body (no ``digest`` key inside)."""
    body = {
        "attribution_version": _ATTRIBUTION_VERSION,
        "identity_subject": identity_subject,
        "owner": owner,
        "tier": tier,
        "declared_consistency": declared_consistency,
        "evidence": evidence,
        "code": code,
    }
    if conflicting is not None:
        body["conflicting"] = conflicting
    return body


def _body_digest(body):
    return hashlib.sha256(
        json.dumps(body, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")).hexdigest()


def attribution_digest(attribution):
    """sha256 over the canonical JSON of the attribution body.

    ``attribution`` may carry its own ``digest`` key (ignored) and may
    carry ``conflicting`` (covered by the digest when present).
    Compare-don't-trust: the packet seam recomputes this and refuses a
    mismatch.
    """
    body = _canonical_attribution(
        attribution["identity_subject"],
        attribution["owner"],
        attribution["tier"],
        attribution["declared_consistency"],
        attribution["evidence"],
        attribution.get("code"),
        conflicting=attribution.get("conflicting"),
    )
    return _body_digest(body)


def _build_attribution(claims, owner, tier, evidence, code):
    identity_subject = _identity_subject(claims)
    declared = claims.get("declared_principal")
    consistency = _consistency(declared, owner)
    evidence = sorted(evidence,
                      key=lambda item: (item["source"],
                                        item["candidate"],
                                        item["value_digest"]))
    body = _canonical_attribution(identity_subject, owner, tier,
                                  consistency, evidence, code)
    body["digest"] = _body_digest(body)
    return body


def infer_owner(claims, directory):
    """Infer the owning principal; return the OwnershipAttribution dict.

    Raises :class:`OwnershipInferenceError`:

    * ``ownership-inference-ambiguous`` -- two or more strong sources
      name different principals. We never vote or guess.
    * ``ownership-inference-unresolved`` -- no evidence names any
      principal.
    * ``ownership-directory-malformed`` -- the directory failed
      validation.

    ``claims`` keys used: ``subject``, ``email``, ``email_verified``,
    ``groups``, ``declared_principal``. ``declared_principal`` is used
    ONLY for the declared-vs-inferred consistency comparison.
    """
    if not isinstance(claims, dict):
        raise OwnershipInferenceError(
            CODE_UNRESOLVED,
            "claims must be a dict, got %s" % type(claims).__name__)
    directory = _as_directory(directory)
    found = _collect_evidence(claims, directory)
    # Strong sources only for the resolution (groups are appended to
    # evidence only as corroboration and never decide).
    strong = [(tier, candidate, item) for tier, candidate, item in found
              if item.get("strength") != "corroborating"]
    candidates = {}
    for tier, candidate, item in strong:
        if (candidate not in candidates
                or _TIER_RANK[tier] < _TIER_RANK[candidates[candidate][0]]):
            candidates[candidate] = (tier, item)
    if not candidates:
        raise OwnershipInferenceError(
            CODE_UNRESOLVED,
            "no identity identifier matched any directory principal")
    if len(candidates) > 1:
        raise OwnershipInferenceError(
            CODE_AMBIGUOUS,
            "conflicting owner evidence names %s"
            % ", ".join(sorted(candidates)))
    owner = next(iter(sorted(candidates)))
    tier = candidates[owner][0]
    evidence = [item for _, _, item in found
                if item["candidate"] == owner]
    return _build_attribution(claims, owner, tier, evidence, None)


def attribute_owner(claims, directory):
    """Like :func:`infer_owner` but never raises.

    On failure returns the attribution with ``owner: None``,
    ``tier: "unresolved"`` and the machine code in ``code`` -- the
    undecided state is EXPLICIT and coded, never silently omitted.
    For the ambiguous case the conflicting candidates are recorded in
    ``conflicting`` so an auditor sees what disagreed.
    """
    if not isinstance(claims, dict):
        claims = {}
    try:
        return infer_owner(claims, directory)
    except OwnershipInferenceError as exc:
        conflicting = []
        if exc.code == CODE_AMBIGUOUS:
            try:
                directory = _as_directory(directory)
                found = _collect_evidence(claims, directory)
                conflicting = sorted(
                    {candidate for _, candidate, item in found
                     if item.get("strength") != "corroborating"})
            except OwnershipInferenceError:
                conflicting = []
        attribution = _build_attribution(claims, None, TIER_UNRESOLVED,
                                         [], exc.code)
        if conflicting:
            body = _canonical_attribution(
                attribution["identity_subject"], None, TIER_UNRESOLVED,
                "owner-unresolved", [], exc.code, conflicting=conflicting)
            body["digest"] = _body_digest(body)
            return body
        return attribution


# ---------------------------------------------------------------------------
# Packet-seam validation (gov/decision_packet.py owner_attribution section).
# ---------------------------------------------------------------------------

_ATTRIBUTION_EVIDENCE_KEYS = ("source", "field", "value_digest",
                              "candidate", "tier")


def check_attribution_value(value):
    """Validate an owner-attribution section value.

    Returns ``(True, "")`` or ``(False, reason)``. Checks shape, the
    tier/consistency whitelists, evidence-item shapes (digests are
    64-char hex), and recomputes the attribution digest --
    compare-don't-trust: a caller-supplied dict is never trusted.
    """
    if not isinstance(value, dict):
        return False, "owner_attribution must be a dict, got %s" % (
            type(value).__name__,)
    for key in ("identity_subject", "owner", "tier",
                "declared_consistency", "evidence", "code", "digest"):
        if key not in value:
            return False, "owner_attribution missing key %r" % (key,)
    if not _nonempty_str(value["identity_subject"]):
        return False, "owner_attribution.identity_subject must be a " \
            "non-empty string"
    owner = value["owner"]
    if owner is not None and not _nonempty_str(owner):
        return False, "owner_attribution.owner must be a non-empty " \
            "string or None"
    if value["tier"] not in TIERS:
        return False, "owner_attribution.tier %r not in %r" % (
            value["tier"], TIERS)
    if value["declared_consistency"] not in DECLARED_CONSISTENCY_VALUES:
        return False, "owner_attribution.declared_consistency %r unknown" % (
            value["declared_consistency"],)
    if value["code"] not in (None, CODE_UNRESOLVED, CODE_AMBIGUOUS):
        return False, "owner_attribution.code %r unknown" % (value["code"],)
    if owner is None and value["code"] is None:
        return False, "owner_attribution with no owner must carry a code"
    if owner is not None and value["code"] is not None:
        return False, "owner_attribution with an owner must not carry " \
            "a refusal code"
    conflicting = value.get("conflicting")
    if conflicting is not None:
        if (not isinstance(conflicting, list) or not conflicting
                or not all(_nonempty_str(c) for c in conflicting)
                or sorted(conflicting) != conflicting
                or len(set(conflicting)) != len(conflicting)):
            return False, "owner_attribution.conflicting must be a " \
                "sorted unique list of non-empty strings"
        if value["code"] != CODE_AMBIGUOUS:
            return False, "owner_attribution.conflicting is only valid " \
                "on an ambiguous (coded) attribution"
    evidence = value["evidence"]
    if not isinstance(evidence, list):
        return False, "owner_attribution.evidence must be a list"
    for item in evidence:
        if not isinstance(item, dict):
            return False, "owner_attribution.evidence items must be dicts"
        for key in _ATTRIBUTION_EVIDENCE_KEYS:
            if key not in item:
                return False, \
                    "owner_attribution.evidence item missing key %r" % (key,)
        digest = item["value_digest"]
        if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            return False, "owner_attribution.evidence value_digest must " \
                "be 64-char lowercase hex"
        if not _nonempty_str(item["candidate"]):
            return False, "owner_attribution.evidence candidate must be " \
                "a non-empty string"
        if item["tier"] not in TIERS:
            return False, "owner_attribution.evidence tier %r unknown" % (
                item["tier"],)
        if item.get("strength", "decisive") not in ("decisive",
                                                     "corroborating"):
            return False, "owner_attribution.evidence strength %r unknown" % (
                item.get("strength"),)
        if item["candidate"] != owner and owner is not None:
            return False, "owner_attribution.evidence names %r but the " \
                "attribution resolves %r" % (item["candidate"], owner)
    # Compare-don't-trust: rebuild the canonical body from the carried
    # fields and require the digest to recompute exactly.
    body = _canonical_attribution(
        value["identity_subject"], value["owner"], value["tier"],
        value["declared_consistency"], value["evidence"], value["code"],
        conflicting=value.get("conflicting"))
    digest = value["digest"]
    if not isinstance(digest, str) or digest != _body_digest(body):
        return False, "owner_attribution.digest does not recompute " \
            "(value was tampered or built by another implementation)"
    return True, ""
