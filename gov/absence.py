#!/usr/bin/env python3
"""Signed absence-attribution: a signed record of a negative outcome.

ADAPT of the SEP-0000 absence-attribution pattern (re-derived prose;
nothing copied): silence is never an acceptable answer. When a
credential, permit, or artifact is missing, the party that would have
advertised it must produce a SIGNED negative outcome whose claim
distinguishes the two materially different cases:

* ``never-advertised`` — this issuer never published the subject, so
  there is nothing to look for (consumer code
  ``absence-never-advertised``);
* ``advertised-but-missing`` — the issuer DID advertise the subject and
  it is now absent (consumer code ``absence-advertised-but-missing``);
* ``revoked`` — the subject was revoked by exact-target revocation
  (``gov/revocation.py``); the entry pins the exact revoked digest in
  ``revocation_target`` (consumer code ``absence-revoked``).

Consumers MUST distinguish these: :func:`evaluate_negative` raises the
claim-specific refusal, so a verifier cannot accidentally treat
"never advertised" as "advertised but missing". An unsigned, forged,
or malformed negative refuses ``absence-unverifiable`` — never silently
trusted.

Ed25519 comes from the repo's vendored RFC 8032 ``gov/ed25519.py``;
``verify`` there is fail-closed (malformed is False, never an
exception), and this module keeps that property: every verification
failure becomes ``absence-unverifiable``.

Algorithm agility (see ``gov/alg_registry.py``): ``AbsenceIssuer``
takes an optional ``alg`` naming its signing tier, and
``attest_absence`` accepts a per-record override. The default
``ed25519-rfc8032`` emits byte-identical negatives to the pre-agility
format (no "alg" field); non-default tiers carry their "alg" name in
the signed record. ``verify_negative`` dispatches by the record's
named algorithm, resolves legacy records (no "alg") as
``ed25519-rfc8032``, and accepts an ``expect_alg`` pin that refuses
``alg-mismatch`` when the record's tier differs. MAC-tier negatives
prove authenticity only to key-holders — never treat them as
non-repudiation evidence.

Issuer key custody is deployment-owned (the ``seed`` is held by the
issuing deployment, exactly like the permit-lease and ARAP issuers).

Stdlib only. No network. $0.
"""

import json
import time
from datetime import datetime, timezone

from . import alg_registry as _algs
from .ed25519 import publickey as _ed_pub

_ALGS = _algs.default_registry()

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class AbsenceError(Exception):
    """Base class for all absence-attribution refusals. ``code`` is
    machine-readable."""

    code = "absence-refused"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class AbsenceUnverifiableError(AbsenceError):
    """The negative outcome is unsigned, forged, or malformed."""

    code = "absence-unverifiable"


class AbsenceNeverAdvertisedError(AbsenceError):
    """The issuer never advertised the subject — there is nothing to
    look for."""

    code = "absence-never-advertised"


class AbsenceAdvertisedButMissingError(AbsenceError):
    """The issuer advertised the subject and it is now absent."""

    code = "absence-advertised-but-missing"


class AbsenceRevokedError(AbsenceError):
    """The subject was revoked by exact-target revocation."""

    code = "absence-revoked"


# ----------------------------------------------------------------------
# Canonical encoding.
# ----------------------------------------------------------------------

_ABSENCE_DOMAIN = b"sasanam-absence/v1:"
_NEGATIVE_VERSION = 1

_CLAIMS = ("never-advertised", "advertised-but-missing", "revoked")


def _canonical(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":"), default=str)


def _subject_ok(subject_digest):
    return (isinstance(subject_digest, str) and len(subject_digest) > 0
            and "*" not in subject_digest)


def _negative_body(negative):
    """The bytes the signature covers: everything but the signature."""
    unsigned = {k: v for k, v in negative.items() if k != "signature"}
    return _ABSENCE_DOMAIN + _canonical(unsigned).encode("utf-8")


def _iso(now):
    dt = datetime.fromtimestamp(float(now), tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


# ----------------------------------------------------------------------
# Issuer.
# ----------------------------------------------------------------------


class AbsenceIssuer:
    """Signs absence attributions for subjects it tracks.

    ``seed`` is the issuer's 32-byte secret (deployment-owned key
    custody): an Ed25519 seed for the default tier, a symmetric MAC
    key for the ``hmac-sha256-mac`` tier. ``alg`` names the issuer's
    signing tier (see ``gov/alg_registry.py``); it defaults to
    ``ed25519-rfc8032``. Symmetric (MAC-tier) issuers have NO public
    key — ``public_key`` is None and verifiers hold the shared key.
    MAC-tier negatives prove authenticity only to key-holders and
    must never be treated as non-repudiation evidence.

    ``advertise(subject_digest)`` records a subject the issuer
    publishes; ``attest_absence`` then distinguishes never-advertised
    from advertised-but-missing, and consults an optional
    exact-target revocation list for the revoked claim.
    """

    def __init__(self, issuer_id, seed, *, alg="ed25519-rfc8032"):
        if not isinstance(issuer_id, str) or not issuer_id:
            raise ValueError("issuer_id must be a non-empty string")
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        try:
            _ALGS.info(alg)  # alg-unregistered for unknown tiers
        except _algs.AlgError as exc:
            raise AbsenceError(str(exc), code=exc.code)
        self.issuer_id = issuer_id
        self.seed = bytes(seed)
        self.alg = alg
        self.public_key = (_ed_pub(self.seed)
                           if alg == _algs.DEFAULT_ALG else None)
        self._advertised = set()

    def advertise(self, subject_digest):
        """Record that this issuer publishes ``subject_digest``."""
        if not _subject_ok(subject_digest):
            raise ValueError("advertise: subject_digest must be a "
                             "non-empty string without wildcards")
        self._advertised.add(subject_digest)

    def attest_absence(self, subject_digest, *, revocation=None,
                       now=None, alg=None):
        """Sign a negative outcome for ``subject_digest``.

        Claim selection: revoked (when ``revocation`` is supplied and
        reports the digest revoked) -> advertised-but-missing (the
        issuer advertised it) -> never-advertised. The revoked claim
        carries the exact revoked digest in ``revocation_target``.

        ``alg`` names the signing tier and defaults to the issuer's
        own tier (``self.alg``); pass it explicitly to override
        per-record. The default tier emits byte-identical records to
        the pre-agility format (no "alg" field); non-default tiers
        carry their "alg" name in the signed record.
        """
        if not _subject_ok(subject_digest):
            raise ValueError("attest_absence: subject_digest must be a "
                             "non-empty string without wildcards")
        if alg is None:
            alg = self.alg
        try:
            _ALGS.info(alg)  # alg-unregistered for unknown tiers
        except _algs.AlgError as exc:
            raise AbsenceError(str(exc), code=exc.code)
        revoked = (revocation is not None
                   and revocation.check(subject_digest) == "revoked")
        if revoked:
            claim = "revoked"
            target = subject_digest
        elif subject_digest in self._advertised:
            claim = "advertised-but-missing"
            target = None
        else:
            claim = "never-advertised"
            target = None
        negative = {
            "v": _NEGATIVE_VERSION,
            "subject_digest": subject_digest,
            "claim": claim,
            "revocation_target": target,
            "issued_at": _iso(time.time() if now is None else now),
            "issuer_id": self.issuer_id,
        }
        _algs.stamp_record_alg(negative, alg)
        negative["signature"] = _ALGS.sign(alg, _negative_body(negative),
                                           self.seed).hex()
        return negative


# ----------------------------------------------------------------------
# Verification (consumer side; public keys only).
# ----------------------------------------------------------------------

_NEGATIVE_FIELDS = ("v", "subject_digest", "claim", "revocation_target",
                    "issued_at", "issuer_id", "signature")


def verify_negative(negative, pubkey, *, expect_alg=None):
    """Verify a signed negative outcome against a public key.

    Returns a copy of the negative record on success. Raises
    :class:`AbsenceUnverifiableError` for anything unsigned, forged,
    or malformed — verification never trusts, never raises raw.

    Algorithm agility (see ``gov/alg_registry.py``): the signature
    check dispatches by the record's named "alg"; legacy records
    (no "alg") verify as ``ed25519-rfc8032``. Unknown names refuse
    ``alg-unregistered``; a pinned ``expect_alg`` that differs
    refuses ``alg-mismatch``.
    """
    if not isinstance(negative, dict):
        raise AbsenceUnverifiableError(
            "absence-unverifiable: negative outcome is not a record")
    for field in _NEGATIVE_FIELDS:
        if field not in negative:
            raise AbsenceUnverifiableError(
                "absence-unverifiable: missing field %r" % (field,))
    if negative["v"] != _NEGATIVE_VERSION:
        raise AbsenceUnverifiableError(
            "absence-unverifiable: unsupported version %r"
            % (negative.get("v"),))
    if negative["claim"] not in _CLAIMS:
        raise AbsenceUnverifiableError(
            "absence-unverifiable: unknown claim %r"
            % (negative.get("claim"),))
    if not _subject_ok(negative["subject_digest"]):
        raise AbsenceUnverifiableError(
            "absence-unverifiable: malformed subject_digest")
    if negative["claim"] == "revoked":
        if negative["revocation_target"] != negative["subject_digest"]:
            raise AbsenceUnverifiableError(
                "absence-unverifiable: revoked claim must pin the exact "
                "revoked digest in revocation_target")
    elif negative["revocation_target"] is not None:
        raise AbsenceUnverifiableError(
            "absence-unverifiable: revocation_target must be null unless "
            "the claim is revoked")
    try:
        sig = bytes.fromhex(negative["signature"])
    except (TypeError, ValueError):
        raise AbsenceUnverifiableError(
            "absence-unverifiable: malformed signature")
    try:
        alg = _algs.extract_record_alg(
            negative, expect_alg,
            lambda: AbsenceUnverifiableError(
                "absence-unverifiable: malformed alg field %r"
                % (negative.get("alg"),)))
    except _algs.AlgError as exc:
        # Keep the module's error contract ("every verification
        # failure becomes absence-unverifiable") while preserving the
        # machine-readable agility code.
        raise AbsenceUnverifiableError(str(exc), code=exc.code)
    if not _ALGS.verify(alg, _negative_body(negative), sig, pubkey):
        raise AbsenceUnverifiableError(
            "absence-unverifiable: signature does not verify against the "
            "pinned issuer key")
    return dict(negative)


def evaluate_negative(negative, pubkey):
    """Consume a signed negative outcome.

    Verifies the signature first (``absence-unverifiable`` on
    failure), then raises the claim-specific refusal so the caller is
    FORCED to distinguish the cases::

        absence-never-advertised
        absence-advertised-but-missing
        absence-revoked

    A negative outcome is never a permission — every path raises. The
    distinction is the point: "the issuer never published it" and
    "the issuer published it and it vanished" demand different
    incident responses.
    """
    neg = verify_negative(negative, pubkey)
    claim = neg["claim"]
    if claim == "never-advertised":
        raise AbsenceNeverAdvertisedError(
            "absence-never-advertised: issuer %r never advertised subject "
            "%r; there is nothing to look for"
            % (neg["issuer_id"], neg["subject_digest"]))
    if claim == "advertised-but-missing":
        raise AbsenceAdvertisedButMissingError(
            "absence-advertised-but-missing: issuer %r advertised subject "
            "%r and it is now absent"
            % (neg["issuer_id"], neg["subject_digest"]))
    # claim == "revoked" (verify_negative already rejected anything else)
    raise AbsenceRevokedError(
        "absence-revoked: subject %r was revoked (exact target %r)"
        % (neg["subject_digest"], neg["revocation_target"]))
