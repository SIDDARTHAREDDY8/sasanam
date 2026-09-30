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

Issuer key custody is deployment-owned (the ``seed`` is held by the
issuing deployment, exactly like the permit-lease and ARAP issuers).

Stdlib only. No network. $0.
"""

import json
import time
from datetime import datetime, timezone

from .ed25519 import publickey as _ed_pub
from .ed25519 import sign as _ed_sign
from .ed25519 import verify as _ed_verify

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

    ``seed`` is the issuer's 32-byte Ed25519 seed (deployment-owned
    key custody). ``advertise(subject_digest)`` records a subject the
    issuer publishes; ``attest_absence`` then distinguishes
    never-advertised from advertised-but-missing, and consults an
    optional exact-target revocation list for the revoked claim.
    """

    def __init__(self, issuer_id, seed):
        if not isinstance(issuer_id, str) or not issuer_id:
            raise ValueError("issuer_id must be a non-empty string")
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self.issuer_id = issuer_id
        self.seed = bytes(seed)
        self.public_key = _ed_pub(self.seed)
        self._advertised = set()

    def advertise(self, subject_digest):
        """Record that this issuer publishes ``subject_digest``."""
        if not _subject_ok(subject_digest):
            raise ValueError("advertise: subject_digest must be a "
                             "non-empty string without wildcards")
        self._advertised.add(subject_digest)

    def attest_absence(self, subject_digest, *, revocation=None, now=None):
        """Sign a negative outcome for ``subject_digest``.

        Claim selection: revoked (when ``revocation`` is supplied and
        reports the digest revoked) -> advertised-but-missing (the
        issuer advertised it) -> never-advertised. The revoked claim
        carries the exact revoked digest in ``revocation_target``.
        """
        if not _subject_ok(subject_digest):
            raise ValueError("attest_absence: subject_digest must be a "
                             "non-empty string without wildcards")
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
        negative["signature"] = _ed_sign(self.seed,
                                         _negative_body(negative)).hex()
        return negative


# ----------------------------------------------------------------------
# Verification (consumer side; public keys only).
# ----------------------------------------------------------------------

_NEGATIVE_FIELDS = ("v", "subject_digest", "claim", "revocation_target",
                    "issued_at", "issuer_id", "signature")


def verify_negative(negative, pubkey):
    """Verify a signed negative outcome against a public key.

    Returns a copy of the negative record on success. Raises
    :class:`AbsenceUnverifiableError` for anything unsigned, forged,
    or malformed — verification never trusts, never raises raw.
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
    if not _ed_verify(pubkey, _negative_body(negative), sig):
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
