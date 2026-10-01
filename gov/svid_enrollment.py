"""Pre-auth-key enrollment ceremony in front of the TEST SVID issuer.

Wave-260 lane 3 (identity-mesh follow-up). Stdlib only.

Headscale shape: a one-time enrollment key, issued out-of-band,
admits exactly one workload to receive its first SVID. The key is
random, single-use, and expiring; it is burned on redemption. A
used, expired, or unknown key is refused with a machine code --
never silently accepted, never downgraded.

``EnrollmentAuthority`` wraps a ``gov.svid_issuer.TestSvidIssuer``:
``issue_key`` mints the key, ``redeem`` burns it and -- exactly once --
calls ``issuer.issue`` to mint the workload's first SVID. The TEST
issuer stays a test issuer: the seed still lives in-process, and
production issuer wiring (SPIRE server, Vault PKI, step-ca, or a
cfssl-style authsign hook in front of signing) remains
deployment-owned. This ceremony gates first issuance; it does not
upgrade custody.

Fail-closed ordering inside ``redeem``: structural key validation
(``svid-malformed``), unknown key (``svid-enrollment-key-unknown``),
already consumed (``svid-enrollment-key-replayed``), expired
(``svid-enrollment-key-expired``), spiffe-id binding mismatch
(``svid-enrollment-spiffe-mismatch``), then issuance. The key burns
BEFORE issuance is attempted: a redemption whose issuance fails
still retires the key, so a second redemption refuses as replayed,
never as a fresh issuance.

Key hygiene: only the sha256 digest of the key is stored; the raw key
is never retained after ``issue_key`` returns and never appears in
error detail. Digests are compared as stored strings (the key space
is 192 bits of ``secrets`` entropy; lookup is by exact digest
match). A redemption may optionally be bound to one spiffe id at
issue time (``spiffe_id``); a bound key presented for a different id
is burned and refused.

Machine codes (domain "svid", registered in gov/decision_codes.py):

* ``svid-enrollment-key-unknown`` -- the key matches no issued key.
* ``svid-enrollment-key-replayed`` -- the key was already consumed
  (or retired by a failed redemption); replay refused.
* ``svid-enrollment-key-expired`` -- ``now >= expires_at``; the key
  is burned on this refusal.
* ``svid-enrollment-spiffe-mismatch`` -- the key is bound to a
  different spiffe id; the key is burned on this refusal.

Honest residuals (documented, not solved here):
  - Single-process, in-memory key table: distributed revocation of
    enrollment keys and cross-instance burn atomicity are
    deployment-owned (a shared store behind this API keeps the same
    burn-before-issue ordering).
  - Bearer keys: whoever holds the key enrolls. Out-of-band delivery
    is the deployment's channel; this module assumes it is secret.
  - The minutes-scale SVID TTL remains the revocation story for the
    issued SVID (wave-259 residual).
"""

import hashlib
import secrets

from .svid_issuer import (
    SvidError,
    TestSvidIssuer,
    _parse_spiffe_id,
    _validate_now,
)

__all__ = [
    "EnrollmentAuthority",
    "ENROLLMENT_KEY_UNKNOWN_CODE",
    "ENROLLMENT_KEY_REPLAYED_CODE",
    "ENROLLMENT_KEY_EXPIRED_CODE",
    "ENROLLMENT_SPIFFE_MISMATCH_CODE",
]

ENROLLMENT_KEY_UNKNOWN_CODE = "svid-enrollment-key-unknown"
ENROLLMENT_KEY_REPLAYED_CODE = "svid-enrollment-key-replayed"
ENROLLMENT_KEY_EXPIRED_CODE = "svid-enrollment-key-expired"
ENROLLMENT_SPIFFE_MISMATCH_CODE = "svid-enrollment-spiffe-mismatch"

_SVID_MALFORMED_CODE = "svid-malformed"

#: Default enrollment-key lifetime: ten minutes. Headscale pre-auth
#: keys expire by default; a silent default here is documented rather
#: than fail-closed because the key is worthless without an explicit
#: redemption and the expiry is recorded on the key itself.
DEFAULT_KEY_TTL_SECONDS = 600

#: 192 bits of entropy, URL-safe for out-of-band delivery.
_KEY_BYTES = 24


def _key_digest(key):
    """sha256 hex of the raw key: the only form ever stored."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class EnrollmentAuthority(object):
    """Issue and redeem one-time pre-auth enrollment keys.

    ``issuer`` must be a ``gov.svid_issuer.TestSvidIssuer`` whose
    first-issuance ceremony this authority gates.
    ``default_key_ttl_seconds`` caps how long an issued key lives.
    """

    def __init__(self, issuer, default_key_ttl_seconds=None):
        if not isinstance(issuer, TestSvidIssuer):
            raise SvidError(
                _SVID_MALFORMED_CODE,
                "issuer must be a gov.svid_issuer.TestSvidIssuer")
        if default_key_ttl_seconds is None:
            default_key_ttl_seconds = DEFAULT_KEY_TTL_SECONDS
        if isinstance(default_key_ttl_seconds, bool) or \
                not isinstance(default_key_ttl_seconds, int) or \
                default_key_ttl_seconds <= 0:
            raise SvidError(
                _SVID_MALFORMED_CODE,
                "default_key_ttl_seconds must be a positive int")
        self._issuer = issuer
        self._default_ttl = default_key_ttl_seconds
        # digest -> {"issued_at", "expires_at", "used", "bind_spiffe_id"}
        self._records = {}

    def issue_key(self, spiffe_id=None, ttl_seconds=None, now=None):
        """Mint one enrollment key (shown once: the return value).

        ``spiffe_id`` optionally binds the key to one workload id
        (validated now, at issue time). ``ttl_seconds`` overrides the
        default lifetime. Returns the raw key string.
        """
        bind = None
        if spiffe_id is not None:
            # Validates strictly (svid-identity-malformed on bad id);
            # binding is stored normalized.
            _parse_spiffe_id(spiffe_id)
            bind = spiffe_id.lower()
        if ttl_seconds is None:
            ttl_seconds = self._default_ttl
        if isinstance(ttl_seconds, bool) or \
                not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise SvidError(
                _SVID_MALFORMED_CODE,
                "ttl_seconds must be a positive int")
        issued_at = int(_validate_now(now))
        key = secrets.token_urlsafe(_KEY_BYTES)
        digest = _key_digest(key)
        # 192-bit collision with an existing live record is not a
        # practical event; a fresh draw keeps the table unambiguous.
        while digest in self._records and \
                not self._records[digest]["used"]:
            key = secrets.token_urlsafe(_KEY_BYTES)
            digest = _key_digest(key)
        self._records[digest] = {
            "issued_at": issued_at,
            "expires_at": issued_at + ttl_seconds,
            "used": False,
            "bind_spiffe_id": bind,
        }
        return key

    def redeem(self, key, spiffe_id, public_key, ttl_minutes,
               profile="workload", now=None):
        """Redeem one enrollment key for the workload's first SVID.

        Burns the key BEFORE calling the issuer: exactly one SVID per
        key, even when issuance itself fails. Returns the SVID dict.
        Raises :class:`SvidError` with the enrollment machine codes
        (or the issuer's codes when issuance fails post-burn).
        """
        at = _validate_now(now)
        if not isinstance(key, str) or not key:
            raise SvidError(
                _SVID_MALFORMED_CODE,
                "enrollment key must be a non-empty string")
        digest = _key_digest(key)
        record = self._records.get(digest)
        if record is None:
            raise SvidError(
                ENROLLMENT_KEY_UNKNOWN_CODE,
                "the presented enrollment key matches no issued key; "
                "refused fail-closed")
        if record["used"]:
            raise SvidError(
                ENROLLMENT_KEY_REPLAYED_CODE,
                "the presented enrollment key was already consumed; "
                "replay refused fail-closed")
        if at >= record["expires_at"]:
            record["used"] = True  # burn: dead keys do not linger
            raise SvidError(
                ENROLLMENT_KEY_EXPIRED_CODE,
                "the presented enrollment key is expired "
                "(now >= expires_at); refused fail-closed")
        bound = record["bind_spiffe_id"]
        if bound is not None and (
                not isinstance(spiffe_id, str)
                or spiffe_id.lower() != bound):
            record["used"] = True  # burn: misuse retires the key
            raise SvidError(
                ENROLLMENT_SPIFFE_MISMATCH_CODE,
                "the enrollment key is bound to a different spiffe "
                "id; refused fail-closed")
        # Burn BEFORE issuance: exactly one SVID per key, even if the
        # issuer refuses (its codes propagate, the key stays burned).
        record["used"] = True
        return self._issuer.issue(spiffe_id, public_key, ttl_minutes,
                                  profile=profile, now=at)

    def live_keys(self):
        """Count of issued, unconsumed keys (test hook).

        Expired-but-never-redeemed keys still count until a
        redemption attempt burns them; burn is redemption-driven,
        not sweep-driven, by design (no background expiry thread in
        this in-process authority).
        """
        return sum(1 for r in self._records.values() if not r["used"])
