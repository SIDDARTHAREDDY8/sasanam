#!/usr/bin/env python3
"""Per-request attenuation binding for permit leases.

RE-DERIVED pattern (fora-protocol ADR-001, no foreign source copied):
the cryptographic embodiment of the tighten-only/no-downgrade rules
that ``gov/permit_leases.py`` already enforces. A requester signs a
fresh ATTENUATION BLOCK for the exact lease it intends to redeem. The
block carries a short TTL (at most 600 seconds) and a scope that may
only NARROW the lease's grant — never widen it.

The block is a sealed constraint, not a credential. It never
authorizes anything by itself: redemption still requires the lease's
exact ``parameter_digest`` (the digest remains the capability), the
lease's own used/expired/digest/revocation checks run first, and a
bound block only constrains the request further. Issuer seed custody
and clock trust are deployment-owned.

Rules (all fail closed, all refusals carry machine-readable codes):

* ``issue()`` refuses ``attenuation-ttl-refused`` when ``ttl_s`` is
  not in (0, 600] — a block lives at most ten minutes, and the span
  is re-checked at bind time so no signer can smuggle a longer span
  past issuance.
* ``bind(block, lease)`` checks in the order: shape -> signature ->
  lease-digest match -> TTL span -> expiry -> tighten-only. A forged
  or tampered block refuses ``attenuation-unverifiable``; a block for
  another lease refuses ``attenuation-lease-mismatch``; a stale block
  refuses ``attenuation-expired``; a scope broader than the grant
  refuses ``attenuation-widening-refused``.
* The scope comparison reuses ``PermitLease.check_scope`` (the same
  conservative subset rule): every dimension the block names must be
  in the grant with the block's values a subset of the grant's.
* ``PermitLease.redeem(..., attenuation=None,
  require_attenuation=False)`` — the only existing-file seam, additive
  + tighten-only: a missing block under a required policy refuses
  ``attenuation-missing``; a presented block binds BEFORE the scope
  check and additionally constrains ``request_scope`` to the narrowed
  scope; no policy and no block behaves exactly as before.

Stdlib only. No network. $0.
"""

import time
from hmac import compare_digest

from .ed25519 import publickey as _ed_pub
from .ed25519 import sign as _ed_sign
from .ed25519 import verify as _ed_verify
from .permit_leases import PermitDowngradeRefusedError
from .permit_leases import PermitLease
from .permit_leases import _normalize_scope

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class AttenuationError(Exception):
    """Base class for all attenuation refusals. ``code`` is
    machine-readable."""

    code = "attenuation-refused"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class AttenuationUnverifiableError(AttenuationError):
    """The block's shape is malformed or its requester signature does
    not verify — it cannot be authenticated."""

    code = "attenuation-unverifiable"


class AttenuationLeaseMismatchError(AttenuationError):
    """The block authenticates but binds a different lease's digest."""

    code = "attenuation-lease-mismatch"


class AttenuationTtlRefusedError(AttenuationError):
    """The block's TTL span is not in (0, 600] seconds."""

    code = "attenuation-ttl-refused"


class AttenuationExpiredError(AttenuationError):
    """The block's validity window has closed."""

    code = "attenuation-expired"


class AttenuationWideningRefusedError(AttenuationError):
    """The block's narrowed scope is broader than (or not comparable
    to) the lease's grant scope."""

    code = "attenuation-widening-refused"


class AttenuationMissingError(AttenuationError):
    """The redeem policy requires an attenuation block and none was
    presented."""

    code = "attenuation-missing"


# ----------------------------------------------------------------------
# Canonical encoding.
# ----------------------------------------------------------------------

_ATTENUATION_DOMAIN = b"sasanam-attenuation/v1:"
_BLOCK_VERSION = 1
_MAX_TTL_S = 600.0


def _canonical(obj):
    import json
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":"), default=str)


def _block_body(block):
    """The bytes the requester signature covers: everything but the
    signature itself."""
    unsigned = {k: v for k, v in block.items() if k != "requester_signature"}
    return _ATTENUATION_DOMAIN + _canonical(unsigned).encode("utf-8")


_BLOCK_FIELDS = ("v", "lease_digest", "narrowed_scope", "issued_at",
                 "expires_at", "requester_id", "requester_pubkey",
                 "requester_signature")


def _clock(now):
    """``now`` may be an epoch float or a no-arg callable returning one;
    None means the wall clock."""
    if now is None:
        return time.time()
    if callable(now):
        return float(now())
    return float(now)


def _check_block_shape(block):
    """Fail closed on malformed blocks (shape, not signature).

    Returns the parsed (requester_pubkey, signature) bytes so the
    signature check does not re-parse them."""
    if not isinstance(block, dict):
        raise AttenuationUnverifiableError(
            "attenuation-unverifiable: block is not a record")
    for field in _BLOCK_FIELDS:
        if field not in block:
            raise AttenuationUnverifiableError(
                "attenuation-unverifiable: missing field %r" % (field,))
    if block["v"] != _BLOCK_VERSION:
        raise AttenuationUnverifiableError(
            "attenuation-unverifiable: unsupported version %r"
            % (block.get("v"),))
    if (not isinstance(block["lease_digest"], str)
            or not block["lease_digest"]):
        raise AttenuationUnverifiableError(
            "attenuation-unverifiable: malformed lease_digest")
    if not isinstance(block["narrowed_scope"], dict):
        raise AttenuationUnverifiableError(
            "attenuation-unverifiable: narrowed_scope is not a dict")
    if (not isinstance(block["requester_id"], str)
            or not block["requester_id"]):
        raise AttenuationUnverifiableError(
            "attenuation-unverifiable: malformed requester_id")
    try:
        pubkey = bytes.fromhex(block["requester_pubkey"])
    except (TypeError, ValueError):
        raise AttenuationUnverifiableError(
            "attenuation-unverifiable: malformed requester_pubkey")
    if len(pubkey) != 32:
        raise AttenuationUnverifiableError(
            "attenuation-unverifiable: malformed requester_pubkey")
    try:
        sig = bytes.fromhex(block["requester_signature"])
    except (TypeError, ValueError):
        raise AttenuationUnverifiableError(
            "attenuation-unverifiable: malformed signature")
    if len(sig) != 64:
        raise AttenuationUnverifiableError(
            "attenuation-unverifiable: malformed signature")
    for ts in ("issued_at", "expires_at"):
        try:
            float(block[ts])
        except (TypeError, ValueError):
            raise AttenuationUnverifiableError(
                "attenuation-unverifiable: malformed %s" % ts)
    return pubkey, sig


def _verify_block_signature(block, pubkey, sig):
    """Verify the requester signature over the block body."""
    ok = _ed_verify(pubkey, _block_body(block), sig)
    if not ok:
        raise AttenuationUnverifiableError(
            "attenuation-unverifiable: requester signature does not "
            "verify")


# ----------------------------------------------------------------------
# Issuance.
# ----------------------------------------------------------------------


def issue(lease_digest, narrowed_scope, requester_id, seed, *,
          ttl_s=600, now=None):
    """Seal a requester-signed attenuation block for one lease.

    ``ttl_s`` must be in (0, 600]: the block lives at most ten minutes.
    Longer spans refuse ``attenuation-ttl-refused``. ``narrowed_scope``
    is normalized conservatively at issuance; ``seed`` is the
    requester's 32-byte Ed25519 seed (custody is the requester's job).
    """
    if not isinstance(lease_digest, str) or not lease_digest:
        raise AttenuationUnverifiableError(
            "attenuation-unverifiable: lease_digest must be a non-empty "
            "string")
    ttl = float(ttl_s)
    if not 0 < ttl <= _MAX_TTL_S:
        raise AttenuationTtlRefusedError(
            "attenuation-ttl-refused: ttl_s=%r is outside (0, 600]" % (ttl_s,))
    if not isinstance(narrowed_scope, dict):
        raise AttenuationUnverifiableError(
            "attenuation-unverifiable: narrowed_scope must be a dict")
    # Normalize conservatively: malformed narrowing is a caller bug,
    # caught here, never at bind time.
    try:
        narrowed = _normalize_scope(narrowed_scope, "narrowed")
    except PermitDowngradeRefusedError as exc:
        raise AttenuationWideningRefusedError(
            "attenuation-widening-refused: %s" % exc) from exc
    # Re-expand to plain {dim: sorted list} for the signed record.
    narrowed_wire = {dim: sorted(values)
                     for dim, values in narrowed.items()}
    issued = _clock(now)
    pubkey = _ed_pub(bytes(seed))
    block = {
        "v": _BLOCK_VERSION,
        "lease_digest": lease_digest,
        "narrowed_scope": narrowed_wire,
        "issued_at": issued,
        "expires_at": issued + ttl,
        "requester_id": requester_id,
        "requester_pubkey": pubkey.hex(),
    }
    block["requester_signature"] = _ed_sign(bytes(seed), _block_body(block)).hex()
    return block


# ----------------------------------------------------------------------
# Binding.
# ----------------------------------------------------------------------


def bind(block, lease, now=None):
    """Bind an attenuation block to the lease it names.

    Check order: shape -> signature -> lease-digest match -> TTL span
    -> expiry -> tighten-only. Returns the normalized narrowed scope
    (``{dimension: frozenset(values)}``) on success. The block itself
    grants nothing; the caller still redeems the lease normally.
    """
    _pubkey, _sig = _check_block_shape(block)
    _verify_block_signature(block, _pubkey, _sig)
    if not compare_digest(block["lease_digest"], lease.parameter_digest):
        raise AttenuationLeaseMismatchError(
            "attenuation-lease-mismatch: block binds a different lease")
    span = float(block["expires_at"]) - float(block["issued_at"])
    if not 0 < span <= _MAX_TTL_S:
        raise AttenuationTtlRefusedError(
            "attenuation-ttl-refused: block TTL span %r is outside "
            "(0, 600]" % (span,))
    at = _clock(now)
    if at >= float(block["expires_at"]):
        raise AttenuationExpiredError(
            "attenuation-expired: block window closed at %r"
            % (block["expires_at"],))
    try:
        PermitLease.check_scope(block["narrowed_scope"], lease.grant_scope)
    except PermitDowngradeRefusedError as exc:
        raise AttenuationWideningRefusedError(
            "attenuation-widening-refused: %s" % exc) from exc
    return _normalize_scope(block["narrowed_scope"], "narrowed")


__all__ = [
    "AttenuationError",
    "AttenuationUnverifiableError",
    "AttenuationLeaseMismatchError",
    "AttenuationTtlRefusedError",
    "AttenuationExpiredError",
    "AttenuationWideningRefusedError",
    "AttenuationMissingError",
    "issue",
    "bind",
]
