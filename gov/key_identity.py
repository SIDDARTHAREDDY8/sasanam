#!/usr/bin/env python3
"""Registered-key resolution with a hybrid-signature mandate check.

Two governance primitives, re-derived (nothing copied):

1. ``RegisteredKey`` — a SINGLE validated unit tying ``(key-type,
   digest-alg)`` together so a signing algorithm and a key can never
   be mismatched downstream. ``RegisteredKey.build(key_id, key_type,
   digest_alg, pubkey_bytes, ...)`` refuses
   ``key-identity-unregistered`` when ``key_type`` is not a scheme in
   ``gov/alg_registry.py`` or ``digest_alg`` is not a system-registered
   digest (sha256/sha384/sha512); the ``pubkey_digest`` is recomputed
   from the presented public key, so the digest in the record can
   never disagree with the key material it names. ``KeyRegistry``
   stores records by ``key_id``; ``resolve(key_id)`` refuses
   ``key-identity-unknown`` for ids that were never registered.
   ``status`` is ``"active"`` or ``"retired"``; resolution of a
   retired key refuses ``key-identity-revoked``, as does resolution of
   a key whose ``pubkey_digest`` is listed in an attached
   ``gov/revocation.py`` ``RevocationList``. With no registry
   attached, resolution is nominal (documented): the module refuses
   nothing it has no evidence for.

2. Hybrid mandate check — a registered key MAY declare
   ``hybrid_of=(leg_a_id, leg_b_id)``. ``verify_hybrid(key_id, message,
   sig_a, sig_b, pubkey_a, pubkey_b)`` requires BOTH legs to verify
   under the caller's presented leg keys, each bound to the
   registered ``pubkey_digest`` of its leg. Either failing signature
   refuses ``hybrid-leg-failed`` — a hybrid NEVER falls back to a
   single leg. The leg checks run BEFORE any signature verification
   (forgery fails before state lookups, so a dead leg is never a
   signature oracle); a leg that is unknown, retired/revoked, a
   MAC-tier key (a MAC is not a signature), itself a hybrid, or whose
   presented key does not recompute the registered digest refuses
   ``hybrid-leg-invalid``. This module implements no crypto
   primitives: the mandate check is the discipline, and signing /
   verifying dispatches through the registry's named algorithms.

Error vocabulary (all raised as :class:`KeyIdentityError` with a
machine-readable ``code``):

* ``key-identity-unregistered`` — ``key_type`` is not a scheme known
  to ``gov/alg_registry.py``, or ``digest_alg`` is not a
  system-registered digest. Fail closed: an unknown scheme never
  degrades to a known one.
* ``key-identity-unknown`` — ``resolve`` / ``verify_hybrid`` for a
  ``key_id`` that was never registered.
* ``key-identity-revoked`` — the key is ``"retired"`` or its
  ``pubkey_digest`` is revoked in the attached revocation registry.
* ``hybrid-leg-failed`` — a hybrid's leg signature did not verify.
  Both legs are required; this is never a downgrade path.
* ``hybrid-leg-invalid`` — the hybrid's leg set is malformed:
  unknown / retired / revoked / MAC-tier / nested-hybrid leg, or a
  caller-presented leg key whose digest does not match the
  registered ``pubkey_digest``.
* ``key-identity-malformed`` — bad input shape (empty ids, empty
  key bytes, non-bytes message/signatures/keys, bad ``status``,
  malformed ``hybrid_of``). Raised before any trust decision.

Stdlib only. No network. $0.
"""

import hashlib

from .alg_registry import default_registry

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class KeyIdentityError(Exception):
    """Base class for all key-identity refusals. ``code`` is
    machine-readable."""

    code = "key-identity-refused"


class _Unregistered(KeyIdentityError):
    code = "key-identity-unregistered"


class _Unknown(KeyIdentityError):
    code = "key-identity-unknown"


class _Revoked(KeyIdentityError):
    code = "key-identity-revoked"


class _HybridLegFailed(KeyIdentityError):
    code = "hybrid-leg-failed"


class _HybridLegInvalid(KeyIdentityError):
    code = "hybrid-leg-invalid"


class _Malformed(KeyIdentityError):
    code = "key-identity-malformed"


# Digests this module is willing to register. Small, closed, stdlib.
_DIGEST_ALGS = ("sha256", "sha384", "sha512")

_STATUSES = ("active", "retired")


def _non_empty_str(value, field):
    if not isinstance(value, str) or not value:
        raise _Malformed(
            "key-identity-malformed: %s must be a non-empty string"
            % (field,))
    return value


class RegisteredKey:
    """An immutable validated (key-type, digest-alg) registration unit.

    Construct via :meth:`build`, which validates the schemes against
    the system registries and recomputes ``pubkey_digest`` from the
    presented public key. ``record()`` returns the portable,
    digest-bound record.
    """

    __slots__ = ("_record",)

    def __init__(self, record):
        # Private: all construction goes through build()/from_record().
        self._record = dict(record)

    @classmethod
    def build(cls, key_id, key_type, digest_alg, pubkey_bytes, *,
              status="active", hybrid_of=None):
        """Validate and bind a new key registration.

        ``key_type`` must be a scheme in ``gov/alg_registry.py`` and
        ``digest_alg`` one of ``sha256``/``sha384``/``sha512`` —
        anything else refuses ``key-identity-unregistered``.
        ``pubkey_digest`` is recomputed here, never caller-supplied.
        ``hybrid_of`` is ``None`` or a 2-tuple of distinct non-empty
        ``key_id`` strings naming the hybrid's legs.
        """
        _non_empty_str(key_id, "key_id")
        _non_empty_str(key_type, "key_type")
        _non_empty_str(digest_alg, "digest_alg")
        try:
            default_registry().info(key_type)
        except Exception:  # noqa: BLE001 - any registry refusal
            raise _Unregistered(
                "key-identity-unregistered: key_type %r is not a "
                "registered algorithm" % (key_type,))
        if digest_alg not in _DIGEST_ALGS:
            raise _Unregistered(
                "key-identity-unregistered: digest_alg %r is not a "
                "registered digest" % (digest_alg,))
        if not isinstance(pubkey_bytes, (bytes, bytearray)) \
                or not pubkey_bytes:
            raise _Malformed(
                "key-identity-malformed: pubkey_bytes must be non-empty "
                "bytes")
        if status not in _STATUSES:
            raise _Malformed(
                "key-identity-malformed: status must be one of %r"
                % (_STATUSES,))
        legs = None
        if hybrid_of is not None:
            legs = cls._check_legs(key_id, hybrid_of)
        return cls({"v": 1,
                    "key_id": key_id,
                    "key_type": key_type,
                    "digest_alg": digest_alg,
                    "pubkey_digest": hashlib.new(
                        digest_alg, bytes(pubkey_bytes)).hexdigest(),
                    "status": status,
                    "hybrid_of": legs})

    @staticmethod
    def _check_legs(key_id, hybrid_of):
        if not isinstance(hybrid_of, (tuple, list)) \
                or len(hybrid_of) != 2:
            raise _Malformed(
                "key-identity-malformed: hybrid_of must be a 2-tuple of "
                "key ids")
        legs = tuple(_non_empty_str(leg, "hybrid_of leg")
                     for leg in hybrid_of)
        if legs[0] == legs[1]:
            raise _Malformed(
                "key-identity-malformed: hybrid legs must be distinct")
        if key_id in legs:
            raise _Malformed(
                "key-identity-malformed: a hybrid cannot be its own leg")
        return legs

    def record(self):
        """The portable record. ``pubkey_digest`` is the digest of
        the public key presented at build time."""
        return dict(self._record)


class KeyRegistry:
    """Resolve registered keys and enforce the hybrid mandate.

    ``revocation_registry`` is an optional ``gov/revocation.py``
    ``RevocationList`` (duck-typed: anything with
    ``check(digest) -> "revoked" | "active"``). The registry is
    in-memory; persistence is deployment-owned.

    Design note: ``digest_alg`` is validated against a closed stdlib
    set (``sha256``/``sha384``/``sha512``), not against
    ``gov/alg_registry.py`` — the registry holds *signing schemes*,
    and a digest is not a signing scheme. Unknown digests still
    refuse ``key-identity-unregistered``: fail closed on an
    unrecognized scheme, never degrade.
    """

    def __init__(self, revocation_registry=None):
        self._keys = {}
        self._revocation = revocation_registry

    def register(self, key):
        """Store a :class:`RegisteredKey`. Re-registering a ``key_id``
        replaces the record (deployment-owned rotation discipline)."""
        if not isinstance(key, RegisteredKey):
            raise _Malformed(
                "key-identity-malformed: register() takes a RegisteredKey")
        record = key.record()
        self._keys[record["key_id"]] = record
        return record["key_id"]

    def _lookup(self, key_id):
        try:
            return self._keys[key_id]
        except (KeyError, TypeError):
            raise _Unknown(
                "key-identity-unknown: %r was never registered"
                % (key_id,))

    def _check_status(self, record):
        if record["status"] != "active":
            raise _Revoked(
                "key-identity-revoked: key %r has status %r"
                % (record["key_id"], record["status"]))
        rev = self._revocation
        if rev is not None:
            try:
                state = rev.check(record["pubkey_digest"])
            except Exception:  # noqa: BLE001 - fail closed on lookup error
                raise _Revoked(
                    "key-identity-revoked: revocation lookup failed for "
                    "key %r" % (record["key_id"],))
            if state == "revoked":
                raise _Revoked(
                    "key-identity-revoked: key %r is revoked"
                    % (record["key_id"],))
        return True

    def resolve(self, key_id):
        """Return a copy of the registered record, after status and
        revocation checks. Unknown ids refuse ``key-identity-unknown``;
        retired or revoked keys refuse ``key-identity-revoked``. With
        no revocation registry attached, resolution is nominal —
        nothing is invented."""
        record = self._lookup(key_id)
        self._check_status(record)
        return dict(record)

    def verify_hybrid(self, key_id, message, sig_a, sig_b,
                      pubkey_a, pubkey_b):
        """Verify a hybrid key: BOTH legs must verify. Returns True.

        Check order (deliberate): key shape -> leg validity (unknown,
        retired/revoked, MAC-tier, nested-hybrid, digest-mismatched
        presented key) -> signature verification. A dead leg is never
        a signature oracle, and a hybrid never falls back to a single
        leg: either failing signature refuses ``hybrid-leg-failed``.
        """
        if not isinstance(message, (bytes, bytearray)):
            raise _Malformed(
                "key-identity-malformed: message must be bytes")
        for name, blob in (("sig_a", sig_a), ("sig_b", sig_b)):
            if not isinstance(blob, (bytes, bytearray)) or not blob:
                raise _Malformed(
                    "key-identity-malformed: %s must be non-empty bytes"
                    % (name,))
        record = self._lookup(key_id)
        self._check_status(record)
        legs = record["hybrid_of"]
        if legs is None:
            raise _HybridLegInvalid(
                "hybrid-leg-invalid: key %r declares no hybrid legs"
                % (key_id,))
        leg_a = self._validated_leg(legs[0], pubkey_a)
        leg_b = self._validated_leg(legs[1], pubkey_b)
        areg = default_registry()
        if not areg.verify(leg_a["key_type"], bytes(message), bytes(sig_a),
                           bytes(pubkey_a)):
            raise _HybridLegFailed(
                "hybrid-leg-failed: leg %r signature did not verify"
                % (legs[0],))
        if not areg.verify(leg_b["key_type"], bytes(message), bytes(sig_b),
                           bytes(pubkey_b)):
            raise _HybridLegFailed(
                "hybrid-leg-failed: leg %r signature did not verify"
                % (legs[1],))
        return True

    def _validated_leg(self, leg_id, presented_pubkey):
        """Resolve a hybrid leg and bind the caller's presented key to
        the registered digest. Anything invalid refuses
        ``hybrid-leg-invalid`` — before any signature is touched."""
        try:
            leg = self._keys[leg_id]
        except (KeyError, TypeError):
            raise _HybridLegInvalid(
                "hybrid-leg-invalid: leg %r is not registered" % (leg_id,))
        if leg["hybrid_of"] is not None:
            raise _HybridLegInvalid(
                "hybrid-leg-invalid: leg %r is itself a hybrid; legs are "
                "leaf keys" % (leg_id,))
        if leg["status"] != "active":
            raise _HybridLegInvalid(
                "hybrid-leg-invalid: leg %r has status %r"
                % (leg_id, leg["status"]))
        rev = self._revocation
        if rev is not None:
            try:
                state = rev.check(leg["pubkey_digest"])
            except Exception:  # noqa: BLE001 - fail closed
                raise _HybridLegInvalid(
                    "hybrid-leg-invalid: revocation lookup failed for "
                    "leg %r" % (leg_id,))
            if state == "revoked":
                raise _HybridLegInvalid(
                    "hybrid-leg-invalid: leg %r is revoked" % (leg_id,))
        if not default_registry().info(leg["key_type"])["non_repudiation"]:
            raise _HybridLegInvalid(
                "hybrid-leg-invalid: leg %r uses MAC-tier %r — a MAC is "
                "not a signature and cannot be a hybrid leg"
                % (leg_id, leg["key_type"]))
        if not isinstance(presented_pubkey, (bytes, bytearray)) \
                or not presented_pubkey:
            raise _HybridLegInvalid(
                "hybrid-leg-invalid: leg %r presented key must be "
                "non-empty bytes" % (leg_id,))
        recomputed = hashlib.new(
            leg["digest_alg"], bytes(presented_pubkey)).hexdigest()
        if recomputed != leg["pubkey_digest"]:
            raise _HybridLegInvalid(
                "hybrid-leg-invalid: leg %r presented key does not match "
                "the registered pubkey_digest" % (leg_id,))
        return leg
