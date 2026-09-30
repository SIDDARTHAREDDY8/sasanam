#!/usr/bin/env python3
"""Exact-target signed revocation (portable revocation lists).

ADAPT of the EMILIA PIP-011 EP-REVOCATION-v1 pattern (re-derived
prose; nothing copied): revocation is portable — a revocation entry is
a SIGNED record that pins an EXACT credential/permit digest plus the
issuer, so any verifier holding the issuer's public key can check it
without trusting the transport.

The one hard rule: an entry can NEVER revoke by prefix or by class.
``revoke()`` refuses ``revocation-inexact-target-refused`` for
anything that is not a full 64-hex digest (optionally with the
``sha256:`` / ``hmac-sha256-v1:`` scheme the rest of the repo already
uses). A short prefix, a wildcard, a class label, or a bare scheme is
an authoring error and fails closed — revoking "everything under
this prefix" would be a standing privilege, the exact thing
one-use leases and short TTLs exist to prevent.

Entries are append-only: revoking an already-revoked digest is a
no-op that keeps the original entry (history is never rewritten).
``check(target_digest)`` answers ``"revoked"`` or ``"active"``.
``export()`` / ``import_entries(entries, issuer_pubkeys)`` moves
lists between deployments; import verifies every entry's signature
against the pinned keyset and refuses
``revocation-entry-unverifiable`` on the first bad entry — the whole
import aborts, nothing is half-trusted.

Ed25519 comes from the repo's vendored RFC 8032 ``gov/ed25519.py``.
Issuer seed custody is deployment-owned. The list itself is
in-memory; persistence is the deployer's job, same as the
wave-219 seen-version floors.

Stdlib only. No network. $0.
"""

import json
import re
import time
from datetime import datetime, timezone

from .ed25519 import sign as _ed_sign
from .ed25519 import verify as _ed_verify

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class RevocationError(Exception):
    """Base class for all revocation refusals. ``code`` is
    machine-readable."""

    code = "revocation-refused"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class RevocationInexactTargetError(RevocationError):
    """The revocation target is not an exact full digest — a prefix,
    class, wildcard, or malformed digest was offered."""

    code = "revocation-inexact-target-refused"


class RevocationEntryUnverifiableError(RevocationError):
    """A revocation entry's signature does not verify against the
    pinned issuer keyset."""

    code = "revocation-entry-unverifiable"


# ----------------------------------------------------------------------
# Canonical encoding.
# ----------------------------------------------------------------------

_REVOCATION_DOMAIN = b"sasanam-revocation/v1:"
_ENTRY_VERSION = 1

# Exact digests only: 64 lowercase hex chars, optionally carrying one of
# the digest schemes the repo already uses (sha256: parameter digests,
# hmac-sha256-v1: ARAP context bindings). Anything shorter, longer, or
# non-hex — prefixes, wildcards, class labels — is inexact.
_EXACT_DIGEST = re.compile(
    r"^(?:sha256:|hmac-sha256-v1:)?[0-9a-f]{64}$")


def is_exact_digest(target):
    """True when ``target`` is a full canonical digest (exact target)."""
    return (isinstance(target, str)
            and _EXACT_DIGEST.match(target) is not None)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":"), default=str)


def _entry_body(entry):
    """The bytes the signature covers: everything but the signature."""
    unsigned = {k: v for k, v in entry.items() if k != "signature"}
    return _REVOCATION_DOMAIN + _canonical(unsigned).encode("utf-8")


def _iso(now):
    dt = datetime.fromtimestamp(float(now), tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


_ENTRY_FIELDS = ("v", "target_digest", "issuer_id", "revoked_at",
                 "signature")


def _check_entry_shape(entry):
    """Raise RevocationEntryUnverifiableError when the entry record is
    malformed (shape, not signature)."""
    if not isinstance(entry, dict):
        raise RevocationEntryUnverifiableError(
            "revocation-entry-unverifiable: entry is not a record")
    for field in _ENTRY_FIELDS:
        if field not in entry:
            raise RevocationEntryUnverifiableError(
                "revocation-entry-unverifiable: missing field %r"
                % (field,))
    if entry["v"] != _ENTRY_VERSION:
        raise RevocationEntryUnverifiableError(
            "revocation-entry-unverifiable: unsupported version %r"
            % (entry.get("v"),))
    if not is_exact_digest(entry["target_digest"]):
        raise RevocationEntryUnverifiableError(
            "revocation-entry-unverifiable: entry target is not an "
            "exact digest")
    if (not isinstance(entry["issuer_id"], str)
            or not entry["issuer_id"]):
        raise RevocationEntryUnverifiableError(
            "revocation-entry-unverifiable: malformed issuer_id")


def _verify_entry_signature(entry, pubkey):
    try:
        sig = bytes.fromhex(entry["signature"])
    except (TypeError, ValueError):
        raise RevocationEntryUnverifiableError(
            "revocation-entry-unverifiable: malformed signature")
    if not _ed_verify(pubkey, _entry_body(entry), sig):
        raise RevocationEntryUnverifiableError(
            "revocation-entry-unverifiable: entry signature does not "
            "verify against the pinned issuer key")


# ----------------------------------------------------------------------
# The list.
# ----------------------------------------------------------------------


class RevocationList:
    """In-memory signed revocation list (deployment-owned).

    ``check(target_digest)`` returns ``"revoked"`` or ``"active"`` and
    is the seam other registries consume (duck-typed: any object with
    ``check(digest) -> "revoked" | "active"`` works).

    ``signal_issuer`` is an optional additive hook: when it is
    ``(issuer_id, seed, scope)``, every ``revoke()`` also signs a
    posture signal (``gov/posture.py``) about the revoked digest and
    hands it to ``signal_sink`` (a callable taking the signal dict);
    the signal also rides this list's audit trail. Without both
    configured, ``revoke()`` behaves exactly as before — the hook is
    opt-in and fail-silent-free: no configuration, no signal, no
    behavior change.

    Note: the signal is emitted AFTER the revocation is recorded and
    audited, so if ``signal_sink`` raises, the exception propagates
    but the revocation itself stands. Deploy the hook with a sink
    that does not raise if you need revoke() to stay total.
    """

    def __init__(self, audit=None, signal_issuer=None, signal_sink=None):
        self._entries = {}
        self._audit = audit
        if signal_issuer is not None:
            # Fail loud at construction, not at the first revoke():
            # the hook needs exactly (issuer_id, seed, scope).
            try:
                issuer_id, seed, scope = signal_issuer
            except (TypeError, ValueError):
                raise ValueError(
                    "signal_issuer must be (issuer_id, seed, scope)")
            if not isinstance(issuer_id, str) or not issuer_id \
                    or not isinstance(seed, (bytes, bytearray)) \
                    or len(seed) != 32 \
                    or not isinstance(scope, str) or not scope:
                raise ValueError(
                    "signal_issuer must be (issuer_id, seed, scope)")
        if signal_issuer is not None and signal_sink is not None \
                and not callable(signal_sink):
            raise ValueError("signal_sink must be callable")
        self._signal_issuer = signal_issuer
        self._signal_sink = signal_sink

    def revoke(self, target_digest, *, issuer_id, seed, now=None):
        """Pin and sign the revocation of an EXACT digest.

        Refuses ``revocation-inexact-target-refused`` for anything but
        a full canonical digest. Idempotent: revoking an already-listed
        digest keeps the original entry.
        """
        if not is_exact_digest(target_digest):
            raise RevocationInexactTargetError(
                "revocation-inexact-target-refused: %r is not an exact "
                "digest — revocation by prefix, class, or wildcard is "
                "refused" % (target_digest,))
        if not isinstance(issuer_id, str) or not issuer_id:
            raise ValueError("issuer_id must be a non-empty string")
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        existing = self._entries.get(target_digest)
        if existing is not None:
            return dict(existing)
        entry = {
            "v": _ENTRY_VERSION,
            "target_digest": target_digest,
            "issuer_id": issuer_id,
            "revoked_at": _iso(time.time() if now is None else now),
        }
        entry["signature"] = _ed_sign(bytes(seed),
                                      _entry_body(entry)).hex()
        self._entries[target_digest] = entry
        if self._audit is not None:
            self._audit({"event": "revoked",
                         "target_digest": target_digest,
                         "issuer_id": issuer_id,
                         "revoked_at": entry["revoked_at"]})
        self._emit_revocation_signal(target_digest, now)
        return dict(entry)

    def _emit_revocation_signal(self, target_digest, now):
        """Optional additive hook: sign a posture signal about the
        revocation and hand it to the configured sink. No
        configuration — no signal, no behavior change."""
        if self._signal_issuer is None or self._signal_sink is None:
            return
        issuer_id, seed, scope = self._signal_issuer
        # Lazy import: revocation stays importable and byte-identical
        # in behavior without gov/posture; the hook is opt-in.
        from . import posture as _posture
        signal = _posture.emit_signal(
            "revocation", target_digest, scope, seed,
            issuer_id=issuer_id,
            now=time.time() if now is None else now,
            audit=self._audit)
        self._signal_sink(signal)

    def check(self, target_digest):
        """Return ``"revoked"`` when the exact digest is listed,
        ``"active"`` otherwise."""
        return ("revoked" if target_digest in self._entries else "active")

    def verify(self, issuer_pubkeys):
        """Verify every local entry against the pinned issuer keyset.

        Raises :class:`RevocationEntryUnverifiableError` on the first
        bad entry.
        """
        for entry in self._entries.values():
            _check_entry_shape(entry)
            pub = issuer_pubkeys.get(entry["issuer_id"])
            if pub is None:
                raise RevocationEntryUnverifiableError(
                    "revocation-entry-unverifiable: issuer %r not in the "
                    "pinned keyset" % (entry["issuer_id"],))
            _verify_entry_signature(entry, pub)
        return True

    def export(self):
        """Portable copy of the signed entries."""
        return [dict(entry) for entry in self._entries.values()]

    def import_entries(self, entries, issuer_pubkeys):
        """Import signed entries from another deployment.

        Every entry is shape-checked and its signature verified against
        the pinned keyset BEFORE anything is stored: the first bad
        entry aborts the whole import with
        ``revocation-entry-unverifiable`` and nothing is half-trusted.
        """
        if not isinstance(entries, list):
            raise RevocationEntryUnverifiableError(
                "revocation-entry-unverifiable: entries must be a list")
        staged = []
        for entry in entries:
            _check_entry_shape(entry)
            pub = issuer_pubkeys.get(entry["issuer_id"])
            if pub is None:
                raise RevocationEntryUnverifiableError(
                    "revocation-entry-unverifiable: issuer %r not in the "
                    "pinned keyset" % (entry["issuer_id"],))
            _verify_entry_signature(entry, pub)
            staged.append(dict(entry))
        for entry in staged:
            self._entries.setdefault(entry["target_digest"], entry)
