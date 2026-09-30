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

Algorithm agility (see ``gov/alg_registry.py``): ``revoke`` takes an
optional ``alg`` naming the signing tier. The default
``ed25519-rfc8032`` emits byte-identical entries to the pre-agility
format (no "alg" field); non-default tiers carry their "alg" name in
the signed entry. ``verify`` / ``import_entries`` dispatch by the
entry's named algorithm, resolve legacy entries (no "alg") as
``ed25519-rfc8032``, and accept an ``expect_alg`` pin that refuses
``alg-mismatch`` when the entry's tier differs. MAC-tier entries
prove authenticity only to key-holders — never treat them as
non-repudiation evidence.

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

from . import alg_registry as _algs

_ALGS = _algs.default_registry()

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


def _verify_entry_signature(entry, pubkey, expect_alg=None):
    """Verify the entry's signature under its named algorithm.

    Legacy entries carry no "alg" field and verify as
    ``ed25519-rfc8032``. Unknown names refuse ``alg-unregistered``;
    a pinned ``expect_alg`` that differs refuses ``alg-mismatch``.
    """
    try:
        sig = bytes.fromhex(entry["signature"])
    except (TypeError, ValueError):
        raise RevocationEntryUnverifiableError(
            "revocation-entry-unverifiable: malformed signature")
    try:
        alg = _algs.extract_record_alg(
            entry, expect_alg,
            lambda: RevocationEntryUnverifiableError(
                "revocation-entry-unverifiable: malformed alg field %r"
                % (entry.get("alg"),)))
    except _algs.AlgError as exc:
        # Keep the module's error contract (a bad entry refuses
        # revocation-entry-unverifiable) while preserving the
        # machine-readable agility code.
        raise RevocationEntryUnverifiableError(str(exc),
                                               code=exc.code)
    # Algorithm-confusion opt-in (CWE-347): only a caller that pinned
    # expect_alg to a symmetric tier declares the key a shared secret.
    # Otherwise a MAC-tier entry refuses instead of HMACing with an
    # attacker-known public key.
    for_secret = expect_alg is not None \
        and _ALGS.is_symmetric(expect_alg)
    if not _ALGS.verify(alg, _entry_body(entry), sig, pubkey,
                        for_symmetric_key=for_secret):
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

    def revoke(self, target_digest, *, issuer_id, seed, now=None,
               alg=_algs.DEFAULT_ALG):
        """Pin and sign the revocation of an EXACT digest.

        Refuses ``revocation-inexact-target-refused`` for anything but
        a full canonical digest, and ``alg-unregistered`` for an
        unknown signing algorithm. Idempotent: revoking an
        already-listed digest keeps the original entry.

        ``alg`` names the signing tier (see ``gov/alg_registry.py``);
        the default tier emits byte-identical entries to the
        pre-agility format (no "alg" field). MAC-tier entries prove
        authenticity only to key-holders — never treat them as
        non-repudiation evidence.
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
        try:
            _ALGS.info(alg)  # alg-unregistered for unknown tiers
        except _algs.AlgError as exc:
            raise RevocationError(str(exc), code=exc.code)
        existing = self._entries.get(target_digest)
        if existing is not None:
            return dict(existing)
        entry = {
            "v": _ENTRY_VERSION,
            "target_digest": target_digest,
            "issuer_id": issuer_id,
            "revoked_at": _iso(time.time() if now is None else now),
        }
        _algs.stamp_record_alg(entry, alg)
        entry["signature"] = _ALGS.sign(alg, _entry_body(entry),
                                        bytes(seed)).hex()
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

    def verify(self, issuer_pubkeys, *, expect_alg=None):
        """Verify every local entry against the pinned issuer keyset.

        Raises :class:`RevocationEntryUnverifiableError` on the first
        bad entry. ``expect_alg`` pins the expected signing tier:
        unknown tiers refuse ``alg-unregistered`` and a differing
        tier refuses ``alg-mismatch``. Legacy entries (no "alg")
        verify as ``ed25519-rfc8032``.
        """
        for entry in self._entries.values():
            _check_entry_shape(entry)
            pub = issuer_pubkeys.get(entry["issuer_id"])
            if pub is None:
                raise RevocationEntryUnverifiableError(
                    "revocation-entry-unverifiable: issuer %r not in the "
                    "pinned keyset" % (entry["issuer_id"],))
            _verify_entry_signature(entry, pub, expect_alg=expect_alg)
        return True

    def export(self):
        """Portable copy of the signed entries."""
        return [dict(entry) for entry in self._entries.values()]

    def import_entries(self, entries, issuer_pubkeys, *,
                       expect_alg=None):
        """Import signed entries from another deployment.

        Every entry is shape-checked and its signature verified against
        the pinned keyset BEFORE anything is stored: the first bad
        entry aborts the whole import with
        ``revocation-entry-unverifiable`` and nothing is half-trusted.
        ``expect_alg`` pins the expected signing tier (see
        :meth:`verify`).
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
            _verify_entry_signature(entry, pub, expect_alg=expect_alg)
            staged.append(dict(entry))
        for entry in staged:
            self._entries.setdefault(entry["target_digest"], entry)
