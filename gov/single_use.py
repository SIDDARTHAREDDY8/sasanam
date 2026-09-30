#!/usr/bin/env python3
"""Single-use attestations + fail-closed incomplete-evidence states.

Two small governance primitives, re-derived (nothing copied):

1. ``SingleUseRegistry`` — an attestation record that can be consumed
   exactly once. Issuance binds the attestation digest, the issuer, and
   a caller-supplied nonce into a derived ``jti`` (domain-separated
   SHA-256 over the three fields): there is no issuer-signed random
   identifier to trust, and a nonce may be used at most once — reusing
   it with a different digest still refuses, so "replay across
   different digests" cannot mint a fresh attestation. ``consume()``
   marks the ``jti`` consumed; a second ``consume`` of the same ``jti``
   refuses ``single-use-replay-refused``, an unknown ``jti`` refuses
   ``single-use-unknown``, and a tampered record (fields that no longer
   recompute its ``jti``) refuses ``single-use-malformed``. When the
   issuer bound an issuer public-key digest at issuance and a
   ``gov/revocation.py`` registry is attached, a consume whose issuer
   key is revoked refuses ``single-use-issuer-revoked`` — checked
   AFTER the replay check (replays of already-consumed records are
   replays regardless of issuer state) and BEFORE the record is marked
   consumed.

   Check order at consume (deliberate): shape -> jti recompute ->
   registry membership -> consumed (replay) -> issuer revocation.
   A forgery never learns issuer state: forgeries fail before the
   revocation lookup.

2. ``EvidenceChecker`` — fail-closed evidence completeness.
   ``require_complete(evidence_items, required_kinds)`` demands every
   required kind be present AND individually verifiable. A missing kind
   refuses ``evidence-incomplete``; a present-but-unverifiable item
   refuses ``evidence-unverifiable-item`` — the item is present, so
   claiming "incomplete" would launder a bad item into a milder code.
   Verifiers are registered per kind; an item whose verifier raises or
   returns falsy fails closed as unverifiable. Composition:
   ``SingleUseRegistry.attestation_evidence_verifier()`` returns the
   verifier for kind ``"single-use-attestation"`` — a successfully
   consumed attestation counts as one verified evidence item.

The list is in-memory; persistence (crash-safe consumed sets,
shared atomic state) is deployment-owned, documented here as an
honest residual: a restarted process forgets consumed ``jti``s, so
deployments MUST persist the consumed set before they are
replay-safe across restarts.

Stdlib only. No network. $0.
"""

import hashlib
import time
from datetime import datetime, timezone

from .revocation import is_exact_digest

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class SingleUseError(Exception):
    """Base class for all single-use attestation refusals. ``code`` is
    machine-readable."""

    code = "single-use-refused"


class _Replay(SingleUseError):
    code = "single-use-replay-refused"


class _Unknown(SingleUseError):
    code = "single-use-unknown"


class _IssuerRevoked(SingleUseError):
    code = "single-use-issuer-revoked"


class _Malformed(SingleUseError):
    code = "single-use-malformed"


class EvidenceError(Exception):
    """Base class for all evidence-completeness refusals. ``code`` is
    machine-readable."""

    code = "evidence-refused"


class _Incomplete(EvidenceError):
    code = "evidence-incomplete"


class _UnverifiableItem(EvidenceError):
    code = "evidence-unverifiable-item"


# ----------------------------------------------------------------------
# Internals.
# ----------------------------------------------------------------------

_JTI_DOMAIN = b"sasanam-single-use-v1:"
_RECORD_VERSION = 1
_EVIDENCE_KIND = "single-use-attestation"


def _derive_jti(attestation_digest, issuer, nonce):
    """Domain-separated SHA-256 over the bound fields. Deterministic:
    the jti commits to exactly (digest, issuer, nonce)."""
    h = hashlib.sha256(_JTI_DOMAIN)
    for part in (attestation_digest, issuer, nonce):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def _iso(now):
    return datetime.fromtimestamp(now, tz=timezone.utc).isoformat()


# ----------------------------------------------------------------------
# Single-use attestation registry.
# ----------------------------------------------------------------------


class SingleUseRegistry:
    """Issue-once, consume-once attestation records.

    ``revocation_registry`` is optional and duck-typed: any object with
    ``check(digest) -> "revoked" | "active"`` works
    (``gov/revocation.py``'s ``RevocationList`` qualifies). Without one,
    no issuer-revocation check runs — the issuer key binding is then
    purely nominal, documented per record.
    """

    def __init__(self, revocation_registry=None):
        if revocation_registry is not None \
                and not callable(getattr(revocation_registry, "check",
                                         None)):
            raise ValueError(
                "revocation_registry must expose check(digest)")
        self._revocation_registry = revocation_registry
        self._records = {}   # jti -> record dict
        self._nonces = set()  # every nonce ever issued (single-use)
        self._consumed = set()  # jtis consumed

    def issue(self, attestation_digest, issuer, nonce, *,
              issuer_pubkey_digest=None, now=None):
        """Bind (digest, issuer, nonce) into an attestation record with a
        derived jti. Refuses ``single-use-replay-refused`` if the nonce
        was ever used before — including with a DIFFERENT digest, so a
        nonce cannot mint a second attestation. ``issuer_pubkey_digest``
        optionally binds the issuer's key so a later key revocation can
        be checked at consume time."""
        if not is_exact_digest(attestation_digest):
            raise ValueError(
                "attestation_digest must be an exact full digest")
        if not isinstance(issuer, str) or not issuer:
            raise ValueError("issuer must be a non-empty string")
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("nonce must be a non-empty string")
        if issuer_pubkey_digest is not None \
                and not is_exact_digest(issuer_pubkey_digest):
            raise ValueError(
                "issuer_pubkey_digest must be an exact full digest")
        if nonce in self._nonces:
            raise _Replay(
                "single-use-replay-refused: nonce %r was already issued — "
                "nonces are single-use, even across digests" % (nonce,))
        jti = _derive_jti(attestation_digest, issuer, nonce)
        record = {
            "v": _RECORD_VERSION,
            "jti": jti,
            "attestation_digest": attestation_digest,
            "issuer": issuer,
            "issuer_pubkey_digest": issuer_pubkey_digest,
            "nonce": nonce,
            "issued_at": _iso(time.time() if now is None else now),
        }
        self._records[jti] = dict(record)
        self._nonces.add(nonce)
        return dict(record)

    def consume(self, attestation):
        """Consume an attestation record exactly once.

        Check order (deliberate): shape -> jti recompute -> registry
        membership -> consumed (replay) -> issuer revocation. On success
        the jti is marked consumed and a ``"single-use-attestation"``
        evidence item is returned.
        """
        if not isinstance(attestation, dict) \
                or attestation.get("v") != _RECORD_VERSION:
            raise _Malformed(
                "single-use-malformed: attestation is not a v%d record"
                % _RECORD_VERSION)
        for field in ("jti", "attestation_digest", "issuer", "nonce"):
            if not isinstance(attestation.get(field), str) \
                    or not attestation[field]:
                raise _Malformed(
                    "single-use-malformed: field %r missing or invalid"
                    % (field,))
        expected = _derive_jti(attestation["attestation_digest"],
                               attestation["issuer"],
                               attestation["nonce"])
        if attestation["jti"] != expected:
            raise _Malformed(
                "single-use-malformed: jti does not recompute from the "
                "record's (digest, issuer, nonce) — the record was "
                "tampered with")
        jti = attestation["jti"]
        if jti not in self._records:
            raise _Unknown(
                "single-use-unknown: jti %s was never issued here"
                % (jti[:16],))
        if jti in self._consumed:
            raise _Replay(
                "single-use-replay-refused: jti %s already consumed"
                % (jti[:16],))
        issuer_pubkey_digest = attestation.get("issuer_pubkey_digest")
        if self._revocation_registry is not None \
                and issuer_pubkey_digest is not None \
                and self._revocation_registry.check(
                    issuer_pubkey_digest) == "revoked":
            raise _IssuerRevoked(
                "single-use-issuer-revoked: the issuer key bound to this "
                "attestation is revoked")
        self._consumed.add(jti)
        return {
            "kind": _EVIDENCE_KIND,
            "jti": jti,
            "attestation_digest": attestation["attestation_digest"],
            "issuer": attestation["issuer"],
            "consumed_at": _iso(time.time()),
        }

    def is_consumed(self, jti):
        """True when the jti was issued here and already consumed."""
        return isinstance(jti, str) and jti in self._consumed

    def attestation_evidence_verifier(self):
        """The ``EvidenceChecker`` verifier for kind
        ``"single-use-attestation"``: accepts exactly the evidence items
        this registry produced (jti issued here AND consumed here)."""
        registry = self

        def verify(item):
            if not isinstance(item, dict):
                return False
            if item.get("kind") != _EVIDENCE_KIND:
                return False
            jti = item.get("jti")
            if not registry.is_consumed(jti):
                return False
            record = registry._records.get(jti)
            return (isinstance(record, dict)
                    and record.get("attestation_digest")
                    == item.get("attestation_digest")
                    and record.get("issuer") == item.get("issuer"))

        return verify


# ----------------------------------------------------------------------
# Fail-closed evidence completeness.
# ----------------------------------------------------------------------


class EvidenceChecker:
    """Demand every required evidence kind present AND verifiable.

    Verifiers are registered per kind: ``callable(item) -> bool``.
    A verifier that raises fails closed (the item is unverifiable).
    """

    def __init__(self, verifiers=None):
        self._verifiers = {}
        for kind, verifier in (verifiers or {}).items():
            self.register(kind, verifier)

    def register(self, kind, verifier):
        """Add (or replace) the verifier for a kind. Additive."""
        if not isinstance(kind, str) or not kind:
            raise ValueError("kind must be a non-empty string")
        if not callable(verifier):
            raise ValueError("verifier must be callable")
        self._verifiers[kind] = verifier

    def require_complete(self, evidence_items, required_kinds):
        """Verify completeness. For each required kind: missing kind ->
        ``evidence-incomplete``; any present item whose verifier fails
        or is absent -> ``evidence-unverifiable-item``. Returns
        ``{"kinds": [...], "items": [...]}`` of verified items."""
        if not isinstance(evidence_items, list):
            raise ValueError("evidence_items must be a list")
        required = list(required_kinds or [])
        for kind in required:
            if not isinstance(kind, str) or not kind:
                raise ValueError("required kinds must be non-empty strings")
        seen_kinds = []
        verified_items = []
        for kind in required:
            items = [i for i in evidence_items
                     if isinstance(i, dict) and i.get("kind") == kind]
            if not items:
                raise _Incomplete(
                    "evidence-incomplete: required kind %r is absent — "
                    "absence is never treated as benign" % (kind,))
            verifier = self._verifiers.get(kind)
            for item in items:
                try:
                    ok = bool(verifier(item)) if verifier is not None else False
                except Exception:  # noqa: BLE001
                    ok = False  # a verifier that raises fails closed
                if not ok:
                    raise _UnverifiableItem(
                        "evidence-unverifiable-item: kind %r is present "
                        "but its evidence could not be verified — a bad "
                        "item is not the same as a missing kind" % (kind,))
            seen_kinds.append(kind)
            verified_items.extend(items)
        return {"kinds": seen_kinds, "items": verified_items}
