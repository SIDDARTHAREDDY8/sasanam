#!/usr/bin/env python3
"""Live parent re-verification at use time.

ADAPT of the Mandate JWT -06 direction (re-derived prose; nothing
copied): a credential, capsule, or lease chain that was verified once
at issuance is not enough. At USE time the consumer must re-verify
the parent record's signature AND its current non-revoked state AND
its liveness. Trust is re-established per use, never inherited from
an earlier check.

A "use envelope" carries the parent record plus what is needed to
re-check it::

    {"v": 1,
     "parent_kind": "posture-signal" | "absence-negative" | "revocation-entry",
     "parent": <the signed parent record dict>,
     "parent_pubkeys": {issuer_id: pubkey_bytes},
     "parent_digest": <exact digest, for the revocation lookup>,
     "parent_expires_at": <float epoch | None>,
     "last_verified_at": <float epoch of a prior verification | None>}

``UseTimeVerifier.verify_at_use`` checks, in fixed order — signature,
revocation, liveness — so a forged parent never learns whether it is
revoked, and a revoked parent never gets a liveness pass:

* signature: kind-dispatched to the repo's own public verify seams
  (``gov/posture.py``, ``gov/absence.py``, ``gov/revocation.py``),
  which themselves dispatch by the record's named algorithm via
  ``gov/alg_registry.py``. Any failure refuses
  ``reverify-parent-signature-invalid`` (the inner module's code is
  preserved in the detail); an unknown ``parent_kind`` refuses
  ``reverify-unknown-parent-kind``. Deployments may
  ``register_parent_kind`` their own adapters; the registry never
  admits silently.
* revocation: when a ``revocation_registry`` is attached (duck-typed:
  ``check(digest) -> "revoked" | "active"``), a revoked
  ``parent_digest`` refuses ``reverify-revoked``. With no registry
  attached the check is skipped, never invented — a missing registry
  is a documented deployment gap, not a pass.
* liveness: a ``parent_expires_at`` at or before now refuses
  ``reverify-stale``; a ``last_verified_at`` older than
  ``max_verification_age`` (default 300s) also refuses
  ``reverify-stale`` — a cached verification replayed past its age
  is not a live check.

On success a ``UseTimeReceipt`` is returned::

    {"v": 1, "record_digest": <sha256 of the canonical parent>,
     "parent_digest": <...>, "verified_at": <float epoch>,
     "outcome": "verified"}

The receipt is EVIDENCE, never authority:
``reverify_receipt_carries_no_authority`` refuses
``reverify-not-authorization`` for receipt-shaped records at
authority seams.

Malformed envelopes refuse ``reverify-malformed`` — runtime data is
never trusted enough for a bare TypeError escape.

Stdlib only. No network. $0.
"""

import json
import time
from hashlib import sha256

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class ReverifyError(Exception):
    """Base class for all use-time re-verification refusals. ``code``
    is machine-readable."""

    code = "reverify-refused"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class ReverifyMalformedError(ReverifyError):
    """The use envelope is not a well-formed record."""

    code = "reverify-malformed"


class ReverifyUnknownParentKindError(ReverifyError):
    """The envelope names a parent kind no adapter verifies."""

    code = "reverify-unknown-parent-kind"


class ReverifyParentSignatureInvalidError(ReverifyError):
    """The parent record's signature does not verify against the
    pinned keyset (or the keyset has no key for its issuer)."""

    code = "reverify-parent-signature-invalid"


class ReverifyRevokedError(ReverifyError):
    """The parent digest is revoked in the attached registry."""

    code = "reverify-revoked"


class ReverifyStaleError(ReverifyError):
    """The parent is past its TTL, or the last verification is
    older than max_verification_age — this is not a live check."""

    code = "reverify-stale"


class ReverifyRequiredError(ReverifyError):
    """A use-time re-verification was required and is missing or
    invalid (permit-leases redeem seam)."""

    code = "reverify-required"


class ReverifyNotAuthorizationError(ReverifyError):
    """A use-time receipt was offered where authorization is
    required. Receipts are evidence, never authority."""

    code = "reverify-not-authorization"


# ----------------------------------------------------------------------
# Canonical encoding.
# ----------------------------------------------------------------------

_RECEIPT_VERSION = 1
_ENVELOPE_VERSION = 1


def _canonical(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":"), default=str)


def _record_digest(parent):
    return "sha256:" + sha256(
        _canonical(parent).encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------
# Parent-kind adapters (public verify seams only).
# ----------------------------------------------------------------------


def _verify_posture_signal(parent, pubkeys, expect_alg):
    from . import posture as _posture  # lazy: keeps module importable
    if not isinstance(pubkeys, dict) or not pubkeys:
        raise ReverifyParentSignatureInvalidError(
            "reverify-parent-signature-invalid: no pinned issuer "
            "keyset for a posture-signal parent")
    return _posture.verify_signal(parent, pubkeys,
                                  expect_alg=expect_alg)


def _verify_absence_negative(parent, pubkeys, expect_alg):
    from . import absence as _absence  # lazy: keeps module importable
    issuer_id = parent.get("issuer_id") if isinstance(parent, dict) \
        else None
    key = pubkeys.get(issuer_id) if isinstance(pubkeys, dict) else None
    if key is None:
        raise ReverifyParentSignatureInvalidError(
            "reverify-parent-signature-invalid: no pinned key for "
            "absence issuer %r" % (issuer_id,))
    return _absence.verify_negative(parent, key,
                                    expect_alg=expect_alg)


def _verify_revocation_entry(parent, pubkeys, expect_alg):
    from . import revocation as _revocation  # lazy: keeps importable
    if not isinstance(pubkeys, dict) or not pubkeys:
        raise ReverifyParentSignatureInvalidError(
            "reverify-parent-signature-invalid: no pinned issuer "
            "keyset for a revocation-entry parent")
    # The public import seam verifies every entry's signature
    # against the pinned keyset and refuses revocation-entry-
    # unverifiable on the first bad one: exactly the use-time
    # check we need. The throwaway list holds only this entry.
    _revocation.RevocationList().import_entries([parent], pubkeys,
                                                expect_alg=expect_alg)
    return parent


_BUILTIN_ADAPTERS = {
    "posture-signal": _verify_posture_signal,
    "absence-negative": _verify_absence_negative,
    "revocation-entry": _verify_revocation_entry,
}


# ----------------------------------------------------------------------
# The verifier.
# ----------------------------------------------------------------------


class UseTimeVerifier:
    """Re-verify a parent record at the moment of use.

    ``revocation_registry`` is an optional duck-typed source with
    ``check(digest) -> "revoked" | "active"``
    (``gov/revocation.py``'s ``RevocationList.check`` or any
    equivalent). ``max_verification_age`` caps how old a prior
    ``last_verified_at`` may be (seconds, default 300).
    ``now`` is an injectable clock for determinism; ``audit``
    receives ``reverify_verified`` / ``reverify_refused`` entries.
    """

    def __init__(self, *, revocation_registry=None,
                 max_verification_age=300, now=None, audit=None):
        self._revocation_registry = revocation_registry
        self._max_age = float(max_verification_age)
        if not self._max_age > 0:
            raise ValueError("max_verification_age must be positive")
        self._now = now or time.time
        self._audit = audit
        self._adapters = dict(_BUILTIN_ADAPTERS)

    def register_parent_kind(self, kind, verify_fn):
        """Register an adapter for a new parent kind.

        ``verify_fn(parent_record, parent_pubkeys, expect_alg)``
        must raise on anything unverifiable and return the verified
        record otherwise. Malformed registrations are an authoring
        bug (ValueError), caught here, never at use time.
        """
        if not isinstance(kind, str) or not kind:
            raise ValueError("kind must be a non-empty string")
        if not callable(verify_fn):
            raise ValueError("verify_fn must be callable")
        if kind in self._adapters:
            raise ValueError("parent kind %r is already registered"
                             % (kind,))
        self._adapters[kind] = verify_fn

    def _refuse(self, exc, envelope):
        if self._audit is not None:
            self._audit({"event": "reverify_refused",
                         "code": exc.code,
                         "parent_kind": envelope.get("parent_kind")
                         if isinstance(envelope, dict) else None,
                         "parent_digest": envelope.get("parent_digest")
                         if isinstance(envelope, dict) else None})
        raise exc

    @staticmethod
    def _check_envelope_shape(envelope):
        """Authoring/runtime-data validation: malformed envelopes
        refuse ``reverify-malformed``, never escape raw."""
        if not isinstance(envelope, dict):
            raise ReverifyMalformedError(
                "reverify-malformed: use envelope is not a record")
        if envelope.get("v") != _ENVELOPE_VERSION:
            raise ReverifyMalformedError(
                "reverify-malformed: unsupported envelope version %r"
                % (envelope.get("v"),))
        kind = envelope.get("parent_kind")
        if not isinstance(kind, str) or not kind:
            raise ReverifyMalformedError(
                "reverify-malformed: parent_kind must be a non-empty "
                "string")
        if not isinstance(envelope.get("parent"), dict):
            raise ReverifyMalformedError(
                "reverify-malformed: parent must be a record")
        if not isinstance(envelope.get("parent_pubkeys"), dict) \
                or not envelope["parent_pubkeys"]:
            raise ReverifyMalformedError(
                "reverify-malformed: parent_pubkeys must be a "
                "non-empty dict")
        if not isinstance(envelope.get("parent_digest"), str) \
                or not envelope["parent_digest"]:
            raise ReverifyMalformedError(
                "reverify-malformed: parent_digest must be a "
                "non-empty string")
        for field in ("parent_expires_at", "last_verified_at"):
            value = envelope.get(field)
            if value is not None and not isinstance(value,
                                                    (int, float)):
                raise ReverifyMalformedError(
                    "reverify-malformed: %s must be a number or null"
                    % (field,))
        return envelope

    def _verify_parent_signature(self, envelope, expect_alg):
        adapter = self._adapters.get(envelope["parent_kind"])
        if adapter is None:
            raise ReverifyUnknownParentKindError(
                "reverify-unknown-parent-kind: no adapter verifies "
                "parent kind %r — fail closed, never trust"
                % (envelope["parent_kind"],))
        try:
            adapter(envelope["parent"], envelope["parent_pubkeys"],
                    expect_alg)
        except ReverifyError:
            raise
        except Exception as exc:  # noqa: BLE001 - wrapped, never raw
            # The module's own verify seam refused: wrap it in the
            # reverify vocabulary while preserving the inner code in
            # the detail for triage.
            inner = getattr(exc, "code", exc.__class__.__name__)
            raise ReverifyParentSignatureInvalidError(
                "reverify-parent-signature-invalid: parent signature "
                "does not verify (%s)" % (inner,))

    def _check_revocation(self, envelope):
        if self._revocation_registry is None:
            return  # no registry: the check is skipped, not invented
        if self._revocation_registry.check(
                envelope["parent_digest"]) != "active":
            raise ReverifyRevokedError(
                "reverify-revoked: parent digest %r is revoked in "
                "the attached registry"
                % (envelope["parent_digest"],))

    def _check_liveness(self, envelope, now):
        expires = envelope.get("parent_expires_at")
        if expires is not None and now >= float(expires):
            raise ReverifyStaleError(
                "reverify-stale: parent record is past its TTL "
                "(expired at %r)" % (expires,))
        last = envelope.get("last_verified_at")
        if last is not None:
            # The spec names only the "older than max_verification_age"
            # case: a last_verified_at in the future (clock skew) is
            # not "older", so it is not refused here — the parent
            # signature check is the forgery boundary, not this clock.
            if now - float(last) > self._max_age:
                raise ReverifyStaleError(
                    "reverify-stale: last verification is older than "
                    "max_verification_age %ss — this is not a live "
                    "check" % (self._max_age,))

    def verify_at_use(self, envelope, *, expect_alg=None):
        """Re-verify the envelope's parent at the moment of use.

        Fixed order: signature -> revocation -> liveness. Returns a
        ``UseTimeReceipt`` ``{v, record_digest, parent_digest,
        verified_at, outcome}``. ``expect_alg`` pins the parent's
        expected signing tier; the adapters refuse the inner
        ``alg-mismatch`` (surfaced as
        ``reverify-parent-signature-invalid``) when it differs.
        """
        try:
            envelope = self._check_envelope_shape(envelope)
            now = float(self._now())
            self._verify_parent_signature(envelope, expect_alg)
            self._check_revocation(envelope)
            self._check_liveness(envelope, now)
            verified_at = float(self._now())  # check-complete, not
            # check-start: the receipt evidences a completed check.
        except ReverifyError as exc:
            self._refuse(exc, envelope)
        receipt = {"v": _RECEIPT_VERSION,
                   "record_digest": _record_digest(envelope["parent"]),
                   "parent_digest": envelope["parent_digest"],
                   "verified_at": verified_at,
                   "outcome": "verified"}
        if self._audit is not None:
            self._audit({"event": "reverify_verified",
                         "parent_kind": envelope["parent_kind"],
                         "parent_digest": envelope["parent_digest"],
                         "verified_at": now})
        return receipt


def reverify_receipt_carries_no_authority(record):
    """Refuse ``reverify-not-authorization`` for receipt-shaped
    records at authority seams.

    A use-time receipt is evidence that a live check ran — it never
    authorizes anything. The marker is the receipt's own full shape
    (``v`` + ``record_digest`` + ``parent_digest`` + ``verified_at``
    + ``outcome: "verified"``), so records that merely carry adjacent
    timestamp fields pass through.
    """
    if (isinstance(record, dict)
            and record.get("v") == _RECEIPT_VERSION
            and record.get("outcome") == "verified"
            and "record_digest" in record
            and "parent_digest" in record
            and "verified_at" in record):
        raise ReverifyNotAuthorizationError(
            "reverify-not-authorization: a use-time receipt is "
            "evidence of a live check, never authorization — it "
            "cannot stand in for a grant")
    return True


__all__ = [
    "ReverifyError",
    "ReverifyMalformedError",
    "ReverifyUnknownParentKindError",
    "ReverifyParentSignatureInvalidError",
    "ReverifyRevokedError",
    "ReverifyStaleError",
    "ReverifyRequiredError",
    "ReverifyNotAuthorizationError",
    "UseTimeVerifier",
    "reverify_receipt_carries_no_authority",
]
