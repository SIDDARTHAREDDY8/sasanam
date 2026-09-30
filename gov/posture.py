#!/usr/bin/env python3
"""Signed posture signals: events, not authority.

ADAPT of the EMILIA PIP-011 EP-EYE-SET-v1 pattern (re-derived prose;
nothing copied): when revocation or denial events occur, the system
emits a signed posture SIGNAL record — shaped like an RFC 8417
Security Event Token with our own event URNs::

    {v, iss, jti, iat, sub, events, scope, signature}

The signal rides IN-BAND with the decision (the audit trail), never
as the decision. The key invariant, enforced in code:

    A POSTURE SIGNAL IS NEVER AUTHORIZATION.

:func:`signal_carries_no_authority` is the guard at authorization
seams: a signal-shaped record offered where authority is required
fails closed with ``signal-not-authorization`` — even a perfectly
valid, well-signed signal. A record that looks like a signal with a
field stripped (a fragment) is refused too: ambiguity about whether
something is a signal fails closed. Anything that is neither a
signal nor a fragment passes through for the real gate to decide.

Signals carry a ``scope`` claim (e.g. ``"permit"``,
``"admission"``): a consumer pins the scope it cares about, and
cross-scope replay refuses ``signal-scope-mismatch`` — a revocation
signal cannot be replayed as an admission signal.

The event vocabulary is closed. ``emit_signal`` refuses
``signal-unknown-event`` for anything outside::

    revocation | permit-refusal | admission-refusal | absence-attribution

Each maps to a URN under ``urn:sasanam:posture:v1:`` (RFC 8417 uses
URIs for event names; URNs avoid claiming a domain we do not own).

Events other than ``revocation`` also carry a closed KIND so the
refusal cause is discriminated, not collapsed: ``permit-refusal``
distinguishes ``permit-revoked`` from ``approval-digest-diverged``;
``admission-refusal`` carries the admission refusal code;
``absence-attribution`` carries the absence claim. ``emit_signal``
refuses ``signal-kind-required`` when the event demands a kind and
none was given, and ``signal-unknown-kind`` for a kind outside the
event's closed set.

:func:`emit_absence_signal` composes with ``gov/absence.py``: it
attests the absence through the issuer's own absence machinery and
then signs the posture signal with the absence claim as the kind —
the signal is evidence ABOUT the negative outcome, never the
outcome itself.

Ed25519 comes from the repo's vendored RFC 8032 ``gov/ed25519.py``;
``verify`` there is fail-closed and this module keeps that property:
every verification failure becomes ``signal-unverifiable``.

Algorithm agility (see ``gov/alg_registry.py``): ``emit_signal``
takes an optional ``alg`` naming the signing algorithm. The default
``ed25519-rfc8032`` emits byte-identical records to the pre-agility
format (no "alg" field); non-default tiers carry their "alg" name in
the signed record. ``verify_signal`` dispatches by the record's
named algorithm, resolves legacy records (no "alg") as
``ed25519-rfc8032``, and accepts an ``expect_alg`` pin that refuses
``alg-mismatch`` when the record's tier differs. MAC-tier signals
prove authenticity only to key-holders — never treat them as
non-repudiation evidence.

Issuer seed custody is deployment-owned, same as the absence and
revocation issuers. The module is in-memory; persistence is the
deployer's job.

Stdlib only. No network. $0.
"""

import hashlib
import json
import time
from datetime import datetime, timezone

from . import alg_registry as _algs

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class PostureError(Exception):
    """Base class for all posture-signal refusals. ``code`` is
    machine-readable."""

    code = "posture-refused"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class SignalUnverifiableError(PostureError):
    """The signal is unsigned, forged, tampered, or malformed."""

    code = "signal-unverifiable"


class SignalScopeMismatchError(PostureError):
    """The signal's scope does not match the consumer's pinned
    scope — cross-scope replay."""

    code = "signal-scope-mismatch"


class SignalNotAuthorizationError(PostureError):
    """A posture signal was offered where authorization was
    required. Signals are evidence for the audit trail, never
    authority."""

    code = "signal-not-authorization"


class SignalUnknownEventError(PostureError):
    """The event is outside the closed posture-signal vocabulary."""

    code = "signal-unknown-event"


class SignalKindRequiredError(PostureError):
    """The event's closed kind set is non-empty and no kind was
    given — the refusal cause would be undiscriminated."""

    code = "signal-kind-required"


class SignalUnknownKindError(PostureError):
    """The kind is outside the event's closed kind set."""

    code = "signal-unknown-kind"


# ----------------------------------------------------------------------
# Canonical encoding.
# ----------------------------------------------------------------------

_POSTURE_DOMAIN = b"sasanam-posture/v1:"
_SIGNAL_VERSION = 1
_POSTURE_URN_PREFIX = "urn:sasanam:posture:v1:"

# Closed vocabulary. Re-derived; nothing copied.
_EVENTS = {
    "revocation": "urn:sasanam:posture:v1:revocation",
    "permit-refusal": "urn:sasanam:posture:v1:permit-refusal",
    "admission-refusal": "urn:sasanam:posture:v1:admission-refusal",
    "absence-attribution": "urn:sasanam:posture:v1:absence-attribution",
}

# Closed kind sets per event. The kinds are the repo's own refusal
# codes (admission) and claim vocabulary (absence), so a signal
# names the exact cause instead of collapsing it.
_EVENT_KINDS = {
    "revocation": (),
    "permit-refusal": ("permit-revoked", "approval-digest-diverged"),
    "admission-refusal": ("admission-digest-mismatch",
                          "admission-issuer-untrusted",
                          "admission-format-unknown",
                          "admission-unverifiable"),
    "absence-attribution": ("never-advertised",
                            "advertised-but-missing", "revoked"),
}

_SIGNAL_FIELDS = ("v", "iss", "jti", "iat", "sub", "events",
                  "scope", "signature")

# Records minted with the default algorithm carry no "alg" field:
# they are byte-identical to the pre-agility records, and legacy
# records without one verify as ed25519-rfc8032. Only non-default
# tiers name their algorithm.
_ALGS = _algs.default_registry()


def _canonical(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":"), default=str)


def _iso(now):
    dt = datetime.fromtimestamp(float(now), tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _signal_body(signal):
    """The bytes the signature covers: everything but the signature."""
    unsigned = {k: v for k, v in signal.items() if k != "signature"}
    return _POSTURE_DOMAIN + _canonical(unsigned).encode("utf-8")


def _jti(iss, sub, events, iat):
    """Deterministic unique id: the digest of the signed content that
    makes the signal unique. Same inputs, same jti — replayable for
    audits, and deterministic under a fixed clock for tests."""
    material = _canonical({"iss": iss, "sub": sub,
                           "events": events, "iat": iat})
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _shape_is_signal(record):
    """True when the record has the full posture-signal shape."""
    return (isinstance(record, dict)
            and record.get("v") == _SIGNAL_VERSION
            and isinstance(record.get("events"), dict)
            and "iss" in record and "jti" in record
            and "sub" in record)


def _looks_like_signal_fragment(record):
    """True when the record carries posture-specific markers but is
    not a full signal — a stripped or hand-built fragment.

    The markers are chosen to avoid false positives on the repo's
    other records: attestation statements carry iss/jti/sub/iat but
    no ``v`` and no posture-URN events map; artifact-sweep reports
    carry an ``events`` LIST, never a dict. Ambiguity about whether
    something is a signal fails closed at authority seams.
    """
    if not isinstance(record, dict):
        return False
    events = record.get("events")
    if isinstance(events, dict) and any(
            isinstance(k, str) and k.startswith(_POSTURE_URN_PREFIX)
            for k in events):
        return True
    return (record.get("v") == _SIGNAL_VERSION
            and "iss" in record and "jti" in record)


# ----------------------------------------------------------------------
# Emission (issuer side; holds the seed).
# ----------------------------------------------------------------------


def _resolve_alg(record, expect_alg):
    """Resolve and validate the record's algorithm name.

    The "alg" field is optional: records minted with the default
    algorithm (and all legacy records) carry none and resolve to
    ``ed25519-rfc8032``. Unknown names refuse ``alg-unregistered``
    and a pinned ``expect_alg`` that differs refuses
    ``alg-mismatch`` — both wrapped as
    :class:`SignalUnverifiableError` so the module's error contract
    holds while the machine-readable code is preserved. A
    non-string "alg" field is a malformed record and refuses
    ``signal-unverifiable``.
    """
    try:
        return _algs.extract_record_alg(
            record, expect_alg,
            lambda: SignalUnverifiableError(
                "signal-unverifiable: malformed alg field %r"
                % (record.get("alg"),)))
    except _algs.AlgError as exc:
        raise SignalUnverifiableError(str(exc), code=exc.code)


def _check_kind(event, kind):
    allowed = _EVENT_KINDS[event]
    if not allowed:
        if kind is not None:
            raise SignalUnknownKindError(
                "signal-unknown-kind: event %r takes no kind"
                % (event,))
        return None
    if kind is None:
        raise SignalKindRequiredError(
            "signal-kind-required: event %r demands one of %r"
            % (event, list(allowed)))
    if kind not in allowed:
        raise SignalUnknownKindError(
            "signal-unknown-kind: %r is outside the closed kind set "
            "for event %r" % (kind, event))
    return kind


def emit_signal(event, subject_digest, scope, issuer_seed, *,
                issuer_id, now=None, audit=None, kind=None,
                alg=_algs.DEFAULT_ALG):
    """Sign and return a posture signal for ``event`` about
    ``subject_digest``.

    Refuses ``signal-unknown-event`` for anything outside the closed
    vocabulary, ``signal-kind-required`` when the event demands a
    kind and none was given, ``signal-unknown-kind`` for a kind
    outside the event's closed set, and ``alg-unregistered`` when
    ``alg`` is not a registered algorithm. When ``audit`` is
    supplied, the signal also rides the audit trail as a
    ``posture_signal`` entry (in-band, never as a decision).

    ``alg`` names the signing algorithm (see ``gov/alg_registry.py``).
    It defaults to ``ed25519-rfc8032`` and the default emit is
    byte-identical to the pre-agility records: no "alg" field is
    added. Non-default tiers (e.g. the ``hmac-sha256-mac`` MAC tier)
    carry their "alg" name in the signed record. MAC-tier signals
    are authenticity-only evidence — they must never be treated as
    non-repudiation; see ``AlgorithmRegistry.require_non_repudiation``.
    """
    if event not in _EVENTS:
        raise SignalUnknownEventError(
            "signal-unknown-event: %r is outside the closed "
            "posture-signal vocabulary" % (event,))
    kind = _check_kind(event, kind)
    try:
        _ALGS.info(alg)  # alg-unregistered for unknown algorithms
    except _algs.AlgError as exc:
        raise PostureError(str(exc), code=exc.code)
    if not isinstance(subject_digest, str) or not subject_digest:
        raise ValueError("subject_digest must be a non-empty string")
    if not isinstance(scope, str) or not scope:
        raise ValueError("scope must be a non-empty string")
    if not isinstance(issuer_id, str) or not issuer_id:
        raise ValueError("issuer_id must be a non-empty string")
    if (not isinstance(issuer_seed, (bytes, bytearray))
            or len(issuer_seed) != 32):
        raise ValueError("issuer_seed must be 32 bytes")
    iat = _iso(time.time() if now is None else now)
    payload = {"digest": subject_digest}
    if kind is not None:
        payload["kind"] = kind
    events = {_EVENTS[event]: payload}
    signal = {
        "v": _SIGNAL_VERSION,
        "iss": issuer_id,
        "jti": _jti(issuer_id, subject_digest, events, iat),
        "iat": iat,
        "sub": subject_digest,
        "events": events,
        "scope": scope,
    }
    _algs.stamp_record_alg(signal, alg)
    signal["signature"] = _ALGS.sign(alg, _signal_body(signal),
                                     bytes(issuer_seed)).hex()
    if audit is not None:
        audit({"event": "posture_signal",
               "jti": signal["jti"],
               "iss": issuer_id,
               "sub": subject_digest,
               "scope": scope,
               "signal_event": event,
               "signal_kind": kind,
               "iat": iat})
    return signal


def emit_absence_signal(issuer, subject_digest, scope, *,
                        revocation=None, now=None, audit=None,
                        alg=None):
    """Compose with ``gov/absence.py``: attest the absence through
    the issuer's own absence machinery, then sign a posture signal
    whose kind is the absence claim.

    The signal is evidence ABOUT the signed negative outcome — the
    claim (never-advertised / advertised-but-missing / revoked) rides
    the signal's events payload — never the outcome itself, and never
    authorization.

    ``alg`` names the signal's signing tier and defaults to the
    absence issuer's own tier (``issuer.alg``), so the same key is
    never used under two different algorithms. Passing an ``alg``
    that differs from the issuer's tier refuses ``alg-mismatch``:
    signing one key's bytes under a different algorithm is key-role
    confusion, not composition.
    """
    from . import absence as _absence
    issuer_alg = getattr(issuer, "alg", _algs.DEFAULT_ALG)
    if alg is None:
        alg = issuer_alg
    if alg != issuer_alg:
        raise PostureError(
            "alg-mismatch: signal tier %r differs from the absence "
            "issuer's tier %r — one key must not sign under two "
            "algorithms" % (alg, issuer_alg),
            code="alg-mismatch")
    negative = issuer.attest_absence(subject_digest,
                                     revocation=revocation, now=now)
    if not isinstance(negative, dict) or \
            negative.get("claim") not in \
            _EVENT_KINDS["absence-attribution"]:
        raise SignalUnverifiableError(
            "signal-unverifiable: absence issuer produced no usable "
            "negative outcome")
    return emit_signal("absence-attribution", subject_digest, scope,
                       issuer.seed, issuer_id=issuer.issuer_id,
                       now=now, audit=audit, alg=alg,
                       kind=negative["claim"])


# ----------------------------------------------------------------------
# Verification (consumer side; public keys only).
# ----------------------------------------------------------------------


def verify_signal(signal, issuer_pubkeys, *, require_scope=None,
                  expect_alg=None):
    """Verify a signed posture signal against a public keyset.

    Returns a copy of the signal on success. Raises
    :class:`SignalUnverifiableError` for anything unsigned, forged,
    tampered, or malformed, :class:`SignalScopeMismatchError` when
    ``require_scope`` is pinned and the signal's scope differs,
    ``alg-unregistered`` when the signal names an unknown algorithm,
    and ``alg-mismatch`` when ``expect_alg`` is pinned and the
    signal's algorithm differs.

    Legacy records carry no "alg" field and verify as
    ``ed25519-rfc8032`` — no backward break. The signature check
    dispatches by the record's named algorithm.

    A verified signal is STILL not authorization — it is evidence for
    the audit trail. Call :func:`signal_carries_no_authority` at
    authority seams.
    """
    if not isinstance(signal, dict):
        raise SignalUnverifiableError(
            "signal-unverifiable: signal is not a record")
    for field in _SIGNAL_FIELDS:
        if field not in signal:
            raise SignalUnverifiableError(
                "signal-unverifiable: missing field %r" % (field,))
    if signal["v"] != _SIGNAL_VERSION:
        raise SignalUnverifiableError(
            "signal-unverifiable: unsupported version %r"
            % (signal.get("v"),))
    if not isinstance(signal["iss"], str) or not signal["iss"]:
        raise SignalUnverifiableError(
            "signal-unverifiable: malformed iss")
    if not isinstance(issuer_pubkeys, dict):
        raise SignalUnverifiableError(
            "signal-unverifiable: keyset is not a mapping")
    pub = issuer_pubkeys.get(signal["iss"])
    if pub is None:
        raise SignalUnverifiableError(
            "signal-unverifiable: issuer %r not in the pinned keyset"
            % (signal["iss"],))
    if not isinstance(signal["events"], dict) or not signal["events"]:
        raise SignalUnverifiableError(
            "signal-unverifiable: malformed events map")
    alg = _resolve_alg(signal, expect_alg)
    try:
        sig = bytes.fromhex(signal["signature"])
    except (TypeError, ValueError):
        raise SignalUnverifiableError(
            "signal-unverifiable: malformed signature")
    # Algorithm-confusion opt-in (CWE-347): only a caller that pinned
    # expect_alg to a symmetric tier declares the key a shared secret.
    # This function is documented "public keys only"; a MAC-tier
    # signal without the pin refuses (the registry guard returns
    # False) instead of HMACing with an attacker-known public key.
    for_secret = expect_alg is not None \
        and _ALGS.is_symmetric(expect_alg)
    if not _ALGS.verify(alg, _signal_body(signal), sig, pub,
                        for_symmetric_key=for_secret):
        raise SignalUnverifiableError(
            "signal-unverifiable: signature does not verify against "
            "the pinned issuer key")
    expected_jti = _jti(signal["iss"], signal["sub"],
                        signal["events"], signal["iat"])
    if signal["jti"] != expected_jti:
        raise SignalUnverifiableError(
            "signal-unverifiable: jti does not match the signal body")
    if require_scope is not None and signal["scope"] != require_scope:
        raise SignalScopeMismatchError(
            "signal-scope-mismatch: signal scope %r does not match "
            "the pinned scope %r"
            % (signal["scope"], require_scope))
    return dict(signal)


# ----------------------------------------------------------------------
# The authority guard.
# ----------------------------------------------------------------------


def signal_carries_no_authority(candidate):
    """The guard at authorization seams.

    A posture signal is never authority: when ``candidate`` has the
    posture-signal shape — or looks like a stripped fragment of one —
    this refuses ``signal-not-authorization``, even for a well-formed,
    well-signed signal. Anything that is neither a signal nor a
    fragment passes through unchanged for the real gate to decide.

    Consumers: call this where an authorization decision is made, so
    a signal accidentally (or adversarially) routed into an
    authority check fails closed instead of being misread.
    """
    if _shape_is_signal(candidate) or \
            _looks_like_signal_fragment(candidate):
        raise SignalNotAuthorizationError(
            "signal-not-authorization: a posture signal is evidence "
            "for the audit trail, never authorization; route it to "
            "the real gate (permit lease, admission policy, quorum)")
    return candidate


def require_authorization(candidate):
    """Alias of :func:`signal_carries_no_authority` kept for
    consumers that name the seam rather than the invariant."""
    return signal_carries_no_authority(candidate)
