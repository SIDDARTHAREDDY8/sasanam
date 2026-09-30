#!/usr/bin/env python3
"""Agent action capsules: per-verdict digest-committed evidence.

ADAPT of the draft-mih-scitt-agent-action-capsule-05 pattern
(re-derived prose; nothing copied from the draft): every agent
verdict — admit OR refusal — seals a digest-committed JSON capsule
so an auditor can verify what was decided and what actually
happened. A blocked or denied capsule is the auditor-grade evidence
that a gate worked.

A capsule separates the ATTEMPT (what was requested) from the
EFFECT (what actually happened) and binds both by digest::

    {v, capsule_digest, verdict_digest, effect_digest, jcs_json}

``capsule_digest`` is the SHA-256 of the canonical (JCS-style: sorted
keys, no whitespace) JSON bytes of the capsule body. The body itself
embeds the attempt and the effect, so the capsule is self-describing
and replayable by any verifier holding the bytes.

Key properties, enforced in code:

* Refusals are first-class evidence. :func:`seal_capsule` seals a
  refused verdict exactly like an admitted one; the effect records
  the refusal code and its evidence. :func:`capsule_from_refusal`
  is the additive helper that seals any named refusal the repo
  emits, binding the refusal code into the capsule.
* Confirmed-effect binding. The attempt and the effect must be
  present, distinct, and the effect must carry evidence. A verdict
  whose attempt and effect are conflated (identical), or whose
  effect claims an outcome without evidence, refuses
  ``capsule-attempt-effect-diverged`` — attempt and effect are not
  the same claim, and a claim without evidence is not evidence.
* JCS-only, fail-closed. :func:`seal_capsule_json` takes raw JSON
  bytes and requires them to BE the canonical encoding: non-UTF8
  bytes, duplicate keys, unsorted keys, or non-canonical number
  forms all refuse ``capsule-noncanonical``. Python dicts cannot
  express duplicate keys, so the strict byte gate is the only seam
  where the check is meaningful.
* Evidence, never authority. A capsule records a decision; it never
  grants one. :func:`capsule_carries_no_authority` refuses
  ``capsule-not-authorization`` when a verdict smuggles
  authority-shaped fields (grant, authorization, authority,
  permit, capability, scope) into the evidence.

:func:`verify_capsule` replays: it recomputes ``capsule_digest``
over the stored bytes (constant-time compare) and the two
component digests over the embedded attempt and effect. A mismatch
refuses ``capsule-digest-mismatch``; a malformed capsule refuses
``capsule-malformed``.

Stdlib only. No network. $0.
"""

import hashlib
import hmac
import json

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class CapsuleError(Exception):
    """Base class for all action-capsule refusals. ``code`` is
    machine-readable."""

    code = "capsule-refused"


class _Noncanonical(CapsuleError):
    code = "capsule-noncanonical"


class _Diverged(CapsuleError):
    code = "capsule-attempt-effect-diverged"


class _NotAuthorization(CapsuleError):
    code = "capsule-not-authorization"


class _UnknownField(CapsuleError):
    code = "capsule-unknown-field"


class _DigestMismatch(CapsuleError):
    code = "capsule-digest-mismatch"


class _Malformed(CapsuleError):
    code = "capsule-malformed"


# ----------------------------------------------------------------------
# Constants.
# ----------------------------------------------------------------------

CAPSULE_VERSION = 1

# Top-level verdict fields that would smuggle authority into evidence.
_AUTHORITY_FIELDS = frozenset(
    {"grant", "authorization", "authority", "permit", "capability",
     "scope", "delegation", "token"}
)

# Closed effect statuses.
_EFFECT_STATUSES = frozenset({"admitted", "refused"})

# JSON value types the JCS gate admits. Floats are refused: JCS has
# strict number rules and a float cannot be canonically re-encoded
# without a representation decision.
_JCS_SCALARS = (str, int, bool, type(None))


# ----------------------------------------------------------------------
# JCS canonicalization.
# ----------------------------------------------------------------------


def _check_jcs_value(value, path="$"):
    """Refuse values that have no canonical JSON encoding."""
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, float):
        raise _Noncanonical(
            "float at %s has no canonical JSON encoding" % path)
    if isinstance(value, _JCS_SCALARS):
        return
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise _Noncanonical(
                    "non-string key at %s" % path)
        for key, sub in value.items():
            _check_jcs_value(sub, "%s.%s" % (path, key))
        return
    if isinstance(value, (list, tuple)):
        for idx, item in enumerate(value):
            _check_jcs_value(item, "%s[%d]" % (path, idx))
        return
    raise _Noncanonical(
        "unencodable value of type %s at %s"
        % (type(value).__name__, path))


def canonical_json_bytes(obj):
    """Encode ``obj`` as JCS-style canonical JSON bytes.

    Sorted keys at every level, no whitespace, UTF-8. Refuses
    ``capsule-noncanonical`` for unencodable values.
    """
    _check_jcs_value(obj)
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)
    return text.encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------------------
# Input gates.
# ----------------------------------------------------------------------


def capsule_carries_no_authority(verdict_record):
    """Refuse ``capsule-not-authorization`` if the verdict smuggles
    authority-shaped fields into the evidence.

    A capsule records a decision; it never grants one. Any
    authority-shaped top-level field fails closed.
    """
    if not isinstance(verdict_record, dict):
        raise _Malformed("verdict record must be a dict")
    smuggled = _AUTHORITY_FIELDS.intersection(verdict_record.keys())
    if smuggled:
        raise _NotAuthorization(
            "verdict carries authority-shaped fields: %s"
            % sorted(smuggled))
    return True


def _require_attempt_effect(verdict_record):
    """Validate the attempt/effect separation; fail closed."""
    unknown = set(verdict_record.keys()) - {"attempt", "effect"}
    if unknown:
        # The capsule digest commits to the body; a top-level claim
        # that is neither attempt nor effect would seal evidence that
        # does not commit to it. Fail closed instead of silently
        # dropping it.
        raise _UnknownField(
            "unknown top-level verdict fields: %s" % sorted(unknown))
    attempt = verdict_record.get("attempt")
    effect = verdict_record.get("effect")
    if not isinstance(attempt, dict) or not attempt:
        raise _Diverged("attempt must be a non-empty object")
    if not isinstance(effect, dict) or not effect:
        raise _Diverged("effect must be a non-empty object")
    if attempt == effect:
        raise _Diverged("attempt and effect are conflated")
    status = effect.get("status")
    if status not in _EFFECT_STATUSES:
        raise _Diverged("effect status must be admitted|refused")
    evidence = effect.get("evidence")
    if not isinstance(evidence, str) or not evidence:
        raise _Diverged("effect claims an outcome without evidence")
    if status == "refused" and not effect.get("code"):
        raise _Diverged("refused effect must name the refusal code")
    return attempt, effect


# ----------------------------------------------------------------------
# Sealing.
# ----------------------------------------------------------------------


def seal_capsule(verdict_record):
    """Seal a verdict into a digest-committed action capsule.

    ``verdict_record`` is a dict with distinct ``attempt`` and
    ``effect`` objects. Refused verdicts seal exactly like admitted
    ones. Returns::

        {v, capsule_digest, verdict_digest, effect_digest, jcs_json}

    where ``jcs_json`` is the canonical JSON text of the capsule
    body and ``capsule_digest`` is SHA-256 of its UTF-8 bytes.
    """
    capsule_carries_no_authority(verdict_record)
    attempt, effect = _require_attempt_effect(verdict_record)

    attempt_bytes = canonical_json_bytes(attempt)
    effect_bytes = canonical_json_bytes(effect)
    verdict_digest = _digest(attempt_bytes)
    effect_digest = _digest(effect_bytes)
    body = {
        "v": CAPSULE_VERSION,
        "verdict_digest": verdict_digest,
        "effect_digest": effect_digest,
        "attempt": attempt,
        "effect": effect,
    }
    body_bytes = canonical_json_bytes(body)
    return {
        "v": CAPSULE_VERSION,
        "capsule_digest": _digest(body_bytes),
        "verdict_digest": verdict_digest,
        "effect_digest": effect_digest,
        "jcs_json": body_bytes.decode("utf-8"),
    }


def _parse_strict(raw: bytes):
    """Parse raw JSON bytes with duplicate-key detection.

    Refuses ``capsule-noncanonical`` on non-UTF8 bytes or
    duplicate keys.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _Noncanonical("input is not UTF-8: %s" % exc) from exc

    def _no_dupes(pairs):
        seen = set()
        for key, _ in pairs:
            if key in seen:
                raise _Noncanonical("duplicate key: %r" % (key,))
            seen.add(key)
        return dict(pairs)

    try:
        return json.loads(text, object_pairs_hook=_no_dupes)
    except _Noncanonical:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _Noncanonical("invalid JSON: %s" % exc) from exc


def seal_capsule_json(raw: bytes):
    """Seal a verdict given as raw JSON bytes through the strict
    JCS gate.

    The raw bytes must BE the canonical encoding — sorted keys at
    every level, no whitespace — otherwise
    ``capsule-noncanonical`` refuses. This is the seam where
    duplicate keys, unsorted keys, and non-UTF8 bytes are caught.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise _Malformed("seal_capsule_json requires bytes")
    obj = _parse_strict(bytes(raw))
    canonical = canonical_json_bytes(obj)
    if canonical != bytes(raw):
        raise _Noncanonical(
            "input is not canonical JCS form")
    # seal_capsule owns the authority and attempt/effect gates; no
    # second validation pass here.
    return seal_capsule(obj)


# ----------------------------------------------------------------------
# Verification.
# ----------------------------------------------------------------------


def verify_capsule(capsule):
    """Replay a capsule: recompute every digest, fail closed.

    Returns the parsed capsule body (attempt + effect). Tampering
    refuses ``capsule-digest-mismatch``; malformed capsules refuse
    ``capsule-malformed``.
    """
    if not isinstance(capsule, dict):
        raise _Malformed("capsule must be a dict")
    required = {"v", "capsule_digest", "verdict_digest",
                "effect_digest", "jcs_json"}
    if not required.issubset(capsule.keys()):
        raise _Malformed("capsule missing required fields")
    jcs_text = capsule.get("jcs_json")
    if not isinstance(jcs_text, str):
        raise _Malformed("jcs_json must be text")
    body_bytes = jcs_text.encode("utf-8")
    if not hmac.compare_digest(_digest(body_bytes),
                               str(capsule["capsule_digest"])):
        raise _DigestMismatch(
            "capsule_digest does not match jcs_json bytes")
    body = _parse_strict(body_bytes)
    if body.get("v") != CAPSULE_VERSION:
        raise _Malformed("unsupported capsule version")
    attempt = body.get("attempt")
    effect = body.get("effect")
    if not isinstance(attempt, dict) or not isinstance(effect, dict):
        raise _Malformed("capsule body missing attempt/effect")
    if not hmac.compare_digest(_digest(canonical_json_bytes(attempt)),
                               str(capsule["verdict_digest"])):
        raise _DigestMismatch("verdict_digest does not match attempt")
    if not hmac.compare_digest(_digest(canonical_json_bytes(effect)),
                               str(capsule["effect_digest"])):
        raise _DigestMismatch("effect_digest does not match effect")
    return body


# ----------------------------------------------------------------------
# Refusal helper.
# ----------------------------------------------------------------------


def capsule_from_refusal(refusal_code, subject_digest):
    """Seal a named refusal as first-class evidence.

    ``refusal_code`` is the repo's named refusal code (e.g.
    ``permit-revoked``); ``subject_digest`` identifies what was
    refused. The returned capsule's effect binds the refusal code
    and records that nothing was executed.
    """
    if not isinstance(refusal_code, str) or not refusal_code:
        raise _Malformed("refusal_code must be a non-empty string")
    if not isinstance(subject_digest, str) or not subject_digest:
        raise _Malformed("subject_digest must be a non-empty string")
    return seal_capsule({
        "attempt": {
            "action": "refusal-evidence",
            "subject_digest": subject_digest,
        },
        "effect": {
            "status": "refused",
            "code": refusal_code,
            "evidence": _digest(
                ("refusal:%s:%s" % (refusal_code,
                                    subject_digest)).encode("utf-8")),
            "observed": "refusal emitted; nothing executed",
        },
    })
