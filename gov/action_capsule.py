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

Batch verification (recompute-don't-assert): :func:`chain_capsules`
replays every capsule digest, RECOMPUTES the counts (verdicts,
refusal capsules, links) from the sealed items, and DERIVES the
close state from the acknowledges/rebuts links — no links means
"open", any "rebuts" means "closed-rebutted", otherwise any
"acknowledges" means "closed-acknowledged". An issuer-claimed count
that disagrees refuses ``capsule-count-mismatch``; a claimed close
state that disagrees with the derived state refuses
``capsule-closestate-mismatch``. The issuer's claims are checked,
never trusted.

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


class _CountMismatch(CapsuleError):
    code = "capsule-count-mismatch"


class _CloseStateMismatch(CapsuleError):
    code = "capsule-closestate-mismatch"


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

# Closed close states, derived from links — never asserted.
_CLOSE_STATES = frozenset({"open", "closed-acknowledged",
                           "closed-rebutted"})

# Closed link kinds.
_LINK_KINDS = frozenset({"acknowledges", "rebuts"})

# Top-level keys a batch may claim counts under. Only these keys
# are recomputed; an issuer cannot invent new count claims.
_KNOWN_COUNT_KEYS = frozenset({"verdicts", "refusal_capsules",
                               "links"})

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


# ----------------------------------------------------------------------
# Batch verification: recompute-don't-assert.
#
# ADAPT of the upstream action-capsule recompute rules (re-derived;
# nothing copied): a batch verifier must RECOMPUTE what it can
# instead of trusting the issuer's assertions.
#
# * claimed counts (number of sealed verdicts, number of refusal
#   capsules, number of links) are recomputed from the sealed items
#   themselves; disagreement refuses ``capsule-count-mismatch``.
# * close state is DERIVED from the acknowledges/rebuts links, never
#   asserted: no links -> "open"; any "rebuts" link ->
#   "closed-rebutted"; otherwise any "acknowledges" link ->
#   "closed-acknowledged". A claimed close state that mismatches the
#   derived state refuses ``capsule-closestate-mismatch``.
# * ``chain_capsules`` verifies every capsule digest via
#   ``verify_capsule`` and returns a chain commitment over the
#   capsule digests and links. Link tampering refuses with the
#   original module codes.
#
# Like capsules, batches are evidence, never authority.
# ----------------------------------------------------------------------


def _validate_links(links, capsule_digests):
    """Validate link records against the batch's capsule digests.

    Fails closed: unknown link fields refuse
    ``capsule-unknown-field``; unknown link kinds refuse
    ``capsule-malformed``; a link whose target digest matches no
    sealed capsule in the batch refuses ``capsule-digest-mismatch``
    (the link claims a target that does not exist here).
    """
    digest_set = set(capsule_digests)
    for link in links:
        if not isinstance(link, dict):
            raise _Malformed("link must be an object")
        unknown = set(link.keys()) - {"kind",
                                      "target_capsule_digest"}
        if unknown:
            raise _UnknownField(
                "unknown link fields: %s" % sorted(unknown))
        kind = link.get("kind")
        if kind not in _LINK_KINDS:
            raise _Malformed("unknown link kind: %r" % (kind,))
        target = link.get("target_capsule_digest")
        if not isinstance(target, str) or not target:
            raise _Malformed(
                "link target_capsule_digest must be a non-empty string")
        if target not in digest_set:
            raise _DigestMismatch(
                "link target digest matches no capsule in the batch")


def _derive_close_state(links):
    """Derive the batch close state from its links.

    No links -> "open". Any "rebuts" link -> "closed-rebutted" (a
    rebuttal dominates an acknowledgement). Otherwise any
    "acknowledges" link -> "closed-acknowledged". The state is
    computed here; the issuer's claim is checked against it, never
    trusted.
    """
    kinds = {link["kind"] for link in links}
    if "rebuts" in kinds:
        return "closed-rebutted"
    if "acknowledges" in kinds:
        return "closed-acknowledged"
    return "open"


def chain_capsules(capsules, links=()):
    """Verify every capsule digest, recompute counts, derive close
    state, and return a chain commitment.

    ``capsules`` is a list of sealed capsule dicts; ``links`` is an
    optional list of ``{"kind", "target_capsule_digest"}`` records.
    Every capsule is replayed through :func:`verify_capsule`, so
    tampering refuses with the original module codes. Returns::

        {v, chain_digest, capsule_digests, counts, close_state}

    ``counts`` is ``{verdicts, refusal_capsules, links}`` recomputed
    from the sealed items. ``chain_digest`` is SHA-256 of the
    canonical JSON bytes of ``{v, capsule_digests, links}``.
    """
    if not isinstance(capsules, (list, tuple)):
        raise _Malformed("capsules must be a list")
    if not isinstance(links, (list, tuple)):
        raise _Malformed("links must be a list")
    bodies = [verify_capsule(capsule) for capsule in capsules]
    capsule_digests = [str(capsule["capsule_digest"])
                       for capsule in capsules]
    _validate_links(links, capsule_digests)
    link_list = [{"kind": link["kind"],
                  "target_capsule_digest": link["target_capsule_digest"]}
                 for link in links]
    refusal_capsules = sum(
        1 for body in bodies
        if isinstance(body.get("effect"), dict)
        and body["effect"].get("status") == "refused")
    counts = {"verdicts": len(capsules),
              "refusal_capsules": refusal_capsules,
              "links": len(links)}
    close_state = _derive_close_state(link_list)
    commitment_body = {"v": CAPSULE_VERSION,
                       "capsule_digests": capsule_digests,
                       "links": link_list}
    chain_digest = _digest(canonical_json_bytes(commitment_body))
    return {"v": CAPSULE_VERSION,
            "chain_digest": chain_digest,
            "capsule_digests": capsule_digests,
            "counts": counts,
            "close_state": close_state}


def verify_capsule_batch(batch):
    """Verify a capsule batch: per-capsule digest replay, recomputed
    counts, derived close state, all chained.

    ``batch`` is ``{"capsules": [...], "links": [...],
    "claimed_counts": {...}, "claimed_close_state": ...}``. Only
    ``capsules`` is required; everything else is optional. Claimed
    counts are checked against the counts recomputed from the
    sealed items — disagreement refuses
    ``capsule-count-mismatch``. A claimed close state is checked
    against the state derived from the links — disagreement
    refuses ``capsule-closestate-mismatch``. Unknown top-level
    batch fields or unknown count keys fail closed with
    ``capsule-unknown-field``. Returns the chain commitment from
    :func:`chain_capsules`.
    """
    if not isinstance(batch, dict):
        raise _Malformed("batch must be a dict")
    unknown = set(batch.keys()) - {"capsules", "links",
                                   "claimed_counts",
                                   "claimed_close_state"}
    if unknown:
        raise _UnknownField(
            "unknown batch fields: %s" % sorted(unknown))
    capsules = batch.get("capsules", [])
    links = batch.get("links", [])
    commitment = chain_capsules(capsules, links)
    claimed_counts = batch.get("claimed_counts")
    if claimed_counts is not None:
        if not isinstance(claimed_counts, dict):
            raise _Malformed("claimed_counts must be an object")
        unknown_counts = (set(claimed_counts.keys())
                          - _KNOWN_COUNT_KEYS)
        if unknown_counts:
            raise _UnknownField(
                "unknown count keys: %s" % sorted(unknown_counts))
        for key, claimed in claimed_counts.items():
            if (not isinstance(claimed, int)
                    or isinstance(claimed, bool)
                    or claimed < 0):
                raise _Malformed(
                    "count values must be non-negative integers")
            actual = commitment["counts"][key]
            if claimed != actual:
                raise _CountMismatch(
                    "claimed %s=%d, recomputed %d"
                    % (key, claimed, actual))
    claimed_close = batch.get("claimed_close_state")
    if claimed_close is not None:
        if claimed_close not in _CLOSE_STATES:
            raise _Malformed(
                "unknown claimed_close_state: %r" % (claimed_close,))
        if claimed_close != commitment["close_state"]:
            raise _CloseStateMismatch(
                "claimed close_state=%r, derived=%r"
                % (claimed_close, commitment["close_state"]))
    return commitment
