"""Untrusted-text rendering policy (EMILIA PIP-007 ADAPT).

EMILIA lesson: text from untrusted sources — model output, tool
results, fetched content — must render to the approver plain-text-only,
capped in length, and labeled as an UNVERIFIED CLAIM. The approver's
decision input is the operator-rendered Action Object, never the
model's prose; the two are kept as distinct typed records that cannot
be nested inside each other.

Seams:

* ``render_untrusted_claim(text, *, max_chars, source_label, strict=False)``
  -> :class:`UntrustedClaim`: sanitized (no markup; control characters
  stripped except \\t and \\n, which the approver needs for structure —
  an explicit, deliberate narrowing of "no control chars"),
  capped, digest-bound, labeled. Over-length input truncates with
  ``was_truncated=True`` (never silently) or refuses with
  ``untrusted-claim-too-long`` when ``strict=True``.
* ``render_action_object(fields)`` -> :class:`ActionObject`: the
  operator-rendered decision input — strictly typed ``action`` verb,
  ``parameter_digest``, ``constraints`` — with its own type tag and
  digest. An embedded :class:`UntrustedClaim` (or a dict wearing the
  claim type tag) refuses with ``action-object-contaminated``;
  an Action Object (or action-tagged dict) offered as claim text
  refuses with ``untrusted-claim-contaminated``.
* ``verify_claim`` / ``verify_action_object``: digest re-checks.
* ``check_render_pair(action_object, untrusted_claims, *, audit=None)``:
  the approval-path gate. Fails closed when the decision input is not
  a typed :class:`ActionObject` (``render-pair-no-action-object``),
  when the Action Object fails its own digest
  (``render-pair-action-object-tampered``), when a claim is not a
  proper record (``render-pair-claim-malformed``), or when a claim
  fails its digest (``render-pair-claim-tampered``). Returns an
  audit-visible report on success.

All refusals raise :class:`UntrustedRenderError` subclasses with a
machine-readable ``code``. Wrong Python types at any seam are
authoring misuse and raise plain ``TypeError`` — the named codes are
reserved for attack shapes and malformed values, never for type
errors. (Values like an empty label or a non-positive cap are
malformed *values*, so they keep named codes.)

Honest boundaries:

* Sanitization strips markup and control characters; it cannot judge
  semantic deception — a plain-text lie still renders. The label is the
  defense, not the filter.
* The digest binds the *capped* text the approver saw, plus the source
  label and the truncation flag; the full text is stored on the record
  but the approver never saw it.
* Labeling rides the record type: every UntrustedClaim renders labeled
  via ``.render()``; the gate pins that claims are proper labeled-type
  records with valid digests, but it cannot observe what the UI
  displayed — display enforcement is the UI's job.
* The contamination scan walks containers without a depth limit
  (cycle-safe via visited ids); a claim at any nesting depth inside
  Action Object fields is refused.
* ``check_render_pair`` is opt-in: the legacy approval path never
  calls it, and importing this module changes nothing about
  ``gov.approvals``.

$0 spend. stdlib only. No network.
"""

import hashlib
import json
import re
import unicodedata

__all__ = [
    "CLAIM_TYPE",
    "ACTION_TYPE",
    "UNTRUSTED_CLAIM_TOO_LONG",
    "UNTRUSTED_CLAIM_MALFORMED",
    "UNTRUSTED_CLAIM_CONTAMINATED",
    "ACTION_OBJECT_CONTAMINATED",
    "ACTION_OBJECT_MALFORMED",
    "RENDER_PAIR_REFUSED",
    "RENDER_PAIR_NO_ACTION_OBJECT",
    "RENDER_PAIR_ACTION_OBJECT_TAMPERED",
    "RENDER_PAIR_CLAIM_TAMPERED",
    "RENDER_PAIR_CLAIM_MALFORMED",
    "UntrustedRenderError",
    "UntrustedClaimTooLongError",
    "UntrustedClaimMalformedError",
    "UntrustedClaimContaminatedError",
    "ActionObjectContaminatedError",
    "ActionObjectMalformedError",
    "RenderPairError",
    "UntrustedClaim",
    "ActionObject",
    "render_untrusted_claim",
    "render_action_object",
    "verify_claim",
    "verify_action_object",
    "check_render_pair",
]

#: Type tags. An Action Object never carries the claim tag and vice
#: versa; the contamination scans key off these tags (plus real
#: record instances).
CLAIM_TYPE = "sasanam-untrusted-claim/v1"
ACTION_TYPE = "sasanam-action-object/v1"

#: Named refusal codes (greppable).
UNTRUSTED_CLAIM_TOO_LONG = "untrusted-claim-too-long"
UNTRUSTED_CLAIM_MALFORMED = "untrusted-claim-malformed"
UNTRUSTED_CLAIM_CONTAMINATED = "untrusted-claim-contaminated"
ACTION_OBJECT_CONTAMINATED = "action-object-contaminated"
ACTION_OBJECT_MALFORMED = "action-object-malformed"
RENDER_PAIR_REFUSED = "render-pair-refused"
RENDER_PAIR_NO_ACTION_OBJECT = "render-pair-no-action-object"
RENDER_PAIR_ACTION_OBJECT_TAMPERED = "render-pair-action-object-tampered"
RENDER_PAIR_CLAIM_TAMPERED = "render-pair-claim-tampered"
RENDER_PAIR_CLAIM_MALFORMED = "render-pair-claim-malformed"

_ACTION_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_TAG_RE = re.compile(r"<[^<>]*>")


# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------

class UntrustedRenderError(Exception):
    """Base class for all rendering refusals. ``code`` is the
    machine-readable, greppable failure mode."""

    code = "untrusted-render-error"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class UntrustedClaimTooLongError(UntrustedRenderError):
    """Over-length untrusted text under a strict cap: refused, never
    silently truncated."""

    code = UNTRUSTED_CLAIM_TOO_LONG


class UntrustedClaimMalformedError(UntrustedRenderError):
    """Missing source label, bad cap value, or wrong input shape for a
    claim — malformed *values* at the claim seam. Wrong Python types
    are TypeError instead."""

    code = UNTRUSTED_CLAIM_MALFORMED


class UntrustedClaimContaminatedError(UntrustedRenderError):
    """An Action Object (or a dict wearing the action type tag) was
    offered as untrusted claim text: the operator's decision input
    must never be rendered as the model's prose."""

    code = UNTRUSTED_CLAIM_CONTAMINATED


class ActionObjectContaminatedError(UntrustedRenderError):
    """An untrusted claim (or a dict wearing the claim type tag) was
    found inside an Action Object's fields: the operator's decision
    input must never carry the model's prose."""

    code = ACTION_OBJECT_CONTAMINATED


class ActionObjectMalformedError(UntrustedRenderError):
    """Action Object fields are not the strictly typed shape
    {action, parameter_digest, constraints}."""

    code = ACTION_OBJECT_MALFORMED


class RenderPairError(UntrustedRenderError):
    """The approval-path render-pair gate refused. The ``code``
    distinguishes the shape: no typed Action Object as decision input,
    a tampered Action Object, a malformed claim, or a tampered
    claim."""

    code = RENDER_PAIR_REFUSED


def _refuse(code, message, audit=None):
    """Fail closed with the named code, recording the refusal audit
    event first when a sink is present."""
    if audit is not None:
        audit({"event": "render_pair_refused", "code": code})
    raise RenderPairError(message, code=code)


# ----------------------------------------------------------------------
# Sanitization.
# ----------------------------------------------------------------------

def _sanitize(text):
    """Plain-text sanitization: strip markup tags and control
    characters. Keeps \\t and \\n (structure the approver needs);
    strips everything else in Unicode category C — including bidi
    overrides, zero-width characters, and ANSI escape openers."""
    # Repeat: a single pass leaves "<a<b>>" shaped nests.
    previous = None
    cleaned = text
    while cleaned != previous:
        previous = cleaned
        cleaned = _TAG_RE.sub("", cleaned)
    out = []
    for ch in cleaned:
        if ch in ("\t", "\n"):
            out.append(ch)
        elif unicodedata.category(ch).startswith("C"):
            continue
        else:
            out.append(ch)
    return "".join(out)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _claim_digest_body(capped_text, source_label, was_truncated,
                       max_chars):
    return _sha256_hex(_canonical({
        "type": CLAIM_TYPE,
        "capped_text": capped_text,
        "source_label": source_label,
        "was_truncated": was_truncated,
        "max_chars": max_chars,
    }))


def _action_digest_body(action, parameter_digest, constraints):
    return _sha256_hex(_canonical({
        "type": ACTION_TYPE,
        "action": action,
        "parameter_digest": parameter_digest,
        "constraints": list(constraints),
    }))


# ----------------------------------------------------------------------
# Records.
# ----------------------------------------------------------------------

class UntrustedClaim:
    """An untrusted-source text rendered for the approver: sanitized,
    capped, labeled, digest-bound. Construct only via
    ``render_untrusted_claim``."""

    __slots__ = ("plain_text", "capped_text", "was_truncated",
                 "source_label", "max_chars", "claim_digest")

    def __init__(self, plain_text, capped_text, was_truncated,
                 source_label, max_chars, claim_digest):
        self.plain_text = plain_text
        self.capped_text = capped_text
        self.was_truncated = was_truncated
        self.source_label = source_label
        self.max_chars = max_chars
        self.claim_digest = claim_digest

    @property
    def type(self):
        return CLAIM_TYPE

    def render(self):
        """The approver-facing display: always labeled, never raw."""
        lines = [
            "UNVERIFIED CLAIM (source: %s)" % self.source_label,
            "---",
            self.capped_text,
            "---",
            "truncated: %s (cap %d chars)"
            % ("yes" if self.was_truncated else "no", self.max_chars),
            "claim digest: %s" % self.claim_digest,
        ]
        return "\n".join(lines)


class ActionObject:
    """The operator-rendered decision input: strictly typed, digest
    bound, never carrying untrusted prose. Construct only via
    ``render_action_object``."""

    __slots__ = ("action", "parameter_digest", "constraints",
                 "object_digest")

    def __init__(self, action, parameter_digest, constraints,
                 object_digest):
        self.action = action
        self.parameter_digest = parameter_digest
        self.constraints = tuple(constraints)
        self.object_digest = object_digest

    @property
    def type(self):
        return ACTION_TYPE


# ----------------------------------------------------------------------
# Contamination scans (cycle-safe, no depth limit — any nesting depth
# is refused, so deep nesting is not an evasion path).
# ----------------------------------------------------------------------

def _contains(value, record_cls, tag):
    """True when a record of ``record_cls`` (or a dict wearing ``tag``)
    appears anywhere inside ``value``."""
    seen = set()
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, record_cls):
            return True
        if isinstance(current, dict):
            if id(current) in seen:
                continue
            seen.add(id(current))
            if current.get("type") == tag:
                return True
            stack.extend(current.values())
        elif isinstance(current, (list, tuple, set, frozenset)):
            if id(current) in seen:
                continue
            seen.add(id(current))
            stack.extend(current)
    return False


def _contains_claim(value):
    return _contains(value, UntrustedClaim, CLAIM_TYPE)


def _contains_action_object(value):
    return _contains(value, ActionObject, ACTION_TYPE)


# ----------------------------------------------------------------------
# Rendering seams.
# ----------------------------------------------------------------------

def render_untrusted_claim(text, *, max_chars, source_label, strict=False,
                           audit=None):
    """Render untrusted-source text for the approver.

    ``text`` must be a str (``TypeError`` otherwise). ``max_chars``
    must be a positive int (``TypeError`` for the wrong type,
    ``untrusted-claim-malformed`` for a non-positive value) and
    ``source_label`` a non-empty str (``TypeError`` for the wrong
    type, ``untrusted-claim-malformed`` for an empty one).
    Over-length input truncates with ``was_truncated=True`` — or
    refuses with ``untrusted-claim-too-long`` when ``strict=True``.
    An Action Object offered as the text refuses with
    ``untrusted-claim-contaminated``.
    """
    if isinstance(text, str):
        pass
    elif _contains_action_object(text):
        raise UntrustedClaimContaminatedError(
            "an Action Object must never be rendered as an untrusted "
            "claim")
    else:
        raise TypeError("text must be a str, got %s" % type(text).__name__)
    if not isinstance(max_chars, int) or isinstance(max_chars, bool):
        raise TypeError("max_chars must be an int, got %s"
                        % type(max_chars).__name__)
    if max_chars < 1:
        raise UntrustedClaimMalformedError(
            "max_chars must be a positive int")
    if not isinstance(source_label, str):
        raise TypeError("source_label must be a str, got %s"
                        % type(source_label).__name__)
    if not source_label:
        raise UntrustedClaimMalformedError(
            "source_label must be a non-empty str")
    plain = _sanitize(text)
    was_truncated = len(plain) > max_chars
    if was_truncated and strict:
        raise UntrustedClaimTooLongError(
            "untrusted text of %d chars exceeds strict cap %d"
            % (len(plain), max_chars))
    capped = plain[:max_chars]
    digest = _claim_digest_body(capped, source_label, was_truncated,
                                max_chars)
    claim = UntrustedClaim(plain, capped, was_truncated, source_label,
                           max_chars, digest)
    if audit is not None:
        audit({"event": "claim_rendered", "type": CLAIM_TYPE,
               "source_label": source_label,
               "was_truncated": was_truncated,
               "claim_digest": digest})
    return claim


def render_action_object(fields, *, audit=None):
    """Render the operator's decision input as a strictly typed
    ActionObject.

    ``fields`` must be exactly ``{"action", "parameter_digest",
    "constraints"}`` (``TypeError`` for a non-dict): the verb matches
    ``^[a-z][a-z0-9_.-]{0,63}$``, the digest is 64 hex chars,
    constraints is a list of non-empty strings (<=256 chars each).
    Any embedded claim (or claim-tagged dict, at any nesting depth)
    refuses with ``action-object-contaminated`` — checked before the
    record is returned.
    """
    if not isinstance(fields, dict):
        raise TypeError("fields must be a dict, got %s"
                        % type(fields).__name__)
    expected = {"action", "parameter_digest", "constraints"}
    unknown = sorted(set(fields) - expected)
    if unknown:
        raise ActionObjectMalformedError(
            "unknown fields %s" % (unknown,))
    missing = sorted(expected - set(fields))
    if missing:
        raise ActionObjectMalformedError(
            "missing fields %s" % (missing,))
    for value in fields.values():
        if _contains_claim(value):
            raise ActionObjectContaminatedError(
                "untrusted claim found inside Action Object fields")
    action = fields["action"]
    if not isinstance(action, str) or not _ACTION_RE.match(action):
        raise ActionObjectMalformedError(
            "action must match %s" % (_ACTION_RE.pattern,))
    digest = fields["parameter_digest"]
    if not isinstance(digest, str) or not _HEX64_RE.match(digest):
        raise ActionObjectMalformedError(
            "parameter_digest must be 64 hex chars")
    constraints = fields["constraints"]
    if not isinstance(constraints, list) or any(
            not isinstance(c, str) or not c or len(c) > 256
            for c in constraints):
        raise ActionObjectMalformedError(
            "constraints must be a list of non-empty strings (<=256)")
    object_digest = _action_digest_body(action, digest, constraints)
    ao = ActionObject(action, digest, constraints, object_digest)
    if audit is not None:
        audit({"event": "action_object_rendered", "type": ACTION_TYPE,
               "action": action, "object_digest": object_digest})
    return ao


def verify_claim(claim):
    """Recompute the claim digest. False on tamper; False (not an
    exception) for non-claim input so gate callers choose their own
    refusal code."""
    if not isinstance(claim, UntrustedClaim):
        return False
    return claim.claim_digest == _claim_digest_body(
        claim.capped_text, claim.source_label, claim.was_truncated,
        claim.max_chars)


def verify_action_object(action_object):
    """Recompute the Action Object digest. False on tamper or
    non-ActionObject input."""
    if not isinstance(action_object, ActionObject):
        return False
    return action_object.object_digest == _action_digest_body(
        action_object.action, action_object.parameter_digest,
        action_object.constraints)


def check_render_pair(action_object, untrusted_claims, *, audit=None):
    """The approval-path gate: verify the decision input is a typed,
    digest-valid Action Object while untrusted claims stay labeled,
    capped, and separate.

    Refuses fail-closed: ``render-pair-no-action-object`` when the
    decision input is not an :class:`ActionObject` (raw prose or a
    bare dict as the decision basis is the core violation this gate
    exists to catch); ``render-pair-action-object-tampered`` when the
    Action Object fails its own digest (post-render swap);
    ``render-pair-claim-malformed`` when a claim is not a proper
    :class:`UntrustedClaim`; ``render-pair-claim-tampered`` when a
    claim fails its digest. A non-list ``untrusted_claims`` is an
    authoring bug (``TypeError``). Returns an audit-visible report on
    success.
    """
    if not isinstance(action_object, ActionObject):
        _refuse(RENDER_PAIR_NO_ACTION_OBJECT,
                "decision input is not a typed Action Object", audit)
    if not verify_action_object(action_object):
        _refuse(RENDER_PAIR_ACTION_OBJECT_TAMPERED,
                "Action Object failed its digest", audit)
    if not isinstance(untrusted_claims, (list, tuple)):
        raise TypeError("untrusted_claims must be a list, got %s"
                        % type(untrusted_claims).__name__)
    digests = []
    for item in untrusted_claims:
        if not isinstance(item, UntrustedClaim):
            _refuse(RENDER_PAIR_CLAIM_MALFORMED,
                    "claim is not an UntrustedClaim", audit)
        if not verify_claim(item):
            _refuse(RENDER_PAIR_CLAIM_TAMPERED,
                    "claim failed its digest", audit)
        digests.append(item.claim_digest)
    report = {
        "pair_ok": True,
        "action_object_digest": action_object.object_digest,
        "claim_digests": digests,
        "n_claims": len(digests),
    }
    if audit is not None:
        audit({"event": "render_pair_verified",
               "action_object_digest": action_object.object_digest,
               "n_claims": len(digests)})
    return report
