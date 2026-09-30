"""Action-bound permits (W243-5, ADAPT — patterns only).

A cross-trust-boundary permit bound to exactly one
(recipient, key, request, action-instance) via the ``present_bound``
obligation hook. Adapted from the bound-permit direction: instead of
binding a permit to a delegation chain, the binding is to the
presentation quadruple itself, so a permit that crosses a trust
boundary cannot be re-presented by a different key or replayed for a
different action instance.

Rules:
  * The permit carries a ``binding_digest`` — HMAC-SHA256 of the
    canonical binding fields under the issuer's key. Any edit after
    issue refuses ``permit-tampered`` (detects re-binding, not lies
    in the original request).
  * Presentation is verified by ``present_bound``: the presenter key
    and the action instance must equal the bound values. Mismatch
    refuses ``permit-presenter-mismatch`` / ``permit-instance-replay``.
  * The permit declares a currentness mode: ``none`` (no freshness
    requirement) or ``fresh-at-use`` (presentation must carry
    freshness evidence). A declared mode that is not satisfied
    refuses ``permit-currentness-violated``.
  * Every refusal this module raises comes from the REGISTERED
    vocabulary. Raising an unregistered reason refuses
    ``permit-refusal-vocabulary-invalid`` — the permit (or the raise)
    is non-conformant. There is no ad-hoc refusal vocabulary.
  * The recipient's confirmation is signature-bound to the binding
    digest (Ed25519 via in-repo ``gov.ed25519``): ``recipient_confirm``
    signs, ``verify_recipient_confirmation`` verifies.

Integration: an optional ``base_permit`` (a ``gov.bound_permit``
permit dict) may be attached; its digest is pinned in the binding
record and ``present_bound`` runs ``bound_permit.verify_permit``
over it when supplied — reuse, not duplication.

Stdlib only (plus in-repo ``gov.ed25519`` and ``gov.bound_permit`` /
``gov.decision_codes``). Deterministic. No key material is generated
here; the issuer key is deployment-supplied and required.
"""

import hashlib
import hmac
import json

try:
    from . import ed25519 as _ed
    from . import bound_permit as _bp
    from . import decision_codes as _dc
except ImportError:  # standalone: sibling modules beside this file
    import ed25519 as _ed
    import bound_permit as _bp
    import decision_codes as _dc

PERMIT_VERSION = 1

CURRENTNESS_MODES = ("none", "fresh-at-use")

_REFUSAL_DOMAIN = "permit"


def registered_refusals():
    """The closed refusal vocabulary this module may raise, sorted."""
    return tuple(sorted((
        "permit-presenter-mismatch",
        "permit-instance-replay",
        "permit-refusal-vocabulary-invalid",
        "permit-currentness-violated",
    )))


class ActionBoundPermitError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail=""):
        _dc.code_for(code)  # fail closed: unmapped codes never leave
        super(ActionBoundPermitError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise ActionBoundPermitError(code, detail)


def raise_refusal(reason, detail=""):
    """Raise a refusal using the registered vocabulary.

    An unregistered ``reason`` is not raised as-is: the raise itself
    is non-conformant and refuses ``permit-refusal-vocabulary-invalid``.
    This is how the module enforces that there is no ad-hoc refusal
    vocabulary anywhere in its callers.
    """
    if reason not in registered_refusals():
        _refuse("permit-refusal-vocabulary-invalid",
                "unregistered refusal reason %r" % (reason,))
    _refuse(reason, detail)


def _is_bare_digest(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _canonical_dumps(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _binding_fields(recipient, key_ref, request_digest, action_instance,
                    currentness_mode, base_permit_digest):
    return {
        "v": PERMIT_VERSION,
        "recipient": recipient,
        "key_ref": key_ref,
        "request_digest": request_digest,
        "action_instance": action_instance,
        "currentness_mode": currentness_mode,
        "base_permit_digest": base_permit_digest,
    }


def _binding_digest(fields, issuer_key):
    return hmac.new(issuer_key, _canonical_dumps(fields),
                    hashlib.sha256).hexdigest()


_REQUIRED = ("v", "recipient", "key_ref", "request_digest",
             "action_instance", "currentness_mode",
             "base_permit_digest", "binding_digest")


def bind_permit(recipient, key_ref, request_digest, action_instance,
                currentness_mode="none", issuer_key=None,
                base_permit=None):
    """Mint an action-bound permit record. Never executes anything.

    ``issuer_key`` is required (deployment-supplied); without it the
    binding digest cannot be computed and the call is malformed.
    ``base_permit`` (optional) is a ``gov.bound_permit`` permit whose
    digest is pinned in this binding.
    """
    if issuer_key is None:
        _refuse("permit-malformed", "issuer_key is required")
    if not isinstance(recipient, str) or not recipient:
        _refuse("permit-malformed", "recipient must be a non-empty string")
    if not isinstance(key_ref, str) or not key_ref:
        _refuse("permit-malformed", "key_ref must be a non-empty string")
    if not _is_bare_digest(request_digest):
        _refuse("permit-malformed",
                "request_digest must be a bare 64-hex digest")
    if not isinstance(action_instance, str) or not action_instance:
        _refuse("permit-malformed",
                "action_instance must be a non-empty string")
    if currentness_mode not in CURRENTNESS_MODES:
        _refuse("permit-malformed",
                "unknown currentness_mode %r" % (currentness_mode,))
    base_permit_digest = ""
    if base_permit is not None:
        if not isinstance(base_permit, dict):
            _refuse("permit-malformed", "base_permit must be a dict")
        base_permit_digest = hashlib.sha256(
            _canonical_dumps(base_permit)).hexdigest()
    fields = _binding_fields(recipient, key_ref, request_digest,
                             action_instance, currentness_mode,
                             base_permit_digest)
    permit = dict(fields)
    permit["binding_digest"] = _binding_digest(fields, issuer_key)
    return permit


def _check_shape(permit):
    if not isinstance(permit, dict):
        _refuse("permit-malformed", "permit must be a dict")
    for field in _REQUIRED:
        if field not in permit:
            _refuse("permit-malformed", "missing field %r" % (field,))
    if permit.get("v") != PERMIT_VERSION:
        _refuse("permit-malformed", "unsupported version")
    if not _is_bare_digest(permit.get("binding_digest", "")):
        _refuse("permit-malformed", "binding_digest must be a bare digest")
    if not _is_bare_digest(permit.get("request_digest", "")):
        _refuse("permit-malformed",
                "request_digest must be a bare 64-hex digest")
    if permit.get("currentness_mode") not in CURRENTNESS_MODES:
        _refuse("permit-malformed",
                "unknown currentness_mode %r"
                % (permit.get("currentness_mode"),))


def present_bound(permit, presenter_key, action_instance,
                  issuer_key=None, freshness_evidence=None,
                  base_permit=None):
    """Verify presentation of a bound permit. Returns True on admit.

    Order: shape, digest recomputation (tamper), presenter binding,
    action-instance binding, currentness mode, optional base-permit
    pin. Every refusal is a registered-vocabulary code.
    """
    _check_shape(permit)
    if issuer_key is None:
        _refuse("permit-malformed", "issuer_key is required")
    fields = _binding_fields(
        permit["recipient"], permit["key_ref"], permit["request_digest"],
        permit["action_instance"], permit["currentness_mode"],
        permit["base_permit_digest"])
    if not hmac.compare_digest(
            _binding_digest(fields, issuer_key), permit["binding_digest"]):
        _refuse("permit-tampered",
                "binding digest does not recompute: the record was "
                "edited after issue")
    if not isinstance(presenter_key, str) or \
            presenter_key != permit["key_ref"]:
        _refuse("permit-presenter-mismatch",
                "permit is bound to %r, presented by %r"
                % (permit["key_ref"], presenter_key))
    if not isinstance(action_instance, str) or \
            action_instance != permit["action_instance"]:
        _refuse("permit-instance-replay",
                "permit is bound to action instance %r, replayed for %r"
                % (permit["action_instance"], action_instance))
    if permit["currentness_mode"] == "fresh-at-use" and \
            not freshness_evidence:
        _refuse("permit-currentness-violated",
                "currentness mode fresh-at-use declared but no freshness "
                "evidence was presented")
    if permit["base_permit_digest"]:
        if base_permit is None:
            _refuse("permit-malformed",
                    "permit pins a base_permit but none was supplied")
        _bp.verify_permit(base_permit)
        pinned = hashlib.sha256(
            _canonical_dumps(base_permit)).hexdigest()
        if not hmac.compare_digest(pinned, permit["base_permit_digest"]):
            _refuse("permit-tampered",
                    "supplied base_permit does not match the pinned digest")
    return True


def recipient_confirm(permit, recipient_seed):
    """Sign the binding digest as recipient confirmation.

    Returns the raw signature bytes. The signature binds the
    recipient's confirmation to the exact binding record.
    """
    _check_shape(permit)
    if not isinstance(recipient_seed, bytes) or len(recipient_seed) != 32:
        _refuse("permit-malformed", "recipient_seed must be 32 bytes")
    return _ed.sign(recipient_seed,
                    bytes.fromhex(permit["binding_digest"]))


def verify_recipient_confirmation(permit, recipient_pub, signature):
    """Verify a recipient confirmation over the binding digest.

    Refuses ``permit-tampered`` when the signature does not verify —
    a forged confirmation is indistinguishable from a forged record.
    Returns True when valid.
    """
    _check_shape(permit)
    ok = False
    try:
        ok = bool(_ed.verify(recipient_pub,
                             bytes.fromhex(permit["binding_digest"]),
                             signature))
    except Exception:
        ok = False
    if not ok:
        _refuse("permit-tampered",
                "recipient confirmation does not verify over the "
                "binding digest")
    return True
