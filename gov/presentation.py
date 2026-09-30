"""Presentation-faithfulness for the approval pipeline (EMILIA steal) and
mission-bound authorization-relevant context (mission-bound ARAP adapt).

EMILIA lesson: the approver must see a FAITHFUL rendering of what is
being signed. A display whose digest differs from the digest of the
signed artifact is a named attack — ``display-hash-mismatch`` — and is
refused fail-closed here, never silently tolerated.

Mission-bound ARAP (adapted from the ``mission-bound-authorization``
pattern, not vendored): an approval binds the request's
``parameter_digest``. The binding is exact (no downgrade to a relaxed
match), and one-use permit leases make replaying an authorization
impossible.

This module is additive: it imports ``gov.approvals`` read-only
(``canonical_packet``, ``sanitize_preview_text``) and never changes
the queue path. All refusals raise ``FaithfulnessError`` subclasses
with a machine-readable ``code``. Authoring misuse (non-dict inputs,
malformed records) raises plain ``ValueError``/``TypeError`` — those
are caller bugs, not attack shapes.

A note on digest domains: presentation digests are taken over the
rendered text the human saw; artifact digests are taken over the
canonical packet JSON. They live in different domains and are never
compared to each other. "Faithful" means the sealed presentation
re-renders byte-identically from the current record — that comparison
is ``verify_seal`` in ``gov.approval_render``, not this module.

$0 spend. stdlib only. No network. Deployment-owned keys where keys
appear (mission binding uses plain digests; no key needed).
"""

import hashlib
import hmac
import json
import secrets
import time

from .approvals import canonical_packet

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------

DISPLAY_HASH_MISMATCH = "display-hash-mismatch"
PRESENTATION_MISSING = "presentation-missing"
MISSION_BINDING_MISMATCH = "mission-binding-mismatch"
PERMIT_REUSED = "permit-reused"
DOWNGRADE_REFUSED = "downgrade-refused"


class FaithfulnessError(Exception):
    """Base class for all presentation / mission-binding refusals.

    ``code`` is machine-readable and greppable. Subclasses pin the
    code so a bare ``FaithfulnessError`` never leaks from the module.
    """

    code = "faithfulness-error"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class DisplayHashMismatchError(FaithfulnessError):
    """The presentation digest does not match the digest of the signed
    artifact, or the rendered presentation was tampered with between
    view and sign: display != hash."""

    code = DISPLAY_HASH_MISMATCH


class PresentationMissingError(FaithfulnessError):
    """No (or a malformed) presentation was offered where the
    presentation seam was invoked: fail closed, never assume the
    approver saw anything."""

    code = PRESENTATION_MISSING


class MissionBindingMismatchError(FaithfulnessError):
    """The request's parameter_digest changed after the authorization
    was issued, or an unknown lease was presented: the permit cannot
    be retargeted."""

    code = MISSION_BINDING_MISMATCH


class PermitReusedError(FaithfulnessError):
    """A one-use permit lease was presented a second time: replay of
    an authorization is impossible."""

    code = PERMIT_REUSED


class DowngradeRefusedError(FaithfulnessError):
    """A permit was asked to match on a relaxed (non-exact) basis: the
    no-downgrade rule refuses — the binding is exact or it does not
    bind."""

    code = DOWNGRADE_REFUSED


# ----------------------------------------------------------------------
# Canonical helpers.
# ----------------------------------------------------------------------

_DIGEST_SCHEME = "sha256"


def canonical_json(obj):
    """Canonical JSON for digesting: sorted keys, tight separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str)


def sha256_hex(text):
    """sha256 hex of UTF-8 text (public: shared with approval_render)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def utcnow_iso():
    """Current local time as an ISO-ish timestamp (audit stamps)."""
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())


def presentation_digest(text):
    """Digest of the exact text shown to the approver.

    ``text`` must already be the final rendered surface (see
    ``gov.approval_render.render_approval``, which applies the same
    ``sanitize_preview_text`` normalization the wave-174
    display-execution seam uses — one normalizer, not two).
    """
    if not isinstance(text, str):
        raise TypeError("presentation text must be a string")
    return "%s:%s" % (_DIGEST_SCHEME, sha256_hex(text))


def artifact_digest(record):
    """Digest of the signed artifact: the canonical decision packet.

    ``canonical_packet`` is a pure function of the stored record
    fields — the same WYSINWYS surface the queue shows the human —
    so any tampering with the record between render and sign changes
    this digest. The artifact is the packet, not the preview string:
    the preview is advisory prose; the packet is what executes.
    """
    if not isinstance(record, dict):
        raise TypeError("record must be a dict")
    return "%s:%s" % (_DIGEST_SCHEME,
                      sha256_hex(canonical_json(canonical_packet(record))))


def check_presentation_integrity(presentation):
    """Verify the presentation digest covers the presented text.

    ``presentation`` is ``{"text": ..., "digest": ...}`` as produced by
    ``gov.approval_render.render_approval``. This is the tamper check
    only: it proves the render was not edited between view and sign.
    The artifact-binding checks (swapped display, stale display) live
    in ``gov.approval_render.verify_seal``, which is where the record
    is in scope. Raises ``PresentationMissingError`` when the
    presentation is absent or malformed; ``DisplayHashMismatchError``
    when the digest does not cover the text. Returns True on an
    intact presentation.
    """
    if not isinstance(presentation, dict):
        raise PresentationMissingError(
            "presentation-missing: no presentation offered where the "
            "presentation seam was invoked")
    text = presentation.get("text")
    digest = presentation.get("digest")
    if not isinstance(text, str) or not isinstance(digest, str):
        raise PresentationMissingError(
            "presentation-missing: malformed presentation "
            "(need text+digest strings)")
    want = presentation_digest(text)
    if not hmac.compare_digest(digest, want):
        raise DisplayHashMismatchError(
            "display-hash-mismatch: the presentation text does not "
            "digest to its attached digest — the render was tampered "
            "with between view and sign")
    return True


# ----------------------------------------------------------------------
# Mission-bound authorization-relevant context.
# ----------------------------------------------------------------------

def parameter_digest(payload):
    """Bind an approval to the request it authorizes.

    ``payload`` is the canonical request shape, e.g.
    ``{"subject", "resource", "action", "args"}``. Any change to the
    parameters changes the digest — the authorization cannot drift
    onto different parameters.
    """
    if not isinstance(payload, dict):
        raise TypeError("parameter payload must be a dict")
    return "%s:%s" % (_DIGEST_SCHEME, sha256_hex(canonical_json(payload)))


def mission_bind_approval(sealed, parameter_digest_value):
    """Attach the mission parameter_digest to a sealed approval.

    Returns a NEW dict (the sealed approval is immutable-by-convention:
    binding never mutates the caller's copy). Missing/empty digests
    are an authoring bug (ValueError) — a binding to nothing is never
    emitted.
    """
    if not isinstance(sealed, dict):
        raise TypeError("sealed approval must be a dict")
    if not isinstance(parameter_digest_value, str) or not parameter_digest_value:
        raise ValueError("parameter_digest must be a non-empty string")
    bound = dict(sealed)
    bound["parameter_digest"] = parameter_digest_value
    return bound


def verify_mission_binding(sealed, parameter_digest_value):
    """Refuse unless the sealed approval binds exactly this digest.

    Exact match only — the no-downgrade rule is enforced here too:
    there is no relaxed-match mode at this seam. A non-dict ``sealed``
    is authoring misuse (TypeError); a missing/differing digest is a
    data refusal.
    """
    if not isinstance(sealed, dict):
        raise TypeError("sealed approval must be a dict")
    bound = sealed.get("parameter_digest")
    if not isinstance(bound, str) or not hmac.compare_digest(
            bound, parameter_digest_value or ""):
        raise MissionBindingMismatchError(
            "mission-binding-mismatch: the request's parameter_digest "
            "differs from the digest the approval binds — the "
            "authorization cannot be retargeted")
    return True


class MissionPermitRegistry:
    """One-use permit leases binding an approval to a parameter_digest.

    ``issue`` mints a lease for ``(approval_id, parameter_digest)``.
    ``consume`` verifies the presented digest against the lease exactly
    and marks the lease used: a lease authorizes ONE authorization
    event. A second consume is refused as ``permit-reused`` (replay is
    impossible); a different digest is refused as
    ``mission-binding-mismatch``; any non-exact match mode is refused
    as ``downgrade-refused`` (the no-downgrade rule).
    """

    def __init__(self):
        self._leases = {}

    def issue(self, approval_id, parameter_digest_value):
        """Mint a one-use lease binding approval_id to the digest."""
        if not isinstance(approval_id, str) or not approval_id:
            raise ValueError("approval_id must be a non-empty string")
        if not isinstance(parameter_digest_value, str) \
                or not parameter_digest_value:
            raise ValueError("parameter_digest must be a non-empty string")
        lease_id = "mission-permit-" + secrets.token_urlsafe(24)
        self._leases[lease_id] = {
            "lease_id": lease_id,
            "approval_id": approval_id,
            "parameter_digest": parameter_digest_value,
            "used": False,
            "issued_at": utcnow_iso(),
        }
        return dict(self._leases[lease_id])

    def consume(self, lease_id, parameter_digest_value, *,
                match="exact", audit=None):
        """Consume a lease for the presented digest.

        Returns True on the single authorized consumption. Refuses
        fail-closed otherwise; the refusal leaves the lease's
        used-state unchanged so a refused attempt never burns a
        legitimate lease.
        """
        if match != "exact":
            raise DowngradeRefusedError(
                "downgrade-refused: permit matching is exact-only; "
                "relaxed matching is a downgrade of the mission "
                "binding and is refused")
        lease = self._leases.get(lease_id)
        if lease is None:
            raise MissionBindingMismatchError(
                "mission-binding-mismatch: unknown permit lease")
        if not hmac.compare_digest(lease["parameter_digest"],
                                    parameter_digest_value or ""):
            raise MissionBindingMismatchError(
                "mission-binding-mismatch: presented parameter_digest "
                "differs from the digest the permit binds")
        if lease["used"]:
            raise PermitReusedError(
                "permit-reused: this permit was already consumed — "
                "one-use leases cannot be replayed")
        lease["used"] = True
        if audit is not None:
            audit({"event": "mission_permit_consumed",
                   "lease_id": lease_id,
                   "approval_id": lease["approval_id"],
                   "at": utcnow_iso()})
        return True


__all__ = [
    "DISPLAY_HASH_MISMATCH",
    "PRESENTATION_MISSING",
    "MISSION_BINDING_MISMATCH",
    "PERMIT_REUSED",
    "DOWNGRADE_REFUSED",
    "FaithfulnessError",
    "DisplayHashMismatchError",
    "PresentationMissingError",
    "MissionBindingMismatchError",
    "PermitReusedError",
    "DowngradeRefusedError",
    "presentation_digest",
    "artifact_digest",
    "check_presentation_integrity",
    "canonical_json",
    "sha256_hex",
    "utcnow_iso",
    "parameter_digest",
    "mission_bind_approval",
    "verify_mission_binding",
    "MissionPermitRegistry",
]
