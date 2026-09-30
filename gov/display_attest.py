"""Deterministic display attestation (PIP-010 pattern, re-derived prose).

The core property: rendering is a PURE DETERMINISTIC FUNCTION of the
signed bytes. ``attest_display(artifact_digest, render_policy_digest,
renderer_id, render_bytes)`` produces a ``DisplayAttestation`` —
``{artifact_digest, render_policy_digest, renderer_id,
render_bytes_digest, attested_at}`` — and
``verify_attestation(attestation, artifact_bytes)`` re-derives the
render from the signed artifact bytes under the pinned render policy,
refusing fail-closed with the named code
``display-rederivation-failed`` on any mismatch. A verifier needs only
the signed bytes and the pinned policy to reproduce exactly what the
approver was shown.

Render policies are deployment-pinned: ``register_render_policy``
binds a ``policy_digest`` to a pure ``bytes -> bytes`` render
function. Registration CHECKS determinism — the function is called
twice on fixed probe bytes and refused (``ValueError``) unless both
calls return byte-identical output. This is a necessary but NOT
sufficient condition: a function deterministic on the probe bytes but
nondeterministic elsewhere still passes registration. Full purity
across the input domain remains the policy author's responsibility;
any divergence surfaces fail-closed as
``display-rederivation-failed`` at verify time. A renderer that cannot
reproduce its own output deterministically proves nothing about what
the approver saw.

Commitment composition (wave-221 ``gov.render_commit``): an
attestation that CLAIMS a renderer (non-empty ``renderer_id``) must be
backed by a rendering commitment — the hash anchor of the exact
view-time bytes — or verification fails closed with the named code
``display-no-render-commitment``. Legacy attestations
(``renderer_id == ""``) stay verifiable by pure re-derivation: no
backward break.

WHAT THIS DOES NOT PROVE (honest caveat): this proves the RENDERING
is deterministic from the signed bytes. It does NOT prove the approver
looked at the display, read it, or understood it — WYSIWYS as a claim
about human attention and intent is not solved here and cannot be
solved by a digest. Approver-intent verification (ceremony design, UI
logging, liveness) is a deployment boundary. Likewise an attestation
NEVER authorizes: it is a replayable record, not a grant, not a
permit — presenting one where an authorization is expected fails
closed.

$0 spend. stdlib only. No network. No keys (plain digests).
"""

import hashlib
import hmac
import json

from .approvals import canonical_packet, sanitize_preview_text
from . import presentation as _pres
from . import render_commit as _rc

DISPLAY_REDERIVATION_FAILED = "display-rederivation-failed"
DISPLAY_NO_RENDER_COMMITMENT = "display-no-render-commitment"
DISPLAY_POLICY_UNKNOWN = "display-policy-unknown"


class DisplayAttestationError(_pres.FaithfulnessError):
    """Base class for display-attestation refusals.

    ``code`` is machine-readable and greppable. Subclasses pin the
    code so a bare ``DisplayAttestationError`` never leaks.
    """

    code = "display-attestation-error"


class RederivationFailedError(DisplayAttestationError):
    """The render could not be re-derived from the signed bytes: the
    offered bytes are not the attested artifact, the re-derived render
    does not match the attested render bytes, the backing commitment
    does not anchor the re-derived render, or the render policy raised.
    A renderer that cannot reproduce the display surface proves nothing
    about what the approver saw."""

    code = DISPLAY_REDERIVATION_FAILED


class NoRenderCommitmentError(DisplayAttestationError):
    """The attestation claims a renderer (non-empty ``renderer_id``)
    but no rendering commitment was offered: a live renderer is
    expected to anchor the exact view-time bytes, and its absence is a
    fail-closed refusal, not a downgrade to digest-only."""

    code = DISPLAY_NO_RENDER_COMMITMENT


class PolicyUnknownError(DisplayAttestationError):
    """No render policy is registered for the attestation's
    ``render_policy_digest``: re-derivation is impossible without the
    pinned policy, so verification fails closed."""

    code = DISPLAY_POLICY_UNKNOWN


#: Exact key set of a DisplayAttestation. No authorization-shaped
#: fields may ever appear here (see the module docstring).
_ATTESTATION_KEYS = frozenset((
    "artifact_digest",
    "render_policy_digest",
    "renderer_id",
    "render_bytes_digest",
    "attested_at",
))

#: policy_digest -> (policy_id, render_fn). Deployment-pinned.
_POLICY_REGISTRY = {}


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def register_render_policy(policy_id, policy_digest, render_fn):
    """Pin a render policy: ``policy_digest`` -> pure ``render_fn``.

    ``render_fn`` must be a pure ``bytes -> bytes`` function: it is
    called twice on fixed probe bytes at registration and refused with
    ``ValueError`` unless both calls return byte-identical bytes.
    Re-registering the same digest for a DIFFERENT function is refused
    (pin confusion); re-registering the identical function is a no-op.
    Authoring misuse (empty ids/digests, non-callable) raises
    ``TypeError``/``ValueError`` — caller bugs, not attack shapes.
    """
    if not isinstance(policy_id, str) or not policy_id:
        raise ValueError("policy_id must be a non-empty string")
    if not isinstance(policy_digest, str) or not policy_digest:
        raise ValueError("policy_digest must be a non-empty string")
    if not callable(render_fn):
        raise TypeError("render_fn must be callable")
    try:
        first = render_fn(_PURITY_PROBE_BYTES)
        second = render_fn(_PURITY_PROBE_BYTES)
    except Exception as exc:  # noqa: BLE001 - authoring bug surface
        raise ValueError(
            "render_fn raised on probe bytes (not a pure function?): %r"
            % (exc,))
    if not isinstance(first, (bytes, bytearray)) or \
            not isinstance(second, (bytes, bytearray)):
        raise ValueError("render_fn must return bytes")
    if bytes(first) != bytes(second):
        raise ValueError(
            "render_fn is not deterministic: two calls on identical "
            "input diverged — a renderer that cannot reproduce its own "
            "output proves nothing")
    existing = _POLICY_REGISTRY.get(policy_digest)
    if existing is not None and existing[1] is not render_fn:
        raise ValueError(
            "policy_digest %r is already pinned to a different render "
            "function" % (policy_digest,))
    _POLICY_REGISTRY[policy_digest] = (policy_id, render_fn)
    return True


def unregister_render_policy(policy_digest):
    """Remove a policy pin. Support seam for tests and for deployments
    rotating a policy; returns True when a pin was removed."""
    return _POLICY_REGISTRY.pop(policy_digest, None) is not None


def _lookup_policy(render_policy_digest):
    """Return the ``(policy_id, render_fn)`` pin for a digest, or fail
    closed with ``display-policy-unknown`` when nothing is pinned."""
    entry = _POLICY_REGISTRY.get(render_policy_digest)
    if entry is None:
        raise PolicyUnknownError(
            "display-policy-unknown: no render policy registered for "
            "digest %r" % (render_policy_digest,))
    return entry


def rederive(artifact_bytes, render_policy_digest):
    """Re-derive the render bytes from the signed artifact bytes.

    Low-level seam: looks up the pinned render policy and applies it.
    Unknown policy digests fail closed with ``display-policy-unknown``;
    render-function errors propagate to the caller (``verify`` wraps
    them as ``display-rederivation-failed``).
    """
    if not isinstance(artifact_bytes, (bytes, bytearray)):
        raise TypeError("artifact_bytes must be bytes")
    return bytes(_lookup_policy(render_policy_digest)[1](
        bytes(artifact_bytes)))


def _check_attestation_shape(attestation):
    """Validate the shape of a DisplayAttestation dict.

    Any shape violation fails closed with
    ``display-rederivation-failed``: a malformed attestation cannot be
    re-derived, whether the cause is tampering or a malformed caller.
    """
    if not isinstance(attestation, dict):
        raise RederivationFailedError(
            "display-rederivation-failed: attestation is not a dict")
    if set(attestation) != set(_ATTESTATION_KEYS):
        raise RederivationFailedError(
            "display-rederivation-failed: attestation keys %s != %s"
            % (sorted(attestation), sorted(_ATTESTATION_KEYS)))
    for field in ("artifact_digest", "render_policy_digest",
                  "render_bytes_digest"):
        if not isinstance(attestation[field], str) or \
                not attestation[field]:
            raise RederivationFailedError(
                "display-rederivation-failed: %r must be a non-empty "
                "string" % (field,))
    if not isinstance(attestation["renderer_id"], str):
        raise RederivationFailedError(
            "display-rederivation-failed: renderer_id must be a string")
    if not isinstance(attestation["attested_at"], str) or \
            not attestation["attested_at"]:
        raise RederivationFailedError(
            "display-rederivation-failed: attested_at must be a "
            "non-empty string")
    return True


def attest_display(artifact_digest, render_policy_digest, renderer_id,
                   render_bytes, rendering_commitment=None):
    """Attest to the exact bytes the approver was shown.

    ``artifact_digest`` binds the signed artifact; ``render_bytes`` is
    the final view-time byte stream (committed verbatim, byte for
    byte); ``renderer_id`` names the rendering seam — pass ``""`` for
    legacy digest-only attestations, a non-empty id (e.g.
    ``"queue-view"``) when a live renderer produced the bytes.
    ``rendering_commitment`` (optional, wave-221) is a
    ``gov.render_commit`` ``RenderingCommitment`` over the view-time
    bytes: when present it must commit to THESE render bytes and THIS
    artifact, or attestation fails closed at attest time with
    ``rendering-commitment-broken``.

    Returns a ``DisplayAttestation`` dict. Authoring misuse raises
    ``TypeError``/``ValueError`` — caller bugs, not attack shapes.
    """
    if not isinstance(artifact_digest, str) or not artifact_digest:
        raise ValueError("artifact_digest must be a non-empty string")
    if not isinstance(render_policy_digest, str) or not render_policy_digest:
        raise ValueError("render_policy_digest must be a non-empty string")
    if not isinstance(renderer_id, str):
        raise TypeError(
            "renderer_id must be a string ('' for legacy digest-only "
            "attestations)")
    if not isinstance(render_bytes, (bytes, bytearray)):
        raise TypeError("render_bytes must be bytes")
    render_bytes = bytes(render_bytes)
    if rendering_commitment is not None:
        # Fail closed at attest time: a commitment that does not
        # commit to these render bytes / this artifact is never
        # attached to the attestation.
        _rc.check_commitment_shape(rendering_commitment)
        if not hmac.compare_digest(rendering_commitment["artifact_digest"],
                                   artifact_digest):
            raise _rc.RenderingCommitmentError(
                "rendering-commitment-broken: the commitment binds a "
                "different artifact than the one being attested")
        _rc.verify(rendering_commitment, render_bytes)
    return {
        "artifact_digest": artifact_digest,
        "render_policy_digest": render_policy_digest,
        "renderer_id": renderer_id,
        "render_bytes_digest": _digest(render_bytes),
        "attested_at": _pres.utcnow_iso(),
    }


def verify_attestation(attestation, artifact_bytes, rendering_commitment=None):
    """Re-derive the render and verify the attestation, fail-closed.

    Fail-closed refuses (all named):
    * ``display-no-render-commitment`` — the attestation claims a
      renderer (non-empty ``renderer_id``) but no rendering commitment
      was offered;
    * ``display-rederivation-failed`` — the offered bytes are not the
      attested artifact; the re-derived render does not match the
      attested render bytes; the render policy raised or did not
      return bytes; or the backing commitment does not anchor the
      re-derived render;
    * ``display-policy-unknown`` — no render policy is registered for
      the attestation's ``render_policy_digest``.

    Legacy attestations (``renderer_id == ""``) verify by pure
    re-derivation with ``rendering_commitment=None`` — no backward
    break. Returns True when the attestation re-derives cleanly.
    """
    _check_attestation_shape(attestation)
    if not isinstance(artifact_bytes, (bytes, bytearray)):
        raise TypeError("artifact_bytes must be bytes")
    artifact_bytes = bytes(artifact_bytes)
    # (1) A renderer claim requires a backing commitment: a live
    # renderer is expected to anchor the exact view-time bytes.
    if attestation["renderer_id"] and rendering_commitment is None:
        raise NoRenderCommitmentError(
            "display-no-render-commitment: the attestation claims "
            "renderer %r but carries no rendering commitment"
            % (attestation["renderer_id"],))
    # (2) The offered bytes must be the attested artifact.
    if not hmac.compare_digest(_digest(artifact_bytes),
                               attestation["artifact_digest"]):
        raise RederivationFailedError(
            "display-rederivation-failed: the offered bytes are not "
            "the attested artifact")
    # (3) The render policy must be pinned; (4) re-derive.
    render_fn = _lookup_policy(attestation["render_policy_digest"])[1]
    try:
        rederived = render_fn(artifact_bytes)
    except Exception as exc:  # noqa: BLE001 - fail closed, never assume
        raise RederivationFailedError(
            "display-rederivation-failed: the render policy raised: "
            "%r" % (exc,))
    if not isinstance(rederived, (bytes, bytearray)):
        raise RederivationFailedError(
            "display-rederivation-failed: the render policy did not "
            "return bytes")
    rederived = bytes(rederived)
    if not hmac.compare_digest(_digest(rederived),
                               attestation["render_bytes_digest"]):
        raise RederivationFailedError(
            "display-rederivation-failed: the re-derived render does "
            "not match the attested render bytes")
    # (5) When a commitment backs the attestation, it must anchor the
    # re-derived render and the attested artifact: this ties the
    # view-time hash anchor to the deterministic re-derivation.
    if rendering_commitment is not None:
        _rc.check_commitment_shape(rendering_commitment)
        if not hmac.compare_digest(rendering_commitment["render_hash"],
                                   attestation["render_bytes_digest"]):
            raise RederivationFailedError(
                "display-rederivation-failed: the backing commitment "
                "does not anchor the attested render bytes")
        if not hmac.compare_digest(rendering_commitment["artifact_digest"],
                                   attestation["artifact_digest"]):
            raise RederivationFailedError(
                "display-rederivation-failed: the backing commitment "
                "binds a different artifact")
        try:
            _rc.verify(rendering_commitment, rederived)
        except _rc.RenderingCommitmentError as exc:
            raise RederivationFailedError(
                "display-rederivation-failed: the backing commitment "
                "does not replay the re-derived render: %s" % (exc,))
    return True


# ----------------------------------------------------------------------
# Built-in render policy: the approval display (approval-display-v1).
# ----------------------------------------------------------------------
#
# The signed input bytes are the canonical JSON of
# ``{"approval_id": ..., "packet": canonical_packet(record)}`` — the
# approval id rides the envelope because the render shows it, and the
# packet is the signed artifact (``gov.presentation.artifact_digest``
# digests the same packet). The render function below is an
# independent re-implementation of the ``gov.approval_render`` view-
# time render over that envelope: any drift between the two surfaces
# as ``display-rederivation-failed`` (fail-closed), never as silent
# agreement. The eval battery pins byte-identity against the real
# renderer across fixture variants.

APPROVAL_DISPLAY_V1 = "approval-display-v1"

#: Well-known constant identifying the built-in policy. This is a
#: stable identifier, NOT an audited pin: deployments that want an
#: audited pin re-register the same render function under their own
#: digest after review (``register_render_policy``).
APPROVAL_DISPLAY_V1_DIGEST = "sha256:" + hashlib.sha256(
    b"sasanam:display-attestation:approval-display-v1:1").hexdigest()


def approval_render_input(record):
    """The signed input bytes for the built-in approval render policy.

    Canonical JSON of ``{"approval_id": record["id"], "packet":
    canonical_packet(record)}``, UTF-8 encoded. ``sha256`` of these
    bytes is the ``artifact_digest`` the attestation binds; the packet
    is the same signed artifact ``gov.presentation.artifact_digest``
    digests.
    """
    if not isinstance(record, dict):
        raise TypeError("record must be a dict")
    envelope = {
        "approval_id": record.get("id"),
        "packet": canonical_packet(record),
    }
    return _pres.canonical_json(envelope).encode("utf-8")


def approval_display_v1_render(artifact_bytes):
    """Re-derive the approver-facing render from the signed bytes.

    Pure deterministic ``bytes -> bytes`` function: parses the
    ``approval_render_input`` envelope and renders the identical line
    list the ``gov.approval_render`` view-time renderer produces,
    under the same ``sanitize_preview_text`` normalization (one
    normalizer, not two). Malformed input raises ``ValueError`` —
    authoring bug, surfaced as ``display-rederivation-failed`` by
    ``verify_attestation``.
    """
    try:
        raw = bytes(artifact_bytes)
    except TypeError:
        raise ValueError("artifact_bytes must be bytes")
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(
            "artifact_bytes are not canonical JSON: %r" % (exc,))
    if not isinstance(envelope, dict):
        raise ValueError("artifact_bytes must encode a JSON object envelope")
    packet = envelope.get("packet")
    if not isinstance(packet, dict):
        raise ValueError("envelope lacks a 'packet' object")
    policy = packet.get("policy") or {}
    agent = packet.get("agent") or {}
    lines = [
        "APPROVAL %s" % (envelope.get("approval_id") or ""),
        "action: %s" % (packet.get("action") or ""),
        "target: %s" % (packet.get("target") or ""),
        "canonical_target: %s" % (packet.get("canonical_target") or ""),
        "risk: %s (%s)" % (packet.get("risk_tier") or "",
                           packet.get("risk_score") or 0),
        "risk_factors: %s"
        % (", ".join(packet.get("risk_factors") or []) or "none"),
        "packet_digest: %s" % _pres.sha256_hex(
            _pres.canonical_json(packet)),
        "preview_sha256: %s" % (packet.get("preview_sha256") or ""),
        "policy: %s v%s matched=%s"
        % (policy.get("policy_id") or "",
           policy.get("policy_version") or "",
           ",".join(policy.get("matched_rules") or []) or "none"),
        "agent: %s role=%s" % (agent.get("agent_id") or "",
                               agent.get("role") or ""),
    ]
    text = "\n".join(lines) + "\n"
    return sanitize_preview_text(text).encode("utf-8")


#: Fixed probe bytes for the registration purity check: a minimal
#: valid envelope. Must be defined before the built-in registration.
_PURITY_PROBE_BYTES = _pres.canonical_json(
    {"approval_id": "purity-probe", "packet": {}}).encode("utf-8")

register_render_policy(APPROVAL_DISPLAY_V1, APPROVAL_DISPLAY_V1_DIGEST,
                       approval_display_v1_render)


__all__ = [
    "DISPLAY_REDERIVATION_FAILED",
    "DISPLAY_NO_RENDER_COMMITMENT",
    "DISPLAY_POLICY_UNKNOWN",
    "DisplayAttestationError",
    "RederivationFailedError",
    "NoRenderCommitmentError",
    "PolicyUnknownError",
    "register_render_policy",
    "unregister_render_policy",
    "rederive",
    "attest_display",
    "verify_attestation",
    "approval_render_input",
    "approval_display_v1_render",
    "APPROVAL_DISPLAY_V1",
    "APPROVAL_DISPLAY_V1_DIGEST",
]
