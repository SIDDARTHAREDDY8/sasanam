"""Approval rendering commitments (mission-bound STEAL, not vendored).

mission-bound's ``consent_rendering_hash`` is a hash-anchored, replayable
commitment to EXACTLY what the approver was shown — explicitly
non-authorizing. This module re-expresses that shape for the Sasanam
approval pipeline:

* ``commit(render_bytes, artifact_digest, renderer_id)`` produces a
  ``RenderingCommitment`` — a plain dict
  ``{artifact_digest, render_hash, rendered_at, renderer_id,
  render_policy_digest}`` where ``render_hash`` is ``sha256:<hex>`` over
  the exact bytes the approver saw;
* ``verify(commitment, replay_bytes)`` replays the commitment: it
  recomputes the hash over the replayed bytes and refuses fail-closed
  with the named code ``rendering-commitment-broken`` when the replay
  does not match.

THE COMMITMENT NEVER CARRIES AUTHORITY. It is a replayable record —
proof that a later auditor can recompute exactly what the approver was
shown — not a grant, not a permit, not an authorization. Presenting a
rendering commitment where an authorization is expected must fail
closed: it carries no ``permit_id``, no ``scope``, no grant shape, and
no issuance timestamp semantics. (See probe p10 in
``evals/w221_rendercommit_probes.py``.) Custody of the replay bytes —
the exact render the approver saw — is the auditor's job: a commitment
replays only against bytes it actually commits to.

Digest formats match ``gov.presentation`` (``sha256:<hex>``), but
rendering commitments bind the *view-time byte stream*, not the
canonical packet — one normalizer, not two: the bytes are committed as
presented, unmodified.

$0 spend. stdlib only. No network. No keys (plain digests).
"""

import hashlib
import hmac
import time

RENDERING_COMMITMENT_BROKEN = "rendering-commitment-broken"

#: Exact key set of a RenderingCommitment. No authorization-shaped
#: fields may ever appear here (see the module docstring).
_COMMITMENT_KEYS = frozenset((
    "artifact_digest",
    "render_hash",
    "rendered_at",
    "renderer_id",
    "render_policy_digest",
))


class RenderingCommitmentError(Exception):
    """A rendering commitment did not replay, or was malformed.

    ``code`` is the machine-readable, greppable refusal. The only code
    this module emits is ``rendering-commitment-broken``: both a
    tampered replay and a malformed commitment input fail here, because
    a commitment that cannot be replayed byte-for-byte is useless as
    evidence either way.
    """

    code = RENDERING_COMMITMENT_BROKEN

    def __init__(self, message=""):
        super(RenderingCommitmentError, self).__init__(message)


def _render_hash(render_bytes):
    return "sha256:" + hashlib.sha256(render_bytes).hexdigest()


def utcnow_iso():
    """Current local time as an ISO-ish timestamp (audit stamps)."""
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())


def commit(render_bytes, artifact_digest, renderer_id,
           render_policy_digest=None):
    """Commit to the exact bytes the approver saw.

    ``render_bytes`` is the final view-time byte stream (already
    normalized by the caller's renderer — this module commits it
    verbatim, byte for byte). ``artifact_digest`` binds the commitment
    to the signed artifact. ``renderer_id`` names the rendering seam
    (e.g. ``"queue-view"``). ``render_policy_digest`` is the optional
    digest of the render policy used.

    Returns a ``RenderingCommitment`` dict. Authoring misuse (non-bytes
    input, empty digest/renderer) raises ``TypeError``/``ValueError`` —
    caller bugs, not attack shapes.
    """
    if not isinstance(render_bytes, (bytes, bytearray)):
        raise TypeError("render_bytes must be bytes")
    if not isinstance(artifact_digest, str) or not artifact_digest:
        raise ValueError("artifact_digest must be a non-empty string")
    if not isinstance(renderer_id, str) or not renderer_id:
        raise ValueError("renderer_id must be a non-empty string")
    if render_policy_digest is not None and (
            not isinstance(render_policy_digest, str)
            or not render_policy_digest):
        raise ValueError(
            "render_policy_digest must be None or a non-empty string")
    return {
        "artifact_digest": artifact_digest,
        "render_hash": _render_hash(bytes(render_bytes)),
        "rendered_at": utcnow_iso(),
        "renderer_id": renderer_id,
        "render_policy_digest": render_policy_digest or "",
    }


def check_commitment_shape(commitment):
    """Validate the shape of a RenderingCommitment dict.

    Raises ``RenderingCommitmentError`` (code
    ``rendering-commitment-broken``) on any shape violation: not a
    dict, wrong key set, non-string or empty render_hash /
    artifact_digest / renderer_id. A commitment that cannot be
    replayed is refused whether the cause is tampering or a
    malformed caller — the verifier cannot distinguish them, and
    guessing wrong is the attack.
    """
    if not isinstance(commitment, dict):
        raise RenderingCommitmentError(
            "rendering-commitment-broken: commitment is not a dict")
    if set(commitment) != set(_COMMITMENT_KEYS):
        raise RenderingCommitmentError(
            "rendering-commitment-broken: commitment keys %s != %s"
            % (sorted(commitment), sorted(_COMMITMENT_KEYS)))
    for field in ("artifact_digest", "render_hash", "renderer_id"):
        if not isinstance(commitment[field], str) or not commitment[field]:
            raise RenderingCommitmentError(
                "rendering-commitment-broken: %r must be a non-empty "
                "string" % (field,))
    if commitment["render_hash"].startswith("sha256:"):
        tail = commitment["render_hash"][len("sha256:"):]
        if len(tail) != 64 or any(c not in "0123456789abcdef" for c in tail):
            raise RenderingCommitmentError(
                "rendering-commitment-broken: render_hash is not "
                "sha256:<64-hex>")
    if not isinstance(commitment.get("render_policy_digest"), str):
        raise RenderingCommitmentError(
            "rendering-commitment-broken: render_policy_digest must be "
            "a string")
    return True


def verify(commitment, replay_bytes):
    """Replay a commitment against the presented byte stream.

    Recomputes ``sha256`` over ``replay_bytes`` and compares with the
    commitment's ``render_hash`` (constant-time). Returns True on an
    exact replay; raises ``RenderingCommitmentError`` (code
    ``rendering-commitment-broken``) on any mismatch or malformed
    commitment. Non-bytes replay input is an authoring bug
    (``TypeError``).
    """
    check_commitment_shape(commitment)
    if not isinstance(replay_bytes, (bytes, bytearray)):
        raise TypeError("replay_bytes must be bytes")
    recomputed = _render_hash(bytes(replay_bytes))
    if not hmac.compare_digest(commitment["render_hash"], recomputed):
        raise RenderingCommitmentError(
            "rendering-commitment-broken: the replay bytes do not hash "
            "to the committed render_hash — the render presented for "
            "replay is not the render the approver saw")
    return True


__all__ = [
    "RENDERING_COMMITMENT_BROKEN",
    "RenderingCommitmentError",
    "commit",
    "verify",
    "check_commitment_shape",
    "utcnow_iso",
]
