"""The approver-facing rendering seam: what the human saw, with its
digest attached, so the approval pipeline can refuse a signature over
a mismatched display.

``render_approval(record)`` produces ``{"text", "digest"}``: the exact
text shown to the approver (rendered from the same ``canonical_packet``
display surface the queue path shows, sanitized with the same
``sanitize_preview_text`` normalizer the wave-174 display-execution
seam uses — one normalizer, not two) plus its digest.

``seal_approval(record, presentation, signer=...)`` binds the signing
ceremony: ``{approval_id, artifact_digest, presentation_digest,
presentation_text, signer, at}``, optionally stamped with the
request's ``parameter_digest`` (mission-bound seals).

``verify_seal(record, sealed)`` is the approval-pipeline gate. It
refuses fail-closed with the named ``display-hash-mismatch`` code when:
(1) the presentation text no longer digests to its attached digest
(tampered render); (2) the signed artifact digest differs from the
digest of the current record (swapped display / show A, sign B); or
(3) the record drifted since the presentation was rendered (the
approver saw a stale display). Malformed input is refused as
``presentation-missing``.

``guarded_decide(queue, approval_id, approved, reason, *,
sealed=None, **kw)`` is the opt-in pipeline wrapper: with
``sealed=None`` it calls the underlying ``queue.decide`` byte-
identically (the legacy path is untouched); with a sealed presentation
it verifies the seal against the live record first and only then
decides.

$0 spend. stdlib only. No network.
"""

import hmac

from .approvals import canonical_packet, sanitize_preview_text
from . import presentation as _pres


def _render_text(record):
    """The approver-facing rendering of the canonical decision packet.

    Rendered from ``canonical_packet`` — the same machine-generated,
    agent-prose-free packet the queue shows the human — so the digest
    attached here binds what the approver actually saw. Whitespace
    discipline follows ``sanitize_preview_text`` (no trimming, no
    collapsing: what executes is what was displayed, byte for byte).
    """
    packet = canonical_packet(record)
    lines = [
        "APPROVAL %s" % (record.get("id") or ""),
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
        % ((packet.get("policy") or {}).get("policy_id") or "",
           (packet.get("policy") or {}).get("policy_version") or "",
           ",".join((packet.get("policy") or {}).get("matched_rules")
                    or []) or "none"),
        "agent: %s role=%s" % ((packet.get("agent") or {}).get("agent_id")
                               or "",
                               (packet.get("agent") or {}).get("role")
                               or ""),
    ]
    text = "\n".join(lines) + "\n"
    return sanitize_preview_text(text)


def render_approval(record):
    """Render the approver-facing presentation WITH its digest.

    Returns ``{"text", "digest"}`` where ``digest`` is
    ``sha256:<hex>`` over the exact rendered text. Call this at view
    time and carry the presentation into the signing ceremony.
    """
    if not isinstance(record, dict):
        raise TypeError("record must be a dict")
    text = _render_text(record)
    return {"text": text, "digest": _pres.presentation_digest(text)}


def seal_approval(record, presentation, *, signer, parameter_digest=None):
    """Bind the signing ceremony to the artifact AND its presentation.

    Returns the sealed envelope ``{approval_id, artifact_digest,
    presentation_digest, presentation_text, signer, at}``. The seal
    refuses a render tampered before sealing — but sealing does NOT
    compare the presentation against the record: swapped displays
    (show A, seal B) are refused by ``verify_seal`` against the LIVE
    record, which is where the signature step runs. ``signer`` is the
    principal whose signature this ceremony records.

    ``parameter_digest`` (optional) stamps the request's parameter
    digest into the seal, making the seal itself mission-bound:
    ``verify_seal`` refuses the signature when the authorization path
    presents a different digest.
    """
    if not isinstance(record, dict):
        raise TypeError("record must be a dict")
    if not isinstance(signer, str) or not signer:
        raise ValueError("signer must be a non-empty string")
    if parameter_digest is not None and (
            not isinstance(parameter_digest, str) or not parameter_digest):
        raise ValueError("parameter_digest must be a non-empty string")
    _pres.check_presentation_integrity(presentation)
    sealed = {
        "approval_id": record.get("id"),
        "artifact_digest": _pres.artifact_digest(record),
        "presentation_digest": presentation["digest"],
        "presentation_text": presentation["text"],
        "signer": signer,
        "at": _pres.utcnow_iso(),
    }
    if parameter_digest is not None:
        sealed["parameter_digest"] = parameter_digest
    return sealed


def verify_seal(record, sealed, *, parameter_digest=None):
    """The approval-pipeline gate: refuse a signature over a mismatched
    display.

    Fail-closed refuses (all named):
    * ``presentation-missing`` — sealed is None/malformed;
    * ``display-hash-mismatch`` — the presentation text was tampered
      between view and sign; the artifact digest no longer matches the
      current record (swapped display); or the record drifted since
      the presentation was rendered (stale display);
    * ``mission-binding-mismatch`` — when the authorization path
      supplies the request's ``parameter_digest``, a seal binding a
      different digest (or none) is refused: the approval cannot be
      retargeted onto different parameters.

    Returns True when the presentation faithfully renders the artifact
    the approver is signing.
    """
    if not isinstance(sealed, dict):
        raise _pres.PresentationMissingError(
            "presentation-missing: no sealed presentation offered")
    for field in ("presentation_text", "presentation_digest",
                  "artifact_digest"):
        if not isinstance(sealed.get(field), str):
            raise _pres.PresentationMissingError(
                "presentation-missing: sealed presentation lacks %r"
                % (field,))
    # (1) The presentation text must still digest to its attached
    # digest: a render tampered between view and sign fails here.
    _pres.check_presentation_integrity(
        {"text": sealed["presentation_text"],
         "digest": sealed["presentation_digest"]})
    # (2) The signed artifact must be the CURRENT artifact: a swapped
    # display (show A, sign B) fails here.
    current_artifact = _pres.artifact_digest(record)
    if not hmac.compare_digest(sealed["artifact_digest"],
                               current_artifact):
        raise _pres.DisplayHashMismatchError(
            "display-hash-mismatch: the signed artifact digest does "
            "not match the current record — the approver was shown a "
            "different artifact than the one being signed")
    # (3) The presentation must be fresh for the current record: a
    # record drifted after rendering (stale display) fails here. This
    # re-derives the exact view-time render and compares digests.
    fresh = render_approval(record)
    if not hmac.compare_digest(sealed["presentation_digest"],
                               fresh["digest"]):
        raise _pres.DisplayHashMismatchError(
            "display-hash-mismatch: the record changed after the "
            "presentation was rendered — the approver saw a stale "
            "display")
    # (4) Mission binding: when the authorization path supplies the
    # request's parameter_digest, the seal must bind exactly it.
    if parameter_digest is not None:
        _pres.verify_mission_binding(sealed, parameter_digest)
    return True


def guarded_decide(queue, approval_id, approved, reason, *, sealed=None,
                   parameter_digest=None, **kw):
    """Opt-in approval-pipeline wrapper with presentation faithfulness.

    With ``sealed=None`` the call passes straight through to
    ``queue.decide(approval_id, approved, reason, **kw)`` —
    byte-identical to the legacy path (the queue is never touched).
    With a sealed presentation, the seal is verified against the live
    record fetched from the queue BEFORE the decision is recorded;
    any mismatch refuses fail-closed and the decision is never made.
    ``parameter_digest`` passes the request's parameter digest through
    to ``verify_seal`` so the signature is mission-bound.
    """
    if sealed is None:
        return queue.decide(approval_id, approved, reason, **kw)
    record = queue.get(approval_id)
    verify_seal(record, sealed, parameter_digest=parameter_digest)
    return queue.decide(approval_id, approved, reason, **kw)


__all__ = [
    "render_approval",
    "seal_approval",
    "verify_seal",
    "guarded_decide",
]
