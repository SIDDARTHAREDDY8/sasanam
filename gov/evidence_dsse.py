"""DSSE export envelope for the offline evidence bundle (wave-309 lane E).

Additive export path implementing build-order step 1 of the evidence-envelope
prospectus (``research/prospecting/w308_evidence_envelopes.md``): wrap the
EXISTING offline evidence bundle bytes in a DSSE envelope (protocol v1.0.2,
implemented from the algorithm — not spec prose — per the Community
Specification License 1.0) so third-party verifiers (cosign,
``gh attestation verify``) can consume evidence without the engine.

The bundle format (``gov/evidence_bundle.py``), its standalone verifier, and
all governance verdict paths are untouched: this module only *wraps opaque
bytes* the caller supplies. Step 2 of the build order (re-enveloping as an
in-toto Statement) and Sigstore-bundle distribution are later work, not here.

Wire format (DSSE v1.0.2)::

    SIGNATURE = Sign(PAE(UTF8(PAYLOAD_TYPE), SERIALIZED_BODY))
    PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body

with ``PAYLOAD_TYPE = "application/vnd.in-toto+json"``. The type is inside
the signed bytes, so a signature cannot be transplanted onto a different
payload type; the raw serialized bytes are signed (no canonicalization).

Same-bytes discipline (the critical verifier rule): :func:`verify_dsse_envelope`
parses the envelope exactly ONCE, verifies the threshold signatures over the
exact parsed payload bytes, binds those bytes against the caller's expected
bundle bytes, and returns THE PARSED BYTES — never re-parses, never
re-serializes, never substitutes the caller's expected bytes. There is no
other payload-extraction path in this module: the only way bytes come out of
an envelope here is through the verifying function.

``keyid`` is an unauthenticated hint: it narrows which verifier to try, never
decides. A signature entry whose keyid matches no trusted verifier falls back
to try-all (stripping the keyid is already accepted by the base machinery, so
the fallback grants an attacker nothing new; it only avoids spurious refusals
from misconfigured keyids). Authentication is never weakened: an untrusted
key verifies against nothing.

Key custody: :func:`signer_from_anchor_key` reuses the operator anchor-key
seam (``gov/anchorer.py::resolve_anchor_key`` — ``GOV_ANCHOR_KEY`` /
``GOV_ANCHOR_KEY_FILE``), the same operator identity that signs the evidence
bundle itself. Unconfigured raises ``NoAnchorKeyError``: the DSSE export stays
disabled, never silently unsigned.

Stdlib only. $0 spend. Synthetic/local testing.
"""

from __future__ import annotations

from gov import dsse_envelope as _dsse
from gov import anchorer as _anchorer
from gov.signing import Ed25519Signer, Verifier

__all__ = [
    "EVIDENCE_DSSE_PAYLOAD_TYPE",
    "seal_evidence_bundle",
    "signer_from_anchor_key",
    "verify_dsse_envelope",
]

#: DSSE payloadType for the evidence export. The in-toto statement media
#: type: step 2 of the build order re-envelopes the bundle as an in-toto
#: Statement, and binding the type NOW (inside the PAE signature) means a
#: signature minted today cannot be transplanted onto a differently-typed
#: payload later.
EVIDENCE_DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def seal_evidence_bundle(bundle_bytes, signers):
    """Seal ``bundle_bytes`` into a DSSE envelope.

    ``bundle_bytes`` is opaque (the caller supplies the serialized evidence
    bundle); ``signers`` is a non-empty list of ``gov.signing.Signer``. Each
    signer signs ``pae(EVIDENCE_DSSE_PAYLOAD_TYPE, bundle_bytes)`` — (t, n)
    threshold is policy at verify time, so ``n`` is just ``len(signers)``.

    Returns the envelope dict ``{payload, payloadType, signatures}``.
    Raises :class:`dsse_envelope.EnvelopeError` on bad inputs.
    """
    if not isinstance(bundle_bytes, (bytes, bytearray)) or not bundle_bytes:
        raise _dsse.EnvelopeError(
            "seal_evidence_bundle requires non-empty bundle bytes")
    return _dsse.seal(bytes(bundle_bytes), EVIDENCE_DSSE_PAYLOAD_TYPE,
                      signers)


def signer_from_anchor_key(explicit=None):
    """Build an ``Ed25519Signer`` from the operator anchor-key seam.

    Precedence: explicit hex seed > ``GOV_ANCHOR_KEY`` > ``GOV_ANCHOR_KEY_FILE``
    (see :func:`gov.anchorer.resolve_anchor_key`). Nothing configured raises
    ``NoAnchorKeyError`` — fail-closed, never silently unsigned.

    The envelope ``keyid`` is the signer's ``key_id``
    (``sha256(pub)[:16]``, the ``gov.signing`` convention).
    """
    key = _anchorer.resolve_anchor_key(explicit)
    return Ed25519Signer(key["seed"])


def verify_dsse_envelope(envelope, expected_bundle_bytes, verifiers,
                         threshold=1):
    """Verify a DSSE evidence envelope and return the verified bundle bytes.

    Checks, in order: strict single parse of the envelope; payloadType
    binding against ``EVIDENCE_DSSE_PAYLOAD_TYPE``; ``threshold``
    distinct-key signatures over ``pae(payloadType, payload)`` where the
    payload is the EXACT parsed bytes; payload-bytes binding against
    ``expected_bundle_bytes``.

    Returns the parsed payload bytes — the identical buffer the signatures
    were verified over. Raises :class:`dsse_envelope.EnvelopeError` loudly
    on any violation; no payload bytes escape an unverified envelope.
    """
    verifiers = list(verifiers)
    if not verifiers:
        raise _dsse.EnvelopeError(
            "verify_dsse_envelope requires at least one verifier")
    if (isinstance(threshold, bool) or not isinstance(threshold, int)
            or threshold < 1):
        raise _dsse.EnvelopeError("threshold must be a positive int")
    if (not isinstance(expected_bundle_bytes, (bytes, bytearray))
            or not expected_bundle_bytes):
        raise _dsse.EnvelopeError(
            "expected_bundle_bytes must be non-empty bytes")

    # THE single parse. Everything below operates on these exact objects;
    # nothing here re-parses, re-serializes, or re-derives the payload.
    payload, got_type, sig_entries = _dsse.parse_envelope(envelope)
    if got_type != EVIDENCE_DSSE_PAYLOAD_TYPE:
        raise _dsse.EnvelopeError(
            "payloadType mismatch: envelope carries %r, expected %r"
            % (got_type, EVIDENCE_DSSE_PAYLOAD_TYPE))
    if not payload:
        raise _dsse.EnvelopeError("empty payload refused")

    # keyid is a hint, never an authority: entries naming an unknown key
    # fall back to try-all (see module docstring for why this is safe).
    known_ids = {v.key_id for v in verifiers if isinstance(v, Verifier)}
    entries = [(kid if (kid is None or kid in known_ids) else None, sig)
               for kid, sig in sig_entries]
    _dsse.verify_threshold(payload, got_type, entries, verifiers, threshold)

    # Authentication precedes binding: a tampered payload is refused on
    # the signature path above; this only binds the verified bytes to
    # what the caller expected.
    if payload != bytes(expected_bundle_bytes):
        raise _dsse.EnvelopeError(
            "payload binding mismatch: envelope payload does not equal "
            "the expected bundle bytes")
    return payload
