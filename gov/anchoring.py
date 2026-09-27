"""Pluggable external anchoring for the K-060 export path.

K-060 residual: the export bundle (``gov.log.export_bundle``) proves
authenticity of INCLUDED entries, not completeness against a key-holding
exporter; and without a pinned external anchor, verification proves
self-consistency only. This module is the pluggable seam that lets an
operator bind an export to an external commitment WITHOUT hard-coding
local-only anchoring into the product.

Deliberate non-duplication note (read before "simplifying"): this module
does NOT define a second anchor interface. ``gov.anchor_backend`` already
ships the break-tested interface (``AnchorBackend.submit`` /
``verify_receipt``, ``LocalAnchorLog``, ``FakeWitness``, ``RekorBackend``).
This module re-exports it and adds ONLY the export-path wiring:

* :func:`bundle_head_digest` -- the canonical commitment: a
  domain-separated SHA-256 over the bundle's signed checkpoints.
* :func:`anchor_bundle` -- submit that digest to any ``AnchorBackend``.
* :func:`verify_bundle_anchor` -- re-derive the digest and verify the
  receipt; never raises on malformed input (fail-closed for auditors).

A note on ``gov.anchor_adapter`` (H24), the other anchor-adjacent seam:
it anchors whole ``gov.evidence_bundle`` dicts via an Ed25519-signed
bundle statement (``AnchorAdapter.anchor(bundle) -> receipt``), keyed to
the evidence-bundle path. This module serves the K-060 ``gov.log``
export path, whose natural commitment is a *hash of the signed
checkpoints* -- exactly ``AnchorBackend.submit(anchor_hash)``'s shape.
Using ``AnchorAdapter`` here would have meant dragging evidence-bundle
statement machinery into the log exporter; using ``anchor_backend``
directly keeps the commitment at the hash layer both seams can share.
Standards review, wave-137.

What the anchor buys (and does not): anchoring commits the exporter to a
specific set of signed checkpoints at a point in time. With a REAL witness
(RFC3161 TSA, transparency log), a key-holder who later rewrites history
cannot produce a matching anchor for the forged checkpoints -- the
witness's Merkle tree / timestamp won't agree. It does NOT prove
filter-completeness: an exporter who omits entries BEFORE anchoring is
still invisible (H20 pins this adversarially). Scope honesty, always.

Bring-your-own backends (the extension point -- implement
``gov.anchor_backend.AnchorBackend``; no network code ships here):

1. RFC3161 TSA (e.g. freetsa.org). ``submit``: build a TimeStampReq with
   messageImprint = SHA-256(anchor_hash bytes), POST to the TSA,
   return receipt ``{"backend": "rfc3161-tsa", "tsa_url": ...,
   "anchor_hash": hex, "tst_token_der_b64": ..., "witness_time": ...}``.
   ``verify_receipt``: parse the CMS SignedData, check the messageImprint
   digest equals the anchor hash, verify the TSA signature against the
   operator-pinned TSA certificate chain. Trust: the TSA's key + clock.

2. Transparency log (Sigstore Rekor -- ``gov.anchor_backend.RekorBackend``
   already implements this shape over stdlib urllib; the field names
   below are its actual receipt fields). Receipt
   ``{"backend": "rekor-v1", "url": ..., "uuid": ...,
   "log_index": int, "log_id": ..., "anchor_hash": hex,
   "integrated_time": ..., "inclusion_proof": {"hashes": [...],
   "root_hash": ..., "tree_size": ..., "log_index": ...},
   "body": ..., "signed_entry_timestamp": ..., "set_verified": False,
   "submitted_at": ...}``. ``verify_receipt`` recomputes the RFC 6962
   root from the inclusion proof, checks the pinned log_id, and
   rejects future integrated_time. Trust: Sigstore's log key (pinned
   at import in ``gov.anchor_backend``; a rotation fails closed).
   Honest boundary (carried, not verified): the SET's ECDSA P-256
   signature is stored in the receipt but NOT cryptographically
   verified -- no ECDSA in this tree. The verified core is the
   inclusion proof + pinned log_id.

3. Calendar-hash via a public gist (weakest, $0, no new infra). The
   operator keeps a local calendar chain
   ``cal_n = sha256(b"gist-calendar/v1\\x00" | cal_{n-1} | anchor_hash)``
   and periodically publishes the head as a public gist. Receipt
   ``{"backend": "gist-calendar", "gist_id": ..., "gist_rev": ...,
   "anchor_hash": hex, "calendar_hash": hex, "witness_time": ...}``.
   ``verify_receipt`` recomputes the calendar link (out-of-band gist
   fetch at the pinned rev is the auditor's job). Trust: GitHub's
   serving integrity + the operator's publishing discipline -- this
   proves the operator PUBLISHED something at a time, not that the
   timestamp is cryptographically bound. Never present it as a TSA.

Honest ceilings (documented, not hidden):
* The ``LocalAnchorLog`` reference backend adds NO external trust: it is
  a second local hash chain in the same trust domain as the operator.
  (It is the documented reference backend, not an automatic default --
  ``export_bundle`` anchors nothing unless a backend is passed.) It
  raises the bar from one-file tampering to two-file tampering and it
  proves the anchor FORMAT and the verification PATH -- nothing more.
  Never present its receipts as third-party attestation.
* Live external anchoring remains unvalidated in this repo (RekorBackend
  exists but no live-anchor battery runs against the network; $0).
* A receipt verified without a pinned/independent anchor proves
  self-consistency only -- the pre-existing K-060 ceiling, restated.

$0, stdlib only, deterministic.
"""

import hashlib
import json

from .anchor_backend import (AnchorBackend, FakeWitness, LocalAnchorLog,
                             RekorBackend)

__all__ = [
    "AnchorBackend",
    "FakeWitness",
    "LocalAnchorLog",
    "RekorBackend",
    "BUNDLE_ANCHOR_DOMAIN",
    "bundle_head_digest",
    "anchor_bundle",
    "verify_bundle_anchor",
]

BUNDLE_ANCHOR_DOMAIN = b"gov-export-anchor/v1\x00"
# NOTE: this domain MUST differ from gov.anchor_adapter._STATEMENT_DOMAIN
# (b"gov-bundle-anchor/v1\x00"): domain separation exists so two different
# hash protocols never share a prefix. (Standards review, wave-137.)


def _canonical(obj):
    """Deterministic JSON bytes for hashing. Fail-closed on any value that
    is not JSON-native: ``default=str`` would silently stringify values
    whose ``str()`` is nondeterministic (e.g. a set), producing an
    unstable commitment instead of refusing."""
    def _strict(o):
        if isinstance(o, (dict, list, str, int, float, bool)) or o is None:
            return o
        raise TypeError("non-canonical value in anchor input: %r" % type(o))
    return json.dumps(_walk(obj, _strict), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _walk(o, conv):
    conv_o = conv(o)
    if isinstance(conv_o, dict):
        return {k: _walk(v, conv) for k, v in conv_o.items()}
    if isinstance(conv_o, (list, tuple)):
        return [_walk(v, conv) for v in conv_o]
    return conv_o


def bundle_head_digest(bundle):
    """Canonical commitment over a bundle's signed checkpoints.

    Returns the 64-char hex SHA-256 of
    ``BUNDLE_ANCHOR_DOMAIN + canonical_json(bundle["checkpoints"])``.
    The checkpoints are the signed heads the bundle's inclusion proofs
    verify against, so this digest binds exactly what the bundle
    proves. An export with no checkpoints (empty filter result)
    commits to the empty list -- the anchor still records that the
    exporter attested "no entries matched". Raises ValueError on a
    malformed bundle (fail-closed at export time, never a silent
    unanchored export when a backend was requested).
    """
    if not isinstance(bundle, dict):
        raise ValueError("bundle must be a dict")
    checkpoints = bundle.get("checkpoints")
    if not isinstance(checkpoints, list):
        raise ValueError("bundle has no checkpoints list")
    return hashlib.sha256(
        BUNDLE_ANCHOR_DOMAIN + _canonical(checkpoints)).hexdigest()


def anchor_bundle(bundle, backend):
    """Anchor a bundle's head digest via ``backend``; return the receipt.

    ``backend`` must be a ``gov.anchor_backend.AnchorBackend``.
    Raises ValueError on a malformed bundle, TypeError on a wrong-typed
    backend; backend submission failures propagate (the export must
    not silently drop a requested anchor).
    """
    if not isinstance(backend, AnchorBackend):
        raise TypeError("backend must be a gov.anchor_backend.AnchorBackend"
                        ", got %r" % type(backend))
    digest = bundle_head_digest(bundle)
    receipt = backend.submit(digest)
    if not isinstance(receipt, dict):
        raise ValueError("backend returned a non-dict receipt")
    return receipt


def verify_bundle_anchor(bundle, receipt, backend):
    """Verify ``receipt`` anchors ``bundle``'s head digest via ``backend``.

    Returns ``(ok, reason)``; never raises on malformed input
    (fail-closed for auditors, matching the AnchorBackend contract).
    """
    try:
        if not isinstance(backend, AnchorBackend):
            return False, "backend is not an AnchorBackend"
        if not isinstance(receipt, dict):
            return False, "receipt is not an object"
        digest = bundle_head_digest(bundle)
    except (ValueError, TypeError) as e:
        return False, "malformed bundle: %s" % (e,)
    # Belt-and-suspenders: the BYO contract asks backends to never raise,
    # but a third-party backend may; the auditor path must not propagate
    # it. A raising backend is an unverifiable anchor -- fail closed.
    try:
        return backend.verify_receipt(receipt, anchor_hash=digest)
    except Exception as e:
        return False, "backend verify raised: %s" % (e,)
