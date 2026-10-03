"""in-toto Statement v1 re-enveloping for the offline evidence bundle (wave-310 lane E).

Additive export path implementing build-order step 2 of the evidence-envelope
prospectus (``research/prospecting/w308_evidence_envelopes.md``): wrap the
EXISTING offline evidence bundle in an in-toto Statement v1, then seal the
canonical statement bytes with the wave-309 DSSE module
(``gov/evidence_dsse.py`` — ``payloadType`` ``application/vnd.in-toto+json``
is already bound inside the PAE signature, so a signature minted over a
statement cannot be transplanted onto a differently-typed payload).

The statement shape (four fields)::

    {
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [{"name": "evidence-bundle",
                   "digest": {"sha256": "<hex of the bundle bytes>"}}],
      "predicateType": "https://sasanam.dev/predicate/evidence-bundle/v1",
      "predicate": { ... the bundle's own claims, passed through ... }
    }

Semantics this module pins:

- **Subjects are digest-matched.** ``subject[0].digest.sha256`` is the
  sha256 of the EXACT bundle bytes handed to :func:`build_statement` —
  capture-time, never recomputed at export. A verifier matches the
  subject purely by digest; no filename or content-type trust.
- **The predicateType namespace is ours to mint.** Custom predicate
  types are the sanctioned extension mechanism; standard verifiers
  check envelope + signature without knowing our schema, while OUR
  verifier additionally checks the predicate (type URI and shape).
- **The predicate passes through untouched.** This lane does not
  redesign the bundle; it re-envelopes it. The caller supplies the
  bundle's claims object.
- **Same-bytes discipline (inherited from the DSSE layer):**
  :func:`open_statement` parses the envelope exactly ONCE, verifies the
  threshold signatures over the exact parsed payload bytes, parses the
  statement from those verified bytes (payload parsing, not envelope
  re-parsing), and only then binds the statement's subject digest
  against the caller's expected bundle bytes. Authentication precedes
  binding: no statement content is trusted before the signature
  verifies, and the returned statement is the envelope's own bytes,
  never the caller's expected bytes re-serialized.
- **``keyid`` is an unauthenticated hint** (inherited): it narrows
  which verifier to try, never decides. Unknown keyids fall back to
  try-all; an untrusted key verifies against nothing.

Key custody and threshold policy are inherited from
:mod:`gov.evidence_dsse` unchanged. The bundle format
(``gov/evidence_bundle.py``), its standalone verifier, and all
governance verdict paths are untouched: this module only wraps bytes
the caller supplies. Sigstore-bundle distribution is build-order step
3, not here.

Stdlib only. $0 spend. Synthetic/local testing.
"""

from __future__ import annotations

import hashlib
import json

from gov import dsse_envelope as _dsse
from gov import evidence_dsse as _edsse
from gov.signing import Verifier

__all__ = [
    "INTOTO_STATEMENT_TYPE",
    "SASANAM_EVIDENCE_PREDICATE_TYPE",
    "STATEMENT_SUBJECT_NAME",
    "build_statement",
    "statement_bytes",
    "seal_statement",
    "open_statement",
]

#: The fixed in-toto Statement v1 type URI.
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

#: Our predicateType namespace for evidence-bundle claims. Custom
#: predicate types are the sanctioned extension mechanism; standard
#: verifiers ignore the predicate while checking envelope + signature.
SASANAM_EVIDENCE_PREDICATE_TYPE = (
    "https://sasanam.dev/predicate/evidence-bundle/v1")

#: Subject name for the single subject entry our builder emits.
STATEMENT_SUBJECT_NAME = "evidence-bundle"


def _check_bundle_bytes(bundle_bytes, where="bundle_bytes"):
    if not isinstance(bundle_bytes, (bytes, bytearray)) \
            or not bundle_bytes:
        raise _dsse.EnvelopeError(
            "%s must be non-empty bytes" % where)
    return bytes(bundle_bytes)


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdefABCDEF" for c in value))


def build_statement(bundle_bytes, predicate_claims):
    """Build the in-toto Statement v1 dict for ``bundle_bytes``.

    ``bundle_bytes`` is opaque (the caller supplies the serialized
    evidence bundle); the subject digest commits to those exact bytes.
    ``predicate_claims`` is the bundle's own claims object, passed
    through by reference — this lane re-envelopes the bundle, it does
    not redesign it.

    Returns the statement dict (not yet sealed; see
    :func:`seal_statement`).
    """
    bundle_bytes = _check_bundle_bytes(bundle_bytes)
    if not isinstance(predicate_claims, dict):
        raise _dsse.EnvelopeError("predicate_claims must be a dict")
    return {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [{
            "name": STATEMENT_SUBJECT_NAME,
            "digest": {"sha256": hashlib.sha256(bundle_bytes).hexdigest()},
        }],
        "predicateType": SASANAM_EVIDENCE_PREDICATE_TYPE,
        "predicate": predicate_claims,
    }


def statement_bytes(statement):
    """Canonical serialization of a statement dict.

    ``sort_keys`` + no-whitespace separators + ASCII, the same canonical
    form as ``gov/evidence_bundle.py::canonical``: deterministic bytes
    for signing, so every signer and verifier agrees on the payload.
    """
    if not isinstance(statement, dict):
        raise _dsse.EnvelopeError("statement must be a dict")
    try:
        return json.dumps(statement, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"), default=str).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _dsse.EnvelopeError(
            "statement is not JSON-serializable: %s" % exc)


def _check_statement_shape(statement):
    """Fail-fast shape check for a parsed statement dict. Raises loudly."""
    if not isinstance(statement, dict):
        raise _dsse.EnvelopeError("statement must be a JSON object")
    if statement.get("_type") != INTOTO_STATEMENT_TYPE:
        raise _dsse.EnvelopeError(
            "unsupported statement _type: %r" % (statement.get("_type"),))
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise _dsse.EnvelopeError(
            "statement subject must be a non-empty list")
    first = subjects[0]
    digest = first.get("digest") if isinstance(first, dict) else None
    if not isinstance(digest, dict) or not _is_hex64(digest.get("sha256")):
        raise _dsse.EnvelopeError(
            "subject[0].digest.sha256 must be a hex sha256 digest")
    if statement.get("predicateType") != SASANAM_EVIDENCE_PREDICATE_TYPE:
        raise _dsse.EnvelopeError(
            "unsupported predicateType: %r"
            % (statement.get("predicateType"),))
    if not isinstance(statement.get("predicate"), dict):
        raise _dsse.EnvelopeError("statement predicate must be an object")


def seal_statement(statement, signers):
    """Seal a statement dict (from :func:`build_statement`) into a DSSE envelope.

    The statement shape is validated BEFORE signing: a malformed
    statement is never signed. Each signer signs
    ``pae("application/vnd.in-toto+json", statement_bytes(statement))``
    via :func:`gov.evidence_dsse.seal_evidence_bundle` — (t, n)
    threshold is policy at verify time.

    Returns the envelope dict ``{payload, payloadType, signatures}``.
    """
    _check_statement_shape(statement)
    return _edsse.seal_evidence_bundle(statement_bytes(statement), signers)


def _coerce_envelope(envelope):
    # The wire journey is bytes; accept both, but parse exactly once.
    if isinstance(envelope, (bytes, bytearray)):
        try:
            envelope = json.loads(bytes(envelope).decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise _dsse.EnvelopeError(
                "envelope bytes are not valid JSON: %s" % exc)
    return envelope


def open_statement(envelope, expected_bundle_bytes, verifiers, threshold=1):
    """Verify a sealed in-toto evidence statement; return the parsed statement.

    Checks, in order: strict single parse of the envelope (dict or JSON
    bytes); ``payloadType`` binding against
    ``application/vnd.in-toto+json``; ``threshold`` distinct-key
    signatures over the PAE of the EXACT parsed payload bytes
    (``keyid`` treated as a hint, never an authority); the payload
    parses as a well-shaped in-toto Statement under OUR predicateType;
    the statement's ``subject[0]`` digest binds against
    ``expected_bundle_bytes``.

    Returns the parsed statement dict — the envelope's own verified
    bytes, never the caller's expected bytes re-serialized. Raises
    :class:`dsse_envelope.EnvelopeError` loudly on any violation; no
    statement content escapes an unverified envelope.
    """
    verifiers = list(verifiers)
    if not verifiers:
        raise _dsse.EnvelopeError(
            "open_statement requires at least one verifier")
    if (isinstance(threshold, bool) or not isinstance(threshold, int)
            or threshold < 1):
        raise _dsse.EnvelopeError("threshold must be a positive int")
    expected_bundle_bytes = _check_bundle_bytes(expected_bundle_bytes,
                                                "expected_bundle_bytes")

    # THE single envelope parse. Everything below operates on these
    # exact objects; nothing here re-parses the envelope.
    payload, got_type, sig_entries = _dsse.parse_envelope(
        _coerce_envelope(envelope))
    if got_type != _edsse.EVIDENCE_DSSE_PAYLOAD_TYPE:
        raise _dsse.EnvelopeError(
            "payloadType mismatch: envelope carries %r, expected %r"
            % (got_type, _edsse.EVIDENCE_DSSE_PAYLOAD_TYPE))
    if not payload:
        raise _dsse.EnvelopeError("empty payload refused")

    # keyid is a hint, never an authority (same discipline as
    # verify_dsse_envelope): entries naming an unknown key fall back to
    # try-all.
    known_ids = {v.key_id for v in verifiers if isinstance(v, Verifier)}
    entries = [(kid if (kid is None or kid in known_ids) else None, sig)
               for kid, sig in sig_entries]
    _dsse.verify_threshold(payload, got_type, entries, verifiers, threshold)

    # Parse the statement from the VERIFIED payload bytes. This is
    # payload parsing, not envelope re-parsing: the signature above was
    # checked over exactly these bytes.
    try:
        statement = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise _dsse.EnvelopeError(
            "statement payload is not valid JSON: %s" % exc)
    _check_statement_shape(statement)

    # Authentication precedes binding: the signature was verified over
    # the exact payload bytes above; this only binds the statement's
    # subject digest to the bundle the caller expected.
    got_digest = statement["subject"][0]["digest"]["sha256"]
    want_digest = hashlib.sha256(expected_bundle_bytes).hexdigest()
    if got_digest.lower() != want_digest.lower():
        raise _dsse.EnvelopeError(
            "subject digest mismatch: statement attests a different "
            "bundle than expected")
    return statement
