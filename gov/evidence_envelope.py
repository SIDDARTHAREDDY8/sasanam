"""Per-record DSSE envelope for the offline evidence bundle.

PATTERN LINEAGE: secure-systems-lab/dsse (Apache-2.0) -- the envelope
shape ``{payload, payloadType, signatures}`` with PAE
(Pre-Authentication Encoding). Re-implemented in stdlib Python via
:mod:`gov.dsse_envelope`; no DSSE code is vendored here, only the
pattern. This module is the *evidence-bundle integration layer*: each
audit record becomes one DSSE envelope whose ``payloadType`` names the
record schema, so a signature cannot be transplanted onto a different
record kind.

Why a second module on top of ``gov/dsse_envelope``: the base module
is the generic envelope mechanic (any payloadType, any caller). This
module fixes the evidence-bundle policy:

* exactly one signature per record envelope (blamejs pin a -- a
  two-signature envelope whose second signature is forged refuses
  ``dsse-envelope-multi-signature``; the base module's default
  exactly-one discipline is *not* relaxed here);
* payloadType is fixed to the evidence namespace
  (``application/vnd.sasanam.audit-entry+json`` for records,
  ``application/vnd.sasanam.bundle-manifest+json`` for manifests);
  anything else refuses before crypto;
* verification work is bounded (blamejs pin b): ``open_records``
  refuses ``evidence-envelope-record-limit`` when the envelope count
  exceeds :data:`MAX_RECORDS_PER_BUNDLE` *before* any signature is
  verified, so verification work never scales with attacker-chosen
  entry counts (work-multiplier DoS);
* a single record's canonical bytes are bounded by
  :data:`MAX_RECORD_BYTES` (``evidence-envelope-record-too-large``).

Envelope JSON (via :mod:`gov.dsse_envelope`)::

    {"payload": "<base64>",
     "payloadType": "application/vnd.sasanam.audit-entry+json",
     "signatures": [{"keyid": "<key id>", "sig": "<hex ed25519>"}],
     "signing_input_digest": "<sha256 hex of the PAE bytes>"}

The signature covers the PAE bytes
``DSSEv1 SP LEN(type) SP type SP LEN(body) SP body``, binding the
payload TYPE into the signed bytes -- envelope shape bugs are killed
by construction.

Integration: the envelope wraps the same record dicts that
:mod:`gov.offline_bundle` exports (canonical JSON, sorted keys). It
does not replace the offline bundle format; it is the per-record
signing envelope a deployment uses when it needs DSSE-typed,
transplant-proof record signatures.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import base64
import json

from . import dsse_envelope as _dsse
from . import ed25519 as _ed

# ---------------------------------------------------------------------------
# Policy constants.
# ---------------------------------------------------------------------------

#: payloadType naming the audit-record schema.
PAYLOAD_TYPE_AUDIT_ENTRY = (
    "application/vnd.sasanam.audit-entry+json")
#: payloadType naming the bundle-manifest schema.
PAYLOAD_TYPE_BUNDLE_MANIFEST = (
    "application/vnd.sasanam.bundle-manifest+json")

_EVIDENCE_TYPES = frozenset(
    (PAYLOAD_TYPE_AUDIT_ENTRY, PAYLOAD_TYPE_BUNDLE_MANIFEST))

#: Blamejs pin (b): maximum record envelopes verified in one
#: ``open_records`` call. Exceeding this refuses
#: ``evidence-envelope-record-limit`` BEFORE any signature
#: verification runs, so verification work never scales with an
#: attacker-chosen entry count.
MAX_RECORDS_PER_BUNDLE = 10000

#: Maximum canonical bytes of a single sealed record.
MAX_RECORD_BYTES = 1024 * 1024

_DOMAIN = "evidence"


def _register():
    for ptype in _EVIDENCE_TYPES:
        _dsse.register_envelope_domain(_DOMAIN, ptype)


_register()


# ---------------------------------------------------------------------------
# Errors.
# ---------------------------------------------------------------------------

class EvidenceEnvelopeError(Exception):
    """Fail-closed envelope refusal carrying a taxonomy ``code``."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def _refuse(code, detail):
    raise EvidenceEnvelopeError("%s: %s" % (code, detail), code)


# ---------------------------------------------------------------------------
# Canonical record bytes.
# ---------------------------------------------------------------------------

def _canonical_record(record):
    """JCS-shaped canonical bytes for a record dict."""
    if not isinstance(record, dict):
        _refuse("dsse-envelope-malformed",
                "record must be a dict, got %s" % type(record).__name__)
    try:
        raw = json.dumps(record, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, default=str).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _refuse("dsse-envelope-malformed",
                "record is not JSON-serializable: %s" % (exc,))
    if len(raw) > MAX_RECORD_BYTES:
        _refuse("evidence-envelope-record-too-large",
                "record canonical bytes %d exceed cap %d"
                % (len(raw), MAX_RECORD_BYTES))
    return raw


# ---------------------------------------------------------------------------
# Seal / open one record.
# ---------------------------------------------------------------------------

def seal_record(record, seed, *, key_id=None):
    """Wrap ``record`` in a single-signature DSSE envelope.

    ``seed``: 32-byte Ed25519 seed. Returns the envelope dict.
    Refuses ``evidence-envelope-record-too-large`` when the record's
    canonical bytes exceed :data:`MAX_RECORD_BYTES`.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        _refuse("dsse-envelope-malformed",
                "seed must be 32 bytes")
    payload = _canonical_record(record)

    def _sign(pae_bytes):
        return _ed.sign(bytes(seed), pae_bytes)

    try:
        return _dsse.envelope(payload, payload_type=PAYLOAD_TYPE_AUDIT_ENTRY,
                              sign=_sign, key_id=key_id)
    except _dsse.EnvelopeError as exc:
        _refuse(exc.reason, str(exc))


def open_record(envelope, pub, *, expected_seq=None):
    """Verify a record envelope and return the record dict.

    Exactly one signature is required (blamejs pin a): a
    two-signature envelope -- even with a valid first signature --
    refuses ``dsse-envelope-multi-signature``. The payloadType must be
    the audit-entry type; anything else refuses before crypto.
    ``expected_seq`` optionally pins the record's ``seq`` field.
    """
    opened = _verify(envelope, pub, PAYLOAD_TYPE_AUDIT_ENTRY)
    try:
        record = json.loads(opened["payload"].decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        _refuse("dsse-envelope-malformed",
                "payload is not JSON: %s" % (exc,))
    if not isinstance(record, dict):
        _refuse("dsse-envelope-malformed",
                "payload is not a JSON object")
    if expected_seq is not None and record.get("seq") != expected_seq:
        _refuse("dsse-envelope-malformed",
                "record seq %r != expected %r"
                % (record.get("seq"), expected_seq))
    return record


def _verify(envelope, pub, expected_type):
    """Shared verify path: shape, type, count, then crypto."""
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        _refuse("dsse-envelope-malformed",
                "pub must be 32 bytes")
    pub = bytes(pub)

    def _verify_sig(pae_bytes, sig_bytes):
        # gov.ed25519.verify returns True/False, never raises.
        return _ed.verify(pub, pae_bytes, sig_bytes) is True

    try:
        return _dsse.verify_envelope(
            envelope, verify=_verify_sig,
            expect_payload_type=expected_type,
            expected_domain=_DOMAIN)
    except _dsse.EnvelopeError as exc:
        _refuse(exc.reason, str(exc))


# ---------------------------------------------------------------------------
# Seal / open one manifest.
# ---------------------------------------------------------------------------

def seal_manifest(manifest, seed, *, key_id=None):
    """Wrap a bundle manifest dict in a DSSE envelope."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        _refuse("dsse-envelope-malformed",
                "seed must be 32 bytes")
    payload = _canonical_record(manifest)

    def _sign(pae_bytes):
        return _ed.sign(bytes(seed), pae_bytes)

    try:
        return _dsse.envelope(payload,
                              payload_type=PAYLOAD_TYPE_BUNDLE_MANIFEST,
                              sign=_sign, key_id=key_id)
    except _dsse.EnvelopeError as exc:
        _refuse(exc.reason, str(exc))


def open_manifest(envelope, pub):
    """Verify a manifest envelope and return the manifest dict."""
    opened = _verify(envelope, pub, PAYLOAD_TYPE_BUNDLE_MANIFEST)
    try:
        manifest = json.loads(opened["payload"].decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        _refuse("dsse-envelope-malformed",
                "payload is not JSON: %s" % (exc,))
    if not isinstance(manifest, dict):
        _refuse("dsse-envelope-malformed",
                "payload is not a JSON object")
    return manifest


# ---------------------------------------------------------------------------
# Seal / open a bundle of records.
# ---------------------------------------------------------------------------

def seal_records(records, seed, *, key_id=None):
    """Seal each record in ``records``; returns the envelope list.

    Refuses ``evidence-envelope-record-limit`` when the record count
    exceeds :data:`MAX_RECORDS_PER_BUNDLE` (fail-closed at seal time:
    a bundle that could never be opened is never produced).
    """
    records = list(records)
    if len(records) > MAX_RECORDS_PER_BUNDLE:
        _refuse("evidence-envelope-record-limit",
                "%d records exceed cap %d"
                % (len(records), MAX_RECORDS_PER_BUNDLE))
    return [seal_record(r, seed, key_id=key_id) for r in records]


def open_records(envelopes, pub):
    """Verify every record envelope; returns the record list.

    Blamejs pin (b): the envelope count is checked FIRST --
    ``evidence-envelope-record-limit`` refuses before ANY signature
    verification runs, so verification work never scales with an
    attacker-chosen entry count.
    """
    envelopes = list(envelopes)
    if len(envelopes) > MAX_RECORDS_PER_BUNDLE:
        _refuse("evidence-envelope-record-limit",
                "%d envelopes exceed cap %d: refusing before any "
                "signature verification"
                % (len(envelopes), MAX_RECORDS_PER_BUNDLE))
    return [open_record(e, pub) for e in envelopes]


__all__ = [
    "PAYLOAD_TYPE_AUDIT_ENTRY",
    "PAYLOAD_TYPE_BUNDLE_MANIFEST",
    "MAX_RECORDS_PER_BUNDLE",
    "MAX_RECORD_BYTES",
    "EvidenceEnvelopeError",
    "seal_record",
    "open_record",
    "seal_manifest",
    "open_manifest",
    "seal_records",
    "open_records",
]
