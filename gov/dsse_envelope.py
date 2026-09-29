"""DSSE (Dead Simple Signing Envelope) for Sasanam.

PATTERN LINEAGE: secure-systems-lab/dsse (Apache-2.0) -- the envelope
shape ``{payload, payloadType, signatures}`` with explicit parsing rules
and PAE (Pre-Authentication Encoding). Re-implemented in stdlib Python;
no DSSE code is vendored here, only the pattern. This envelope
SUPERSEDES the age/minisign trusted-comments sketch of
gov.signature_envelope_v2 for envelope FORMAT (wave-203 prospecting,
section 3, verdict STEAL): the payload *type* is inside the signed
bytes, so a signature cannot be transplanted onto a different payload
type -- envelope shape bugs are killed by construction. It also aligns
with Rekor v2, whose typed entries already only accept DSSE shapes.

Envelope JSON::

    {"payload": "<base64>",
     "payloadType": "application/vnd.sasanam.statement+json",
     "signatures": [{"keyid": "<key id>", "sig": "<hex ed25519>"}, ...]}

``payload``, ``payloadType``, ``signature`` and ``signature.sig`` are
REQUIRED; ``signature.keyid`` is OPTIONAL (per the DSSE spec). Unknown
top-level fields are refused fail-closed.

PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body,
signed with the project's Ed25519 ceremony (algorithm agility is by
design in DSSE; our ``gov.signing`` signers drop straight in).

Trusted-comments port (brief section 3): DSSE has no comments field.
The choice made here is to carry the trusted comments -- and the
provenance binding -- INSIDE the signed payload as a canonical-JSON
statement::

    {"payload_sha256": "<hex>",
     "provenance_digest": "<hex>" | null,
     "trusted_comments": ["..."]}

Trade-off, stated honestly: the DSSE payload is a *binding statement*,
not the raw artifact bytes -- the artifact is bound by digest (exactly
as in gov.signature_envelope_v2). An auditor hashes the artifact and
compares to ``payload_sha256`` rather than reading it from the envelope.
What this buys: ONE signature still covers key + payload + provenance +
comments (the wave-202 lane-B discipline, unchanged), while the PAE
additionally binds the payload TYPE into the signed bytes.

Migration: v2 (minisign-pattern) envelopes still verify -- ``open_any``
dispatches on envelope shape and delegates v2 envelopes to
gov.signature_envelope_v2. New envelopes are DSSE-shaped.

Quorum is policy, not format: DSSE carries the signatures; the caller
names the ``threshold`` of distinct keys that must verify. ``threshold``
defaults to 1.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import base64
import binascii
import hashlib
import json

from .signing import Verifier

__all__ = [
    "STATEMENT_PAYLOAD_TYPE",
    "EnvelopeError",
    "pae",
    "seal",
    "parse_envelope",
    "open_envelope",
    "seal_statement",
    "open_statement",
    "detect_envelope",
    "open_any",
]

STATEMENT_PAYLOAD_TYPE = "application/vnd.sasanam.statement+json"

_ENVELOPE_FIELDS = frozenset({"payload", "payloadType", "signatures"})
_SIGNATURE_FIELDS = frozenset({"keyid", "sig"})
_STATEMENT_FIELDS = frozenset({"payload_sha256", "provenance_digest",
                               "trusted_comments"})


class EnvelopeError(ValueError):
    """Raised loudly on any DSSE envelope parse/verify failure."""


def _check_hex_digest(value, where):
    if not isinstance(value, str):
        raise EnvelopeError("%s: digest must be str, got %s"
                            % (where, type(value).__name__))
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise EnvelopeError("%s: not a sha256 hex digest: %r"
                            % (where, value))
    return value


def _check_sig_hex(value, where):
    if not isinstance(value, str):
        raise EnvelopeError("%s: signature must be str, got %s"
                            % (where, type(value).__name__))
    if len(value) != 128 or any(c not in "0123456789abcdef" for c in value):
        raise EnvelopeError("%s: signature must be 128 lowercase hex chars"
                            % where)
    return value


def pae(payload_type, payload):
    """Pre-Authentication Encoding: b"DSSEv1" SP LEN(type) SP type SP
    LEN(body) SP body. Length-prefixing kills concatenation ambiguity;
    the type is inside the signed bytes, killing type-swap attacks."""
    if not isinstance(payload_type, str) or not payload_type:
        raise EnvelopeError("payload_type must be a non-empty str")
    if not isinstance(payload, (bytes, bytearray)):
        raise EnvelopeError("payload must be bytes")
    type_bytes = payload_type.encode("utf-8")
    body = bytes(payload)
    return (b"DSSEv1 " + str(len(type_bytes)).encode("ascii") + b" "
            + type_bytes + b" " + str(len(body)).encode("ascii") + b" "
            + body)


def _b64_decode(value, where):
    if not isinstance(value, str):
        raise EnvelopeError("%s: must be a base64 str, got %s"
                            % (where, type(value).__name__))
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise EnvelopeError("%s: invalid base64: %s" % (where, exc))


def seal(payload, payload_type, signers):
    """Seal ``payload`` bytes into a DSSE envelope, signed by each signer
    in ``signers`` over ``pae(payload_type, payload)``."""
    pae_bytes = pae(payload_type, payload)  # validates type + payload
    signers = list(signers)
    if not signers:
        raise EnvelopeError("seal requires at least one signer")
    sigs = []
    for signer in signers:
        sig = signer.sign(pae_bytes)
        sigs.append({"keyid": signer.key_id, "sig": bytes(sig).hex()})
    return {
        "payload": base64.b64encode(bytes(payload)).decode("ascii"),
        "payloadType": payload_type,
        "signatures": sigs,
    }


def parse_envelope(envelope):
    """Strict-parse a DSSE envelope.

    Returns ``(payload_bytes, payload_type, [(keyid_or_None, sig_bytes)])``.
    Refuses unknown fields, missing fields, bad base64, and malformed
    signature entries -- fail-closed, never defaulted.
    """
    if not isinstance(envelope, dict):
        raise EnvelopeError("envelope must be a dict")
    extra = set(envelope) - _ENVELOPE_FIELDS
    if extra:
        raise EnvelopeError("unknown envelope field(s) refused: %s"
                            % sorted(extra))
    missing = _ENVELOPE_FIELDS - set(envelope)
    if missing:
        raise EnvelopeError("envelope missing field(s): %s" % sorted(missing))
    payload_type = envelope["payloadType"]
    if not isinstance(payload_type, str) or not payload_type:
        raise EnvelopeError("payloadType must be a non-empty str")
    payload = _b64_decode(envelope["payload"], "payload")
    sig_entries = envelope["signatures"]
    if not isinstance(sig_entries, list) or not sig_entries:
        raise EnvelopeError("signatures must be a non-empty list")
    parsed = []
    for i, entry in enumerate(sig_entries):
        where = "signatures[%d]" % i
        if not isinstance(entry, dict):
            raise EnvelopeError("%s: must be a dict" % where)
        extra = set(entry) - _SIGNATURE_FIELDS
        if extra:
            raise EnvelopeError("%s: unknown field(s) refused: %s"
                                % (where, sorted(extra)))
        if "sig" not in entry:
            raise EnvelopeError("%s: missing required 'sig'" % where)
        sig = _check_sig_hex(entry["sig"], where + ".sig")
        keyid = entry.get("keyid")
        if keyid is not None and (not isinstance(keyid, str) or not keyid):
            raise EnvelopeError("%s: keyid must be a non-empty str when "
                                "present" % where)
        parsed.append((keyid, bytes.fromhex(sig)))
    return payload, payload_type, parsed


def _verifier_for(keyid, verifiers):
    if keyid is None:
        return None  # keyid-less: try every verifier at open time
    for verifier in verifiers:
        if verifier.key_id == keyid:
            return verifier
    return None


def open_envelope(envelope, expected_payload, payload_type, verifiers,
                  threshold=1, allowed_payload_types=None):
    """Open and verify a DSSE envelope. Raises loudly on any violation.

    Checks, in order: strict parse; payloadType binding against
    ``payload_type``; allowlist (when given); ``threshold`` distinct-key
    signatures over ``pae(payload_type, payload)``; payload-bytes binding
    against ``expected_payload``.

    The signature is checked BEFORE the payload binding: authentication
    precedes binding, so a tampered payload is refused on the signature
    path, not merely on the digest comparison.
    """
    verifiers = list(verifiers)
    if not verifiers:
        raise EnvelopeError("open_envelope requires at least one verifier")
    if not isinstance(threshold, int) or threshold < 1:
        raise EnvelopeError("threshold must be a positive int")
    if not isinstance(payload_type, str) or not payload_type:
        raise EnvelopeError("payload_type must be a non-empty str")
    if not isinstance(expected_payload, (bytes, bytearray)):
        raise EnvelopeError("expected_payload must be bytes")

    payload, got_type, sig_entries = parse_envelope(envelope)
    if got_type != payload_type:
        raise EnvelopeError("payloadType mismatch: envelope carries %r, "
                            "expected %r" % (got_type, payload_type))
    if allowed_payload_types is not None and \
            got_type not in allowed_payload_types:
        raise EnvelopeError("payloadType %r not in allowlist" % got_type)

    pae_bytes = pae(payload_type, payload)
    good_key_ids = set()
    for keyid, sig in sig_entries:
        if keyid is None:
            # keyid-less signature: try every verifier, attribute to the
            # one whose key actually verifies (fail-closed: unverifiable
            # against all verifiers contributes nothing).
            matches = [v for v in verifiers
                       if isinstance(v, Verifier) and v.verify(pae_bytes, sig)]
        else:
            verifier = _verifier_for(keyid, verifiers)
            if verifier is None or not isinstance(verifier, Verifier):
                continue
            matches = [verifier] if verifier.verify(pae_bytes, sig) else []
        for match in matches:
            good_key_ids.add(match.key_id)
    if len(good_key_ids) < threshold:
        raise EnvelopeError("signature threshold not met: %d of %d "
                            "distinct key(s) verified"
                            % (len(good_key_ids), threshold))
    if payload != bytes(expected_payload):
        raise EnvelopeError("payload binding mismatch: envelope payload "
                            "does not equal the expected payload bytes")
    return {
        "key_ids": sorted(good_key_ids),
        "payload_type": got_type,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }


def _statement_bytes(payload_digest, provenance_digest, comments):
    payload_digest = _check_hex_digest(payload_digest, "payload_digest")
    if provenance_digest is not None:
        provenance_digest = _check_hex_digest(provenance_digest,
                                              "provenance_digest")
    comments = list(comments)
    if not comments or not all(isinstance(c, str) and c for c in comments):
        raise EnvelopeError("trusted_comments must be a non-empty list of "
                            "non-empty strings")
    return json.dumps({"payload_sha256": payload_digest,
                       "provenance_digest": provenance_digest,
                       "trusted_comments": comments},
                      sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def seal_statement(payload_digest, provenance_digest, comments, signers,
                   payload_type=STATEMENT_PAYLOAD_TYPE):
    """Seal the trusted-comments + provenance binding statement as a DSSE
    envelope. One signature binds key + payload digest + provenance digest
    + comments (the wave-202 lane-B discipline), with the payload TYPE
    additionally bound by the PAE."""
    return seal(_statement_bytes(payload_digest, provenance_digest,
                                comments),
                payload_type, signers)


def open_statement(envelope, payload_digest, provenance_digest, comments,
                   verifiers, threshold=1,
                   payload_type=STATEMENT_PAYLOAD_TYPE,
                   allowed_payload_types=None):
    """Open a statement envelope and check every binding. Raises loudly.

    ``provenance_digest`` is positional and always explicit: pass None to
    accept a provenance-free statement. There is no silent downgrade from
    a provenance-carrying statement to a provenance-free one.
    """
    if not isinstance(verifiers, list):
        verifiers = list(verifiers)
    payload = _statement_bytes(payload_digest, provenance_digest, comments)
    opened = open_envelope(envelope, payload, payload_type, verifiers,
                           threshold=threshold,
                           allowed_payload_types=allowed_payload_types)
    try:
        stmt = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise EnvelopeError("statement payload is not valid JSON: %s" % exc)
    if not isinstance(stmt, dict):
        raise EnvelopeError("statement payload must be a JSON object")
    extra = set(stmt) - _STATEMENT_FIELDS
    if extra:
        raise EnvelopeError("statement has unknown field(s) refused: %s"
                            % sorted(extra))
    missing = _STATEMENT_FIELDS - set(stmt)
    if missing:
        raise EnvelopeError("statement missing field(s): %s" % sorted(missing))
    # Re-derive the canonical bytes from the decoded statement and require
    # byte-equality with the envelope payload: the signature already
    # authenticates the payload, this additionally pins the shape so a
    # non-canonical-but-equivalent JSON cannot slip through.
    rederived = _statement_bytes(stmt["payload_sha256"],
                                stmt["provenance_digest"],
                                stmt["trusted_comments"])
    if rederived != payload:
        raise EnvelopeError("statement is not in canonical form")
    return {
        "key_ids": opened["key_ids"],
        "payload_type": opened["payload_type"],
        "payload_sha256": stmt["payload_sha256"],
        "provenance_digest": stmt["provenance_digest"],
        "trusted_comments": list(stmt["trusted_comments"]),
    }


def detect_envelope(envelope):
    """Identify an envelope's format by shape: "dsse" or "v2". Raises
    loudly on anything else."""
    if not isinstance(envelope, dict):
        raise EnvelopeError("envelope must be a dict")
    if {"payload", "payloadType", "signatures"} <= set(envelope):
        return "dsse"
    if envelope.get("format") == "sasanam-envelope/v2":
        return "v2"
    raise EnvelopeError("unrecognized envelope shape: not DSSE and not "
                        "sasanam-envelope/v2")


def open_any(envelope, payload_digest, provenance_digest, comments,
             verifiers):
    """Migration helper: open either a DSSE statement envelope or a legacy
    minisign-pattern v2 envelope. v2 envelopes are delegated to
    gov.signature_envelope_v2 with the provenance expectation passed
    explicitly -- already-sealed envelopes are not stranded."""
    kind = detect_envelope(envelope)
    if kind == "dsse":
        got = open_statement(envelope, payload_digest, provenance_digest,
                             comments, verifiers)
        got["format"] = "dsse"
        return got
    from . import signature_envelope_v2 as _env2
    got = _env2.open_envelope(envelope, payload_digest,
                              _first_verifier(verifiers),
                              expected_provenance_digest=provenance_digest)
    got["format"] = "v2"
    return got


def _first_verifier(verifiers):
    verifiers = list(verifiers)
    if not verifiers:
        raise EnvelopeError("open_any requires at least one verifier")
    return verifiers[0]
