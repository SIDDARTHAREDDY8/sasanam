"""Signature envelope v2: minisign/age-pattern signed envelopes.

PATTERN LINEAGE: Frank Denis's minisign (ISC) -- the "trusted comment +
global signature" envelope: human-readable context that is BOUND INTO
the signature, not stapled beside it -- and age's (BSD-3-Clause)
header discipline: strict, versioned, fail-closed parsing. Reimplemented
in stdlib Python -- no minisign/age code is vendored here, only the
pattern.

An envelope binds four things in one signature:

    key_id            -- which key signed (short id, like minisign's)
    payload_digest    -- sha256 of the payload bytes
    provenance_digest -- canonical digest of the sealed provenance
                         statement (gov.build_provenance) -- optional
                         only in the sense that a caller may ship a
                         payload without provenance, but then it says
                         so explicitly (see provenance_digest=None)
    trusted_comments  -- human-readable context, bound into the
                         signature: editing a comment breaks the
                         signature exactly like editing the payload

Strictness: envelopes carry an exact field allowlist; unknown fields
are refused (fail-closed), and the format version is checked -- a v3
envelope is never opened by a v2 parser. ``EnvelopeError`` is raised
loudly on every violation.

Key-ID-based selection: ``open_envelope`` requires the caller's
``verifier`` to match the envelope's ``key_id`` -- a signature from
the wrong key is a loud refusal, not a quiet mismatch.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import hashlib
import json

from .signing import Verifier

__all__ = [
    "ENVELOPE_FORMAT",
    "EnvelopeError",
    "parse_envelope",
    "seal",
    "open_envelope",
]

ENVELOPE_FORMAT = "sasanam-envelope/v2"

_ENVELOPE_FIELDS = frozenset(
    {"format", "key_id", "payload_digest", "provenance_digest",
     "trusted_comments", "signature"})


class EnvelopeError(ValueError):
    """Raised loudly on any envelope parse/verify failure."""


def _check_hex_digest(value, where):
    if not isinstance(value, str):
        raise EnvelopeError("%s: digest must be str, got %s"
                            % (where, type(value).__name__))
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise EnvelopeError("%s: not a sha256 hex digest: %r"
                            % (where, value))
    return value


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _sig_body(payload_digest, provenance_digest, trusted_comments, key_id):
    # Domain-separated signing body: one signature binds key, payload,
    # provenance, and comments. provenance_digest=None is written as an
    # explicit null so "no provenance" and "stripped provenance" are
    # distinguishable -- a caller that strips a provenance digest gets
    # a signature mismatch, not a downgrade.
    return _canonical({
        "domain": "sasanam-envelope-seal/v2",
        "key_id": key_id,
        "payload_digest": payload_digest,
        "provenance_digest": provenance_digest,
        "trusted_comments": list(trusted_comments),
    })


def seal(payload_hex, signer, trusted_comments, provenance_digest=None):
    """Seal ``payload_hex`` into a v2 envelope.

    ``trusted_comments`` is a non-empty list of human-readable strings
    (a sealed envelope with no context is an operational smell; the
    layer refuses to mint one). ``provenance_digest`` is the canonical
    digest of the sealed provenance statement, or None for an
    explicitly provenance-free envelope.
    """
    payload = _check_hex_digest(payload_hex, "payload")
    if provenance_digest is not None:
        provenance_digest = _check_hex_digest(provenance_digest,
                                              "provenance")
    comments = list(trusted_comments)
    if not comments or not all(isinstance(c, str) and c for c in comments):
        raise EnvelopeError("trusted_comments must be a non-empty list "
                            "of non-empty strings")
    body = _sig_body(payload, provenance_digest, comments, signer.key_id)
    sig = signer.sign(body)
    return {
        "format": ENVELOPE_FORMAT,
        "key_id": signer.key_id,
        "payload_digest": payload,
        "provenance_digest": provenance_digest,
        "trusted_comments": comments,
        "signature": sig.hex(),
    }


def parse_envelope(envelope):
    """Strict-parse an envelope; refuses unknown fields and versions."""
    if not isinstance(envelope, dict):
        raise EnvelopeError("envelope must be a dict")
    extra = set(envelope) - _ENVELOPE_FIELDS
    if extra:
        raise EnvelopeError("unknown envelope field(s) refused: %s"
                            % sorted(extra))
    missing = _ENVELOPE_FIELDS - set(envelope)
    if missing:
        raise EnvelopeError("envelope missing field(s): %s"
                            % sorted(missing))
    if envelope["format"] != ENVELOPE_FORMAT:
        raise EnvelopeError("unsupported envelope format: %r "
                            "(this parser opens %r only)"
                            % (envelope["format"], ENVELOPE_FORMAT))
    _check_hex_digest(envelope["payload_digest"], "payload_digest")
    if envelope["provenance_digest"] is not None:
        _check_hex_digest(envelope["provenance_digest"],
                          "provenance_digest")
    comments = envelope["trusted_comments"]
    if (not isinstance(comments, list) or not comments
            or not all(isinstance(c, str) and c for c in comments)):
        raise EnvelopeError("trusted_comments must be a non-empty list "
                            "of non-empty strings")
    sig_hex = envelope["signature"]
    if (not isinstance(sig_hex, str) or len(sig_hex) != 128
            or any(c not in "0123456789abcdef" for c in sig_hex)):
        raise EnvelopeError("signature must be 128 lowercase hex chars")
    key_id = envelope["key_id"]
    if not isinstance(key_id, str) or not key_id:
        raise EnvelopeError("key_id must be a non-empty str")
    return envelope


def open_envelope(envelope, expected_payload_hex, verifier,
                  expected_provenance_digest="__require__"):
    """Open and verify an envelope. Raises loudly on any violation.

    Checks, in order: strict parse; key_id match with ``verifier``;
    payload-digest binding against ``expected_payload_hex``;
    provenance-digest binding; signature validity.

    ``expected_provenance_digest`` defaults to ``"__require__"``: the
    caller must supply the expected provenance digest, or pass None
    explicitly to accept a provenance-free envelope. There is no silent
    downgrade from provenance-carrying to provenance-free.
    """
    if not isinstance(verifier, Verifier):
        raise EnvelopeError("verifier must be a gov.signing.Verifier")
    env = parse_envelope(envelope)
    if env["key_id"] != verifier.key_id:
        raise EnvelopeError("envelope key_id %r does not match verifier "
                            "key_id %r" % (env["key_id"], verifier.key_id))
    expected_payload = _check_hex_digest(expected_payload_hex,
                                         "expected_payload")
    if env["payload_digest"] != expected_payload:
        raise EnvelopeError("payload binding mismatch: envelope is for "
                            "%s, expected %s"
                            % (env["payload_digest"], expected_payload))
    if expected_provenance_digest == "__require__":
        raise EnvelopeError("expected_provenance_digest is required: pass "
                            "the expected digest or None explicitly to "
                            "accept a provenance-free envelope")
    if expected_provenance_digest is not None:
        expected_provenance_digest = _check_hex_digest(
            expected_provenance_digest, "expected_provenance")
    if env["provenance_digest"] != expected_provenance_digest:
        raise EnvelopeError("provenance binding mismatch: envelope "
                            "carries %r, expected %r"
                            % (env["provenance_digest"],
                               expected_provenance_digest))
    body = _sig_body(env["payload_digest"], env["provenance_digest"],
                     env["trusted_comments"], env["key_id"])
    sig = bytes.fromhex(env["signature"])
    if not verifier.verify(body, sig):
        raise EnvelopeError("envelope signature invalid")
    return {
        "key_id": env["key_id"],
        "payload_digest": env["payload_digest"],
        "provenance_digest": env["provenance_digest"],
        "trusted_comments": list(env["trusted_comments"]),
    }


def payload_digest_of(data):
    """sha256 hex digest of payload bytes."""
    if not isinstance(data, (bytes, bytearray)):
        raise EnvelopeError("payload must be bytes")
    return hashlib.sha256(bytes(data)).hexdigest()
