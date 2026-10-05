"""COSE_Sign1 run receipt — a wire-compatible signed statement about a
governed run's binding block (R37, spec: research/r37-cose-run-receipt-2026-10-05.md).

Pattern lineage: sipyourdrink-ltd/bernstein PR #6392 (Apache-2.0),
ADAPT only — clean-room reimplementation of three decisions:

1. The payload is the binding BYTES (journal head + spine head), not a
   digest, so a transparency service can register the envelope as a
   statement about the binding block itself.
2. The envelope's payload copy and the verifier's recomputed subject
   binding are COMPARED byte-for-byte, never trusted. A correctly
   signed envelope over the wrong binding is ``tampered``.
3. ``verify_run_receipt`` returns a ``tampered`` status for content
   anomalies (never raises on content); it takes bytes, not paths.

Unlike ``gov/evidence_receipt.py``'s JSON-shaped analog, this envelope
is genuinely RFC 8152 wire-compatible (tag 18, CBOR, Sig_structure),
so an off-the-shelf COSE verifier with EdDSA support validates it.

Threat model (read the spec before trusting a receipt):
- Registration of a statement, not truth of the events.
- No-rollback: an older valid receipt verified against a newer expected
  binding is ``tampered`` (payload-mismatch).
- ``kid`` is a hint, never authority: the verifier uses the
  caller-pinned 32-byte public key, never any key id in the envelope.
- Receipts are statements, not nonces: replay of the same receipt
  against the same binding verifies; freshness is the auditor's job.

$0 spend, deterministic, stdlib only. No network.
"""

from __future__ import annotations

import hashlib
import hmac

from gov.signing import Ed25519Verifier as _Ed25519Verifier

# ---------------------------------------------------------------- constants

COSE_SIGN1_TAG = 18
ALG_EDDSA = -8
DEFAULT_CONTENT_TYPE = "application/vnd.sasanam.run-receipt+cbor"
BINDING_VERSION = "run-receipt/1"

_STATUS_VERIFIED = "verified"
_STATUS_TAMPERED = "tampered"
_STATUS_NO_ENVELOPE = "no-envelope"

_REASON_SIGNATURE = "signature"
_REASON_CONTENT_TYPE = "content-type"
_REASON_PAYLOAD_MISMATCH = "payload-mismatch"
_REASON_PAYLOAD_MALFORMED = "payload-malformed"
_REASON_ENVELOPE_MALFORMED = "envelope-malformed"
_REASON_ALGORITHM = "algorithm"


class RunReceiptError(Exception):
    """Usage error (bad inputs, missing key). Content anomalies are never
    raised — they become ``tampered`` results."""


# ---------------------------------------------------------------- minimal CBOR
# Definite-length subset only. Anything outside the subset refuses
# loudly; this is NOT a general CBOR library.

_CBOR_MAX_DEPTH = 16


class _CborTag:
    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        self.tag = tag
        self.value = value


def _cbor_head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 256:
        return bytes([(major << 5) | 24, value])
    if value < 65536:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 4294967296:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value < 18446744073709551616:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise RunReceiptError("cbor: integer out of range")


def _cbor_encode(obj, _depth=0):
    if _depth > _CBOR_MAX_DEPTH:
        raise RunReceiptError("cbor: nesting too deep")
    if isinstance(obj, _CborTag):
        return _cbor_head(6, obj.tag) + _cbor_encode(obj.value, _depth + 1)
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if obj is None:
        return b"\xf6"
    if isinstance(obj, int):
        if obj >= 0:
            return _cbor_head(0, obj)
        if obj >= -18446744073709551616:
            return _cbor_head(1, -1 - obj)
        raise RunReceiptError("cbor: integer out of range")
    if isinstance(obj, (bytes, bytearray)):
        return _cbor_head(2, len(obj)) + bytes(obj)
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(obj, (list, tuple)):
        out = [_cbor_head(4, len(obj))]
        for item in obj:
            out.append(_cbor_encode(item, _depth + 1))
        return b"".join(out)
    if isinstance(obj, dict):
        # RFC 7049 canonical ordering: shorter encoded key first, then
        # lexicographic. Encoded keys only (int/str/bytes supported).
        pairs = []
        for k, v in obj.items():
            if not isinstance(k, (int, str, bytes, bytearray)):
                raise RunReceiptError("cbor: unsupported map key type")
            ek = _cbor_encode(bytes(k) if isinstance(k, bytearray) else k,
                              _depth + 1)
            pairs.append((ek, _cbor_encode(v, _depth + 1)))
        pairs.sort(key=lambda kv: (len(kv[0]), kv[0]))
        out = [_cbor_head(5, len(pairs))]
        for ek, ev in pairs:
            out.append(ek)
            out.append(ev)
        return b"".join(out)
    raise RunReceiptError("cbor: unsupported type %s" % type(obj).__name__)


class _CborDecodeError(RunReceiptError):
    pass


def _cbor_decode(buf):
    """Strict definite-length decode. Returns the object; refuses on
    indefinite lengths, trailing bytes, or structures outside the subset."""
    obj, pos = _decode_one(buf, 0, 0)
    if pos != len(buf):
        raise _CborDecodeError("trailing bytes after CBOR item")
    return obj


def _decode_one(buf, pos, depth):
    if depth > _CBOR_MAX_DEPTH:
        raise _CborDecodeError("nesting too deep")
    if pos >= len(buf):
        raise _CborDecodeError("truncated input")
    initial = buf[pos]
    pos += 1
    major = initial >> 5
    info = initial & 31
    if info < 24:
        value = info
    elif info == 24:
        if pos >= len(buf):
            raise _CborDecodeError("truncated length")
        value = buf[pos]
        pos += 1
    elif info == 25:
        if pos + 2 > len(buf):
            raise _CborDecodeError("truncated length")
        value = int.from_bytes(buf[pos:pos + 2], "big")
        pos += 2
    elif info == 26:
        if pos + 4 > len(buf):
            raise _CborDecodeError("truncated length")
        value = int.from_bytes(buf[pos:pos + 4], "big")
        pos += 4
    elif info == 27:
        if pos + 8 > len(buf):
            raise _CborDecodeError("truncated length")
        value = int.from_bytes(buf[pos:pos + 8], "big")
        pos += 8
    else:
        # 28-30 reserved, 31 indefinite — all refused.
        raise _CborDecodeError("indefinite or reserved length")
    if major == 0:
        return value, pos
    if major == 1:
        return -1 - value, pos
    if major in (2, 3):
        if pos + value > len(buf):
            raise _CborDecodeError("truncated string")
        raw = buf[pos:pos + value]
        pos += value
        if major == 2:
            return bytes(raw), pos
        try:
            return raw.decode("utf-8"), pos
        except UnicodeDecodeError:
            raise _CborDecodeError("invalid utf-8 in text string")
    if major == 4:
        items = []
        for _ in range(value):
            item, pos = _decode_one(buf, pos, depth + 1)
            items.append(item)
        return items, pos
    if major == 5:
        result = {}
        for _ in range(value):
            k, pos = _decode_one(buf, pos, depth + 1)
            v, pos = _decode_one(buf, pos, depth + 1)
            if not isinstance(k, (int, str, bytes)):
                raise _CborDecodeError("unsupported map key type")
            result[k] = v
        return result, pos
    if major == 6:
        inner, pos = _decode_one(buf, pos, depth + 1)
        return _CborTag(value, inner), pos
    # major 7: only false/true/null accepted.
    if major == 7 and value in (20, 21, 22):
        return (False, True, None)[value - 20], pos
    raise _CborDecodeError("unsupported simple/float value")


# ---------------------------------------------------------------- binding block

def _canonical_binding_bytes(journal_head, spine_head):
    """Canonical CBOR bytes of the binding block (the bytes that go in
    the payload AND the bytes the verifier recomputes for comparison)."""
    block = {
        1: BINDING_VERSION,
        2: journal_head,
        3: {
            1: spine_head["tree_size"],
            2: spine_head["root_hash"],
            3: spine_head["timestamp"],
            4: spine_head["log_id"],
        },
    }
    return _cbor_encode(block)


def _check_spine_head(spine_head, where):
    if not isinstance(spine_head, dict):
        raise RunReceiptError("%s: spine_head must be a dict" % where)
    ts = spine_head.get("tree_size")
    rh = spine_head.get("root_hash")
    t = spine_head.get("timestamp")
    lid = spine_head.get("log_id")
    if not isinstance(ts, int) or ts < 0:
        raise RunReceiptError("%s: spine_head.tree_size must be uint" % where)
    if not isinstance(rh, (bytes, bytearray)) or len(rh) != 32:
        raise RunReceiptError("%s: spine_head.root_hash must be 32 bytes"
                              % where)
    if not isinstance(t, int) or t < 0:
        raise RunReceiptError("%s: spine_head.timestamp must be uint" % where)
    if not isinstance(lid, str) or not lid:
        raise RunReceiptError("%s: spine_head.log_id must be a string"
                              % where)
    return {"tree_size": ts, "root_hash": bytes(rh),
            "timestamp": t, "log_id": lid}


def _check_journal_head(journal_head, where):
    if not isinstance(journal_head, (bytes, bytearray)) or \
            len(journal_head) != 32:
        raise RunReceiptError("%s: journal_head must be 32 bytes" % where)
    return bytes(journal_head)


def _check_signer(signer, where):
    pub = getattr(signer, "public_key", None)
    sign = getattr(signer, "sign", None)
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        raise RunReceiptError("%s: signer.public_key must be 32 bytes"
                              % where)
    if not callable(sign):
        raise RunReceiptError("%s: signer needs .sign(bytes)" % where)
    return bytes(pub), sign


def _check_public_key(public_key):
    if not isinstance(public_key, (bytes, bytearray)) or \
            len(public_key) != 32:
        raise RunReceiptError(
            "verify_run_receipt: public_key must be 32 bytes "
            "(pin the operator key explicitly; envelope kid is never used)")
    return bytes(public_key)


# ---------------------------------------------------------------- result

class RunReceiptResult:
    """Verdict of verify_run_receipt. Content anomalies are statuses,
    never exceptions."""

    __slots__ = ("status", "tampered_reason", "cose_verified",
                 "binding_compared", "binding")

    def __init__(self, status, tampered_reason=None, cose_verified=None,
                 binding_compared=False, binding=None):
        self.status = status
        self.tampered_reason = tampered_reason
        self.cose_verified = cose_verified
        self.binding_compared = binding_compared
        self.binding = binding

    def __repr__(self):
        return ("RunReceiptResult(status=%r, tampered_reason=%r, "
                "cose_verified=%r, binding_compared=%r)"
                % (self.status, self.tampered_reason,
                   self.cose_verified, self.binding_compared))


def _tampered(reason):
    return RunReceiptResult(_STATUS_TAMPERED, tampered_reason=reason,
                            cose_verified=False, binding_compared=False)


# ---------------------------------------------------------------- build

def build_run_receipt(*, journal_head, spine_head, signer,
                      content_type=DEFAULT_CONTENT_TYPE):
    """Build an RFC 8152 COSE_Sign1 run receipt (wire bytes).

    Pure function of (journal_head, spine_head, signer seed,
    content_type): same inputs, same bytes.
    """
    journal_head = _check_journal_head(journal_head, "build_run_receipt")
    spine_head = _check_spine_head(spine_head, "build_run_receipt")
    _pub, sign = _check_signer(signer, "build_run_receipt")
    if not isinstance(content_type, str) or not content_type:
        raise RunReceiptError("build_run_receipt: content_type must be "
                              "a non-empty string")

    payload = _canonical_binding_bytes(journal_head, spine_head)
    protected = _cbor_encode({1: ALG_EDDSA, 3: content_type})
    # RFC 8152 §4.4 Sig_structure for COSE_Sign1.
    sig_structure = _cbor_encode(["Signature1", protected, b"", payload])
    try:
        signature = sign(sig_structure)
    except Exception as exc:
        raise RunReceiptError("build_run_receipt: signer failed: %s" % exc)
    if not isinstance(signature, (bytes, bytearray)) or \
            len(signature) != 64:
        raise RunReceiptError("build_run_receipt: signer must return "
                              "64 bytes")
    envelope = _cbor_encode(
        _CborTag(COSE_SIGN1_TAG, [protected, {}, payload,
                                  bytes(signature)]))
    return envelope


# ---------------------------------------------------------------- verify

def verify_run_receipt(cose_bytes, *, public_key, expected=None,
                       content_type=DEFAULT_CONTENT_TYPE):
    """Verify a COSE_Sign1 run receipt from its own bytes.

    - ``cose_bytes=None`` → status ``no-envelope`` (``cose_verified`` None):
      a missing envelope is never readable as "checked out".
    - ``public_key`` (32 bytes, required): the pinned operator key. The
      envelope's key id, if any, is never consulted.
    - ``expected``: the recomputed subject binding
      ``{"journal_head": bytes, "spine_head": {...}}``. When supplied,
      the envelope payload is compared byte-for-byte against the
      canonical recomputation (compare, don't trust). When omitted, the
      signature/content-type/structure still verify, but
      ``binding_compared`` is False so the pass cannot be misread.
    """
    if cose_bytes is None:
        return RunReceiptResult(_STATUS_NO_ENVELOPE, cose_verified=None)
    pub = _check_public_key(public_key)
    if not isinstance(cose_bytes, (bytes, bytearray)) or not cose_bytes:
        return _tampered(_REASON_ENVELOPE_MALFORMED)

    try:
        envelope = _cbor_decode(bytes(cose_bytes))
    except RunReceiptError:
        return _tampered(_REASON_ENVELOPE_MALFORMED)
    if not isinstance(envelope, _CborTag) or \
            envelope.tag != COSE_SIGN1_TAG:
        return _tampered(_REASON_ENVELOPE_MALFORMED)
    body = envelope.value
    if not isinstance(body, list) or len(body) != 4:
        return _tampered(_REASON_ENVELOPE_MALFORMED)
    protected_b, unprotected, payload_b, signature = body
    if not isinstance(protected_b, bytes) or \
            not isinstance(unprotected, dict) or \
            not isinstance(signature, bytes) or len(signature) != 64:
        return _tampered(_REASON_ENVELOPE_MALFORMED)
    # A non-bytes payload (nil = detached, text, ...) parses as COSE but
    # carries no statement for this profile: payload-malformed, not
    # envelope-malformed. Checked before the signature so the reason is
    # precise; it is tampered either way.
    if not isinstance(payload_b, bytes):
        return _tampered(_REASON_PAYLOAD_MALFORMED)

    try:
        protected = _cbor_decode(protected_b)
    except RunReceiptError:
        return _tampered(_REASON_ENVELOPE_MALFORMED)
    if not isinstance(protected, dict):
        return _tampered(_REASON_ENVELOPE_MALFORMED)
    # Algorithm is pinned: EdDSA (-8) only. No negotiation, no fallback.
    if protected.get(1) != ALG_EDDSA:
        return _tampered(_REASON_ALGORITHM)
    # Content type read from the PROTECTED header only; an unprotected
    # copy is ignored, never trusted.
    if protected.get(3) != content_type:
        return _tampered(_REASON_CONTENT_TYPE)

    sig_structure = _cbor_encode(["Signature1", protected_b, b"", payload_b])
    verifier = _Ed25519Verifier(pub)
    # verify() is bool-returning (wave-243 lesson): check the return,
    # assert is True / is False semantics.
    if verifier.verify(sig_structure, signature) is not True:
        return _tampered(_REASON_SIGNATURE)

    try:
        binding = _cbor_decode(payload_b)
    except RunReceiptError:
        return _tampered(_REASON_PAYLOAD_MALFORMED)
    parsed = _parse_binding(binding)
    if parsed is None:
        return _tampered(_REASON_PAYLOAD_MALFORMED)

    if expected is None:
        return RunReceiptResult(_STATUS_VERIFIED, cose_verified=True,
                                binding_compared=False, binding=parsed)
    if not isinstance(expected, dict):
        raise RunReceiptError("verify_run_receipt: expected must be a dict")
    try:
        exp_jh = _check_journal_head(expected.get("journal_head"),
                                     "verify_run_receipt expected")
        exp_sh = _check_spine_head(expected.get("spine_head"),
                                   "verify_run_receipt expected")
    except RunReceiptError:
        raise
    recomputed = _canonical_binding_bytes(exp_jh, exp_sh)
    if hmac.compare_digest(payload_b, recomputed) is not True:
        return _tampered(_REASON_PAYLOAD_MISMATCH)
    return RunReceiptResult(_STATUS_VERIFIED, cose_verified=True,
                            binding_compared=True, binding=parsed)


def _parse_binding(binding):
    """Parse the decoded payload into the binding dict, or None when the
    shape is wrong (a digest-instead-of-binding payload lands here)."""
    if not isinstance(binding, dict):
        return None
    if binding.get(1) != BINDING_VERSION:
        return None
    journal_head = binding.get(2)
    spine = binding.get(3)
    if not isinstance(journal_head, bytes) or len(journal_head) != 32:
        return None
    if not isinstance(spine, dict):
        return None
    tree_size = spine.get(1)
    root_hash = spine.get(2)
    timestamp = spine.get(3)
    log_id = spine.get(4)
    if not isinstance(tree_size, int) or tree_size < 0:
        return None
    if not isinstance(root_hash, bytes) or len(root_hash) != 32:
        return None
    if not isinstance(timestamp, int) or timestamp < 0:
        return None
    if not isinstance(log_id, str) or not log_id:
        return None
    return {"journal_head": journal_head,
            "spine_head": {"tree_size": tree_size, "root_hash": root_hash,
                           "timestamp": timestamp, "log_id": log_id}}


def binding_digest(cose_bytes):
    """sha256 of the raw envelope bytes (for logs and ledgers)."""
    return hashlib.sha256(bytes(cose_bytes)).hexdigest()
