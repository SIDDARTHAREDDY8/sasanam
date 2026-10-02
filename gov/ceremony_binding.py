"""Ceremony-bound evidence: bind the verifier's challenge into the signed
artifact.

Pattern lineage: the "bind the verifier's challenge into the signed
artifact" discipline confirmed independently by five industry mechanisms
-- AWS Nitro Enclaves attestation (nonce/user_data in the attestation
document), SEV-SNP REPORT_DATA (64-byte challenge binding), risc0
image-ID pinning, aTLS (nonce bound into the handshake), and Sigstore
gitsign content binding. Clean-room stdlib-only Python; no code lifted.

The honest gap this closes: Sasanam proves CONTENT (anchors, provenance,
posture) but not CEREMONY. A well-formed, validly-signed evidence
record can be replayed into a different appraisal request -- the record
says nothing about which ceremony it was minted for. This module binds
a verifier-supplied challenge ``(nonce >= 64 bits, purpose)`` into the
operator-signed envelope, and anchors the ``(content_digest, nonce,
purpose)`` tuple so the anchor chain witnesses BOTH the content AND
the ceremony it was minted for.

Freshness comes from gov/timestamp_authority.py tokens, which a binding
may reference via ``tsa_token`` (honoring the TSA's own nonce
discipline); this module invents no timestamping and owns no clock.

Honest limitations (documented, not hidden):
  * Software binding only: the signature proves the operator signed
    (content_digest, nonce, purpose); it cannot prove the verifier
    actually issued that challenge (the verifier must bind its nonce to
    its own request tracking out-of-band).
  * The nonce floor is 64 bits (RFC 9711 minimum, mirrored from
    gov/runtime_posture.py's eat_nonce discipline).
  * A compromised operator host can mint well-formed bindings for any
    challenge -- operator key compromise is the module's trust root.
"""

import hashlib
import json

from gov import ed25519 as _ed25519

# ---------------------------------------------------------------------------
# Module error convention (coded refusals; mirrors sibling modules)
# ---------------------------------------------------------------------------

CEREMONY_FORMAT = "sasanam-challenge-binding/1"
_BINDING_VERSION = 1
_SIG_CONTEXT = "sasanam-challenge-binding/v1"

# Machine codes (registered in gov/decision_codes.py, domain 'challenge').
INVALID_SHAPE = "challenge-invalid-shape"
SIGNATURE_INVALID = "challenge-signature-invalid"
NONCE_INVALID = "challenge-nonce-invalid"
NONCE_MISMATCH = "challenge-nonce-mismatch"
PURPOSE_MISMATCH = "challenge-purpose-mismatch"
ANCHOR_MISMATCH = "challenge-anchor-mismatch"

# Nonce floor: RFC 9711 minimum, mirrored from gov/runtime_posture.py.
_MIN_NONCE_BYTES = 8


class CeremonyError(Exception):
    """Coded refusal for ceremony-binding operations."""

    def __init__(self, message, code):
        super(CeremonyError, self).__init__(message)
        self.code = code


def _fail(code, detail):
    raise CeremonyError(detail, code=code)


_emit = None


def set_emit(emit):
    """Install an audit-event sink (dict -> None)."""
    global _emit
    _emit = emit


def _emit_event(event):
    """Emit an audit event to the installed sink. A broken audit sink
    must never break ceremony issuance or verification: the sink
    failure is isolated (the failure mode is recorded in this
    docstring/comment, not the event -- the same trade-off as
    ``gov/timestamp_authority.py`` and ``gov/evidence_provenance.py``),
    never the sink's raw exception type escaping at a public seam
    (F352)."""
    if _emit is None:
        return
    try:
        _emit(dict(event))
    except Exception:
        pass


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


def _digest(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


_HEX = frozenset("0123456789abcdefABCDEF")


def _is_hex(value, length):
    return (isinstance(value, str) and len(value) == length
            and all(c in _HEX for c in value))


def _check_operator_seed(seed):
    if not isinstance(seed, (bytes, bytearray)) or len(bytes(seed)) != 32:
        _fail(INVALID_SHAPE, "operator_seed must be 32 bytes")


def _check_keyid(keyid):
    if not isinstance(keyid, str) or not keyid:
        _fail(INVALID_SHAPE, "operator_keyid must be a non-empty string")


def _check_challenge_nonce(nonce):
    """Verifier-supplied nonce: bytes of at least 64 bits. Returns hex."""
    if not isinstance(nonce, (bytes, bytearray)) \
            or len(bytes(nonce)) < _MIN_NONCE_BYTES:
        _fail(NONCE_INVALID,
              "challenge_nonce must be verifier-supplied bytes of at "
              "least 64 bits (RFC 9711 minimum); the issuer refuses to "
              "mint without one")
    return bytes(nonce).hex()


def _check_purpose(purpose):
    if not isinstance(purpose, str) or not purpose:
        _fail(INVALID_SHAPE,
              "challenge_purpose must be a non-empty string")
    if len(purpose) > 256:
        _fail(INVALID_SHAPE,
              "challenge_purpose must be at most 256 chars")
    return purpose


def _check_content_digest(content_digest):
    if not _is_hex(content_digest, 64):
        _fail(INVALID_SHAPE,
              "content_digest must be a 64-hex digest")
    return content_digest.lower()


def _sig_structure(protected, payload):
    return _canonical({
        "context": _SIG_CONTEXT,
        "protected": protected,
        "payload": payload,
    })


# ---------------------------------------------------------------------------
# Issuance
# ---------------------------------------------------------------------------

def issue_binding(*, operator_seed, operator_keyid, challenge_nonce,
                  challenge_purpose, content_digest, tsa_token=None):
    """Mint a challenge-bound evidence record.

    The verifier supplies ``challenge_nonce`` (>= 64 bits) and
    ``challenge_purpose``; the issuer refuses to mint without both.
    ``content_digest`` is the 64-hex identity of the evidence the
    binding witnesses. The operator signature covers the
    ``(nonce, purpose, content_digest)`` tuple, so the record cannot be
    detached from its ceremony without breaking the signature.

    ``tsa_token`` is an optional reference to a
    gov/timestamp_authority.py token that supplies freshness; this
    module performs no time checks of its own.

    Returns the JSON-serializable record dict. All argument violations
    fail closed with coded ``challenge-*`` refusals.
    """
    _check_operator_seed(operator_seed)
    _check_keyid(operator_keyid)
    nonce_hex = _check_challenge_nonce(challenge_nonce)
    purpose = _check_purpose(challenge_purpose)
    digest = _check_content_digest(content_digest)
    if tsa_token is not None and not isinstance(tsa_token, dict):
        _fail(INVALID_SHAPE, "tsa_token must be a mapping or None")

    protected = {
        "alg": "EdDSA",
        "kid": operator_keyid,
        "ceremony_format": CEREMONY_FORMAT,
    }
    payload = {
        "v": _BINDING_VERSION,
        "challenge_nonce": nonce_hex,
        "challenge_purpose": purpose,
        "content_digest": digest,
    }
    if tsa_token is not None:
        payload["tsa_token"] = tsa_token

    sig_structure = _sig_structure(protected, payload)
    signature = _ed25519.sign(bytes(operator_seed), sig_structure).hex()
    record = {
        "ceremony_format": CEREMONY_FORMAT,
        "protected": protected,
        "payload": payload,
        "signature": signature,
    }
    _emit_event({"event": "binding-issued",
                 "kid": operator_keyid,
                 "binding_digest": _digest(record),
                 "nonce": nonce_hex,
                 "purpose": purpose,
                 "content_digest": digest})
    return record


# ---------------------------------------------------------------------------
# Verification (fail closed, coded)
# ---------------------------------------------------------------------------

def _require_record_shape(record):
    if not isinstance(record, dict):
        _fail(INVALID_SHAPE, "record must be a mapping")
    if record.get("ceremony_format") != CEREMONY_FORMAT:
        _fail(INVALID_SHAPE,
              "record ceremony_format must be %r" % (CEREMONY_FORMAT,))
    protected = record.get("protected")
    payload = record.get("payload")
    signature = record.get("signature")
    if not isinstance(protected, dict) or not isinstance(payload, dict):
        _fail(INVALID_SHAPE,
              "record must carry protected/payload mappings")
    if not isinstance(signature, str) or not signature:
        _fail(SIGNATURE_INVALID, "record carries no signature")
    return protected, payload, signature


def verify_binding(record, operator_pubkey_hex, *, expected_nonce=None,
                   expected_purpose=None):
    """Verify a challenge-bound record against the pinned operator key.

    Checks, in order: shape -> signature (``ok is not True`` refuses)
    -> nonce (>= 64 bits, and equal to ``expected_nonce`` when given --
    replay into a different appraisal request refuses
    ``challenge-nonce-mismatch``) -> purpose (equal to
    ``expected_purpose`` when given -- purpose confusion refuses
    ``challenge-purpose-mismatch``) -> content digest shape.

    Returns the verified payload.
    """
    protected, payload, signature = _require_record_shape(record)
    if not _is_hex(operator_pubkey_hex, 64):
        _fail(INVALID_SHAPE,
              "operator_pubkey_hex must be a 64-hex Ed25519 public key")

    # F355: a non-hex signature string would raise a raw ValueError from
    # bytes.fromhex. Refuse LOUD and coded before touching hex decode.
    if not _is_hex(signature, 128):
        _fail(SIGNATURE_INVALID,
              "signature must be a 128-hex Ed25519 signature")

    sig_structure = _sig_structure(protected, payload)
    ok = _ed25519.verify(bytes.fromhex(operator_pubkey_hex),
                        sig_structure, bytes.fromhex(signature))
    if ok is not True:
        _fail(SIGNATURE_INVALID,
              "operator signature did not verify -- record is forged "
              "or tampered")

    nonce_hex = payload.get("challenge_nonce")
    if (not isinstance(nonce_hex, str)
            or len(nonce_hex) < 2 * _MIN_NONCE_BYTES
            or not all(c in _HEX for c in nonce_hex)):
        _fail(NONCE_INVALID,
              "challenge_nonce must be at least 64 bits of hex")
    if expected_nonce is not None:
        want = (expected_nonce.hex()
                if isinstance(expected_nonce, (bytes, bytearray))
                else expected_nonce)
        if not isinstance(want, str) or want.lower() != nonce_hex.lower():
            _fail(NONCE_MISMATCH,
                  "challenge_nonce does not match the appraisal request "
                  "-- possible replay into a different ceremony")

    purpose = payload.get("challenge_purpose")
    if not isinstance(purpose, str) or not purpose:
        _fail(INVALID_SHAPE,
              "challenge_purpose must be a non-empty string")
    if expected_purpose is not None:
        if not isinstance(expected_purpose, str) \
                or expected_purpose != purpose:
            _fail(PURPOSE_MISMATCH,
                  "challenge_purpose does not match the appraisal "
                  "request -- possible purpose confusion")

    _check_content_digest(payload.get("content_digest"))
    return payload


# ---------------------------------------------------------------------------
# Composition: anchoring the (content digest + challenge) tuple
# ---------------------------------------------------------------------------

def _require_leaf_keys(payload):
    """Extract the (content_digest, nonce, purpose) tuple for anchoring.

    F353: direct indexing raised an uncoded KeyError on a shape-valid
    but keyless payload. All three tuple members are refused LOUD with
    coded challenge-invalid-shape when absent or non-string.
    """
    values = []
    for key in ("content_digest", "challenge_nonce", "challenge_purpose"):
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            _fail(INVALID_SHAPE,
                  "record payload must bind a non-empty %r for "
                  "ceremony anchoring" % (key,))
        values.append(value)
    return values[0], values[1], values[2]


def ceremony_leaf(record):
    """The anchor leaf: the tuple's content identity.

    The leaf commits to BOTH the content digest and the ceremony
    (nonce + purpose); the anchor chain therefore witnesses the
    ceremony the evidence was minted for, not just the content.
    """
    protected, payload, _ = _require_record_shape(record)
    content_digest, nonce, purpose = _require_leaf_keys(payload)
    return _digest({
        "content_digest": content_digest,
        "challenge_nonce": nonce,
        "challenge_purpose": purpose,
    })


def anchor_binding(log, record, witness_policy=None, witness_seeds=None):
    """Anchor a challenge binding's ceremony tuple.

    Thin wrapper over gov/evidence_anchor.anchor: the leaf is
    ``ceremony_leaf(record)``, so the receipt binds the exact
    ``(content_digest, nonce, purpose)`` tuple. Witness cosigning flows
    through unchanged. Returns ``(receipt, leaf_digest)``.
    """
    from gov import evidence_anchor as _ea
    leaf = ceremony_leaf(record)
    receipt = _ea.anchor(log, leaf, witness_policy=witness_policy,
                         witness_seeds=witness_seeds)
    return receipt, leaf


def verify_anchored_binding(record, receipt, log_pubkey_hex,
                            operator_pubkey_hex, witness_policy=None,
                            expected_nonce=None, expected_purpose=None):
    """Verify a record against its anchor receipt AND the pinned keys.

    Checks: record verifies under the operator key with the expected
    challenge -> ceremony leaf recomputed from the record matches the
    receipt's bundle digest (challenge-anchor-mismatch refuses
    anchor-substitution between ceremonies) -> receipt verifies under
    the log key. Returns the verified payload.
    """
    payload = verify_binding(record, operator_pubkey_hex,
                             expected_nonce=expected_nonce,
                             expected_purpose=expected_purpose)
    from gov import evidence_anchor as _ea
    leaf = ceremony_leaf(record)
    if not isinstance(receipt, dict) \
            or receipt.get("bundle_digest") != leaf:
        _fail(ANCHOR_MISMATCH,
              "anchor receipt does not cover this record's ceremony "
              "tuple -- possible anchor substitution between ceremonies")
    if not _is_hex(log_pubkey_hex, 64):
        _fail(INVALID_SHAPE,
              "log_pubkey_hex must be a 64-hex Ed25519 public key")
    _ea.verify_receipt(receipt, bytes.fromhex(log_pubkey_hex),
                       witness_policy=witness_policy)
    return payload
