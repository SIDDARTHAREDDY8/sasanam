"""Runtime posture attestation records in the EAT JSON-profile shape.

Pattern lineage: ietf-rats-wg/eat. EAT is RFC 9711 (Standards Track,
April 2025), not a draft. This module adapts the JSON profile (no CBOR):
``eat_nonce`` of at least 64 bits, ``submods`` anti-substitution nesting,
and agent-runtime equivalents of the ``dbgstat``/``intuse`` claims.
Clean-room stdlib-only Python -- no code lifted from the IETF documents.

The appraisal wire stays behind indirection: EAR/AR4SI are still drafts,
so this module does NOT commit to the draft AR4SI wire format. Records
are consumable by gov/trust_vector.py through the narrow
``(claim_digest, scheme_id, endorsements)`` seam under the registered
``runtime-posture/v1`` scheme.

Honest limitations (documented, not hidden):
  * Software attestation only. There is no hardware root of trust here;
    measurements attest what the operator's software CLAIMS about the
    runtime (the $0 simulator-first posture). A compromised operator host
    can lie in a well-formed record.
  * Endorsement quality bounds the appraisal vector: an endorsement slot
    is a reference to an anchor-log position, not inline trust. An empty
    or low-quality endorsement can only ever grade ``insufficient``.
    Endorsement independence (slots must be separately sourced from the
    record's producer) is enforced at BOTH issuance and verification,
    against the producer identity bound in the signed payload (F350).
    Records minted before the producer binding carry no ``producer_id``
    and are refused.
  * Freshness comes from gov/timestamp_authority.py tokens, which a
    record may reference via ``tsa_token``. This module has no clock of
    its own and invents no timestamping.
"""

import hashlib
import json
import os

from gov import ed25519 as _ed25519

# ---------------------------------------------------------------------------
# Module error convention (coded refusals; mirrors sibling modules)
# ---------------------------------------------------------------------------

POSTURE_FORMAT = "sasanam-runtime-posture/1"
_POSTURE_VERSION = 1
_SIG_CONTEXT = "sasanam-runtime-posture/v1"

# Machine codes (registered in gov/decision_codes.py, domain 'posture').
INVALID_SHAPE = "posture-invalid-shape"
SIGNATURE_INVALID = "posture-signature-invalid"
NONCE_INVALID = "posture-nonce-invalid"
SUBMOD_INVALID = "posture-submod-invalid"
ENDORSEMENT_MISSING = "posture-endorsement-missing"
ENDORSEMENT_NOT_INDEPENDENT = "posture-endorsement-not-independent"

# Nonce floor: RFC 9711 requires eat_nonce to be at least 64 bits.
_MIN_NONCE_BYTES = 8

# Every claim must carry a separately-sourced endorsement slot (the
# wave-286 design rule). Top-level claim names covered by the rule.
_CLAIM_NAMES = ("software_id", "config_digest", "submods")

# Trust-vector scheme id (registered with gov/trust_vector.py).
SCHEME_ID = "runtime-posture/v1"


class PostureError(Exception):
    """Coded refusal for runtime-posture operations."""

    def __init__(self, message, code):
        super(PostureError, self).__init__(message)
        self.code = code


def _fail(code, detail):
    raise PostureError(detail, code=code)


_emit = None


def set_emit(emit):
    """Install an audit-event sink (dict -> None)."""
    global _emit
    _emit = emit


def _emit_event(event):
    """Emit an audit event to the installed sink. A broken audit sink
    must never break posture issuance or verification: the sink failure
    is isolated (the failure mode is recorded in this docstring/comment,
    not the event -- the same trade-off as ``gov/timestamp_authority.py``
    and ``gov/evidence_provenance.py``), never the sink's raw exception
    type escaping at a public seam (F346)."""
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


def _check_nonce(nonce):
    if not isinstance(nonce, (bytes, bytearray)) \
            or len(bytes(nonce)) < _MIN_NONCE_BYTES:
        _fail(NONCE_INVALID,
              "eat_nonce must be bytes of at least 64 bits "
              "(RFC 9711 minimum)")
    return bytes(nonce).hex()


def _check_software_id(software_id):
    if not isinstance(software_id, str) or not software_id:
        _fail(INVALID_SHAPE, "software_id must be a non-empty string")


def _check_config_digest(config_digest):
    if not _is_hex(config_digest, 64):
        _fail(INVALID_SHAPE, "config_digest must be a 64-hex digest")


def _check_submods(submods):
    """Validate submod nesting. Returns the normalized submod dict."""
    if not isinstance(submods, dict) or not submods:
        _fail(SUBMOD_INVALID,
              "submods must be a non-empty mapping of component name "
              "-> measurement")
    normalized = {}
    for name, meas in submods.items():
        if not isinstance(name, str) or not name:
            _fail(SUBMOD_INVALID, "submod name must be a non-empty string")
        if not isinstance(meas, dict):
            _fail(SUBMOD_INVALID,
                  "submod %r must be a mapping" % (name,))
        digest = meas.get("digest")
        if not _is_hex(digest, 64):
            _fail(SUBMOD_INVALID,
                  "submod %r digest must be a 64-hex digest" % (name,))
        entry = {"digest": digest.lower()}
        description = meas.get("description")
        if description is not None:
            if not isinstance(description, str):
                _fail(SUBMOD_INVALID,
                      "submod %r description must be a string" % (name,))
            entry["description"] = description
        normalized[name] = entry
    return normalized


def _check_endorsements(endorsements, producer_id):
    """Validate per-claim endorsement slots.

    Endorsements are REFERENCES to anchor-log positions, not inline
    trust. Every claim in _CLAIM_NAMES must have a slot; a slot sourced
    from the record's own producer refuses LOUD (endorsement must be
    separately sourced).
    """
    if not isinstance(endorsements, dict):
        _fail(ENDORSEMENT_MISSING, "endorsements must be a mapping")
    missing = [c for c in _CLAIM_NAMES if c not in endorsements]
    if missing:
        _fail(ENDORSEMENT_MISSING,
              "claims %r lack an endorsement slot" % (sorted(missing),))
    normalized = {}
    for name in _CLAIM_NAMES:
        slot = endorsements[name]
        if not isinstance(slot, dict):
            _fail(INVALID_SHAPE,
                  "endorsement slot %r must be a mapping" % (name,))
        for field in ("log_id", "log_index", "expected_digest",
                      "source_id"):
            if field not in slot:
                _fail(INVALID_SHAPE,
                      "endorsement slot %r missing field %r"
                      % (name, field))
        if not isinstance(slot["log_id"], str) or not slot["log_id"]:
            _fail(INVALID_SHAPE,
                  "endorsement slot %r log_id must be a non-empty string"
                  % (name,))
        if not isinstance(slot["log_index"], int) \
                or slot["log_index"] < 0:
            _fail(INVALID_SHAPE,
                  "endorsement slot %r log_index must be a non-negative "
                  "integer" % (name,))
        if not _is_hex(slot["expected_digest"], 64):
            _fail(INVALID_SHAPE,
                  "endorsement slot %r expected_digest must be a 64-hex "
                  "digest" % (name,))
        if not isinstance(slot["source_id"], str) or not slot["source_id"]:
            _fail(INVALID_SHAPE,
                  "endorsement slot %r source_id must be a non-empty "
                  "string" % (name,))
        if producer_id is not None and slot["source_id"] == producer_id:
            _fail(ENDORSEMENT_NOT_INDEPENDENT,
                  "endorsement slot %r is sourced from the record's own "
                  "producer -- endorsements must be separately sourced"
                  % (name,))
        normalized[name] = {
            "log_id": slot["log_id"],
            "log_index": slot["log_index"],
            "expected_digest": slot["expected_digest"].lower(),
            "source_id": slot["source_id"],
        }
    return normalized


def _sig_structure(protected, payload):
    return _canonical({
        "context": _SIG_CONTEXT,
        "protected": protected,
        "payload": payload,
    })


# ---------------------------------------------------------------------------
# Issuance
# ---------------------------------------------------------------------------

def issue_posture(*, operator_seed, operator_keyid, eat_nonce, submods,
                  software_id, config_digest, endorsements, tsa_token=None,
                  producer_id="operator"):
    """Issue a signed runtime-posture attestation record.

    ``eat_nonce`` must be verifier-supplied bytes of at least 64 bits
    (RFC 9711 minimum); the issuer refuses to mint without one, which
    binds the record to the appraisal request and prevents replay.
    ``submods`` maps component name -> {"digest": <64-hex>, ...}; every
    digest is covered by the signature, so substitution is detectable.
    ``endorsements`` must carry a separately-sourced anchor-log
    reference for every claim (software_id, config_digest, submods).

    ``tsa_token`` is an optional reference to a
    gov/timestamp_authority.py token that supplies freshness; this
    module invents no timestamping of its own.

    Returns the JSON-serializable record dict. All argument violations
    fail closed with coded ``posture-*`` refusals.
    """
    _check_operator_seed(operator_seed)
    _check_keyid(operator_keyid)
    nonce_hex = _check_nonce(eat_nonce)
    _check_software_id(software_id)
    _check_config_digest(config_digest)
    submods = _check_submods(submods)
    endorsements = _check_endorsements(endorsements, producer_id)
    if not isinstance(producer_id, str) or not producer_id:
        _fail(INVALID_SHAPE, "producer_id must be a non-empty string")
    if tsa_token is not None and not isinstance(tsa_token, dict):
        _fail(INVALID_SHAPE, "tsa_token must be a mapping or None")

    protected = {
        "alg": "EdDSA",
        "kid": operator_keyid,
        "posture_format": POSTURE_FORMAT,
    }
    # F350: the producer identity is part of the signed payload. A
    # verifier can therefore re-check endorsement independence at
    # verify time; independence is no longer issuance-only.
    payload = {
        "v": _POSTURE_VERSION,
        "eat_nonce": nonce_hex,
        "producer_id": producer_id,
        "submods": submods,
        "software_id": software_id,
        "config_digest": config_digest.lower(),
        "endorsements": endorsements,
    }
    if tsa_token is not None:
        payload["tsa_token"] = tsa_token

    sig_structure = _sig_structure(protected, payload)
    signature = _ed25519.sign(bytes(operator_seed), sig_structure).hex()
    record = {
        "posture_format": POSTURE_FORMAT,
        "protected": protected,
        "payload": payload,
        "signature": signature,
    }
    _emit_event({"event": "posture-issued",
                 "kid": operator_keyid,
                 "posture_digest": _digest(record),
                 "nonce": nonce_hex,
                 "submods": sorted(submods)})
    return record


# ---------------------------------------------------------------------------
# Verification (fail closed, coded)
# ---------------------------------------------------------------------------

def _require_record_shape(record):
    if not isinstance(record, dict):
        _fail(INVALID_SHAPE, "record must be a mapping")
    if record.get("posture_format") != POSTURE_FORMAT:
        _fail(INVALID_SHAPE,
              "record posture_format must be %r" % (POSTURE_FORMAT,))
    protected = record.get("protected")
    payload = record.get("payload")
    signature = record.get("signature")
    if not isinstance(protected, dict) or not isinstance(payload, dict):
        _fail(INVALID_SHAPE,
              "record must carry protected/payload mappings")
    if not isinstance(signature, str) or not signature:
        _fail(SIGNATURE_INVALID, "record carries no signature")
    return protected, payload, signature


def verify_posture(record, operator_pubkey_hex, *, expected_nonce=None,
                   now=None):
    """Verify a posture record against the pinned operator public key.

    Checks, in order: shape -> signature (``ok is not True`` refuses) ->
    nonce (>= 64 bits, and equal to ``expected_nonce`` when given, which
    binds the record to the appraisal request) -> submod entries ->
    endorsement slots (every claim has a separately-sourced slot), where
    the independence check uses the ``producer_id`` BOUND IN THE SIGNED
    PAYLOAD (F350) -- a record whose producer is missing, or whose
    endorsements are self-sourced, refuses coded. Records minted before
    the producer binding was added carry no ``producer_id`` and are
    refused as malformed: the binding is fail-closed, not best-effort.

    ``now`` is accepted for interface symmetry with the TSA module and
    is currently unused: this module performs no time checks of its own
    (freshness is the TSA token's job). Returns the verified payload.
    """
    _ = now  # documented: no clock in this module
    protected, payload, signature = _require_record_shape(record)
    if not _is_hex(operator_pubkey_hex, 64):
        _fail(INVALID_SHAPE,
              "operator_pubkey_hex must be a 64-hex Ed25519 public key")

    sig_structure = _sig_structure(protected, payload)
    ok = _ed25519.verify(bytes.fromhex(operator_pubkey_hex),
                        sig_structure, bytes.fromhex(signature))
    if ok is not True:
        _fail(SIGNATURE_INVALID,
              "operator signature did not verify -- record is forged "
              "or tampered")

    nonce_hex = payload.get("eat_nonce")
    if (not isinstance(nonce_hex, str)
            or len(nonce_hex) < 2 * _MIN_NONCE_BYTES
            or not all(c in _HEX for c in nonce_hex)):
        _fail(NONCE_INVALID,
              "eat_nonce must be at least 64 bits of hex")
    if expected_nonce is not None:
        want = (expected_nonce.hex()
                if isinstance(expected_nonce, (bytes, bytearray))
                else expected_nonce)
        if not isinstance(want, str) or want.lower() != nonce_hex.lower():
            _fail(NONCE_INVALID,
                  "eat_nonce does not match the appraisal request -- "
                  "possible replay")

    _check_software_id(payload.get("software_id"))
    _check_config_digest(payload.get("config_digest"))
    _check_submods(payload.get("submods"))
    # F350: endorsement independence is enforced on the VERIFY path
    # against the producer identity bound in the signed payload. A
    # hand-built operator-signed self-endorsed record (the F350 finding)
    # cannot pass: producer missing -> INVALID_SHAPE, self-sourced slot
    # -> ENDORSEMENT_NOT_INDEPENDENT.
    producer_id = payload.get("producer_id")
    if not isinstance(producer_id, str) or not producer_id:
        _fail(INVALID_SHAPE,
              "record payload must bind a non-empty producer_id "
              "(records minted before the F350 producer binding are "
              "refused)")
    _check_endorsements(payload.get("endorsements"), producer_id)
    return payload


# ---------------------------------------------------------------------------
# Composition: anchoring and the trust-vector seam
# ---------------------------------------------------------------------------

def posture_digest(record):
    """Content identity of a posture record (for anchoring)."""
    _require_record_shape(record)
    return _digest(record)


def anchor_posture(log, record, witness_policy=None, witness_seeds=None):
    """Anchor a posture record's digest like any other artifact.

    Thin wrapper over gov/evidence_anchor.anchor: the leaf is
    ``posture_digest(record)``. Witness cosigning flows through
    unchanged.
    """
    from gov import evidence_anchor as _ea
    return _ea.anchor(log, posture_digest(record),
                      witness_policy=witness_policy,
                      witness_seeds=witness_seeds)


def _ensure_scheme():
    from gov import trust_vector as _tv
    if SCHEME_ID in _tv.registered_schemes():
        return
    descriptor = _tv.SchemeDescriptor(
        SCHEME_ID,
        claim_grammar={
            "posture_digest": "digest",
            "software_id": "str",
            "config_digest": "digest",
            "submods_digest": "digest",
        },
        dimensions=[{
            "name": "posture-integrity",
            "rule": _tv.RULE_ENDORSED_MATCH,
            "claims": ["posture_digest", "software_id", "config_digest",
                       "submods_digest"],
        }],
    )
    _tv.register_scheme(descriptor)


_ensure_scheme()


def as_appraisal_evidence(record, producer_id):
    """Narrow seam for gov/trust_vector.py appraisal.

    Returns ``(claim_digest, scheme_id, endorsements)`` where
    ``claim_digest`` is the record's content digest, ``scheme_id`` is the
    registered ``runtime-posture/v1`` scheme, and ``endorsements`` is a
    list of ``{"claim_name", "expected_value", "source_id"}`` dicts drawn
    from the record's endorsement slots. The caller feeds these into
    ``trust_vector.submit_evidence`` / ``trust_vector.endorse`` /
    ``trust_vector.appraise``; this module never reaches into appraisal
    internals. Signature verification is the verifier's job
    (``verify_posture`` with the pinned operator key), not the seam's.
    """
    if not isinstance(record, dict) or "payload" not in record:
        _fail(INVALID_SHAPE, "record must be an issued posture record")
    if not isinstance(producer_id, str) or not producer_id:
        _fail(INVALID_SHAPE, "producer_id must be a non-empty string")
    payload = record.get("payload")
    # F351b class: endorsements.get on a non-dict raises a raw
    # AttributeError; payload.get on a non-dict the same. Refuse coded.
    if not isinstance(payload, dict):
        _fail(INVALID_SHAPE, "record must carry a payload mapping")
    endorsements = payload.get("endorsements", {})
    if not isinstance(endorsements, dict):
        _fail(ENDORSEMENT_MISSING, "endorsements must be a mapping")
    # Map record-internal claim names to the scheme's claim grammar.
    mapping = {
        "software_id": ("software_id", payload.get("software_id")),
        "config_digest": ("config_digest", payload.get("config_digest")),
        "submods": ("submods_digest", payload.get("submods")),
    }
    out = []
    for record_name, (scheme_name, value) in mapping.items():
        slot = endorsements.get(record_name)
        if not isinstance(slot, dict):
            _fail(ENDORSEMENT_MISSING,
                  "claim %r lacks an endorsement slot" % (record_name,))
        source_id = slot.get("source_id")
        if not isinstance(source_id, str) or not source_id:
            _fail(INVALID_SHAPE,
                  "endorsement slot %r needs a source_id string"
                  % (record_name,))
        # F351c class: a hand-mutated record can carry non-JSON values
        # whose digest raises a raw TypeError. Refuse coded.
        try:
            expected_value = _digest(value)
        except (TypeError, ValueError):
            _fail(SUBMOD_INVALID,
                  "claim %r value is not JSON-serializable" % (record_name,))
        out.append({
            "claim_name": scheme_name,
            "expected_value": expected_value,
            "source_id": source_id,
        })
    return (_digest(record), SCHEME_ID, out)
