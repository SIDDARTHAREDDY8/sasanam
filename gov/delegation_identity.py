"""Attested identity binding for delegation receipts (didkit/go-tpm-tools patterns).

Pattern lineage: spruceid/didkit (ADAPT, Apache-2.0 -- Trail-of-Bits audited
2022) -- the ``capabilityDelegation`` proof purpose: delegation chains as
signed, resolvable, OFFLINE-verifiable documents; the downstream agent's
evidence IS the chain. google/go-tpm-tools (ADAPT, Apache-2.0) -- the
client/server attestation split: the verifier never touches a TPM;
event-log replay as the pattern for the delegation log; hardware root
where it exists, ceremony transcript as the honest software fallback.
Mechanisms only; no vendored code; stdlib only.

Wave-298 design rule honored: *"Delegation narrows, never widens -- every
handoff is a signed, attenuated receipt on the chain."* This module binds
IDENTITY to each handoff: a receipt is only as good as the proof that its
signer was authorized to delegate. A receipt signed by a key the identity
document never authorized for delegation refuses coded
``delegation-identity-unauthorized-key``.

This module is a DECISION layer, like ``gov/supervision.py`` and
``gov/memory_reconcile.py``: ``verify_identity_evidence`` /
``verify_chain_offline`` return verification records; the actual
application (granting the sub-agent the capability) is deployment-owned
(lane 2, ``gov/delegation.py``, built in parallel this wave -- see
MERGE-SEAM below).

MERGE-SEAM (for the wave-299 merge coordinator -- lane 2 builds
``gov/delegation.py`` in parallel; this module deliberately does NOT
import it. The merge seam is a receipt-shape contract: this module
defines, consumes, and emits receipts in the shape
``delegation-receipt/v1``:

    {"schema": "delegation-receipt/v1",
     "receipt_id": <64 lowercase hex>,  # sha256 of the canonical
                                        # (from, to, scope_digest,
                                        #  not_before, not_after,
                                        #  parent_digest)
     "from": <agent id>,                # [a-z][a-z0-9-]{0,63}
     "to": <agent id>,
     "scope_digest": <64 lowercase hex>,  # WHAT is delegated (digest,
                                        # never the capability itself)
     "not_before": <non-negative int>,
     "not_after": <non-negative int>,     # not_before < not_after
     "parent_digest": <64 hex | None>,    # None for the root link
     "revocation_pointer": <64 hex | None>,  # optional; checked against
                                        # the deployment revocation list
     "identity_evidence": <identity-evidence/v1 | None>,
     "signature": <128 lowercase hex>}    # ed25519 over the canonical
                                        # JSON of the unsigned receipt
                                        # body, signed by FROM's key

WAVE-299 MERGE COMPOSITION: ``gov/delegation.py`` is the canonical
native receipt issuer. Its receipts do NOT use this module's local
10-field shape, and they do not need to:

* ``verify_identity_evidence`` takes the receipt digest and signer key
  as EXPLICIT parameters, so it composes directly: pass a native
  receipt's ``receipt_id`` and ``delegator_pubkey``.
* ``export_native_chain`` / ``verify_native_chain_offline`` (below)
  export and verify chains of native receipts, checking each native
  signature via ``gov/delegation.verify_chain`` (lazy import) and each
  entry's identity evidence via ``verify_identity_evidence``.

This module's local ``delegation-receipt/v1`` shape (``make_receipt``)
is retained for standalone use and for this module's own battery.

COMPOSITION with gov/decision_trace.py (documented, not wired -- this
module does not import decision_trace): a delegation link becomes a
trace edge via ``delegated_authority_edge``::

    {"kind": "delegated-authority",
     "from": <agent id>,
     "to": <agent id>,
     "receipt_digest": <64 lowercase hex>,
     "identity_evidence_digest": <64 lowercase hex>}

The decision-trace lane that ingests edges must accept edges whose
``kind`` is ``"delegated-authority"`` with exactly these four fields;
the digests let the offline evidence-bundle verifier re-resolve the
receipt and its identity evidence without the engine.

Identity evidence (``identity-evidence/v1``) has three methods:

* ``"did"`` -- the receipt signer is authorized by a DID document whose
  ``delegation_keys`` list names the keys allowed to delegate
  (didkit ``capabilityDelegation``). The evidence carries the DID, the
  document digest, and a controller proof binding the evidence to this
  receipt.
* ``"attestation"`` -- the receipt signer's key is attested. Where a TPM
  quote exists it may be attached; where none exists (this environment
  has no TPM -- and the module refuses to pretend otherwise) the evidence
  carries a SIGNED CEREMONY TRANSCRIPT (who generated the key, when, on
  what host class, witnessed by whom). ``claim_hardware`` without quote
  bytes refuses coded ``delegation-identity-false-hardware-claim`` --
  honest naming is enforced in code, not in comments.
* ``"key"`` -- bare public key, no authorization check. The weakest
  method, labeled as such in every verification record; deployment
  decides whether to accept it.

All refusals carry machine codes (the F351 contract). Timestamps are
freshness markers supplied by the caller. The audit sink is F345-class:
it never breaks the module; digests and ids only -- key material NEVER
reaches the sink.
"""

import hashlib
import json
from collections.abc import Mapping

from gov import ed25519


# ---------------------------------------------------------------------------
# Machine codes (registered in gov/decision_codes.py at true sorted
# positions; raw literals 1812/1812/0/sorted).; Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)
# ---------------------------------------------------------------------------

DI_INVALID = "delegation-identity-invalid"
DI_UNAUTHORIZED_KEY = "delegation-identity-unauthorized-key"
DI_FALSE_HARDWARE_CLAIM = "delegation-identity-false-hardware-claim"

# Pre-existing taxonomy codes this module reuses (no new literals minted
# for these refusal shapes).
_DELEGATION_CHAIN_BROKEN = "delegation-chain-broken"
_DELEGATION_EXPIRED = "delegation-expired"
_DELEGATION_SIGNATURE_INVALID = "delegation-signature-invalid"


# ---------------------------------------------------------------------------
# Errors (F351: every refusal carries a machine code).
# ---------------------------------------------------------------------------

class DelegationIdentityError(Exception):
    """Base class; carries the machine ``code`` so every refusal is coded."""

    code = DI_INVALID

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise DelegationIdentityError(detail, code=code)


# ---------------------------------------------------------------------------
# Audit sink (deployment chains these into the HMAC audit log).
# Digests and ids only -- key material NEVER reaches the sink.
# ---------------------------------------------------------------------------

_SINK = None


def set_sink(fn):
    """Install the audit sink callable (or None to disable). Never raises."""
    global _SINK
    _SINK = fn


def _emit(kind, **fields):
    if _SINK is None:
        return
    try:
        _SINK({"module": "delegation_identity", "kind": kind, **fields})
    except Exception:
        pass  # F345-class: the sink never breaks the module.


# ---------------------------------------------------------------------------
# Canonicalization / digests / shape helpers.
# ---------------------------------------------------------------------------

def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError):
        _fail(DI_INVALID, "not canonical-JSON-serializable")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _is_hex(s, length):
    return (isinstance(s, str) and len(s) == length
            and all(c in "0123456789abcdef" for c in s))


def _is_hex64(s):
    return _is_hex(s, 64)


def _is_hex128(s):
    return _is_hex(s, 128)


def _is_agent_id(s):
    return (isinstance(s, str) and 1 <= len(s) <= 64
            and s[0].islower() and s[0].isalpha()
            and all(c.islower() or c.isdigit() or c == "-" for c in s))


def _is_nonneg_int(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _check_ed25519_verify(pub_hex, msg, sig_hex):
    """Verify with the wave-243 contract: ``is True`` / ``is False``."""
    try:
        pub = bytes.fromhex(pub_hex)
        sig = bytes.fromhex(sig_hex)
    except (ValueError, TypeError):
        return False
    return ed25519.verify(pub, msg, sig) is True


def _pubkey_hex(seed):
    return ed25519.publickey(seed).hex()


def _sign_hex(seed, msg):
    return ed25519.sign(seed, msg).hex()


# ---------------------------------------------------------------------------
# DID documents (didkit capabilityDelegation pattern).
# ---------------------------------------------------------------------------

_DID_RE = None


def _did_ok(did):
    # did:<method>:<method-specific-id>, conservative charset.
    if not isinstance(did, str) or len(did) > 128:
        return False
    parts = did.split(":")
    if len(parts) != 3 or parts[0] != "did":
        return False
    method, msid = parts[1], parts[2]
    if not method or not all(c.islower() or c.isdigit() for c in method):
        return False
    return bool(msid) and all(c.isalnum() or c in "._-" for c in msid)


_DID_DOC_FIELDS = ("schema", "did", "controller_pubkey", "delegation_keys",
                   "created_at")


def issue_did_document(did, controller_seed, delegation_pubkeys, created_at,
                       sink_emit=True):
    """Issue a signed DID document naming which keys may delegate.

    ``controller_seed`` is the 32-byte seed of the controller key;
    ``delegation_pubkeys`` is the non-empty list of 64-hex public keys
    authorized for ``capabilityDelegation``. Returns the signed document.
    """
    if not _did_ok(did):
        _fail(DI_INVALID, "did document: malformed did")
    if not isinstance(controller_seed, (bytes, bytearray)) \
            or len(controller_seed) != 32:
        _fail(DI_INVALID, "did document: controller seed must be 32 bytes")
    if (not isinstance(delegation_pubkeys, list) or not delegation_pubkeys
            or any(not _is_hex64(k) for k in delegation_pubkeys)
            or len(set(delegation_pubkeys)) != len(delegation_pubkeys)):
        _fail(DI_INVALID,
              "did document: delegation_keys must be a non-empty list of "
              "unique 64-hex public keys")
    if not _is_nonneg_int(created_at):
        _fail(DI_INVALID, "did document: created_at must be a non-negative int")
    controller_pubkey = _pubkey_hex(bytes(controller_seed))
    body = {
        "schema": "identity-did-document/v1",
        "did": did,
        "controller_pubkey": controller_pubkey,
        "delegation_keys": list(delegation_pubkeys),
        "created_at": created_at,
    }
    doc = dict(body)
    doc["signature"] = _sign_hex(bytes(controller_seed), _canonical(body))
    if sink_emit:
        _emit("did_document_issued", did=did,
              doc_digest=did_document_digest(doc))
    return doc


def did_document_digest(doc):
    """Digest of a DID document over its canonical UNSIGNED body."""
    if not isinstance(doc, dict):
        _fail(DI_INVALID, "did document: not a dict")
    body = {k: doc[k] for k in _DID_DOC_FIELDS if k in doc}
    return _sha256_hex(_canonical(body))


def verify_did_document(doc):
    """Verify shape + controller signature of a DID document.

    Returns the document digest. Refuses coded on any failure.
    """
    if not isinstance(doc, dict):
        _fail(DI_INVALID, "did document: not a dict")
    if doc.get("schema") != "identity-did-document/v1":
        _fail(DI_INVALID, "did document: bad schema")
    did = doc.get("did")
    controller_pubkey = doc.get("controller_pubkey")
    delegation_keys = doc.get("delegation_keys")
    created_at = doc.get("created_at")
    signature = doc.get("signature")
    if not _did_ok(did):
        _fail(DI_INVALID, "did document: malformed did")
    if not _is_hex64(controller_pubkey):
        _fail(DI_INVALID, "did document: malformed controller_pubkey")
    if (not isinstance(delegation_keys, list) or not delegation_keys
            or any(not _is_hex64(k) for k in delegation_keys)):
        _fail(DI_INVALID, "did document: malformed delegation_keys")
    if not _is_nonneg_int(created_at):
        _fail(DI_INVALID, "did document: malformed created_at")
    if not _is_hex128(signature):
        _fail(DI_INVALID, "did document: malformed signature")
    body = {k: doc[k] for k in _DID_DOC_FIELDS}
    if _check_ed25519_verify(controller_pubkey, _canonical(body),
                             signature) is not True:
        _fail(DI_INVALID, "did document: controller signature invalid")
    return did_document_digest(doc)


# ---------------------------------------------------------------------------
# Identity evidence (identity-evidence/v1).
# ---------------------------------------------------------------------------

_EVIDENCE_FIELDS = ("schema", "method", "did", "did_document_digest",
                    "attestation", "pubkey")

_ATTESTATION_FIELDS = ("claim_hardware", "quote_bytes",
                       "ceremony_transcript")

_TRANSCRIPT_FIELDS = ("generated_by", "generator_pubkey", "generated_at",
                      "host_class", "witnessed_by", "witness_signatures")

_HOST_CLASSES = ("tpm2-hardware", "tee-hardware", "hsm-hardware",
                 "software-ceremony")


def _check_transcript(transcript):
    if not isinstance(transcript, dict):
        _fail(DI_INVALID, "attestation: ceremony_transcript not a dict")
    for field in ("generated_by", "generator_pubkey", "generated_at",
                  "host_class", "witnessed_by"):
        if field not in transcript:
            _fail(DI_INVALID,
                  "attestation: ceremony_transcript missing " + field)
    if not _is_agent_id(transcript["generated_by"]):
        _fail(DI_INVALID, "attestation: malformed generated_by")
    if not _is_hex64(transcript["generator_pubkey"]):
        _fail(DI_INVALID, "attestation: malformed generator_pubkey")
    if not _is_nonneg_int(transcript["generated_at"]):
        _fail(DI_INVALID, "attestation: malformed generated_at")
    if transcript["host_class"] not in _HOST_CLASSES:
        _fail(DI_INVALID, "attestation: unknown host_class")
    if (not isinstance(transcript["witnessed_by"], list)
            or not transcript["witnessed_by"]
            or any(not _is_agent_id(w) for w in transcript["witnessed_by"])):
        _fail(DI_INVALID, "attestation: malformed witnessed_by")
    sigs = transcript.get("witness_signatures")
    if not isinstance(sigs, list) or not sigs:
        _fail(DI_INVALID, "attestation: missing witness_signatures")
    body = {k: transcript[k] for k in _TRANSCRIPT_FIELDS
            if k != "witness_signatures"}
    seen = set()
    for entry in sigs:
        if not isinstance(entry, dict):
            _fail(DI_INVALID, "attestation: malformed witness signature")
        witness = entry.get("witness")
        pubkey = entry.get("pubkey")
        signature = entry.get("signature")
        if not _is_agent_id(witness) or not _is_hex64(pubkey) \
                or not _is_hex128(signature):
            _fail(DI_INVALID, "attestation: malformed witness signature")
        if witness in seen:
            _fail(DI_INVALID, "attestation: duplicate witness signature")
        seen.add(witness)
        if _check_ed25519_verify(pubkey, _canonical(body),
                                 signature) is not True:
            _fail(DI_INVALID,
                  "attestation: witness signature invalid for " + witness)
    # The witness set must cover the declared witnessed_by list.
    if not set(transcript["witnessed_by"]) <= seen:
        _fail(DI_INVALID,
              "attestation: witnessed_by not covered by signatures")


def make_ceremony_transcript(generated_by, generator_seed, generated_at,
                             host_class, witnesses):
    """Build a signed ceremony transcript.

    ``witnesses`` is a list of (witness_agent_id, witness_seed) tuples;
    every witness signs the transcript body. The generator key is derived
    from ``generator_seed``. Returns the transcript dict (unsigned
    envelope -- the signatures live inside ``witness_signatures``).
    """
    if not _is_agent_id(generated_by):
        _fail(DI_INVALID, "transcript: malformed generated_by")
    if not isinstance(generator_seed, (bytes, bytearray)) \
            or len(generator_seed) != 32:
        _fail(DI_INVALID, "transcript: generator seed must be 32 bytes")
    if not _is_nonneg_int(generated_at):
        _fail(DI_INVALID, "transcript: malformed generated_at")
    if host_class not in _HOST_CLASSES:
        _fail(DI_INVALID, "transcript: unknown host_class")
    if (not isinstance(witnesses, list) or not witnesses
            or any(not (isinstance(w, tuple) and len(w) == 2
                        and _is_agent_id(w[0])
                        and isinstance(w[1], (bytes, bytearray))
                        and len(w[1]) == 32) for w in witnesses)):
        _fail(DI_INVALID, "transcript: witnesses must be a non-empty list "
                          "of (agent_id, 32-byte seed)")
    body = {
        "generated_by": generated_by,
        "generator_pubkey": _pubkey_hex(bytes(generator_seed)),
        "generated_at": generated_at,
        "host_class": host_class,
        "witnessed_by": [w[0] for w in witnesses],
    }
    transcript = dict(body)
    transcript["witness_signatures"] = [
        {"witness": wid,
         "pubkey": _pubkey_hex(bytes(wseed)),
         "signature": _sign_hex(bytes(wseed), _canonical(body))}
        for wid, wseed in witnesses
    ]
    return transcript


def make_identity_evidence(method, receipt_digest, **kwargs):
    """Build an identity-evidence/v1 block for a receipt digest.

    method "did": kwargs = did, did_document_digest, controller_seed
      (the DID controller signs the binding proof).
    method "attestation": kwargs = ceremony_transcript,
      claim_hardware=False, quote_bytes=None. ``claim_hardware=True``
      with no quote bytes is refused HERE (honest naming, fail fast).
    method "key": kwargs = pubkey (the signer's bare key; weakest).
    """
    if not _is_hex64(receipt_digest):
        _fail(DI_INVALID, "evidence: malformed receipt_digest")
    if method == "did":
        did = kwargs.get("did")
        doc_digest = kwargs.get("did_document_digest")
        controller_seed = kwargs.get("controller_seed")
        if not _did_ok(did) or not _is_hex64(doc_digest):
            _fail(DI_INVALID, "evidence(did): malformed did or digest")
        if not isinstance(controller_seed, (bytes, bytearray)) \
                or len(controller_seed) != 32:
            _fail(DI_INVALID, "evidence(did): controller seed invalid")
        controller_pubkey = _pubkey_hex(bytes(controller_seed))
        binding = {"receipt_digest": receipt_digest, "did": did,
                   "did_document_digest": doc_digest}
        evidence = {
            "schema": "identity-evidence/v1",
            "method": "did",
            "did": did,
            "did_document_digest": doc_digest,
            "controller_proof": {
                "controller_pubkey": controller_pubkey,
                "signature": _sign_hex(bytes(controller_seed),
                                       _canonical(binding)),
            },
        }
    elif method == "attestation":
        transcript = kwargs.get("ceremony_transcript")
        claim_hardware = kwargs.get("claim_hardware", False)
        quote_bytes = kwargs.get("quote_bytes")
        if claim_hardware is True and not quote_bytes:
            # Honest naming enforced in code: a hardware claim without a
            # real quote path is a lie the module refuses to tell.
            _fail(DI_FALSE_HARDWARE_CLAIM,
                  "evidence(attestation): claim_hardware without quote bytes")
        if claim_hardware is not True and claim_hardware is not False:
            _fail(DI_INVALID, "evidence(attestation): claim_hardware not bool")
        if quote_bytes is not None and not isinstance(quote_bytes, str):
            _fail(DI_INVALID, "evidence(attestation): malformed quote_bytes")
        _check_transcript(transcript)  # raises coded on any failure
        evidence = {
            "schema": "identity-evidence/v1",
            "method": "attestation",
            "attestation": {
                "claim_hardware": bool(claim_hardware),
                "quote_bytes": quote_bytes,
                "ceremony_transcript": transcript,
            },
        }
    elif method == "key":
        pubkey = kwargs.get("pubkey")
        if not _is_hex64(pubkey):
            _fail(DI_INVALID, "evidence(key): malformed pubkey")
        evidence = {
            "schema": "identity-evidence/v1",
            "method": "key",
            "pubkey": pubkey,
        }
    else:
        _fail(DI_INVALID, "evidence: unknown method")
    _emit("identity_evidence_made", method=method,
          evidence_digest=_sha256_hex(_canonical(evidence)))
    return evidence


def evidence_digest(evidence):
    """Digest of an identity-evidence block (for trace edges)."""
    if not isinstance(evidence, dict):
        _fail(DI_INVALID, "evidence: not a dict")
    return _sha256_hex(_canonical(evidence))


# ---------------------------------------------------------------------------
# Receipt contract (delegation-receipt/v1) -- the MERGE-SEAM shape.
# ---------------------------------------------------------------------------

_RECEIPT_BODY_FIELDS = ("schema", "receipt_id", "from", "to",
                        "scope_digest", "not_before", "not_after",
                        "parent_digest", "revocation_pointer",
                        "identity_evidence")

# The receipt_id binds exactly these fields (identity evidence attaches
# after issuance without changing the receipt's identity).
_RECEIPT_ID_FIELDS = ("from", "to", "scope_digest", "not_before",
                      "not_after", "parent_digest")


def receipt_digest(receipt):
    """Digest of a receipt over its canonical UNSIGNED identity fields."""
    if not isinstance(receipt, dict):
        _fail(DI_INVALID, "receipt: not a dict")
    body = {k: receipt[k] for k in _RECEIPT_ID_FIELDS if k in receipt}
    return _sha256_hex(_canonical(body))


def make_receipt(from_id, to_id, scope_digest, from_seed, not_before,
                 not_after, parent_digest=None, revocation_pointer=None,
                 identity_evidence=None, from_pubkey=None):
    """Issue a delegation receipt signed by FROM's key.

    ``identity_evidence`` (optional) is an identity-evidence/v1 block;
    when present, lane 2's merge seam requires the evidence's signer
    authorization to be verified via ``verify_identity_evidence`` before
    the receipt is honored.
    """
    if not _is_agent_id(from_id) or not _is_agent_id(to_id):
        _fail(DI_INVALID, "receipt: malformed from/to")
    if not _is_hex64(scope_digest):
        _fail(DI_INVALID, "receipt: malformed scope_digest")
    if not isinstance(from_seed, (bytes, bytearray)) \
            or len(from_seed) != 32:
        _fail(DI_INVALID, "receipt: from seed must be 32 bytes")
    if not _is_nonneg_int(not_before) or not _is_nonneg_int(not_after) \
            or not not_before < not_after:
        _fail(DI_INVALID, "receipt: not_before < not_after required")
    if parent_digest is not None and not _is_hex64(parent_digest):
        _fail(DI_INVALID, "receipt: malformed parent_digest")
    if revocation_pointer is not None and not _is_hex64(revocation_pointer):
        _fail(DI_INVALID, "receipt: malformed revocation_pointer")
    if identity_evidence is not None:
        if not isinstance(identity_evidence, dict) or \
                identity_evidence.get("schema") != "identity-evidence/v1":
            _fail(DI_INVALID, "receipt: malformed identity_evidence")
    if from_pubkey is not None and from_pubkey != _pubkey_hex(bytes(from_seed)):
        _fail(DI_INVALID, "receipt: from_pubkey does not match from_seed")
    receipt_id = _sha256_hex(_canonical({
        k: v for k, v in (("from", from_id), ("to", to_id),
                          ("scope_digest", scope_digest),
                          ("not_before", not_before),
                          ("not_after", not_after),
                          ("parent_digest", parent_digest))
    }))
    body = {
        "schema": "delegation-receipt/v1",
        "receipt_id": receipt_id,
        "from": from_id,
        "to": to_id,
        "scope_digest": scope_digest,
        "not_before": not_before,
        "not_after": not_after,
        "parent_digest": parent_digest,
        "revocation_pointer": revocation_pointer,
        "identity_evidence": identity_evidence,
    }
    receipt = dict(body)
    receipt["signature"] = _sign_hex(bytes(from_seed), _canonical(body))
    _emit("receipt_issued", receipt_digest=receipt_id, from_id=from_id,
          to_id=to_id)
    return receipt


def _check_receipt_shape(receipt):
    if not isinstance(receipt, dict):
        _fail(DI_INVALID, "receipt: not a dict")
    if receipt.get("schema") != "delegation-receipt/v1":
        _fail(DI_INVALID, "receipt: bad schema")
    if not _is_hex64(receipt.get("receipt_id")):
        _fail(DI_INVALID, "receipt: malformed receipt_id")
    if not _is_agent_id(receipt.get("from")) \
            or not _is_agent_id(receipt.get("to")):
        _fail(DI_INVALID, "receipt: malformed from/to")
    if not _is_hex64(receipt.get("scope_digest")):
        _fail(DI_INVALID, "receipt: malformed scope_digest")
    not_before = receipt.get("not_before")
    not_after = receipt.get("not_after")
    if not _is_nonneg_int(not_before) or not _is_nonneg_int(not_after) \
            or not not_before < not_after:
        _fail(DI_INVALID, "receipt: not_before < not_after required")
    parent_digest = receipt.get("parent_digest")
    if parent_digest is not None and not _is_hex64(parent_digest):
        _fail(DI_INVALID, "receipt: malformed parent_digest")
    revocation_pointer = receipt.get("revocation_pointer")
    if revocation_pointer is not None \
            and not _is_hex64(revocation_pointer):
        _fail(DI_INVALID, "receipt: malformed revocation_pointer")
    evidence = receipt.get("identity_evidence")
    if evidence is not None and (
            not isinstance(evidence, dict)
            or evidence.get("schema") != "identity-evidence/v1"):
        _fail(DI_INVALID, "receipt: malformed identity_evidence")
    if not _is_hex128(receipt.get("signature")):
        _fail(DI_INVALID, "receipt: malformed signature")
    # receipt_id must be the digest of the unsigned body (binding check).
    if receipt_digest(receipt) != receipt["receipt_id"]:
        _fail(DI_INVALID, "receipt: receipt_id does not match body digest")


# ---------------------------------------------------------------------------
# Identity evidence verification.
# ---------------------------------------------------------------------------

def verify_identity_evidence(evidence, receipt_digest_hex,
                             receipt_signer_pubkey, trusted_did_docs):
    """Verify an identity-evidence/v1 block for a receipt.

    ``receipt_digest_hex`` is the digest of the receipt the evidence is
    attached to; ``receipt_signer_pubkey`` is the 64-hex key that signed
    the receipt; ``trusted_did_docs`` maps did -> verified DID document
    (the caller's trust roots -- no engine state is consulted).

    Returns a verification record describing what was proven. Every
    failure refuses coded.
    """
    if not isinstance(evidence, dict):
        _fail(DI_INVALID, "evidence: not a dict")
    if evidence.get("schema") != "identity-evidence/v1":
        _fail(DI_INVALID, "evidence: bad schema")
    if not _is_hex64(receipt_digest_hex):
        _fail(DI_INVALID, "evidence: malformed receipt_digest")
    if not _is_hex64(receipt_signer_pubkey):
        _fail(DI_INVALID, "evidence: malformed receipt_signer_pubkey")
    if not isinstance(trusted_did_docs, dict):
        _fail(DI_INVALID, "evidence: trusted_did_docs not a dict")
    method = evidence.get("method")

    if method == "did":
        did = evidence.get("did")
        doc_digest = evidence.get("did_document_digest")
        proof = evidence.get("controller_proof")
        if not _did_ok(did) or not _is_hex64(doc_digest):
            _fail(DI_INVALID, "evidence(did): malformed did or digest")
        if did not in trusted_did_docs:
            _fail(DI_UNAUTHORIZED_KEY,
                  "evidence(did): did is not a trusted identity")
        doc = trusted_did_docs[did]
        # The caller's roots are verified here, not trusted blindly.
        if verify_did_document(doc) != doc_digest:
            _fail(DI_INVALID,
                  "evidence(did): did document digest mismatch")
        if doc["did"] != did:
            _fail(DI_INVALID, "evidence(did): did document did mismatch")
        if not isinstance(proof, dict):
            _fail(DI_INVALID, "evidence(did): missing controller_proof")
        controller_pubkey = proof.get("controller_pubkey")
        signature = proof.get("signature")
        if controller_pubkey != doc["controller_pubkey"] \
                or not _is_hex128(signature):
            _fail(DI_INVALID,
                  "evidence(did): controller_proof not from the "
                  "document controller")
        binding = {"receipt_digest": receipt_digest_hex, "did": did,
                   "did_document_digest": doc_digest}
        if _check_ed25519_verify(controller_pubkey, _canonical(binding),
                                 signature) is not True:
            _fail(DI_INVALID,
                  "evidence(did): controller_proof signature invalid")
        # The capabilityDelegation check: the receipt signer must be one
        # of the keys the DID document authorizes to delegate.
        if receipt_signer_pubkey not in doc["delegation_keys"]:
            _fail(DI_UNAUTHORIZED_KEY,
                  "evidence(did): receipt signer is not authorized for "
                  "delegation by " + did)
        _emit("identity_verified", method="did", did=did,
              evidence_digest=evidence_digest(evidence))
        return {"verified": True, "method": "did", "did": did,
                "controller": controller_pubkey,
                "authorization": "capabilityDelegation"}

    if method == "attestation":
        attestation = evidence.get("attestation")
        if not isinstance(attestation, dict):
            _fail(DI_INVALID, "evidence(attestation): malformed")
        claim_hardware = attestation.get("claim_hardware")
        quote_bytes = attestation.get("quote_bytes")
        # Honest naming, checked before any signature work: a hardware
        # claim without a real quote path is refused loud.
        if claim_hardware is True and not quote_bytes:
            _fail(DI_FALSE_HARDWARE_CLAIM,
                  "evidence(attestation): claim_hardware without quote bytes")
        if claim_hardware not in (True, False):
            _fail(DI_INVALID,
                  "evidence(attestation): claim_hardware not bool")
        if quote_bytes is not None and not isinstance(quote_bytes, str):
            _fail(DI_INVALID, "evidence(attestation): malformed quote_bytes")
        transcript = attestation.get("ceremony_transcript")
        _check_transcript(transcript)
        # The attested key is the receipt signer: the ceremony must be
        # ABOUT the key that signed the receipt.
        if transcript["generator_pubkey"] != receipt_signer_pubkey:
            _fail(DI_UNAUTHORIZED_KEY,
                  "evidence(attestation): transcript is not about the "
                  "receipt signer")
        label = ("hardware-attested"
                 if claim_hardware is True else "software-ceremony")
        _emit("identity_verified", method="attestation", label=label,
              evidence_digest=evidence_digest(evidence))
        return {"verified": True, "method": "attestation",
                "label": label,
                "witnesses": list(transcript["witnessed_by"])}

    if method == "key":
        pubkey = evidence.get("pubkey")
        if not _is_hex64(pubkey):
            _fail(DI_INVALID, "evidence(key): malformed pubkey")
        if pubkey != receipt_signer_pubkey:
            _fail(DI_UNAUTHORIZED_KEY,
                  "evidence(key): pubkey does not match receipt signer")
        _emit("identity_verified", method="key",
              evidence_digest=evidence_digest(evidence))
        return {"verified": True, "method": "key",
                "label": "unattested-bare-key"}

    _fail(DI_INVALID, "evidence: unknown method")


# ---------------------------------------------------------------------------
# Offline chain export / verification (didkit chain-document pattern).
# ---------------------------------------------------------------------------

_CHAIN_BODY_FIELDS = ("schema", "exported_at", "exporter_pubkey", "links")


def export_chain(entries, exporter_seed, exported_at):
    """Export a delegation chain as a self-contained signed document.

    ``entries`` is a list of {"receipt": receipt, "from_pubkey": hex,
    "did_documents": {did: doc}} in chain order (root first). Every
    receipt signature, parent linkage, and identity evidence is verified
    at export time; the exported document then verifies OFFLINE via
    ``verify_chain_offline`` -- the downstream agent's evidence IS the
    chain (offline evidence-bundle discipline).

    Returns the signed chain document.
    """
    if not isinstance(entries, list) or not entries:
        _fail(DI_INVALID, "chain: entries must be a non-empty list")
    if not isinstance(exporter_seed, (bytes, bytearray)) \
            or len(exporter_seed) != 32:
        _fail(DI_INVALID, "chain: exporter seed must be 32 bytes")
    if not _is_nonneg_int(exported_at):
        _fail(DI_INVALID, "chain: malformed exported_at")
    links = []
    expected_parent = None
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            _fail(DI_INVALID, "chain: entry %d not a dict" % index)
        receipt = entry.get("receipt")
        from_pubkey = entry.get("from_pubkey")
        did_documents = entry.get("did_documents", {})
        _check_receipt_shape(receipt)
        if not _is_hex64(from_pubkey):
            _fail(DI_INVALID, "chain: entry %d malformed from_pubkey"
                  % index)
        if not isinstance(did_documents, dict):
            _fail(DI_INVALID, "chain: entry %d malformed did_documents"
                  % index)
        body = {k: receipt[k] for k in _RECEIPT_BODY_FIELDS}
        if _check_ed25519_verify(from_pubkey, _canonical(body),
                                 receipt["signature"]) is not True:
            _fail(_DELEGATION_SIGNATURE_INVALID,
                  "chain: entry %d receipt signature invalid" % index)
        if receipt["parent_digest"] != expected_parent:
            _fail(_DELEGATION_CHAIN_BROKEN,
                  "chain: entry %d parent linkage broken" % index)
        evidence = receipt.get("identity_evidence")
        if evidence is not None:
            verify_identity_evidence(evidence, receipt["receipt_id"],
                                     from_pubkey, did_documents)
        for did, doc in did_documents.items():
            verify_did_document(doc)
            if doc["did"] != did:
                _fail(DI_INVALID,
                      "chain: entry %d did document key mismatch" % index)
        expected_parent = receipt["receipt_id"]
        links.append({
            "receipt": receipt,
            "from_pubkey": from_pubkey,
            "did_documents": dict(did_documents),
        })
    chain_body = {
        "schema": "delegation-chain/v1",
        "exported_at": exported_at,
        "exporter_pubkey": _pubkey_hex(bytes(exporter_seed)),
        "links": links,
    }
    chain_doc = dict(chain_body)
    chain_doc["chain_signature"] = _sign_hex(bytes(exporter_seed),
                                             _canonical(chain_body))
    _emit("chain_exported", depth=len(links),
          leaf=links[-1]["receipt"]["to"])
    return chain_doc


def verify_chain_offline(chain_doc, at, trusted_did_docs):
    """Verify an exported chain document with NO engine state.

    ``at`` is the caller-supplied verification instant; ``trusted_did_docs``
    maps did -> DID document (the verifier's own trust roots). Every link,
    signature, parent binding, time window, and identity evidence is
    re-verified from the document alone. Returns a verification record.
    """
    if not isinstance(chain_doc, dict):
        _fail(DI_INVALID, "chain: not a dict")
    if chain_doc.get("schema") != "delegation-chain/v1":
        _fail(DI_INVALID, "chain: bad schema")
    exporter_pubkey = chain_doc.get("exporter_pubkey")
    chain_signature = chain_doc.get("chain_signature")
    links = chain_doc.get("links")
    exported_at = chain_doc.get("exported_at")
    if not _is_hex64(exporter_pubkey) or not _is_hex128(chain_signature):
        _fail(DI_INVALID, "chain: malformed exporter/signature")
    if not isinstance(links, list) or not links:
        _fail(DI_INVALID, "chain: no links")
    if not _is_nonneg_int(exported_at) or not _is_nonneg_int(at):
        _fail(DI_INVALID, "chain: malformed instants")
    chain_body = {k: chain_doc[k] for k in _CHAIN_BODY_FIELDS}
    if _check_ed25519_verify(exporter_pubkey, _canonical(chain_body),
                             chain_signature) is not True:
        _fail(_DELEGATION_SIGNATURE_INVALID,
              "chain: exporter signature invalid")
    expected_parent = None
    for index, link in enumerate(links):
        if not isinstance(link, dict):
            _fail(DI_INVALID, "chain: link %d not a dict" % index)
        receipt = link.get("receipt")
        from_pubkey = link.get("from_pubkey")
        embedded_docs = link.get("did_documents", {})
        _check_receipt_shape(receipt)
        if not _is_hex64(from_pubkey):
            _fail(DI_INVALID, "chain: link %d malformed from_pubkey"
                  % index)
        body = {k: receipt[k] for k in _RECEIPT_BODY_FIELDS}
        if _check_ed25519_verify(from_pubkey, _canonical(body),
                                 receipt["signature"]) is not True:
            _fail(_DELEGATION_SIGNATURE_INVALID,
                  "chain: link %d receipt signature invalid" % index)
        if receipt["parent_digest"] != expected_parent:
            _fail(_DELEGATION_CHAIN_BROKEN,
                  "chain: link %d parent linkage broken" % index)
        if not receipt["not_before"] <= at < receipt["not_after"]:
            _fail(_DELEGATION_EXPIRED,
                  "chain: link %d outside its time window" % index)
        # Trust roots: the verifier's OWN pinned roots are authoritative.
        # Embedded documents are untrusted claims: they may fill in for
        # DIDs the verifier never pinned, but they NEVER silently replace
        # a pinned root (F377). A conflicting embedded document for a
        # pinned DID is a substitution attempt and refuses coded.
        roots = dict(trusted_did_docs) if isinstance(trusted_did_docs,
                                                    dict) else {}
        if not isinstance(embedded_docs, dict):
            _fail(DI_INVALID, "chain: link %d malformed did_documents"
                  % index)
        for did, doc in embedded_docs.items():
            verify_did_document(doc)
            if doc["did"] != did:
                _fail(DI_INVALID,
                      "chain: link %d embedded did mismatch" % index)
            if did in roots:
                if did_document_digest(doc) != did_document_digest(
                        roots[did]):
                    _fail(DI_INVALID,
                          "chain: link %d embedded did document conflicts "
                          "with the verifier's pinned trust root" % index)
                # Digests match: the embedded copy is redundant; the
                # pinned root stays authoritative.
            else:
                roots[did] = doc
        evidence = receipt.get("identity_evidence")
        if evidence is not None:
            verify_identity_evidence(evidence, receipt["receipt_id"],
                                     from_pubkey, roots)
        expected_parent = receipt["receipt_id"]
    leaf = links[-1]["receipt"]["to"]
    _emit("chain_verified_offline", depth=len(links), leaf=leaf)
    return {"verified": True, "depth": len(links), "leaf": leaf,
            "root": links[0]["receipt"]["from"],
            "offline": True}


# ---------------------------------------------------------------------------
# Wave-299 merge composition: gov/delegation.py NATIVE receipt chains.
# ---------------------------------------------------------------------------
# The canonical delegation receipt is issued by ``gov/delegation.py``.
# Its shape differs from this module's local ``delegation-receipt/v1``
# (kept for standalone use). The functions below compose the two:
# native receipts carry their own signatures (verified with
# ``gov.delegation.verify_chain`` via lazy import -- delegation never
# imports this module, so there is no cycle); identity evidence is
# verified with ``verify_identity_evidence`` against the native
# receipt's own ``receipt_id`` and ``delegator_pubkey``.

_NATIVE_CHAIN_SCHEMA = "delegation-native-chain/v1"


def _to_plain(value):
    """Recursively convert mappings to plain dicts for JSON serialization.

    Native receipts are frozen ``MappingProxyType``s; the chain document
    must be canonical-JSON-serializable, so mappings become dicts.
    (Lane-2 receipts already store rights as sorted lists and
    constraints as plain dicts, so no value transformation is needed --
    only the mapping wrappers.)
    """
    if isinstance(value, Mapping):
        return {k: _to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_plain(v) for v in value]
    return value


def export_native_chain(entries, exporter_seed, exported_at, at,
                        trust_roots):
    """Export a ``gov/delegation.py`` native receipt chain as a signed document.

    ``entries`` is a list of ``{"receipt": native_receipt,
    "identity_evidence": evidence-or-None, "did_documents": {did: doc}}``
    in chain order (root first). Every native receipt signature and the
    parent linkage are verified with ``gov/delegation.verify_chain``;
    each entry's identity evidence (when present) is verified with
    ``verify_identity_evidence`` against that receipt's own
    ``receipt_id`` / ``delegator_pubkey``. The exported document then
    verifies OFFLINE via ``verify_native_chain_offline``.

    Returns the signed chain document.
    """
    from gov import delegation as _dg  # lazy: delegation never imports this module
    if not isinstance(entries, list) or not entries:
        _fail(DI_INVALID, "native chain: entries must be a non-empty list")
    if not isinstance(exporter_seed, (bytes, bytearray)) \
            or len(exporter_seed) != 32:
        _fail(DI_INVALID, "native chain: exporter seed must be 32 bytes")
    if not _is_nonneg_int(exported_at) or not _is_nonneg_int(at):
        _fail(DI_INVALID, "native chain: malformed instants")
    receipts = []
    links = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            _fail(DI_INVALID, "native chain: entry %d not a dict" % index)
        receipt = entry.get("receipt")
        evidence = entry.get("identity_evidence")
        did_documents = entry.get("did_documents", {})
        if not isinstance(receipt, Mapping):
            _fail(DI_INVALID, "native chain: entry %d has no receipt"
                  % index)
        if not isinstance(did_documents, dict):
            _fail(DI_INVALID, "native chain: entry %d malformed did_documents"
                  % index)
        receipts.append(receipt)
        if evidence is not None:
            verify_identity_evidence(evidence, receipt["receipt_id"],
                                     receipt["delegator_pubkey"],
                                     did_documents)
        links.append({
            "receipt": _to_plain(receipt),
            "identity_evidence": _to_plain(evidence)
            if evidence is not None else None,
            "did_documents": _to_plain(did_documents),
        })
    # One native verification pass: signatures, linkage, narrowing, expiry.
    _dg.verify_chain(receipts[-1], receipts, at=at, trust_roots=trust_roots)
    chain_body = {
        "schema": _NATIVE_CHAIN_SCHEMA,
        "exported_at": exported_at,
        "exporter_pubkey": _pubkey_hex(bytes(exporter_seed)),
        "links": links,
    }
    chain_doc = dict(chain_body)
    chain_doc["chain_signature"] = _sign_hex(bytes(exporter_seed),
                                            _canonical(chain_body))
    _emit("native_chain_exported", depth=len(links),
          leaf=links[-1]["receipt"]["receipt_id"][:16])
    return chain_doc


def verify_native_chain_offline(chain_doc, at, trusted_did_docs,
                                trust_roots):
    """Verify an exported native chain document with NO engine state.

    ``trusted_did_docs`` maps did -> DID document (the verifier's own
    trust roots); ``trust_roots`` are the accepted native root
    delegator pubkeys (hex). Every native signature, parent binding,
    time window, and identity evidence is re-verified from the document
    alone. Returns a verification record.
    """
    from gov import delegation as _dg  # lazy: delegation never imports this module
    if not isinstance(chain_doc, dict):
        _fail(DI_INVALID, "native chain: not a dict")
    if chain_doc.get("schema") != _NATIVE_CHAIN_SCHEMA:
        _fail(DI_INVALID, "native chain: bad schema")
    exporter_pubkey = chain_doc.get("exporter_pubkey")
    chain_signature = chain_doc.get("chain_signature")
    links = chain_doc.get("links")
    exported_at = chain_doc.get("exported_at")
    if not _is_hex64(exporter_pubkey) or not _is_hex128(chain_signature):
        _fail(DI_INVALID, "native chain: malformed exporter/signature")
    if not isinstance(links, list) or not links:
        _fail(DI_INVALID, "native chain: no links")
    if not _is_nonneg_int(exported_at) or not _is_nonneg_int(at):
        _fail(DI_INVALID, "native chain: malformed instants")
    chain_body = {k: chain_doc[k] for k in _CHAIN_BODY_FIELDS}
    if _check_ed25519_verify(exporter_pubkey, _canonical(chain_body),
                             chain_signature) is not True:
        _fail(_DELEGATION_SIGNATURE_INVALID,
              "native chain: exporter signature invalid")
    receipts = []
    for index, link in enumerate(links):
        if not isinstance(link, dict):
            _fail(DI_INVALID, "native chain: link %d not a dict" % index)
        receipt = link.get("receipt")
        evidence = link.get("identity_evidence")
        embedded_docs = link.get("did_documents", {})
        if not isinstance(receipt, Mapping):
            _fail(DI_INVALID, "native chain: link %d has no receipt" % index)
        if not isinstance(embedded_docs, dict):
            _fail(DI_INVALID,
                  "native chain: link %d malformed did_documents" % index)
        # Trust roots: the verifier's OWN pinned roots are authoritative.
        # Embedded documents are untrusted claims: they may fill in for
        # DIDs the verifier never pinned, but they NEVER silently replace
        # a pinned root (F377). A conflicting embedded document for a
        # pinned DID is a substitution attempt and refuses coded.
        roots = dict(trusted_did_docs) if isinstance(trusted_did_docs,
                                                    dict) else {}
        for did, doc in embedded_docs.items():
            verify_did_document(doc)
            if doc["did"] != did:
                _fail(DI_INVALID,
                      "native chain: link %d embedded did mismatch" % index)
            if did in roots:
                if did_document_digest(doc) != did_document_digest(
                        roots[did]):
                    _fail(DI_INVALID,
                          "native chain: link %d embedded did document "
                          "conflicts with the verifier's pinned trust "
                          "root" % index)
                # Digests match: the embedded copy is redundant; the
                # pinned root stays authoritative.
            else:
                roots[did] = doc
        if evidence is not None:
            verify_identity_evidence(evidence, receipt["receipt_id"],
                                     receipt["delegator_pubkey"], roots)
        receipts.append(receipt)
    # Re-verify every native signature, linkage, narrowing, and window.
    _dg.verify_chain(receipts[-1], receipts, at=at, trust_roots=trust_roots)
    leaf = receipts[-1]["receipt_id"]
    _emit("native_chain_verified_offline", depth=len(links),
          leaf=leaf[:16])
    return {"verified": True, "depth": len(links), "leaf": leaf,
            "root": receipts[0]["receipt_id"], "offline": True}


# ---------------------------------------------------------------------------
# Delegated-authority trace edge (composition point for
# gov/decision_trace.py -- documented here, wired by a future lane).
# ---------------------------------------------------------------------------

def delegated_authority_edge(from_id, to_id, receipt_digest_hex,
                             identity_evidence_digest_hex):
    """Build the ``delegated-authority`` trace edge for decision traces.

    Exact shape the decision-trace lane must accept::

        {"kind": "delegated-authority",
         "from": <agent id>,
         "to": <agent id>,
         "receipt_digest": <64 lowercase hex>,
         "identity_evidence_digest": <64 lowercase hex>}

    The digests let the offline evidence-bundle verifier re-resolve the
    receipt and its identity evidence without the engine.
    """
    if not _is_agent_id(from_id) or not _is_agent_id(to_id):
        _fail(DI_INVALID, "trace edge: malformed from/to")
    if not _is_hex64(receipt_digest_hex):
        _fail(DI_INVALID, "trace edge: malformed receipt_digest")
    if not _is_hex64(identity_evidence_digest_hex):
        _fail(DI_INVALID, "trace edge: malformed identity_evidence_digest")
    return {
        "kind": "delegated-authority",
        "from": from_id,
        "to": to_id,
        "receipt_digest": receipt_digest_hex,
        "identity_evidence_digest": identity_evidence_digest_hex,
    }
