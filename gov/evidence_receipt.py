"""CCF-pattern inclusion receipts for evidence bundles (clean-room).

Pattern lineage: microsoft/CCF (Apache-2.0), specifically the RFC 9942
(COSE Merkle Tree Proofs) receipt shape -- a per-artifact,
operator-signed binding of (bundle digest, log position, tree size,
root hash, inclusion proof) that an auditor verifies OFFLINE, without
the engine, the log store, or any live service -- and CCF's
fork-denunciation rule (two signed roots at one log position = fork
proof). This module is a clean-room stdlib-only Python reimplementation
of the RECEIPT SHAPE and the RULE. No CCF code is vendored, imported,
or translated line-by-line.

Relationship to gov/evidence_anchor.py: the anchor module is the
issuance backend. ``issue_receipt`` anchors a bundle digest through the
tessera-shape log (Add -> await_publication -> inclusion proof), then
wraps the result in the signed receipt envelope. The receipt is the
auditor-facing artifact; the anchor module remains the log-side
machinery.

Receipt envelope (COSE_Sign1-*shaped*)::

    {
      "receipt_format": "ccf-inclusion-receipt/1",
      "protected":   {"alg": "EdDSA", "tree_alg": "RFC6962_SHA256",
                      "kid": <operator key id>},
      "payload":     {"vds": "gov/evidence-anchor/tlog-tiles",
                      "origin": <log origin>,
                      "leaf_index": <int>, "tree_size": <int>,
                      "root": <64 hex>, "bundle_digest": <64 hex>,
                      "inclusion_path": [<64 hex> ...],  # leaf-level-up
                      "witness_policy_id": <id | "none">,
                      "issued_at": <int unix time>},
      "signature":   <128 hex: Ed25519 over the Sig_structure>,
      "unprotected": {"witness_signatures":
                        [{"keyid": <id>, "sig": <128 hex>} ...]}
    }

The signed binding mirrors COSE_Sign1's Sig_structure construction --
context string + body_protected + external_aad + payload -- with CBOR
replaced by canonical JSON (sort_keys, compact separators, UTF-8),
because this tree is stdlib-only. The inclusion path, root, size,
index, and digest are ALL inside the signed payload: tampering with
any of them trips ``receipt-signature-invalid``, never silent drift.
This is deliberately NOT RFC 9942 wire-compatible (no CBOR); the
honest claim is "same receipt semantics and verification rule",
not "parses in a COSE library".

THREAT MODEL (read this before trusting a receipt):

* Offline verifiability depends on the AUDITOR'S PINNED KEY SET. The
  operator public key (and any witness policy) must reach the auditor
  through a channel the attacker does not control. This module cannot
  solve key distribution; a substituted key set verifies forged
  receipts. Key ids in ``protected.kid`` are informational -- the
  auditor's pinned key does the work.
* A receipt proves INCLUSION in a tree, not tree honesty. An operator
  who signs two different roots at one log position is caught by
  ``denounce_fork`` (fork proof), but an operator who signs one
  dishonest tree is not detectable from receipts alone -- that needs
  a consistency story / gossip the operator cannot forge, which is
  out of scope here and documented as such.
* ``issued_at`` is operator-claimed (the log is local POSIX; there is
  no trusted clock). It is informational and NOT part of any ordering
  guarantee.
* Witnesses cosign the receipt binding (the per-artifact payload),
  unlike the anchor module where they cosign the checkpoint body.
  A receipt witness set proves "quorum witnesses saw THIS binding",
  not "witnesses reviewed the evidence content".
* Single-writer log (inherited from gov.evidence_anchor): concurrent
  writers are unsupported; corruption surfaces as receipt refusals.
"""

import binascii
import hashlib
import json
import re
import time

from gov import ed25519 as _ed25519
from gov import evidence_anchor as _ea

# ---------------------------------------------------------------------------
# Decision codes (domain: receipt). Registered in gov/decision_codes.py.
# ---------------------------------------------------------------------------

MALFORMED = "inclusion-receipt-malformed"
SIGNATURE_INVALID = "receipt-signature-invalid"
INCLUSION_MISMATCH = "receipt-inclusion-mismatch"
LEAF_MISMATCH = "receipt-leaf-mismatch"
POLICY_MISMATCH = "receipt-policy-mismatch"
FORK_DETECTED = "receipt-fork-detected"


class ReceiptError(Exception):
    """Base class; carries the machine ``code``."""

    code = MALFORMED

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise ReceiptError(detail, code=code)


# ---------------------------------------------------------------------------
# Audit sink (deployment chains these into the HMAC audit log).
# Digests and ids only -- key material NEVER reaches the sink.
# ---------------------------------------------------------------------------

_EMIT = None


def set_emit(emit):
    """Install (or clear, with None) the audit-event sink."""
    global _EMIT
    _EMIT = emit


def _emit(event):
    """Emit an audit event to the installed sink. A broken audit sink
    must never break receipt issuance or verification: the sink failure
    is isolated (the failure mode is recorded in this docstring/comment,
    not the event -- the same trade-off as ``gov/timestamp_authority.py``
    and ``gov/evidence_provenance.py``), never the sink's raw exception
    type escaping at a public seam (F347)."""
    if _EMIT is None:
        return
    try:
        _EMIT(dict(event))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Canonical serialization + the Sig_structure (COSE_Sign1-shaped).
# ---------------------------------------------------------------------------

RECEIPT_FORMAT = "ccf-inclusion-receipt/1"
_VDS = "gov/evidence-anchor/tlog-tiles"
_TREE_ALG = "RFC6962_SHA256"
_SIG_CONTEXT = b"receipt-sig/v1\x00"

_ORIGIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}$")
_POLICY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_KEYID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{1,128}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _canon(obj):
    """Canonical JSON bytes (sort_keys, compact separators, UTF-8)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _sig_structure(protected, payload):
    """The signed bytes: context + canonical protected + canonical payload.

    Mirrors COSE_Sign1's Sig_structure (["Signature1",
    body_protected, external_aad, payload]) with an empty external_aad
    and canonical JSON standing in for CBOR (stdlib-only constraint).
    """
    return _SIG_CONTEXT + _canon(protected) + b"\x00" + _canon(payload)


def _check_digest(value, what):
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        _fail(MALFORMED, "%s must be 64 lowercase hex chars" % what)


def _check_sig_hex(value, keyid):
    if not isinstance(value, str):
        _fail(MALFORMED,
              "signature by %r must be a hex string" % (keyid,))
    try:
        raw = bytes.fromhex(value)
    except (TypeError, ValueError, binascii.Error):
        _fail(MALFORMED,
              "signature by %r is not hex" % (keyid,))
    if len(raw) != 64:
        _fail(MALFORMED,
              "signature by %r is not 64 bytes" % (keyid,))
    return raw


def _verify_sig(pubkey, sig_structure, sig_hex, keyid, code):
    ok = _ed25519.verify(bytes(pubkey), bytes(sig_structure),
                         bytes.fromhex(sig_hex))
    # Wave-243 lesson: gov.ed25519.verify returns True/False -- the
    # return must be checked, never assumed.
    if ok is not True:
        _fail(code, "signature by %r does not verify" % (keyid,))


# ---------------------------------------------------------------------------
# Issuance.
# ---------------------------------------------------------------------------

def _check_witness_policy_arg(witness_policy):
    if witness_policy is not None and \
            not isinstance(witness_policy, _ea.WitnessPolicy):
        _fail(POLICY_MISMATCH,
              "witness_policy must be a WitnessPolicy")


def _check_operator_pubkey(operator_pubkey):
    if not isinstance(operator_pubkey, (bytes, bytearray)) or \
            len(bytes(operator_pubkey)) != 32:
        _fail(MALFORMED, "operator_pubkey must be 32 bytes")


def _operator_pubkey_from_seed(operator_seed):
    # F351a: bytes(str) raises a raw TypeError. Refuse LOUD and coded
    # before touching the value.
    if not isinstance(operator_seed, (bytes, bytearray)):
        _fail(MALFORMED, "operator_seed must be 32 bytes")
    seed = bytes(operator_seed)
    if len(seed) != 32:
        _fail(MALFORMED, "operator_seed must be 32 bytes")
    return _ed25519.publickey(seed)


def issue_receipt(log, bundle_digest, operator_seed, witness_policy=None,
                  witness_seeds=None):
    """Anchor a bundle digest and issue its inclusion receipt.

    Convenience wrapper: performs the full Add -> await_publication ->
    proof sequence via gov.evidence_anchor, then binds the result with
    :func:`bind_receipt`. See :func:`bind_receipt` for the receipt
    semantics and the operator-seed fail-fast rule.

    Returns the receipt dict. Emits a ``receipt-issued`` audit event
    (digests/ids only).
    """
    _check_digest(bundle_digest, "bundle_digest")
    _check_witness_policy_arg(witness_policy)
    anchored = _ea.anchor(log, bundle_digest,
                          witness_policy=witness_policy,
                          witness_seeds=witness_seeds)
    return bind_receipt(anchored, operator_seed,
                        witness_policy=witness_policy,
                        witness_seeds=witness_seeds)


def bind_receipt(anchored, operator_seed, witness_policy=None,
                 witness_seeds=None):
    """Bind an anchor receipt into the signed inclusion-receipt envelope.

    ``anchored`` is an anchor receipt as returned by
    ``gov.evidence_anchor.anchor`` (``bundle_digest``, ``log_index``,
    ``inclusion_proof``, ``checkpoint_signature``,
    ``witness_policy_id``). The (bundle_digest, leaf_index, tree_size,
    root, inclusion_path) tuple is bound under the operator's Ed25519
    signature in the COSE_Sign1-shaped envelope.

    ``operator_seed`` must be the log's own operator seed -- a mismatch
    refuses LOUD at issuance (fail fast) instead of minting a receipt
    that is dead on arrival at verify time. The inclusion tuple is
    re-verified (bundle_digest -> checkpoint root) before signing, so a
    fabricated anchor dict cannot mint a dead operator-signed receipt
    (F337). Witness cosigning mirrors the anchor module's fail-fast
    quorum rule: the witness set is checked against the pinned policy
    BEFORE the receipt is returned.

    Re-binding the same anchor receipt twice yields two receipts over
    the identical (index, size, root) -- only ``issued_at`` differs --
    which is exactly what ``denounce_fork`` expects for agreement
    checks.
    """
    if not isinstance(anchored, dict):
        _fail(MALFORMED, "anchor receipt must be a dict")
    for field in ("bundle_digest", "log_index", "inclusion_proof",
                  "checkpoint_signature", "witness_policy_id"):
        if field not in anchored:
            _fail(MALFORMED,
                  "anchor receipt missing field %r" % field)
    _check_digest(anchored["bundle_digest"], "bundle_digest")
    _check_witness_policy_arg(witness_policy)
    pub = _operator_pubkey_from_seed(operator_seed)

    # Bind issuance to the real operator: the seed must verify the
    # checkpoint note's operator signature line, or the receipt would
    # be issued under a key the auditor never pinned. Coded as
    # inclusion-receipt-malformed: this is fail-fast ARGUMENT
    # validation (the repo's established pattern -- cf. the anchor
    # module coding bad log_root/signer_seed arguments under
    # anchor-log-corrupt/anchor-checkpoint-invalid), not a signature
    # over the receipt itself.
    body, sigs = _ea.parse_checkpoint(
        anchored["checkpoint_signature"])
    ok = _ed25519.verify(pub, body["canonical"],
                         bytes.fromhex(sigs[0]["sig"]))
    if ok is not True:
        _fail(MALFORMED, "operator_seed does not match the log's "
                         "operator key: the checkpoint operator "
                         "signature does not verify under the "
                         "seed-derived key")

    # F337: re-verify the inclusion tuple BEFORE signing. The
    # operator-seed fail-fast above proves the caller holds the
    # operator key; it says nothing about the anchor dict's honesty.
    # A fabricated anchor (bundle_digest swapped) would otherwise mint
    # an operator-signed receipt that verify_receipt_offline rejects --
    # dead-on-arrival issuance. Refuse LOUD here instead.
    proof = anchored["inclusion_proof"]
    if not isinstance(proof, dict):
        _fail(MALFORMED, "inclusion_proof must be an object")
    if proof.get("leaf_index") != anchored["log_index"] or \
            proof.get("tree_size") != body["size"]:
        _fail(INCLUSION_MISMATCH,
              "inclusion proof index/size does not match the anchor "
              "receipt and checkpoint")
    _check_digest(anchored["bundle_digest"], "bundle_digest")
    leaf_hash = _ea._hash_leaf(bytes.fromhex(anchored["bundle_digest"]))
    try:
        chained = _ea.verify_inclusion(leaf_hash, proof, body["root"])
    except _ea.AnchorError:
        _fail(INCLUSION_MISMATCH,
              "inclusion proof shape rejected by the Merkle verifier")
    if chained is not True:
        _fail(INCLUSION_MISMATCH,
              "inclusion path does not chain the anchor bundle_digest "
              "to the checkpoint root: refusing to sign")

    payload = {
        "vds": _VDS,
        "origin": body["origin"],
        "leaf_index": anchored["log_index"],
        "tree_size": body["size"],
        "root": body["root"].hex(),
        "bundle_digest": anchored["bundle_digest"],
        "inclusion_path": list(proof["hashes"]),
        "witness_policy_id": anchored["witness_policy_id"],
        "issued_at": int(time.time()),
    }
    protected = {"alg": "EdDSA", "tree_alg": _TREE_ALG,
                 "kid": sigs[0]["keyid"]}
    sig_structure = _sig_structure(protected, payload)
    signature = _ed25519.sign(bytes(operator_seed), sig_structure).hex()

    unprotected = {"witness_signatures": []}
    if witness_policy is not None:
        unprotected["witness_signatures"] = _cosign(
            sig_structure, witness_policy, witness_seeds or {},
            log_operator_keyid=sigs[0]["keyid"])

    receipt = {"receipt_format": RECEIPT_FORMAT,
               "protected": protected,
               "payload": payload,
               "signature": signature,
               "unprotected": unprotected}
    _emit({"event": "receipt-issued",
           "leaf": anchored["bundle_digest"],
           "index": payload["leaf_index"], "size": payload["tree_size"],
           "origin": payload["origin"]})
    return receipt


def _cosign(sig_structure, policy, seeds, log_operator_keyid):
    """Witness-cosign a receipt binding (fail-fast quorum)."""
    out = []
    for kid, seed in seeds.items():
        if kid not in policy.witnesses:
            _fail(POLICY_MISMATCH,
                  "cosigning key %r is not a pinned witness" % (kid,))
        # F351a class: bytes(str) raises a raw TypeError. Refuse coded.
        if not isinstance(seed, (bytes, bytearray)):
            _fail(POLICY_MISMATCH,
                  "witness seed for %r is not 32 bytes" % (kid,))
        raw = bytes(seed)
        if len(raw) != 32:
            _fail(POLICY_MISMATCH,
                  "witness seed for %r is not 32 bytes" % (kid,))
        # Defense in depth (anchor-module rule): the seed must match the
        # pinned witness key, otherwise the cosignature is unverifiable
        # -- loud now, not at verify time.
        if _ed25519.publickey(raw).hex() != policy.witnesses[kid]:
            _fail(POLICY_MISMATCH,
                  "witness seed does not match pinned key %r" % (kid,))
        out.append({"keyid": kid,
                    "sig": _ed25519.sign(raw, sig_structure).hex()})
    # The operator's own key id never counts toward the witness quorum.
    counted = [s for s in out if s["keyid"] != log_operator_keyid]
    distinct = {s["keyid"] for s in counted}
    if len(distinct) < policy.quorum:
        _fail(POLICY_MISMATCH,
              "only %d distinct witness cosignature(s) for quorum %d"
              % (len(distinct), policy.quorum))
    return out


def issue_receipt_for_envelope(log, envelope, operator_seed,
                               witness_policy=None, witness_seeds=None):
    """Issue an inclusion receipt for a sealed bundle envelope.

    The receipt covers ``envelope_digest(envelope)`` -- the sealed
    bundle's content identity -- so the receipt binds the exact sealed
    bytes the auditor holds.
    """
    from gov import bundle_envelope as _be
    if not isinstance(envelope, dict):
        _fail(MALFORMED, "envelope must be a dict")
    return issue_receipt(log, _be.envelope_digest(envelope),
                         operator_seed, witness_policy=witness_policy,
                         witness_seeds=witness_seeds)


# ---------------------------------------------------------------------------
# Offline verification (no engine, no log store, no live service).
# ---------------------------------------------------------------------------

def _parse_receipt(receipt):
    """Strict-parse a receipt; returns (protected, payload, sig, wsigs)."""
    if not isinstance(receipt, dict):
        _fail(MALFORMED, "receipt must be a dict")
    if receipt.get("receipt_format") != RECEIPT_FORMAT:
        _fail(MALFORMED, "receipt_format must be %r" % RECEIPT_FORMAT)
    for field in ("protected", "payload", "signature", "unprotected"):
        if field not in receipt:
            _fail(MALFORMED, "receipt missing field %r" % field)
    protected = receipt["protected"]
    payload = receipt["payload"]
    unprotected = receipt["unprotected"]
    if not isinstance(protected, dict) or \
            not isinstance(payload, dict) or \
            not isinstance(unprotected, dict):
        _fail(MALFORMED, "receipt sections must be objects")
    if protected.get("alg") != "EdDSA":
        _fail(MALFORMED, "protected.alg must be EdDSA")
    if protected.get("tree_alg") != _TREE_ALG:
        _fail(MALFORMED, "protected.tree_alg must be %r" % _TREE_ALG)
    kid = protected.get("kid")
    if not isinstance(kid, str) or not _KEYID_RE.match(kid):
        _fail(MALFORMED, "protected.kid fails grammar")
    if payload.get("vds") != _VDS:
        _fail(MALFORMED, "payload.vds must be %r" % _VDS)
    origin = payload.get("origin")
    if not isinstance(origin, str) or not _ORIGIN_RE.match(origin):
        _fail(MALFORMED, "payload.origin fails grammar")
    idx = payload.get("leaf_index")
    size = payload.get("tree_size")
    if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
        _fail(MALFORMED, "payload.leaf_index must be a non-negative int")
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        _fail(MALFORMED, "payload.tree_size must be a positive int")
    if idx >= size:
        _fail(MALFORMED, "leaf_index %d out of range for tree_size %d"
              % (idx, size))
    _check_digest(payload.get("root"), "payload.root")
    _check_digest(payload.get("bundle_digest"), "payload.bundle_digest")
    path = payload.get("inclusion_path")
    if not isinstance(path, list):
        _fail(MALFORMED, "payload.inclusion_path must be a list")
    for h in path:
        _check_digest(h, "inclusion_path entry")
    wpid = payload.get("witness_policy_id")
    if not isinstance(wpid, str) or \
            (wpid != "none" and not _POLICY_ID_RE.match(wpid)):
        _fail(MALFORMED, "payload.witness_policy_id fails grammar")
    issued = payload.get("issued_at")
    if not isinstance(issued, int) or isinstance(issued, bool) \
            or issued < 0:
        _fail(MALFORMED, "payload.issued_at must be a non-negative int")
    _check_sig_hex(receipt["signature"], kid)
    wsigs = unprotected.get("witness_signatures", [])
    if not isinstance(wsigs, list):
        _fail(MALFORMED, "unprotected.witness_signatures must be a list")
    for w in wsigs:
        if not isinstance(w, dict):
            _fail(MALFORMED, "witness signature must be an object")
        wkid = w.get("keyid")
        if not isinstance(wkid, str) or not _KEYID_RE.match(wkid):
            _fail(MALFORMED, "witness keyid fails grammar")
        _check_sig_hex(w.get("sig"), wkid)
    return protected, payload, receipt["signature"], wsigs


def verify_receipt_offline(receipt, operator_pubkey, witness_policy=None,
                           log_root=None):
    """Verify an inclusion receipt OFFLINE. Returns True.

    Needs only the receipt and the auditor-pinned operator public key
    (32 raw bytes) -- no engine, no log store, no live service.
    Checks, in order: envelope shape -> operator signature over the
    Sig_structure -> the inclusion path chains the claimed bundle
    digest's leaf hash to the signed root -> witness quorum (when a
    policy is pinned) -> optional tile-leaf cross-check (``log_root``;
    the receipt already binds the digest cryptographically, this is
    belt-and-braces against a store that disagrees with the receipt).
    Any failure raises ReceiptError with its machine code.
    """
    protected, payload, sig_hex, wsigs = _parse_receipt(receipt)
    _check_operator_pubkey(operator_pubkey)
    sig_structure = _sig_structure(protected, payload)
    _verify_sig(bytes(operator_pubkey), sig_structure, sig_hex,
                protected["kid"], SIGNATURE_INVALID)
    _check_witness_binding(sig_structure, wsigs, payload,
                           protected["kid"], witness_policy)
    leaf_hash = _ea._hash_leaf(bytes.fromhex(payload["bundle_digest"]))
    proof = {"leaf_index": payload["leaf_index"],
             "tree_size": payload["tree_size"],
             "hashes": payload["inclusion_path"]}
    try:
        chained = _ea.verify_inclusion(leaf_hash, proof,
                                       bytes.fromhex(payload["root"]))
    except _ea.AnchorError:
        _fail(INCLUSION_MISMATCH,
              "inclusion proof shape rejected by the Merkle verifier")
    if chained is not True:
        _fail(INCLUSION_MISMATCH,
              "inclusion path does not chain to the signed root")
    if log_root is not None:
        _check_tile_leaf(log_root, payload)
    _emit({"event": "receipt-verified", "leaf": payload["bundle_digest"],
           "index": payload["leaf_index"], "ok": True})
    return True


def _check_witness_binding(sig_structure, wsigs, payload,
                           operator_keyid, witness_policy):
    wpid = payload["witness_policy_id"]
    if witness_policy is None:
        if wpid != "none":
            _fail(POLICY_MISMATCH,
                  "receipt names witness policy %r but no policy was "
                  "pinned for verification" % (wpid,))
        if wsigs:
            # Cosignatures with no pinned policy are unverifiable --
            # loud, not silently ignored.
            _fail(POLICY_MISMATCH,
                  "receipt carries witness cosignatures but no policy "
                  "was pinned for verification")
        return
    if not isinstance(witness_policy, _ea.WitnessPolicy):
        _fail(POLICY_MISMATCH, "witness_policy must be a WitnessPolicy")
    if wpid != witness_policy.policy_id:
        _fail(POLICY_MISMATCH,
              "receipt names witness policy %r, expected %r"
              % (wpid, witness_policy.policy_id))
    seen = set()
    for w in wsigs:
        wkid = w["keyid"]
        if wkid == operator_keyid:
            continue  # the operator's line never counts as a witness
        if wkid not in witness_policy.witnesses or wkid in seen:
            continue
        pub = bytes.fromhex(witness_policy.witnesses[wkid])
        ok = _ed25519.verify(pub, bytes(sig_structure),
                             bytes.fromhex(w["sig"]))
        if ok is True:
            seen.add(wkid)
    if len(seen) < witness_policy.quorum:
        _fail(POLICY_MISMATCH,
              "%d of %d required witnesses cosigned the receipt"
              % (len(seen), witness_policy.quorum))


def _check_tile_leaf(log_root, payload):
    leaves = _ea._scan_tiles(log_root)  # fail-closed on tampering
    idx = payload["leaf_index"]
    if idx >= len(leaves):
        _fail(LEAF_MISMATCH,
              "log has %d leaves; receipt claims index %d"
              % (len(leaves), idx))
    want = _ea._hash_leaf(bytes.fromhex(payload["bundle_digest"]))
    if bytes.fromhex(leaves[idx]) != want:
        _fail(LEAF_MISMATCH,
              "tile leaf at index %d is not the claimed bundle digest"
              % idx)


# ---------------------------------------------------------------------------
# Fork denunciation: two signed roots at one log position = fork proof.
# ---------------------------------------------------------------------------

def denounce_fork(receipt_a, receipt_b, operator_pubkey):
    """Compare two receipts' signed tree heads for a fork.

    Both receipts must verify offline under ``operator_pubkey``
    (signatures checked first -- an unverifiable "head" proves
    nothing). They must name the same log (vds + origin) at the same
    tree size; a size mismatch refuses
    ``inclusion-receipt-malformed`` because the fork rule only speaks
    about ONE log position.

    Returns ``{"fork": True, "proof": {...}}`` when the two validly-
    signed heads disagree on the root -- the proof carries both roots
    and both operator signatures -- and ``{"fork": False, ...}`` when
    they agree. A proven fork emits a ``fork-denounced`` audit event
    carrying the ``receipt-fork-detected`` code.

    Composition note: auditors can pin the latest signed tree head
    inside HMAC-chained audit-log entries and run this rule whenever a
    new head arrives at a previously-seen size -- that is the fork-
    denunciation rule applied to the chained log's view of the tree.
    The integration MECHANISM (not just documentation) is the
    ``fork-denounced`` audit event this function emits with code
    ``receipt-fork-detected``: deployments chain the module's audit
    sink (``set_emit``) into the HMAC-chained audit log, so a proven
    fork lands IN the chained log itself -- the fork proof becomes
    part of the tamper-evident record, and any later head that
    contradicts a chained fork proof is denounceable by replaying
    this rule over the log's own history.
    """
    _pa, _pb = _parse_for_fork(receipt_a, receipt_b, operator_pubkey)
    ra, rb = _pa["root"], _pb["root"]
    if ra != rb:
        proof = {"origin": _pa["origin"],
                 "tree_size": _pa["tree_size"],
                 "root_a": ra, "root_b": rb,
                 "operator_keyid": _pa["operator_keyid"],
                 "signature_a": _pa["signature"],
                 "signature_b": _pb["signature"]}
        _emit({"event": "fork-denounced", "code": FORK_DETECTED,
               "origin": _pa["origin"],
               "tree_size": _pa["tree_size"],
               "root_a": ra, "root_b": rb})
        return {"fork": True, "proof": proof}
    return {"fork": False, "origin": _pa["origin"],
            "tree_size": _pa["tree_size"], "root": ra}


def _parse_for_fork(receipt_a, receipt_b, operator_pubkey):
    """Verify both receipts and extract their signed heads."""
    heads = []
    for tag, rcpt in (("a", receipt_a), ("b", receipt_b)):
        protected, payload, sig_hex, _wsigs = _parse_receipt(rcpt)
        _check_operator_pubkey(operator_pubkey)
        sig_structure = _sig_structure(protected, payload)
        _verify_sig(bytes(operator_pubkey), sig_structure, sig_hex,
                    protected["kid"], SIGNATURE_INVALID)
        heads.append({"origin": payload["origin"],
                      "tree_size": payload["tree_size"],
                      "root": payload["root"],
                      "operator_keyid": protected["kid"],
                      "signature": sig_hex})
    ha, hb = heads
    if ha["origin"] != hb["origin"]:
        _fail(MALFORMED, "fork comparison needs one log origin, got %r "
                         "and %r" % (ha["origin"], hb["origin"]))
    if ha["tree_size"] != hb["tree_size"]:
        _fail(MALFORMED, "fork comparison needs equal tree sizes, got "
                         "%d and %d" % (ha["tree_size"], hb["tree_size"]))
    return ha, hb


# ---------------------------------------------------------------------------
# Transport.
# ---------------------------------------------------------------------------

def receipt_to_json(receipt):
    """Serialize a receipt to canonical JSON bytes for transport."""
    _parse_receipt(receipt)  # strict; never serialize a malformed receipt
    return _canon(receipt)


def receipt_from_json(blob):
    """Strict-parse a receipt from JSON bytes (fail-closed)."""
    if not isinstance(blob, (bytes, bytearray)):
        _fail(MALFORMED, "receipt JSON must be bytes")
    try:
        receipt = json.loads(bytes(blob).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        _fail(MALFORMED, "receipt is not valid JSON")
    _parse_receipt(receipt)
    return receipt


# ---------------------------------------------------------------------------
# Internal consistency self-check (used by the unit suite).
# ---------------------------------------------------------------------------

def _self_check():
    """Exercise issue/verify/fork on throwaway temp logs."""
    import tempfile
    from gov import ed25519 as _e

    seed = _e.generate_seed()
    pub = _e.publickey(bytes(seed))
    with tempfile.TemporaryDirectory() as tmp:
        log = _ea.TransparencyLog(tmp + "/a", "self-check.example",
                                  "op-1", signer_seed=seed)
        digest = hashlib.sha256(b"self-check").hexdigest()
        rcpt = issue_receipt(log, digest, seed)
        assert verify_receipt_offline(rcpt, pub) is True
        blob = receipt_to_json(rcpt)
        assert verify_receipt_offline(receipt_from_json(blob),
                                      pub) is True
    return True
