"""Rekor-pattern transparency witness over the local Merkle witness log.

Wave-314 lane 2 (evidence-envelope build order, step 5): in-toto
re-enveloping (wave-310) -> Sigstore-bundle distribution (wave-311) ->
offline verifier (wave-311) -> **Rekor-pattern witness (this module)**
-> VSA decision packets (future).

What this module is: the Rekor-pattern public seam the product was
missing. ``gov.rekor_v2_witness`` is a degrade-only SECOND witness (it
never fails closed); ``gov.evidence_verify_offline.seal_witness_entry``
is a verifier-internal sealer. This module is the standalone,
fail-closed transparency-witness API:

* :func:`anchor_evidence` -- anchor a bundle digest into the local
  Merkle witness log (``gov.witness_log.WitnessLog``) and mint a
  self-contained signed inclusion receipt that travels WITH the
  evidence bundle.
* :func:`verify_inclusion` -- verify a receipt fully OFFLINE,
  checkpoint-first, against a pinned witness key and its validFor
  window. No network, no log access, no engine state.
* :func:`to_offline_entry` -- project a receipt onto the exact
  ``sasanam-witness-log/v1`` entry shape the offline verifier's
  witness step consumes (byte-for-byte identical to
  ``seal_witness_entry`` for identical inputs, pinned by
  ``evals/w314_rekor_probes.py``).

Rekor-pattern semantics (adapted, not a Rekor client):

* The RECEIPT is the transparency promise: checkpoint signature +
  inclusion proof + entry body, all verifiable offline.
* The receipt proves DIGEST EXISTENCE ONLY (the standing lesson:
  Rekor proves digest existence, not authorization/signature
  correctness). The entry body binds the digest plus the evidence
  context (wire signatures, verified keyids, policy digest); a receipt
  presented for a different digest refuses
  ``witness-rekor-digest-mismatch`` -- receipts do not travel between
  bundles.
* Checkpoint-first (sigstore-python#248): the signature is verified
  before any size/hash is parsed; tree size and root hash come ONLY
  from the verified checkpoint. The proof block's own ``tree_size``
  is informational and ignored.
* The anchor is TIME-BOUND: the checkpoint time must sit inside the
  witness key's validFor window AT ANCHOR TIME (the CVE-2026-24122
  analogue), must not be in the future vs the observed time, and --
  when a ``max_anchor_age`` is set -- must not be older than that age
  vs the observed time. A stale or out-of-window anchor refuses
  ``witness-rekor-anchor-expired``. There is no trusted-now by
  default: the caller supplies ``now``; when omitted, ``time.time()``
  is used (a named time source is the offline verifier's stricter
  contract -- this module is the engine-side seam, not the auditor).

All failures raise :class:`WitnessRekorError` with a machine ``code``
(registered in ``gov.decision_codes``). No new cryptography: Ed25519
via the existing key ceremony (``gov.signing`` signers satisfy the
``witness_log`` signer contract; checkpoints are verified with the
vendored RFC 8032 primitive inside ``gov.witness_log``).

Stdlib only. $0 spend, synthetic/local.
"""

import binascii
import base64
import time

from .witness_log import (WitnessLog, WitnessError, canonical_bytes,
                          verify_checkpoint)
from .witness_log import verify_inclusion as _wl_verify_inclusion

__all__ = [
    "WITNESS_ENTRY_KIND",
    "WITNESS_ENTRY_BODY_KIND",
    "WITNESS_ENTRY_API_VERSION",
    "WitnessRekorError",
    "anchor_evidence",
    "verify_inclusion",
    "to_offline_entry",
]

# Entry shapes match the offline verifier's witness stage
# (gov/evidence_verify_offline.py: WITNESS_ENTRY_KIND etc.) so receipts
# are consumable there unchanged.
WITNESS_ENTRY_KIND = "sasanam-witness-log/v1"
WITNESS_ENTRY_BODY_KIND = "sasanam-witness-log"
WITNESS_ENTRY_API_VERSION = "0.0.1"


class WitnessRekorError(Exception):
    """A coded transparency-witness failure. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("[%s] %s" % (code, detail) if detail else
                         "[%s]" % (code,))


def _refuse(code, detail=""):
    raise WitnessRekorError(code, detail)


def _check_digest(value, where):
    if (not isinstance(value, str) or len(value) != 64
            or any(c not in "0123456789abcdefABCDEF" for c in value)):
        _refuse("witness-rekor-malformed",
                "%s: bundle digest must be 64 hex chars" % (where,))
    return value.lower()


def _check_pubkey(value, where):
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        _refuse("witness-rekor-malformed",
                "%s: witness public key must be 32 bytes" % (where,))
    return bytes(value)


def _check_timestamp(value, where):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _refuse("witness-rekor-malformed",
                "%s: timestamp must be a non-negative int" % (where,))
    return value


def _check_window(value, where):
    if (not isinstance(value, (tuple, list)) or len(value) != 2):
        _refuse("witness-rekor-malformed",
                "%s: valid_for must be a (not_before, not_after) pair"
                % (where,))
    lo, hi = (_check_timestamp(value[0], where + ".not_before"),
              _check_timestamp(value[1], where + ".not_after"))
    if lo > hi:
        _refuse("witness-rekor-malformed",
                "%s: not_before %d > not_after %d" % (where, lo, hi))
    return lo, hi


def _entry_body(bundle_digest, timestamp, signatures, verified_keyids,
                policy_digest):
    """The canonical leaf body, byte-identical in shape to the offline
    verifier's own sealer (seal_witness_entry)."""
    if not isinstance(signatures, (tuple, list)):
        _refuse("witness-rekor-malformed",
                "signatures must be a list/tuple")
    sigs = []
    for i, s in enumerate(signatures):
        if not isinstance(s, dict):
            _refuse("witness-rekor-malformed",
                    "signatures[%d] must be an object" % i)
        sigs.append(dict(s))
    if (not isinstance(verified_keyids, (tuple, list))
            or not all(isinstance(k, str) and k for k in verified_keyids)):
        _refuse("witness-rekor-malformed",
                "verified_keyids must be a list/tuple of non-empty str")
    if not isinstance(policy_digest, str):
        _refuse("witness-rekor-malformed",
                "policy_digest must be a str")
    if policy_digest and (len(policy_digest) != 64
                          or any(c not in "0123456789abcdefABCDEF"
                                 for c in policy_digest)):
        _refuse("witness-rekor-malformed",
                "policy_digest must be 64 hex chars or empty")
    return {
        "apiVersion": WITNESS_ENTRY_API_VERSION,
        "kind": WITNESS_ENTRY_BODY_KIND,
        "spec": {
            "artifactDigest": bundle_digest,
            "signatures": sigs,
            "verifiedKeyids": sorted(set(verified_keyids)),
            "policyDigest": policy_digest.lower(),
            "integratedTime": timestamp,
        },
    }


def anchor_evidence(bundle_digest, *, witness_log, witness_signer,
                    timestamp=None, signatures=(), verified_keyids=(),
                    policy_digest=""):
    """Anchor a bundle digest into the witness log; return the signed
    inclusion receipt.

    The receipt is the transparency promise: the entry body (binding
    the digest and its evidence context), the log index, the sealed
    checkpoint at anchor time, and the Merkle inclusion proof. It is
    self-contained: :func:`verify_inclusion` needs only the receipt,
    the claimed digest, and the pinned witness key.

    ``witness_signer`` must hold THIS log's witness key --
    ``WitnessLog.sealed_checkpoint`` refuses a foreign signer coded
    ``witness-log-key-mismatch`` (a log never co-signs for another key).
    """
    digest = _check_digest(bundle_digest, "anchor_evidence")
    if not isinstance(witness_log, WitnessLog):
        _refuse("witness-rekor-malformed",
                "witness_log must be a gov.witness_log.WitnessLog")
    ts = int(time.time()) if timestamp is None else _check_timestamp(
        timestamp, "anchor_evidence.timestamp")
    body = _entry_body(digest, ts, signatures, verified_keyids,
                       policy_digest)
    try:
        index = witness_log.append(canonical_bytes(body))
    except WitnessError as exc:
        _refuse("witness-rekor-malformed",
                "entry body rejected by the log: [%s] %s"
                % (exc.code, exc.detail))
    try:
        sealed = witness_log.sealed_checkpoint(ts, witness_signer)
    except WitnessError as exc:
        _refuse("witness-rekor-malformed",
                "checkpoint sealing failed: [%s] %s"
                % (exc.code, exc.detail))
    proof = witness_log.inclusion_proof(index)
    return {
        "kind": WITNESS_ENTRY_KIND,
        "log_index": index,
        "entry_body": body,
        "checkpoint": sealed["checkpoint"],
        "checkpoint_signature": sealed["signature"],
        "proof": {
            "leaf_index": proof["leaf_index"],
            "tree_size": proof["tree_size"],
            "path": proof["path"],
        },
    }


def to_offline_entry(receipt):
    """Project a receipt onto the offline verifier's witness-entry shape.

    Returns exactly what ``evidence_verify_offline.seal_witness_entry``
    emits for identical inputs (pinned byte-for-byte by the battery),
    so the verifier's witness stage consumes our receipts unchanged.
    """
    entry = _checked_receipt(receipt, "to_offline_entry")
    return {
        "kind": WITNESS_ENTRY_KIND,
        "log_index": entry["log_index"],
        "entry_body": entry["entry_body"],
        "checkpoint": entry["checkpoint"],
        "checkpoint_signature": entry["checkpoint_signature"],
        "inclusion_path": entry["proof"]["path"],
    }


def _checked_receipt(receipt, where):
    """Validate receipt transport shape; narrow the input before any
    crypto touches it."""
    if receipt is None:
        _refuse("witness-rekor-anchor-missing",
                "%s: no anchor receipt presented for the bundle digest"
                % (where,))
    if not isinstance(receipt, dict):
        _refuse("witness-rekor-malformed",
                "%s: receipt must be an object" % (where,))
    if receipt.get("kind") != WITNESS_ENTRY_KIND:
        _refuse("witness-rekor-malformed",
                "%s: receipt kind must be %r, got %r"
                % (where, WITNESS_ENTRY_KIND, receipt.get("kind")))
    for field in ("log_index", "entry_body", "checkpoint",
                  "checkpoint_signature", "proof"):
        if field not in receipt:
            _refuse("witness-rekor-malformed",
                    "%s: receipt missing field %r" % (where, field))
    if (isinstance(receipt["log_index"], bool)
            or not isinstance(receipt["log_index"], int)
            or receipt["log_index"] < 0):
        _refuse("witness-rekor-malformed",
                "%s: log_index must be a non-negative int" % (where,))
    if not isinstance(receipt["entry_body"], dict):
        _refuse("witness-rekor-malformed",
                "%s: entry_body must be an object" % (where,))
    if not isinstance(receipt["checkpoint"], dict):
        _refuse("witness-rekor-malformed",
                "%s: checkpoint must be an object" % (where,))
    sig = receipt["checkpoint_signature"]
    if not isinstance(sig, str):
        _refuse("witness-rekor-malformed",
                "%s: checkpoint_signature must be a base64 str" % (where,))
    try:
        base64.b64decode(sig.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        _refuse("witness-rekor-malformed",
                "%s: checkpoint_signature is not valid base64" % (where,))
    proof = receipt["proof"]
    if not isinstance(proof, dict) or not isinstance(proof.get("path"),
                                                    list):
        _refuse("witness-rekor-malformed",
                "%s: proof must be an object with a path list" % (where,))
    return receipt


def verify_inclusion(bundle_digest, receipt, *, witness_public_key,
                     valid_for, now=None, max_anchor_age=None):
    """Verify a receipt fully offline, checkpoint-first.

    ``witness_public_key`` (32 bytes) is the pinned witness key -- the
    checkpoint's logId must name it, and its signature is checked
    before anything is parsed. ``valid_for`` is the key's
    ``(not_before, not_after)`` window: the checkpoint time must sit
    inside it AT ANCHOR TIME. ``now`` is the observed time (defaults to
    ``time.time()``; inject for determinism). ``max_anchor_age``, when
    set, bounds how old the anchor may be vs ``now``.

    Check order (cheap to expensive, fail-closed): shape -> checkpoint
    signature -> anchor time (window, future, age) -> log_index bounds
    -> Merkle inclusion -> digest binding.

    Returns an info dict ``{log_index, tree_size, root_hash,
    checkpoint_time, log_id}``. Sizes and hashes come ONLY from the
    verified checkpoint, never from the proof block.
    """
    digest = _check_digest(bundle_digest, "verify_inclusion")
    pub = _check_pubkey(witness_public_key, "verify_inclusion")
    lo, hi = _check_window(valid_for, "verify_inclusion.valid_for")
    obs = int(time.time()) if now is None else _check_timestamp(
        now, "verify_inclusion.now")
    if max_anchor_age is not None:
        max_anchor_age = _check_timestamp(max_anchor_age,
                                          "verify_inclusion.max_anchor_age")

    entry = _checked_receipt(receipt, "verify_inclusion")

    # --- checkpoint signature FIRST, before parsing anything ---
    try:
        verified_cp = verify_checkpoint(
            {"checkpoint": entry["checkpoint"],
             "signature": entry["checkpoint_signature"]}, pub)
    except WitnessError as exc:
        _refuse("witness-rekor-checkpoint-invalid",
                "checkpoint rejected: [%s] %s" % (exc.code, exc.detail))

    # --- times and sizes ONLY from the verified checkpoint ---
    cp_time = verified_cp["timestamp"]
    if not (lo <= cp_time <= hi):
        _refuse("witness-rekor-anchor-expired",
                "anchor time %d outside the witness key validFor window "
                "[%d, %d] at anchor time" % (cp_time, lo, hi))
    if cp_time > obs:
        _refuse("witness-rekor-checkpoint-invalid",
                "checkpoint time %d is in the future vs observed time %d"
                % (cp_time, obs))
    if max_anchor_age is not None and obs - cp_time > max_anchor_age:
        _refuse("witness-rekor-anchor-expired",
                "anchor age %d exceeds max_anchor_age %d"
                % (obs - cp_time, max_anchor_age))

    tree_size = verified_cp["treeSize"]
    root_hash = bytes.fromhex(verified_cp["rootHash"])
    log_index = entry["log_index"]
    if log_index >= tree_size:
        _refuse("witness-rekor-inclusion-invalid",
                "log_index %d outside [0, %d)" % (log_index, tree_size))

    try:
        leaf = canonical_bytes(entry["entry_body"])
    except WitnessError as exc:
        _refuse("witness-rekor-malformed",
                "entry_body not canonical-serializable: [%s] %s"
                % (exc.code, exc.detail))
    try:
        _wl_verify_inclusion(leaf, log_index, entry["proof"]["path"],
                             tree_size, root_hash)
    except WitnessError as exc:
        _refuse("witness-rekor-inclusion-invalid",
                "inclusion proof rejected: [%s] %s" % (exc.code, exc.detail))

    # --- entry-body binding: the receipt must bind THIS digest ---
    body = entry["entry_body"]
    if (body.get("kind") != WITNESS_ENTRY_BODY_KIND
            or body.get("apiVersion") != WITNESS_ENTRY_API_VERSION):
        _refuse("witness-rekor-malformed",
                "entry_body kind/apiVersion must be %r/%r" %
                (WITNESS_ENTRY_BODY_KIND, WITNESS_ENTRY_API_VERSION))
    spec = body.get("spec")
    if not isinstance(spec, dict):
        _refuse("witness-rekor-malformed", "entry_body.spec missing")
    bound = spec.get("artifactDigest")
    if not isinstance(bound, str) or bound.lower() != digest:
        _refuse("witness-rekor-digest-mismatch",
                "receipt binds digest %r, not the claimed bundle digest"
                % (bound,))

    return {
        "log_index": log_index,
        "tree_size": tree_size,
        "root_hash": root_hash.hex(),
        "checkpoint_time": cp_time,
        "log_id": verified_cp["logId"],
    }
