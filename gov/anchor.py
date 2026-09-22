"""Transparency-log anchoring for audit checkpoints (K-049).

Sigstore/Rekor pattern, local-first: the deployment periodically
anchors its signed checkpoints (CT-style signed tree heads) into a
transparency log -- an append-only Merkle tree whose operator returns
a Signed Entry Timestamp (SET) per submission. An auditor who trusts
the transparency log's public key (out-of-band, like the offline root
in ``gov/signing.py``) can verify that a checkpoint was publicly
committed at a point in time, WITHOUT trusting the log writer.

Threat model: a key holder who rewrites the whole history (fresh HMAC
chain + fresh signed checkpoints under compromised keys) cannot
rewrite the transparency log's Merkle tree. The anchored
(seq, merkle_root) will not match the forged log, and submitting a
second, conflicting checkpoint for the same seq is equivocation --
the log refuses it and preserves both as evidence.

Scope honesty (read before extending):
* ``FakeTransparencyLog`` is a deterministic in-process TEST DOUBLE
  (same role as ``FakeKmsProvider``): it proves the anchor FORMAT and
  the verification PATH, not a remote service. $0 spend, no network.
* The external side (real Rekor) is DESIGN-ONLY: the docstring maps
  each artifact to Rekor's API, but nothing here performs HTTP.
* Anchoring does not replace the HMAC chain, the signed checkpoints,
  or the offline root -- it is the complementary control A5 names for
  exporter/writer misbehavior (K-060's export bundle proves what was
  INCLUDED; the anchor proves what was COMMITTED).

Rekor API mapping (design-only, for the future integration):
* ``build_anchor`` -> Rekor ``proposedEntry`` (a DSSE-style envelope
  carrying the checkpoint; Rekor would hash the canonical anchor the
  same way ``anchor_hash`` does here).
* ``FakeTransparencyLog.submit`` -> ``POST /api/v1/log/entries``;
  the returned SET's ``log_index`` / ``inclusion_proof`` /
  ``log_root`` correspond to Rekor's ``verification.inclusionProof``
  (``logIndex``, ``hashes``, ``rootHash``, ``treeSize``).
* ``log_sig`` corresponds to Rekor's
  ``verification.signedEntryTimestamp`` (the log's signature over the
  entry); here it is a plain Ed25519 signature under the log's key.
* Equivocation refusal corresponds to Rekor's duplicate-entry policy
  plus client-side monitoring for conflicting entries at one index.
"""

import hashlib
import json
from datetime import datetime, timezone

from . import ed25519 as _ed
from . import log as _log
from . import merkle as _merkle

ANCHOR_VERSION = 1
GENESIS_ANCHOR = "GENESIS"

_ANCHOR_DOMAIN = b"gov-anchor/v1\x00"
_SET_SIG_DOMAIN = b"gov-transparency-set/v1\x00"


class EquivocationError(Exception):
    """Raised when a conflicting checkpoint is submitted for an
    already-anchored seq. ``evidence`` is (first_set, conflicting_anchor)."""

    def __init__(self, message, evidence):
        super().__init__(message)
        self.evidence = evidence


def _utcnow():
    return datetime.now(timezone.utc).isoformat()


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def anchor_hash(anchor):
    """Content hash of an anchor dict (the leaf in the log's tree)."""
    return hashlib.sha256(
        _ANCHOR_DOMAIN + _canonical(anchor)).hexdigest()


def build_anchor(checkpoint, log_pubkey, prev_anchor_hash=None):
    """Build the anchor statement for a v2 checkpoint.

    ``checkpoint``: the full v2 checkpoint dict (embedded verbatim, so
    the SET is self-contained for an auditor). ``log_pubkey``: the
    transparency log's 32-byte public key (binds WHICH log this anchor
    is for). ``prev_anchor_hash``: hash of the previously submitted
    anchor, or None for the first (GENESIS) -- the anchor chain makes
    the log's own history tamper-evident.
    """
    if not isinstance(checkpoint, dict) or checkpoint.get(
            "format_version") != _log.CHECKPOINT_SIG_VERSION:
        raise ValueError("anchor requires a v2 signed checkpoint")
    if not isinstance(log_pubkey, (bytes, bytearray)) \
            or len(log_pubkey) != 32:
        raise ValueError("log_pubkey must be 32 bytes")
    return {
        "anchor_version": ANCHOR_VERSION,
        "log_id": hashlib.sha256(bytes(log_pubkey)).hexdigest(),
        "checkpoint": checkpoint,
        "prev_anchor": prev_anchor_hash or GENESIS_ANCHOR,
        "integrated_time": _utcnow(),
    }


class FakeTransparencyLog:
    """Deterministic in-process transparency log -- TEST DOUBLE.

    Owns an Ed25519 key and an append-only Merkle tree over submitted
    anchor hashes. ``submit`` enforces: well-formed anchors addressed
    to this log, the prev_anchor chain (submission order), and
    no-conflicting-checkpoint-per-seq (equivocation refusal).
    Idempotent re-submission of the identical anchor returns the
    original SET.

    This is NOT a network service and MUST NOT be mistaken for one:
    it exists so the anchor format and verification path are exercised
    deterministically in tests. A production deployment points at an
    external log (Rekor mapping above).
    """

    def __init__(self, seed):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self._seed = bytes(seed)
        self._pub = _ed.publickey(self._seed)
        # The log's own Merkle tree over anchor hashes. The incremental
        # MerkleStack cannot produce inclusion proofs, so the leaves are
        # kept and the batch proof functions are used (the log is tiny
        # relative to the audit log; O(n) root recomputation per submit
        # is acceptable for a test double).
        self._leaves = []
        self._sets = []          # SETs in submission order
        self._by_seq = {}        # checkpoint seq -> anchor_hash
        self._last_hash = GENESIS_ANCHOR

    @property
    def public_key(self):
        return self._pub

    @property
    def log_id(self):
        return hashlib.sha256(self._pub).hexdigest()

    def __len__(self):
        return len(self._sets)

    def _set_sig_body(self, log_index, log_root_hex, ahash):
        return (_SET_SIG_DOMAIN
                + ("%d|%s|%s" % (log_index, log_root_hex, ahash)
                   ).encode("utf-8"))

    def submit(self, anchor):
        """Submit an anchor; return its Signed Entry Timestamp (SET).

        The SET is ``{"anchor", "anchor_hash", "log_index",
        "tree_size", "inclusion_proof" (hex list), "log_root" (hex),
        "log_sig" (hex)}``. Raises EquivocationError on a conflicting
        checkpoint for an already-anchored seq; ValueError on malformed
        anchors, wrong log_id, or a broken prev_anchor chain.
        """
        if not isinstance(anchor, dict):
            raise ValueError("anchor must be a dict")
        if anchor.get("anchor_version") != ANCHOR_VERSION:
            raise ValueError("unsupported anchor_version")
        if anchor.get("log_id") != self.log_id:
            raise ValueError("anchor addressed to a different log")
        cp = anchor.get("checkpoint")
        if not isinstance(cp, dict) or cp.get(
                "format_version") != _log.CHECKPOINT_SIG_VERSION:
            raise ValueError("anchor must embed a v2 checkpoint")
        seq = cp.get("seq")
        # Idempotency / equivocation are decided by CHECKPOINT content
        # per seq, before the chain check: re-submitting the identical
        # checkpoint is harmless (return the original SET); submitting a
        # DIFFERENT checkpoint for an anchored seq is equivocation.
        first_hash = self._by_seq.get(seq)
        if first_hash is not None:
            first_set = next(s for s in self._sets
                             if s["anchor_hash"] == first_hash)
            if first_set["anchor"]["checkpoint"] == cp:
                return first_set
            raise EquivocationError(
                "conflicting checkpoint already anchored for seq %r"
                % (seq,),
                (first_set, anchor))
        if anchor.get("prev_anchor") != self._last_hash:
            raise ValueError(
                "prev_anchor does not chain from the last submission")
        ahash = anchor_hash(anchor)
        log_index = len(self._sets)
        self._leaves.append(bytes.fromhex(ahash))
        proof = _merkle.inclusion_proof(self._leaves, log_index)
        root_hex = _merkle.tree_root(self._leaves).hex()
        tree_size = log_index + 1
        sig = _ed.sign(
            self._seed,
            self._set_sig_body(log_index, root_hex, ahash)).hex()
        entry = {"anchor": anchor,
                 "anchor_hash": ahash,
                 "log_index": log_index,
                 "tree_size": tree_size,
                 "inclusion_proof": [p.hex() for p in proof],
                 "log_root": root_hex,
                 "log_sig": sig}
        self._sets.append(entry)
        self._by_seq[seq] = ahash
        self._last_hash = ahash
        return entry

    def inclusion_proof(self, log_index):
        """Current inclusion proof for a submitted anchor (tree may
        have grown since submission -- the proof is against the CURRENT
        root)."""
        if not (0 <= log_index < len(self._sets)):
            raise ValueError("log_index out of range")
        return {"log_index": log_index,
                "tree_size": len(self._sets),
                "inclusion_proof": [p.hex() for p in
                                    _merkle.inclusion_proof(
                                        self._leaves, log_index)],
                "log_root": _merkle.tree_root(self._leaves).hex()}


def verify_anchor(entry, checkpoint, trusted_log_pub, expected_prev=None):
    """Verify a Signed Entry Timestamp against a local checkpoint.

    Checks: (1) the SET addresses the trusted log (log_id binding);
    (2) the SET's embedded checkpoint EQUALS the local checkpoint
    (dict equality -- the anchored statement is exactly this head);
    (3) the anchor's inclusion proof verifies against the SET's
    log_root; (4) the log's Ed25519 signature over the SET verifies
    under ``trusted_log_pub``; (5) optionally, the anchor chain link
    (``expected_prev``). Returns (ok, error); never raises on malformed
    input.
    """
    try:
        if not isinstance(entry, dict):
            return False, "SET is not an object"
        anchor = entry["anchor"]
        if not isinstance(anchor, dict):
            return False, "SET has no anchor"
        if anchor.get("anchor_version") != ANCHOR_VERSION:
            return False, "unsupported anchor_version"
        if not isinstance(trusted_log_pub, (bytes, bytearray)) \
                or len(trusted_log_pub) != 32:
            return False, "trusted log pubkey malformed"
        if anchor.get("log_id") != hashlib.sha256(
                bytes(trusted_log_pub)).hexdigest():
            return False, "SET is from a different transparency log"
        if anchor.get("checkpoint") != checkpoint:
            return False, ("SET's checkpoint does not equal the local "
                           "checkpoint")
        if expected_prev is not None and anchor.get(
                "prev_anchor") != expected_prev:
            return False, "anchor chain link mismatch"
        ahash = anchor_hash(anchor)
        if entry.get("anchor_hash") != ahash:
            return False, "anchor_hash mismatch"
        proof = [bytes.fromhex(p) for p in entry["inclusion_proof"]]
        root = bytes.fromhex(entry["log_root"])
        if not _merkle.verify_inclusion(
                bytes.fromhex(ahash), entry["log_index"], proof, root,
                entry["tree_size"]):
            return False, "anchor inclusion proof does not verify"
        sig = bytes.fromhex(entry["log_sig"])
        body = (_SET_SIG_DOMAIN
                + ("%d|%s|%s" % (entry["log_index"], entry["log_root"],
                                 ahash)).encode("utf-8"))
        if not _ed.verify(bytes(trusted_log_pub), body, sig):
            return False, "transparency log signature invalid"
        return True, None
    except (KeyError, TypeError, ValueError) as e:
        return False, "malformed SET: %s" % (e,)


def anchor_checkpoint(log_path, seq, tlog, prev_anchor_hash=None):
    """Convenience: anchor the v2 checkpoint at ``seq`` into ``tlog``.

    Returns (SET, anchor_hash). Raises ValueError when no signed
    checkpoint exists at ``seq``; EquivocationError propagates from
    the log on conflicting re-anchoring.
    """
    cp = _log.signed_checkpoint(log_path, seq)
    if cp is None:
        raise ValueError(
            "no signed (v2) checkpoint at seq %r to anchor" % (seq,))
    anchor = build_anchor(cp, tlog.public_key, prev_anchor_hash)
    entry = tlog.submit(anchor)
    return entry, entry["anchor_hash"]
