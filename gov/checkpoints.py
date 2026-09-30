#!/usr/bin/env python3
"""MMR-signed audit-log checkpoints.

A Merkle Mountain Range over the audit log's existing chained entry
digests, with signed checkpoints committing to the peak list + entry
count. Checkpoints prove order, contemporaneity and completeness of the
log WITHOUT publishing record bodies: a verifier that collected the
digest list can check a checkpoint without seeing (or being) the log.

The pattern (append-only MMR, signed peak-list checkpoints, checkpoint
chaining) is re-derived from the checkpointed-local-log direction; no
prose or code is copied from any external source.

How it differs from ``gov/log.py`` format-2 checkpoints (the RFC
6962-style signed tree heads already in the repo): those need a
``Signer`` at append time and commit one Merkle root over a contiguous
``1..seq`` range of a concrete log file. The MMR here folds in
incrementally (peak lists), works over digest hex strings alone (no log
file, no signer at append time), and checkpoints are standalone
governance records. Neither replaces the other; the honest residual is
the same for both: a checkpoint proves the committed log contents are
unchanged and ordered, not that the log records reality (caller-supplied
observations are still caller-supplied).

Key material follows ``gov/key_identity.py`` conventions: signing and
verification dispatch through the registry's named algorithms
(``gov/alg_registry.py``); this module implements no crypto. A
MAC-tier checkpoint (``hmac-sha256-mac``) verifies fine but is
honestly labeled ``non_repudiation=False`` — a MAC is not a signature,
and anyone holding the shared key can forge one.

Checkpoint chaining: each checkpoint commits to the digest of the
previous checkpoint (``prev_digest``, genesis is 64 zeros), so a
sequence of checkpoints is itself tamper-evident; dropping or
reordering checkpoints refuses ``checkpoint-chain-broken``.

Error vocabulary (all raised as :class:`CheckpointError` with a
machine-readable ``code``):

* ``checkpoint-malformed`` — checkpoint or entry-digest shape is not
  what the schema says (wrong types, non-hex digests, missing fields,
  unknown algorithm, bad count). Raised before any trust decision.
* ``checkpoint-signature-invalid`` — the checkpoint's signature/MAC
  does not verify under the caller's key. Checked BEFORE any log
  comparison: forgery fails before state lookups, so a forged
  checkpoint is never a log oracle.
* ``checkpoint-log-incomplete`` — fewer entries were supplied than the
  checkpoint commits to (tail truncation).
* ``checkpoint-count-mismatch`` — MORE entries were supplied than the
  checkpoint commits to. A checkpoint commits to exactly ``count``
  entries; a longer log is not evidence against this checkpoint.
* ``checkpoint-log-reordered`` — the count matches but the recomputed
  peaks disagree. Covers reordering AND silent content substitution at
  fixed count; the two are indistinguishable from peaks alone, so the
  code names the weaker claim honestly.
* ``checkpoint-chain-broken`` — a checkpoint chain's ``prev_digest``
  link does not match the previous checkpoint's digest.
* ``checkpoint-evidence-not-authorization`` — a checkpoint evidence
  record was used as authority. Evidence proves log commitment, never
  authorization.

Stdlib only. No network. $0.
"""

import hashlib
import json
from datetime import datetime, timezone

from .alg_registry import default_registry

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class CheckpointError(Exception):
    """Base class for all checkpoint refusals. ``code`` is
    machine-readable."""

    code = "checkpoint-refused"


class _Malformed(CheckpointError):
    code = "checkpoint-malformed"


class _SigInvalid(CheckpointError):
    code = "checkpoint-signature-invalid"


class _Incomplete(CheckpointError):
    code = "checkpoint-log-incomplete"


class _CountMismatch(CheckpointError):
    code = "checkpoint-count-mismatch"


class _Reordered(CheckpointError):
    code = "checkpoint-log-reordered"


class _ChainBroken(CheckpointError):
    code = "checkpoint-chain-broken"


class _NotAuthority(CheckpointError):
    code = "checkpoint-evidence-not-authorization"


__all__ = [
    "CheckpointError",
    "MerkleMountainRange",
    "verify_checkpoint",
    "verify_checkpoint_chain",
    "checkpoint_evidence",
    "evidence_digest",
    "evidence_as_authority",
    "CHECKPOINT_VERSION",
]

CHECKPOINT_VERSION = 1
_GENESIS_DIGEST = "00" * 32


def _hex64(value):
    """True if value is a 64-char lowercase hex string."""
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=repr)


def _domain(tag):
    return b"gov-checkpoints/v1\x00" + tag.encode("ascii") + b"\x00"


def _leaf_node(digest_hex):
    return hashlib.sha256(
        _domain("leaf") + bytes.fromhex(digest_hex)).hexdigest()


def _inner_node(left_hex, right_hex):
    return hashlib.sha256(
        _domain("node") + bytes.fromhex(left_hex)
        + bytes.fromhex(right_hex)).hexdigest()


# ----------------------------------------------------------------------
# MMR.
# ----------------------------------------------------------------------


class MerkleMountainRange:
    """Append-only Merkle Mountain Range over entry-digest hex strings.

    Internal state is a stack of ``(height, digest)`` nodes; appending a
    leaf merges equal-height siblings exactly as the classic MMR
    construction. ``peaks()`` returns the current peak digests (the
    commitment), ``count()`` the number of folded leaves.
    """

    def __init__(self):
        self._stack = []  # list of (height, digest_hex)
        self._count = 0

    def append(self, digest_hex):
        """Fold one entry digest (64-hex string) into the range."""
        if not _hex64(digest_hex):
            raise _Malformed("append: entry digest must be 64-hex, "
                             "got %r" % (digest_hex,))
        height = 0
        node = _leaf_node(digest_hex)
        while self._stack and self._stack[-1][0] == height:
            _, left = self._stack.pop()
            node = _inner_node(left, node)
            height += 1
        self._stack.append((height, node))
        self._count += 1

    def peaks(self):
        """The current peak digests (the commitment), oldest first."""
        return [digest for _, digest in self._stack]

    def count(self):
        return self._count

    def checkpoint(self, alg, secret, key_id, prev_checkpoint=None):
        """Emit a signed checkpoint committing to peaks + count.

        ``alg`` is a registry-named algorithm; ``secret`` is the signing
        seed (ed25519) or shared key (MAC tier); ``key_id`` names the
        key in the caller's records. ``prev_checkpoint`` (dict or None)
        chains this checkpoint to its predecessor.
        """
        reg = default_registry()
        try:
            info = reg.info(alg)
        except Exception as exc:  # noqa: BLE001
            raise _Malformed("checkpoint: unknown algorithm %r" % (alg,)
                             ) from exc
        if not isinstance(key_id, str) or not key_id:
            raise _Malformed("checkpoint: key_id must be a non-empty str")
        if not isinstance(secret, (bytes, bytearray)) or not secret:
            raise _Malformed("checkpoint: secret must be non-empty bytes")
        if prev_checkpoint is not None and not _is_checkpoint(prev_checkpoint):
            raise _Malformed("checkpoint: prev_checkpoint is not a "
                             "checkpoint dict")
        body = {
            "v": CHECKPOINT_VERSION,
            "kind": "mmr-checkpoint",
            "alg": alg,
            "key_id": key_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "count": self._count,
            "peaks": self.peaks(),
            "prev_digest": (_checkpoint_digest(prev_checkpoint)
                            if prev_checkpoint is not None
                            else _GENESIS_DIGEST),
            "non_repudiation": bool(info.get("non_repudiation")),
        }
        sig = reg.sign(alg, _canonical(body).encode("utf-8"), bytes(secret))
        body["signature"] = bytes(sig).hex()
        return body


# ----------------------------------------------------------------------
# Checkpoint verification.
# ----------------------------------------------------------------------

_REQUIRED_FIELDS = (
    ("v", int), ("kind", str), ("alg", str), ("key_id", str),
    ("ts", str), ("count", int), ("peaks", list),
    ("prev_digest", str), ("non_repudiation", bool),
    ("signature", str),
)


def _is_checkpoint(value):
    if not isinstance(value, dict):
        return False
    for name, typ in _REQUIRED_FIELDS:
        if name not in value or not isinstance(value[name], typ):
            return False
    return (value["v"] == CHECKPOINT_VERSION
            and value["kind"] == "mmr-checkpoint"
            and value["count"] >= 0
            and all(isinstance(p, str) and _hex64(p)
                    for p in value["peaks"])
            and _hex64(value["prev_digest"])
            and all(c in "0123456789abcdef"
                    for c in value["signature"])
            and len(value["signature"]) > 0)


def _signature_body(checkpoint):
    return _canonical({k: v for k, v in checkpoint.items()
                       if k != "signature"})


def _checkpoint_digest(checkpoint):
    """Digest binding a checkpoint's full content (for chaining and
    evidence records)."""
    return hashlib.sha256(
        _domain("checkpoint") + _signature_body(checkpoint).encode(
            "utf-8")).hexdigest()


def _verify_signature(checkpoint, key):
    """Verify shape + signature; raise on any failure. Does NOT touch
    the log — forgery fails before state lookups."""
    if not _is_checkpoint(checkpoint):
        raise _Malformed("verify: checkpoint shape invalid")
    if not isinstance(key, (bytes, bytearray)) or not key:
        raise _Malformed("verify: key must be non-empty bytes")
    reg = default_registry()
    try:
        info = reg.info(checkpoint["alg"])
    except Exception as exc:  # noqa: BLE001
        raise _Malformed("verify: unknown algorithm %r"
                         % (checkpoint["alg"],)) from exc
    try:
        sig = bytes.fromhex(checkpoint["signature"])
    except ValueError as exc:
        raise _Malformed("verify: signature not hex") from exc
    ok = reg.verify(checkpoint["alg"],
                    _signature_body(checkpoint).encode("utf-8"),
                    sig, bytes(key))
    if not ok:
        raise _SigInvalid("checkpoint signature does not verify under "
                          "the caller's key")
    if checkpoint["non_repudiation"] != bool(info.get("non_repudiation")):
        raise _Malformed("verify: non_repudiation flag disagrees with "
                         "the registry tier")


def verify_checkpoint(checkpoint, entry_digests, key):
    """Verify a checkpoint against a supplied digest list.

    ``entry_digests`` is a list of 64-hex entry digests in log order.
    Returns ``{"ok": True, "count": n, "non_repudiation": bool}``.
    Refusals name the exact failure (see module docstring).
    """
    _verify_signature(checkpoint, key)
    if not isinstance(entry_digests, list) or not all(
            _hex64(d) for d in entry_digests):
        raise _Malformed("verify: entry_digests must be a list of "
                         "64-hex digests")
    count = checkpoint["count"]
    if len(entry_digests) < count:
        raise _Incomplete("log has %d entries; checkpoint commits to %d"
                          % (len(entry_digests), count))
    if len(entry_digests) > count:
        raise _CountMismatch("log has %d entries; checkpoint commits to "
                             "%d" % (len(entry_digests), count))
    mmr = MerkleMountainRange()
    for digest in entry_digests:
        mmr.append(digest)
    if mmr.peaks() != checkpoint["peaks"]:
        raise _Reordered("peaks disagree at committed count %d" % (count,))
    return {"ok": True, "count": count,
            "non_repudiation": checkpoint["non_repudiation"]}


def verify_checkpoint_chain(checkpoints, keys):
    """Verify a sequence of checkpoints: every signature verifies and
    every ``prev_digest`` link matches the previous checkpoint's
    digest. ``keys[i]`` verifies ``checkpoints[i]``. Returns
    ``{"ok": True, "checked": n}``."""
    if not isinstance(checkpoints, list) or not checkpoints:
        raise _Malformed("verify_chain: checkpoints must be a non-empty "
                         "list")
    if not isinstance(keys, list) or len(keys) != len(checkpoints):
        raise _Malformed("verify_chain: one key per checkpoint")
    prev_digest = _GENESIS_DIGEST
    for checkpoint, key in zip(checkpoints, keys):
        _verify_signature(checkpoint, key)
        if checkpoint["prev_digest"] != prev_digest:
            raise _ChainBroken("checkpoint prev_digest does not match "
                               "the previous checkpoint")
        prev_digest = _checkpoint_digest(checkpoint)
    return {"ok": True, "checked": len(checkpoints)}


# ----------------------------------------------------------------------
# Evidence composition (additive, opt-in).
# ----------------------------------------------------------------------


def checkpoint_evidence(checkpoint):
    """Return a digest-linked evidence record for a checkpoint.

    An audit-log entry or action capsule may carry this record as plain
    data; the record commits to the checkpoint by digest, so tampering
    the evidence breaks the commitment. This changes no existing
    format: it is a new dict a caller may attach.
    """
    if not _is_checkpoint(checkpoint):
        raise _Malformed("evidence: not a checkpoint dict")
    return {
        "kind": "mmr-checkpoint-evidence",
        "checkpoint_digest": _checkpoint_digest(checkpoint),
        "alg": checkpoint["alg"],
        "key_id": checkpoint["key_id"],
        "count": checkpoint["count"],
        "peaks_digest": hashlib.sha256(
            _canonical(checkpoint["peaks"]).encode("utf-8")).hexdigest(),
        "non_repudiation": checkpoint["non_repudiation"],
    }


def evidence_digest(evidence):
    """Digest binding an evidence record's content (tamper-evident)."""
    if not isinstance(evidence, dict) or evidence.get("kind") != \
            "mmr-checkpoint-evidence":
        raise _Malformed("evidence_digest: not a checkpoint evidence "
                         "record")
    return hashlib.sha256(
        _domain("evidence") + _canonical(evidence).encode(
            "utf-8")).hexdigest()


def evidence_as_authority(evidence):
    """Refuse authority-shaped use of a checkpoint evidence record.

    Evidence proves log commitment; it is never authorization.
    """
    raise _NotAuthority("checkpoint evidence is not authorization")
