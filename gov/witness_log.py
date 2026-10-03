"""Append-only transparency log with signed checkpoints and Merkle proofs.

Wave-312 lane D: build-order step 4 of the evidence-envelope prospectus
(``research/prospecting/w310_offline_verifier_auditor_ux.md``) -- the
Rekor-pattern witness LOG. ``gov/evidence_sigstore.py`` mints witness
ENTRIES (entry shape only, local witness key); this module is the
persistent log behind them: an append-only Merkle tree (RFC 6962-style
domain separation, stdlib hashlib only) with signed checkpoints,
inclusion proofs, and consistency proofs.

What this log proves (and does not prove):

- Transparency proves REGISTRATION, not truth. An inclusion proof
  proves an entry's bytes were appended at a position, nothing about
  their content.
- Subjects are digests: leaves are opaque bytes to this module. The
  entry-body binding (artifact digest + exact wire signatures + primary
  key, the CVE-2026-22703 rule) is the sealer's job -- this module
  binds leaf bytes to tree positions.
- ``keyid`` is a hint, never authority: checkpoint verification uses
  the raw 32-byte witness public key, never a keyid.

Checkpoint-first contract (Rekor v2 CLIENTS.md, adapted):

1. The checkpoint SIGNATURE is verified first, over the canonical
   bytes of the checkpoint document.
2. ``tree_size`` and ``root_hash`` are parsed ONLY from the verified
   checkpoint. Duplicated copies anywhere else (inside an inclusion
   proof envelope, beside the entry) are IGNORED, never trusted --
   the sigstore-python#248 lesson: an unpinned root hash verifies
   against any log.
3. ``integrated_time`` is ignored (always 0 upstream); our checkpoint
   carries an explicit unix ``timestamp`` instead.

Merkle tree (RFC 6962 section 2.1 hashing):

- ``leaf_hash = sha256(0x00 || leaf_bytes)``
- ``node_hash = sha256(0x01 || left || right)``
- the tree root splits at the largest power of two strictly smaller
  than the leaf count (RFC 6962 section 2.1).

Inclusion proofs are the standard RFC 6962 audit path (leaf-to-root
sibling hashes with sides). Consistency proofs use our
border-decomposition format: the roots of the maximal perfect aligned
subtrees tiling ``[0, old_size)`` followed by those tiling
``[old_size, new_size)``. The verifier recomputes BOTH roots
deterministically from ``(old_size, new_size, proof)`` and compares --
a forged proof needs a hash preimage or collision to pass. This is
what lets an auditor detect a forked log: two inconsistent checkpoints
from the same key can never produce a valid consistency proof.

Coded refusals (``WitnessError.code``; also registered in
``gov/decision_codes.py`` -- pin moves 1841 -> 1851):

- ``witness-log-malformed`` -- bad inputs (non-bytes leaf, bad JSON
  shapes, bad base64/hex, bad proof structure).
- ``witness-log-empty`` -- checkpoint/proof requested on an empty log.
- ``witness-log-index-out-of-range`` -- leaf index or size arguments
  outside the log.
- ``witness-log-key-mismatch`` -- the checkpoint signer key is not this
  log's bound witness key.
- ``witness-log-checkpoint-signature-invalid`` -- the checkpoint
  signature does not verify (checked FIRST, before parsing).
- ``witness-log-checkpoint-malformed`` -- the VERIFIED checkpoint's
  fields are bad (treeSize/rootHash/timestamp/logId).
- ``witness-log-inclusion-invalid`` -- the inclusion proof does not
  verify the leaf against the checkpoint root.
- ``witness-log-consistency-invalid`` -- the consistency proof does not
  verify old -> new.

Every refusal raises; nothing unverified escapes. ``verify_*``
functions never return True/False -- they return the verified values
or raise.

Stdlib only (hashlib, json, base64). No gov imports: this module is
extractable -- an auditor can lift this single file. The Ed25519
verifier below is a minimal RFC 8032 implementation (hashlib only),
cross-tested against ``gov.ed25519`` in ``tests/test_witness_log.py``.

$0 spend. Synthetic/local testing.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json

__all__ = [
    "WITNESS_LOG_VERSION",
    "CHECKPOINT_VERSION",
    "WitnessError",
    "canonical_bytes",
    "leaf_hash",
    "node_hash",
    "WitnessLog",
    "verify_checkpoint",
    "verify_inclusion",
    "verify_consistency",
]

#: Log format version (stamped on checkpoints' provenance, not consensus).
WITNESS_LOG_VERSION = "sasanam-witness-log/v1"

#: Checkpoint document version marker (informational).
CHECKPOINT_VERSION = "sasanam-witness-checkpoint/v1"

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


class WitnessError(Exception):
    """A coded witness-log failure. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("[%s] %s" % (code, detail) if detail else
                         "[%s]" % (code,))


def _refuse(code, detail=""):
    raise WitnessError(code, detail)


# ---------------------------------------------------------------------------
# Canonical bytes.
# ---------------------------------------------------------------------------

def canonical_bytes(obj):
    """Canonical JSON bytes: sort_keys, no whitespace, ASCII.

    The leaf preimage form: every signer and verifier must hash the
    same bytes. Raises ``witness-log-malformed`` on unserializable
    input (never silently degrades).
    """
    try:
        return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _refuse("witness-log-malformed",
                "entry not JSON-serializable: %s" % (exc,))


# ---------------------------------------------------------------------------
# RFC 6962-style Merkle hashing (stdlib hashlib only).
# ---------------------------------------------------------------------------

def leaf_hash(leaf):
    """sha256(0x00 || leaf). Domain separation: a leaf hash can never
    equal an interior node hash for the same preimage."""
    if not isinstance(leaf, (bytes, bytearray)) or not leaf:
        _refuse("witness-log-malformed",
                "leaf must be non-empty bytes, got %s"
                % type(leaf).__name__)
    return hashlib.sha256(_LEAF_PREFIX + bytes(leaf)).digest()


def node_hash(left, right):
    """sha256(0x01 || left || right)."""
    for name, h in (("left", left), ("right", right)):
        if not isinstance(h, (bytes, bytearray)) or len(h) != 32:
            _refuse("witness-log-malformed",
                    "node %s hash must be 32 bytes" % name)
    return hashlib.sha256(_NODE_PREFIX + bytes(left)
                          + bytes(right)).digest()


def _largest_pow2_lt(n):
    """Largest power of two strictly smaller than n (n >= 2)."""
    return 1 << (n - 1).bit_length() - 1


def _calc_root(hashes):
    """Merkle root of a list of 32-byte leaf hashes (RFC 6962 2.1)."""
    n = len(hashes)
    if n == 0:
        _refuse("witness-log-empty", "no leaves")
    if n == 1:
        return hashes[0]
    k = _largest_pow2_lt(n)
    return node_hash(_calc_root(hashes[:k]), _calc_root(hashes[k:]))


def _audit_path(hashes, m):
    """Audit path for leaf m: [(sibling_hash, side)] leaf-to-root."""
    n = len(hashes)
    if n == 1:
        if m != 0:
            _refuse("witness-log-index-out-of-range",
                    "leaf %d not in 1-leaf tree" % m)
        return []
    k = _largest_pow2_lt(n)
    if m < k:
        return _audit_path(hashes[:k], m) + [(_calc_root(hashes[k:]),
                                              "right")]
    return _audit_path(hashes[k:], m - k) + [(_calc_root(hashes[:k]),
                                              "left")]


def _audit_path_len(m, n):
    """Expected audit-path length for leaf m in a tree of size n.

    The verifier binds the proof to the claimed tree size: a proof
    whose length is inconsistent with (leaf_index, tree_size) is
    refused even if it folds to the right root.
    """
    if n == 1:
        return 0
    k = _largest_pow2_lt(n)
    if m < k:
        return _audit_path_len(m, k) + 1
    return _audit_path_len(m - k, n - k) + 1


def _decomp(lo, hi):
    """Maximal perfect aligned subtrees tiling [lo, hi), left-to-right.

    A subtree [a, b) is emitted whole when b - a is a power of two and
    a is aligned to it; otherwise the interval splits at
    a + largest_pow2_lt(b - a) (the RFC 6962 split rule, translated).
    Every emitted interval is a genuine node of the RFC 6962 tree, and
    its root is translation-invariant: root([a,b)) == _calc_root over
    the slice, because the split rule depends only on interval length.
    """
    if hi <= lo:
        _refuse("witness-log-malformed",
                "empty interval [%d, %d)" % (lo, hi))
    out = []

    def rec(a, b):
        size = b - a
        if size >= 1 and (size & (size - 1)) == 0 and a % size == 0:
            out.append((a, b))
            return
        k = a + _largest_pow2_lt(size)
        rec(a, k)
        rec(k, b)

    rec(lo, hi)
    return out


def _reval(lo, hi, env):
    """Re-evaluate a tree root from known subtree roots.

    ``env`` maps (a, b) intervals to their 32-byte roots. Splits follow
    the RFC 6962 rule exactly, so the result equals the true root when
    every env value is the true subtree root. Raises
    ``witness-log-malformed`` if evaluation reaches an uncovered leaf
    (a proof that does not tile its claimed range).
    """
    key = (lo, hi)
    if key in env:
        return env[key]
    if hi - lo == 1:
        _refuse("witness-log-malformed",
                "proof does not cover leaf %d" % lo)
    k = lo + _largest_pow2_lt(hi - lo)
    return node_hash(_reval(lo, k, env), _reval(k, hi, env))


# ---------------------------------------------------------------------------
# Minimal RFC 8032 Ed25519 verification (hashlib only).
#
# Self-contained so this module stays stdlib-only and extractable.
# Cross-tested against gov.ed25519 in tests/test_witness_log.py.
# Verify-only: no key generation, no signing here.
# ---------------------------------------------------------------------------

_ED_P = 2 ** 255 - 19
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_GX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_ED_GY = 46316835694926478169428394003475163141307993866256225615783033603165251855960


def _ed_add(p, q):
    # Twisted Edwards (a = -1) affine addition:
    #   x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)
    #   y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
    # (the y3 numerator is a PLUS for a = -1; the minus form is the
    # untwisted curve -- cross-tested against gov.ed25519).
    x1, y1 = p
    x2, y2 = q
    t1 = (x1 * x2) % _ED_P
    t2 = (y1 * y2) % _ED_P
    x3 = ((x1 * y2 + x2 * y1)
          * pow((1 + _ED_D * t1 * t2) % _ED_P, _ED_P - 2, _ED_P)) % _ED_P
    y3 = ((t2 + t1)
          * pow((1 - _ED_D * t1 * t2) % _ED_P, _ED_P - 2, _ED_P)) % _ED_P
    return (x3, y3)


def _ed_scalarmult(p, e):
    q = (0, 1)  # identity
    while e > 0:
        if e & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        e >>= 1
    return q


def _ed_decode_point(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = (s[31] >> 7) & 1
    if y >= _ED_P:
        return None
    x2 = ((_ed_sq(y) - 1)
          * pow((_ED_D * _ed_sq(y) + 1) % _ED_P, _ED_P - 2, _ED_P)) % _ED_P
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (_ed_sq(x) - x2) % _ED_P != 0:
        x = (x * pow(2, (_ED_P - 1) // 4, _ED_P)) % _ED_P
        if (_ed_sq(x) - x2) % _ED_P != 0:
            return None
    if (x & 1) != sign:
        x = _ED_P - x
    return (x, y)


def _ed_sq(x):
    return (x * x) % _ED_P


def _ed25519_verify(public_key, message, signature):
    """Return True iff the Ed25519 signature verifies. Never raises on
    malformed inputs -- they verify as False."""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        a = _ed_decode_point(bytes(public_key))
        r = _ed_decode_point(bytes(signature[:32]))
        if a is None or r is None:
            return False
        s = int.from_bytes(bytes(signature[32:]), "little")
        if s >= _ED_L:
            return False
        h = (int.from_bytes(hashlib.sha512(
            bytes(signature[:32]) + bytes(public_key)
            + bytes(message)).digest(), "little") % _ED_L)
        lhs = _ed_scalarmult((_ED_GX, _ED_GY), s)
        rhs = _ed_add(r, _ed_scalarmult(a, h))
        return lhs == rhs
    except Exception:
        return False


# ---------------------------------------------------------------------------
# The log.
# ---------------------------------------------------------------------------

def _check_pubkey(value, where):
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        _refuse("witness-log-malformed",
                "%s: witness public key must be 32 bytes, got %s"
                % (where, type(value).__name__))
    return bytes(value)


def _check_timestamp(value, where):
    if (isinstance(value, bool) or not isinstance(value, int)
            or value < 0):
        _refuse("witness-log-malformed",
                "%s: timestamp must be a non-negative int unix time"
                % (where,))
    return value


class WitnessLog:
    """An append-only Merkle log bound to one witness key.

    ``witness_public_key`` (32 bytes) is the ONLY key whose signatures
    make checkpoints for this log. Entries are opaque leaf bytes;
    position binding is by Merkle inclusion proof.
    """

    def __init__(self, witness_public_key):
        self._witness_public_key = _check_pubkey(witness_public_key,
                                                 "WitnessLog")
        self._entries = []

    @property
    def witness_public_key(self):
        return self._witness_public_key

    @property
    def log_id(self):
        """Hex sha256 of the witness public key (the log's identity)."""
        return hashlib.sha256(self._witness_public_key).hexdigest()

    def __len__(self):
        return len(self._entries)

    @property
    def tree_size(self):
        return len(self._entries)

    def append(self, leaf):
        """Append leaf bytes; return the leaf index. Fail-closed on
        bad input."""
        if not isinstance(leaf, (bytes, bytearray)) or not leaf:
            _refuse("witness-log-malformed",
                    "append: leaf must be non-empty bytes, got %s"
                    % type(leaf).__name__)
        self._entries.append(bytes(leaf))
        return len(self._entries) - 1

    def entries(self):
        """A snapshot tuple of the leaf bytes (oldest first)."""
        return tuple(self._entries)

    def _leaf_hashes(self):
        return [leaf_hash(e) for e in self._entries]

    def root_hash(self):
        """Current tree root (32 bytes). Refuses on an empty log."""
        return _calc_root(self._leaf_hashes())

    def checkpoint(self, timestamp):
        """Build the unsigned checkpoint document for the current tree.

        ``{"logId", "treeSize", "rootHash", "timestamp"}`` -- the exact
        bytes the witness signs (canonical form).
        """
        timestamp = _check_timestamp(timestamp, "checkpoint")
        if not self._entries:
            _refuse("witness-log-empty",
                    "cannot checkpoint an empty log")
        return {
            "logId": self.log_id,
            "treeSize": len(self._entries),
            "rootHash": self.root_hash().hex(),
            "timestamp": timestamp,
        }

    def sealed_checkpoint(self, timestamp, signer):
        """Sign the current checkpoint with the log's witness key.

        ``signer`` exposes ``.public_key`` (32 bytes) and
        ``.sign(bytes) -> bytes``. The signer's key MUST be this log's
        bound witness key -- a foreign signer refuses
        ``witness-log-key-mismatch`` (never silently co-signs).
        Returns ``{"checkpoint": dict, "signature": "<base64>"}``.
        """
        cp = self.checkpoint(timestamp)
        pub = getattr(signer, "public_key", None)
        if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
            _refuse("witness-log-malformed",
                    "sealed_checkpoint: signer public_key must be 32 bytes")
        if bytes(pub) != self._witness_public_key:
            _refuse("witness-log-key-mismatch",
                    "signer key %s is not this log's witness key %s"
                    % (hashlib.sha256(bytes(pub)).hexdigest()[:16],
                       self.log_id[:16]))
        sign = getattr(signer, "sign", None)
        if not callable(sign):
            _refuse("witness-log-malformed",
                    "sealed_checkpoint: signer needs .sign(bytes)")
        try:
            sig = sign(canonical_bytes(cp))
        except WitnessError:
            raise
        except Exception as exc:
            _refuse("witness-log-malformed",
                    "sealed_checkpoint: signer failed: %s" % (exc,))
        if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
            _refuse("witness-log-malformed",
                    "sealed_checkpoint: signer must return 64 bytes")
        return {"checkpoint": cp,
                "signature": base64.b64encode(bytes(sig)).decode("ascii")}

    def inclusion_proof(self, index):
        """Wire inclusion proof for leaf ``index`` against the current
        tree: ``{"leaf_index", "tree_size", "path": [{"hash", "side"}]}``.

        ``tree_size`` here is informational -- verifiers MUST take the
        tree size from the verified checkpoint, never from the proof
        (sigstore-python#248).
        """
        if not self._entries:
            _refuse("witness-log-empty",
                    "no inclusion proof on an empty log")
        if (isinstance(index, bool) or not isinstance(index, int)
                or not 0 <= index < len(self._entries)):
            _refuse("witness-log-index-out-of-range",
                    "leaf index %r outside [0, %d)"
                    % (index, len(self._entries)))
        hashes = self._leaf_hashes()
        path = [{"hash": h.hex(), "side": side}
                for h, side in _audit_path(hashes, index)]
        return {"leaf_index": index,
                "tree_size": len(self._entries),
                "path": path}

    def consistency_proof(self, old_size, new_size=None):
        """Wire consistency proof old_size -> new_size (default: current).

        ``{"old_size", "new_size", "hashes": [...]}`` -- the roots of
        the maximal perfect aligned subtrees tiling [0, old_size) then
        [old_size, new_size). Sizes are informational; the verifier
        takes them from the two verified checkpoints.
        """
        if not self._entries:
            _refuse("witness-log-empty",
                    "no consistency proof on an empty log")
        new_size = len(self._entries) if new_size is None else new_size
        for name, v in (("old_size", old_size), ("new_size", new_size)):
            if (isinstance(v, bool) or not isinstance(v, int)
                    or not 1 <= v <= len(self._entries)):
                _refuse("witness-log-index-out-of-range",
                        "%s %r outside [1, %d]"
                        % (name, v, len(self._entries)))
        if not old_size < new_size:
            _refuse("witness-log-malformed",
                    "consistency needs old_size < new_size, got %d >= %d"
                    % (old_size, new_size))
        hashes = self._leaf_hashes()
        out = []
        for a, b in _decomp(0, old_size) + _decomp(old_size, new_size):
            out.append(_calc_root(hashes[a:b]).hex())
        return {"old_size": old_size, "new_size": new_size,
                "hashes": out}

    def export(self):
        """Serialize the log (entries + bound key) for persistence."""
        return {
            "version": WITNESS_LOG_VERSION,
            "witness_public_key": self._witness_public_key.hex(),
            "entries": [base64.b64encode(e).decode("ascii")
                        for e in self._entries],
        }

    @classmethod
    def import_log(cls, doc):
        """Rebuild a log from :meth:`export`. Strict: anything off
        refuses ``witness-log-malformed``."""
        if not isinstance(doc, dict):
            _refuse("witness-log-malformed", "export must be an object")
        try:
            pub = bytes.fromhex(doc["witness_public_key"])
        except (KeyError, ValueError, TypeError):
            _refuse("witness-log-malformed",
                    "export has bad witness_public_key")
        log = cls(pub)
        entries = doc.get("entries")
        if not isinstance(entries, list):
            _refuse("witness-log-malformed", "export entries must be a list")
        for i, e in enumerate(entries):
            try:
                raw = base64.b64decode(e, validate=True)
            except (binascii.Error, ValueError, TypeError):
                _refuse("witness-log-malformed",
                        "export entry %d: bad base64" % i)
            log.append(raw)
        return log


# ---------------------------------------------------------------------------
# Verification. Checkpoint signature FIRST; sizes/hashes only from the
# verified checkpoint afterwards.
# ---------------------------------------------------------------------------

def _b64_str(value, where):
    if not isinstance(value, str):
        _refuse("witness-log-checkpoint-malformed",
                "%s: must be a base64 str" % (where,))
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        _refuse("witness-log-checkpoint-malformed",
                "%s: invalid base64: %s" % (where, exc))


def verify_checkpoint(sealed, witness_public_key):
    """Verify a sealed checkpoint and return the checkpoint document.

    ``sealed`` is ``{"checkpoint": {...}, "signature": "<base64>"}``.
    The signature is verified FIRST over the canonical bytes; only
    then are ``treeSize``/``rootHash``/``timestamp``/``logId`` parsed
    from the verified document. ``witness_public_key`` (32 bytes) is
    the pinned key -- the checkpoint's ``logId`` must name it.

    Returns the verified checkpoint dict. Raises ``WitnessError`` coded
    on any failure; never returns partial trust.
    """
    pub = _check_pubkey(witness_public_key, "verify_checkpoint")
    if not isinstance(sealed, dict):
        _refuse("witness-log-checkpoint-malformed",
                "sealed checkpoint must be an object")
    cp = sealed.get("checkpoint")
    if not isinstance(cp, dict):
        _refuse("witness-log-checkpoint-malformed",
                "checkpoint must be an object")
    # --- signature FIRST, before parsing anything ---
    sig = _b64_str(sealed.get("signature"), "checkpoint.signature")
    if len(sig) != 64:
        _refuse("witness-log-checkpoint-signature-invalid",
                "signature is %d bytes, want 64" % len(sig))
    try:
        signed_bytes = canonical_bytes(cp)
    except WitnessError as exc:
        _refuse("witness-log-checkpoint-malformed",
                "checkpoint not canonical-serializable: %s" % exc)
    if _ed25519_verify(pub, signed_bytes, sig) is not True:
        _refuse("witness-log-checkpoint-signature-invalid",
                "checkpoint signature does not verify against the "
                "pinned witness key")
    # --- only now parse the verified document (narrow input) ---
    if set(cp.keys()) != {"logId", "treeSize", "rootHash", "timestamp"}:
        _refuse("witness-log-checkpoint-malformed",
                "checkpoint keys must be exactly "
                "{logId, treeSize, rootHash, timestamp}, got %s"
                % sorted(cp.keys()))
    tree_size = cp["treeSize"]
    if (isinstance(tree_size, bool) or not isinstance(tree_size, int)
            or tree_size < 1):
        _refuse("witness-log-checkpoint-malformed",
                "treeSize must be a positive int")
    root_hex = cp["rootHash"]
    if (not isinstance(root_hex, str) or len(root_hex) != 64
            or any(c not in "0123456789abcdefABCDEF"
                   for c in root_hex)):
        _refuse("witness-log-checkpoint-malformed",
                "rootHash must be 64 hex chars")
    timestamp = cp["timestamp"]
    if (isinstance(timestamp, bool) or not isinstance(timestamp, int)
            or timestamp < 0):
        _refuse("witness-log-checkpoint-malformed",
                "timestamp must be a non-negative int unix time")
    log_id = cp["logId"]
    if (not isinstance(log_id, str)
            or log_id.lower() != hashlib.sha256(pub).hexdigest()):
        _refuse("witness-log-checkpoint-malformed",
                "logId does not name the pinned witness key")
    return cp


def _path_leaf_index(path, tree_size):
    """Recover the leaf index a wire audit path addresses.

    The path is leaf-to-root; reversed, it walks root-to-leaf through
    the RFC 6962 split structure. A path whose sides do not describe a
    real root-to-leaf walk for ``tree_size`` refuses
    ``witness-log-malformed``.
    """
    lo, hi = 0, tree_size
    for sib, side in reversed(path):
        if hi - lo == 1:
            _refuse("witness-log-malformed",
                    "inclusion: path longer than the tree depth")
        k = lo + _largest_pow2_lt(hi - lo)
        if side == "right":
            hi = k
        else:
            lo = k
    if hi - lo != 1:
        _refuse("witness-log-malformed",
                "inclusion: path does not reach a leaf")
    return lo


def _parse_path(path, where):
    """Strict-parse a wire audit path into [(hash_bytes, side)]."""
    if not isinstance(path, list):
        _refuse("witness-log-malformed", "%s: path must be a list" % where)
    out = []
    for i, node in enumerate(path):
        w = "%s[%d]" % (where, i)
        if not isinstance(node, dict):
            _refuse("witness-log-malformed", "%s: must be an object" % w)
        h = node.get("hash")
        if (not isinstance(h, str) or len(h) != 64
                or any(c not in "0123456789abcdefABCDEF" for c in h)):
            _refuse("witness-log-malformed",
                    "%s.hash: must be 64 hex chars" % w)
        side = node.get("side")
        if side not in ("left", "right"):
            _refuse("witness-log-malformed",
                    "%s.side: must be 'left' or 'right'" % w)
        out.append((bytes.fromhex(h), side))
    return out


def verify_inclusion(leaf, leaf_index, path, tree_size, root_hash):
    """Verify a leaf's inclusion against a checkpoint's root.

    ``leaf``: the raw leaf bytes. ``leaf_index``/``tree_size``/
    ``root_hash`` come ONLY from a verified checkpoint -- never from
    the proof envelope. ``path`` is the wire audit path. The path's
    sides must address exactly ``leaf_index`` (position binding), the
    path length must match ``(leaf_index, tree_size)``, and the fold
    must recompute ``root_hash``. Raises
    ``witness-log-inclusion-invalid`` when the proof does not verify;
    ``witness-log-malformed`` on structurally bad input.
    """
    if not isinstance(leaf, (bytes, bytearray)) or not leaf:
        _refuse("witness-log-malformed",
                "inclusion: leaf must be non-empty bytes")
    for name, v, lo in (("leaf_index", leaf_index, 0),
                        ("tree_size", tree_size, 1)):
        if (isinstance(v, bool) or not isinstance(v, int) or v < lo):
            _refuse("witness-log-malformed",
                    "inclusion: %s must be an int >= %d" % (name, lo))
    if not 0 <= leaf_index < tree_size:
        _refuse("witness-log-inclusion-invalid",
                "leaf_index %d outside tree_size %d"
                % (leaf_index, tree_size))
    if not isinstance(root_hash, (bytes, bytearray)) or len(root_hash) != 32:
        _refuse("witness-log-malformed",
                "inclusion: root_hash must be 32 bytes")
    nodes = _parse_path(path, "inclusion_path")
    # Bind the proof to the claimed size: a path whose length is
    # inconsistent with (leaf_index, tree_size) is refused even before
    # folding (a wrong-size proof must never be "close enough").
    want_len = _audit_path_len(leaf_index, tree_size)
    if len(nodes) != want_len:
        _refuse("witness-log-inclusion-invalid",
                "audit path length %d, want %d for leaf %d in tree "
                "of size %d" % (len(nodes), want_len, leaf_index,
                                tree_size))
    # Bind the proof to the claimed POSITION: the path's sides address
    # exactly one leaf; a proof for another index presented under this
    # one refuses even when it folds to the right root.
    addressed = _path_leaf_index(nodes, tree_size)
    if addressed != leaf_index:
        _refuse("witness-log-inclusion-invalid",
                "audit path addresses leaf %d, not claimed leaf %d"
                % (addressed, leaf_index))
    h = leaf_hash(bytes(leaf))
    for sib, side in nodes:
        h = node_hash(sib, h) if side == "left" else node_hash(h, sib)
    if h != bytes(root_hash):
        _refuse("witness-log-inclusion-invalid",
                "audit path does not recompute the checkpoint root")
    # No return value: success is silent, failure raises. (There is no
    # "False" -- a soft False would let callers forget to check.)


def verify_consistency(old_size, old_root, new_size, new_root,
                       proof_hashes):
    """Verify old_size -> new_size consistency (the old tree is a
    prefix of the new tree).

    ``old_size``/``new_size``/``old_root``/``new_root`` come ONLY from
    two verified checkpoints. ``proof_hashes`` is the wire list of hex
    subtree roots (border decomposition). Both roots are recomputed
    deterministically from the proof and compared -- a forged proof
    needs a hash preimage/collision. Raises
    ``witness-log-consistency-invalid`` on any mismatch.
    """
    for name, v in (("old_size", old_size), ("new_size", new_size)):
        if (isinstance(v, bool) or not isinstance(v, int) or v < 1):
            _refuse("witness-log-malformed",
                    "consistency: %s must be a positive int" % name)
    if not old_size < new_size:
        _refuse("witness-log-consistency-invalid",
                "need old_size < new_size, got %d >= %d"
                % (old_size, new_size))
    for name, r in (("old_root", old_root), ("new_root", new_root)):
        if not isinstance(r, (bytes, bytearray)) or len(r) != 32:
            _refuse("witness-log-malformed",
                    "consistency: %s must be 32 bytes" % name)
    if not isinstance(proof_hashes, list) or not proof_hashes:
        _refuse("witness-log-malformed",
                "consistency: proof_hashes must be a non-empty list")
    decoded = []
    for i, h in enumerate(proof_hashes):
        if (not isinstance(h, str) or len(h) != 64
                or any(c not in "0123456789abcdefABCDEF" for c in h)):
            _refuse("witness-log-malformed",
                    "consistency: proof_hashes[%d] must be 64 hex chars"
                    % i)
        decoded.append(bytes.fromhex(h))
    want = len(_decomp(0, old_size)) + len(_decomp(old_size, new_size))
    if len(decoded) != want:
        _refuse("witness-log-consistency-invalid",
                "proof has %d hashes, want %d for %d -> %d"
                % (len(decoded), want, old_size, new_size))
    dm = _decomp(0, old_size)
    dr = _decomp(old_size, new_size)
    env_old = dict(zip(dm, decoded[:len(dm)]))
    calc_old = _reval(0, old_size, env_old)
    if calc_old != bytes(old_root):
        _refuse("witness-log-consistency-invalid",
                "proof does not recompute the old checkpoint root")
    env_all = dict(zip(dm + dr, decoded))
    calc_new = _reval(0, new_size, env_all)
    if calc_new != bytes(new_root):
        _refuse("witness-log-consistency-invalid",
                "proof does not recompute the new checkpoint root")
