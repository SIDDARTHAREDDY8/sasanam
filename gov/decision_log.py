"""RFC 6962 Merkle-tree decision log for the policy combiner.

Wave-250 lane 2. Stdlib only.

transparency-dev/merkle ADAPT (Apache-2.0 -- a pattern adaptation
only, never upstream code): an append-only Merkle tree over combined
policy decisions, closing the two documented wave-248 combiner
residuals:

  1. same-revision equivocation: two decisions from one pinned policy
     revision with different effects used to combine without
     complaint. Now every combined decision is a leaf, and
     ``detect_equivocation()`` produces inclusion-proven evidence
     when two logged decisions share (request digest, policy
     revision set) but differ in effect.
  2. no request binding: the combiner never verified all decisions
     were made for the same request. The log binds appends to one
     request digest per epoch; a different digest refuses
     (``decision-log-request-mismatch``) unless the operator
     explicitly opens a new epoch via ``new_epoch()``. Request
     binding is therefore structural at the logging seam.

RFC 6962 construction (SHA-256):
  * ``hash_leaf(data)  = SHA256(0x00 || data)``
  * ``hash_node(l, r)  = SHA256(0x01 || l || r)``
  * empty tree root    = SHA256(b"")
  * subtree split: largest power of two strictly below n

The inclusion/consistency proof algorithms are ported from
transparency-dev/merkle/proof/verify.go (Apache-2.0, pattern only)
and pinned against the upstream testdata vectors
(``testdata/inclusion`` and ``testdata/consistency`` happy-path
vectors, plus the ``rfc6962_test.go`` hash vectors); the vectors are
embedded in ``evals/w250_decision_log_probes.py`` and
``tests/test_decision_log.py``.

Trust model: the log DETECTS, it does not PREVENT. An equivocating
policy set is recorded (refusing to log it would hide the evidence);
``detect_equivocation()`` surfaces the proof. Signed tree heads
(STH) bind (tree_size, root, timestamp); the STH signing key is
deployment-owned -- ``sign_sth()`` takes the caller's seed and the
module never generates or stores keys.

Fail-closed: malformed leaves, non-32-byte request digests, mixed
request digests without epoch separation, and proof verification
failures all raise ``DecisionLogError`` (never a silent False at the
log seam; the pure ``MerkleTree`` verifiers return bool like the
upstream Go API).
"""

import hashlib
import hmac
import json
import struct
import time

from .ed25519 import sign as _ed_sign
from .ed25519 import verify as _ed_verify
from .policy_combine import CombinedDecision

__all__ = [
    "DecisionLog",
    "DecisionLogError",
    "EquivocationProof",
    "MerkleTree",
    "detect_equivocation",
    "empty_root",
    "hash_leaf",
    "hash_node",
]

# Machine decision codes emitted at this seam (also in
# gov/decision_codes.py under domain "decision-log").
MALFORMED_CODE = "decision-log-malformed"
REQUEST_MISMATCH_CODE = "decision-log-request-mismatch"
PROOF_INVALID_CODE = "decision-log-proof-invalid"
EQUIVOCATION_CODE = "decision-log-equivocation"

_HASH_LEN = 32
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
_STH_DOMAIN = b"decision-log-sth-v1"


class DecisionLogError(ValueError):
    """Fail-closed refusal at the decision-log seam.

    Carries the machine ``code`` (one of the decision-log codes).
    """

    def __init__(self, code, detail):
        super(DecisionLogError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# ------------------------------------------------- RFC 6962 hashes


def hash_leaf(data):
    """SHA256(0x00 || data). ``data`` must be bytes."""
    if not isinstance(data, bytes):
        raise DecisionLogError(
            MALFORMED_CODE, "leaf data must be bytes, got %s"
            % (type(data).__name__,))
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def hash_node(left, right):
    """SHA256(0x01 || left || right).

    Matches the upstream hasher API: children are arbitrary bytes
    (the tree itself always passes 32-byte hashes).
    """
    for name, value in (("left", left), ("right", right)):
        if not isinstance(value, bytes):
            raise DecisionLogError(
                MALFORMED_CODE,
                "node child %s must be bytes, got %s"
                % (name, type(value).__name__))
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def empty_root():
    """The RFC 6962 root of the empty tree: SHA256(b"")."""
    return hashlib.sha256(b"").digest()


def _split(n):
    """Largest power of two strictly below n (n >= 2)."""
    if n < 2:
        raise DecisionLogError(
            MALFORMED_CODE, "split needs n >= 2, got %r" % (n,))
    return 1 << ((n - 1).bit_length() - 1)


def _trailing_zeros(n):
    if n <= 0:
        raise DecisionLogError(
            MALFORMED_CODE, "trailing zeros needs n > 0, got %r" % (n,))
    return (n & -n).bit_length() - 1


# ------------------------------------------------- Merkle tree


class MerkleTree(object):
    """Append-only RFC 6962 Merkle tree over opaque leaf bytes.

    The tree keeps every leaf hash; proofs are computed on demand.
    Proof ordering is the upstream convention: inner (sibling)
    hashes leaf-ward first, then border (left-only) hashes.
    """

    def __init__(self):
        self._leaf_hashes = []

    def __len__(self):
        return len(self._leaf_hashes)

    def append(self, leaf_data):
        """Append one leaf; returns its 0-based index."""
        self._leaf_hashes.append(hash_leaf(leaf_data))
        return len(self._leaf_hashes) - 1

    def _node(self, lo, n):
        if n == 1:
            return self._leaf_hashes[lo]
        k = _split(n)
        return hash_node(self._node(lo, k), self._node(lo + k, n - k))

    def root(self):
        """Current tree root (empty_root() for the empty tree)."""
        if not self._leaf_hashes:
            return empty_root()
        return self._node(0, len(self._leaf_hashes))

    def _inclusion(self, lo, n, m):
        if n == 1:
            return []
        k = _split(n)
        if m < k:
            return (self._inclusion(lo, k, m)
                    + [self._node(lo + k, n - k)])
        return (self._inclusion(lo + k, n - k, m - k)
                + [self._node(lo, k)])

    def inclusion_proof(self, index):
        """Inclusion proof for leaf ``index`` (leaf-ward order)."""
        n = len(self._leaf_hashes)
        if not isinstance(index, int) or index < 0 or index >= n:
            raise DecisionLogError(
                MALFORMED_CODE,
                "leaf index %r out of range for tree of size %d"
                % (index, n))
        return self._inclusion(0, n, index)

    def consistency_proof(self, size1):
        """Proof that the size-``size1`` prefix is consistent.

        Returns the canonical proof: for power-of-two ``size1`` the
        suffix of the inclusion proof of leaf ``size1-1``; otherwise
        that suffix prefixed with the root of the rightmost perfect
        subtree of [0, size1).
        """
        n = len(self._leaf_hashes)
        if not isinstance(size1, int) or size1 <= 0 or size1 > n:
            raise DecisionLogError(
                MALFORMED_CODE,
                "consistency needs 0 < size1 <= %d, got %r" % (n, size1))
        if size1 == n:
            return []
        full = self._inclusion(0, n, size1 - 1)
        shift = _trailing_zeros(size1)
        suffix = full[shift:]
        if size1 == (1 << shift):
            return suffix
        rsub = 1 << shift
        rightmost = self._node(size1 - rsub, rsub)
        return [rightmost] + suffix

    # -- static verifiers (upstream-shaped: bool, never raise) --

    @staticmethod
    def verify_inclusion(index, leaf_hash, tree_size, proof, root):
        """True iff the inclusion proof chains leaf to root."""
        if (not isinstance(index, int) or not isinstance(tree_size, int)
                or index < 0 or index >= tree_size or tree_size <= 0):
            return False
        if (not isinstance(leaf_hash, bytes)
                or len(leaf_hash) != _HASH_LEN
                or not isinstance(root, bytes)
                or len(root) != _HASH_LEN):
            return False
        if (not isinstance(proof, (list, tuple))
                or any(not isinstance(p, bytes) or len(p) != _HASH_LEN
                       for p in proof)):
            return False
        inner = (index ^ (tree_size - 1)).bit_length()
        border = bin(index >> inner).count("1")
        if len(proof) != inner + border:
            return False
        calc = leaf_hash
        for i, sib in enumerate(proof[:inner]):
            if (index >> i) & 1 == 0:
                calc = hash_node(calc, sib)
            else:
                calc = hash_node(sib, calc)
        for sib in proof[inner:]:
            calc = hash_node(sib, calc)
        return hmac.compare_digest(calc, root)

    @staticmethod
    def verify_consistency(size1, size2, proof, root1, root2):
        """True iff the proof shows size1's tree inside size2's."""
        if (not isinstance(size1, int) or not isinstance(size2, int)
                or size1 <= 0 or size1 > size2):
            return False
        for value in (root1, root2):
            if not isinstance(value, bytes) or len(value) != _HASH_LEN:
                return False
        if (not isinstance(proof, (list, tuple))
                or any(not isinstance(p, bytes) or len(p) != _HASH_LEN
                       for p in proof)):
            return False
        if size1 == size2:
            return len(proof) == 0 and hmac.compare_digest(root1, root2)
        # Port of rootFromSubtreeConsistencyProof(start=0, end=size1).
        end, size = size1, size2
        fork_inner = ((end - 1) ^ (size - 1)).bit_length()
        fork_border = bin((end - 1) >> fork_inner).count("1")
        shift = _trailing_zeros(end)
        inner = fork_inner - shift
        if end == (1 << shift):
            seed, rest = root1, list(proof)
        else:
            if not proof:
                return False
            seed, rest = proof[0], list(proof[1:])
        if len(rest) != inner + fork_border:
            return False
        if seed is not root1:
            # Sub-proof: seed must chain back to root1 (the argument
            # subtree root). Port of decompSubtreeProof(start=0).
            h = (end - 1).bit_length()
            sub_inner = min(h, fork_inner) - shift
            sub_border = max(
                0, fork_border - bin((end - 1) >> h).count("1"))
            if sub_inner < 0 or inner + sub_border > len(rest):
                return False
            mask = (end - 1) >> shift
            calc = seed
            for i, sib in enumerate(rest[:sub_inner]):
                if (mask >> i) & 1 == 1:
                    calc = hash_node(sib, calc)
            for sib in rest[inner:inner + sub_border]:
                calc = hash_node(sib, calc)
            if not hmac.compare_digest(calc, root1):
                return False
        mask = (end - 1) >> shift
        calc = seed
        for i, sib in enumerate(rest[:inner]):
            if (mask >> i) & 1 == 0:
                calc = hash_node(calc, sib)
            else:
                calc = hash_node(sib, calc)
        for sib in rest[inner:]:
            calc = hash_node(sib, calc)
        return hmac.compare_digest(calc, root2)


# ------------------------------------------------- canonical leaves


def _policy_key(combined):
    """Sortable identity of the deciding policy-revision set."""
    parts = []
    for dec in combined.decisions:
        parts.append((
            "" if dec.policy_id is None else str(dec.policy_id),
            "" if dec.policy_rev_id is None else str(dec.policy_rev_id),
            "" if dec.policy_digest is None else str(dec.policy_digest),
        ))
    return tuple(sorted(parts))


def _canonical_leaf_bytes(combined, request_digest):
    policies = []
    for dec in combined.decisions:
        policies.append({
            "digest": dec.policy_digest,
            "effect": dec.effect,
            "policy_id": dec.policy_id,
            "rev_id": dec.policy_rev_id,
        })
    policies.sort(key=lambda p: (
        str(p["policy_id"]), str(p["rev_id"]), str(p["digest"])))
    doc = {
        "code": "decision-log-leaf-v1",
        "effect": combined.effect,
        "n_decisions": len(combined.decisions),
        "policies": policies,
        "request_digest": request_digest.hex(),
    }
    return json.dumps(doc, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _check_request_digest(value):
    if not isinstance(value, bytes) or len(value) != _HASH_LEN:
        raise DecisionLogError(
            MALFORMED_CODE,
            "request digest must be %d bytes, got %r"
            % (_HASH_LEN, type(value).__name__))
    return value


# ------------------------------------------------- equivocation proof


class EquivocationProof(object):
    """Proven equivocation: same (request, policy revisions), two effects.

    Carries both leaf indices, both inclusion proofs, and the tree
    root/size they verify against. ``verify(log)`` re-checks both
    proofs against the log's current root -- True means the
    equivocation is cryptographically demonstrated.
    """

    code = EQUIVOCATION_CODE

    def __init__(self, request_digest, policy_key, index_a, effect_a,
                 proof_a, index_b, effect_b, proof_b, tree_size, root):
        self.request_digest = request_digest
        self.policy_key = policy_key
        self.index_a = index_a
        self.effect_a = effect_a
        self.proof_a = tuple(proof_a)
        self.index_b = index_b
        self.effect_b = effect_b
        self.proof_b = tuple(proof_b)
        self.tree_size = tree_size
        self.root = root

    def verify(self, log):
        """Re-verify both halves against the log's current root."""
        if not isinstance(log, DecisionLog):
            return False
        if log.tree_size() < self.tree_size:
            return False
        root = log.root()
        if not hmac.compare_digest(root, self.root):
            return False
        if self.effect_a == self.effect_b:
            return False
        leaf_a = log._leaf_hash_at(self.index_a)
        leaf_b = log._leaf_hash_at(self.index_b)
        ok_a = MerkleTree.verify_inclusion(
            self.index_a, leaf_a,
            self.tree_size, list(self.proof_a), self.root)
        ok_b = MerkleTree.verify_inclusion(
            self.index_b, leaf_b,
            self.tree_size, list(self.proof_b), self.root)
        return bool(ok_a and ok_b)

    def to_dict(self):
        return {
            "code": self.code,
            "request_digest": self.request_digest.hex(),
            "policy_key": [list(p) for p in self.policy_key],
            "index_a": self.index_a,
            "effect_a": self.effect_a,
            "index_b": self.index_b,
            "effect_b": self.effect_b,
            "tree_size": self.tree_size,
            "root": self.root.hex(),
        }


def detect_equivocation(log):
    """Find proven equivocations in the log.

    Groups leaves by (request digest, policy-revision set); a group
    with two different combined effects yields one EquivocationProof
    (first index of each effect). Returns a list (possibly empty).
    The log detects -- it does not prevent: equivocating leaves are
    recorded, and this function surfaces the evidence.
    """
    if not isinstance(log, DecisionLog):
        raise DecisionLogError(
            MALFORMED_CODE, "detect_equivocation needs a DecisionLog")
    groups = {}
    order = []
    for idx, (req, combined) in enumerate(log._entries()):
        key = (req, _policy_key(combined))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((idx, combined.effect))
    root = log.root()
    size = log.tree_size()
    out = []
    for key in order:
        items = groups[key]
        effects = {}
        for idx, effect in items:
            effects.setdefault(effect, idx)
        if len(effects) < 2:
            continue
        (eff_a, idx_a), (eff_b, idx_b) = list(effects.items())[:2]
        out.append(EquivocationProof(
            key[0], key[1], idx_a, eff_a,
            log.inclusion_proof(idx_a), idx_b, eff_b,
            log.inclusion_proof(idx_b), size, root))
    return out


# ------------------------------------------------- the log


class DecisionLog(object):
    """Append-only decision log with structural request binding.

    ``append(combined, request_digest)`` records one CombinedDecision
    under a 32-byte request digest. The first append binds the log's
    epoch; a later append with a different digest raises
    ``decision-log-request-mismatch`` -- the operator must call
    ``new_epoch(digest)`` explicitly to move on. Epochs are logical
    (one Merkle tree); every leaf stays inclusion-provable against
    the current root.
    """

    def __init__(self):
        self._tree = MerkleTree()
        self._leaf_hashes = []  # parallel: leaf hashes (32 bytes)
        self._entries_data = []  # (request_digest, CombinedDecision)
        self._epochs = []
        self._bound = None

    # -- internal accessors used by detect_equivocation --

    def _entries(self):
        return list(self._entries_data)

    def _leaf_hash_at(self, index):
        return self._leaf_hashes[index]

    # -- append / epochs --

    def append(self, combined, request_digest):
        """Append one combined decision; returns its leaf index."""
        if not isinstance(combined, CombinedDecision):
            raise DecisionLogError(
                MALFORMED_CODE,
                "leaf must be a CombinedDecision, got %s"
                % (type(combined).__name__,))
        _check_request_digest(request_digest)
        if self._bound is None:
            self._bound = request_digest
            self._epochs.append({
                "request_digest": request_digest.hex(),
                "start_index": len(self._tree),
            })
        elif not hmac.compare_digest(request_digest, self._bound):
            raise DecisionLogError(
                REQUEST_MISMATCH_CODE,
                "append carries a different request digest than the "
                "bound epoch; call new_epoch() explicitly to separate")
        leaf = _canonical_leaf_bytes(combined, request_digest)
        idx = self._tree.append(leaf)
        self._leaf_hashes.append(hash_leaf(leaf))
        self._entries_data.append((request_digest, combined))
        return idx

    def new_epoch(self, request_digest):
        """Explicitly start a new request epoch.

        Same-digest is a no-op. A different digest rebinds; the
        boundary (start index) is recorded so auditors can attribute
        leaves to epochs.
        """
        _check_request_digest(request_digest)
        if self._bound is not None and hmac.compare_digest(
                request_digest, self._bound):
            return dict(self._epochs[-1])
        self._bound = request_digest
        epoch = {
            "request_digest": request_digest.hex(),
            "start_index": len(self._tree),
        }
        self._epochs.append(epoch)
        return dict(epoch)

    def epochs(self):
        """Epoch boundaries: [{request_digest, start_index}]."""
        return [dict(e) for e in self._epochs]

    # -- reads --

    def tree_size(self):
        return len(self._tree)

    def root(self):
        return self._tree.root()

    def inclusion_proof(self, index):
        return self._tree.inclusion_proof(index)

    def verify_leaf(self, index):
        """True iff leaf ``index`` inclusion-proves to current root."""
        proof = self._tree.inclusion_proof(index)
        return MerkleTree.verify_inclusion(
            index, self._leaf_hashes[index], len(self._tree), proof,
            self._tree.root())

    def verify_proof(self, index, proof):
        """Check an externally supplied proof; True or raise."""
        if not isinstance(index, int) or index < 0 \
                or index >= len(self._tree):
            raise DecisionLogError(
                MALFORMED_CODE, "leaf index %r out of range" % (index,))
        ok = MerkleTree.verify_inclusion(
            index, self._leaf_hashes[index], len(self._tree),
            proof, self._tree.root())
        if ok is not True:
            raise DecisionLogError(
                PROOF_INVALID_CODE,
                "inclusion proof for leaf %d does not verify" % (index,))
        return True

    def consistency_proof(self, old_size):
        """Proof that the ``old_size`` prefix tree is consistent."""
        return self._tree.consistency_proof(old_size)

    def verify_consistency(self, old_size, old_root, proof):
        """True or raise: old tree consistent with the current one."""
        if not isinstance(old_root, bytes) or len(old_root) != _HASH_LEN:
            raise DecisionLogError(
                MALFORMED_CODE, "old root must be 32 bytes")
        ok = MerkleTree.verify_consistency(
            old_size, len(self._tree), proof, old_root,
            self._tree.root())
        if ok is not True:
            raise DecisionLogError(
                PROOF_INVALID_CODE,
                "consistency proof %d -> %d does not verify"
                % (old_size, len(self._tree)))
        return True

    # -- signed tree heads (deployment-owned key) --

    @staticmethod
    def _sth_bytes(tree_size, root, timestamp):
        return (_STH_DOMAIN
                + struct.pack(">Q", tree_size)
                + root
                + struct.pack(">Q", timestamp))

    def issue_sth(self):
        """Issue an unsigned tree head over the current tree."""
        return {
            "tree_size": len(self._tree),
            "root": self._tree.root().hex(),
            "timestamp": int(time.time()),
            "signature": None,
        }

    def sign_sth(self, sth, seed):
        """Sign a tree head with the deployment-owned seed.

        ``seed`` is the Ed25519 seed (32 bytes); the module never
        generates or stores it.
        """
        if not isinstance(sth, dict):
            raise DecisionLogError(MALFORMED_CODE, "STH must be a dict")
        try:
            tree_size = sth["tree_size"]
            root = bytes.fromhex(sth["root"])
            timestamp = sth["timestamp"]
        except (KeyError, ValueError, TypeError):
            raise DecisionLogError(
                MALFORMED_CODE, "STH missing tree_size/root/timestamp")
        if (not isinstance(tree_size, int) or len(root) != _HASH_LEN
                or not isinstance(timestamp, int)):
            raise DecisionLogError(MALFORMED_CODE, "STH fields malformed")
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise DecisionLogError(
                MALFORMED_CODE, "STH seed must be 32 bytes")
        msg = self._sth_bytes(tree_size, root, timestamp)
        signed = dict(sth)
        signed["signature"] = _ed_sign(seed, msg).hex()
        return signed

    def verify_sth(self, sth, pubkey):
        """True iff the STH signature verifies under ``pubkey``."""
        try:
            if not isinstance(sth, dict):
                return False
            sig_hex = sth.get("signature")
            root = bytes.fromhex(sth["root"])
            msg = self._sth_bytes(sth["tree_size"], root,
                                  sth["timestamp"])
            sig = bytes.fromhex(sig_hex)
        except (KeyError, ValueError, TypeError, AttributeError):
            return False
        if not isinstance(pubkey, bytes) or len(pubkey) != 32:
            return False
        return _ed_verify(pubkey, msg, sig) is True
