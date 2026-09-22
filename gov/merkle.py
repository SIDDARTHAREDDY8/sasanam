"""RFC 6962-style Merkle history tree over audit-log entries.

P2 (crypto workstream): the tamper-evidence data structure for the audit
log, implementing the literature IMPLEMENT items:

* **Certificate Transparency (Laurie, Langley, Kasper; RFC 6962/9162).**
  This module is the log's Merkle tree; ``gov/log.py`` checkpoints with
  ``format_version == 2`` are the *signed tree heads* (STH); inclusion
  proofs and consistency proofs below are the CT auditor primitives.
  The explicit STH field mapping lives in ``gov/log.py``'s docstring.
  What CT's gossip protocol does for public logs (detecting a
  split-view/equivocating log), our deployment does out-of-band via the
  trusted signing-key set -- there is deliberately no in-repo gossip
  protocol; claiming otherwise would overstate the design.
* **Crosby & Wallach, "Efficient Data Structures for Tamper-Evident
  Logging" (USENIX Security 2009).** The paper's guidance is adopted as
  the graduation criterion for this module: a hash chain is only
  efficient when every auditor replays the whole log. The history tree
  here lets a third-party auditor verify any single entry with an
  O(log n) inclusion proof and verify that a newer tree head extends an
  older one with an O(log n) consistency proof -- no HMAC key, no full
  replay. Until this module, every auditor of this log paid O(n).

Leaves commit to the full stored entry (canonical JSON *including* the
chain ``hash``), so a length-preserving rewrite that keeps the hash
string -- the F70 shape -- still changes the leaf. Internal nodes are
domain-separated per RFC 6962 (0x00 leaf / 0x01 node), with our own
domain strings to avoid cross-protocol collisions.

Division of labor (same as Certificate Transparency): proof *generation*
is O(n) server-side -- the log operator holds all leaves; the proof
itself is O(log n) and *verification* is O(log n) given only the leaf,
the proof, the tree size, and the signed root. Per-append root updates
are O(log n) amortized via the incremental stack below.
"""

import hashlib
import hmac

LEAF_DOMAIN = b"gov-merkle-leaf/v1\x00"
NODE_DOMAIN = b"gov-merkle-node/v1\x00"
EMPTY_ROOT = b"\x00" * 32


def leaf_hash(canonical_entry_bytes):
    """Leaf hash committing to one stored entry's canonical bytes."""
    if not isinstance(canonical_entry_bytes, (bytes, bytearray)):
        raise TypeError("canonical entry must be bytes")
    return hashlib.sha256(LEAF_DOMAIN + bytes(canonical_entry_bytes)).digest()


def _node_hash(left, right):
    return hashlib.sha256(NODE_DOMAIN + bytes(left) + bytes(right)).digest()


def _largest_pow2_lt(n):
    k = 1
    while 2 * k < n:
        k *= 2
    return k


def tree_root(leaves):
    """RFC 6962 MTH over a list of 32-byte leaf hashes.

    Pairwise fold with odd-carry-up; equals the RFC's recursive split on
    the largest power of two < n (cross-checked in selftest).
    """
    leaves = [bytes(l) for l in leaves]
    for l in leaves:
        if len(l) != 32:
            raise ValueError("leaf hashes must be 32 bytes")
    if not leaves:
        return EMPTY_ROOT
    level = leaves
    while len(level) > 1:
        nxt = [_node_hash(level[i], level[i + 1])
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


class MerkleStack:
    """Incremental CT-style append stack.

    ``sub[h]`` holds the root of a complete 2**h-leaf subtree (or is
    absent); the set bits of ``n`` say which heights are present.
    Appending one leaf is amortized O(1) merges; the root is O(log n).
    The stack serializes to ``{"n": n, "sub": {h: hex}}`` for checkpoint
    persistence, so crash recovery never needs the full leaf list.
    """

    def __init__(self, n=0, sub=None):
        self.n = int(n)
        self.sub = {int(h): bytes(v) for h, v in (sub or {}).items()}
        for h, v in self.sub.items():
            if len(v) != 32:
                raise ValueError("subtree roots must be 32 bytes")
        if sum(1 << h for h in self.sub) != self.n:
            raise ValueError("stack subtrees do not cover n=%d" % self.n)

    def append(self, leaf):
        carry = bytes(leaf)
        if len(carry) != 32:
            raise ValueError("leaf must be 32 bytes")
        h = 0
        while h in self.sub:
            carry = _node_hash(self.sub.pop(h), carry)
            h += 1
        self.sub[h] = carry
        self.n += 1

    def root(self):
        if self.n == 0:
            return EMPTY_ROOT
        # Right fold over leaf-ordered subtrees: root = foldr node.
        hs = [self.sub[h] for h in sorted(self.sub, reverse=True)]
        r = hs[-1]
        for x in reversed(hs[:-1]):
            r = _node_hash(x, r)
        return r

    def to_dict(self):
        return {"n": self.n,
                "sub": {str(h): v.hex() for h, v in self.sub.items()}}

    @classmethod
    def from_dict(cls, d):
        return cls(n=d["n"],
                   sub={h: bytes.fromhex(x)
                        for h, x in d["sub"].items()})


def inclusion_proof(leaves, index):
    """O(log n)-sized inclusion proof for ``leaves[index]`` (0-based).

    Returned list is ordered root-level-first, consumed top-down by
    :func:`verify_inclusion`.
    """
    leaves = [bytes(l) for l in leaves]
    n = len(leaves)
    if not (0 <= index < n):
        raise ValueError("index out of range")
    if n == 1:
        return []
    k = _largest_pow2_lt(n)
    if index < k:
        return [tree_root(leaves[k:])] + inclusion_proof(leaves[:k], index)
    return [tree_root(leaves[:k])] + inclusion_proof(leaves[k:], index - k)


def verify_inclusion(leaf, index, proof, root, tree_size):
    """Verify a leaf's inclusion under ``root``.

    Needs only the 32-byte leaf, the O(log n) proof, the leaf index, the
    tree size, and the trusted root -- no log access. Returns True/False;
    never raises on malformed inputs (fail-closed for verifiers).
    """
    if (not isinstance(leaf, (bytes, bytearray)) or len(leaf) != 32
            or not isinstance(root, (bytes, bytearray)) or len(root) != 32):
        return False
    if not isinstance(index, int) or not isinstance(tree_size, int):
        return False
    if not (0 <= index < tree_size):
        return False
    try:
        proof = [bytes(p) for p in proof]
    except TypeError:
        return False
    if any(len(p) != 32 for p in proof):
        return False
    h = bytes(leaf)
    pos = 0

    def rec(m, n):
        nonlocal h, pos
        if n == 1:
            return True
        if pos >= len(proof):
            return False
        k = _largest_pow2_lt(n)
        sib = proof[pos]
        pos += 1
        if m < k:
            if not rec(m, k):
                return False
            h = _node_hash(h, sib)
        else:
            if not rec(m - k, n - k):
                return False
            h = _node_hash(sib, h)
        return True

    if not rec(index, tree_size):
        return False
    if pos != len(proof):
        return False
    return hmac.compare_digest(h, bytes(root))



def consistency_proof(leaves, old_size):
    """RFC 6962 section 2.1.2 consistency proof.

    Proves the tree over ``leaves[:old_size]`` is a prefix of the tree
    over all of ``leaves`` -- i.e. the log only ever appended. Returns
    the O(log n) node hashes a verifier needs; verification is
    :func:`verify_consistency`. Raises ValueError on out-of-range
    ``old_size`` (fail-fast for the *prover*; the verifier side is
    fail-closed and never raises).
    """
    leaves = [bytes(l) for l in leaves]
    n = len(leaves)
    m = int(old_size)
    if isinstance(old_size, bool) or not (0 <= m <= n):
        raise ValueError("old_size out of range")
    if m == n or m == 0 or n == 0:
        return []
    return _consistency_nodes(leaves, m)


def _consistency_nodes(leaves, m):
    """Recursive worker for :func:`consistency_proof` (0 < m < n).

    Emits exactly the node sequence :func:`verify_consistency`'s
    reconstruction consumes: a fully-covered subtree contributes its
    root as one node (the ``m == n`` / ``m == 0`` base cases), otherwise
    the proof splits at the largest power of two below n, mirroring the
    tree's own split.
    """
    n = len(leaves)
    if m == 0 or m == n:
        return [tree_root(leaves)]
    k = _largest_pow2_lt(n)
    if m <= k:
        return _consistency_nodes(leaves[:k], m) + [tree_root(leaves[k:])]
    return [tree_root(leaves[:k])] + _consistency_nodes(leaves[k:], m - k)


def verify_consistency(old_root, new_root, old_size, new_size, proof):
    """Verify an RFC 6962 consistency proof. Fail-closed: any malformed
    input, any proof mismatch, or any sign of a forked/rewritten history
    returns False -- never raises, never returns True on doubt.

    Asserts the tree of ``old_size`` leaves rooted at ``old_root`` is a
    prefix of the tree of ``new_size`` leaves rooted at ``new_root``.
    A log that rewrote history between the two heads cannot produce a
    proof this accepts: the recomputed roots would differ.
    """
    if (not isinstance(old_root, (bytes, bytearray)) or len(old_root) != 32
            or not isinstance(new_root, (bytes, bytearray))
            or len(new_root) != 32):
        return False
    if (not isinstance(old_size, int) or not isinstance(new_size, int)
            or isinstance(old_size, bool) or isinstance(new_size, bool)):
        return False
    if not (0 <= old_size <= new_size):
        return False
    try:
        proof = [bytes(p) for p in proof]
    except TypeError:
        return False
    if any(len(p) != 32 for p in proof):
        return False
    old_root = bytes(old_root)
    new_root = bytes(new_root)
    m, n = old_size, new_size
    if m == n:
        return (not proof) and hmac.compare_digest(old_root, new_root)
    if m == 0:
        # The empty tree is a prefix of every tree: vacuous, nothing to
        # prove and nothing a forger gains.
        return not proof
    pos = [0]

    def take():
        if pos[0] >= len(proof):
            return None
        node = proof[pos[0]]
        pos[0] += 1
        return node

    def rec(mm, nn):
        # Recompute (old_candidate, new_candidate) for a subtree of nn
        # leaves whose first mm are the old prefix. Returns None when
        # the proof runs dry.
        if mm == 0 or mm == nn:
            node = take()
            if node is None:
                return None
            return (None, node) if mm == 0 else (node, node)
        k = _largest_pow2_lt(nn)
        if mm <= k:
            sub = rec(mm, k)
            if sub is None:
                return None
            old_sub, left = sub
            right = take()
            if right is None:
                return None
            return old_sub, _node_hash(left, right)
        left = take()
        if left is None:
            return None
        sub = rec(mm - k, nn - k)
        if sub is None:
            return None
        old_right, right = sub
        return _node_hash(left, old_right), _node_hash(left, right)

    got = rec(m, n)
    if got is None:
        return False
    old_c, new_c = got
    if pos[0] != len(proof):
        return False
    return (hmac.compare_digest(old_c, old_root)
            and hmac.compare_digest(new_c, new_root))


def selftest():
    import os
    # Stack root agrees with batch root for n = 1..64.
    for n in range(1, 65):
        leaves = [os.urandom(32) for _ in range(n)]
        st = MerkleStack()
        for lf in leaves:
            st.append(lf)
        assert st.root() == tree_root(leaves), n
        # Round-trip through serialization.
        st2 = MerkleStack.from_dict(st.to_dict())
        assert st2.root() == st.root() and st2.n == n, n
    # Inclusion proofs: positive for every leaf, n = 1..24; negatives.
    for n in range(1, 25):
        leaves = [os.urandom(32) for _ in range(n)]
        root = tree_root(leaves)
        for i in range(n):
            proof = inclusion_proof(leaves, i)
            assert len(proof) <= (n - 1).bit_length() + 1, (n, len(proof))
            assert verify_inclusion(leaves[i], i, proof, root, n), (n, i)
            assert not verify_inclusion(os.urandom(32), i, proof, root, n)
            assert not verify_inclusion(leaves[i], i, proof,
                                        os.urandom(32), n)
            if proof:
                bad = [bytes(b) for b in proof]
                bad[0] = os.urandom(32)
                assert not verify_inclusion(leaves[i], i, bad, root, n)
            # truncated / overlong proofs fail
            assert not verify_inclusion(leaves[i], i, proof[:-1], root, n) \
                or n == 1
            assert not verify_inclusion(leaves[i], i,
                                        proof + [os.urandom(32)], root, n)
    # Consistency proofs: every (m, n) with 1 <= m <= n <= 24 verifies;
    # forgeries fail closed.
    for n in range(1, 25):
        leaves = [os.urandom(32) for _ in range(n)]
        new_root = tree_root(leaves)
        for m in range(1, n + 1):
            old_root = tree_root(leaves[:m])
            proof = consistency_proof(leaves, m)
            assert len(proof) <= 2 * (n.bit_length() + 1), (m, n)
            assert verify_consistency(old_root, new_root, m, n, proof), \
                (m, n)
            if proof:
                bad = [bytes(b) for b in proof]
                bad[0] = os.urandom(32)
                assert not verify_consistency(old_root, new_root, m, n,
                                              bad), (m, n)
                assert not verify_consistency(old_root, new_root, m, n,
                                              proof[:-1]), (m, n)
                assert not verify_consistency(old_root, new_root, m, n,
                                              proof + [os.urandom(32)]), \
                    (m, n)
            # forked history: same sizes, different leaves -> reject
            fork = [os.urandom(32) for _ in range(n)]
            assert not verify_consistency(tree_root(fork[:m]), new_root,
                                          m, n, proof), (m, n)
            assert not verify_consistency(old_root, os.urandom(32), m, n,
                                          proof), (m, n)
        # degenerate sizes
        assert verify_consistency(new_root, new_root, n, n, [])
        assert not verify_consistency(new_root, os.urandom(32), n, n, [])
        assert verify_consistency(tree_root([]), new_root, 0, n, [])
    print("merkle: stack==batch (1..64), proofs +/- (1..24), "
          "consistency +/- (1..24)")


if __name__ == "__main__":
    selftest()
