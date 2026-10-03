"""Third-party acceptance for the witness log (wave-312 lane D).

Verifies a sealed checkpoint + Merkle inclusion proof with STDLIB ONLY
(json, base64, hashlib, argparse) and a self-contained RFC 8032 Ed25519
verifier -- NO Sasanam import. Asserts the no-import claim via
sys.modules before doing any work.

This is the "sell evidence, not the engine" check: everything the log
promises is re-derivable from the documented algorithm (canonical JSON,
RFC 6962 domain-separated hashing, RFC 8032 signatures).

Usage:
  python3 w312_thirdparty_witness_accept.py --checkpoint checkpoint.json \\
      --pubkey <hex 32-byte witness pubkey> --leaf leaf.bin \\
      --proof proof.json
Prints THIRDPARTY_WITNESS_VALID on success; exits non-zero otherwise.
"""

import argparse
import base64
import hashlib
import json
import sys

for _mod in list(sys.modules):
    if _mod == "gov" or _mod.startswith("gov."):
        sys.stderr.write("THIRDPARTY VIOLATION: Sasanam module %r imported\n"
                         % (_mod,))
        sys.exit(3)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")


# --- Minimal RFC 8032 Ed25519 verify (hashlib only; the third party's
# own implementation of the documented algorithm). ---
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_G = (15112221349535400772501151409588531511454012693041857206046113283949847762202,
      46316835694926478169428394003475163141307993866256225615783033603165251855960)


def _add(p, q):
    # Twisted Edwards (a = -1) affine addition.
    x1, y1 = p
    x2, y2 = q
    t1 = (x1 * x2) % _P
    t2 = (y1 * y2) % _P
    x3 = ((x1 * y2 + x2 * y1)
          * pow((1 + _D * t1 * t2) % _P, _P - 2, _P)) % _P
    y3 = ((t2 + t1)
          * pow((1 - _D * t1 * t2) % _P, _P - 2, _P)) % _P
    return (x3, y3)


def _scalarmult(p, e):
    q = (0, 1)
    while e > 0:
        if e & 1:
            q = _add(q, p)
        p = _add(p, p)
        e >>= 1
    return q


def _decode(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = (s[31] >> 7) & 1
    if y >= _P:
        return None
    x2 = ((y * y - 1)
          * pow((_D * y * y + 1) % _P, _P - 2, _P)) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = (x * pow(2, (_P - 1) // 4, _P)) % _P
        if (x * x - x2) % _P != 0:
            return None
    if (x & 1) != sign:
        x = _P - x
    return (x, y)


def _verify_ed25519(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64:
        return False
    a = _decode(pub)
    r = _decode(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    h = (int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(),
                        "little") % _L)
    return (_scalarmult(_G, s)
            == _add(r, _scalarmult(a, h)))


# --- RFC 6962 hashing. ---
def _leaf_hash(leaf):
    return hashlib.sha256(b"\x00" + leaf).digest()


def _node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkpoint", required=True)
    ap.add_argument("--pubkey", required=True)
    ap.add_argument("--leaf", required=True)
    ap.add_argument("--proof", required=True)
    args = ap.parse_args()

    def fail(why):
        sys.stderr.write("THIRDPARTY INVALID: %s\n" % why)
        return 1

    try:
        pub = bytes.fromhex(args.pubkey)
    except ValueError:
        return fail("bad pubkey hex")
    if len(pub) != 32:
        return fail("pubkey not 32 bytes")
    try:
        with open(args.checkpoint, encoding="utf-8") as fh:
            sealed = json.load(fh)
        with open(args.leaf, "rb") as fh:
            leaf = fh.read()
        with open(args.proof, encoding="utf-8") as fh:
            proof = json.load(fh)
    except (OSError, ValueError) as exc:
        return fail("unreadable input: %s" % exc)

    # 1. Checkpoint: signature FIRST, then parse from the verified doc.
    cp = sealed.get("checkpoint")
    if not isinstance(cp, dict):
        return fail("checkpoint not an object")
    try:
        sig = base64.b64decode(sealed.get("signature"), validate=True)
    except Exception:
        return fail("bad checkpoint signature encoding")
    if not _verify_ed25519(pub, _canonical(cp), sig):
        return fail("checkpoint signature invalid")
    if set(cp.keys()) != {"logId", "treeSize", "rootHash", "timestamp"}:
        return fail("checkpoint keys %r" % sorted(cp.keys()))
    if cp["logId"].lower() != hashlib.sha256(pub).hexdigest():
        return fail("logId does not name the key")
    tree_size = cp["treeSize"]
    try:
        root = bytes.fromhex(cp["rootHash"])
    except ValueError:
        return fail("bad rootHash hex")
    if len(root) != 32:
        return fail("rootHash not 32 bytes")

    # 2. Inclusion proof against the checkpoint's root (the proof's own
    # tree_size copy is ignored -- sizes come from the checkpoint).
    index = proof.get("leaf_index")
    path = proof.get("path")
    if not isinstance(index, int) or not 0 <= index < tree_size:
        return fail("leaf index out of range")
    if not isinstance(path, list):
        return fail("path not a list")
    h = _leaf_hash(leaf)
    for node in path:
        try:
            sib = bytes.fromhex(node["hash"])
        except (KeyError, ValueError, TypeError):
            return fail("bad path node")
        if node.get("side") == "left":
            h = _node_hash(sib, h)
        elif node.get("side") == "right":
            h = _node_hash(h, sib)
        else:
            return fail("bad side")
    if h != root:
        return fail("audit path does not recompute the checkpoint root")

    print("THIRDPARTY_WITNESS_VALID")
    print("  log: %s  tree_size: %d  leaf_index: %d"
          % (cp["logId"][:16], tree_size, index))
    return 0


if __name__ == "__main__":
    sys.exit(main())
