"""W242-8: author the directed refusal-set probe vector.

Builds a sealed-record statement where exactly one clean-row conjunct fails,
starting from corpus accept vector vcf20eae7df4f1f1b. The vector keeps the
clean sealed record AND appends a dirty twin (wrong aeePostureDigest), because
the reference checker's existential seal requirement refuses with a generic
message when no clean sealed record exists; the specific refusal-set reason
only fires on a statement carrying both.

Signing uses the corpus's published test-seed recipe
(SHA-256("in-toto-aee-test-key/<role>/v1"), Ed25519) via the repo's vendored
pure-Python RFC 8032 implementation -- test-only material, never a product
key path.

Authored BEFORE reading the head spec text containing the refusal-set rule;
labeled directed regardless.
"""

import base64
import copy
import hashlib
import json
import os
import sys

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gov"
    ),
)
import ed25519  # vendored pure-Python RFC 8032 (test-only use)

ROLE = "substrate-observation-test"
BASE_VECTOR_ID = "vcf20eae7df4f1f1b"
WRONG_POSTURE = "3" * 64
VECTOR_ID = "w242-refusal-set-authored"


def _utf16_key(s):
    # RFC 8785 3.2.3: object keys sort by UTF-16 code unit
    return s.encode("utf-16-be")


def canonical_bytes(v):
    """RFC 8785 canonical JSON. Verified byte-exact against the corpus's own
    sealed/interception record payloads before use (the reference checker
    rejects payload bytes that are not in canonical form)."""
    if v is None:
        return b"null"
    if v is True:
        return b"true"
    if v is False:
        return b"false"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v).encode()
    if isinstance(v, list):
        return b"[" + b",".join(canonical_bytes(x) for x in v) + b"]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: _utf16_key(kv[0]))
        return (
            b"{"
            + b",".join(
                canonical_bytes(k) + b":" + canonical_bytes(val)
                for k, val in items
            )
            + b"}"
        )
    raise ValueError(f"unsupported JSON value: {type(v)}")


def pae(payload_type, payload):
    pt = payload_type.encode()
    out = b"DSSEv1 "
    out += str(len(pt)).encode() + b" " + pt + b" "
    out += str(len(payload)).encode() + b" " + payload
    return out


def leaf_hash(pae_bytes):
    h = hashlib.sha256()
    h.update(b"\x00")
    h.update(pae_bytes)
    return h.digest()


def _node_hash(left, right):
    h = hashlib.sha256()
    h.update(b"\x01")
    h.update(left)
    h.update(right)
    return h.digest()


def merkle_root(leaves):
    """RFC 6962 root, largest-power-of-two-below split, no padding."""
    n = len(leaves)
    if n == 0:
        return None
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return _node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def test_seed(role=ROLE):
    return hashlib.sha256(f"in-toto-aee-test-key/{role}/v1".encode()).digest()


def sign_record(payload_type, payload_bytes, seed):
    sig = ed25519.sign(seed, pae(payload_type, payload_bytes))
    keyid = hashlib.sha256(ed25519.publickey(seed)).hexdigest()
    return {
        "keyid": keyid,
        "sig": base64.b64encode(sig).decode(),
    }


def make_authored_vector(corpus_vectors_dir, out_dir):
    """Write the authored vector + manifest into out_dir. Returns the vector id."""
    seed = test_seed()
    stmt_path = os.path.join(
        corpus_vectors_dir, "statements", BASE_VECTOR_ID + ".json"
    )
    stmt = json.load(open(stmt_path))
    stmt = copy.deepcopy(stmt)
    recs = stmt["predicate"]["observationRecords"]
    # Keep the clean sealed record AND append a dirty twin.
    dirty = None
    for r in recs:
        payload = json.loads(base64.b64decode(r["payload"]).decode())
        if payload.get("aeeKind") != "sealed":
            continue
        if payload["aeeStillArmed"] is not True:
            raise ValueError("base vector changed: aeeStillArmed")
        if payload["aeeDropCount"] != 0:
            raise ValueError("base vector changed: aeeDropCount")
        payload["aeePostureDigest"] = WRONG_POSTURE
        payload_bytes = canonical_bytes(payload)
        dirty = {
            "payload": base64.b64encode(payload_bytes).decode(),
            "payloadType": r["payloadType"],
            "signatures": [sign_record(r["payloadType"], payload_bytes, seed)],
        }
    if dirty is None:
        raise ValueError("no sealed record in base vector")
    recs.append(dirty)

    leaves = [
        leaf_hash(pae(r["payloadType"], base64.b64decode(r["payload"])))
        for r in recs
    ]
    stmt["predicate"]["batchRoot"] = merkle_root(leaves).hex()

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, VECTOR_ID + ".json"), "w") as f:
        json.dump(stmt, f, indent=1)
        f.write("\n")
    manifest = {
        "vectors": [
            {
                "id": VECTOR_ID,
                "kind": "reject",
                "file": VECTOR_ID + ".json",
                "expected": {"verdict": "invalid"},
                "probe": {
                    "authored": "2026-09-30",
                    "before_head_spec_read": True,
                    "label": "directed",
                    "mutated_conjunct": "posture",
                    "forbidden_names": [
                        "aeeStillArmed is false",
                        "aeeDropCount",
                    ],
                },
            }
        ]
    }
    with open(os.path.join(out_dir, "MANIFEST.json"), "w") as f:
        json.dump(manifest, f, indent=1)
        f.write("\n")
    return VECTOR_ID


if __name__ == "__main__":
    corpus = sys.argv[1] if len(sys.argv) > 1 else "/tmp/aee-conformance/vectors"
    out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/w242aee/vectors"
    print("wrote vector", make_authored_vector(corpus, out), "to", out)
