#!/usr/bin/env python3
"""F203 closure battery: RekorBackend Ed25519ph/sha512 hashedrekord shape.

Wave-198 lane A. F203 (MEDIUM): ``gov.anchor_backend.RekorBackend.submit``
emitted raw Ed25519/SHA-256 hashedrekord envelopes, which real Rekor
v1.5.4 rejects with HTTP 400
``unsupported hash algorithm: "SHA-256" not in [SHA-512]``.

Red-first record (2026-09-29, local Rekor v1.5.4 + Trillian v1.8.0 +
MySQL + Redis stack, see docs/REKOR_RUNBOOK.md):
  RED (pristine d933dd1): submit -> WitnessDownError: rekor HTTP 400:
    ... unsupported hash algorithm: "SHA-256" not in [SHA-512]
  GREEN (fixed): submit -> real entry -> verify_receipt OK.

The fixed shape (measured live against Rekor v1.5.4, not assumed):
  * signature = Ed25519ph (RFC 8032 5.1, SHA-512 prehash, empty
    context) over the 32-byte anchor hash -- the ONLY Ed25519 shape
    hashedrekord's verifier (sigstore WithED25519ph()) accepts;
  * envelope data.hash = {"algorithm": "sha512",
    "value": hex(sha512(anchor_hash))} -- the verifier allow-lists
    ONLY SHA-512 as the hash, so a "sha256" declaration dies with the
    400 above before any signature math;
  * the server treats the declared digest as the already-computed
    PH(M) (no double hash): sign_ph(seed, anchor_hash) verifies,
    sign_ph(seed, sha512(anchor_hash)) is rejected as invalid.

Probe map:
  p_import_seam:     product seam present; RFC 8032 ph self-test green.
  p_ph_shape:        ph vector byte-exact; raw/ph domain separation both
                     directions; context separation.
  p_envelope_shape:  fake transport captures the POSTed envelope:
                     kind/apiVersion, sha512 declaration of
                     sha512(anchor_hash), signature is Ed25519ph over
                     the 32-byte anchor hash (and NOT raw Ed25519),
                     pubkey SPKI matches.
  p_verify_happy:    fake submit -> verify_receipt OK; receipt carries
                     anchor_algorithm="ed25519ph-sha512".
  p_verify_tampered: flipped proof sibling / root / body hash all fail.
  p_verify_wrong_key: different log_id refused; unknown
                     anchor_algorithm refused; wrong anchor_hash refused.
  p_stale_proof_guard: proof valid for tree size N but presented with
                     tree_size N+1 (stale/grown tree) refused -- the
                     receipt's proof must be consistent with its claimed
                     tree size; root recomputation is the guard.
  p_live_roundtrip:  live-conditional. If a Rekor v1 answers on
                     localhost:3000: submit -> real entry ->
                     verify_receipt OK (HELD). Else EXPECTED/skipped.
  p_deterministic_x2: verdicts byte-identical across 2 runs.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic. Real product code
(gov.anchor_backend, gov.ed25519); the only network use is the
opt-in live round-trip against localhost.

Run (fresh UNIQUE /var/tmp TMPDIR per run -- never reuse one across
runs, and always mkdir -p first: Python 3.12 silently ignores a
nonexistent TMPDIR):
  T=/var/tmp/g198a-$$; mkdir -p $T
  TMPDIR=$T ~/workspace/.gov-venv/bin/python evals/rekor_f203_probes.py
Also standalone (must be identical -- deployment mode is pinned at
module level):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=$T ~/workspace/.gov-venv/bin/python \\
      evals/rekor_f203_probes.py
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import base64  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import socket  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402

from gov import anchor_backend as ab  # noqa: E402
from gov import ed25519 as ed  # noqa: E402

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-22s %-10s %s" % (name, verdict, detail))


# ---------------------------------------------------------------------------
# Deterministic fake with Rekor v1.5.4 envelope semantics (no network).
# ---------------------------------------------------------------------------

def _h_leaf(b):
    return hashlib.sha256(b"\x00" + b).digest()


def _h_node(l, r):
    return hashlib.sha256(b"\x01" + l + r).digest()


def _subtree_root(leaf_hashes, lo, n):
    if n == 1:
        return leaf_hashes[lo]
    k = 1
    while 2 * k < n:
        k *= 2
    return _h_node(_subtree_root(leaf_hashes, lo, k),
                   _subtree_root(leaf_hashes, lo + k, n - k))


def _inclusion_proof(leaf_hashes, idx, n):
    # Sibling hashes, leaf-level-first -- Rekor's `hashes` order.
    if n == 1:
        return []
    k = 1
    while 2 * k < n:
        k *= 2
    if idx < k:
        return _inclusion_proof(leaf_hashes, idx, k) + [
            _subtree_root(leaf_hashes, k, n - k)]
    return _inclusion_proof(leaf_hashes, idx - k, n - k) + [
        _subtree_root(leaf_hashes, 0, k)]


class FakeRekor154:
    """Fake Rekor enforcing the v1.5.4 envelope contract that matters
    for F203: the data.hash declaration allow-list (sha512 only --
    anything else gets the real server's 400). Signature acceptance
    itself is proven live; the fake records envelopes for shape
    assertions and serves well-formed entries for receipt checks."""

    def __init__(self, log_id="f203-battery-log-id"):
        self.log_id = log_id
        self.bodies = []
        self.last_proposed = None

    def _entry_for(self, idx):
        leaf_hashes = [_h_leaf(b) for b in self.bodies]
        proof = _inclusion_proof(leaf_hashes, idx, len(self.bodies))
        return {
            "body": base64.b64encode(self.bodies[idx]).decode("ascii"),
            "integratedTime": int(time.time()),
            "logIndex": idx,
            "logID": self.log_id,
            "verification": {
                "inclusionProof": {
                    "hashes": [h.hex() for h in proof],
                    "rootHash": _subtree_root(
                        leaf_hashes, 0, len(self.bodies)).hex(),
                    "treeSize": len(self.bodies),
                    "logIndex": idx,
                },
                "signedEntryTimestamp": "fake-set-%d" % idx,
            },
        }

    def __call__(self, request):
        method = request.get("method", "POST")
        url = request["url"]
        if method == "POST" and url.endswith("/api/v1/log/entries"):
            proposed = json.loads(request["body"])
            self.last_proposed = proposed
            halg = proposed["spec"]["data"]["hash"]["algorithm"]
            if halg != "sha512":
                # The real v1.5.4 400, verbatim in the relevant part.
                raise ab.WitnessDownError(
                    "rekor HTTP 400: {\"code\":400,\"message\":"
                    "\"error processing entry: verifying signature: "
                    "unsupported hash algorithm: \\\"SHA-256\\\" not in "
                    "[SHA-512]\"}")
            body = json.dumps({"kind": proposed["kind"],
                               "apiVersion": proposed["apiVersion"],
                               "spec": proposed["spec"]},
                              separators=(",", ":")).encode("utf-8")
            self.bodies.append(body)
            idx = len(self.bodies) - 1
            return {"status": 201,
                    "body": json.dumps({"fakeuuid%06d" % idx:
                                        self._entry_for(idx)})}
        raise AssertionError("unexpected request %s %s" % (method, url))


def _backend(seed=None, log_id="f203-battery-log-id", transport=None):
    seed = seed if seed is not None else ed.generate_seed()
    return (ab.RekorBackend(url="http://fake-rekor:3000", log_id=log_id,
                            transport=transport,
                            anchor_seed=seed,
                            anchor_pubkey=ed.publickey(seed)),
            seed)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def p_import_seam():
    name = "p_import_seam"
    for fn in ("sign_ph", "verify_ph", "rfc8032_ph_selftest"):
        if not hasattr(ed, fn):
            _record(name, "BREAK", "gov.ed25519.%s missing" % fn)
            return
    if not hasattr(ab.RekorBackend, "submit"):
        _record(name, "BREAK", "RekorBackend.submit missing")
        return
    try:
        ed.rfc8032_ph_selftest()
    except AssertionError as e:
        _record(name, "BREAK", "RFC 8032 ph self-test failed: %s" % (e,))
        return
    _record(name, "HELD",
            "seam present; RFC 8032 section 7.3 vector byte-exact")


def p_ph_shape():
    name = "p_ph_shape"
    seed = bytes([7]) * 32
    pub = ed.publickey(seed)
    msg = bytes(range(32))  # the hashedrekord message shape
    sig = ed.sign_ph(seed, msg)
    if not ed.verify_ph(pub, msg, sig):
        _record(name, "BREAK", "ph round-trip failed")
        return
    # Domain separation is load-bearing for F203: the old raw shape
    # must never verify as ph, and ph must never verify as raw.
    if ed.verify(pub, msg, sig):
        _record(name, "BREAK", "raw verifier accepted a ph signature")
        return
    if ed.verify_ph(pub, msg, ed.sign(seed, msg)):
        _record(name, "BREAK", "ph verifier accepted a raw signature")
        return
    if ed.verify_ph(pub, msg, sig, context=b"other"):
        _record(name, "BREAK", "context not separated")
        return
    if ed.verify_ph(pub, msg, sig[:-1] + b"\x00"):
        _record(name, "BREAK", "bit-flipped signature verified")
        return
    _record(name, "HELD",
            "ph round-trips; raw/ph cross-reject; context separated")


def p_envelope_shape():
    name = "p_envelope_shape"
    fake = FakeRekor154()
    be, seed = _backend(transport=fake)
    pub = ed.publickey(seed)
    ahash = hashlib.sha256(b"f203-envelope").hexdigest()
    try:
        be.submit(ahash)
    except Exception as e:  # noqa: BLE001
        _record(name, "BREAK", "submit raised: %r" % (e,))
        return
    proposed = fake.last_proposed
    if proposed["kind"] != "hashedrekord" or \
            proposed["apiVersion"] != "0.0.1":
        _record(name, "BREAK", "envelope kind/apiVersion wrong")
        return
    halg = proposed["spec"]["data"]["hash"]["algorithm"]
    hval = proposed["spec"]["data"]["hash"]["value"]
    if halg != "sha512":
        _record(name, "BREAK",
                "envelope declares %r, not sha512 (the F203 400)" % halg)
        return
    if hval != hashlib.sha512(bytes.fromhex(ahash)).hexdigest():
        _record(name, "BREAK", "envelope value != sha512(anchor_hash)")
        return
    sig = base64.b64decode(proposed["spec"]["signature"]["content"])
    if not ed.verify_ph(pub, bytes.fromhex(ahash), sig):
        _record(name, "BREAK",
                "envelope signature is not Ed25519ph over the anchor hash")
        return
    if ed.verify(pub, bytes.fromhex(ahash), sig):
        _record(name, "BREAK", "envelope emits the raw-Ed25519 shape")
        return
    pk_pem = base64.b64decode(
        proposed["spec"]["signature"]["publicKey"]["content"]).decode()
    if pk_pem != ab.anchor_spki_pem(pub):
        _record(name, "BREAK", "envelope pubkey != anchor pubkey")
        return
    _record(name, "HELD",
            "envelope is Ed25519ph/sha512; signature over the anchor "
            "hash; never raw Ed25519")


def p_verify_happy():
    name = "p_verify_happy"
    fake = FakeRekor154()
    be, _seed = _backend(transport=fake)
    ahash = hashlib.sha256(b"f203-happy").hexdigest()
    try:
        receipt = be.submit(ahash)
    except Exception as e:  # noqa: BLE001
        _record(name, "BREAK", "submit raised: %r" % (e,))
        return
    if receipt.get("anchor_algorithm") != \
            ab.ANCHOR_ALGORITHM_ED25519PH_SHA512:
        _record(name, "BREAK",
                "receipt anchor_algorithm != ed25519ph-sha512")
        return
    ok, why = be.verify_receipt(receipt, anchor_hash=ahash)
    if not ok:
        _record(name, "BREAK", "valid receipt refused: %s" % (why,))
        return
    _record(name, "HELD", "fake submit -> verify_receipt OK")


def p_verify_tampered():
    name = "p_verify_tampered"
    # Two leaves so the receipt under test carries a real sibling hash.
    fake = FakeRekor154()
    be, _seed = _backend(transport=fake)
    be.submit(hashlib.sha256(b"f203-tamper-a").hexdigest())
    ahash = hashlib.sha256(b"f203-tamper").hexdigest()
    receipt = be.submit(ahash)

    def check(mut, what):
        ok, _why = be.verify_receipt(mut, anchor_hash=ahash)
        return not ok

    tampers = []
    r1 = dict(receipt)
    p1 = dict(r1["inclusion_proof"])
    h = bytearray(bytes.fromhex(p1["hashes"][0]))
    h[0] ^= 0xFF
    p1["hashes"] = [bytes(h).hex()] + p1["hashes"][1:]
    r1["inclusion_proof"] = p1
    tampers.append((r1, "flipped proof sibling"))
    r2 = dict(receipt)
    p2 = dict(r2["inclusion_proof"])
    p2["root_hash"] = "00" * 32
    r2["inclusion_proof"] = p2
    tampers.append((r2, "wrong root_hash"))
    r3 = dict(receipt)
    body = json.loads(base64.b64decode(r3["body"]).decode())
    body["spec"]["data"]["hash"]["value"] = "ff" * 64
    r3["body"] = base64.b64encode(
        json.dumps(body).encode()).decode()
    tampers.append((r3, "body hash swapped"))
    for mut, what in tampers:
        if not check(mut, what):
            _record(name, "BREAK", "%s verified?!" % what)
            return
    _record(name, "HELD",
            "flipped sibling / wrong root / swapped body hash refused")


def p_verify_wrong_key():
    name = "p_verify_wrong_key"
    fake = FakeRekor154()
    be, _seed = _backend(transport=fake)
    ahash = hashlib.sha256(b"f203-wrongkey").hexdigest()
    receipt = be.submit(ahash)
    # Different transparency log: refused.
    be2, _s2 = _backend(log_id="some-other-log", transport=fake)
    ok, _why = be2.verify_receipt(receipt, anchor_hash=ahash)
    if ok:
        _record(name, "BREAK", "foreign log_id receipt verified?!")
        return
    # Receipt for a different anchor: refused.
    ok, _why = be.verify_receipt(receipt, anchor_hash="00" * 32)
    if ok:
        _record(name, "BREAK", "cross-anchor receipt verified?!")
        return
    # Receipt claiming an unknown anchor algorithm: refused.
    r3 = dict(receipt)
    r3["anchor_algorithm"] = "raw-ed25519-sha256"
    ok, _why = be.verify_receipt(r3, anchor_hash=ahash)
    if ok:
        _record(name, "BREAK", "unknown anchor_algorithm verified?!")
        return
    # An unlabeled receipt whose body carries the F203 shape still
    # verifies (genuine pre-F203 sha256-declared bodies are refused by
    # the shape check -- the raw path is repaired, not grandfathered).
    r4 = dict(receipt)
    del r4["anchor_algorithm"]
    ok, why = be.verify_receipt(r4, anchor_hash=ahash)
    if not ok:
        _record(name, "BREAK", "unlabeled F203-shape receipt refused: %s"
                % (why,))
        return
    _record(name, "HELD",
            "foreign log / cross-anchor / unknown algorithm refused; "
            "unlabeled F203-shape accepted")


def p_stale_proof_guard():
    name = "p_stale_proof_guard"
    fake = FakeRekor154()
    be, _seed = _backend(transport=fake)
    ah1 = hashlib.sha256(b"f203-stale-1").hexdigest()
    ah2 = hashlib.sha256(b"f203-stale-2").hexdigest()
    r1 = be.submit(ah1)   # tree size 1 when this proof was minted
    be.submit(ah2)        # the tree has since grown to size 2
    # Replay the size-1 proof against a size-2 claim: the recomputed
    # root cannot match -- this is the stale-proof guard for this
    # seam (the receipt's proof must be consistent with its claimed
    # tree size).
    stale = dict(r1)
    p = dict(stale["inclusion_proof"])
    p["tree_size"] = 2
    stale["inclusion_proof"] = p
    ok, _why = be.verify_receipt(stale, anchor_hash=ah1)
    if ok:
        _record(name, "BREAK", "stale (grown-tree) proof verified?!")
        return
    # And the reverse: a size-2 proof claimed at size 1.
    r2 = be.submit(hashlib.sha256(b"f203-stale-3").hexdigest())
    shrunk = dict(r2)
    p2 = dict(shrunk["inclusion_proof"])
    p2["tree_size"] = 1
    shrunk["inclusion_proof"] = p2
    ok, _why = be.verify_receipt(shrunk, anchor_hash=r2["anchor_hash"])
    if ok:
        _record(name, "BREAK", "shrunk-tree proof verified?!")
        return
    _record(name, "HELD",
            "proof/tree-size mismatch (stale in both directions) refused")


def p_live_roundtrip():
    name = "p_live_roundtrip"
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect(("127.0.0.1", 3000))
        s.close()
    except OSError:
        _record(name, "EXPECTED",
                "no live Rekor on localhost:3000; live behavior pinned "
                "by the 2026-09-29 run")
        return
    seed = ed.generate_seed()
    be = ab.RekorBackend(url="http://localhost:3000", log_id="discovery",
                         anchor_seed=seed,
                         anchor_pubkey=ed.publickey(seed))
    ahash = hashlib.sha256(
        b"f203-live-%d" % int(time.time())).hexdigest()
    try:
        discovery = be.submit(ahash)
    except ab.WitnessDownError as e:
        _record(name, "BREAK",
                "live discovery submit rejected: %s" % (str(e)[:120],))
        return
    except Exception as e:  # noqa: BLE001
        _record(name, "BREAK", "unexpected exception: %r" % (e,))
        return
    be = ab.RekorBackend(url="http://localhost:3000",
                         log_id=discovery["log_id"],
                         anchor_seed=seed,
                         anchor_pubkey=ed.publickey(seed))
    ahash2 = hashlib.sha256(
        b"f203-live2-%d" % int(time.time())).hexdigest()
    try:
        receipt = be.submit(ahash2)
    except Exception as e:  # noqa: BLE001
        _record(name, "BREAK", "live submit failed: %r" % (e,))
        return
    ok, why = be.verify_receipt(receipt, anchor_hash=ahash2)
    if not ok:
        _record(name, "BREAK", "live entry did not verify: %s" % (why,))
        return
    _record(name, "HELD",
            "live Rekor v1.5.4: submit -> entry %s -> verify OK"
            % (receipt["uuid"][:12],))


def _run_all():
    _RESULTS.clear()
    p_import_seam()
    p_ph_shape()
    p_envelope_shape()
    p_verify_happy()
    p_verify_tampered()
    p_verify_wrong_key()
    p_stale_proof_guard()
    p_live_roundtrip()
    return list(_RESULTS)


def p_deterministic_x2():
    name = "p_deterministic_x2"
    first = _run_all()
    second = _run_all()
    v1 = [(n, v) for n, v, _ in first]
    v2 = [(n, v) for n, v, _ in second]
    if v1 != v2:
        _record(name, "BREAK",
                "verdicts differ: %r vs %r" % (v1, v2))
        return
    _record(name, "HELD",
            "%d probes byte-identical across 2 runs" % len(v1))


def green_check():
    """Depth-1 green check: adjacent unit suites, no nested batteries.

    Honors GOV_SKIP_GREEN (set in child envs by parent batteries).
    """
    if os.environ.get("GOV_SKIP_GREEN"):
        print("green_check: skipped (GOV_SKIP_GREEN set)")
        return True
    suites = ["tests.test_w72_anchor", "tests.test_anchoring"]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    for suite in suites:
        r = subprocess.run(
            [sys.executable, "-m", "unittest", suite],
            cwd=REPO_ROOT, env=env,
            capture_output=True, text=True, timeout=600)
        tail = (r.stderr.strip().splitlines() or [""]) [-1]
        print("green_check %-28s %s" % (suite, tail))
        if r.returncode != 0:
            print(r.stderr[-2000:])
            return False
    return True


def main():
    _run_all()
    p_deterministic_x2()
    ok = green_check()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("rekor_f203_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR / green=%s"
          % (held, brk, exp, err, ok))
    return 1 if (brk or err or not ok) else 0


if __name__ == "__main__":
    sys.exit(main())
