#!/usr/bin/env python3
"""Rekor transparency anchoring: red-first probe battery (wave-194 lane D).

What is red on pristine (aa231a6): there is NO product seam for
self-hosted Rekor anchoring -- no signed-checkpoint / sealed-manifest
anchor path, no stale-proof guard, no productized witness
equivocation refusal, and the one live Rekor backend in the tree
(``gov.anchor_backend.RekorBackend``) is incompatible with real
Rekor v1.5.4 (F203: raw Ed25519 rejected -- ``unsupported hash
algorithm: "SHA-256" not in [SHA-512]``).

What is green post-fix: ``gov/rekor_anchor.py`` -- self-hosted-only
client, digest-existence-only receipts (``present_as_authority``
always raises), stale-proof refusing ``verify_inclusion``, an
independent Merkle-recomputing ``RekorWitness``, and offline
proof bundles that verify with the server down.

F203 was closed by wave-198 (2026-09-29): ``RekorBackend.submit``
now emits the Ed25519ph/sha512 hashedrekord shape that real Rekor
v1.5.4 accepts, and the live pin (p_f203_live_pin) pins the FIXED
behavior -- submit succeeds and the entry verifies via inclusion
proof (BREAK on any 400/SHA-512 regression).

Probe map:
  p_import_seam: gov.rekor_anchor imports; grade constant pinned.
  p_f203_live_pin: live-conditional. If a Rekor v1 answers on
    localhost:3000, submit via the EXISTING backend and expect SUCCESS
    (F203 closed 2026-09-29, wave-198: Ed25519ph/sha512 envelope) plus
    verify_receipt OK -- BREAK if reality contradicts the fix either
    way (400/SHA-512 rejection = F203 regressed). If no live server,
    EXPECTED/skipped.
  p_prod_pins_refused: Sigstore prod URL / prod log_id refused.
  p_raw_ed25519_refused: algorithm="ed25519" refused fail-closed.
  p_layering: receipt grade is digest-existence-only; presenting it
    as authority always raises, even for a forged "perfect" receipt.
  p_anchor_verify_roundtrip: real format-2 checkpoint STH + sealed
    evidence-bundle manifest anchor and verify.
  p_stale_proof_refused: internally-consistent but stale proof is
    refused; the same entry re-fetched (fresh proof) verifies.
  p_equivocation_refused: forged same-size/different-root checkpoint
    is refused by the witness and recorded.
  p_witness_quorum: 2-of-3 distinct cosigs verify; duplicates and
    singletons do not satisfy quorum.
  p_offline_bundle: bundle built, server killed, bundle still
    verifies; tampered leaf fails.
  p_deterministic_x2: byte-identical verdicts across 2 runs.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic. Real product code
(gov.rekor_anchor), no stubs. The only network use is the
opt-in live F203 pin against localhost.

Run (fresh UNIQUE /var/tmp TMPDIR per run -- never reuse one across
runs, and always mkdir -p first: Python 3.12 silently ignores a
nonexistent TMPDIR):
  T=/var/tmp/g194rekor-$$; mkdir -p $T
  TMPDIR=$T ~/workspace/.gov-venv/bin/python \
      evals/rekor_anchor_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=$T ~/workspace/.gov-venv/bin/python \
      evals/rekor_anchor_probes.py
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
_TESTS_DIR = os.path.join(REPO_ROOT, "tests")
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)

from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

import base64  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import socket  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402

try:
    from gov import rekor_anchor as ra  # noqa: E402
    _RA = ra
    _RA_IMPORT_ERROR = None
except ImportError as e:
    _RA = None
    _RA_IMPORT_ERROR = e

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-28s %-10s %s" % (name, verdict, detail))


def _needs_ra(name):
    if _RA is None:
        _record(name, "BREAK",
                "no product seam on pristine: %s" % (_RA_IMPORT_ERROR,))
        return None
    return _RA


class FakeRekor:
    """Deterministic in-memory Rekor v1 (dict-contract transport)."""

    def __init__(self):
        self.log_id = "battery-log-id-0123456789abcdef"
        self.tree_id = "777001"
        self.bodies = []
        self.down = False

    def _root(self):
        return ra._r6962_root(
            [ra._r6962_leaf(b) for b in self.bodies])

    def _entry_for(self, idx):
        leaf_hashes = [ra._r6962_leaf(b) for b in self.bodies]
        proof = ra._r6962_inclusion_proof(leaf_hashes, idx)
        return {
            "body": base64.b64encode(self.bodies[idx]).decode("ascii"),
            "integratedTime": 1700000000 + idx,
            "logIndex": idx,
            "logID": self.log_id,
            "verification": {
                "inclusionProof": {
                    "hashes": [h.hex() for h in proof],
                    "rootHash": self._root().hex(),
                    "treeSize": len(self.bodies),
                    "logIndex": idx,
                    "checkpoint": "fake-checkpoint-%d" % len(self.bodies),
                },
                "signedEntryTimestamp": "fake-set-%d" % idx,
            },
        }

    def __call__(self, request):
        if self.down:
            raise ra.RekorDownError("rekor is down (battery)")
        method = request.get("method", "POST")
        url = request["url"]
        if method == "POST" and url.endswith("/api/v1/log/entries"):
            body = request["body"].encode("utf-8")
            self.bodies.append(body)
            idx = len(self.bodies) - 1
            return {"status": 200,
                    "body": json.dumps(
                        {"fakeuuid%06d" % idx: self._entry_for(idx)})}
        if method == "GET" and url.endswith("/api/v1/log"):
            return {"status": 200, "body": json.dumps({
                "treeID": self.tree_id,
                "treeSize": len(self.bodies),
                "rootHash": self._root().hex(),
                "signedTreeHead": "fake-sth"})}
        if method == "GET" and "/api/v1/log/entries/" in url:
            uuid = url.rsplit("/", 1)[1]
            idx = int(uuid.replace("fakeuuid", ""))
            return {"status": 200,
                    "body": json.dumps({uuid: self._entry_for(idx)})}
        raise AssertionError("unexpected request %s %s" % (method, url))


def _openssl(*args, cwd, input=None):
    return subprocess.run(["openssl"] + list(args), cwd=cwd,
                          input=input, capture_output=True, check=True)


_CTX = {}


def _ctx():
    """Build the shared battery context (keys, checkpoint, manifest)."""
    if _CTX:
        return _CTX
    from gov import log as _log
    from gov import evidence_bundle as _eb
    from gov import signing as _signing
    tmp = tempfile.mkdtemp(prefix="rekor-battery-")
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout",
             "-out", "op.key", cwd=tmp)
    _openssl("ec", "-in", "op.key", "-pubout", "-out", "op.pub.pem",
             cwd=tmp)
    with open(os.path.join(tmp, "op.pub.pem")) as fh:
        pubkey_pem = fh.read()

    def sign(digest):
        # Raw ECDSA sign over the 32-byte digest (the shape real Rekor
        # verifies: WithDigest -- `dgst -sha256 -sign` would
        # double-hash and be rejected).
        r = _openssl("pkeyutl", "-sign", "-inkey", "op.key",
                     cwd=tmp, input=bytes(digest))
        return (base64.b64encode(r.stdout).decode("ascii"),
                pubkey_pem, "ecdsa-p256-sha256")

    log_path = os.path.join(tmp, "audit.log")
    signer = _signing.Ed25519Signer(bytes.fromhex("44" * 32))
    log = _log.ActionLog(log_path, signer=signer,
                         deployment_mode="staging")
    log.append({"event": "policy_loaded", "policy_hash": "p" * 16,
                "policy_path": "policies/p1.yaml", "pinned": True,
                "policy_version": "1.0"})
    checkpoint = log.write_checkpoint()
    eb = _eb.EvidenceBundle(log_path, operator_id="battery-194")
    manifest = eb.seal(eb.build(), signer=signer)
    from gov import ed25519 as _ed
    _CTX.update(tmp=tmp, sign=sign, checkpoint=checkpoint,
                manifest=manifest,
                witness_seed=_ed.generate_seed())
    return _CTX


def p_import_seam():
    name = "p_import_seam"
    ra = _needs_ra(name)
    if ra is None:
        return
    if ra.EVIDENTIARY_GRADE != "digest-existence-only":
        _record(name, "BREAK",
                "grade constant wrong: %r" % (ra.EVIDENTIARY_GRADE,))
        return
    _record(name, "HELD", "module + grade constant present")


def p_f203_live_pin():
    name = "p_f203_live_pin"
    # Live-conditional: only meaningful against a real Rekor v1.
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect(("127.0.0.1", 3000))
        s.close()
    except OSError:
        _record(name, "EXPECTED",
                "no live Rekor on localhost:3000; F203 closed by the "
                "2026-09-29 live run (Ed25519ph/sha512 accepted, entry "
                "verified)")
        return
    from gov import anchor_backend as ab
    from gov import ed25519 as ed
    seed = ed.generate_seed()
    be = ab.RekorBackend(
        url="http://localhost:3000", log_id="discovery",
        anchor_seed=seed, anchor_pubkey=ed.publickey(seed))
    ahash = "ab" * 32
    try:
        discovery = be.submit(ahash)
    except ab.WitnessDownError as e:
        msg = str(e)
        if "400" in msg and "SHA-512" in msg:
            _record(name, "BREAK",
                    "F203 REGRESSED: live Rekor v1.5.4 rejects the "
                    "Ed25519ph envelope (%s)" % (msg[:100],))
        else:
            _record(name, "BREAK",
                    "live rejection, unexpected shape: %s" % (msg[:120],))
        return
    except Exception as e:  # noqa: BLE001
        _record(name, "BREAK",
                "unexpected exception type: %r" % (e,))
        return
    # Pin the real log id from the server's own response, then run the
    # close-when end to end: submit -> entry -> inclusion verification.
    be = ab.RekorBackend(
        url="http://localhost:3000", log_id=discovery["log_id"],
        anchor_seed=seed, anchor_pubkey=ed.publickey(seed))
    try:
        receipt = be.submit("cd" * 32)
    except Exception as e:  # noqa: BLE001
        _record(name, "BREAK",
                "pinned-log_id submit failed: %r" % (e,))
        return
    ok, why = be.verify_receipt(receipt, anchor_hash="cd" * 32)
    if not ok:
        _record(name, "BREAK",
                "live entry did not verify: %s" % (why,))
        return
    if receipt.get("anchor_algorithm") != "ed25519ph-sha512":
        _record(name, "BREAK",
                "receipt anchor_algorithm not ed25519ph-sha512")
        return
    _record(name, "HELD",
            "F203 closed: live Rekor v1.5.4 accepts the Ed25519ph/sha512 "
            "envelope; entry %s verifies via inclusion proof"
            % (receipt["uuid"][:12],))


def p_prod_pins_refused():
    name = "p_prod_pins_refused"
    ra = _needs_ra(name)
    if ra is None:
        return
    try:
        ra.SelfHostedRekor("https://rekor.sigstore.dev", "abc")
        _record(name, "BREAK", "prod URL accepted")
        return
    except ra.RekorConfigError:
        pass
    try:
        ra.SelfHostedRekor("http://rekor.local:3000",
                           ra._ab.REKOR_LOG_ID)
        _record(name, "BREAK", "prod log_id accepted")
        return
    except ra.RekorConfigError:
        pass
    _record(name, "HELD", "Sigstore prod pins refused")


def p_raw_ed25519_refused():
    name = "p_raw_ed25519_refused"
    ra = _needs_ra(name)
    if ra is None:
        return
    ctx = _ctx()
    client = ra.SelfHostedRekor(
        "http://rekor.local:3000", "battery-log",
        transport=FakeRekor())
    try:
        client.submit("ab" * 32,
                      signature_b64=base64.b64encode(b"x" * 64).decode(),
                      pubkey_pem=ctx["sign"](b"\x00" * 32)[1],
                      algorithm="ed25519")
        _record(name, "BREAK", "raw ed25519 accepted (F203)")
    except ra.RekorConfigError as e:
        _record(name, "HELD", "refused: %s" % (str(e)[:60],))


def p_layering():
    name = "p_layering"
    ra = _needs_ra(name)
    if ra is None:
        return
    ctx = _ctx()
    fake = FakeRekor()
    client = ra.SelfHostedRekor(
        "http://rekor.local:3000", fake.log_id, transport=fake)
    sig_b64, pem, alg = ctx["sign"](bytes.fromhex("ab" * 32))
    receipt = client.submit("ab" * 32, signature_b64=sig_b64,
                            pubkey_pem=pem, algorithm=alg)
    if receipt["evidentiary_grade"] != "digest-existence-only" \
            or receipt["authority_proof"]:
        _record(name, "BREAK", "receipt misgraded")
        return
    try:
        ra.present_as_authority(receipt)
        _record(name, "BREAK", "present_as_authority did not raise")
        return
    except ra.RekorLayeringError:
        pass
    forged = dict(receipt)
    forged["authority_proof"] = True
    try:
        ra.present_as_authority(forged)
        _record(name, "BREAK", "forged authority receipt accepted")
        return
    except ra.RekorLayeringError:
        pass
    _record(name, "HELD", "receipts can never become authority")


def p_anchor_verify_roundtrip():
    name = "p_anchor_verify_roundtrip"
    ra = _needs_ra(name)
    if ra is None:
        return
    ctx = _ctx()
    fake = FakeRekor()
    client = ra.SelfHostedRekor(
        "http://rekor.local:3000", fake.log_id, transport=fake)
    ahash, receipt = ra.anchor_checkpoint_sth(
        ctx["checkpoint"], client=client, sign=ctx["sign"])
    ok, reason = ra.verify_inclusion(receipt, ahash, client=client)
    if not ok:
        _record(name, "BREAK", "checkpoint: %s" % (reason,))
        return
    mhash, mreceipt = ra.anchor_bundle_manifest(
        ctx["manifest"], client=client, sign=ctx["sign"])
    ok, reason = ra.verify_inclusion(mreceipt, mhash, client=client)
    if not ok:
        _record(name, "BREAK", "manifest: %s" % (reason,))
        return
    _record(name, "HELD",
            "checkpoint STH + sealed manifest anchored and verified")


def p_stale_proof_refused():
    name = "p_stale_proof_refused"
    ra = _needs_ra(name)
    if ra is None:
        return
    ctx = _ctx()
    fake = FakeRekor()
    client = ra.SelfHostedRekor(
        "http://rekor.local:3000", fake.log_id, transport=fake)
    sig = ctx["sign"]
    r_a = client.submit("aa" * 32, signature_b64=sig(
        bytes.fromhex("aa" * 32))[0], pubkey_pem=sig(b"\x00" * 32)[1])
    client.submit("bb" * 32, signature_b64=sig(
        bytes.fromhex("bb" * 32))[0], pubkey_pem=sig(b"\x00" * 32)[1])
    ok, reason = ra.verify_inclusion(r_a, "aa" * 32, client=client)
    if ok or "STALE" not in (reason or ""):
        _record(name, "BREAK",
                "stale proof not refused: %r" % (reason,))
        return
    fresh = client.get_entry(r_a["uuid"])
    r_a["inclusion_proof"] = client.proof_of(fresh)
    ok, reason = ra.verify_inclusion(r_a, "aa" * 32, client=client)
    if not ok:
        _record(name, "BREAK", "fresh proof rejected: %s" % (reason,))
        return
    _record(name, "HELD", "stale refused; fresh-proof re-fetch verifies")


def p_equivocation_refused():
    name = "p_equivocation_refused"
    ra = _needs_ra(name)
    if ra is None:
        return
    from gov import ed25519 as ed
    ctx = _ctx()
    fake = FakeRekor()
    client = ra.SelfHostedRekor(
        "http://rekor.local:3000", fake.log_id, transport=fake)
    sig = ctx["sign"]
    client.submit("aa" * 32, signature_b64=sig(
        bytes.fromhex("aa" * 32))[0], pubkey_pem=sig(b"\x00" * 32)[1])
    checkpoint = client.fetch_checkpoint()
    leaves = list(fake.bodies)
    w = ra.RekorWitness(ed.generate_seed())
    cosig, reason = w.cosign_checkpoint(checkpoint, leaves)
    if cosig is None:
        _record(name, "BREAK", "honest checkpoint refused: %s" % (reason,))
        return
    forged = dict(checkpoint)
    forged["root_hash"] = "ff" * 32  # same size, different root
    cosig2, reason2 = w.cosign_checkpoint(forged, leaves)
    if cosig2 is not None or "EQUIVOCATION" not in (reason2 or ""):
        _record(name, "BREAK", "forged checkpoint not refused")
        return
    if not w.equivocations_seen:
        _record(name, "BREAK", "equivocation not recorded")
        return
    _record(name, "HELD", "same-size/different-root refused + recorded")


def p_witness_quorum():
    name = "p_witness_quorum"
    ra = _needs_ra(name)
    if ra is None:
        return
    from gov import ed25519 as ed
    ctx = _ctx()
    fake = FakeRekor()
    client = ra.SelfHostedRekor(
        "http://rekor.local:3000", fake.log_id, transport=fake)
    sig = ctx["sign"]
    client.submit("aa" * 32, signature_b64=sig(
        bytes.fromhex("aa" * 32))[0], pubkey_pem=sig(b"\x00" * 32)[1])
    checkpoint = client.fetch_checkpoint()
    leaves = list(fake.bodies)
    ws = [ra.RekorWitness(ed.generate_seed()) for _ in range(3)]
    cosigs = []
    for w in ws:
        c, r = w.cosign_checkpoint(checkpoint, leaves)
        if c is None:
            _record(name, "BREAK", "honest cosign failed: %s" % (r,))
            return
        cosigs.append(c)
    registry = {w.witness_id: w.pubkey_hex for w in ws}
    ok, _ = ra.verify_witness_cosignatures(
        checkpoint, cosigs[:2], registry, quorum=2)
    if not ok:
        _record(name, "BREAK", "2-of-3 quorum failed")
        return
    ok, _ = ra.verify_witness_cosignatures(
        checkpoint, [cosigs[0], cosigs[0]], registry, quorum=2)
    if ok:
        _record(name, "BREAK", "duplicate witness satisfied quorum")
        return
    ok, _ = ra.verify_witness_cosignatures(
        checkpoint, cosigs[:1], registry, quorum=2)
    if ok:
        _record(name, "BREAK", "1-of-2 satisfied quorum")
        return
    _record(name, "HELD", "quorum needs distinct registered witnesses")


def p_offline_bundle():
    name = "p_offline_bundle"
    ra = _needs_ra(name)
    if ra is None:
        return
    ctx = _ctx()
    fake = FakeRekor()
    client = ra.SelfHostedRekor(
        "http://rekor.local:3000", fake.log_id, transport=fake)
    ahash, receipt = ra.anchor_checkpoint_sth(
        ctx["checkpoint"], client=client, sign=ctx["sign"])
    checkpoint = client.fetch_checkpoint()
    leaves = list(fake.bodies)
    w = ra.RekorWitness(ctx["witness_seed"])
    cosig, reason = w.cosign_checkpoint(checkpoint, leaves)
    if cosig is None:
        _record(name, "BREAK", "witness would not cosign: %s" % (reason,))
        return
    registry = {w.witness_id: w.pubkey_hex}
    bundle = ra.build_offline_bundle(
        anchor_hash=ahash, receipt=receipt, checkpoint=checkpoint,
        leaves=leaves, witness_cosigs=[cosig])
    fake.down = True  # the server is availability, not truth
    ok, reason = ra.verify_offline_bundle(
        bundle, witness_registry=registry, quorum=1)
    if not ok:
        _record(name, "BREAK", "offline verify failed: %s" % (reason,))
        return
    # quorum-less acceptance must fail closed (spec review).
    ok, _ = ra.verify_offline_bundle(bundle)
    if ok:
        _record(name, "BREAK", "quorum-less bundle verified")
        return
    bundle["leaves_b64"][0] = base64.b64encode(b"tampered").decode()
    ok, _ = ra.verify_offline_bundle(
        bundle, witness_registry=registry, quorum=1)
    if ok:
        _record(name, "BREAK", "tampered leaf verified")
        return
    _record(name, "HELD", "offline bundle verifies server-down")


def _run_all():
    _RESULTS.clear()
    p_import_seam()
    p_f203_live_pin()
    p_prod_pins_refused()
    p_raw_ed25519_refused()
    p_layering()
    p_anchor_verify_roundtrip()
    p_stale_proof_refused()
    p_equivocation_refused()
    p_witness_quorum()
    p_offline_bundle()
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
    suites = ["tests.test_rekor_anchor", "tests.test_w72_anchor",
              "tests.test_anchoring", "tests.test_evidence_bundle",
              "tests.test_offline_bundle"]
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
    print("rekor_anchor_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR / green=%s"
          % (held, brk, exp, err, ok))
    return 1 if (brk or err or not ok) else 0


if __name__ == "__main__":
    sys.exit(main())
