#!/usr/bin/env python3
"""Rekor v2 (tile-backed) anchoring migration shape: red-first probe battery.

Wave-207 lane B. ADAPT of the Rekor v2 migration shape (wave-205
prospecting §5): dual-write anchors with a ``verification.source``
field on receipts, behind a flag. v1 stays the default anchor;
this lane builds the migration shape hermetically.

What is red on pristine (467ae1a): there is NO v2 anchoring seam at
all -- no ``gov.rekor_v2_anchor`` module, no ``verification.source``
on receipts, no dual-write path, no tile-framed inclusion field,
no TSA-separated timestamp field, no v2 local index.

What is green post-fix: ``gov/rekor_v2_anchor.py`` -- a hermetic
(offline, fixture-driven) v2-shaped backend accepting ONLY the
``hashedrekord`` entry type (wave-212/F207 correction: the v2.0.1-era
``dsse`` entry type is gone upstream -- sigstore/rekor-tiles
CLIENTS.md at commit 5e6ebbad supports only
HashedRekordLogEntryV002; DSSE envelopes are committed as their PAE
hash inside a hashedrekord entry); receipts carrying
``verification.source`` (``rekor-v1`` / ``rekor-v2-hermetic`` /
``dual-write``); client-computed tile-framed inclusion proofs (no
online proof API in v2 -- this is the documented v2 model);
timestamps as a separate TSA-shaped field, never folded into the
transparency proof; a local v2 index (v2 drops search indexing, so
we keep our own); dual-write behind ``dual_write=True`` /
``GOV_REKOR_V2_DUAL_WRITE`` with v1-only as the default.

Probe map:
  p_import_seam:      gov.rekor_v2_anchor imports; source constants +
                      entry-type allowlist pinned.
  p_hashedrekord_receipt: v2-shaped receipt for a hashedrekord entry:
                      verification.source == "rekor-v2-hermetic",
                      entry_type pinned, uuid/log_index present,
                      tile-framed inclusion, separate tsa field.
  p_dsse_receipt:     a DSSE envelope committed as its PAE hash
                      inside a hashedrekord entry (F207: DSSE is NOT a
                      v2 entry type upstream; the receipt is
                      kind:hashedrekord, apiVersion 0.0.2, carrying
                      payload_type / payload_sha256 / pae_sha256).
  p_bad_type_refused: "rekord" (a v1-only type, REMOVED in v2),
                      "intoto", "cose", and the superseded native
                      "dsse" entry kind are refused loudly -- v2 takes
                      only hashedrekord.
  p_dual_write:       DualWriteAnchor with dual_write=True writes
                      BOTH logs; combined receipt carries both entries
                      with DISTINCT verification.source values.
  p_default_v1_only:  dual_write=False (default): the receipt is the
                      v1 shape with verification.source == "rekor-v1"
                      and carries NO v2 entry data.
  p_inclusion_self_consistent: verify_inclusion_v2 recomputes the
                      root from the proof; a stale proof (log grown
                      after anchoring) is refused.
  p_prod_pins_refused: Sigstore production log pins refused
                      (self-hosted-only stance, same as the v1 module).
  p_local_index:      the v2 local index records and answers
                      digest -> receipt lookups (v2 drops search
                      indexing; we keep our own).
  p_deterministic_x2: byte-identical verdicts across 2 runs.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic, stdlib only. No network:
v1 live POST already hangs from this network, so the whole lane is
hermetic by design (honest residual: no live v2 round-trip yet).

Run (fresh UNIQUE /var/tmp TMPDIR per run -- never reuse one across
runs, and always mkdir -p first: Python 3.12 silently ignores a
nonexistent TMPDIR):
  T=/var/tmp/g207bv2-$$; mkdir -p $T
  TMPDIR=$T ~/workspace/.gov-venv/bin/python \
      evals/rekor_v2_anchor_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=$T ~/workspace/.gov-venv/bin/python \
      evals/rekor_v2_anchor_probes.py
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import hashlib  # noqa: E402
import json  # noqa: E402
import subprocess  # noqa: E402

try:
    from gov import rekor_v2_anchor as v2  # noqa: E402
    _V2 = v2
    _V2_IMPORT_ERROR = None
except ImportError as e:
    _V2 = None
    _V2_IMPORT_ERROR = e

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-28s %-10s %s" % (name, verdict, detail))


def _needs_v2(name):
    if _V2 is None:
        _record(name, "ERROR",
                "no product seam on pristine: %s" % (_V2_IMPORT_ERROR,))
        return None
    return _V2


_TEST_LOG_URL = "https://rekor-v2.example-operator.invalid"
_TEST_LOG_ID = "deadbeef" * 8
_TEST_TSA_URL = "https://tsa.example-operator.invalid"


def _signing_config():
    return {"log_url": _TEST_LOG_URL, "log_id": _TEST_LOG_ID,
            "tsa_url": _TEST_TSA_URL}


def _client():
    return _V2.HermeticRekorV2(signing_config=_signing_config())


def _anchor_material():
    digest = hashlib.sha256(b"artifact-bytes-wave207").hexdigest()
    seed = bytes([77]) * 32
    from gov.signing import Ed25519Signer
    signer = Ed25519Signer(seed)
    # Ed25519ph-SHA512 over the 32-byte digest: the F203-fixed shape
    # that real hashedrekord accepts. gov.ed25519 exposes sign_ph.
    from gov import ed25519 as _ed
    sig = _ed.sign_ph(seed, bytes.fromhex(digest))
    from gov import anchor_backend as _ab
    pubkey_pem = _ab.anchor_spki_pem(_ed.publickey(seed))
    return digest, sig.hex(), pubkey_pem


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

def p_import_seam():
    name = "p_import_seam"
    m = _needs_v2(name)
    if m is None:
        return
    ok = (m.SOURCE_V1 == "rekor-v1"
          and m.SOURCE_V2 == "rekor-v2-hermetic"
          and m.SOURCE_DUAL == "dual-write"
          and m.V2_ENTRY_TYPES == frozenset({"hashedrekord"}))
    _record(name, "HELD" if ok else "BREAK",
            "source constants + hashedrekord-only allowlist pinned")


def p_hashedrekord_receipt():
    name = "p_hashedrekord_receipt"
    m = _needs_v2(name)
    if m is None:
        return
    digest, sig_hex, pubkey_pem = _anchor_material()
    try:
        r = _client().submit_hashedrekord(
            digest, signature_b64=_b64(sig_hex), pubkey_pem=pubkey_pem,
            algorithm="ed25519ph-sha512")
    except Exception as e:  # noqa: BLE001
        _record(name, "BREAK", "submit raised: %r" % (e,))
        return
    checks = [
        r.get("verification.source") == "rekor-v2-hermetic",
        r.get("entry_type") == "hashedrekord",
        bool(isinstance(r.get("uuid"), str) and r["uuid"]),
        isinstance(r.get("log_index"), int),
        isinstance(r.get("inclusion"), dict)
        and "root_hash" in r["inclusion"] and "hashes" in r["inclusion"],
        isinstance(r.get("tile"), dict)
        and r["tile"].get("tile_size") == 256,
        isinstance(r.get("tsa"), dict)
        and "signed_time" in r["tsa"] and r["tsa"].get("hermetic") is True,
        r.get("evidentiary_grade") == "digest-existence-only",
        r.get("authority_proof") is False,
    ]
    _record(name, "HELD" if all(checks) else "BREAK",
            "v2 hashedrekord receipt shape: %d/9 checks" % sum(checks))


def _b64(hexstr):
    import base64
    return base64.b64encode(bytes.fromhex(hexstr)).decode("ascii")


def p_dsse_receipt():
    name = "p_dsse_receipt"
    m = _needs_v2(name)
    if m is None:
        return
    try:
        from gov import dsse_envelope as dsse
        from gov.signing import Ed25519Signer
        signer = Ed25519Signer(bytes([78]) * 32)
        env = dsse.seal(b"release-artifact", "application/vnd.in-toto+json",
                        [signer])
        # F207: DSSE is not a v2 entry type -- committed as its PAE
        # hash inside a hashedrekord entry. One client: the hermetic
        # log is in-memory per client.
        client = _client()
        r = client.submit_dsse_as_hashedrekord(env)
    except Exception as e:  # noqa: BLE001
        _record(name, "BREAK", "dsse pae-hash submit raised: %r" % (e,))
        return
    import base64 as _b64mod
    import hashlib as _hl
    tb = b"application/vnd.in-toto+json"
    payload = _b64mod.b64decode(env["payload"].encode("ascii"),
                                validate=True)
    pae = (b"DSSEv1 " + str(len(tb)).encode() + b" " + tb + b" "
           + str(len(payload)).encode() + b" " + payload)
    pae_sha = _hl.sha256(pae).hexdigest()
    try:
        body = json.loads(
            client.entry_bytes_for_receipt(r).decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        _record(name, "BREAK", "entry bytes unreadable: %r" % (e,))
        return
    ok = (r.get("verification.source") == "rekor-v2-hermetic"
          and r.get("entry_type") == "hashedrekord"
          and r.get("payload_type") == "application/vnd.in-toto+json"
          and r.get("pae_sha256") == pae_sha
          and r.get("dsse_routing") == "pae-hash-in-hashedrekord"
          and body.get("kind") == "hashedrekord"
          and body.get("apiVersion") == "0.0.2"
          and body["spec"]["data"]["hash"]["value"] == pae_sha)
    _record(name, "HELD" if ok else "BREAK",
            "dsse->pae-hash->hashedrekord receipt; kind pinned")


def p_bad_type_refused():
    name = "p_bad_type_refused"
    m = _needs_v2(name)
    if m is None:
        return
    client = _client()
    refused = 0
    # F207: the superseded native "dsse" entry kind is refused exactly
    # like every other removed type -- v2 takes only hashedrekord.
    for bad in ("rekord", "intoto", "cose", "dsse", ""):
        try:
            client.submit(bad, b"whatever")
        except (m.V2ConfigError, ValueError):
            refused += 1
        except Exception as e:  # noqa: BLE001
            _record(name, "BREAK",
                    "wrong exception for %r: %r" % (bad, e))
            return
    _record(name, "HELD" if refused == 5 else "BREAK",
            "%d/5 non-v2 types refused" % refused)


def p_dual_write():
    name = "p_dual_write"
    m = _needs_v2(name)
    if m is None:
        return
    digest, sig_hex, pubkey_pem = _anchor_material()

    def fake_v1_submit(anchor_hash, *, signature_b64, pubkey_pem,
                       algorithm):
        return {"backend": "rekor-v1-fake", "uuid": "v1-uuid-1",
                "anchor_hash": anchor_hash}

    anchor = m.DualWriteAnchor(v1_submit=fake_v1_submit,
                               v2_client=_client(), dual_write=True)
    try:
        r = anchor.anchor(digest, signature_b64=_b64(sig_hex),
                          pubkey_pem=pubkey_pem,
                          algorithm="ed25519ph-sha512")
    except Exception as e:  # noqa: BLE001
        _record(name, "BREAK", "dual-write raised: %r" % (e,))
        return
    entries = r.get("entries", {})
    v1e = entries.get("rekor-v1", {})
    v2e = entries.get("rekor-v2-hermetic", {})
    ok = (r.get("verification.source") == "dual-write"
          and v1e.get("verification.source") == "rekor-v1"
          and v2e.get("verification.source") == "rekor-v2-hermetic"
          and v1e.get("anchor_hash") == digest
          and v2e.get("entry_type") == "hashedrekord")
    _record(name, "HELD" if ok else "BREAK",
            "dual-write receipt: both entries, distinct sources")


def p_default_v1_only():
    name = "p_default_v1_only"
    m = _needs_v2(name)
    if m is None:
        return
    digest, sig_hex, pubkey_pem = _anchor_material()

    def fake_v1_submit(anchor_hash, *, signature_b64, pubkey_pem,
                       algorithm):
        return {"backend": "rekor-v1-fake", "uuid": "v1-uuid-1",
                "anchor_hash": anchor_hash}

    anchor = m.DualWriteAnchor(v1_submit=fake_v1_submit,
                               v2_client=_client())  # dual_write off
    try:
        r = anchor.anchor(digest, signature_b64=_b64(sig_hex),
                          pubkey_pem=pubkey_pem,
                          algorithm="ed25519ph-sha512")
    except Exception as e:  # noqa: BLE001
        _record(name, "BREAK", "default anchor raised: %r" % (e,))
        return
    blob = json.dumps(r, sort_keys=True)
    ok = (r.get("verification.source") == "rekor-v1"
          and "entries" not in r
          and "rekor-v2" not in blob
          and "tile" not in blob)
    _record(name, "HELD" if ok else "BREAK",
            "default path: v1-only, no v2 fields")


def p_inclusion_self_consistent():
    name = "p_inclusion_self_consistent"
    m = _needs_v2(name)
    if m is None:
        return
    digest, sig_hex, pubkey_pem = _anchor_material()
    client = _client()
    r = client.submit_hashedrekord(
        digest, signature_b64=_b64(sig_hex), pubkey_pem=pubkey_pem,
        algorithm="ed25519ph-sha512")
    entry_bytes = client.entry_bytes_for_receipt(r)
    try:
        fresh_ok = client.verify_inclusion(r, entry_bytes)
    except Exception as e:  # noqa: BLE001
        _record(name, "BREAK", "fresh verify raised: %r" % (e,))
        return
    # Grow the log: the old receipt's proof is now stale and must be
    # refused (same guard the v1 module enforces).
    digest2 = hashlib.sha256(b"second-artifact").hexdigest()
    from gov import ed25519 as _ed
    sig2 = _ed.sign_ph(bytes([77]) * 32, bytes.fromhex(digest2))
    client.submit_hashedrekord(
        digest2, signature_b64=_b64(sig2.hex()), pubkey_pem=pubkey_pem,
        algorithm="ed25519ph-sha512")
    try:
        stale_ok = client.verify_inclusion(r, entry_bytes)
    except m.V2AnchorError:
        stale_ok = False
    ok = fresh_ok is True and stale_ok is False
    _record(name, "HELD" if ok else "BREAK",
            "fresh verifies; stale (grown log) refused")


def p_prod_pins_refused():
    name = "p_prod_pins_refused"
    m = _needs_v2(name)
    if m is None:
        return
    refused = 0
    for cfg in ({"log_url": "https://rekor.sigstore.dev",
                 "log_id": _TEST_LOG_ID},
                {"log_url": _TEST_LOG_URL,
                 "log_id": "c0d23d6ad406973f9559f3ba1d1ca01f84147d8ffc5b8445c2249c2cc77d6cd9d69"},):
        try:
            m.HermeticRekorV2(signing_config=cfg)
        except m.V2ConfigError:
            refused += 1
        except Exception as e:  # noqa: BLE001
            _record(name, "BREAK", "wrong exception: %r" % (e,))
            return
    _record(name, "HELD" if refused == 2 else "BREAK",
            "production pins refused: %d/2" % refused)


def p_local_index():
    name = "p_local_index"
    m = _needs_v2(name)
    if m is None:
        return
    digest, sig_hex, pubkey_pem = _anchor_material()
    idx = m.V2LocalIndex()
    r = _client().submit_hashedrekord(
        digest, signature_b64=_b64(sig_hex), pubkey_pem=pubkey_pem,
        algorithm="ed25519ph-sha512")
    idx.record(digest, r)
    hit = idx.lookup(digest)
    miss = idx.lookup("ff" * 32)
    ok = (hit is not None and hit.get("uuid") == r["uuid"]
          and miss is None)
    _record(name, "HELD" if ok else "BREAK",
            "local v2 index: hit returns receipt, miss returns None")


def _run_all():
    _RESULTS.clear()
    p_import_seam()
    p_hashedrekord_receipt()
    p_dsse_receipt()
    p_bad_type_refused()
    p_dual_write()
    p_default_v1_only()
    p_inclusion_self_consistent()
    p_prod_pins_refused()
    p_local_index()
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
    suites = ["tests.test_rekor_v2_anchor", "tests.test_rekor_anchor",
              "tests.test_anchoring"]
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
    print("rekor_v2_anchor_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR / green=%s"
          % (held, brk, exp, err, ok))
    return 1 if (brk or err or not ok) else 0


if __name__ == "__main__":
    sys.exit(main())
