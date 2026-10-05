"""Break-first probes for gov/offline_verify (wave-324 lane 2).

Red-first: on the open tree this battery dies at import
(ModuleNotFoundError: gov.offline_verify). On the lane tree every
attack below must refuse with the coded reason, and the good package
must verify with a fully itemized report.

Staging default is set at module level (the harness refuses the
declared ungoverned_ack in production mode).
"""

import base64
import copy
import hashlib
import json
import os
import secrets
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2128 # 1990 + 16 offline-verify-*; Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 1: pin 2020 -> 2021 (+1 witness-alert-state-lost); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)
_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _error(pid, note):
    _record(pid, "ERROR", note)


def probe(pid):
    def deco(fn):
        def run():
            try:
                fn()
            except AssertionError as exc:
                _break(pid, "assertion failed: %s" % (exc,))
            except Exception as exc:  # noqa: BLE001
                _error(pid, "%s: %s" % (type(exc).__name__, exc))
        run.__name__ = pid
        return run
    return deco


def _expect_code(pid, fn, code):
    """fn() must raise an error whose .code == code; anything else BREAKs."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None)
        if got == code:
            _held(pid, "refused coded %s" % (code,))
        else:
            _break(pid, "wrong refusal: code=%r (%s: %s)"
                   % (got, type(exc).__name__, exc))
        return
    _break(pid, "no refusal (expected coded %s)" % (code,))


# ---------------------------------------------------------------------------
# Imports (die on the open tree: red-first).
# ---------------------------------------------------------------------------

from gov import offline_verify as OV  # noqa: E402
from gov import export_witness as EW  # noqa: E402
from gov import witness_policy as WP  # noqa: E402
from gov import witness_log as WL  # noqa: E402
from gov import checkpoint_note as CN  # noqa: E402
from gov import offline_bundle as OB  # noqa: E402
from gov import anchor_adapter as AA  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures (fixed seeds: deterministic keys across runs).
# ---------------------------------------------------------------------------

_SEED_ENTRY = hashlib.sha256(b"w324-offver-entry-signer").digest()
_SEED_LOG = hashlib.sha256(b"w324-offver-log").digest()
_SEED_OP = bytes(range(32))
_SEED_W1 = bytes([255 - i for i in range(32)])
_SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
_SEED_W3 = bytes([(i * 13 + 5) % 256 for i in range(32)])
_SEED_P1 = bytes([(i * 3 + 11) % 256 for i in range(32)])
_SEED_P2 = bytes([(i * 5 + 17) % 256 for i in range(32)])
_SEED_P3 = bytes([(i * 11 + 23) % 256 for i in range(32)])

_NOW = 1798765432
_ORIGIN = "sasanam-offline-verify-test/v1"
_NLEAF = 8


def _signer(seed):
    return Ed25519Signer(seed)


def _op_vkey():
    s = _signer(_SEED_OP)
    return CN.vkey_string(
        "op", CN.derive_key_id("op", CN.SIG_TYPE_ED25519, s.public_key),
        CN.SIG_TYPE_ED25519, s.public_key)


def _wit_vkey(name, seed):
    s = _signer(seed)
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519_COSIGNATURE_V1,
                               s.public_key),
        CN.SIG_TYPE_ED25519_COSIGNATURE_V1, s.public_key)


def _wit(name, seed):
    return {"name": name, "vkey": _wit_vkey(name, seed),
            "operator": "%s-operator" % name,
            "contact": "%s@example.org" % name,
            "not_before": _NOW - 100000, "not_after": _NOW + 100000,
            "status": "usable"}


def _policy_body(threshold=2, policy_threshold=2, issued_at=None,
                 expires_at=None, policy_id="sasanam-witness-policy"):
    p1, p2 = _signer(_SEED_P1), _signer(_SEED_P2)
    return {
        "schema": "witness-policy/v1",
        "policy_id": policy_id,
        "version": 1,
        "issued_at": _NOW - 1000 if issued_at is None else issued_at,
        "expires_at": _NOW + 86400 * 90 if expires_at is None else expires_at,
        "threshold": threshold,
        "log": {"name": "op", "vkey": _op_vkey()},
        "witnesses": [_wit("w1", _SEED_W1), _wit("w2", _SEED_W2),
                      _wit("w3", _SEED_W3)],
        "policy_signers": [{"key_id": s.public_key.hex(),
                            "public_key": s.public_key.hex()}
                           for s in (p1, p2)],
        "policy_threshold": policy_threshold,
        "max_checkpoint_staleness_seconds": 10800,
    }


def _anchor_signers():
    p1, p2 = _signer(_SEED_P1), _signer(_SEED_P2)
    return [{"key_id": s.public_key.hex(), "public_key": s.public_key.hex()}
            for s in (p1, p2)]


def _anchor():
    return {"policy_signers": _anchor_signers(), "policy_threshold": 2}


def _sealed(**kw):
    return WP.seal_policy(_policy_body(**kw),
                          [_signer(_SEED_P1), _signer(_SEED_P2)])


def _trust_root(adapter):
    return {"policy_signers": _anchor_signers(),
            "policy_threshold": 2,
            "anchor_log_pubkey_hex": adapter.public_key.hex()}


def _leaves(digest_hex):
    d = bytes.fromhex(digest_hex)
    return [EW.bundle_leaf_hash(d, i) for i in range(_NLEAF)]


def _note(leaves, ts=None, witnesses=("w1", "w2"), origin=_ORIGIN,
          op_seed=_SEED_OP):
    root = WL._calc_root(leaves)
    note = CN.emit_checkpoint(origin, len(leaves), root, "op", op_seed)
    seeds = {"w1": _SEED_W1, "w2": _SEED_W2, "w3": _SEED_W3}
    for w in witnesses:
        line = CN.emit_cosignature_line(w, _signer(seeds[w]), origin,
                                        len(leaves), root,
                                        _NOW - 100 if ts is None else ts)
        note += (line + "\n").encode("utf-8")
    return note.decode("utf-8")


def _bundle_digest(bundle_dir):
    """Inline mirror of the documented digest algorithm (cross-checks
    OV.bundle_digest_for_dir)."""
    h = hashlib.sha256()
    rels = []
    for root, _d, names in os.walk(bundle_dir):
        for n in names:
            rel = os.path.relpath(os.path.join(root, n), bundle_dir)
            if rel in ("BUNDLE_DIGEST.sha256", "witness_layer.json",
                       "small_carrier.bin"):
                continue
            rels.append(rel)
    for rel in sorted(rels):
        with open(os.path.join(bundle_dir, rel), "rb") as f:
            content = f.read()
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(content)
        h.update(b"\x00")
    return h.hexdigest()


def _build_log(tmp):
    os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
    signer = _signer(_SEED_ENTRY)
    log_path = os.path.join(tmp, "audit.jsonl")
    lg = ActionLog(log_path, signer=signer)
    for i in range(8):
        lg.append({"event": "tool_call", "tool": "t%d" % i,
                   "target": "/x/%d" % i})
    return log_path, signer


def _export(tmp, name, log_path, signer, adapter, **kw):
    bundle_dir = os.path.join(tmp, name)
    OB.export_offline_bundle(
        log_path, bundle_dir, adapter,
        entry_signer_pubkey=signer.public_key, **kw)
    return bundle_dir


def _attach_layer(bundle_dir, adapter, policy_doc=None, note_ts=None,
                  layer_tamper=None, carrier=False, now=_NOW,
                  witnesses=("w1", "w2")):
    """Build the witness layer over the bundle's current bytes and
    attach it. The digest is computed over the pre-attachment bytes
    (the attachments are excluded from the digest by construction)."""
    digest = _bundle_digest(bundle_dir)
    leaves = _leaves(digest)
    doc = policy_doc if policy_doc is not None else _sealed()
    layer = EW.build_witness_layer(
        digest, checkpoint=_note(leaves, ts=note_ts, witnesses=witnesses),
        policy_doc=doc, trust_anchor=_anchor(),
        consistency_proof=EW.make_consistency_proof(leaves, 3),
        inclusion_proofs=[EW.make_inclusion_proof(leaves, 0)],
        bundle_id="test-bundle-1", now=now)
    if layer_tamper is not None:
        layer_tamper(layer)
    with open(os.path.join(bundle_dir, "witness_layer.json"), "w",
              encoding="utf-8") as f:
        f.write(json.dumps(layer, sort_keys=True))
    if carrier:
        blob = EW.encode_small_carrier(layer, exported_at=now - 10)
        with open(os.path.join(bundle_dir, "small_carrier.bin"),
                  "wb") as f:
            f.write(blob)
    return layer


def _good_package(tmp, name="bundle", bundle_id=None, **kw):
    """A fully valid package: real exported bundle + attached witness
    layer. Returns (bundle_dir, trust_root, adapter)."""
    log_path, signer = _build_log(tmp)
    adapter = AA.FakeLogAdapter(_SEED_LOG)
    bundle_dir = _export(tmp, name, log_path, signer, adapter,
                         bundle_id=bundle_id)
    _attach_layer(bundle_dir, adapter, **kw)
    return bundle_dir, _trust_root(adapter), adapter


def _verify(bundle_dir, trust_root, **kw):
    kw.setdefault("now", _NOW)
    return OV.verify_evidence_bundle(bundle_dir, trust_root, **kw)


def _refresh_digest(bundle_dir):
    """Rewrite BUNDLE_DIGEST.sha256 over the current bytes (models a
    tamperer who updates the untrusted digest file, so the specific
    integrity check -- not the tripwire -- is exercised)."""
    with open(os.path.join(bundle_dir, "BUNDLE_DIGEST.sha256"), "w",
              encoding="utf-8") as f:
        f.write(_bundle_digest(bundle_dir) + "\n")


def _rechain(bundle_dir, adapter):
    """Recompute the export chain over the current ledger bytes, update
    the manifest tip, and re-anchor under ``adapter`` (models a
    malicious operator who re-anchors a tampered bundle)."""
    with open(os.path.join(bundle_dir, "ledger.jsonl"),
              encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    prev = OB.EXPORT_GENESIS
    for e in entries:
        body = {k: v for k, v in e.items() if k != "export_hash"}
        prev = OB._chain_hash(prev, OB._canonical(body))
        e["export_hash"] = prev
    with open(os.path.join(bundle_dir, "ledger.jsonl"), "w",
              encoding="utf-8") as f:
        for e in entries:
            f.write(OB._canonical(e).decode("utf-8") + "\n")
    with open(os.path.join(bundle_dir, "manifest.json"),
              encoding="utf-8") as f:
        manifest = json.load(f)
    manifest["ledger_digest"] = prev
    manifest["anchor"]["log_pubkey_hex"] = adapter.public_key.hex()
    manifest["anchor"]["log_id"] = adapter.log_id
    with open(os.path.join(bundle_dir, "manifest.json"), "w",
              encoding="utf-8") as f:
        f.write(OB._canonical(manifest).decode("utf-8") + "\n")
    receipt = adapter.anchor(OB._anchor_input(manifest))
    with open(os.path.join(bundle_dir, "anchor_receipt.json"), "w",
              encoding="utf-8") as f:
        f.write(OB._canonical(receipt).decode("utf-8") + "\n")
    _refresh_digest(bundle_dir)
    return entries


def _read_json(bundle_dir, name):
    with open(os.path.join(bundle_dir, name), encoding="utf-8") as f:
        return json.load(f)


def _write_json(bundle_dir, name, obj):
    with open(os.path.join(bundle_dir, name), "w",
              encoding="utf-8") as f:
        f.write(json.dumps(obj, sort_keys=True))


# ---------------------------------------------------------------------------
# P1: the good path verifies with a fully itemized report.
# ---------------------------------------------------------------------------

@probe("P1-good-package-verifies")
def _p1():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, _adapter = _good_package(tmp)
    report = _verify(bundle_dir, trust_root)
    assert report["format"] == "sasanam-offline-verification-report/v1", \
        report["format"]
    assert report["verdict"] == "pass", report["verdict"]
    steps = [c["step"] for c in report["checks"]]
    # Every pipeline step is itemized -- never a bare "Verified OK".
    for want in ("package-parse", "trust-root-pin", "bundle-digest",
                 "bundle-format", "bundle-monotonicity",
                 "bundle-containment", "bundle-chain",
                 "bundle-entry-signatures", "bundle-redaction",
                 "bundle-anchor", "witness-layer", "policy-window",
                 "small-carrier"):
        assert want in steps, "missing step %s in %s" % (want, steps)
    assert all(c["result"] == "pass" for c in report["checks"]), \
        [c for c in report["checks"] if c["result"] != "pass"]
    assert report["bundle_digest"] == _bundle_digest(bundle_dir)
    assert report["facts"]["policy_id"] == "sasanam-witness-policy"
    _held("P1-good-package-verifies",
          "verdict pass, %d checks itemized" % (len(steps),))


@probe("P1b-digest-agreement")
def _p1b():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, _tr, _ad = _good_package(tmp)
    assert OV.bundle_digest_for_dir(bundle_dir) == _bundle_digest(bundle_dir)
    _held("P1b-digest-agreement", "module digest == inline digest")


@probe("P1c-bytes-package-verifies")
def _p1c():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, _adapter = _good_package(tmp)
    files = {}
    for root, _d, names in os.walk(bundle_dir):
        for n in names:
            rel = os.path.relpath(os.path.join(root, n), bundle_dir)
            if rel == "witness_layer.json":
                continue
            with open(os.path.join(root, n), encoding="utf-8") as f:
                files[rel] = f.read()
    layer = _read_json(bundle_dir, "witness_layer.json")
    pkg = {"format": "sasanam-offline-evidence-package/v1",
           "files": files, "witness_layer": layer}
    blob = json.dumps(pkg, sort_keys=True).encode("utf-8")
    report = OV.verify_evidence_bundle(blob, trust_root, now=_NOW)
    assert report["verdict"] == "pass", report["verdict"]
    _held("P1c-bytes-package-verifies", "serialized form verifies")


# ---------------------------------------------------------------------------
# P2: bundle-integrity attacks.
# ---------------------------------------------------------------------------

@probe("P2-forged-entry-breaks-chain")
def _p2():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(tmp)

    def tamper(d):
        p = os.path.join(d, "ledger.jsonl")
        with open(p, encoding="utf-8") as f:
            entries = [json.loads(line) for line in f if line.strip()]
        entries[3]["target"] = "/evil/x"
        with open(p, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(OB._canonical(e).decode("utf-8") + "\n")
    tamper(bundle_dir)
    _refresh_digest(bundle_dir)
    # The attacker rebuilds the witness layer over the tampered bytes
    # (models an operator holding the witness keys); the chain must
    # still catch the forgery.
    _attach_layer(bundle_dir, adapter)
    _expect_code("P2-forged-entry-breaks-chain",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-chain-broken")


@probe("P2b-monotonicity-gap")
def _p2b():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(tmp)
    p = os.path.join(bundle_dir, "ledger.jsonl")
    with open(p, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    del entries[4]
    with open(p, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(OB._canonical(e).decode("utf-8") + "\n")
    _refresh_digest(bundle_dir)
    _attach_layer(bundle_dir, adapter)
    _expect_code("P2b-monotonicity-gap",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-monotonicity")


@probe("P2c-containment-entry-count")
def _p2c():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(tmp)
    manifest = _read_json(bundle_dir, "manifest.json")
    manifest["window"]["entry_count"] += 1
    _write_json(bundle_dir, "manifest.json", manifest)
    _refresh_digest(bundle_dir)
    _attach_layer(bundle_dir, adapter)
    _expect_code("P2c-containment-entry-count",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-containment")


@probe("P2d-entry-signature-forged")
def _p2d():
    # A malicious operator re-anchors a bundle whose entry signature
    # is forged: the chain is intact (recomputed), so the per-entry
    # signature check must catch it.
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    log_path, signer = _build_log(tmp)
    adapter = AA.FakeLogAdapter(_SEED_LOG)
    bundle_dir = _export(tmp, "bundle", log_path, signer, adapter)
    p = os.path.join(bundle_dir, "ledger.jsonl")
    with open(p, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    entries[2]["ed_sig"] = "00" * 64
    with open(p, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(OB._canonical(e).decode("utf-8") + "\n")
    adapter2 = AA.FakeLogAdapter(hashlib.sha256(b"w324-log2").digest())
    _rechain(bundle_dir, adapter2)
    _attach_layer(bundle_dir, adapter2)
    trust_root = _trust_root(adapter2)
    _expect_code("P2d-entry-signature-forged",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-entry-signature-invalid")


@probe("P2e-undisclosed-redaction")
def _p2e():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    log_path, signer = _build_log(tmp)
    adapter = AA.FakeLogAdapter(_SEED_LOG)
    bundle_dir = _export(tmp, "bundle", log_path, signer, adapter)
    p = os.path.join(bundle_dir, "ledger.jsonl")
    with open(p, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    e = entries[2]
    del e["target"]
    e.pop("ed_sig", None)
    e.pop("sig_key_id", None)
    e["redacted"] = True
    with open(p, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(OB._canonical(e).decode("utf-8") + "\n")
    adapter2 = AA.FakeLogAdapter(hashlib.sha256(b"w324-log3").digest())
    _rechain(bundle_dir, adapter2)
    _attach_layer(bundle_dir, adapter2)
    trust_root = _trust_root(adapter2)
    _expect_code("P2e-undisclosed-redaction",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-redaction-undisclosed")


@probe("P2f-disclosed-redaction-verifies")
def _p2f():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    log_path, signer = _build_log(tmp)
    adapter = AA.FakeLogAdapter(_SEED_LOG)
    bundle_dir = _export(tmp, "bundle", log_path, signer, adapter,
                         redact_fields=("target",))
    _attach_layer(bundle_dir, adapter)
    report = _verify(bundle_dir, _trust_root(adapter))
    assert report["verdict"] == "pass", report["verdict"]
    _held("P2f-disclosed-redaction-verifies", "redacted bundle verifies")


@probe("P2g-anchor-receipt-forged")
def _p2g():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(tmp)
    receipt = _read_json(bundle_dir, "anchor_receipt.json")
    sig = receipt["log_sig"]
    receipt["log_sig"] = ("00" if sig[:2] != "00" else "ff") + sig[2:]
    _write_json(bundle_dir, "anchor_receipt.json", receipt)
    _refresh_digest(bundle_dir)
    _attach_layer(bundle_dir, adapter)
    _expect_code("P2g-anchor-receipt-forged",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-anchor-invalid")


@probe("P2g2-anchor-statement-hash-mismatch")
def _p2g2():
    # The receipt's self-declared statement_hash does not hash the
    # statement it carries (spec review note: the internal-consistency
    # link must be asserted, not just the Merkle fold under it).
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(tmp)
    receipt = _read_json(bundle_dir, "anchor_receipt.json")
    h = receipt["statement_hash"]
    receipt["statement_hash"] = ("00" if h[:2] != "00" else "ff") + h[2:]
    _write_json(bundle_dir, "anchor_receipt.json", receipt)
    _refresh_digest(bundle_dir)
    _attach_layer(bundle_dir, adapter)
    _expect_code("P2g2-anchor-statement-hash-mismatch",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-anchor-invalid")


@probe("P2h-anchor-key-mismatch")
def _p2h():
    # The bundle pins a different anchor log key than the auditor's
    # trust root: the receipt may be self-consistent, but it is not
    # the auditor's log.
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(tmp)
    other = AA.FakeLogAdapter(hashlib.sha256(b"w324-other-log").digest())
    bad_root = _trust_root(other)
    _expect_code("P2h-anchor-key-mismatch",
                 lambda: _verify(bundle_dir, bad_root),
                 "offline-verify-anchor-key-mismatch")


# ---------------------------------------------------------------------------
# P3: witness-layer attacks.
# ---------------------------------------------------------------------------

@probe("P3-witness-layer-forged-checkpoint")
def _p3():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(tmp)

    def tamper(layer):
        note = layer["checkpoint"]
        layer["checkpoint"] = note[:-20] + "AAAAAAAAAAAAAAAAAAAA"
    _attach_layer(bundle_dir, adapter, layer_tamper=tamper)
    # Rebuild AFTER the tamper so the digest binds the tampered layer
    # file... (the layer is excluded from the digest; the tamper is in
    # the layer itself, so the digest is unchanged and the transplant
    # check passes -- the witness check must fire.)
    _expect_code("P3-witness-layer-forged-checkpoint",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-witness-layer-invalid")


@probe("P3b-policy-seal-forged")
def _p3b():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(tmp)
    # A policy sealed by outsiders (p3), not the anchor's signers.
    # build_witness_layer is fail-closed at build, so the swap happens
    # post-build (models a hand-crafted layer).
    body = _policy_body()
    bad_doc = WP.seal_policy(body, [_signer(_SEED_P3)])

    def tamper(layer):
        layer["policy"] = bad_doc
    _attach_layer(bundle_dir, adapter, layer_tamper=tamper)
    _expect_code("P3b-policy-seal-forged",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-witness-layer-invalid")


@probe("P3c-trust-root-swapped")
def _p3c():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(tmp)
    p3 = _signer(_SEED_P3)
    bad_root = {"policy_signers": [
        {"key_id": p3.public_key.hex(),
         "public_key": p3.public_key.hex()}],
        "policy_threshold": 1,
        "anchor_log_pubkey_hex": adapter.public_key.hex()}
    _expect_code("P3c-trust-root-swapped",
                 lambda: _verify(bundle_dir, bad_root),
                 "offline-verify-witness-layer-invalid")


@probe("P3d-stale-checkpoint")
def _p3d():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(
        tmp, note_ts=_NOW - 10800 - 100)
    _expect_code("P3d-stale-checkpoint",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-witness-layer-invalid")


@probe("P3e-policy-expired")
def _p3e():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(tmp)
    # build_witness_layer refuses an expired policy at build
    # (fail-closed), so the swap happens post-build.
    bad_doc = WP.seal_policy(_policy_body(expires_at=_NOW - 100),
                             [_signer(_SEED_P1), _signer(_SEED_P2)])

    def tamper(layer):
        layer["policy"] = bad_doc
    _attach_layer(bundle_dir, adapter, layer_tamper=tamper)
    _expect_code("P3e-policy-expired",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-witness-layer-invalid")


@probe("P3f-missing-proofs")
def _p3f():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(tmp)

    def tamper(layer):
        del layer["consistency_proof"]
    _attach_layer(bundle_dir, adapter, layer_tamper=tamper)
    _expect_code("P3f-missing-proofs",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-witness-layer-invalid")


@probe("P3g-small-carrier-tampered")
def _p3g():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(tmp, carrier=True)
    report = _verify(bundle_dir, trust_root)
    assert report["verdict"] == "pass", report["verdict"]
    p = os.path.join(bundle_dir, "small_carrier.bin")
    with open(p, "rb") as f:
        blob = f.read()
    bad = blob[:-10] + b"XXXXXXXXXX"
    with open(p, "wb") as f:
        f.write(bad)
    _expect_code("P3g-small-carrier-tampered",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-witness-layer-invalid")


# ---------------------------------------------------------------------------
# P4: the CVE negative rules.
# ---------------------------------------------------------------------------

@probe("P4-cve24122-policy-window")
def _p4():
    # CVE-2026-24122: validity checked at the *timestamp's* time. The
    # policy is valid NOW (future issued_at is accepted as a
    # pre-provisioned successor) but the checkpoint was cosigned BEFORE
    # the policy was issued: it does not cover that checkpoint.
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    doc = _sealed(issued_at=_NOW + 5000, expires_at=_NOW + 90000)
    bundle_dir, trust_root, adapter = _good_package(tmp, policy_doc=doc)
    _expect_code("P4-cve24122-policy-window",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-policy-window")


@probe("P4b-cve22703-transplant")
def _p4b():
    # CVE-2026-22703: bind the log entry to the artifact. A valid
    # witness layer for bundle A, transplanted onto bundle B, must
    # refuse -- never "a valid layer" alone.
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    dir_a, _tr, _ad = _good_package(tmp, name="bundleA",
                                    bundle_id="bundle-A")
    dir_b, trust_b, _ad2 = _good_package(tmp, name="bundleB",
                                         bundle_id="bundle-B")
    layer_a = _read_json(dir_a, "witness_layer.json")
    with open(os.path.join(dir_b, "witness_layer.json"), "w",
              encoding="utf-8") as f:
        f.write(json.dumps(layer_a, sort_keys=True))
    _expect_code("P4b-cve22703-transplant",
                 lambda: _verify(dir_b, trust_b),
                 "offline-verify-bundle-digest-mismatch")


@probe("P4c-cve39395-no-quiet-mode")
def _p4c():
    # CVE-2026-39395: predicate/content checks always on, never opt-in.
    # There is no quiet/existence-only/skip flag: the report is always
    # itemized, and a subtle single-entry forgery still fails LOUD with
    # the coded check (never a bare OK).
    import inspect
    sig = inspect.signature(OV.verify_evidence_bundle)
    for bad in ("quiet", "existence_only", "skip", "check_claims",
                "fast", "lax"):
        assert bad not in sig.parameters, \
            "verifier has opt-out flag %r" % (bad,)
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    log_path, signer = _build_log(tmp)
    adapter = AA.FakeLogAdapter(_SEED_LOG)
    bundle_dir = _export(tmp, "bundle", log_path, signer, adapter)
    p = os.path.join(bundle_dir, "ledger.jsonl")
    with open(p, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    entries[5]["ed_sig"] = "ff" * 64
    with open(p, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(OB._canonical(e).decode("utf-8") + "\n")
    adapter2 = AA.FakeLogAdapter(hashlib.sha256(b"w324-log4").digest())
    _rechain(bundle_dir, adapter2)
    _attach_layer(bundle_dir, adapter2)
    trust_root = _trust_root(adapter2)
    try:
        OV.verify_evidence_bundle(bundle_dir, trust_root, now=_NOW)
    except OV.OfflineVerifyError as exc:
        assert exc.code == "offline-verify-entry-signature-invalid", exc.code
        assert len(exc.checks) >= 7, len(exc.checks)
        assert exc.report["verdict"] == "fail"
        _held("P4c-cve39395-no-quiet-mode",
              "no opt-out flags; forgery fails LOUD with %d itemized "
              "checks" % (len(exc.checks),))
        return
    _break("P4c-cve39395-no-quiet-mode", "forged bundle verified")


@probe("P4d-cve44310-crash-never-succeeds")
def _p4d():
    # CVE-2026-44310: a crash must never produce a success signal.
    # Every malformed input yields a typed OfflineVerifyError -- never
    # an unhandled exception, never a passing report.
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, _adapter = _good_package(tmp)
    bad_inputs = [None, 42, b"{truncated", b"[1,2",
                  json.dumps({"format": "x"}).encode()]
    for i, bad in enumerate(bad_inputs):
        try:
            OV.verify_evidence_bundle(bad, trust_root, now=_NOW)
        except OV.OfflineVerifyError as exc:
            assert exc.code.startswith("offline-verify-"), exc.code
        except Exception as exc:  # noqa: BLE001
            _break("P4d-cve44310-crash-never-succeeds",
                   "input %d escaped as %s" % (i, type(exc).__name__))
            return
        else:
            _break("P4d-cve44310-crash-never-succeeds",
                   "input %d verified" % (i,))
            return
    _held("P4d-cve44310-crash-never-succeeds",
          "all malformed inputs fail typed")


# ---------------------------------------------------------------------------
# P5: package-shape attacks.
# ---------------------------------------------------------------------------

@probe("P5-unknown-package-field")
def _p5():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, _adapter = _good_package(tmp)
    files = {"VERSION": "offline-evidence-bundle/1.0\n"}
    layer = _read_json(bundle_dir, "witness_layer.json")
    pkg = {"format": "sasanam-offline-evidence-package/v1",
           "files": files, "witness_layer": layer, "evil": 1}
    blob = json.dumps(pkg, sort_keys=True).encode("utf-8")
    _expect_code("P5-unknown-package-field",
                 lambda: OV.verify_evidence_bundle(
                     blob, trust_root, now=_NOW),
                 "offline-verify-malformed")


@probe("P5b-version-skew")
def _p5b():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, _adapter = _good_package(tmp)
    pkg = {"format": "sasanam-offline-evidence-package/v2",
           "files": {}, "witness_layer": {}}
    blob = json.dumps(pkg, sort_keys=True).encode("utf-8")
    _expect_code("P5b-version-skew",
                 lambda: OV.verify_evidence_bundle(
                     blob, trust_root, now=_NOW),
                 "offline-verify-version-skew")


@probe("P5c-no-trusted-time")
def _p5c():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, _adapter = _good_package(tmp)
    _expect_code("P5c-no-trusted-time",
                 lambda: OV.verify_evidence_bundle(bundle_dir, trust_root),
                 "offline-verify-malformed")


@probe("P5d-trust-root-incomplete")
def _p5d():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, _adapter = _good_package(tmp)
    bad = {"policy_signers": _anchor_signers(), "policy_threshold": 2}
    _expect_code("P5d-trust-root-incomplete",
                 lambda: _verify(bundle_dir, bad),
                 "offline-verify-trust-root-invalid")


@probe("P5e-missing-witness-layer")
def _p5e():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    log_path, signer = _build_log(tmp)
    adapter = AA.FakeLogAdapter(_SEED_LOG)
    bundle_dir = _export(tmp, "bundle", log_path, signer, adapter)
    _expect_code("P5e-missing-witness-layer",
                 lambda: _verify(bundle_dir, _trust_root(adapter)),
                 "offline-verify-witness-layer-missing")


@probe("P5f-layer-unknown-field")
def _p5f():
    tmp = tempfile.mkdtemp(prefix="w324offver-")
    bundle_dir, trust_root, adapter = _good_package(tmp)

    def tamper(layer):
        layer["evil"] = 1
    _attach_layer(bundle_dir, adapter, layer_tamper=tamper)
    _expect_code("P5f-layer-unknown-field",
                 lambda: _verify(bundle_dir, trust_root),
                 "offline-verify-witness-layer-invalid")


# ---------------------------------------------------------------------------
# P6: pin + footer state.
# ---------------------------------------------------------------------------

@probe("P6-pin-taxonomy-2128-sorted")
def _p6():
    from gov import decision_codes as DC
    n = len(DC.TAXONOMY)
    assert n == TAXONOMY_PIN, "taxonomy %d != pin %d" % (n, TAXONOMY_PIN)
    keys = list(DC.TAXONOMY.keys())
    assert keys == sorted(keys), "taxonomy not sorted"
    assert len(set(keys)) == n, "taxonomy not unique"
    _held("P6-pin-taxonomy-2128-sorted", "%d/%d/0 sorted" % (n, n))


@probe("P6-footer-state")
def _p6b():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as f:
        text = f.read()
    if "Next free finding: **F417**" in text \
            and "**Open findings: F424, F425.**" in text:
        _held("P6-footer-state", "open none / next F417")
    else:
        _break("P6-footer-state", "footer mismatch")


# ---------------------------------------------------------------------------
# Green check (depth-1): adjacent batteries, GOV_SKIP_GREEN honored.
# Child-mode tallies (GOV_SKIP_GREEN=1): probes-only counts.
# ---------------------------------------------------------------------------

GREEN_EVALS = [
    # (short name, rel path, (breaks, held, errors))
    ("w323-exwitness", "evals/w323_exwitness_probes.py", (0, 30, 0)),
    ("w323-monitor", "evals/w323_monitor_probes.py", (0, 24, 0)),
    ("w323-redteam", "evals/w323_redteam_probes.py", (0, 42, 0)),
    ("w322-redteam", "evals/w322_redteam_probes.py", (0, 46, 0)),
]


def _run_green_eval(name, rel, expect):
    import re
    import subprocess
    tmp = tempfile.mkdtemp(prefix="g324offver-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, rel)],
            capture_output=True, text=True, env=env, cwd=REPO,
            timeout=600)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "spawn failed: %s" % (exc,)
    out = proc.stdout + proc.stderr
    m = re.search(r"(\d+)\s+BREAK\s*/\s*(\d+)\s+HELD\s*/\s*(\d+)\s+ERROR",
                  out)
    got = None
    if m:
        got = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    if got == expect:
        return name, "HELD", "%d/%d/%d OK" % got
    return name, "BREAK", "got %s, want %s" % (got, expect)


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-skipped",
                "HELD", "green check skipped (GOV_SKIP_GREEN=1)")
        return
    for name, rel, expect in GREEN_EVALS:
        n, v, note = _run_green_eval(name, rel, expect)
        _record("green-" + n, v, note)


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    probes = [(v.__name__, v) for k, v in globals().items()
              if callable(v) and getattr(v, "__name__", k) != k]
    for pid, fn in sorted(probes):
        if only is not None and pid != only:
            continue
        fn()
    if only is None:
        green_check()
    breaks = errors = 0
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "ERROR":
            errors += 1
    print("w324_offver battery: %d BREAK / %d HELD / %d ERROR "
          % (breaks, len(_results) - breaks - errors, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
