"""Break-first probes for gov/export_witness (wave-323 lane 3).

Red-first: on the open tree this battery dies at import
(ModuleNotFoundError: gov.export_witness). On the lane tree every
attack below must refuse with the coded reason.

Staging default is set at module level (the harness refuses the
declared ungoverned_ack in production mode).
"""

import copy
import hashlib
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


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

from gov import export_witness as EW  # noqa: E402
from gov import witness_policy as WP  # noqa: E402
from gov import witness_log as WL  # noqa: E402
from gov import checkpoint_note as CN  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures (fixed seeds: deterministic keys across runs).
# ---------------------------------------------------------------------------

_SEED_OP = bytes(range(32))
_SEED_W1 = bytes([255 - i for i in range(32)])
_SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
_SEED_W3 = bytes([(i * 13 + 5) % 256 for i in range(32)])
_SEED_P1 = bytes([(i * 3 + 11) % 256 for i in range(32)])
_SEED_P2 = bytes([(i * 5 + 17) % 256 for i in range(32)])
_SEED_P3 = bytes([(i * 11 + 23) % 256 for i in range(32)])

_NOW = 1798765432
_ORIGIN = "sasanam-export-witness-test/v1"
_BUNDLE = b"test-bundle-artifact-bytes"
_BUNDLE_DIGEST = hashlib.sha256(_BUNDLE).hexdigest()
_NLEAF = 8


def _signer(seed):
    return Ed25519Signer(seed)


def _op_vkey():
    s = _signer(_SEED_OP)
    return CN.vkey_string(
        "op", CN.derive_key_id("op", CN.SIG_TYPE_ED25519,
                               s.public_key),
        CN.SIG_TYPE_ED25519, s.public_key)


def _wit_vkey(name, seed):
    # Witness vkeys pin signature type 0x04 (cosignature/v1).
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


def _body(threshold=2, policy_threshold=2):
    p1, p2 = _signer(_SEED_P1), _signer(_SEED_P2)
    return {
        "schema": "witness-policy/v1",
        "policy_id": "sasanam-witness-policy",
        "version": 1,
        "issued_at": _NOW - 1000,
        "expires_at": _NOW + 86400 * 90,
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


def _anchor():
    p1, p2 = _signer(_SEED_P1), _signer(_SEED_P2)
    return {"policy_signers": [{"key_id": s.public_key.hex(),
                                "public_key": s.public_key.hex()}
                               for s in (p1, p2)],
            "policy_threshold": 2}


def _sealed(**kw):
    return WP.seal_policy(_body(**kw),
                          [_signer(_SEED_P1), _signer(_SEED_P2)])


def _leaves(digest=None):
    d = bytes.fromhex(digest or _BUNDLE_DIGEST)
    return [EW.bundle_leaf_hash(d, i) for i in range(_NLEAF)]


def _note(leaves=None, ts=None, witnesses=("w1", "w2"), origin=_ORIGIN,
          op_seed=_SEED_OP):
    leaves = leaves or _leaves()
    root = WL._calc_root(leaves)
    note = CN.emit_checkpoint(origin, len(leaves), root, "op", op_seed)
    seeds = {"w1": _SEED_W1, "w2": _SEED_W2, "w3": _SEED_W3}
    for w in witnesses:
        line = CN.emit_cosignature_line(w, _signer(seeds[w]), origin,
                                        len(leaves), root,
                                        _NOW - 100 if ts is None else ts)
        note += (line + "\n").encode("utf-8")
    return note.decode("utf-8")


def _good_layer(**kw):
    leaves = _leaves()
    doc = _sealed()
    layer = EW.build_witness_layer(
        _BUNDLE_DIGEST, checkpoint=_note(leaves), policy_doc=doc,
        trust_anchor=_anchor(),
        consistency_proof=EW.make_consistency_proof(leaves, 3),
        inclusion_proofs=[EW.make_inclusion_proof(leaves, 0),
                          EW.make_inclusion_proof(leaves, 5)],
        bundle_id="test-bundle-1", now=_NOW, **kw)
    return layer, doc


def _verify(layer, **kw):
    return EW.verify_witness_layer(layer, _anchor(),
                                   bundle_digest=_BUNDLE_DIGEST,
                                   now=_NOW, **kw)


# ---------------------------------------------------------------------------
# P1: the good path verifies.
# ---------------------------------------------------------------------------

@probe("P1-good-layer-verifies")
def _p1():
    layer, _doc = _good_layer()
    out = _verify(layer)
    assert out["bundle_digest"] == _BUNDLE_DIGEST, out
    assert out["witnesses"] == ["w1", "w2"], out
    assert out["quorum_k"] == 2, out
    assert out["policy_version"] == 1, out
    assert out["inclusion"] == [0, 5], out
    assert out["checkpoint"]["size"] == _NLEAF, out
    _held("P1-good-layer-verifies", "good layer verifies offline")


@probe("P1-deterministic-build")
def _p1b():
    a, _ = _good_layer()
    b, _ = _good_layer()
    assert EW.canonical_layer_bytes(a) == EW.canonical_layer_bytes(b), \
        "build not deterministic"
    _held("P1-deterministic-build", "same inputs -> same bytes")


# ---------------------------------------------------------------------------
# P2: transplant / forgery attacks.
# ---------------------------------------------------------------------------

@probe("P2-bundle-transplant-refused")
def _p2a():
    layer, _doc = _good_layer()
    other = hashlib.sha256(b"another-bundle").hexdigest()
    _expect_code("P2-bundle-transplant-refused",
                 lambda: EW.verify_witness_layer(
                     layer, _anchor(), bundle_digest=other, now=_NOW),
                 "export-witness-bundle-mismatch")


@probe("P2-forged-checkpoint-refused")
def _p2b():
    layer, _doc = _good_layer()
    evil = dict(layer)
    # Attacker re-signs a checkpoint for a DIFFERENT tree with their
    # own operator key but keeps the policy: the operator signature
    # will not verify under the policy's log vkey.
    leaves = _leaves(hashlib.sha256(b"evil-tree").hexdigest())
    root = WL._calc_root(leaves)
    evil_note = CN.emit_checkpoint(_ORIGIN, len(leaves), root, "op",
                                   bytes([9] * 32)).decode("utf-8")
    evil_note += (CN.emit_cosignature_line(
        "w1", _signer(_SEED_W1), _ORIGIN, len(leaves), root, _NOW - 100)
        + "\n")
    evil_note += (CN.emit_cosignature_line(
        "w2", _signer(_SEED_W2), _ORIGIN, len(leaves), root, _NOW - 100)
        + "\n")
    evil["checkpoint"] = evil_note
    _expect_code("P2-forged-checkpoint-refused",
                 lambda: _verify(evil), "export-witness-checkpoint-invalid")


@probe("P2-below-threshold-refused")
def _p2c():
    layer, _doc = _good_layer()
    evil = dict(layer)
    evil["checkpoint"] = _note(witnesses=("w1",))  # k=2, only 1 cosigns
    _expect_code("P2-below-threshold-refused",
                 lambda: _verify(evil), "export-witness-checkpoint-invalid")


@probe("P2-policy-doc-swap-refused")
def _p2d():
    layer, _doc = _good_layer()
    evil = dict(layer)
    # Attacker's own policy, sealed by their own signers: the
    # auditor's trust anchor does not authorize them.
    atk_p = _signer(_SEED_P3)
    body = _body()
    evil_doc = WP.seal_policy(body, [atk_p, atk_p])
    evil["policy"] = evil_doc
    _expect_code("P2-policy-doc-swap-refused",
                 lambda: _verify(evil), "export-witness-policy-invalid")


@probe("P2-trust-anchor-swap-refused")
def _p2e():
    layer, _doc = _good_layer()
    atk = {"policy_signers": [{"key_id": _signer(_SEED_P3).public_key.hex(),
                               "public_key":
                               _signer(_SEED_P3).public_key.hex()}],
           "policy_threshold": 1}
    _expect_code("P2-trust-anchor-swap-refused",
                 lambda: EW.verify_witness_layer(
                     layer, atk, bundle_digest=_BUNDLE_DIGEST, now=_NOW),
                 "export-witness-policy-invalid")


@probe("P2-vkey-swap-refused")
def _p2f():
    # Keep the real policy but swap the EMBEDDED vkeys for attacker
    # keys: the embedded copy must equal the verified policy exactly.
    layer, _doc = _good_layer()
    evil = dict(layer)
    atk_vkey = _wit_vkey("w1", _SEED_P3)
    evil_keys = dict(layer["witness_vkeys"])
    evil_keys["w1"] = atk_vkey
    evil["witness_vkeys"] = evil_keys
    _expect_code("P2-vkey-swap-refused",
                 lambda: _verify(evil), "export-witness-vkey-mismatch")


@probe("P2-inclusion-tree-size-mismatch-refused")
def _p2g2():
    # Inclusion proof claiming a different tree size than the
    # checkpoint's: refused even though the path is well-formed.
    layer, _doc = _good_layer()
    evil = dict(layer)
    evil_proofs = [dict(p) for p in layer["inclusion_proofs"]]
    wrong = dict(evil_proofs[0])
    wrong["tree_size"] = _NLEAF + 8
    evil_proofs[0] = wrong
    evil["inclusion_proofs"] = evil_proofs
    _expect_code("P2-inclusion-tree-size-mismatch-refused",
                 lambda: _verify(evil), "export-witness-proof-mismatch")


@probe("P2-proof-bundle-mismatch-refused")
def _p2g():
    # Inclusion proof transplanted from another bundle's layer: the
    # derived leaf hash will not fold to this checkpoint's root.
    layer, _doc = _good_layer()
    other_leaves = _leaves(hashlib.sha256(b"other-bundle").hexdigest())
    evil = dict(layer)
    evil_proofs = [dict(p) for p in layer["inclusion_proofs"]]
    evil_proofs[0] = EW.make_inclusion_proof(other_leaves, 0)
    evil["inclusion_proofs"] = evil_proofs
    _expect_code("P2-proof-bundle-mismatch-refused",
                 lambda: _verify(evil), "export-witness-proof-mismatch")


@probe("P2-consistency-proof-tamper-refused")
def _p2h():
    layer, _doc = _good_layer()
    evil = dict(layer)
    cp = copy.deepcopy(layer["consistency_proof"])
    cp["from_root"] = "00" * 32
    evil["consistency_proof"] = cp
    _expect_code("P2-consistency-proof-tamper-refused",
                 lambda: _verify(evil), "export-witness-proof-mismatch")


@probe("P2-stale-checkpoint-refused")
def _p2i():
    layer, _doc = _good_layer()
    evil = dict(layer)
    # Cosignatures older than max_checkpoint_staleness_seconds (10800).
    evil["checkpoint"] = _note(ts=_NOW - 20000)
    _expect_code("P2-stale-checkpoint-refused",
                 lambda: _verify(evil), "export-witness-stale")


@probe("P2-name-collision-freshness-bypass-refused")
def _p2k():
    # Keyless staleness bypass: the checkpoint's real cosignatures
    # are stale, and the attacker appends a line with a verified
    # witness's NAME but a non-matching key id and a fresh timestamp.
    # require_cosignatures ignores the unknown line (signed-note
    # collision rules), and the freshness check must ignore it too --
    # timestamps come only from (name, key_id)-verified lines.
    import base64 as _b64
    layer, _doc = _good_layer()
    evil = dict(layer)
    stale_note = _note(ts=_NOW - 20000)
    forged = "— w1 " + _b64.b64encode(
        b"\xde\xad\xbe\xef" + (_NOW).to_bytes(8, "big") + b"\x00" * 64
    ).decode("ascii") + "\n"
    evil["checkpoint"] = stale_note + forged
    _expect_code("P2-name-collision-freshness-bypass-refused",
                 lambda: _verify(evil), "export-witness-stale")


@probe("P2-future-cosignature-refused")
def _p2j():
    layer, _doc = _good_layer()
    evil = dict(layer)
    evil["checkpoint"] = _note(ts=_NOW + 3600)
    _expect_code("P2-future-cosignature-refused",
                 lambda: _verify(evil), "export-witness-stale")


# ---------------------------------------------------------------------------
# P3: shape attacks.
# ---------------------------------------------------------------------------

@probe("P3-malformed-layer-refused")
def _p3a():
    _expect_code("P3-malformed-layer-refused",
                 lambda: _verify({"format": EW.LAYER_FORMAT}),
                 "export-witness-malformed")


@probe("P3-unknown-field-refused")
def _p3b():
    layer, _doc = _good_layer()
    evil = dict(layer)
    evil["smuggled"] = "x"
    _expect_code("P3-unknown-field-refused",
                 lambda: _verify(evil), "export-witness-malformed")


@probe("P3-unknown-proof-field-refused")
def _p3c():
    layer, _doc = _good_layer()
    evil = dict(layer)
    cp = dict(layer["consistency_proof"])
    cp["extra"] = 1
    evil["consistency_proof"] = cp
    _expect_code("P3-unknown-proof-field-refused",
                 lambda: _verify(evil), "export-witness-malformed")


@probe("P3-bad-digest-shape-refused")
def _p3d():
    layer, _doc = _good_layer()
    evil = dict(layer)
    evil["bundle_digest"] = "not-hex"
    _expect_code("P3-bad-digest-shape-refused",
                 lambda: _verify(evil), "export-witness-malformed")


@probe("P3-no-now-fails-closed")
def _p3e():
    layer, _doc = _good_layer()
    _expect_code("P3-no-now-fails-closed",
                 lambda: EW.verify_witness_layer(
                     layer, _anchor(), bundle_digest=_BUNDLE_DIGEST,
                     now=None),
                 "export-witness-malformed")


# ---------------------------------------------------------------------------
# P4: small carrier.
# ---------------------------------------------------------------------------

@probe("P4-carrier-roundtrip")
def _p4a():
    layer, _doc = _good_layer()
    blob = EW.encode_small_carrier(layer, exported_at=_NOW - 50)
    assert len(blob) < EW.SMALL_CARRIER_MAX_BYTES, len(blob)
    out = EW.decode_small_carrier(blob, _doc, _anchor(), now=_NOW)
    assert out["policy_version"] == 1, out
    assert out["checkpoint"]["size"] == _NLEAF, out
    assert out["witnesses"] == ["w1", "w2"], out
    _held("P4-carrier-roundtrip",
          "carrier %d bytes < budget %d" % (len(blob),
                                            EW.SMALL_CARRIER_MAX_BYTES))


@probe("P4-carrier-oversize-refused")
def _p4b():
    layer, _doc = _good_layer()
    # A checkpoint with a huge cosigner set cannot ride the QR.
    many = ["w%d" % i for i in range(60)]
    leaves = _leaves()
    root = WL._calc_root(leaves)
    note = CN.emit_checkpoint(_ORIGIN, len(leaves), root, "op", _SEED_OP)
    for i, w in enumerate(many):
        seed = bytes([(i * 31 + 7) % 256 for _ in range(32)])
        line = CN.emit_cosignature_line(w, _signer(seed), _ORIGIN,
                                        len(leaves), root, _NOW - 100)
        note += (line + "\n").encode("utf-8")
    big = dict(layer)
    big["checkpoint"] = note.decode("utf-8")
    _expect_code("P4-carrier-oversize-refused",
                 lambda: EW.encode_small_carrier(big, exported_at=_NOW),
                 "export-witness-carrier-oversize")


@probe("P4-carrier-forged-checkpoint-refused")
def _p4c():
    layer, _doc = _good_layer()
    blob = EW.encode_small_carrier(layer, exported_at=_NOW - 50)
    obj = json.loads(blob.decode("utf-8"))
    # Flip the tree size inside the carried checkpoint: the operator
    # signature no longer verifies.
    obj["checkpoint"] = obj["checkpoint"].replace(
        "\n8\n", "\n9\n", 1)
    tampered = json.dumps(obj, sort_keys=True, ensure_ascii=True,
                           separators=(",", ":")).encode("utf-8")
    _expect_code("P4-carrier-forged-checkpoint-refused",
                 lambda: EW.decode_small_carrier(
                     tampered, _doc, _anchor(), now=_NOW),
                 "export-witness-checkpoint-invalid")


@probe("P4-carrier-stale-policy-refused")
def _p4d():
    layer, _doc = _good_layer()
    blob = EW.encode_small_carrier(layer, exported_at=_NOW - 50)
    obj = json.loads(blob.decode("utf-8"))
    obj["freshness"]["policy_version"] = 99  # not the verified policy
    tampered = json.dumps(obj, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":")).encode("utf-8")
    _expect_code("P4-carrier-stale-policy-refused",
                 lambda: EW.decode_small_carrier(
                     tampered, _doc, _anchor(), now=_NOW),
                 "export-witness-malformed")


@probe("P4-carrier-future-export-refused")
def _p4e():
    layer, _doc = _good_layer()
    blob = EW.encode_small_carrier(layer, exported_at=_NOW + 3600)
    _expect_code("P4-carrier-future-export-refused",
                 lambda: EW.decode_small_carrier(
                     blob, _doc, _anchor(), now=_NOW),
                 "export-witness-stale")


@probe("P4-carrier-no-now-fails-closed")
def _p4f():
    layer, _doc = _good_layer()
    blob = EW.encode_small_carrier(layer, exported_at=_NOW - 50)
    _expect_code("P4-carrier-no-now-fails-closed",
                 lambda: EW.decode_small_carrier(
                     blob, _doc, _anchor(), now=None),
                 "export-witness-malformed")


# ---------------------------------------------------------------------------
# P5: build-time fail-closed.
# ---------------------------------------------------------------------------

@probe("P5-build-rejects-unverifiable-policy")
def _p5a():
    leaves = _leaves()
    atk_p = _signer(_SEED_P3)
    bad_doc = WP.seal_policy(_body(), [atk_p, atk_p])
    _expect_code("P5-build-rejects-unverifiable-policy",
                 lambda: EW.build_witness_layer(
                     _BUNDLE_DIGEST, checkpoint=_note(leaves),
                     policy_doc=bad_doc, trust_anchor=_anchor(),
                     consistency_proof=EW.make_consistency_proof(
                         leaves, 3),
                     inclusion_proofs=[], now=_NOW),
                 "export-witness-policy-invalid")


@probe("P5-build-rejects-unparseable-checkpoint")
def _p5b():
    leaves = _leaves()
    _expect_code("P5-build-rejects-unparseable-checkpoint",
                 lambda: EW.build_witness_layer(
                     _BUNDLE_DIGEST, checkpoint="not a checkpoint",
                     policy_doc=_sealed(), trust_anchor=_anchor(),
                     consistency_proof=EW.make_consistency_proof(
                         leaves, 3),
                     inclusion_proofs=[], now=_NOW),
                 "export-witness-malformed")


# ---------------------------------------------------------------------------
# P6: pin + footer state.
# ---------------------------------------------------------------------------

@probe("P6-pin-taxonomy-2140-sorted")


def _p6a():
    from gov import decision_codes as DC
    n = len(DC.TAXONOMY)
    codes = sorted(DC.TAXONOMY.keys())
    if n == TAXONOMY_PIN and list(DC.TAXONOMY.keys()) == codes:
        _held("P6-pin-taxonomy-2140-sorted", "2140/2140/0 sorted")
    else:
        _break("P6-pin-taxonomy-2140-sorted",
               "want 2140/2121/00 sorted, got %d (sorted=%s)"


               % (n, list(DC.TAXONOMY.keys()) == codes))


@probe("P6-footer-state")
def _p6b():
    src = open(os.path.join(REPO, "evals", "FINDINGS.md")).read()
    # Wave-336 lane 1: repaired stale F412/F413-era assertions.
    if ("Next free finding: **F672**" in src  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640  # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
            and "Open findings: F662, F663, F664, F665, F666, F667, F668, F669, F670, F671." in src):  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640  # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
        _held("P6-footer-state", "open none / next F430")
    else:
        _break("P6-footer-state", "footer mismatch")


# ---------------------------------------------------------------------------
# Green check (depth-1): adjacent batteries, GOV_SKIP_GREEN honored.
# Child-mode tallies (GOV_SKIP_GREEN=1): probes-only counts.
# ---------------------------------------------------------------------------

GREEN_EVALS = [
    # (short name, rel path, (breaks, held, errors))
    ("w322-witpol", "evals/w322_witpol_probes.py", (0, 24, 0)),
    ("w322-witpub", "evals/w322_witpub_probes.py", (0, 21, 0)),
    ("w322-redteam", "evals/w322_redteam_probes.py", (0, 46, 0)),
    ("w321-oci", "evals/w321_oci_probes.py", (0, 9, 0)),
]


def _run_green_eval(name, rel, expect):
    import re
    import subprocess
    import tempfile
    tmp = tempfile.mkdtemp(prefix="g323exw-")
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
    print("w323_exwitness battery: %d BREAK / %d HELD / %d ERROR "
          % (breaks, len(_results) - breaks - errors, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
