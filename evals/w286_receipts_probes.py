"""Wave-286 lane 7 red-first battery: CCF-pattern inclusion receipts.

Base: wave-285 push 76e0f24. The gap under test is per-artifact offline
inclusion receipts for evidence bundles: the wave-285 tessera lane
anchors bundles and returns anchor receipts, but there is no
RFC-9942-style receipt -- a single self-contained, operator-signed
artifact binding (bundle_digest, log position, tree size, root hash,
inclusion proof) that an auditor can verify OFFLINE, without the
engine, the log store, or any live service. microsoft/CCF (Apache-2.0,
pattern only -- clean-room stdlib Python reimplementation of the
RECEIPT SHAPE and the fork-denunciation rule; no CCF code vendored)
supplies the mechanisms: COSE_Sign1-shaped signed binding over the
inclusion data, witness cosigning policy, and the fork-denunciation
rule (two signed roots at one log position = fork proof).

Red-first: on the pristine base (module absent) every capability probe
BREAKs. After the build, all HELD in staging and under
env -u GOV_DEPLOYMENT_MODE.

$0 spend, synthetic/local, deterministic (secrets only for random
key material, never asserted on). Stdlib only, no in-repo git
subprocesses.
"""

import copy
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w286-receipts")
os.environ.setdefault("TMPDIR", "/var/tmp/g286-receipts")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Wave-286 lane 7: pin 1641 -> 1647 (+6 receipt-* codes).
TAXONOMY_PIN = 2012 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)



_RESULTS = []

PLUGIN_META = ("ccf-receipts", "direct", "held-vs-expected")
PROBE_METADATA = {}

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict,
                     "note": note})
    PROBE_METADATA.setdefault(probe_id, PLUGIN_META)


def _needs_module(probe_id):
    try:
        from gov import evidence_receipt as er
        return er
    except ImportError:
        _record(probe_id, "BREAK", "gov.evidence_receipt absent on base")
        return None


def _literals():
    with open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "gov", "decision_codes.py"),
            encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def _fresh_log(er, tmp):
    from gov import evidence_anchor as ea
    from gov import ed25519
    seed = ed25519.generate_seed()
    root = os.path.join(tmp, "log-%s" % secrets.token_hex(4))
    log = ea.TransparencyLog(root, origin="test-log.example",
                             signer_keyid="op-1", signer_seed=seed)
    pub = ed25519.publickey(bytes(seed))
    return log, pub, root, seed


def _anchor_bundle(er, log, digest=None):
    from gov import evidence_anchor as ea
    if digest is None:
        digest = secrets.token_hex(32)
    ea.anchor(log, digest)
    return digest


# ---------------------------------------------------------------------------
# Capability probes (BREAK on base by missing module; HELD after the build)
# ---------------------------------------------------------------------------

def p_module_present():
    er = _needs_module("module-present")
    if er is None:
        return
    _record("module-present", "HELD", "gov.evidence_receipt importable")


def p_issue_shape():
    er = _needs_module("issue-shape")
    if er is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, _root, seed = _fresh_log(er, tmp)
        digest = _anchor_bundle(er, log)
        rcpt = er.issue_receipt(log, digest, seed)
    try:
        assert rcpt["receipt_format"] == "ccf-inclusion-receipt/1", \
            "format tag"
        for field in ("protected", "payload", "signature", "unprotected"):
            assert field in rcpt, "missing %s" % field
        p = rcpt["payload"]
        for field in ("vds", "origin", "leaf_index", "tree_size",
                      "root", "bundle_digest", "inclusion_path"):
            assert field in p, "payload missing %s" % field
        assert p["bundle_digest"] == digest, "digest bound"
        assert isinstance(rcpt["signature"], str) \
            and len(rcpt["signature"]) == 128, "64-byte hex signature"
    except (AssertionError, KeyError, TypeError) as exc:
        _record("issue-shape", "BREAK", "malformed receipt: %s" % exc)
        return
    _record("issue-shape", "HELD",
            "receipt binds digest+position+size+root+proof")


def p_offline_verify():
    er = _needs_module("offline-verify")
    if er is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, _root, seed = _fresh_log(er, tmp)
        digest = _anchor_bundle(er, log)
        rcpt = er.issue_receipt(log, digest, seed)
        # Offline: the log store is gone; only the operator public key.
        del log
    try:
        ok = er.verify_receipt_offline(rcpt, pub)
    except Exception as exc:  # noqa: BLE001 -- probe must not die
        _record("offline-verify", "BREAK", "raised: %r" % exc)
        return
    if ok is not True:
        _record("offline-verify", "BREAK", "did not return True")
        return
    _record("offline-verify", "HELD",
            "verifies offline with only the operator public key")


def p_tampered_proof_refused():
    er = _needs_module("tampered-proof-refused")
    if er is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, _root, seed = _fresh_log(er, tmp)
        for _ in range(3):
            _anchor_bundle(er, log)
        digest = _anchor_bundle(er, log)
        rcpt = er.issue_receipt(log, digest, seed)
    bad = copy.deepcopy(rcpt)
    path = bad["payload"]["inclusion_path"]
    first = path[0]
    path[0] = ("00" if first[:2] != "00" else "ff") + first[2:]
    try:
        er.verify_receipt_offline(bad, pub)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", "")
        if code == "receipt-signature-invalid":
            _record("tampered-proof-refused", "HELD",
                    "flipped proof byte trips signature (proof is "
                    "inside the signed binding)")
            return
        _record("tampered-proof-refused", "BREAK",
                "wrong code: %r" % code)
        return
    _record("tampered-proof-refused", "BREAK",
            "tampered proof verified -- silent acceptance")


def p_tampered_root_refused():
    er = _needs_module("tampered-root-refused")
    if er is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, _root, seed = _fresh_log(er, tmp)
        digest = _anchor_bundle(er, log)
        rcpt = er.issue_receipt(log, digest, seed)
    bad = copy.deepcopy(rcpt)
    root = bad["payload"]["root"]
    bad["payload"]["root"] = ("00" if root[:2] != "00" else "ff") \
        + root[2:]
    try:
        er.verify_receipt_offline(bad, pub)
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", "") == "receipt-signature-invalid":
            _record("tampered-root-refused", "HELD",
                    "flipped root trips the signature")
            return
        _record("tampered-root-refused", "BREAK",
                "wrong code: %r" % getattr(exc, "code", ""))
        return
    _record("tampered-root-refused", "BREAK",
            "tampered root verified -- silent acceptance")


def p_forged_signature_refused():
    er = _needs_module("forged-signature-refused")
    if er is None:
        return
    from gov import ed25519
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, _root, seed = _fresh_log(er, tmp)
        digest = _anchor_bundle(er, log)
        rcpt = er.issue_receipt(log, digest, seed)
    other_pub = ed25519.publickey(ed25519.generate_seed())
    try:
        er.verify_receipt_offline(rcpt, other_pub)
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", "") == "receipt-signature-invalid":
            _record("forged-signature-refused", "HELD",
                    "wrong operator key refuses signature-invalid")
            return
        _record("forged-signature-refused", "BREAK",
                "wrong code: %r" % getattr(exc, "code", ""))
        return
    _record("forged-signature-refused", "BREAK",
            "receipt verified under the wrong key")


def p_wrong_digest_refused():
    er = _needs_module("wrong-digest-refused")
    if er is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, _root, seed = _fresh_log(er, tmp)
        digest = _anchor_bundle(er, log)
        rcpt = er.issue_receipt(log, digest, seed)
    bad = copy.deepcopy(rcpt)
    bad["payload"]["bundle_digest"] = secrets.token_hex(32)
    try:
        er.verify_receipt_offline(bad, pub)
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", "") == "receipt-signature-invalid":
            _record("wrong-digest-refused", "HELD",
                    "swapped digest trips the signed binding")
            return
        _record("wrong-digest-refused", "BREAK",
                "wrong code: %r" % getattr(exc, "code", ""))
        return
    _record("wrong-digest-refused", "BREAK",
            "receipt accepted for a different bundle digest")


def p_witness_cosign():
    er = _needs_module("witness-cosign")
    if er is None:
        return
    from gov import evidence_anchor as ea
    from gov import ed25519
    from gov import signing
    wit, seeds = {}, {}
    for i in range(3):
        seed = ed25519.generate_seed()
        pub = ed25519.publickey(bytes(seed))
        kid = signing.ed25519_key_id(pub)
        wit[kid] = pub.hex()
        seeds[kid] = seed
    policy = ea.WitnessPolicy(policy_id="wp-1", witnesses=wit, quorum=2)
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, _root, seed = _fresh_log(er, tmp)
        digest = _anchor_bundle(er, log)
        rcpt = er.issue_receipt(log, digest, seed,
                                witness_policy=policy,
                                witness_seeds=seeds)
    try:
        ok = er.verify_receipt_offline(rcpt, pub, witness_policy=policy)
    except Exception as exc:  # noqa: BLE001
        _record("witness-cosign", "BREAK", "raised: %r" % exc)
        return
    if ok is not True:
        _record("witness-cosign", "BREAK", "did not return True")
        return
    # Strip one cosignature: quorum 2 needs both.
    thin = copy.deepcopy(rcpt)
    thin["unprotected"]["witness_signatures"] = \
        thin["unprotected"]["witness_signatures"][:1]
    try:
        er.verify_receipt_offline(thin, pub, witness_policy=policy)
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", "") == "receipt-policy-mismatch":
            _record("witness-cosign", "HELD",
                    "2-of-3 verifies; under-quorum refuses "
                    "policy-mismatch")
            return
        _record("witness-cosign", "BREAK",
                "wrong code: %r" % getattr(exc, "code", ""))
        return
    _record("witness-cosign", "BREAK",
            "under-quorum cosigning verified -- silent acceptance")


def p_fork_denounced():
    er = _needs_module("fork-denounced")
    if er is None:
        return
    # A forking operator: the same operator key signs two tree heads at
    # the SAME log position with DIFFERENT roots (two logs, one key).
    from gov import evidence_anchor as ea
    from gov import ed25519
    seed = ed25519.generate_seed()
    pub = ed25519.publickey(bytes(seed))
    rcpts = []
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(2):
            root = os.path.join(tmp, "forklog-%d" % i)
            log = ea.TransparencyLog(root, origin="test-log.example",
                                     signer_keyid="op-1",
                                     signer_seed=seed)
            digest = secrets.token_hex(32)
            ea.anchor(log, digest)
            rcpts.append(er.issue_receipt(log, digest, seed))
    rcpt_a, rcpt_b = rcpts
    if rcpt_a["payload"]["tree_size"] != rcpt_b["payload"]["tree_size"]:
        _record("fork-denounced", "ERROR",
                "fixture did not produce equal-size heads")
        return
    if rcpt_a["payload"]["root"] == rcpt_b["payload"]["root"]:
        _record("fork-denounced", "ERROR",
                "fixture did not produce diverging roots")
        return
    try:
        proof = er.denounce_fork(rcpt_a, rcpt_b, pub)
    except Exception as exc:  # noqa: BLE001
        _record("fork-denounced", "BREAK", "raised: %r" % exc)
        return
    if not isinstance(proof, dict) or proof.get("fork") is not True:
        _record("fork-denounced", "BREAK", "no fork proven")
        return
    _record("fork-denounced", "HELD",
            "two signed roots at one position -> fork proof")


def p_fork_agreement_clean():
    er = _needs_module("fork-agreement-clean")
    if er is None:
        return
    from gov import evidence_anchor as ea
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, _root, seed = _fresh_log(er, tmp)
        digest = secrets.token_hex(32)
        anchored = ea.anchor(log, digest)
        # Re-binding the same anchor receipt yields two receipts over
        # the identical (index, size, root): the agreement case.
        rcpt_a = er.bind_receipt(anchored, seed)
        rcpt_b = er.bind_receipt(anchored, seed)
    try:
        verdict = er.denounce_fork(rcpt_a, rcpt_b, pub)
    except Exception as exc:  # noqa: BLE001
        _record("fork-agreement-clean", "BREAK", "raised: %r" % exc)
        return
    if isinstance(verdict, dict) and verdict.get("fork") is False:
        _record("fork-agreement-clean", "HELD",
                "agreeing heads -> clean verdict, no fork alleged")
        return
    _record("fork-agreement-clean", "BREAK",
            "agreeing heads misreported: %r" % (verdict,))


def p_envelope_composition():
    er = _needs_module("envelope-composition")
    if er is None:
        return
    from gov import bundle_envelope as be
    from gov import evidence_anchor as ea
    from gov import ed25519
    seed = ed25519.generate_seed()
    pub = ed25519.publickey(bytes(seed))
    xpriv = secrets.token_bytes(32)
    policy = be.make_recipient_policy(
        [{"id": "auditor-1", "type": "offline",
          "x25519_pub": be.x25519_pub(xpriv).hex()}])
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "log-env")
        log = ea.TransparencyLog(root, origin="test-log.example",
                                 signer_keyid="op-1", signer_seed=seed)
        env = be.seal_envelope(b'{"note": "evidence"}', bundle_id="b1",
                               policy=policy, signer_seed=seed)
        rcpt = er.issue_receipt_for_envelope(log, env, seed)
    try:
        ok = er.verify_receipt_offline(rcpt, pub)
    except Exception as exc:  # noqa: BLE001
        _record("envelope-composition", "BREAK", "raised: %r" % exc)
        return
    if ok is not True:
        _record("envelope-composition", "BREAK", "did not return True")
        return
    _record("envelope-composition", "HELD",
            "receipt covers the sealed envelope digest")


def p_taxonomy_pin():
    lits = _literals()
    uniq = sorted(set(lits))
    if len(lits) != TAXONOMY_PIN or len(uniq) != TAXONOMY_PIN \
            or uniq != sorted(lits):
        _record("taxonomy-pin", "BREAK",
                "taxonomy %d raw / %d unique (pin %d)"
                % (len(lits), len(uniq), TAXONOMY_PIN))
        return
    for code in ("inclusion-receipt-malformed",
                 "receipt-signature-invalid",
                 "receipt-inclusion-mismatch", "receipt-leaf-mismatch",
                 "receipt-policy-mismatch", "receipt-fork-detected"):
        if code not in uniq:
            _record("taxonomy-pin", "BREAK",
                    "missing new code %s" % code)
            return
    _record("taxonomy-pin", "HELD",
            "pin %d raw/unique/sorted; 6 receipt-* codes present"
            % TAXONOMY_PIN)


# Regression probes added post-green (spec review): the two refusal
# codes with no red-first coverage. They exercise the public seams
# directly; on the pristine base they would have BREAKed with the
# rest via the missing module.

def p_inclusion_mismatch_signed_bad_proof():
    er = _needs_module("inclusion-mismatch-signed-bad-proof")
    if er is None:
        return
    from gov import evidence_anchor as ea
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, _root, seed = _fresh_log(er, tmp)
        for _ in range(3):
            ea.anchor(log, secrets.token_hex(32))
        anchored = ea.anchor(log, secrets.token_hex(32))
    # The operator genuinely signs a doctored proof: the signature
    # verifies, so the Merkle check must refuse inclusion-mismatch.
    bad = copy.deepcopy(anchored)
    first = bad["inclusion_proof"]["hashes"][0]
    bad["inclusion_proof"]["hashes"][0] = \
        ("00" if first[:2] != "00" else "ff") + first[2:]
    rcpt = er.bind_receipt(bad, seed)
    try:
        er.verify_receipt_offline(rcpt, pub)
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", "") == "receipt-inclusion-mismatch":
            _record("inclusion-mismatch-signed-bad-proof", "HELD",
                    "signed-but-bad proof refuses inclusion-mismatch")
            return
        _record("inclusion-mismatch-signed-bad-proof", "BREAK",
                "wrong code: %r" % getattr(exc, "code", ""))
        return
    _record("inclusion-mismatch-signed-bad-proof", "BREAK",
            "bad proof chained -- silent acceptance")


def p_leaf_mismatch_divergent_store():
    er = _needs_module("leaf-mismatch-divergent-store")
    if er is None:
        return
    from gov import evidence_anchor as ea
    with tempfile.TemporaryDirectory() as tmp:
        log_a, pub_a, _root, seed = _fresh_log(er, tmp)
        root_b = os.path.join(tmp, "log-b")
        log_b = ea.TransparencyLog(root_b, "test-log.example",
                                   "op-1", signer_seed=seed)
        rcpt = er.issue_receipt(log_a, secrets.token_hex(32), seed)
        ea.anchor(log_b, secrets.token_hex(32))  # same size,
        # different leaf at the index
    try:
        er.verify_receipt_offline(rcpt, pub_a, log_root=root_b)
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", "") == "receipt-leaf-mismatch":
            _record("leaf-mismatch-divergent-store", "HELD",
                    "divergent tile store refuses leaf-mismatch")
            return
        _record("leaf-mismatch-divergent-store", "BREAK",
                "wrong code: %r" % getattr(exc, "code", ""))
        return
    _record("leaf-mismatch-divergent-store", "BREAK",
            "divergent store accepted -- silent acceptance")


def p_json_roundtrip():
    er = _needs_module("json-roundtrip")
    if er is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, _root, seed = _fresh_log(er, tmp)
        digest = _anchor_bundle(er, log)
        rcpt = er.issue_receipt(log, digest, seed)
    try:
        blob = er.receipt_to_json(rcpt)
        back = er.receipt_from_json(blob)
        ok = er.verify_receipt_offline(back, pub)
    except Exception as exc:  # noqa: BLE001
        _record("json-roundtrip", "BREAK", "raised: %r" % exc)
        return
    if ok is not True:
        _record("json-roundtrip", "BREAK", "did not return True")
        return
    _record("json-roundtrip", "HELD",
            "receipt survives JSON transport and still verifies")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    for probe in (p_module_present, p_issue_shape, p_offline_verify,
                  p_tampered_proof_refused, p_tampered_root_refused,
                  p_forged_signature_refused, p_wrong_digest_refused,
                  p_witness_cosign, p_fork_denounced,
                  p_fork_agreement_clean, p_envelope_composition,
                  p_taxonomy_pin, p_json_roundtrip,
                  p_inclusion_mismatch_signed_bad_proof,
                  p_leaf_mismatch_divergent_store):
        try:
            probe()
        except Exception as exc:  # noqa: BLE001 -- battery never dies
            _record(probe.__name__, "ERROR", "probe crashed: %r" % exc)
    green_results = []
    if not SKIP_GREEN:
        green_results = _green_checks()
    breaks = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    helds = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    errors = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    print("w286_receipts: %d BREAK / %d HELD / %d ERROR"
          % (breaks, helds, errors))
    for r in _RESULTS:
        if r["verdict"] != "HELD":
            print("  %s %s: %s" % (r["verdict"], r["probe_id"],
                                   r["note"]))
    for g in green_results:
        print("  green %s: %s" % (g["battery"], g["summary"]))
    return 0 if (breaks == 0 and errors == 0) else 1


def _green_checks():
    """Depth-1 green checks: adjacent batteries with GOV_SKIP_GREEN=1."""
    out = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    adj = ["evals/w285_tessera_probes.py"]
    for rel in adj:
        path = os.path.join(repo, rel)
        if not os.path.exists(path):
            out.append({"battery": rel, "summary": "missing, skipped"})
            continue
        d = tempfile.mkdtemp(prefix="g286-green-",
                             dir="/var/tmp")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d))
        except subprocess.TimeoutExpired:
            out.append({"battery": rel, "summary": "TIMEOUT"})
            continue
        tail = (proc.stdout or "").strip().splitlines()
        tail = tail[-1] if tail else "(no output)"
        out.append({"battery": rel,
                    "summary": "rc=%d %s" % (proc.returncode, tail)})
    return out


if __name__ == "__main__":
    sys.exit(main())
