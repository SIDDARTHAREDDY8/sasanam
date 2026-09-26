#!/usr/bin/env python3
"""Normative tamper battery for evidence bundles (spec docs/evidence-bundle-spec.md §5: T1–T10).

Each §5 scenario gets a dedicated tamper case asserting the exact
expected exit code and the exact check that must fail, PLUS a fresh
untampered positive control. The four §5 benign controls are explicit
cases (C1–C4).

Deterministic, hermetic, $0: fixed synthetic keys (no RNG), no sleeps,
no network. Each probe builds a fresh bundle from a synthetic log in
its own temp dir (one log per directory — gov/log.py keeps the
checkpoint sidecar per parent dir), applies exactly one tamper (or
none, for controls), and runs the REAL standalone verifier
(tools/evidence-verify) as a subprocess — no repo on sys.path for the
verifier process.

Verdicts: CAUGHT (tamper stopped: expected exit + expected check named)
/ MISS (tamper not caught — the bad outcome) / CONTROL (positive or
benign behavior must keep holding) / ERROR (harness failure).

Probes (normative §5):
  T1  flip one byte in a log_slice.jsonl payload  -> V9 fail, exit 1
  T2  drop one slice entry                         -> V9 (+V10) fail, exit 1
  T3  swap two adjacent slice entries              -> V9 fail, exit 1
  T4a delete the manifest signing envelope         -> V7 fail, exit 1
  T4b corrupt the operator pubkey in its envelope  -> V5/V7 fail, exit 1
  T4c set signing scheme to "none"                 -> V7 fail, exit 1, never VERIFIED
  T5  swap operator key for an attacker key + re-sign -> V6 fail (genuine pin), exit 1
  T6  inflate an approval count in evidence.json   -> V4 fail, exit 1
  T7  forged checkpoint head binding a mutated slice -> V8 (Ed25519) fail, exit 1
  T8a cut the slice tail                           -> V9+V10 fail, exit 1
  T8b detach the receipt from the window tip       -> V12 fail, exit 1
  T8c coherent truncation (window re-declared [1,4],
      receipt still bound to old tip)              -> V12+V10 fail, exit 1
  T9  attacker self-sealed bundle, unpinned        -> exit 2 SELF_CONSISTENT, never exit 0
  T10 substitute another policy into evidence.json
      (white-box re-sign to isolate V11)           -> V11 fail, exit 1
  C1  genuine bundle + genuine pin                 -> exit 0 VERIFIED
  C2  genuine bundle, no pin                       -> exit 2 SELF_CONSISTENT, authorship NOT established
  C3  HMAC-only-checkpoint log bundle              -> exit 0 with explicit reduced coverage
  C4  bundle with no sealed SAR                     -> exit 0, benchmark stays "unsealed"
  C5  genuine bundle, policy_loaded w/o policy_version (F172) -> exit 0

White-box notes (documented, not hidden): T5 re-signs with the
attacker's key and T10 re-signs with the operator's key because the
battery holds the test keys. A keyless attacker cannot reach V6's
pin comparison past a valid signature, nor V11 past V4 — the re-sign
isolates the check logic under test (the pin comparison itself; the
payload-vs-log policy comparison itself). T9 needs no re-sign: the
attacker genuinely self-seals with their own key.

Exit 0 iff every tamper is CAUGHT and every control holds.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from importlib.machinery import SourceFileLoader

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Fixed synthetic HMAC key: the battery must be deterministic (no RNG).
os.environ.setdefault("GOV_LOG_KEY", "eb" * 32)
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "evidence-tamper-battery")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov.log import ActionLog  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402
from gov.evidence_bundle import (  # noqa: E402
    EvidenceBundle, canonical, log_evidence_bundle_receipt)
from gov.safeguard_bundle import compute_bundle_digest  # noqa: E402

VERIFY_SCRIPT = os.path.join(REPO_ROOT, "tools", "evidence-verify")

# Fixed synthetic Ed25519 identities (deterministic, never real keys).
OPERATOR = Ed25519Signer(bytes.fromhex("11" * 32))
ATTACKER = Ed25519Signer(bytes.fromhex("aa" * 32))

# The verifier's own Merkle helpers, for forging a checkpoint head that
# binds a mutated slice (T7). Loading the module does not run it.
_EVV = SourceFileLoader("evidence_verify_mod", VERIFY_SCRIPT).load_module()

EXPORTED_AT = "2026-09-26T00:00:00+00:00"

# Every fixture lives in its own mkdtemp dir; remove them all at exit so
# repeated runs don't litter $TMPDIR.
_TMP_DIRS = []


def _cleanup_tmp_dirs():
    for d in _TMP_DIRS:
        shutil.rmtree(d, ignore_errors=True)


import atexit  # noqa: E402
atexit.register(_cleanup_tmp_dirs)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

def _build_log(path, signer, *, hmac_only=False, unversioned_policy=False):
    """Synthetic 5-entry log: policy_loaded, approval_decision, 3 tool_calls."""
    log = ActionLog(path, signer=None if hmac_only else signer,
                    deployment_mode="staging")
    policy_ev = {"event": "policy_loaded",
                 "policy_hash": "h" * 16,
                 "policy_path": "policies/p1.yaml",
                 "pinned": True}
    if not unversioned_policy:
        policy_ev["policy_version"] = "1.0"
    log.append(policy_ev)
    log.append({"event": "approval_decision", "decision": "approve",
                "ticket": "T-42"})
    for i in range(3):
        log.append({"event": "tool_call", "decision": "allow",
                    "tool": "tool-%d" % i})
    return log


def _assemble(tag, signer, *, hmac_only=False, unversioned_policy=False,
              attacker_log=False):
    """Build a genuine bundle in its own temp dir. Returns a fixture dict."""
    tmp = tempfile.mkdtemp(prefix="ebt-%s-" % tag)
    _TMP_DIRS.append(tmp)
    log_path = os.path.join(tmp, "audit.log")
    use_signer = ATTACKER if attacker_log else signer
    _build_log(log_path, use_signer, hmac_only=hmac_only,
               unversioned_policy=unversioned_policy)
    eb = EvidenceBundle(log_path, exported_at=EXPORTED_AT,
                        operator_id="battery-%s" % tag)
    payload = eb.build()
    manifest = eb.seal(payload, signer=use_signer)
    log_evidence_bundle_receipt(
        manifest,
        ActionLog(log_path,
                  signer=None if hmac_only else use_signer,
                  deployment_mode="staging"),
        signer=use_signer)
    key = use_signer
    op = {"key_id": key.key_id, "public_key_hex": key.public_key.hex()}
    out = os.path.join(tmp, "bundle")
    eb.assemble(payload, manifest, operator_key=op,
                checkpoint_keys=[dict(op)], out_dir=out)
    return {"tmp": tmp, "dir": out, "signer": use_signer,
            "payload": payload, "manifest": manifest}


def _run(bundle_dir, *args):
    """Run the REAL standalone verifier as a subprocess."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, VERIFY_SCRIPT, bundle_dir] + list(args),
        capture_output=True, text=True, env=env, cwd="/tmp")
    return proc.returncode, proc.stdout, proc.stderr


def _pin_args(signer=OPERATOR):
    return ["--pin-operator-pubkey", signer.public_key.hex()]


def _redigest(bundle_dir):
    with open(os.path.join(bundle_dir, "BUNDLE_DIGEST.sha256"), "w") as f:
        f.write(compute_bundle_digest(bundle_dir) + "\n")


def _rewrite(bundle_dir, rel, obj):
    """Rewrite a JSON bundle file (canonical bytes + newline)."""
    with open(os.path.join(bundle_dir, rel), "wb") as f:
        f.write(canonical(obj) + b"\n")


def _read_json(bundle_dir, rel):
    with open(os.path.join(bundle_dir, rel), "r", encoding="utf-8") as f:
        return json.load(f)


def _read_slice(bundle_dir):
    with open(os.path.join(bundle_dir, "log_slice.jsonl"),
              encoding="utf-8") as f:
        return [line for line in f.read().splitlines() if line.strip()]


def _write_slice(bundle_dir, lines):
    with open(os.path.join(bundle_dir, "log_slice.jsonl"), "w",
              encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Assertion helper
# ---------------------------------------------------------------------------

def _expect(code, stdout, *, exit_code, fail_ids=(), pass_ids=(),
            text=(), not_text=()):
    """Return a list of problems (empty == expectations met)."""
    problems = []
    if code != exit_code:
        problems.append("exit %d != expected %d" % (code, exit_code))
    for fid in fail_ids:
        if ("[FAIL] " + fid) not in stdout:
            problems.append("expected [FAIL] %s not in output" % fid)
    for pid in pass_ids:
        if ("[PASS] " + pid) not in stdout:
            problems.append("expected [PASS] %s not in output" % pid)
    for t in text:
        if t not in stdout:
            problems.append("expected text %r not in output" % t)
    for t in not_text:
        if t in stdout:
            problems.append("forbidden text %r found in output" % t)
    return problems


def _expect_any_fail(code, stdout, *, exit_code, fail_ids, **kw):
    """Like _expect, but at least one of fail_ids must be [FAIL]."""
    problems = _expect(code, stdout, exit_code=exit_code, **kw)
    if not any(("[FAIL] " + fid) in stdout for fid in fail_ids):
        problems.append("expected one of [FAIL] %s not in output"
                        % ("/".join(fail_ids),))
    return problems


# ---------------------------------------------------------------------------
# Benign controls (spec §5)
# ---------------------------------------------------------------------------

def _control(tag):
    """Fresh untampered bundle + genuine pin: must exit 0 VERIFIED.

    The normative §5 requires one fresh positive control per tamper
    scenario; they all assert the same thing through this one path so a
    copy-paste drift between controls cannot silently weaken one.
    """
    fx = _assemble(tag, OPERATOR)
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=0, text=("verdict: VERIFIED",))

def c1_genuine_pinned():
    fx = _assemble("c1", OPERATOR)
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=0, text=("verdict: VERIFIED",))


def c2_genuine_unpinned():
    fx = _assemble("c2", OPERATOR)
    code, out, _ = _run(fx["dir"])
    return _expect(code, out, exit_code=2,
                   text=("SELF_CONSISTENT", "NOT established"),
                   not_text=("verdict: VERIFIED",))


def c3_hmac_only_checkpoints():
    fx = _assemble("c3", OPERATOR, hmac_only=True)
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=0,
                   text=("verdict: VERIFIED", "reduced-coverage"))


def c4_sar_unsealed():
    fx = _assemble("c4", OPERATOR)
    problems = []
    seal_status = ((fx["payload"].get("benchmark") or {})
                   .get("seal_status"))
    if seal_status != "unsealed":
        problems.append("benchmark seal_status %r != 'unsealed'" % seal_status)
    code, out, _ = _run(fx["dir"], *_pin_args())
    problems.extend(_expect(code, out, exit_code=0,
                            text=("verdict: VERIFIED",)))
    return problems


def c5_unversioned_policy():
    """F172: policy_loaded without a policy_version field must verify."""
    fx = _assemble("c5", OPERATOR, unversioned_policy=True)
    problems = []
    pv = ((fx["payload"].get("policy") or {}).get("policy_version") or {})
    if pv.get("value") != "unversioned":
        problems.append("payload policy_version %r != 'unversioned'"
                        % (pv.get("value"),))
    code, out, _ = _run(fx["dir"], *_pin_args())
    problems.extend(_expect(code, out, exit_code=0,
                            text=("verdict: VERIFIED",)))
    return problems


# ---------------------------------------------------------------------------
# T1: log edit — flip one byte in a log_slice.jsonl payload
# ---------------------------------------------------------------------------

def t1_log_edit():
    fx = _assemble("t1", OPERATOR)
    lines = _read_slice(fx["dir"])
    # seq 4 is tool_call "tool-1": flip one payload byte inside a string.
    entry = json.loads(lines[3])
    assert entry["seq"] == 4 and entry["tool"] == "tool-1", entry
    entry["tool"] = "tool-X"
    lines[3] = canonical(entry).decode("utf-8")
    _write_slice(fx["dir"], lines)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    # The inclusion leaf changed: V9 must fail (V8's root recomputation
    # also fails — both are correct, V9 is the normative one).
    return _expect(code, out, exit_code=1, fail_ids=("V9",))


def t1_control():
    return _control("t1c")


# ---------------------------------------------------------------------------
# T2: record drop — remove one slice entry
# ---------------------------------------------------------------------------

def t2_record_drop():
    fx = _assemble("t2", OPERATOR)
    lines = _read_slice(fx["dir"])
    assert json.loads(lines[1])["seq"] == 2
    del lines[1]  # drop the approval_decision record (seq 2)
    _write_slice(fx["dir"], lines)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=1, fail_ids=("V9", "V10"))


def t2_control():
    return _control("t2c")


# ---------------------------------------------------------------------------
# T3: reorder — swap two adjacent slice entries
# ---------------------------------------------------------------------------

def t3_reorder():
    fx = _assemble("t3", OPERATOR)
    lines = _read_slice(fx["dir"])
    assert json.loads(lines[2])["seq"] == 3
    assert json.loads(lines[3])["seq"] == 4
    lines[2], lines[3] = lines[3], lines[2]
    _write_slice(fx["dir"], lines)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=1, fail_ids=("V9",))


def t3_control():
    return _control("t3c")


# ---------------------------------------------------------------------------
# T4: signature strip — delete signing / corrupt pubkey / scheme none
# ---------------------------------------------------------------------------

def t4a_signing_deleted():
    fx = _assemble("t4a", OPERATOR)
    manifest = _read_json(fx["dir"], "manifest.json")
    del manifest["signing"]
    _rewrite(fx["dir"], "manifest.json", manifest)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=1, fail_ids=("V7",))


def t4b_operator_pubkey_corrupted():
    fx = _assemble("t4b", OPERATOR)
    env = _read_json(fx["dir"], "keys/operator_ed25519.json")
    pub = env["public_key_hex"]
    # Flip one hex digit of the 32-byte pubkey (key_id no longer matches).
    env["public_key_hex"] = ("f" if pub[0] != "f" else "e") + pub[1:]
    _rewrite(fx["dir"], "keys/operator_ed25519.json", env)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    # The corrupted envelope may trip V5 (key_id mismatch) or V7
    # (signature no longer verifies) first; either is a fail-closed stop.
    return _expect_any_fail(code, out, exit_code=1, fail_ids=("V5", "V7"))


def t4c_scheme_none():
    fx = _assemble("t4c", OPERATOR)
    manifest = _read_json(fx["dir"], "manifest.json")
    manifest["signing"]["scheme"] = "none"
    _rewrite(fx["dir"], "manifest.json", manifest)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    # scheme: none must never produce VERIFIED. Spec tension (documented,
    # not redefined): §4.3's exit-2 paragraph lists scheme:"none" as a
    # SELF_CONSISTENT case, but §5 T4 says V5/V7 fail closed — the battery
    # follows the normative §5 (fail-closed, exit 1).
    return _expect(code, out, exit_code=1, fail_ids=("V7",),
                   not_text=("verdict: VERIFIED",))


def t4_control():
    return _control("t4c0")


# ---------------------------------------------------------------------------
# T5: key swap — attacker operator key + re-sign (white-box: battery holds
# the test keys; isolates V6's pin comparison past a valid signature)
# ---------------------------------------------------------------------------

def t5_key_swap():
    fx = _assemble("t5", OPERATOR)
    manifest = _read_json(fx["dir"], "manifest.json")
    manifest["signing"]["key_id"] = ATTACKER.key_id
    manifest["signing"]["sig"] = ATTACKER.sign(
        EvidenceBundle.signed_body(manifest)).hex()
    _rewrite(fx["dir"], "manifest.json", manifest)
    _rewrite(fx["dir"], "keys/operator_ed25519.json",
             {"key_id": ATTACKER.key_id,
              "public_key_hex": ATTACKER.public_key.hex()})
    _redigest(fx["dir"])
    # Genuine pin against the attacker bundle: V6 must fail.
    code, out, _ = _run(fx["dir"], *_pin_args(OPERATOR))
    problems = _expect(code, out, exit_code=1, fail_ids=("V6",))
    # And the attacker bundle pinned to the ATTACKER key is the
    # attacker's bundle, not the operator's — it must NOT verify as the
    # operator's either (V6 fails against the genuine pin, shown above).
    return problems


def t5_control():
    # Genuine bundle plus genuine pin exits 0.
    return _control("t5c")


# ---------------------------------------------------------------------------
# T6: payload digest tamper — inflate an approval count in evidence.json
# ---------------------------------------------------------------------------

def t6_payload_digest_tamper():
    fx = _assemble("t6", OPERATOR)
    payload = _read_json(fx["dir"], "evidence.json")
    recs = payload["approvals"]["approval_decision"]
    assert len(recs) == 1, recs
    # Inflate the approval count: duplicate the approval record.
    recs.append(dict(recs[0]))
    _rewrite(fx["dir"], "evidence.json", payload)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=1, fail_ids=("V4",))


def t6_control():
    return _control("t6c")


# ---------------------------------------------------------------------------
# T7: checkpoint forgery — forged head binding a mutated slice.
# The forged head's Merkle root correctly recomputes over the MUTATED
# slice (via the verifier's own helpers); only the Ed25519 signature is
# forged (garbage — the forger has no key). V8 must fail closed on the
# signature.
# ---------------------------------------------------------------------------

def t7_checkpoint_forgery():
    fx = _assemble("t7", OPERATOR)
    # 1. Mutate one slice entry payload byte.
    lines = _read_slice(fx["dir"])
    entry = json.loads(lines[3])
    assert entry["seq"] == 4 and entry["tool"] == "tool-1", entry
    entry["tool"] = "tool-X"
    lines[3] = canonical(entry).decode("utf-8")
    _write_slice(fx["dir"], lines)
    # 2. Forge the head: root over the MUTATED slice, forged signature.
    entries = [json.loads(line) for line in lines]
    leaves = [_EVV._mk_leaf_hash(_EVV._leaf_input(e)) for e in entries]
    forged_root = _EVV._recompute_root(leaves)
    heads = [json.loads(line) for line in
             open(os.path.join(fx["dir"], "checkpoints.jsonl"),
                  encoding="utf-8").read().splitlines() if line.strip()]
    assert len(heads) == 1, heads
    forged = dict(heads[0])
    forged["merkle_root"] = forged_root
    forged["sigs"] = [{"key_id": OPERATOR.key_id, "sig": "00" * 64}]
    with open(os.path.join(fx["dir"], "checkpoints.jsonl"), "w",
              encoding="utf-8") as f:
        f.write(canonical(forged).decode("utf-8") + "\n")
    manifest = _read_json(fx["dir"], "manifest.json")
    manifest["checkpoints"] = [forged]
    manifest["checkpoints_digest"] = hashlib.sha256(
        canonical([forged])).hexdigest()
    _rewrite(fx["dir"], "manifest.json", manifest)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    problems = _expect(code, out, exit_code=1, fail_ids=("V8",),
                       text=("signature does NOT verify",))
    return problems


def t7_control():
    return _control("t7c")


# ---------------------------------------------------------------------------
# T8: truncation / window shift
# ---------------------------------------------------------------------------

def t8a_slice_tail_cut():
    fx = _assemble("t8a", OPERATOR)
    lines = _read_slice(fx["dir"])
    assert json.loads(lines[-1])["seq"] == 5
    del lines[-1]  # cut the tail; manifest window still [1,5]
    _write_slice(fx["dir"], lines)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=1, fail_ids=("V9", "V10"))


def t8b_receipt_detached():
    fx = _assemble("t8b", OPERATOR)
    receipt = _read_json(fx["dir"], "receipt.json")
    prev = receipt["entry"]["prev_hash"]
    # Detach the receipt from the window tip.
    receipt["entry"]["prev_hash"] = (
        "f" if prev[0] != "f" else "e") + prev[1:]
    _rewrite(fx["dir"], "receipt.json", receipt)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=1, fail_ids=("V12",),
                   text=("does not chain onto",))


def t8c_window_shift_coherent():
    """Spec §5 T8, second shape: coherent truncation.

    The attacker cuts the slice tail AND re-declares the window to match
    ([1,4], re-signed white-box so V7 passes), presenting the truncated
    bundle as complete. The honestly-generated receipt still binds the
    old tip, and the payload sections still reference seq 5 — so V12
    (receipt prev_hash != re-declared tip) and V10 (inclusion coverage
    inconsistent; section seq refs outside [from_seq, to_seq]) must fail.
    """
    fx = _assemble("t8c", OPERATOR)
    lines = _read_slice(fx["dir"])
    assert json.loads(lines[-1])["seq"] == 5
    del lines[-1]  # cut the tail
    _write_slice(fx["dir"], lines)
    new_tip = json.loads(lines[-1])["hash"]  # seq 4's chained hash
    manifest = _read_json(fx["dir"], "manifest.json")
    manifest["window"]["to_seq"] = 4
    manifest["window"]["tip_hash"] = new_tip
    manifest["window"]["entry_count"] = 4
    # Deliberately NOT updating inclusion_coverage.entries (5) or the
    # payload's 5-entry coverage: that staleness is the V10 signal.
    # The receipt still binds the old seq-5 tip: the V12 signal.
    manifest["signing"]["sig"] = OPERATOR.sign(
        EvidenceBundle.signed_body(manifest)).hex()
    _rewrite(fx["dir"], "manifest.json", manifest)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=1, fail_ids=("V12", "V10"),
                   text=("does not chain onto",))


def t8_control():
    return _control("t8c0")


# ---------------------------------------------------------------------------
# T9: authorship confusion — attacker self-sealed bundle, unpinned
# ---------------------------------------------------------------------------

def t9_authorship_confusion():
    fx = _assemble("t9", OPERATOR, attacker_log=True)
    # Unpinned: must be SELF_CONSISTENT (exit 2) with explicit
    # not-the-operator's language; must NEVER be exit 0.
    code, out, _ = _run(fx["dir"])
    problems = _expect(code, out, exit_code=2,
                       text=("SELF_CONSISTENT", "NOT established"),
                       not_text=("verdict: VERIFIED",))
    if code == 0:
        problems.append("attacker bundle verified without a pin (exit 0)")
    # With the GENUINE operator pin, the attacker bundle must fail V6.
    code2, out2, _ = _run(fx["dir"], *_pin_args(OPERATOR))
    problems.extend(_expect(code2, out2, exit_code=1, fail_ids=("V6",)))
    return problems


def t9_control():
    # The operator's bundle is distinguishable from the attacker's:
    # genuine bundle plus genuine pin exits 0.
    return _control("t9c")


# ---------------------------------------------------------------------------
# T10: policy substitution — white-box re-sign isolates V11's
# payload-vs-log comparison (a keyless attacker cannot get past V4).
# ---------------------------------------------------------------------------

_ALT_POLICY = {"policy_version": "2.0", "policy_hash": "p" * 16,
               "policy_path": "policies/p2.yaml", "pinned": True}


def t10_policy_substitution():
    fx = _assemble("t10", OPERATOR)
    payload = _read_json(fx["dir"], "evidence.json")
    pol = payload["policy"]
    for field, value in _ALT_POLICY.items():
        pol[field]["value"] = value
    # Keep the bundle internally consistent (V14 is non-normative, but
    # the tamper under test is the policy substitution, not the id).
    probe = json.loads(json.dumps(payload))
    probe["bundle_meta"]["bundle_id"] = None
    payload["bundle_meta"]["bundle_id"] = (
        "EVB-" + hashlib.sha256(canonical(probe)).hexdigest()[:16])
    _rewrite(fx["dir"], "evidence.json", payload)
    manifest = _read_json(fx["dir"], "manifest.json")
    manifest["export_sha256"] = hashlib.sha256(
        canonical(payload)).hexdigest()
    manifest["bundle_id"] = payload["bundle_meta"]["bundle_id"]
    manifest["signing"]["sig"] = OPERATOR.sign(
        EvidenceBundle.signed_body(manifest)).hex()
    _rewrite(fx["dir"], "manifest.json", manifest)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    # V4 passes (re-signed); V11 must fail against the slice's
    # policy_loaded events.
    return _expect(code, out, exit_code=1, fail_ids=("V11",),
                   pass_ids=("V4",))


def t10_control():
    return _control("t10c")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

# (name, kind, function, what it proves)
# kind: "tamper" (must be CAUGHT) or "control" (must HOLD).
CASES = [
    # §5 benign controls
    ("C1 genuine bundle, pinned", "control", c1_genuine_pinned,
     "exit 0 VERIFIED"),
    ("C2 genuine bundle, unpinned", "control", c2_genuine_unpinned,
     "exit 2 SELF_CONSISTENT, authorship NOT established"),
    ("C3 HMAC-only checkpoints", "control", c3_hmac_only_checkpoints,
     "exit 0 with explicit reduced inclusion coverage"),
    ("C4 SAR unsealed", "control", c4_sar_unsealed,
     "exit 0, benchmark section stays seal_status=unsealed"),
    ("C5 unversioned policy (F172)", "control", c5_unversioned_policy,
     "exit 0: policy_loaded w/o policy_version renders unversioned"),
    # T1–T10 with a fresh positive control each
    ("T1 log edit (byte flip in slice payload)", "tamper", t1_log_edit,
     "V9 fails, exit 1"),
    ("T1 control: untampered bundle", "control", t1_control, "exit 0"),
    ("T2 record drop", "tamper", t2_record_drop,
     "V9 and V10 fail, exit 1"),
    ("T2 control: untampered bundle", "control", t2_control, "exit 0"),
    ("T3 reorder adjacent entries", "tamper", t3_reorder,
     "V9 fails, exit 1"),
    ("T3 control: untampered bundle", "control", t3_control, "exit 0"),
    ("T4a signing envelope deleted", "tamper", t4a_signing_deleted,
     "V7 fails, exit 1"),
    ("T4b operator pubkey corrupted", "tamper", t4b_operator_pubkey_corrupted,
     "V5/V7 fail, exit 1"),
    ("T4c signing scheme none", "tamper", t4c_scheme_none,
     "V7 fails, exit 1, never VERIFIED"),
    ("T4 control: untampered bundle", "control", t4_control, "exit 0"),
    ("T5 attacker key swap + re-sign", "tamper", t5_key_swap,
     "V6 fails against genuine pin, exit 1"),
    ("T5 control: genuine bundle + genuine pin", "control", t5_control,
     "exit 0"),
    ("T6 approval count inflated", "tamper", t6_payload_digest_tamper,
     "V4 fails, exit 1"),
    ("T6 control: untampered bundle", "control", t6_control, "exit 0"),
    ("T7 forged checkpoint head", "tamper", t7_checkpoint_forgery,
     "V8 Ed25519 fails closed, exit 1"),
    ("T7 control: untampered bundle", "control", t7_control, "exit 0"),
    ("T8a slice tail cut", "tamper", t8a_slice_tail_cut,
     "V9 and V10 fail, exit 1"),
    ("T8b receipt detached from tip", "tamper", t8b_receipt_detached,
     "V12 fails, exit 1"),
    ("T8c coherent window shift (truncation as complete)", "tamper",
     t8c_window_shift_coherent,
     "V12 and V10 fail, exit 1"),
    ("T8 control: untampered bundle", "control", t8_control, "exit 0"),
    ("T9 attacker self-sealed, unpinned", "tamper", t9_authorship_confusion,
     "exit 2 SELF_CONSISTENT with not-operator language, never exit 0; "
     "V6 fails with genuine pin"),
    ("T9 control: genuine bundle + genuine pin", "control", t9_control,
     "exit 0"),
    ("T10 policy substitution", "tamper", t10_policy_substitution,
     "V11 fails, exit 1"),
    ("T10 control: untampered bundle", "control", t10_control, "exit 0"),
]


def main():
    caught = missed = held = broken = errors = 0
    failures = []
    for name, kind, fn, proves in CASES:
        try:
            problems = fn()
        except Exception as e:  # harness failure, never a silent pass
            errors += 1
            failures.append((name, ["ERROR: %r" % (e,)]))
            print("[ERROR] %-42s %s" % (name, e))
            continue
        if not problems:
            if kind == "tamper":
                caught += 1
                print("[CAUGHT] %-42s %s" % (name, proves))
            else:
                held += 1
                print("[CONTROL] %-41s %s" % (name, proves))
        else:
            failures.append((name, problems))
            if kind == "tamper":
                missed += 1
                print("[MISS]   %-42s %s" % (name, "; ".join(problems)))
            else:
                broken += 1
                print("[BROKEN] %-42s %s" % (name, "; ".join(problems)))
    print()
    print("CAUGHT=%d MISS=%d CONTROL=%d BROKEN=%d ERROR=%d"
          % (caught, missed, held, broken, errors))
    if failures:
        print("failures:")
        for name, problems in failures:
            for p in problems:
                print("  - %s: %s" % (name, p))
        return 1
    print("normative §5 battery: all tampers caught, all controls hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
