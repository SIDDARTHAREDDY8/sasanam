#!/usr/bin/env python3
"""Adversarial battery for evidence bundles — BEYOND the spec §5 T1–T10.

The normative tamper battery (evals/evidence_bundle_tamper.py) covers the
spec's MUST-detect cases. THIS battery attacks the product the way a real
adversary would: at the seams the spec battery never exercises.

Attack shapes (see the lane brief):
  (a) Threshold confusion — duplicate-key k-of-n, wrong-signer key,
      key-ID aliasing, roster substitution.
  (b) Receipt replay across bundles/windows.
  (c) Verifier differentials — tools/evidence-verify vs
      gov/evidence_verify.py must agree on every input, including hostile
      ones (byte-identity re-verified + differential fuzz).
  (d) Auditor-misleading bundles — VERIFIED bundles that mislead about
      what was proven (F174: claimed operator now surfaced with its
      disclaimer, verified by regression probe D1).
  (e) Checkpoint binding gaps — stale/forged checkpoints.
  (f) Coverage downgrade — no-key strip of inclusion/receipt bundles
      (F173: bound into the operator-signed claim, verified by
      regression probes F1a/F1b).

Verdicts:
  CAUGHT  attack stopped (expected exit + expected check) — the good case
  MISS    attack NOT caught — the bad case (would file a finding)
  BREAK   break-demo: the vulnerable behavior reproduces as documented in
          a FILED finding. The probe pins the vulnerable behavior
          red-first so the fix lane can flip it to expect FAIL (F173's
          F1a/F1b and F174's D1 have been flipped: they now run as
          "attack" regression probes).
  CONTROL benign behavior holds
  AGREE   differential: both verifiers agree
  DIVERGE differential: verifiers disagree — the bad case
  ERROR   harness failure (never a silent pass)

White-box notes (documented, not hidden): several probes re-sign the
manifest with the test operator key or re-sign checkpoint heads with the
test threshold keys. This isolates the CHECK logic under test (the k-of-n
dedup; the roster structural check; the signer binding) the same way the
§5 battery's T5/T10 white-box re-signs isolate V6/V11. A keyless attacker
cannot reach these code paths past V7 — the probes prove the inner checks
hold even when the outer signature is (hypothetically) satisfied.

Weakened verifier: --weakened swaps in a deliberately broken copy of the
verifier (threshold branch counts duplicate-key signatures instead of
distinct keys). The battery must FAIL against it (A1 MISSES) — proving
the A1 probe is red-capable, not vacuous.

Deterministic, hermetic, $0: fixed synthetic keys, fixed GOV_LOG_KEY,
no sleeps, no network. Each probe builds fresh fixtures in its own temp
dir and runs the REAL standalone verifier as a subprocess (cwd=/tmp,
PYTHONPATH stripped) — no repo on sys.path for the verifier process.

Exit 0 iff: every attack CAUGHT, every control holds, every break-demo
reproduces as filed, no divergences, no errors. BREAK > 0 is expected:
F173 and F174 are filed in evals/FINDINGS.md; these probes are their
red-first regression pins.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from importlib.machinery import SourceFileLoader

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Fixed synthetic HMAC key: deterministic chains across fixtures.
os.environ.setdefault("GOV_LOG_KEY", "eb" * 32)
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "evidence-adversarial")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov.log import ActionLog  # noqa: E402
import gov.log as gov_log  # noqa: E402
import gov.merkle  # noqa: E402
from gov.signing import (  # noqa: E402
    Ed25519Signer, ThresholdSigner, make_roster)
from gov.evidence_bundle import (  # noqa: E402
    EvidenceBundle, canonical, log_evidence_bundle_receipt)
from gov.safeguard_bundle import compute_bundle_digest  # noqa: E402

VERIFY_SCRIPT = os.path.join(REPO_ROOT, "tools", "evidence-verify")
VERIFY_COPY = os.path.join(REPO_ROOT, "gov", "evidence_verify.py")

# Fixed synthetic Ed25519 identities (deterministic, never real keys).
OPERATOR = Ed25519Signer(bytes.fromhex("11" * 32))  # manifest signer / pin
CK1 = Ed25519Signer(bytes.fromhex("22" * 32))       # checkpoint key
CK2 = Ed25519Signer(bytes.fromhex("33" * 32))       # second checkpoint key
S1 = Ed25519Signer(bytes.fromhex("44" * 32))        # threshold set 2-of-3
S2 = Ed25519Signer(bytes.fromhex("55" * 32))
S3 = Ed25519Signer(bytes.fromhex("66" * 32))
TROOT = Ed25519Signer(bytes.fromhex("77" * 32))      # offline roster root

EXPORTED_AT = "2026-09-26T00:00:00+00:00"
PINNED_TS = "2026-09-26T00:00:00+00:00"

# The verifier's own Merkle/checkpoint helpers (white-box instrumentation,
# same convention as the §5 battery's T7).
_EVV = SourceFileLoader("evidence_verify_mod", VERIFY_SCRIPT).load_module()

_TMP_DIRS = []


def _cleanup_tmp_dirs():
    for d in _TMP_DIRS:
        shutil.rmtree(d, ignore_errors=True)


import atexit  # noqa: E402
atexit.register(_cleanup_tmp_dirs)

WEAKENED = "--weakened" in sys.argv
_weakened_path = [None]


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

def _build_log(path, signer, *, variant=""):
    """Synthetic 5-entry governed log (single-key checkpoints)."""
    log = ActionLog(path, signer=signer, deployment_mode="staging")
    log.append({"event": "policy_loaded", "policy_version": "1.0",
                "policy_hash": "h" * 16, "policy_path": "policies/p1.yaml",
                "pinned": True})
    log.append({"event": "approval_decision", "decision": "approve",
                "ticket": "T-42"})
    for i in range(3):
        log.append({"event": "tool_call", "decision": "allow",
                    "tool": "tool-%s%d" % (variant, i)})
    return log


def _build_threshold_log(path):
    """Synthetic 5-entry log with 2-of-3 threshold checkpoints (A5)."""
    roster = make_roster([S1, S2, S3], 2, TROOT)
    tsigner = ThresholdSigner([S1, S2, S3], 2)
    log = ActionLog(path, signer=tsigner, roster=roster,
                    deployment_mode="staging")
    log.append({"event": "policy_loaded", "policy_version": "1.0",
                "policy_hash": "h" * 16, "policy_path": "policies/p1.yaml",
                "pinned": True})
    log.append({"event": "approval_decision", "decision": "approve",
                "ticket": "T-42"})
    for i in range(3):
        log.append({"event": "tool_call", "decision": "allow",
                    "tool": "tool-%d" % i})
    return roster, tsigner


def _envelope(signer):
    return {"key_id": signer.key_id,
            "public_key_hex": signer.public_key.hex()}


def _mint_receipt(fx):
    """Append the seal receipt to the fixture's log and attach it to the
    in-memory manifest. Split out so a probe can mint receipts at a
    different time than the (pinned) bundle build — the receipt binds
    the manifest's export_sha256, which does not depend on the receipt
    itself."""
    receipt_log = ActionLog(
        fx["log_path"], signer=fx["receipt_signer"],
        **({"roster": fx["roster"]} if fx["threshold"] else {}),
        deployment_mode="staging")
    # F173: the receipt attachment re-signs the extended claim, so the
    # operator signer must be passed explicitly (hermetic keys here).
    return log_evidence_bundle_receipt(fx["manifest"], receipt_log,
                                       signer=fx["operator"])


def _assemble_files(fx):
    """Write the bundle directory from the fixture's payload/manifest."""
    out = os.path.join(fx["tmp"], "bundle")
    fx["eb"].assemble(fx["payload"], fx["manifest"],
                      operator_key=_envelope(fx["operator"]),
                      checkpoint_keys=[dict(k) for k in fx["cp_keys"]],
                      out_dir=out)
    fx["dir"] = out
    return fx


def _assemble(tag, *, operator=OPERATOR, log_signer=None,
              operator_id=None, threshold=False, variant="",
              mint_receipt=True):
    """Build a genuine bundle in its own temp dir. Returns a fixture dict."""
    tmp = tempfile.mkdtemp(prefix="ebadv-%s-" % tag)
    _TMP_DIRS.append(tmp)
    log_path = os.path.join(tmp, "audit.log")
    roster = tsigner = None
    if threshold:
        roster, tsigner = _build_threshold_log(log_path)
        cp_keys = [_envelope(s) for s in (S1, S2, S3)]
        receipt_signer = tsigner
    else:
        resolved = log_signer or operator
        _build_log(log_path, resolved, variant=variant)
        cp_keys = [_envelope(resolved)]
        receipt_signer = resolved
    eb = EvidenceBundle(log_path, exported_at=EXPORTED_AT,
                        operator_id="adv-%s" % tag
                        if operator_id is None else operator_id,
                        roster=roster)
    payload = eb.build()
    manifest = eb.seal(payload, signer=operator)
    fx = {"tmp": tmp, "log_path": log_path, "operator": operator,
          "payload": payload, "manifest": manifest, "roster": roster,
          "tsigner": tsigner, "threshold": threshold,
          "receipt_signer": receipt_signer, "cp_keys": cp_keys, "eb": eb}
    if mint_receipt:
        _mint_receipt(fx)
        return _assemble_files(fx)
    # Deferred: the caller mints the receipt (e.g. at a different time)
    # then calls _assemble_files(fx) explicitly.
    return fx


@contextmanager
def _pinned_time(ts=PINNED_TS):
    """Pin gov.log's clock so two independently built logs are byte-identical."""
    real = gov_log._utcnow
    gov_log._utcnow = lambda: ts
    try:
        yield
    finally:
        gov_log._utcnow = real


# ---------------------------------------------------------------------------
# Runner helpers
# ---------------------------------------------------------------------------

def _verifier_script():
    if WEAKENED:
        if _weakened_path[0] is None:
            _weakened_path[0] = _make_weakened_verifier()
        return _weakened_path[0]
    return VERIFY_SCRIPT


def _run(bundle_dir, *args, verifier=None):
    """Run the (real or weakened) standalone verifier as a subprocess."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, verifier or _verifier_script(), bundle_dir]
        + list(args),
        capture_output=True, text=True, env=env, cwd="/tmp")
    return proc.returncode, proc.stdout, proc.stderr


def _pin_args(signer=OPERATOR):
    return ["--pin-operator-pubkey", signer.public_key.hex()]


def _redigest(bundle_dir):
    with open(os.path.join(bundle_dir, "BUNDLE_DIGEST.sha256"), "w") as f:
        f.write(compute_bundle_digest(bundle_dir) + "\n")


def _rewrite(bundle_dir, rel, obj):
    with open(os.path.join(bundle_dir, rel), "wb") as f:
        f.write(canonical(obj) + b"\n")


def _read_json(bundle_dir, rel):
    with open(os.path.join(bundle_dir, rel), "r", encoding="utf-8") as f:
        return json.load(f)


def _write_raw(bundle_dir, rel, data: bytes):
    full = os.path.join(bundle_dir, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(data)


def _resign_manifest(bundle_dir, signer):
    """White-box: re-sign the manifest after coherent mutation."""
    manifest = _read_json(bundle_dir, "manifest.json")
    manifest["signing"]["signature_hex"] = signer.sign(
        EvidenceBundle.signed_body(manifest)).hex()
    _rewrite(bundle_dir, "manifest.json", manifest)
    _redigest(bundle_dir)
    return manifest


def _expect(code, stdout, *, exit_code, fail_ids=(), pass_ids=(),
            text=(), not_text=()):
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


def _make_weakened_verifier():
    """Deliberately broken copy: the threshold branch counts SIGNATURES,
    not DISTINCT keys — duplicate sigs from one key satisfy k-of-n."""
    with open(VERIFY_SCRIPT, "r", encoding="utf-8") as f:
        src = f.read()
    edits = [
        # 1. drop the duplicate-key skip ...
        ("        if not isinstance(kid, str) or kid in good \\\n"
         "                or kid not in roster_pubs:\n",
         "        if not isinstance(kid, str) or kid not in roster_pubs:\n"),
        # 2. ... and count every valid signature (list, not set).
        ("    roster_pubs = roster[\"keys\"]\n    good = set()\n",
         "    roster_pubs = roster[\"keys\"]\n    good = []\n"),
        ("        if verify(bytes.fromhex(roster_pubs[kid]), entry_body, sig):\n"
         "            good.add(kid)\n",
         "        if verify(bytes.fromhex(roster_pubs[kid]), entry_body, sig):\n"
         "            good.append(kid)\n"),
    ]
    for old, new in edits:
        assert src.count(old) == 1, "weakening anchor not unique: %r" % old
        src = src.replace(old, new)
    tmp = tempfile.mkdtemp(prefix="ebadv-weakened-")
    _TMP_DIRS.append(tmp)
    path = os.path.join(tmp, "evidence-verify-weakened")
    with open(path, "w", encoding="utf-8") as f:
        f.write(src)
    return path


# ---------------------------------------------------------------------------
# (c) Verifier differentials
# ---------------------------------------------------------------------------

def drift_c1():
    """tools/evidence-verify is byte-identical to gov/evidence_verify.py."""
    with open(VERIFY_SCRIPT, "rb") as f:
        a = f.read()
    with open(VERIFY_COPY, "rb") as f:
        b = f.read()
    if a != b:
        return ["drift: tools/evidence-verify != gov/evidence_verify.py "
                "(%d vs %d bytes)" % (len(a), len(b))]
    return []


def _fuzz_corpus():
    """(name, dir, args) — diverse + malformed inputs for the differential."""
    fx = _assemble("fuzz-base", log_signer=CK1)
    base = fx["dir"]
    pin = _pin_args()
    cases = []

    def clone(tag, mutate):
        d = os.path.join(fx["tmp"], "fuzz-" + tag)
        shutil.copytree(base, d)
        mutate(d)
        cases.append((tag, d, pin + ["--format", "json"]))

    clone("genuine", lambda d: None)
    # T1-style: byte flip inside a slice payload
    def t1(d):
        p = os.path.join(d, "log_slice.jsonl")
        lines = open(p, encoding="utf-8").read().splitlines()
        e = json.loads(lines[3])
        e["tool"] = "tool-X"
        lines[3] = canonical(e).decode("utf-8")
        open(p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    clone("log-edit", t1)
    # T4c-style: scheme none
    def t4c(d):
        m = _read_json(d, "manifest.json")
        m["signing"]["scheme"] = "none"
        _rewrite(d, "manifest.json", m)
    clone("scheme-none", t4c)
    # F173a-style: stripped inclusion bundles (no-key downgrade)
    def strip2(d):
        m = _read_json(d, "manifest.json")
        n = 0
        for ib in m["inclusion_bundles"]:
            if ib["seq"] in (2, 4):
                ib["bundle"] = None
                ib["unavailable_reason"] = "stripped"
                n += 1
        m["inclusion_coverage"]["with_bundle"] -= n
        _rewrite(d, "manifest.json", m)
    clone("stripped-bundles", strip2)

    def raw(tag, files):
        d = os.path.join(fx["tmp"], "fuzz-" + tag)
        os.makedirs(d)
        for rel, data in files.items():
            _write_raw(d, rel, data)
        cases.append((tag, d, pin + ["--format", "json"]))

    raw("empty-dir", {})
    raw("version-only", {"VERSION": b"evidence-bundle/1.0\n"})
    raw("manifest-array", {"VERSION": b"evidence-bundle/1.0\nschema: "
                                      b"evidence-schema/1.0\n",
                           "manifest.json": b"[]\n"})
    raw("evidence-truncated", {"evidence.json": b'{"bundle_meta": {"bu'})
    raw("slice-garbage-line", {"log_slice.jsonl": b"not json\n"})
    raw("digest-garbage", {"BUNDLE_DIGEST.sha256": b"zzz\n"})
    raw("version-future", {"VERSION": b"evidence-bundle/9.9\nschema: "
                                      b"evidence-schema/9.9\n"})
    raw("manifest-no-window",
        {"manifest.json": canonical({"kind": "x"}) + b"\n"})
    raw("receipt-empty-obj", {"receipt.json": b"{}\n"})
    raw("checkpoints-empty", {"checkpoints.jsonl": b""})

    # missing operator envelope (delete the file from a genuine clone)
    d = os.path.join(fx["tmp"], "fuzz-missing-opkey")
    shutil.copytree(base, d)
    os.remove(os.path.join(d, "keys", "operator_ed25519.json"))
    cases.append(("missing-opkey", d, pin + ["--format", "json"]))

    # a regular file, not a directory
    fpath = os.path.join(fx["tmp"], "fuzz-file-not-dir")
    with open(fpath, "w") as f:
        f.write("nope")
    cases.append(("file-not-dir", fpath, pin + ["--format", "json"]))

    # text format on a couple of inputs too
    d2 = os.path.join(fx["tmp"], "fuzz-text")
    shutil.copytree(base, d2)
    cases.append(("genuine-text", d2, pin + ["--format", "text"]))
    return cases


def c2_diff_fuzz():
    """Both verifier copies agree on every corpus input (exit + stdout)."""
    problems = []
    for name, d, args in _fuzz_corpus():
        c1, o1, _ = _run(d, *args, verifier=VERIFY_SCRIPT)
        c2, o2, _ = _run(d, *args, verifier=VERIFY_COPY)
        if (c1, o1) != (c2, o2):
            problems.append(
                "DIVERGE on %r: tools exit=%d vs gov exit=%d "
                "(stdout %d vs %d bytes)" % (name, c1, c2, len(o1),
                                             len(o2)))
    return problems


def c3_cli_parity():
    """Usage/config errors: identical exit-3 behavior on both copies.

    The usage line embeds the script's own basename (argparse prog), so
    stderr is normalized on the basename before comparison — the parity
    under test is the failure MODE (exit 3, same message shape), not the
    filename.
    """
    fx = _assemble("cli-base", log_signer=CK1)
    problems = []
    arg_sets = [
        ["--bogus-flag"],
        ["/nonexistent-dir-xyz-ebadv"],
        [fx["dir"], "--pin-operator-pubkey", "zz"],
        [fx["dir"], "--pin-checkpoint-key-ids", "short"],
    ]
    names = {os.path.basename(VERIFY_SCRIPT): "VERIFIER",
             os.path.basename(VERIFY_COPY): "VERIFIER"}
    for args in arg_sets:
        outs = []
        for script in (VERIFY_SCRIPT, VERIFY_COPY):
            r = subprocess.run(
                [sys.executable, script] + args, capture_output=True,
                text=True, cwd="/tmp",
                env={k: v for k, v in os.environ.items()
                     if k != "PYTHONPATH"})
            err = r.stderr
            for name, norm in names.items():
                err = err.replace(name, norm)
            # argparse wraps usage text to the prog-name length; collapse
            # whitespace so only the message content is compared.
            err = re.sub(r"\s+", " ", err)
            outs.append((r.returncode, re.sub(r"\s+", " ", r.stdout),
                         err))
        (c1, o1, e1), (c2, o2, e2) = outs
        if (c1, o1, e1) != (c2, o2, e2):
            problems.append("CLI DIVERGE on %r: exit %d vs %d; "
                            "stderr %r vs %r" % (args, c1, c2, e1, e2))
        if c1 != 3:
            problems.append("expected exit 3 on %r, got %d" % (args, c1))
    return problems


# ---------------------------------------------------------------------------
# Controls (benign baselines)
# ---------------------------------------------------------------------------

def c_threshold_genuine():
    """Genuine 2-of-3 threshold bundle verifies exit 0 (A-probe baseline)."""
    fx = _assemble("c-thr", threshold=True)
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=0, text=("verdict: VERIFIED",),
                   pass_ids=("V8",))


# ---------------------------------------------------------------------------
# (a) Threshold confusion
# ---------------------------------------------------------------------------

def a1_dupkey_threshold():
    """Duplicate-key k-of-n: a 2-of-3 head carrying TWO signatures from ONE
    key (the same kid twice) must NOT satisfy the threshold.

    Hypothesis: the verifier counts DISTINCT roster key ids, so the
    duplicated sig counts once -> V8 fails closed. The weakened verifier
    (counts signatures) must be fooled -> exit 0, proving red-capability.
    White-box: the head is re-pointed and the manifest re-signed with the
    test operator key to isolate V8's dedup past a valid V7.
    """
    fx = _assemble("a1", threshold=True)
    heads = [json.loads(l) for l in
             open(os.path.join(fx["dir"], "checkpoints.jsonl"),
                  encoding="utf-8").read().splitlines() if l.strip()]
    assert len(heads) == 1 and heads[0]["threshold"] == 2, heads
    head = dict(heads[0])
    s1sig = [s for s in head["sigs"] if s["key_id"] == S1.key_id][0]
    head["sigs"] = [dict(s1sig), dict(s1sig)]  # one key, twice
    with open(os.path.join(fx["dir"], "checkpoints.jsonl"), "w",
              encoding="utf-8") as f:
        f.write(canonical(head).decode("utf-8") + "\n")
    manifest = _read_json(fx["dir"], "manifest.json")
    manifest["checkpoints"] = [head]
    manifest["checkpoints_digest"] = hashlib.sha256(
        canonical([head])).hexdigest()
    _rewrite(fx["dir"], "manifest.json", manifest)
    _resign_manifest(fx["dir"], OPERATOR)
    code, out, _ = _run(fx["dir"], *_pin_args())
    problems = _expect(code, out, exit_code=1, fail_ids=("V8",),
                       text=("only 1/2 valid distinct signatures",))
    # Red-capability: the weakened verifier must be FOOLED (exit 0).
    wcode, wout, _ = _run(fx["dir"], *_pin_args(),
                          verifier=_make_weakened_verifier())
    if wcode != 0 or "verdict: VERIFIED" not in wout:
        problems.append("weakened verifier was NOT fooled by the "
                        "duplicate-key threshold (exit %d) — the probe "
                        "may be vacuous" % wcode)
    return problems


def a2_wrong_signer_key():
    """A checkpoint signature from a VALID envelope key that is NOT the
    roster-bound signer must be rejected.

    Hypothesis: V8's single-key branch binds sigs[0].key_id to the
    roster_hash-embedded kid; a genuine signature from another envelope
    key (white-box: signed with the test CK2 key) fails closed.
    """
    tmp = tempfile.mkdtemp(prefix="ebadv-a2-")
    _TMP_DIRS.append(tmp)
    log_path = os.path.join(tmp, "audit.log")
    _build_log(log_path, CK1)
    eb = EvidenceBundle(log_path, exported_at=EXPORTED_AT,
                        operator_id="adv-a2")
    payload = eb.build()
    manifest = eb.seal(payload, signer=OPERATOR)
    log_evidence_bundle_receipt(
        manifest, ActionLog(log_path, signer=CK1,
                            deployment_mode="staging"),
        signer=OPERATOR)
    out = os.path.join(tmp, "bundle")
    eb.assemble(payload, manifest, operator_key=_envelope(OPERATOR),
                checkpoint_keys=[_envelope(CK1), _envelope(CK2)],
                out_dir=out)
    heads = [json.loads(l) for l in
             open(os.path.join(out, "checkpoints.jsonl"),
                  encoding="utf-8").read().splitlines() if l.strip()]
    assert len(heads) == 1, heads
    head = dict(heads[0])
    body = _EVV._checkpoint_sig_body(head["seq"], head["hash"],
                                     head["merkle_root"],
                                     head["key_epoch"], head["threshold"],
                                     head["roster_hash"], head["ts"])
    # Genuine CK2 signature over the real body — but CK2 is not the
    # roster-bound signer.
    head["sigs"] = [{"key_id": CK2.key_id,
                     "sig": CK2.sign(body).hex()}]
    with open(os.path.join(out, "checkpoints.jsonl"), "w",
              encoding="utf-8") as f:
        f.write(canonical(head).decode("utf-8") + "\n")
    manifest = _read_json(out, "manifest.json")
    manifest["checkpoints"] = [head]
    manifest["checkpoints_digest"] = hashlib.sha256(
        canonical([head])).hexdigest()
    _rewrite(out, "manifest.json", manifest)
    _resign_manifest(out, OPERATOR)
    code, out_s, _ = _run(out, *_pin_args(OPERATOR))
    return _expect(code, out_s, exit_code=1, fail_ids=("V8",),
                   text=("does not match roster",))


def a3_roster_keyid_alias():
    """Key-ID aliasing: a roster entry whose key_id does not equal
    sha256(pub)[:16] must be rejected even when every signature on the
    head is genuine.

    Hypothesis: _verify_roster_structure enforces kid == sha256(pub)[:16]
    per roster key, so aliasing (s1's kid labeled onto s2's pubkey)
    fails V8. White-box: the aliased roster's hash is signed into a
    fresh head with the real threshold keys to isolate the structural
    check past genuine signatures.
    """
    fx = _assemble("a3", threshold=True)
    roster = json.loads(json.dumps(fx["roster"]))
    # Alias: s1's key id now labels s2's public key.
    roster["keys"][S1.key_id] = S2.public_key.hex()
    rh = hashlib.sha256(canonical(
        {k: v for k, v in roster.items() if k != "sig"})).hexdigest()
    heads = [json.loads(l) for l in
             open(os.path.join(fx["dir"], "checkpoints.jsonl"),
                  encoding="utf-8").read().splitlines() if l.strip()]
    head = dict(heads[0])
    head["roster_hash"] = rh
    body = _EVV._checkpoint_sig_body(head["seq"], head["hash"],
                                     head["merkle_root"],
                                     head["key_epoch"], head["threshold"],
                                     rh, head["ts"])
    head["sigs"] = fx["tsigner"].sign_all(body)
    with open(os.path.join(fx["dir"], "checkpoints.jsonl"), "w",
              encoding="utf-8") as f:
        f.write(canonical(head).decode("utf-8") + "\n")
    manifest = _read_json(fx["dir"], "manifest.json")
    manifest["checkpoints"] = [head]
    manifest["checkpoints_digest"] = hashlib.sha256(
        canonical([head])).hexdigest()
    _rewrite(fx["dir"], "manifest.json", manifest)
    _rewrite(fx["dir"], "keys/checkpoint_roster.json", roster)
    _resign_manifest(fx["dir"], OPERATOR)
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=1, fail_ids=("V8",),
                   text=("does not match its pubkey",))


def a4_roster_substitution():
    """Roster substitution without the operator key: swapping
    keys/checkpoint_roster.json for a different valid roster must fail.

    Hypothesis: the head's signed roster_hash pins the exact roster
    bytes; a substituted roster mismatches -> V8 fails closed.
    """
    fx = _assemble("a4", threshold=True)
    other = make_roster(
        [Ed25519Signer(bytes.fromhex("88" * 32)),
         Ed25519Signer(bytes.fromhex("99" * 32)),
         Ed25519Signer(bytes.fromhex("ab" * 32))], 2, TROOT)
    _rewrite(fx["dir"], "keys/checkpoint_roster.json", other)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=1, fail_ids=("V8",),
                   text=("roster_hash mismatch",))


# ---------------------------------------------------------------------------
# (b) Receipt replay across bundles/windows
# ---------------------------------------------------------------------------

def b1_receipt_cross_content_replay():
    """Replay a receipt minted for bundle A against bundle B (different
    log content, different tip, different digest).

    Hypothesis: V12 binds the receipt to THIS bundle via prev_hash ==
    window tip AND export_sha256 == manifest digest AND seq == to_seq+1,
    so a foreign receipt fails closed.
    """
    with _pinned_time():
        fx_a = _assemble("b1a", log_signer=CK1, variant="A")
        fx_b = _assemble("b1b", log_signer=CK1, variant="B")
    da = _read_json(fx_a["dir"], "manifest.json")
    db = _read_json(fx_b["dir"], "manifest.json")
    assert da["bundle_id"] != db["bundle_id"], \
        "B must differ from A for a meaningful cross-bundle replay"
    # Replay A's receipt into B (different log content/tip/digest).
    shutil.copy(os.path.join(fx_a["dir"], "receipt.json"),
                os.path.join(fx_b["dir"], "receipt.json"))
    _redigest(fx_b["dir"])
    code, out, _ = _run(fx_b["dir"], *_pin_args())
    return _expect(code, out, exit_code=1, fail_ids=("V12",))


def b2_receipt_same_content_replay():
    """NEGATIVE (control): a receipt minted for bundle D1 replays cleanly
    against bundle D2 only because D2's content is byte-identical —
    the receipt binding is content-addressed (tip + digest + seq), not
    bundle-instance-addressed.

    Both bundles are built under pinned time with the same operator_id
    so their payloads are byte-identical; the receipts are then minted
    at real time so the two receipt entries genuinely differ. Replaying
    D1's receipt into D2 must VERIFY (exit 0), including V12b against
    the source log — proving cross-bundle replay is impossible for
    DIFFERENT content (b1) and harmless for IDENTICAL content (here).
    """
    with _pinned_time():
        fx1 = _assemble("b2d1", log_signer=CK1, operator_id="b2-shared",
                        mint_receipt=False)
        fx2 = _assemble("b2d2", log_signer=CK1, operator_id="b2-shared",
                        mint_receipt=False)
    # Mint the receipts at deterministically different wall-clock times
    # (_utcnow has 1-second resolution; two rapid mints would collide).
    # The bundles stay byte-identical; only the receipt entries differ.
    _mint_receipt(fx1)
    real_utcnow = gov_log._utcnow
    gov_log._utcnow = lambda: "2026-09-26T12:01:00+00:00"
    try:
        _mint_receipt(fx2)
    finally:
        gov_log._utcnow = real_utcnow
    _assemble_files(fx1)
    _assemble_files(fx2)
    # Sanity: byte-identical evidence (the manifest legitimately differs
    # in its attached receipt section).
    for rel in ("evidence.json", "log_slice.jsonl", "checkpoints.jsonl"):
        a = open(os.path.join(fx1["dir"], rel), "rb").read()
        b = open(os.path.join(fx2["dir"], rel), "rb").read()
        assert a == b, "fixture not byte-identical: %s" % rel
    r_old = _read_json(fx1["dir"], "receipt.json")
    r_new = _read_json(fx2["dir"], "receipt.json")
    assert r_old["entry"]["hash"] != r_new["entry"]["hash"], \
        "receipts must differ (different ts) for a meaningful replay"
    assert r_old["entry"]["export_sha256"] == \
        r_new["entry"]["export_sha256"]
    # Replay D1's receipt into D2.
    shutil.copy(os.path.join(fx1["dir"], "receipt.json"),
                os.path.join(fx2["dir"], "receipt.json"))
    _redigest(fx2["dir"])
    problems = []
    code, out, _ = _run(fx2["dir"], *_pin_args())
    problems.extend(_expect(code, out, exit_code=0,
                            text=("verdict: VERIFIED",),
                            pass_ids=("V12",)))
    # V12b: the replayed receipt exists in the source log (fx1's log,
    # which carries R_old at seq 6).
    code2, out2, _ = _run(fx2["dir"], *_pin_args(),
                          "--log", fx1["log_path"])
    problems.extend(_expect(code2, out2, exit_code=0,
                            text=("V12b",)))
    return problems


# ---------------------------------------------------------------------------
# (d) Auditor-misleading bundles
# ---------------------------------------------------------------------------

_MISLEADING_OPERATOR_ID = "Acme Corp \u2014 Independent Audit Division"


def d1_operator_id_invisible():
    """REGRESSION (F174 CLOSED): a VERIFIED bundle carrying an
    authoritative-sounding operator_id must surface that name WITH its
    disclaimer in both text and JSON output — disclosure, not
    rejection. The bundle still verifies exit 0; the fix is that an
    auditor skimming the verdict can no longer mistake key-pinning for
    verification of the claimed name.
    """
    fx = _assemble("d1", log_signer=CK1,
                   operator_id=_MISLEADING_OPERATOR_ID)
    problems = []
    code, out, _ = _run(fx["dir"], *_pin_args())
    problems.extend(_expect(code, out, exit_code=0,
                            text=("verdict: VERIFIED",
                                  "Acme",
                                  "operator-supplied, not independently "
                                  "verified")))
    code2, out2, _ = _run(fx["dir"], *_pin_args(), "--format", "json")
    problems.extend(_expect(code2, out2, exit_code=0,
                            text=("Acme",
                                  "operator-supplied, not independently "
                                  "verified")))
    if code2 == 0:
        doc = json.loads(out2)
        cop = doc.get("claimed_operator") or {}
        if cop.get("value") != _MISLEADING_OPERATOR_ID:
            problems.append("json claimed_operator.value %r != the "
                            "payload operator_id"
                            % (cop.get("value"),))
    # The claim IS in the payload with honest provenance — the fix is
    # the verifier's disclosure, not a payload change.
    prov = ((fx["payload"].get("bundle_meta", {}).get("operator_id")
             or {}).get("provenance") or {}).get("kind")
    if prov != "operator_supplied":
        problems.append("payload operator_id provenance %r != "
                        "'operator_supplied'" % prov)
    return problems


def d2_footer_present():
    """The normative §7 honesty footer must ride on every verdict path
    (exit 0 pinned, exit 2 unpinned, exit 1 failed)."""
    fx = _assemble("d2", log_signer=CK1)
    problems = []
    code, out, _ = _run(fx["dir"], *_pin_args())
    problems.extend(_expect(code, out, exit_code=0,
                            text=("WHAT THIS DOES NOT PROVE",)))
    code, out, _ = _run(fx["dir"])
    problems.extend(_expect(code, out, exit_code=2,
                            text=("WHAT THIS DOES NOT PROVE",)))
    # Tampered (V9 fail): footer still present on the FAILED path.
    lines = open(os.path.join(fx["dir"], "log_slice.jsonl"),
                 encoding="utf-8").read().splitlines()
    e = json.loads(lines[3])
    e["tool"] = "tool-X"
    lines[3] = canonical(e).decode("utf-8")
    open(os.path.join(fx["dir"], "log_slice.jsonl"), "w",
         encoding="utf-8").write("\n".join(lines) + "\n")
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    problems.extend(_expect(code, out, exit_code=1,
                            text=("WHAT THIS DOES NOT PROVE",)))
    return problems


# ---------------------------------------------------------------------------
# (e) Checkpoint binding gaps
# ---------------------------------------------------------------------------

def _sidecar_heads(log_path):
    cp = os.path.join(os.path.dirname(log_path), "checkpoints.jsonl")
    return [json.loads(l) for l in open(cp, encoding="utf-8")
            .read().splitlines() if l.strip()]


def e1_stale_head_no_resign():
    """Substitute a genuine-but-STALE checkpoint head (seq 3) without
    re-signing the manifest.

    Hypothesis: checkpoints_digest in the signed claim binds the
    exact head list — the substitution fails V8 closed, so a no-key
    attacker cannot smuggle a stale head past the verifier.
    """
    fx = _assemble("e1", log_signer=CK1)
    stale = [h for h in _sidecar_heads(fx["log_path"])
             if h["seq"] == 3]
    assert len(stale) == 1, "need one genuine seq-3 head"
    head3 = stale[0]
    with open(os.path.join(fx["dir"], "checkpoints.jsonl"), "w",
              encoding="utf-8") as f:
        f.write(canonical(head3).decode("utf-8") + "\n")
    manifest = _read_json(fx["dir"], "manifest.json")
    manifest["checkpoints"] = [head3]
    # Deliberately NOT updating checkpoints_digest / signature.
    _rewrite(fx["dir"], "manifest.json", manifest)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=1, fail_ids=("V8",),
                   text=("do not hash to the signed checkpoints_digest",))


def e2_stale_head_resigned():
    """NEGATIVE (control): white-box stale head WITH operator re-sign.

    The operator ships heads=[genuine head seq 3] over a 5-entry window,
    honestly regenerated inclusion bundles for seq 1..3, explicit
    unavailable_reasons (and matching payload coverage flags) for seq
    4..5, a fresh receipt, and a fresh operator signature. Hypothesis:
    the bundle VERIFIES with explicitly reduced coverage — staleness
    surfaces as labeled reduced coverage, never as silent acceptance of
    full coverage.
    """
    fx = _assemble("e2", log_signer=CK1, mint_receipt=False)
    stale = [h for h in _sidecar_heads(fx["log_path"])
             if h["seq"] == 3]
    assert len(stale) == 1, "need one genuine seq-3 head"
    head3 = stale[0]
    entries = [json.loads(l) for l in
               open(fx["log_path"], encoding="utf-8").read().splitlines()
               if l.strip()]
    assert [e["seq"] for e in entries] == [1, 2, 3, 4, 5]
    # Sanity: the stale head's root recomputes over the first 3 entries
    # (it is a genuine historical head).
    leaves = [_EVV._mk_leaf_hash(_EVV._leaf_input(e))
              for e in entries[:3]]
    assert _EVV._recompute_root(leaves) == head3["merkle_root"]
    reason = ("shipped head covers only seq 1..3 (stale checkpoint); "
              "no inclusion bundle available")
    new_bundles = []
    for i in range(3):
        proof = gov.merkle.inclusion_proof(leaves, i)
        new_bundles.append({
            "seq": i + 1,
            "bundle": {"bundle_version": 1, "kind": "inclusion",
                       "entry": entries[i], "index": i,
                       "proof": [p.hex() for p in proof],
                       "tree_size": 3,
                       "merkle_root": head3["merkle_root"],
                       "checkpoint": head3},
            "unavailable_reason": None})
    for seq in (4, 5):
        new_bundles.append({"seq": seq, "bundle": None,
                            "unavailable_reason": reason})
    manifest = fx["manifest"]
    manifest["checkpoints"] = [head3]
    manifest["checkpoints_digest"] = hashlib.sha256(
        canonical([head3])).hexdigest()
    manifest["inclusion_bundles"] = new_bundles
    manifest["inclusion_coverage"] = {
        "entries": 5, "with_bundle": 3,
        "note": "stale-head demonstration: only seq 1..3 anchored"}
    # Honest payload: coverage flags for 4..5 flipped with reasons.
    payload = fx["payload"]
    for cov in payload["log_slice"]["coverage"]:
        if cov["seq"] in (4, 5):
            cov["has_bundle"] = False
            cov["unavailable_reason"] = reason
    probe = json.loads(json.dumps(payload))
    probe["bundle_meta"]["bundle_id"] = None
    payload["bundle_meta"]["bundle_id"] = (
        "EVB-" + hashlib.sha256(canonical(probe)).hexdigest()[:16])
    manifest["bundle_id"] = payload["bundle_meta"]["bundle_id"]
    manifest["export_sha256"] = hashlib.sha256(
        canonical(payload)).hexdigest()
    # Fresh receipt binding the new digest, then re-sign and assemble.
    _mint_receipt(fx)
    manifest["signing"]["signature_hex"] = OPERATOR.sign(
        EvidenceBundle.signed_body(manifest)).hex()
    _assemble_files(fx)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=0, pass_ids=("V8", "V9"),
                   text=("verdict: VERIFIED",
                         "3 inclusion bundles verified",
                         "2 reduced-coverage entries"))


# ---------------------------------------------------------------------------
# (F173) Inclusion-coverage downgrade without detection — break demos
# ---------------------------------------------------------------------------

def f1a_coverage_downgrade():
    """REGRESSION (F173 CLOSED): no-key attacker strips inclusion
    bundles from the manifest and adjusts the unsigned counts.

    Root cause (fixed): the operator signature's claim did not cover
    inclusion_bundles/inclusion_coverage. Post-fix the signed claim
    binds the per-entry presence vector and the coverage counts, so
    the strip fails V7 (signature) instead of sailing to VERIFIED.
    """
    fx = _assemble("f1a", log_signer=CK1)
    manifest = _read_json(fx["dir"], "manifest.json")
    n = 0
    for ib in manifest["inclusion_bundles"]:
        if ib["seq"] in (2, 4):
            ib["bundle"] = None
            ib["unavailable_reason"] = \
                "inclusion service unavailable (simulated strip)"
            n += 1
    assert n == 2
    manifest["inclusion_coverage"]["with_bundle"] -= n
    _rewrite(fx["dir"], "manifest.json", manifest)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    # The fix: unsigned alteration of the bound coverage fails V7.
    return _expect(code, out, exit_code=1, fail_ids=("V7",),
                   not_text=("verdict: VERIFIED",))


def f1b_receipt_bundle_strip():
    """REGRESSION (F173 CLOSED): no-key attacker strips the receipt's
    own inclusion bundle with a fabricated reason.

    Post-fix the transported receipt.json must be canonical-equal to
    the operator-signed manifest receipt binding (whose
    bundle-presence/reason rides in the signed claim), so the strip
    fails V12 — the export's chaining proof can no longer be silently
    dropped.
    """
    fx = _assemble("f1b", log_signer=CK1)
    receipt = _read_json(fx["dir"], "receipt.json")
    assert receipt["bundle"] is not None
    receipt["bundle"] = None
    receipt["unavailable_reason"] = "receipt inclusion bundle withheld"
    _rewrite(fx["dir"], "receipt.json", receipt)
    _redigest(fx["dir"])
    code, out, _ = _run(fx["dir"], *_pin_args())
    return _expect(code, out, exit_code=1, fail_ids=("V12",),
                   text=("does not match the operator-signed",
                         "manifest receipt binding"),
                   not_text=("verdict: VERIFIED",))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

# (name, kind, function, what it proves)
# kind: attack (must be CAUGHT) | control (must HOLD) | break (break-demo:
#   the filed finding's vulnerable behavior must reproduce) |
#   differential (both verifiers must AGREE).
CASES = [
    # (c) verifier differentials
    ("C1 verifier copies byte-identical", "control", drift_c1,
     "tools/evidence-verify == gov/evidence_verify.py"),
    ("C2 differential fuzz (16 hostile/diverse inputs)", "differential",
     c2_diff_fuzz,
     "both verifiers agree on exit code + stdout on every input"),
    ("C3 CLI usage-error parity", "differential", c3_cli_parity,
     "identical exit-3 behavior on both copies"),
    # benign baselines
    ("C4 genuine 2-of-3 threshold bundle", "control",
     c_threshold_genuine, "exit 0 VERIFIED"),
    # (a) threshold confusion
    ("A1 duplicate-key k-of-n (one key, two sigs)", "attack",
     a1_dupkey_threshold,
     "V8 fails: only 1/2 valid distinct signatures; weakened "
     "verifier fooled (exit 0)"),
    ("A2 checkpoint sig from wrong envelope key", "attack",
     a2_wrong_signer_key,
     "V8 fails: sig key_id does not match roster"),
    ("A3 roster key-ID aliasing", "attack", a3_roster_keyid_alias,
     "V8 fails: key id does not match its pubkey"),
    ("A4 roster substitution (no re-sign)", "attack",
     a4_roster_substitution,
     "V8 fails: roster_hash mismatch"),
    # (b) receipt replay
    ("B1 receipt replay across different content", "attack",
     b1_receipt_cross_content_replay,
     "V12 fails: foreign receipt does not bind this bundle"),
    ("B2 receipt replay, byte-identical content", "control",
     b2_receipt_same_content_replay,
     "exit 0 incl. V12b: replay only works when the receipt "
     "genuinely binds the content"),
    # (d) auditor-misleading bundles
    ("D1 claimed operator surfaced with disclaimer [F174]", "attack",
     d1_operator_id_invisible,
     "exit 0 VERIFIED and the authoritative-sounding operator_id is "
     "visible WITH its unverified-assertion disclaimer in both text "
     "and JSON"),
    ("D2 §7 honesty footer on all verdict paths", "control",
     d2_footer_present,
     "footer present on exit 0 / 2 / 1"),
    # (e) checkpoint binding gaps
    ("E1 stale head without re-sign", "attack", e1_stale_head_no_resign,
     "V8 fails: heads do not hash to the signed checkpoints_digest"),
    ("E2 stale head with re-sign (white-box)", "control",
     e2_stale_head_resigned,
     "exit 0 with EXPLICIT reduced coverage (3 anchored, 2 labeled)"),
    # (F173) coverage downgrade — regression probes (closed)
    ("F1a inclusion-bundle strip, no keys [F173]", "attack",
     f1a_coverage_downgrade,
     "exit 1 [FAIL] V7: unsigned strip of the bound presence/coverage "
     "breaks the operator signature"),
    ("F1b receipt-bundle strip, no keys [F173]", "attack",
     f1b_receipt_bundle_strip,
     "exit 1 [FAIL] V12: stripped receipt.json no longer matches the "
     "signed manifest receipt binding"),
]


def main():
    if WEAKENED:
        print("WEAKENED MODE: running against the deliberately broken "
              "verifier (duplicate-key threshold accepted)")
        print()
    caught = missed = broken = held = broken_controls = 0
    agreed = diverged = errors = 0
    failures = []
    for name, kind, fn, proves in CASES:
        try:
            problems = fn()
        except Exception as e:  # harness failure, never a silent pass
            errors += 1
            failures.append((name, ["ERROR: %r" % (e,)]))
            print("[ERROR]    %-46s %s" % (name, e))
            continue
        if not problems:
            if kind == "attack":
                caught += 1
                print("[CAUGHT]   %-46s %s" % (name, proves))
            elif kind == "control":
                held += 1
                print("[CONTROL]  %-46s %s" % (name, proves))
            elif kind == "break":
                broken += 1
                print("[BREAK]    %-46s %s" % (name, proves))
            else:
                agreed += 1
                print("[AGREE]    %-46s %s" % (name, proves))
        else:
            failures.append((name, problems))
            if kind == "attack":
                missed += 1
                print("[MISS]     %-46s %s" % (name, "; ".join(problems)))
            elif kind == "differential":
                diverged += 1
                print("[DIVERGE]  %-46s %s" % (name, "; ".join(problems)))
            elif kind == "break":
                # A break-demo that does NOT reproduce means the gap may
                # already be closed — loud, never silent.
                errors += 1
                print("[BREAK?]   %-46s %s" % (name, "; ".join(problems)))
            else:
                broken_controls += 1
                print("[BROKEN]   %-46s %s" % (name, "; ".join(problems)))
    print()
    print("CAUGHT=%d MISS=%d BREAK=%d CONTROL=%d BROKEN=%d AGREE=%d "
          "DIVERGE=%d ERROR=%d"
          % (caught, missed, broken, held, broken_controls, agreed,
             diverged, errors))
    if failures:
        print("failures:")
        for name, problems in failures:
            for p in problems:
                print("  - %s: %s" % (name, p))
        return 1
    if broken_controls or missed or diverged or errors:
        return 1
    if broken:
        print("break-demos reproduced as filed — see evals/FINDINGS.md; "
              "these probes are the red-first pins for the fix lane")
    print("adversarial battery: all attacks caught, all controls hold, "
          "no verifier divergence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
