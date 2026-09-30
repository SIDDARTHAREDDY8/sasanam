#!/usr/bin/env python3
"""Wave-230 lane A: signed denial receipts as first-class outcomes.

ADAPT (re-derived prose; nothing copied) of the spt-txn §6 signed
denial-receipt pattern: every decision -- PERMIT and DENY alike --
emits a signed receipt {verdict, class ok|violation|unavailable,
rule path, token hash, policy-bundle hash, intent digest,
jurisdiction profile} over a domain-separated signature input,
hashes-only (no PII).

Seams under test:
* gov/deny_receipts.py -- emit(decision_record, signer) refuses
  ``taxonomy-receipt-missing`` when the decision lacks receipt
  evidence; verify(receipt, key) re-derives the domain-separated
  input and refuses ``deny-receipt-signature-invalid`` on tamper;
  an unavailable (outage) decision carries class=unavailable and a
  permit verdict paired with an unavailable class refuses
  ``deny-receipt-unavailable-as-permit`` (outages never default to
  permit); receipt evidence is digest-shaped hex64 only
  (hashes-only, no PII); receipts are keyed by an explicit signer
  (dedicated receipt key, never blindly the audit-log key);
  receipts are evidence, never authority
  (``deny-receipt-not-authorization``).
* decision-packet composition: keyword-only ``deny_receipt`` kwarg
  attaches the receipt as digest-linked, signature-covered evidence;
  ``None`` (default) builds a legacy packet byte-identical to one
  without the kwarg.

Attack shapes: forge a receipt; flip a receipt field; pair a
permit verdict with an unavailable class; omit intent evidence;
smuggle a raw PII string through a digest field; cross-verify under
the wrong key; offer the receipt as authority.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-229 HEAD
eb3ed254e5afb268dac2d46bdcca1f9e54f96b3b.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g230a
  TMPDIR=/var/tmp/g230a ~/workspace/.gov-venv/bin/python evals/w230_deny_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import subprocess
import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import deny_receipts as _dr
    from gov import alg_registry as _ar
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

PROBE_NAMES = [
    "permit-receipt-verifies",
    "deny-receipt-verifies",
    "unavailable-class-honest",
    "tampered-receipt-refused",
    "missing-evidence-refused",
    "hashes-only-no-pii",
    "receipt-keyed-per-log-key",
    "malformed-receipt-refused",
    "receipt-not-authority",
    "packet-composition",
]


def _refuses(fn, code):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None)
        if got == code:
            return True
        raise AssertionError(
            "expected code %r, got %r (%r)" % (code, got, exc))
    return False


def _signer(alg, key_id="receipt-log-key-1"):
    reg = _ar.default_registry()
    secret, pub = reg.keygen(alg)
    return _dr.Signer(alg=alg, secret=secret, key_id=key_id), pub


def _permit_decision():
    return {
        "verdict": "permit",
        "rule_path": "policy/default/allow-public-read",
        "token_digest": hashlib.sha256(b"mandate-1").hexdigest(),
        "policy_bundle_digest": hashlib.sha256(b"bundle-1").hexdigest(),
        "intent_digest": hashlib.sha256(b"intent-1").hexdigest(),
        "jurisdiction_profile": "default",
    }


def _deny_decision():
    d = _permit_decision()
    d["verdict"] = "deny"
    d["rule_path"] = "policy/default/deny-write"
    return d


def _outage_decision():
    d = _deny_decision()
    d["outage"] = True
    return d


def _p01_permit():
    signer, pub = _signer(_ar.ED25519_RFC8032)
    rec = _dr.emit(_permit_decision(), signer=signer)
    out = _dr.verify(rec, key=pub)
    if not out.get("ok"):
        return "BREAK", "permit receipt did not verify: %r" % out
    if out.get("verdict") != "PERMIT" or out.get("class") != "ok":
        return "BREAK", "permit receipt mislabeled: %r" % out
    if not out.get("non_repudiation"):
        return "BREAK", "Ed25519 permit receipt not non-repudiation"
    return "HELD", "permit receipt verifies, class=ok, non-repudiation=True"


def _p02_deny():
    signer, pub = _signer(_ar.ED25519_RFC8032)
    rec = _dr.emit(_deny_decision(), signer=signer)
    out = _dr.verify(rec, key=pub)
    if not out.get("ok"):
        return "BREAK", "deny receipt did not verify: %r" % out
    if out.get("verdict") != "DENY" or out.get("class") != "violation":
        return "BREAK", "deny receipt mislabeled: %r" % out
    return "HELD", "deny receipt verifies, class=violation"


def _p03_unavailable():
    signer, pub = _signer(_ar.ED25519_RFC8032)
    rec = _dr.emit(_outage_decision(), signer=signer)
    out = _dr.verify(rec, key=pub)
    if out.get("class") != "unavailable":
        return "BREAK", "outage receipt class not unavailable: %r" % out
    # An outage must never default to permit: permit verdict with an
    # unavailable class refuses at emission.
    bad = _permit_decision()
    bad["outage"] = True
    ok = _refuses(lambda: _dr.emit(bad, signer=signer),
                  "deny-receipt-unavailable-as-permit")
    if not ok:
        return "BREAK", "permit+unavailable did not refuse permit-classification"
    return "HELD", "outage receipt class=unavailable; permit+outage refused"


def _p04_tampered():
    signer, pub = _signer(_ar.ED25519_RFC8032)
    rec = _dr.emit(_deny_decision(), signer=signer)
    tampered = dict(rec)
    tampered["rule_path"] = "policy/tampered/allow-all"
    ok = _refuses(lambda: _dr.verify(tampered, key=pub),
                  "deny-receipt-signature-invalid")
    if not ok:
        return "BREAK", "field-flipped receipt did not refuse signature-invalid"
    # Also flip the signature bytes themselves.
    tampered2 = dict(rec)
    sig = bytes.fromhex(tampered2["signature"])
    tampered2["signature"] = (bytes([sig[0] ^ 0xFF]) + sig[1:]).hex()
    ok2 = _refuses(lambda: _dr.verify(tampered2, key=pub),
                   "deny-receipt-signature-invalid")
    return (("HELD", "tampered receipts refuse deny-receipt-signature-invalid")
            if ok2 else ("BREAK", "signature-byte flip not refused"))


def _p05_missing_evidence():
    signer, _pub = _signer(_ar.ED25519_RFC8032)
    thin = _deny_decision()
    del thin["intent_digest"]
    ok = _refuses(lambda: _dr.emit(thin, signer=signer),
                  "taxonomy-receipt-missing")
    return (("HELD", "evidence-thin decision refuses taxonomy-receipt-missing")
            if ok else ("BREAK", "thin decision emitted a receipt"))


def _p06_hashes_only():
    signer, pub = _signer(_ar.ED25519_RFC8032)
    pii = _deny_decision()
    pii["token_digest"] = "alice.ssn@example.com"  # raw PII, not a digest
    ok = _refuses(lambda: _dr.emit(pii, signer=signer),
                  "taxonomy-receipt-missing")
    if not ok:
        return "BREAK", "raw PII in a digest field was accepted"
    rec = _dr.emit(_permit_decision(), signer=signer)
    blob = json.dumps(rec, sort_keys=True)
    if "alice.ssn" in blob or "ssn" in blob:
        return "BREAK", "PII-shaped string present in receipt bytes"
    return "HELD", "digest fields digest-shaped only; no PII in receipts"


def _p07_per_log_key():
    from gov.ed25519 import publickey as _pub_from_seed
    seed1 = bytes(range(32))
    seed2 = bytes(32 - i - 1 for i in range(32))
    s1 = _dr.Signer(alg=_ar.ED25519_RFC8032, secret=seed1, key_id="receipt-log-A")
    s2 = _dr.Signer(alg=_ar.ED25519_RFC8032, secret=seed2, key_id="receipt-log-B")
    rec = _dr.emit(_deny_decision(), signer=s1)
    if rec.get("key_id") != "receipt-log-A":
        return "BREAK", "receipt did not carry the signer key_id: %r" % rec
    out1 = _dr.verify(rec, key=_pub_from_seed(seed1))
    if not out1.get("ok"):
        return "BREAK", "own-key verify failed: %r" % out1
    ok = _refuses(lambda: _dr.verify(rec, key=_pub_from_seed(seed2)),
                  "deny-receipt-signature-invalid")
    return (("HELD", "receipts keyed per signer; cross-key verify refused")
            if ok else ("BREAK", "cross-key verify did not refuse"))


def _p08_malformed():
    signer, pub = _signer(_ar.ED25519_RFC8032)
    rec = _dr.emit(_deny_decision(), signer=signer)
    for bad in ("not-a-dict", {}, {"kind": "deny-receipt"}):
        ok = _refuses(lambda b=bad: _dr.verify(b, key=pub),
                      "deny-receipt-malformed")
        if not ok:
            return "BREAK", "malformed receipt not refused: %r" % (bad,)
    return "HELD", "malformed receipts refuse deny-receipt-malformed"


def _p09_not_authority():
    signer, _pub = _signer(_ar.ED25519_RFC8032)
    rec = _dr.emit(_permit_decision(), signer=signer)
    ok = _refuses(lambda: _dr.receipt_as_authority(rec),
                  "deny-receipt-not-authorization")
    return (("HELD", "authority-shaped use refuses deny-receipt-not-authorization")
            if ok else ("BREAK", "receipt usable as authority"))


def _p10_packet_composition():
    from gov import decision_packet as _dp
    from gov import decision_bom as _bom_mod
    signer, pub = _signer(_ar.ED25519_RFC8032)
    rec = _dr.emit(_deny_decision(), signer=signer)
    ev = _dr.receipt_evidence(rec)
    issued = "2026-09-30T00:00:00+00:00"
    bom = _bom_mod.build_bom(
        policy_id="default", policy_version="unversioned",
        policy_digest="ab" * 32, evidence_head_digest="GENESIS",
        principal={"agent_id": None, "role": None,
                   "principal": None, "run_id": None})
    kwargs = dict(decision="deny", boundary_declared=False,
                  bill_of_materials=bom, issued_at=issued,
                  policy_id="default", policy_version="unversioned")
    legacy = _dp.build_decision_packet(**kwargs)
    with_r = _dp.build_decision_packet(deny_receipt=rec, **kwargs)
    if legacy == with_r:
        return "BREAK", "packet unchanged when deny_receipt attached"
    sec = with_r.get("deny_receipt_evidence")
    if not isinstance(sec, dict) or sec.get("value", {}).get(
            "digest") != ev["digest"]:
        return "BREAK", "packet section not digest-linked evidence: %r" % sec
    # Legacy byte-identity: two builds without the kwarg must match.
    legacy2 = _dp.build_decision_packet(**kwargs)
    if json.dumps(legacy, sort_keys=True) != json.dumps(
            legacy2, sort_keys=True):
        return "BREAK", "legacy packets not byte-identical"
    # The packet signature covers the evidence section: swap the
    # digest and the signature must break.
    signed = _dp.sign_packet(with_r, bytes.fromhex("22" * 32))
    good_ok, good_reason = _dp.verify_decision_packet(signed)
    if not good_ok:
        return "BREAK", "honest signed packet did not verify: %r" % (
            good_reason,)
    bad = json.loads(json.dumps(signed))
    bad["deny_receipt_evidence"]["value"]["digest"] = "ff" * 32
    bad_ok, _bad_reason = _dp.verify_decision_packet(bad)
    if bad_ok:
        return "BREAK", "swapped receipt digest passed packet verification"
    # The receipt evidence digest must agree with the receipt itself.
    if ev["digest"] != _dr.receipt_evidence(rec)["digest"]:
        return "BREAK", "receipt evidence digest not stable"
    return "HELD", "receipt attached as digest-linked signature-covered evidence"


_PROBES = [
    _p01_permit, _p02_deny, _p03_unavailable, _p04_tampered,
    _p05_missing_evidence, _p06_hashes_only, _p07_per_log_key,
    _p08_malformed, _p09_not_authority, _p10_packet_composition,
]


def _run_once():
    results = []
    for name, probe in zip(PROBE_NAMES, _PROBES):
        if not HAVE_MODULE:
            results.append((name, "GAP",
                            "gov/deny_receipts.py absent (pristine red)"))
            continue
        t0 = time.time()
        try:
            verdict, detail = probe()
        except Exception as exc:  # noqa: BLE001
            verdict = "ERROR"
            detail = "%r %s" % (exc, traceback.format_exc(limit=2))
        dt = time.time() - t0
        results.append((name, verdict, "%s (%.2fs)" % (detail, dt)))
    return results


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_decision_packet.py",
                 "tests/test_decision_codes.py"):
        path = os.path.join(REPO, unit)
        if not os.path.exists(path):
            notes.append((unit, "SKIP", "unit test not present"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", unit.replace("/", ".")[:-3]],
            env=env, cwd=REPO,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600)
        out = proc.stdout.decode("utf-8", "replace")
        if proc.returncode == 0:
            notes.append((unit, "PASS", "adjacent unit suite green"))
        else:
            tail = out[-400:] if out else "no output"
            notes.append((unit, "FAIL", tail))
    return notes


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v, _d in first] == [v for _, v, _d in second]
    green = _run_green_checks()
    held = sum(1 for _, v, _d in first if v == "HELD")
    gap = sum(1 for _, v, _d in first if v == "GAP")
    brk = sum(1 for _, v, _d in first if v == "BREAK")
    err = sum(1 for _, v, _d in first if v == "ERROR")
    print("w230 deny-receipt probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "of %d; determinism %s"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in first:
        print("  [%s] %s %s" % (verdict, name, detail))
    for name, status, detail in green:
        print("  [%s] %s %s" % (status, name, detail))
    bad = [n for n, v, _d in first if v in ("BREAK", "ERROR")]
    sys.exit(1 if bad or not det_ok else 0)


if __name__ == "__main__":
    main()
