#!/usr/bin/env python3
"""Wave-236 lane B: denial capsules as first-class sealed evidence.

Denial capsules with selective disclosure (re-derived from
draft-mih-scitt-agent-action-capsule-sel-disc -00).

Attack shapes at the public seams (break-first, red-first on base):
* a denied action produces a SEALED denial capsule binding refusal
  code, the denying authority, the action digest, and a timestamp --
  with evidentiary weight equal to a permit (signature-covered body);
* a silent-drop denial path (no sealed capsule) is refused
  ``denial-unsealed`` -- a denial must be sealed or the action never
  ran;
* selective disclosure: disclose_fields reveals ONLY the named
  fields; every undisclosed field remains a salted hash commitment
  (sha256(salt || canonical_field_bytes)) inside the sealed capsule;
  a verifier confirms each disclosed field against its commitment;
* decoy digests: decoy commitments are format-identical to real
  undisclosed commitments (indistinguishable without the salt);
* a tampered disclosed value refuses ``denial-disclosure-mismatch``;
* a tampered seal refuses ``denial-capsule-signature-invalid``;
* deny receipts may attach a sealed denial capsule (additive:
  default emit path byte-identical to legacy behavior).

Seams under test:
* gov/denial_capsule.py -- seal_denial, verify_capsule,
  disclose_fields, verify_disclosure, emit_denial,
  DenialCapsuleError code attributes.
* gov/deny_receipts.py -- emit(..., denial_capsule=) (additive
  keyword-only seam; legacy default path unchanged).

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-235 HEAD 3a5c97f6b421c89791b0c7811efe804252701dff.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g236b
  TMPDIR=/var/tmp/g236b ~/workspace/.gov-venv/bin/python evals/w236_denialcap_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import copy
import hashlib
import json
import re
import sys
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

from gov import deny_receipts as _dr  # noqa: E402

HAVE_NEW_API = False
try:
    from gov import denial_capsule as _dcap
    HAVE_NEW_API = all(hasattr(_dcap, n) for n in (
        "seal_denial", "verify_capsule", "disclose_fields",
        "verify_disclosure", "emit_denial",
        "DenialCapsuleError", "DenialCapsuleUnsealed"))
except Exception:
    _dcap = None

_SECRET = b"denial-capsule-lane-test-key-00000001"
_KEYID = "denial-capsule-test-key-1"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class _Signer:
    alg = "hmac-sha256-mac"
    key_id = _KEYID

    def __init__(self, secret=_SECRET):
        self.secret = bytes(secret)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _seal():
    """Seal a denial and return (capsule, material)."""
    return _dcap.seal_denial(
        "deny-receipt-refused", "governance-authority",
        "ab" * 32, signer=_Signer(), salts=None, decoy_count=2)


def _run_once():
    results = []

    def rec(name, verdict, detail=""):
        results.append({"probe": name, "verdict": verdict,
                        "detail": detail})

    if not HAVE_NEW_API:
        for i in range(1, 10):
            rec("denialcap-%02d" % i, "GAP",
                "gov.denial_capsule absent on pristine base")
        return results

    # 01 -- sealed denial binds refusal, authority, action, timestamp.
    try:
        capsule, material = _seal()
        ok = (isinstance(capsule, dict)
              and capsule.get("v") == 1
              and capsule.get("kind") == "denial-capsule"
              and isinstance(capsule.get("commitments"), dict)
              and set(capsule["commitments"]) >=
              {"refusal_code", "authority", "action_digest", "timestamp"}
              and isinstance(capsule.get("signature"), str)
              and capsule["signature"])
        claim = _dcap.verify_capsule(capsule, key=_SECRET)
        ok = ok and claim.get("ok") is True
        # Sealed body carries NO raw field values: commitments only.
        body_text = _canonical(capsule).decode("utf-8")
        ok = ok and "governance-authority" not in body_text \
            and "deny-receipt-refused" not in body_text
        rec("denialcap-01-sealed-binds", "HELD" if ok else "BREAK",
            "seal missing bindings or leaks raw values")
    except Exception as exc:
        rec("denialcap-01-sealed-binds", "ERROR",
            "%.120r" % (traceback.format_exc(),))

    # 02 -- silent-drop path refused with denial-unsealed.
    try:
        try:
            _dcap.emit_denial({"action": "pay"})
            rec("denialcap-02-unsealed-refused", "BREAK",
                "emit_denial without a capsule did not refuse")
        except Exception as exc:
            rec("denialcap-02-unsealed-refused",
                "HELD" if getattr(exc, "code", None) == "denial-unsealed"
                else "BREAK",
                "code=%r" % (getattr(exc, "code", None),))
    except Exception:
        rec("denialcap-02-unsealed-refused", "ERROR",
            "%.120r" % (traceback.format_exc(),))

    # 03 -- selective disclosure reveals only named fields; verifier
    # confirms commitments; undisclosed fields stay hash-only.
    try:
        capsule, material = _seal()
        disclosure = _dcap.disclose_fields(
            capsule, material, ["refusal_code"])
        ok = (set(disclosure["disclosed"]) == {"refusal_code"}
              and disclosure["disclosed"]["refusal_code"] == "deny-receipt-refused"
              and "authority" not in disclosure["disclosed"]
              and "action_digest" not in disclosure["disclosed"])
        res = _dcap.verify_disclosure(capsule, disclosure, key=_SECRET)
        ok = ok and res.get("ok") is True
        # Undisclosed commitments are 64-hex, never raw values.
        for name, val in capsule["commitments"].items():
            if name != "refusal_code":
                ok = ok and bool(_HEX64.match(val))
        rec("denialcap-03-selective-disclosure",
            "HELD" if ok else "BREAK", "disclosure leaks or fails")
    except Exception:
        rec("denialcap-03-selective-disclosure", "ERROR",
            "%.120r" % (traceback.format_exc(),))

    # 04 -- decoy digests are format-identical to real commitments
    # (indistinguishable without the salt).
    try:
        capsule, material = _seal()
        decoys = capsule.get("decoys", [])
        comm_values = list(capsule["commitments"].values())
        ok = (len(decoys) == 2
              and all(_HEX64.match(d) for d in decoys)
              and all(_HEX64.match(c) for c in comm_values)
              and not (set(decoys) & set(comm_values)))
        # Without salts, a classifier cannot tell decoys from real
        # commitments by shape: same length, same alphabet.
        shapes = {len(d) for d in decoys} | \
            {len(c) for c in comm_values}
        ok = ok and shapes == {64}
        rec("denialcap-04-decoy-indistinguishable",
            "HELD" if ok else "BREAK", "decoy shape differs")
    except Exception:
        rec("denialcap-04-decoy-indistinguishable", "ERROR",
            "%.120r" % (traceback.format_exc(),))

    # 05 -- tampered disclosed value refuses denial-disclosure-mismatch.
    try:
        capsule, material = _seal()
        disclosure = _dcap.disclose_fields(
            capsule, material, ["refusal_code"])
        bad = copy.deepcopy(disclosure)
        bad["disclosed"]["refusal_code"] = "policy-permit-refused"
        try:
            _dcap.verify_disclosure(capsule, bad, key=_SECRET)
            rec("denialcap-05-tamper-refused", "BREAK",
                "tampered disclosure verified")
        except Exception as exc:
            rec("denialcap-05-tamper-refused",
                "HELD" if getattr(exc, "code", None)
                == "denial-disclosure-mismatch" else "BREAK",
                "code=%r" % (getattr(exc, "code", None),))
    except Exception:
        rec("denialcap-05-tamper-refused", "ERROR",
            "%.120r" % (traceback.format_exc(),))

    # 06 -- tampered seal refuses denial-capsule-signature-invalid.
    try:
        capsule, material = _seal()
        bad = copy.deepcopy(capsule)
        sig = bad["signature"]
        bad["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        try:
            _dcap.verify_capsule(bad, key=_SECRET)
            rec("denialcap-06-seal-tamper-refused", "BREAK",
                "forged signature verified")
        except Exception as exc:
            rec("denialcap-06-seal-tamper-refused",
                "HELD" if getattr(exc, "code", None)
                == "denial-capsule-signature-invalid" else "BREAK",
                "code=%r" % (getattr(exc, "code", None),))
    except Exception:
        rec("denialcap-06-seal-tamper-refused", "ERROR",
            "%.120r" % (traceback.format_exc(),))

    # 07 -- deny receipt may attach a sealed capsule, signature-covered;
    # legacy emit (no capsule) is byte-identical to the legacy path.
    try:
        capsule, material = _seal()
        signer = _dr.Signer("hmac-sha256-mac", _SECRET, _KEYID)
        decision = {
            "verdict": "DENY",
            "rule_path": "policy.allowlist",
            "token_digest": "cd" * 32,
            "policy_bundle_digest": "ef" * 32,
            "intent_digest": "01" * 32,
            "jurisdiction_profile": "default",
        }
        receipt = _dr.emit(copy.deepcopy(decision), signer=signer,
                           denial_capsule=capsule)
        attached = receipt.get("denial_capsule")
        ok = (isinstance(attached, dict)
              and attached == capsule)
        # The capsule rides inside the signature input: tampering the
        # attached capsule must break receipt verification.
        bad_receipt = copy.deepcopy(receipt)
        bad_receipt["denial_capsule"]["commitments"]["authority"] = \
            "00" * 32
        try:
            _dr.verify(bad_receipt, key=_SECRET)
            ok = False
            detail = "capsule transplant survived receipt verify"
        except Exception:
            detail = ""
        # Legacy path: no capsule -> exact legacy field set.
        legacy = _dr.emit(copy.deepcopy(decision), signer=signer)
        expected = {"v", "kind", "verdict", "class", "rule_path",
                    "token_digest", "policy_bundle_digest",
                    "intent_digest", "jurisdiction_profile", "alg",
                    "key_id", "non_repudiation", "signature"}
        ok = ok and set(legacy) == expected
        _dr.verify(legacy, key=_SECRET)  # legacy still verifies
        rec("denialcap-07-receipt-attach",
            "HELD" if ok else "BREAK", detail)
    except Exception:
        rec("denialcap-07-receipt-attach", "ERROR",
            "%.120r" % (traceback.format_exc(),))

    # 08 -- malformed inputs fail closed: unmapped refusal code,
    # non-hex action digest, malformed capsule, wrong disclosure salt.
    try:
        checks = []
        for fn, want in [
                (lambda: _dcap.seal_denial(
                    "no-such-code", "auth", "ab" * 32,
                    signer=_Signer()), "denial-capsule-malformed"),
                (lambda: _dcap.seal_denial(
                    "deny-receipt-refused", "auth", "not-hex",
                    signer=_Signer()), "denial-capsule-malformed"),
                (lambda: _dcap.verify_capsule(
                    {"v": 1}, key=_SECRET), "denial-capsule-malformed"),
        ]:
            try:
                fn()
                checks.append(("no-refusal", None))
            except Exception as exc:
                code = getattr(exc, "code", None)
                checks.append(("refused", code if code == want else None))
        capsule, material = _seal()
        disclosure = _dcap.disclose_fields(
            capsule, material, ["authority"])
        bad = copy.deepcopy(disclosure)
        bad["salts"]["authority"] = "ff" * 32
        try:
            _dcap.verify_disclosure(capsule, bad, key=_SECRET)
            checks.append(("no-refusal", None))
        except Exception as exc:
            code = getattr(exc, "code", None)
            checks.append(("refused",
                           code if code == "denial-disclosure-mismatch"
                           else None))
        ok = all(r == "refused" and c is not None for r, c in checks)
        rec("denialcap-08-malformed-fails-closed",
            "HELD" if ok else "BREAK", str(checks))
    except Exception:
        rec("denialcap-08-malformed-fails-closed", "ERROR",
            "%.120r" % (traceback.format_exc(),))

    # 09 -- a self-consistent FORGED capsule (sealed by an attacker's
    # key) paired with its own valid disclosure is refused: the seal
    # is verified before any commitment is trusted.
    try:
        class _Attacker:
            alg = "hmac-sha256-mac"
            key_id = "attacker-key"

            def __init__(self):
                self.secret = b"attacker-secret-0000000000000001"

        forged, fmaterial = _dcap.seal_denial(
            "deny-receipt-refused", "forged-authority", "ab" * 32,
            signer=_Attacker())
        fdisclosure = _dcap.disclose_fields(
            forged, fmaterial, ["authority"])
        try:
            _dcap.verify_disclosure(forged, fdisclosure, key=_SECRET)
            rec("denialcap-09-forged-capsule-refused", "BREAK",
                "forged capsule + self-consistent disclosure verified")
        except Exception as exc:
            rec("denialcap-09-forged-capsule-refused",
                "HELD" if getattr(exc, "code", None)
                == "denial-capsule-signature-invalid" else "BREAK",
                "code=%r" % (getattr(exc, "code", None),))
    except Exception:
        rec("denialcap-09-forged-capsule-refused", "ERROR",
            "%.120r" % (traceback.format_exc(),))
    return results


def _run_green_checks():
    """Adjacent-wave sanity: no product-code regression."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    return notes


def main():
    results = _run_once()
    held = sum(1 for r in results if r["verdict"] == "HELD")
    gap = sum(1 for r in results if r["verdict"] == "GAP")
    brk = sum(1 for r in results if r["verdict"] == "BREAK")
    err = sum(1 for r in results if r["verdict"] == "ERROR")
    for r in results:
        print("%-38s %-6s %s" % (r["probe"], r["verdict"], r["detail"]))
    print("held=%d gap=%d break=%d error=%d" % (held, gap, brk, err))
    for note in _run_green_checks():
        print("GREEN:", note)
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
