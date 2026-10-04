#!/usr/bin/env python3
"""Wave-233 lane B: exactly-one-signature DSSE discipline + payloadType binding.

Attack shapes at the public seams (break-first, red-first on base):
* a zero-signature envelope must refuse ``dsse-envelope-no-signature``
  (currently refuses as malformed -- the shape is now named);
* a multi-signature envelope must refuse ``dsse-envelope-multi-signature``
  by default (silently verifying every listed signature is the F195
  envelope-shape discipline: ambiguity is a refusal, not acceptance);
* opting in via keyword-only ``expected_signatures=N`` (N>=1) verifies
  ALL N signatures -- one bad signature refuses, no partial acceptance;
* ``expected_type=...`` binding refuses ``dsse-payloadtype-mismatch``
  when the envelope's payloadType differs from the expected one;
* cross-module transplant: a decision-packet payloadType envelope
  presented to the denial-receipt verifier refuses
  ``dsse-envelope-transplant`` (verify functions bind the expected
  module domain, not just the type string);
* a wave-232 single-signature envelope still verifies by default --
  the discipline is narrowing, never widened, never broken.

Seams under test:
* gov/dsse_envelope.py -- verify_envelope(env, verify, expected_type,
  expected_domain, expected_signatures), register_envelope_domain;
* gov/deny_receipts.py -- verify binds expected_type + expected_domain
  "deny_receipts";
* gov/decision_packet.py -- verify_decision_packet binds expected_type +
  expected_domain "decision_packet".

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-232 HEAD 4ac83e2da908db2ec28b947bb8a2423f9dba20f6.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (new kwargs absent)
is expected GAP for probes 1-6; probe 7 is HELD on base (no-widening
guard) and must stay HELD.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g233b
  TMPDIR=/var/tmp/g233b ~/workspace/.gov-venv/bin/python evals/w233_dsseone_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import base64
import hashlib
import hmac
import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_NEW_API = False
try:
    from gov import dsse_envelope as _ds
    HAVE_NEW_API = all(hasattr(_ds, n) for n in (
        "verify_envelope", "register_envelope_domain"))
except ImportError:
    _ds = None

PROBE_NAMES = [
    "dsse-zero-signature-refused",
    "dsse-two-signatures-default-refused",
    "dsse-two-signatures-opt-in-verifies",
    "dsse-multi-signature-no-partial",
    "dsse-wrong-expected-type-refused",
    "dsse-cross-module-transplant-refused",
    "dsse-single-signature-still-verifies",
]

_PT_RECEIPT = "application/vnd.sasanam.denial-receipt+json"
_PT_PACKET = "application/vnd.sasanam.decision-packet+json"
_PAYLOAD = b'{"probe":"one-signature"}'


def _signer_cb(secret):
    def _sign(msg):
        return hmac.new(secret, msg, hashlib.sha256).digest()
    return _sign


def _verifier_cb(secret):
    def _verify(msg, sig):
        return hmac.compare_digest(
            hmac.new(secret, msg, hashlib.sha256).digest(), sig)
    return _verify


def _reason(exc):
    return getattr(exc, "reason", str(exc)) or ""


def _run_all():
    results = {}
    secret = hashlib.sha256(b"dsse-one-sig-probe-key").digest()
    sign = _signer_cb(secret)
    verify = _verifier_cb(secret)

    # 1. zero signatures -> dsse-envelope-no-signature -----------------
    try:
        env = _ds.envelope(_PAYLOAD, payload_type=_PT_RECEIPT, sign=sign)
        env = dict(env)
        env["signatures"] = []
        _ds.verify_envelope(env, verify=verify,
                            expect_payload_type=_PT_RECEIPT)
        results["dsse-zero-signature-refused"] = "BREAK: no refusal"
    except Exception as exc:
        reason = _reason(exc)
        if "dsse-envelope-no-signature" in reason:
            results["dsse-zero-signature-refused"] = "HELD"
        else:
            results["dsse-zero-signature-refused"] = \
                "GAP (feature absent: %r)" % (reason,)

    # 2. two signatures, default -> dsse-envelope-multi-signature ----
    try:
        env = _ds.envelope(_PAYLOAD, payload_type=_PT_RECEIPT, sign=sign)
        env = dict(env)
        sig2 = hmac.new(secret, _ds.pae(_PT_RECEIPT, _PAYLOAD),
                        hashlib.sha256).digest().hex()
        env["signatures"] = list(env["signatures"]) + [
            {"keyid": "k2", "sig": sig2}]
        _ds.verify_envelope(env, verify=verify,
                            expect_payload_type=_PT_RECEIPT)
        results["dsse-two-signatures-default-refused"] = \
            "GAP (feature absent: multi-sig accepted on base)"
    except Exception as exc:
        reason = _reason(exc)
        if "dsse-envelope-multi-signature" in reason:
            results["dsse-two-signatures-default-refused"] = "HELD"
        elif isinstance(exc, TypeError):
            results["dsse-two-signatures-default-refused"] = \
                "GAP (feature absent)"
        else:
            results["dsse-two-signatures-default-refused"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 3. two valid signatures, expected_signatures=2 -> verifies ------
    try:
        env = _ds.envelope(_PAYLOAD, payload_type=_PT_RECEIPT, sign=sign)
        env = dict(env)
        sig2 = hmac.new(secret, _ds.pae(_PT_RECEIPT, _PAYLOAD),
                        hashlib.sha256).digest().hex()
        env["signatures"] = list(env["signatures"]) + [
            {"keyid": "k2", "sig": sig2}]
        out = _ds.verify_envelope(env, verify=verify,
                                  expect_payload_type=_PT_RECEIPT,
                                  expected_signatures=2)
        if out.get("ok") is True:
            results["dsse-two-signatures-opt-in-verifies"] = "HELD"
        else:
            results["dsse-two-signatures-opt-in-verifies"] = \
                "BREAK: opt-in did not verify"
    except TypeError:
        results["dsse-two-signatures-opt-in-verifies"] = "GAP (feature absent)"
    except Exception:
        results["dsse-two-signatures-opt-in-verifies"] = \
            "BREAK\n" + traceback.format_exc(limit=2)

    # 4. opt-in but one signature bad -> refuses, no partial ----------
    try:
        env = _ds.envelope(_PAYLOAD, payload_type=_PT_RECEIPT, sign=sign)
        env = dict(env)
        env["signatures"] = list(env["signatures"]) + [
            {"keyid": "k2", "sig": "00" * 32}]
        _ds.verify_envelope(env, verify=verify,
                            expect_payload_type=_PT_RECEIPT,
                            expected_signatures=2)
        results["dsse-multi-signature-no-partial"] = \
            "BREAK: partially-signed envelope accepted"
    except TypeError:
        results["dsse-multi-signature-no-partial"] = "GAP (feature absent)"
    except Exception as exc:
        reason = _reason(exc)
        if "dsse-signature-invalid" in reason:
            results["dsse-multi-signature-no-partial"] = "HELD"
        else:
            results["dsse-multi-signature-no-partial"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 5. expected_type mismatch -> dsse-payloadtype-mismatch ---------
    try:
        env = _ds.envelope(_PAYLOAD, payload_type=_PT_RECEIPT, sign=sign)
        _ds.verify_envelope(env, verify=verify, expected_type=_PT_PACKET)
        results["dsse-wrong-expected-type-refused"] = "BREAK: no refusal"
    except TypeError:
        results["dsse-wrong-expected-type-refused"] = "GAP (feature absent)"
    except Exception as exc:
        reason = _reason(exc)
        if "dsse-payloadtype-mismatch" in reason:
            results["dsse-wrong-expected-type-refused"] = "HELD"
        else:
            results["dsse-wrong-expected-type-refused"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 6. cross-module transplant: packet envelope into receipt verify -
    try:
        from gov import deny_receipts as _dr
        from gov import decision_packet as _dp
        from gov import decision_bom as _bom
        bom = _bom.build_bom(
            policy_id="probe", policy_version="probe",
            policy_digest=hashlib.sha256(b"p").hexdigest(),
            evidence_head_digest="GENESIS", principal={})
        pkt = _dp.sign_packet(
            _dp.build_decision_packet(
                decision="allow", boundary_declared=False,
                policy_id="probe", policy_version="probe",
                evidence_head_digest="GENESIS",
                bill_of_materials=bom,
                issued_at="2026-09-30T00:00:00+00:00"),
            bytes(32), envelope=True)
        signer = _dr.Signer(alg="hmac-sha256-mac", secret=secret, key_id="k1")
        rec = {
            "verdict": "deny", "rule_path": "policy.reception.deny",
            "token_digest": hashlib.sha256(b"t").hexdigest(),
            "policy_bundle_digest": hashlib.sha256(b"p").hexdigest(),
            "intent_digest": hashlib.sha256(b"i").hexdigest(),
            "jurisdiction_profile": "profile-1",
        }
        receipt = _dr.emit(rec, signer=signer, envelope=_PT_RECEIPT)
        transplanted = dict(receipt)
        transplanted["envelope"] = pkt["envelope"]
        _dr.verify(transplanted, key=secret)
        results["dsse-cross-module-transplant-refused"] = \
            "BREAK: transplanted envelope accepted"
    except ImportError:
        results["dsse-cross-module-transplant-refused"] = \
            "ERROR: modules missing"
    except Exception as exc:
        reason = _reason(exc)
        if "dsse-envelope-transplant" in reason:
            results["dsse-cross-module-transplant-refused"] = "HELD"
        else:
            results["dsse-cross-module-transplant-refused"] = \
                "GAP (feature absent: %r)" % (reason,)
    # note: GAP here is genuine red, not a defect -- the base refuses
    # the transplant too (as dsse-payload-type-refused), but not with
    # the new transplant code.

    # 7. single-signature wave-232 envelope still verifies (no widen) -
    try:
        env = _ds.envelope(_PAYLOAD, payload_type=_PT_RECEIPT, sign=sign,
                           key_id="k1")
        out = _ds.verify_envelope(env, verify=verify,
                                  expect_payload_type=_PT_RECEIPT)
        if out.get("ok") is True and out.get("payload") == _PAYLOAD:
            results["dsse-single-signature-still-verifies"] = "HELD"
        else:
            results["dsse-single-signature-still-verifies"] = \
                "BREAK: single-sig envelope no longer verifies"
    except Exception:
        results["dsse-single-signature-still-verifies"] = \
            "BREAK\n" + traceback.format_exc(limit=2)

    return results


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md), red-first: GAP -> BREAK.
# The verdict token is the first word of the recorded verdict string; the
# original first line is kept verbatim as the note (evidence preserved), with
# any multi-line detail collapsed to its first line (" // "-joined).
# Unknown tokens fail closed as ERROR (loud, never silent). Raw results keep
# the battery's own vocabulary (count code and exit contract untouched); the
# mapping happens at emission.
_VERDICT_TOKEN_MAP = {"HELD": "HELD", "GAP": "BREAK", "BREAK": "BREAK",
                      "ERROR": "ERROR"}


def _split_row(name, v):
    first = probe_lines.first_line(v)
    tok = (first.split(":")[0].split() or [""])[0]
    mapped = _VERDICT_TOKEN_MAP.get(tok)
    if mapped is None:
        return {"probe_id": name, "verdict": "ERROR",
                "note": "unparseable verdict string: %r" % (first,)}
    _, _, rest = v.partition("\n")
    rest_first = probe_lines.first_line(rest).strip()
    note = first if not rest_first else first + " // " + rest_first
    return {"probe_id": name, "verdict": mapped, "note": note}

def main():
    t0 = time.time()
    if not HAVE_NEW_API:
        # Feature entirely absent: probes 1-6 GAP, probe 7 cannot run.
        rows = [{"probe_id": name, "verdict": "BREAK",
                 "note": "GAP (dsse one-sig API absent)"}
                for name in PROBE_NAMES[:-1]]
        rows.append({"probe_id": PROBE_NAMES[-1], "verdict": "BREAK",
                     "note": "GAP (module absent)"})
        probe_lines.emit_dicts(rows)
        print("%d BREAK / %d HELD / %d ERROR" % (len(PROBE_NAMES), 0, 0))
        return 2
    results = _run_all()
    held = sum(1 for v in results.values() if v == "HELD")
    gap = sum(1 for v in results.values() if v.startswith("GAP"))
    brk = sum(1 for v in results.values() if v.startswith("BREAK"))
    err = sum(1 for v in results.values() if v.startswith("ERROR"))
    rows = [_split_row(name, results.get(name, "ERROR: missing"))
            for name in PROBE_NAMES]
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        [(r["probe_id"], r["verdict"], r["note"]) for r in rows],
        brk + gap, held, err)
    probe_lines.emit_dicts(rows)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR (%.1fs)"
          % (brk + gap, held, err, time.time() - t0))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
