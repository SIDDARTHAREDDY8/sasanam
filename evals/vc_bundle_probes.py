#!/usr/bin/env python3
"""Wave-208 Lane A: red-first battery for VC-shaped evidence emission.

RED-FIRST: run against the PRISTINE tree first. Every probe imports
gov.vc_bundle -- absent there -- so the pristine run is uniformly ERROR
(missing public seams), and the fixed tree holds.

The W3C VC Data Model 2.0 ADAPT (wave-207 prospecting §1, data model
only): issuer -> holder -> verifier maps onto "sell evidence, not the
engine" (the auditor holds the bundle without the engine = the
verifier); the `evidence` property carries attestation reports and
break-battery results; conforming verifiers fail closed on
non-conforming documents; "verifiable" != "true" (narrow-claims
discipline carried in `claimBounds`); selective disclosure v1 is
redaction-by-copy re-issued with a new signature, honestly labeled as
NOT ECDSA-SD-2023.

Probes:

  vc_conforming_verifies   -- emit -> verify passes, detail names keys
  vc_missing_issuer_refused -- issuer deleted -> refused
  vc_malformed_proof_refused -- proof envelope smashed -> refused
  vc_tampered_claim_fails  -- flipped byte inside the envelope payload
                               dies on the signature path (authentication
                               precedes binding)
  vc_claim_swap_binding_fails
                            -- claim swapped with the envelope untouched
                               dies at payload binding, never verified
  vc_unknown_field_refused -- extra top-level field refused
  vc_expired_refused       -- validUntil in the past refused
  vc_not_yet_valid_refused -- validFrom in the future refused
  vc_foreign_cryptosuite_refused
                            -- proof claiming a W3C cryptosuite is
                               refused: honest non-claim of interop
  vc_redaction_reissues_not_sd
                            -- redact_copy produces a valid bundle whose
                               redactionNotice says redaction-by-copy
                               and explicitly disclaims ECDSA-SD-2023
  vc_redacted_verifies_under_holder
                            -- redacted bundle verifies under the
                               holder's key, NOT the original issuer's
  vc_verifiers_none_refused
                            -- verifiers=None refused as VCBundleError
                               (one fail-closed vocabulary)
  vc_proof_unknown_field_refused
                            -- unknown proof sub-fields refused
  vc_emit_threshold_honest  -- emit refuses threshold above 1 (seals
                               with one signer; no quorum overstatement)
  vc_non_json_native_refused
                            -- non-JSON-native claim values refused at
                               issuance (no str()-rendering ambiguity)
  vc_offline_verify        -- verification succeeds with sockets
                               blocked: no issuer interaction, no
                               @context resolution
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
sys.path.insert(0, REPO_ROOT)

_records = []


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md): this battery
# records PASS/FAIL/HELD/BROKEN/GAP/RED/GREEN/ERROR/SKIP; the
# canonical emission vocabulary is BREAK/HELD/ERROR/SKIP, mapped
# red-first (PASS/GREEN->HELD, FAIL/BROKEN/GAP/RED->BREAK). Probe
# logic, verdict computation and count code are untouched -- only
# the print loop below maps.
_VERDICT_MAP = {
    "PASS": "HELD", "HELD": "HELD", "GREEN": "HELD",
    "FAIL": "BREAK", "BROKEN": "BREAK", "GAP": "BREAK",
    "RED": "BREAK", "BREAK": "BREAK",
    "ERROR": "ERROR", "SKIP": "SKIP", "SKIPPED": "SKIP",
}


def _record(name, verdict, detail):
    _records.append((name, verdict, detail))


_SEED_ISSUER = bytes.fromhex("71" * 32)
_SEED_HOLDER = bytes.fromhex("72" * 32)


def _setup():
    from gov import vc_bundle as vcb
    from gov.signing import Ed25519Signer, Ed25519Verifier
    return vcb, Ed25519Signer, Ed25519Verifier


def _parties(vcb, Ed25519Signer, Ed25519Verifier):
    iss = Ed25519Signer(_SEED_ISSUER)
    hold = Ed25519Signer(_SEED_HOLDER)
    iv = Ed25519Verifier(iss.public_key)
    hv = Ed25519Verifier(hold.public_key)
    return iss, hold, iv, hv


def _emit(vcb, iss, **kw):
    args = dict(
        issuer="sasanam:issuer:test-1",
        subject_id="sha256:abcdef",
        subject_claims={"audit_log_tip": "sha256:010203",
                        "decision_packet": "sha256:040506"},
        evidence=[{"type": "AttestationReport",
                   "attester": "tpm-quote",
                   "verdict": "pass"},
                  {"type": "BreakBatteryResult",
                   "battery": "bundle_refresh",
                   "held": 10, "gap": 0}],
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2027-01-01T00:00:00Z",
        signer=iss,
    )
    args.update(kw)
    return vcb.emit_credential(**args)


def _run_once():
    vcb, Ed25519Signer, Ed25519Verifier = _setup()
    iss, hold, iv, hv = _parties(vcb, Ed25519Signer, Ed25519Verifier)

    # -- (a) conforming bundle verifies --------------------------------
    doc = _emit(vcb, iss)
    try:
        detail = vcb.verify_credential(doc, verifiers=[iv],
                                       now="2026-06-01T00:00:00Z")
        ok = (detail.get("valid") is True
              and iv.key_id in detail.get("key_ids", []))
    except Exception as exc:
        ok, detail = False, "%s: %s" % (type(exc).__name__, exc)
    _record("vc_conforming_verifies",
            "HELD" if ok else "BROKEN",
            "detail=%r" % (detail,))

    # -- (b) missing issuer refused ------------------------------------
    bad = dict(doc)
    del bad["issuer"]
    try:
        vcb.verify_credential(bad, verifiers=[iv],
                              now="2026-06-01T00:00:00Z")
        _record("vc_missing_issuer_refused", "BROKEN",
                "accepted a document with no issuer")
    except vcb.VCBundleError as exc:
        _record("vc_missing_issuer_refused",
                "HELD" if "issuer" in str(exc).lower() else "BROKEN",
                "refused: %s" % exc)

    # -- (c) malformed proof refused -----------------------------------
    bad = dict(doc)
    bad["proof"] = {"type": "SasanamDSSEProof",
                    "cryptosuite": vcb.CRYPTO_SUITE,
                    "envelope": {"payload": "!!not-base64!!",
                                 "payloadType": "x", "signatures": []}}
    try:
        vcb.verify_credential(bad, verifiers=[iv],
                              now="2026-06-01T00:00:00Z")
        _record("vc_malformed_proof_refused", "BROKEN",
                "accepted a malformed proof")
    except vcb.VCBundleError as exc:
        _record("vc_malformed_proof_refused", "HELD", "refused: %s" % exc)

    # -- (d) envelope payload tamper dies on the signature path ------
    # (authentication precedes binding: the signature is over the
    # envelope's own payload bytes, so tampering inside the envelope
    # breaks the signature before binding is even reached)
    import base64 as _b64
    import copy as _copy
    tampered = _copy.deepcopy(doc)
    env = tampered["proof"]["envelope"]
    raw = bytearray(_b64.b64decode(env["payload"]))
    raw[10] ^= 0xFF
    env["payload"] = _b64.b64encode(bytes(raw)).decode("ascii")
    try:
        vcb.verify_credential(tampered, verifiers=[iv],
                              now="2026-06-01T00:00:00Z")
        _record("vc_tampered_claim_fails", "BROKEN",
                "envelope-tampered credential verified")
    except vcb.VCBundleError as exc:
        sig_path = ("signature" in str(exc).lower()
                    or "threshold" in str(exc).lower())
        _record("vc_tampered_claim_fails",
                "HELD" if sig_path else "BROKEN",
                "refused on %s: %s"
                % ("signature path" if sig_path else "unexpected path",
                   exc))

    # -- (d2) claim swap with the envelope untouched dies at binding ---
    swapped = _copy.deepcopy(doc)
    swapped["credentialSubject"]["audit_log_tip"] = "sha256:ffff"
    try:
        vcb.verify_credential(swapped, verifiers=[iv],
                              now="2026-06-01T00:00:00Z")
        _record("vc_claim_swap_binding_fails", "BROKEN",
                "claim-swapped credential verified")
    except vcb.VCBundleError as exc:
        _record("vc_claim_swap_binding_fails",
                "HELD" if "binding" in str(exc).lower() else "BROKEN",
                "refused: %s" % exc)

    # -- (e) unknown top-level field refused ---------------------------
    bad = _copy.deepcopy(doc)
    bad["sneaky"] = "extra"
    try:
        vcb.verify_credential(bad, verifiers=[iv],
                              now="2026-06-01T00:00:00Z")
        _record("vc_unknown_field_refused", "BROKEN",
                "accepted an unknown top-level field")
    except vcb.VCBundleError as exc:
        _record("vc_unknown_field_refused", "HELD", "refused: %s" % exc)

    # -- (f) expired refused -------------------------------------------
    expired = _emit(vcb, iss, valid_from="2025-01-01T00:00:00Z",
                    valid_until="2025-06-01T00:00:00Z")
    try:
        vcb.verify_credential(expired, verifiers=[iv],
                              now="2026-06-01T00:00:00Z")
        _record("vc_expired_refused", "BROKEN", "accepted an expired doc")
    except vcb.VCBundleError as exc:
        _record("vc_expired_refused",
                "HELD" if "expir" in str(exc).lower() else "BROKEN",
                "refused: %s" % exc)

    # -- (g) not-yet-valid refused -------------------------------------
    future = _emit(vcb, iss, valid_from="2026-12-01T00:00:00Z",
                   valid_until="2027-06-01T00:00:00Z")
    try:
        vcb.verify_credential(future, verifiers=[iv],
                              now="2026-06-01T00:00:00Z")
        _record("vc_not_yet_valid_refused", "BROKEN",
                "accepted a not-yet-valid doc")
    except vcb.VCBundleError as exc:
        _record("vc_not_yet_valid_refused", "HELD", "refused: %s" % exc)

    # -- (h) foreign cryptosuite refused (honest non-interop) ----------
    foreign = _copy.deepcopy(doc)
    foreign["proof"]["cryptosuite"] = "ecdsa-sd-2023"
    try:
        vcb.verify_credential(foreign, verifiers=[iv],
                              now="2026-06-01T00:00:00Z")
        _record("vc_foreign_cryptosuite_refused", "BROKEN",
                "attempted to verify a foreign cryptosuite")
    except vcb.VCBundleError as exc:
        _record("vc_foreign_cryptosuite_refused",
                "HELD" if "cryptosuite" in str(exc).lower() else "BROKEN",
                "refused: %s" % exc)

    # -- (i) redaction re-issues, never claims selective disclosure ----
    red = vcb.redact_copy(
        doc,
        keep_subject_fields={"audit_log_tip"},
        keep_evidence_types={"AttestationReport"},
        holder_issuer="sasanam:holder:test-2",
        signer=hold,
        verifiers=[iv],
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2027-01-01T00:00:00Z",
        now="2026-06-01T00:00:00Z")
    notice = red.get("redactionNotice", {})
    method_ok = notice.get("method") == "redaction-by-copy"
    sd_disclaimed = ("NOT" in notice.get("note", "")
                     and "ecdsa-sd-2023" in notice.get("note", "").lower())
    dropped = ("decision_packet" not in red["credentialSubject"]
               and all(e["type"] != "BreakBatteryResult"
                       for e in red["evidence"]))
    kept = (red["credentialSubject"].get("audit_log_tip") == "sha256:010203"
            and any(e["type"] == "AttestationReport"
                    for e in red["evidence"]))
    derived = bool(notice.get("derivedFrom"))
    _record("vc_redaction_reissues_not_sd",
            "HELD" if (method_ok and sd_disclaimed and dropped and kept
                       and derived) else "BROKEN",
            "method_ok=%s sd_disclaimed=%s dropped=%s kept=%s derived=%s"
            % (method_ok, sd_disclaimed, dropped, kept, derived))

    # -- (j) redacted verifies under holder, not issuer ----------------
    try:
        rdetail = vcb.verify_credential(red, verifiers=[hv],
                                        now="2026-06-01T00:00:00Z")
        holder_ok = (rdetail.get("valid") is True
                     and hv.key_id in rdetail.get("key_ids", []))
    except Exception as exc:
        holder_ok, rdetail = False, "%s: %s" % (type(exc).__name__, exc)
    try:
        vcb.verify_credential(red, verifiers=[iv],
                              now="2026-06-01T00:00:00Z")
        issuer_rejected = False
    except vcb.VCBundleError:
        issuer_rejected = True
    _record("vc_redacted_verifies_under_holder",
            "HELD" if (holder_ok and issuer_rejected) else "BROKEN",
            "holder_ok=%s issuer_rejected=%s" % (holder_ok, issuer_rejected))

    # -- (k1) verifiers=None refused in the seam vocabulary ------------
    try:
        vcb.verify_credential(doc, verifiers=None,
                              now="2026-06-01T00:00:00Z")
        _record("vc_verifiers_none_refused", "BROKEN",
                "accepted verifiers=None")
    except vcb.VCBundleError as exc:
        _record("vc_verifiers_none_refused", "HELD", "refused: %s" % exc)

    # -- (k2) unknown proof sub-field refused ---------------------------
    bad = _copy.deepcopy(doc)
    bad["proof"]["evil"] = 1
    try:
        vcb.verify_credential(bad, verifiers=[iv],
                              now="2026-06-01T00:00:00Z")
        _record("vc_proof_unknown_field_refused", "BROKEN",
                "accepted an unknown proof sub-field")
    except vcb.VCBundleError as exc:
        _record("vc_proof_unknown_field_refused", "HELD",
                "refused: %s" % exc)

    # -- (k3) emit refuses quorum-overstating threshold -----------------
    try:
        _emit(vcb, iss, threshold=2)
        _record("vc_emit_threshold_honest", "BROKEN",
                "emitted a threshold-2 doc sealed by one signer")
    except vcb.VCBundleError as exc:
        _record("vc_emit_threshold_honest", "HELD", "refused: %s" % exc)

    # -- (k4) non-JSON-native claim refused at issuance ----------------
    class _O(object):
        def __str__(self):
            return "same"

    try:
        _emit(vcb, iss, subject_claims={"k": _O()})
        _record("vc_non_json_native_refused", "BROKEN",
                "emitted a non-JSON-native claim value")
    except vcb.VCBundleError as exc:
        _record("vc_non_json_native_refused", "HELD", "refused: %s" % exc)

    # -- (l) offline verify: sockets blocked ---------------------------
    import socket as _socket
    real_socket = _socket.socket

    def _blocked(*a, **k):
        raise AssertionError("network access attempted during verify")

    _socket.socket = _blocked
    try:
        odetail = vcb.verify_credential(doc, verifiers=[iv],
                                        now="2026-06-01T00:00:00Z")
        offline_ok = odetail.get("valid") is True
    except AssertionError as exc:
        offline_ok = False
        _record("vc_offline_verify", "BROKEN", str(exc))
    except Exception as exc:
        offline_ok = False
        _record("vc_offline_verify", "BROKEN",
                "%s: %s" % (type(exc).__name__, exc))
    finally:
        _socket.socket = real_socket
    if offline_ok or not any(n == "vc_offline_verify"
                             for n, _, _ in _records):
        _record("vc_offline_verify",
                "HELD" if offline_ok else "BROKEN",
                "verified with sockets blocked: %s" % offline_ok)


def _green_check_adjacent():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP", "depth-1 green check: skipped by convention "
                "(tests/test_vc_bundle.py standalone)")
    import subprocess  # noqa: E402
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="vcb-green-")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_vc_bundle", "tests.test_dsse_envelope", "-v"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=600)
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    return ("PASS" if r.returncode == 0 else "FAIL",
            "adjacent unit tests rc=%d %s" % (r.returncode, tail[0]))


def main():
    try:
        _run_once()
    except Exception as exc:  # pristine tree: module absent -> genuine red
        _record("vcb_setup", "ERROR", "%s: %s"
                % (type(exc).__name__, exc))
    second_start = len(_records)
    try:
        _run_once()
    except Exception as exc:
        _record("vcb_setup_run2", "ERROR", "%s: %s"
                % (type(exc).__name__, exc))
    first = _records[:second_start]
    second = _records[second_start:]
    det_ok = ([(n, v) for n, v, _ in first]
              == [(n, v) for n, v, _ in second])
    del _records[second_start:]
    _record("determinism",
            "PASS" if det_ok else "FAIL",
            "two in-process runs agree on all %d probes" % len(first)
            if det_ok else "MISMATCH between run 1 and run 2")
    gv, gd = _green_check_adjacent()
    _record("green_check_adjacent_units", gv, gd)
    print("== VC-shaped evidence emission battery ==")
    final = [(n, _VERDICT_MAP[v], d) for n, v, d in _records]
    probe_lines.emit(final)
    npass = sum(1 for _, v, _ in _records if v in ("PASS", "HELD"))
    nfail = sum(1 for _, v, _ in _records if v in ("FAIL", "BROKEN", "ERROR"))
    nskip = sum(1 for _, v, _ in _records if v == "SKIP")
    brk = sum(1 for _, v, _ in final if v == "BREAK")
    held = sum(1 for _, v, _ in final if v == "HELD")
    err = sum(1 for _, v, _ in final if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        final, brk, held, err)
    if not _coh_ok:
        print("coherence-WARNING: %s"
              % ("; ".join(_coh_diags)))
    print("%d BREAK / %d HELD / %d ERROR"
          % (brk, held, err))
    print("PASS=%d FAIL/ERROR=%d SKIP=%d" % (npass, nfail, nskip))
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
