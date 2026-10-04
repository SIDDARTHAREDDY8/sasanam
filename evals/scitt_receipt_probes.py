#!/usr/bin/env python3
"""Wave-208 Lane B: red-first battery for SCITT-shaped receipts.

RED-FIRST: run against the PRISTINE tree first. Every probe imports
gov.scitt_receipt -- absent there -- so the pristine run is uniformly
ERROR (missing public seams), and the fixed tree holds.

The IETF SCITT (RFC 9943) architecture ADAPTED (wave-207 prospecting
§2): the evidence bundle is the **Signed Statement** (issuer identity
+ subject bound, DSSE/PAE-shaped -- NOT COSE, stdlib only); the
transparency service keeps an append-only verifiable record and
issues **Receipts** (TS-signed inclusion proofs); the TS checks a
**registration policy** before recording (admission enforcement --
the wave-205 Harbor lesson); the offline verifier is the **Auditor**
role. Narrow-claims discipline: a receipt proves registration
(authenticity, visibility, completeness of history) -- explicitly NOT
"correct, safe, or wise."

Probes:

  scitt_conforming_statement_recorded
      -- a conforming statement is recorded and a TS-signed receipt
         issued; the transparent statement carries exactly
         {statement, receipt, transparency_service}.
  scitt_policy_violation_refused
      -- unallowlisted issuer / denied subject / oversized statement
         are refused LOUDLY at register time with NO receipt.
  scitt_receipt_verifies_offline
      -- the Auditor verifies the whole transparent statement with
         only pinned public verifiers (no engine, no log).
  scitt_tampered_receipt_fails
      -- a bit-flipped receipt envelope and a swapped statement both
         fail offline verification (VerificationFailed, never a pass).
  scitt_equivocation_detected
      -- two conflicting statements for one subject are BOTH present
         (non-shredding) and the auditor flags the conflict
         (equivocation_detected).
  scitt_narrow_claims
      -- the receipt carries the honest evidentiary grade and the
         narrow-claim text; verify_transparent_statement surfaces it.
"""

import os
import sys

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


_SEED_ISSUER = bytes.fromhex("61" * 32)
_SEED_TS = bytes.fromhex("62" * 32)
_SEED_OTHER = bytes.fromhex("63" * 32)

_POLICY_NAME = "sasanam-anchor-admission"
_POLICY_VERSION = "v1"


def _setup():
    from gov import scitt_receipt as sr
    from gov.signing import Ed25519Signer, Ed25519Verifier
    return sr, Ed25519Signer, Ed25519Verifier


def _ts(sr, Ed25519Signer, Ed25519Verifier, policy=None, issuer_threshold=1):
    issuer_signer = Ed25519Signer(_SEED_ISSUER)
    ts_signer = Ed25519Signer(_SEED_TS)
    issuer_verifiers = [Ed25519Verifier(issuer_signer.public_key)]
    ts_verifiers = [Ed25519Verifier(ts_signer.public_key)]
    policy = policy or sr.RegistrationPolicy(
        name=_POLICY_NAME, version=_POLICY_VERSION,
        allowed_issuers=("issuer-a",),
        allowed_content_types=("application/octet-stream",),
        max_statement_bytes=65536)
    ts = sr.TransparencyService(
        identity="ts-hermetic-1", ts_signer=ts_signer,
        registration_policy=policy,
        signing_config={"log_url": "hermetic://scitt",
                        "log_id": "scitt-test-log",
                        "tsa_url": "hermetic://tsa"},
        issuer_verifiers=issuer_verifiers,
        issuer_threshold=issuer_threshold)
    return ts, issuer_signer, ts_signer, issuer_verifiers, ts_verifiers


def _statement(sr, issuer_signer, issuer="issuer-a", subject="agent/7",
               content=b"evidence-bytes", content_type="application/octet-stream",
               claims=None):
    return sr.issue_statement(
        issuer_signer, issuer=issuer, subject=subject, content=content,
        content_type=content_type, claims=claims)


def _verify_args(ts, issuer_verifiers, ts_verifiers, policy):
    return dict(issuer_verifiers=issuer_verifiers, ts_verifiers=ts_verifiers,
                ts_identity=ts.identity,
                pinned_policy_digest=policy.digest)


def _run_once():
    sr, Ed25519Signer, Ed25519Verifier = _setup()
    policy = sr.RegistrationPolicy(
        name=_POLICY_NAME, version=_POLICY_VERSION,
        allowed_issuers=("issuer-a",),
        allowed_content_types=("application/octet-stream",),
        max_statement_bytes=65536)
    ts, issuer_signer, ts_signer, issuer_verifiers, ts_verifiers = _ts(
        sr, Ed25519Signer, Ed25519Verifier, policy=policy)

    # -- (a) conforming statement recorded, receipt issued -----------------
    stmt = _statement(sr, issuer_signer)
    transparent = ts.register(stmt)
    ok_a = (set(transparent) == {"statement", "receipt",
                                 "transparency_service"}
            and transparent["transparency_service"] == "ts-hermetic-1")
    # the receipt is TS-signed over a body that binds this statement
    report = sr.verify_transparent_statement(
        transparent, **_verify_args(ts, issuer_verifiers, ts_verifiers,
                                   policy))
    ok_a = ok_a and report["verified"] and report["issuer"] == "issuer-a" \
        and report["subject"] == "agent/7"
    _record("scitt_conforming_statement_recorded",
            "HELD" if ok_a else "BROKEN",
            "keys=%r verified=%s" % (sorted(transparent), ok_a))

    # -- (b) registration-policy violations refused, no receipt ------------
    refused = 0
    other_signer = Ed25519Signer(_SEED_OTHER)
    bad = [
        _statement(sr, other_signer, issuer="issuer-b"),          # issuer not allowlisted
        _statement(sr, issuer_signer, subject="denied-zone/x"),    # placeholder, see below
        _statement(sr, issuer_signer,
                   claims={"pad": "x" * 70000}),                    # oversized
        _statement(sr, issuer_signer,
                   content_type="application/x-evil"),             # bad content type
    ]
    # rebuild the policy with a denied subject for the second case
    policy2 = sr.RegistrationPolicy(
        name=_POLICY_NAME, version=_POLICY_VERSION,
        allowed_issuers=("issuer-a",),
        denied_subjects=("denied-zone/x",),
        allowed_content_types=("application/octet-stream",),
        max_statement_bytes=65536)
    ts2, _, _, _, _ = _ts(sr, Ed25519Signer, Ed25519Verifier,
                          policy=policy2)
    targets = [(ts, bad[0]), (ts2, bad[1]), (ts, bad[2]), (ts, bad[3])]
    all_loud = True
    for target_ts, stmt_bad in targets:
        try:
            target_ts.register(stmt_bad)
            all_loud = False
            detail = "policy-violating statement was recorded"
            break
        except sr.RegistrationRefused:
            refused += 1
        except Exception as exc:  # noqa: BLE001 - wrong exception class is a break
            all_loud = False
            detail = "wrong exception %s: %s" % (type(exc).__name__, exc)
            break
    else:
        detail = "%d/4 violations refused loudly, no receipt" % refused
    _record("scitt_policy_violation_refused",
            "HELD" if (all_loud and refused == 4) else "BROKEN", detail)

    # -- (c) receipt verifies offline (Auditor role) -----------------------
    stmt_c = _statement(sr, issuer_signer, subject="agent/9",
                        content=b"offline-check")
    tc = ts.register(stmt_c)
    rep_c = sr.verify_transparent_statement(
        tc, **_verify_args(ts, issuer_verifiers, ts_verifiers, policy))
    ok_c = (rep_c["verified"] and rep_c["inclusion_verified"]
            and rep_c["policy_digest"] == policy.digest
            and rep_c["transparency_service"] == "ts-hermetic-1")
    _record("scitt_receipt_verifies_offline",
            "HELD" if ok_c else "BROKEN",
            "verified=%s inclusion=%s" % (rep_c.get("verified"),
                                          rep_c.get("inclusion_verified")))

    # -- (d) tampered receipt / swapped statement fail ---------------------
    stmt_d = _statement(sr, issuer_signer, subject="agent/10",
                        content=b"tamper-me")
    td = ts.register(stmt_d)
    # bit-flip inside the receipt envelope payload
    import base64 as _b64
    import copy as _copy
    tampered = _copy.deepcopy(td)
    payload = _b64.b64decode(tampered["receipt"]["payload"])
    flipped = bytes([payload[0] ^ 0x01]) + payload[1:]
    tampered["receipt"]["payload"] = _b64.b64encode(flipped).decode("ascii")
    fail1 = False
    try:
        sr.verify_transparent_statement(
            tampered, **_verify_args(ts, issuer_verifiers, ts_verifiers,
                                     policy))
    except sr.VerificationFailed:
        fail1 = True
    # statement swapped after receipt issuance
    stmt_d2 = _statement(sr, issuer_signer, subject="agent/10",
                         content=b"different-bytes")
    swapped = {"statement": stmt_d2, "receipt": td["receipt"],
               "transparency_service": td["transparency_service"]}
    fail2 = False
    try:
        sr.verify_transparent_statement(
            swapped, **_verify_args(ts, issuer_verifiers, ts_verifiers,
                                    policy))
    except sr.VerificationFailed:
        fail2 = True
    _record("scitt_tampered_receipt_fails",
            "HELD" if (fail1 and fail2) else "BROKEN",
            "flipped_receipt_failed=%s swapped_statement_failed=%s"
            % (fail1, fail2))

    # -- (e) two conflicting statements: both present, conflict flagged ----
    s1 = _statement(sr, issuer_signer, subject="agent/11",
                    content=b"verdict-allow")
    s2 = _statement(sr, issuer_signer, subject="agent/11",
                    content=b"verdict-deny")
    t1 = ts.register(s1)
    t2 = ts.register(s2)
    audit = sr.audit_subject(
        ts, "agent/11",
        **_verify_args(ts, issuer_verifiers, ts_verifiers, policy))
    ok_e = (audit["statement_count"] == 2
            and audit["verified"] == 2
            and audit["distinct_contents"] == 2
            and audit["equivocation_detected"] is True
            and len(ts.statements_for("agent/11")) == 2)
    _record("scitt_equivocation_detected",
            "HELD" if ok_e else "BROKEN",
            "statements=%s verified=%s distinct=%s equivocation=%s"
            % (audit.get("statement_count"), audit.get("verified"),
               audit.get("distinct_contents"),
               audit.get("equivocation_detected")))

    # -- (f) narrow claims are carried and surfaced -------------------------
    rep_f = sr.verify_transparent_statement(
        t1, **_verify_args(ts, issuer_verifiers, ts_verifiers, policy))
    ok_f = (rep_f["evidentiary_grade"] == "registration-proven-not-content"
            and "correct, safe, or wise" in rep_f["narrow_claim"])
    _record("scitt_narrow_claims",
            "HELD" if ok_f else "BROKEN",
            "grade=%r" % rep_f.get("evidentiary_grade"))


def _green_check_adjacent():
    """Depth-1 green check: adjacent unit suites, never nested batteries."""
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN"):
        return ("SKIP", "GOV_SKIP_GREEN set -- child battery, no nesting")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpdir = os.environ.get("TMPDIR", "/tmp")
    suites = ["tests.test_scitt_receipt", "tests.test_rekor_v2_anchor",
              "tests.test_dsse_envelope"]
    tails = []
    for suite in suites:
        r = subprocess.run(
            [sys.executable, "-m", "unittest", suite, "-v"],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True,
            timeout=300)
        tail = (r.stderr or r.stdout).strip().splitlines()
        tails.append("%s rc=%d %s" % (suite, r.returncode,
                                     tail[-1] if tail else "no-output"))
        if r.returncode != 0:
            return ("FAIL", "; ".join(tails))
    return ("PASS", "; ".join(tails))


def main():
    try:
        _run_once()
    except Exception as exc:  # pristine tree: module absent -> genuine red
        _record("scitt_setup", "ERROR", "%s: %s"
                % (type(exc).__name__, exc))
    second_start = len(_records)
    try:
        _run_once()
    except Exception as exc:
        _record("scitt_setup_run2", "ERROR", "%s: %s"
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
    print("== scitt-receipt battery ==")
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
