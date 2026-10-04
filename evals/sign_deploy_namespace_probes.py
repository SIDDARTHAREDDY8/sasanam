#!/usr/bin/env python3
"""Wave-207 Lane C: red-first battery for sign-vs-deploy namespace separation.

RED-FIRST: run against the PRISTINE tree first. Every probe imports
gov.sign_deploy_namespaces -- absent there -- so the pristine run is
uniformly ERROR (missing public seams), and the fixed tree holds.

The Harbor signed-only pattern ADAPTED (wave-205 prospecting §4):
"Signed-only" is project policy + *deployment admission*, not registry
refusal -- the registry *records* trust state; the *admission point*
enforces it. And the goharbor#22650 lesson: a naive unsigned-block
breaks the *signing* operation itself -- so the *staging* namespace
(where signing happens) is separate from the *enforced* namespace
(where only signed, digest-pinned bundles deploy).

Probes:

  sdn_unsigned_staging_labeled  -- unsigned content ENTERS staging but
                                   is loudly labeled UNSIGNED; it is
                                   not admittable to enforced.
  sdn_unsigned_cannot_enter_enforced
                                -- promote() on an unsigned record is
                                   refused (unsigned-refused).
  sdn_name_only_refused         -- name-only references (and 40-hex
                                   git-SHA-shaped references, the
                                   Plugin4Shell lesson) are refused
                                   at enforced admission
                                   (reference-not-digest).
  sdn_signed_promotes_and_admits
                                -- signed (2-of-2) + two-operator
                                   promotion -> digest-pinned admission
                                   returns the record with signed_by /
                                   promoted_by provenance.
  sdn_enforcement_does_not_break_signing
                                -- goharbor#22650 shape: with
                                   enforcement on, a fresh bundle can
                                   still be staged, signed, promoted
                                   and admitted.
  sdn_promotion_needs_two_operators
                                -- one / duplicate / bool / empty
                                   operator identities are refused
                                   (ceremony-refused).
  sdn_tampered_content_refused  -- bytes swapped after signing are
                                   refused at admission
                                   (digest-mismatch), never deployed.
  sdn_threshold_unmet           -- fewer valid signatures than the
                                   registry threshold -> refused at
                                   promotion.
  sdn_staging_is_not_deploy_source
                                -- admission from staging is refused
                                   (bad-namespace): deploys come only
                                   from enforced.
  sdn_audit_chained             -- every registry mutation is a
                                   hash-chained audit entry.
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


_SEED1 = bytes.fromhex("51" * 32)
_SEED2 = bytes.fromhex("52" * 32)
_SEED3 = bytes.fromhex("53" * 32)


def _setup():
    from gov import sign_deploy_namespaces as sdn
    from gov.signing import Ed25519Signer, Ed25519Verifier
    return sdn, Ed25519Signer, Ed25519Verifier


def _registry(sdn, Ed25519Signer, Ed25519Verifier, threshold=1):
    signers = [Ed25519Signer(_SEED1), Ed25519Signer(_SEED2)]
    verifiers = [Ed25519Verifier(s.public_key) for s in signers]
    reg = sdn.NamespaceRegistry(verifiers=verifiers, threshold=threshold)
    return reg, signers, verifiers


def _run_once():
    sdn, Ed25519Signer, Ed25519Verifier = _setup()

    # -- (a) unsigned enters staging, loudly labeled; not admittable ----
    reg, signers, _ = _registry(sdn, Ed25519Signer, Ed25519Verifier)
    rec = reg.stage("skill/search", b"bundle-bytes-v1")
    label = reg.staging_label("skill/search")
    labeled = ("UNSIGNED" in label and "enforced" in label.lower())
    try:
        reg.admit_deploy(rec["digest"], namespace=sdn.ENFORCED)
        refused = False
    except sdn.NamespaceError as exc:
        refused = exc.code in ("unknown-bundle", "unsigned-refused")
    _record("sdn_unsigned_staging_labeled",
            "HELD" if (labeled and refused) else "BROKEN",
            "label=%r refused_from_enforced=%s" % (label, refused))

    # -- (b) unsigned cannot enter enforced ------------------------------
    try:
        reg.promote("skill/search", operator_ids=["op-a", "op-b"])
        _record("sdn_unsigned_cannot_enter_enforced", "BROKEN",
                "promote() accepted an unsigned record")
    except sdn.NamespaceError as exc:
        _record("sdn_unsigned_cannot_enter_enforced",
                "HELD" if exc.code == "unsigned-refused" else "BROKEN",
                "refused with code=%s" % exc.code)

    # -- (c) name-only references refused at enforced admission ----------
    for ref, why in (("skill/search", "bare name"),
                     ("a" * 40, "40-hex git-SHA-shaped reference")):
        try:
            reg.admit_deploy(ref, namespace=sdn.ENFORCED)
            _record("sdn_name_only_refused", "BROKEN",
                    "admitted %s %r" % (why, ref))
            break
        except sdn.NamespaceError as exc:
            if exc.code != "reference-not-digest":
                _record("sdn_name_only_refused", "BROKEN",
                        "%s refused with wrong code %s" % (why, exc.code))
                break
    else:
        _record("sdn_name_only_refused", "HELD",
                "bare name and 40-hex reference both refused")

    # -- (d) signed + two-operator promotion -> digest-pinned admission ---
    reg2, signers2, _ = _registry(sdn, Ed25519Signer, Ed25519Verifier,
                                 threshold=2)
    rec2 = reg2.stage("skill/search", b"bundle-bytes-v1")
    reg2.sign("skill/search", signers2)
    reg2.promote("skill/search", operator_ids=["op-a", "op-b"])
    admitted2 = reg2.admit_deploy(rec2["digest"], namespace=sdn.ENFORCED)
    ok = (admitted2["digest"] == rec2["digest"]
          and len(admitted2["signed_by"]) == 2
          and admitted2["promoted_by"] == ["op-a", "op-b"]
          and admitted2["content"] == b"bundle-bytes-v1")
    _record("sdn_signed_promotes_and_admits",
            "HELD" if ok else "BROKEN",
            "signed_by=%r promoted_by=%r"
            % (admitted2.get("signed_by"), admitted2.get("promoted_by")))

    # -- (e) goharbor#22650: enforcement on, signing still works ----------
    try:
        reg3, signers3, _ = _registry(sdn, Ed25519Signer, Ed25519Verifier)
        r3 = reg3.stage("skill/fresh", b"fresh-bytes")
        reg3.sign("skill/fresh", [signers3[0]])
        reg3.promote("skill/fresh", operator_ids=["op-a", "op-b"])
        a3 = reg3.admit_deploy(r3["digest"], namespace=sdn.ENFORCED)
        _record("sdn_enforcement_does_not_break_signing",
                "HELD" if a3["content"] == b"fresh-bytes" else "BROKEN",
                "stage->sign->promote->admit all succeed with enforcement on")
    except sdn.NamespaceError as exc:
        _record("sdn_enforcement_does_not_break_signing", "BROKEN",
                "signing/promotion blocked by enforcement: %s" % exc)

    # -- (f) promotion ceremony: two distinct operators required ----------
    reg4, signers4, _ = _registry(sdn, Ed25519Signer, Ed25519Verifier)
    reg4.stage("skill/ceremony", b"bytes")
    reg4.sign("skill/ceremony", [signers4[0]])
    bad_ops = (["op-a"], ["op-a", "op-a"], [True, "op-b"],
               ["", "op-b"], "op-a", [None, "op-b"])
    refused_all = True
    for ops in bad_ops:
        try:
            reg4.promote("skill/ceremony", operator_ids=ops)
            refused_all = False
            detail = "accepted operators=%r" % (ops,)
            break
        except sdn.NamespaceError as exc:
            if exc.code != "ceremony-refused":
                refused_all = False
                detail = "wrong code %s for operators=%r" % (exc.code, ops)
                break
    else:
        detail = "1/dup/bool/empty/non-list operators all refused"
    _record("sdn_promotion_needs_two_operators",
            "HELD" if refused_all else "BROKEN", detail)

    # -- (g) tampered content refused at admission ------------------------
    reg5, signers5, _ = _registry(sdn, Ed25519Signer, Ed25519Verifier)
    r5 = reg5.stage("skill/tamper", b"original-bytes")
    reg5.sign("skill/tamper", [signers5[0]])
    reg5.promote("skill/tamper", operator_ids=["op-a", "op-b"])
    reg5._enforced[r5["digest"]]["content"] = b"swapped-bytes"  # white-box
    try:
        reg5.admit_deploy(r5["digest"], namespace=sdn.ENFORCED)
        _record("sdn_tampered_content_refused", "BROKEN",
                "swapped bytes admitted")
    except sdn.NamespaceError as exc:
        _record("sdn_tampered_content_refused",
                "HELD" if exc.code in ("digest-mismatch", "bad-signature")
                else "BROKEN",
                "refused with code=%s" % exc.code)

    # -- (g2) bytes swapped between sign and promote are refused --------
    reg5b, signers5b, _ = _registry(sdn, Ed25519Signer, Ed25519Verifier)
    reg5b.stage("skill/swap", b"bytes-at-sign-time")
    reg5b.sign("skill/swap", [signers5b[0]])
    reg5b._staging["skill/swap"]["content"] = b"different-bytes"  # white-box
    try:
        reg5b.promote("skill/swap", operator_ids=["op-a", "op-b"])
        _record("sdn_swap_before_promote_refused", "BROKEN",
                "promoted bytes the signature never covered")
    except sdn.NamespaceError as exc:
        _record("sdn_swap_before_promote_refused",
                "HELD" if exc.code in ("digest-mismatch", "bad-signature")
                else "BROKEN",
                "refused with code=%s" % exc.code)

    # -- (h) signature threshold unmet ------------------------------------
    reg6, signers6, _ = _registry(sdn, Ed25519Signer, Ed25519Verifier,
                                 threshold=2)
    reg6.stage("skill/threshold", b"bytes")
    reg6.sign("skill/threshold", [signers6[0]])  # only 1 of 2
    try:
        reg6.promote("skill/threshold", operator_ids=["op-a", "op-b"])
        _record("sdn_threshold_unmet", "BROKEN",
                "promote() accepted 1-of-2 signatures")
    except sdn.NamespaceError as exc:
        _record("sdn_threshold_unmet",
                "HELD" if exc.code == "threshold-unmet" else "BROKEN",
                "refused with code=%s" % exc.code)

    # -- (i) staging is not a deploy source -------------------------------
    reg7, _, _ = _registry(sdn, Ed25519Signer, Ed25519Verifier)
    r7 = reg7.stage("skill/stageonly", b"bytes")
    try:
        reg7.admit_deploy(r7["digest"], namespace=sdn.STAGING)
        _record("sdn_staging_is_not_deploy_source", "BROKEN",
                "admission from staging accepted")
    except sdn.NamespaceError as exc:
        _record("sdn_staging_is_not_deploy_source",
                "HELD" if exc.code == "bad-namespace" else "BROKEN",
                "refused with code=%s" % exc.code)

    # -- (j) audit is hash-chained ----------------------------------------
    reg8, signers8, _ = _registry(sdn, Ed25519Signer, Ed25519Verifier)
    reg8.stage("skill/audit", b"bytes")
    reg8.sign("skill/audit", [signers8[0]])
    reg8.promote("skill/audit", operator_ids=["op-a", "op-b"])
    chained = True
    prev = "GENESIS"
    for entry in reg8.audit:
        if entry["prev"] != prev:
            chained = False
            break
        prev = entry["entry_hash"]
    _record("sdn_audit_chained",
            "HELD" if (chained and len(reg8.audit) >= 3) else "BROKEN",
            "%d chained audit entries" % len(reg8.audit))


def _green_check_adjacent():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP", "depth-1 green check: skipped by convention "
                "(tests/test_sign_deploy_namespaces.py standalone)")
    import subprocess  # noqa: E402
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="sdn-green-")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_dsse_envelope", "tests.test_sign_deploy_namespaces",
         "-v"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=600)
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    return ("PASS" if r.returncode == 0 else "FAIL",
            "adjacent unit tests rc=%d %s" % (r.returncode, tail[0]))


def main():
    try:
        _run_once()
    except Exception as exc:  # pristine tree: module absent -> genuine red
        _record("sdn_setup", "ERROR", "%s: %s"
                % (type(exc).__name__, exc))
    second_start = len(_records)
    try:
        _run_once()
    except Exception as exc:
        _record("sdn_setup_run2", "ERROR", "%s: %s"
                % (type(exc).__name__, exc))
    first = _records[:second_start]
    second = _records[second_start:]
    det_ok = ([(n, v) for n, v, _ in first]
              == [(n, v) for n, v, _ in second])
    # keep only the first run's probe records plus determinism + green
    del _records[second_start:]
    _record("determinism",
            "PASS" if det_ok else "FAIL",
            "two in-process runs agree on all %d probes" % len(first)
            if det_ok else "MISMATCH between run 1 and run 2")
    gv, gd = _green_check_adjacent()
    _record("green_check_adjacent_units", gv, gd)
    print("== sign-vs-deploy-namespace battery ==")
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
