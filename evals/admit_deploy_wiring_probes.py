#!/usr/bin/env python3
"""Wave-209 Lane B: red-first battery for admit_deploy seam wiring.

RED-FIRST: run against the PRISTINE tree first. The pristine
``SkillLoader`` has no ``namespace_registry`` kwarg, so constructing a
wired loader raises ``TypeError`` -- every probe is uniformly ERROR
(wiring absent), and the fixed tree holds.

Wave-207 Lane C built the sign-vs-deploy namespace separation but left
an honest residual: ``admit_deploy`` was not wired into
``gov/load_gate.py`` -- callers had to invoke it at the seam manually.
This lane closes that gap: ``SkillLoader`` takes an optional
``namespace_registry``; when wired, ``load_skill`` additionally requires
the pin's digest to be admittable to the ENFORCED namespace. The wiring
is default-off (``None``) so legacy callers are byte-identical.

Probes:

  adw_unsigned_refused_through_gate -- unsigned (staged, never signed)
      bundle pinned in the pinset and present in the store is REFUSED
      through the wired load gate (namespace_admission_refused).
  adw_signed_unpromoted_refused     -- signed but never promoted is
      refused: promotion is part of admission.
  adw_staging_flow_unchanged       -- full stage -> sign -> promote ->
      load through the wired gate succeeds with identical bytes.
  adw_name_only_refused            -- the wired deployment's registry
      refuses name-only references at enforced admission
      (reference-not-digest).
  adw_signing_works_with_enforcement_on
                                   -- goharbor#22650 shape: the wired
      loader is constructed FIRST (enforcement "on"), then a fresh
      bundle is staged, signed, promoted and loaded -- the signing
      pipeline is never bricked by enforcement.
  adw_legacy_callers_unchanged      -- unwired SkillLoader and
      load_skill_content without the new kwarg load an
      unsigned-but-pinned bundle exactly as before.
  adw_constructor_rejects_non_registry
                                   -- a non-registry object is refused
      at construction (TypeError), not at load time.
  adw_admission_provenance_logged   -- a successful wired load logs
      namespace_admitted with signed_by / promoted_by provenance.
"""

import hashlib
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


# Fixed seeds: deterministic key material (no per-run randomness).
_SEED_SIGN = bytes.fromhex("61" * 32)
_SEED_PIN = bytes.fromhex("62" * 32)

_TS = "2026-09-23T00:00:00+00:00"

PROBE_NAMES = (
    "adw_unsigned_refused_through_gate",
    "adw_signed_unpromoted_refused",
    "adw_staging_flow_unchanged",
    "adw_name_only_refused",
    "adw_signing_works_with_enforcement_on",
    "adw_legacy_callers_unchanged",
    "adw_constructor_rejects_non_registry",
    "adw_admission_provenance_logged",
)


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _setup():
    """Build a fresh world. On the PRISTINE tree the wired
    ``SkillLoader`` construction raises TypeError (wiring absent) --
    genuine red."""
    from gov import load_gate as lg
    from gov import sign_deploy_namespaces as sdn
    from gov.signing import Ed25519Signer, Ed25519Verifier
    from gov.delegation_tokens import DelegationTrust

    pin_signer = Ed25519Signer(_SEED_PIN)
    authority = Ed25519Signer(bytes.fromhex("63" * 32))
    trust = DelegationTrust(
        human_keys={pin_signer.key_id: pin_signer.public_key},
        authority_keys={authority.key_id: authority.public_key},
        user_issuer_keys={pin_signer.key_id: pin_signer.public_key},
    )
    pinset = lg.ArtifactPinset(trust)

    signers = [Ed25519Signer(_SEED_SIGN)]
    verifiers = [Ed25519Verifier(s.public_key) for s in signers]
    registry = sdn.NamespaceRegistry(verifiers=verifiers, threshold=1)

    def pin_skill(name, content):
        digest = _digest(content)
        na = lg._resolve_pin_not_after(_TS, None)
        body = lg._canonical_pin_body("dev", "skill:" + name, digest,
                                      _TS, version=1, not_after=na)
        pinset.pin("skill:" + name, digest, pin_signer.key_id,
                   pin_signer.sign(body).hex(), ts=_TS, tier="dev",
                   version=1, not_after=na)
        return digest

    return {
        "lg": lg, "sdn": sdn, "pinset": pinset, "registry": registry,
        "signers": signers, "pin_skill": pin_skill,
    }


def _ceremony(ctx, name, content, store, operators=("op-a", "op-b")):
    """Stage -> sign -> promote a bundle; pin it; put it in the store."""
    reg = ctx["registry"]
    reg.stage(name, content)
    reg.sign(name, ctx["signers"])
    reg.promote(name, operator_ids=list(operators))
    digest = ctx["pin_skill"](name, content)
    store[name] = content
    return digest


def _run_once():
    try:
        ctx = _setup()
        # The wiring probe: construct ONE wired loader to prove the
        # kwarg exists. TypeError here means the pristine tree (no
        # wiring) -- every probe goes ERROR, genuine red.
        lg = ctx["lg"]
        lg.SkillLoader(ctx["pinset"], {}, namespace_registry=ctx["registry"])
    except TypeError as exc:
        for name in PROBE_NAMES:
            _record(name, "ERROR",
                    "wiring absent (pristine tree): %s: %s"
                    % (type(exc).__name__, exc))
        return

    sdn = ctx["sdn"]
    pinset = ctx["pinset"]
    registry = ctx["registry"]

    # -- (a) unsigned bundle refused through the wired gate ------------
    store = {}
    content = b"unsigned-bundle-bytes"
    digest = ctx["pin_skill"]("unsigned-skill", content)
    store["unsigned-skill"] = content
    registry.stage("unsigned-skill", content)  # staged, never signed
    log = []
    loader = lg.SkillLoader(pinset, store, log=log,
                            namespace_registry=registry)
    try:
        loader.load_skill("unsigned-skill")
        _record("adw_unsigned_refused_through_gate", "BROKEN",
                "wired gate loaded an unsigned bundle")
    except lg.ArtifactRefused as exc:
        refused = "namespace_admission_refused" in str(exc)
        logged = any(e.get("event") == "artifact_load_refused"
                     and e.get("reason") == "namespace_admission_refused"
                     for e in log)
        _record("adw_unsigned_refused_through_gate",
                "HELD" if (refused and logged) else "BROKEN",
                "refused=%s logged=%s msg=%r"
                % (refused, logged, str(exc)[:80]))

    # -- (b) signed but unpromoted is refused ---------------------------
    store2 = {}
    content2 = b"signed-not-promoted-bytes"
    digest2 = ctx["pin_skill"]("halfway-skill", content2)
    store2["halfway-skill"] = content2
    registry.stage("halfway-skill", content2)
    registry.sign("halfway-skill", ctx["signers"])  # signed, not promoted
    loader2 = lg.SkillLoader(pinset, store2, namespace_registry=registry)
    try:
        loader2.load_skill("halfway-skill")
        _record("adw_signed_unpromoted_refused", "BROKEN",
                "wired gate loaded a signed-but-unpromoted bundle")
    except lg.ArtifactRefused as exc:
        _record("adw_signed_unpromoted_refused",
                "HELD" if "namespace_admission_refused" in str(exc)
                else "BROKEN",
                "msg=%r" % (str(exc)[:80],))

    # -- (c) staging flow unchanged: full ceremony loads ---------------
    store3 = {}
    content3 = b"full-ceremony-bundle-bytes"
    digest3 = _ceremony(ctx, "full-skill", content3, store3)
    log3 = []
    loader3 = lg.SkillLoader(pinset, store3, log=log3,
                             namespace_registry=registry)
    try:
        verified = loader3.load_skill("full-skill")
        ok = (verified.data == content3 and verified.digest == digest3)
        _record("adw_staging_flow_unchanged",
                "HELD" if ok else "BROKEN",
                "bytes_match=%s digest=%s" % (ok, verified.digest[:20]))
    except Exception as exc:
        _record("adw_staging_flow_unchanged", "BROKEN",
                "%s: %s" % (type(exc).__name__, exc))

    # -- (d) name-only reference refused at enforced admission ---------
    try:
        registry.admit_deploy("full-skill", namespace=sdn.ENFORCED)
        _record("adw_name_only_refused", "BROKEN",
                "wired registry admitted a bare name")
    except sdn.NamespaceError as exc:
        _record("adw_name_only_refused",
                "HELD" if exc.code == "reference-not-digest" else "BROKEN",
                "refused with code=%s" % exc.code)

    # -- (e) goharbor#22650: enforcement on, signing still works --------
    # The wired loader (enforcement "on") is constructed FIRST; only
    # then does a fresh bundle go through stage -> sign -> promote.
    store5 = {}
    log5 = []
    loader5 = lg.SkillLoader(pinset, store5, log=log5,
                             namespace_registry=registry)
    fresh = b"fresh-bundle-under-enforcement"
    _ceremony(ctx, "fresh-skill", fresh, store5)
    try:
        verified5 = loader5.load_skill("fresh-skill")
        _record("adw_signing_works_with_enforcement_on",
                "HELD" if verified5.data == fresh else "BROKEN",
                "signing pipeline works with enforcement on")
    except Exception as exc:
        _record("adw_signing_works_with_enforcement_on", "BROKEN",
                "%s: %s" % (type(exc).__name__, exc))

    # -- (f) legacy callers unchanged -----------------------------------
    store6 = {"legacy-skill": content}
    # Re-pin under the legacy name (pinset pins are per artifact_id).
    ctx["pin_skill"]("legacy-skill", content)
    legacy_loader = lg.SkillLoader(pinset, store6)  # no registry
    try:
        legacy = legacy_loader.load_skill("legacy-skill")
        legacy_ok = legacy.data == content
    except Exception as exc:
        legacy_ok = False
        _record("adw_legacy_callers_unchanged", "BROKEN",
                "unwired loader failed: %s: %s"
                % (type(exc).__name__, exc))
    if legacy_ok:
        try:
            from gov.sterile import Unvetted  # noqa: F401
            marker = lg.load_skill_content(pinset, store6, "legacy-skill")
            _record("adw_legacy_callers_unchanged", "HELD",
                    "unwired SkillLoader + load_skill_content unchanged")
        except Exception as exc:
            _record("adw_legacy_callers_unchanged", "BROKEN",
                    "load_skill_content without kwarg failed: %s: %s"
                    % (type(exc).__name__, exc))

    # -- (g) constructor rejects a non-registry -------------------------
    try:
        lg.SkillLoader(pinset, store6, namespace_registry=object())
        _record("adw_constructor_rejects_non_registry", "BROKEN",
                "accepted a non-registry object")
    except TypeError:
        _record("adw_constructor_rejects_non_registry", "HELD",
                "non-registry refused at construction")

    # -- (h) admission provenance is logged ------------------------------
    admitted_events = [e for e in log3
                       if e.get("event") == "namespace_admitted"]
    prov_ok = (len(admitted_events) == 1
               and admitted_events[0].get("digest") == digest3
               and admitted_events[0].get("signed_by")
               and admitted_events[0].get("promoted_by") == ["op-a", "op-b"])
    _record("adw_admission_provenance_logged",
            "HELD" if prov_ok else "BROKEN",
            "events=%d" % len(admitted_events))


def _green_check_adjacent():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP", "depth-1 green check: skipped by convention "
                        "(tests/test_admit_deploy_wiring.py standalone)")
    import subprocess  # noqa: E402
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="adw-green-")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_sign_deploy_namespaces",
         "tests.test_admit_deploy_wiring",
         "-v"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=600)
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    return ("PASS" if r.returncode == 0 else "FAIL",
            "adjacent unit tests rc=%d %s" % (r.returncode, tail[0]))


def main():
    try:
        _run_once()
    except Exception as exc:
        _record("adw_setup", "ERROR", "%s: %s"
                % (type(exc).__name__, exc))
    second_start = len(_records)
    try:
        _run_once()
    except Exception as exc:
        _record("adw_setup_run2", "ERROR", "%s: %s"
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
    print("== admit-deploy-wiring battery ==")
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
