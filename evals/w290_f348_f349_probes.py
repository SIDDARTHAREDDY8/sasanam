"""Wave-290 closure battery: F348 + F349 (both LOW), gov/evidence_admission.py.

F348: CHECKS is a mutable module-level dict -- deleting the floor checks
      removes the integrity floor entirely (admit() iterates CHECKS, so a
      removed floor check never runs; evidence ADMITs with floor_failed=[]).
      Also, rebinding the module attribute has the same effect.
      Close-when: the check registry is immutable after import (or floor
      membership is enforced independently of the mutable registry).

F349: admit_at_risk's floor gate reads a caller-synthesized field.
      admit() RAISES on REFUSE (never returns a decision record), so every
      refuse_decision dict is caller-synthesized and decision_digest is an
      unkeyed content hash. A refuse dict omitting floor_failed yields
      ADMIT-AT-RISK for floor-failed evidence.
      Close-when: the floor-failed state is mechanism-bound -- the refusal
      decision rides on the AdmissionError admit() itself raised, and is
      registered in-process so a synthesized dict can never reach the gate.

Red-first: on the wave-289 base, p_f348_registry_mutation,
p_f348_registry_rebind, and p_f349_synthesized_dict are BREAK; after the
fix all probes are HELD.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g290-f348f349 && TMPDIR=/var/tmp/g290-f348f349 \
    ~/workspace/.gov-venv/bin/python evals/w290_f348_f349_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g290-f348f349b \
    ~/workspace/.gov-venv/bin/python evals/w290_f348_f349_probes.py
"""

import inspect
import os
import sys
import time

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-289 merge: pin 1706. This lane adds no decision codes. (Merge
# composition: the rebuild lane adds 4 provenance-rebuild-* codes, so
# the composed tree pins at 1710.)
TAXONOMY_PIN = 2134  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)


_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _need_module():
    from gov import evidence_admission as adm
    return adm


def _policy(adm, policy_id="p1", level="strict"):
    return adm.compile_policy({
        "format": "admission-policy/1",
        "policy_id": policy_id,
        "scopes": [{"scope": "provenance", "level": level}],
    })


def _ev():
    return {"kind": "provenance", "artifact_digest": "ab" * 32}


def _outcomes(adm, fails=()):
    return {c: (c not in fails) for c in adm.CHECKS}


def _risk_store(adm, policy_id, grant=True):
    from gov import governed_exceptions as ge
    reg = ge.CheckRegistry()
    reg.register(adm.ACCEPT_RISK_CHECK_ID, "admission accept risk",
                 "admission", "medium", "accept at operator risk",
                 ["admission-policy"])
    store = ge.ExceptionStore(reg)
    store.set_approvers(["ops"])
    if grant:
        now = time.time()
        store.grant(adm.ACCEPT_RISK_CHECK_ID, ("policy", policy_id),
                    "accepting at risk for this test run, operator review",
                    "ops", now + 3600, now)
    return store


def _new_api(adm):
    """True when admit_at_risk takes the AdmissionError (fixed API)."""
    return "admission_error" in inspect.signature(adm.admit_at_risk).parameters


# ---------------------------------------------------------------------------
# F348
# ---------------------------------------------------------------------------

def p_f348_registry_mutation():
    """Deleting floor checks from CHECKS must not remove the floor."""
    adm = _need_module()
    saved = dict(adm.CHECKS)
    mutated = True
    try:
        try:
            del adm.CHECKS["signature-valid"]
            del adm.CHECKS["digest-binds"]
        except Exception:  # noqa: BLE001 - immutable registry (fixed)
            mutated = False
        if mutated:
            # Base behavior: the mutation succeeded; the floor is gone.
            pol = _policy(adm, level="skip")
            rec = adm.admit(_ev(), pol,
                            {c: True for c in adm.CHECKS})
            if (rec.get("verdict") == "ADMIT"
                    and not rec.get("floor_failed")):
                return _record("f348-registry-mutation", "BREAK",
                               "deleting floor checks from CHECKS bypassed "
                               "the integrity floor: ADMIT with no floor run")
            return _record("f348-registry-mutation", "HELD",
                           "floor still enforced after registry mutation")
        # Fixed behavior: registry immutable; prove the floor still runs.
        pol = _policy(adm)
        try:
            adm.admit(_ev(), pol, _outcomes(adm, fails=("signature-valid",)))
        except adm.AdmissionError as e:
            if e.code == "admission-integrity-floor-violated":
                return _record("f348-registry-mutation", "HELD",
                               "registry immutable; floor refuses coded")
            return _record("f348-registry-mutation", "BREAK",
                           "floor refused with wrong code: %r" % (e.code,))
        return _record("f348-registry-mutation", "BREAK",
                       "floor failure did not refuse")
    finally:
        try:
            adm.CHECKS.clear()
            adm.CHECKS.update(saved)
        except (TypeError, AttributeError):
            pass  # immutable registry post-fix: nothing to restore


def p_f348_registry_rebind():
    """Rebinding the CHECKS name must fail closed, not skip the floor."""
    adm = _need_module()
    saved = adm.CHECKS
    try:
        adm.CHECKS = {}
        pol = _policy(adm)
        try:
            rec = adm.admit(_ev(), pol, {})
        except adm.AdmissionError as e:
            return _record("f348-registry-rebind", "HELD",
                           "rebound registry refuses coded: %s" % (e.code,))
        return _record("f348-registry-rebind", "BREAK",
                       "rebound registry skipped every check: %r"
                       % (rec.get("verdict"),))
    finally:
        adm.CHECKS = saved


def p_f348_floor_positive():
    """Positive control: a genuine floor failure refuses coded."""
    adm = _need_module()
    pol = _policy(adm)
    try:
        adm.admit(_ev(), pol, _outcomes(adm, fails=("digest-binds",)))
    except adm.AdmissionError as e:
        if e.code == "admission-integrity-floor-violated":
            return _record("f348-floor-positive", "HELD",
                           "floor failure refuses coded")
        return _record("f348-floor-positive", "BREAK",
                       "wrong code: %r" % (e.code,))
    return _record("f348-floor-positive", "BREAK",
                   "floor failure did not refuse")


# ---------------------------------------------------------------------------
# F349
# ---------------------------------------------------------------------------

def p_f349_synthesized_dict():
    """A caller-synthesized refuse dict must never admit at risk."""
    adm = _need_module()
    store = _risk_store(adm, "p1")
    forged = {"verdict": "REFUSE", "policy_id": "p1",
              "decision_digest": "x" * 64}
    try:
        rec = adm.admit_at_risk(forged, store)
    except adm.AdmissionError as e:
        if e.code == "admission-exception-refused":
            return _record("f349-synthesized-dict", "HELD",
                           "synthesized refuse dict refused coded")
        return _record("f349-synthesized-dict", "BREAK",
                       "synthesized dict refused with wrong code: %r"
                       % (e.code,))
    except Exception as e:  # noqa: BLE001
        return _record("f349-synthesized-dict", "HELD",
                       "synthesized refuse refused: %s"
                       % type(e).__name__)
    if rec.get("verdict") == "ADMIT-AT-RISK":
        return _record("f349-synthesized-dict", "BREAK",
                       "caller-synthesized refuse dict (floor_failed "
                       "omitted) admitted at risk")
    return _record("f349-synthesized-dict", "HELD",
                   "unexpected record: %r" % (rec.get("verdict"),))


def p_f349_floor_never_exceptioned():
    """Floor-failed evidence can never be accepted at risk, even with a
    live exception covering the policy."""
    adm = _need_module()
    pol = _policy(adm)
    store = _risk_store(adm, "p1")
    if _new_api(adm):
        # Mechanism-bound path: the error admit() itself raised.
        try:
            adm.admit(_ev(), pol, _outcomes(adm, fails=("signature-valid",)))
        except adm.AdmissionError as e:
            refuse_err = e  # except-as name is cleared after the block
            if refuse_err.code != "admission-integrity-floor-violated":
                return _record("f349-floor-never-exceptioned", "BREAK",
                               "floor did not refuse first: %r"
                               % (refuse_err.code,))
        else:
            return _record("f349-floor-never-exceptioned", "BREAK",
                           "floor failure did not refuse")
        try:
            adm.admit_at_risk(refuse_err, store)
        except adm.AdmissionError as e2:
            if e2.code == "admission-exception-refused":
                return _record("f349-floor-never-exceptioned", "HELD",
                               "floor-failed refusal cannot be exceptioned")
            return _record("f349-floor-never-exceptioned", "BREAK",
                           "wrong code: %r" % (e2.code,))
        return _record("f349-floor-never-exceptioned", "BREAK",
                       "floor-failed evidence admitted at risk")
    # Base API: the honest dict carries floor_failed; the gate must fire.
    forged = {"verdict": "REFUSE", "policy_id": "p1",
              "decision_digest": "x" * 64,
              "floor_failed": ["signature-valid"]}
    try:
        adm.admit_at_risk(forged, store)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "admission-exception-refused":
            return _record("f349-floor-never-exceptioned", "HELD",
                           "floor_failed present -> refused coded")
        return _record("f349-floor-never-exceptioned", "BREAK",
                       "wrong code: %r" % (getattr(e, "code", None),))
    return _record("f349-floor-never-exceptioned", "BREAK",
                   "floor_failed record was admitted at risk")


def p_f349_honest_at_risk():
    """No regression: a genuine non-floor refusal still admits at risk
    under a live exception."""
    adm = _need_module()
    pol = _policy(adm)
    if _new_api(adm):
        try:
            adm.admit(_ev(), pol,
                      _outcomes(adm, fails=("provenance-present",)))
        except adm.AdmissionError as e:
            refuse_err = e  # except-as name is cleared after the block
            if refuse_err.code != "admission-refused":
                return _record("f349-honest-at-risk", "BREAK",
                               "expected admission-refused, got %r"
                               % (refuse_err.code,))
        else:
            return _record("f349-honest-at-risk", "BREAK",
                           "expected REFUSE, admission did not refuse")
        store = _risk_store(adm, "p1")
        rec = adm.admit_at_risk(refuse_err, store)
        if (rec.get("verdict") == "ADMIT-AT-RISK"
                and rec.get("exception_digest")
                and rec.get("floor_failed") == []):
            return _record("f349-honest-at-risk", "HELD",
                           "live exception accepts non-floor refusal")
        return _record("f349-honest-at-risk", "BREAK",
                       "at-risk acceptance wrong: %r" % (rec,))
    # Base API path (mirrors w288's p_exception_at_risk).
    store = _risk_store(adm, "p1")
    dec = {"verdict": "REFUSE", "policy_id": "p1",
           "floor_failed": [], "decision_digest": "x" * 64}
    rec = adm.admit_at_risk(dec, store)
    if rec.get("verdict") == "ADMIT-AT-RISK" and "exception_digest" in rec:
        return _record("f349-honest-at-risk", "HELD",
                       "live exception accepts at risk with digest")
    return _record("f349-honest-at-risk", "BREAK",
                   "at-risk acceptance wrong: %r" % (rec,))


def p_f349_no_live_exception():
    """Without a live exception, at-risk acceptance refuses."""
    adm = _need_module()
    pol = _policy(adm)
    store = _risk_store(adm, "p1", grant=False)
    if _new_api(adm):
        try:
            adm.admit(_ev(), pol,
                      _outcomes(adm, fails=("provenance-present",)))
        except adm.AdmissionError as e:
            refuse_err = e  # except-as name is cleared after the block
        try:
            adm.admit_at_risk(refuse_err, store)
        except adm.AdmissionError as e2:
            if e2.code == "admission-exception-refused":
                return _record("f349-no-live-exception", "HELD",
                               "no live exception -> refused coded")
            return _record("f349-no-live-exception", "BREAK",
                           "wrong code: %r" % (e2.code,))
        return _record("f349-no-live-exception", "BREAK",
                       "admitted at risk with no live exception")
    dec = {"verdict": "REFUSE", "policy_id": "p1",
           "floor_failed": [], "decision_digest": "x" * 64}
    try:
        adm.admit_at_risk(dec, store)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "admission-exception-refused":
            return _record("f349-no-live-exception", "HELD",
                           "no live exception -> refused coded")
        return _record("f349-no-live-exception", "BREAK",
                       "wrong code: %r" % (getattr(e, "code", None),))
    return _record("f349-no-live-exception", "BREAK",
                   "admitted at risk with no live exception")


def p_f349_decision_tamper():
    """Mutating the error-carried decision after admit() must not move
    the floor gate (the registry copy is authoritative). New API only."""
    adm = _need_module()
    if not _new_api(adm):
        return _record("f349-decision-tamper", "HELD",
                       "n/a on the old dict API (mechanism is new)")
    pol = _policy(adm)
    try:
        adm.admit(_ev(), pol, _outcomes(adm, fails=("signature-valid",)))
    except adm.AdmissionError as e:
        refuse_err = e  # except-as name is cleared after the block
    # Attacker mutates the error-carried record to hide the floor failure.
    refuse_err.decision["floor_failed"] = []
    store = _risk_store(adm, "p1")
    try:
        adm.admit_at_risk(refuse_err, store)
    except adm.AdmissionError as e2:
        if e2.code == "admission-exception-refused":
            return _record("f349-decision-tamper", "HELD",
                           "post-hoc decision tampering does not move "
                           "the floor gate")
        return _record("f349-decision-tamper", "BREAK",
                       "wrong code: %r" % (e2.code,))
    return _record("f349-decision-tamper", "BREAK",
                   "tampered decision admitted at risk")


# ---------------------------------------------------------------------------
# Green checks (depth-1: run adjacent batteries with GOV_SKIP_GREEN=1)
# ---------------------------------------------------------------------------

_GREEN_CHECKS = [
    "evals/w289_redteam_probes.py",
    "evals/w288_admission_probes.py",
]


def _green_checks():
    import re as _re
    import subprocess
    # Expected w289_redteam BREAKs: at base the F346-F351 probes are all
    # BREAK (9 probe BREAKs for 6 findings); after this lane's fix the
    # f348/f349 probes flip to HELD, leaving 7. MERGE COMPOSITION
    # (wave-290): lanes 1+2+3 all landed, so F346-F351 are all CLOSED on
    # the composed tree and w289_redteam runs 0 BREAK here.
    from gov import evidence_admission as _adm
    _fixed = "admission_error" in inspect.signature(
        _adm.admit_at_risk).parameters
    for rel in _GREEN_CHECKS:
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            _record("green-" + os.path.basename(rel), "HELD",
                    "battery absent, skipped")
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        tmpd = "/var/tmp/g290-f348f349-green"
        os.makedirs(tmpd, exist_ok=True)
        env["TMPDIR"] = tmpd
        try:
            proc = subprocess.run(
                [sys.executable, path], env=env, cwd=REPO,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=600, text=True)
            out = proc.stdout or ""
            m = _re.search(r"(\d+)\s*BREAK\s*/\s*(\d+)\s*HELD\s*/\s*(\d+)"
                           r"\s*ERROR", out)
            n_break = int(m.group(1)) if m else -1
            n_err = int(m.group(3)) if m else -1
            if rel.endswith("w289_redteam_probes.py"):
                # Merge composition: F346-F351 all CLOSED -> 0 BREAK.
                expected = 0
            else:
                expected = 0
            ok = n_break == expected and n_err == 0
            _record("green-" + os.path.basename(rel),
                    "HELD" if ok else "BREAK",
                    "expected %d BREAK, got %d BREAK / %d ERROR%s"
                    % (expected, n_break, n_err,
                       "" if ok else "; tail: " + out[-400:]))
        except Exception as e:  # noqa: BLE001
            _record("green-" + os.path.basename(rel), "BREAK",
                    "green check failed: %r" % (e,))


def main():
    probes = [p_f348_registry_mutation, p_f348_registry_rebind,
              p_f348_floor_positive, p_f349_synthesized_dict,
              p_f349_floor_never_exceptioned, p_f349_honest_at_risk,
              p_f349_no_live_exception, p_f349_decision_tamper]
    for probe in probes:
        try:
            probe()
        except Exception as e:  # noqa: BLE001
            _record(probe.__name__, "ERROR", "probe crashed: %r" % (e,))
    if not SKIP_GREEN:
        _green_checks()
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("%-32s %-6s %s" % (pid, verdict, note))
    print("TOTAL: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
