"""Break-first F227 closure battery: emit_profile_results must validate
per-result record keys fail-closed instead of escaping raw KeyError.

Wave-260 lane A (F227 closure). Stdlib only. Deterministic across
runs (staging + `env -u GOV_DEPLOYMENT_MODE`).

F227 (LOW, OPEN at write time): emit_profile_results() claims the
caller-supplied profile_results shape is "re-validated fail-closed
here", but only five top-level keys (profile_id, profile_title,
profile_digest, success, results) are checked. Per-result record keys
are trusted: _finding_ref() and the findings-mapping loop index
r["control_id"], r["status"], r["reason"], r["impact"],
r["severity"], r["digest"] directly. A caller-built record with a
fail/error entry missing any of these escapes raw KeyError from the
public seam instead of ControlProfileError(control-profile-malformed).
Same defect class as F226 (wrong error type at a public seam; a caller
catching only ControlProfileError misses the refusal entirely).

Close-when (from FINDINGS.md): (1) emit_profile_results() validates
per-result record keys and refuses malformed caller-built records with
ControlProfileError carrying a control-profile-* machine code -- no
raw KeyError escapes on any missing per-result key; (2) break-first
battery: the malformed-results probes BREAK (raw KeyError) on old
code, HELD (machine-coded refusal) on fixed code, in both staging and
`env -u GOV_DEPLOYMENT_MODE`; (3) adjacent suites green
(tests.test_control_profiles, w257 profiles battery).

Fix choice (validate-before-use, F226 analog): the fix reuses the
EXISTING control-profile-malformed code -- no new taxonomy code, pin
stays 1080. Validation runs on every record (dict + six required
keys) before the pass/fail split, so the pass-mapping path, the
findings-mapping path, and _default_findings_index() all see only
validated records.

Method (diagnosing-bugs skill): each probe is falsifiable. Verdicts:
HELD (ControlProfileError(control-profile-malformed)) or BREAK (a raw
KeyError/TypeError escapes, a wrong envelope code, or a malformed
record emits without refusal).
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

from gov import control_profiles as cp  # noqa: E402
from gov import decision_codes  # noqa: E402  (taxonomy pin below)

TAXONOMY_PIN = 1888  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*)

WANT_CODE = "control-profile-malformed"

# The exact per-result keys emit_profile_results indexes on the
# pre-fix tree (the ones the seam must validate before use).
RESULT_KEYS = ("control_id", "status", "reason", "impact",
               "severity", "digest")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _full_record(**overrides):
    rec = {"control_id": "C0", "impact": 0.9, "severity": "high",
           "check": "f", "check_version": "1", "status": "fail",
           "reason": "x", "exception_info": None,
           "digest": "11" * 32}
    rec.update(overrides)
    return rec


def _fake_results(records):
    return {"profile_id": "P1", "profile_title": "t",
            "profile_digest": "00" * 32, "success": False,
            "results": records}


def _expect_refused(fake, what):
    """The F227 envelope check: a malformed caller-built record must
    surface as ControlProfileError(control-profile-malformed) --
    never as a raw KeyError/TypeError."""
    try:
        cp.emit_profile_results(fake, fmt="json")
    except cp.ControlProfileError as exc:
        if exc.code != WANT_CODE:
            return _break("%s: wrong envelope code %s (want %s)"
                          % (what, exc.code, WANT_CODE))
        return _held("%s refused as %s" % (what, WANT_CODE))
    except KeyError as exc:
        return _break("%s: raw KeyError %r escaped the "
                      "control-profiles seam instead of "
                      "ControlProfileError" % (what, exc))
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("%s: raw %s escaped the control-profiles "
                      "seam instead of ControlProfileError"
                      % (what, type(exc).__name__))
    return _break("%s: malformed record emitted without refusal"
                  % (what,))


def _missing_key_probe(key):
    def probe():
        rec = _full_record()
        del rec[key]
        return _expect_refused(_fake_results([rec]),
                               "fail record missing %r" % (key,))
    probe.__name__ = "p_missing_%s" % (key,)
    probe.__doc__ = ("F227 core: a fail record missing %r must not "
                     "escape raw KeyError." % (key,))
    return probe


for _k in RESULT_KEYS:
    globals()[_missing_key_probe(_k).__name__] = _missing_key_probe(_k)


def p_non_dict_record_refused():
    # Defense in depth: a non-dict record cannot have keys checked --
    # it must be refused with the machine code, not escape raw
    # TypeError from r["status"] on the pre-fix tree.
    return _expect_refused(_fake_results(["not-a-record"]),
                           "non-dict record")


def p_results_not_list_refused():
    # Defense in depth: results must be a list of records; a dict
    # iterates its keys and escapes raw TypeError on the pre-fix
    # tree ("status" in "a" then "a"["status"]).
    return _expect_refused(_fake_results({"a": 1}),
                           "results not a list")


def p_pass_record_missing_key_refused():
    # Control (behavior pin): validation is status-agnostic -- it
    # runs before the pass/fail split, so even a pass record missing
    # a key is refused. On the pre-fix tree a pass record missing
    # "digest" emits fine (the pass-mapping loop never reads it), so
    # this probe is a control, not break-first: it pins the
    # fail-closed choice.
    rec = _full_record(status="pass")
    del rec["digest"]
    fake = _fake_results([rec])
    fake["success"] = True
    verdict, detail = _expect_refused(fake, "pass record missing key")
    if verdict == "HELD" and "refused as" in detail:
        return _held("control: pass record missing digest refused "
                     "as %s" % (WANT_CODE,))
    if verdict == "BREAK" and "emitted without refusal" in detail:
        return _held("control: pre-fix emits a pass record missing "
                     "digest (no raw escape); fixed tree must refuse")
    return (verdict, detail)


def p_well_formed_still_emits():
    # Control (no regression / trust boundary): a well-formed
    # run_profile() result still emits -- the finding pins this
    # HELD (fabricated well-formed results emit per the documented
    # trust boundary).
    prof = {"id": "P-F227", "title": "f227-probe",
            "controls": [{"id": "C1", "impact": 0.9, "title": "t",
                          "desc": "d",
                          "check": lambda snap: False}]}
    try:
        out = cp.emit_profile_results(cp.run_profile(prof, {"e": 1}),
                                      fmt="json")
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("well-formed run_profile() result raised %s"
                      % (type(exc).__name__,))
    if '"kind": "finding"' in out:
        return _held("control: well-formed fail still emits")
    return _break("control: well-formed result emitted without "
                  "finding mapping")


def p_malformed_code_registered():
    # The envelope code on the refusal is a registered
    # control-profile-* taxonomy code (machine-code contract) --
    # this is the EXISTING code, so the taxonomy pin is unchanged.
    entry = decision_codes.TAXONOMY.get(WANT_CODE)
    if entry is None:
        return _break("%s not in TAXONOMY" % (WANT_CODE,))
    if entry.get("domain") != "control-profile":
        return _break("wrong domain %r" % (entry.get("domain"),))
    return _held("%s registered, domain=control-profile" % (WANT_CODE,))


PROBES = ([globals()["p_missing_%s" % (k,)] for k in RESULT_KEYS]
          + [p_non_dict_record_refused,
             p_results_not_list_refused,
             p_pass_record_missing_key_refused,
             p_well_formed_still_emits,
             p_malformed_code_registered])


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    suites = [
        ("unittest", ["-m", "unittest", "tests.test_control_profiles"],
         "/var/tmp/g260-f227-green-cp"),
        ("battery", ["evals/w257_profiles_probes.py"],
         "/var/tmp/g260-f227-green-w257"),
        ("battery", ["evals/w258_f222_probes.py"],
         "/var/tmp/g260-f227-green-w258f222"),
        ("battery", ["evals/w259_f226_probes.py"],
         "/var/tmp/g260-f227-green-w259f226"),
    ]
    for kind, argv, td in suites:
        os.makedirs(td, exist_ok=True)
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = td
        cmd = [sys.executable] + argv
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=600)
        if r.returncode != 0:
            print("GREEN CHECK FAILED:", " ".join(cmd))
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            return False
        print("GREEN CHECK: %s %s green"
              % (kind, argv[-1]))
    return True


def main():
    assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, (
        "taxonomy pin: expected %d, got %d"
        % (TAXONOMY_PIN, len(decision_codes.TAXONOMY)))
    results = []
    for fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- probe harness
            verdict, detail = ("ERROR", "%r" % (exc,))
        results.append((fn.__name__, verdict, detail))
    probe_lines.emit(results)
    held = sum(1 for _, v, _ in results if v == "HELD")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    print("w260_f227: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        results, brk, held, err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    ok = green_check()
    print("green=%s" % ("OK" if ok else "FAIL"))
    # `broken == 0` (old) counted every non-HELD verdict; verdicts here
    # are HELD/BREAK/ERROR only, so `brk == 0 and err == 0` is identical.
    return 0 if (brk == 0 and err == 0 and ok) else 1


if __name__ == "__main__":
    sys.exit(main())
