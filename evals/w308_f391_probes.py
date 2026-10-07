"""Wave-308 lane A battery: F391 -- the lease manager is bound by the
coordinator (CLOSED).

F391 (MEDIUM, filed 2026-10-03T10:37:32Z, wave-307 independent
red-team): gov/workflow_branch.py::suspend_lease proved lease-holdership
at suspend time via check_write BEFORE parking (F389) -- but the lease
manager was a caller-supplied argument, so the proof was vacuous
against an attacker who brought their own rubber-stamp manager: the
re-park was ACCEPTED (clobbering the holder's suspension) and the
attacker's own resume_lease with the fake manager returned True (fake
liveness attestation).

Closed: the coordinator binds the manager object to the transaction at
begin() time (identity check, never per-call) -- before any park can
happen, so the first-park race is eliminated by construction. A later
suspend/resume presenting a different manager object -- or any
suspend/resume on a transaction begun without a bound manager --
refuses coded ``coord-lease-manager-mismatch`` before any oracle call
-- at BOTH ends: the suspend-time holdership proof consults the bound
manager, and the resume-time liveness check consults the bound manager
(third limb, wave-308 red-team lane D: a legitimate park resumed with a
substituted fake manager must refuse coded, never self-attest). +1
decision code (pin 1827 -> 1828).

Probes (all through the public BranchCoordinator API):
  F391-suspend-substitute-refused: holder parks with the real manager;
     attacker's re-park with a rubber-stamp manager refuses coded
     coord-lease-manager-mismatch; the holder's resume still works.
  F391-resume-substitute-refused: begin with fake1 bound, park with
     fake1; resume with a DIFFERENT fake2 refuses coded
     coord-lease-manager-mismatch (no self-attested liveness).
  F391-legit-suspend-resume: legitimate park + resume with the bound
     manager still works (no regression).
  F391-repark-same-manager: re-park with the identical manager object
     keeps the documented latest-wins semantics.
  F391-bogus-token-still-fencing: real manager + bogus token still
     refuses coord-lease-fencing (F389 intact).
  F391-bind-after-proof: a refused park (bogus token) disturbs
     nothing -- the legitimate park afterwards still works against
     the begin-bound manager.
  F391-first-park-race-eliminated (wave-309 lane B): the attacker's
     first park now refuses coded at park time -- the race is
     eliminated by begin-time binding, no longer a residual.
  F391-park-without-begin-binding-refuses (wave-309 lane B):
     a transaction begun without a bound manager refuses parks coded
     (fail-closed; no silent first-park binding).

Run:
  mkdir -p /var/tmp/g308-f391 && TMPDIR=/var/tmp/g308-f391 \\
    ~/workspace/.gov-venv/bin/python evals/w308_f391_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g308-f391b \\
    ~/workspace/.gov-venv/bin/python evals/w308_f391_probes.py
"""

import os
import re
import sys
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check  # noqa: E402  (wave-305 shared fail-closed green checks)
import probe_lines  # noqa: E402  (canonical probe-line form)

# Wave-307 merge pin 1827; this lane mints +1 coord-lease-manager-mismatch.
TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)

LEASE_MISMATCH = "coord-lease-manager-mismatch"

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "2135/2135/0 sorted")




def p_footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    matches = re.findall(
        r"Next free finding: \*\*F(\d+)\*\*\. \*\*Open findings: ([^*]*)\.\*\*",
        text)
    if not matches:
        return _record("footer-state", "BREAK", "footer pattern not found")
    nxt, open_s = int(matches[-1][0]), matches[-1][1]
    # Wave-322 lane 1 repoint: footer open none / next F409 (F406 CLOSED).
    # Wave-359 merge: repointed to open F489, F490, F491, F492, F493, F494, F495 / next F506 (footer-state probe audit).
    if nxt != 526 or open_s != "F521, F522, F523, F524, F525":  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d open %r (want next F429 "
                       "open 'F429')" % (nxt, open_s))
    _record("footer-state", "HELD", "footer pins open F521, F522, F523, F524, F525 / next F526")  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)


class _RubberStampManager:
    """An attacker's lease manager: check_write is a no-op."""
    def check_write(self, scope, fencing_token, holder_id,
                    checked_at=None):
        return True


def _branch_fx(bound=None):
    from gov import workflow_branch as wb
    from gov import coordination_lease as cl
    from gov import ed25519
    lm = cl.LeaseManager()
    lease = lm.acquire("scope-x", 100, "holder-1",
                       authority_seed=ed25519.generate_seed(),
                       issued_at=1000)
    c = wb.BranchCoordinator()
    # Wave-309 lane B: the manager is bound at begin() time, before
    # any park. `bound` overrides the default real manager (probes
    # that need a different oracle bound, e.g. the resume-side probe).
    xid = c.begin(ed25519.generate_seed(),
                  lease_manager=lm if bound is None else bound)
    return lm, lease["fencing_token"], c, xid


def _code_of(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", None)
    return "no-refusal"


def p_f391_suspend_substitute_refused():
    # The filed BREAK: after the holder's legitimate park, the
    # attacker's re-park with a rubber-stamp manager was ACCEPTED.
    # Now it must refuse coded coord-lease-manager-mismatch, and the
    # holder's park must be intact.
    lm, tok, c, xid = _branch_fx()
    rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                          suspended_at=1050)
    code = _code_of(lambda: c.suspend_lease(
        xid, _RubberStampManager(), "scope-x", 999999, "mallory",
        suspended_at=1060))
    if code != LEASE_MISMATCH:
        return _record("F391-suspend-substitute-refused", "BREAK",
                       "substitute-manager re-park not refused coded: "
                       "%r (F391 open?)" % (code,))
    try:
        ok = c.resume_lease(rec, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        return _record("F391-suspend-substitute-refused", "ERROR",
                       "holder resume refused after refused re-park: "
                       "%r" % (getattr(e, "code", e),))
    if ok is not True:
        return _record("F391-suspend-substitute-refused", "ERROR",
                       "holder resume returned %r" % (ok,))
    _record("F391-suspend-substitute-refused", "HELD",
            "substitute-manager re-park refused coded %s; holder "
            "resume intact" % LEASE_MISMATCH)


def p_f391_resume_substitute_refused():
    # The resume side: the liveness oracle must be the bound manager.
    # Begin with fake1 BOUND (begin-time binding), park with fake1,
    # then resume with a DIFFERENT substitute fake2 -- must refuse
    # coded, never let fake2 self-attest liveness.
    from gov import workflow_branch as wb
    from gov import ed25519 as _ed
    c = wb.BranchCoordinator()
    fake1 = _RubberStampManager()
    xid = c.begin(_ed.generate_seed(), lease_manager=fake1)
    evil = c.suspend_lease(xid, fake1, "scope-x", 999999, "mallory",
                           suspended_at=1060)
    code = _code_of(lambda: c.resume_lease(evil, _RubberStampManager(),
                                           checked_at=1090))
    if code != LEASE_MISMATCH:
        return _record("F391-resume-substitute-refused", "BREAK",
                       "substitute-manager resume not refused coded: "
                       "%r (F391 open?)" % (code,))
    _record("F391-resume-substitute-refused", "HELD",
            "substituted-manager resume refused coded %s"
            % LEASE_MISMATCH)


def p_f391_resume_substitute_after_legit_park():
    # F391 THIRD limb (wave-308 red-team lane D): the resume-time
    # liveness oracle is substitutable independently of the
    # suspend-time substitution. Legitimate park with the real manager
    # and the real token, then resume the parked record with a
    # SUBSTITUTED fake manager -- the coordinator must refuse coded
    # coord-lease-manager-mismatch, never let the fake self-attest
    # liveness. The legitimate resume afterwards must still work.
    lm, tok, c, xid = _branch_fx()
    rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                          suspended_at=1050)
    code = _code_of(lambda: c.resume_lease(rec, _RubberStampManager(),
                                           checked_at=1090))
    if code != LEASE_MISMATCH:
        return _record("F391-resume-substitute-after-legit-park",
                       "BREAK",
                       "fake-manager resume after legitimate park not "
                       "refused coded: %r (F391 third limb open)"
                       % (code,))
    try:
        ok = c.resume_lease(rec, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        return _record("F391-resume-substitute-after-legit-park",
                       "ERROR",
                       "legitimate resume after refused substitute "
                       "failed: %r" % (getattr(e, "code", e),))
    if ok is not True:
        return _record("F391-resume-substitute-after-legit-park",
                       "ERROR", "legitimate resume returned %r" % (ok,))
    _record("F391-resume-substitute-after-legit-park", "HELD",
            "fake-manager resume after legitimate park refused coded "
            "%s; legitimate resume intact" % LEASE_MISMATCH)


def p_f391_first_park_race_eliminated():
    # Wave-309 lane B: the first-park race is ELIMINATED by
    # begin-time binding. The deployment binds the real manager at
    # begin(); the attacker's first park with a substitute manager now
    # refuses coded coord-lease-manager-mismatch at park time -- there
    # is no unbound window to win. The holder's legitimate park
    # afterwards still works. (Replaces the wave-308 documented
    # residual probe: the residual is closed, not merely documented.)
    lm, tok, c, xid = _branch_fx()
    code = _code_of(lambda: c.suspend_lease(
        xid, _RubberStampManager(), "scope-x", 999999, "mallory",
        suspended_at=1060))
    if code != LEASE_MISMATCH:
        return _record("F391-first-park-race-eliminated", "BREAK",
                       "attacker's first park not refused coded: %r "
                       "(race still winnable)" % (code,))
    try:
        rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                              suspended_at=1070)
        ok = c.resume_lease(rec, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        return _record("F391-first-park-race-eliminated", "ERROR",
                       "holder park/resume after refused race failed: "
                       "%r" % (getattr(e, "code", e),))
    if ok is not True:
        return _record("F391-first-park-race-eliminated", "ERROR",
                       "holder resume returned %r" % (ok,))
    _record("F391-first-park-race-eliminated", "HELD",
            "attacker's first park refused coded %s at park time; "
            "holder park/resume intact (race eliminated)"
            % LEASE_MISMATCH)


def p_f391_park_without_begin_binding_refuses():
    # Fail-closed: a transaction begun WITHOUT a bound manager refuses
    # parks coded -- binding can never be won by racing the first
    # park, and a deployment that forgets to bind fails loudly at
    # suspend time instead of silently binding the first presenter.
    from gov import workflow_branch as wb
    from gov import coordination_lease as cl
    from gov import ed25519
    lm = cl.LeaseManager()
    lease = lm.acquire("scope-x", 100, "holder-1",
                       authority_seed=ed25519.generate_seed(),
                       issued_at=1000)
    c = wb.BranchCoordinator()
    xid = c.begin(ed25519.generate_seed())  # no manager bound
    code = _code_of(lambda: c.suspend_lease(
        xid, lm, "scope-x", lease["fencing_token"], "holder-1",
        suspended_at=1050))
    if code != LEASE_MISMATCH:
        return _record("F391-park-without-begin-binding-refuses",
                       "BREAK",
                       "park on unbound transaction not refused "
                       "coded: %r" % (code,))
    _record("F391-park-without-begin-binding-refuses", "HELD",
            "park on a transaction begun without a bound manager "
            "refuses coded %s (fail-closed)" % LEASE_MISMATCH)


def p_f391_legit_suspend_resume():
    # No regression: the legitimate park + resume with the bound
    # (identical) manager object works end to end.
    lm, tok, c, xid = _branch_fx()
    try:
        rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                              suspended_at=1050)
        ok = c.resume_lease(rec, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        return _record("F391-legit-suspend-resume", "BREAK",
                       "legitimate suspend/resume refused: %r "
                       "(regression)" % (getattr(e, "code", e),))
    if ok is not True:
        return _record("F391-legit-suspend-resume", "BREAK",
                       "legitimate resume returned %r (regression)"
                       % (ok,))
    _record("F391-legit-suspend-resume", "HELD",
            "legitimate suspend/resume with the bound manager works")


def p_f391_repark_same_manager():
    # The documented latest-wins re-park semantics survive: re-parking
    # with the IDENTICAL manager object still works.
    lm, tok, c, xid = _branch_fx()
    try:
        c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                        suspended_at=1050)
        rec2 = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                               suspended_at=1060)
        ok = c.resume_lease(rec2, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        return _record("F391-repark-same-manager", "BREAK",
                       "same-manager re-park refused: %r (regression)"
                       % (getattr(e, "code", e),))
    if ok is not True:
        return _record("F391-repark-same-manager", "BREAK",
                       "re-parked resume returned %r (regression)"
                       % (ok,))
    _record("F391-repark-same-manager", "HELD",
            "same-manager re-park keeps latest-wins semantics")


def p_f391_bogus_token_still_fencing():
    # F389 intact: with the REAL (bound) manager, a bogus token still
    # refuses coord-lease-fencing.
    lm, tok, c, xid = _branch_fx()
    c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                    suspended_at=1050)
    code = _code_of(lambda: c.suspend_lease(
        xid, lm, "scope-x", 999999, "mallory", suspended_at=1060))
    if code != "coord-lease-fencing":
        return _record("F391-bogus-token-still-fencing", "BREAK",
                       "bogus token with bound manager refused %r, "
                       "want coord-lease-fencing (F389 regressed)"
                       % (code,))
    _record("F391-bogus-token-still-fencing", "HELD",
            "bogus token with bound manager still refuses "
            "coord-lease-fencing (F389 intact)")


def p_f391_bind_after_proof():
    # The begin-time binding is independent of the F389 holdership
    # proof: a refused park (bogus token) disturbs nothing -- the
    # legitimate park afterwards still works against the bound
    # manager.
    lm, tok, c, xid = _branch_fx()
    code = _code_of(lambda: c.suspend_lease(
        xid, lm, "scope-x", 999999, "mallory", suspended_at=1050))
    if code != "coord-lease-fencing":
        return _record("F391-bind-after-proof", "ERROR",
                       "setup refusal was %r, want "
                       "coord-lease-fencing" % (code,))
    try:
        rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                              suspended_at=1060)
        ok = c.resume_lease(rec, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        return _record("F391-bind-after-proof", "BREAK",
                       "legitimate park after refused park failed: "
                       "%r" % (getattr(e, "code", e),))
    if ok is not True:
        return _record("F391-bind-after-proof", "BREAK",
                       "resume returned %r" % (ok,))
    _record("F391-bind-after-proof", "HELD",
            "refused park disturbs nothing; later legitimate park "
            "works against the begin-bound manager")


def _green_checks():
    if os.environ.get("GOV_SKIP_GREEN"):
        _record("green-skipped", "HELD", "green check skipped "
                                        "(GOV_SKIP_GREEN=1)")
        return
    # Depth-1 adjacent green checks (wave-134 lesson: never nest).
    # No expected-open BREAKs: F391 is closed, so every child must be
    # fully green.
    green_check.check_battery(
        _record, "green-w303_f389", "evals/w303_f389_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_battery(
        _record, "green-w303_f385", "evals/w303_f385_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_battery(
        _record, "green-w307_redteam", "evals/w307_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_unittest(
        _record, "green-test-workflow-branch",
        "tests.test_workflow_branch", repo=REPO)
    green_check.check_unittest(
        _record, "green-test-workflow-f389",
        "tests.test_workflow_f389", repo=REPO)


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F391-suspend-substitute-refused",
           p_f391_suspend_substitute_refused)
    _safe("F391-resume-substitute-refused",
           p_f391_resume_substitute_refused)
    _safe("F391-resume-substitute-after-legit-park",
           p_f391_resume_substitute_after_legit_park)
    _safe("F391-first-park-race-eliminated",
           p_f391_first_park_race_eliminated)
    _safe("F391-park-without-begin-binding-refuses",
           p_f391_park_without_begin_binding_refuses)
    _safe("F391-legit-suspend-resume", p_f391_legit_suspend_resume)
    _safe("F391-repark-same-manager", p_f391_repark_same_manager)
    _safe("F391-bogus-token-still-fencing",
           p_f391_bogus_token_still_fencing)
    _safe("F391-bind-after-proof", p_f391_bind_after_proof)
    _green_checks()
    b = h = e = 0
    for pid, verdict, note in _results:
        if verdict == "BREAK":
            b += 1
        elif verdict == "HELD":
            h += 1
        else:
            e += 1
    probe_lines.emit(_results)
    print("----")
    print("%d BREAK / %d HELD / %d ERROR" % (b, h, e))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, b, h, e)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    return 1 if (b or e) else 0


if __name__ == "__main__":
    sys.exit(main())
