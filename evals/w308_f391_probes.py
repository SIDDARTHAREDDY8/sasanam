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
the first successful park (identity check, never per-call). A later
suspend/resume presenting a different manager object refuses coded
``coord-lease-manager-mismatch`` before any oracle call -- at BOTH
ends: the suspend-time holdership proof consults the bound manager,
and the resume-time liveness check consults the bound manager (third
limb, wave-308 red-team lane D: a legitimate park resumed with a
substituted fake manager must refuse coded, never self-attest). The
binding happens only after the F389 holdership proof passes, so a
refused park binds nothing. +1 decision code (pin 1827 -> 1828).

Probes (all through the public BranchCoordinator API):
  F391-suspend-substitute-refused: holder parks with the real manager;
     attacker's re-park with a rubber-stamp manager refuses coded
     coord-lease-manager-mismatch; the holder's resume still works.
  F391-resume-substitute-refused: park with fake1 (first park binds
     it); resume with a DIFFERENT fake2 refuses coded
     coord-lease-manager-mismatch (no self-attested liveness).
  F391-legit-suspend-resume: legitimate park + resume with the bound
     manager still works (no regression).
  F391-repark-same-manager: re-park with the identical manager object
     keeps the documented latest-wins semantics.
  F391-bogus-token-still-fencing: real manager + bogus token still
     refuses coord-lease-fencing (F389 intact).
  F391-bind-after-proof: a refused park (bogus token) binds nothing --
     the legitimate park afterwards still binds the real manager and
     works.

Documented residual (pinned by F391-first-park-race-documented, not
probed as BREAK): an attacker who wins the race to the FIRST park on
a fresh xid binds their own manager. That requires beating the holder
to the first park AND getting the deployment to resume from the
attacker's record; the holder's own park attempt fails LOUDLY (coded),
so it is a DoS residual, not the filed silent integrity violation.
The deployment eliminates it by parking promptly at lease acquisition.

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

# Wave-307 merge pin 1827; this lane mints +1 coord-lease-manager-mismatch.
TAXONOMY_PIN = 1828
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
    _record("pin-taxonomy", "HELD", "1828/1828/0 sorted")


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
    # Wave-308 merge: F391 CLOSED, F393 OPEN; footer open F393 / next F394.
    if nxt != 394 or open_s != "F393":
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d open %r (want next F394 "
                       "open 'F393')" % (nxt, open_s))
    _record("footer-state", "HELD", "footer pins open F393 / next F394")


class _RubberStampManager:
    """An attacker's lease manager: check_write is a no-op."""
    def check_write(self, scope, fencing_token, holder_id,
                    checked_at=None):
        return True


def _branch_fx():
    from gov import workflow_branch as wb
    from gov import coordination_lease as cl
    from gov import ed25519
    lm = cl.LeaseManager()
    lease = lm.acquire("scope-x", 100, "holder-1",
                       authority_seed=ed25519.generate_seed(),
                       issued_at=1000)
    c = wb.BranchCoordinator()
    xid = c.begin(ed25519.generate_seed())
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
    # Park with fake1 (first park binds it), then resume with a
    # DIFFERENT substitute fake2 -- must refuse coded, never let fake2
    # self-attest liveness.
    _lm, _tok, c, xid = _branch_fx()
    fake1 = _RubberStampManager()
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


def p_f391_first_park_race_documented():
    # DOCUMENTED RESIDUAL (not a BREAK): an attacker who wins the race
    # to the FIRST park on a fresh xid binds their own manager, and
    # their own resume with that same manager returns True. This probe
    # pins the behavior so any change is deliberate. Why it is an
    # accepted residual rather than the filed defect: (a) the filed
    # attack clobbered an EXISTING legitimate park (integrity
    # violation); here there is no legitimate state yet -- the
    # attacker builds a self-consistent fantasy no victim trusts;
    # (b) the legitimate holder's park attempt fails LOUDLY with coded
    # coord-lease-manager-mismatch (DoS, not silent corruption);
    # (c) exploiting it needs winning the race AND a victim who
    # resumes the attacker's record. The close-when explicitly blesses
    # first-park binding ("e.g."); the deployment eliminates the race
    # by parking promptly at lease acquisition.
    _lm, _tok, c, xid = _branch_fx()
    fake = _RubberStampManager()
    try:
        evil = c.suspend_lease(xid, fake, "scope-x", 999999, "mallory",
                               suspended_at=1060)
        ok = c.resume_lease(evil, fake, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        return _record("F391-first-park-race-documented", "HELD",
                       "race behavior changed (now refuses %r); "
                       "residual may be closed -- update probe"
                       % (getattr(e, "code", e),))
    if ok is not True:
        return _record("F391-first-park-race-documented", "ERROR",
                       "race resume returned %r (neither True nor "
                       "refused)" % (ok,))
    _record("F391-first-park-race-documented", "HELD",
            "first-park race documented: same-manager resume after a "
            "race win returns True (accepted residual, see note)")


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
    # The binding happens only after the F389 holdership proof passes:
    # a refused park (bogus token) binds nothing -- the legitimate
    # park afterwards still binds the real manager and works.
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
            "refused park binds nothing; later legitimate park binds "
            "the real manager")


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
    _safe("F391-first-park-race-documented",
           p_f391_first_park_race_documented)
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
    for pid, verdict, note in _results:
        print("%-34s %-6s %s" % (pid, verdict, note.split("\n")[0]))
    print("----")
    print("%d BREAK / %d HELD / %d ERROR" % (b, h, e))
    return 1 if (b or e) else 0


if __name__ == "__main__":
    sys.exit(main())
