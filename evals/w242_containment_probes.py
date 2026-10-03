"""Wave-242 parent-permit refusal + currentness could-not-check (red-first).

W242-5 — parent-permit refusal + currentness could-not-check (onedoor
docs ADAPT). A permit naming a ``parent_permit`` reference is refused
outright (delegation containment; rhymes with wei §13 ``Contains``).
Presentation-time policy-currentness is recognized in the claim
vocabulary but always reports ``could-not-check`` (unavailable
mechanism, not a refusal).

Probes:
  parent-permit-refused -- permit declaring parent_permit -> refuse
      permit-parent-named at the admission step, never forwarded.
  parentless-permit-admitted -- same permit without a parent -> admitted
      (positive control).
  currentness-could-not-check -- check_currentness() with no authority
      wired -> could-not-check naming the currentness dependency, never
      "verified" (falsifies misattribution).
  currentness-wired-still-could-not-check -- the mechanism is unavailable
      even with an authority wired: honest gap, not a refusal.
  containment-violation-refused -- child grant bounds exceeding the
      parent's -> refuse delegation-containment-violated.
  containment-within-parent-ok -- child bounds within the parent's ->
      verifies (positive control).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_DC = False
try:
    from gov import delegation_containment as _dc
    HAVE_DC = all(hasattr(_dc, n) for n in (
        "declare_permit", "check_currentness", "verify_containment",
        "ContainmentError"))
except ImportError:
    _dc = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "parent-permit-refused",
    "parentless-permit-admitted",
    "currentness-could-not-check",
    "currentness-wired-still-could-not-check",
    "containment-violation-refused",
    "containment-within-parent-ok",
]


def _run_probe(name, fn, have):
    if not have:
        # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
        # gap-demonstrated evidence in the note.
        return name, "BREAK", "GAP: capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _probe_parent_permit_refused():
    try:
        _dc.declare_permit("permit-1", bounds={"spend": 100},
                           parent_permit="permit-0")
    except _dc.ContainmentError as exc:
        assert exc.code == "permit-parent-named", exc.code
        assert exc.step == "admission", exc.step
        assert "permit-0" in exc.detail, exc.detail
        return "refused permit-parent-named at admission, never forwarded"
    raise AssertionError("parent-permit reference was forwarded")


def _probe_parentless_permit_admitted():
    permit = _dc.declare_permit("permit-1", bounds={"spend": 100})
    assert permit["permit_id"] == "permit-1", permit
    assert permit["parent_permit"] is None, permit
    return "parentless permit admitted (positive control)"


def _probe_currentness_could_not_check():
    verdict = _dc.check_currentness()
    assert verdict["status"] == "could-not-check", verdict
    assert verdict["dependency"] == "policy-currentness-authority", verdict
    assert "verified" not in verdict["status"], verdict
    return "currentness could-not-check names its dependency"


def _probe_currentness_wired_still_could_not_check():
    # The currentness mechanism is unavailable even with an authority
    # wired: an honest gap, not a refusal. Must never claim "verified".
    verdict = _dc.check_currentness(policy_authority={"name": "ops"})
    assert verdict["status"] == "could-not-check", verdict
    assert verdict["dependency"] == "policy-currentness-authority", verdict
    return "wired currentness still could-not-check (honest gap)"


def _probe_containment_violation_refused():
    try:
        _dc.verify_containment(parent_bounds={"spend": 100, "depth": 3},
                               child_bounds={"spend": 150, "depth": 2})
    except _dc.ContainmentError as exc:
        assert exc.code == "delegation-containment-violated", exc.code
        assert "spend" in exc.detail, exc.detail
        return "refused delegation-containment-violated naming spend"
    raise AssertionError("child exceeding parent passed containment")


def _probe_containment_within_parent_ok():
    verdict = _dc.verify_containment(parent_bounds={"spend": 100, "depth": 3},
                                     child_bounds={"spend": 50, "depth": 3})
    assert verdict["ok"] is True, verdict
    assert verdict["violated"] == [], verdict
    return "child within parent bounds verifies"


_PROBES = {
    "parent-permit-refused": (_probe_parent_permit_refused, HAVE_DC),
    "parentless-permit-admitted": (_probe_parentless_permit_admitted, HAVE_DC),
    "currentness-could-not-check": (_probe_currentness_could_not_check,
                                    HAVE_DC),
    "currentness-wired-still-could-not-check": (
        _probe_currentness_wired_still_could_not_check, HAVE_DC),
    "containment-violation-refused": (_probe_containment_violation_refused,
                                      HAVE_DC),
    "containment-within-parent-ok": (_probe_containment_within_parent_ok,
                                     HAVE_DC),
}


def _run_green_checks():
    """Adjacent-seam sanity: no product-code regression. Depth-1 only;
    honors GOV_SKIP_GREEN=1 (never spawns another battery's main)."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import decision_codes as _tax
        for code in ("permit-parent-named",
                     "permit-currentness-could-not-check",
                     "delegation-containment-violated"):
            _tax.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-242 parent-permit / currentness probes (containment: %s)"
          % (HAVE_DC,))
    results = []
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        results.append((name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    held = sum(1 for _n, s, _d in results if s == "HELD")
    brk = sum(1 for _n, s, _d in results if s == "BREAK")
    err = sum(1 for _n, s, _d in results if s == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(results, brk, held, err)
    probe_lines.emit(results)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
