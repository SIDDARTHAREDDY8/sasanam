"""Wave-242 stale-authority probe class (red-first).

W242-2 — stale-authority probe class (emirdag lapse as first instance).
After 2026-10-13T20:40:30Z, any evidence/verifier path accepting authority
citing ``draft-emirdag-scitt-ai-agent-execution-00`` must name the lapse.

  lapsed-authority-refused -- receipt minted 2026-10-14 citing the draft as
      normative authority -> refuse stale-authority with cause (a verifier
      that passes this probe has the "green on lapsed authority" defect).
  pre-expiry-receipt-annotated -- receipt minted 2026-10-01 citing the draft
      -> passes with downgraded-provenance annotation
      authority-expired-2026-10-13.
  live-draft-no-flag -- receipt minted 2026-10-14 citing a live draft
      (draft-saha-bound-permit-00) -> no stale-authority flag (control).
  prestaged-omp-refused -- receipt minted 2026-11-20 citing
      draft-veridom-omp-02 (pre-staged lapse posture) -> refuse
      stale-authority.
  malformed-minted-at-refused -- non-datetime minted_at -> refuse
      stale-authority-malformed (fail closed, never a silent pass).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback
from datetime import datetime, timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_SA = False
try:
    from gov import stale_authority as _sa
    HAVE_SA = all(hasattr(_sa, n) for n in (
        "check_authority", "StaleAuthorityError", "LAPSED_AUTHORITIES",
        "EMIRDAG_LAPSE_UTC"))
except ImportError:
    _sa = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "lapsed-authority-refused",
    "pre-expiry-receipt-annotated",
    "live-draft-no-flag",
    "prestaged-omp-refused",
    "malformed-minted-at-refused",
]


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _ts(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).replace(
        tzinfo=timezone.utc)


def _probe_lapsed_authority_refused():
    try:
        _sa.check_authority("draft-emirdag-scitt-ai-agent-execution-00",
                            _ts("2026-10-14T00:00:00Z"))
    except _sa.StaleAuthorityError as exc:
        assert exc.code == "stale-authority", exc.code
        assert "2026-10-13" in exc.detail, exc.detail
        assert "cause" in exc.detail.lower(), exc.detail
        return "refused stale-authority with cause for post-lapse receipt"
    raise AssertionError("post-lapse authority passed: green-on-lapsed defect")


def _probe_pre_expiry_receipt_annotated():
    verdict = _sa.check_authority("draft-emirdag-scitt-ai-agent-execution-00",
                                  _ts("2026-10-01T00:00:00Z"))
    assert verdict["status"] == "accepted", verdict
    assert verdict["provenance"] == "downgraded", verdict
    assert verdict["annotation"] == "authority-expired-2026-10-13", verdict
    return "pre-expiry receipt accepted with downgraded provenance"


def _probe_live_draft_no_flag():
    verdict = _sa.check_authority("draft-saha-bound-permit-00",
                                  _ts("2026-10-14T00:00:00Z"))
    assert verdict["status"] == "accepted", verdict
    assert "annotation" not in verdict, verdict
    return "live draft cites no stale-authority flag (control)"


def _probe_prestaged_omp_refused():
    try:
        _sa.check_authority("draft-veridom-omp-02",
                            _ts("2026-11-20T00:00:00Z"))
    except _sa.StaleAuthorityError as exc:
        assert exc.code == "stale-authority", exc.code
        assert "2026-11-14" in exc.detail, exc.detail
        return "pre-staged veridom-omp lapse posture refused"
    raise AssertionError("pre-staged lapsed authority passed")


def _probe_malformed_minted_at_refused():
    try:
        _sa.check_authority("draft-emirdag-scitt-ai-agent-execution-00",
                            "yesterday")
    except _sa.StaleAuthorityError as exc:
        assert exc.code == "stale-authority-malformed", exc.code
        return "non-datetime minted_at fails closed"
    raise AssertionError("malformed minted_at was not refused")


_PROBES = {
    "lapsed-authority-refused": (_probe_lapsed_authority_refused, HAVE_SA),
    "pre-expiry-receipt-annotated": (_probe_pre_expiry_receipt_annotated,
                                     HAVE_SA),
    "live-draft-no-flag": (_probe_live_draft_no_flag, HAVE_SA),
    "prestaged-omp-refused": (_probe_prestaged_omp_refused, HAVE_SA),
    "malformed-minted-at-refused": (_probe_malformed_minted_at_refused,
                                     HAVE_SA),
}


def _run_green_checks():
    """Adjacent-seam sanity: no product-code regression. Depth-1 only;
    honors GOV_SKIP_GREEN=1 (never spawns another battery's main)."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import decision_codes as _dc
        for code in ("stale-authority", "stale-authority-malformed"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-242 stale-authority probes (emirdag: %s)"
          % (HAVE_SA,))
    held = gap = 0
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        if status == "HELD":
            held += 1
        elif status == "GAP":
            gap += 1
        print("%-42s %s %s" % (name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    print("summary: %d HELD / %d GAP / %d total"
          % (held, gap, len(PROBE_NAMES)))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
