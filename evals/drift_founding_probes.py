#!/usr/bin/env python3
"""Row-9 founding-evidence gate probes (row-9 team).

Row 9's measured residual: wave-134's ``validate_baseline_against_population``
compares tool-distribution fingerprints only. An attacker who shapes a
from-birth baseline to match the population (exact-copy validates trusted --
the pinned ceiling) keeps a poisoned baseline, and every later drift verdict
computes against it. Meanwhile the founding runs may carry triage signals on
OTHER seams (DLP flags, canary trips, erosion counters, denied approvals)
that no baseline-validation seam ever looks at. Pre-seam,
``gov.drift_budget`` has no API and no record for founding-window triage
signals: they are dropped on the floor.

The seam under test (``BudgetStore.note_founding_signal`` /
``confirm_founding`` + the founding-suspect mark): a founding run (first
``founding_window_runs`` runs, default 5) carrying any triage signal keeps
the baseline provisional -- a chained ``founding_suspect`` mark plus a LOUD
``founding_evidence_suspect`` event. While the mark holds, the agent budgets
as if one adaptive tightening had occurred (effective level floor 1 --
reused machinery, not a parallel tripwire). Clearance: human
``confirm_founding`` or ``founding_confirm_runs`` (default 3) consecutive
signal-free recorded runs (auto). This composes with -- never duplicates or
consults -- gov.drift's population check: different evidence (founding
triage signals vs tool-distribution distances), different mark.

  f1_core_mark: in-window triage signal -> mark set, exactly one LOUD
     ``founding_evidence_suspect``, chained ``founding_suspect`` record,
     chain verifies.
  f2_benign_silent: no signals -> never marked, zero LOUD founding
     events (FP pin).
  f3_late_signal_no_mark: signal past the founding window -> recorded
     (audited, non-LOUD) but no mark, no LOUD.
  f4_human_confirm: mark -> confirm_founding -> cleared, non-LOUD
     ``founding_evidence_confirmed`` (reason human); enforcement back
     to unmarked limits.
  f5_auto_confirm: mark at run 2, signal-free runs 3-5 -> auto-cleared
     after run 5 (reason auto), chained ``founding_confirmed``.
  f6_auto_confirm_broken: a second in-window signal restarts the
     signal-free count (clears after run 7, not run 5).
  f7_enforcement: while marked, one 0.7-threshold contributing run
     trips check() (tightened 0.6 limit + single-run trip rule); the
     identical run unmarked stays ok. Measurable enforcement, not
     just an event.
  f8_remark_after_confirm: human confirm, then a NEW in-window signal
     -> marked again with a second LOUD event (confirmation covers
     evidence seen so far; late evidence re-marks).
  f9_determinism: the f1 sequence twice -> identical record-kind and
     audit-event sequences.
  f10_silent_founding_ceiling: EXPECTED, not a BREAK. A from-birth
     attacker whose founding window is clean of EVERY triage seam
     still validates -- the gate answers "founding carried signals",
     not "agent is good". Pinned honest ceiling.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

If the seam is missing, f1-f9 are BREAK ("not implemented"): the gap
is pinned red (pre-feature state). f10 is EXPECTED with or without
the seam.

Honest ceilings (also in the module docstring):
- A from-birth attacker who keeps the founding window clean of all
  triage signals validates (f10) -- the gate narrows the
  exact-copy-population evasion, it does not kill from-birth malice.
- Whole-population/Sybil shaping still defeats the wave-134 half;
  this gate is the independent second input, not a fix for that.
- founding_window_runs / founding_confirm_runs are operator policy:
  an attacker who keeps triage signals out of the first 5 runs, or
  who spaces signals so 3 signal-free runs always follow, evades by
  construction.
- The mark is the BUDGET's provisional stance only; it does not
  change gov.drift's baseline trust state (different module, not
  touched).
- Signals are operator-reported: the gate cannot see a triage signal
  the harness never reports (same boundary as every other seam).

$0 spend, synthetic/local, deterministic (no RNG; no wall-clock in
verdicts). Stdlib only.

Run:
  mkdir -p /tmp/gov-founding
  TMPDIR=/tmp/gov-founding ~/workspace/.gov-venv/bin/python \\
    evals/drift_founding_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-foundingb \\
    ~/workspace/.gov-venv/bin/python evals/drift_founding_probes.py
"""

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-founding-%d" % os.getpid())
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from gov import drift as _drift  # noqa: E402
    from gov import drift_budget as _budget  # noqa: E402
    _HAVE = True
    _IMPORT_ERROR = ""
except ImportError as _e:  # noqa: E402
    _drift = None
    _budget = None
    _HAVE = False
    _IMPORT_ERROR = str(_e)

_HAVE_SEAM = _HAVE and all(
    hasattr(_budget.BudgetStore, n)
    for n in ("note_founding_signal", "confirm_founding"))

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-34s %-10s %s" % (name, verdict, detail))


def _need_seam(name):
    if not _HAVE_SEAM:
        _record(name, "BREAK",
                "founding-evidence seam missing: %s" % _IMPORT_ERROR)
        return False
    return True


# ------------------------------------------------------------ fixtures

_BASE_TOOLS = {"search": 90, "summarize": 80, "email": 60,
               "read_file": 40, "http_post": 10}


def _fp(tools, run_seq=0, run_id="r"):
    return _drift.RunFingerprint(
        tool_counts=dict(tools),
        decisions={"allow": sum(tools.values()), "require_approval": 0,
                   "deny": 0},
        approvals_requested=0, approvals_granted=0, approvals_denied=0,
        egress_events=1, egress_bytes=1000,
        run_seq=run_seq, run_id="%s-%d" % (run_id, run_seq))


def _shifted(x):
    t = dict(_BASE_TOOLS)
    t["search"] -= x
    t["http_post"] += x
    return t


_BASE_FP = None


def _base_fp():
    global _BASE_FP
    if _BASE_FP is None:
        _BASE_FP = _fp(_BASE_TOOLS)
    return _BASE_FP


def _calibrate():
    d10 = _drift.fingerprint_tool_distance(_fp(_shifted(10)), _base_fp())
    return d10 / 0.4


def _scan_ratio(warn, lo_frac, hi_frac, lo=1, hi=120):
    """Largest shift x with lo_frac <= D(x)/warn < hi_frac."""
    # Keep every tool count strictly positive: _shifted(x) moves x
    # calls from "search" (90 base) to "http_post".
    hi = min(hi, _BASE_TOOLS["search"] - 1)
    best = None
    for x in range(lo, hi + 1):
        d = _drift.fingerprint_tool_distance(_fp(_shifted(x)),
                                             _base_fp())
        r = d / warn
        if lo_frac <= r < hi_frac:
            best = (x, r)
    return best


class _Ctx:
    """Fresh store + event sink per probe."""

    def __init__(self, tag, policy):
        self.events = []
        root = Path(tempfile.mkdtemp(prefix="founding_%s_" % tag,
                                     dir=os.environ["TMPDIR"]))
        self.store = _budget.BudgetStore(root / "budget",
                                        audit=self._audit)
        self.policy = policy

    def _audit(self, event):
        self.events.append(dict(event))

    def record(self, agent, tools, seq, run_id="r"):
        return self.store.record_run(agent, seq, "run-%d" % seq,
                                     _fp(tools, seq, run_id),
                                     _base_fp(), self.policy)

    def note(self, agent, seq, kind="dlp_entropy_flag", detail=None):
        return self.store.note_founding_signal(
            agent, seq, kind, detail=detail, policy=self.policy,
            audit=self._audit)

    def loud(self, name=None):
        return [e for e in self.events
                if e.get("severity") == "LOUD"
                and (name is None or e.get("event") == name)]

    def kinds(self, agent):
        return [r.get("kind") for r in self.store._read_all(agent)]

    def marked(self, agent):
        return self.store._founding_fold(
            self.store._read_all(agent))[0]


# --------------------------------------------------------------- probes

def f1_core_mark(warn):
    name = "f1_core_mark"
    if not _need_seam(name):
        return
    try:
        policy = _budget.BudgetPolicy(warn)
        ctx = _Ctx("f1", policy)
        note = ctx.note("mallory", 2, "dlp_entropy_flag",
                        detail={"egress": "http_post"})
        ok = (note.in_window and note.mark_set and note.marked
              and ctx.marked("mallory"))
        loud = ctx.loud("founding_evidence_suspect")
        kinds = ctx.kinds("mallory")
        ok = ok and len(loud) == 1 and "founding_suspect" in kinds \
            and "founding_signal" in kinds
        ok = ok and loud[0].get("signal_kind") == "dlp_entropy_flag" \
            and loud[0].get("run_seq") == 2
        ok = ok and ctx.store.verify_chain("mallory")
        _record(name, "HELD" if ok else "BREAK",
                "mark=%s loud_suspect=%d chain_kinds=%s"
                % (ctx.marked("mallory"), len(loud), kinds))
    except Exception as e:  # noqa: BLE001
        _record(name, "ERROR", "%r" % (e,))


def f2_benign_silent(warn):
    name = "f2_benign_silent"
    if not _need_seam(name):
        return
    try:
        policy = _budget.BudgetPolicy(warn)
        ctx = _Ctx("f2", policy)
        for seq in (1, 2, 3):
            ctx.record("alice", _BASE_TOOLS, seq)
        chk = ctx.store.check("alice", policy, audit=ctx._audit)
        ok = (not ctx.marked("alice")
              and len(ctx.loud("founding_evidence_suspect")) == 0
              and chk.status == "ok")
        _record(name, "HELD" if ok else "BREAK",
                "marked=%s loud=%d check=%s"
                % (ctx.marked("alice"),
                   len(ctx.loud("founding_evidence_suspect")),
                   chk.status))
    except Exception as e:  # noqa: BLE001
        _record(name, "ERROR", "%r" % (e,))


def f3_late_signal_no_mark(warn):
    name = "f3_late_signal_no_mark"
    if not _need_seam(name):
        return
    try:
        policy = _budget.BudgetPolicy(warn)
        ctx = _Ctx("f3", policy)
        for seq in range(1, 7):
            ctx.record("bob", _BASE_TOOLS, seq)
        note = ctx.note("bob", 9, "canary_trip")
        ok = (not note.in_window and not note.mark_set
              and not note.marked and not ctx.marked("bob"))
        ok = ok and len(ctx.loud("founding_evidence_suspect")) == 0
        noted = [e for e in ctx.events
                 if e.get("event") == "founding_signal_noted"]
        ok = ok and len(noted) == 1 and "founding_signal" in \
            ctx.kinds("bob")
        _record(name, "HELD" if ok else "BREAK",
                "in_window=%s marked=%s noted_events=%d"
                % (note.in_window, ctx.marked("bob"), len(noted)))
    except Exception as e:  # noqa: BLE001
        _record(name, "ERROR", "%r" % (e,))


def f4_human_confirm(warn):
    name = "f4_human_confirm"
    if not _need_seam(name):
        return
    try:
        policy = _budget.BudgetPolicy(warn)
        ctx = _Ctx("f4", policy)
        ctx.note("mallory", 2, "erosion_signal")
        assert ctx.marked("mallory")
        confirmed = ctx.store.confirm_founding("mallory",
                                              audit=ctx._audit)
        ok = confirmed and not ctx.marked("mallory")
        ev = [e for e in ctx.events
              if e.get("event") == "founding_evidence_confirmed"]
        ok = ok and len(ev) == 1 and ev[0].get("reason") == "human" \
            and ev[0].get("severity") != "LOUD"
        ok = ok and "founding_confirmed" in ctx.kinds("mallory")
        # Enforcement back to unmarked limits: a lone 0.7 run is ok.
        x, ratio = _scan_ratio(warn, 0.6, 0.95)
        ctx.record("mallory", _shifted(x), 3)
        chk = ctx.store.check("mallory", policy, audit=ctx._audit)
        ok = ok and chk.status == "ok"
        _record(name, "HELD" if ok else "BREAK",
                "confirmed=%s marked=%s check=%s ratio=%.3f"
                % (confirmed, ctx.marked("mallory"), chk.status,
                   ratio))
    except Exception as e:  # noqa: BLE001
        _record(name, "ERROR", "%r" % (e,))


def f5_auto_confirm(warn):
    name = "f5_auto_confirm"
    if not _need_seam(name):
        return
    try:
        policy = _budget.BudgetPolicy(warn)
        ctx = _Ctx("f5", policy)
        ctx.note("carol", 2, "approval_denied")
        assert ctx.marked("carol")
        for seq in (3, 4):
            ctx.record("carol", _BASE_TOOLS, seq)
            assert ctx.marked("carol"), "cleared too early"
        ctx.record("carol", _BASE_TOOLS, 5)
        ok = not ctx.marked("carol")
        ev = [e for e in ctx.events
              if e.get("event") == "founding_evidence_confirmed"]
        ok = ok and len(ev) == 1 and ev[0].get("reason") == "auto"
        rec = [r for r in ctx.store._read_all("carol")
               if r.get("kind") == "founding_confirmed"]
        ok = ok and len(rec) == 1 and rec[0].get("reason") == "auto"
        _record(name, "HELD" if ok else "BREAK",
                "marked_after_5=%s confirm_events=%d"
                % (ctx.marked("carol"), len(ev)))
    except Exception as e:  # noqa: BLE001
        _record(name, "ERROR", "%r" % (e,))


def f6_auto_confirm_broken(warn):
    name = "f6_auto_confirm_broken"
    if not _need_seam(name):
        return
    try:
        policy = _budget.BudgetPolicy(warn)
        ctx = _Ctx("f6", policy)
        ctx.note("dave", 2, "dlp_entropy_flag")
        ctx.record("dave", _BASE_TOOLS, 3)
        ctx.note("dave", 4, "canary_trip")  # second in-window signal
        for seq in (5, 6):
            ctx.record("dave", _BASE_TOOLS, seq)
        mid = ctx.marked("dave")
        ctx.record("dave", _BASE_TOOLS, 7)
        ok = mid and not ctx.marked("dave")
        _record(name, "HELD" if ok else "BREAK",
                "marked_after_6=%s marked_after_7=%s" % (mid,
                      ctx.marked("dave")))
    except Exception as e:  # noqa: BLE001
        _record(name, "ERROR", "%r" % (e,))


def f7_enforcement(warn):
    name = "f7_enforcement"
    if not _need_seam(name):
        return
    try:
        policy = _budget.BudgetPolicy(warn)
        found = _scan_ratio(warn, 0.6, 0.95)
        assert found, "no 0.6-0.95 shift in scan range"
        x, ratio = found
        # Marked agent: one 0.7 run trips under the tightened limit.
        ctx = _Ctx("f7a", policy)
        ctx.note("mallory", 1, "dlp_entropy_flag")
        c = ctx.record("mallory", _shifted(x), 1)
        assert c.contributes, "probe run must contribute (ratio=%.3f)" \
            % ratio
        chk = ctx.store.check("mallory", policy, audit=ctx._audit)
        trip_ev = [e for e in ctx.events
                   if e.get("event") == "drift_budget_tripped"]
        ok = (chk.status == "tripped" and len(trip_ev) == 1
              and trip_ev[0].get("founding_suspect") is True)
        # Control: identical run, no mark -> ok.
        ctl = _Ctx("f7b", policy)
        ctl.record("mallory", _shifted(x), 1)
        chk2 = ctl.store.check("mallory", policy, audit=ctl._audit)
        ok = ok and chk2.status == "ok"
        _record(name, "HELD" if ok else "BREAK",
                "marked=%s control=%s ratio=%.3f"
                % (chk.status, chk2.status, ratio))
    except Exception as e:  # noqa: BLE001
        _record(name, "ERROR", "%r" % (e,))


def f8_remark_after_confirm(warn):
    name = "f8_remark_after_confirm"
    if not _need_seam(name):
        return
    try:
        policy = _budget.BudgetPolicy(warn)
        ctx = _Ctx("f8", policy)
        ctx.note("erin", 2, "dlp_entropy_flag")
        assert ctx.marked("erin")
        assert ctx.store.confirm_founding("erin", audit=ctx._audit)
        assert not ctx.marked("erin")
        note = ctx.note("erin", 4, "canary_trip")
        ok = note.mark_set and note.marked and ctx.marked("erin")
        ok = ok and len(ctx.loud("founding_evidence_suspect")) == 2
        _record(name, "HELD" if ok else "BREAK",
                "remarked=%s loud_suspect_events=%d"
                % (ctx.marked("erin"),
                   len(ctx.loud("founding_evidence_suspect"))))
    except Exception as e:  # noqa: BLE001
        _record(name, "ERROR", "%r" % (e,))


def f9_determinism(warn):
    name = "f9_determinism"
    if not _need_seam(name):
        return
    try:
        seqs = []
        for tag in ("f9a", "f9b"):
            policy = _budget.BudgetPolicy(warn)
            ctx = _Ctx(tag, policy)
            ctx.note("mallory", 2, "dlp_entropy_flag",
                     detail={"egress": "http_post"})
            ctx.record("mallory", _BASE_TOOLS, 3)
            ctx.store.confirm_founding("mallory", audit=ctx._audit)
            seqs.append((
                [r.get("kind") for r in
                 ctx.store._read_all("mallory")],
                [(e.get("event"), e.get("severity")) for e in
                 ctx.events]))
        ok = seqs[0] == seqs[1]
        _record(name, "HELD" if ok else "BREAK",
                "identical=%s" % ok)
    except Exception as e:  # noqa: BLE001
        _record(name, "ERROR", "%r" % (e,))


def f10_silent_founding_ceiling(warn):
    # EXPECTED with or without the seam: a from-birth attacker whose
    # founding window is clean of every triage seam still validates.
    # The gate answers "founding carried signals", not "agent is good".
    name = "f10_silent_founding_ceiling"
    if not _HAVE_SEAM:
        _record(name, "EXPECTED",
                "no seam; ceiling holds vacuously pre-seam")
        return
    try:
        policy = _budget.BudgetPolicy(warn)
        ctx = _Ctx("f10", policy)
        for seq in range(1, 6):
            ctx.record("ghost", _BASE_TOOLS, seq)
        ok = (not ctx.marked("ghost")
              and len(ctx.loud("founding_evidence_suspect")) == 0)
        _record(name, "EXPECTED" if ok else "BREAK",
                "signal-free founding validates by design "
                "(marked=%s)" % ctx.marked("ghost"))
    except Exception as e:  # noqa: BLE001
        _record(name, "ERROR", "%r" % (e,))


def main():
    print("row-9 founding-evidence gate probes")
    print("seam present: %s" % _HAVE_SEAM)
    if not _HAVE:
        for n in ("f1_core_mark", "f2_benign_silent",
                  "f3_late_signal_no_mark", "f4_human_confirm",
                  "f5_auto_confirm", "f6_auto_confirm_broken",
                  "f7_enforcement", "f8_remark_after_confirm",
                  "f9_determinism"):
            _record(n, "BREAK", "import failed: %s" % _IMPORT_ERROR)
        f10_silent_founding_ceiling(None)
    else:
        warn = _calibrate()
        print("calibrated warn_distance=%.6f" % warn)
        f1_core_mark(warn)
        f2_benign_silent(warn)
        f3_late_signal_no_mark(warn)
        f4_human_confirm(warn)
        f5_auto_confirm(warn)
        f6_auto_confirm_broken(warn)
        f7_enforcement(warn)
        f8_remark_after_confirm(warn)
        f9_determinism(warn)
        f10_silent_founding_ceiling(warn)
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("summary: %d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
