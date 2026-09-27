#!/usr/bin/env python3
"""Row-9 framing suspect audit-before-mutation ordering probes (wave-150 lane 1).

Wave-149 residual: the framing-drift tripwire (``_framing_check`` in
``gov/drift_budget.py``) emitted the LOUD ``framing_drift_suspect``
audit event BEFORE the chained adapt write. If the adapt write failed
(disk full, read-only store dir, crash between the two), the suspect
event existed WITHOUT its adaptation -- an inconsistent state: the
audit log claims a tightening that never landed, while the budget
silently stays at its prior level.

Wave-150 fix (a CONSISTENCY fix, not a new detector): the suspect
verdict is computed, the chained adapt write is attempted FIRST, and
the LOUD ``framing_drift_suspect`` event is emitted only on
successful write. On write failure a LOUD
``framing_adapt_write_failed`` event carries the verdict details and
the budget stays at its prior level (fail-closed; never a phantom
suspect).

RED-FIRST: pre-fix, o1 is BREAK -- the suspect event is emitted even
though the chained adapt write raises, so the audit log holds a
phantom suspect with no adapt record and the level unchanged.

Probe map:
  o1_adapt_write_failure_no_phantom_suspect: 9 contributing runs land
     normally; the 10th run's chained adapt write is failed at the
     adapt seam. A literal read-only directory would fail the
     contribution write first under the same fail-closed convention
     (a different, already-closed seam), so the injection is surgical
     at the adapt seam -- exactly the residual under test -- and is
     faithful: with the framing path's post-write-audit mode there is
     nothing to emit before the chained write raises, so NO audit
     event precedes the failure (the wave-150 review strengthened
     this: the pre-review fix still emitted a phantom
     ``drift_budget_adapted`` via the class-wide audit-before-write
     convention). Expect: one LOUD ``framing_adapt_write_failed``
     carrying the verdict details, ZERO ``framing_drift_suspect``
     events, ZERO ``drift_budget_adapted`` (framing_drift) events,
     budget level 0, no framing_drift adapt record in the chain.
  o1b_audit_failure_after_landed_write_not_misreported: cold
     corner of the post-write-audit mode -- the chained adapt write
     LANDS, then the audit callable itself raises (audit pipeline
     failure, distinct from a store write failure). Must NOT be
     misreported as ``framing_adapt_write_failed`` (phantom-failure
     claim: the adaptation is real). Expect: the OSError propagates
     fail-loud out of record_run, no write_failed event, no suspect
     event, chain verifies with the real adapt at level 1 (the
     chain stays the source of truth).
  o2_normal_path_suspect_and_adapt_together: 10 contributing runs on
     a healthy store -> LOUD ``framing_drift_suspect`` AND the
     ``drift_budget_adapted`` (framing_drift) event, with the suspect
     AFTER the adapt write in event order (adapted is emitted
     post-write, then the suspect -- pins the new ordering), level 1,
     chain verifies.
  o3_deterministic_x2: byte-identical verdicts across 2 runs.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic. Stdlib only.

Run:
  mkdir -p /tmp/gov-framingorder
  TMPDIR=/tmp/gov-framingorder ~/workspace/.gov-venv/bin/python \\
      evals/framing_order_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-framingorder2 \\
      ~/workspace/.gov-venv/bin/python evals/framing_order_probes.py
"""

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-framingorder-%d" % os.getpid())
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import drift as _drift  # noqa: E402
from gov import drift_budget as _budget  # noqa: E402
from gov.chained_store import canonical, sha256_hex  # noqa: E402

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


BOILERPLATE = "routine cleanup"


class _Ctx:
    """Fresh store + event sink per probe."""

    def __init__(self, tag, policy):
        self.events = []
        root = Path(tempfile.mkdtemp(prefix="framingorder_%s_" % tag,
                                     dir=os.environ["TMPDIR"]))
        self.store = _budget.BudgetStore(root / "budget",
                                         audit=self._audit)
        self.policy = policy

    def _audit(self, event):
        self.events.append(dict(event))

    def record(self, agent, tools, seq, framing=""):
        return self.store.record_run(agent, seq, "run-%d" % seq,
                                     _fp(tools, run_seq=seq,
                                         run_id="run-%d" % seq),
                                     _base_fp(), self.policy,
                                     framing=framing)

    def suspects(self):
        return [e for e in self.events
                if e.get("event") == "framing_drift_suspect"]

    def failures(self):
        return [e for e in self.events
                if e.get("event") == "framing_adapt_write_failed"]

    def level(self, agent):
        records = self.store._read_all(agent)
        lvl, _, _, _, _, _, _, _ = self.store._adapt_fold(records)
        return lvl

    def framing_adapts(self, agent):
        return [r for r in self.store._read_all(agent)
                if r.get("kind") == "adapt"
                and r.get("trigger") == "framing_drift"]


def _adaptive_policy(warn, **kw):
    args = dict(warn_distance=warn, budget_limit=1.0, window_runs=8,
                noise_floor=0.1, min_consistency=0.5,
                slow_trip=1e9)  # park slow-burn: isolate framing
    args.update(kw)
    return _budget.AdaptiveBudgetPolicy(**args)


_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-44s %-10s %s" % (name, verdict, detail))


# ------------------------------------------- write-failure injection

_orig_append = _budget.BudgetStore._append_chained


def _seam_failing_append(self, agent_id, record, audit_event, auditor):
    """Fail exactly the chained ADAPT write, faithfully.

    Reproduces a genuine write failure at the chained-write line
    (read-only store dir, disk full): digests are computed, then the
    file write raises OSError. With the framing path's
    post-write-audit mode the auditor is suppressed for this write,
    so -- faithfully -- no audit event is emitted before the raise:
    there is nothing to emit yet, because the adaptation never
    landed.
    """
    if record.get("kind") == "adapt":
        prev = self._head(agent_id)
        record["prev_digest"] = prev
        record["digest"] = sha256_hex(canonical(
            {k: v for k, v in record.items() if k != "digest"}))
        if auditor is not None:
            event = dict(audit_event)
            event["digest"] = record["digest"]
            event["prev_digest"] = prev
            auditor(event)
        raise OSError("injected write failure at the chained adapt "
                      "seam (simulated read-only store dir)")
    return _orig_append(self, agent_id, record, audit_event, auditor)


# ---------------------------------------------------------------- probes

def o1_adapt_write_failure_no_phantom_suspect():
    name = "o1_adapt_write_failure_no_phantom_suspect"
    warn = _calibrate()
    ctx = _Ctx("o1", _adaptive_policy(warn))
    _budget.BudgetStore._append_chained = _seam_failing_append
    raised = None
    try:
        for i in range(10):
            ctx.record("agent-fail", _shifted(10), i + 1,
                       framing=BOILERPLATE)
    except OSError as exc:
        # Pre-fix behavior: the write failure propagates out of
        # record_run uncaught. Post-fix: _framing_check converts it
        # into the LOUD failure event and record_run returns.
        raised = exc
    finally:
        _budget.BudgetStore._append_chained = _orig_append
    failures = ctx.failures()
    suspects = ctx.suspects()
    level = ctx.level("agent-fail")
    adapts = ctx.framing_adapts("agent-fail")
    if raised is not None:
        _record(name, "BREAK",
                "write failure propagated out of record_run uncaught "
                "(%s) AND %d suspect event(s) already emitted -- the "
                "pre-fix ordering" % (raised, len(suspects)))
        return
    if len(failures) != 1:
        _record(name, "BREAK",
                "want exactly 1 framing_adapt_write_failed, got %d"
                % len(failures))
        return
    if failures[0].get("severity") != "LOUD":
        _record(name, "BREAK",
                "failure event is not LOUD: %r"
                % failures[0].get("severity"))
        return
    verdict = failures[0].get("verdict") or {}
    if (verdict.get("event") != "framing_drift_suspect"
            or verdict.get("trigger") != "framing_drift"):
        _record(name, "BREAK",
                "failure event does not carry the verdict details: %r"
                % (verdict,))
        return
    if suspects:
        _record(name, "BREAK",
                "PHANTOM SUSPECT: %d framing_drift_suspect event(s) "
                "emitted although the adapt write failed (pre-fix "
                "ordering)" % len(suspects))
        return
    adapted = [e for e in ctx.events
               if e.get("event") == "drift_budget_adapted"
               and e.get("trigger") == "framing_drift"]
    if adapted:
        _record(name, "BREAK",
                "PHANTOM ADAPTED: %d drift_budget_adapted "
                "(framing_drift) event(s) emitted although the adapt "
                "write failed -- the audit log claims a tightening "
                "that never landed" % len(adapted))
        return
    if adapts or level != 0:
        _record(name, "BREAK",
                "budget moved despite the failed write: adapts=%d "
                "level=%d (want 0/0)" % (len(adapts), level))
        return
    if not ctx.store.verify_chain("agent-fail"):
        _record(name, "BREAK",
                "chain does not verify after the failed write")
        return
    _record(name, "HELD",
            "adapt write failed -> 1 LOUD framing_adapt_write_failed "
            "with verdict details, 0 suspect events, 0 phantom "
            "drift_budget_adapted events, level stays 0, chain "
            "intact (fail-closed)")


def o1b_audit_failure_after_landed_write_not_misreported():
    name = "o1b_audit_failure_after_landed_write_not_misreported"
    # Cold corner of the post-write-audit mode: the chained adapt
    # write LANDS, then the audit callable itself raises (audit
    # pipeline failure, distinct from a store write failure). The
    # failure must NOT be misreported as framing_adapt_write_failed
    # (that would be a phantom-failure claim: the adaptation is
    # real and the chain holds it). Expect: the OSError propagates
    # fail-loud out of record_run, no write_failed event, no
    # suspect event, chain verifies with the real adapt at level 1.
    warn = _calibrate()
    ctx = _Ctx("o1b", _adaptive_policy(warn))
    healthy_audit = ctx.store._audit

    def failing_audit(event):
        if (event.get("event") == "drift_budget_adapted"
                and event.get("trigger") == "framing_drift"):
            raise OSError("injected audit-pipeline failure "
                          "(post-write emit)")
        return healthy_audit(event)

    ctx.store._audit = failing_audit
    raised = None
    try:
        for i in range(10):
            ctx.record("agent-auditfail", _shifted(10), i + 1,
                       framing=BOILERPLATE)
    except OSError as exc:
        raised = exc
    if raised is None:
        _record(name, "BREAK",
                "audit-pipeline OSError was swallowed")
        return
    if "audit-pipeline" not in str(raised):
        _record(name, "BREAK",
                "wrong exception propagated: %r" % (raised,))
        return
    if ctx.failures():
        _record(name, "BREAK",
                "PHANTOM-FAILURE REPORT: framing_adapt_write_failed "
                "emitted although the adapt record LANDED "
                "(audit-pipeline failure misreported as write "
                "failure)")
        return
    if ctx.suspects():
        _record(name, "BREAK",
                "suspect event emitted despite the failed audit "
                "pipeline")
        return
    adapts = ctx.framing_adapts("agent-auditfail")
    level = ctx.level("agent-auditfail")
    if not adapts or level != 1:
        _record(name, "BREAK",
                "landed adapt record missing: adapts=%d level=%d "
                "(want 1/1)" % (len(adapts), level))
        return
    if not ctx.store.verify_chain("agent-auditfail"):
        _record(name, "BREAK",
                "chain does not verify after the audit failure")
        return
    _record(name, "HELD",
            "audit failure after landed write -> OSError "
            "propagates fail-loud (not misreported as "
            "write_failed), no suspect, chain holds the real "
            "adapt (level 1)")


def o2_normal_path_suspect_and_adapt_together():
    name = "o2_normal_path_suspect_and_adapt_together"
    warn = _calibrate()
    ctx = _Ctx("o2", _adaptive_policy(warn))
    for i in range(10):
        ctx.record("agent-ok", _shifted(10), i + 1,
                   framing=BOILERPLATE)
    suspects = ctx.suspects()
    adapts = [e for e in ctx.events
              if e.get("event") == "drift_budget_adapted"
              and e.get("trigger") == "framing_drift"]
    level = ctx.level("agent-ok")
    if len(suspects) != 1 or len(adapts) != 1:
        _record(name, "BREAK",
                "want 1 suspect + 1 framing_drift adapt, got %d/%d"
                % (len(suspects), len(adapts)))
        return
    if suspects[0].get("severity") != "LOUD":
        _record(name, "BREAK", "suspect event is not LOUD")
        return
    # The new ordering pins the suspect AFTER the successful adapt
    # write: the drift_budget_adapted event (emitted post-write by
    # the framing path's post-write-audit mode) precedes the suspect
    # in event order.
    if not (ctx.events.index(adapts[0])
            < ctx.events.index(suspects[0])):
        _record(name, "BREAK",
                "suspect event precedes the adapt write -- the old "
                "audit-before-mutation ordering is still in place")
        return
    if level != 1 or len(ctx.framing_adapts("agent-ok")) != 1:
        _record(name, "BREAK",
                "adaptation did not land: level=%d adapts=%d (want "
                "1/1)" % (level, len(ctx.framing_adapts("agent-ok"))))
        return
    if not ctx.store.verify_chain("agent-ok"):
        _record(name, "BREAK", "chain does not verify")
        return
    _record(name, "HELD",
            "healthy store: LOUD suspect emitted after the chained "
            "adapt write landed (level 0 -> 1, chain verifies)")


def _run_all():
    global _RESULTS
    _RESULTS = []
    o1_adapt_write_failure_no_phantom_suspect()
    o1b_audit_failure_after_landed_write_not_misreported()
    o2_normal_path_suspect_and_adapt_together()
    return list(_RESULTS)


def o3_deterministic_x2():
    name = "o3_deterministic_x2"
    first = _run_all()
    second = _run_all()
    v1 = [(n, v) for n, v, _ in first]
    v2 = [(n, v) for n, v, _ in second]
    if v1 != v2:
        _record(name, "BREAK",
                "verdicts differ between runs: %r vs %r" % (v1, v2))
        return
    _record(name, "HELD",
            "%d probes byte-identical verdicts across 2 runs" % len(v1))


def main():
    _run_all()
    o3_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("framing_order_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
