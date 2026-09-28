#!/usr/bin/env python3
"""Ceremony-timing telemetry: break-first battery (wave-173 lane 3).

The product's single-decider approval records now carry a
review-timing triple (review_opened_at / review_resolved_at /
review_latency_ms), stamped by the decision instrument at decide()
time, MAC-bound in the security payload, with explicit nulls for
unobserved paths. Six advisory-only fleet signals read the triple.

RED-FIRST (closed by this lane):
  RED-1: decided records carried no timing -- a 300 ms rubber stamp
         and a 4 min careful review were indistinguishable. Now the
         triple is stamped and the two are distinguishable.
  RED-2: the six automater.ai fleet signals were uncomputable.
         Now they compute over real decided records.
  RED-3: backfilling "latency" from ts/decided_at measured queue wait,
         not review time (the eval-kit impersonation hazard). Now the
         stamp comes from the instrument, never from queue times.

GREEN (reproduced):
  GREEN-1: sub-second cluster flags the rubber-stamper and clears the
           careful reviewer.
  GREEN-2: null timing yields "unobserved", never clear/pass.
  GREEN-3: doctored latency is "corrupt", never rounded into shape.
  GREEN-4: deterministic twice.
  GREEN-5: fatigued fleet flags dominance, after-hours, allow-list
           growth, and terse tier-3.
  GREEN-6: filler prose defeats the terse-reason signal but not the
           300 ms timing signal.

Also verified: the wave-171 ceremony gates still refuse and
re-present; the fail-closed MAC upgrade (pre-upgrade records do not
verify post-upgrade -- drain before upgrading).

Advisory only -- no gate added. $0 spend, synthetic/local,
deterministic. Real product code (gov.approvals,
gov.ceremony_integrity), no stubs.

Run:
  mkdir -p /tmp/gov-timing
  TMPDIR=/tmp/gov-timing ~/workspace/.gov-venv/bin/python \
      evals/ceremony_timing_battery.py
Also standalone under a clean env:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-timing2 \
      ~/workspace/.gov-venv/bin/python evals/ceremony_timing_battery.py
"""

import os
import secrets
import subprocess
import sys
import time
from datetime import timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-timing-%d" % os.getpid())

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import ceremony_integrity as ci  # noqa: E402
from gov.approvals import approval_record_digest  # noqa: E402
from gov.policy import PolicyDecision  # noqa: E402
from harness import make_run  # noqa: E402

_RESULTS = []

# Green-check adjacency: depth-1 only. The child env sets
# GOV_SKIP_GREEN=1 so nested green checks do not spawn further.
ADJACENT = [
    ("evals/ceremony_integrity_probes.py", "battery"),
    ("tests.test_ceremony_timing", "unittest"),
]


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-38s %-10s %s" % (name, verdict, detail))


def _queue_one(q, ident):
    action = {"tool": "write_file",
              "args": {"path": "/tmp/x.txt", "content": "hello"},
              "identity": ident.as_dict(),
              "agent_justification": "timing battery",
              "redactions": []}
    return q.queue(action,
                   PolicyDecision("require_approval", "timing battery",
                                  policy_id="timing-battery", flag="b"),
                   "agent_direct", "preview", caller_identity=ident)


def _ctx():
    ctx = make_run()
    q = ctx["approvals"]
    ident = ctx["mint_identity"]("agent-1", "researcher", "user-1")
    return q, ident


def _decide(q, ident, latency_s, reason, decided_by="op-rios",
            opened_at=None):
    aid = _queue_one(q, ident)
    if opened_at is None:
        opened_at = time.time() - latency_s
    q.decide(aid, True, reason, decided_by=decided_by,
             review_opened_at=opened_at)
    return q.get(aid)


def _iso_epoch(s):
    from datetime import datetime
    return datetime.fromisoformat(s).timestamp()


def _retime(rec, opened_epoch, latency_ms):
    """Re-stamp a decided record's triple to synthetic times.

    The product always stamps resolved_at as now; a synthetic fleet
    (e.g. 23:30 decisions) needs deterministic clocks. Recomputes the
    ISO pair from the given epoch + latency so the triple stays
    self-consistent. Signals read dicts, not MACs, so this is honest
    synthesis for the advisory layer.
    """
    from datetime import datetime
    opened_dt = datetime.fromtimestamp(opened_epoch).astimezone()
    resolved_dt = datetime.fromtimestamp(
        opened_epoch + latency_ms / 1000.0).astimezone()
    rec["review_opened_at"] = opened_dt.isoformat(timespec="milliseconds")
    rec["review_resolved_at"] = resolved_dt.isoformat(
        timespec="milliseconds")
    rec["review_latency_ms"] = latency_ms
    return rec


# ------------------------------------------------- RED-1 (closed)

def f_red1_closed_triple_distinguishes():
    name = "f_red1_closed_triple_distinguishes"
    q, ident = _ctx()
    fast = _decide(q, ident, 0.3, "ok", decided_by="op-rios")
    slow = _decide(q, ident, 183.0,
                   "verified the destination path is inside the project "
                   "dir and the diff only touches the migration files",
                   decided_by="op-rios")
    for label, rec in (("fast", fast), ("slow", slow)):
        triple = [rec.get(f) for f in ("review_opened_at",
                                       "review_resolved_at",
                                       "review_latency_ms")]
        if any(v is None for v in triple):
            _record(name, "BREAK",
                    "%s record missing timing triple" % label)
            return
        if ci.check_review_timing_consistency(rec) != "consistent":
            _record(name, "BREAK",
                    "%s triple not self-consistent" % label)
            return
    if not (fast["review_latency_ms"] < 1000
            < slow["review_latency_ms"]):
        _record(name, "BREAK",
                "triple does not distinguish: fast=%r slow=%r"
                % (fast["review_latency_ms"],
                   slow["review_latency_ms"]))
        return
    _record(name, "HELD",
            "300 ms stamp (%d ms) vs careful review (%d ms) "
            "distinguishable and self-consistent"
            % (fast["review_latency_ms"], slow["review_latency_ms"]))


# ------------------------------------------------- RED-2 (closed)

def f_red2_closed_signals_computable():
    name = "f_red2_closed_signals_computable"
    q, ident = _ctx()
    recs = ([_decide(q, ident, 0.3, "ok") for _ in range(6)]
            + [_decide(q, ident, 183.0,
                       "verified the destination path is inside the "
                       "project dir and the diff is scoped")
               for _ in range(4)])
    missing = [n for n in ("check_review_timing_consistency",
                           "sig_latency_cluster_under_1s",
                           "sig_approver_dominance", "sig_after_hours",
                           "sig_approver_stall", "sig_allow_list_growth",
                           "sig_tier3_terse")
               if not hasattr(ci, n)]
    if missing:
        _record(name, "BREAK", "missing: %s" % ",".join(missing))
        return
    verdict, note = ci.sig_latency_cluster_under_1s(recs)
    if verdict != "flag":
        _record(name, "BREAK",
                "latency cluster did not flag 6/10 sub-second: %s" % note)
        return
    _record(name, "HELD",
            "all six signals + consistency check compute; "
            "6/10 sub-second cluster flags (%s)" % note)


# ------------------------------------------------- RED-3 (closed)

def f_red3_closed_no_backfill():
    name = "f_red3_closed_no_backfill"
    q, ident = _ctx()
    aid = _queue_one(q, ident)
    time.sleep(1.2)  # queue wait, NOT review time
    opened_at = time.time() - 0.3  # the instrument's observed review
    q.decide(aid, True, "verified the destination path",
             decided_by="op-rios", review_opened_at=opened_at)
    rec = q.get(aid)
    queue_wait_ms = (_iso_epoch(rec["decided_at"])
                     - _iso_epoch(rec["ts"])) * 1000.0
    latency_ms = rec["review_latency_ms"]
    # The stamp must be the instrument's ~300 ms, not the ~1200 ms
    # queue wait a ts/decided_at backfill would report.
    if not (latency_ms < 1000 <= queue_wait_ms):
        _record(name, "BREAK",
                "stamp looks backfilled: latency=%r queue_wait=%.0f"
                % (latency_ms, queue_wait_ms))
        return
    _record(name, "HELD",
            "instrument stamp %d ms vs queue-wait backfill %.0f ms: "
            "no impersonation" % (latency_ms, queue_wait_ms))


# ------------------------------------------------- GREEN-1

def f_green1_cluster_flags_rubber_stamp():
    name = "f_green1_cluster_flags_rubber_stamp"
    q, ident = _ctx()
    stamp_fleet = [_decide(q, ident, 0.3, "ok",
                           decided_by="op-rios") for _ in range(6)]
    careful_fleet = [_decide(q, ident, 183.0,
                             "verified the destination path is inside "
                             "the project dir and the diff is scoped",
                             decided_by="op-chen") for _ in range(6)]
    v_stamp, n_stamp = ci.sig_latency_cluster_under_1s(stamp_fleet)
    v_careful, n_careful = ci.sig_latency_cluster_under_1s(careful_fleet)
    if v_stamp != "flag" or v_careful != "clear":
        _record(name, "BREAK",
                "stamp=%s (%s) careful=%s (%s)"
                % (v_stamp, n_stamp, v_careful, n_careful))
        return
    _record(name, "HELD",
            "rubber-stamp cluster flags; careful reviewer clears")


# ------------------------------------------------- GREEN-2

def f_green2_unobserved_never_clear():
    name = "f_green2_unobserved_never_clear"
    q, ident = _ctx()
    aid = _queue_one(q, ident)
    q.decide(aid, True, "verified the destination path",
             decided_by="op-rios")  # no instrument: explicit nulls
    rec = q.get(aid)
    if ci.check_review_timing_consistency(rec) != "unobserved":
        _record(name, "BREAK", "null triple not reported as unobserved")
        return
    for fn in (ci.sig_latency_cluster_under_1s, ci.sig_approver_stall):
        verdict, _ = fn([rec])
        if verdict != "unobserved":
            _record(name, "BREAK",
                    "%s reported %r on null timing (must be unobserved)"
                    % (fn.__name__, verdict))
            return
    v_dom, _ = ci.sig_approver_dominance([rec])
    if v_dom != "unobserved":
        _record(name, "BREAK",
                "dominance reported %r on a 1-record window" % v_dom)
        return
    _record(name, "HELD",
            "null triple -> unobserved everywhere; never clear/pass")


# ------------------------------------------------- GREEN-3

def f_green3_doctored_latency_corrupt():
    name = "f_green3_doctored_latency_corrupt"
    q, ident = _ctx()
    rec = _decide(q, ident, 183.0,
                  "verified the destination path is inside the project "
                  "dir and the diff is scoped")
    doctored = dict(rec)
    doctored["review_latency_ms"] = 300  # post-hoc tamper
    if ci.check_review_timing_consistency(doctored) != "corrupt":
        _record(name, "BREAK", "doctored latency not reported corrupt")
        return
    # And the MAC binds it: the doctored triple does not verify.
    if approval_record_digest(doctored) == rec["args_digest"]:
        _record(name, "BREAK", "doctored triple still MAC-verifies")
        return
    _record(name, "HELD",
            "doctored 183000 ms -> 300 ms is corrupt and breaks the MAC")


# ------------------------------------------------- GREEN-5 (fatigued fleet)

def f_green5_fatigued_fleet_flags():
    name = "f_green5_fatigued_fleet_flags"
    q, ident = _ctx()
    recs = []
    # One approver owns 7 of 10, all sub-second, all "ok", at 23:30.
    for i in range(7):
        r = _decide(q, ident, 0.3, "ok", decided_by="op-rios")
        _retime(r, 1_700_004_600.0 + i * 600, 300)  # 23:30 UTC
        r["risk_tier"] = "critical"  # tier-3 decision, terse reason
        recs.append(r)
    for i in range(3):
        r = _decide(q, ident, 183.0,
                    "verified the destination path is inside "
                    "the project dir and the diff is scoped",
                    decided_by="op-chen")
        _retime(r, 1_700_056_800.0 + i * 600, 183_000)  # 14:00 UTC
        recs.append(r)
    checks = [
        ("dominance",
         ci.sig_approver_dominance(recs)[0] == "flag"),
        ("after_hours",
         ci.sig_after_hours(recs, tzinfo=timezone.utc)[0] == "flag"),
        ("allow_list_growth",
         ci.sig_allow_list_growth(12, 25, days=7)[0] == "flag"),
        ("tier3_terse",
         ci.sig_tier3_terse(recs)[0] == "flag"),
    ]
    bad = [label for label, ok in checks if not ok]
    if bad:
        _record(name, "BREAK", "did not flag: %s" % ",".join(bad))
        return
    _record(name, "HELD",
            "fatigued fleet flags dominance, after-hours, allow-list "
            "growth, and terse tier-3")


# ------------------------------------------------- GREEN-6 (filler prose)

def f_green6_filler_prose_timing_still_flags():
    name = "f_green6_filler_prose_timing_still_flags"
    q, ident = _ctx()
    # Verbose reasons defeat the terse-reason signal...
    recs = [_decide(q, ident, 0.3,
                    "after careful consideration of all the relevant "
                    "factors and a thorough review of the change, "
                    "i approve this request",
                    decided_by="op-rios")
            for _ in range(6)]
    v_terse, _ = ci.sig_tier3_terse(recs)
    # ...but the 300 ms timing signal still fires.
    v_timing, n_timing = ci.sig_latency_cluster_under_1s(recs)
    if v_timing != "flag":
        _record(name, "BREAK",
                "timing signal missed filler-prose rubber stamps: %s"
                % n_timing)
        return
    _record(name, "HELD",
            "filler prose clears terse-reason (%s) but the 300 ms "
            "cluster still flags (%s)" % (v_terse, n_timing))


# ------------------------------------------------- ceremony gates hold

def f_gates_still_refuse_and_represent():
    name = "f_gates_still_refuse_and_represent"
    q, ident = _ctx()
    aid = _queue_one(q, ident)
    t0 = time.time() - 4.0
    try:
        q.decide(aid, True, "   ", decided_by="op-rios",
                 review_opened_at=t0)
        _record(name, "BREAK", "empty reason with timing not bounced")
        return
    except ValueError as e:
        if "ceremony_integrity" not in str(e):
            _record(name, "BREAK", "wrong refusal: %s" % e)
            return
    if q.get(aid)["status"] != "pending":
        _record(name, "BREAK", "bounced record did not stay pending")
        return
    # Re-present with a real reason: decides, and carries the triple.
    q.decide(aid, True, "verified the destination path is inside the "
                        "project dir",
             decided_by="op-rios", review_opened_at=time.time() - 61.0)
    rec = q.get(aid)
    if rec["status"] != "approved" or rec["review_latency_ms"] is None:
        _record(name, "BREAK", "re-presented decision missing timing")
        return
    if ci.check_review_timing_consistency(rec) != "consistent":
        _record(name, "BREAK", "re-presented triple not consistent")
        return
    _record(name, "HELD",
            "empty reason bounced, record stayed pending, re-present "
            "decided with a consistent triple")


# ------------------------------------------------- fail-closed upgrade

def f_fail_closed_upgrade():
    name = "f_fail_closed_upgrade"
    q, ident = _ctx()
    rec = _decide(q, ident, 61.0, "verified the destination path")
    # Simulate a pre-upgrade decided record: strip the wave-173
    # fields. Its stored digest must NOT verify under the new tuple
    # (drain-or-decide before upgrading, same as the F190 packet
    # version migration).
    legacy = {k: v for k, v in rec.items()
              if k not in ("review_opened_at", "review_resolved_at",
                           "review_latency_ms")}
    if approval_record_digest(legacy) == rec["args_digest"]:
        _record(name, "BREAK",
                "pre-upgrade record verifies post-upgrade: not fail-closed")
        return
    _record(name, "HELD",
            "pre-upgrade records fail verification post-upgrade "
            "(drain before upgrading)")


# ------------------------------------------------- green (depth-1)

def f_timing_green():
    name = "f_timing_green"
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record(name, "HELD",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); "
                "run standalone for full depth-1 adjacency")
        return
    failures = []
    for i, (target, kind) in enumerate(ADJACENT):
        tmp = os.path.join(os.environ["TMPDIR"], "adj-%d" % i)
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmp)
        env.pop("GOV_DEPLOYMENT_MODE", None)
        env["GOV_SKIP_GREEN"] = "1"
        if kind == "battery":
            cmd = [sys.executable, target]
        else:
            cmd = [sys.executable, "-m", "unittest", target]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              env=env, cwd=REPO_ROOT, timeout=600)
        if proc.returncode != 0:
            tail = proc.stderr.strip().splitlines()
            failures.append("%s -> rc=%d (%s)"
                            % (target, proc.returncode,
                               tail[-1] if tail else ""))
    if failures:
        _record(name, "BREAK", "; ".join(failures))
    else:
        _record(name, "HELD",
                "%d adjacent suites green (ceremony battery + "
                "timing unit tests)" % len(ADJACENT))


def _run_all():
    global _RESULTS
    _RESULTS = []
    f_red1_closed_triple_distinguishes()
    f_red2_closed_signals_computable()
    f_red3_closed_no_backfill()
    f_green1_cluster_flags_rubber_stamp()
    f_green2_unobserved_never_clear()
    f_green3_doctored_latency_corrupt()
    f_green5_fatigued_fleet_flags()
    f_green6_filler_prose_timing_still_flags()
    f_gates_still_refuse_and_represent()
    f_fail_closed_upgrade()
    f_timing_green()
    return list(_RESULTS)


def f_deterministic_x2():
    first = _run_all()
    second = _run_all()
    v1 = [(n, v) for n, v, _ in first]
    v2 = [(n, v) for n, v, _ in second]
    if v1 != v2:
        _record("f_deterministic_x2", "BREAK",
                "verdicts differ between runs")
    else:
        _record("f_deterministic_x2", "HELD",
                "%d probes byte-identical verdicts across 2 runs"
                % len(v1))


def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
    os.environ.setdefault("GOV_LOG_KEY_EPOCH", "timing-battery")
    print("ceremony-timing telemetry probes")
    _run_all()
    f_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("RESULT: %d HELD, %d BREAK, %d EXPECTED, %d ERROR (%d total)"
          % (held, brk, exp, err, len(_RESULTS)))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
