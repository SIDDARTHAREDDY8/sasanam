#!/usr/bin/env python3
"""Ceremony-integrity pre-verification: the R5 deterministic rebuild of
the awaithumans pre-verification *shape* (re-check the human's answer;
REFUSE and re-present with a reason on failure), wired into the real
``ApprovalQueue.decide()`` seam before the receipt is stamped.

RED-FIRST: pre-fix, all six no-read decisions sailed through decide()
(empty reason, whitespace reason, "ok", "lgtm", approve+denial-note,
reject+approval-note) -- the reason was stored verbatim
(``target["decision_reason"] = reason``) with no content check. Post-fix,
the bouncable four are REFUSED with a ``ceremony_integrity_bounce``
audit event and the record stays pending; "ok"/"lgtm" still decide
(DELIBERATE: the lane rejected the min-length gate -- terse legitimate
operators and our own test suite must never be blocked).

Gates (gov/ceremony_integrity.py):
  1. reason_empty -- empty/whitespace-only reason.
  2. reason_contradicts_decision -- denial language on an approval /
     approval language on a rejection, scoped to the approval act.
Signals (rubber-stamp streak, copy-paste reason) stay advisory-only:
they ride the bounce event as forensics and never gate.

Expected: TP=14 FP<=1 TN=39 FN=0 on the 54-case synthetic corpus
(precision>=0.933, recall=1.000); 6/6 red-first probes at the intended
verdicts; the single known FP class (self-correcting prose) remains the
only FP.

$0 spend, synthetic/local, deterministic. Real product code
(gov.approvals, gov.ceremony_integrity), no stubs.

Run:
  mkdir -p /tmp/gov-ceremony
  TMPDIR=/tmp/gov-ceremony ~/workspace/.gov-venv/bin/python \\
      evals/ceremony_integrity_probes.py
Also standalone under a clean env:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-ceremony2 \\
      ~/workspace/.gov-venv/bin/python evals/ceremony_integrity_probes.py
"""

import json
import os
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-ceremony-%d" % os.getpid())

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.ceremony_integrity import (  # noqa: E402
    check_decision_reason, copypaste_reason, rubber_stamp_streak)
from gov.policy import PolicyDecision  # noqa: E402
from harness import make_run  # noqa: E402

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-38s %-10s %s" % (name, verdict, detail))


def _queue_one(q, ident, tool="write_file"):
    action = {"tool": tool,
              "args": {"path": "/tmp/x.txt", "content": "hello"},
              "identity": ident.as_dict(),
              "agent_justification": "ceremony battery",
              "redactions": []}
    return q.queue(action,
                   PolicyDecision("require_approval", "ceremony battery",
                                  policy_id="ceremony", flag="b"),
                   "agent_direct", "preview", caller_identity=ident)


# ------------------------------------------------- red-first, wired
# (label, approved, reason, expect_bounce, expected_code_or_None)
_RED_FIRST = [
    ("empty", True, "", True, "reason_empty"),
    ("whitespace", True, "   ", True, "reason_empty"),
    ("ok", True, "ok", False, None),
    ("lgtm", True, "lgtm", False, None),
    ("contradict_approve", True,
     "do not approve this, it looks dangerous", True,
     "reason_contradicts_decision"),
    ("contradict_reject", False,
     "yes, approve this, looks good to me", True,
     "reason_contradicts_decision"),
]


def f_red_first_now_bounces():
    bad = []
    for label, approved, reason, expect_bounce, code in _RED_FIRST:
        ctx = make_run()
        q = ctx["approvals"]
        ident = ctx["mint_identity"]("agent-1", "researcher", "user-1")
        aid = _queue_one(q, ident)
        try:
            rec, _ = q.decide(aid, approved, reason,
                              decided_by="human-operator")
            bounced = False
            full = ""
            detail = "decided %s" % rec["status"]
        except ValueError as e:
            bounced = True
            full = str(e)
            detail = full[:60]
        if bounced != expect_bounce:
            bad.append("%s: bounce=%s want %s (%s)"
                       % (label, bounced, expect_bounce, detail))
        elif bounced and code not in full:
            bad.append("%s: bounced but code %r missing (%s)"
                       % (label, code, detail))
    if bad:
        _record("f_red_first_now_bounces", "BREAK", "; ".join(bad))
    else:
        _record("f_red_first_now_bounces", "HELD",
                "4/6 bounce with ceremony codes; ok/lgtm still decide")


def f_bounce_keeps_pending_and_represents():
    name = "f_bounce_keeps_pending_and_represents"
    ctx = make_run()
    q = ctx["approvals"]
    ident = ctx["mint_identity"]("agent-1", "researcher", "user-1")
    aid = _queue_one(q, ident)
    try:
        q.decide(aid, True, "", decided_by="human-operator")
        _record(name, "BREAK", "empty reason was not bounced")
        return
    except ValueError:
        pass
    if q.get(aid)["status"] != "pending":
        _record(name, "BREAK", "record left %s after bounce, not pending"
                % q.get(aid)["status"])
        return
    rec, _ = q.decide(aid, True, "reviewed the temp file write",
                      decided_by="human-operator")
    if rec["status"] != "approved":
        _record(name, "BREAK", "re-submit did not decide")
        return
    events = []
    for line in open(q.log.path, encoding="utf-8"):
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("approval_id") == aid and e.get("event") in (
                "ceremony_integrity_bounce", "approval_decision_attempt",
                "approval_decision"):
            events.append(e["event"])
    if events != ["ceremony_integrity_bounce", "approval_decision_attempt",
                  "approval_decision"]:
        _record(name, "BREAK", "audit chain wrong: %s" % events)
        return
    _record(name, "HELD",
            "bounce keeps pending; re-present decides; chain bounce->"
            "attempt->decision")


# ------------------------------------------------- synthetic precision
GENUINE = [
    ("reviewed the diff, matches the ticket AC-123", True),
    ("approved - verified the dangerous-looking filename is the right one", True),
    ("checked the recipient against the vendor list, all good", True),
    ("the unsafe flag was a false positive from the scanner; payload verified", True),
    ("I reject the premise this is risky - the sandbox contains it", True),
    ("read the full payload, amounts match the invoice", True),
    ("ok", True),
    ("lgtm", True),
    ("trust me", True),
    ("looks fine", True),
    ("test decision", True),
    ("approved per policy p7, low-risk tier", True),
    ("compared args to the approved manifest entry, identical", True),
    ("ran the dry-run, output as expected", True),
    ("discussed with the requester, scope confirmed", True),
    ("do not run this on prod - oh wait, this is the staging queue, approved", True),
    ("rejected: amount exceeds the delegated limit", False),
    ("denied - the destination is not allowlisted", False),
    ("rejecting, payload references an unapproved tool", False),
    ("do not approve in this form; needs the ticket reference first", False),
    ("no - the justification does not match the args", False),
    ("not approved: missing change ticket", False),
    ("this looks dangerous, rejecting until reviewed", False),
    ("unsafe to run without the backup completing first", False),
    ("I don't approve of rushing this, but the payload itself is fine - approved", True),
    ("go ahead is premature; rejecting for now", False),
    ("the previous approval was a mistake, this one is correct", True),
    ("verified checksums, approving the rollout", True),
    ("read it twice, still fine", True),
    ("approved.", True),
    ("yes", True),
    ("no", False),
    ("nack", False),
    ("ack", True),
    ("+1", True),
    ("confirmed with finance, within budget", True),
    ("the tool is approved for this data class", True),
    ("expiry window acceptable, approved", True),
    ("matches the break-glass ticket BG-42 scope", True),
    ("reviewed", True),
]

NOREAD = [
    ("", True),
    ("   ", True),
    (None, True),
    ("do not approve this, it looks dangerous", True),
    ("don't approve - not safe", True),
    ("reject this, wrong environment", True),
    ("this should not be approved in its current form", True),
    ("too risky to approve without review", True),
    ("unsafe to approve", True),
    ("do not run this", True),
    ("yes, approve this, looks good to me", False),
    ("approved, go ahead", False),
    ("do it, looks fine", False),
    ("approve this now", False),
]


def f_precision_recall():
    tp = fp = tn = fn = 0
    fp_cases, fn_cases = [], []
    for reason, approved in GENUINE:
        passed, code, _ = check_decision_reason({}, approved, reason)
        if passed:
            tn += 1
        else:
            fp += 1
            fp_cases.append((reason, code))
    for reason, approved in NOREAD:
        passed, code, _ = check_decision_reason({}, approved, reason)
        if not passed:
            tp += 1
        else:
            fn += 1
            fn_cases.append((reason, code))
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    detail = ("TP=%d FP=%d TN=%d FN=%d precision=%.3f recall=%.3f"
              % (tp, fp, tn, fn, prec, rec))
    if tp == 14 and fp <= 1 and tn >= 39 and fn == 0:
        _record("f_precision_recall", "HELD",
                detail + "; FP cases: %s" % (fp_cases,))
    else:
        _record("f_precision_recall", "BREAK",
                detail + "; FP=%s FN=%s" % (fp_cases, fn_cases))


# ------------------------------------------------- internal deciders
def f_internal_deciders_unaffected():
    name = "f_internal_deciders_unaffected"
    machine_reasons = [
        (True, "AUTO-APPROVED by policy auto_approve (risk score 5 <= "
               "policy cap 20; policy explicitly permits low-risk "
               "auto-approval)"),
        (True, "BATCH [approve]: quarterly vendor payouts reviewed"),
        (False, "BATCH [reject]: holding for the new quarter"),
        (True, "BREAK-GLASS by ops-lead: prod DB failover during "
               "incident INC-7"),
    ]
    bad = []
    for approved, reason in machine_reasons:
        passed, code, _ = check_decision_reason({}, approved, reason)
        if not passed:
            bad.append("%r -> %s" % (reason[:40], code))
    if bad:
        _record(name, "BREAK", "; ".join(bad))
    else:
        _record(name, "HELD",
                "auto-approve / batch / break-glass reasons pass")


# ------------------------------------------------- signals stay advisory
def f_signal_sanity():
    name = "f_signal_sanity"
    try:
        assert rubber_stamp_streak([True] * 7, window=5) == 5
        assert rubber_stamp_streak([True, True, False, True, True]) == 2
        assert rubber_stamp_streak([]) == 0
        assert copypaste_reason("looks good", ["looks good"] * 4,
                                threshold=3) is True
        assert copypaste_reason("looks good", ["looks good", "checked"],
                                threshold=3) is False
        assert copypaste_reason("", ["", ""], threshold=1) is False
    except AssertionError as e:
        _record(name, "BREAK", "signal assertion failed: %s" % e)
        return
    _record(name, "HELD", "streak/copypaste sanity OK (advisory only)")


# ------------------------------------------------- depth-1 green
ADJACENT_UNIT_TESTS = [
    "tests.test_approvals_d1",
    "tests.test_approval_abuse",
]


def f_ceremony_green():
    name = "f_ceremony_green"
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record(name, "HELD",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); "
                "run standalone for full depth-1 adjacency")
        return
    failures = []
    for i, mod in enumerate(ADJACENT_UNIT_TESTS):
        tmp = os.path.join(os.environ["TMPDIR"], "ut-%d" % i)
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmp)
        env.pop("GOV_DEPLOYMENT_MODE", None)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", mod],
            capture_output=True, text=True, env=env, cwd=REPO_ROOT,
            timeout=600)
        if proc.returncode != 0:
            err_tail = proc.stderr.strip().splitlines()
            err_tail = err_tail[-1] if err_tail else ""
            failures.append("%s -> rc=%d (%s)" % (mod, proc.returncode,
                                                 err_tail))
    if failures:
        _record(name, "BREAK", "; ".join(failures))
    else:
        _record(name, "HELD",
                "%d adjacent approval suites green" % len(ADJACENT_UNIT_TESTS))


def _run_all():
    global _RESULTS
    _RESULTS = []
    f_red_first_now_bounces()
    f_bounce_keeps_pending_and_represents()
    f_precision_recall()
    f_internal_deciders_unaffected()
    f_signal_sanity()
    f_ceremony_green()
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
                "%d probes byte-identical verdicts across 2 runs" % len(v1))


def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
    os.environ.setdefault("GOV_LOG_KEY_EPOCH", "ceremony-battery")
    print("ceremony-integrity probes")
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
