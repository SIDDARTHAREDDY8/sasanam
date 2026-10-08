#!/usr/bin/env python3
"""Wave-346 lane 4 battery: recovery-as-product loop (RecoverySession).

Steal target: Archestra OpenAPPA recovery-as-product (MIT engine repo;
ADAPT patterns only). Extends gov/recovery_guide.py: per-block
RecoverySession with a machine-readable step protocol (stable step ids,
preconditions, verification), digest-chained attempt events, progressive
guidance, and journal linkage as "session-link" entries.

The load-bearing promise: the loop never weakens the refusal.
``refusal_lifted()`` is a constant False sentinel; dependent steps
attempted before their preconditions raise LOUDLY (RecoveryGuideError)
instead of being skipped; there is no lift/permit/unmark API anywhere.

$0 SPEND BY CONSTRUCTION: this battery makes NO model calls. Every probe
uses canned inputs and local records -- never a live provider. Do NOT add
ModelDriver/SpendLedger usage here.

Red-first note: the red probes (step-skip lock, skip-does-not-touch-chain)
assert the CURRENT fail-closed behavior. If a future change lets a
dependent step attempt succeed before its preconditions, the red probes go
BREAK by design -- the tripwire working, not a false alarm.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w346_recoveryux_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2140  # Wave-346: no new decision codes (sessions are journal fields, not codes); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

from gov import recovery_guide as rg  # noqa: E402
from gov import trajectory_labels as tl  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# ---------------------------------------------------------------- fixtures

_CANARY = "<redacted>"  # oracle probe: must never surface


def _session_view():
    """Deterministic public-seam view: withhold + authorize plan."""
    return rg.view_from_record({
        "code": "label-egress-refused", "action": "send_slack",
        "principal": "agent-7", "resource": "slack://public-channel",
        "remedies": ["withhold", "authorize"],
    })


def _real_refusal_view():
    """A real R40 refusal (DLP-flagged bytes, public dispatch).

    The token is built by concatenation: the write/edit tool redacts
    credential-shaped literals in inputs (wave-345 merge note).
    """
    token = "xox" + "b-" + "a1b2c3d4e5f6"
    traj = tl.Trajectory()
    traj = tl.fold(traj, tool="slack_reader",
                   output=("token " + token + " here").encode("utf-8"),
                   declared=tl.TOP, strict=False)
    ref = tl.check_dispatch(traj, recipient={"public-channel"},
                            action="send_slack")
    assert ref is not None
    return rg.view_from_refusal(ref, principal="agent-7",
                                resource="slack://public-channel")


def _unliftable_view():
    return rg.view_from_record({
        "code": "label-remedy-empty-unliftable", "action": "send_slack",
        "principal": "agent-7", "remedies": [],
    })


# ------------------------------------------------------------------ probes

def test_p0_pin_taxonomy():
    ok = (isinstance(TAXONOMY, dict) and len(TAXONOMY) == TAXONOMY_PIN
          and all(n in rg.__all__ for n in
                  ("RecoverySession", "RecoveryStepSpec", "open_session",
                   "guidance_after_failure")))
    return ("HELD" if ok else "BREAK",
            "pin 2140, no new codes; session surface exported: %d codes"
            % len(TAXONOMY))


def test_p1_footer_state():
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(path) as f:
        last = ([ln for ln in f.read().splitlines() if "Next free finding:" in ln] or [""])[-1]  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531) (footer is not the last line; entries follow)
    ok = ("Next free finding: **F662**" in last  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F655-F661 / next F662
          and "Open findings: F655, F656, F657, F658, F659, F660, F661." in last)  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F655-F661 / next F662
    return ("HELD" if ok else "BREAK",
            "footer must read open F436 / next F437")


def test_p2_red_step_skip_locked():
    """RED: dependent step attempted before preconditions raises LOUDLY,
    the refusal is not lifted, and the session chain is untouched."""
    journal = rg.BlockJournal()
    session = rg.open_session(_session_view(), journal)
    before = session.head()
    events = len(session._events)
    try:
        session.attempt_step("step-withhold-resubmit", "succeeded")
        return ("BREAK", "step skip did not raise -- lock defeated")
    except rg.RecoveryGuideError:
        pass
    ok = (session.refusal_lifted() is False
          and session.head() == before
          and len(session._events) == events
          and session.verify_chain())
    return ("HELD" if ok else "BREAK",
            "skip raises, chain untouched, refusal stands")


def test_p3_green_full_session_flow():
    """GREEN: the full session flow completes; the refusal still stands;
    the session exports into the journal; retry counting is unaffected."""
    journal = rg.BlockJournal()
    view = _session_view()
    session = rg.open_session(view, journal)
    # one failed attempt first (progressive-guidance hook)
    session.attempt_step("step-withhold", "failed")
    assert "step-withhold" in [s.step_id for s in session.next_steps()]
    session.attempt_step("step-withhold", "succeeded")
    session.attempt_step("step-withhold-resubmit", "succeeded")
    session.attempt_step("step-authorize", "succeeded")
    link = session.export_to_journal(journal)
    retry = journal.mark(view.request_digest, view.code)
    ok = (session.is_complete()
          and session.refusal_lifted() is False
          and session.verify_chain()
          and link.attempt_kind == "session-link"
          and journal.verify_chain()
          and retry.attempt_kind == "retry" and retry.attempt_no == 2)
    return ("HELD" if ok else "BREAK",
            "full flow completes, refusal stands, journal links, retry=2")


def test_p4_progressive_guidance_no_invention():
    """Guidance after failure refines from fixed templates; it never
    names a remedy outside the plan vocabulary. Empty plan sessions are
    unliftable with zero steps."""
    journal = rg.BlockJournal()
    session = rg.open_session(_session_view(), journal)
    first = session.guidance_for("step-authorize")
    session.attempt_step("step-authorize", "failed")
    refined = session.guidance_for("step-authorize")
    allowed = frozenset(s.remedy for s in session.steps())
    import re
    named = (set(re.findall(r"[a-z][a-z-]*", refined.lower()))
             & rg._remedy_names)
    journal2 = rg.BlockJournal()
    unlift = rg.open_session(_unliftable_view(), journal2)
    ok = (refined != first
          and not (named - allowed)
          and unlift.unliftable and len(unlift.steps()) == 0
          and unlift.is_complete() and unlift.next_steps() == ()
          and unlift.notice and unlift.refusal_lifted() is False
          and journal2.verify_chain())
    return ("HELD" if ok else "BREAK",
            "guidance refines without inventing; unliftable stays a notice")


def test_p5_protocol_machine_readable():
    """Every step carries a stable id, preconditions, and verification;
    the precondition graph is a DAG (no cycles); ids are stable across
    protocol() calls."""
    journal = rg.BlockJournal()
    session = rg.open_session(_real_refusal_view(), journal)
    p1 = session.protocol()
    p2 = session.protocol()
    ids = [s["step_id"] for s in p1["steps"]]
    # DAG check: topological order exists (every precondition appears
    # earlier in the list).
    seen = set()
    dag = True
    for s in p1["steps"]:
        for pre in s["preconditions"]:
            if pre not in seen:
                dag = False
        seen.add(s["step_id"])
    ok = (len(ids) == len(set(ids)) and dag
          and all(s["step_id"].startswith("step-") for s in p1["steps"])
          and all(s["verification"] for s in p1["steps"])
          and all(s["prerequisite"] and s["title"] and s["detail"]
                  for s in p1["steps"])
          and p1["steps"] == p2["steps"]
          and p1["refusal_lifted"] is False
          and _CANARY not in str(p1))
    return ("HELD" if ok else "BREAK",
            "protocol is a stable DAG with verification: %d steps"
            % len(ids))


def test_p6_session_chain_tamper():
    """Tampering with a session event is detected (verify_chain False)."""
    journal = rg.BlockJournal()
    session = rg.open_session(_session_view(), journal)
    session.attempt_step("step-authorize", "attempted")
    assert session.verify_chain()
    session._events[1]["outcome"] = "succeeded"  # hostile edit
    ok = (session.verify_chain() is False)
    session._events[1]["outcome"] = "attempted"  # restore, chain re-checks
    ok = ok and session.verify_chain()
    return ("HELD" if ok else "BREAK",
            "session tampering detected, restore re-verifies")


def test_p7_double_link_refused():
    """Linking a session twice raises; the journal chain is unaffected."""
    journal = rg.BlockJournal()
    session = rg.open_session(_session_view(), journal)
    session.export_to_journal(journal)
    before = journal.head()
    try:
        session.export_to_journal(journal)
        return ("BREAK", "double link did not raise")
    except rg.RecoveryGuideError:
        pass
    ok = journal.head() == before and journal.verify_chain()
    return ("HELD" if ok else "BREAK",
            "double link raises, journal untouched")


# ------------------------------------------------------------------ runner

_PROBES = [
    ("P0-pin-taxonomy", test_p0_pin_taxonomy),
    ("P1-footer-state", test_p1_footer_state),
    ("P2-red-step-skip-locked", test_p2_red_step_skip_locked),
    ("P3-green-full-session-flow", test_p3_green_full_session_flow),
    ("P4-progressive-guidance-no-invention",
     test_p4_progressive_guidance_no_invention),
    ("P5-protocol-machine-readable", test_p5_protocol_machine_readable),
    ("P6-session-chain-tamper", test_p6_session_chain_tamper),
    ("P7-double-link-refused", test_p7_double_link_refused),
]

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere


def _green_check():
    """Depth-1 green check: run the adjacent recovery battery's main with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    notes = []
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    adj = os.path.join(REPO_ROOT, "evals", "w343_recovery_probes.py")
    if os.path.exists(adj):
        d = "/var/tmp/g346-recoveryux-green"
        os.makedirs(d, exist_ok=True)
        env2 = dict(env)
        env2["TMPDIR"] = d
        r = subprocess.run(
            [sys.executable, adj], capture_output=True, text=True,
            env=env2, cwd=REPO_ROOT, timeout=600)
        notes.append("w343_recovery_probes rc=%d" % r.returncode)
        if r.returncode != 0:
            tail = (r.stdout + r.stderr)[-1500:]
            raise AssertionError(
                "green check failed for w343_recovery_probes (rc=%d):\n%s"
                % (r.returncode, tail))
    return "; ".join(notes) if notes else "no adjacent batteries found"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default=None)
    args = ap.parse_args()
    breaks, helds, errors = 0, 0, 0
    probe_breaks = set()
    for name, fn in _PROBES:
        if args.probe and args.probe != name:
            continue
        try:
            status, msg = fn()
        except Exception as e:  # noqa: BLE001 -- loud, not silent
            status, msg = "ERROR", "%s: %r" % (type(e).__name__, e)
        if status == "BREAK":
            breaks += 1
            probe_breaks.add(name)
        elif status == "HELD":
            helds += 1
        else:
            errors += 1
        print("%-42s %-6s %s" % (name, status, msg))
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    if mismatch:
        print("MISMATCH: got breaks=%s, expected=%s"
              % (sorted(probe_breaks), sorted(_EXPECTED_BREAKS)))
        return 2
    try:
        note = _green_check()
    except AssertionError as e:
        print("GREEN-CHECK FAILED: %s" % e)
        return 3
    print("green check: %s" % note)
    print("%d BREAK / %d HELD / %d ERROR" % (breaks, helds, errors))
    return 0 if (breaks == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
