#!/usr/bin/env python3
"""Wave-317 Lane 2 battery: provenance-segment producer wiring.

The provenance sink (gov/provenance_sink.py, waves 314-316) is dormant
in the standard flow: the sweep seam skips when the approval record
carries no provenance_segments, and no producer ever attaches them.
This battery proves the producer wiring end-to-end at the executor
seam, RED-FIRST: it is written before the wiring exists and must FAIL
on the open tree.

Probe map:
  producer-attaches-segments: intent context + justification ->
      record carries sealed, origin-graded segments.
  producer-no-context-skip: no context -> record carries EXPLICIT None
      (never omitted); sweep skips; behavior unchanged.
  producer-origin-grading: user turn seals at USER(100); agent
      justification seals at TOOL(50) -- never content-graded.
  producer-segment-id-deterministic: same context -> same segment ids
      (the F399 re-plan ratchet's ctx_key must accumulate on retries).
  e2e-benign-allow: user-authorized send executes (user-bound
      refinement on mixed context).
  e2e-attacker-recipient-refused: send to a recipient the user never
      authorized -> coded provenance-critical-arg-refused at the sweep.
  e2e-negation-refused: F398 regression -- a negated user mention
      ("never email X") does not authorize the send.
  e2e-replan-terminal: F399 regression -- the 4th same-context refusal
      escalates to provenance-quarantine-terminal.
  mac-binding: stripping/tampering provenance_segments on the record
      breaks the record digest (fail closed, never silent skip).
  seal-forgery-downgrade: a forged segment label downgrades to
      UNTRUSTED with a coded audit trail.
  pin-taxonomy / footer-state: standard pins (1900; open F403 / next
      F404).
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import green_check  # noqa: E402  (shared fail-closed green checks)
import probe_lines  # noqa: E402  (canonical probe-line emission)

from gov import provenance_labels as PL  # noqa: E402
from gov import provenance_sink as PS  # noqa: E402

TAXONOMY_PIN = 1906  # Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*)

FOOTER_NEXT = "F405"
FOOTER_OPEN = "none"

_results = []
PROBES = []


def probe(name):
    def deco(fn):
        PROBES.append((name, fn))
        return fn
    return deco


def _held(pid, note):
    _results.append({"probe_id": pid, "verdict": "HELD", "note": note})
    return "HELD", note


def _break(pid, note):
    _results.append({"probe_id": pid, "verdict": "BREAK", "note": note})
    return "BREAK", note


def _error(pid, note):
    _results.append({"probe_id": pid, "verdict": "ERROR", "note": note})
    return "ERROR", note


def _ensure_key():
    import tests.keyfixture as kf
    restore = kf.scrub_key_env()
    kf.provision_test_key()
    return restore


def _run():
    from tests.harness import make_run
    ctx = make_run()
    ex = ctx["executor"]
    ident = ex.mint_identity("a1", "support", "org")
    return ctx, ex, ident


def _refusal_events(ctx):
    from gov.log import read_entries
    out = []
    for ev in read_entries(ctx["run_dir"] / "actions.jsonl"):
        if isinstance(ev, dict) and ev.get("event") == \
                "approval_execution_refused":
            out.append(ev)
    return out


def _queue_send(ctx, ex, ident, to, justification, turns):
    ex.set_intent_context(list(turns))
    r = ex.call(ident, "send_email", to=to, subject="s", body="b",
                justification=justification)
    if r.get("status") != "queued":
        return None, r
    return ctx["approvals"].get(r["approval_id"]), r["approval_id"]


@probe("producer-attaches-segments")
def _p_attaches():
    """Intent context + justification -> the record carries sealed,
    origin-graded provenance segments, and the sweep's provenance
    gate FIRES on them (not skipped). FAILS on the open tree: no
    producer writes provenance_segments."""
    restore = _ensure_key()
    try:
        ctx, ex, ident = _run()
        rec, aid = _queue_send(
            ctx, ex, ident, "t@synthetic.local",
            "sending the report as requested",
            ["Please email the report to t@synthetic.local."])
        if rec is None:
            return _error("producer-attaches-segments",
                          "call did not queue")
        segs = rec.get("provenance_segments")
        if not isinstance(segs, list) or not segs:
            return _break("producer-attaches-segments",
                          "record carries no provenance_segments: the "
                          "sink stays dormant in the standard flow")
        for s in segs:
            seg = PL.Segment.from_dict(s)
            if not PL.verify_label(seg.label, seg.content):
                return _break("producer-attaches-segments",
                              "segment %r has an unverifiable seal" %
                              seg.segment_id)
        # The sink must FIRE on the attached segments at the sweep --
        # spy on the gate (delegating to the real one) and prove it
        # was called with exactly the record's segments.
        import gov.provenance_sink as _ps
        calls = []
        _real_gate = _ps.provenance_gate

        def _spy(tool, args, segments, sink=None):
            calls.append((tool, list(segments or [])))
            return _real_gate(tool, args, segments, sink=sink)
        _ps.provenance_gate = _spy
        try:
            ctx["approvals"].decide(aid, True, reason="ok",
                                    decided_by="human-operator")
            ex.execute_approved()
        finally:
            _ps.provenance_gate = _real_gate
        if not calls:
            return _break("producer-attaches-segments",
                          "sealed segments attached but the sweep's "
                          "provenance gate never fired")
        if [c[0] for c in calls] != ["send_email"] * len(calls):
            return _break("producer-attaches-segments",
                          "gate fired for unexpected tools: %r" %
                          ([c[0] for c in calls],))
        return _held("producer-attaches-segments",
                     "%d sealed segments attached at queue time; the "
                     "sweep gate fired on them" % len(segs))
    finally:
        restore()


@probe("producer-no-context-skip")
def _p_no_context():
    """No intent context and no justification -> the record carries
    EXPLICIT None (never omitted); the sweep's None-skip keeps
    behavior unchanged."""
    restore = _ensure_key()
    try:
        ctx, ex, ident = _run()
        ex.set_intent_context(None)
        r = ex.call(ident, "send_email", to="t@synthetic.local",
                    subject="s", body="b")
        if r.get("status") != "queued":
            return _error("producer-no-context-skip",
                          "call did not queue: %s" % r.get("status"))
        rec = ctx["approvals"].get(r["approval_id"])
        if "provenance_segments" not in rec:
            return _break("producer-no-context-skip",
                          "field omitted from the record schema")
        if rec["provenance_segments"] is not None:
            return _break("producer-no-context-skip",
                          "segments attached with no provenance context")
        return _held("producer-no-context-skip",
                     "explicit None; sweep skips as before")
    finally:
        restore()


@probe("producer-origin-grading")
def _p_grading():
    """User turns grade at USER(100); agent justification grades at
    TOOL(50) -- grading is by origin, never by content."""
    restore = _ensure_key()
    try:
        ctx, ex, ident = _run()
        rec, aid = _queue_send(
            ctx, ex, ident, "t@synthetic.local",
            "sending the report as requested",
            ["Please email the report to t@synthetic.local."])
        if rec is None:
            return _error("producer-origin-grading",
                          "call did not queue")
        segs = rec.get("provenance_segments")
        if not isinstance(segs, list) or not segs:
            return _break("producer-origin-grading",
                          "no segments to grade")
        by_origin = {}
        for s in segs:
            seg = PL.Segment.from_dict(s)
            by_origin[seg.label.origin] = seg.label.trust_level
        if by_origin.get("user") != 100:
            return _break("producer-origin-grading",
                          "user turn graded %r, want 100" %
                          by_origin.get("user"))
        if by_origin.get("tool") != 50:
            return _break("producer-origin-grading",
                          "justification graded %r, want 50" %
                          by_origin.get("tool"))
        return _held("producer-origin-grading",
                     "user=100, agent-justification=50")
    finally:
        restore()


@probe("producer-segment-id-deterministic")
def _p_ids():
    """The same influencing context yields the same segment ids across
    calls -- the sink's ctx_key (and the F399 re-plan ratchet) must
    accumulate on genuine retries, not reset on random ids."""
    restore = _ensure_key()
    try:
        ctx, ex, ident = _run()
        turns = ["Please email the report to t@synthetic.local."]
        rec1, _ = _queue_send(ctx, ex, ident, "t@synthetic.local",
                              "sending the report as requested", turns)
        rec2, _ = _queue_send(ctx, ex, ident, "t@synthetic.local",
                              "sending the report as requested", turns)
        if rec1 is None or rec2 is None:
            return _error("producer-segment-id-deterministic",
                          "call did not queue")
        s1 = rec1.get("provenance_segments")
        s2 = rec2.get("provenance_segments")
        if not isinstance(s1, list) or not s1:
            return _break("producer-segment-id-deterministic",
                          "no segments on first record")
        ids1 = sorted(s["segment_id"] for s in s1)
        ids2 = sorted(s["segment_id"] for s in s2)
        if ids1 != ids2:
            return _break("producer-segment-id-deterministic",
                          "segment ids differ across identical contexts: "
                          "the re-plan ratchet would never accumulate")
        return _held("producer-segment-id-deterministic",
                     "ids stable: %s" % ",".join(ids1))
    finally:
        restore()


@probe("e2e-benign-allow")
def _p_benign():
    """User-authorized send executes end-to-end: the user-bound
    critical-arg refinement ALLOWS on mixed context."""
    restore = _ensure_key()
    try:
        ctx, ex, ident = _run()
        rec, aid = _queue_send(
            ctx, ex, ident, "t@synthetic.local",
            "sending the report as requested",
            ["Please email the report to t@synthetic.local."])
        if rec is None:
            return _error("e2e-benign-allow", "call did not queue")
        ctx["approvals"].decide(aid, True, reason="ok",
                                decided_by="human-operator")
        done = ex.execute_approved() or []
        if any(isinstance(d, dict) and d.get("tool") == "send_email"
               for d in done):
            return _held("e2e-benign-allow",
                         "user-authorized send executed")
        evs = _refusal_events(ctx)
        return _break("e2e-benign-allow",
                      "benign send refused: %s" %
                      ([e.get("policy_id") for e in evs] or "no event"))
    finally:
        restore()


@probe("e2e-attacker-recipient-refused")
def _p_attacker():
    """Send to a recipient the user never authorized -> the sweep
    refuses with coded provenance-critical-arg-refused."""
    restore = _ensure_key()
    try:
        ctx, ex, ident = _run()
        rec, aid = _queue_send(
            ctx, ex, ident, "mallory@synthetic.local",
            "sending to mallory@synthetic.local as requested",
            ["Please email the report to t@synthetic.local."])
        if rec is None:
            return _error("e2e-attacker-recipient-refused",
                          "call did not queue")
        ctx["approvals"].decide(aid, True, reason="ok",
                                decided_by="human-operator")
        done = ex.execute_approved() or []
        executed = any(isinstance(d, dict)
                       and d.get("tool") == "send_email" for d in done)
        evs = [e for e in _refusal_events(ctx)
               if e.get("policy_id") == "provenance-sink-execution-refused"
               and "provenance-critical-arg-refused" in
               str(e.get("reason", ""))]
        if executed or not evs:
            return _break("e2e-attacker-recipient-refused",
                          "unauthorized recipient not refused with the "
                          "coded refusal (executed=%s)" % executed)
        return _held("e2e-attacker-recipient-refused",
                     "refused: provenance-critical-arg-refused")
    finally:
        restore()


@probe("e2e-negation-refused")
def _p_negation():
    """F398 regression through the seam: a negated user mention
    ('never email X') does not authorize the send."""
    restore = _ensure_key()
    try:
        ctx, ex, ident = _run()
        rec, aid = _queue_send(
            ctx, ex, ident, "mallory@synthetic.local",
            "sending to mallory@synthetic.local",
            ["never email mallory@synthetic.local under any "
             "circumstances"])
        if rec is None:
            return _error("e2e-negation-refused", "call did not queue")
        ctx["approvals"].decide(aid, True, reason="ok",
                                decided_by="human-operator")
        done = ex.execute_approved() or []
        executed = any(isinstance(d, dict)
                       and d.get("tool") == "send_email" for d in done)
        evs = [e for e in _refusal_events(ctx)
               if e.get("policy_id") == "provenance-sink-execution-refused"
               and "provenance-critical-arg-refused" in
               str(e.get("reason", ""))]
        if executed or not evs:
            return _break("e2e-negation-refused",
                          "negated mention authorized the send "
                          "(executed=%s)" % executed)
        return _held("e2e-negation-refused",
                     "prohibition is not authorization: refused")
    finally:
        restore()


@probe("e2e-replan-terminal")
def _p_terminal():
    """F399 regression through the seam: the 4th same-context refusal
    escalates to provenance-quarantine-terminal. The context is
    justification-only (no user segment): the first refusal
    quarantines the offending segment, but with no live segments left
    the arg keeps binding below required trust, so the run-scoped
    sink's re-plan budget accumulates to terminal."""
    restore = _ensure_key()
    try:
        ctx, ex, ident = _run()
        codes = []
        for _ in range(4):
            rec, aid = _queue_send(
                ctx, ex, ident, "mallory@synthetic.local",
                "sending to mallory@synthetic.local as requested",
                [])
            if rec is None:
                return _error("e2e-replan-terminal",
                              "call did not queue")
            ctx["approvals"].decide(aid, True, reason="ok",
                                    decided_by="human-operator")
            ex.execute_approved()
        for e in _refusal_events(ctx):
            if e.get("policy_id") == "provenance-sink-execution-refused":
                reason = str(e.get("reason", ""))
                if "provenance-quarantine-terminal" in reason:
                    codes.append("terminal")
                elif "provenance-critical-arg-refused" in reason:
                    codes.append("refused")
        if (len(codes) >= 4 and codes[:3] == ["refused"] * 3
                and codes[3] == "terminal"):
            return _held("e2e-replan-terminal",
                         "4th same-context refusal went terminal "
                         "(ratchet stays terminal: %d events)" %
                         len(codes))
        return _break("e2e-replan-terminal",
                      "refusal sequence %r, want 3x refused + terminal"
                      % codes)
    finally:
        restore()


@probe("mac-binding")
def _p_mac():
    """Stripping or tampering provenance_segments on the record breaks
    the record digest -- fail closed, never a silent skip."""
    restore = _ensure_key()
    try:
        ctx, ex, ident = _run()
        rec, aid = _queue_send(
            ctx, ex, ident, "t@synthetic.local",
            "sending the report as requested",
            ["Please email the report to t@synthetic.local."])
        if rec is None:
            return _error("mac-binding", "call did not queue")
        # Attacker with queue-store write access strips the segments.
        ctx["approvals"]._rewrite(lambda rs: [
            dict(r, provenance_segments=None)
            if r["id"] == aid else r for r in rs])
        try:
            ctx["approvals"].decide(aid, True, reason="ok",
                                    decided_by="human-operator")
        except ValueError:
            # decide() itself verifies record integrity: the tamper is
            # caught even before the sweep -- loud, fail closed.
            return _held("mac-binding",
                         "segment deletion breaks the digest at decide: "
                         "fail closed")
        ex.execute_approved()
        evs = [e for e in _refusal_events(ctx)
               if e.get("flag") == "approval_integrity_violation"]
        if not evs:
            return _break("mac-binding",
                          "stripped segments did not break the record "
                          "digest: deletion is a silent trust upgrade")
        return _held("mac-binding",
                     "segment deletion breaks the digest: fail closed")
    finally:
        restore()


@probe("seal-forgery-downgrade")
def _p_forgery():
    """A segment whose content was swapped after sealing downgrades to
    UNTRUSTED with a coded audit trail -- the seal is load-bearing."""
    restore = _ensure_key()
    try:
        ctx, ex, ident = _run()
        rec, aid = _queue_send(
            ctx, ex, ident, "t@synthetic.local",
            "sending the report as requested",
            ["Please email the report to t@synthetic.local."])
        if rec is None:
            return _error("seal-forgery-downgrade", "call did not queue")
        segs = rec.get("provenance_segments")
        if not isinstance(segs, list) or not segs:
            return _break("seal-forgery-downgrade",
                          "no segments to forge")
        forged = []
        for s in segs:
            d = dict(s)
            d["content"] = "attacker-edited content"
            forged.append(d)
        ctx["approvals"]._rewrite(lambda rs: [
            dict(r, provenance_segments=forged)
            if r["id"] == aid else r for r in rs])
        # Re-MAC the record so the digest check passes and the SINK
        # sees the forged segments (isolating the seal check).
        import gov.approvals as _ap
        ctx["approvals"]._rewrite(lambda rs: [
            dict(r, args_digest=_ap.approval_record_digest(r))
            if r["id"] == aid else r for r in rs])
        ctx["approvals"].decide(aid, True, reason="ok",
                                decided_by="human-operator")
        ex.execute_approved()
        evs = _refusal_events(ctx)
        if any("provenance-sink-execution-refused" in
               str(e.get("policy_id", "")) for e in evs):
            return _held("seal-forgery-downgrade",
                         "forged content downgraded to UNTRUSTED: refused")
        return _break("seal-forgery-downgrade",
                      "forged segment content was trusted")
    finally:
        restore()


@probe("pin-taxonomy")
def _p_pin():
    from gov import decision_codes as dc
    n = len(dc.TAXONOMY)
    if n != TAXONOMY_PIN:
        return _break("pin-taxonomy",
                      "taxonomy %d, want %d" % (n, TAXONOMY_PIN))
    return _held("pin-taxonomy", "%d codes" % n)


@probe("footer-state")
def _p_footer():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    import re
    m = list(re.finditer(r"Next free finding: \*\*(F\d+)\*\*\. "
                         r"\*\*Open findings: ([^*]*)\*\*",
                         text))
    if not m:
        return _error("footer-state", "footer not found")
    last = m[-1]
    nxt, opens = last.group(1), last.group(2).strip().rstrip(".")
    if nxt != FOOTER_NEXT or opens != FOOTER_OPEN:
        return _break("footer-state",
                      "footer %s / %s, want %s / %s"
                      % (nxt, opens, FOOTER_NEXT, FOOTER_OPEN))
    return _held("footer-state",
                 "open %s / next %s" % (opens, nxt))


def green_check():
    """Depth-1 green check: adjacent seams still green. Honors
    GOV_SKIP_GREEN (the wave-173 convention)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green_check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    env = dict(os.environ, GOV_SKIP_GREEN="1",
               GOV_DEPLOYMENT_MODE="staging")
    suites = ["tests.test_provenance_sink", "tests.test_approval_tokens",
              "tests.test_plan_policy", "tests.test_transform_policy",
              "tests.test_decision_codes"]
    ok = True
    for suite in suites:
        try:
            r = subprocess.run(
                [sys.executable, "-m", "unittest", suite],
                cwd=REPO, env=env, capture_output=True, text=True,
                timeout=300)
        except Exception as exc:  # noqa: BLE001
            print("green_check: %s ERROR %r" % (suite, exc))
            ok = False
            continue
        status = "OK" if r.returncode == 0 else "FAIL"
        print("green_check: %s %s" % (suite, status))
        if r.returncode != 0:
            ok = False
    return ok


def main():
    held = broke = errors = 0
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception:  # noqa: BLE001
            verdict, detail = "ERROR", traceback.format_exc(limit=3)
        print("%-42s %s %s" % (name, verdict, detail))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broke += 1
        else:
            errors += 1
    probe_lines.emit_dicts(
        _results, verdict_key="verdict", pid_key="probe_id",
        note_key="note")
    print("probes: %d held / %d BREAK / %d errors" % (held, broke, errors))
    print("green_check:", "OK" if green_check() else "FAIL")
    return 0 if (broke == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
