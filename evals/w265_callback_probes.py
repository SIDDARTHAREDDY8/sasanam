"""Break-first battery: ADK-style callback/HITL execution seams (wave-265).

Probes the fail-closed composition: callbacks are untrusted code, the
enforcement decision is the floor, and every refusal is machine-coded.

Modes: ``GOV_CALLBACK_UNDER_TEST=stub`` runs the probes against a
permissive stub executor that ignores callbacks and enforcement
entirely (red phase: attacks MUST break). Default (module) runs them
against ``gov.agent_callbacks`` (green phase: all MUST hold).

Probes inapplicable to the stub report BASELINE (no claim either way).

Depth-1 green check honoring ``GOV_SKIP_GREEN``; no in-repo git
subprocesses; stdlib only.
"""

import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

MODE = os.environ.get("GOV_CALLBACK_UNDER_TEST", "module")

try:
    from gov import agent_callbacks as ac
    from gov import decision_codes
    HAVE_MODULE = True
except Exception:  # red phase: module not written yet
    ac = None
    decision_codes = None
    HAVE_MODULE = False

TAXONOMY_PIN = 1964 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)
# pin 1177 -> 1186 (+9 callback-*).

EXPECTED_CALLBACK_CODES = (
    "callback-approval-denied",
    "callback-approval-expired",
    "callback-approval-requested",
    "callback-blocked",
    "callback-cannot-widen",
    "callback-faulted",
    "callback-finding-escalated",
    "callback-malformed-verdict",
    "callback-unknown-approval",
)


class _PermissiveStub(object):
    """Red-phase stub: ignores callbacks AND enforcement, always runs."""

    def __init__(self, journal=None):
        self.journal = journal if journal is not None else []

    def add_before(self, fn):
        pass

    def add_after(self, fn):
        pass

    def add_on_error(self, fn):
        pass

    def execute(self, action_fn, tool_name, args,
                enforcement=None, before=(), after=()):
        return action_fn(tool_name, args)


def _executor(journal=None):
    if MODE == "stub":
        return _PermissiveStub(journal=journal)
    return ac.CallbackExecutor(journal=journal)


def _run_tool(tool_name, args):
    return {"ok": True, "tool": tool_name, "args": dict(args)}


def _verdict(name, held, detail=""):
    return {"name": name, "result": "HELD" if held else "BREAK",
            "detail": detail}


def _baseline(name, detail=""):
    return {"name": name, "result": "BASELINE", "detail": detail}


# ---------------------------------------------------------------- probes

def p_block_before_tool():
    journal = []
    ex = _executor(journal=journal)
    def blocker(tool_name, args):
        return ac.Block() if HAVE_MODULE else None
    ran = []
    def spy(tool_name, args):
        ran.append(tool_name)
        return _run_tool(tool_name, args)
    try:
        ex.execute(spy, "db.query", {"q": "1"}, before=(blocker,))
    except Exception as exc:
        code = getattr(exc, "code", None)
        if HAVE_MODULE and code == "callback-blocked" and not ran:
            return _verdict("block-before-tool", True,
                            "blocked with callback-blocked, tool never ran")
        return {"name": "block-before-tool", "result": "ERROR",
                "detail": "unexpected exception %r" % (exc,)}
    if MODE == "stub" and ran:
        return _verdict("block-before-tool", False,
                        "stub ran the tool despite BLOCK verdict")
    return _verdict("block-before-tool", True, "no block requested; ran")


def p_rewrite_args():
    ex = _executor()
    def rewriter(tool_name, args):
        if not HAVE_MODULE:
            return None
        return ac.Rewrite({"q": "rewritten", "limit": 1})
    seen = []
    def spy(tool_name, args):
        seen.append(dict(args))
        return _run_tool(tool_name, args)
    ex.execute(spy, "db.query", {"q": "original"}, before=(rewriter,))
    if not seen:
        return {"name": "rewrite-args", "result": "ERROR",
                "detail": "tool never ran"}
    if MODE == "stub":
        if seen[0].get("q") == "original":
            return _verdict("rewrite-args", False,
                            "stub ignored REWRITE, ran original args")
        return _verdict("rewrite-args", True, "args rewritten")
    if seen[0].get("q") == "rewritten" and seen[0].get("limit") == 1:
        return _verdict("rewrite-args", True, "rewritten args used")
    return _verdict("rewrite-args", False,
                    "rewrite not honored: %r" % (seen[0],))


def p_enforcement_floor():
    journal = []
    ex = _executor(journal=journal)
    def deny_all(tool_name, args):
        return (False, "scope-listing-denied")
    ran = []
    def spy(tool_name, args):
        ran.append(tool_name)
        return _run_tool(tool_name, args)
    try:
        ex.execute(spy, "db.query", {"q": "1"}, enforcement=deny_all,
                   before=(lambda t, a: (ac.Continue()
                                        if HAVE_MODULE else None),))
    except Exception as exc:
        code = getattr(exc, "code", None)
        if HAVE_MODULE and code == "scope-listing-denied" and not ran:
            return _verdict("enforcement-floor", True,
                            "enforcement denial held; callbacks skipped")
        return {"name": "enforcement-floor", "result": "ERROR",
                "detail": "unexpected %r" % (exc,)}
    if MODE == "stub" and ran:
        return _verdict("enforcement-floor", False,
                        "stub ran the tool despite enforcement DENY")
    return _verdict("enforcement-floor", True, "enforcement allowed")


def p_callback_cannot_widen():
    journal = []
    ex = _executor(journal=journal)

    def allow_only_reads(tool_name, args):
        if args.get("write"):
            return (False, "scope-listing-denied")
        return (True, None)

    def widen(tool_name, args):
        if not HAVE_MODULE:
            return None
        new_args = dict(args)
        new_args["write"] = True  # rewrite smuggles a wider grant
        return ac.Rewrite(new_args)

    ran = []

    def spy(tool_name, args):
        ran.append((tool_name, dict(args)))
        return _run_tool(tool_name, args)
    try:
        ex.execute(spy, "db.read", {"q": "1"},
                   enforcement=allow_only_reads, before=(widen,))
    except Exception as exc:
        code = getattr(exc, "code", None)
        if HAVE_MODULE and code == "callback-cannot-widen" and not ran:
            return _verdict("callback-cannot-widen", True,
                            "widening rewrite refused callback-cannot-widen")
        return {"name": "callback-cannot-widen", "result": "ERROR",
                "detail": "unexpected %r" % (exc,)}
    if MODE == "stub" and ran:
        return _verdict("callback-cannot-widen", False,
                        "stub ran the widened call with no widen check")
    return _verdict("callback-cannot-widen", False,
                    "widening rewrite was not refused")


def p_throwing_callback():
    journal = []
    ex = _executor(journal=journal)
    def boom(tool_name, args):
        raise RuntimeError("callback exploded")
    ran = []
    def spy(tool_name, args):
        ran.append(tool_name)
        return _run_tool(tool_name, args)
    try:
        ex.execute(spy, "db.query", {"q": "1"}, before=(boom,))
    except Exception as exc:
        code = getattr(exc, "code", None)
        if HAVE_MODULE and code == "callback-faulted" and not ran:
            return _verdict("throwing-callback", True,
                            "throwing callback failed closed callback-faulted")
        return _verdict("throwing-callback", False,
                        "raw exception escaped: %r (ran=%r)" % (exc, ran))
    if ran:
        return _verdict("throwing-callback", False,
                        "tool ran despite throwing callback")
    return _verdict("throwing-callback", True, "no exception path taken")


def p_hitl_escalate_pause():
    journal = []
    if MODE == "stub":
        ex = _executor(journal=journal)
        ran = []
        def spy(tool_name, args):
            ran.append(tool_name)
            return _run_tool(tool_name, args)
        ex.execute(spy, "payments.refund", {"amount": 500})
        if ran:
            return _verdict("hitl-escalate-pause", False,
                            "stub ran the tool with no approval pause")
        return _verdict("hitl-escalate-pause", True, "tool did not run")
    gate = ac.HumanApprovalGate(journal=journal)
    ex = ac.CallbackExecutor(journal=journal)
    ran = []
    def spy(tool_name, args):
        ran.append(tool_name)
        return _run_tool(tool_name, args)
    outcome = ex.execute(spy, "payments.refund", {"amount": 500},
                         before=(gate.before,))
    paused = isinstance(outcome, ac.EscalatedCall) and not ran
    requested = any(r.get("code") == "callback-approval-requested"
                    and r.get("state") == "pending" for r in journal)
    if paused and requested:
        return _verdict("hitl-escalate-pause", True,
                        "execution paused; approval-request journaled")
    return _verdict("hitl-escalate-pause", False,
                    "paused=%r requested=%r ran=%r" % (paused, requested, ran))


def p_hitl_deny_resume():
    if MODE == "stub":
        return _baseline("hitl-deny-resume", "module-only probe")
    journal = []
    gate = ac.HumanApprovalGate(journal=journal)
    approval_id = gate.request("payments.refund", {"amount": 500})
    try:
        gate.resolve(approval_id, False, decider="human-1",
                     note="not this quarter")
    except Exception as exc:
        code = getattr(exc, "code", None)
        denied = any(r.get("code") == "callback-approval-denied"
                     for r in journal)
        if code == "callback-approval-denied" and denied:
            return _verdict("hitl-deny-resume", True,
                            "denial refused callback-approval-denied"
                            " + journaled")
        return {"name": "hitl-deny-resume", "result": "ERROR",
                "detail": "unexpected %r" % (exc,)}
    return _verdict("hitl-deny-resume", False, "denial did not refuse")


def p_hitl_expire():
    if MODE == "stub":
        return _baseline("hitl-expire", "module-only probe")
    journal = []
    gate = ac.HumanApprovalGate(journal=journal)
    approval_id = gate.request("payments.refund", {"amount": 500})
    gate.expire(approval_id)
    expired = any(r.get("code") == "callback-approval-expired"
                  for r in journal)
    try:
        gate.resolve(approval_id, True)
    except Exception as exc:
        code = getattr(exc, "code", None)
        if code == "callback-unknown-approval" and expired:
            return _verdict("hitl-expire", True,
                            "expired approval cannot be resolved")
        return {"name": "hitl-expire", "result": "ERROR",
                "detail": "unexpected %r" % (exc,)}
    return _verdict("hitl-expire", False, "expired approval resolved")


def p_after_finding_journal():
    journal = []
    if MODE == "stub":
        ex = _executor(journal=journal)
        res = ex.execute(_run_tool, "db.query", {"q": "1"},
                         after=(lambda t, a, r: None,))
        findings = [r for r in journal
                    if r.get("code") == "callback-finding-escalated"]
        if res.get("ok") and not findings:
            return _verdict("after-finding-journal", False,
                            "stub recorded no finding (no escalation seam)")
        return _verdict("after-finding-journal", True, "finding recorded")
    ex = ac.CallbackExecutor(journal=journal)
    def watcher(tool_name, args, result):
        if result.get("tool") == "db.query":
            return ac.Escalate("result-shape-anomaly",
                               {"note": "unexpected envelope"})
        return None
    res = ex.execute(_run_tool, "db.query", {"q": "1"}, after=(watcher,))
    findings = [r for r in journal
                if r.get("code") == "callback-finding-escalated"]
    good = (res.get("ok") and findings
            and findings[0]["reason"] == "result-shape-anomaly")
    if good:
        return _verdict("after-finding-journal", True,
                        "finding escalated into journal; result returned")
    return _verdict("after-finding-journal", False,
                    "result=%r findings=%r" % (res, findings))


def p_malformed_verdict():
    journal = []
    ex = _executor(journal=journal)
    def garbage(tool_name, args):
        return "i am not a verdict"
    ran = []
    def spy(tool_name, args):
        ran.append(tool_name)
        return _run_tool(tool_name, args)
    try:
        ex.execute(spy, "db.query", {"q": "1"}, before=(garbage,))
    except Exception as exc:
        code = getattr(exc, "code", None)
        if HAVE_MODULE and code == "callback-malformed-verdict" and not ran:
            return _verdict("malformed-verdict", True,
                            "non-verdict refused callback-malformed-verdict")
        return _verdict("malformed-verdict", False,
                        "unexpected %r" % (exc,))
    if MODE == "stub" and ran:
        return _verdict("malformed-verdict", False,
                        "stub ran the tool on a garbage verdict")
    return _verdict("malformed-verdict", True, "verdict accepted")


def p_block_unknown_code():
    if MODE == "stub":
        return _baseline("block-unknown-code", "module-only probe")
    journal = []
    ex = ac.CallbackExecutor(journal=journal)
    def blocker(tool_name, args):
        return ac.Block("definitely-not-a-code")
    ran = []
    def spy(tool_name, args):
        ran.append(tool_name)
        return _run_tool(tool_name, args)
    try:
        ex.execute(spy, "db.query", {"q": "1"}, before=(blocker,))
    except Exception as exc:
        code = getattr(exc, "code", None)
        if code == "callback-malformed-verdict" and not ran:
            return _verdict("block-unknown-code", True,
                            "unknown block code refused fail-closed")
        return {"name": "block-unknown-code", "result": "ERROR",
                "detail": "unexpected %r" % (exc,)}
    return _verdict("block-unknown-code", False, "unknown code accepted")


def p_control_plain_execution():
    ex = _executor()
    res = ex.execute(_run_tool, "db.query", {"q": "1"})
    if res.get("ok") and res.get("tool") == "db.query":
        return _verdict("control-plain-execution", True,
                        "unadorned execution works")
    return _verdict("control-plain-execution", False, "plain run failed")


def p_control_continue_observer():
    journal = []
    ex = _executor(journal=journal)
    seen = []
    def observer(tool_name, args):
        seen.append(("before", tool_name))
        return ac.Continue() if HAVE_MODULE else None
    def watcher(tool_name, args, result):
        seen.append(("after", tool_name))
        return None
    res = ex.execute(_run_tool, "db.query", {"q": "1"},
                     before=(observer,), after=(watcher,))
    if MODE == "stub":
        return _verdict("control-continue-observer", True,
                        "stub passes observers through")
    if res.get("ok") and seen == [("before", "db.query"),
                                  ("after", "db.query")]:
        return _verdict("control-continue-observer", True,
                        "observers saw both seams; result unchanged")
    return _verdict("control-continue-observer", False, "seen=%r" % (seen,))


def p_control_hitl_approve_path():
    if MODE == "stub":
        return _baseline("control-hitl-approve-path", "module-only probe")
    journal = []
    gate = ac.HumanApprovalGate(journal=journal)
    ex = ac.CallbackExecutor(journal=journal)
    approval_id = gate.request("payments.refund", {"amount": 500})
    verdict = gate.resolve(approval_id, True, decider="human-1")
    ran = []
    def spy(tool_name, args):
        ran.append((tool_name, dict(args)))
        return _run_tool(tool_name, args)
    res = ex.execute(spy, "payments.refund", {"amount": 500},
                     before=(lambda t, a: verdict,))
    if res.get("ok") and ran == [("payments.refund", {"amount": 500})]:
        return _verdict("control-hitl-approve-path", True,
                        "approved call runs with original args")
    return _verdict("control-hitl-approve-path", False,
                    "res=%r ran=%r" % (res, ran))


def p_control_on_error_suppress():
    if MODE == "stub":
        return _baseline("control-on-error-suppress", "module-only probe")
    ex = ac.CallbackExecutor()
    def failer(tool_name, args):
        raise IOError("tool blew up")
    def suppressor(tool_name, args, error):
        if isinstance(error, IOError):
            return {"ok": False, "suppressed": True}
        return None
    res = ex.execute(failer, "db.query", {"q": "1"},
                     on_error=(suppressor,))
    if res == {"ok": False, "suppressed": True}:
        return _verdict("control-on-error-suppress", True,
                        "error callback suppressed with replacement")
    return _verdict("control-on-error-suppress", False, "res=%r" % (res,))


def p_taxonomy_pin():
    if MODE == "stub" or not HAVE_MODULE:
        return _baseline("taxonomy-pin", "module-only probe")
    codes = decision_codes.TAXONOMY
    missing = [c for c in EXPECTED_CALLBACK_CODES if c not in codes]
    import re as _re
    src = open(os.path.join(REPO_ROOT, "gov", "decision_codes.py")).read()
    lits = [a or b for a, b in
            _re.findall(r'"code": \'([^\']+)\'|"code": "([^"]+)"', src)]
    if missing:
        return _verdict("taxonomy-pin", False, "missing %r" % (missing,))
    if len(codes) != TAXONOMY_PIN:
        return _verdict("taxonomy-pin", False,
                        "len(TAXONOMY)=%d != %d" % (len(codes), TAXONOMY_PIN))
    if len(lits) != len(set(lits)):
        dups = sorted({c for c in lits if lits.count(c) > 1})
        return _verdict("taxonomy-pin", False,
                        "duplicate literals %r" % (dups,))
    if len(lits) != TAXONOMY_PIN:
        return _verdict("taxonomy-pin", False,
                        "raw literals %d != %d" % (len(lits), TAXONOMY_PIN))
    return _verdict("taxonomy-pin", True,
                    "%d codes, %d unique raw literals"
                    % (len(codes), len(lits)))


PROBES = (
    p_block_before_tool,
    p_rewrite_args,
    p_enforcement_floor,
    p_callback_cannot_widen,
    p_throwing_callback,
    p_hitl_escalate_pause,
    p_hitl_deny_resume,
    p_hitl_expire,
    p_after_finding_journal,
    p_malformed_verdict,
    p_block_unknown_code,
    p_control_plain_execution,
    p_control_continue_observer,
    p_control_hitl_approve_path,
    p_control_on_error_suppress,
    p_taxonomy_pin,
)


def green_check():
    """Depth-1 green check: adjacent batteries run with GOV_SKIP_GREEN=1."""
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN"):
        print("green_check: skipped (GOV_SKIP_GREEN set)")
        return True
    ok = True
    for battery in ("durable_approval_probes.py",):
        path = os.path.join(REPO_ROOT, "evals", battery)
        if not os.path.exists(path):
            print("green_check: missing %s (skip)" % battery)
            continue
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        proc = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600, env=env, cwd=REPO_ROOT)
        print("green_check: %s exit=%d" % (battery, proc.returncode))
        if proc.returncode != 0:
            ok = False
            print(proc.stdout[-2000:])
            print(proc.stderr[-2000:])
    return ok


def main():
    results = []
    for probe in PROBES:
        try:
            results.append(probe())
        except Exception as exc:  # never let a probe crash the battery
            results.append({"name": probe.__name__, "result": "ERROR",
                            "detail": "probe crashed: %r" % (exc,)})
    held = [r for r in results if r["result"] == "HELD"]
    broke = [r for r in results if r["result"] == "BREAK"]
    baseline = [r for r in results if r["result"] == "BASELINE"]
    errors = [r for r in results if r["result"] == "ERROR"]
    print("mode=%s deployment=%s" % (
        MODE, os.environ.get("GOV_DEPLOYMENT_MODE", "(unset)")))
    for r in results:
        print("%-28s %-8s %s" % (r["name"], r["result"], r["detail"]))
    print("HELD %d / BREAK %d / BASELINE %d / ERROR %d"
          % (len(held), len(broke), len(baseline), len(errors)))
    if not green_check():
        print("GREEN CHECK FAILED")
        return 2
    if broke or errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
