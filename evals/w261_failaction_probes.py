"""Break-first battery: failure-action correction pipeline (wave-261 lane 2).

guardrails-ai OnFailAction ADAPT (pattern only, no guardrails code): the
8-member failure-action vocabulary (reask/fix/fix_reask/filter/refrain/
noop/exception/custom) plus the FailResult diagnostics handoff, re-grounded
for agent-governance: our fail-closed checks refuse and stop; this lane
adds the correction pipeline -- a named action per refusal, a safe
executable subset, and agentic actions as structured caller-honored
requests (never auto-repair of caller data).

Seams under test (tdd: agreed up front):
  1. ``gov.failure_actions.apply_action`` -- the module contract.
  2. ``gov.evidence_quality`` -- the wired seam: refusals carry a
     FailResult naming the prescribed action; default behavior
     unchanged (refusals still refuse) unless the caller opts into
     ``evaluate_with_action``.

Verdicts: HELD (contract holds / refusal preserved), BREAK (genuine
defect), GAP (the seam does not exist pre-fix -- expected before the
lane lands), ERROR (harness bug -- fix the harness, never the product).

Red-first: run BEFORE the lane lands -- every probe must be GAP.
Run AFTER -- every probe must be HELD. Run twice (staging +
``env -u GOV_DEPLOYMENT_MODE``); verdicts must agree.

No in-repo git subprocesses. Stdlib only. Deterministic.

Taxonomy pin: 1092 -- this lane adds NO new decision codes (failures
re-raise the FailResult's own machine code; see gov/failure_actions.py),
so the pin must NOT move.
"""

import copy
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

try:
    from gov import failure_actions as fa  # noqa: E402
    HAVE_MODULE = True
except ImportError:
    fa = None  # noqa: F841
    HAVE_MODULE = False

from gov import evidence_quality as eq  # noqa: E402 (exists at base)
from gov import decision_codes  # noqa: E402 (taxonomy pin below)

TAXONOMY_PIN = 2069 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*)



_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _gap(detail=""):
    return ("GAP", detail)


def _fr(code="evidence-quality-malformed", action="exception",
        detail="probe failure", diagnostics=None):
    return fa.FailResult(code=code, action=action, detail=detail,
                         diagnostics=diagnostics)


# ---------------------------------------------------------------------------
# 1. Unknown action name -> exception (fail-closed, code preserved)
# ---------------------------------------------------------------------------

@probe("unknown-action-fails-closed")
def p_unknown_action():
    # Unknown action NAMES (strings outside the vocabulary) fail
    # closed at apply time: the FailResult's own machine code is
    # re-raised, never widened, never silently allowed.
    for bad in ("teleport", "FILTER", " filter", "re ask"):
        fr = fa.FailResult(code="evidence-quality-malformed",
                           action=bad, detail="bad action name")
        try:
            fa.apply_action(fr, {"value": [1, 2]})
        except fa.FailureActionError as exc:
            if exc.code != "evidence-quality-malformed":
                return _break("unknown action %r changed the machine "
                              "code to %r" % (bad, exc.code))
            continue
        except Exception as exc:  # noqa: BLE001
            return _break("unknown action %r raised non-machine "
                          "error %r" % (bad, exc))
        return _break("unknown action %r did not raise" % (bad,))
    # Malformed actions (non-string / empty) are programming errors:
    # FailResult construction itself refuses with TypeError -- also
    # fail-closed, just earlier.
    for bad in (None, 42, "", b"filter"):
        try:
            fa.FailResult(code="evidence-quality-malformed",
                          action=bad)
        except TypeError:
            continue
        return _break("malformed action %r constructed" % (bad,))
    return _held("4 unknown names -> FailureActionError, original "
                 "code preserved; 4 malformed -> TypeError")


# ---------------------------------------------------------------------------
# 2. Handler errors -> exception (never a silent downgrade)
# ---------------------------------------------------------------------------

@probe("handler-error-fails-closed")
def p_handler_error():
    # custom handler that raises -> exception with the original code
    def _raiser(fail_result, context):
        raise RuntimeError("handler blew up")

    fr = _fr(action="custom")
    try:
        fa.apply_action(fr, {"handler": _raiser})
        return _break("raising custom handler did not raise")
    except fa.FailureActionError as exc:
        if exc.code != "evidence-quality-malformed":
            return _break("handler error changed the code to %r"
                          % (exc.code,))

    # custom with no handler configured -> exception (fail closed)
    try:
        fa.apply_action(_fr(action="custom"), {})
        return _break("custom without handler did not raise")
    except fa.FailureActionError:
        pass

    # filter with no value to filter -> exception, not a blind pass
    try:
        fa.apply_action(_fr(action="filter",
                            diagnostics={"field_path": "[0]"}), {})
        return _break("filter without a value did not raise")
    except fa.FailureActionError:
        pass

    # filter with a malformed field path -> exception
    try:
        fa.apply_action(_fr(action="filter",
                            diagnostics={"field_path": "evidence["}),
                        {"value": [1]})
        return _break("filter with malformed field path did not raise")
    except fa.FailureActionError:
        pass

    # BaseException from a handler must NOT be converted (fail-closed
    # philosophy: never mask an interpreter-level abort)
    def _kbd(fail_result, context):
        raise KeyboardInterrupt()

    try:
        fa.apply_action(_fr(action="custom"), {"handler": _kbd})
        return _break("KeyboardInterrupt was swallowed")
    except KeyboardInterrupt:
        pass
    except fa.FailureActionError:
        return _break("KeyboardInterrupt converted to FailureActionError")
    return _held("raising/missing/malformed handlers -> exception; "
                 "BaseException propagates raw")


# ---------------------------------------------------------------------------
# 3. Filter must not let the offending bytes through (bypass attempt)
# ---------------------------------------------------------------------------

@probe("filter-no-bypass")
def p_filter_no_bypass():
    bad = {"seq": "not-a-number", "marker": "OFFENDING-BYTES-1"}
    # The offending object is ALIASED at a second path the diagnostics
    # do not name. A naive delete-at-path filter would return a value
    # that still carries the offending bytes.
    evidence = [{"seq": 1}, bad, {"seq": 3, "alias": bad}]
    fr = _fr(code="evidence-quality-evidence-malformed", action="filter",
             detail="item 1 is not well-formed",
             diagnostics={"field_path": "[1]"})
    try:
        out = fa.apply_action(fr, {"value": evidence})
    except fa.FailureActionError as exc:
        detail = str(exc).lower()
        if "survive" not in detail and "bypass" not in detail:
            return _break("filter refused but not for bypass: %r"
                          % (str(exc)[:120],))
    else:
        return _break("aliased offending bytes survived filtering: "
                      "returned value still carries them")

    # Positive control: no aliasing -> exact redaction, caller untouched
    clean = [{"seq": 1}, {"seq": "bad"}, {"seq": 3}]
    snapshot = copy.deepcopy(clean)
    fr2 = _fr(code="evidence-quality-evidence-malformed", action="filter",
              diagnostics={"field_path": "[1]"})
    out = fa.apply_action(fr2, {"value": clean})
    if out["disposition"] != "continued":
        return _break("filter disposition %r" % (out["disposition"],))
    if out["payload"]["value"] != [{"seq": 1}, {"seq": 3}]:
        return _break("filter redacted the wrong bytes: %r"
                      % (out["payload"]["value"],))
    if clean != snapshot:
        return _break("filter mutated the caller's value")
    # every surviving subvalue byte-identical to the input
    if out["payload"]["value"][0] != snapshot[0] or\
            out["payload"]["value"][1] != snapshot[2]:
        return _break("filter altered non-offending fields")
    return _held("aliased bypass -> exception; clean filter exact, "
                 "caller unmutated")


# ---------------------------------------------------------------------------
# 4. Refrain stops the step, not the whole run's audit
# ---------------------------------------------------------------------------

@probe("refrain-scope")
def p_refrain_scope():
    audit = []    # the run's audit log: caller-owned, module must not touch
    journal = []  # the pipeline's decision log: context-owned
    fr = _fr(code="evidence-quality-gate-failed", action="refrain",
             detail="gate refused emission")

    def step(name, fail=None):
        if fail is not None:
            outcome = fa.apply_action(fail, {"journal": journal})
            if outcome["disposition"] != "refrained":
                raise AssertionError("disposition %r"
                                     % (outcome["disposition"],))
            return
        audit.append(name)

    step("ingest")
    step("emit", fail=fr)   # this step stops ...
    step("archive")          # ... but the run continues
    if audit != ["ingest", "archive"]:
        return _break("refrain disturbed the run audit: %r" % (audit,))
    if len(journal) != 1 or journal[0]["action"] != "refrain":
        return _break("refrain decision not recorded: %r" % (journal,))
    return _held("step stopped, run continued, audit intact, "
                 "decision recorded")


# ---------------------------------------------------------------------------
# 5. exception is the default: the machine-coded error, carried FailResult
# ---------------------------------------------------------------------------

@probe("exception-is-default")
def p_exception_default():
    fr = _fr(code="evidence-quality-empty-evidence", action="exception",
             detail="no evidence presented")
    try:
        fa.apply_action(fr, {})
    except fa.FailureActionError as exc:
        if exc.code != "evidence-quality-empty-evidence":
            return _break("code not preserved: %r" % (exc.code,))
        if exc.fail_result is not fr:
            return _break("FailResult not carried on the exception")
        return _held("raises the machine-coded error, FailResult carried")
    except Exception as exc:  # noqa: BLE001
        return _break("wrong exception type: %r" % (exc,))
    return _break("exception action did not raise")


# ---------------------------------------------------------------------------
# 6. Wired seam: malformed evidence carries filter + field path
# ---------------------------------------------------------------------------

@probe("seam-malformed-carries-filter")
def p_seam_malformed():
    exp = [{"expectation_type": "expect_evidence_monotonic",
            "kwargs": {}}]
    evidence = [{"seq": 1}, "not-a-dict", {"seq": 3}]
    try:
        eq.evaluate(exp, evidence)
        return _break("malformed evidence did not refuse")
    except eq.EvidenceQualityError as exc:
        if exc.code != "evidence-quality-evidence-malformed":
            return _break("wrong code: %r" % (exc.code,))
        fr = exc.fail_result
        if fr is None:
            return _break("refusal carries no FailResult")
        if fr.action != "filter":
            return _break("prescribed action %r, want 'filter'"
                          % (fr.action,))
        if fr.diagnostics.get("field_path") != "[1]":
            return _break("field path %r, want '[1]'"
                          % (fr.diagnostics.get("field_path"),))
    # the prescribed action actually executes end to end
    out = fa.apply_action(fr, {"value": evidence})
    if out["payload"]["value"] != [{"seq": 1}, {"seq": 3}]:
        return _break("end-to-end filter wrong: %r"
                      % (out["payload"]["value"],))
    return _held("refusal carries filter + field path; filter executes")


# ---------------------------------------------------------------------------
# 7. Wired seam: empty evidence still refuses (default unchanged); the
#    caller can opt into handling via evaluate_with_action
# ---------------------------------------------------------------------------

@probe("seam-empty-evidence-still-refuses")
def p_seam_empty():
    exp = [{"expectation_type": "expect_evidence_monotonic",
            "kwargs": {}}]
    try:
        eq.evaluate(exp, [])
        return _break("empty evidence did not refuse")
    except eq.EvidenceQualityError as exc:
        if exc.code != "evidence-quality-empty-evidence":
            return _break("wrong code: %r" % (exc.code,))
        if exc.fail_result is None or\
                exc.fail_result.action != "exception":
            return _break("empty evidence must prescribe exception")
    # opt-in handling path: returns the FailResult instead of raising
    report, fr = eq.evaluate_with_action(exp, [])
    if report is not None:
        return _break("opt-in path returned a report on refusal")
    if fr is None or fr.code != "evidence-quality-empty-evidence" or\
            fr.action != "exception":
        return _break("opt-in FailResult wrong: %r" % (fr,))
    # success path unchanged: (report, None)
    good = [{"seq": 1}, {"seq": 2}]
    report2, fr2 = eq.evaluate_with_action(exp, good)
    if fr2 is not None or not report2["success"]:
        return _break("success path changed")
    return _held("default still refuses; opt-in returns FailResult; "
                 "success path unchanged")


# ---------------------------------------------------------------------------
# 8. Agentic actions are structured caller-honored requests, never
#    auto-repair
# ---------------------------------------------------------------------------

@probe("agentic-actions-are-requests")
def p_agentic():
    for action in ("reask", "fix", "fix_reask"):
        data = {"evidence": [{"seq": 1}]}
        snapshot = copy.deepcopy(data)
        journal = []
        fr = _fr(action=action, detail="needs regeneration",
                 diagnostics={"field_path": "[0]"})
        out = fa.apply_action(fr, {"value": data, "journal": journal})
        if out["disposition"] != "requested":
            return _break("%s disposition %r" % (action,
                                                 out["disposition"]))
        req = out["payload"]
        if not isinstance(req, dict) or\
                req.get("type") != "action-request" or\
                req.get("action") != action or\
                req.get("code") != "evidence-quality-malformed":
            return _break("%s request malformed: %r" % (action, req))
        if data != snapshot:
            return _break("%s mutated caller data" % (action,))
        if len(journal) != 1 or journal[0]["action"] != action:
            return _break("%s decision not recorded" % (action,))
    return _held("reask/fix/fix_reask -> structured requests, "
                 "caller data untouched, decisions recorded")


# ---------------------------------------------------------------------------
# 9. noop records and continues
# ---------------------------------------------------------------------------

@probe("noop-records-and-continues")
def p_noop():
    journal = []
    out = fa.apply_action(_fr(action="noop", detail="benign"),
                          {"journal": journal})
    if out["disposition"] != "continued":
        return _break("noop disposition %r" % (out["disposition"],))
    if len(journal) != 1 or journal[0]["action"] != "noop":
        return _break("noop decision not recorded")
    # noop without a journal still continues
    out2 = fa.apply_action(_fr(action="noop"), {})
    if out2["disposition"] != "continued":
        return _break("journal-less noop did not continue")
    return _held("noop continues; decision recorded when journaled")


# ---------------------------------------------------------------------------
# 10. custom: caller handler honored; missing handler fails closed
# ---------------------------------------------------------------------------

@probe("custom-handler")
def p_custom():
    journal = []
    out = fa.apply_action(
        _fr(action="custom", detail="escalate",
            diagnostics={"queue": "approval"}),
        {"handler": lambda fr, ctx: {"escalated": True},
         "journal": journal})
    if out["disposition"] != "custom":
        return _break("custom disposition %r" % (out["disposition"],))
    if out["payload"] != {"escalated": True}:
        return _break("custom payload not passed through: %r"
                      % (out["payload"],))
    if len(journal) != 1 or journal[0]["action"] != "custom":
        return _break("custom decision not recorded")
    return _held("custom handler result passed through; recorded")


# ---------------------------------------------------------------------------
# 11. Wired seam: gate failure prescribes refrain
# ---------------------------------------------------------------------------

@probe("seam-gate-failed-refrains")
def p_gate_failed():
    exp = [{"expectation_type": "expect_evidence_monotonic",
            "kwargs": {}}]
    evidence = [{"seq": 2}, {"seq": 1}]  # decreasing -> gate fails
    try:
        eq.emit_with_quality_gate("probe-src", "json", exp, evidence)
        return _break("failing gate did not refuse")
    except eq.EvidenceQualityError as exc:
        if exc.code != "evidence-quality-gate-failed":
            return _break("wrong code: %r" % (exc.code,))
        fr = exc.fail_result
        if fr is None or fr.action != "refrain":
            return _break("gate failure must prescribe refrain, got %r"
                          % (fr.action if fr else None,))
        failed = fr.diagnostics.get("failed_expectations", [])
        if "expect_evidence_monotonic" not in failed:
            return _break("diagnostics missing failed expectation: %r"
                          % (fr.diagnostics,))
    return _held("gate failure carries refrain + failed expectations")


# ---------------------------------------------------------------------------
# 12. Taxonomy pin: repointed by the wave-262 alert lane (1106 -> 1110:
#     +4 detector-* codes: detector-deprecated,
#     detector-exception-malformed, detector-unknown-maturity,
#     detector-unknown-priority)
# ---------------------------------------------------------------------------

@probe("taxonomy-pin-unchanged")
def p_pin():
    n = len(decision_codes.TAXONOMY)
    if n != TAXONOMY_PIN:
        return _break("taxonomy pin moved: %d != %d" % (n, TAXONOMY_PIN))
    return _held("pin 1110 holds (+4 detector-* codes, wave-262 alert lane)")


# ---------------------------------------------------------------------------
# Depth-1 green check (honors GOV_SKIP_GREEN)
# ---------------------------------------------------------------------------

def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    if not HAVE_MODULE:
        print("GREEN CHECK: skipped (module absent pre-fix)")
        return True
    import subprocess
    import tempfile
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    td = tempfile.mkdtemp(prefix="g261-failaction-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = td
    adj = [
        [sys.executable, "-m", "unittest", "tests.test_evidence_quality",
         "-v"],
        [sys.executable, "-m", "unittest", "tests.test_failure_actions",
         "-v"],
        [sys.executable, "-m", "unittest", "tests.test_decision_codes",
         "-v"],
    ]
    for cmd in adj:
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=600)
        if r.returncode != 0:
            print("GREEN CHECK FAILED:", " ".join(cmd))
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            return False
    print("GREEN CHECK: evidence_quality + failure_actions + "
          "decision_codes green")
    return True


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md), red-first: GAP -> BREAK.
# Raw rows keep the battery's own vocabulary (count code and exit contract
# untouched); the mapping happens here, at emission. Anything unexpected
# fails closed as ERROR.
def _mapped(rows):
    out = []
    for _name, _verdict, _detail in rows:
        if _verdict == "GAP":
            out.append((_name, "BREAK", "GAP: %s" % (_detail,)))
        elif _verdict in ("HELD", "BREAK", "ERROR"):
            out.append((_name, _verdict, _detail))
        else:
            out.append((_name, "ERROR",
                        "unexpected verdict %r: %s" % (_verdict, _detail)))
    return out

def main():
    results = []
    if not HAVE_MODULE:
        for name, _p in _PROBES:
            results.append((name, "GAP", "module absent pre-fix"))
    else:
        for name, p in _PROBES:
            try:
                verdict, detail = p()
                results.append((name, verdict, detail))
            except Exception as exc:  # never mask a crash
                results.append((name, "BREAK",
                                "harness crash: %r" % (exc,)))
    held = sum(1 for _, v, _ in results if v == "HELD")
    brk = sum(1 for _, v, _ in results if v.startswith("BREAK"))
    gap = sum(1 for _, v, _ in results if v == "GAP")
    mapped = _mapped(results)
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        mapped, brk + gap, held, 0)
    probe_lines.emit(mapped)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk + gap, held, 0))
    ok = green_check()
    return held, brk, gap, ok


if __name__ == "__main__":
    held, brk, gap, ok = main()
    sys.exit(0 if (gap or (held, brk, gap) == (len(_PROBES), 0, 0))
             and ok else 1)
