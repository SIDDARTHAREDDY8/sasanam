"""Break-first red battery: deterministic approval remediation taxonomy
(wave-279 lane 6; guardrails-ai ``OnFailAction`` ADAPT -- the taxonomy of
remediation outcomes only, no guardrails-ai code, schemas, or RAIL/XML
machinery).

The gap under test: on the wave-278 base, when an approval elicitation
fails validation, the refusal is an ad-hoc error path -- the audit entry
carries a free-text reason but NO deterministic, coded remediation
classification, and there is no bounded re-ask-with-repair loop at the
approval seam (retry discipline is whatever the caller improvises).

Break shapes pinned here (all must report HELD on the lane tree):
  (a) every elicit_decision refusal is classified by a deterministic
      remediation taxonomy: the audit entry carries a ``remediation``
      sub-record {failure_class, action, retry_permitted, ...} and the
      raised ElicitationError carries the same outcome as
      ``.remediation`` -- no more ad-hoc error paths;
  (b) fixable validation failures (schema-invalid / missing rationale)
      -> action "reask", retry_permitted True, budget untouched;
  (c) caller-contract violations (unknown response vocabulary) ->
      action "exception", terminal;
  (d) secret-shaped rationale -> action "refrain" (fail-closed, LOUD,
      secret never echoed), retry_permitted False;
  (e) budget exhaustion -> action "refrain" with budget_remaining 0;
  (f) the re-ask-repair loop is BOUNDED: an always-failing producer
      terminates within max_rounds (fail-closed refrain), never raises,
      and records every step;
  (g) a declared fix that re-verifies clean -> action "fix", proceed
      with the repaired value;
  (h) the harness driver shares the elicitation budget semantics: with
      the queue budget exhausted it never calls produce() and returns
      a terminal refrain outcome;
  (i) determinism: the same failure classifies identically twice;
  (j) no new decision codes: the taxonomy pin stays 1493 (the lane
      adds no refusal idioms -- remediation rides as data inside
      existing audit events).

$0 spend, synthetic/local, deterministic (fixed fixtures, no
wall-clock assertions). Stdlib only, no in-repo git subprocesses.
Fresh TMPDIR per process is the caller's concern; the depth-1 green
checks below mint their own TMPDIRs.

Run:
  mkdir -p /var/tmp/g279-remediation && TMPDIR=/var/tmp/g279-remediation \
    ~/workspace/.gov-venv/bin/python evals/w279_remediation_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g279-remediation2 \
    ~/workspace/.gov-venv/bin/python evals/w279_remediation_probes.py
"""

import os
import sys

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

from harness import make_run  # noqa: E402
from gov import elicitation_contract as ec  # noqa: E402

try:
    from gov import remediation as rem  # noqa: E402
    HAVE_REM = True
except Exception:  # noqa: BLE001
    rem = None
    HAVE_REM = False

RESULTS = []


def _record(name, verdict, detail=""):
    RESULTS.append({"probe": name, "verdict": verdict, "detail": detail})
    return verdict


def _held(name, detail=""):
    return _record(name, "HELD", detail)


def _broken(name, detail=""):
    return _record(name, "BREAK", detail)


def _error(name, detail=""):
    return _record(name, "ERROR", detail)


def _events(run, name):
    return [e for e in run["read_log"]() if e.get("event") == name]


def _queue_one(run, agent_id="agent-1"):
    ident = run["executor"].mint_identity(agent_id, "support", agent_id)
    res = run["executor"].call(
        ident, "send_email", to="victim@synthetic.local",
        subject="hello", body="hello")
    assert res["status"] == "queued", res
    return res["approval_id"]


def _refuse_once(run, aid, response, rationale=None):
    """Elicit once; expect refusal. Returns (exc, remediation outcome)."""
    try:
        run["approvals"].elicit_decision(aid, response, rationale=rationale)
    except ValueError as exc:
        return exc, getattr(exc, "remediation", None)
    return None, None


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

def probe_schema_invalid_reask_classified():
    name = "schema-invalid-reask-classified"
    try:
        run = make_run()
        aid = _queue_one(run)
        exc, outcome = _refuse_once(
            run, aid, "decline", rationale={"reason": 123})
        if exc is None:
            return _broken(name, "schema-invalid rationale accepted")
        evs = _events(run, "elicitation_refused")
        if not evs:
            return _broken(name, "no elicitation_refused event")
        logged = evs[-1].get("remediation")
        if outcome is None or logged is None:
            return _broken(
                name, "ad-hoc refusal: no remediation classification "
                "(outcome=%r logged=%r)" % (outcome, logged))
        if outcome.get("failure_class") != "schema-invalid":
            return _broken(name, "failure_class=%r"
                           % (outcome.get("failure_class"),))
        if outcome.get("action") != "reask":
            return _broken(name, "action=%r" % (outcome.get("action"),))
        if outcome.get("retry_permitted") is not True:
            return _broken(name, "retry_permitted=%r"
                           % (outcome.get("retry_permitted"),))
        if outcome.get("budget_remaining") != 3:
            return _broken(name, "budget_remaining=%r (failed validation "
                           "must not burn budget)"
                           % (outcome.get("budget_remaining"),))
        if logged != outcome:
            return _broken(name, "logged remediation != raised outcome")
        if run["approvals"].get(aid)["status"] != "pending":
            return _broken(name, "record mutated")
        return _held(name, "classified reask; budget untouched")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_rationale_missing_reask_classified():
    name = "rationale-missing-reask-classified"
    try:
        run = make_run()
        aid = _queue_one(run)
        exc, outcome = _refuse_once(run, aid, "decline", rationale=None)
        if exc is None:
            return _broken(name, "reasonless decline accepted")
        if outcome is None:
            return _broken(name, "ad-hoc refusal: no remediation outcome")
        if outcome.get("failure_class") != "rationale-missing":
            return _broken(name, "failure_class=%r"
                           % (outcome.get("failure_class"),))
        if outcome.get("action") != "reask":
            return _broken(name, "action=%r" % (outcome.get("action"),))
        return _held(name, "classified reask")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_vocabulary_unknown_exception_terminal():
    name = "vocabulary-unknown-exception-terminal"
    try:
        run = make_run()
        aid = _queue_one(run)
        exc, outcome = _refuse_once(run, aid, "bogus-response")
        if exc is None:
            return _broken(name, "unknown response accepted")
        if outcome is None:
            return _broken(name, "ad-hoc refusal: no remediation outcome")
        if outcome.get("failure_class") != "vocabulary-unknown":
            return _broken(name, "failure_class=%r"
                           % (outcome.get("failure_class"),))
        if outcome.get("action") != "exception":
            return _broken(name, "action=%r" % (outcome.get("action"),))
        if outcome.get("retry_permitted") is not False:
            return _broken(name, "retry_permitted=%r"
                           % (outcome.get("retry_permitted"),))
        return _held(name, "terminal exception classification")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_secret_detected_refrain_loud():
    name = "secret-detected-refrain-loud"
    try:
        run = make_run()
        aid = _queue_one(run)
        exc, outcome = _refuse_once(
            run, aid, "decline",
            rationale={"reason": "declining because api_key=sk-live-abc123"})
        if exc is None:
            return _broken(name, "secret-shaped rationale accepted")
        evs = _events(run, "elicitation_secret_detected")
        if not evs:
            return _broken(name, "no elicitation_secret_detected event")
        if outcome is None:
            return _broken(name, "ad-hoc refusal: no remediation outcome")
        if outcome.get("failure_class") != "secret-detected":
            return _broken(name, "failure_class=%r"
                           % (outcome.get("failure_class"),))
        if outcome.get("action") != "refrain":
            return _broken(name, "action=%r" % (outcome.get("action"),))
        if outcome.get("retry_permitted") is not False:
            return _broken(name, "retry_permitted=%r"
                           % (outcome.get("retry_permitted"),))
        blob = "".join(str(e) for e in run["read_log"]())
        if "sk-live-abc123" in blob:
            return _broken(name, "secret echoed into the audit log")
        if run["approvals"].get(aid)["status"] != "pending":
            return _broken(name, "record mutated")
        return _held(name, "fail-closed refrain; secret never echoed")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_budget_exhausted_refrain():
    name = "budget-exhausted-refrain"
    try:
        run = make_run()
        aid = _queue_one(run)
        q = run["approvals"]
        # Three well-formed elicitations, each bounced downstream by
        # decide()'s ceremony-integrity gate (rationale contradicts the
        # decline) -- the record stays pending, each burns one attempt.
        for _ in range(3):
            try:
                q.elicit_decision(aid, "decline",
                                  rationale={"reason":
                                             "yes, approve this now"})
                return _broken(name, "contradictory rationale accepted")
            except ValueError:
                pass
        exc, outcome = _refuse_once(
            run, aid, "decline", rationale={"reason": "still no"})
        if exc is None:
            return _broken(name, "4th elicitation accepted")
        if "budget exhausted" not in str(exc):
            return _broken(name, "wrong refusal: %s" % exc)
        evs = _events(run, "elicitation_budget_exhausted")
        if not evs:
            return _broken(name, "no elicitation_budget_exhausted event")
        if outcome is None:
            return _broken(name, "ad-hoc refusal: no remediation outcome")
        if outcome.get("failure_class") != "budget-exhausted":
            return _broken(name, "failure_class=%r"
                           % (outcome.get("failure_class"),))
        if outcome.get("action") != "refrain":
            return _broken(name, "action=%r" % (outcome.get("action"),))
        if outcome.get("budget_remaining") != 0:
            return _broken(name, "budget_remaining=%r"
                           % (outcome.get("budget_remaining"),))
        if outcome.get("retry_permitted") is not False:
            return _broken(name, "retry_permitted=%r"
                           % (outcome.get("retry_permitted"),))
        return _held(name, "terminal refrain; budget 0")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_repair_loop_bounded():
    name = "repair-loop-bounded"
    try:
        if not HAVE_REM:
            return _error(name, "gov.remediation absent: no bounded "
                          "re-ask-repair loop on this tree")
        calls = []

        def produce():
            calls.append(1)
            return {"broken": True}

        def validate(value):
            return False, "always-invalid"

        outcome = rem.reask_repair(produce, validate, max_rounds=2)
        if len(calls) != 3:
            return _broken(name, "produce called %d times, want 3 "
                           "(initial + 2 re-asks)" % len(calls))
        if outcome.get("action") != "refrain":
            return _broken(name, "exhaustion action=%r, want refrain"
                           % (outcome.get("action"),))
        if outcome.get("retry_permitted") is not False:
            return _broken(name, "exhaustion must be terminal")
        if len(outcome.get("steps", ())) != 3:
            return _broken(name, "steps=%r, want one per round"
                           % (outcome.get("steps"),))
        return _held(name, "always-failing loop terminates fail-closed")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_repair_loop_fix_verified():
    name = "repair-loop-fix-verified"
    try:
        if not HAVE_REM:
            return _error(name, "gov.remediation absent")
        schema = ec.validate_flat_schema(ec.DEFAULT_RATIONALE_SCHEMA)

        def validate(value):
            try:
                ec.validate_rationale(value, schema)
            except ec.ElicitationError as exc:
                return False, str(exc)
            return True, None

        def fix(value):
            # Declared static fix: drop undeclared keys (FILTER-class
            # repair), then the loop re-verifies.
            return {k: v for k, v in value.items()
                    if k in schema["properties"]}

        outcome = rem.reask_repair(
            lambda: {"reason": "no", "undeclared": "x"},
            validate, max_rounds=2, fix=fix)
        if outcome.get("action") != "fix":
            return _broken(name, "action=%r, want fix"
                           % (outcome.get("action"),))
        if outcome.get("proceed") is not True:
            return _broken(name, "proceed=%r" % (outcome.get("proceed"),))
        if outcome.get("repaired_value") != {"reason": "no"}:
            return _broken(name, "repaired_value=%r"
                           % (outcome.get("repaired_value"),))
        steps = outcome.get("steps", ())
        if not any(s.get("fix_applied") for s in steps):
            return _broken(name, "no fix_applied step recorded")
        return _held(name, "declared fix re-verified clean; step logged")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_driver_shares_budget():
    name = "driver-shares-budget"
    try:
        if not HAVE_REM:
            return _error(name, "gov.remediation absent: no harness "
                          "driver on this tree")
        run = make_run()
        aid = _queue_one(run)
        q = run["approvals"]
        for _ in range(3):
            try:
                q.elicit_decision(aid, "decline",
                                  rationale={"reason":
                                             "yes, approve this now"})
            except ValueError:
                pass
        calls = []

        def produce(round_no, last_outcome):
            calls.append(round_no)
            return ("decline", {"reason": "late retry"}, None)

        ok, outcome = rem.elicit_with_remediation(
            q, aid, produce, max_rounds=5)
        if ok:
            return _broken(name, "driver decided on an exhausted budget")
        if calls:
            return _broken(name, "produce() called %d times on an "
                           "exhausted budget: the driver must share the "
                           "elicitation budget" % len(calls))
        if outcome.get("action") != "refrain":
            return _broken(name, "action=%r, want refrain"
                           % (outcome.get("action"),))
        if outcome.get("retry_permitted") is not False:
            return _broken(name, "must be terminal")
        return _held(name, "driver never re-asks past the shared budget")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_determinism():
    name = "determinism"
    try:
        run = make_run()
        aid = _queue_one(run)
        _, first = _refuse_once(
            run, aid, "decline", rationale={"reason": 123})
        _, second = _refuse_once(
            run, aid, "decline", rationale={"reason": 123})
        if first is None or second is None:
            return _broken(name, "ad-hoc refusal: no remediation outcome")
        key = lambda o: (o.get("failure_class"), o.get("action"),  # noqa: E731
                         o.get("retry_permitted"))
        if key(first) != key(second):
            return _broken(name, "nondeterministic: %r vs %r"
                           % (key(first), key(second)))
        return _held(name, "identical failures classify identically")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_no_new_decision_codes():
    name = "no-new-decision-codes"
    try:
        from gov import decision_codes as dc  # noqa: E402
        if len(dc.TAXONOMY) != 1742:
            return _broken(name, "taxonomy pin moved: %d (wave-280 merge pin was 1541; wave-281 lane 9 adds 10 guardplugin-*)"
                           % len(dc.TAXONOMY))
        return _held(name, "pin stays 1579; no new refusal idioms")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


PROBES = (
    probe_schema_invalid_reask_classified,
    probe_rationale_missing_reask_classified,
    probe_vocabulary_unknown_exception_terminal,
    probe_secret_detected_refrain_loud,
    probe_budget_exhausted_refrain,
    probe_repair_loop_bounded,
    probe_repair_loop_fix_verified,
    probe_driver_shares_budget,
    probe_determinism,
    probe_no_new_decision_codes,
)


# ------------------------------------------------- green checks (depth-1)

def _green():
    """Depth-1: run the focused unit tests and one adjacent approval
    battery with GOV_SKIP_GREEN=1 and require zero BREAK/ERROR.
    Honors GOV_SKIP_GREEN itself (records skip, never spawns)."""
    import subprocess
    import tempfile
    if SKIP_GREEN:
        return ["green checks skipped (GOV_SKIP_GREEN=1)"]
    notes = []
    tmpd = tempfile.mkdtemp(prefix="w279-remediation-green-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    # (a) the focused unit tests for this seam.
    proc = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_remediation"],
        env=env, capture_output=True, text=True, timeout=600,
        cwd=REPO_ROOT)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0 or "OK" not in out:
        raise AssertionError(
            "green check failed: unit tests:\n%s" % out[-3000:])
    notes.append("tests.test_remediation: OK")
    # (b) the adjacent approval-v2 battery (depth-1: it honors
    # GOV_SKIP_GREEN and runs no green checks of its own). The
    # remediation lane must not change any wave-278 elicitation
    # behavior.
    bat = os.path.join(REPO_ROOT, "evals",
                       "w278_approvalv2_probes.py")
    proc = subprocess.run(
        [sys.executable, bat],
        env=env, capture_output=True, text=True, timeout=900,
        cwd=REPO_ROOT)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise AssertionError(
            "green check failed: w278_approvalv2_probes.py:\n%s"
            % out[-3000:])
    notes.append("evals/w278_approvalv2_probes.py: exit 0")
    return notes


def main():
    for probe in PROBES:
        probe()
    held = sum(1 for r in RESULTS if r["verdict"] == "HELD")
    broken = [r for r in RESULTS if r["verdict"] == "BREAK"]
    errors = [r for r in RESULTS if r["verdict"] == "ERROR"]
    print("w279 approval remediation probes: %d/%d HELD"
          % (held, len(RESULTS)))
    for r in RESULTS:
        print("  [%s] %s %s" % (r["verdict"], r["probe"], r["detail"]))
    green_notes = _green()
    for note in green_notes:
        print("  green: %s" % note)
    if broken or errors:
        print("RED: %d BREAK, %d ERROR" % (len(broken), len(errors)))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
