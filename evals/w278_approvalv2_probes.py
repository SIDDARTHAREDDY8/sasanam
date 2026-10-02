"""Break-first red battery: approval-queue v2 tri-state elicitation
contract (wave-278 lane 5; MCP ``elicitation/create`` ADAPT -- mechanism
only, no MCP code; spec revision 2026-07-28 RC pinned in
``gov/elicitation_contract.py``).

The gap under test: the human approval queue has no elicitation
contract. On the pristine base (d46ad29):

* ``decide()`` takes a free-text reason -- there is no rationale
  SCHEMA, so a decline rides on any non-empty string (a decline with
  reason "ok whatever" is accepted; nested/undeclared rationale
  fields are meaningless because no schema exists to violate);
* there is no secret ban on the decision path -- a reason carrying
  ``api_key=sk-live-...`` is accepted and logged verbatim;
* there is no tri-state vocabulary -- "cancel" does not exist, so a
  dismissed elicitation leaves the record pending SILENTLY;
* there is no re-prompt budget and no requester-identity display.

(Correction to the lane brief's premise, verified against the base
tree: decline-with-EMPTY-reason is NOT accepted on base -- the
ceremony-integrity bounce refuses it. The real base gap is the
missing contract: schema, secret ban, cancel state, budget, and
record-derived identity. The probes below pin the contract, not the
brief's inaccurate premise.)

Break shapes pinned here (all must report HELD on the lane tree):
  (a) decline without a rationale -> refused (elicitation_refused),
      record stays pending;
  (b) nested rationale value / nested rationale schema -> refused at
      validation / at build;
  (c) credential-shaped rationale -> FAIL-CLOSED refusal, record
      stays pending, LOUD elicitation_secret_detected event, secret
      NEVER echoed into the log;
  (d) requester identity on the elicitation request is derived from
      the stored record (never caller-supplied); the action summary
      is the executor-generated preview (no agent framing);
  (e) re-prompt budget: 3 well-formed elicitations burn the budget,
      the 4th is refused fail-closed with elicitation_budget_exhausted;
  (f) failed-validation / malformed attempts do NOT burn budget;
  (g) cancel -> status "cancelled" + elicitation_cancelled event, and
      the executor never executes a cancelled record;
  (h) accept with rationale -> approved, rationale chained into the
      audit entry via decide()'s reason logging;
  (i) invalid response value / unknown id / SoD self-elicitation ->
      refused and audit-logged before raising.

$0 spend, synthetic/local, deterministic (fixed fixtures, no
wall-clock assertions). Stdlib only, no in-repo git subprocesses.
Fresh TMPDIR per process is the caller's concern; the depth-1 green
checks below mint their own TMPDIRs.

Run:
  mkdir -p /var/tmp/g278-approvalv2-bat && TMPDIR=/var/tmp/g278-approvalv2-bat \
    ~/workspace/.gov-venv/bin/python evals/w278_approvalv2_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g278-approvalv2-bat2 \
    ~/workspace/.gov-venv/bin/python evals/w278_approvalv2_probes.py
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


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

def probe_decline_without_rationale_refused():
    name = "decline-without-rationale-refused"
    try:
        run = make_run()
        aid = _queue_one(run)
        try:
            run["approvals"].elicit_decision(aid, "decline",
                                            rationale=None)
            return _broken(name, "decline with no rationale accepted")
        except ValueError:
            pass
        rec = run["approvals"].get(aid)
        if rec["status"] != "pending":
            return _broken(name, "record left %s" % rec["status"])
        if not _events(run, "elicitation_refused"):
            return _broken(name, "no elicitation_refused audit event")
        return _held(name, "refused; record pending; event logged")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_nested_rationale_refused():
    name = "nested-rationale-refused"
    try:
        run = make_run()
        aid = _queue_one(run)
        # Nested VALUE against the flat default schema.
        try:
            run["approvals"].elicit_decision(
                aid, "decline",
                rationale={"reason": {"text": "nested"}})
            return _broken(name, "nested rationale value accepted")
        except ValueError:
            pass
        # Nested SCHEMA rejected at build time.
        try:
            ec.build_elicitation_request(
                run["approvals"].get(aid),
                rationale_schema={
                    "type": "object",
                    "properties": {"d": {"type": "object"}},
                })
            return _broken(name, "nested schema accepted at build")
        except ec.ElicitationError:
            pass
        if run["approvals"].get(aid)["status"] != "pending":
            return _broken(name, "record mutated by refused elicitation")
        return _held(name, "nested value + nested schema both refused")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_credential_in_rationale_fail_closed():
    name = "credential-in-rationale-fail-closed"
    try:
        run = make_run()
        aid = _queue_one(run)
        secret = "sk-live-9f8e7d6c5b4a"
        try:
            run["approvals"].elicit_decision(
                aid, "decline",
                rationale={"reason": "api_key=" + secret})
            return _broken(name, "credential-shaped rationale accepted")
        except ValueError:
            pass
        rec = run["approvals"].get(aid)
        if rec["status"] != "pending":
            return _broken(name, "record not pending after secret hit")
        hits = _events(run, "elicitation_secret_detected")
        if not hits:
            return _broken(name, "no elicitation_secret_detected event")
        if hits[0].get("decided_by") != "human-operator":
            return _broken(name, "decider not bound on secret event")
        log_text = "\n".join(str(e) for e in run["read_log"]())
        if secret in log_text:
            return _broken(name, "SECRET ECHOED INTO THE LOG")
        return _held(name, "refused; pending; LOUD event; secret redacted")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_requester_identity_from_record():
    name = "requester-identity-from-record"
    try:
        run = make_run()
        aid = _queue_one(run, agent_id="agent-7")
        rec = run["approvals"].get(aid)
        req = ec.build_elicitation_request(rec)
        # Identity is the RECORD's -- there is no caller-supplied
        # identity parameter on the builder at all.
        if req.requester_identity != {"agent_id": "agent-7",
                                      "role": "support"}:
            return _broken(name, "identity mismatch: %r"
                           % (req.requester_identity,))
        # Action summary is the executor-generated preview: no agent
        # framing can reach the decider through this seam.
        from gov.approvals import sanitize_preview_text
        if req.action_summary != sanitize_preview_text(rec["preview"]):
            return _broken(name, "summary is not the record preview")
        return _held(name, "identity+summary derived from the record")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_reprompt_budget_exhausted():
    name = "reprompt-budget-exhausted"
    try:
        run = make_run()
        aid = _queue_one(run)
        q = run["approvals"]
        # Three well-formed elicitations, each bounced downstream by
        # decide()'s ceremony-integrity gate (rationale contradicts
        # the decline) -- the record stays pending, each burns one
        # attempt.
        for i in range(3):
            try:
                q.elicit_decision(aid, "decline",
                                  rationale={"reason":
                                             "yes, approve this now"})
                return _broken(name, "contradictory rationale accepted")
            except ValueError as exc:
                if "ceremony" not in str(exc):
                    return _broken(name, "unexpected refusal: %s" % exc)
        rec = q.get(aid)
        if rec.get("elicitation_attempts") != 3:
            return _broken(name, "attempts=%r, want 3"
                           % (rec.get("elicitation_attempts"),))
        if rec["status"] != "pending":
            return _broken(name, "record left %s" % rec["status"])
        try:
            q.elicit_decision(aid, "decline",
                              rationale={"reason": "still no"})
            return _broken(name, "4th elicitation accepted")
        except ValueError as exc:
            if "budget exhausted" not in str(exc):
                return _broken(name, "wrong refusal: %s" % exc)
        if not _events(run, "elicitation_budget_exhausted"):
            return _broken(name, "no elicitation_budget_exhausted event")
        return _held(name, "3 burns then fail-closed refusal + event")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_failed_validation_does_not_burn():
    name = "failed-validation-does-not-burn"
    try:
        run = make_run()
        aid = _queue_one(run)
        q = run["approvals"]
        bad_calls = [
            lambda: q.elicit_decision(aid, "bogus-response"),
            lambda: q.elicit_decision(aid, "decline", rationale=None),
            lambda: q.elicit_decision(aid, "decline",
                                      rationale={"reason": 123}),
            lambda: q.elicit_decision(aid, "decline",
                                      rationale={"reason":
                                                 {"nested": True}}),
        ]
        for call in bad_calls:
            try:
                call()
                return _broken(name, "malformed elicitation accepted")
            except ValueError:
                pass
        attempts = q.get(aid).get("elicitation_attempts", 0)
        if attempts != 0:
            return _broken(name, "budget burned by invalid attempts: %r"
                           % (attempts,))
        if q.get(aid)["status"] != "pending":
            return _broken(name, "record mutated")
        return _held(name, "malformed/invalid attempts burn nothing")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_cancel_marks_cancelled_never_executes():
    name = "cancel-marks-cancelled-never-executes"
    try:
        run = make_run()
        aid = _queue_one(run)
        q = run["approvals"]
        rec, entry = q.elicit_decision(aid, "cancel")
        if rec["status"] != "cancelled":
            return _broken(name, "status=%r" % (rec["status"],))
        if entry["event"] != "elicitation_cancelled":
            return _broken(name, "event=%r" % (entry["event"],))
        if entry.get("decided_by") != "human-operator":
            return _broken(name, "decider not bound on cancel event")
        from gov.approvals import approval_digest_ok
        if not approval_digest_ok(q.get(aid)):
            return _broken(name, "cancelled record digest broken")
        # The executor's approved sweep only executes
        # status == "approved" (gov/executor.py
        # _execute_approved_locked): a cancelled record must never run.
        # Positive control: an approved sibling in the same sweep DOES
        # execute, so the assertion below is not a vacuous sweep.
        aid_ok = _queue_one(run, agent_id="agent-1b")
        q.elicit_decision(aid_ok, "accept")
        run["executor"].execute_approved()
        if not q.get(aid_ok).get("executed"):
            return _broken(name, "positive control did not execute")
        rec2 = q.get(aid)
        if rec2.get("executed"):
            return _broken(name, "CANCELLED RECORD WAS EXECUTED")
        tool_calls = [e for e in run["read_log"]()
                      if e.get("event") == "tool_call"
                      and e.get("approval_id") == aid
                      # the queue-time queued_pending event is the
                      # original call(), not an execution.
                      and e.get("decision") != "queued_pending"]
        if tool_calls:
            return _broken(name, "tool_call emitted for cancelled id")
        # And it can never be decided afterwards either.
        try:
            q.decide(aid, True, "late approve attempt")
            return _broken(name, "cancelled record decided")
        except ValueError:
            pass
        return _held(name, "cancelled; never executes; never decidable")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_accept_with_rationale_approved():
    name = "accept-with-rationale-approved"
    try:
        run = make_run()
        aid = _queue_one(run)
        q = run["approvals"]
        rationale = {"reason": "verified recipient", "category": "other"}
        rec, entry = q.elicit_decision(aid, "accept", rationale=rationale)
        if rec["status"] != "approved":
            return _broken(name, "status=%r" % (rec["status"],))
        # The rationale is chained into the audit log through
        # decide()'s existing reason logging.
        if "verified recipient" not in rec.get("decision_reason", ""):
            return _broken(name, "rationale missing from decision_reason")
        decisions = _events(run, "approval_decision")
        if not decisions or "verified recipient" not in str(
                decisions[0].get("reason", "")):
            return _broken(name, "rationale missing from audit entry")
        return _held(name, "approved; rationale in record + audit")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_invalid_response_refused():
    name = "invalid-response-refused"
    try:
        run = make_run()
        aid = _queue_one(run)
        try:
            run["approvals"].elicit_decision(aid, "ACCEPT")
            return _broken(name, "case-variant accepted")
        except ValueError:
            pass
        try:
            run["approvals"].elicit_decision(aid, "")
            return _broken(name, "empty response accepted")
        except ValueError:
            pass
        if not _events(run, "elicitation_refused"):
            return _broken(name, "no elicitation_refused event")
        if run["approvals"].get(aid)["status"] != "pending":
            return _broken(name, "record mutated")
        return _held(name, "bad response values refused + logged")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_unknown_id_refused():
    name = "unknown-id-refused"
    try:
        run = make_run()
        _queue_one(run)
        try:
            run["approvals"].elicit_decision("no-such-approval", "accept")
            return _broken(name, "unknown id accepted")
        except ValueError:
            pass
        if not _events(run, "elicitation_refused"):
            return _broken(name, "no elicitation_refused event")
        return _held(name, "unknown id refused + logged")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def probe_sod_self_elicitation_refused():
    name = "sod-self-elicitation-refused"
    try:
        run = make_run()
        aid = _queue_one(run, agent_id="agent-sod")
        try:
            run["approvals"].elicit_decision(aid, "accept",
                                            decided_by="agent-sod")
            return _broken(name, "requester elicited own approval")
        except ValueError as exc:
            if "separation of duties" not in str(exc):
                return _broken(name, "wrong refusal: %s" % exc)
        if run["approvals"].get(aid)["status"] != "pending":
            return _broken(name, "record mutated by SoD attempt")
        return _held(name, "SoD refusal; record pending")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


PROBES = (
    probe_decline_without_rationale_refused,
    probe_nested_rationale_refused,
    probe_credential_in_rationale_fail_closed,
    probe_requester_identity_from_record,
    probe_reprompt_budget_exhausted,
    probe_failed_validation_does_not_burn,
    probe_cancel_marks_cancelled_never_executes,
    probe_accept_with_rationale_approved,
    probe_invalid_response_refused,
    probe_unknown_id_refused,
    probe_sod_self_elicitation_refused,
)


# ------------------------------------------------- green checks (depth-1)

def _green():
    """Depth-1: run the adjacent unit seam and one adjacent approval
    battery with GOV_SKIP_GREEN=1 and require zero BREAK/ERROR.
    Honors GOV_SKIP_GREEN itself (records skip, never spawns)."""
    import subprocess
    import tempfile
    if SKIP_GREEN:
        return ["green checks skipped (GOV_SKIP_GREEN=1)"]
    notes = []
    tmpd = tempfile.mkdtemp(prefix="w278-approvalv2-green-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    # (a) the focused unit tests for this seam.
    proc = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_elicitation_contract"],
        env=env, capture_output=True, text=True, timeout=600,
        cwd=REPO_ROOT)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0 or "OK" not in out:
        raise AssertionError(
            "green check failed: unit tests:\n%s" % out[-3000:])
    notes.append("tests.test_elicitation_contract: OK")
    # (b) one adjacent approval battery (depth-1: it honors
    # GOV_SKIP_GREEN and runs no green checks of its own). Chosen
    # because it is fully green on the lane tree (11/11-adjacent
    # discipline): revoke_after_approve_probes.py carries
    # pre-existing base-identical BREAKs and would fail the check on
    # a pristine tree too.
    bat = os.path.join(REPO_ROOT, "evals",
                       "durable_approval_probes.py")
    proc = subprocess.run(
        [sys.executable, bat],
        env=env, capture_output=True, text=True, timeout=900,
        cwd=REPO_ROOT)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise AssertionError(
            "green check failed: durable_approval_probes.py:\n%s"
            % out[-3000:])
    notes.append("evals/durable_approval_probes.py: exit 0")
    return notes


def main():
    for probe in PROBES:
        probe()
    held = sum(1 for r in RESULTS if r["verdict"] == "HELD")
    broken = [r for r in RESULTS if r["verdict"] == "BREAK"]
    errors = [r for r in RESULTS if r["verdict"] == "ERROR"]
    print("w278 approval-v2 elicitation probes: %d/%d HELD"
          % (held, len(RESULTS)))
    for r in RESULTS:
        print("  [%s] %s %s" % (r["verdict"], r["probe"], r["detail"]))
    green_notes = _green()
    for note in green_notes:
        print("  green: %s" % note)
    if broken or errors:
        print("RED: %d BREAK, %d ERROR" % (len(broken), len(errors)))
        return 1
    print("ALL HELD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
