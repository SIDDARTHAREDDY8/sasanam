"""Wave-306 lane B battery: F390 -- composed _resolve_replay does not bind
the ref's step to the replaying unit.

The F388 fix (wave-304 lane C) binds the idempotency record's
``(result_digest, result_ref)`` pair to the run (run_id match), the
caller (record_caller == plan actor), completion, and digest -- but NOT
the ref's step to the replaying unit. An attacker who begins AND
completes as the legitimate plan actor (the F388 threat model) can plant
a record under the victim unit's idempotency key whose ``result_ref``
names a *different completed step of the same run*: every F388 check
passes and the composer returns the wrong step's outputs without
executing the unit's fn.

F390 (MEDIUM, filed 2026-10-03T10:05:00Z, wave-306 lane B): same-run
wrong-step replay resolution accepts a (digest, ref) pair naming a
different unit's completed step.

Probes (all through the public ``WorkflowComposer.execute`` API plus the
idem store's public begin/complete, the F388 plant seam):
  A1 F390-same-run-wrong-step: attacker (as the plan actor) plants a
     record under u2's key with the exact op_digest, real digest of
     u1's completed step, ref ``wfstep:R:1``. Executing u2 under run R
     must refuse coded ``workflow-composed-replay-foreign`` (BREAK =
     u1's outputs returned without u2 executing).
  A2 F390-saga-action-step-bound: same defect class through the saga
     action replay path -- plant under a saga action's key with a ref to
     a different step of the same run. BREAK = wrong outputs returned;
     HELD = coded refusal.
  C1 F390-legit-replay-survives: the idempotency contract must survive
     the fix -- the same plan re-executed under the same run replays
     the recorded outputs without re-running the fn. Must stay HELD
     (no regression).

Run:
  mkdir -p /var/tmp/g306-f390 && TMPDIR=/var/tmp/g306-f390 \\
    ~/workspace/.gov-venv/bin/python evals/w303_f390_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g306-f390b \\
    ~/workspace/.gov-venv/bin/python evals/w303_f390_probes.py
"""

import hashlib
import os
import re
import sys
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check  # noqa: E402  (wave-305 shared fail-closed green checks)
import probe_lines  # noqa: E402  (canonical probe-line form)

TAXONOMY_PIN = 1869  # Wave-303 merge pin; Wave-304 lane C: pin 1827 -> 1827 (+1 workflow-composed-replay-foreign); Wave-306 lane B: F390 reuses that code, pin unchanged

FOREIGN_CODE = "workflow-composed-replay-foreign"

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "literal count %d != pin %d" % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD",
            "%d/%d/0 sorted" % (TAXONOMY_PIN, TAXONOMY_PIN))


def p_footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    matches = re.findall(
        r"Next free finding: \*\*F(\d+)\*\*\. \*\*Open findings: ([^*]*)\.\*\*",
        text)
    if not matches:
        return _record("footer-state", "BREAK", "footer pattern not found")
    nxt, open_s = int(matches[-1][0]), matches[-1][1]
    # Wave-313 lane A footer: F397 CLOSED; no open findings.
    want_open = "none"
    if nxt != 398 or open_s != want_open:
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d open %r (want next F398 open %r)"
                       % (nxt, open_s, want_open))
    _record("footer-state", "HELD",
            "footer pins open none / next F398")


AT = 1_700_000_000


def _seed(tag):
    return hashlib.sha256(("w306f390-" + tag).encode()).digest()


def _scaffold():
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    from gov import workflow_composed as wc
    from gov import delegation as dg
    from gov import ed25519
    from gov import delegation_revocation as rv
    sa, sb = _seed("a"), _seed("b")
    pa, pb = ed25519.publickey(sa).hex(), ed25519.publickey(sb).hex()
    cons = {"expires_at": AT + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root = dg.issue(sa, "agent-a", "agent-b", pb, ("tool.invoke",),
                    issued_at=AT, constraints=dict(cons))
    ledger = rv.DelegationRevoker(sa, "agent-a")
    auth = {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": [root], "trust_roots": [pa],
            "revocation_ledger": ledger}
    ws = wf.WorkflowStore()
    sm = saga.SagaManager()
    im = idem.IdempotencyStore()
    comp = wc.WorkflowComposer(ws, sm, im)
    return wc, wf, saga, idem, comp, ws, sm, im, auth


def _fn_op_digest(wc, plan, unit_name, inputs):
    # White-box: the exact op_digest construction in
    # WorkflowComposer._execute_fn_unit.
    return wc._digest({"plan": plan.digest, "op": "unit",
                       "unit": unit_name,
                       "inputs": wc._digest(inputs)})


def _refused_foreign(e):
    return getattr(e, "code", None) == FOREIGN_CODE


def p_f390_same_run_wrong_step():
    # A1: the composed unit returns a DIFFERENT unit's completed step
    # outputs from the SAME run without executing its fn. F393
    # (wave-309) stops this two-plan shape EARLIER at the run->plan
    # gate (coded workflow-composed-plan-mismatch); the name check
    # itself is covered end-to-end by tests/test_workflow_f390.py
    # (plant-before-execution, same plan).
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    actor = "agent-b"  # the plan actor: the F388 "begins AND completes
    # as one caller" threat model, now with legitimate credentials.
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    plan1 = wc.ComposedPlan([
        {"kind": "fn", "name": "u1", "fn": lambda i: {"one": 1},
         "inputs": {}, "idem_key": "k1"}])
    comp.execute(plan1, run_id="R", authority=auth, at=AT)
    # The attacker's plant: a completed idempotency record under u2's
    # key, begun as the plan actor, with the real digest of u1's step
    # and a ref naming u1's step. Every F388 check passes (same run,
    # same caller, step completed, digest matches).
    plan2 = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": lambda i: {"two": 2},
         "inputs": {}, "idem_key": "k2"}])
    forged = _fn_op_digest(wc, plan2, "u2", {})
    plant = im.begin("composed", "composed-unit", "k2", forged,
                     caller=actor, authority_verifier=lambda **k: True,
                     at=AT)
    if plant.status != "new":
        return _record("F390-same-run-wrong-step", "ERROR",
                       "plant did not begin new: %s" % (plant.status,))
    plant.complete(wc._digest({"one": 1}), "wfstep:R:1", at=AT)
    # The composer's own execution of u2 under run R.
    executed = []
    plan2b = wc.ComposedPlan([
        {"kind": "fn", "name": "u2",
         "fn": lambda i: executed.append(1) or {"two": 2},
         "inputs": {}, "idem_key": "k2"}])
    try:
        res = comp.execute(plan2b, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-composed-plan-mismatch":
            if executed:
                return _record("F390-same-run-wrong-step", "ERROR",
                               "victim fn ran before the gate refusal")
            return _record("F390-same-run-wrong-step", "HELD",
                           "wrong-step attack refused coded "
                           "workflow-composed-plan-mismatch at the "
                           "run->plan gate (F390 attack path closed "
                           "earlier)")
        return _record("F390-same-run-wrong-step", "ERROR",
                       "unexpected refusal: %r" % (getattr(e, "code", e),))
    outputs = res["units"]["u2"]["outputs"]
    if outputs == {"one": 1} and not executed:
        return _record("F390-same-run-wrong-step", "BREAK",
                       "unit u2 returned unit u1's outputs without "
                       "executing its fn")
    _record("F390-same-run-wrong-step", "HELD",
            "wrong-step outputs not returned (outputs=%r)" % (outputs,))


def p_f390_saga_action_step_bound():
    # A2: same defect class through the saga action replay path. A
    # saga action's replay must resolve to the step its own unit
    # created, not another unit's completed step of the same run.
    # F393 (wave-309) stops this two-plan shape EARLIER at the
    # run->plan gate (coded workflow-composed-plan-mismatch).
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    actor = "agent-b"
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    # A completed saga action step to point at (outputs have the
    # {"result", "payloads"} shape the action replay path expects).
    sd = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    def act1(p):
        return ({"real": 1}, [])
    unit1 = {"kind": "saga", "name": "su1", "idem_key": "sk1",
             "definition": sd,
             "action_fns": {"s1": act1},
             "comp_fns": {"s1": lambda p: {"c": 1}}}
    plan1 = wc.ComposedPlan([unit1])
    comp.execute(plan1, run_id="R", authority=auth, at=AT)
    step1 = ws.get_step("R", 1)
    # Plant under su2's action key, as the plan actor, with the real
    # digest of su1's step and a ref naming su1's step.
    executed = []
    def act2(p):
        executed.append(1)
        return ({"fake": 2}, [])
    unit2 = {"kind": "saga", "name": "su2", "idem_key": "sk2",
             "definition": sd,
             "action_fns": {"s1": act2},
             "comp_fns": {"s1": lambda p: {"c": 1}}}
    plan2 = wc.ComposedPlan([unit2])
    op_digest = wc._digest({
        "plan": plan2.digest, "op": "saga-action",
        "unit": "su2", "step": "s1",
        "params": wc._digest({})})
    plant = im.begin("composed", "composed-saga-action", "sk2:action:s1",
                     op_digest, caller=actor,
                     authority_verifier=lambda **k: True, at=AT)
    if plant.status != "new":
        return _record("F390-saga-action-step-bound", "ERROR",
                       "plant did not begin new: %s" % (plant.status,))
    plant.complete(wc._digest(step1["outputs"]), "wfstep:R:1", at=AT)
    try:
        res = comp.execute(plan2, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-composed-plan-mismatch":
            if executed:
                return _record("F390-saga-action-step-bound", "ERROR",
                               "victim action ran before the gate refusal")
            return _record("F390-saga-action-step-bound", "HELD",
                           "saga-action wrong-step attack refused coded "
                           "workflow-composed-plan-mismatch at the "
                           "run->plan gate (F390 attack path closed "
                           "earlier)")
        return _record("F390-saga-action-step-bound", "ERROR",
                       "unexpected refusal: %r" % (getattr(e, "code", e),))
    got = res["units"]["su2"]
    # The action fn records execution. If it never ran but the saga
    # succeeded, the action replayed su1's outputs (BREAK). If the F390
    # name check refused, the saga compensates (HELD).
    if not executed and got.get("status") == "succeeded":
        return _record("F390-saga-action-step-bound", "BREAK",
                       "saga action su2 returned su1's outputs without "
                       "executing")
    if not executed:
        return _record("F390-saga-action-step-bound", "HELD",
                       "saga action did not return foreign outputs "
                       "(status=%s)" % (got.get("status"),))
    _record("F390-saga-action-step-bound", "HELD",
            "saga action executed fresh (plant not hit)")


def p_f390_legit_replay_survives():
    # C1: the idempotency contract must survive the fix -- the same
    # plan re-executed under the same run replays without re-running.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    calls = []
    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u",
         "fn": lambda i: calls.append(1) or {"real": 1},
         "inputs": {}, "idem_key": "ak"}])
    r1 = comp.execute(plan, run_id="R", authority=auth, at=AT)
    r2 = comp.execute(plan, run_id="R", authority=auth, at=AT)
    if len(calls) != 1:
        return _record("F390-legit-replay-survives", "BREAK",
                       "fn re-ran on replay (%d calls)" % len(calls))
    if r2["units"]["u"]["outputs"] != {"real": 1}:
        return _record("F390-legit-replay-survives", "BREAK",
                       "replay returned wrong outputs: %r"
                       % (r2["units"]["u"]["outputs"],))
    if not r2["units"]["u"].get("replayed"):
        return _record("F390-legit-replay-survives", "BREAK",
                       "second execute did not replay")
    _record("F390-legit-replay-survives", "HELD",
            "legitimate replay returns own outputs without re-running")


def _green_battery(path, label):
    # Depth-1 adjacent green check, wave-305: delegates to
    # evals/green_check.py (fail-closed contract). Any BREAK or ERROR in
    # the child is a regression (no expected-open BREAKs here).
    green_check.check_battery(_record, "green-%s" % label, path,
                              repo=REPO)


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F390-same-run-wrong-step", p_f390_same_run_wrong_step)
    _safe("F390-saga-action-step-bound", p_f390_saga_action_step_bound)
    _safe("F390-legit-replay-survives", p_f390_legit_replay_survives)
    # Depth-1 adjacent green checks (wave-134 lesson: never nest).
    _green_battery("evals/w302_workflow_composed_probes.py", "composed")
    _green_battery("evals/w303_f388_probes.py", "f388")
    _green_battery("evals/w303_f381_probes.py", "f381")
    b = h = e = 0
    for pid, verdict, note in _results:
        if verdict == "BREAK":
            b += 1
        elif verdict == "HELD":
            h += 1
        else:
            e += 1
    probe_lines.emit(_results)
    print("----")
    print("%d BREAK / %d HELD / %d ERROR" % (b, h, e))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, b, h, e)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    return 1 if (b or e) else 0


if __name__ == "__main__":
    sys.exit(main())
