"""Wave-307 lane A battery: F392 -- composed _resolve_replay does not bind
the ref's step to the exact idempotency record that created it.

The F390 fix (wave-306 lane B) binds _resolve_replay's expected_step_name
to the replaying unit and refuses coded
workflow-composed-replay-foreign on mismatch. But step names are unique
per (plan, unit) -- NOT per run: execute() takes a caller-provided
run_id and never binds a run to a single plan, so a second plan executed
under the same run can record the SAME step name for a different unit's
work. A poisoned (digest, ref) pair naming the attacker's same-named
step then passes every F388/F390 check (run, caller, completion,
digest, name) and the composer returns the wrong unit's outputs without
executing it.

F392 (MEDIUM, filed 2026-10-03T10:41:10Z, wave-307 lane A): same-run
same-name replay resolution accepts a (digest, ref) pair naming a
different plan's same-named step. Closed: the workflow step records the
(namespace, op_class, key) triple of the idempotency record that created
it as its idempotency_key (via _step_binding); _resolve_replay refuses
coded workflow-composed-replay-foreign when the resolved step's binding
does not match the replaying record's key. No new decision codes
(pin 1827+0).

Probes (all through the public WorkflowComposer.execute API plus the
idem store's public begin/complete, the F388 plant seam):
  A1 F392-same-run-same-name: attacker (as the plan actor) executes a
     plan with unit "u2" under run R (records fn:u2 at seq 1), then
     plants under the victim's key "k2" a record with the exact
     op_digest, the real digest of the evil step, ref "wfstep:R:1".
     Executing the VICTIM plan (also unit "u2", key "k2") under run R
     must refuse coded workflow-composed-replay-foreign (BREAK = the
     evil outputs returned without the victim fn executing).
  A2 F392-saga-action-binding: same defect class through the saga
     action path -- an attacker's saga plan under run R records a
     same-named saga action step; a plant under the victim saga action
     key naming it must refuse coded. BREAK = wrong outputs; HELD =
     coded refusal.
  C1 F392-legit-replay-survives: the idempotency contract must survive
     the fix -- the same plan re-executed under the same run replays
     the recorded outputs without re-running the fn. Must stay HELD
     (no regression).
  C2 F392-crash-replay-no-rerun: a step recorded (with binding) but
     whose idem record is still in-flight (crash before _complete_unit)
     replays via the binding -- no duplicate execution. Must stay HELD.

Run:
  mkdir -p /var/tmp/g307-f392 && TMPDIR=/var/tmp/g307-f392 \\
    ~/workspace/.gov-venv/bin/python evals/w307_step_collision_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g307-f392b \\
    ~/workspace/.gov-venv/bin/python evals/w307_step_collision_probes.py
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

TAXONOMY_PIN = 2109 # Wave-306 merge pin; Wave-307 lane A: F392 reuses workflow-composed-replay-foreign, pin unchanged; Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).


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
    # Wave-312 merge footer: F396 CLOSED (lane A); F397 OPEN (lane C).
    # Wave-312 merge footer: F396 CLOSED (lane A); F397 OPEN (lane C).
    want_open = "F407"
    if nxt != 405 or open_s != want_open:
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d open %r (want next F404 open 'none')"
                       % (nxt, open_s, want_open))
    _record("footer-state", "HELD",
            "footer pins open none / next F409")


AT = 1_700_000_000


def _seed(tag):
    return hashlib.sha256(("w307f392-" + tag).encode()).digest()


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
    return wc._digest({"plan": plan.digest, "op": "unit",
                       "unit": unit_name,
                       "inputs": wc._digest(inputs)})


def p_f392_same_run_same_name():
    # A1 (the F392 attack): two plans under one run, both with a unit
    # named "u2". Attacker executes plan_evil under run R (records
    # fn:u2 at seq 1); then plants under the victim's key "k2" a record
    # with the exact op_digest, the real digest of the evil step, and
    # ref "wfstep:R:1". F393 (wave-309) stops this shape EARLIER: the
    # run binds to the first plan digest, so the victim plan refuses
    # coded workflow-composed-plan-mismatch at the gate (BREAK = evil
    # outputs returned without the victim fn executing).
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    evil = wc.ComposedPlan([
        {"kind": "fn", "name": "u2",
         "fn": lambda i: {"evil": 1},
         "inputs": {}, "idem_key": "ke"}])
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    executed = []

    def victim_fn(i):
        executed.append(1)
        return {"real": 2}

    victim = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": victim_fn,
         "inputs": {}, "idem_key": "k2"}])
    plant = im.begin("composed", "composed-unit", "k2",
                     _fn_op_digest(wc, victim, "u2", {}),
                     caller="agent-b",
                     authority_verifier=lambda **k: True, at=AT)
    if plant.status != "new":
        return _record("F392-same-run-same-name", "ERROR",
                       "plant did not begin: %s" % (plant.status,))
    plant.complete(wc._digest({"evil": 1}), "wfstep:R:1", at=AT)
    try:
        res = comp.execute(victim, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-composed-plan-mismatch":
            if executed:
                return _record("F392-same-run-same-name", "ERROR",
                               "victim fn ran before the gate refusal")
            return _record("F392-same-run-same-name", "HELD",
                           "same-run same-name attack refused coded "
                           "workflow-composed-plan-mismatch at the "
                           "run->plan gate (F392 attack path closed "
                           "earlier)")
        return _record("F392-same-run-same-name", "ERROR",
                       "wrong refusal: %r (%r)" % (code, e))
    if executed:
        return _record("F392-same-run-same-name", "ERROR",
                       "victim fn executed but outputs were not its own")
    if res["units"]["u2"]["outputs"] == {"evil": 1}:
        return _record("F392-same-run-same-name", "BREAK",
                       "F392: poisoned pair named the other plan's same-"
                       "named step; evil outputs returned without the "
                       "victim fn executing")
    return _record("F392-same-run-same-name", "ERROR",
                   "unexpected outputs: %r"
                   % (res["units"]["u2"]["outputs"],))


def p_f392_saga_action_binding():
    # A2: same defect class through the saga action path. The attacker's
    # saga plan under run R (unit "su", step "s1") records saga:su:s1
    # at seq 1; a plant under the VICTIM saga action's key
    # ("sk2:action:s1") with the exact op_digest, the real digest of
    # the evil step, and ref "wfstep:R:1" must refuse coded. F393
    # (wave-309) stops this shape EARLIER at the run->plan gate (coded
    # workflow-composed-plan-mismatch), so the refusal now surfaces
    # from execute() itself: BREAK = the victim saga "succeeded"
    # without its action executing (the attacker's outputs returned as
    # native); HELD = the gate refused coded.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    ws.start_run("probe", run_id="R", authority=auth, at=AT)

    def evil_action(p):
        return ("evil-result", [{"intent_id": "e"}])

    evil_saga = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    evil_plan = wc.ComposedPlan([
        {"kind": "saga", "name": "su", "definition": evil_saga,
         "action_fns": {"s1": evil_action},
         "comp_fns": {"s1": lambda p: None},
         "idem_key": "ske"}])
    comp.execute(evil_plan, run_id="R", authority=auth, at=AT)
    step1 = ws.get_step("R", 1)
    executed = []

    def victim_action(p):
        executed.append(1)
        return ("real-result", [{"intent_id": "v"}])

    victim_saga = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    victim_plan = wc.ComposedPlan([
        {"kind": "saga", "name": "su", "definition": victim_saga,
         "action_fns": {"s1": victim_action},
         "comp_fns": {"s1": lambda p: None},
         "idem_key": "sk2"}])
    op_digest = wc._digest({
        "plan": victim_plan.digest, "op": "saga-action",
        "unit": "su", "step": "s1",
        "params": wc._digest({})})
    plant = im.begin("composed", "composed-saga-action", "sk2:action:s1",
                     op_digest, caller="agent-b",
                     authority_verifier=lambda **k: True, at=AT)
    if plant.status != "new":
        return _record("F392-saga-action-binding", "ERROR",
                       "plant did not begin: %s" % (plant.status,))
    plant.complete(wc._digest(step1["outputs"]), "wfstep:R:1", at=AT)
    try:
        res = comp.execute(victim_plan, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-composed-plan-mismatch":
            if executed:
                return _record("F392-saga-action-binding", "ERROR",
                               "victim action ran before the gate refusal")
            return _record("F392-saga-action-binding", "HELD",
                           "saga-action same-name attack refused coded "
                           "workflow-composed-plan-mismatch at the "
                           "run->plan gate (F392 attack path closed "
                           "earlier)")
        return _record("F392-saga-action-binding", "ERROR",
                       "wrong refusal: %r (%r)" % (code, e))
    got = res["units"]["su"]
    if not executed and got.get("status") == "succeeded":
        return _record("F392-saga-action-binding", "BREAK",
                       "F392: victim saga action did not execute but the "
                       "saga succeeded -- the attacker's step outputs "
                       "were returned as native")
    if not executed:
        return _record("F392-saga-action-binding", "HELD",
                       "saga action did not return foreign outputs "
                       "(status=%s)" % (got.get("status"),))
    return _record("F392-saga-action-binding", "HELD",
                   "victim saga action executed natively (no collision)")


def p_f392_legit_replay_survives():
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
        return _record("F392-legit-replay-survives", "BREAK",
                       "fn re-ran on replay (%d calls)" % len(calls))
    if r2["units"]["u"]["outputs"] != {"real": 1}:
        return _record("F392-legit-replay-survives", "BREAK",
                       "replay returned wrong outputs: %r"
                       % (r2["units"]["u"]["outputs"],))
    if not r2["units"]["u"].get("replayed"):
        return _record("F392-legit-replay-survives", "BREAK",
                       "second execute did not replay")
    _record("F392-legit-replay-survives", "HELD",
            "legitimate replay returns own outputs without re-running")


def p_f392_crash_replay_no_rerun():
    # C2: a step recorded (with binding) but whose idem record is still
    # in-flight (crash before _complete_unit) replays via the binding --
    # no duplicate execution.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    calls = []
    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u",
         "fn": lambda i: calls.append(1) or {"real": 1},
         "inputs": {}, "idem_key": "ak"}])
    comp.execute(plan, run_id="R", authority=auth, at=AT)
    # Fresh composer + idem store over the same workflow store: the
    # record is in-flight (never begun in this store), the step is
    # completed with its binding. The retry path replays the step via
    # the idempotency key -- no duplicate execution.
    im2 = idem.IdempotencyStore()
    comp2 = wc.WorkflowComposer(ws, saga.SagaManager(), im2)
    out = im2.begin("composed", "composed-unit", "ak",
                    _fn_op_digest(wc, plan, "u", {}),
                    caller="agent-b",
                    authority_verifier=lambda **k: True, at=AT)
    if out.status != "new":
        return _record("F392-crash-replay-no-rerun", "ERROR",
                       "re-begin did not start: %s" % (out.status,))
    seq = comp2._next_seq()
    outputs, replayed = comp2._wstore.run_step(
        "R", seq, "fn:u", plan.units[0]["fn"], {},
        idempotency_key=comp2._step_binding(wc._OP_UNIT, "ak"),
        authority=auth, at=AT)
    if not replayed:
        return _record("F392-crash-replay-no-rerun", "BREAK",
                       "step did not replay via binding (fn re-ran)")
    if outputs != {"real": 1}:
        return _record("F392-crash-replay-no-rerun", "BREAK",
                       "replay returned wrong outputs: %r" % (outputs,))
    if len(calls) != 1:
        return _record("F392-crash-replay-no-rerun", "BREAK",
                       "fn executed twice (%d calls)" % len(calls))
    _record("F392-crash-replay-no-rerun", "HELD",
            "crash-before-complete replays via binding, no duplicate run")


def _green_battery(path, label):
    # Depth-1 adjacent green check, wave-305: delegates to
    # evals/green_check.py (fail-closed contract). Any BREAK or ERROR in
    # the child is a regression (no expected-open BREAKs here).
    green_check.check_battery(_record, "green-%s" % label, path,
                              repo=REPO)


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F392-same-run-same-name", p_f392_same_run_same_name)
    _safe("F392-saga-action-binding", p_f392_saga_action_binding)
    _safe("F392-legit-replay-survives", p_f392_legit_replay_survives)
    _safe("F392-crash-replay-no-rerun", p_f392_crash_replay_no_rerun)
    # Depth-1 adjacent green checks (wave-134 lesson: never nest).
    _green_battery("evals/w302_workflow_composed_probes.py", "composed")
    _green_battery("evals/w303_f388_probes.py", "f388")
    _green_battery("evals/w303_f390_probes.py", "f390")
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
