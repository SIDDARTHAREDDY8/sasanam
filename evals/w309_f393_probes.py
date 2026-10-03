#!/usr/bin/env python3
"""Wave-309 regression battery: F393 (MEDIUM, CLOSED) -- the composed
idempotency identity now binds the unit's code AND the run binds to the
first plan's digest.

F393 (filed wave-308 lane D): ComposedPlan.digest covered kind/name/
idem_key/inputs_digest but NOT the fn callable, so a descriptor-
identical evil plan (same kind, name, idem_key, inputs; different fn)
yielded a bit-identical op_digest. The victim's _begin_unit returned
REPLAY on the attacker's record and _resolve_replay passed every check
-- the victim's fn never executed and the attacker's outputs returned
as native. Verified on the fn path and the saga action path.

Close-when (wave-309 lane A): the run binds to the FIRST PLAN DIGEST
(a different plan digest under the same run refuses coded
workflow-composed-plan-mismatch; same-plan crash-recovery re-execution
still replays), AND the op identity binds the executed code (per-unit
code_digest in ComposedPlan.digest).

Probe verdicts: HELD = the closure holds; BREAK = the F393 attack (or a
regression of the close-when properties) reproduces; ERROR = probe or
scaffold failure.
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
import green_check

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-309 pin: lane A minted workflow-composed-plan-mismatch.
TAXONOMY_PIN = 1829

PLAN_MISMATCH = "workflow-composed-plan-mismatch"

AT = 1000000

# Module-level call counter for the crash-recovery probe (see note
# there): closure values are digest-bound, so the counter must not be
# a closure.
_CRASH_CALLS = []

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
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "1829/1829/0 sorted")


def p_footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    matches = re.findall(
        r"Next free finding: \*\*F(\d+)\*\*\.\s*\*\*Open findings: ([^*]*)\.\*\*",
        text)
    if not matches:
        return _record("footer-state", "ERROR", "footer pattern not found")
    nxt, open_s = int(matches[-1][0]), matches[-1][1]
    # Wave-309 lane A footer: F393 CLOSED, no open findings, next F394.
    if nxt != 396 or open_s != "F394, F395":
        return _record("footer-state", "BREAK",
                       "footer pins next F%d open '%s', want next F396 "
                       "open 'F394, F395'" % (nxt, open_s))
    _record("footer-state", "HELD", "footer pins open F394, F395 / next F396")


# ------------------------------------------------------------------
# Shared scaffolds
# ------------------------------------------------------------------

def _seed(s):
    return hashlib.sha256(("w309-" + s).encode()).digest()


def _composed_scaffold(tag, journal_path=None):
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    from gov import workflow_composed as wc
    from gov import delegation as dg
    from gov import ed25519
    from gov import delegation_revocation as rv
    sa, sb = _seed(tag + "-a"), _seed(tag + "-b")
    pa, pb = ed25519.publickey(sa).hex(), ed25519.publickey(sb).hex()
    cons = {"expires_at": AT + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root = dg.issue(sa, "agent-a", "agent-b", pb, ("tool.invoke",),
                    issued_at=AT, constraints=dict(cons))
    ledger = rv.DelegationRevoker(sa, "agent-a")
    auth = {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": [root], "trust_roots": [pa],
            "revocation_ledger": ledger}
    ws = wf.WorkflowStore(path=journal_path)
    sm = saga.SagaManager()
    im = idem.IdempotencyStore()
    comp = wc.WorkflowComposer(ws, sm, im)
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    return wc, wf, saga, idem, comp, ws, sm, im, auth


def _fn_op_digest(wc, plan, unit_name, inputs):
    # White-box: the exact op_digest construction in
    # WorkflowComposer._execute_fn_unit.
    return wc._digest({"plan": plan.digest, "op": "unit",
                       "unit": unit_name,
                       "inputs": wc._digest(inputs)})


# ------------------------------------------------------------------
# Closure probes
# ------------------------------------------------------------------

def p_f393_fn_code_confusion_closed():
    # The filed F393 fn-path attack: descriptor-identical evil plan
    # (same kind/name/idem_key/inputs, different fn) executes under
    # run R; then the victim plan executes under R. On the open tree
    # the victim's _begin_unit found the evil plan's completed record
    # (bit-identical op_digest) and returned evil outputs without
    # running the victim fn. Must now refuse coded
    # workflow-composed-plan-mismatch at the run->plan gate; the
    # victim fn must never execute.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("c1")
    evil = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": lambda i: {"evil": 1},
         "inputs": {}, "idem_key": "k"}])
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    executed = []

    def victim_fn(i):
        executed.append(1)
        return {"real": 1}

    victim = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": victim_fn,
         "inputs": {}, "idem_key": "k"}])
    if evil.digest == victim.digest:
        return _record("F393-fn-code-confusion", "BREAK",
                       "descriptor-identical plans share a digest: the "
                       "code identity is not bound")
    try:
        res = comp.execute(victim, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == PLAN_MISMATCH:
            if executed:
                return _record("F393-fn-code-confusion", "ERROR",
                               "victim fn ran before the gate refusal")
            return _record("F393-fn-code-confusion", "HELD",
                           "fn code-confusion attack refused coded "
                           "workflow-composed-plan-mismatch; victim fn "
                           "never executed")
        return _record("F393-fn-code-confusion", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    if res["units"]["u"]["outputs"] == {"evil": 1} and not executed:
        return _record("F393-fn-code-confusion", "BREAK",
                       "F393 STILL OPEN: evil outputs returned without "
                       "the victim fn executing")
    return _record("F393-fn-code-confusion", "ERROR",
                   "unexpected: %r" % (res["units"]["u"],))


def p_f393_saga_code_confusion_closed():
    # The filed F393 saga-action-path attack: descriptor-identical evil
    # saga plan executes under run R; then the victim saga plan
    # executes under R. On the open tree the victim action never ran
    # and the saga succeeded with the attacker's outputs. Must now
    # refuse coded at the gate; the victim action must never execute.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("c2")

    def evil_action(p):
        return ({"evil": 1}, [])

    evil_saga = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    evil_plan = wc.ComposedPlan([
        {"kind": "saga", "name": "su", "definition": evil_saga,
         "action_fns": {"s1": evil_action},
         "comp_fns": {"s1": lambda p: None},
         "idem_key": "sk"}])
    comp.execute(evil_plan, run_id="R", authority=auth, at=AT)
    executed = []

    def victim_action(p):
        executed.append(1)
        return ({"real": 1}, [])

    victim_saga = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    victim_plan = wc.ComposedPlan([
        {"kind": "saga", "name": "su", "definition": victim_saga,
         "action_fns": {"s1": victim_action},
         "comp_fns": {"s1": lambda p: None},
         "idem_key": "sk"}])
    if evil_plan.digest == victim_plan.digest:
        return _record("F393-saga-code-confusion", "BREAK",
                       "descriptor-identical saga plans share a digest")
    try:
        res = comp.execute(victim_plan, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == PLAN_MISMATCH:
            if executed:
                return _record("F393-saga-code-confusion", "ERROR",
                               "victim action ran before the gate refusal")
            return _record("F393-saga-code-confusion", "HELD",
                           "saga code-confusion attack refused coded "
                           "workflow-composed-plan-mismatch; victim "
                           "action never executed")
        return _record("F393-saga-code-confusion", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    got = res["units"]["su"]
    if not executed and got.get("status") == "succeeded":
        return _record("F393-saga-code-confusion", "BREAK",
                       "F393 STILL OPEN: saga succeeded without the "
                       "victim action executing")
    return _record("F393-saga-code-confusion", "ERROR",
                   "unexpected: %r" % (got,))


def p_f393_crash_recovery_replays():
    # Close-when property: same-plan crash-recovery re-execution still
    # replays (the digest is identical, so the binding matches). The
    # fn must run exactly once across the crash.
    #
    # NOTE: the call counter is a module global, not a closure value:
    # closure VALUES are bound into the digest (F393), so a probe-local
    # list mutated by the first execution would legitimately change the
    # rebuilt plan's digest. A real crash rebuilds from source with
    # fresh state.
    import tempfile
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("c3")
    # Use a real journal file so the "crash" reloads from disk.
    journal = tempfile.NamedTemporaryFile(
        prefix="w309-crash-", suffix=".jsonl", delete=False).name
    ws_j = wf.WorkflowStore(path=journal)
    ws_j.start_run("probe", run_id="R", authority=auth, at=AT)
    comp_j = wc.WorkflowComposer(ws_j, saga.SagaManager(), im)
    _CRASH_CALLS.clear()

    def fn(i):
        _CRASH_CALLS.append(1)
        return {"n": len(_CRASH_CALLS)}

    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": fn,
         "inputs": {}, "idem_key": "k"}])
    r1 = comp_j.execute(plan, run_id="R", authority=auth, at=AT)
    # "Crash": rebuild the workflow store from the journal file (the
    # run->plan binding is journal-appended, so it survives); share
    # the idempotency backing dict (the durable idempotency store).
    ws2 = wf.WorkflowStore(path=journal)
    im2 = idem.IdempotencyStore(backing=im._backing)
    comp2 = wc.WorkflowComposer(ws2, saga.SagaManager(), im2)

    def fn_rebuilt(i):
        _CRASH_CALLS.append(1)
        return {"n": len(_CRASH_CALLS)}

    plan_rebuilt = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": fn_rebuilt,
         "inputs": {}, "idem_key": "k"}])
    if plan.digest != plan_rebuilt.digest:
        return _record("F393-crash-recovery-replays", "ERROR",
                       "identical-source rebuild changed the digest")
    r2 = comp2.execute(plan_rebuilt, run_id="R", authority=auth, at=AT)
    if len(_CRASH_CALLS) != 1:
        return _record("F393-crash-recovery-replays", "BREAK",
                       "fn executed %d times across the crash (want 1)"
                       % len(_CRASH_CALLS))
    if r2["units"]["u"]["outputs"] != r1["units"]["u"]["outputs"]:
        return _record("F393-crash-recovery-replays", "BREAK",
                       "replay returned different outputs: %r vs %r"
                       % (r2["units"]["u"]["outputs"],
                          r1["units"]["u"]["outputs"]))
    _record("F393-crash-recovery-replays", "HELD",
            "same-plan crash-recovery replays: 1 fn call, outputs match")


def p_f393_closure_value_confusion():
    # Same bytecode, different closed-over value -> different digest.
    # (Exotic non-JSON closure values bind by type name only -- a
    # documented residual, not probed as a break here.)
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("c4")

    def make(threshold):
        def fn(i):
            return {"over": i.get("x", 0) > threshold}
        return fn

    pa = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": make(5),
         "inputs": {}, "idem_key": "k"}])
    pb = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": make(10),
         "inputs": {}, "idem_key": "k"}])
    if pa.digest == pb.digest:
        return _record("F393-closure-value-confusion", "BREAK",
                       "same bytecode with different closure values "
                       "shares a digest")
    _record("F393-closure-value-confusion", "HELD",
            "closure values are bound by value: digests differ")


def p_f393_uninspectable_fn_refused():
    # Callables without __code__ (builtins, functools.partial) cannot
    # be fingerprinted -- plan construction must fail closed.
    import functools
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("c5")
    for label, bad_fn in (("builtin", len),
                          ("partial", functools.partial(lambda i, x: x, x=1))):
        try:
            wc.ComposedPlan([
                {"kind": "fn", "name": "u", "fn": bad_fn,
                 "inputs": {}, "idem_key": "k"}])
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", None) != "workflow-composed-definition-invalid":
                return _record("F393-uninspectable-fn-refused", "ERROR",
                               "%s: wrong refusal %r" % (label, getattr(e, "code", e)))
        else:
            return _record("F393-uninspectable-fn-refused", "BREAK",
                           "%s: uninspectable fn accepted into a plan" % label)
    _record("F393-uninspectable-fn-refused", "HELD",
            "builtin and functools.partial refuse coded at plan "
            "construction (fail closed)")


def p_f393_binding_survives_reload():
    # The run->plan binding is journal-appended: it survives a store
    # reload, so a different plan under the same run is still refused
    # after recovery.
    import tempfile
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("c6")
    journal = tempfile.NamedTemporaryFile(
        prefix="w309-reload-", suffix=".jsonl", delete=False).name
    ws_j = wf.WorkflowStore(path=journal)
    ws_j.start_run("probe", run_id="R", authority=auth, at=AT)
    comp_j = wc.WorkflowComposer(ws_j, saga.SagaManager(), im)
    plan_a = wc.ComposedPlan([
        {"kind": "fn", "name": "ua", "fn": lambda i: {"a": 1},
         "inputs": {}, "idem_key": "ka"}])
    comp_j.execute(plan_a, run_id="R", authority=auth, at=AT)
    # Reload the store from the journal file.
    ws2 = wf.WorkflowStore(path=journal)
    bound = ws2.bind_plan_digest("R", plan_a.digest, authority=auth, at=AT)
    if bound != plan_a.digest:
        return _record("F393-binding-survives-reload", "BREAK",
                       "binding lost across journal reload")
    plan_b = wc.ComposedPlan([
        {"kind": "fn", "name": "ub", "fn": lambda i: {"b": 2},
         "inputs": {}, "idem_key": "kb"}])
    im2 = idem.IdempotencyStore(backing=im._backing)
    comp2 = wc.WorkflowComposer(ws2, saga.SagaManager(), im2)
    try:
        comp2.execute(plan_b, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == PLAN_MISMATCH:
            return _record("F393-binding-survives-reload", "HELD",
                           "binding survived reload: different plan "
                           "refused coded")
        return _record("F393-binding-survives-reload", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    return _record("F393-binding-survives-reload", "BREAK",
                   "different plan executed under a bound run after reload")


def p_f393_first_execute_binds():
    # A fresh run binds on first execute; the same plan re-executes
    # (replay) without refusal.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("c7")
    calls = []

    def fn(i):
        calls.append(1)
        return {"v": 1}

    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": fn,
         "inputs": {}, "idem_key": "k"}])
    comp.execute(plan, run_id="R", authority=auth, at=AT)
    if ws.bind_plan_digest("R", plan.digest, authority=auth,
                           at=AT) != plan.digest:
        return _record("F393-first-execute-binds", "ERROR",
                       "first execute did not bind the plan digest")
    r2 = comp.execute(plan, run_id="R", authority=auth, at=AT)
    if len(calls) != 1 or r2["units"]["u"]["outputs"] != {"v": 1}:
        return _record("F393-first-execute-binds", "BREAK",
                       "same-plan re-execution did not replay cleanly")
    _record("F393-first-execute-binds", "HELD",
            "first execute binds; same-plan re-execution replays")


def p_f393_refused_execute_keeps_binding():
    # A refused execute must not clobber the binding: the original
    # plan still replays afterwards.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("c8")
    calls = []

    def fn(i):
        calls.append(1)
        return {"v": 1}

    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": fn,
         "inputs": {}, "idem_key": "k"}])
    comp.execute(plan, run_id="R", authority=auth, at=AT)
    evil = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": lambda i: {"evil": 1},
         "inputs": {}, "idem_key": "k"}])
    try:
        comp.execute(evil, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != PLAN_MISMATCH:
            return _record("F393-refused-execute-keeps-binding", "ERROR",
                           "wrong refusal: %r" % (getattr(e, "code", e),))
    else:
        return _record("F393-refused-execute-keeps-binding", "BREAK",
                       "evil plan was not refused")
    r2 = comp.execute(plan, run_id="R", authority=auth, at=AT)
    if len(calls) != 1 or r2["units"]["u"]["outputs"] != {"v": 1}:
        return _record("F393-refused-execute-keeps-binding", "BREAK",
                       "refused execute clobbered the binding")
    _record("F393-refused-execute-keeps-binding", "HELD",
            "refused execute kept the binding; original plan replays")


# ------------------------------------------------------------------
# Green checks (depth-1; honor GOV_SKIP_GREEN)
# ------------------------------------------------------------------

def _green_battery(path, label):
    # Depth-1 adjacent green check, wave-305: delegates to
    # evals/green_check.py (fail-closed contract).
    green_check.check_battery(_record, "green-%s" % label, path,
                              repo=REPO)


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F393-fn-code-confusion", p_f393_fn_code_confusion_closed)
    _safe("F393-saga-code-confusion", p_f393_saga_code_confusion_closed)
    _safe("F393-crash-recovery-replays", p_f393_crash_recovery_replays)
    _safe("F393-closure-value-confusion", p_f393_closure_value_confusion)
    _safe("F393-uninspectable-fn-refused", p_f393_uninspectable_fn_refused)
    _safe("F393-binding-survives-reload", p_f393_binding_survives_reload)
    _safe("F393-first-execute-binds", p_f393_first_execute_binds)
    _safe("F393-refused-execute-keeps-binding",
           p_f393_refused_execute_keeps_binding)
    if not SKIP_GREEN:
        # Depth-1 adjacent green checks (wave-134 lesson: never nest).
        _green_battery("evals/w308_redteam_probes.py", "w308-redteam")
        _green_battery("evals/w303_f390_probes.py", "f390")
        _green_battery("evals/w303_f388_probes.py", "f388")
    else:
        _record("green-skip", "HELD", "GOV_SKIP_GREEN=1; child batteries not spawned")
    brk = sum(1 for _, v, _ in _results if v == "BREAK")
    held = sum(1 for _, v, _ in _results if v == "HELD")
    err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("----")
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    for pid, v, note in _results:
        print("[%s] %s: %s" % (v, pid, note.split("\n")[0][:100]))


if __name__ == "__main__":
    main()
