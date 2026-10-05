"""Wave-306 lane E battery: independent red team vs the wave-305 tree.

Base: wave-305 merge d9554021 (F387 closed; op-registry hygiene;
fail-closed green-check contract; F389 filed OPEN; pin 1827; footer
open F389 / next F390).

Targets (all verified empirically with throwaway scripts BEFORE this
battery was written -- diagnosing-bugs loop):
 1. The F387 closure at its bypass boundaries (completed-path drift
    refusal: type confusion sleep/recv, authority-vs-drift ordering,
    digest domain separation).
 2. gov/workflow_branch.py suspend_lease re-park clobbering (F389,
    still OPEN on base -- expected-open control).
 3. The F390 same-run-wrong-step resolver variant (independently
    confirmed; filed by wave-306 lane B at 10:05:00Z -- annotated,
    not re-filed).
 4. Op-registry cleanup (stale scoped ops post-finally; stability).
 5. Outbox discard contract (poisoned dispatcher returns).
 6. Green-check contract (deliberately-broken child must ERROR).
 7. F385/F386/F388 closure regressions.
 8. Pending sleep/recv drift (lane C territory -- observation only).

New findings filed by this lane: NONE. F390 was independently
confirmed but filed first by wave-306 lane B (claim 2026-10-03T10:05:00Z);
per the wave-272 earliest-filed rule, lane B keeps F390. This battery
records the independent confirmation as F390-CONFIRMED (BREAK).

Run:
  mkdir -p /var/tmp/g306-rt && TMPDIR=/var/tmp/g306-rt \\
    ~/workspace/.gov-venv/bin/python evals/w306_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g306-rt2 \\
    ~/workspace/.gov-venv/bin/python evals/w306_redteam_probes.py
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
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

# Wave-305 merge pin 1827; this lane mints no codes (red team only), so
# the pin stays 1827. The merge-time sweep repoints to the wave-306 pin.
TAXONOMY_PIN = 2134  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)


AT = 1000000

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


def _seed(s):
    return hashlib.sha256(("seed-" + s).encode()).digest()[:32]


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
    _record("pin-taxonomy", "HELD", "2134/2134/0 sorted")




def p_footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    matches = re.findall(
        r"Next free finding: \*\*F(\d+)\*\*\.\s*\*\*Open findings: ([^*]*)\.\*\*",
        text)
    if not matches:
        return _record("footer-state", "BREAK", "footer not parseable")
    nxt, open_s = int(matches[-1][0]), matches[-1][1].strip()
    # Wave-312 merge footer: F396 CLOSED (lane A); F397 OPEN (lane C).
    # Wave-342 lane 6: repointed to open F429 / next F430 (footer-state probe audit).
    if nxt != 436 or open_s != "F433, F434, F435":
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d open %r (want next F404 open "
                       "'F396')" % (nxt, open_s))
    _record("footer-state", "HELD",
            "footer pins open F433, F434, F435 / next F436")


def _chain_fx():
    from gov import delegation as dg
    from gov import ed25519
    sa, sb = _seed("a"), _seed("b")
    pa, pb = ed25519.publickey(sa).hex(), ed25519.publickey(sb).hex()
    cons = {"expires_at": AT + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root = dg.issue(sa, "agent-b", "agent-b", pb, ("tool.invoke",),
                    issued_at=AT, constraints=dict(cons))
    return sa, sb, pa, pb, [root], [pa], root


def _authority(chain, trust_roots, ledger=None):
    # F380 closure: the workflow store requires a revocation ledger on
    # every authority verification (fail closed when absent). Mint a
    # fresh (empty) revoker when none is passed.
    if ledger is None:
        from gov import delegation_revocation as rv
        ledger = rv.DelegationRevoker(_seed("a"), "agent-a")
    return {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": chain, "trust_roots": trust_roots,
            "revocation_ledger": ledger}


def _scaffold():
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    from gov import workflow_composed as wc
    sa, sb, pa, pb, chain, trust_roots, _root = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    sm = saga.SagaManager()
    im = idem.IdempotencyStore()
    comp = wc.WorkflowComposer(ws, sm, im)
    return wc, wf, saga, idem, comp, ws, sm, im, auth


def _fn_op_digest(wc, plan, unit_name, inputs):
    return wc._digest({"plan": plan.digest, "op": "unit",
                       "unit": unit_name,
                       "inputs": wc._digest(inputs)})


# ------------------------------------------------------------------
# F389 expected-open control
# ------------------------------------------------------------------

def _branch_fx():
    from gov import workflow_branch as wb
    from gov import coordination_lease as cl
    from gov import ed25519
    lm = cl.LeaseManager()
    lease = lm.acquire("scope-x", 100, "holder-1",
                       authority_seed=ed25519.generate_seed(),
                       issued_at=1000)
    c = wb.BranchCoordinator()
    xid = c.begin(ed25519.generate_seed(), lease_manager=lm)
    return lm, lease["fencing_token"], c, xid, ed25519


def p_f389_suspend_lease_clobber():
    # F389 (LOW, CLOSED at the wave-306 merge): suspend_lease now proves
    # lease-holdership at suspend time via check_write before parking. An
    # unauthenticated re-park with a bogus fencing token must refuse coded
    # coord-lease-fencing; the legitimate holder's park stays intact and
    # their resume still works.
    lm, tok, c, xid, ed25519 = _branch_fx()
    # Legitimate holder suspends.
    rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                          suspended_at=1050)
    # Attacker re-parks with a bogus fencing token. On the closed tree
    # this raises instead of parking.
    try:
        rec2 = c.suspend_lease(xid, lm, "scope-x", 999999, "mallory",
                               suspended_at=1060)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "coord-lease-fencing":
            return _record("F389-suspend-lease-clobber", "HELD",
                           "unauthenticated re-park refused coded "
                           "coord-lease-fencing (F389 closed)")
        return _record("F389-suspend-lease-clobber", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    if rec2["fencing_token"] != 999999 or rec2["holder_id"] != "mallory":
        return _record("F389-suspend-lease-clobber", "ERROR",
                       "re-park did not take: %r" % (rec2,))
    # The legitimate holder's resume now refuses (clobbering sticks).
    try:
        c.resume_lease(rec, lm, 1070)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-branch-xid-mismatch":
            return _record("F389-suspend-lease-clobber", "BREAK",
                           "unauthenticated re-park clobbered the parked "
                           "suspension; legitimate resume now refuses "
                           "workflow-branch-xid-mismatch (F389)")
        return _record("F389-suspend-lease-clobber", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    _record("F389-suspend-lease-clobber", "HELD",
            "re-park refused or did not clobber (F389 closed?)")


# ------------------------------------------------------------------
# F387 closure verification (HELD expected)
# ------------------------------------------------------------------

def p_f387_recv_event_drift():
    # F387 (LOW, CLOSED): recv_step's completed path refuses event
    # drift coded workflow-step-unauthorized.
    from gov import workflow as wf
    sa, sb, pa, pb, chain, trust_roots, root = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    ws.start_run("wf", run_id="r1", authority=auth, at=AT)
    ws.notify("r1", "settled", {"amount": 100}, authority=auth, at=AT)
    p1, rep1 = ws.recv_step("r1", 1, "wait", "settled",
                            authority=auth, at=AT)
    if p1 != {"amount": 100} or rep1:
        return _record("F387-recv-event-drift", "ERROR",
                       "setup failed: %r %r" % (p1, rep1))
    try:
        ws.recv_step("r1", 1, "wait", "refunded",
                     authority=auth, at=AT + 5)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-step-unauthorized":
            return _record("F387-recv-event-drift", "HELD",
                           "completed path refused event drift coded "
                           "(F387 closed)")
        return _record("F387-recv-event-drift", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    _record("F387-recv-event-drift", "BREAK",
            "completed recv replayed for a different event (F387 open)")


def p_f387_sleep_wakeat_drift():
    # F387 (LOW, CLOSED): sleep_step's completed path refuses wake_at
    # drift coded workflow-step-unauthorized.
    from gov import workflow as wf
    sa, sb, pa, pb, chain, trust_roots, root = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    ws.start_run("wf", run_id="r1", authority=auth, at=AT)
    a1, rep1 = ws.sleep_step("r1", 1, "nap", AT + 100,
                             authority=auth, at=AT, now=AT + 100)
    if not a1 or rep1:
        return _record("F387-sleep-wakeat-drift", "ERROR",
                       "setup failed: %r %r" % (a1, rep1))
    try:
        ws.sleep_step("r1", 1, "nap", AT + 200,
                      authority=auth, at=AT + 5, now=AT + 200)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-step-unauthorized":
            return _record("F387-sleep-wakeat-drift", "HELD",
                           "completed path refused wake_at drift coded "
                           "(F387 closed)")
        return _record("F387-sleep-wakeat-drift", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    _record("F387-sleep-wakeat-drift", "BREAK",
            "completed sleep replayed for a different wake_at (F387 open)")


# ------------------------------------------------------------------
# F387 bypass attempts
# ------------------------------------------------------------------

def p_f387b_sleep_recv_type_confusion():
    # Try to confuse the step TYPE: complete a sleep at seq 1, then
    # re-present as recv_step at seq 1 with the same name. The digest
    # domains ({"wake_at": ...} vs {"event": ...}) must refuse.
    from gov import workflow as wf
    sa, sb, pa, pb, chain, trust_roots, root = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    ws.start_run("wf", run_id="r1", authority=auth, at=AT)
    ws.sleep_step("r1", 1, "s", AT + 100, authority=auth, at=AT,
                  now=AT + 100)
    ws.notify("r1", "e", {"x": 1}, authority=auth, at=AT)
    try:
        ws.recv_step("r1", 1, "s", "e", authority=auth, at=AT + 5)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-step-unauthorized":
            return _record("F387b-sleep-recv-type-confusion", "HELD",
                           "sleep/recv type confusion refused coded "
                           "(digest domains separated)")
        return _record("F387b-sleep-recv-type-confusion", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    _record("F387b-sleep-recv-type-confusion", "BREAK",
            "sleep completed slot replayed as recv (type confusion)")


def p_f387b_authority_first_ordering():
    # Drift + revoked ledger: authority (F380) must refuse FIRST with
    # workflow-authority-revoked, not the drift code.
    from gov import workflow as wf
    sa, sb, pa, pb, chain, trust_roots, root = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    ws.start_run("wf", run_id="r1", authority=auth, at=AT)
    ws.sleep_step("r1", 1, "nap", AT + 100, authority=auth, at=AT,
                  now=AT + 100)
    # Revoke the chain, then re-present with drift.
    ledger = auth["revocation_ledger"]
    ledger.revoke(root["receipt_id"], AT + 5)
    try:
        ws.sleep_step("r1", 1, "nap", AT + 200, authority=auth,
                      at=AT + 6, now=AT + 200)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-authority-revoked":
            return _record("F387b-authority-first-ordering", "HELD",
                           "authority re-proof refused first (F380 "
                           "ordering preserved)")
        return _record("F387b-authority-first-ordering", "ERROR",
                       "wrong refusal: %r (want "
                       "workflow-authority-revoked)" % (code,))
    _record("F387b-authority-first-ordering", "BREAK",
            "drifted replay with revoked ledger was not refused")


# ------------------------------------------------------------------
# F390 independent confirmation (filed by lane B -- annotated)
# ------------------------------------------------------------------

def p_f390_same_run_wrong_step():
    # F390 (filed by wave-306 lane B at 10:05:00Z; this probe is an
    # independent confirmation, NOT a re-filing): a poisoned
    # (digest, ref) pair naming a different completed step of the SAME
    # run, begun as the plan actor, passes the F388 checks and the
    # composer returns the wrong step's outputs without executing.
    # F393 (wave-309) stops this two-plan shape EARLIER at the
    # run->plan gate (coded workflow-composed-plan-mismatch).
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    plan1 = wc.ComposedPlan([
        {"kind": "fn", "name": "u1", "fn": lambda i: {"one": 1},
         "inputs": {}, "idem_key": "k1"}])
    comp.execute(plan1, run_id="R", authority=auth, at=AT)
    plan2 = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": lambda i: {"two": 2},
         "inputs": {}, "idem_key": "k2"}])
    forged = _fn_op_digest(wc, plan2, "u2", {})
    step_digest = wc._digest({"one": 1})
    # Plant as the plan actor (agent-b) with a caller-supplied verifier
    # (the idem store trusts the provided verifier).
    plant = im.begin("composed", "composed-unit", "k2", forged,
                     caller="agent-b", authority_verifier=lambda **k: True,
                     at=AT)
    if plant.status != "new":
        return _record("F390-CONFIRMED-same-run-wrong-step", "ERROR",
                       "plant did not begin new: %s" % (plant.status,))
    plant.complete(step_digest, "wfstep:R:1", at=AT)
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
                return _record("F390-CONFIRMED-same-run-wrong-step",
                               "ERROR",
                               "victim fn ran before the gate refusal")
            return _record("F390-CONFIRMED-same-run-wrong-step", "HELD",
                           "same-run wrong-step attack refused coded "
                           "workflow-composed-plan-mismatch at the "
                           "run->plan gate (F390 attack path closed "
                           "earlier)")
        return _record("F390-CONFIRMED-same-run-wrong-step", "ERROR",
                       "unexpected refusal: %r" % (getattr(e, "code", e),))
    outputs = res["units"]["u2"]["outputs"]
    if outputs == {"one": 1} and not executed:
        return _record("F390-CONFIRMED-same-run-wrong-step", "BREAK",
                       "CONFIRMS lane B's F390: u2 returned u1's outputs "
                       "without executing (same run, same caller, "
                       "different step)")
    _record("F390-CONFIRMED-same-run-wrong-step", "HELD",
            "wrong-step outputs not returned (outputs=%r)" % (outputs,))


# ------------------------------------------------------------------
# Op-registry cleanup controls
# ------------------------------------------------------------------

def _saga_plan_fx(key):
    from gov import workflow_saga as _saga
    from gov import workflow_composed as wc
    definition = _saga.SagaDefinition([
        _saga.SagaStepDef(step_id="a", action_op="noop",
                          compensation_op="noop")])
    return wc.ComposedPlan([{
        "kind": "saga", "name": "s1", "definition": definition,
        "action_fns": {"a": lambda params: {"ok": True}},
        "comp_fns": {"a": lambda params: {"undone": True}},
        "inputs": {}, "idem_key": key}])


def p_opreg_stale_ops_removed():
    # After a composed saga unit completes, its nonce-scoped op names
    # must be gone from the process-global registry.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    from gov import workflow_saga as _saga
    before = set(_saga._OPS)
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    comp.execute(_saga_plan_fx("sk1"), run_id="R", authority=auth, at=AT)
    after = set(_saga._OPS)
    leaked = [n for n in after - before if n.startswith("composed:")]
    if leaked:
        return _record("OPREG-stale-ops-removed", "BREAK",
                       "scoped op names leaked: %r" % (leaked[:3],))
    _record("OPREG-stale-ops-removed", "HELD",
            "no scoped op names leaked post-completion")


def p_opreg_stability():
    # 10 executions must not grow the registry.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    from gov import workflow_saga as _saga
    sizes = []
    for i in range(10):
        run_id = "R%d" % i
        ws.start_run("probe", run_id=run_id, authority=auth, at=AT)
        comp.execute(_saga_plan_fx("sk%d" % i), run_id=run_id,
                     authority=auth, at=AT)
        sizes.append(len(_saga._OPS))
    if sizes[-1] != sizes[0]:
        return _record("OPREG-stability", "BREAK",
                       "registry grew across executions: %r" % (sizes,))
    _record("OPREG-stability", "HELD",
            "registry stable across 10 executions")


# ------------------------------------------------------------------
# Outbox discard contract (control)
# ------------------------------------------------------------------

def p_outbox_discard_contract():
    # A poisoned outbox dispatcher return is inert: drain_outbox
    # discards the dispatcher's return value (returns the int dispatch
    # count). Lane B's wave-305 verdict was NEGATIVE (falsified).
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    from gov import workflow_saga as _saga
    definition = _saga.SagaDefinition([
        _saga.SagaStepDef(step_id="a", action_op="noop",
                          compensation_op="noop")])
    _saga.register_op("noop", lambda params: {"ok": True})
    try:
        inst = sm.start(definition)
        sm.run(inst)
        # Poisoned dispatcher returns an attacker string.
        n = sm.drain_outbox(inst, lambda intent: "ATTACKER-STRING")
    finally:
        _saga._OPS.pop("noop", None)
    if not isinstance(n, int):
        return _record("OUTBOX-discard-contract", "BREAK",
                       "drain_outbox returned non-int: %r" % (n,))
    _record("OUTBOX-discard-contract", "HELD",
            "drain_outbox discards dispatcher return (int %d)" % (n,))


# ------------------------------------------------------------------
# Green-check contract probe
# ------------------------------------------------------------------

def p_greencheck_broken_child_fails_closed():
    # The shared green_check helper must ERROR (not HELD) on a child
    # battery that raises before emitting a summary.
    if os.environ.get("GOV_SKIP_GREEN"):
        # Depth-1 convention (wave-307 merge): when this battery itself
        # runs as a green-check child, the helper skips instead of
        # spawning, so this self-test's premise does not hold -- skip
        # depth-aware rather than misreport BREAK.
        return _record("GREENCHECK-broken-child-fails-closed", "HELD",
                       "skipped: depth-1 green check (GOV_SKIP_GREEN=1)")
    broken = os.path.join(tempfile.gettempdir(),
                          "w306_broken_child_%d.py" % os.getpid())
    with open(broken, "w", encoding="utf-8") as fh:
        fh.write("import nothing_missing_xyz  # noqa\n")
    try:
        verdict, note = green_check.check_battery_result(
            "green-broken-child", broken, repo=REPO, timeout=60)
    finally:
        try:
            os.unlink(broken)
        except OSError:
            pass
    if verdict == "ERROR":
        return _record("GREENCHECK-broken-child-fails-closed", "HELD",
                       "broken child failed closed loudly: %s"
                       % (note[:80],))
    _record("GREENCHECK-broken-child-fails-closed", "BREAK",
            "broken child did not fail closed: %s %s" % (verdict, note))


# ------------------------------------------------------------------
# F385/F386/F388 regression controls
# ------------------------------------------------------------------

def p_f385_resume_xid_bound():
    # F385 (LOW, CLOSED): resume_lease resolves the XID against live
    # transactions; a swapped XID refuses.
    lm, tok, c, xid_a, ed25519 = _branch_fx()
    xid_b = c.begin(ed25519.generate_seed())
    rec = c.suspend_lease(xid_a, lm, "scope-x", tok, "holder-1",
                          suspended_at=1050)
    rec_swapped = dict(rec, xid=xid_b)
    try:
        c.resume_lease(rec_swapped, lm, 1060)
    except Exception as e:  # noqa: BLE001
        return _record("F385-resume-xid-bound", "HELD",
                       "swapped XID refused coded %r (F385 holds)"
                       % (getattr(e, "code", e),))
    _record("F385-resume-xid-bound", "BREAK",
            "swapped XID resumed (F385 regressed)")


def p_f386_verifier_nonce_scoped():
    # F386 (LOW, CLOSED): two composers sharing one manager get
    # distinct nonce-scoped verifier refs.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    c1 = wc.WorkflowComposer(ws, sm, idem.IdempotencyStore())
    c2 = wc.WorkflowComposer(ws, sm, idem.IdempotencyStore())
    if c1._verifier_nonce == c2._verifier_nonce:
        return _record("F386-verifier-nonce-scoped", "BREAK",
                       "composer nonces collided (F386 regressed)")
    _record("F386-verifier-nonce-scoped", "HELD",
            "composer nonces distinct; verifier refs scoped")


def p_f388_foreign_run_refused():
    # F388 (MEDIUM, CLOSED): a poisoned pair naming a FOREIGN run
    # refuses coded workflow-composed-replay-foreign.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    ws.start_run("probe", run_id="victim", authority=auth, at=AT)
    ws.run_step("victim", 1, "vstep", lambda i: {"stolen": 1}, {},
                authority=auth, at=AT)
    victim_digest = wc._digest({"stolen": 1})
    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": lambda i: {"real": 1},
         "inputs": {}, "idem_key": "ak"}])
    forged = _fn_op_digest(wc, plan, "u", {})
    plant = im.begin("composed", "composed-unit", "ak", forged,
                     caller="mallory", authority_verifier=lambda **k: True,
                     at=AT)
    plant.complete(victim_digest, "wfstep:victim:1", at=AT)
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    try:
        comp.execute(plan, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-composed-replay-foreign":
            return _record("F388-foreign-run-refused", "HELD",
                           "foreign pair refused coded (F388 holds)")
        return _record("F388-foreign-run-refused", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    _record("F388-foreign-run-refused", "BREAK",
            "foreign pair accepted (F388 regressed)")


# ------------------------------------------------------------------
# Pending-path drift observation (lane C territory -- not filed)
# ------------------------------------------------------------------

def p_pending_sleep_drift_observed():
    # OBSERVATION ONLY (wave-306 lane C's territory): a pending sleep
    # re-presented with a different wake_at is not drift-checked; the
    # first wake_at wins. Documented, not filed.
    from gov import workflow as wf
    sa, sb, pa, pb, chain, trust_roots, root = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    ws.start_run("wf", run_id="r1", authority=auth, at=AT)
    # Pending at T1 (now < T1).
    a1, rep1 = ws.sleep_step("r1", 1, "nap", AT + 100,
                             authority=auth, at=AT, now=AT)
    if a1 or rep1:
        return _record("PENDING-sleep-drift-observed", "ERROR",
                       "setup failed: %r %r" % (a1, rep1))
    # Re-present pending with a different wake_at; now passes the NEW
    # wake_at but is before the OLD one.
    a2, rep2 = ws.sleep_step("r1", 1, "nap", AT + 50,
                             authority=auth, at=AT + 1, now=AT + 60)
    step = ws.get_step("r1", 1)
    _record("PENDING-sleep-drift-observed", "HELD",
            "pending re-presented with wake_at drift: completed=%r, "
            "recorded inputs_digest=%s (observation only; lane C "
            "territory)" % (a2, step["inputs_digest"][:12]))


# ------------------------------------------------------------------
# Green checks (shared helper, fail-closed form)
# ------------------------------------------------------------------

def _green_checks():
    def _rec(pid, verdict, note):
        _record(pid, verdict, note)
    if SKIP_GREEN:
        _record("green-skipped", "HELD", "green check skipped "
                "(GOV_SKIP_GREEN=1)")
        return
    # Wave-306 merge: F389 CLOSED by lane A -- w305 reports 0 BREAKs now.
    green_check.check_battery(
        _rec, "green-w305-redteam", "evals/w305_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_battery(
        _rec, "green-w304-redteam", "evals/w304_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_battery(
        _rec, "green-w303-f387", "evals/w303_f387_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_battery(
        _rec, "green-w303-f388", "evals/w303_f388_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_battery(
        _rec, "green-w303-f386", "evals/w303_f386_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_unittest(
        _rec, "green-test-workflow", "tests.test_workflow", repo=REPO)


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F389-suspend-lease-clobber", p_f389_suspend_lease_clobber)
    _safe("F387-recv-event-drift", p_f387_recv_event_drift)
    _safe("F387-sleep-wakeat-drift", p_f387_sleep_wakeat_drift)
    _safe("F387b-sleep-recv-type-confusion",
           p_f387b_sleep_recv_type_confusion)
    _safe("F387b-authority-first-ordering",
           p_f387b_authority_first_ordering)
    _safe("F390-CONFIRMED-same-run-wrong-step",
           p_f390_same_run_wrong_step)
    _safe("OPREG-stale-ops-removed", p_opreg_stale_ops_removed)
    _safe("OPREG-stability", p_opreg_stability)
    _safe("OUTBOX-discard-contract", p_outbox_discard_contract)
    _safe("GREENCHECK-broken-child-fails-closed",
           p_greencheck_broken_child_fails_closed)
    _safe("F385-resume-xid-bound", p_f385_resume_xid_bound)
    _safe("F386-verifier-nonce-scoped", p_f386_verifier_nonce_scoped)
    _safe("F388-foreign-run-refused", p_f388_foreign_run_refused)
    _safe("PENDING-sleep-drift-observed", p_pending_sleep_drift_observed)
    _green_checks()
    n_b = sum(1 for _, v, _ in _results if v == "BREAK")
    n_h = sum(1 for _, v, _ in _results if v == "HELD")
    n_e = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note.split("\n")[0]))
    print("----")
    print("%d BREAK / %d HELD / %d ERROR" % (n_b, n_h, n_e))
    sys.exit(1 if n_b else 0)


if __name__ == "__main__":
    main()
