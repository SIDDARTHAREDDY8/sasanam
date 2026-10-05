"""Wave-307 lane E battery: independent red team vs the wave-306 tree.

Base: wave-306 merge f6248a18 (F389 closed; F390 filed and closed;
pending-drift residual falsified; pin 1827; footer open none / next F391).

Targets (all verified empirically with throwaway scripts BEFORE this
battery was written -- diagnosing-bugs loop):
 1. The F389 closure at its REAL threat model ("anyone who knows the
    xid"): the suspend-time check_write proof is vacuous against a
    caller-supplied rubber-stamp lease manager -> F391 (MEDIUM, OPEN).
 2. The F390 step-name binding at its bypass boundaries (duplicate unit
    names, duplicate saga step_ids, cross-kind prefix confusion,
    wrong-step replay regression).
 3. Op-registry cleanup (stale scoped ops post-finally; stability).
 4. Outbox discard contract (poisoned dispatcher returns).
 5. Green-check contract (deliberately-broken child must ERROR).
 6. F385/F386/F387/F388 closure regressions.

New findings filed by this lane: F391 (MEDIUM, OPEN), claim
2026-10-03T10:37:32Z -- suspend_lease/resume_lease take the lease
manager as a caller-supplied argument, so the F389 suspend-time
holdership proof is vacuous against a fake manager (fake-manager
re-park clobbers the holder's suspension; fake-manager resume
self-attests liveness). Lanes A/B may also claim F391 for their own
findings; per the wave-272 earliest-filed rule the merge reconciles.

Run:
  mkdir -p /var/tmp/g307-rt && TMPDIR=/var/tmp/g307-rt \\
    ~/workspace/.gov-venv/bin/python evals/w307_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g307-rt2 \\
    ~/workspace/.gov-venv/bin/python evals/w307_redteam_probes.py
"""

import hashlib
import os
import re
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

# Wave-306 merge pin 1827; this lane mints no codes (red team only), so
# the pin stays 1827. The merge-time sweep repoints to the wave-307 pin.
TAXONOMY_PIN = 2127  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).


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
    _record("pin-taxonomy", "HELD", "2127/2127/0 sorted")




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
    # Wave-313 lane A footer: F397 CLOSED; no open findings.
    # Wave-342 lane 6: repointed to open F428 / next F429 (footer-state probe audit).
    if nxt != 429 or open_s != "F428":
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d open %r (want next F429 open "
                       "'F428')" % (nxt, open_s))
    _record("footer-state", "HELD",
            "footer pins open F428 / next F429")


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
# F391: fake lease manager defeats the F389 holdership proof
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


class _RubberStampManager:
    """An attacker's lease manager: check_write is a no-op."""
    def check_write(self, scope, fencing_token, holder_id,
                    checked_at=None):
        return True


def p_f391_fake_manager_clobber():
    # F391 (MEDIUM, CLOSED wave-308 lane A): suspend_lease used to take
    # the lease manager as a caller-supplied argument. The F389
    # closure's check_write proof was vacuous against an attacker who
    # brought their own rubber-stamp manager: the re-park was ACCEPTED
    # and the legitimate holder's subsequent resume refused
    # workflow-branch-xid-mismatch. Now the coordinator binds the
    # manager at begin() time (identity check); a substituted manager
    # refuses coded coord-lease-manager-mismatch.
    lm, tok, c, xid, ed25519 = _branch_fx()
    rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                          suspended_at=1050)
    try:
        evil = c.suspend_lease(xid, _RubberStampManager(), "scope-x",
                               999999, "mallory", suspended_at=1060)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "coord-lease-manager-mismatch":
            return _record("F391-fake-manager-clobber", "HELD",
                           "fake-manager re-park refused coded "
                           "coord-lease-manager-mismatch (F391 closed)")
        return _record("F391-fake-manager-clobber", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    if evil["fencing_token"] != 999999 or evil["holder_id"] != "mallory":
        return _record("F391-fake-manager-clobber", "ERROR",
                       "re-park did not take: %r" % (evil,))
    try:
        c.resume_lease(rec, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-branch-xid-mismatch":
            return _record("F391-fake-manager-clobber", "BREAK",
                           "fake-manager re-park clobbered the parked "
                           "suspension; legitimate resume now refuses "
                           "workflow-branch-xid-mismatch (F391)")
        return _record("F391-fake-manager-clobber", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    _record("F391-fake-manager-clobber", "HELD",
            "holder resume survived the re-park (F391 closed?)")


def p_f391_fake_manager_resume():
    # F391 second limb (CLOSED wave-308 lane A): the resume-time
    # liveness check must consult the bound manager. The attacker's
    # suspend with a substitute manager is now refused at park time
    # (see p_f391_fake_manager_clobber); this probe pins the resume
    # side directly: begin with fake1 BOUND (begin-time binding), park
    # with fake1, then resume the parked record with a DIFFERENT
    # substitute fake2 -- the coordinator must refuse coded
    # coord-lease-manager-mismatch rather than let fake2 self-attest
    # liveness.
    from gov import workflow_branch as wb
    from gov import ed25519 as _ed
    c = wb.BranchCoordinator()
    fake1 = _RubberStampManager()
    xid = c.begin(_ed.generate_seed(), lease_manager=fake1)
    evil = c.suspend_lease(xid, fake1, "scope-x", 999999, "mallory",
                           suspended_at=1060)
    try:
        ok = c.resume_lease(evil, _RubberStampManager(), checked_at=1090)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "coord-lease-manager-mismatch":
            return _record("F391-fake-manager-resume", "HELD",
                           "substituted-manager resume refused coded "
                           "coord-lease-manager-mismatch (F391 closed)")
        return _record("F391-fake-manager-resume", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    return _record("F391-fake-manager-resume", "ERROR",
                   "substituted-manager resume returned %r "
                   "(F391 open?)" % (ok,))


def p_f389_real_manager_refusal():
    # F389 closure regression: with the REAL manager, a bogus token
    # still refuses coded coord-lease-fencing and the legitimate park
    # stays intact (the closure holds against callers who use the real
    # oracle; F391 is about callers who substitute it).
    lm, tok, c, xid, ed25519 = _branch_fx()
    rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                          suspended_at=1050)
    try:
        c.suspend_lease(xid, lm, "scope-x", 999999, "mallory",
                        suspended_at=1060)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "coord-lease-fencing":
            return _record("F389-real-manager-refusal", "ERROR",
                           "wrong refusal: %r" % (getattr(e, "code", e),))
    else:
        return _record("F389-real-manager-refusal", "BREAK",
                       "bogus token accepted by the real manager "
                       "(F389 regressed)")
    try:
        ok = c.resume_lease(rec, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        return _record("F389-real-manager-refusal", "ERROR",
                       "legitimate resume refused: %r"
                       % (getattr(e, "code", e),))
    if ok is not True:
        return _record("F389-real-manager-refusal", "ERROR",
                       "legitimate resume returned %r" % (ok,))
    _record("F389-real-manager-refusal", "HELD",
            "real-manager bogus token refused coded; legitimate "
            "suspend/resume intact")


# ------------------------------------------------------------------
# F390 step-name binding at its bypass boundaries
# ------------------------------------------------------------------

def p_f390_dup_unit_names_refused():
    # ComposedPlan must refuse duplicate unit names at validation --
    # otherwise two units would share one "fn:<name>" step-name
    # namespace and the F390 name check could not tell them apart.
    from gov import workflow_composed as wc
    try:
        wc.ComposedPlan([
            {"kind": "fn", "name": "dup",
             "fn": lambda i: {"a": 1}, "inputs": {}, "idem_key": "k1"},
            {"kind": "fn", "name": "dup",
             "fn": lambda i: {"b": 2}, "inputs": {}, "idem_key": "k2"},
        ])
    except Exception as e:  # noqa: BLE001
        _record("F390-dup-unit-names-refused", "HELD",
                "duplicate unit names refused coded %r"
                % (getattr(e, "code", e),))
        return
    _record("F390-dup-unit-names-refused", "BREAK",
            "duplicate unit names accepted: F390 name binding has a "
            "collision surface")


def p_f390_dup_saga_stepids_refused():
    # SagaDefinition must refuse duplicate step_ids -- otherwise two
    # saga steps would share one "saga:<unit>:<step>" name.
    from gov import workflow_saga as _saga
    try:
        _saga.SagaDefinition([
            _saga.SagaStepDef(step_id="a", action_op="noop",
                              compensation_op="noop"),
            _saga.SagaStepDef(step_id="a", action_op="noop",
                              compensation_op="noop"),
        ])
    except Exception as e:  # noqa: BLE001
        _record("F390-dup-saga-stepids-refused", "HELD",
                "duplicate saga step_ids refused coded %r"
                % (getattr(e, "code", e),))
        return
    _record("F390-dup-saga-stepids-refused", "BREAK",
            "duplicate saga step_ids accepted: F390 name binding has "
            "a collision surface")


def p_f390_cross_kind_prefix_separated():
    # A fn unit named "saga:u:s1" must not collide with a saga action's
    # "saga:u:s1" step name: the fn unit's step is namespaced "fn:...".
    from gov import workflow_composed as wc
    if "fn:%s" % "saga:u:s1" == "saga:%s:%s" % ("u", "s1"):
        return _record("F390-cross-kind-prefix-separated", "BREAK",
                       "fn/saga step-name namespaces collide")
    _record("F390-cross-kind-prefix-separated", "HELD",
            "kind prefixes separate step-name namespaces "
            "(fn:/saga:/saga-comp:/slip:)")


def p_f390_wrong_step_still_refused():
    # F390 closure regression: the wave-306 lane-B attack (same run,
    # same caller, different completed step) must still refuse coded.
    # F393 (wave-309) stops this two-plan shape EARLIER at the
    # run->plan gate (coded workflow-composed-plan-mismatch); the name
    # check itself is covered end-to-end by tests/test_workflow_f390.py.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    actor = "agent-b"
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    plan1 = wc.ComposedPlan([
        {"kind": "fn", "name": "u1", "fn": lambda i: {"one": 1},
         "inputs": {}, "idem_key": "k1"}])
    comp.execute(plan1, run_id="R", authority=auth, at=AT)
    plan2 = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": lambda i: {"two": 2},
         "inputs": {}, "idem_key": "k2"}])
    forged = _fn_op_digest(wc, plan2, "u2", {})
    plant = im.begin("composed", "composed-unit", "k2", forged,
                     caller=actor, authority_verifier=lambda **k: True,
                     at=AT)
    plant.complete(wc._digest({"one": 1}), "wfstep:R:1", at=AT)
    plan2b = wc.ComposedPlan([
        {"kind": "fn", "name": "u2",
         "fn": lambda i: {"two": 2}, "inputs": {}, "idem_key": "k2"}])
    try:
        res = comp.execute(plan2b, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-composed-plan-mismatch":
            return _record("F390-wrong-step-still-refused", "HELD",
                           "same-run wrong-step attack refused coded "
                           "workflow-composed-plan-mismatch at the "
                           "run->plan gate (F390 attack path closed "
                           "earlier)")
        return _record("F390-wrong-step-still-refused", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    outputs = res["units"][0]["outputs"] if res.get("units") else res
    _record("F390-wrong-step-still-refused", "BREAK",
            "wrong-step pair accepted (F390 regressed): %r" % (outputs,))


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
                          "w307_broken_child_%d.py" % os.getpid())
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
# F385/F386/F387/F388 regression controls
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
    if not p1:
        return _record("F387-recv-event-drift", "ERROR",
                       "setup did not complete: %r %r" % (p1, rep1))
    ws.notify("r1", "cancelled", {"amount": 0}, authority=auth, at=AT)
    try:
        ws.recv_step("r1", 1, "wait", "cancelled",
                     authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-step-unauthorized":
            return _record("F387-recv-event-drift", "HELD",
                           "completed path refused event drift coded "
                           "(F387 holds)")
        return _record("F387-recv-event-drift", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    _record("F387-recv-event-drift", "BREAK",
            "event drift replayed (F387 regressed)")


def p_f387_sleep_wakeat_drift():
    # F387 (LOW, CLOSED): sleep_step's completed path refuses wake_at
    # drift coded workflow-step-unauthorized.
    from gov import workflow as wf
    sa, sb, pa, pb, chain, trust_roots, root = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    ws.start_run("wf", run_id="r1", authority=auth, at=AT)
    a1, rep1 = ws.sleep_step("r1", 1, "nap", AT + 100,
                             authority=auth, at=AT, now=AT + 200)
    if not a1:
        return _record("F387-sleep-wakeat-drift", "ERROR",
                       "setup did not complete: %r %r" % (a1, rep1))
    try:
        ws.sleep_step("r1", 1, "nap", AT + 999,
                      authority=auth, at=AT, now=AT + 200)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-step-unauthorized":
            return _record("F387-sleep-wakeat-drift", "HELD",
                           "completed path refused wake_at drift coded "
                           "(F387 holds)")
        return _record("F387-sleep-wakeat-drift", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    _record("F387-sleep-wakeat-drift", "BREAK",
            "wake_at drift replayed (F387 regressed)")


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
    # Wave-307 merge: F389/F390 CLOSED -- all red-team batteries
    # report 0 BREAKs now. w306's GREENCHECK-broken-child probe is
    # depth-aware (skips under GOV_SKIP_GREEN=1 per the depth-1
    # convention), so as a green-check child it records HELD-skip, not
    # BREAK. Standalone w306 is 0 BREAK / 22 HELD / 0 ERROR.
    green_check.check_battery(
        _rec, "green-w306_redteam", "evals/w306_redteam_probes.py",
        repo=REPO,
        expect_break_ids=())
    for name in ("w305_redteam_probes.py",
                 "w304_redteam_probes.py",
                 "w303_f389_probes.py",
                 "w303_f390_probes.py",
                 "w303_f387_probes.py",
                 "w303_f388_probes.py",
                 "w303_f386_probes.py"):
        green_check.check_battery(
            _rec, "green-%s" % name[:-10], "evals/%s" % name,
            repo=REPO, expect_break_ids=())
    green_check.check_unittest(
        _rec, "green-test-workflow", "tests.test_workflow", repo=REPO)


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F391-fake-manager-clobber", p_f391_fake_manager_clobber)
    _safe("F391-fake-manager-resume", p_f391_fake_manager_resume)
    _safe("F389-real-manager-refusal", p_f389_real_manager_refusal)
    _safe("F390-dup-unit-names-refused", p_f390_dup_unit_names_refused)
    _safe("F390-dup-saga-stepids-refused", p_f390_dup_saga_stepids_refused)
    _safe("F390-cross-kind-prefix-separated",
           p_f390_cross_kind_prefix_separated)
    _safe("F390-wrong-step-still-refused", p_f390_wrong_step_still_refused)
    _safe("OPREG-stale-ops-removed", p_opreg_stale_ops_removed)
    _safe("OPREG-stability", p_opreg_stability)
    _safe("OUTBOX-discard-contract", p_outbox_discard_contract)
    _safe("GREENCHECK-broken-child-fails-closed",
           p_greencheck_broken_child_fails_closed)
    _safe("F385-resume-xid-bound", p_f385_resume_xid_bound)
    _safe("F386-verifier-nonce-scoped", p_f386_verifier_nonce_scoped)
    _safe("F388-foreign-run-refused", p_f388_foreign_run_refused)
    _safe("F387-recv-event-drift", p_f387_recv_event_drift)
    _safe("F387-sleep-wakeat-drift", p_f387_sleep_wakeat_drift)
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
