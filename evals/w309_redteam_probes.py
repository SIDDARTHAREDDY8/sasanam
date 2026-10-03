"""Wave-309 lane D battery: independent red team vs the wave-308 tree.

Base: wave-308 merge 018887f1 (F391 CLOSED -- coordinator-bound lease
manager, +1 code coord-lease-manager-mismatch, pin 1828; F393 OPEN --
op_digest does not bind the unit's code).

Targets (all verified empirically with throwaway scripts BEFORE this
battery was written -- diagnosing-bugs loop):
 1. F394 (LOW, OPEN -- filed by this lane, claim 2026-10-03T12:13:00Z):
    the F384 operator recovery path does not function for composed
    sagas. After a composed saga unit escalates, the composer's
    post-escalation cleanup (F386 verifier scoping + wave-305 wrapper-op
    removal) deletes the nonce-scoped wrapper ops AND the step
    authority verifiers. Every re-drive recovery action then fails:
    retry_compensation / abort_and_compensate_all raise misleading
    workflow-saga-compensation-unauthorized ("revoked or unknown" --
    nothing was revoked; the verifier was removed), the compensation
    is never re-invoked, and the saga stays escalated. Control: the
    identical scenario on a direct saga (deployment-registered ops)
    recovers fine -- the gap is specific to the composed path. Only
    accept_manual_remediation (attestation, no re-drive) works.
 2. F393 (MEDIUM, CLOSED at wave-309 merge): the filed attack shapes
    (fn + saga code confusion) plus the NEW slip-leg variant now assert
    the coded workflow-composed-plan-mismatch refusal (descriptor-identical
    only in leg_fns yield identical digests; the victim's leg replays
    the attacker's outputs, victim leg fn never runs). Same defect
    class -- not a new finding.
 3. F391 closure regressions: binding-confusion probes -- a
    value-equal (but not identical) manager clone is still refused
    coded (identity, not equality); per-transaction bindings (same
    manager binds separately per xid; resume works); the documented
    first-park race refuses LOUDLY coded (DoS residual, not silent).
 4. Wave-308 seams: the _is_coded_refusal boundary (plain/empty/int
    codes are transient; a non-empty string code -- even a
    semantically-transient one -- escalates immediately; documents the
    fail-closed direction); probe_lines.py soundness (notes are
    first-lined -- no probe-line injection; the parser is strict).
 5. F385-F392 closure regressions via green checks on the adjacent
    batteries.

New findings filed by this lane: F394 (LOW, OPEN), claim
2026-10-03T12:13:00Z. Wave-309 merge: F393 CLOSED (coded
workflow-composed-plan-mismatch); F394 stays OPEN; pin 1841;
footer open F397 / next F398. Wave-310 lane A: F394 CLOSED via
WorkflowComposer.retry_saga_unit (composer-level operator-retry
API; no new codes; pin unchanged 1841); the F394 probes in this
battery were updated from the direct-SagaManager call pattern to
the supported composer-API call pattern (probe IDs and intent
unchanged); footer open F397 / next F398. This battery's expected
BREAKs: none.

Run:
  mkdir -p /var/tmp/g309-rt && TMPDIR=/var/tmp/g309-rt \\
    ~/workspace/.gov-venv/bin/python evals/w309_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g309-rt2 \\
    ~/workspace/.gov-venv/bin/python evals/w309_redteam_probes.py
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

# Wave-308 pin 1828 (+1 coord-lease-manager-mismatch). This lane mints
# no codes (red team only), so the pin stays 1828.
TAXONOMY_PIN = 1888  # wave-309 merge: +1 workflow-composed-plan-mismatch; Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*)

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
    _record("pin-taxonomy", "HELD", "1888/1888/0 sorted")


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
    # Wave-313 lane A footer: F397 CLOSED; no open findings.
    if nxt != 401 or open_s != "F399, F400":
        return _record("footer-state", "BREAK",
                       "footer pins next F%d open '%s', want next F401 "
                       "open 'none'" % (nxt, open_s))
    _record("footer-state", "HELD", "footer pins open F399, F400 / next F401")


# ------------------------------------------------------------------
# Shared scaffolds
# ------------------------------------------------------------------

def _seed(s):
    return hashlib.sha256(("w309-" + s).encode()).digest()


def _branch_fx():
    from gov import workflow_branch as wb
    from gov import coordination_lease as cl
    from gov import ed25519
    lm = cl.LeaseManager()
    lease = lm.acquire("scope-x", 100, "holder-1",
                       authority_seed=ed25519.generate_seed(),
                       issued_at=1000)
    c = wb.BranchCoordinator()
    # Wave-309 lane B: the lease manager binds at begin() time.
    xid = c.begin(ed25519.generate_seed(), lease_manager=lm)
    return lm, lease["fencing_token"], c, xid, ed25519


def _composed_scaffold(tag, operator_ref=False):
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
    ws = wf.WorkflowStore()
    if operator_ref:
        sm = saga.SagaManager(
            authority_verifiers={"op-ref": lambda: True},
            operator_authority_ref="op-ref")
    else:
        sm = saga.SagaManager()
    im = idem.IdempotencyStore()
    comp = wc.WorkflowComposer(ws, sm, im)
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    return wc, wf, saga, idem, comp, ws, sm, im, auth


def _escalated_composed_saga(tag):
    """Drive a composed saga unit to escalation: s2's action fails,
    s1's compensation fails transiently 3x. Returns
    (comp, sm, instance, comp_calls)."""
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        tag, operator_ref=True)
    calls = {"comp": 0}

    def good_action(params):
        return {"ok": True}, []

    def bad_action(params):
        raise RuntimeError("action boom")

    def flaky_comp(params):
        calls["comp"] += 1
        raise RuntimeError("downstream blip %d" % calls["comp"])

    definition = saga.SagaDefinition([
        saga.SagaStepDef(step_id="s1", action_op="a1", action_params={},
                         compensation_op="c1", compensation_params={}),
        saga.SagaStepDef(step_id="s2", action_op="a2", action_params={},
                         compensation_op="c2", compensation_params={}),
    ])
    plan = wc.ComposedPlan([{
        "kind": "saga", "name": "u1", "definition": definition,
        "action_fns": {"s1": good_action, "s2": bad_action},
        "comp_fns": {"s1": flaky_comp, "s2": flaky_comp},
        "idem_key": "k1",
    }])
    try:
        comp.execute(plan, run_id="R", authority=auth, at=AT)
    except Exception:
        pass
    inst = comp._saga_instances["u1"]
    return comp, sm, inst, calls


def _escalated_composed_saga_fixable(tag):
    """Drive a composed saga unit to escalation with a compensation
    that fails transiently during the initial window (3 attempts) but
    succeeds once the downstream is "fixed" (4th call onward).
    Returns (comp, sm, instance, comp_calls). Used by the F394
    operator-recovery probes: the operator path must re-drive the
    compensation to a terminal state after the cause is fixed."""
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        tag, operator_ref=True)
    calls = {"comp": 0}

    def good_action(params):
        return {"ok": True}, []

    def bad_action(params):
        raise RuntimeError("action boom")

    def flaky_then_fixed(params):
        calls["comp"] += 1
        if calls["comp"] <= 3:
            raise RuntimeError("downstream blip %d" % calls["comp"])
        return {"recovered": True}

    definition = saga.SagaDefinition([
        saga.SagaStepDef(step_id="s1", action_op="a1", action_params={},
                         compensation_op="c1", compensation_params={}),
        saga.SagaStepDef(step_id="s2", action_op="a2", action_params={},
                         compensation_op="c2", compensation_params={}),
    ])
    plan = wc.ComposedPlan([{
        "kind": "saga", "name": "u1", "definition": definition,
        "action_fns": {"s1": good_action, "s2": bad_action},
        "comp_fns": {"s1": flaky_then_fixed, "s2": flaky_then_fixed},
        "idem_key": "k1",
    }])
    try:
        comp.execute(plan, run_id="R", authority=auth, at=AT)
    except Exception:
        pass
    inst = comp._saga_instances["u1"]
    return comp, sm, inst, calls


# ------------------------------------------------------------------
# F394 (LOW, CLOSED wave-310): the F384 operator recovery path did not
# function for composed sagas. Closure direction: a composer-level
# operator-retry API (WorkflowComposer.retry_saga_unit) re-establishes
# the unit's execution prerequisites (retry execution context, step
# authority verifier, nonce-scoped wrapper ops), delegates to the
# saga manager's resolve_escalation, and tears everything down
# deterministically. The supported operator path for a composed saga
# is the composer API; calling the saga manager directly on a
# composed instance still fails closed and coded. Probes updated from
# the direct-SagaManager call pattern to the supported composer-API
# call pattern (probe intent -- re-drive works after the downstream
# is fixed -- unchanged).
# ------------------------------------------------------------------

def p_f394_op_retry_composed():
    # F394 CLOSED: after a composed saga escalates, the operator
    # re-drives via comp.retry_saga_unit("u1",
    # {"action": "retry_compensation"}, at=AT). The composer re-establishes
    # the prerequisites, so the fixed compensation is actually
    # invoked and the saga reaches compensated. The misleading
    # workflow-saga-compensation-unauthorized on this path is gone.
    comp, sm, inst, calls = _escalated_composed_saga_fixable("f394retry")
    if inst.status != "escalated":
        return _record("F394-op-retry-composed", "ERROR",
                       "saga did not escalate; probe void")
    before = calls["comp"]
    try:
        # F397: the retry instant must be strictly after the
        # escalation's logical instant (AT here); AT+1 is within the
        # delegation's validity window, so the re-drive succeeds.
        comp.retry_saga_unit("u1", {"action": "retry_compensation"}, at=AT + 1)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-saga-compensation-unauthorized":
            return _record("F394-op-retry-composed", "BREAK",
                           "F394 regression: misleading "
                           "workflow-saga-compensation-unauthorized "
                           "on composer retry")
        return _record("F394-op-retry-composed", "ERROR",
                       "composer retry raised %r" % (code,))
    if inst.status == "compensated" and calls["comp"] > before:
        return _record("F394-op-retry-composed", "HELD",
                       "composer retry re-drove the compensation "
                       "(%d->%d calls); saga compensated (F394 closed)"
                       % (before, calls["comp"]))
    return _record("F394-op-retry-composed", "ERROR",
                   "unexpected: status=%r calls=%d->%d"
                   % (inst.status, before, calls["comp"]))


def p_f394_abort_composed():
    # F394 CLOSED: the second re-drive action,
    # abort_and_compensate_all, now works through the composer API:
    # the fixed compensation is re-driven (remaining attempt budget)
    # and the saga reaches compensated.
    comp, sm, inst, calls = _escalated_composed_saga_fixable("f394abort")
    if inst.status != "escalated":
        return _record("F394-abort-composed", "ERROR",
                       "saga did not escalate; probe void")
    before = calls["comp"]
    try:
        # F397: the retry instant must be strictly after the
        # escalation's logical instant (AT here); AT+1 is within the
        # delegation's validity window, so the re-drive succeeds.
        comp.retry_saga_unit("u1",
                             {"action": "abort_and_compensate_all"},
                             at=AT + 1)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        return _record("F394-abort-composed", "ERROR",
                       "composer abort raised %r (calls %d->%d)"
                       % (code, before, calls["comp"]))
    if inst.status == "compensated" and calls["comp"] > before:
        return _record("F394-abort-composed", "HELD",
                       "composer abort_and_compensate_all re-drove the "
                       "compensation (%d->%d calls); saga compensated "
                       "(F394 closed)" % (before, calls["comp"]))
    return _record("F394-abort-composed", "ERROR",
                   "unexpected: status=%r calls=%d->%d"
                   % (inst.status, before, calls["comp"]))


def p_f394_direct_saga_retry_works():
    # Control: the identical scenario on a DIRECT saga
    # (deployment-registered ops, persistent verifiers) recovers fine.
    # Proves the gap is specific to the composed path's cleanup.
    from gov import workflow_saga as saga
    sm = saga.SagaManager(authority_verifiers={"op-ref": lambda: True},
                          operator_authority_ref="op-ref")
    saga.register_op("w309-d-action-ok", lambda p: ({"ok": True}, []))

    def _boom(p):
        raise RuntimeError("action boom")
    saga.register_op("w309-d-action-boom", _boom)
    calls = {"n": 0}

    def _flaky(p):
        calls["n"] += 1
        raise RuntimeError("blip")
    saga.register_op("w309-d-comp-flaky", _flaky)
    definition = sm.define([
        saga.SagaStepDef(step_id="s1", action_op="w309-d-action-ok",
                         action_params={},
                         compensation_op="w309-d-comp-flaky",
                         compensation_params={}, authority_ref="op-ref"),
        saga.SagaStepDef(step_id="s2", action_op="w309-d-action-boom",
                         action_params={},
                         compensation_op="w309-d-comp-flaky",
                         compensation_params={}, authority_ref="op-ref"),
    ])
    inst = sm.start(definition)
    try:
        sm.run(inst)
    except Exception:
        pass
    if inst.status != "escalated":
        return _record("F394-direct-saga-retry-works", "ERROR",
                       "control did not escalate; probe void")

    def _fixed(p):
        calls["n"] += 1
        return {"undone": True}
    saga.register_op("w309-d-comp-flaky", _fixed)
    try:
        sm.retry_compensation(inst)
    except Exception as e:  # noqa: BLE001
        return _record("F394-direct-saga-retry-works", "ERROR",
                       "control retry raised %r" % (getattr(e, "code", e),))
    if inst.status == "compensated":
        return _record("F394-direct-saga-retry-works", "HELD",
                       "direct-saga operator retry re-drives compensation "
                       "(control green; gap is composed-path-specific)")
    return _record("F394-direct-saga-retry-works", "ERROR",
                   "control status=%r" % (inst.status,))


# ------------------------------------------------------------------
# F393 (MEDIUM, OPEN): confirm the filed BREAKs still reproduce
# ------------------------------------------------------------------

def p_f393_fn_code_confusion():
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f393fn")
    evil = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": lambda i: {"evil": 1},
         "inputs": {}, "idem_key": "k2"}])
    executed = []

    def victim_fn(i):
        executed.append(1)
        return {"real": 2}

    victim = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": victim_fn,
         "inputs": {}, "idem_key": "k2"}])
    if evil.digest == victim.digest:
        return _record("F393-fn-code-confusion", "BREAK",
                       "code binding failed: descriptor-identical plans "
                       "share a digest")
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    try:
        res = comp.execute(victim, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-composed-plan-mismatch":
            return _record("F393-fn-code-confusion", "HELD",
                           "different plan under same run refused coded "
                           "workflow-composed-plan-mismatch (F393 closed)")
        return _record("F393-fn-code-confusion", "BREAK",
                       "refused with wrong code %r (want "
                       "workflow-composed-plan-mismatch)" % (code,))
    if res["units"]["u2"]["outputs"] == {"evil": 1} and not executed:
        return _record("F393-fn-code-confusion", "BREAK",
                       "F393: victim fn never executed; attacker's "
                       "outputs returned as native")
    return _record("F393-fn-code-confusion", "ERROR",
                   "unexpected: outputs=%r executed=%r"
                   % (res["units"]["u2"]["outputs"], bool(executed)))


def p_f393_saga_code_confusion():
    from gov import workflow_saga as saga_mod
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f393saga")
    ran = {"victim": 0}

    def evil_action(params):
        return {"evil": 1}, []

    def victim_action(params):
        ran["victim"] += 1
        return {"real": 2}, []

    def comp_fn(params):
        return {"undone": True}

    def mkdef():
        return saga_mod.SagaDefinition([
            saga_mod.SagaStepDef(step_id="s1", action_op="a",
                                 action_params={},
                                 compensation_op="c",
                                 compensation_params={}),
        ])

    def mkplan(action):
        return wc.ComposedPlan([{
            "kind": "saga", "name": "sg", "definition": mkdef(),
            "action_fns": {"s1": action},
            "comp_fns": {"s1": comp_fn},
            "idem_key": "ksg"}])

    evil, victim = mkplan(evil_action), mkplan(victim_action)
    if evil.digest == victim.digest:
        return _record("F393-saga-code-confusion", "BREAK",
                       "code binding failed: descriptor-identical saga "
                       "plans share a digest")
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    try:
        res = comp.execute(victim, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-composed-plan-mismatch":
            return _record("F393-saga-code-confusion", "HELD",
                           "different saga plan under same run refused "
                           "coded workflow-composed-plan-mismatch "
                           "(F393 closed)")
        return _record("F393-saga-code-confusion", "BREAK",
                       "refused with wrong code %r (want "
                       "workflow-composed-plan-mismatch)" % (code,))
    steps = res["units"]["sg"]["steps"]
    if ran["victim"] == 0 and res["units"]["sg"]["status"] == "succeeded":
        return _record("F393-saga-code-confusion", "BREAK",
                       "F393: victim saga action never executed; saga "
                       "succeeded with the attacker's outputs")
    return _record("F393-saga-code-confusion", "ERROR",
                   "unexpected: ran=%r steps=%r" % (ran, steps))


def p_f393_slip_code_confusion():
    # Supporting evidence (same defect class, not a new finding): a
    # descriptor-identical slip plan differing ONLY in leg_fns: pre-fix
    # this yielded a bit-identical plan digest; post-fix the digests
    # differ (code_digest) and the run->plan binding refuses the swap.
    from gov import workflow_routing as wr
    from gov import ed25519 as ed
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f393slip")
    sa = _seed("f393slip-a")
    pa = ed.publickey(sa).hex()
    legs = [{"handler_id": "h1", "handler_pubkey_hex": pa,
             "rights": ["tool.invoke"], "input_digest": "0" * 64,
             "output_digest": "0" * 64}]
    slip = wr.issue_slip(sa, "issuer", legs, AT)
    ran = {"victim": 0}

    def evil_leg(i):
        return {"l": "evil"}

    def victim_leg(i):
        ran["victim"] += 1
        return {"l": "real"}

    def mkplan(fn):
        return wc.ComposedPlan([{
            "kind": "slip", "name": "rt", "slip": slip,
            "trust_roots": [pa],
            "leg_fns": {0: (sa, fn)},
            "idem_key": "kslip"}])

    evil, victim = mkplan(evil_leg), mkplan(victim_leg)
    if evil.digest == victim.digest:
        return _record("F393-slip-code-confusion", "BREAK",
                       "code binding failed: descriptor-identical slip "
                       "plans share a digest")
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    # Fresh composer: the cross-process victim (also avoids the
    # per-composer slip cache). The run->plan binding lives in the
    # journaled WorkflowStore, so it survives the composer swap.
    comp2 = wc.WorkflowComposer(ws, sm, im)
    try:
        res = comp2.execute(victim, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-composed-plan-mismatch":
            return _record("F393-slip-code-confusion", "HELD",
                           "different slip plan under same run refused "
                           "coded workflow-composed-plan-mismatch "
                           "(F393 closed)")
        return _record("F393-slip-code-confusion", "BREAK",
                       "refused with wrong code %r (want "
                       "workflow-composed-plan-mismatch)" % (code,))
    leg = res["units"]["rt"]["legs"][0]
    if leg["outputs"] == {"l": "evil"} and ran["victim"] == 0:
        return _record("F393-slip-code-confusion", "BREAK",
                       "F393: victim slip leg fn never executed; "
                       "attacker's leg outputs returned as native "
                       "(slip-leg op_digest does not bind code)")
    return _record("F393-slip-code-confusion", "ERROR",
                   "unexpected: leg=%r ran=%r" % (leg, ran))


# ------------------------------------------------------------------
# F391 closure regressions: binding-confusion probes
# ------------------------------------------------------------------

def p_f391_clone_manager_refused():
    # Identity, not equality: a value-equal clone (with __eq__ wired
    # to True) is still a substituted manager and must refuse coded.
    from gov import workflow_branch as wb
    lm, tok, c, xid, ed25519 = _branch_fx()
    c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                    suspended_at=1050)

    class ValueEqualClone:
        def __eq__(self, other):
            return True

        def __hash__(self):
            return 1

        def check_write(self, scope, fencing_token, holder_id,
                        checked_at=None):
            return lm.check_write(scope, fencing_token, holder_id,
                                  checked_at=checked_at)

    try:
        c.suspend_lease(xid, ValueEqualClone(), "scope-x", tok,
                        "holder-1", suspended_at=1060)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "coord-lease-manager-mismatch":
            return _record("F391-clone-manager-refused", "HELD",
                           "value-equal clone refused coded "
                           "coord-lease-manager-mismatch (identity, "
                           "not equality)")
        return _record("F391-clone-manager-refused", "ERROR",
                       "wrong code %r" % (getattr(e, "code", e),))
    return _record("F391-clone-manager-refused", "BREAK",
                   "value-equal clone manager ACCEPTED -- binding "
                   "confusion")


def p_f391_cross_xid_binding():
    # Bindings are per-transaction: the same manager object may bind
    # to two xids independently; resume on each still works, and a
    # foreign manager on either still refuses.
    lm, tok, c, xid, ed25519 = _branch_fx()
    xid_b = c.begin(ed25519.generate_seed(), lease_manager=lm)
    rec_a = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                           suspended_at=1050)
    rec_b = c.suspend_lease(xid_b, lm, "scope-x", tok, "holder-1",
                            suspended_at=1060)

    class Other:
        def check_write(self, *a, **k):
            return True

    try:
        c.suspend_lease(xid, Other(), "scope-x", tok, "holder-1",
                        suspended_at=1070)
        return _record("F391-cross-xid-binding", "BREAK",
                       "foreign manager accepted on bound xid")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "coord-lease-manager-mismatch":
            return _record("F391-cross-xid-binding", "ERROR",
                           "wrong code %r" % (getattr(e, "code", e),))
    if c.resume_lease(rec_a, lm, checked_at=1090) is not True:
        return _record("F391-cross-xid-binding", "ERROR",
                       "resume xid_a failed")
    if c.resume_lease(rec_b, lm, checked_at=1090) is not True:
        return _record("F391-cross-xid-binding", "ERROR",
                       "resume xid_b failed")
    _record("F391-cross-xid-binding", "HELD",
            "per-transaction bindings independent; bound manager "
            "resumes on both; foreign manager refused coded")


def p_f391_first_park_race():
    # Wave-309 lane B eliminated the first-park race via begin-time
    # binding: suspend_lease on an xid with no begin-bound manager
    # refuses coded coord-lease-manager-mismatch at park time. There
    # is no first park to win -- the attacker cannot bind their own
    # manager by racing. The holder's own begin-bound xid parks fine.
    from gov import workflow_branch as wb
    lm, tok, c, xid, ed25519 = _branch_fx()

    class Rubber:
        def check_write(self, *a, **k):
            return True

    race_xid = c.begin(ed25519.generate_seed())
    try:
        c.suspend_lease(race_xid, Rubber(), "scope-x", 999, "mallory",
                        suspended_at=1050)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "coord-lease-manager-mismatch":
            return _record("F391-first-park-race", "ERROR",
                           "wrong code %r" % (getattr(e, "code", e),))
    else:
        return _record("F391-first-park-race", "BREAK",
                       "attacker first park ACCEPTED -- race still open")
    rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                         suspended_at=1060)
    if c.resume_lease(rec, lm, checked_at=1070) is not True:
        return _record("F391-first-park-race", "ERROR",
                       "holder park/resume on begin-bound xid failed")
    return _record("F391-first-park-race", "HELD",
                   "attacker first park refused coded at park time "
                   "(race eliminated); holder's begin-bound xid "
                   "parks and resumes")


# ------------------------------------------------------------------
# Wave-308 seam: the _is_coded_refusal boundary
# ------------------------------------------------------------------

def p_coded_refusal_boundary():
    # The boundary as documented: a code IS the verdict. Plain, empty,
    # and non-string codes are transient; a non-empty string code --
    # even a semantically-transient one -- is a verdict.
    from gov import workflow_saga as saga
    cases = [
        (Exception("plain"), False),
        (ValueError("no code"), False),
    ]
    e = Exception("empty")
    e.code = ""
    cases.append((e, False))
    e = Exception("int")
    e.code = 500
    cases.append((e, False))
    e = Exception("none")
    e.code = None
    cases.append((e, False))
    e = Exception("coded")
    e.code = "workflow-step-unauthorized"
    cases.append((e, True))
    bad = []
    for exc, want in cases:
        if saga._is_coded_refusal(exc) is not want:
            bad.append((getattr(exc, "code", "<absent>"), want))
    if bad:
        return _record("coded-refusal-boundary", "BREAK",
                       "boundary mismatch: %r" % (bad,))
    _record("coded-refusal-boundary", "HELD",
            "code-is-verdict boundary holds (plain/empty/int/None "
            "transient; non-empty string coded)")


def p_coded_refusal_transient_code_escalates():
    # Behavioral: a compensation op raising a coded-but-semantically-
    # transient failure escalates on the FIRST attempt (fail-closed
    # direction, documented). Op authors must not wrap transient
    # failures in codes.
    from gov import workflow_saga as saga
    sm = saga.SagaManager(authority_verifiers={"op-ref": lambda: True})
    saga.register_op("w309-cr-ok", lambda p: ({"ok": True}, []))
    saga.register_op("w309-cr-boom",
                     lambda p: (_ for _ in ()).throw(
                         RuntimeError("action boom")))
    calls = {"n": 0}

    def _coded_transient(p):
        calls["n"] += 1
        e = RuntimeError("downstream blip (coded)")
        e.code = "TRANSIENT_BLIP"
        raise e
    saga.register_op("w309-cr-coded", _coded_transient)
    definition = sm.define([
        saga.SagaStepDef(step_id="s1", action_op="w309-cr-ok",
                         action_params={},
                         compensation_op="w309-cr-coded",
                         compensation_params={}, authority_ref="op-ref"),
        saga.SagaStepDef(step_id="s2", action_op="w309-cr-boom",
                         action_params={},
                         compensation_op="w309-cr-coded",
                         compensation_params={}, authority_ref="op-ref"),
    ])
    inst = sm.start(definition)
    try:
        sm.run(inst)
    except Exception:
        pass
    if inst.status != "escalated":
        return _record("coded-refusal-transient-code-escalates", "ERROR",
                       "did not escalate; probe void")
    if calls["n"] == 1:
        return _record("coded-refusal-transient-code-escalates", "HELD",
                       "coded-but-transient failure escalated on "
                       "attempt 1 (fail-closed direction documented)")
    return _record("coded-refusal-transient-code-escalates", "BREAK",
                   "coded transient failure retried %d times"
                   % (calls["n"],))


# ------------------------------------------------------------------
# probe_lines.py soundness
# ------------------------------------------------------------------

def p_probe_lines_no_injection():
    # Notes are first-lined: an embedded newline cannot inject a fake
    # probe line.
    sys.path.insert(0, os.path.join(REPO, "evals"))
    import probe_lines
    line = probe_lines.format_line("pid1", "HELD",
                                   "note line1\n[BREAK] fake: injected")
    if "\n" in line:
        return _record("probe-lines-no-injection", "BREAK",
                       "newline survived format_line: %r" % (line,))
    if line != "[HELD] pid1: note line1":
        return _record("probe-lines-no-injection", "ERROR",
                       "unexpected rendering: %r" % (line,))
    _record("probe-lines-no-injection", "HELD",
            "notes first-lined; no probe-line injection")


def p_probe_lines_strict_parse():
    sys.path.insert(0, os.path.join(REPO, "evals"))
    import probe_lines
    if probe_lines.parse_line("  [HELD] pid1: indented") is not None:
        return _record("probe-lines-strict-parse", "BREAK",
                       "indented line parsed as canonical")
    if probe_lines.parse_line("[HELD] bad pid!: note") is not None:
        return _record("probe-lines-strict-parse", "BREAK",
                       "out-of-class pid parsed")
    if probe_lines.parse_line("[HELD] pid1: note") is None:
        return _record("probe-lines-strict-parse", "ERROR",
                       "canonical line rejected")
    _record("probe-lines-strict-parse", "HELD",
            "parser strict (column 0, pid class enforced)")


# ------------------------------------------------------------------
# Green checks (depth-1)
# ------------------------------------------------------------------

def _green_checks():
    def _rec(pid, verdict, note):
        _record(pid, verdict, note)
    if SKIP_GREEN:
        _record("green-skipped", "HELD", "green check skipped "
                "(GOV_SKIP_GREEN=1)")
        return
    # F391 CLOSED: the w308 battery's F391 probes assert the coded
    # refusal; expect no BREAKs.
    green_check.check_battery(
        _rec, "green-w308_f391", "evals/w308_f391_probes.py",
        repo=REPO, expect_break_ids=())
    # F393 CLOSED (wave-309 lane A): the w308 red-team battery's F393
    # probes now assert the coded workflow-composed-plan-mismatch refusal;
    # expect no BREAKs.
    green_check.check_battery(
        _rec, "green-w308_redteam", "evals/w308_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # Wave-308 lane B: the new-attack-rows battery reports 0 BREAKs.
    green_check.check_battery(
        _rec, "green-w308_new_attack_rows",
        "evals/w308_new_attack_rows.py", repo=REPO,
        expect_break_ids=())
    # Wave-308 lane D's own earlier battery: 0 BREAKs standalone.
    green_check.check_battery(
        _rec, "green-w307_redteam", "evals/w307_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # Wave-307 lane B negative result: 0 BREAKs.
    green_check.check_battery(
        _rec, "green-w307_saga_signal",
        "evals/w307_saga_signal_probes.py", repo=REPO,
        expect_break_ids=())
    # The w303_f384 real green check.
    green_check.check_battery(
        _rec, "green-w303_f384", "evals/w303_f384_probes.py",
        repo=REPO, expect_break_ids=())
    # F388 / F390 closure regressions.
    green_check.check_battery(
        _rec, "green-w303_f388", "evals/w303_f388_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_battery(
        _rec, "green-w303_f390", "evals/w303_f390_probes.py",
        repo=REPO, expect_break_ids=())


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F394-op-retry-composed", p_f394_op_retry_composed)
    _safe("F394-abort-composed", p_f394_abort_composed)
    _safe("F394-direct-saga-retry-works", p_f394_direct_saga_retry_works)
    _safe("F393-fn-code-confusion", p_f393_fn_code_confusion)
    _safe("F393-saga-code-confusion", p_f393_saga_code_confusion)
    _safe("F393-slip-code-confusion", p_f393_slip_code_confusion)
    _safe("F391-clone-manager-refused", p_f391_clone_manager_refused)
    _safe("F391-cross-xid-binding", p_f391_cross_xid_binding)
    _safe("F391-first-park-race", p_f391_first_park_race)
    _safe("coded-refusal-boundary", p_coded_refusal_boundary)
    _safe("coded-refusal-transient-code-escalates",
           p_coded_refusal_transient_code_escalates)
    _safe("probe-lines-no-injection", p_probe_lines_no_injection)
    _safe("probe-lines-strict-parse", p_probe_lines_strict_parse)
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
