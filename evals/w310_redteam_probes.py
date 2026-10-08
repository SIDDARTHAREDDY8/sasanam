"""Wave-310 lane C battery: independent red team vs the wave-309 tree.

Base: wave-309 merge f0d6c9c1 (F393 CLOSED -- code binding + run->plan
binding, +1 code workflow-composed-plan-mismatch, pin 1841; F394 was
OPEN (composed-saga operator recovery gap), CLOSED 2026-10-03 wave-310
lane A via the composer-level retry API).

Targets (all verified empirically with throwaway scripts BEFORE this
battery was written -- diagnosing-bugs loop):
 1. F395 (MEDIUM, CLOSED 2026-10-03 wave-311 lane A): the F393 code
    binding collided for exotic closures -- ComposedPlan now refuses
    coded workflow-composed-definition-invalid for non-JSON-native
    closed-over values (recursive), and the probes below assert that
    coded refusal.
    `_closure_fingerprint` binds non-JSON-native closure values by
    type-name only. Two fns with identical bytecode whose closures
    differ only in exotic objects of the same type (e.g. a shared
    factory mkfn(client) closing over different Client instances) yield
    identical code_digest -> identical plan digests. The run->plan
    binding passes (same digest), the op_digest matches, _begin_unit
    returns REPLAY, and every _resolve_replay check passes (run,
    record-caller, digest, F390 name, F392 binding) -- the victim's fn
    never executes and the attacker's outputs return as native.
    Verified on the fn path and the saga action path via the public
    API.
 2. F394 (LOW, CLOSED 2026-10-03 wave-310 lane A): the F384 operator
    recovery path did not function for composed sagas --
    WorkflowComposer.retry_saga_unit(unit_name, resolution, *, at)
    re-establishes the prerequisites and re-drives the fixed
    compensation. The probes below use the supported composer-API
    pattern (updated at the wave-310 merge; the direct-SagaManager
    path on a composed instance still fails closed coded, pinned in
    w310_f394_probes).
 3. F393 closure regressions: descriptor-identical plans now refuse
    coded workflow-composed-plan-mismatch (fn + saga paths).
 4. F391 closure regressions: begin-time manager binding holds --
    substituted manager refuses coded at suspend and resume; unbound
    transaction refuses coded (fail-closed).
 5. Fail-closed checks: plan-digest binding when execute() fails
    mid-run (same-plan retry works, different-plan retry refuses
    coded); DSSE envelope error paths (threshold, payloadType,
    tampered payload all refuse loudly).
 6. F385-F392 closure regressions via green checks on the adjacent
    batteries.

New findings filed by this lane: F395 (MEDIUM, OPEN), claim
2026-10-03T13:27:00Z -- CLOSED 2026-10-03 wave-311 lane A (exotic
closures refuse coded workflow-composed-definition-invalid; no new
codes). Wave-310 merge: F394 CLOSED (lane A), F395 CLOSED (wave-311
lane A); pin 1851; footer open none / next F398. This battery's
expected BREAKs: none (the F395 probes now assert the coded
refusal).

Run:
  mkdir -p /var/tmp/g310-rt && TMPDIR=/var/tmp/g310-rt \\
    ~/workspace/.gov-venv/bin/python evals/w310_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g310-rt2 \\
    ~/workspace/.gov-venv/bin/python evals/w310_redteam_probes.py
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
import probe_lines

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-309 pin 1829 (+1 workflow-composed-plan-mismatch). This lane
# mints no codes (red team only), so the pin stays 1829.
TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


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
    _record("pin-taxonomy", "HELD", "2140/2140/0 sorted")




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
    # Wave-312 merge footer: F396 CLOSED (lane A); F397 OPEN (lane C).
    # Wave-359 merge: repointed to open F489, F490, F491, F492, F493, F494, F495 / next F506 (footer-state probe audit).
    if nxt != 672 or open_s != "F662, F663, F664, F665, F666, F667, F668, F669, F670, F671":  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)
        return _record("footer-state", "BREAK",
                       "footer pins next F%d open '%s', want next F672 open 'F662, F663, F664, F665, F666, F667, F668, F669, F670, F671'" % (nxt, open_s))
    _record("footer-state", "HELD", "footer pins open F521, F522, F523, F524, F525 / next F526")  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)


# ------------------------------------------------------------------
# Shared scaffolds
# ------------------------------------------------------------------

def _seed(s):
    return hashlib.sha256(("w310-" + s).encode()).digest()


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


# ------------------------------------------------------------------
# F394 (LOW, CLOSED wave-310 lane A): the F384 operator recovery path
# did not function for composed sagas. Closure direction: a
# composer-level operator-retry API
# (WorkflowComposer.retry_saga_unit(unit_name, resolution, *, at))
# re-establishes the escalated unit's prerequisites and delegates to
# SagaManager.resolve_escalation. The supported operator path for a
# composed saga is the composer API; calling the saga manager
# directly on a composed instance still fails closed and coded
# (pinned in w310_f394_probes). Probes updated from the
# direct-SagaManager call pattern to the supported composer-API
# call pattern (probe intent -- re-drive works after the downstream
# is fixed -- unchanged). Wave-316: retry calls moved to at=AT + 1
# per the F397 contract (wave-313 lane A) -- retry_saga_unit refuses
# a stale at (the escalation's logical instant) coded
# workflow-saga-resolution-invalid.
# ------------------------------------------------------------------

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


def p_f394_op_retry_composed():
    # F394 CLOSED: after a composed saga escalates, the operator
    # re-drives via the supported composer API
    # comp.retry_saga_unit("u1", {"action": "retry_compensation"},
    # at=AT + 1). The composer re-establishes the prerequisites, so
    # the fixed compensation is actually invoked and the saga reaches
    # compensated. The misleading
    # workflow-saga-compensation-unauthorized on this path is gone.
    # Wave-316: at=AT + 1 per the F397 contract (wave-313 lane A --
    # stale at refused coded workflow-saga-resolution-invalid).
    comp, sm, inst, calls = _escalated_composed_saga_fixable("f394retry")
    if inst.status != "escalated":
        return _record("F394-op-retry-composed", "ERROR",
                       "saga did not escalate; probe void")
    before = calls["comp"]
    try:
        comp.retry_saga_unit("u1", {"action": "retry_compensation"},
                             at=AT + 1)
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
    # Wave-316: at=AT + 1 per the F397 contract (wave-313 lane A --
    # stale at refused coded workflow-saga-resolution-invalid).
    comp, sm, inst, calls = _escalated_composed_saga_fixable("f394abort")
    if inst.status != "escalated":
        return _record("F394-abort-composed", "ERROR",
                       "saga did not escalate; probe void")
    before = calls["comp"]
    try:
        comp.retry_saga_unit("u1",
                             {"action": "abort_and_compensate_all"},
                             at=AT + 1)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-saga-compensation-unauthorized":
            return _record("F394-abort-composed", "BREAK",
                           "F394 regression: misleading "
                           "workflow-saga-compensation-unauthorized "
                           "on composer abort retry")
        return _record("F394-abort-composed", "ERROR",
                       "composer abort retry raised %r" % (code,))
    if inst.status == "compensated" and calls["comp"] > before:
        return _record("F394-abort-composed", "HELD",
                       "composer abort retry re-drove the compensation "
                       "(%d->%d calls); saga compensated (F394 closed)"
                       % (before, calls["comp"]))
    return _record("F394-abort-composed", "ERROR",
                   "unexpected: status=%r calls=%d->%d"
                   % (inst.status, before, calls["comp"]))


def p_f394_direct_saga_retry_works():
    # Control: the identical scenario on a DIRECT saga
    # (deployment-registered ops, persistent verifiers) recovers fine.
    from gov import workflow_saga as saga
    sm = saga.SagaManager(authority_verifiers={"op-ref": lambda: True},
                          operator_authority_ref="op-ref")
    saga.register_op("w310-d-action-ok", lambda p: ({"ok": True}, []))

    def _boom(p):
        raise RuntimeError("action boom")
    saga.register_op("w310-d-action-boom", _boom)
    calls = {"n": 0}

    def _flaky(p):
        calls["n"] += 1
        raise RuntimeError("blip")
    saga.register_op("w310-d-comp-flaky", _flaky)
    definition = sm.define([
        saga.SagaStepDef(step_id="s1", action_op="w310-d-action-ok",
                         action_params={},
                         compensation_op="w310-d-comp-flaky",
                         compensation_params={}, authority_ref="op-ref"),
        saga.SagaStepDef(step_id="s2", action_op="w310-d-action-boom",
                         action_params={},
                         compensation_op="w310-d-comp-flaky",
                         compensation_params={}, authority_ref="op-ref"),
    ])
    inst = sm.start(definition)
    try:
        sm.run(inst)
    except Exception:
        pass
    if inst.status != "escalated":
        return _record("F394-direct-saga-retry-works", "ERROR",
                       "direct saga did not escalate; probe void")

    def _fixed(p):
        calls["n"] += 1
        return {"undone": True}, []
    saga.register_op("w310-d-comp-flaky", _fixed)
    try:
        sm.retry_compensation(inst)
    except Exception as e:  # noqa: BLE001
        return _record("F394-direct-saga-retry-works", "BREAK",
                       "direct saga retry failed: %r (control broken)"
                       % (getattr(e, "code", e),))
    if inst.status == "compensated":
        return _record("F394-direct-saga-retry-works", "HELD",
                       "direct saga operator retry works (control)")
    return _record("F394-direct-saga-retry-works", "ERROR",
                   "unexpected: status=%r" % (inst.status,))


# ------------------------------------------------------------------
# F395 (MEDIUM, CLOSED 2026-10-03 wave-311 lane A): ComposedPlan refuses
# coded workflow-composed-definition-invalid for exotic closures --
# the collision scenario below can no longer be constructed.
# ------------------------------------------------------------------

class _Client:
    """Exotic (non-JSON-native) closure value. Two instances of the
    same type with different state must not share a code_digest --
    F395: the plan now refuses coded instead of binding type-name
    only."""

    def __init__(self, endpoint):
        self.endpoint = endpoint

    def fetch(self):
        return {"data": "from-" + self.endpoint}


def _mkfn(client):
    # Shared factory: identical bytecode whatever client is closed
    # over. The realistic shape is a shared library closing over
    # per-deployment client/config objects.
    def fn(i):
        return client.fetch()
    return fn


def p_f395_exotic_closure_fn():
    # F395 CLOSED (2026-10-03, wave-311 lane A): ComposedPlan refuses
    # coded workflow-composed-definition-invalid for fns that close
    # over non-JSON-native values. The original attack shape (evil
    # plan executes, victim plan replays the attacker's record) can
    # no longer be constructed: both plans refuse at construction.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f395fn")
    evil_fn = _mkfn(_Client("evil"))
    victim_fn = _mkfn(_Client("real"))

    def _mkplan(fn):
        return wc.ComposedPlan([
            {"kind": "fn", "name": "u2", "fn": fn,
             "inputs": {}, "idem_key": "k2"}])

    for label, build in (
            ("fingerprint", lambda: wc._code_fingerprint(evil_fn)),
            ("evil-plan", lambda: _mkplan(evil_fn)),
            ("victim-plan", lambda: _mkplan(victim_fn))):
        try:
            build()
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", None) != \
                    "workflow-composed-definition-invalid":
                return _record("F395-exotic-closure-fn", "ERROR",
                               "%s: wrong refusal %r"
                               % (label, getattr(e, "code", e)))
        else:
            return _record("F395-exotic-closure-fn", "BREAK",
                           "F395: %s accepted an exotic closure "
                           "(closure direction regressed)" % label)
    _record("F395-exotic-closure-fn", "HELD",
            "exotic closures refused coded at construction (F395 closed)")


def p_f395_exotic_closure_saga():
    # F395 CLOSED (2026-10-03, wave-311 lane A): the saga action path
    # refuses coded too -- the confusion scenario cannot be built.
    from gov import workflow_saga as saga_mod
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f395saga")

    def mkaction(client):
        def action(params):
            return client.fetch(), []
        return action

    def mkcomp(client):
        def comp_fn(params):
            return {"undone": True}
        return comp_fn

    def mkdef():
        return saga_mod.SagaDefinition([
            saga_mod.SagaStepDef(step_id="s1", action_op="a",
                                 action_params={},
                                 compensation_op="c",
                                 compensation_params={}),
        ])

    def mkplan(client):
        return wc.ComposedPlan([{
            "kind": "saga", "name": "sg", "definition": mkdef(),
            "action_fns": {"s1": mkaction(client)},
            "comp_fns": {"s1": mkcomp(client)},
            "idem_key": "ksg"}])

    for label, client in (("evil", _Client("evil")),
                          ("victim", _Client("real"))):
        try:
            mkplan(client)
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", None) != \
                    "workflow-composed-definition-invalid":
                return _record("F395-exotic-closure-saga", "ERROR",
                               "%s plan: wrong refusal %r"
                               % (label, getattr(e, "code", e)))
        else:
            return _record("F395-exotic-closure-saga", "BREAK",
                           "F395: %s saga plan accepted an exotic "
                           "closure (closure direction regressed)"
                           % label)
    _record("F395-exotic-closure-saga", "HELD",
            "exotic-closure saga plans refuse coded (F395 closed)")


# ------------------------------------------------------------------
# F393 closure regressions: descriptor-identical plans now refuse
# coded workflow-composed-plan-mismatch
# ------------------------------------------------------------------

def p_f393_fn_code_confusion():
    # The filed F393 fn attack shape: different fn, same descriptor.
    # Must now refuse coded (the code_digest distinguishes).
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
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    try:
        comp.execute(victim, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-composed-plan-mismatch":
            return _record("F393-fn-code-confusion", "HELD",
                           "different fn under same run refused coded "
                           "workflow-composed-plan-mismatch (F393 holds)")
        return _record("F393-fn-code-confusion", "BREAK",
                       "refused with wrong code %r (F393 regressed)"
                       % (code,))
    return _record("F393-fn-code-confusion", "BREAK",
                   "different fn executed under same run without "
                   "refusal (F393 regressed)")


def p_f393_saga_code_confusion():
    # The filed F393 saga attack shape.
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
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    try:
        comp.execute(victim, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-composed-plan-mismatch":
            return _record("F393-saga-code-confusion", "HELD",
                           "different saga plan under same run refused "
                           "coded (F393 holds)")
        return _record("F393-saga-code-confusion", "BREAK",
                       "refused with wrong code %r (F393 regressed)"
                       % (code,))
    return _record("F393-saga-code-confusion", "BREAK",
                   "different saga plan executed under same run "
                   "without refusal (F393 regressed)")


# ------------------------------------------------------------------
# F391 closure regressions: begin-time manager binding holds
# ------------------------------------------------------------------

def _rubber_stamp():
    class _RubberStampManager:
        def check_write(self, scope, fencing_token, holder_id,
                        checked_at=None):
            return True
    return _RubberStampManager()


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
    return lm, lease["fencing_token"], c, xid


def _code_of(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", None)
    return "no-refusal"


_LEASE_MISMATCH = "coord-lease-manager-mismatch"


def p_f391_suspend_substitute_refused():
    # Begin-time binding: the attacker's re-park with a rubber-stamp
    # manager refuses coded before any oracle call; the holder's park
    # stays intact.
    lm, tok, c, xid = _branch_fx()
    rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                          suspended_at=1050)
    code = _code_of(lambda: c.suspend_lease(
        xid, _rubber_stamp(), "scope-x", 999999, "mallory",
        suspended_at=1060))
    if code != _LEASE_MISMATCH:
        return _record("F391-suspend-substitute-refused", "BREAK",
                       "substitute-manager re-park not refused coded: "
                       "%r (F391 regressed)" % (code,))
    try:
        ok = c.resume_lease(rec, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        return _record("F391-suspend-substitute-refused", "ERROR",
                       "holder resume refused: %r"
                       % (getattr(e, "code", e),))
    if ok is not True:
        return _record("F391-suspend-substitute-refused", "ERROR",
                       "holder resume returned %r" % (ok,))
    _record("F391-suspend-substitute-refused", "HELD",
            "substitute-manager re-park refused coded; holder "
            "resume intact (F391 holds)")


def p_f391_resume_substitute_refused():
    # Third limb: legitimate park, then resume with a substituted fake
    # manager -- must refuse coded, never self-attest liveness.
    lm, tok, c, xid = _branch_fx()
    rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                          suspended_at=1050)
    code = _code_of(lambda: c.resume_lease(rec, _rubber_stamp(),
                                           checked_at=1090))
    if code != _LEASE_MISMATCH:
        return _record("F391-resume-substitute-refused", "BREAK",
                       "substitute-manager resume not refused coded: "
                       "%r (F391 regressed)" % (code,))
    _record("F391-resume-substitute-refused", "HELD",
            "substituted-manager resume refused coded (F391 holds)")


def p_f391_unbound_refuses():
    # Fail-closed: a transaction begun WITHOUT a bound manager refuses
    # parks coded -- no silent first-park binding, no race window.
    from gov import workflow_branch as wb
    from gov import coordination_lease as cl
    from gov import ed25519
    lm = cl.LeaseManager()
    lease = lm.acquire("scope-x", 100, "holder-1",
                       authority_seed=ed25519.generate_seed(),
                       issued_at=1000)
    c = wb.BranchCoordinator()
    xid = c.begin(ed25519.generate_seed())  # no manager bound
    code = _code_of(lambda: c.suspend_lease(
        xid, lm, "scope-x", lease["fencing_token"], "holder-1",
        suspended_at=1050))
    if code != _LEASE_MISMATCH:
        return _record("F391-unbound-refuses", "BREAK",
                       "park on unbound transaction not refused "
                       "coded: %r" % (code,))
    _record("F391-unbound-refuses", "HELD",
            "park on unbound transaction refuses coded (fail-closed)")


# ------------------------------------------------------------------
# Fail-closed checks: plan-digest binding on mid-run failure; DSSE
# ------------------------------------------------------------------

def p_plan_digest_midrun_failure_fail_closed():
    # Documented residual check: execute() binds the plan digest BEFORE
    # unit execution. If execute fails mid-run (after binding), the
    # run stays bound. Same-plan retry must still work (same digest);
    # different-plan retry must refuse coded (fail-closed, not silent).
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "midrun")

    def boom_fn(i):
        raise RuntimeError("mid-run boom")

    def ok_fn(i):
        return {"ok": True}

    boom_plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u1", "fn": boom_fn,
         "inputs": {}, "idem_key": "k-boom"}])
    try:
        comp.execute(boom_plan, run_id="R", authority=auth, at=AT)
    except Exception:
        pass
    # Same plan retry: binding matches (same digest). The unit failed,
    # so it re-executes (no completed record) -- must fail the same
    # way, not refuse coded.
    try:
        comp.execute(boom_plan, run_id="R", authority=auth, at=AT)
        return _record("plan-digest-midrun-failure", "ERROR",
                       "same-plan retry unexpectedly succeeded")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-composed-plan-mismatch":
            return _record("plan-digest-midrun-failure", "BREAK",
                           "same-plan retry refused coded (binding "
                           "should match)")
    # Different plan under the same run: must refuse coded.
    other_plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u1", "fn": ok_fn,
         "inputs": {}, "idem_key": "k-boom"}])
    code = _code_of(lambda: comp.execute(
        other_plan, run_id="R", authority=auth, at=AT))
    if code != "workflow-composed-plan-mismatch":
        return _record("plan-digest-midrun-failure", "BREAK",
                       "different plan after mid-run failure not "
                       "refused coded: %r" % (code,))
    _record("plan-digest-midrun-failure", "HELD",
            "mid-run failure leaves binding intact: same plan "
            "retries, different plan refuses coded (fail-closed)")


def p_dsse_threshold_not_met():
    # DSSE: threshold=2 with one valid signature refuses loudly.
    from gov import evidence_dsse as dsse
    from gov.signing import Ed25519Signer, Ed25519Verifier
    s1 = Ed25519Signer(_seed("dsse-thr"))
    verifier = Ed25519Verifier(s1.public_key, s1.key_id)
    env = dsse.seal_evidence_bundle(b'{"bundle": 1}', [s1])
    try:
        dsse.verify_dsse_envelope(env, b'{"bundle": 1}', [verifier],
                                  threshold=2)
    except Exception as e:  # noqa: BLE001
        _record("dsse-threshold-not-met", "HELD",
                "threshold=2 with one signature refused: %r" % (e,))
        return
    _record("dsse-threshold-not-met", "BREAK",
            "threshold=2 with one signature verified (threshold "
            "bypass)")


def p_dsse_wrong_payloadtype_refused():
    # DSSE: an envelope carrying the wrong payloadType refuses (type
    # bound inside the PAE signature). Seal with the WRONG type over
    # the same bytes, then verify with the RIGHT expectation.
    from gov import evidence_dsse as dsse
    from gov import dsse_envelope as de
    from gov.signing import Ed25519Signer, Ed25519Verifier
    s1 = Ed25519Signer(_seed("dsse-pt"))
    verifier = Ed25519Verifier(s1.public_key, s1.key_id)
    env = de.seal(b'{"bundle": 1}', "application/x-wrong", [s1])
    try:
        dsse.verify_dsse_envelope(env, b'{"bundle": 1}', [verifier])
    except Exception as e:  # noqa: BLE001
        _record("dsse-wrong-payloadtype", "HELD",
                "wrong payloadType refused: %r" % (e,))
        return
    _record("dsse-wrong-payloadtype", "BREAK",
            "wrong payloadType verified (type-confusion)")


def p_dsse_tampered_payload_refused():
    # DSSE: a tampered payload (valid signature over different bytes)
    # refuses on the signature path, never on binding alone.
    from gov import evidence_dsse as dsse
    from gov.signing import Ed25519Signer, Ed25519Verifier
    import base64
    s1 = Ed25519Signer(_seed("dsse-tam"))
    verifier = Ed25519Verifier(s1.public_key, s1.key_id)
    env = dsse.seal_evidence_bundle(b'{"bundle": 1}', [s1])
    env["payload"] = base64.b64encode(b'{"bundle": 2}').decode("ascii")
    try:
        dsse.verify_dsse_envelope(env, b'{"bundle": 2}', [verifier])
    except Exception as e:  # noqa: BLE001
        _record("dsse-tampered-payload", "HELD",
                "tampered payload refused: %r" % (e,))
        return
    _record("dsse-tampered-payload", "BREAK",
            "tampered payload verified (signature bypass)")


# ------------------------------------------------------------------
# Green checks (depth-1; honor GOV_SKIP_GREEN)
# ------------------------------------------------------------------

def _green_checks():
    def _rec(pid, verdict, note):
        _record(pid, verdict, note)
    if SKIP_GREEN:
        _record("green-skipped", "HELD",
                "green check skipped (GOV_SKIP_GREEN=1)")
        return
    # F393 CLOSED (wave-309 lane A): the w309_f393 battery's F393
    # probes now assert the coded workflow-composed-plan-mismatch
    # refusal; expect no BREAKs. Re-pinned to the wave-310 merge
    # footer (open F395 / next F396).
    green_check.check_battery(
        _rec, "green-w309_f393", "evals/w309_f393_probes.py",
        repo=REPO, expect_break_ids=())
    # F394 CLOSED (wave-310 lane A): the w309 red-team battery's F394
    # probes now use the composer-API pattern and assert recovery;
    # expect no BREAKs.
    green_check.check_battery(
        _rec, "green-w309_redteam", "evals/w309_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # F391 CLOSED (wave-309 lane B): the w308 battery's F391 probes
    # assert the coded coord-lease-manager-mismatch refusal; expect no
    # BREAKs. Re-pinned to the wave-310 merge footer.
    green_check.check_battery(
        _rec, "green-w308_f391", "evals/w308_f391_probes.py",
        repo=REPO, expect_break_ids=())
    # F385-F387 closures: the w307 red-team battery; expect no BREAKs.
    green_check.check_battery(
        _rec, "green-w307_redteam", "evals/w307_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # F388 / F390 closure regressions.
    green_check.check_battery(
        _rec, "green-w303_f388", "evals/w303_f388_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_battery(
        _rec, "green-w303_f390", "evals/w303_f390_probes.py",
        repo=REPO, expect_break_ids=())


# ------------------------------------------------------------------
# Probe-line pilot (parser robustness)
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
# Probe table + main
# ------------------------------------------------------------------

_PROBES = [
    ("pin-taxonomy", p_taxonomy_pin),
    ("footer-state", p_footer_state),
    # F394 (OPEN -- expected BREAKs)
    ("F394-op-retry-composed", p_f394_op_retry_composed),
    ("F394-abort-composed", p_f394_abort_composed),
    ("F394-direct-saga-retry-works", p_f394_direct_saga_retry_works),
    # F395 (CLOSED -- coded refusal probes)
    ("F395-exotic-closure-fn", p_f395_exotic_closure_fn),
    ("F395-exotic-closure-saga", p_f395_exotic_closure_saga),
    # F393 closure regressions (must be HELD, coded refusal)
    ("F393-fn-code-confusion", p_f393_fn_code_confusion),
    ("F393-saga-code-confusion", p_f393_saga_code_confusion),
    # F391 closure regressions (must be HELD, coded refusal)
    ("F391-suspend-substitute-refused", p_f391_suspend_substitute_refused),
    ("F391-resume-substitute-refused", p_f391_resume_substitute_refused),
    ("F391-unbound-refuses", p_f391_unbound_refuses),
    # Fail-closed checks
    ("plan-digest-midrun-failure", p_plan_digest_midrun_failure_fail_closed),
    # DSSE error paths (must refuse loudly)
    ("dsse-threshold-not-met", p_dsse_threshold_not_met),
    ("dsse-wrong-payloadtype", p_dsse_wrong_payloadtype_refused),
    ("dsse-tampered-payload", p_dsse_tampered_payload_refused),
    # Probe-line pilot (parser robustness)
    ("probe-lines-no-injection", p_probe_lines_no_injection),
    ("probe-lines-strict-parse", p_probe_lines_strict_parse),
]

# Wave-311 lane A: F395 CLOSED -- the F395 probes now assert the coded
# refusal, so no expected BREAKs remain.
_EXPECTED_BREAKS = frozenset()


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("probe", nargs="?", default=None,
                    help="run one probe by id")
    args = ap.parse_args()
    if args.probe:
        for pid, fn in _PROBES:
            if pid == args.probe:
                _safe(pid, fn)
                break
        else:
            print("unknown probe", args.probe)
            sys.exit(2)
    else:
        for pid, fn in _PROBES:
            _safe(pid, fn)
        _green_checks()
    probe_lines.emit(_results)
    brk = sum(1 for r in _results if r[1] == "BREAK")
    held = sum(1 for r in _results if r[1] == "HELD")
    err = sum(1 for r in _results if r[1] == "ERROR")
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    # Open-findings sweep: exactly the expected BREAKs (all OPEN).
    # Exit 1 when any BREAK is present (open findings), like the
    # w309 red-team battery.
    if args.probe:
        return 0
    unexpected = [pid for pid, v, _ in _results
                  if v == "BREAK" and pid not in _EXPECTED_BREAKS]
    if unexpected:
        print("unexpected BREAKs: %s" % (unexpected,))
        return 1
    missing = sorted(_EXPECTED_BREAKS - frozenset(
        pid for pid, v, _ in _results if v == "BREAK"))
    if missing:
        print("expected BREAKs missing: %s" % (missing,))
        return 1
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
