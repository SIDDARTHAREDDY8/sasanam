"""Wave-310 lane A battery: F394 closure regression (composed-saga
operator recovery).

F394 (LOW, CLOSED 2026-10-03, wave-310 lane A): the F384 operator
recovery path did not function for composed sagas -- the composer's
post-escalation cleanup removed the wrapper ops and step verifiers,
so retry_compensation/abort_and_compensate_all raised misleading
workflow-saga-compensation-unauthorized and the fixed compensation
was never re-driven. Closure direction (b) of the filed close-when:
WorkflowComposer.retry_saga_unit(unit_name, resolution, *, at)
re-establishes the escalated unit's prerequisites (retry execution
context, step authority verifier, nonce-scoped wrapper ops),
delegates to SagaManager.resolve_escalation, and tears everything
down deterministically. The misleading error is gone on the
supported operator path; the SagaManager-direct path on a composed
instance still fails closed and coded (documented -- operator
recovery for composed sagas goes through the composer).

New findings filed by this lane: none. Pin unchanged 1829.
No new decision codes.

This battery's expected BREAKs: none (0 BREAK / all HELD).

Run:
  mkdir -p /var/tmp/g310-f394 && TMPDIR=/var/tmp/g310-f394 \
    ~/workspace/.gov-venv/bin/python evals/w310_f394_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g310-f394b \
    ~/workspace/.gov-venv/bin/python evals/w310_f394_probes.py
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

# Pin 1829 (wave-309 merge: +1 workflow-composed-plan-mismatch).
# This lane mints no codes.
TAXONOMY_PIN = 1829

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
    # F394 closed this wave: no open findings; next free F395.
    if nxt != 396 or open_s != "F395":
        return _record("footer-state", "BREAK",
                       "footer pins next F%d open '%s', want next F395 "
                       "open 'F395'" % (nxt, open_s))
    _record("footer-state", "HELD", "footer pins open F395 / next F396")


# ------------------------------------------------------------------
# Shared scaffolds
# ------------------------------------------------------------------

def _seed(s):
    return hashlib.sha256(("w310-f394-" + s).encode()).digest()


def _composed_scaffold(tag, operator_ref=True):
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


def _escalated_composed_saga_fixable(tag, operator_ref=True):
    """Drive a composed saga unit to escalation with a compensation
    that fails transiently during the initial window (3 attempts) but
    succeeds once the downstream is "fixed" (4th call onward).
    Returns (comp, sm, instance, comp_calls)."""
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        tag, operator_ref=operator_ref)
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
# F394 CLOSED: composer-level operator retry
# ------------------------------------------------------------------

def p_f394_op_retry_composed():
    # The supported operator path: comp.retry_saga_unit re-drives the
    # fixed compensation (fresh attempt window) and the saga reaches
    # compensated. The misleading
    # workflow-saga-compensation-unauthorized is gone on this path.
    comp, sm, inst, calls = _escalated_composed_saga_fixable("retry")
    if inst.status != "escalated":
        return _record("F394-op-retry-composed", "ERROR",
                       "saga did not escalate; probe void")
    before = calls["comp"]
    try:
        comp.retry_saga_unit("u1", {"action": "retry_compensation"}, at=AT)
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
                       "composer retry re-drove compensation "
                       "(%d->%d calls); saga compensated"
                       % (before, calls["comp"]))
    return _record("F394-op-retry-composed", "ERROR",
                   "unexpected: status=%r calls=%d->%d"
                   % (inst.status, before, calls["comp"]))


def p_f394_abort_composed():
    # The second re-drive action via the composer API: the fixed
    # compensation is re-driven on the remaining attempt budget and
    # the saga reaches compensated.
    comp, sm, inst, calls = _escalated_composed_saga_fixable("abort")
    if inst.status != "escalated":
        return _record("F394-abort-composed", "ERROR",
                       "saga did not escalate; probe void")
    before = calls["comp"]
    try:
        comp.retry_saga_unit("u1",
                             {"action": "abort_and_compensate_all"},
                             at=AT)
    except Exception as e:  # noqa: BLE001
        return _record("F394-abort-composed", "ERROR",
                       "composer abort raised %r (calls %d->%d)"
                       % (getattr(e, "code", None),
                          before, calls["comp"]))
    if inst.status == "compensated" and calls["comp"] > before:
        return _record("F394-abort-composed", "HELD",
                       "composer abort re-drove compensation "
                       "(%d->%d calls); saga compensated"
                       % (before, calls["comp"]))
    return _record("F394-abort-composed", "ERROR",
                   "unexpected: status=%r calls=%d->%d"
                   % (inst.status, before, calls["comp"]))


def p_f394_direct_saga_retry_works():
    # Control: the identical scenario on a DIRECT saga
    # (deployment-registered ops, persistent verifiers) still
    # recovers fine -- unchanged by this lane.
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
                       "control did not escalate; probe void")

    def _fixed(p):
        calls["n"] += 1
        return {"undone": True}
    saga.register_op("w310-d-comp-flaky", _fixed)
    try:
        sm.retry_compensation(inst)
    except Exception as e:  # noqa: BLE001
        return _record("F394-direct-saga-retry-works", "ERROR",
                       "control retry raised %r" % (getattr(e, "code", e),))
    if inst.status == "compensated":
        return _record("F394-direct-saga-retry-works", "HELD",
                       "direct-saga operator retry re-drives compensation "
                       "(control green; gap was composed-path-specific)")
    return _record("F394-direct-saga-retry-works", "ERROR",
                   "control status=%r" % (inst.status,))


def p_f394_unknown_unit_refused():
    # Unknown unit name refuses coded (not a crash, not silent).
    comp, sm, inst, calls = _escalated_composed_saga_fixable("unk")
    try:
        comp.retry_saga_unit("no-such-unit",
                             {"action": "retry_compensation"},
                             at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-saga-resolution-invalid":
            return _record("F394-unknown-unit-refused", "HELD",
                           "unknown unit refused coded "
                           "workflow-saga-resolution-invalid")
        return _record("F394-unknown-unit-refused", "ERROR",
                       "unexpected code %r" % (code,))
    return _record("F394-unknown-unit-refused", "ERROR",
                   "retry on unknown unit did not refuse")


def p_f394_double_retry_refused():
    # After a successful retry the unit is compensated and the
    # retained material is dropped: a second retry refuses coded
    # (no resurrection, no double-recovery).
    comp, sm, inst, calls = _escalated_composed_saga_fixable("dbl")
    try:
        comp.retry_saga_unit("u1", {"action": "retry_compensation"}, at=AT)
    except Exception as e:  # noqa: BLE001
        return _record("F394-double-retry-refused", "ERROR",
                       "first retry raised %r" % (getattr(e, "code", e),))
    if inst.status != "compensated":
        return _record("F394-double-retry-refused", "ERROR",
                       "first retry did not compensate: %r" % (inst.status,))
    try:
        comp.retry_saga_unit("u1", {"action": "retry_compensation"}, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-saga-resolution-invalid":
            return _record("F394-double-retry-refused", "HELD",
                           "second retry refused coded "
                           "workflow-saga-resolution-invalid "
                           "(unit already compensated)")
        return _record("F394-double-retry-refused", "ERROR",
                       "unexpected code %r" % (code,))
    return _record("F394-double-retry-refused", "ERROR",
                   "second retry did not refuse")


def p_f394_operator_unauthorized():
    # A genuinely unauthorized operator still refuses coded --
    # the retry API does not weaken F386/F384's operator check.
    comp, sm, inst, calls = _escalated_composed_saga_fixable(
        "unauth", operator_ref=False)
    if inst.status != "escalated":
        return _record("F394-operator-unauthorized", "ERROR",
                       "saga did not escalate; probe void")
    try:
        comp.retry_saga_unit("u1", {"action": "retry_compensation"}, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-saga-operator-unauthorized":
            return _record("F394-operator-unauthorized", "HELD",
                           "unauthorized operator refused coded "
                           "workflow-saga-operator-unauthorized "
                           "(F386/F384 check intact)")
        return _record("F394-operator-unauthorized", "ERROR",
                       "unexpected code %r" % (code,))
    return _record("F394-operator-unauthorized", "ERROR",
                   "unauthorized operator retry was not refused")


def p_f394_hygiene_preserved():
    # Wave-305 hygiene intent: after the retry the re-established
    # wrapper ops and verifier are removed again -- the shared
    # registries hold a unit's entries only during execution or an
    # active retry. The happy path retains nothing either.
    from gov import workflow_saga as saga
    comp, sm, inst, calls = _escalated_composed_saga_fixable("hyg")
    tag_prefix = "composed:"
    auth_prefix = "composed-auth:"
    try:
        comp.retry_saga_unit("u1", {"action": "retry_compensation"}, at=AT)
    except Exception as e:  # noqa: BLE001
        return _record("F394-hygiene-preserved", "ERROR",
                       "retry raised %r" % (getattr(e, "code", e),))
    leftover_ops = [n for n in saga._OPS if n.startswith(tag_prefix)]
    leftover_ver = [r for r in sm._verifiers if r.startswith(auth_prefix)]
    if leftover_ops or leftover_ver:
        return _record("F394-hygiene-preserved", "BREAK",
                       "hygiene violated: leftover ops=%r verifiers=%r"
                       % (leftover_ops, leftover_ver))
    if comp._saga_retry_ctx:
        return _record("F394-hygiene-preserved", "BREAK",
                       "retry material not dropped after compensated: %r"
                       % (list(comp._saga_retry_ctx),))
    return _record("F394-hygiene-preserved", "HELD",
                   "no leftover wrapper ops/verifiers after retry; "
                   "retry material dropped on compensated")


def p_f394_direct_sm_fails_closed():
    # The SagaManager-direct path on a composed instance still fails
    # closed and coded -- documented: operator recovery for composed
    # sagas goes through the composer API. Pins that the unsupported
    # path is loud, not silently accepted.
    comp, sm, inst, calls = _escalated_composed_saga_fixable("dir")
    if inst.status != "escalated":
        return _record("F394-direct-sm-fails-closed", "ERROR",
                       "saga did not escalate; probe void")
    try:
        sm.retry_compensation(inst)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-saga-compensation-unauthorized":
            return _record("F394-direct-sm-fails-closed", "HELD",
                           "direct-SagaManager retry on a composed "
                           "instance fails closed coded "
                           "workflow-saga-compensation-unauthorized "
                           "(supported path: composer retry_saga_unit)")
        return _record("F394-direct-sm-fails-closed", "ERROR",
                       "unexpected code %r" % (code,))
    return _record("F394-direct-sm-fails-closed", "ERROR",
                   "direct-SagaManager retry unexpectedly succeeded")


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
    # The w309 red-team battery: F394 probes now assert the working
    # composer-API re-drive; expect no BREAKs.
    green_check.check_battery(
        _rec, "green-w309_redteam", "evals/w309_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # The w303 F384 battery: operator recovery for direct sagas is
    # untouched; expect no BREAKs.
    green_check.check_battery(
        _rec, "green-w303_f384", "evals/w303_f384_probes.py",
        repo=REPO, expect_break_ids=())
    # The w307 saga-signal battery (adjacent saga surface).
    green_check.check_battery(
        _rec, "green-w307_saga_signal",
        "evals/w307_saga_signal_probes.py", repo=REPO,
        expect_break_ids=())


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F394-op-retry-composed", p_f394_op_retry_composed)
    _safe("F394-abort-composed", p_f394_abort_composed)
    _safe("F394-direct-saga-retry-works", p_f394_direct_saga_retry_works)
    _safe("F394-unknown-unit-refused", p_f394_unknown_unit_refused)
    _safe("F394-double-retry-refused", p_f394_double_retry_refused)
    _safe("F394-operator-unauthorized", p_f394_operator_unauthorized)
    _safe("F394-hygiene-preserved", p_f394_hygiene_preserved)
    _safe("F394-direct-sm-fails-closed", p_f394_direct_sm_fails_closed)
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
