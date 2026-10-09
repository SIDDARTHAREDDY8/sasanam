"""Wave-313 lane A: F397 closure battery.

F397 (LOW, CLOSED 2026-10-03 wave-313 lane A):
``WorkflowComposer.retry_saga_unit`` accepted a stale ``at`` -- the
step authority was re-verified at a caller-chosen past instant,
resurrecting an expired delegation for the compensation re-drive.

Fix: the composer retains the escalation's logical instant
(``escalated_at``) in the ``_saga_retry_ctx`` material and refuses
coded ``workflow-saga-resolution-invalid`` when the caller's ``at``
is not strictly after it. The retry is causally after the
escalation, so a retry instant at or before the escalation (replayed
execution instant, ``at=0``, ...) is a stale clock claim. No wall
clock is introduced; no new decision code (pin stays 1851).

Expected counts: 13 probes -- 0 BREAK / 13 HELD / 0 ERROR direct
probes. A full standalone run adds 4 depth-1 green checks (17 lines:
0/17/0); under GOV_SKIP_GREEN=1 the checks are replaced by one
green-skipped HELD line (14 lines: 0/14/0).

Run:
  mkdir -p /var/tmp/g313-f397 && TMPDIR=/var/tmp/g313-f397 \\
    ~/workspace/.gov-venv/bin/python evals/w313_f397_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g313-f397b \\
    ~/workspace/.gov-venv/bin/python evals/w313_f397_probes.py
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

# Pin 1851. This lane mints no decision codes (the fix is an `at`
# monotonicity bound refusing the existing
# workflow-saga-resolution-invalid), so the pin stays 1851.
TAXONOMY_PIN = 2144  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144


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
    _record("pin-taxonomy", "HELD", "2144/2144/0 sorted")  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144




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
    # Wave-359 merge: repointed to open F489, F490, F491, F492, F493, F494, F495 / next F506 (footer-state probe audit).
    if nxt != 672 or open_s != "F662, F663, F664, F665, F666, F667, F669, F670, F671":  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-379 lane 6: F668 CLOSED (lane-local)
        return _record("footer-state", "BREAK",
                       "footer pins next F%d open '%s', want next F672 open 'F662, F663, F664, F665, F666, F667, F669, F670, F671'" % (nxt, open_s))  # Wave-379 lane 6: F668 CLOSED (lane-local)
    _record("footer-state", "HELD",
            "footer pins open F662, F663, F664, F665, F666, F667, F669, F670, F671 / next F672")  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-379 lane 6: F668 CLOSED (lane-local)


# ------------------------------------------------------------------
# Shared scaffolds (adapted from evals/w312_redteam_probes.py)
# ------------------------------------------------------------------

def _seed(s):
    return hashlib.sha256(("w313-" + s).encode()).digest()


def _f397_scaffold(tag, ttl):
    """Composed scaffold with a time-boxed delegation: issued_at=AT,
    expires_at=AT+ttl. Returns (comp, saga_mod, auth, ledger, root)."""
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    from gov import workflow_composed as wc
    from gov import delegation as dg
    from gov import ed25519
    from gov import delegation_revocation as rv
    sa, sb = _seed(tag + "-a"), _seed(tag + "-b")
    pa, pb = ed25519.publickey(sa).hex(), ed25519.publickey(sb).hex()
    root = dg.issue(sa, "agent-a", "agent-b", pb, ("tool.invoke",),
                    issued_at=AT,
                    constraints={"expires_at": AT + ttl, "max_depth": 4,
                                 "allowed_targets": ["agent-b"]})
    ledger = rv.DelegationRevoker(sa, "agent-a")
    auth = {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": [root], "trust_roots": [pa],
            "revocation_ledger": ledger}
    ws = wf.WorkflowStore()
    sm = saga.SagaManager(
        authority_verifiers={"op-ref": lambda: True},
        operator_authority_ref="op-ref")
    im = idem.IdempotencyStore()
    comp = wc.WorkflowComposer(ws, sm, im)
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    return comp, saga, auth, ledger, root


def _f397_escalated(tag, ttl=3600):
    """Drive a composed saga unit to escalation under the time-boxed
    delegation; compensation fails transiently (3 attempts) then the
    downstream is "fixed". Returns (comp, inst, calls, escalated_at)."""
    from gov import workflow_composed as wc
    comp, saga_mod, auth, ledger, root = _f397_scaffold(tag, ttl)
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

    definition = saga_mod.SagaDefinition([
        saga_mod.SagaStepDef(step_id="s1", action_op="a1", action_params={},
                             compensation_op="c1", compensation_params={}),
        saga_mod.SagaStepDef(step_id="s2", action_op="a2", action_params={},
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
    mat = comp._saga_retry_ctx.get("u1", {})
    return comp, inst, calls, mat.get("escalated_at"), ledger, root


def _code_of(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", None)
    return "no-refusal"


# ------------------------------------------------------------------
# F397 closure probes
# ------------------------------------------------------------------

def p_f397_stale_at_retry():
    # The demonstrated break: retry with the stale execution instant
    # (at=AT, the escalation's logical instant) must now refuse coded
    # instead of re-driving the compensation under the expired
    # delegation.
    comp, inst, calls, esc_at, _ledger, _root = _f397_escalated("r1")
    if inst.status != "escalated":
        return _record("F397-stale-at-retry", "ERROR",
                       "saga did not escalate; probe void")
    if esc_at != AT:
        return _record("F397-stale-at-retry", "ERROR",
                       "retained escalation instant %r, want AT=%d"
                       % (esc_at, AT))
    before = calls["comp"]
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=AT))
    if code != "workflow-saga-resolution-invalid":
        return _record("F397-stale-at-retry",
                       "BREAK" if code == "no-refusal" else "ERROR",
                       "stale at=AT not refused coded: code=%r "
                       "calls=%d->%d status=%r"
                       % (code, before, calls["comp"], inst.status))
    if calls["comp"] != before or inst.status != "escalated":
        return _record("F397-stale-at-retry", "ERROR",
                       "refused but side effects observed: calls %d->%d "
                       "status %r" % (before, calls["comp"], inst.status))
    _record("F397-stale-at-retry", "HELD",
            "stale at=AT refused coded "
            "workflow-saga-resolution-invalid; saga still escalated")


def p_f397_stale_at_zero():
    # Extreme stale: at=0 (before the delegation even existed).
    comp, inst, calls, _esc, _ledger, _root = _f397_escalated("r2")
    if inst.status != "escalated":
        return _record("F397-stale-at-zero", "ERROR",
                       "saga did not escalate; probe void")
    before = calls["comp"]
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=0))
    if code != "workflow-saga-resolution-invalid":
        return _record("F397-stale-at-zero",
                       "BREAK" if code == "no-refusal" else "ERROR",
                       "at=0 not refused coded: code=%r calls=%d->%d"
                       % (code, before, calls["comp"]))
    _record("F397-stale-at-zero", "HELD",
            "at=0 refused coded workflow-saga-resolution-invalid")


def p_f397_stale_at_just_before():
    # Boundary: one tick before the escalation instant is still stale.
    comp, inst, calls, esc_at, _ledger, _root = _f397_escalated("r3")
    if inst.status != "escalated":
        return _record("F397-stale-at-just-before", "ERROR",
                       "saga did not escalate; probe void")
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=esc_at - 1))
    if code != "workflow-saga-resolution-invalid":
        return _record("F397-stale-at-just-before",
                       "BREAK" if code == "no-refusal" else "ERROR",
                       "at=escalated_at-1 not refused coded: code=%r"
                       % (code,))
    _record("F397-stale-at-just-before", "HELD",
            "at=escalated_at-1 refused coded "
            "workflow-saga-resolution-invalid")


def p_f397_stale_at_negative():
    # Malformed `at` still refuses coded (existing shape check).
    comp, inst, _calls, _esc, _ledger, _root = _f397_escalated("r4")
    if inst.status != "escalated":
        return _record("F397-stale-at-negative", "ERROR",
                       "saga did not escalate; probe void")
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=-1))
    if code != "workflow-composed-definition-invalid":
        return _record("F397-stale-at-negative", "ERROR",
                       "at=-1 -> code=%r (want "
                       "workflow-composed-definition-invalid)" % (code,))
    _record("F397-stale-at-negative", "HELD",
            "at=-1 refused coded workflow-composed-definition-invalid")


def p_f397_stale_at_nonint():
    # Non-int `at` still refuses coded (existing shape check).
    comp, inst, _calls, _esc, _ledger, _root = _f397_escalated("r5")
    if inst.status != "escalated":
        return _record("F397-stale-at-nonint", "ERROR",
                       "saga did not escalate; probe void")
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at="AT+1"))
    if code != "workflow-composed-definition-invalid":
        return _record("F397-stale-at-nonint", "ERROR",
                       "at='AT+1' -> code=%r (want "
                       "workflow-composed-definition-invalid)" % (code,))
    _record("F397-stale-at-nonint", "HELD",
            "non-int at refused coded "
            "workflow-composed-definition-invalid")


def p_f397_legitimate_retry_succeeds():
    # The F394 operator path is unweakened: a retry at a genuine
    # post-escalation instant with a live delegation re-drives the
    # fixed compensation and the saga reaches compensated.
    comp, inst, calls, _esc, _ledger, _root = _f397_escalated(
        "r6", ttl=10000)
    if inst.status != "escalated":
        return _record("F397-legitimate-retry-succeeds", "ERROR",
                       "saga did not escalate; probe void")
    before = calls["comp"]
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=AT + 7200))
    if code != "no-refusal":
        return _record("F397-legitimate-retry-succeeds", "ERROR",
                       "legitimate retry refused coded %r" % (code,))
    if inst.status != "compensated" or calls["comp"] <= before:
        return _record("F397-legitimate-retry-succeeds", "ERROR",
                       "retry did not re-drive: status=%r calls=%d->%d"
                       % (inst.status, before, calls["comp"]))
    _record("F397-legitimate-retry-succeeds", "HELD",
            "retry at=AT+7200 on a live delegation re-drove "
            "compensation (%d->%d); saga compensated (F394 holds)"
            % (before, calls["comp"]))


def p_f397_expired_delegation_refuses():
    # Expiry is still honored at the true retry instant: the
    # delegation expired at AT+3600, the retry claims AT+7200, the
    # step authority fails closed coded (the F397 control).
    comp, inst, calls, _esc, _ledger, _root = _f397_escalated("r7")
    if inst.status != "escalated":
        return _record("F397-expired-delegation-refuses", "ERROR",
                       "saga did not escalate; probe void")
    before = calls["comp"]
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=AT + 7200))
    if code != "workflow-saga-compensation-unauthorized":
        return _record("F397-expired-delegation-refuses", "ERROR",
                       "expired delegation at true instant -> code=%r "
                       "(want workflow-saga-compensation-unauthorized)"
                       % (code,))
    if calls["comp"] != before:
        return _record("F397-expired-delegation-refuses", "ERROR",
                       "compensation ran despite expiry refusal")
    _record("F397-expired-delegation-refuses", "HELD",
            "expired delegation fails closed coded at the true retry "
            "instant; compensation never re-ran")


def p_f397_revocation_sticky():
    # F384: revocation stays sticky regardless of `at`. Revoke the
    # step delegation after the escalation; a retry at a
    # post-escalation instant inside the old validity window must
    # still refuse coded.
    comp, inst, calls, _esc, ledger, root = _f397_escalated(
        "r8", ttl=10000)
    if inst.status != "escalated":
        return _record("F397-revocation-sticky", "ERROR",
                       "saga did not escalate; probe void")
    ledger.revoke(root["receipt_id"], AT + 1)
    before = calls["comp"]
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=AT + 2))
    if code == "no-refusal":
        return _record("F397-revocation-sticky", "BREAK",
                       "revoked delegation re-drove compensation "
                       "(calls %d->%d)" % (before, calls["comp"]))
    if calls["comp"] != before:
        return _record("F397-revocation-sticky", "ERROR",
                       "compensation ran despite revocation")
    _record("F397-revocation-sticky", "HELD",
            "revoked delegation refused coded %r at a post-escalation "
            "instant (F384 sticky revocation intact)" % (code,))


def p_f397_missing_escalated_at():
    # Fail closed: retained material without the escalation instant
    # (e.g. hand-crafted) refuses coded rather than treating the
    # bound as vacuous.
    comp, inst, _calls, _esc, _ledger, _root = _f397_escalated("r9")
    if inst.status != "escalated":
        return _record("F397-missing-escalated-at", "ERROR",
                       "saga did not escalate; probe void")
    del comp._saga_retry_ctx["u1"]["escalated_at"]
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=AT + 1))
    if code != "workflow-saga-resolution-invalid":
        return _record("F397-missing-escalated-at", "ERROR",
                       "missing escalated_at -> code=%r (want "
                       "workflow-saga-resolution-invalid)" % (code,))
    _record("F397-missing-escalated-at", "HELD",
            "missing escalation instant fails closed coded "
            "workflow-saga-resolution-invalid")


def p_f397_unauthorized_operator_refused():
    # F386/F384: a genuinely unauthorized operator still refuses
    # coded -- the stale-at bound fires only on stale instants, and
    # the operator check still gates the recovery action itself.
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    from gov import workflow_composed as wc
    from gov import delegation as dg
    from gov import ed25519
    from gov import delegation_revocation as rv
    sa, sb = _seed("r10-a"), _seed("r10-b")
    pa, pb = ed25519.publickey(sa).hex(), ed25519.publickey(sb).hex()
    root = dg.issue(sa, "agent-a", "agent-b", pb, ("tool.invoke",),
                    issued_at=AT,
                    constraints={"expires_at": AT + 10000, "max_depth": 4,
                                 "allowed_targets": ["agent-b"]})
    ledger = rv.DelegationRevoker(sa, "agent-a")
    auth = {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": [root], "trust_roots": [pa],
            "revocation_ledger": ledger}
    ws = wf.WorkflowStore()
    sm = saga.SagaManager()  # no operator authority configured
    im = idem.IdempotencyStore()
    comp = wc.WorkflowComposer(ws, sm, im)
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
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
    if inst.status != "escalated":
        return _record("F397-unauthorized-operator-refused", "ERROR",
                       "saga did not escalate; probe void")
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=AT + 1))
    if code != "workflow-saga-operator-unauthorized":
        return _record("F397-unauthorized-operator-refused", "ERROR",
                       "unauthorized operator -> code=%r (want "
                       "workflow-saga-operator-unauthorized)" % (code,))
    _record("F397-unauthorized-operator-refused", "HELD",
            "unauthorized operator refused coded "
            "workflow-saga-operator-unauthorized at a fresh instant "
            "(F386/F384 intact)")


def p_f397_double_retry_refused():
    # After a successful retry the unit is compensated and the
    # retained material is dropped: a second retry refuses coded
    # (no resurrection, no double-recovery).
    comp, inst, calls, _esc, _ledger, _root = _f397_escalated(
        "r11", ttl=10000)
    if inst.status != "escalated":
        return _record("F397-double-retry-refused", "ERROR",
                       "saga did not escalate; probe void")
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=AT + 1))
    if code != "no-refusal" or inst.status != "compensated":
        return _record("F397-double-retry-refused", "ERROR",
                       "first retry failed: code=%r status=%r"
                       % (code, inst.status))
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=AT + 2))
    if code != "workflow-saga-resolution-invalid":
        return _record("F397-double-retry-refused", "ERROR",
                       "second retry -> code=%r (want "
                       "workflow-saga-resolution-invalid)" % (code,))
    _record("F397-double-retry-refused", "HELD",
            "second retry refused coded "
            "workflow-saga-resolution-invalid (unit already "
            "compensated)")


_PROBES = [
    ("pin-taxonomy", p_taxonomy_pin),
    ("footer-state", p_footer_state),
    ("F397-stale-at-retry", p_f397_stale_at_retry),
    ("F397-stale-at-zero", p_f397_stale_at_zero),
    ("F397-stale-at-just-before", p_f397_stale_at_just_before),
    ("F397-stale-at-negative", p_f397_stale_at_negative),
    ("F397-stale-at-nonint", p_f397_stale_at_nonint),
    ("F397-legitimate-retry-succeeds", p_f397_legitimate_retry_succeeds),
    ("F397-expired-delegation-refuses", p_f397_expired_delegation_refuses),
    ("F397-revocation-sticky", p_f397_revocation_sticky),
    ("F397-missing-escalated-at", p_f397_missing_escalated_at),
    ("F397-unauthorized-operator-refused",
     p_f397_unauthorized_operator_refused),
    ("F397-double-retry-refused", p_f397_double_retry_refused),
]

_EXPECTED_BREAKS = frozenset({
    # F397 CLOSED 2026-10-03 wave-313 lane A: every probe asserts the
    # fix; no BREAKs expected.
})


def _green_checks():
    def _rec(pid, verdict, note):
        _record(pid, verdict, note)
    if SKIP_GREEN:
        _record("green-skipped", "HELD",
                "green check skipped (GOV_SKIP_GREEN=1)")
        return
    # F397 CLOSED: the w312 red-team battery's F397 probes assert the
    # stale-at refusal; expect no BREAKs. Re-pinned to the lane
    # footer (open none / next F398).
    green_check.check_battery(
        _rec, "green-w312_redteam", "evals/w312_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # F394 CLOSED: the w310_f394 battery asserts the composer-API
    # re-drive at post-escalation instants; expect no BREAKs.
    green_check.check_battery(
        _rec, "green-w310_f394", "evals/w310_f394_probes.py",
        repo=REPO, expect_break_ids=())
    # F396 CLOSED: the w312_f396 battery; expect no BREAKs.
    green_check.check_battery(
        _rec, "green-w312_f396", "evals/w312_f396_probes.py",
        repo=REPO, expect_break_ids=())
    # F395 CLOSED: the w311_f395 battery; expect no BREAKs.
    green_check.check_battery(
        _rec, "green-w311_f395", "evals/w311_f395_probes.py",
        repo=REPO, expect_break_ids=())


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
    # Exit 1 when any BREAK is present (open findings).
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
