"""Wave-311 lane C battery: independent red team vs the wave-310 merge tree.

Base: wave-310 merge 38650946 (F394 CLOSED -- composer-level operator
retry WorkflowComposer.retry_saga_unit; F395 OPEN -- exotic-closure
digest collision; pin 1841).

Targets (all verified empirically with throwaway scripts BEFORE this
battery was written -- diagnosing-bugs loop):
 1. F396 (MEDIUM, OPEN -- filed by this lane, claim 2026-10-03T15:35:10Z):
    the F393 code binding ignores __defaults__/__kwdefaults__. Two fns
    with identical bytecode whose default argument values differ yield
    identical code_digest -> identical plan digests. The run->plan
    binding passes, _begin_unit returns REPLAY, every _resolve_replay
    check passes -- the victim's fn never executes and the attacker's
    outputs return as native. Verified on the fn path and the saga
    action path via the public API. Distinct from F395: defaults are
    function-object state outside __code__ entirely, and the collision
    holds even for JSON-native defaults -- an F395-scoped fix would not
    close this.
 2. F395 (MEDIUM, CLOSED 2026-10-03 wave-311 lane A): exotic-closure
    digest collision, fn + saga paths, plus a nested-lambda
    indirection variant -- the three probes assert the coded
    workflow-composed-definition-invalid refusal (HELD).
 3. F394 CLOSED regressions: composer-API retry/abort re-drive the
    fixed compensation; direct-SagaManager on a composed instance fails
    closed coded; unauthorized operator refuses coded (F386 intact);
    double retry and unknown unit refuse coded; hygiene preserved.
 4. F393 residuals: JSON-native closure stability (same values -> same
    digest; different values -> different digest); uninspectable
    callables (functools.partial, builtins) refuse coded
    workflow-composed-definition-invalid; descriptor-identical
    different-body plans refuse coded; plan-digest binding holds on
    mid-run failure and survives journal reload.
 5. F391 closure regressions: substitute-manager suspend/resume refuse
    coded; unbound transaction refuses coded.
 6. Evidence modules: DSSE threshold games (bool/str/float/zero),
    keyid confusion (spoofed-trusted keyid, unknown keyid fallback),
    payloadType confusion, tampered payload; in-toto predicateType
    tampering, subject-digest mismatch, threshold, _type tampering --
    all must fail closed.
 7. Canonical probe-line parser: adversarial verdicts, empty pid,
    CRLF, unicode, multiline input; pid-injection observation.
 8. F385-F395 closure regressions via green checks on the adjacent
    batteries.

New findings filed by this lane: F396 (MEDIUM, OPEN), claim
2026-10-03T15:35:10Z. Wave-311 merge: F395 CLOSED (lane A), F396 OPEN;
pin 1841; footer open F396 / next F397. This battery's expected
BREAKs: F396-defaults-fn, F396-defaults-saga, F396-kwdefaults-fn
(all OPEN); the 3 F395 probes assert the coded refusal (HELD).

Expected counts: 39 probes -- 3 BREAK / 36 HELD / 0 ERROR direct
probes. A full standalone run adds 8 depth-1 green checks (47 lines:
3 BREAK / 44 HELD / 0 ERROR); under GOV_SKIP_GREEN=1 the checks are
replaced by one green-skipped HELD line (40 lines: 3/37/0).

Run:
  mkdir -p /var/tmp/g311-rt && TMPDIR=/var/tmp/g311-rt \\
    ~/workspace/.gov-venv/bin/python evals/w311_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g311-rt2 \\
    ~/workspace/.gov-venv/bin/python evals/w311_redteam_probes.py
"""

import functools
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

# Pin 1829 (wave-309 merge: +1 workflow-composed-plan-mismatch). This
# lane mints no codes (red team only; F396 needs no new code -- the
# fix is a digest change, not a refusal), so the pin stays 1829.
TAXONOMY_PIN = 1841  # wave-310 merge: pin unchanged

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
    _record("pin-taxonomy", "HELD", "1841/1841/0 sorted")


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
    # Wave-311 merge footer: F395 CLOSED (lane A); F396 OPEN (lane C).
    if nxt != 398 or open_s != "F396, F397":
        return _record("footer-state", "BREAK",
                       "footer pins next F%d open '%s', want next F398 "
                       "open 'F396, F397'" % (nxt, open_s))
    _record("footer-state", "HELD",
            "footer pins open F396, F397 / next F398")

# ------------------------------------------------------------------
# Shared scaffolds
# ------------------------------------------------------------------

def _seed(s):
    return hashlib.sha256(("w311-" + s).encode()).digest()


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


def _escalated_composed_saga_fixable(tag, operator_ref=True):
    """Drive a composed saga unit to escalation with a compensation
    that fails transiently during the initial window (3 attempts) but
    succeeds once the downstream is "fixed" (4th call onward).
    Returns (comp, sm, instance, comp_calls)."""
    from gov import workflow_saga as saga
    wc, wf, saga_mod, idem, comp, ws, sm, im, auth = _composed_scaffold(
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
    return comp, sm, inst, calls


def _code_of(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", None)
    return "no-refusal"


# ------------------------------------------------------------------
# F395 (MEDIUM, OPEN): the F393 code binding collides for exotic
# closures
# ------------------------------------------------------------------

class _Client:
    """Exotic (non-JSON-native) closure value. Two instances of the
    same type with different state must not share a code_digest --
    but _closure_fingerprint binds only type(value).__name__."""

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
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f395saga")

    def mkaction(client):
        def action(params):
            return client.fetch(), []
        return action

    def mkcomp(client):
        def comp_fn(params):
            return {"undone": True}, []
        return comp_fn

    def mkdef():
        return saga.SagaDefinition([
            saga.SagaStepDef(step_id="s1", action_op="a1",
                             action_params={},
                             compensation_op="c1",
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


def p_f395_exotic_closure_nested():
    # F395 CLOSED (2026-10-03, wave-311 lane A): indirection does not
    # save the binding -- the nested lambda closes over the same
    # exotic value, so the fingerprint and the plan refuse coded at
    # construction, recursively.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f395nest")

    def mknest(client):
        def fn(i):
            h = lambda: client.fetch()
            return h()
        return fn

    evil_fn = mknest(_Client("evil"))
    victim_fn = mknest(_Client("real"))

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
                return _record("F395-exotic-closure-nested", "ERROR",
                               "%s: wrong refusal %r"
                               % (label, getattr(e, "code", e)))
        else:
            return _record("F395-exotic-closure-nested", "BREAK",
                           "F395: %s accepted an exotic closure "
                           "through nested indirection (closure "
                           "direction regressed)" % label)
    _record("F395-exotic-closure-nested", "HELD",
            "nested exotic closures refused coded (F395 closed)")


# ------------------------------------------------------------------
# F396 (MEDIUM, OPEN -- filed this lane): the F393 code binding
# ignores __defaults__/__kwdefaults__
# ------------------------------------------------------------------

class _HitDict(dict):
    """Counting dict used as a default-arg value: records whether the
    victim's default object was ever touched."""
    hits = 0

    def __getitem__(self, k):
        _HitDict.hits += 1
        return dict.__getitem__(self, k)


def _mkdefault_fn(client):
    # Shared factory: identical bytecode whatever object is bound as
    # the default. The realistic shape is a shared library whose
    # functions take per-deployment client/config objects as defaults.
    def fn(i, c=client):
        return {"data": "from-" + c["endpoint"]}
    return fn


def _mkdefault_kwfn(client):
    def fn(i, *, c=client):
        return {"data": "from-" + c["endpoint"]}
    return fn


def _f396_fn_attack(pid, factory):
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f396fn")
    _HitDict.hits = 0
    evil_fn = factory({"endpoint": "evil"})
    victim_fn = factory(_HitDict({"endpoint": "real"}))
    if evil_fn.__code__.co_code != victim_fn.__code__.co_code:
        return _record(pid, "ERROR", "bytecode differs; probe void")
    if wc._code_fingerprint(evil_fn) != wc._code_fingerprint(victim_fn):
        return _record(pid, "ERROR",
                       "fingerprints differ; probe void")
    evil = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": evil_fn,
         "inputs": {}, "idem_key": "k2"}])
    victim = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": victim_fn,
         "inputs": {}, "idem_key": "k2"}])
    if evil.digest != victim.digest:
        return _record(pid, "HELD",
                       "defaults distinguished in the digest (F396 "
                       "closed)")
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    try:
        res = comp.execute(victim, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-composed-plan-mismatch":
            return _record(pid, "HELD",
                           "different plan under same run refused coded "
                           "(F396 closed)")
        return _record(pid, "ERROR", "unexpected refusal %r" % (code,))
    out = res["units"]["u2"]["outputs"]
    if out == {"data": "from-evil"} and _HitDict.hits == 0:
        return _record(pid, "BREAK",
                       "F396: victim fn never executed; attacker's "
                       "outputs returned as native (__defaults__ not "
                       "bound by the code fingerprint)")
    return _record(pid, "ERROR",
                   "unexpected: outputs=%r hits=%r" % (out,
                                                      _HitDict.hits))


def p_f396_defaults_fn():
    _f396_fn_attack("F396-defaults-fn", _mkdefault_fn)


def p_f396_kwdefaults_fn():
    _f396_fn_attack("F396-kwdefaults-fn", _mkdefault_kwfn)


def p_f396_defaults_saga():
    # Same defect class on the saga action path: descriptor-identical
    # saga plans whose action_fns differ only in default-arg values
    # share a digest; the victim saga "succeeds" with the attacker's
    # outputs, victim action never runs.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f396saga")
    _HitDict.hits = 0

    def mkaction(client):
        def act(params, c=client):
            return ({"data": "from-" + c["endpoint"]}, [])
        return act

    def mkcomp(params):
        return {"undone": True}, []

    def mkplan(act):
        definition = saga.SagaDefinition([
            saga.SagaStepDef(step_id="s1", action_op="a1",
                             action_params={},
                             compensation_op="c1",
                             compensation_params={}),
        ])
        return wc.ComposedPlan([{
            "kind": "saga", "name": "sg", "definition": definition,
            "action_fns": {"s1": act},
            "comp_fns": {"s1": mkcomp},
            "idem_key": "ksg"}])

    evil = mkplan(mkaction({"endpoint": "evil"}))
    victim = mkplan(mkaction(_HitDict({"endpoint": "real"})))
    if evil.digest != victim.digest:
        return _record("F396-defaults-saga", "HELD",
                       "defaults distinguished in the digest (F396 "
                       "closed)")
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    try:
        res = comp.execute(victim, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-composed-plan-mismatch":
            return _record("F396-defaults-saga", "HELD",
                           "different saga plan under same run refused "
                           "coded (F396 closed)")
        return _record("F396-defaults-saga", "ERROR",
                       "unexpected refusal %r" % (code,))
    unit = res["units"]["sg"]
    if _HitDict.hits == 0 and unit["status"] == "succeeded":
        return _record("F396-defaults-saga", "BREAK",
                       "F396: victim saga action never executed; saga "
                       "succeeded with the attacker's outputs "
                       "(__defaults__ not bound)")
    return _record("F396-defaults-saga", "ERROR",
                   "unexpected: hits=%r status=%r"
                   % (_HitDict.hits, unit["status"]))

# ------------------------------------------------------------------
# F394 (LOW, CLOSED wave-310 lane A): composer-level operator retry
# holds
# ------------------------------------------------------------------

def p_f394_composer_retry_holds():
    # The supported operator path: comp.retry_saga_unit re-drives the
    # fixed compensation (fresh attempt window) and the saga reaches
    # compensated. The misleading
    # workflow-saga-compensation-unauthorized is gone on this path.
    comp, sm, inst, calls = _escalated_composed_saga_fixable("retry")
    if inst.status != "escalated":
        return _record("F394-composer-retry-holds", "ERROR",
                       "saga did not escalate; probe void")
    before = calls["comp"]
    try:
        comp.retry_saga_unit("u1", {"action": "retry_compensation"},
                             at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-saga-compensation-unauthorized":
            return _record("F394-composer-retry-holds", "BREAK",
                           "F394 regression: misleading "
                           "workflow-saga-compensation-unauthorized "
                           "on composer retry")
        return _record("F394-composer-retry-holds", "ERROR",
                       "composer retry raised %r" % (code,))
    if inst.status == "compensated" and calls["comp"] > before:
        return _record("F394-composer-retry-holds", "HELD",
                       "composer retry re-drove compensation "
                       "(%d->%d calls); saga compensated (F394 holds)"
                       % (before, calls["comp"]))
    return _record("F394-composer-retry-holds", "ERROR",
                   "unexpected: status=%r calls=%d->%d"
                   % (inst.status, before, calls["comp"]))


def p_f394_composer_abort_holds():
    # The second re-drive action via the composer API: the fixed
    # compensation is re-driven on the remaining attempt budget and
    # the saga reaches compensated.
    comp, sm, inst, calls = _escalated_composed_saga_fixable("abort")
    if inst.status != "escalated":
        return _record("F394-composer-abort-holds", "ERROR",
                       "saga did not escalate; probe void")
    before = calls["comp"]
    try:
        comp.retry_saga_unit("u1",
                             {"action": "abort_and_compensate_all"},
                             at=AT)
    except Exception as e:  # noqa: BLE001
        return _record("F394-composer-abort-holds", "ERROR",
                       "composer abort raised %r (calls %d->%d)"
                       % (getattr(e, "code", None),
                          before, calls["comp"]))
    if inst.status == "compensated" and calls["comp"] > before:
        return _record("F394-composer-abort-holds", "HELD",
                       "composer abort re-drove compensation "
                       "(%d->%d calls); saga compensated (F394 holds)"
                       % (before, calls["comp"]))
    return _record("F394-composer-abort-holds", "ERROR",
                   "unexpected: status=%r calls=%d->%d"
                   % (inst.status, before, calls["comp"]))


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


def p_f394_unauthorized_operator_refused():
    # A genuinely unauthorized operator still refuses coded --
    # the retry API does not weaken F386/F384's operator check.
    comp, sm, inst, calls = _escalated_composed_saga_fixable(
        "unauth", operator_ref=False)
    if inst.status != "escalated":
        return _record("F394-unauthorized-operator-refused", "ERROR",
                       "saga did not escalate; probe void")
    try:
        comp.retry_saga_unit("u1", {"action": "retry_compensation"},
                             at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-saga-operator-unauthorized":
            return _record("F394-unauthorized-operator-refused", "HELD",
                           "unauthorized operator refused coded "
                           "workflow-saga-operator-unauthorized "
                           "(F386/F384 check intact)")
        return _record("F394-unauthorized-operator-refused", "ERROR",
                       "unexpected code %r" % (code,))
    return _record("F394-unauthorized-operator-refused", "ERROR",
                   "unauthorized operator retry was not refused")


def p_f394_double_retry_refused():
    # After a successful retry the unit is compensated and the
    # retained material is dropped: a second retry refuses coded
    # (no resurrection, no double-recovery).
    comp, sm, inst, calls = _escalated_composed_saga_fixable("dbl")
    try:
        comp.retry_saga_unit("u1", {"action": "retry_compensation"},
                             at=AT)
    except Exception as e:  # noqa: BLE001
        return _record("F394-double-retry-refused", "ERROR",
                       "first retry raised %r" % (getattr(e, "code", e),))
    if inst.status != "compensated":
        return _record("F394-double-retry-refused", "ERROR",
                       "first retry did not compensate: %r"
                       % (inst.status,))
    try:
        comp.retry_saga_unit("u1", {"action": "retry_compensation"},
                             at=AT)
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
        comp.retry_saga_unit("u1", {"action": "retry_compensation"},
                             at=AT)
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


# ------------------------------------------------------------------
# F393 residuals: JSON-native closure stability, uninspectable
# refusal, descriptor confusion, binding on failure and reload
# ------------------------------------------------------------------

def p_f393_json_closure_stability():
    # JSON-native closed-over values bind by value: the same values
    # rebuild the same digest (crash-recovery stability), different
    # values change it.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f393json")

    def mk(tag):
        cfg = {"endpoint": tag, "retries": [1, 2]}
        def fn(i):
            return cfg["endpoint"]
        return fn

    a1, a2, b = mk("x"), mk("x"), mk("y")
    fa1, fa2, fb = (wc._code_fingerprint(f) for f in (a1, a2, b))
    if fa1 != fa2:
        return _record("F393-json-closure-stability", "BREAK",
                       "same JSON-native closure values yield "
                       "different digests (crash-recovery stability "
                       "broken)")
    if fa1 == fb:
        return _record("F393-json-closure-stability", "BREAK",
                       "different JSON-native closure values yield "
                       "the same digest")
    _record("F393-json-closure-stability", "HELD",
            "JSON-native closures bind by value: equal values "
            "collide, different values differ (F393 holds)")


def p_f393_uninspectable_refused():
    # Callables without an introspectable code object (functools
    # .partial, C builtins) refuse coded at plan construction: the
    # digest must bind code, and uninspectable code cannot be bound
    # (fail closed).
    from gov import workflow_composed as wcmod
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f393uninsp")

    def add(i, x):
        return i

    for fn, label in [(functools.partial(add, 1), "partial"),
                      (len, "builtin")]:
        code = _code_of(lambda: wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": fn,
             "inputs": {}, "idem_key": "k"}]))
        if code != "workflow-composed-definition-invalid":
            return _record("F393-uninspectable-refused", "BREAK",
                           "%s not refused coded: %r" % (label, code))
    _record("F393-uninspectable-refused", "HELD",
            "partial and builtin fns refuse coded "
            "workflow-composed-definition-invalid (fail closed)")


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
                           "descriptor-identical different-body plan "
                           "refused coded (F393 holds)")
        return _record("F393-fn-code-confusion", "ERROR",
                       "unexpected refusal %r" % (code,))
    return _record("F393-fn-code-confusion", "BREAK",
                   "different fn body replayed attacker's record "
                   "(F393 regressed)")


def p_f393_saga_code_confusion():
    # The filed F393 saga attack shape: descriptor-identical saga
    # plans whose action fns differ in body.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f393saga")

    def mkplan(action_fn):
        definition = saga.SagaDefinition([
            saga.SagaStepDef(step_id="s1", action_op="a1",
                             action_params={},
                             compensation_op="c1",
                             compensation_params={}),
        ])

        def comp_fn(params):
            return {"undone": True}, []

        return wc.ComposedPlan([{
            "kind": "saga", "name": "sg", "definition": definition,
            "action_fns": {"s1": action_fn},
            "comp_fns": {"s1": comp_fn},
            "idem_key": "ksg"}])

    def evil_action(params):
        return {"evil": True}, []

    def victim_action(params):
        return {"real": True}, []

    comp.execute(mkplan(evil_action), run_id="R", authority=auth, at=AT)
    code = _code_of(lambda: comp.execute(
        mkplan(victim_action), run_id="R", authority=auth, at=AT))
    if code == "workflow-composed-plan-mismatch":
        return _record("F393-saga-code-confusion", "HELD",
                       "descriptor-identical different-action saga "
                       "refused coded (F393 holds)")
    return _record("F393-saga-code-confusion", "BREAK",
                   "different saga action body not refused coded: %r "
                   "(F393 regressed)" % (code,))


def p_plan_digest_midrun_failure():
    # execute() binds the plan digest BEFORE unit execution. If
    # execute fails mid-run (after binding), the run stays bound.
    # Same-plan retry must still work (same digest); different-plan
    # retry must refuse coded (fail-closed, not silent).
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


def p_plan_digest_survives_reload():
    # The run->plan binding is journaled: after a store reload from
    # the same journal, a different plan under the same run still
    # refuses coded (crash-recovery keeps the binding).
    from gov import workflow as wfmod
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "reload")
    journal = os.path.join(tempfile.mkdtemp(), "journal.jsonl")
    ws1 = wfmod.WorkflowStore(path=journal)
    ws1.start_run("probe", run_id="R", authority=auth, at=AT)
    comp1 = wc.WorkflowComposer(
        ws1, saga.SagaManager(), idem.IdempotencyStore())

    def ok_fn(i):
        return {"ok": True}

    plan1 = wc.ComposedPlan([
        {"kind": "fn", "name": "u1", "fn": ok_fn,
         "inputs": {}, "idem_key": "k1"}])
    comp1.execute(plan1, run_id="R", authority=auth, at=AT)

    ws2 = wfmod.WorkflowStore(path=journal)  # reload from journal
    comp2 = wc.WorkflowComposer(
        ws2, saga.SagaManager(), idem.IdempotencyStore())

    def other_fn(i):
        return {"other": 2}

    other_plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u1", "fn": other_fn,
         "inputs": {}, "idem_key": "k1"}])
    code = _code_of(lambda: comp2.execute(
        other_plan, run_id="R", authority=auth, at=AT))
    if code != "workflow-composed-plan-mismatch":
        return _record("plan-digest-survives-reload", "BREAK",
                       "different plan after journal reload not "
                       "refused coded: %r" % (code,))
    _record("plan-digest-survives-reload", "HELD",
            "run->plan binding survives journal reload: different "
            "plan refuses coded")

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
# Evidence modules: DSSE + in-toto error paths must fail closed
# ------------------------------------------------------------------

def _ev_signers(tag, n=1):
    from gov.signing import Ed25519Signer, Ed25519Verifier
    signers = [Ed25519Signer(_seed("ev-%s-%d" % (tag, i)))
               for i in range(n)]
    verifiers = [Ed25519Verifier(s.public_key, s.key_id)
                 for s in signers]
    return signers, verifiers


def p_dsse_threshold_not_met():
    # Threshold=2 with one valid signature refuses loudly.
    from gov import evidence_dsse as dsse
    signers, verifiers = _ev_signers("thr")
    env = dsse.seal_evidence_bundle(b'{"bundle": 1}', signers)
    try:
        dsse.verify_dsse_envelope(env, b'{"bundle": 1}', verifiers,
                                  threshold=2)
    except Exception as e:  # noqa: BLE001
        _record("dsse-threshold-not-met", "HELD",
                "threshold=2 with one signature refused: %r" % (e,))
        return
    _record("dsse-threshold-not-met", "BREAK",
            "threshold=2 with one signature verified (threshold "
            "bypass)")


def p_dsse_threshold_type_games():
    # Non-int/bool/zero/negative thresholds are refused loudly, never
    # coerced (True == 1 must not sneak through as a threshold).
    from gov import evidence_dsse as dsse
    signers, verifiers = _ev_signers("thrt")
    env = dsse.seal_evidence_bundle(b'{"bundle": 1}', signers)
    bad = [True, False, "2", 1.5, 0, -1, None]
    for thr in bad:
        try:
            dsse.verify_dsse_envelope(env, b'{"bundle": 1}', verifiers,
                                      threshold=thr)
        except Exception:
            continue
        return _record("dsse-threshold-type-games", "BREAK",
                       "threshold=%r accepted (type game)" % (thr,))
    _record("dsse-threshold-type-games", "HELD",
            "bool/str/float/zero/negative/None thresholds all "
            "refused loudly")


def p_dsse_keyid_confusion():
    # keyid is a hint, never an authority: (a) an untrusted key's
    # signature carrying a TRUSTED keyid must not verify; (b) a trusted
    # signature carrying an UNKNOWN keyid still verifies (documented
    # try-all fallback); (c) an untrusted signature with an unknown
    # keyid is refused.
    from gov import evidence_dsse as dsse
    signers, verifiers = _ev_signers("kidt")
    evil_signers, _ = _ev_signers("kidx")
    bundle = b'{"bundle": 1}'
    trusted_kid = verifiers[0].key_id

    # (a) attacker seals, then rewrites the keyid to the trusted one.
    env_a = dsse.seal_evidence_bundle(bundle, evil_signers)
    env_a["signatures"][0]["keyid"] = trusted_kid
    try:
        dsse.verify_dsse_envelope(env_a, bundle, verifiers)
    except Exception:
        pass
    else:
        return _record("dsse-keyid-confusion", "BREAK",
                       "untrusted signature with spoofed trusted "
                       "keyid verified (keyid confused for authority)")

    # (b) trusted signature, unknown keyid -> documented fallback.
    env_b = dsse.seal_evidence_bundle(bundle, signers)
    env_b["signatures"][0]["keyid"] = "unknown-key-id"
    try:
        out = dsse.verify_dsse_envelope(env_b, bundle, verifiers)
    except Exception as e:  # noqa: BLE001
        return _record("dsse-keyid-confusion", "ERROR",
                       "trusted sig with unknown keyid refused: %r "
                       "(documented fallback broken)" % (e,))
    if out != bundle:
        return _record("dsse-keyid-confusion", "ERROR",
                       "fallback returned wrong bytes")

    # (c) untrusted signature, unknown keyid -> refused.
    env_c = dsse.seal_evidence_bundle(bundle, evil_signers)
    try:
        dsse.verify_dsse_envelope(env_c, bundle, verifiers)
    except Exception:
        pass
    else:
        return _record("dsse-keyid-confusion", "BREAK",
                       "untrusted signature with unknown keyid "
                       "verified")
    _record("dsse-keyid-confusion", "HELD",
            "keyid is a hint: spoofed-trusted keyid refused, "
            "unknown keyid falls back to try-all, untrusted refused")


def p_dsse_payloadtype_confusion():
    # The payloadType is bound inside the PAE signature: (a) an
    # envelope sealed under a different type refuses; (b) flipping the
    # type string post-seal breaks the signature and refuses.
    from gov import evidence_dsse as dsse
    from gov import dsse_envelope as de
    signers, verifiers = _ev_signers("ptc")
    bundle = b'{"bundle": 1}'

    env_a = de.seal(bundle, "application/vnd.evil+json", signers)
    try:
        dsse.verify_dsse_envelope(env_a, bundle, verifiers)
    except Exception:
        pass
    else:
        return _record("dsse-payloadtype-confusion", "BREAK",
                       "envelope sealed under a foreign payloadType "
                       "verified")

    env_b = dsse.seal_evidence_bundle(bundle, signers)
    env_b["payloadType"] = "application/vnd.in-toto+jsxn"
    try:
        dsse.verify_dsse_envelope(env_b, bundle, verifiers)
    except Exception:
        pass
    else:
        return _record("dsse-payloadtype-confusion", "BREAK",
                       "tampered payloadType string verified")
    _record("dsse-payloadtype-confusion", "HELD",
            "foreign and tampered payloadType both refused "
            "(type bound in PAE)")


def p_dsse_tampered_payload():
    # Flipping one payload byte breaks the signature: refused loudly,
    # and no payload bytes escape.
    import base64
    from gov import evidence_dsse as dsse
    signers, verifiers = _ev_signers("tpp")
    bundle = b'{"bundle": 1}'
    env = dsse.seal_evidence_bundle(bundle, signers)
    raw = bytearray(base64.b64decode(env["payload"]))
    raw[5] ^= 0x01
    env["payload"] = base64.b64encode(bytes(raw)).decode("ascii")
    try:
        dsse.verify_dsse_envelope(env, bundle, verifiers)
    except Exception as e:  # noqa: BLE001
        _record("dsse-tampered-payload", "HELD",
                "bit-flipped payload refused: %r" % (e,))
        return
    _record("dsse-tampered-payload", "BREAK",
            "tampered payload verified (signature bypass)")


def _ev_statement(tag, predicate_type=None, extra_subjects=0,
                  bundle=None):
    from gov import evidence_intoto as ei
    bundle = bundle if bundle is not None else (
        '{"bundle": "%s"}' % tag).encode("ascii")
    stmt = ei.build_statement(bundle, {"claims": [tag]})
    if predicate_type is not None:
        stmt["predicateType"] = predicate_type
    for i in range(extra_subjects):
        stmt["subject"].append({
            "name": "evidence-bundle-extra-%d" % i,
            "digest": {"sha256": "00" * 32}})
    return stmt, bundle


def p_intoto_predicate_type_tamper():
    # A statement carrying a foreign predicateType must not open --
    # neither under the attacker's own key (shape refusal) nor under
    # the victim's key (signature refusal). seal_statement itself
    # must also refuse to sign a mistyped statement.
    from gov import evidence_intoto as ei
    from gov import evidence_dsse as ed
    signers, verifiers = _ev_signers("ipt")
    evil_signers, evil_verifiers = _ev_signers("ipx")
    stmt, bundle = _ev_statement("a",
                                 predicate_type="https://evil.example/p")
    # seal_statement validates shape BEFORE signing.
    try:
        ei.seal_statement(stmt, signers)
    except Exception:
        pass
    else:
        return _record("intoto-predicate-type-tamper", "BREAK",
                       "seal_statement signed a foreign-predicateType "
                       "statement")
    # Attacker hand-seals the mistyped statement with their own key.
    env = ed.seal_evidence_bundle(ei.statement_bytes(stmt),
                                  evil_signers)
    try:
        ei.open_statement(env, bundle, evil_verifiers)
    except Exception:
        pass
    else:
        return _record("intoto-predicate-type-tamper", "BREAK",
                       "mistyped statement opened under attacker key")
    try:
        ei.open_statement(env, bundle, verifiers)
    except Exception:
        pass
    else:
        return _record("intoto-predicate-type-tamper", "BREAK",
                       "mistyped statement opened under victim key")
    _record("intoto-predicate-type-tamper", "HELD",
            "foreign predicateType: seal refuses, open refuses "
            "under both keys")


def p_intoto_subject_digest_mismatch():
    # A statement attesting bundle A does not open against expected
    # bundle B.
    from gov import evidence_intoto as ei
    signers, verifiers = _ev_signers("isd")
    stmt, _ = _ev_statement("aaa")
    env = ei.seal_statement(stmt, signers)
    try:
        ei.open_statement(env, b'{"bundle": "bbb"}', verifiers)
    except Exception as e:  # noqa: BLE001
        _record("intoto-subject-digest-mismatch", "HELD",
                "subject digest mismatch refused: %r" % (e,))
        return
    _record("intoto-subject-digest-mismatch", "BREAK",
            "statement for bundle A opened against bundle B")


def p_intoto_threshold():
    # Threshold=2 with one valid signature refuses loudly.
    from gov import evidence_intoto as ei
    signers, verifiers = _ev_signers("ith")
    stmt, bundle = _ev_statement("t")
    env = ei.seal_statement(stmt, signers)
    try:
        ei.open_statement(env, bundle, verifiers, threshold=2)
    except Exception as e:  # noqa: BLE001
        _record("intoto-threshold", "HELD",
                "threshold=2 with one signature refused: %r" % (e,))
        return
    _record("intoto-threshold", "BREAK",
            "threshold=2 with one signature opened (threshold "
            "bypass)")


def p_intoto_type_tamper():
    # A statement with a foreign _type (hand-sealed, bypassing the
    # shape-validating seal path) must not open.
    from gov import evidence_intoto as ei
    from gov import evidence_dsse as ed
    evil_signers, evil_verifiers = _ev_signers("itp")
    stmt, bundle = _ev_statement("z")
    stmt["_type"] = "https://in-toto.io/Statement/v0.1"
    env = ed.seal_evidence_bundle(ei.statement_bytes(stmt),
                                  evil_signers)
    try:
        ei.open_statement(env, bundle, evil_verifiers)
    except Exception as e:  # noqa: BLE001
        _record("intoto-type-tamper", "HELD",
                "foreign _type refused: %r" % (e,))
        return
    _record("intoto-type-tamper", "BREAK",
            "foreign _type statement opened")


def p_intoto_extra_subject_inert():
    # Observation, not an attack: a well-signed statement carrying
    # extra subject entries opens fine -- the caller binds subject[0]
    # against the expected bundle bytes, and extra subjects are inert
    # data (the builder never emits them). If this ever refused, the
    # shape contract changed; if it opened with subject[0] unbound,
    # that would be a finding.
    from gov import evidence_intoto as ei
    signers, verifiers = _ev_signers("ies")
    stmt, bundle = _ev_statement("e", extra_subjects=2)
    env = ei.seal_statement(stmt, signers)
    try:
        opened = ei.open_statement(env, bundle, verifiers)
    except Exception as e:  # noqa: BLE001
        return _record("intoto-extra-subject-inert", "ERROR",
                       "multi-subject statement refused: %r" % (e,))
    if opened["subject"][0]["name"] != "evidence-bundle":
        return _record("intoto-extra-subject-inert", "ERROR",
                       "subject[0] not the builder subject")
    _record("intoto-extra-subject-inert", "HELD",
            "multi-subject statement opens; subject[0] bound to "
            "expected bytes, extra subjects inert (observation)")


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


def p_probe_lines_adversarial():
    # Adversarial verdicts / shapes must not parse; multiline input
    # must not yield more than the first line.
    sys.path.insert(0, os.path.join(REPO, "evals"))
    import probe_lines
    bad = ["[WEIRD] pid: n", "[break] pid: n", "[HELD] : n",
           "[HELD] pid n", "\n[HELD] pid: n", "[HELD] pid: n\n"
           "[BREAK] x: y\n[HELD] pid: n"]
    for line in bad:
        parsed = probe_lines.parse_line(line)
        if line.startswith("[HELD] pid: n\n"):
            # Multiline: must parse as exactly the first line's
            # triple, never as two lines.
            if parsed != ("HELD", "pid", "n"):
                return _record("probe-lines-adversarial", "BREAK",
                               "multiline input mis-parsed: %r"
                               % (parsed,))
            continue
        if parsed is not None:
            return _record("probe-lines-adversarial", "BREAK",
                           "adversarial line parsed: %r -> %r"
                           % (line, parsed))
    # check_coherence is the advisory backstop: unknown verdicts and
    # count mismatches surface as diagnostics, never as silent green.
    ok, _ = probe_lines.check_coherence(
        [("p1", "HELD", "n"), ("p2", "WEIRD", "n")], 0, 1, 0)
    if ok:
        return _record("probe-lines-adversarial", "BREAK",
                       "check_coherence accepted an unknown verdict")
    ok, _ = probe_lines.check_coherence([("p1", "HELD", "n")], 0, 2, 0)
    if ok:
        return _record("probe-lines-adversarial", "BREAK",
                       "check_coherence accepted a count mismatch")
    ok, diags = probe_lines.check_coherence(
        [("p1", "HELD", "n")], 0, 1, 0)
    if not ok:
        return _record("probe-lines-adversarial", "ERROR",
                       "check_coherence rejected a coherent list: %r"
                       % (diags,))
    _record("probe-lines-adversarial", "HELD",
            "adversarial verdicts/shapes rejected; multiline yields "
            "first line only; coherence check flags unknowns")


def p_probe_lines_pid_injection():
    # Observation, not a finding: format_line does not validate the
    # pid, so a newline-bearing pid emits text containing a parseable
    # fake probe line. Notes are first-lined (no injection there);
    # the pid channel is unguarded. Not a finding because pids are
    # battery-authored literals -- no battery formats an untrusted
    # pid, and a malicious battery could print fake lines directly.
    # Hardening suggestion (do not break the contract): format_line
    # could validate pid/verdict against PID_RE/VALID_VERDICTS.
    sys.path.insert(0, os.path.join(REPO, "evals"))
    import probe_lines
    line = probe_lines.format_line("a\n[BREAK] forged", "HELD", "n")
    parts = line.split("\n")
    if len(parts) != 2:
        return _record("probe-lines-pid-injection", "ERROR",
                       "unexpected rendering: %r" % (line,))
    forged = probe_lines.parse_line(parts[1])
    if forged != ("BREAK", "forged", "n"):
        return _record("probe-lines-pid-injection", "ERROR",
                       "fake line did not parse as expected: %r"
                       % (forged,))
    _record("probe-lines-pid-injection", "HELD",
            "pid channel unguarded (observation): newline pid emits "
            "a parseable fake line; pids are battery-authored "
            "literals, so no finding -- hardening suggestion in "
            "REPORT")

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
    # probes assert the coded workflow-composed-plan-mismatch
    # refusal; expect no BREAKs. Re-pinned to the lane footer
    # (open F395, F396 / next F397).
    green_check.check_battery(
        _rec, "green-w309_f393", "evals/w309_f393_probes.py",
        repo=REPO, expect_break_ids=())
    # F394 CLOSED (wave-310 lane A): the w309 red-team battery's F394
    # probes assert the working composer-API re-drive; expect no
    # BREAKs. Re-pinned to the lane footer.
    green_check.check_battery(
        _rec, "green-w309_redteam", "evals/w309_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # F391 CLOSED (wave-308 lane A): the w308 battery's F391 probes
    # assert the coded coord-lease-manager-mismatch refusal; expect no
    # BREAKs. Re-pinned to the lane footer.
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
    # F395 OPEN: the w310 red-team battery's F395 probes still report
    # BREAK (nested variant is new to this lane). Re-pinned to the
    # lane footer.
    green_check.check_battery(
        _rec, "green-w310_redteam", "evals/w310_redteam_probes.py",
        repo=REPO, expect_break_ids=("F395-exotic-closure-fn",
                                     "F395-exotic-closure-saga"))
    # F394 CLOSED: the w310_f394 battery asserts the composer-API
    # re-drive; expect no BREAKs. Re-pinned to the lane footer.
    green_check.check_battery(
        _rec, "green-w310_f394", "evals/w310_f394_probes.py",
        repo=REPO, expect_break_ids=())


# ------------------------------------------------------------------
# Probe table + main
# ------------------------------------------------------------------

_PROBES = [
    ("pin-taxonomy", p_taxonomy_pin),
    ("footer-state", p_footer_state),
    # F395 (OPEN -- expected BREAKs)
    ("F395-exotic-closure-fn", p_f395_exotic_closure_fn),
    ("F395-exotic-closure-saga", p_f395_exotic_closure_saga),
    ("F395-exotic-closure-nested", p_f395_exotic_closure_nested),
    # F396 (OPEN, filed this lane -- expected BREAKs)
    ("F396-defaults-fn", p_f396_defaults_fn),
    ("F396-defaults-saga", p_f396_defaults_saga),
    ("F396-kwdefaults-fn", p_f396_kwdefaults_fn),
    # F394 CLOSED regressions (must be HELD)
    ("F394-composer-retry-holds", p_f394_composer_retry_holds),
    ("F394-composer-abort-holds", p_f394_composer_abort_holds),
    ("F394-direct-sm-fails-closed", p_f394_direct_sm_fails_closed),
    ("F394-unauthorized-operator-refused",
     p_f394_unauthorized_operator_refused),
    ("F394-double-retry-refused", p_f394_double_retry_refused),
    ("F394-unknown-unit-refused", p_f394_unknown_unit_refused),
    ("F394-hygiene-preserved", p_f394_hygiene_preserved),
    # F393 residuals (must be HELD)
    ("F393-fn-code-confusion", p_f393_fn_code_confusion),
    ("F393-saga-code-confusion", p_f393_saga_code_confusion),
    ("F393-json-closure-stability", p_f393_json_closure_stability),
    ("F393-uninspectable-refused", p_f393_uninspectable_refused),
    ("plan-digest-midrun-failure", p_plan_digest_midrun_failure),
    ("plan-digest-survives-reload", p_plan_digest_survives_reload),
    # F391 closure regressions (must be HELD)
    ("F391-suspend-substitute-refused", p_f391_suspend_substitute_refused),
    ("F391-resume-substitute-refused", p_f391_resume_substitute_refused),
    ("F391-unbound-refuses", p_f391_unbound_refuses),
    # Evidence modules (must fail closed -> HELD)
    ("dsse-threshold-not-met", p_dsse_threshold_not_met),
    ("dsse-threshold-type-games", p_dsse_threshold_type_games),
    ("dsse-keyid-confusion", p_dsse_keyid_confusion),
    ("dsse-payloadtype-confusion", p_dsse_payloadtype_confusion),
    ("dsse-tampered-payload", p_dsse_tampered_payload),
    ("intoto-predicate-type-tamper", p_intoto_predicate_type_tamper),
    ("intoto-subject-digest-mismatch", p_intoto_subject_digest_mismatch),
    ("intoto-threshold", p_intoto_threshold),
    ("intoto-type-tamper", p_intoto_type_tamper),
    ("intoto-extra-subject-inert", p_intoto_extra_subject_inert),
    # Probe-line pilot (parser robustness)
    ("probe-lines-no-injection", p_probe_lines_no_injection),
    ("probe-lines-strict-parse", p_probe_lines_strict_parse),
    ("probe-lines-adversarial", p_probe_lines_adversarial),
    ("probe-lines-pid-injection", p_probe_lines_pid_injection),
]

_EXPECTED_BREAKS = frozenset({
    "F396-defaults-fn",           # F396 OPEN (filed this lane)
    "F396-defaults-saga",         # F396 OPEN (filed this lane)
    "F396-kwdefaults-fn",         # F396 OPEN (filed this lane)
})


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
    for pid, verdict, note in _results:
        first = note.splitlines()[0] if note else ""
        print("[VERDICT] %s: %s: %s" % (verdict, pid, first))
    brk = sum(1 for r in _results if r[1] == "BREAK")
    held = sum(1 for r in _results if r[1] == "HELD")
    err = sum(1 for r in _results if r[1] == "ERROR")
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    # Open-findings sweep: exactly the expected BREAKs (all OPEN).
    # Exit 1 when any BREAK is present (open findings), like the
    # w310 red-team battery.
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
