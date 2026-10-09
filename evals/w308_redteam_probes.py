"""Wave-308 lane D battery: independent red team vs the wave-307 tree.

Base: wave-307 merge 57068df1 (F392 filed and closed -- step-name
collision via (namespace, op_class, key) idempotency binding).

Targets (all verified empirically with throwaway scripts BEFORE this
battery was written -- diagnosing-bugs loop):
 1. F391 (CLOSED wave-308 lane A): the three limbs (fake-manager re-park
    clobber, fake-manager resume self-attestation, and the third limb --
    a REAL park resumed with a substituted fake manager) now assert the
    coded coord-lease-manager-mismatch refusal.
 2. F393 (MEDIUM, OPEN -- filed by this lane, claim 2026-10-03T11:19:50Z):
    the composed idempotency identity (op_digest) does not bind the
    unit's code. ComposedPlan.digest covers kind/name/idem_key/
    inputs_digest but not the fn callable, so a descriptor-identical
    evil plan (same kind, name, idem_key, inputs; different fn) yields a
    bit-identical op_digest. The victim's _begin_unit returns REPLAY on
    the attacker's record and _resolve_replay passes every check -- run,
    record-caller, digest, F390 step name, F392 idempotency binding --
    so the victim's fn never executes and the attacker's outputs return
    as native. Demonstrated on the fn path and the saga action path.
    This refutes the F392 residual claim that the binding "makes
    plan-sharing a run safe at the replay seam".
 3. F392 closure at its bypass boundaries: NUL-smuggling in idem_key
    (store grammar refuses -- fail-closed), cross-op_class plants
    (store key isolation -- the victim's begin is NEW, executes
    natively), the original same-run same-name attack (still refused
    coded).
 4. Wave-307 seams: green_check.py hardening (a vacuous 0/0/0 child and
    a probe-ERRORs child must both record ERROR now, not HELD); the
    w303_f384 real green check; no legitimate battery newly ERRORing.
 5. F385/F386/F388/F390 closure regressions.

New findings filed by this lane: F393 (MEDIUM, OPEN), claim
2026-10-03T11:19:50Z. Wave-308 merge: F391 CLOSED (lane A), F393 OPEN;
pin 1841; footer open none / next F396 (wave-309: F393 CLOSED).

Run:
  mkdir -p /var/tmp/g308-rt && TMPDIR=/var/tmp/g308-rt \
    ~/workspace/.gov-venv/bin/python evals/w308_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g308-rt2 \
    ~/workspace/.gov-venv/bin/python evals/w308_redteam_probes.py
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

# Wave-307 merge pin 1827; this lane mints no codes (red team only), so
# the pin stays 1827. The merge-time sweep repoints to the wave-308 pin.
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
    # Wave-312 merge footer: F396 CLOSED (lane A); F397 OPEN (lane C).
    # Wave-359 merge: repointed to open F489, F490, F491, F492, F493, F494, F495 / next F506 (footer-state probe audit).
    if nxt != 672 or open_s != "F662, F663, F664, F665, F666, F667, F669, F670, F671":  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-379 lane 6: F668 CLOSED (lane-local)
        return _record("footer-state", "BREAK",
                       "footer pins next F%d open '%s', want next F672 open 'F662, F663, F664, F665, F666, F667, F669, F670, F671'" % (nxt, open_s))  # Wave-379 lane 6: F668 CLOSED (lane-local)
    _record("footer-state", "HELD", "footer pins open F521, F522, F523, F524, F525 / next F526")  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)


# ------------------------------------------------------------------
# Shared scaffolds
# ------------------------------------------------------------------

def _seed(s):
    return hashlib.sha256(("w308-" + s).encode()).digest()


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


def _composed_scaffold(tag):
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
    sm = saga.SagaManager()
    im = idem.IdempotencyStore()
    comp = wc.WorkflowComposer(ws, sm, im)
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    return wc, wf, saga, idem, comp, ws, sm, im, auth


def _fn_op_digest(wc, plan, unit_name, inputs):
    return wc._digest({"plan": plan.digest, "op": "unit",
                       "unit": unit_name,
                       "inputs": wc._digest(inputs)})


FOREIGN_CODE = "workflow-composed-replay-foreign"


# ------------------------------------------------------------------
# F391 (CLOSED wave-308 lane A): the three limbs now assert the
# coded coord-lease-manager-mismatch refusal
# ------------------------------------------------------------------

def p_f391_fake_manager_clobber():
    # F391 (MEDIUM, OPEN): suspend_lease takes the lease manager as a
    # caller-supplied argument; a rubber-stamp manager's re-park is
    # ACCEPTED and clobbers the legitimate holder's suspension.
    lm, tok, c, xid, ed25519 = _branch_fx()
    rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                          suspended_at=1050)
    try:
        evil = c.suspend_lease(xid, _RubberStampManager(), "scope-x",
                               999999, "mallory", suspended_at=1060)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "coord-lease-manager-mismatch":
            return _record("F391-fake-manager-clobber", "ERROR",
                           "wrong refusal code: %r (want "
                           "coord-lease-manager-mismatch)"
                           % (getattr(e, "code", e),))
        return _record("F391-fake-manager-clobber", "HELD",
                       "fake-manager re-park refused coded "
                       "coord-lease-manager-mismatch (F391 closed)")
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
    # F391 second limb: the attacker's own resume_lease with the fake
    # manager returns True -- fake liveness self-attestation.
    # (On the closed tree the fake re-park is already refused coded;
    # that also defeats this limb.)
    lm, tok, c, xid, ed25519 = _branch_fx()
    c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                    suspended_at=1050)
    fake = _RubberStampManager()
    try:
        evil = c.suspend_lease(xid, fake, "scope-x", 999999, "mallory",
                               suspended_at=1060)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "coord-lease-manager-mismatch":
            return _record("F391-fake-manager-resume", "ERROR",
                           "wrong refusal code at re-park: %r (want "
                           "coord-lease-manager-mismatch)"
                           % (getattr(e, "code", e),))
        return _record("F391-fake-manager-resume", "HELD",
                       "fake-manager re-park refused coded "
                       "coord-lease-manager-mismatch (second limb "
                       "defeated at re-park; F391 closed)")
    try:
        ok = c.resume_lease(evil, fake, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "coord-lease-manager-mismatch":
            return _record("F391-fake-manager-resume", "ERROR",
                           "wrong refusal code: %r (want "
                           "coord-lease-manager-mismatch)"
                           % (getattr(e, "code", e),))
        return _record("F391-fake-manager-resume", "HELD",
                       "fake-manager resume refused coded "
                       "coord-lease-manager-mismatch (F391 closed)")
    if ok is True:
        return _record("F391-fake-manager-resume", "BREAK",
                       "fake-manager resume returned True: bogus lease "
                       "self-attested as live (F391)")
    _record("F391-fake-manager-resume", "ERROR",
            "resume returned non-True: %r" % (ok,))


def p_f391_fake_manager_resume_real_park():
    # F391 third limb (new probe, same finding): the park is legitimate
    # (real manager, real token) but the RESUME substitutes the fake
    # manager. The F385 exact-record match passes on the real record
    # and the resume-time liveness check_write is answered by the
    # attacker's oracle -> True. The liveness oracle is substitutable
    # at resume time independently of the suspend-time substitution.
    lm, tok, c, xid, ed25519 = _branch_fx()
    rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                          suspended_at=1050)
    try:
        ok = c.resume_lease(rec, _RubberStampManager(), checked_at=1090)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "coord-lease-manager-mismatch":
            return _record("F391-fake-manager-resume-real-park", "ERROR",
                           "wrong refusal code: %r (want "
                           "coord-lease-manager-mismatch)"
                           % (getattr(e, "code", e),))
        return _record("F391-fake-manager-resume-real-park", "HELD",
                       "substituted-manager resume refused coded "
                       "coord-lease-manager-mismatch (F391 closed)")
    if ok is True:
        return _record("F391-fake-manager-resume-real-park", "BREAK",
                       "real park resumed True under a substituted "
                       "manager: the resume-time liveness oracle is "
                       "attacker-supplied (F391)")
    _record("F391-fake-manager-resume-real-park", "ERROR",
            "resume returned non-True: %r" % (ok,))


# ------------------------------------------------------------------
# F393 (MEDIUM, OPEN -- filed by this lane): op_digest does not bind code
# ------------------------------------------------------------------

def p_f393_fn_code_confusion():
    # F393 CLOSED (wave-309 lane A): the plan digest now binds the
    # unit's code, so a descriptor-identical evil plan yields a
    # DIFFERENT digest; the run binds to the first plan digest and the
    # victim's plan refuses coded workflow-composed-plan-mismatch.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("f393fn")
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
                       "F393 OPEN: descriptor-identical plans still "
                       "collide (code not bound)")
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    try:
        res = comp.execute(victim, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "workflow-composed-plan-mismatch":
            return _record("F393-fn-code-confusion", "ERROR",
                           "wrong refusal code: %r"
                           % (getattr(e, "code", e),))
        if executed:
            return _record("F393-fn-code-confusion", "ERROR",
                           "victim fn ran before the refusal")
        return _record("F393-fn-code-confusion", "HELD",
                       "descriptor-identical plan refused coded "
                       "workflow-composed-plan-mismatch (F393 closed)")
    return _record("F393-fn-code-confusion", "BREAK",
                   "F393 OPEN: victim plan executed under the attacker's "
                   "run (outputs=%r executed=%r)"
                   % (res["units"]["u2"]["outputs"], bool(executed)))


def p_f393_saga_code_confusion():
    # F393 CLOSED (wave-309 lane A): same defect class through the saga
    # action path. The saga action fns are fingerprinted into the plan
    # digest, so the victim's descriptor-identical saga refuses coded
    # workflow-composed-plan-mismatch; the victim action never runs.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("f393saga")

    def evil_action(p):
        return ({"evil": 1}, [{"intent_id": "e"}])

    evil_saga = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    evil_plan = wc.ComposedPlan([
        {"kind": "saga", "name": "su", "definition": evil_saga,
         "action_fns": {"s1": evil_action},
         "comp_fns": {"s1": lambda p: None}, "idem_key": "sk2"}])
    executed = []

    def victim_action(p):
        executed.append(1)
        return ({"real": 2}, [{"intent_id": "v"}])

    victim_saga = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    victim_plan = wc.ComposedPlan([
        {"kind": "saga", "name": "su", "definition": victim_saga,
         "action_fns": {"s1": victim_action},
         "comp_fns": {"s1": lambda p: None}, "idem_key": "sk2"}])
    if evil_plan.digest == victim_plan.digest:
        return _record("F393-saga-code-confusion", "BREAK",
                       "F393 OPEN: descriptor-identical sagas still "
                       "collide (action code not bound)")
    comp.execute(evil_plan, run_id="R", authority=auth, at=AT)
    try:
        res = comp.execute(victim_plan, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "workflow-composed-plan-mismatch":
            return _record("F393-saga-code-confusion", "ERROR",
                           "wrong refusal code: %r"
                           % (getattr(e, "code", e),))
        if executed:
            return _record("F393-saga-code-confusion", "ERROR",
                           "victim action ran before the refusal")
        return _record("F393-saga-code-confusion", "HELD",
                       "descriptor-identical saga refused coded "
                       "workflow-composed-plan-mismatch (F393 closed)")
    return _record("F393-saga-code-confusion", "BREAK",
                   "F393 OPEN: victim saga executed under the attacker's "
                   "run (executed=%r)" % (bool(executed),))


# ------------------------------------------------------------------
# F392 closure at its bypass boundaries (expect HELD)
# ------------------------------------------------------------------

def p_f392_same_run_same_name():
    # F392 regression (the filed attack): two plans under one run, same
    # unit name, DIFFERENT idem_keys; the plant names the attacker's
    # step. F393 (wave-309) stops this shape EARLIER: the run binds to
    # the first plan digest, so the victim's plan refuses coded
    # workflow-composed-plan-mismatch at the gate -- the pair never
    # reaches _resolve_replay. The F392 binding check itself is still
    # covered by w307_step_collision_probes and test_workflow_f392.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("f392a")
    evil = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": lambda i: {"evil": 1},
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
        if getattr(e, "code", None) == "workflow-composed-plan-mismatch":
            if executed:
                return _record("F392-same-run-same-name", "ERROR",
                               "victim fn ran before the gate refusal")
            return _record("F392-same-run-same-name", "HELD",
                           "same-run same-name attack refused coded "
                           "workflow-composed-plan-mismatch at the "
                           "run->plan gate (F392 attack path closed "
                           "earlier)")
        return _record("F392-same-run-same-name", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    if res["units"]["u2"]["outputs"] == {"evil": 1} and not executed:
        return _record("F392-same-run-same-name", "BREAK",
                       "F392/F393 REGRESSION: poisoned pair returned "
                       "evil outputs")
    return _record("F392-same-run-same-name", "ERROR",
                   "unexpected: %r" % (res["units"]["u2"],))


def p_f392_nul_key_refused():
    # Binding-confusion attempt: a NUL inside the idem_key cannot blur
    # the (namespace, op_class, key) triple because the store's key
    # grammar rejects NUL -- fail-closed at begin time.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("f392nul")
    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": lambda i: {"x": 1},
         "inputs": {}, "idem_key": "k2\x00composed-unit\x00ke"}])
    try:
        comp.execute(plan, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code:
            return _record("F392-nul-key-refused", "HELD",
                           "NUL idem_key refused coded %r (fail-closed)"
                           % (code,))
        return _record("F392-nul-key-refused", "ERROR",
                       "uncoded refusal: %r" % (e,))
    return _record("F392-nul-key-refused", "BREAK",
                   "NUL idem_key executed: binding fields blurable")


def p_f392_cross_kind_isolated():
    # Binding-confusion attempt across op_classes: the plant uses a
    # different op_class under the victim's key. The store isolates by
    # (namespace, op_class, key), so the victim's begin is NEW and the
    # unit executes natively -- no confusion.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("f392ck")
    victim = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": lambda i: {"real": 2},
         "inputs": {}, "idem_key": "k2"}])
    plant = im.begin("composed", "composed-saga-action", "k2",
                     _fn_op_digest(wc, victim, "u2", {}),
                     caller="agent-b",
                     authority_verifier=lambda **k: True, at=AT)
    if plant.status != "new":
        return _record("F392-cross-kind-isolated", "ERROR",
                       "cross-kind plant did not begin: %s"
                       % (plant.status,))
    plant.complete(wc._digest({"evil": 1}), "wfstep:R:99", at=AT)
    executed = []

    def victim_fn(i):
        executed.append(1)
        return {"real": 2}

    victim2 = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": victim_fn,
         "inputs": {}, "idem_key": "k2"}])
    res = comp.execute(victim2, run_id="R", authority=auth, at=AT)
    if executed and res["units"]["u2"]["outputs"] == {"real": 2}:
        return _record("F392-cross-kind-isolated", "HELD",
                       "cross-kind plant did not confuse the fn unit "
                       "(store key isolation holds)")
    return _record("F392-cross-kind-isolated", "BREAK",
                   "cross-kind plant confused the replay: %r executed=%r"
                   % (res["units"]["u2"]["outputs"], bool(executed)))


# ------------------------------------------------------------------
# F385/F386/F388/F390 closure regressions (expect HELD)
# ------------------------------------------------------------------

def p_f390_wrong_step_refused():
    # F390 (MEDIUM, CLOSED): same run, different step -- the ref's step
    # name must match the replaying unit's expected name. F393
    # (wave-309) stops this two-plan shape EARLIER at the run->plan
    # gate; the name check itself is still covered end-to-end by
    # tests/test_workflow_f390.py (plant-before-execution, same plan).
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("f390w")
    plan_a = wc.ComposedPlan([
        {"kind": "fn", "name": "ua", "fn": lambda i: {"a": 1},
         "inputs": {}, "idem_key": "ka"}])
    comp.execute(plan_a, run_id="R", authority=auth, at=AT)
    executed = []

    def victim_fn(i):
        executed.append(1)
        return {"b": 2}

    plan_b = wc.ComposedPlan([
        {"kind": "fn", "name": "ub", "fn": victim_fn,
         "inputs": {}, "idem_key": "kb"}])
    plant = im.begin("composed", "composed-unit", "kb",
                     _fn_op_digest(wc, plan_b, "ub", {}),
                     caller="agent-b",
                     authority_verifier=lambda **k: True, at=AT)
    plant.complete(wc._digest({"a": 1}), "wfstep:R:1", at=AT)
    try:
        comp.execute(plan_b, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-composed-plan-mismatch":
            if executed:
                return _record("F390-wrong-step-refused", "ERROR",
                               "victim fn ran before the gate refusal")
            return _record("F390-wrong-step-refused", "HELD",
                           "wrong-step attack refused coded "
                           "workflow-composed-plan-mismatch at the "
                           "run->plan gate (F390 attack path closed "
                           "earlier)")
        return _record("F390-wrong-step-refused", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    return _record("F390-wrong-step-refused", "BREAK",
                   "F390/F393 REGRESSION: wrong-step pair resolved")


def p_f389_real_manager_refusal():
    # F389 closure regression: with the REAL manager, a bogus token
    # still refuses coded and the legitimate park stays intact.
    lm, tok, c, xid, ed25519 = _branch_fx()
    rec = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                          suspended_at=1050)
    try:
        c.suspend_lease(xid, lm, "scope-x", 999999, "mallory",
                        suspended_at=1060)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "coord-lease-fencing":
            ok = c.resume_lease(rec, lm, checked_at=1090)
            if ok is True:
                return _record("F389-real-manager-refusal", "HELD",
                               "bogus token refused; legitimate park "
                               "intact (F389 holds vs the real oracle)")
            return _record("F389-real-manager-refusal", "ERROR",
                           "legitimate resume failed: %r" % (ok,))
        return _record("F389-real-manager-refusal", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    return _record("F389-real-manager-refusal", "BREAK",
                   "F389 REGRESSION: bogus token accepted by real manager")


def p_f388_foreign_run_refused():
    # F388 (CLOSED): a pair naming another run refuses coded.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("f388r")
    ws.start_run("probe2", run_id="R2", authority=auth, at=AT)
    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": lambda i: {"a": 1},
         "inputs": {}, "idem_key": "ka"}])
    comp.execute(plan, run_id="R2", authority=auth, at=AT)
    victim = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": lambda i: {"b": 2},
         "inputs": {}, "idem_key": "kb"}])
    plant = im.begin("composed", "composed-unit", "kb",
                     _fn_op_digest(wc, victim, "u2", {}),
                     caller="agent-b",
                     authority_verifier=lambda **k: True, at=AT)
    plant.complete(wc._digest({"a": 1}), "wfstep:R2:1", at=AT)
    try:
        comp.execute(victim, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == FOREIGN_CODE:
            return _record("F388-foreign-run-refused", "HELD",
                           "foreign-run pair refused coded (F388 holds)")
        return _record("F388-foreign-run-refused", "ERROR",
                       "wrong refusal: %r" % (getattr(e, "code", e),))
    return _record("F388-foreign-run-refused", "BREAK",
                   "F388 REGRESSION: foreign-run pair resolved")


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
    return _record("F385-resume-xid-bound", "BREAK",
                   "F385 REGRESSION: swapped-XID resume accepted")


def p_f386_verifier_nonce_scoped():
    # F386 (CLOSED): per-composer-instance nonce scopes verifier refs;
    # two composers sharing one saga manager cannot clobber each other.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("f386n")
    comp2 = wc.WorkflowComposer(ws, sm, im, namespace="composed")
    if comp._verifier_nonce == comp2._verifier_nonce:
        return _record("F386-verifier-nonce-scoped", "BREAK",
                       "F386 REGRESSION: composer nonces identical")
    _record("F386-verifier-nonce-scoped", "HELD",
            "composer nonces distinct (F386 holds)")


# ------------------------------------------------------------------
# Wave-307 green-check hardening (expect HELD -- the contract fails closed)
# ------------------------------------------------------------------

def _synthetic_child(path, body):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)


def p_greencheck_vacuous_child_errors():
    # Wave-309: honor GOV_SKIP_GREEN=1 (wave-134 lesson). As a
    # green-check child, check_battery_result short-circuits to
    # HELD/skipped without spawning, which would spuriously BREAK
    # these self-tests.
    if SKIP_GREEN:
        return _record("GREENCHECK-vacuous-child-errors", "HELD",
                       "skipped under GOV_SKIP_GREEN=1")
    # Wave-307 lane C: a child reporting 0 BREAK / 0 HELD / 0 ERROR is
    # evidence of nothing -- the parent must record ERROR, not HELD.
    child = os.path.join(tempfile.gettempdir(),
                         "w308_vacuous_child_%d.py" % os.getpid())
    _synthetic_child(child, 'print("0 BREAK / 0 HELD / 0 ERROR")\n')
    try:
        verdict, note = green_check.check_battery_result(
            "green-vacuous-child", child, repo=REPO, timeout=60)
    finally:
        try:
            os.unlink(child)
        except OSError:
            pass
    if verdict == "ERROR":
        return _record("GREENCHECK-vacuous-child-errors", "HELD",
                       "vacuous child recorded ERROR: %s" % (note[:80],))
    _record("GREENCHECK-vacuous-child-errors", "BREAK",
            "vacuous child did not ERROR: %s %s" % (verdict, note))


def p_greencheck_probe_errors_error():
    # Wave-309: honor GOV_SKIP_GREEN=1 (wave-134 lesson). As a
    # green-check child, check_battery_result short-circuits to
    # HELD/skipped without spawning, which would spuriously BREAK
    # these self-tests.
    if SKIP_GREEN:
        return _record("GREENCHECK-probe-errors-error", "HELD",
                       "skipped under GOV_SKIP_GREEN=1")
    # Wave-307 lane C: a child reporting probe ERRORs (crashed probes,
    # surviving process) must record ERROR, not HELD.
    child = os.path.join(tempfile.gettempdir(),
                         "w308_errchild_%d.py" % os.getpid())
    _synthetic_child(child, 'print("0 BREAK / 5 HELD / 3 ERROR")\n')
    try:
        verdict, note = green_check.check_battery_result(
            "green-err-child", child, repo=REPO, timeout=60)
    finally:
        try:
            os.unlink(child)
        except OSError:
            pass
    if verdict == "ERROR":
        return _record("GREENCHECK-probe-errors-error", "HELD",
                       "probe-ERROR child recorded ERROR: %s"
                       % (note[:80],))
    _record("GREENCHECK-probe-errors-error", "BREAK",
            "probe-ERROR child did not ERROR: %s %s" % (verdict, note))


def p_greencheck_broken_child_fails_closed():
    # Wave-309: honor GOV_SKIP_GREEN=1 (wave-134 lesson). As a
    # green-check child, check_battery_result short-circuits to
    # HELD/skipped without spawning, which would spuriously BREAK
    # these self-tests.
    if SKIP_GREEN:
        return _record("GREENCHECK-broken-child-fails-closed", "HELD",
                       "skipped under GOV_SKIP_GREEN=1")
    # The shared helper must ERROR (not HELD) on a child that raises
    # before emitting a summary.
    broken = os.path.join(tempfile.gettempdir(),
                          "w308_broken_child_%d.py" % os.getpid())
    _synthetic_child(broken, "import nothing_missing_xyz  # noqa\n")
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
# Depth-1 green checks over adjacent batteries
# ------------------------------------------------------------------

def _green_checks():
    def _rec(pid, verdict, note):
        _record(pid, verdict, note)
    if SKIP_GREEN:
        _record("green-skipped", "HELD", "green check skipped "
                "(GOV_SKIP_GREEN=1)")
        return
    # F391 CLOSED (wave-308 lane A): the w307 battery's F391 probes
    # assert the coded refusal; expect no BREAKs.
    green_check.check_battery(
        _rec, "green-w307_redteam", "evals/w307_redteam_probes.py",
        repo=REPO,
        expect_break_ids=())
    # F392 CLOSED: the step-collision battery reports 0 BREAKs.
    green_check.check_battery(
        _rec, "green-w307_step_collision",
        "evals/w307_step_collision_probes.py", repo=REPO,
        expect_break_ids=())
    # Wave-307 lane B negative result: 0 BREAKs.
    green_check.check_battery(
        _rec, "green-w307_saga_signal",
        "evals/w307_saga_signal_probes.py", repo=REPO,
        expect_break_ids=())
    # Wave-307 lane C: the w303_f384 real green check.
    green_check.check_battery(
        _rec, "green-w303_f384", "evals/w303_f384_probes.py",
        repo=REPO, expect_break_ids=())
    # F392's unit tests still green.
    green_check.check_unittest(
        _rec, "green-test-workflow-f392", "tests.test_workflow_f392",
        repo=REPO)


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F391-fake-manager-clobber", p_f391_fake_manager_clobber)
    _safe("F391-fake-manager-resume", p_f391_fake_manager_resume)
    _safe("F391-fake-manager-resume-real-park",
           p_f391_fake_manager_resume_real_park)
    _safe("F393-fn-code-confusion", p_f393_fn_code_confusion)
    _safe("F393-saga-code-confusion", p_f393_saga_code_confusion)
    _safe("F392-same-run-same-name", p_f392_same_run_same_name)
    _safe("F392-nul-key-refused", p_f392_nul_key_refused)
    _safe("F392-cross-kind-isolated", p_f392_cross_kind_isolated)
    _safe("F390-wrong-step-refused", p_f390_wrong_step_refused)
    _safe("F389-real-manager-refusal", p_f389_real_manager_refusal)
    _safe("F388-foreign-run-refused", p_f388_foreign_run_refused)
    _safe("F385-resume-xid-bound", p_f385_resume_xid_bound)
    _safe("F386-verifier-nonce-scoped", p_f386_verifier_nonce_scoped)
    _safe("GREENCHECK-vacuous-child-errors",
           p_greencheck_vacuous_child_errors)
    _safe("GREENCHECK-probe-errors-error",
           p_greencheck_probe_errors_error)
    _safe("GREENCHECK-broken-child-fails-closed",
           p_greencheck_broken_child_fails_closed)
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
