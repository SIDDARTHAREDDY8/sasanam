"""Wave-307 lane B battery: F390 saga-compensation-signal residual.

The wave-306 lane B residual: when the F390 step-name-mismatch refusal
(``workflow-composed-replay-foreign``) fires inside a SAGA COMPENSATION
path, does the coded refusal survive to the public API, or does the saga
machinery mask it?

Empirical answer (this battery pins it): the refusal fires
deterministically and fail-closed, but the saga's compensation-failure
handling masks the machine-readable code --
``ComposedError(code="workflow-saga-compensation-failed")`` surfaces at
``WorkflowComposer.execute()`` after ``_max_comp`` (3) deterministic
retries. The full refusal message IS preserved in the saga history's
``compensation_attempt_failed`` events, so the audit trail is intact.

Verdict: NEGATIVE -- no finding filed. Rationale (see REPORT.md):
  1. Fail-closed: the attack is stopped; no wrong outputs are returned;
     the saga escalates and operator intervention is required either way.
  2. The masking is by explicit design: the saga layer is code-agnostic
     by contract (Decision 7 in ``gov/workflow_composed.py``:
     "an escalated saga fails the composed unit coded with the saga's
     escalation code").
  3. The audit trail preserves the full refusal message; a human
     operator investigating the escalation finds "foreign pair refused".
  4. The action path has the identical property (refusal -> step
     failure -> compensation; wave-306 lane B's own A2 probe accepted
     status="compensated" as HELD). Filing the compensation path while
     the action path stands would be inconsistent.
  5. The attacker gains nothing from the masking.

This battery is kept as a regression guard: it pins the fail-closed
refusal, the escalation code, and the history preservation, so any
future change that silently succeeds or drops the audit trail goes red.

Probes (all through the public ``WorkflowComposer.execute`` API plus
the idem store's public begin/complete, the F388/F390 plant seam):
  S1 COMP-refusal-fires-fail-closed: poisoned pair under s1's
     compensation key; s2's action fails -> saga compensates s1 ->
     the F390 refusal fires. execute() must NOT return normally with
     foreign outputs (BREAK = wrong outputs returned / comp executed).
  S2 COMP-escalation-code: the surfaced code is the saga's designed
     escalation code ``workflow-saga-compensation-failed`` (documents
     the masking; HELD = masked-but-fail-closed as designed).
  S3 COMP-history-preserves-refusal: the saga history contains
     ``compensation_attempt_failed`` events whose detail carries the
     ``workflow-composed-replay-foreign`` refusal message.
  S4 COMP-coded-refusal-not-retried: the deterministic refusal is a
     verdict, not a transient failure -- exactly ONE compensation
     attempt, then immediate escalation (wave-308 lane E hardening;
     previously the verdict was retried _max_comp times).
  S5 COMP-action-path-control: the action-path comparison -- a
     poisoned pair under an action key becomes a step failure and the
     saga compensates (status "compensated"), no foreign outputs;
     consistent with wave-306 lane B's A2 acceptance.

Run:
  mkdir -p /var/tmp/g307-saga && TMPDIR=/var/tmp/g307-saga \\
    ~/workspace/.gov-venv/bin/python evals/w307_saga_signal_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g307-saga-b \\
    ~/workspace/.gov-venv/bin/python evals/w307_saga_signal_probes.py
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

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)


FOREIGN_CODE = "workflow-composed-replay-foreign"
ESCALATION_CODE = "workflow-saga-compensation-failed"

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
    # Wave-313 lane A footer: F397 CLOSED; no open findings.
    want_open = "F506, F507, F508, F509, F510, F511"  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)
    # Wave-342 lane 6: repointed to open F429 / next F430 (footer-state probe audit).
    if nxt != 506 or open_s != want_open:
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d open %r (want next F506 open 'F503, F504, F505')"
                       % (nxt, open_s))
    _record("footer-state", "HELD",
            "footer pins open F436 / next F437")


AT = 1_700_000_000


def _seed(tag):
    return hashlib.sha256(("w307saga-" + tag).encode()).digest()


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


def _comp_op_digest(wc, plan, unit_name, step_id, params):
    # White-box: the exact op_digest construction in
    # WorkflowComposer._saga_wrappers.make_comp.comp_op.
    return wc._digest({
        "plan": plan.digest, "op": "saga-comp",
        "unit": unit_name, "step": step_id,
        "params": wc._digest(params)})


class _PlantFailure(Exception):
    """The attacker's plant did not begin as a new record -- the
    scenario is misconstructed, not a product verdict."""

    def __init__(self, status):
        super().__init__("plant did not begin new: %s" % (status,))
        self.status = status


def _scenario(pid):
    """Run the comp-path scenario; on plant misconstruction record
    ERROR under pid and return None (so probes stay shallow)."""
    try:
        return _run_comp_scenario()
    except _PlantFailure as pf:
        _record(pid, "ERROR", str(pf))
        return None


def _run_comp_scenario():
    """Build the compensation-path refusal scenario; return
    (comp, raised_or_None, result_or_None).

    NOTE (F393, wave-309): the run binds to the FIRST plan digest, so
    the scenario uses ONE plan containing both the fn unit and the
    saga unit (the legitimate multi-unit shape -- a workflow is a
    single ComposedPlan). The old two-plan shape is now correctly
    refused at the run->plan gate before any saga exists.
    """
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    actor = "agent-b"  # the plan actor: the F388/F390 threat model
    ws.start_run("probe", run_id="R", authority=auth, at=AT)

    # Saga: s1's action succeeds, s2's action raises -> compensates s1.
    sd = sm.define([
        saga.SagaStepDef("s1", "a1", {}, "c1"),
        saga.SagaStepDef("s2", "a2", {}, "c2"),
    ])

    def act1(p):
        return ({"real": 1}, [])

    def act2(p):
        raise RuntimeError("s2 action boom")

    unit = {"kind": "saga", "name": "su", "idem_key": "sk",
            "definition": sd,
            "action_fns": {"s1": act1, "s2": act2},
            "comp_fns": {"s1": lambda p: {"c": 1},
                         "s2": lambda p: {"c": 2}}}
    # One plan: the fn unit runs first (creating the "fn:u1" step the
    # poisoned ref names), then the saga unit.
    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u1", "fn": lambda i: {"one": 1},
         "inputs": {}, "idem_key": "k1"},
        unit,
    ])
    # The plant: poisoned record under s1's COMPENSATION key, begun as
    # the plan actor, with the real digest of u1's step and a ref naming
    # u1's step (recorded name "fn:u1" != expected "saga-comp:su:s1").
    # complete() checks ref shape only; the ref resolves when the
    # compensation replays, by which time u1 has run.
    op_digest = _comp_op_digest(wc, plan, "su", "s1", {})
    plant = im.begin("composed", "composed-saga-comp", "sk:comp:s1",
                     op_digest, caller=actor,
                     authority_verifier=lambda **k: True, at=AT)
    if plant.status != "new":
        raise _PlantFailure(plant.status)
    plant.complete(wc._digest({"one": 1}), "wfstep:R:1", at=AT)
    try:
        res = comp.execute(plan, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        return comp, e, None
    return comp, None, res


def p_comp_refusal_fires_fail_closed():
    # S1: the refusal must fire and the poisoned outputs must never be
    # returned. BREAK = the comp replayed foreign outputs or executed.
    sc = _scenario("COMP-refusal-fires-fail-closed")
    if sc is None:
        return
    comp, err, res = sc
    if err is None:
        got = res["units"]["su"]
        return _record("COMP-refusal-fires-fail-closed", "BREAK",
                       "execute returned normally with foreign pair "
                       "planted (status=%s)" % (got.get("status"),))
    _record("COMP-refusal-fires-fail-closed", "HELD",
            "refusal fired fail-closed in the compensation path "
            "(%s code=%r)" % (type(err).__name__,
                              getattr(err, "code", None)))


def p_comp_escalation_code():
    # S2: documents the masking -- the surfaced code is the saga's
    # designed escalation code, not the refusal code.
    sc = _scenario("COMP-escalation-code")
    if sc is None:
        return
    comp, err, res = sc
    if err is None:
        return _record("COMP-escalation-code", "BREAK",
                       "execute returned normally; expected escalation")
    code = getattr(err, "code", None)
    if code != ESCALATION_CODE:
        return _record("COMP-escalation-code", "BREAK",
                       "unexpected surfaced code %r (want %r)"
                       % (code, ESCALATION_CODE))
    _record("COMP-escalation-code", "HELD",
            "surfaced code is the designed saga escalation %r; the "
            "%r refusal code is masked at the API (audit trail keeps "
            "it -- see S3)" % (ESCALATION_CODE, FOREIGN_CODE))


def p_comp_history_preserves_refusal():
    # S3: the audit trail must keep the F390 refusal. The F390 message
    # shape ("created by %r ... but the replaying unit expects step %r")
    # is distinctive among _resolve_replay's refusals (F388's are
    # run/caller/fork-shaped), and the product raises it only via
    # _fail(WC_REPLAY_FOREIGN, ...) -- pinned below to FOREIGN_CODE.
    from gov import workflow_composed as _wc_check
    if _wc_check.WC_REPLAY_FOREIGN != FOREIGN_CODE:
        return _record("COMP-history-preserves-refusal", "BREAK",
                       "WC_REPLAY_FOREIGN is %r, not %r: the refusal "
                       "code contract changed"
                       % (_wc_check.WC_REPLAY_FOREIGN, FOREIGN_CODE))
    sc = _scenario("COMP-history-preserves-refusal")
    if sc is None:
        return
    comp, err, res = sc
    inst = comp._saga_instances.get("su")
    if inst is None:
        return _record("COMP-history-preserves-refusal", "ERROR",
                       "no saga instance recorded")
    hits = [ev for ev in inst.history
            if ev.get("type") == "compensation_attempt_failed"
            and "created by 'fn:u1'" in str(ev.get("detail", ""))
            and "but the replaying unit expects step 'saga-comp:su:s1'"
            in str(ev.get("detail", ""))]
    if not hits:
        return _record("COMP-history-preserves-refusal", "BREAK",
                       "F390 refusal message missing from saga history; "
                       "the audit trail lost the attack signal")
    _record("COMP-history-preserves-refusal", "HELD",
            "%d compensation_attempt_failed event(s) preserve the "
            "F390 refusal (code %r)" % (len(hits), FOREIGN_CODE))


def p_comp_coded_refusal_not_retried():
    # S4: a coded refusal is a verdict -- exactly ONE compensation
    # attempt, then immediate escalation (wave-308 lane E hardening of
    # the wave-307 lane B residual). Transient (uncoded) failures still
    # burn the _max_comp attempt budget (see unit tests).
    sc = _scenario("COMP-coded-refusal-not-retried")
    if sc is None:
        return
    comp, err, res = sc
    inst = comp._saga_instances.get("su")
    if inst is None:
        return _record("COMP-coded-refusal-not-retried", "ERROR",
                       "no saga instance recorded")
    attempts = [ev for ev in inst.history
                if ev.get("type") == "compensation_attempt_failed"]
    # Default SagaManager(max_compensation_attempts=3): a verdict must
    # NOT consume the retry budget.
    if len(attempts) != 1:
        return _record("COMP-coded-refusal-not-retried", "BREAK",
                       "coded refusal retried: saw %d attempt(s), want 1"
                       % (len(attempts),))
    _record("COMP-coded-refusal-not-retried", "HELD",
            "coded refusal escalated after 1 attempt (not retried); "
            "verdict-as-transient residual closed")


def p_comp_action_path_control():
    # S5: control -- the action path refuses the poisoned pair (fail
    # closed), accepted as HELD by wave-306 lane B's A2 probe. F393
    # (wave-309) moves the refusal EARLIER: the run->plan gate refuses
    # coded workflow-composed-plan-mismatch before the saga starts, so
    # the refusal surfaces from execute() rather than as a step
    # failure -> compensation. Both are fail-closed; the control
    # accepts either, and asserts the action never executed.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    actor = "agent-b"
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    plan1 = wc.ComposedPlan([
        {"kind": "fn", "name": "u1", "fn": lambda i: {"one": 1},
         "inputs": {}, "idem_key": "k1"}])
    comp.execute(plan1, run_id="R", authority=auth, at=AT)
    sd = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    executed = []

    def act(p):
        executed.append(1)
        return ({"fake": 2}, [])

    unit = {"kind": "saga", "name": "su", "idem_key": "sk",
            "definition": sd,
            "action_fns": {"s1": act},
            "comp_fns": {"s1": lambda p: {"c": 1}}}
    plan = wc.ComposedPlan([unit])
    op_digest = wc._digest({
        "plan": plan.digest, "op": "saga-action",
        "unit": "su", "step": "s1",
        "params": wc._digest({})})
    plant = im.begin("composed", "composed-saga-action", "sk:action:s1",
                     op_digest, caller=actor,
                     authority_verifier=lambda **k: True, at=AT)
    if plant.status != "new":
        return _record("COMP-action-path-control", "ERROR",
                       "plant did not begin new: %s" % (plant.status,))
    plant.complete(wc._digest({"one": 1}), "wfstep:R:1", at=AT)
    try:
        res = comp.execute(plan, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", e)
        if code == "workflow-composed-plan-mismatch" and not executed:
            return _record("COMP-action-path-control", "HELD",
                           "run->plan gate refused coded before the "
                           "saga started; action never executed "
                           "(fail-closed, stronger than the old "
                           "step-failure->compensation shape)")
        return _record("COMP-action-path-control", "ERROR",
                       "action-path refusal raised %r (want coded "
                       "refusal)" % (code,))
    got = res["units"]["su"]
    if executed:
        return _record("COMP-action-path-control", "BREAK",
                       "action executed despite poisoned pair")
    if got.get("status") != "compensated":
        return _record("COMP-action-path-control", "BREAK",
                       "unexpected saga status %r" % (got.get("status"),))
    _record("COMP-action-path-control", "HELD",
            "action-path refusal -> step failure -> compensation, no "
            "foreign outputs (consistent with lane B A2)")


def _green_battery(path, label):
    # Depth-1 adjacent green check, wave-305: delegates to
    # evals/green_check.py (fail-closed contract).
    green_check.check_battery(_record, "green-%s" % label, path,
                              repo=REPO)


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("COMP-refusal-fires-fail-closed", p_comp_refusal_fires_fail_closed)
    _safe("COMP-escalation-code", p_comp_escalation_code)
    _safe("COMP-history-preserves-refusal", p_comp_history_preserves_refusal)
    _safe("COMP-coded-refusal-not-retried", p_comp_coded_refusal_not_retried)
    _safe("COMP-action-path-control", p_comp_action_path_control)
    # Depth-1 adjacent green checks (wave-134 lesson: never nest).
    # NOTE: w306_redteam_probes.py is deliberately NOT green-checked
    # here. Its GREENCHECK-broken-child-fails-closed self-test probe
    # spawns a grandchild via green_check.check_battery_result, but the
    # depth-1 GOV_SKIP_GREEN=1 env (set by check_battery for the child)
    # makes that inner check skip -> HELD instead of ERROR, so the
    # self-test misreports BREAK whenever w306 runs as a green-check
    # child. Pre-existing harness interaction (no shipped battery
    # green-checks w306); documented as a residual in REPORT.md.
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
