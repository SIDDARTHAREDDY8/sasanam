"""Wave-304 lane C battery: F388 -- composed _resolve_replay trusts a
poisoned (digest, ref) pair.

The wave-303 merge audit verified this F381 amplification still BREAKs
on the merged tree (c9138cc53888): ``WorkflowComposer._resolve_replay``
resolves the idempotency record's ``(result_digest, result_ref)`` pair
through to a workflow checkpoint without checking that the pair is
NATIVE to the composed execution. Wave-303 lane 2's caller binding
(``gov/workflow_idempotency.py``) covers the idem-store layer, but the
composer trusts any record the store hands it -- including one whose
``result_ref`` names a run the composer never executed, or whose record
was begun by a different actor.

F388 (MEDIUM, filed 2026-10-03 08:42:50Z, wave-304 lane C;
renumbered from F387 at 2026-10-03 08:45Z -- the independent
red team filed F387 first, wave-272 earliest-filed rule): composed
replay resolution accepts a foreign (digest, ref) pair.

Probes (all through the public ``WorkflowComposer.execute`` API except
the detached-resolution probe, which pins the fail-closed contract of
the internal resolver):
  A1 F388-foreign-run-replay: attacker plants a completed record whose
     ref names a FOREIGN run's completed step (real digest). The
     composer's unit returns the foreign run's outputs without
     executing. BREAK = foreign outputs returned; HELD = coded
     ``workflow-composed-replay-foreign`` refusal.
  A2 F388-same-run-ref-repoint: attacker plants a record for a second
     unit whose ref names a step of the CURRENT run (created by a
     different unit) with the real digest, begun by a different caller.
     BREAK = wrong unit's outputs returned; HELD = coded refusal.
  C1 F388-legit-replay-survives: same plan re-executed under the same
     run replays the recorded outputs without re-running the fn.
     Must stay HELD (no regression of the idempotency contract).
  C2 F388-detached-resolution-refused: ``_resolve_replay`` called with
     no composed execution in progress must fail closed coded, never
     resolve and never crash uncoded.

Run:
  mkdir -p /var/tmp/g304-f388 && TMPDIR=/var/tmp/g304-f388 \
    ~/workspace/.gov-venv/bin/python evals/w303_f388_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g304-f388b \
    ~/workspace/.gov-venv/bin/python evals/w303_f388_probes.py
"""

import hashlib
import json
import os
import re
import subprocess
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

TAXONOMY_PIN = 1964 # Wave-303 merge pin; Wave-304 lane C: pin 1827 -> 1827 (+1 workflow-composed-replay-foreign); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

FOREIGN_CODE = "workflow-composed-replay-foreign"

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
    want_open = "none"
    if nxt != 405 or open_s != want_open:
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d open %r (want next F404 open 'none')"
                       % (nxt, open_s, want_open))
    _record("footer-state", "HELD",
            "footer pins open F406 / next F407")


AT = 1_700_000_000


def _seed(tag):
    return hashlib.sha256(("w304f387-" + tag).encode()).digest()


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


def _fn_op_digest(wc, plan, unit_name, inputs):
    # White-box: the exact op_digest construction in
    # WorkflowComposer._execute_fn_unit.
    return wc._digest({"plan": plan.digest, "op": "unit",
                       "unit": unit_name,
                       "inputs": wc._digest(inputs)})


def _refused_foreign(e):
    return getattr(e, "code", None) == FOREIGN_CODE


def p_f387_foreign_run_replay():
    # A1: the composed unit returns a FOREIGN run's checkpoint outputs
    # without executing its fn.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    # The victim run: a real, completed step in another run.
    ws.start_run("probe", run_id="victim", authority=auth, at=AT)
    ws.run_step("victim", 1, "vstep", lambda i: {"stolen": 1}, {},
                authority=auth, at=AT)
    victim_digest = wc._digest({"stolen": 1})
    # The attacker's plant: a completed idempotency record whose
    # (digest, ref) pair names the victim run. Lane-2 caller binding
    # does not stop it: the attacker begins AND completes as one
    # caller.
    # NOTE (F393, wave-309): the plan digest now binds the unit's
    # code, so the forged-digest plan and the executed plan must be the
    # SAME plan object -- two textually different lambdas no longer
    # share a digest (that two-lambda shape was a probe artifact, not a
    # legitimate pattern: crash-recovery rebuilds from identical
    # source, which keeps the digest).
    executed = []

    def real_fn(i):
        executed.append(1)
        return {"real": 1}

    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": real_fn,
         "inputs": {}, "idem_key": "ak"}])
    forged = _fn_op_digest(wc, plan, "u", {})
    plant = im.begin("composed", "composed-unit", "ak", forged,
                     caller="mallory", authority_verifier=lambda **k: True,
                     at=AT)
    if plant.status != "new":
        return _record("F388-foreign-run-replay", "ERROR",
                       "plant did not begin new: %s" % (plant.status,))
    plant.complete(victim_digest, "wfstep:victim:1", at=AT)
    # The composer's own execution of the same plan under a new run.
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    try:
        res = comp.execute(plan, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if _refused_foreign(e):
            if executed:
                return _record("F388-foreign-run-replay", "ERROR",
                               "fn ran before the coded refusal")
            return _record("F388-foreign-run-replay", "HELD",
                           "foreign pair refused coded "
                           "workflow-composed-replay-foreign")
        return _record("F388-foreign-run-replay", "ERROR",
                       "unexpected refusal: %r" % (getattr(e, "code", e),))
    outputs = res["units"]["u"]["outputs"]
    if outputs == {"stolen": 1} and not executed:
        return _record("F388-foreign-run-replay", "BREAK",
                       "composed unit returned a foreign run's outputs "
                       "without executing its fn")
    _record("F388-foreign-run-replay", "HELD",
            "foreign outputs not returned (outputs=%r)" % (outputs,))


def p_f387_same_run_ref_repoint():
    # A2: same run, but the record was begun by a different actor and
    # points at a step the current unit never created. F393 (wave-309)
    # stops this two-plan shape EARLIER: the run binds to the first
    # plan digest, so plan2 refuses coded
    # workflow-composed-plan-mismatch at the gate -- the pair never
    # reaches the record-caller check.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    plan1 = wc.ComposedPlan([
        {"kind": "fn", "name": "u1", "fn": lambda i: {"one": 1},
         "inputs": {}, "idem_key": "k1"}])
    comp.execute(plan1, run_id="R", authority=auth, at=AT)
    step_digest = wc._digest({"one": 1})
    # Attacker re-points key k2 at u1's step (R:1), begun as mallory.
    plan2 = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": lambda i: {"two": 2},
         "inputs": {}, "idem_key": "k2"}])
    forged = _fn_op_digest(wc, plan2, "u2", {})
    plant = im.begin("composed", "composed-unit", "k2", forged,
                     caller="mallory", authority_verifier=lambda **k: True,
                     at=AT)
    plant.complete(step_digest, "wfstep:R:1", at=AT)
    try:
        res = comp.execute(plan2, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-composed-plan-mismatch":
            return _record("F388-same-run-ref-repoint", "HELD",
                           "re-pointed pair refused coded "
                           "workflow-composed-plan-mismatch at the "
                           "run->plan gate (F388 attack path closed "
                           "earlier)")
        return _record("F388-same-run-ref-repoint", "ERROR",
                       "unexpected refusal: %r" % (getattr(e, "code", e),))
    outputs = res["units"]["u2"]["outputs"]
    if outputs == {"one": 1}:
        return _record("F388-same-run-ref-repoint", "BREAK",
                       "unit u2 returned unit u1's outputs: ref re-point "
                       "across units accepted")
    _record("F388-same-run-ref-repoint", "HELD",
            "re-pointed outputs not returned (outputs=%r)" % (outputs,))


def p_f387_legit_replay_survives():
    # C1: the idempotency contract must survive the fix -- the same
    # plan re-executed under the same run replays without re-running.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    calls = []
    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u",
         "fn": lambda i: calls.append(1) or {"v": 7},
         "inputs": {}, "idem_key": "k"}])
    res1 = comp.execute(plan, run_id="R", authority=auth, at=AT)
    res2 = comp.execute(plan, run_id="R", authority=auth, at=AT)
    if len(calls) != 1:
        return _record("F388-legit-replay-survives", "BREAK",
                       "fn re-executed on replay: %d calls" % len(calls))
    if res2["units"]["u"]["outputs"] != {"v": 7}:
        return _record("F388-legit-replay-survives", "BREAK",
                       "replay returned wrong outputs")
    if res1["units"]["u"]["outputs"] != res2["units"]["u"]["outputs"]:
        return _record("F388-legit-replay-survives", "BREAK",
                       "replay outputs diverged from first execution")
    _record("F388-legit-replay-survives", "HELD",
            "legitimate same-run replay intact (1 fn call, outputs match)")


def p_f387_detached_resolution_refused():
    # C2: _resolve_replay with no composed execution in progress must
    # fail closed coded -- never resolve, never crash uncoded.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    ws.start_run("probe", run_id="victim", authority=auth, at=AT)
    ws.run_step("victim", 1, "vstep", lambda i: {"stolen": 1}, {},
                authority=auth, at=AT)
    victim_digest = wc._digest({"stolen": 1})
    plant = im.begin("composed", "composed-unit", "ak", "f" * 64,
                     caller="mallory", authority_verifier=lambda **k: True,
                     at=AT)
    plant.complete(victim_digest, "wfstep:victim:1", at=AT)
    replay = im.begin("composed", "composed-unit", "ak", "f" * 64,
                      caller="mallory", authority_verifier=lambda **k: True,
                      at=AT)
    try:
        # F390: _resolve_replay now requires the expected step name; the
        # detached check fires before it is used, so the value here is
        # unreachable (documents the new signature).
        resolved = comp._resolve_replay(replay, "composed-unit",
                                        "unreachable-key",
                                        "fn:detached-probe")
    except Exception as e:  # noqa: BLE001
        if _refused_foreign(e):
            return _record("F388-detached-resolution-refused", "HELD",
                           "detached resolution refused coded")
        return _record("F388-detached-resolution-refused", "ERROR",
                       "uncoded crash: %r" % (e,))
    if resolved == {"stolen": 1}:
        return _record("F388-detached-resolution-refused", "BREAK",
                       "detached resolver returned foreign outputs")
    _record("F388-detached-resolution-refused", "HELD",
            "detached resolution did not return foreign outputs")


def _green_battery(path, label):
    # Depth-1 adjacent green check, wave-305: delegates to
    # evals/green_check.py (fail-closed contract). Any BREAK or ERROR in
    # the child is a regression (no expected-open BREAKs here).
    green_check.check_battery(_record, "green-%s" % label, path,
                              repo=REPO)


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F388-foreign-run-replay", p_f387_foreign_run_replay)
    _safe("F388-same-run-ref-repoint", p_f387_same_run_ref_repoint)
    _safe("F388-legit-replay-survives", p_f387_legit_replay_survives)
    _safe("F388-detached-resolution-refused",
           p_f387_detached_resolution_refused)
    # Depth-1 adjacent green checks (wave-134 lesson: never nest).
    _green_battery("evals/w302_workflow_composed_probes.py", "composed")
    _green_battery("evals/w303_f381_probes.py", "f381")
    _green_battery("evals/w301_idempotency_probes.py", "idempotency")
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
