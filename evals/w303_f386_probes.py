"""Wave-304 lane B battery: F386 closure probes vs the wave-303 merge.
Wave-305 lane C addition: op-registry cleanup hygiene probes.

Base: wave-303 merge c9138cc53888 (F380-F384 closed, F385/F386 open,
pin 1827, footer open F385,F386 / next free F387).

F386 (LOW, OPEN) -- gov/workflow_composed.py installed saga authority
verifiers into the shared process-global SagaManager under plan-scoped
refs bound to per-composer-instance mutable context, and never removed
them. A second composer sharing the manager overwrote the first's
verifier: the first composer's in-flight saga then failed closed into
escalation (workflow-saga-compensation-unauthorized) during reentrant
same-plan execution. A masked second collision existed too: the wrapper
ops were registered in the process-global op registry under plan-scoped
names, so the second composer's registration shadowed the first's
compensation closures (reading the second composer's _exec_ctx).

Close-when: per-composer-instance nonce in verifier refs plus entry
removal on unit completion. The fix additionally scopes the registered
op names to the composer instance (same close-when spirit: everything a
composer installs on a shared registry is composer-scoped).

Run:
  mkdir -p /var/tmp/g304-f386 && TMPDIR=/var/tmp/g304-f386 \
    ~/workspace/.gov-venv/bin/python evals/w303_f386_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g304-f386b \
    ~/workspace/.gov-venv/bin/python evals/w303_f386_probes.py
"""

import hashlib
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
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)


# Wave-312 merge: the F395 closure contract (coded
# workflow-composed-definition-invalid for non-JSON-native closed-over
# values) fires on this battery's instrumentation closures. Probes that
# need live objects during execution look them up here by a JSON-native
# key instead of closing over them (afab9a59 precedent). F395-safe: the
# registry is process-global, so identical code resolves identical
# objects -- no confusion.
_F386_PROBE_STATE = {}

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
    _record("pin-taxonomy", "HELD", "2135/2135/0 sorted")




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
    want_open = "F503, F504, F505"  # this lane: F386 CLOSED
    # Wave-342 lane 6: repointed to open F429 / next F430 (footer-state probe audit).
    if nxt != 506 or open_s != want_open:
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d open %r (want next F503 open 'F503, F504, F505')"
                       % (nxt, open_s))
    _record("footer-state", "HELD",
            "footer pins open F436 / next F437")


AT = 1_700_000_000


def _seed(tag):
    return hashlib.sha256((b"w304f386-" + tag)).digest()


def _fixture():
    from gov import delegation as dg
    from gov import ed25519
    sa, sb = _seed(b"a"), _seed(b"b")
    pa, pb = ed25519.publickey(sa).hex(), ed25519.publickey(sb).hex()
    cons = {"expires_at": AT + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root = dg.issue(sa, "agent-a", "agent-b", pb, ("tool.invoke",),
                    issued_at=AT, constraints=dict(cons))
    return sa, sb, pa, pb, root


def _harness():
    from gov import delegation_revocation as rv
    from gov import workflow as wf
    from gov import workflow_idempotency as idem
    from gov import workflow_saga as saga
    import gov.workflow_composed as wc
    saga.clear_ops()
    sa, sb, pa, pb, root = _fixture()
    ledger = rv.DelegationRevoker(sa, "agent-a")
    auth = {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": [root], "trust_roots": [pa],
            "revocation_ledger": ledger}
    ws = wf.WorkflowStore()
    sm = saga.SagaManager()
    return {
        "sa": sa, "sb": sb, "pa": pa, "pb": pb, "root": root,
        "ledger": ledger, "auth": auth, "ws": ws, "sm": sm,
        "idem": idem, "saga": saga, "wc": wc,
        "composer": lambda: wc.WorkflowComposer(
            ws, sm, idem.IdempotencyStore()),
    }


def _boom_plan(h, key="ck", comp_fns=None):
    saga, wc = h["saga"], h["wc"]

    def ok(i):
        return ({"r": 1}, [])

    def boom(i):
        raise RuntimeError("kaboom")

    def comp(i):
        return {"u": 1}

    sd = h["sm"].define([
        saga.SagaStepDef("s1", "a1", {}, "c1"),
        saga.SagaStepDef("s2", "a2", {}, "c2"),
        saga.SagaStepDef("s3", "a3", {}, "c3")])
    return wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ok, "s2": ok, "s3": boom},
         "comp_fns": comp_fns or {"s1": comp, "s2": comp, "s3": comp},
         "idem_key": key}])


def p_f386_verifier_collision():
    # The w303 red-team F386 probe shape: two composers share one
    # SagaManager; the second reentrantly executes the SAME plan from
    # inside the first's compensation. Pre-fix: c1 escalated coded
    # workflow-saga-compensation-unauthorized.
    h = _harness()
    wc = h["wc"]
    c1, c2 = h["composer"](), h["composer"]()
    h["ws"].start_run("probe", run_id="col-r1", authority=h["auth"], at=AT)
    h["ws"].start_run("probe", run_id="col-r2", authority=h["auth"], at=AT)

    def ok(i):
        return ({"r": 1}, [])

    def boom(i):
        raise RuntimeError("kaboom")

    def comp_s1(i):
        return {"u": 1}

    def comp_s2(i):
        # F395 contract: no exotic closures (c2/plan/entered/h). The
        # reentrant execution targets travel via the module registry.
        st = _F386_PROBE_STATE["col"]
        if st["entered"]["n"] == 0:
            st["entered"]["n"] += 1
            st["c2"].execute(st["plan"], run_id="col-r2",
                             authority=st["auth"], at=AT)
        return {"u": 2}

    saga = h["saga"]
    sd = h["sm"].define([
        saga.SagaStepDef("s1", "a1", {}, "c1"),
        saga.SagaStepDef("s2", "a2", {}, "c2"),
        saga.SagaStepDef("s3", "a3", {}, "c3")])
    plan = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ok, "s2": ok, "s3": boom},
         "comp_fns": {"s1": comp_s1, "s2": comp_s2, "s3": comp_s1},
         "idem_key": "ck"}])
    _F386_PROBE_STATE["col"] = {"entered": {"n": 0}, "c2": c2,
                                "plan": plan, "auth": h["auth"]}
    try:
        res = c1.execute(plan, run_id="col-r1", authority=h["auth"], at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        return _record(
            "F386-verifier-collision", "BREAK",
            "reentrant same-plan execution escalated: coded %r (%r)"
            % (code, e))
    finally:
        _F386_PROBE_STATE.pop("col", None)
    if res["units"]["sg"]["status"] != "compensated":
        return _record("F386-verifier-collision", "BREAK",
                       "unexpected status %r"
                       % (res["units"]["sg"]["status"],))
    _record("F386-verifier-collision", "HELD",
            "reentrant same-plan execution compensates cleanly")


def p_f386_verifier_removed():
    # Verifier entries must not outlive the unit: after a successful
    # unit AND after a failed (escalated) unit, the shared manager
    # holds no composed-auth entries for the composer.
    h = _harness()
    wc = h["wc"]
    c1 = h["composer"]()
    h["ws"].start_run("probe", run_id="rm-r1", authority=h["auth"], at=AT)
    plan = _boom_plan(h, key="rmk1")
    res = c1.execute(plan, run_id="rm-r1", authority=h["auth"], at=AT)
    if res["units"]["sg"]["status"] != "compensated":
        return _record("F386-verifier-removed", "BREAK",
                       "setup: expected compensated, got %r"
                       % (res["units"]["sg"]["status"],))
    leaks = [k for k in h["sm"]._verifiers if "composed-auth:" in k]
    if leaks:
        return _record("F386-verifier-removed", "BREAK",
                       "verifier entry leaked after success: %r" % (leaks,))

    c2 = h["composer"]()
    h["ws"].start_run("probe", run_id="rm-r2", authority=h["auth"], at=AT)

    def bad_comp(i):
        raise RuntimeError("compensation still broken")

    plan2 = _boom_plan(h, key="rmk2",
                       comp_fns={"s1": bad_comp, "s2": bad_comp,
                                 "s3": bad_comp})
    try:
        c2.execute(plan2, run_id="rm-r2", authority=h["auth"], at=AT)
        return _record("F386-verifier-removed", "BREAK",
                       "setup: broken compensation did not escalate")
    except Exception:  # noqa: BLE001 -- expected escalation
        pass
    leaks = [k for k in h["sm"]._verifiers if "composed-auth:" in k]
    if leaks:
        return _record("F386-verifier-removed", "BREAK",
                       "verifier entry leaked after failure: %r" % (leaks,))
    _record("F386-verifier-removed", "HELD",
            "no verifier entries linger after success or failure")


def p_f386_op_names_scoped():
    # The process-global op registry must not keep plan-scoped
    # (unscoped) composed op names: every registered composed op name
    # carries the installing composer's nonce (checked DURING
    # execution via a spy), and -- wave-305 hygiene -- no scoped
    # entries linger after the unit completes.
    h = _harness()
    saga = h["saga"]
    c1, c2 = h["composer"](), h["composer"]()
    h["ws"].start_run("probe", run_id="op-r1", authority=h["auth"], at=AT)
    h["ws"].start_run("probe", run_id="op-r2", authority=h["auth"], at=AT)

    _F386_PROBE_STATE["op"] = {"seen": {}, "saga": saga}

    def ok(i):
        # F395 contract: no exotic closures (seen/saga). Live objects
        # travel via the module registry.
        st = _F386_PROBE_STATE["op"]
        st["seen"].setdefault("names", []).extend(
            k for k in st["saga"].registered_ops()
            if k.startswith("composed:"))
        return ({"r": 1}, [])

    def comp(i):
        return {"u": 1}

    sd = h["sm"].define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    wc = h["wc"]
    p1 = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ok}, "comp_fns": {"s1": comp},
         "idem_key": "opk1"}])
    p2 = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ok}, "comp_fns": {"s1": comp},
         "idem_key": "opk2"}])
    try:
        c1.execute(p1, run_id="op-r1", authority=h["auth"], at=AT)
        c2.execute(p2, run_id="op-r2", authority=h["auth"], at=AT)
    finally:
        seen = _F386_PROBE_STATE.pop("op", {}).get("seen", {})
    n1, n2 = c1._verifier_nonce, c2._verifier_nonce
    during = seen.get("names", [])
    unscoped = [k for k in during
                if k.startswith("composed:") and n1 not in k
                and n2 not in k]
    if unscoped:
        return _record("F386-op-names-scoped", "BREAK",
                       "unscoped composed op names registered: %r"
                       % (unscoped[:3],))
    if not any(n1 in k for k in during):
        return _record("F386-op-names-scoped", "BREAK",
                       "c1's scoped op names never visible during execution")
    if not any(n2 in k for k in during):
        return _record("F386-op-names-scoped", "BREAK",
                       "c2's scoped op names never visible during execution")
    lingering = [k for k in saga.registered_ops()
                 if k.startswith("composed:")]
    if lingering:
        return _record("F386-op-names-scoped", "BREAK",
                       "scoped op names linger after completion: %r"
                       % (lingering[:3],))
    _record("F386-op-names-scoped", "HELD",
            "op names composer-scoped during execution, removed after")


def p_f386_compensation_authority_intact():
    # F379/F384 semantics intact: compensation re-proves the step
    # authority NOW. Revoking the root delegation mid-flight must still
    # refuse compensation coded workflow-saga-compensation-unauthorized.
    h = _harness()
    wc = h["wc"]
    c1 = h["composer"]()
    h["ws"].start_run("probe", run_id="au-r1", authority=h["auth"], at=AT)

    def ok(i):
        return ({"r": 1}, [])

    def boom_and_revoke(i):
        # F395 contract: no exotic closures (h). Live objects travel
        # via the module registry.
        st = _F386_PROBE_STATE["au"]
        st["ledger"].revoke(st["receipt_id"], AT + 1)
        raise RuntimeError("kaboom")

    def comp(i):
        return {"u": 1}

    saga = h["saga"]
    sd = h["sm"].define([
        saga.SagaStepDef("s1", "a1", {}, "c1"),
        saga.SagaStepDef("s2", "a2", {}, "c2")])
    plan = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ok, "s2": boom_and_revoke},
         "comp_fns": {"s1": comp, "s2": comp}, "idem_key": "auk"}])
    _F386_PROBE_STATE["au"] = {"ledger": h["ledger"],
                               "receipt_id": h["root"]["receipt_id"]}
    try:
        c1.execute(plan, run_id="au-r1", authority=h["auth"], at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == \
                "workflow-saga-compensation-unauthorized":
            return _record("F386-compensation-authority-intact", "HELD",
                           "revoked authority refuses coded at compensation")
        return _record("F386-compensation-authority-intact", "BREAK",
                       "unexpected code %r" % (getattr(e, "code", None),))
    finally:
        _F386_PROBE_STATE.pop("au", None)
    return _record("F386-compensation-authority-intact", "BREAK",
                   "revoked authority compensated without refusal")


def p_f386_control_no_collision():
    # Control: the w303 red-team control shape (second composer runs a
    # DIFFERENT plan reentrantly) still compensates normally.
    h = _harness()
    wc = h["wc"]
    c1, c2 = h["composer"](), h["composer"]()
    h["ws"].start_run("probe", run_id="ctl-r1", authority=h["auth"], at=AT)
    h["ws"].start_run("probe", run_id="ctl-r2", authority=h["auth"], at=AT)

    def ok(i):
        return ({"r": 1}, [])

    def boom(i):
        raise RuntimeError("kaboom")

    def comp_s1(i):
        return {"u": 1}

    def comp_s2(i):
        # F395 contract: no exotic closures (entered/wc/ok/boom/sd/c2/h
        # were all closed over). The reentrant plan and its targets
        # travel via the module registry; this fn closes over nothing.
        st = _F386_PROBE_STATE["ctl"]
        if st["entered"]["n"] == 0:
            st["entered"]["n"] += 1
            st["c2"].execute(st["plan_other"], run_id="ctl-r2",
                             authority=st["auth"], at=AT)
        return {"u": 2}

    saga = h["saga"]
    sd = h["sm"].define([
        saga.SagaStepDef("s1", "a1", {}, "c1"),
        saga.SagaStepDef("s2", "a2", {}, "c2"),
        saga.SagaStepDef("s3", "a3", {}, "c3")])
    # Pre-built (was built inside comp_s2): closure-free comp_s2 above
    # lets the reentrant plan be constructed at probe scope.
    plan_other = wc.ComposedPlan([
        {"kind": "saga", "name": "other", "definition": sd,
         "action_fns": {"s1": ok, "s2": ok, "s3": boom},
         "comp_fns": {"s1": comp_s1, "s2": comp_s2, "s3": comp_s1},
         "idem_key": "ck2"}])
    plan = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ok, "s2": ok, "s3": boom},
         "comp_fns": {"s1": comp_s1, "s2": comp_s2, "s3": comp_s1},
         "idem_key": "ck"}])
    _F386_PROBE_STATE["ctl"] = {"entered": {"n": 0}, "c2": c2,
                                "plan_other": plan_other, "auth": h["auth"]}
    try:
        res = c1.execute(plan, run_id="ctl-r1", authority=h["auth"], at=AT)
    except Exception as e:  # noqa: BLE001
        return _record("F386-control-no-collision", "BREAK",
                       "control escalated unexpectedly: %r"
                       % (getattr(e, "code", None),))
    finally:
        _F386_PROBE_STATE.pop("ctl", None)
    if res["units"]["sg"]["status"] == "compensated":
        return _record("F386-control-no-collision", "HELD",
                       "different plan -> compensated")
    return _record("F386-control-no-collision", "BREAK",
                   "unexpected status %r" % (res["units"]["sg"]["status"],))


def _green(pid, battery, expect_break_ids=()):
    """Depth-1 green check: run an adjacent battery's main with
    GOV_SKIP_GREEN=1 and record its verdict line. expect_break_ids is
    the set of probe ids allowed to BREAK (expected-open findings)."""
    if SKIP_GREEN:
        _record(pid, "HELD", "green check skipped (GOV_SKIP_GREEN=1)")
        return
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmpd = tempfile.mkdtemp(prefix="g304-green-")
    env["TMPDIR"] = tmpd
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, "evals", battery)],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=REPO)
        out = proc.stdout + proc.stderr
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "green check crashed: %r" % (e,))
        return
    breaks = re.findall(r"\[BREAK\] ([A-Za-z0-9_.\-]+)", out)
    unexpected = [b for b in breaks if b not in expect_break_ids]
    if unexpected:
        _record(pid, "BREAK",
                "%s: unexpected BREAKs %r" % (battery, unexpected))
    else:
        _record(pid, "HELD",
                "%s: %d BREAK (all expected-open) / rest held"
                % (battery, len(breaks)))


def p_w305_op_registry_stable():
    # Wave-305 hygiene: the process-global op registry must not grow
    # across composer-instance lifecycles. Ten executions of a 2-step
    # saga unit must leave the registry exactly as it was found
    # (pre-fix: +4 entries per execution, 40 after 10).
    h = _harness()
    saga = h["saga"]
    wc = h["wc"]

    def ok(i):
        return ({"r": 1}, [])

    def comp(i):
        return {"u": 1}

    before = len(saga.registered_ops())
    for i in range(10):
        c = h["composer"]()
        run_id = "stab-r%d" % i
        h["ws"].start_run("probe", run_id=run_id, authority=h["auth"],
                          at=AT)
        sd = h["sm"].define([saga.SagaStepDef("s1", "a1", {}, "c1"),
                             saga.SagaStepDef("s2", "a2", {}, "c2")])
        plan = wc.ComposedPlan([
            {"kind": "saga", "name": "sg", "definition": sd,
             "action_fns": {"s1": ok, "s2": ok},
             "comp_fns": {"s1": comp, "s2": comp},
             "idem_key": "stabk%d" % i}])
        res = c.execute(plan, run_id=run_id, authority=h["auth"], at=AT)
        if res["units"]["sg"]["status"] != "succeeded":
            return _record("W305-op-registry-stable", "BREAK",
                           "setup: execution %d not succeeded" % i)
    after = len(saga.registered_ops())
    if after != before:
        return _record("W305-op-registry-stable", "BREAK",
                       "registry grew %d -> %d across 10 executions"
                       % (before, after))
    _record("W305-op-registry-stable", "HELD",
            "registry size stable across 10 instance lifecycles")


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F386-verifier-collision", p_f386_verifier_collision)
    _safe("F386-verifier-removed", p_f386_verifier_removed)
    _safe("F386-op-names-scoped", p_f386_op_names_scoped)
    _safe("W305-op-registry-stable", p_w305_op_registry_stable)
    _safe("F386-compensation-authority-intact",
           p_f386_compensation_authority_intact)
    _safe("F386-control-no-collision", p_f386_control_no_collision)
    _safe("green-w302-composed",
           lambda: _green("green-w302-composed",
                          "w302_workflow_composed_probes.py"))
    _safe("green-w302-branch",
           lambda: _green("green-w302-branch", "w302_branch_probes.py"))
    _safe("green-w302-approval",
           lambda: _green("green-w302-approval",
                          "w302_workflow_approval_probes.py"))

    nb = sum(1 for _, v, _ in _results if v == "BREAK")
    nh = sum(1 for _, v, _ in _results if v == "HELD")
    ne = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w303_f386: %d BREAK / %d HELD / %d ERROR" % (nb, nh, ne))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nb, nh, ne)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    return 1 if (nb or ne) else 0


if __name__ == "__main__":
    sys.exit(main())
