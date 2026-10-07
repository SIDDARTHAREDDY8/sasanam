"""Wave-302 lane 2 battery: composed workflow path.

Base: wave-301 merge 962dbf4bc27c56351aaa52fbe955568aa1151298
(verified via git rev-parse HEAD + ls-remote before work).

New product surface:
  gov/workflow_composed.py -- the single coherent path adapting the four
  wave-301 workflow modules (durable steps, saga compensation, routing
  slips, idempotency keys). 8 documented seam decisions; 3 new
  workflow-composed-* codes; pin 1812 -> 1815.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ImportError on the new module, and the pin probe sees 1812
literals); on the fixed tree they must HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g302-wc && TMPDIR=/var/tmp/g302-wc \
    ~/workspace/.gov-venv/bin/python evals/w302_workflow_composed_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g302-wc2 \
    ~/workspace/.gov-venv/bin/python evals/w302_workflow_composed_probes.py
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

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


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
        return _record("pin-taxonomy", "BREAK", "duplicate code literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals not sorted")
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted" % (len(lits), len(lits)))


def _scaffold():
    """Import gov.workflow_composed + build authority. Raises ImportError
    on the pristine base (the red-first BREAK)."""
    import gov.workflow_composed as wc  # noqa: F401 -- ImportError is signal
    from gov import delegation as dg
    from gov import delegation_revocation as drv
    from gov import ed25519
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    seed_a = hashlib.sha256(b"w302wc-a").digest()
    seed_b = hashlib.sha256(b"w302wc-b").digest()
    pub_a = ed25519.publickey(seed_a).hex()
    pub_b = ed25519.publickey(seed_b).hex()
    at = 1_700_000_000
    cons = {"expires_at": at + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root = dg.issue(seed_a, "agent-a", "agent-b", pub_b,
                    ("tool.invoke",), issued_at=at, constraints=cons)
    ledger = drv.DelegationRevoker(seed_a, "agent-a")
    auth = {"actor_id": "agent-b", "action": "tool.invoke", "chain": [root],
            "trust_roots": [pub_a], "revocation_ledger": ledger}
    ws = wf.WorkflowStore()
    sm = saga.SagaManager()
    im = idem.IdempotencyStore()
    comp = wc.WorkflowComposer(ws, sm, im)
    run = ws.start_run("probe", run_id="probe-r1", authority=auth, at=at)
    return wc, wf, saga, idem, ed25519, comp, ws, sm, im, auth, at, run


def _break_absent(pid, note="gov.workflow_composed absent"):
    _record(pid, "BREAK", note)


def p_cross_key_replay():
    # Seam 3: a key completed under one op_class must be invisible to
    # every other op_class -- no result leak, no skipped execution.
    try:
        wc, wf, saga, idem, _, comp, ws, sm, im, auth, at, run = _scaffold()
    except ImportError:
        return _break_absent("wc-cross-key-replay")
    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": lambda i: {"secret": 42},
         "inputs": {}, "idem_key": "shared-key"}])
    comp.execute(plan, run_id=run["run_id"], authority=auth, at=at)
    # Same key string, different op_class, direct store access: the
    # saga-action namespace must not see the unit's record.
    outcome = im.begin("composed", "composed-saga-action", "shared-key",
                       "0" * 64, caller="agent-b",
                       authority_verifier=lambda **k: True, at=at)
    if outcome.status != "new":
        return _record("wc-cross-key-replay", "BREAK",
                       "cross-op_class key replay leaked: %s"
                       % outcome.status)
    _record("wc-cross-key-replay", "HELD",
            "op_class isolation holds: no cross-namespace replay")


def p_digest_confusion():
    # Seam 3: same key + different plan digest must refuse
    # permit-idempotency-conflict, never silently replay or overwrite.
    try:
        wc, wf, saga, idem, _, comp, ws, sm, im, auth, at, run = _scaffold()
    except ImportError:
        return _break_absent("wc-digest-confusion")
    plan_a = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": lambda i: {"v": 1},
         "inputs": {"x": 1}, "idem_key": "confuse-key"}])
    comp.execute(plan_a, run_id=run["run_id"], authority=auth, at=at)
    run2 = ws.start_run("probe", run_id="probe-r2", authority=auth, at=at)
    plan_b = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": lambda i: {"v": 2},
         "inputs": {"x": 2}, "idem_key": "confuse-key"}])
    try:
        comp.execute(plan_b, run_id=run2["run_id"], authority=auth, at=at)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "permit-idempotency-conflict":
            return _record("wc-digest-confusion", "HELD",
                           "definition drift refused coded")
        return _record("wc-digest-confusion", "BREAK",
                       "wrong code: %r" % (getattr(e, "code", None),))
    return _record("wc-digest-confusion", "BREAK",
                   "same key under a different plan executed silently")


def p_comp_inside_checkpoint():
    # Seam 7: compensations must execute inside workflow step slots --
    # the checkpoint log reads forward-then-compensation in one trail.
    try:
        wc, wf, saga, idem, _, comp, ws, sm, im, auth, at, run = _scaffold()
    except ImportError:
        return _break_absent("wc-comp-inside-checkpoint")

    def ok(i):
        return ({"r": 1}, [])

    def boom(i):
        raise RuntimeError("kaboom")

    def c1(i):
        return {"u": 1}
    sd = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1"),
                    saga.SagaStepDef("s2", "a2", {}, "c2")])
    plan = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ok, "s2": boom},
         "comp_fns": {"s1": c1, "s2": c1}, "idem_key": "ck"}])
    res = comp.execute(plan, run_id=run["run_id"], authority=auth, at=at)
    if res["units"]["sg"]["status"] != "compensated":
        return _record("wc-comp-inside-checkpoint", "BREAK",
                       "saga did not compensate: %r"
                       % res["units"]["sg"]["status"])
    names = [s["name"] for s in ws.list_steps(run["run_id"])]
    if names != ["saga:sg:s1", "saga:sg:s2", "saga-comp:sg:s1"]:
        return _record("wc-comp-inside-checkpoint", "BREAK",
                       "compensation outside the checkpoint trail: %r"
                       % (names,))
    _record("wc-comp-inside-checkpoint", "HELD",
            "compensations checkpointed in-trail, reverse order")


def p_slip_saga_confusion():
    # Seams 1+2: a routing slip must not be smuggled in as a saga (or a
    # saga as a slip); kinds are disjoint at plan validation.
    try:
        wc, wf, saga, idem, _, comp, ws, sm, im, auth, at, run = _scaffold()
    except ImportError:
        return _break_absent("wc-slip-saga-confusion")
    sd = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    try:
        wc.ComposedPlan([{"kind": "slip", "name": "rt",
                          "definition": sd, "idem_key": "kx"}])
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-composed-definition-invalid":
            return _record("wc-slip-saga-confusion", "HELD",
                           "kind confusion refused at plan validation")
        return _record("wc-slip-saga-confusion", "BREAK",
                       "wrong code: %r" % (getattr(e, "code", None),))
    return _record("wc-slip-saga-confusion", "BREAK",
                   "saga definition accepted as a routing slip")


def p_double_dispatch():
    # Seam 6: outbox dispatch through the idempotency store -- a
    # redrain after the intent was dispatched must NOT begin a new
    # dispatch (begin-replay, never begin-new).
    try:
        wc, wf, saga, idem, _, _, ws, sm, _, auth, at, run = _scaffold()
    except ImportError:
        return _break_absent("wc-double-dispatch")
    backing = {}
    events = []
    ws = wf.WorkflowStore()
    comp = wc.WorkflowComposer(
        ws, saga.SagaManager(),
        idem.IdempotencyStore(backing=backing,
                              sink=lambda r: events.append(r)))
    run = ws.start_run("probe", run_id="probe-ob", authority=auth, at=at)

    def ship(i):
        return ({"r": 1}, [{"intent_id": "i1", "what": "send"}])
    sd = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    plan = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ship},
         "comp_fns": {"s1": lambda i: {}}, "idem_key": "kob"}])
    res = comp.execute(plan, run_id=run["run_id"], authority=auth, at=at)
    if res["units"]["sg"]["outbox_dispatched"] != 1:
        return _record("wc-double-dispatch", "BREAK",
                       "outbox did not dispatch exactly once")
    new1 = [e for e in events
            if e.get("event") == "begin-new"
            and e.get("op_class") == "composed-outbox"]
    if len(new1) != 1:
        return _record("wc-double-dispatch", "BREAK",
                       "expected 1 outbox begin-new, got %d" % len(new1))
    # Crash-redrain: fresh composer, same backing, same workflow store.
    del events[:]
    comp2 = wc.WorkflowComposer(
        ws, saga.SagaManager(),
        idem.IdempotencyStore(backing=backing,
                              sink=lambda r: events.append(r)))
    comp2.load_state(comp.dump_state())
    comp2.execute(plan, run_id=run["run_id"], authority=auth, at=at)
    new2 = [e for e in events
            if e.get("event") == "begin-new"
            and e.get("op_class") == "composed-outbox"]
    replay2 = [e for e in events
               if e.get("event") == "begin-replay"
               and e.get("op_class") == "composed-outbox"]
    if new2:
        return _record("wc-double-dispatch", "BREAK",
                       "redrain began %d new dispatch(es)" % len(new2))
    if len(replay2) != 1:
        return _record("wc-double-dispatch", "BREAK",
                       "redrain did not replay the dispatch")
    _record("wc-double-dispatch", "HELD",
            "outbox dispatch exactly-once across redrain")


def p_authority_mismatch():
    # Seam 4/Decision 3: the plan actor is pinned at first execute; a
    # later call presenting a different actor refuses coded.
    try:
        wc, wf, saga, idem, ed25519, comp, ws, sm, im, auth, at, run = _scaffold()
    except ImportError:
        return _break_absent("wc-authority-mismatch")
    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": lambda i: {},
         "idem_key": "kam"}])
    comp.execute(plan, run_id=run["run_id"], authority=auth, at=at)
    seed_e = hashlib.sha256(b"w302wc-evil").digest()
    pub_e = ed25519.publickey(seed_e).hex()
    from gov import delegation as dg
    from gov import delegation_revocation as drv
    cons = {"expires_at": at + 3600, "max_depth": 4,
            "allowed_targets": ["agent-evil"]}
    evil_chain = [dg.issue(hashlib.sha256(b"w302wc-a").digest(),
                           "agent-a", "agent-evil", pub_e,
                           ("tool.invoke",), issued_at=at,
                           constraints=cons)]
    evil_auth = {"actor_id": "agent-evil", "action": "tool.invoke",
                 "chain": evil_chain,
                 "trust_roots": [ed25519.publickey(
                     hashlib.sha256(b"w302wc-a").digest()).hex()],
                 "revocation_ledger": drv.DelegationRevoker(
                     hashlib.sha256(b"w302wc-a").digest(), "agent-a")}
    run2 = ws.start_run("probe", run_id="probe-r9", authority=evil_auth,
                        at=at)
    plan2 = wc.ComposedPlan([
        {"kind": "fn", "name": "e", "fn": lambda i: {},
         "idem_key": "kem"}])
    try:
        comp.execute(plan2, run_id=run2["run_id"], authority=evil_auth,
                     at=at)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-composed-authority-mismatch":
            return _record("wc-authority-mismatch", "HELD",
                           "plan-actor substitution refused coded")
        return _record("wc-authority-mismatch", "BREAK",
                       "wrong code: %r" % (getattr(e, "code", None),))
    return _record("wc-authority-mismatch", "BREAK",
                   "foreign actor executed under the pinned plan")


def p_divergence():
    # Seam 3/Decision 2: idem says REPLAY but the checkpoint is gone --
    # the layers forked; refuse workflow-composed-divergent.
    try:
        wc, wf, saga, idem, _, comp, ws, sm, im, auth, at, run = _scaffold()
    except ImportError:
        return _break_absent("wc-divergence")
    plan = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": lambda i: {"v": 1},
         "inputs": {}, "idem_key": "kdiv"}])
    comp.execute(plan, run_id=run["run_id"], authority=auth, at=at)
    ws2 = wf.WorkflowStore()
    run2 = ws2.start_run("probe", run_id=run["run_id"], authority=auth,
                         at=at)
    comp2 = wc.WorkflowComposer(ws2, sm, im)
    try:
        comp2.execute(plan, run_id=run2["run_id"], authority=auth, at=at)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-composed-divergent":
            return _record("wc-divergence", "HELD",
                           "layer fork refused fail-closed")
        return _record("wc-divergence", "BREAK",
                       "wrong code: %r" % (getattr(e, "code", None),))
    return _record("wc-divergence", "BREAK",
                   "forked layers silently re-executed")


def p_receipt_binding():
    # Seam 5/Decision 4: the leg's step outputs must carry the receipt
    # digest, binding the receipt chain into the checkpoint trail.
    try:
        wc, wf, saga, idem, ed25519, comp, ws, sm, im, auth, at, run = _scaffold()
    except ImportError:
        return _break_absent("wc-receipt-binding")
    from gov import workflow_routing as wr
    seed_h = hashlib.sha256(b"w302wc-h").digest()
    pub_h = ed25519.publickey(seed_h).hex()
    legs = [{"handler_id": "h1", "handler_pubkey_hex": pub_h,
             "rights": ["tool.invoke"], "input_digest": "0" * 64,
             "output_digest": "0" * 64}]
    seed_i = hashlib.sha256(b"w302wc-a").digest()
    slip = wr.issue_slip(seed_i, "issuer", legs, at)
    plan = wc.ComposedPlan([
        {"kind": "slip", "name": "rt", "slip": slip,
         "trust_roots": [ed25519.publickey(seed_i).hex()],
         "leg_fns": {0: (seed_h, lambda i: {"done": True})},
         "idem_key": "krb"}])
    res = comp.execute(plan, run_id=run["run_id"], authority=auth, at=at)
    unit = res["units"]["rt"]
    if not unit["completed"]:
        return _record("wc-receipt-binding", "BREAK", "slip did not complete")
    receipt_digest = unit["slip"]["receipts"][0]["receipt_digest"]
    steps = ws.list_steps(run["run_id"])
    if not steps or steps[0]["outputs"].get(
            "_composed_receipt_digest") != receipt_digest:
        return _record("wc-receipt-binding", "BREAK",
                       "receipt digest not bound into the checkpoint")
    _record("wc-receipt-binding", "HELD",
            "receipt chain committed into the checkpoint trail")


def p_comp_authority_lapsed():
    # Seam 4/Decision 3: a compensation whose authority lapsed between
    # forward execution and compensation time must escalate, never
    # compensate under stale authority.
    try:
        wc, wf, saga, idem, _, comp, ws, sm, im, auth, at, run = _scaffold()
    except ImportError:
        return _break_absent("wc-comp-authority-lapsed")

    def ok(i):
        return ({"r": 1}, [])

    def boom(i):
        raise RuntimeError("kaboom")
    sd = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1"),
                    saga.SagaStepDef("s2", "a2", {}, "c2")])
    plan = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ok, "s2": boom},
         "comp_fns": {"s1": lambda i: {"u": 1},
                      "s2": lambda i: {"u": 2}}, "idem_key": "krev"}])
    # Revoke the chain BEFORE execute: forward actions run (the saga
    # checks authority per step and fails the step), then compensation
    # of s1 must refuse under the lapsed authority.
    from gov import delegation_revocation as drv
    auth["revocation_ledger"].revoke(auth["chain"][0]["receipt_id"], at)
    try:
        comp.execute(plan, run_id=run["run_id"], authority=auth, at=at)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code in ("workflow-saga-compensation-unauthorized",
                    "workflow-authority-revoked"):
            return _record("wc-comp-authority-lapsed", "HELD",
                           "lapsed authority refused at compensation: %s"
                           % code)
        return _record("wc-comp-authority-lapsed", "BREAK",
                       "wrong code: %r" % (code,))
    return _record("wc-comp-authority-lapsed", "BREAK",
                   "compensated under a revoked chain")


def p_codes_present():
    try:
        import gov.workflow_composed as wc  # noqa: F401
    except ImportError:
        return _record("wc-codes-present", "BREAK",
                       "gov.workflow_composed absent")
    lits = _literals()
    missing = [c for c in ("workflow-composed-divergent",
                           "workflow-composed-definition-invalid",
                           "workflow-composed-authority-mismatch")
               if c not in lits]
    if missing:
        return _record("wc-codes-present", "BREAK",
                       "missing code literals: %r" % (missing,))
    _record("wc-codes-present", "HELD", "3/3 new codes present")


def p_ed25519_contract():
    try:
        from gov import ed25519
    except ImportError:
        return _record("wc-ed25519", "BREAK", "ed25519 absent")
    seed = hashlib.sha256(b"w302wc-es").digest()
    pub = ed25519.publickey(seed)
    sig = ed25519.sign(seed, b"probe")
    if ed25519.verify(pub, b"probe", sig) is not True:
        return _record("wc-ed25519", "BREAK", "good signature not True")
    if ed25519.verify(pub, b"tampered", sig) is not False:
        return _record("wc-ed25519", "BREAK", "forged signature not False")
    _record("wc-ed25519", "HELD", "ed25519 True/False contract holds")


def _green_check(path, name, tolerate=()):
    if SKIP_GREEN:
        _record("green-%s" % name, "HELD", "skipped via GOV_SKIP_GREEN=1")
        return
    if not os.path.exists(path):
        _record("green-%s" % name, "HELD", "battery absent at base")
        return
    tmp = tempfile.mkdtemp(prefix="g302-green-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600, env=env, cwd=REPO).stdout
    except Exception as e:  # noqa: BLE001
        return _record("green-%s" % name, "ERROR",
                       "green check crashed: %r" % (e,))
    bad = [ln for ln in out.splitlines()
           if ln.strip().startswith("[BREAK]")
           and not any(t in ln for t in tolerate)]
    if bad:
        _record("green-%s" % name, "BREAK",
                "unexpected breaks: %s" % "; ".join(bad[:5]))
    else:
        _record("green-%s" % name, "HELD", "green check held")


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    for pid, fn in [
        ("wc-cross-key-replay", p_cross_key_replay),
        ("wc-digest-confusion", p_digest_confusion),
        ("wc-comp-inside-checkpoint", p_comp_inside_checkpoint),
        ("wc-slip-saga-confusion", p_slip_saga_confusion),
        ("wc-double-dispatch", p_double_dispatch),
        ("wc-authority-mismatch", p_authority_mismatch),
        ("wc-divergence", p_divergence),
        ("wc-receipt-binding", p_receipt_binding),
        ("wc-comp-authority-lapsed", p_comp_authority_lapsed),
        ("wc-codes-present", p_codes_present),
        ("wc-ed25519", p_ed25519_contract),
    ]:
        _safe(pid, fn)
    _green_check(os.path.join(REPO, "evals", "w301_workflow_probes.py"),
                 "w301-workflow", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals", "w301_saga_probes.py"),
                 "w301-saga", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals", "w301_routing_probes.py"),
                 "w301-routing", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals", "w301_idempotency_probes.py"),
                 "w301-idempotency", tolerate=("pin-taxonomy",))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w302_workflow_composed: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, n_break, n_held, n_err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
