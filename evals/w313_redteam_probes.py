"""Wave-313 lane C battery: independent red team vs the wave-312 merge tree.

Base: wave-312 merge 4b1fa29e (F397 OPEN on the base -- the only
open finding; F397 CLOSED 2026-10-03 wave-313 lane A;
F396 CLOSED wave-312 lane A; persistent witness log (gov/witness_log.py,
wave-312 lane D); pin 1851 on the base, 1900 merged).

Targets (all verified empirically with throwaway scripts BEFORE this
battery was written -- diagnosing-bugs loop):
 1. F397 (LOW, CLOSED 2026-10-03 wave-313 lane A -- filed wave-312
    independent red-team, claim 2026-10-03T17:44:00Z):
    WorkflowComposer.retry_saga_unit accepted a stale `at`. Two
    probes on the open base: stale-at-retry (at=AT) and
    stale-at-zero (at=0) -- both dual-mode, now HELD (stale-at
    refused coded). The third probe, stale-at-boundary
    (at=expires_at-1, strictly after the escalation and inside the
    delegation's validity), is a residual pin, not a break probe:
    the instant is unfalsifiable under logical time and a genuine
    retry there MUST succeed (F394 happy path); HELD documents the
    inherent residual.
 2. F396 (MEDIUM, CLOSED 2026-10-03 wave-312 lane A):
    defaults/kwdefaults bound by value in the code fingerprint --
    HELD.
 3. F395 (MEDIUM, CLOSED 2026-10-03 wave-311 lane A): exotic-closure
    coded refusal -- HELD.
 4. F394 (LOW, CLOSED 2026-10-03 wave-310 lane A): composer-API retry
    -- HELD.
 5. F393 residuals (MEDIUM, CLOSED wave-309 lane A): code-confusion
    refusals, JSON-native closure stability, plan-digest binding --
    HELD.
 6. F391 (MEDIUM, CLOSED wave-308 lane A): begin-time manager
    binding -- HELD.
 7. Offline verifier witness stage (gov/evidence_verify_offline.py,
    new angles beyond w312): witness-entry transplant across witness
    keys, artifact transplant, inclusion-sibling tamper,
    checkpoint-signature forgery, future checkpoint, expired witness
    key validity window, duplicate witness entries, policyDigest
    rebind, envelope payloadType swap, threshold distinct-key
    counting (same key twice under threshold=2 refuses; two distinct
    keys pass) -- all fail closed coded.
 8. Witness log direct (gov/witness_log.py): inclusion position
    binding (proof for leaf 0 claimed at index 1), forked-log
    consistency (two inconsistent checkpoints from the same key),
    old_size > new_size, empty leaf -- all refuse coded.
 9. in-toto statement (gov/evidence_intoto.py): wrong predicateType,
    re-sealed wrong-subject statement, threshold=2 with one
    signature -- all refuse coded.
10. Observer timestamps (gov/evidence_verify_offline.py): cross-
    authority signature swap, evidence-digest transplant, unmet
    minimum -- all fail closed coded.
11. Sigstore bundle + offline verifier + probe-line regressions
    carried from w312 (all HELD on this base).
12. Canonical probe-line parser (evals/probe_lines.py, new
    adversarial cases): leading-space, tab separator, lowercase
    verdict, slash pid, missing colon all rejected (strict);
    double-newline tolerated like the single-newline case
    (documented leniency, observation).

New findings filed by this lane: NONE -- every fresh attack
hypothesis was falsified (fail-closed coded). Wave-313 merge footer:
open none / next F398; pin 1900 (this lane mints no decision codes).

This battery's expected BREAKs: none (F397 CLOSED 2026-10-03 wave-313
lane A; the three F397 probes are dual-mode and record HELD).

Expected counts: 71 probes -- 0 BREAK / 71 HELD / 0 ERROR direct
probes. A full standalone run adds 11 depth-1 green checks (82
lines: 0 BREAK / 82 HELD / 0 ERROR); under GOV_SKIP_GREEN=1 the
checks are replaced by one green-skipped HELD line (72 lines:
0/72/0).

Probe lines are emitted in the canonical `[VERDICT] pid: note` form
(evals/probe_lines.py) before the `----` separator and the
`N BREAK / M HELD / K ERROR` summary line.

Run:
  mkdir -p /var/tmp/g313-rt && TMPDIR=/var/tmp/g313-rt \
    ~/workspace/.gov-venv/bin/python evals/w313_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g313-rt2 \
    ~/workspace/.gov-venv/bin/python evals/w313_redteam_probes.py
"""
import base64
import copy
import functools
import hashlib
import json
import os
import re
import sys
import tempfile
import traceback
from datetime import datetime, timedelta, timezone

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

# Pin 1851 (wave-312 lane D: 1841 -> 1851, +10 witness codes). This lane mints no
# codes (red team only; F397 needs no new code -- the fix is an `at`
# bound, not a refusal), so the pin stays 1851.
TAXONOMY_PIN = 1984 #Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

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
    _record("pin-taxonomy", "HELD", "1984/1984/0 sorted")


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
    if nxt != 405 or open_s != "none":
        return _record("footer-state", "BREAK",
                       "footer pins next F%d open '%s', want next F404 "
                       "open 'F397'" % (nxt, open_s))
    _record("footer-state", "HELD",
            "footer pins open F407 / next F408")

# ------------------------------------------------------------------
# Shared scaffolds
# ------------------------------------------------------------------

def _seed(s):
    return hashlib.sha256(("w312-" + s).encode()).digest()


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


def _f397_scaffold(tag, ttl):
    """Composed scaffold with a TIME-BOXED delegation: expires_at =
    AT + ttl. The saga escalates at AT; the delegation is expired by
    the time a real operator retries."""
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
    return wc, saga, comp, sm, auth


def _f397_escalated(tag, ttl=3600):
    """Drive a composed saga unit to escalation under the time-boxed
    delegation; compensation fails transiently (3 attempts) then the
    downstream is "fixed". Returns (comp, sm, inst, calls)."""
    from gov import workflow_saga as saga
    wc, saga_mod, comp, sm, auth = _f397_scaffold(tag, ttl)
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


def _coded(fn):
    """Coded refusal for envelope-style errors (.reason) or workflow
    errors (.code); 'no-refusal' when nothing raised."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return (getattr(e, "reason", None) or getattr(e, "code", None)
                or type(e).__name__)
    return "no-refusal"


# ------------------------------------------------------------------
# F397 (LOW, OPEN -- filed this lane): retry_saga_unit accepts a
# stale `at`, resurrecting an expired delegation
# ------------------------------------------------------------------

def p_f397_stale_at_retry():
    # Delegation expires at AT+3600; the saga escalates at AT.
    # Control: retry at the TRUE retry instant (AT+7200) refuses coded
    # workflow-saga-compensation-unauthorized -- the step authority
    # correctly fails closed on expiry, compensation never runs.
    # Attack: retry with the stale execution instant (at=AT)
    # re-drives the compensation under the EXPIRED delegation.
    comp, sm, inst, calls = _f397_escalated("f397a", ttl=3600)
    if inst.status != "escalated":
        return _record("F397-stale-at-retry", "ERROR",
                       "saga did not escalate; probe void")
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=AT + 7200))
    if code != "workflow-saga-compensation-unauthorized":
        return _record("F397-stale-at-retry", "ERROR",
                       "control failed: fresh-at retry -> %r (want the "
                       "coded expiry refusal)" % (code,))
    if calls["comp"] != 3:
        return _record("F397-stale-at-retry", "ERROR",
                       "control failed: compensation ran on refused retry")
    before = calls["comp"]
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=AT))
    if (code == "no-refusal" and inst.status == "compensated"
            and calls["comp"] > before):
        return _record("F397-stale-at-retry", "BREAK",
                       "F397: stale at=AT re-drove compensation under an "
                       "EXPIRED delegation (%d->%d calls; saga "
                       "compensated)" % (before, calls["comp"]))
    if code != "no-refusal":
        return _record("F397-stale-at-retry", "HELD",
                       "stale-at retry refused coded %r (F397 closed)"
                       % (code,))
    return _record("F397-stale-at-retry", "ERROR",
                   "unexpected: code=%r status=%r calls=%d->%d"
                   % (code, inst.status, before, calls["comp"]))


def p_f397_stale_at_zero():
    # Extreme stale: at=0. The step-authority check has no lower bound
    # against the delegation's issued_at, so an instant BEFORE the
    # delegation even existed also resurrects it.
    comp, sm, inst, calls = _f397_escalated("f397b", ttl=3600)
    if inst.status != "escalated":
        return _record("F397-stale-at-zero", "ERROR",
                       "saga did not escalate; probe void")
    before = calls["comp"]
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=0))
    if (code == "no-refusal" and inst.status == "compensated"
            and calls["comp"] > before):
        return _record("F397-stale-at-zero", "BREAK",
                       "F397: at=0 re-drove compensation under an "
                       "EXPIRED delegation (%d->%d calls; saga "
                       "compensated)" % (before, calls["comp"]))
    if code != "no-refusal":
        return _record("F397-stale-at-zero", "HELD",
                       "at=0 retry refused coded %r (F397 closed)"
                       % (code,))
    return _record("F397-stale-at-zero", "ERROR",
                   "unexpected: code=%r status=%r calls=%d->%d"
                   % (code, inst.status, before, calls["comp"]))


# ------------------------------------------------------------------
# F396 (MEDIUM, CLOSED 2026-10-03 wave-312 lane A): the F393 code binding
# binds __defaults__/__kwdefaults__ by value (probes assert the fix:
# digest distinction + coded plan-mismatch + native victim execution +
# coded exotic-default refusal; lane A w311 template)
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
    # F396 CLOSED 2026-10-03 wave-312 lane A: identical-bytecode fns
    # whose JSON-native default values differ must have different code
    # digests (and plan digests); exotic defaults refuse coded. Uses
    # plain dicts (JSON-native) for the digest-distinction channels;
    # the _HitDict dict-subclass exercises the coded exotic refusal.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f396fn")
    evil_fn = factory({"endpoint": "evil"})
    victim_fn = factory({"endpoint": "real"})
    if evil_fn.__code__.co_code != victim_fn.__code__.co_code:
        return _record(pid, "ERROR", "bytecode differs; probe void")
    if wc._code_fingerprint(evil_fn) == wc._code_fingerprint(victim_fn):
        return _record(pid, "BREAK",
                       "F396: descriptor-identical fns with different "
                       "JSON-native default values share a code "
                       "fingerprint")
    evil = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": evil_fn,
         "inputs": {}, "idem_key": "k2"}])
    victim = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": victim_fn,
         "inputs": {}, "idem_key": "k2"}])
    if evil.digest == victim.digest:
        return _record(pid, "BREAK",
                       "F396: descriptor-identical plans with different "
                       "default values share a plan digest")
    # The run->plan binding must refuse the victim's plan under the
    # attacker's run, coded.
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    try:
        comp.execute(victim, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code != "workflow-composed-plan-mismatch":
            return _record(pid, "ERROR",
                           "unexpected refusal %r" % (code,))
    else:
        return _record(pid, "BREAK",
                       "F396: a different plan shared the run")
    # A fresh run executes the victim's fn natively with its own
    # defaults (the fix must not just refuse everything).
    victim_fresh = wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": victim_fn,
         "inputs": {}, "idem_key": "k2-fresh"}])
    ws.start_run("probe", run_id="R-fresh", authority=auth, at=AT)
    res = comp.execute(victim_fresh, run_id="R-fresh", authority=auth,
                       at=AT)
    out = res["units"]["u2"]["outputs"]
    if out != {"data": "from-real"}:
        return _record(pid, "ERROR",
                       "victim fn did not execute natively: %r" % (out,))
    # Channel 2: a non-JSON-native default refuses coded
    # (F395-shaped fail-closed).
    try:
        wc.ComposedPlan([
            {"kind": "fn", "name": "u2",
             "fn": factory(_HitDict({"endpoint": "real"})),
             "inputs": {}, "idem_key": "k2"}])
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-composed-definition-invalid":
            return _record(pid, "HELD",
                           "JSON-native defaults distinguished by value; "
                           "exotic defaults refused coded (F396 closed)")
        return _record(pid, "ERROR", "wrong refusal %r" % (code,))
    return _record(pid, "BREAK",
                   "F396: exotic default accepted (refusal regressed)")


def p_f396_defaults_fn():
    _f396_fn_attack("F396-defaults-fn", _mkdefault_fn)


def p_f396_kwdefaults_fn():
    _f396_fn_attack("F396-kwdefaults-fn", _mkdefault_kwfn)


def p_f396_defaults_saga():
    # F396 CLOSED 2026-10-03 wave-312 lane A: descriptor-identical saga
    # plans whose action_fns differ only in JSON-native default-arg
    # values must have different digests; exotic defaults refuse coded.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f396saga")

    def mkaction(client):
        def act(params, c=client):
            return ({"data": "from-" + c["endpoint"]}, [])
        return act

    def mkcomp(params):
        return {"undone": True}, []

    def mkplan(act, idem_key="ksg"):
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
            "idem_key": idem_key}])

    evil = mkplan(mkaction({"endpoint": "evil"}))
    victim = mkplan(mkaction({"endpoint": "real"}))
    if evil.digest == victim.digest:
        return _record("F396-defaults-saga", "BREAK",
                       "F396: descriptor-identical saga plans with "
                       "different default values share a plan digest")
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    try:
        comp.execute(victim, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code != "workflow-composed-plan-mismatch":
            return _record("F396-defaults-saga", "ERROR",
                           "unexpected refusal %r" % (code,))
    else:
        return _record("F396-defaults-saga", "BREAK",
                       "F396: a different saga plan shared the run")
    # Fresh run: the victim saga executes natively and succeeds.
    victim_fresh = mkplan(mkaction({"endpoint": "real"}),
                          idem_key="ksg-fresh")
    ws.start_run("probe", run_id="R-fresh", authority=auth, at=AT)
    res = comp.execute(victim_fresh, run_id="R-fresh", authority=auth,
                       at=AT)
    unit = res["units"]["sg"]
    if unit["status"] != "succeeded":
        return _record("F396-defaults-saga", "ERROR",
                       "victim saga did not succeed natively: %r"
                       % (unit["status"],))
    return _record("F396-defaults-saga", "HELD",
                   "saga action defaults distinguished by value; "
                   "victim executes natively (F396 closed)")

# ------------------------------------------------------------------
# F395 (MEDIUM, CLOSED 2026-10-03 wave-311 lane A): exotic-closure
# coded refusal holds
# ------------------------------------------------------------------

class _Client:
    """Exotic (non-JSON-native) closure value."""

    def __init__(self, endpoint):
        self.endpoint = endpoint

    def fetch(self):
        return {"data": "from-" + self.endpoint}


def _mkfn(client):
    # Shared factory: identical bytecode whatever client is closed
    # over.
    def fn(i):
        return client.fetch()
    return fn


def p_f395_exotic_closure_fn():
    # F395 CLOSED: ComposedPlan refuses coded
    # workflow-composed-definition-invalid for fns that close over
    # non-JSON-native values, at fingerprint and plan-construction
    # level.
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
    # F395 CLOSED: the saga action path refuses coded too.
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
    # F395 CLOSED: indirection does not save the binding -- the nested
    # lambda closes over the same exotic value, refused coded
    # recursively.
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
                             at=AT + 1)
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
                             at=AT + 1)
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
    # sagas goes through the composer API.
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
                             at=AT + 1)
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
                             at=AT + 1)
    except Exception as e:  # noqa: BLE001
        return _record("F394-double-retry-refused", "ERROR",
                       "first retry raised %r" % (getattr(e, "code", e),))
    if inst.status != "compensated":
        return _record("F394-double-retry-refused", "ERROR",
                       "first retry did not compensate: %r"
                       % (inst.status,))
    try:
        comp.retry_saga_unit("u1", {"action": "retry_compensation"},
                             at=AT + 1)
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
                             at=AT + 1)
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


def p_f394_never_escalated_refused():
    # A unit that completed happily was never escalated: there is no
    # retained retry material, so retry refuses coded (no phantom
    # recovery on a healthy unit).
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f394ok", operator_ref=True)

    def ok_action(params):
        return {"ok": True}, []

    def ok_comp(params):
        return {"undone": True}

    definition = saga.SagaDefinition([
        saga.SagaStepDef(step_id="s1", action_op="a1", action_params={},
                         compensation_op="c1", compensation_params={}),
    ])
    plan = wc.ComposedPlan([{
        "kind": "saga", "name": "u9", "definition": definition,
        "action_fns": {"s1": ok_action},
        "comp_fns": {"s1": ok_comp},
        "idem_key": "k9"}])
    comp.execute(plan, run_id="R", authority=auth, at=AT)
    inst = comp._saga_instances["u9"]
    if inst.status != "succeeded":
        return _record("F394-never-escalated-refused", "ERROR",
                       "saga did not succeed; probe void")
    code = _code_of(lambda: comp.retry_saga_unit(
        "u9", {"action": "retry_compensation"}, at=AT + 1))
    if code == "workflow-saga-resolution-invalid":
        return _record("F394-never-escalated-refused", "HELD",
                       "retry on a never-escalated unit refused coded "
                       "workflow-saga-resolution-invalid")
    return _record("F394-never-escalated-refused", "BREAK",
                   "retry on a never-escalated unit not refused: %r"
                   % (code,))


def p_f394_hygiene_preserved():
    # Wave-305 hygiene intent: after the retry the re-established
    # wrapper ops and verifier are removed again -- the shared
    # registries hold a unit's entries only during execution or an
    # active retry.
    from gov import workflow_saga as saga
    comp, sm, inst, calls = _escalated_composed_saga_fixable("hyg")
    tag_prefix = "composed:"
    auth_prefix = "composed-auth:"
    try:
        comp.retry_saga_unit("u1", {"action": "retry_compensation"},
                             at=AT + 1)
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
# Sigstore bundle (gov/evidence_sigstore.py, new wave-311): every
# error path must fail closed with a coded refusal
# ------------------------------------------------------------------

_SS_BUNDLE = b'{"bundle":"synthetic-w312-rt-001"}'
_SS_OTHER = b'{"bundle":"different-w312-rt-002"}'
_SS_CLAIMS = {"window": "2026-10-03", "decisions": 7}
_SS_T0 = 1791528600
_SS_VALIDITY = (1791528000, 1791530000)


def _ss_signers(n, base=41):
    from gov.signing import Ed25519Signer
    return [Ed25519Signer(bytes([base + i]) * 32) for i in range(n)]


def _ss_verifiers(signers):
    from gov.signing import Ed25519Verifier
    return [Ed25519Verifier(s.public_key, s.key_id) for s in signers]


def _ss_witness(base=77):
    from gov.signing import Ed25519Signer
    return Ed25519Signer(bytes([base]) * 32)


def _ss_witness_verifier(witness):
    from gov.signing import Ed25519Verifier
    return Ed25519Verifier(witness.public_key, witness.key_id)


def _ss_sealed(signers=None, witness=None, bundle_bytes=_SS_BUNDLE,
               integrated_time=_SS_T0, token=None):
    from gov import evidence_intoto, evidence_sigstore as ss
    signers = _ss_signers(1) if signers is None else signers
    witness = _ss_witness() if witness is None else witness
    stmt = evidence_intoto.build_statement(bundle_bytes, _SS_CLAIMS)
    env = evidence_intoto.seal_statement(stmt, signers)
    bundle = ss.seal_sigstore_bundle(env, signers, witness,
                                     rfc3161_token=token,
                                     integrated_time=integrated_time)
    return bundle, signers, witness


def _ss_open(bundle, bundle_bytes=_SS_BUNDLE, signers=None, witness=None,
             threshold=1, validity=_SS_VALIDITY):
    from gov import evidence_sigstore as ss
    signers = _ss_signers(1) if signers is None else signers
    witness = _ss_witness() if witness is None else witness
    return ss.open_sigstore_bundle(
        bundle, bundle_bytes, _ss_verifiers(signers),
        _ss_witness_verifier(witness), threshold=threshold,
        witness_validity=validity)


def p_sigstore_threshold_type_games():
    # Threshold is policy, not arithmetic: bool/str/float/zero/
    # negative/None thresholds are refused loudly, never coerced
    # (True == 1 must not sneak through as a threshold).
    bundle, signers, witness = _ss_sealed()
    for thr in (True, False, "2", 2.0, 0, -1, None):
        code = _coded(lambda t=thr: _ss_open(bundle, threshold=t))
        if code != "evidence-bundle-malformed":
            return _record("sigstore-threshold-type-games", "BREAK",
                           "threshold=%r not refused coded: %r"
                           % (thr, code))
    _record("sigstore-threshold-type-games", "HELD",
            "bool/str/float/zero/negative/None thresholds all refused "
            "coded evidence-bundle-malformed")


def p_sigstore_duplicate_sigs_distinct_keys():
    # Threshold counts DISTINCT keys: two copies of one key's
    # signature must not satisfy threshold=2.
    bundle, signers, witness = _ss_sealed()
    dup = copy.deepcopy(bundle)
    dup["dsseEnvelope"]["signatures"] *= 2
    code = _coded(lambda: _ss_open(dup, threshold=2))
    if code != "evidence-bundle-signature-invalid":
        return _record("sigstore-duplicate-sigs-distinct-keys", "BREAK",
                       "duplicated single-key signatures satisfied "
                       "threshold=2: %r" % (code,))
    _record("sigstore-duplicate-sigs-distinct-keys", "HELD",
            "threshold counts distinct keys: duplicated signatures "
            "refused coded evidence-bundle-signature-invalid")


def p_sigstore_witness_transplant_refused():
    # A well-formed, validly-signed witness entry for bundle A does
    # not verify when transplanted onto bundle B: the entry must bind
    # THIS bundle's artifact digest + signatures + key
    # (CVE-2026-22703 lesson).
    bundle_a, _, _ = _ss_sealed(bundle_bytes=_SS_BUNDLE)
    bundle_b, _, _ = _ss_sealed(bundle_bytes=_SS_OTHER)
    bundle_b["verificationMaterial"]["tlogEntries"] = \
        bundle_a["verificationMaterial"]["tlogEntries"]
    code = _coded(lambda: _ss_open(bundle_b, bundle_bytes=_SS_OTHER))
    if code != "evidence-bundle-witness-unbound":
        return _record("sigstore-witness-transplant-refused", "BREAK",
                       "transplanted witness entry not refused: %r"
                       % (code,))
    _record("sigstore-witness-transplant-refused", "HELD",
            "transplanted witness entry refused coded "
            "evidence-bundle-witness-unbound (entry binds this bundle)")


def p_sigstore_integratedtime_type_refused():
    # integratedTime is int64-as-string on the wire; a bare int is
    # malformed, never silently accepted.
    bundle, _, _ = _ss_sealed()
    bundle["verificationMaterial"]["tlogEntries"][0][
        "integratedTime"] = _SS_T0
    code = _coded(lambda: _ss_open(bundle))
    if code != "evidence-bundle-malformed":
        return _record("sigstore-integratedtime-type-refused", "BREAK",
                       "int integratedTime not refused: %r" % (code,))
    _record("sigstore-integratedtime-type-refused", "HELD",
            "non-string integratedTime refused coded "
            "evidence-bundle-malformed")


def p_sigstore_validity_required():
    # The witness time check needs a caller-pinned window: no window
    # (or a reversed window) refuses loudly -- no silent downgrade.
    from gov import evidence_sigstore as ss
    bundle, signers, witness = _ss_sealed()
    code = _coded(lambda: ss.open_sigstore_bundle(
        bundle, _SS_BUNDLE, _ss_verifiers(signers),
        _ss_witness_verifier(witness), witness_validity=None))
    if code != "evidence-bundle-malformed":
        return _record("sigstore-validity-required", "BREAK",
                       "missing witness_validity not refused: %r"
                       % (code,))
    code = _coded(lambda: _ss_open(
        bundle, validity=(_SS_VALIDITY[1], _SS_VALIDITY[0])))
    if code != "evidence-bundle-malformed":
        return _record("sigstore-validity-required", "BREAK",
                       "reversed witness_validity not refused: %r"
                       % (code,))
    _record("sigstore-validity-required", "HELD",
            "missing/reversed witness_validity refused coded "
            "evidence-bundle-malformed (no silent downgrade)")


def p_sigstore_keyid_swap_refused():
    # keyid is a hint, never authority: an attacker's signature
    # carrying the TRUSTED keyid must not verify (the trusted
    # verifier's key does not verify the attacker's bytes).
    bundle, _, _ = _ss_sealed(signers=_ss_signers(1, base=99))
    trusted_kid = _ss_verifiers(_ss_signers(1))[0].key_id
    bundle["dsseEnvelope"]["signatures"][0]["keyid"] = trusted_kid
    code = _coded(lambda: _ss_open(bundle))
    if code == "no-refusal":
        return _record("sigstore-keyid-swap-refused", "BREAK",
                       "attacker signature with spoofed trusted keyid "
                       "verified (keyid confused for authority)")
    _record("sigstore-keyid-swap-refused", "HELD",
            "spoofed-trusted keyid refused coded %r (keyid is a hint)"
            % (code,))


def p_sigstore_rfc3161_carrier():
    # The RFC 3161 token field is a CARRIER: a malformed token is
    # refused coded, but a well-formed (even garbage) token is
    # carried, not verified -- the bundle MUST verify without it.
    bundle, _, _ = _ss_sealed()
    bundle["verificationMaterial"]["timestampVerificationData"] = {
        "rfc3161Timestamps": [{"signedTimestamp": "!!!notb64!!!"}]}
    code = _coded(lambda: _ss_open(bundle))
    if code != "evidence-bundle-timestamp-malformed":
        return _record("sigstore-rfc3161-carrier", "BREAK",
                       "malformed rfc3161 token not refused coded: %r"
                       % (code,))
    bundle2, _, _ = _ss_sealed(token=b"\x00" * 16)
    try:
        out = _ss_open(bundle2)
    except Exception as e:  # noqa: BLE001
        return _record("sigstore-rfc3161-carrier", "ERROR",
                       "well-formed token broke verification: %r" % (e,))
    if out.get("rfc3161_present") is not True:
        return _record("sigstore-rfc3161-carrier", "ERROR",
                       "token presence not reported")
    _record("sigstore-rfc3161-carrier", "HELD",
            "malformed token refused coded "
            "evidence-bundle-timestamp-malformed; well-formed token "
            "carried (bundle verifies without it)")


def p_sigstore_tampered_payload_refused():
    # Flipping one payload byte breaks the PAE signature: refused
    # loudly, and no payload bytes escape.
    bundle, _, _ = _ss_sealed()
    raw = bytearray(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
    raw[5] ^= 0x01
    bundle["dsseEnvelope"]["payload"] = base64.b64encode(
        bytes(raw)).decode("ascii")
    code = _coded(lambda: _ss_open(bundle))
    if code == "no-refusal":
        return _record("sigstore-tampered-payload-refused", "BREAK",
                       "tampered bundle payload verified (signature "
                       "bypass)")
    _record("sigstore-tampered-payload-refused", "HELD",
            "bit-flipped bundle payload refused coded %r" % (code,))


# ------------------------------------------------------------------
# Offline verifier (gov/evidence_verify_offline.py, new wave-311):
# clock games, trust-root labeling, policy shape, mode labeling
# ------------------------------------------------------------------

_OVF_UTC = timezone.utc
_OVF_NOW = datetime(2026, 10, 3, 14, 0, 0, tzinfo=_OVF_UTC)
_OVF_BUNDLE_BYTES = b'{"evidence":"synthetic-bundle-w312-ovf-001"}'
_OVF_INTOTO_TYPE = "https://in-toto.io/Statement/v1"
_OVF_PREDICATE_TYPE = "https://sasanam.dev/predicate/evidence-bundle/v1"
_OVF_CLAIMS = {"window": "2026-10-03T00:00:00Z", "decisions": 3}
_OVF_ANCHOR = bytes.fromhex(
    "02eb4cee77eb9c934286078d60f8960f6a038a6c9b04906d940ed521de3fa3b6")
_OVF_EVIDENCE_SEED = bytes([7]) * 32
_OVF_TSA_SEED = bytes([9]) * 32


def _ovf_signer(seed):
    from gov.signing import Ed25519Signer
    return Ed25519Signer(seed)


def _ovf_statement(bundle_bytes=_OVF_BUNDLE_BYTES, claims=None,
                   predicate_type=_OVF_PREDICATE_TYPE):
    from gov import evidence_verify_offline as v  # noqa: F401
    claims = _OVF_CLAIMS if claims is None else claims
    return {
        "_type": _OVF_INTOTO_TYPE,
        "subject": [{
            "name": "evidence-bundle",
            "digest": {"sha256": hashlib.sha256(
                bundle_bytes).hexdigest()},
        }],
        "predicateType": predicate_type,
        "predicate": dict(claims),
    }


def _ovf_canon(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")


def _ovf_b64(b):
    return base64.b64encode(b).decode("ascii")


def _ovf_seal(payload_bytes, payload_type, signers):
    from gov import evidence_verify_offline as v
    sigs = []
    for s in signers:
        sigs.append({"keyid": s.key_id,
                     "sig": _ovf_b64(s.sign(v.pae(payload_type,
                                                 payload_bytes)))})
    return {"payload": _ovf_b64(payload_bytes),
            "payloadType": payload_type, "signatures": sigs}


def _ovf_policy_doc(ev_signers, tsa_signers, expires, threshold=1,
                    min_ts=0, required_claims=("window", "decisions")):
    from gov import evidence_verify_offline as v
    return {
        "version": v.POLICY_VERSION,
        "policy_id": "test-policy-w312-ovf",
        "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evidence_signing": {
            "threshold": threshold,
            "keys": [{"keyid": s.key_id,
                      "pubkey_hex": s.public_key.hex()}
                     for s in ev_signers],
        },
        "timestamp_authorities": [{
            "authority_id": "tsa-test-%d" % i,
            "pubkey_hex": s.public_key.hex(),
            "valid_for": {
                "not_before": (_OVF_NOW - timedelta(days=30)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
                "not_after": (_OVF_NOW + timedelta(days=30)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
            },
        } for i, s in enumerate(tsa_signers)],
        "required_predicate_type": _OVF_PREDICATE_TYPE,
        "required_predicate_claims": list(required_claims),
        "observer_timestamps": {"min": min_ts, "max_age_hours": 168},
        "witness_required": False,
    }


def _ovf_seal_policy(policy_doc, signer=None):
    from gov import evidence_verify_offline as v
    signer = _ovf_signer(_OVF_ANCHOR) if signer is None else signer
    return _ovf_seal(_ovf_canon(policy_doc), v.POLICY_PAYLOAD_TYPE,
                     [signer])


def _ovf_timestamp(authority_id, when, bundle_bytes, tsa_signer):
    body = {"authority_id": authority_id,
            "time": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "evidence_digest": hashlib.sha256(
                bundle_bytes).hexdigest()}
    return dict(body, sig=_ovf_b64(tsa_signer.sign(_ovf_canon(body))))


def _ovf_good(threshold=1, min_ts=0, expires=None, claims=None,
              tsa=True):
    from gov import evidence_verify_offline as v
    expires = _OVF_NOW + timedelta(days=10) if expires is None else expires
    ev = [_ovf_signer(_OVF_EVIDENCE_SEED)]
    tsa_s = [_ovf_signer(_OVF_TSA_SEED)] if tsa else []
    policy = _ovf_policy_doc(ev, tsa_s, expires, threshold=threshold,
                             min_ts=min_ts)
    stmt = _ovf_statement(claims=claims)
    envelope = _ovf_seal(_ovf_canon(stmt), v.ENVELOPE_PAYLOAD_TYPE, ev)
    policy_env = _ovf_seal_policy(policy)
    stamps = ([_ovf_timestamp("tsa-test-0", _OVF_NOW - timedelta(hours=1),
                              _OVF_BUNDLE_BYTES,
                              _ovf_signer(_OVF_TSA_SEED))]
              if tsa else [])
    vb = v.build_verification_bundle(envelope, policy_env,
                                     timestamps=stamps)
    return vb, _OVF_BUNDLE_BYTES


def _ovf_clock(at=_OVF_NOW):
    from gov import evidence_verify_offline as v
    return v.FixedClock("test-clock", at)


def p_ovf_naive_clock_internal():
    # Clock as inspectable control: a naive (tz-unaware) or otherwise
    # broken clock is a caller/verifier bug -> InternalError, the
    # documented contract. It must never produce a verdict, pass or
    # fail (CVE-2026-44310: a crash never emits a success signal).
    from gov import evidence_verify_offline as v
    vb, bb = _ovf_good()

    class _NaiveClock:
        name = "naive-clock"
        def now(self):
            return datetime(2026, 10, 3, 14, 0, 0)

    class _BadClock:
        name = "bad-clock"
        def now(self):
            return "not-a-time"

    for clock, label in ((_NaiveClock(), "naive"),
                         (_BadClock(), "non-datetime")):
        try:
            v.verify(bb, vb, time_source=clock)
        except v.InternalError:
            continue
        except v.VerificationError as e:  # noqa: BLE001
            return _record("ovf-naive-clock-internal", "BREAK",
                           "%s clock produced a VERDICT (%s) instead "
                           "of the documented InternalError"
                           % (label, e.code))
        except Exception as e:  # noqa: BLE001
            return _record("ovf-naive-clock-internal", "ERROR",
                           "%s clock: unexpected %r" % (label, e))
        else:
            return _record("ovf-naive-clock-internal", "BREAK",
                           "%s clock verified (a broken clock must "
                           "never verify)" % (label,))
    _record("ovf-naive-clock-internal", "HELD",
            "naive/non-datetime clocks raise InternalError (documented "
            "contract; never a verdict)")


def p_ovf_caller_supplied_root_labeled():
    # Observation, not an attack: a caller-supplied trust root naming
    # an attacker key verifies (the auditor explicitly chose it), but
    # the transcript records trustRoot.source == "caller-supplied" --
    # the trust decision is inspectable, never silent.
    from gov import evidence_verify_offline as v
    atk = _ovf_signer(bytes([13]) * 32)
    policy = _ovf_policy_doc([atk], [], _OVF_NOW + timedelta(days=10))
    envelope = _ovf_seal(_ovf_canon(_ovf_statement()),
                         v.ENVELOPE_PAYLOAD_TYPE, [atk])
    vb = v.build_verification_bundle(
        envelope,
        _ovf_seal(_ovf_canon(policy), v.POLICY_PAYLOAD_TYPE, [atk]))
    root = {"version": v.TRUST_ROOT_VERSION,
            "policy_keys": [{"keyid": atk.key_id,
                             "pubkey_hex": atk.public_key.hex()}]}
    try:
        report = v.verify(_OVF_BUNDLE_BYTES, vb, trust_root=root,
                          time_source=_ovf_clock())
    except Exception as e:  # noqa: BLE001
        return _record("ovf-caller-supplied-root-labeled", "ERROR",
                       "caller-supplied root refused: %r" % (e,))
    if report.get("status") != "VALID":
        return _record("ovf-caller-supplied-root-labeled", "ERROR",
                       "unexpected status %r" % (report.get("status"),))
    if report.get("trustRoot", {}).get("source") != "caller-supplied":
        return _record("ovf-caller-supplied-root-labeled", "BREAK",
                       "caller-supplied root not labeled in transcript "
                       "(silent trust decision)")
    _record("ovf-caller-supplied-root-labeled", "HELD",
            "caller-supplied trust root verifies AND is labeled "
            "'caller-supplied' in the transcript (observation)")


def p_ovf_bool_threshold_policy_malformed():
    # Threshold is policy, not arithmetic, in the policy document
    # too: a bool threshold is malformed (True == 1 must not sneak
    # through).
    from gov import evidence_verify_offline as v
    vb, bb = _ovf_good()
    policy = json.loads(base64.b64decode(
        vb["policy"]["payload"]).decode("utf-8"))
    policy["evidence_signing"]["threshold"] = True
    vb2 = dict(vb)
    vb2["policy"] = _ovf_seal(_ovf_canon(policy), v.POLICY_PAYLOAD_TYPE,
                              [_ovf_signer(_OVF_ANCHOR)])
    try:
        v.verify(bb, vb2, time_source=_ovf_clock())
    except v.VerificationError as e:
        if e.code == "POLICY_MALFORMED" and e.exit_code == 40:
            return _record("ovf-bool-threshold-policy-malformed",
                           "HELD", "bool policy threshold refused "
                           "POLICY_MALFORMED/40")
        return _record("ovf-bool-threshold-policy-malformed", "BREAK",
                       "wrong code: %s/%s" % (e.code, e.exit_code))
    except Exception as e:  # noqa: BLE001
        return _record("ovf-bool-threshold-policy-malformed", "ERROR",
                       "unexpected %r" % (e,))
    return _record("ovf-bool-threshold-policy-malformed", "BREAK",
                   "bool policy threshold accepted")


def p_ovf_existence_only_labeled():
    # Existence-only mode skips the predicate-CONTENT evaluation but
    # is LABELED (never defaulted): the same bundle is VALID with
    # existence_only=True (existenceOnly: true in the report) and
    # refused without it. The crypto core still runs in both modes.
    from gov import evidence_verify_offline as v
    vb, bb = _ovf_good(claims={"window": "2026-10-03T00:00:00Z"})
    try:
        report = v.verify(bb, vb, time_source=_ovf_clock(),
                          existence_only=True)
    except Exception as e:  # noqa: BLE001
        return _record("ovf-existence-only-labeled", "ERROR",
                       "existence-only refused: %r" % (e,))
    if report.get("status") != "VALID" \
            or report.get("existenceOnly") is not True:
        return _record("ovf-existence-only-labeled", "ERROR",
                       "existence-only not labeled: %r"
                       % (report.get("existenceOnly"),))
    try:
        v.verify(bb, vb, time_source=_ovf_clock())
    except v.VerificationError as e:
        if e.code == "STATEMENT_SHAPE_INVALID":
            return _record("ovf-existence-only-labeled", "HELD",
                           "existence-only VALID + labeled; without "
                           "it the missing claim refuses "
                           "STATEMENT_SHAPE_INVALID")
        return _record("ovf-existence-only-labeled", "BREAK",
                       "wrong code without existence_only: %s" % e.code)
    except Exception as e:  # noqa: BLE001
        return _record("ovf-existence-only-labeled", "ERROR",
                       "unexpected %r" % (e,))
    return _record("ovf-existence-only-labeled", "BREAK",
                   "missing predicate claim accepted without "
                   "existence_only")


# ------------------------------------------------------------------
# Probe-line pilot (parser robustness)
# ------------------------------------------------------------------

def _pl():
    sys.path.insert(0, os.path.join(REPO, "evals"))
    import probe_lines
    return probe_lines


def p_probe_lines_no_space_colon():
    # Observation: the canonical form is "[VERDICT] pid: note" but
    # the parser tolerates the missing space after the colon (": ?").
    # Leniency, not a hole: the verdict/pid fields stay strict.
    probe_lines = _pl()
    parsed = probe_lines.parse_line("[HELD] pid:n")
    if parsed != ("HELD", "pid", "n"):
        return _record("probe-lines-no-space-colon", "ERROR",
                       "unexpected parse: %r" % (parsed,))
    _record("probe-lines-no-space-colon", "HELD",
            "missing space after colon tolerated (documented "
            "leniency; verdict/pid strict)")


def p_probe_lines_crlf():
    # Observation: a CRLF-terminated line parses; the note keeps the
    # trailing CR (the note group is permissive on purpose -- notes
    # are human text, only verdict/pid are load-bearing).
    probe_lines = _pl()
    parsed = probe_lines.parse_line("[HELD] pid: note\r\n")
    if parsed != ("HELD", "pid", "note\r"):
        return _record("probe-lines-crlf", "ERROR",
                       "unexpected parse: %r" % (parsed,))
    _record("probe-lines-crlf", "HELD",
            "CRLF line parses; note keeps the CR (permissive note "
            "group, observation)")


def p_probe_lines_unicode_verdict():
    # Fullwidth/lookalike verdicts must not parse: the verdict
    # alternation is ASCII-only.
    probe_lines = _pl()
    bad = ["[ＨＥＬＤ] pid: n", "[héld] pid: n", "[HELD ] pid: n",
           "[HELD] pid: n "]
    for line in bad:
        parsed = probe_lines.parse_line(line)
        if line == "[HELD] pid: n ":
            # Trailing space after the note: the note group absorbs
            # it (permissive notes); the verdict/pid still parse.
            if parsed != ("HELD", "pid", "n "):
                return _record("probe-lines-unicode-verdict", "ERROR",
                               "trailing-space mis-parsed: %r" % (parsed,))
            continue
        if parsed is not None:
            return _record("probe-lines-unicode-verdict", "BREAK",
                           "non-ASCII verdict parsed: %r -> %r"
                           % (line, parsed))
    _record("probe-lines-unicode-verdict", "HELD",
            "fullwidth/accented/spaced verdicts rejected; trailing "
            "space stays inside the permissive note")


def p_probe_lines_null_note():
    # Observation: a null byte inside the note parses (the note group
    # is permissive on purpose). Verdict/pid stay strict.
    probe_lines = _pl()
    parsed = probe_lines.parse_line("[HELD] pid: no\x00te")
    if parsed != ("HELD", "pid", "no\x00te"):
        return _record("probe-lines-null-note", "ERROR",
                       "unexpected parse: %r" % (parsed,))
    _record("probe-lines-null-note", "HELD",
            "null byte inside the note parses (permissive note group, "
            "observation)")


def p_probe_lines_round_trip():
    # format_line/parse_line round-trip: every canonical emission
    # parses back to (verdict, pid, first-line note).
    probe_lines = _pl()
    cases = [("p1", "HELD", "simple note"),
             ("a.b-c_d", "BREAK", "note with: colon"),
             ("x", "ERROR", "multi\nline\nnote"),
             ("y", "SKIP", "")]
    for pid, verdict, note in cases:
        line = probe_lines.format_line(pid, verdict, note)
        parsed = probe_lines.parse_line(line)
        want = (verdict, pid, probe_lines.first_line(note))
        if parsed != want:
            return _record("probe-lines-round-trip", "BREAK",
                           "round-trip failed for %r: got %r want %r"
                           % ((pid, verdict, note), parsed, want))
    _record("probe-lines-round-trip", "HELD",
            "format/parse round-trips on %d cases" % len(cases))

# ------------------------------------------------------------------
# Wave-313 new probes: F397 boundary + evidence modules + parser
# ------------------------------------------------------------------

# --- F397 boundary (expected BREAK while F397 is OPEN) ---

def p_f397_stale_at_boundary():
    # Boundary: at = expires_at - 1 -- the instant JUST inside the
    # delegation's validity (and strictly AFTER the escalation).
    # This is NOT the F397 defect: the F397 close-when refuses a
    # stale `at` (at <= escalation instant); an in-window
    # post-escalation instant is unfalsifiable under the system's
    # pure logical-time model (every `at` is caller-supplied) and a
    # genuine retry at this instant MUST still succeed -- refusing
    # it would break the F394 happy path. This probe is therefore a
    # residual pin, not a break probe: HELD when the in-window retry
    # succeeds (documenting the inherent residual), BREAK if a
    # future change refuses legitimate in-window retries.
    comp, sm, inst, calls = _f397_escalated("f397c", ttl=3600)
    if inst.status != "escalated":
        return _record("F397-stale-at-boundary", "ERROR",
                       "saga did not escalate; probe void")
    before = calls["comp"]
    code = _code_of(lambda: comp.retry_saga_unit(
        "u1", {"action": "retry_compensation"}, at=AT + 3599))
    if (code == "no-refusal" and inst.status == "compensated"
            and calls["comp"] > before):
        return _record("F397-stale-at-boundary", "HELD",
                       "in-window post-escalation retry succeeds "
                       "(delegation genuinely valid at the claimed "
                       "instant); residual: the claim itself is "
                       "unfalsifiable under logical time -- backward "
                       "time travel (at<=escalation) refuses coded")
    if code != "no-refusal":
        return _record("F397-stale-at-boundary", "BREAK",
                       "REGRESSION: legitimate in-window retry refused "
                       "coded %r (F394 happy path broken)" % (code,))
    return _record("F397-stale-at-boundary", "ERROR",
                   "unexpected: code=%r status=%r calls=%d->%d"
                   % (code, inst.status, before, calls["comp"]))


# --- Evidence-module scaffolds (all throwaway-verified first) ---

def _ev_seed(s):
    return hashlib.sha256(("w313-" + s).encode()).digest()


class _EvSigner(object):
    """Ed25519 signer with the .key_id/.keyid/.pubkey_hex/.public_key/
    .sign surface the evidence modules accept (producer side)."""
    def __init__(self, seed):
        from gov import ed25519 as _ed
        self._seed = seed
        self._pub = _ed.publickey(seed)
        self._kid = hashlib.sha256(self._pub).hexdigest()[:16]
        self._ed = _ed

    def key_id(self):
        return self._kid

    def keyid(self):
        return self._kid

    def pubkey_hex(self):
        return self._pub.hex()

    @property
    def public_key(self):
        return self._pub

    def sign(self, msg):
        return self._ed.sign(self._seed, msg)


_EV_NOW = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
_EV_PRED = "https://sasanam.dev/evidence-predicate/v1"
_EV_ANCHOR = bytes.fromhex(
    "02eb4cee77eb9c934286078d60f8960f6a038a6c9b04906d940ed521de3fa3b6")
_EV_A = _ev_seed("ev-a")
_EV_B = _ev_seed("ev-b")
_EV_WIT = _ev_seed("wit")
_EV_WIT2 = _ev_seed("wit2")
_EV_TSA = _ev_seed("tsa")
_EV_TSB = _ev_seed("tsb")


def _ev_seal(payload, ptype, signers):
    from gov import evidence_verify_offline as _v
    msg = _v.pae(ptype, payload)
    return {
        "payload": base64.b64encode(payload).decode("ascii"),
        "payloadType": ptype,
        "signatures": [
            {"keyid": s.keyid(),
             "sig": base64.b64encode(s.sign(msg)).decode("ascii")}
            for s in signers
        ],
    }


def _ev_policy_doc(ev_signers, expires, wit_signers, witness_required=True,
                   threshold=1, wit_window=None):
    from gov import evidence_verify_offline as _v
    nb, na = wit_window or (
        (_EV_NOW - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        (_EV_NOW + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    return {
        "version": "sasanam-verification-policy/v1",
        "policy_id": "w313-attack-policy",
        "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "required_predicate_type": _EV_PRED,
        "required_predicate_claims": ["window"],
        "evidence_signing": {
            "threshold": threshold,
            "keys": [{"keyid": s.keyid(), "pubkey_hex": s.pubkey_hex()}
                     for s in ev_signers],
        },
        "observer_timestamps": {"min": 0, "max_age_hours": 168},
        "timestamp_authorities": [],
        "witness_required": witness_required,
        "witness_log_keys": [
            {"keyid": s.keyid(), "pubkey_hex": s.pubkey_hex(),
             "valid_for": {"not_before": nb, "not_after": na}}
            for s in wit_signers
        ],
    }


def _ev_build_valid(bundle_bytes=None, ev_seed=_EV_A, wit_seed=_EV_WIT,
                    policy_wit_seeds=(_EV_WIT,), threshold=1,
                    expires=None, wit_window=None, leaves=1, ts=None,
                    ev_extra=()):
    """Build a fully valid offline-verifier bundle WITH a log-backed
    witness entry. Returns (bundle_bytes, verification_bundle, ctx)."""
    from gov import evidence_verify_offline as _v
    bundle_bytes = (b'{"evidence":"w313"}\n' if bundle_bytes is None
                    else bundle_bytes)
    ev = _EvSigner(ev_seed)
    evs = [ev] + [_EvSigner(s) for s in ev_extra]
    wit = _EvSigner(wit_seed)
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact.bin",
                     "digest": {"sha256": hashlib.sha256(bundle_bytes)
                                .hexdigest()}}],
        "predicateType": _EV_PRED,
        "predicate": {"window": "2026-10-03T00:00:00Z"},
    }
    payload = _v.canonical(stmt)
    policy = _ev_policy_doc(
        evs, expires or (_EV_NOW + timedelta(days=10)),
        [_EvSigner(s) for s in policy_wit_seeds],
        threshold=threshold, wit_window=wit_window)
    anchor = _EvSigner(_EV_ANCHOR)
    penv = _ev_seal(_v.canonical(policy), _v.POLICY_PAYLOAD_TYPE, [anchor])
    policy_digest = hashlib.sha256(_v.canonical(policy)).hexdigest()
    env = _ev_seal(payload, _v.ENVELOPE_PAYLOAD_TYPE, evs[:threshold]
                   if threshold <= len(evs) else evs)
    log = _v._witness_log().WitnessLog(wit.public_key)
    for i in range(leaves):
        log.append(b"w313-leaf-%d" % i)
    entry = _v.seal_witness_entry(
        log, wit,
        artifact_digest=hashlib.sha256(bundle_bytes).hexdigest(),
        signatures=env["signatures"],
        verified_keyids=[s.keyid() for s in evs[:threshold]],
        policy_digest=policy_digest,
        integrated_time=(ts if ts is not None
                         else int(_EV_NOW.timestamp())))
    vb = _v.build_verification_bundle(env, penv, witness_entries=[entry])
    return bundle_bytes, vb, {"ev": ev, "wit": wit, "log": log,
                             "entry": entry}


def _ev_clock():
    from gov import evidence_verify_offline as _v
    return _v.FixedClock("w313-clock", _EV_NOW)


def _ev_expect_refused(pid, fn, codes=()):
    """Run fn; HELD iff it raises a coded VerificationError (fail
    closed). codes, when given, restricts the acceptable refusal
    codes; any other coded refusal is still fail-closed but recorded
    with the observed code for triage."""
    from gov import evidence_verify_offline as _v
    try:
        fn()
    except _v.VerificationError as e:
        note = ("refused coded %s" % e.code)
        if codes and e.code not in codes:
            note += " (accepted: fail-closed, code differs from %r)" % (
                codes,)
        return _record(pid, "HELD", note)
    except _v.InternalError as e:
        return _record(pid, "HELD",
                       "fail-closed InternalError (verifier contract): %s"
                       % str(e)[:80])
    except Exception as e:  # noqa: BLE001
        return _record(pid, "ERROR",
                       "probe crashed: %r\n%s" % (e, traceback.format_exc(
                           limit=3)))
    return _record(pid, "BREAK",
                   "ATTACK SUCCEEDED: no refusal (fail-open)")


# --- Offline-verifier witness-stage attacks (all must fail closed) ---

def p_ovf_witness_transplant_refused():
    # Entry sealed under witness key WIT2; policy trusts WIT only.
    # The checkpoint logId must name a policy witness key.
    def go():
        from gov import evidence_verify_offline as _v
        bb, vb, _ = _ev_build_valid(wit_seed=_EV_WIT2,
                                    policy_wit_seeds=(_EV_WIT,))
        return _v.verify(bb, copy.deepcopy(vb),
                         time_source=_ev_clock())
    return _ev_expect_refused(
        "ovf-witness-transplant-refused", go,
        codes=("WITNESS_CHECKPOINT_INVALID",))


def p_ovf_witness_artifact_transplant():
    # Witness entry binds artifact A; verify against artifact B bytes.
    def go():
        from gov import evidence_verify_offline as _v
        bb, vb, _ = _ev_build_valid(bundle_bytes=b'artifact-A\n')
        return _v.verify(b'artifact-B\n', copy.deepcopy(vb),
                         time_source=_ev_clock())
    return _ev_expect_refused(
        "ovf-witness-artifact-transplant", go,
        codes=("SUBJECT_DIGEST_MISMATCH", "WITNESS_ENTRY_UNBOUND"))


def p_ovf_witness_sibling_tamper():
    # Multi-leaf log; zero a sibling hash in the inclusion path.
    def go():
        from gov import evidence_verify_offline as _v
        bb, vb, _ = _ev_build_valid(leaves=4)
        e = copy.deepcopy(vb)
        path = e["witness_entries"][0]["inclusion_path"]
        assert len(path) >= 1, "need a non-empty audit path"
        path[0]["hash"] = "00" * 32
        return _v.verify(bb, e, time_source=_ev_clock())
    return _ev_expect_refused(
        "ovf-witness-sibling-tamper", go,
        codes=("WITNESS_INCLUSION_INVALID",))


def p_ovf_witness_checkpoint_forgery():
    # Flip a byte of the sealed checkpoint signature.
    def go():
        from gov import evidence_verify_offline as _v
        bb, vb, _ = _ev_build_valid()
        e = copy.deepcopy(vb)
        we = e["witness_entries"][0]
        sig = base64.b64decode(we["checkpoint_signature"])
        bad = bytes([sig[0] ^ 1]) + sig[1:]
        we["checkpoint_signature"] = base64.b64encode(bad).decode("ascii")
        return _v.verify(bb, e, time_source=_ev_clock())
    return _ev_expect_refused(
        "ovf-witness-checkpoint-forgery", go,
        codes=("WITNESS_CHECKPOINT_INVALID",))


def p_ovf_witness_future_checkpoint():
    # Checkpoint timestamp a year in the future (also outside the
    # witness key's validity window).
    def go():
        from gov import evidence_verify_offline as _v
        bb, vb, _ = _ev_build_valid(
            ts=int((_EV_NOW + timedelta(days=365)).timestamp()))
        return _v.verify(bb, copy.deepcopy(vb),
                         time_source=_ev_clock())
    return _ev_expect_refused(
        "ovf-witness-future-checkpoint", go,
        codes=("WITNESS_CHECKPOINT_INVALID", "TEMPORAL_UNSATISFIED"))


def p_ovf_witness_key_window_expired():
    # Honestly-sealed checkpoint, but the policy's witness-key
    # valid_for window ended before the checkpoint time (CVE-2026-24122
    # analogue: issuing-key expiry must be checked at event time).
    def go():
        from gov import evidence_verify_offline as _v
        bb, vb, _ = _ev_build_valid(wit_window=(
            (_EV_NOW - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            (_EV_NOW - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")))
        return _v.verify(bb, copy.deepcopy(vb),
                         time_source=_ev_clock())
    return _ev_expect_refused(
        "ovf-witness-key-window-expired", go,
        codes=("WITNESS_CHECKPOINT_INVALID",))


def p_ovf_witness_two_entries():
    # Two witness entries: the lane supports exactly one (documented
    # residual); duplication must refuse coded, never be skipped.
    def go():
        from gov import evidence_verify_offline as _v
        bb, vb, _ = _ev_build_valid()
        e = copy.deepcopy(vb)
        e["witness_entries"] = [e["witness_entries"][0],
                                e["witness_entries"][0]]
        return _v.verify(bb, e, time_source=_ev_clock())
    return _ev_expect_refused(
        "ovf-witness-two-entries", go, codes=("BUNDLE_MALFORMED",))


def p_ovf_witness_wrong_policydigest():
    # Rebind the entry to a foreign policy digest. (The leaf preimage
    # also changes, so the inclusion proof fails too -- either coded
    # refusal is fail-closed.)
    def go():
        from gov import evidence_verify_offline as _v
        bb, vb, _ = _ev_build_valid()
        e = copy.deepcopy(vb)
        e["witness_entries"][0]["entry_body"]["spec"]["policyDigest"] = \
            "ab" * 32
        return _v.verify(bb, e, time_source=_ev_clock())
    return _ev_expect_refused(
        "ovf-witness-wrong-policydigest", go,
        codes=("WITNESS_ENTRY_UNBOUND", "WITNESS_INCLUSION_INVALID"))


def p_ovf_envelope_ptype_swap():
    # Envelope payloadType swapped to the POLICY payload type (the
    # signature no longer binds the statement type).
    def go():
        from gov import evidence_verify_offline as _v
        bb, vb, _ = _ev_build_valid()
        e = copy.deepcopy(vb)
        e["envelope"]["payloadType"] = _v.POLICY_PAYLOAD_TYPE
        return _v.verify(bb, e, time_source=_ev_clock())
    return _ev_expect_refused(
        "ovf-envelope-ptype-swap", go,
        codes=("UNSUPPORTED_PAYLOAD_TYPE", "ENVELOPE_SIGNATURE_INVALID"))


def p_ovf_threshold_distinct_keys():
    # Threshold=2, same key signs twice: distinct-key counting must
    # refuse (one distinct trusted key < threshold 2). The policy
    # names two keys so the policy itself is well-formed.
    def go():
        from gov import evidence_verify_offline as _v
        bb, vb, _ = _ev_build_valid(threshold=2, ev_extra=(_EV_B,))
        e = copy.deepcopy(vb)
        sigs = e["envelope"]["signatures"]
        e["envelope"]["signatures"] = [sigs[0], dict(sigs[0])]
        return _v.verify(bb, e, time_source=_ev_clock())
    return _ev_expect_refused(
        "ovf-threshold-distinct-keys", go,
        codes=("ENVELOPE_SIGNATURE_INVALID",))


def p_ovf_threshold_two_keys_pass():
    # Control: threshold=2 with two DISTINCT trusted keys verifies
    # (the counter counts keys, not signatures).
    from gov import evidence_verify_offline as _v
    bb, vb, _ = _ev_build_valid(threshold=2, ev_extra=(_EV_B,))
    try:
        rep = _v.verify(bb, copy.deepcopy(vb), time_source=_ev_clock())
    except Exception as e:  # noqa: BLE001
        return _record("ovf-threshold-two-keys-pass", "ERROR",
                       "control failed: %r" % (e,))
    if rep.get("verificationResult") == "PASSED":
        return _record("ovf-threshold-two-keys-pass", "HELD",
                       "threshold=2 met by two distinct keys: PASSED "
                       "(control)")
    return _record("ovf-threshold-two-keys-pass", "BREAK",
                   "threshold=2 with two distinct keys did not PASS: %r"
                   % (rep.get("verificationResult"),))


# --- Witness-log direct attacks (all must refuse coded) ---

def _wl_expect_refused(pid, fn):
    from gov import evidence_verify_offline as _v
    wl = _v._witness_log()
    try:
        fn(wl)
    except wl.WitnessError as e:
        return _record(pid, "HELD", "refused coded %s" % e.code)
    except Exception as e:  # noqa: BLE001
        return _record(pid, "ERROR",
                       "probe crashed: %r\n%s" % (e, traceback.format_exc(
                           limit=3)))
    return _record(pid, "BREAK", "ATTACK SUCCEEDED: no refusal")


def p_wl_position_binding_refused():
    # A valid inclusion proof for leaf 0, claimed at leaf_index=1:
    # the path sides must address exactly the claimed index.
    def go(wl):
        wit = _EvSigner(_EV_WIT)
        log = wl.WitnessLog(wit.public_key)
        for i in range(4):
            log.append(b"w313-pos-%d" % i)
        ts = int(_EV_NOW.timestamp())
        sealed = log.sealed_checkpoint(ts, wit)
        cp = wl.verify_checkpoint(
            {"checkpoint": sealed["checkpoint"],
             "signature": sealed["signature"]}, wit.public_key)
        proof = log.inclusion_proof(0)
        wl.verify_inclusion(b"w313-pos-0", 1, proof["path"],
                            cp["treeSize"],
                            bytes.fromhex(cp["rootHash"]))
    return _wl_expect_refused("wl-position-binding-refused", go)


def p_wl_fork_consistency_refused():
    # Two inconsistent checkpoints from the SAME witness key (forked
    # log): no valid consistency proof can connect them.
    def go(wl):
        wit = _EvSigner(_EV_WIT)
        log_a = wl.WitnessLog(wit.public_key)
        log_a.append(b"fork-a")
        log_b = wl.WitnessLog(wit.public_key)
        log_b.append(b"fork-b")
        ts = int(_EV_NOW.timestamp())
        sa = log_a.sealed_checkpoint(ts, wit)
        sb = log_b.sealed_checkpoint(ts, wit)
        cpa = wl.verify_checkpoint(
            {"checkpoint": sa["checkpoint"], "signature": sa["signature"]},
            wit.public_key)
        cpb = wl.verify_checkpoint(
            {"checkpoint": sb["checkpoint"], "signature": sb["signature"]},
            wit.public_key)
        proof = log_a.consistency_proof(1, 1)
        wl.verify_consistency(1, 1, proof, cpa["rootHash"],
                              cpb["rootHash"])
    return _wl_expect_refused("wl-fork-consistency-refused", go)


def p_wl_old_gt_new_refused():
    def go(wl):
        wl.verify_consistency(2, 1, [], "aa" * 32, "bb" * 32)
    return _wl_expect_refused("wl-old-gt-new-refused", go)


def p_wl_empty_leaf_refused():
    def go(wl):
        wl.verify_inclusion(b"", 0, [], 1, "cc" * 32)
    return _wl_expect_refused("wl-empty-leaf-refused", go)


# --- in-toto statement attacks (all must refuse coded) ---

def _intoto_expect_refused(pid, fn):
    from gov import dsse_envelope as _dsse
    try:
        fn()
    except _dsse.EnvelopeError as e:
        return _record(pid, "HELD", "refused coded: %s" % str(e)[:100])
    except Exception as e:  # noqa: BLE001
        return _record(pid, "ERROR",
                       "probe crashed: %r\n%s" % (e, traceback.format_exc(
                           limit=3)))
    return _record(pid, "BREAK", "ATTACK SUCCEEDED: no refusal")


def p_intoto_wrong_predicatetype():
    # Statement sealed under a foreign predicateType: the opener
    # pins OUR predicate type.
    def go():
        from gov import evidence_intoto as _ei
        from gov.signing import Ed25519Signer, Ed25519Verifier
        s = Ed25519Signer(_EV_A)
        stmt = _ei.build_statement(b'{"evidence":"w313"}\n',
                                   {"window": "x"})
        stmt["predicateType"] = "https://evil.example/pred"
        env = _ei.seal_statement(stmt, [s])
        ver = Ed25519Verifier(s.public_key, s.key_id)
        return _ei.open_statement(env, b'{"evidence":"w313"}\n', [ver])
    return _intoto_expect_refused("intoto-wrong-predicatetype", go)


def p_intoto_subject_tamper():
    # Re-sealed statement attesting a different bundle than the one
    # the caller expects: subject-digest binding must refuse.
    def go():
        from gov import evidence_intoto as _ei
        from gov.signing import Ed25519Signer, Ed25519Verifier
        s = Ed25519Signer(_EV_A)
        stmt = _ei.build_statement(b'{"evidence":"w313"}\n',
                                   {"window": "x"})
        stmt["subject"][0]["digest"]["sha256"] = "ff" * 32
        env = _ei.seal_statement(stmt, [s])
        ver = Ed25519Verifier(s.public_key, s.key_id)
        return _ei.open_statement(env, b'{"evidence":"w313"}\n', [ver])
    return _intoto_expect_refused("intoto-subject-tamper", go)


def p_intoto_threshold_2_one_sig():
    # Threshold=2 with a single signature: unmet threshold refuses.
    def go():
        from gov import evidence_intoto as _ei
        from gov.signing import Ed25519Signer, Ed25519Verifier
        s = Ed25519Signer(_EV_A)
        env = _ei.seal_statement(
            _ei.build_statement(b'{"evidence":"w313"}\n', {"window": "x"}),
            [s])
        ver = Ed25519Verifier(s.public_key, s.key_id)
        return _ei.open_statement(env, b'{"evidence":"w313"}\n', [ver],
                                  threshold=2)
    return _intoto_expect_refused("intoto-threshold-2-one-sig", go)


# --- Observer-timestamp attacks (all must fail closed) ---

def _ts_token(signer, aid, when, digest):
    from gov import evidence_verify_offline as _v
    body = {"authority_id": aid,
            "time": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "evidence_digest": digest}
    return {"authority_id": aid,
            "time": body["time"],
            "evidence_digest": digest,
            "sig": base64.b64encode(signer.sign(_v.canonical(body)))
            .decode("ascii")}


def _ts_build(min_ts=1, tsa_seeds=(_EV_TSA,), bundle_bytes=None,
              tokens=()):
    from gov import evidence_verify_offline as _v
    bundle_bytes = (b'{"evidence":"w313"}\n' if bundle_bytes is None
                    else bundle_bytes)
    ev = _EvSigner(_EV_A)
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact.bin",
                     "digest": {"sha256": hashlib.sha256(bundle_bytes)
                                .hexdigest()}}],
        "predicateType": _EV_PRED,
        "predicate": {"window": "2026-10-03T00:00:00Z"},
    }
    payload = _v.canonical(stmt)
    tsa = [_EvSigner(s) for s in tsa_seeds]
    policy = {
        "version": "sasanam-verification-policy/v1",
        "policy_id": "w313-ts-policy",
        "expires": (_EV_NOW + timedelta(days=10))
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "required_predicate_type": _EV_PRED,
        "required_predicate_claims": ["window"],
        "evidence_signing": {
            "threshold": 1,
            "keys": [{"keyid": ev.keyid(),
                      "pubkey_hex": ev.pubkey_hex()}],
        },
        "observer_timestamps": {"min": min_ts, "max_age_hours": 168},
        "timestamp_authorities": [
            {"authority_id": s.keyid(), "pubkey_hex": s.pubkey_hex(),
             "valid_for": {
                 "not_before": (_EV_NOW - timedelta(days=30))
                 .strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "not_after": (_EV_NOW + timedelta(days=30))
                 .strftime("%Y-%m-%dT%H:%M:%SZ")}}
            for s in tsa
        ],
        "witness_required": False,
        "witness_log_keys": [],
    }
    anchor = _EvSigner(_EV_ANCHOR)
    vb = {
        "version": _v.BUNDLE_VERSION,
        "envelope": _ev_seal(payload, _v.ENVELOPE_PAYLOAD_TYPE, [ev]),
        "policy": _ev_seal(_v.canonical(policy), _v.POLICY_PAYLOAD_TYPE,
                           [anchor]),
        "timestamps": list(tokens),
    }
    return bundle_bytes, vb


def p_ts_cross_authority_swap():
    # Token names authority A but is signed by authority B's key:
    # authority isolation must refuse.
    def go():
        from gov import evidence_verify_offline as _v
        tsa, tsb = _EvSigner(_EV_TSA), _EvSigner(_EV_TSB)
        bhex = hashlib.sha256(b'{"evidence":"w313"}\n').hexdigest()
        bb, vb = _ts_build(tsa_seeds=(_EV_TSA, _EV_TSB),
                           tokens=[_ts_token(tsb, tsa.keyid(), _EV_NOW,
                                             bhex)])
        return _v.verify(bb, vb, time_source=_ev_clock())
    return _ev_expect_refused(
        "ts-cross-authority-swap", go,
        codes=("TIMESTAMP_SIGNATURE_INVALID",))


def p_ts_evidence_digest_transplant():
    # Token binds a different artifact's digest.
    def go():
        from gov import evidence_verify_offline as _v
        tsa = _EvSigner(_EV_TSA)
        ohex = hashlib.sha256(b'{"evidence":"other"}\n').hexdigest()
        bb, vb = _ts_build(
            tokens=[_ts_token(tsa, tsa.keyid(), _EV_NOW, ohex)])
        return _v.verify(bb, vb, time_source=_ev_clock())
    return _ev_expect_refused(
        "ts-evidence-digest-transplant", go,
        codes=("TIMESTAMP_SIGNATURE_INVALID",))


def p_ts_min_unmet():
    # Policy requires >= 1 observer timestamp; bundle carries none.
    def go():
        from gov import evidence_verify_offline as _v
        bb, vb = _ts_build(min_ts=1)
        return _v.verify(bb, vb, time_source=_ev_clock())
    return _ev_expect_refused(
        "ts-min-unmet", go, codes=("TEMPORAL_UNSATISFIED",))


# --- Canonical probe-line parser: new adversarial cases ---

def p_pl_leading_space_strict():
    import probe_lines as _pl
    if _pl.parse_line(" [BREAK] pid: note") is None:
        return _record("pl-leading-space-strict", "HELD",
                       "indented line rejected (strict column-0 rule)")
    return _record("pl-leading-space-strict", "BREAK",
                   "indented line parsed as canonical")


def p_pl_tab_sep_strict():
    import probe_lines as _pl
    if _pl.parse_line("[BREAK]\tpid: note") is None:
        return _record("pl-tab-sep-strict", "HELD",
                       "tab separator rejected (strict)")
    return _record("pl-tab-sep-strict", "BREAK",
                   "tab-separated line parsed as canonical")


def p_pl_lowercase_verdict_strict():
    import probe_lines as _pl
    if _pl.parse_line("[break] pid: note") is None:
        return _record("pl-lowercase-verdict-strict", "HELD",
                       "lowercase verdict rejected (strict)")
    return _record("pl-lowercase-verdict-strict", "BREAK",
                   "lowercase verdict parsed as canonical")


def p_pl_slash_pid_strict():
    import probe_lines as _pl
    if _pl.parse_line("[BREAK] a/b: note") is None:
        return _record("pl-slash-pid-strict", "HELD",
                       "slash pid rejected (outside the load-bearing "
                       "class; green-check BREAK matching would miss it)")
    return _record("pl-slash-pid-strict", "BREAK",
                   "slash pid parsed as canonical")


def p_pl_double_newline_leniency():
    # Observation, not a break: the parser tolerates trailing
    # newlines beyond the documented single one (match() is
    # start-anchored, not end-anchored). The verdict/pid fields stay
    # strict; only the permissive note tail absorbs the extra newline.
    import probe_lines as _pl
    res = _pl.parse_line("[BREAK] pid: note\n\n")
    if res == ("BREAK", "pid", "note"):
        return _record("pl-double-newline-leniency", "HELD",
                       "double trailing newline tolerated like the "
                       "documented single-newline case (observation; "
                       "verdict/pid fields unaffected)")
    return _record("pl-double-newline-leniency", "ERROR",
                   "unexpected parse result: %r" % (res,))


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
    # F396 CLOSED 2026-10-03 wave-312 lane A: the w311 red-team
    # battery's three F396 probes were rewritten to assert the fix;
    # expect no BREAKs. Re-pinned to the wave-313 merge footer
    # (open none / next F398).
    green_check.check_battery(
        _rec, "green-w311_redteam", "evals/w311_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # F395 CLOSED (wave-311 lane A): the w311_f395 battery asserts the
    # coded exotic-closure refusal; expect no BREAKs. Re-pinned to
    # the lane footer.
    green_check.check_battery(
        _rec, "green-w311_f395", "evals/w311_f395_probes.py",
        repo=REPO, expect_break_ids=())
    # Standalone offline verifier (wave-311 lane E); expect no BREAKs.
    # Re-pinned to the lane footer.
    green_check.check_battery(
        _rec, "green-w311_offline_verifier",
        "evals/w311_offline_verifier_probes.py",
        repo=REPO, expect_break_ids=())
    # F393 CLOSED (wave-309 lane A): the w309_f393 battery's F393
    # probes assert the coded workflow-composed-plan-mismatch
    # refusal; expect no BREAKs. Re-pinned to the lane footer.
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
    # F394 CLOSED: the w310_f394 battery asserts the composer-API
    # re-drive; expect no BREAKs. Re-pinned to the lane footer.
    green_check.check_battery(
        _rec, "green-w310_f394", "evals/w310_f394_probes.py",
        repo=REPO, expect_break_ids=())
    # F385-F387 closures: the w307 red-team battery; expect no BREAKs.
    # Re-pinned to the lane footer.
    green_check.check_battery(
        _rec, "green-w307_redteam", "evals/w307_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # F388 / F390 closure regressions; expect no BREAKs. Re-pinned to
    # the lane footer.
    green_check.check_battery(
        _rec, "green-w303_f388", "evals/w303_f388_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_battery(
        _rec, "green-w303_f390", "evals/w303_f390_probes.py",
        repo=REPO, expect_break_ids=())
    # The wave-312 red-team battery itself (this lane's predecessor):
    # F397 CLOSED (wave-313 lane A): its two F397 probes now assert
    # the coded stale-at refusal; expect no BREAKs. Wave-315 D6
    # reconciliation: the w312 battery now emits canonical probe
    # lines, so BREAK_ID_RE is enforced (it was vacuous on the old
    # literal-[VERDICT] shape); the stale expected-BREAK list for
    # the since-closed F397 was swept.
    green_check.check_battery(
        _rec, "green-w312_redteam", "evals/w312_redteam_probes.py",
        repo=REPO, expect_break_ids=())


# ------------------------------------------------------------------
# Probe table + main
# ------------------------------------------------------------------

_PROBES = [
    ("pin-taxonomy", p_taxonomy_pin),
    ("footer-state", p_footer_state),
    # F397 (OPEN, filed wave-312 -- expected BREAKs)
    ("F397-stale-at-retry", p_f397_stale_at_retry),
    ("F397-stale-at-zero", p_f397_stale_at_zero),
    ("F397-stale-at-boundary", p_f397_stale_at_boundary),
    # F396 (OPEN -- expected BREAKs)
    ("F396-defaults-fn", p_f396_defaults_fn),
    ("F396-defaults-saga", p_f396_defaults_saga),
    ("F396-kwdefaults-fn", p_f396_kwdefaults_fn),
    # F395 CLOSED regressions (must be HELD)
    ("F395-exotic-closure-fn", p_f395_exotic_closure_fn),
    ("F395-exotic-closure-saga", p_f395_exotic_closure_saga),
    ("F395-exotic-closure-nested", p_f395_exotic_closure_nested),
    # F394 CLOSED regressions (must be HELD)
    ("F394-composer-retry-holds", p_f394_composer_retry_holds),
    ("F394-composer-abort-holds", p_f394_composer_abort_holds),
    ("F394-direct-sm-fails-closed", p_f394_direct_sm_fails_closed),
    ("F394-unauthorized-operator-refused",
     p_f394_unauthorized_operator_refused),
    ("F394-double-retry-refused", p_f394_double_retry_refused),
    ("F394-unknown-unit-refused", p_f394_unknown_unit_refused),
    ("F394-never-escalated-refused", p_f394_never_escalated_refused),
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
    # Sigstore bundle (must fail closed -> HELD)
    ("sigstore-threshold-type-games", p_sigstore_threshold_type_games),
    ("sigstore-duplicate-sigs-distinct-keys",
     p_sigstore_duplicate_sigs_distinct_keys),
    ("sigstore-witness-transplant-refused",
     p_sigstore_witness_transplant_refused),
    ("sigstore-integratedtime-type-refused",
     p_sigstore_integratedtime_type_refused),
    ("sigstore-validity-required", p_sigstore_validity_required),
    ("sigstore-keyid-swap-refused", p_sigstore_keyid_swap_refused),
    ("sigstore-rfc3161-carrier", p_sigstore_rfc3161_carrier),
    ("sigstore-tampered-payload-refused",
     p_sigstore_tampered_payload_refused),
    # Offline verifier (must fail closed / per contract -> HELD)
    ("ovf-naive-clock-internal", p_ovf_naive_clock_internal),
    ("ovf-caller-supplied-root-labeled",
     p_ovf_caller_supplied_root_labeled),
    ("ovf-bool-threshold-policy-malformed",
     p_ovf_bool_threshold_policy_malformed),
    ("ovf-existence-only-labeled", p_ovf_existence_only_labeled),
    # Probe-line pilot (parser robustness)
    ("probe-lines-no-space-colon", p_probe_lines_no_space_colon),
    ("probe-lines-crlf", p_probe_lines_crlf),
    ("probe-lines-unicode-verdict", p_probe_lines_unicode_verdict),
    ("probe-lines-null-note", p_probe_lines_null_note),
    ("probe-lines-round-trip", p_probe_lines_round_trip),
    # Wave-313 new parser adversaries (strictness + leniency)
    ("pl-leading-space-strict", p_pl_leading_space_strict),
    ("pl-tab-sep-strict", p_pl_tab_sep_strict),
    ("pl-lowercase-verdict-strict", p_pl_lowercase_verdict_strict),
    ("pl-slash-pid-strict", p_pl_slash_pid_strict),
    ("pl-double-newline-leniency", p_pl_double_newline_leniency),
    # Wave-313: offline-verifier witness stage (must fail closed)
    ("ovf-witness-transplant-refused", p_ovf_witness_transplant_refused),
    ("ovf-witness-artifact-transplant", p_ovf_witness_artifact_transplant),
    ("ovf-witness-sibling-tamper", p_ovf_witness_sibling_tamper),
    ("ovf-witness-checkpoint-forgery", p_ovf_witness_checkpoint_forgery),
    ("ovf-witness-future-checkpoint", p_ovf_witness_future_checkpoint),
    ("ovf-witness-key-window-expired", p_ovf_witness_key_window_expired),
    ("ovf-witness-two-entries", p_ovf_witness_two_entries),
    ("ovf-witness-wrong-policydigest", p_ovf_witness_wrong_policydigest),
    ("ovf-envelope-ptype-swap", p_ovf_envelope_ptype_swap),
    ("ovf-threshold-distinct-keys", p_ovf_threshold_distinct_keys),
    ("ovf-threshold-two-keys-pass", p_ovf_threshold_two_keys_pass),
    # Wave-313: witness log direct (must refuse coded)
    ("wl-position-binding-refused", p_wl_position_binding_refused),
    ("wl-fork-consistency-refused", p_wl_fork_consistency_refused),
    ("wl-old-gt-new-refused", p_wl_old_gt_new_refused),
    ("wl-empty-leaf-refused", p_wl_empty_leaf_refused),
    # Wave-313: in-toto statement (must refuse coded)
    ("intoto-wrong-predicatetype", p_intoto_wrong_predicatetype),
    ("intoto-subject-tamper", p_intoto_subject_tamper),
    ("intoto-threshold-2-one-sig", p_intoto_threshold_2_one_sig),
    # Wave-313: observer timestamps (must fail closed)
    ("ts-cross-authority-swap", p_ts_cross_authority_swap),
    ("ts-evidence-digest-transplant", p_ts_evidence_digest_transplant),
    ("ts-min-unmet", p_ts_min_unmet),
]

_EXPECTED_BREAKS = frozenset({
    # F397 CLOSED 2026-10-03 wave-313 lane A (stale `at` refused coded):
    # the three F397 probes (dual-mode: stale-at-retry / stale-at-zero /
    # stale-at-boundary) now record HELD on the merged tree.
    # F396 CLOSED 2026-10-03 wave-312 lane A: the three F396 probes
    # (dual-mode: digest distinction / coded plan-mismatch) now
    # record HELD on the merged tree.
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
    # Canonical probe-line form (evals/probe_lines.py): one line per
    # probe, in recording order, before the "----" separator and the
    # summary line.
    probe_lines.emit(_results)
    print("----")
    brk = sum(1 for r in _results if r[1] == "BREAK")
    held = sum(1 for r in _results if r[1] == "HELD")
    err = sum(1 for r in _results if r[1] == "ERROR")
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    # Open-findings sweep: exactly the expected BREAKs (all OPEN).
    # Exit 1 when any BREAK is present (open findings), like the
    # w311 red-team battery.
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
