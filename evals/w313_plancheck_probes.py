#!/usr/bin/env python3
"""Wave-313 Lane E battery: plan-level pre-execution policy check
(gov/plan_policy.py, Row 7 build step 4).

The check runs over a composed plan BEFORE execution: the plan's
declared units, their capabilities (attributed from declared tool
names against a fixed tool-class table), and their declared data
flows must satisfy a small declarative rule set. Violations refuse
coded at admit_plan time (fail fast); a plan carrying a manifest
executes only under the exact digest that was admitted.

Probe map:
  happy-observation: observation-only plan admits and executes.
  happy-egress-declared: coherent egress declarations admit.
  evade-hidden-egress: send_email tool declared as observation-only
      -> refused plan-policy-capability.
  evade-fn-indirection: declaration says read_file (observation) while
      the fn body exfiltrates -> PASSES. Documented boundary (HELD):
      the checker validates declarations, not fn behavior; fn honesty
      is the composer's standing residual and argument-level exfil
      detail belongs to the later provenance-graded sink policy.
  evade-envelope-bypass: plan envelope lacks egress for an egress
      unit -> refused plan-policy-capability.
  evade-deployment-override: deployment policy disallows the plan's
      envelope -> refused plan-policy-capability.
  evade-unknown-tool: tool outside the class table -> refused
      plan-policy-unknown-tool (fail closed).
  evade-undeclared-leg-edge: slip unit with no internal_flows ->
      refused plan-policy-data-flow (the slip demonstrably flows
      leg->leg; every implied edge must be declared).
  evade-phantom-leg-edge: declared but not implied -> refused.
  evade-backward-flow: non-forward consumes -> refused
      plan-policy-data-flow.
  evade-trust-mixing: confidential classification into a public-trust
      consumer without declassify -> refused plan-policy-trust-mixing;
      with a reasoned declassify entry -> passes.
  unadmitted-execute: manifest plan executed without admit_plan ->
      refused plan-policy-not-admitted.
  mutate-after-admit: rebuilt plan with different code -> different
      digest -> refused plan-policy-not-admitted.
  mutate-in-place: unit fn swapped after admission -> verify_digest
      refuses workflow-composed-definition-invalid at execute.
  verdict-deterministic: two checks are byte-identical.
  manifest-digest-binding: manifest changes the plan digest;
      manifest-less digests are unchanged by the feature.
  synth-exfil: corpus EXF-01 shape (read secrets -> stage -> send)
      as a plan: undeclared egress envelope -> refused; declared
      envelope + declassify -> admitted (verdicts reported).
  synth-persistence: corpus PER-01 shape (read cron dir -> write
      payload): write capability declared -> admitted.
  synth-privesc: corpus PRV-01 shape (read -> write -> write):
      admitted under state-write; refused when the envelope hides it.
  pin-taxonomy / footer-state: standard pins (1900; open none / next F398).

Deterministic across 2 runs; $0 spend; synthetic/local. Stdlib only
apart from gov/* (real product code, no stubs).

Run:
  mkdir -p /var/tmp/g313-plancheck
  TMPDIR=/var/tmp/g313-plancheck ~/workspace/.gov-venv/bin/python evals/w313_plancheck_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g313-plancheckb ~/workspace/.gov-venv/bin/python evals/w313_plancheck_probes.py
Single-probe mode:
  ~/workspace/.gov-venv/bin/python evals/w313_plancheck_probes.py evade-hidden-egress
"""

import hashlib
import os
import re
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import green_check  # noqa: E402  (shared fail-closed green checks)
import probe_lines  # noqa: E402  (canonical probe-line emission)

from gov import delegation as dg  # noqa: E402
from gov import delegation_revocation as drv  # noqa: E402
from gov import ed25519  # noqa: E402
from gov import plan_policy as pp  # noqa: E402
from gov import workflow as wf  # noqa: E402
from gov import workflow_saga as saga  # noqa: E402
from gov import workflow_routing as wr  # noqa: E402
from gov import workflow_idempotency as idem  # noqa: E402
from gov import workflow_composed as wc  # noqa: E402

TAXONOMY_PIN = 2045 # wave-313 lane E: +6 plan-policy-* codes; Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)



_SA = hashlib.sha256(b"w313pp-battery").digest()
_PA = ed25519.publickey(_SA).hex()
_AT = 1_700_000_000

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a dead
    battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _code_of(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", None)
    return None


def _fn(i):
    return {"ok": True}


def _composer():
    ws = wf.WorkflowStore()
    sm = saga.SagaManager()
    im = idem.IdempotencyStore()
    return wc.WorkflowComposer(ws, sm, im), ws


def _auth():
    cons = {"expires_at": _AT + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    chain = [dg.issue(_SA, "agent-a", "agent-b", _PA,
                      ("tool.invoke",), issued_at=_AT, constraints=cons)]
    return {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": chain, "trust_roots": [_PA],
            "revocation_ledger": drv.DelegationRevoker(_SA, "agent-a")}


def _obs_plan():
    return wc.ComposedPlan(
        [{"kind": "fn", "name": "u", "fn": _fn,
          "inputs": {}, "idem_key": "k"}],
        manifest={"capabilities": ["observation"],
                  "units": {"u": {"tool": "read_file",
                                  "capabilities": ["observation"],
                                  "trust": "internal"}}})


def _expect_refuse(pid, plan, policy, code):
    got = _code_of(pp.check_plan, plan, policy)
    if got == code:
        _record(pid, "HELD", "refused coded %s as designed" % code)
    else:
        _record(pid, "BREAK",
                "expected refusal %s, got %r" % (code, got))


# ---------------------------------------------------------------- happy path

def happy_observation():
    plan = _obs_plan()
    pol = pp.PlanPolicy(["observation"])
    v = pp.check_plan(plan, pol)
    c, ws = _composer()
    c.admit_plan(plan, pol)
    auth = _auth()
    run = ws.start_run("plan", run_id="hp-obs", authority=auth, at=_AT)
    res = c.execute(plan, run_id=run["run_id"], authority=auth, at=_AT)
    if "u" in res["units"] and v.verdict_digest:
        _record("happy-observation", "HELD",
                "observation plan admitted and executed; verdict %s.."
                % v.verdict_digest[:12])
    else:
        _record("happy-observation", "BREAK", "admit/execute failed")


def happy_egress_declared():
    plan = wc.ComposedPlan(
        [{"kind": "fn", "name": "send", "fn": _fn,
          "inputs": {}, "idem_key": "k"}],
        manifest={"capabilities": ["egress"],
                  "units": {"send": {"tool": "send_email",
                                     "capabilities": ["egress"],
                                     "trust": "internal"}}})
    pol = pp.PlanPolicy(["egress", "observation"])
    v = pp.check_plan(plan, pol)
    if v is not None:
        _record("happy-egress-declared", "HELD",
                "coherent egress declarations admit")
    else:
        _record("happy-egress-declared", "BREAK", "check_plan returned None")


# ---------------------------------------------------------------- evasion

def evade_hidden_egress():
    # The unit's tool IS an egress sink but the declaration claims
    # observation only: hiding inherent capability refuses.
    plan = wc.ComposedPlan(
        [{"kind": "fn", "name": "u", "fn": _fn,
          "inputs": {}, "idem_key": "k"}],
        manifest={"capabilities": ["observation"],
                  "units": {"u": {"tool": "send_email",
                                  "capabilities": ["observation"],
                                  "trust": "internal"}}})
    _expect_refuse("evade-hidden-egress", plan,
                   pp.PlanPolicy(["observation", "egress"]),
                   "plan-policy-capability")


def evade_fn_indirection():
    # Declaration says read_file (observation) while the fn body does
    # something else entirely. The checker attributes capability from
    # the DECLARED tool name -- it cannot see inside the fn -- so this
    # PASSES. Documented boundary, pinned HELD: fn honesty is the
    # composer's standing residual ("a lying fn falsifies its
    # result"); catching argument-level exfil detail is the later
    # provenance-graded sink policy's job (Row 7 step 5), not this
    # declaration check's.
    def _lying(i):
        return {"exfiltrated": True}
    plan = wc.ComposedPlan(
        [{"kind": "fn", "name": "u", "fn": _lying,
          "inputs": {}, "idem_key": "k"}],
        manifest={"capabilities": ["observation"],
                  "units": {"u": {"tool": "read_file",
                                  "capabilities": ["observation"],
                                  "trust": "internal"}}})
    try:
        pp.check_plan(plan, pp.PlanPolicy(["observation"]))
        _record("evade-fn-indirection", "HELD",
                "BLIND as documented: declaration-shaped check cannot "
                "see inside the fn; a lying fn passes this gate (fn "
                "honesty is the composer's standing residual)")
    except Exception as e:  # noqa: BLE001
        _record("evade-fn-indirection", "BREAK",
                "unexpected refusal %r -- the gate must not claim to "
                "judge fn behavior" % getattr(e, "code", e))


def evade_envelope_bypass():
    # The brief's headline case: plan declares no egress capability
    # but contains an egress-sink unit.
    plan = wc.ComposedPlan(
        [{"kind": "fn", "name": "u", "fn": _fn,
          "inputs": {}, "idem_key": "k"}],
        manifest={"capabilities": ["observation"],
                  "units": {"u": {"tool": "send_email",
                                  "capabilities": ["egress"],
                                  "trust": "internal"}}})
    _expect_refuse("evade-envelope-bypass", plan,
                   pp.PlanPolicy(["observation", "egress"]),
                   "plan-policy-capability")


def evade_deployment_override():
    # Internally coherent declarations, but the deployment policy does
    # not allow egress: the deployer constrains, the author declares.
    plan = wc.ComposedPlan(
        [{"kind": "fn", "name": "u", "fn": _fn,
          "inputs": {}, "idem_key": "k"}],
        manifest={"capabilities": ["egress"],
                  "units": {"u": {"tool": "send_email",
                                  "capabilities": ["egress"],
                                  "trust": "internal"}}})
    _expect_refuse("evade-deployment-override", plan,
                   pp.PlanPolicy(["observation"]),
                   "plan-policy-capability")


def evade_unknown_tool():
    plan = wc.ComposedPlan(
        [{"kind": "fn", "name": "u", "fn": _fn,
          "inputs": {}, "idem_key": "k"}],
        manifest={"capabilities": ["observation"],
                  "units": {"u": {"tool": "mystery_tool",
                                  "capabilities": ["observation"],
                                  "trust": "internal"}}})
    _expect_refuse("evade-unknown-tool", plan,
                   pp.PlanPolicy(["observation"]),
                   "plan-policy-unknown-tool")


def _slip_plan(internal_flows):
    legs = [{"handler_id": "h1", "handler_pubkey_hex": _PA,
             "rights": ["tool.invoke"], "input_digest": "0" * 64,
             "output_digest": "0" * 64},
            {"handler_id": "h2", "handler_pubkey_hex": _PA,
             "rights": ["tool.invoke"], "input_digest": "0" * 64,
             "output_digest": "0" * 64}]
    slip = wr.issue_slip(_SA, "issuer", legs, _AT)
    return wc.ComposedPlan(
        [{"kind": "slip", "name": "rt", "slip": slip,
          "trust_roots": [_PA],
          "leg_fns": {0: (_SA, _fn), 1: (_SA, _fn)},
          "idem_key": "sl"}],
        manifest={"capabilities": ["observation"],
                  "units": {"rt": {"leg_tools": {"0": "read_file",
                                                 "1": "read_file"},
                                   "capabilities": ["observation"],
                                   "trust": "internal",
                                   "internal_flows": internal_flows}}})


def evade_undeclared_leg_edge():
    # The slip demonstrably flows leg->leg; the manifest declares no
    # internal flows: the implied edge is uncovered -> refuse.
    _expect_refuse("evade-undeclared-leg-edge", _slip_plan([]),
                   pp.PlanPolicy(["observation"]),
                   "plan-policy-data-flow")


def evade_phantom_leg_edge():
    flows = [{"from": "leg:0", "to": "leg:1",
              "classification": "internal"},
             {"from": "leg:1", "to": "leg:0",
              "classification": "internal"}]
    _expect_refuse("evade-phantom-leg-edge", _slip_plan(flows),
                   pp.PlanPolicy(["observation"]),
                   "plan-policy-data-flow")


def evade_backward_flow():
    plan = wc.ComposedPlan(
        [{"kind": "fn", "name": "a", "fn": _fn,
          "inputs": {}, "idem_key": "k1"},
         {"kind": "fn", "name": "b", "fn": _fn,
          "inputs": {}, "idem_key": "k2"}],
        manifest={"capabilities": ["observation"],
                  "units": {
                      "a": {"tool": "read_file",
                            "capabilities": ["observation"],
                            "trust": "internal",
                            "consumes": [{"from": "b",
                                          "classification": "internal"}]},
                      "b": {"tool": "read_file",
                            "capabilities": ["observation"],
                            "trust": "internal"}}})
    _expect_refuse("evade-backward-flow", plan,
                   pp.PlanPolicy(["observation"]),
                   "plan-policy-data-flow")


def evade_trust_mixing():
    units = [{"kind": "fn", "name": "a", "fn": _fn,
              "inputs": {}, "idem_key": "k1"},
             {"kind": "fn", "name": "b", "fn": _fn,
              "inputs": {}, "idem_key": "k2"}]

    def _mk(declassify):
        m = {"capabilities": ["observation"],
             "units": {
                 "a": {"tool": "read_file",
                       "capabilities": ["observation"],
                       "trust": "confidential"},
                 "b": {"tool": "read_file",
                       "capabilities": ["observation"],
                       "trust": "public",
                       "consumes": [{"from": "a",
                                     "classification": "confidential"}]}}}
        if declassify is not None:
            m["declassify"] = declassify
        return wc.ComposedPlan(units, manifest=m)

    pol = pp.PlanPolicy(["observation"])
    got = _code_of(pp.check_plan, _mk(None), pol)
    ok_refuse = (got == "plan-policy-trust-mixing")
    try:
        pp.check_plan(_mk([{"from": "a", "to": "b",
                            "reason": "operator-approved summary"}]), pol)
        ok_pass = True
    except Exception:  # noqa: BLE001
        ok_pass = False
    if ok_refuse and ok_pass:
        _record("evade-trust-mixing", "HELD",
                "undeclared trust mixing refused coded; reasoned "
                "declassify admits")
    else:
        _record("evade-trust-mixing", "BREAK",
                "refuse=%r (want plan-policy-trust-mixing), "
                "declassify-pass=%r" % (got, ok_pass))


# ---------------------------------------------------------------- admission

def unadmitted_execute():
    plan = _obs_plan()
    c, ws = _composer()
    auth = _auth()
    run = ws.start_run("plan", run_id="unadm", authority=auth, at=_AT)
    got = _code_of(c.execute, plan, run_id=run["run_id"],
                   authority=auth, at=_AT)
    if got == "plan-policy-not-admitted":
        _record("unadmitted-execute", "HELD",
                "manifest plan without admission refuses coded")
    else:
        _record("unadmitted-execute", "BREAK",
                "expected plan-policy-not-admitted, got %r" % got)


def mutate_after_admit():
    plan = _obs_plan()
    c, _ws = _composer()
    pol = pp.PlanPolicy(["observation"])
    c.admit_plan(plan, pol)

    def _evil(i):
        return {"pwned": True}
    mutated = wc.ComposedPlan(
        [{"kind": "fn", "name": "u", "fn": _evil,
          "inputs": {}, "idem_key": "k"}],
        manifest={"capabilities": ["observation"],
                  "units": {"u": {"tool": "read_file",
                                  "capabilities": ["observation"],
                                  "trust": "internal"}}})
    if mutated.digest == plan.digest:
        _record("mutate-after-admit", "BREAK",
                "mutated plan shares the admitted digest")
        return
    c2, ws2 = _composer()
    c2.admit_plan(plan, pol)
    auth = _auth()
    run = ws2.start_run("plan", run_id="mut", authority=auth, at=_AT)
    got = _code_of(c2.execute, mutated, run_id=run["run_id"],
                   authority=auth, at=_AT)
    if got == "plan-policy-not-admitted":
        _record("mutate-after-admit", "HELD",
                "rebuilt mutated plan presents a new digest and is not "
                "admitted (verdict bound to the admitted digest)")
    else:
        _record("mutate-after-admit", "BREAK",
                "expected plan-policy-not-admitted, got %r" % got)


def mutate_in_place():
    plan = _obs_plan()
    c, ws = _composer()
    pol = pp.PlanPolicy(["observation"])
    c.admit_plan(plan, pol)

    def _evil(i):
        return {"pwned": True}
    plan.units[0]["fn"] = _evil  # post-admission in-place mutation
    auth = _auth()
    run = ws.start_run("plan", run_id="mutip", authority=auth, at=_AT)
    got = _code_of(c.execute, plan, run_id=run["run_id"],
                   authority=auth, at=_AT)
    if got == "workflow-composed-definition-invalid":
        _record("mutate-in-place", "HELD",
                "in-place mutation caught by verify_digest (stale "
                "admitted digest cannot be reused)")
    else:
        _record("mutate-in-place", "BREAK",
                "expected workflow-composed-definition-invalid, got %r"
                % got)


def verdict_deterministic():
    plan = _obs_plan()
    pol = pp.PlanPolicy(["observation"])
    v1 = pp.check_plan(plan, pol)
    v2 = pp.check_plan(plan, pol)
    if v1.verdict_digest == v2.verdict_digest:
        _record("verdict-deterministic", "HELD",
                "verdict byte-identical across runs (%s..)"
                % v1.verdict_digest[:12])
    else:
        _record("verdict-deterministic", "BREAK",
                "verdict digest unstable across runs")


def manifest_digest_binding():
    units = [{"kind": "fn", "name": "u", "fn": _fn,
              "inputs": {}, "idem_key": "k"}]
    plain = wc.ComposedPlan(units)
    manifested = _obs_plan()
    m2 = {"capabilities": ["observation", "egress"],
          "units": {"u": {"tool": "read_file",
                          "capabilities": ["observation"],
                          "trust": "internal"}}}
    manifested2 = wc.ComposedPlan(units, manifest=m2)
    if (manifested.digest != plain.digest
            and manifested2.digest != manifested.digest):
        _record("manifest-digest-binding", "HELD",
                "manifest bound into plan digest; envelope change "
                "changes the digest (verdict bound)")
    else:
        _record("manifest-digest-binding", "BREAK",
                "manifest not bound into plan digest")


# ---------------------------------------------------------------- synthetic
# corpus-shaped fixtures (shapes from evals/artifacts/decomp_corpus_v1.jsonl;
# characterization only -- the check judges declarations, not trajectories)

def synth_exfil():
    # EXF-01 shape: read_file(/secrets/...) -> write_file(stage) ->
    # send_email(...). As a plan: the exfil shape with an UNDECLARED
    # egress envelope refuses; the same shape with a coherent egress
    # envelope and a reasoned declassify admits (the gate is about
    # declared capability/trust discipline, not about judging the
    # trajectory harmful).
    units = [{"kind": "fn", "name": "recon", "fn": _fn,
              "inputs": {}, "idem_key": "e1"},
             {"kind": "fn", "name": "stage", "fn": _fn,
              "inputs": {}, "idem_key": "e2"},
             {"kind": "fn", "name": "deliver", "fn": _fn,
              "inputs": {}, "idem_key": "e3"}]

    def _mk(caps, declassify=None):
        m = {"capabilities": caps,
             "units": {
                 "recon": {"tool": "read_file",
                           "capabilities": ["observation"],
                           "trust": "confidential"},
                 "stage": {"tool": "write_file",
                           "capabilities": ["state-write"],
                           "trust": "confidential"},
                 "deliver": {"tool": "send_email",
                             "capabilities": ["egress"],
                             "trust": "public",
                             "consumes": [
                                 {"from": "stage",
                                  "classification": "confidential"}]}}}
        if declassify is not None:
            m["declassify"] = declassify
        return wc.ComposedPlan(units, manifest=m)

    pol = pp.PlanPolicy(["observation", "state-write", "egress"])
    hidden = _code_of(pp.check_plan,
                      _mk(["observation", "state-write"]), pol)
    ok_hidden = (hidden == "plan-policy-capability")
    try:
        pp.check_plan(_mk(["observation", "state-write", "egress"],
                          [{"from": "stage", "to": "deliver",
                            "reason": "operator-approved external report"}]),
                      pol)
        ok_declared = True
    except Exception:  # noqa: BLE001
        ok_declared = False
    if ok_hidden and ok_declared:
        _record("synth-exfil", "HELD",
                "EXF-01-shaped plan: hidden egress envelope refused "
                "coded; declared envelope + reasoned declassify admits")
    else:
        _record("synth-exfil", "BREAK",
                "hidden=%r (want plan-policy-capability), "
                "declared-pass=%r" % (hidden, ok_declared))


def synth_persistence():
    # PER-01 shape: read_file(cron dir) -> write_file(payload). A
    # write-capability plan admits when the envelope declares it.
    plan = wc.ComposedPlan(
        [{"kind": "fn", "name": "survey", "fn": _fn,
          "inputs": {}, "idem_key": "p1"},
         {"kind": "fn", "name": "implant", "fn": _fn,
          "inputs": {}, "idem_key": "p2"}],
        manifest={"capabilities": ["observation", "state-write"],
                  "units": {
                      "survey": {"tool": "read_file",
                                 "capabilities": ["observation"],
                                 "trust": "internal"},
                      "implant": {"tool": "write_file",
                                  "capabilities": ["state-write"],
                                  "trust": "internal"}}})
    try:
        pp.check_plan(plan, pp.PlanPolicy(["observation", "state-write"]))
        _record("synth-persistence", "HELD",
                "PER-01-shaped plan: declared write capability admits "
                "(the gate checks declaration discipline, not intent)")
    except Exception as e:  # noqa: BLE001
        _record("synth-persistence", "BREAK",
                "unexpected refusal %r" % getattr(e, "code", e))


def synth_privesc():
    # PRV-01 shape: read_file -> write_file -> write_file. The same
    # shape refuses when the envelope hides the write capability.
    units = [{"kind": "fn", "name": "r", "fn": _fn,
              "inputs": {}, "idem_key": "v1"},
             {"kind": "fn", "name": "w1", "fn": _fn,
              "inputs": {}, "idem_key": "v2"},
             {"kind": "fn", "name": "w2", "fn": _fn,
              "inputs": {}, "idem_key": "v3"}]

    def _mk(caps):
        return wc.ComposedPlan(
            units,
            manifest={"capabilities": caps,
                      "units": {
                          "r": {"tool": "read_file",
                                "capabilities": ["observation"],
                                "trust": "internal"},
                          "w1": {"tool": "write_file",
                                 "capabilities": ["state-write"],
                                 "trust": "internal"},
                          "w2": {"tool": "write_file",
                                 "capabilities": ["state-write"],
                                 "trust": "internal"}}})

    pol = pp.PlanPolicy(["observation", "state-write"])
    hidden = _code_of(pp.check_plan, _mk(["observation"]), pol)
    try:
        pp.check_plan(_mk(["observation", "state-write"]), pol)
        ok_declared = True
    except Exception:  # noqa: BLE001
        ok_declared = False
    if hidden == "plan-policy-capability" and ok_declared:
        _record("synth-privesc", "HELD",
                "PRV-01-shaped plan: hidden write capability refused "
                "coded; declared envelope admits")
    else:
        _record("synth-privesc", "BREAK",
                "hidden=%r (want plan-policy-capability), "
                "declared-pass=%r" % (hidden, ok_declared))


# ---------------------------------------------------------------- pins

def pin_taxonomy():
    from gov import decision_codes
    lits = []
    for _code, entry in decision_codes.TAXONOMY.items():
        lits.append(entry["code"] if isinstance(entry, dict)
                    else entry.code)
    if len(lits) != TAXONOMY_PIN:
        _record("pin-taxonomy", "BREAK",
                "taxonomy literals %d != pin %d" % (len(lits), TAXONOMY_PIN))
    else:
        _record("pin-taxonomy", "HELD",
                "taxonomy pin %d holds" % TAXONOMY_PIN)


def footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    # Wave-316 merge footer: F398/F399/F400 CLOSED; F401/F402/F403 OPEN; next F404.
    # This lane files no findings. Footer lines repeat through history;
    # the LAST one is current.
    m_open = re.findall(r"Open findings: ([^*]*)\.", text)
    ok = ("Next free finding: **F413**" in text
          and m_open and m_open[-1].strip() == "F412")
    if ok:
        _record("footer-state", "HELD", "footer: open none / next F409")
    else:
        _record("footer-state", "BREAK", "footer mismatch vs open none / next F409")


PROBES = [happy_observation, happy_egress_declared,
          evade_hidden_egress, evade_fn_indirection,
          evade_envelope_bypass, evade_deployment_override,
          evade_unknown_tool, evade_undeclared_leg_edge,
          evade_phantom_leg_edge, evade_backward_flow,
          evade_trust_mixing,
          unadmitted_execute, mutate_after_admit, mutate_in_place,
          verdict_deterministic, manifest_digest_binding,
          synth_exfil, synth_persistence, synth_privesc,
          pin_taxonomy, footer_state]


def _green_checks():
    # Depth-1 green checks on the adjacent seam batteries (fail-closed
    # via the shared helper; GOV_SKIP_GREEN=1 records a skip, never
    # spawns). w312_f396_probes pins the digest contract this lane
    # extends; w302_workflow_composed_probes pins the composed path.
    green_check.check_battery(_record, "green-f396",
                              "evals/w312_f396_probes.py", repo=REPO)
    # Merge re-pin 1857->1888 done: w302's pin-taxonomy probe now passes,
    # so no expected-BREAK entry is needed (wave-305 lesson: sweep the
    # transient rather than leaving a stale expectation).
    green_check.check_battery(_record, "green-composed",
                              "evals/w302_workflow_composed_probes.py",
                              repo=REPO)


def run_once(only=None):
    del _results[:]
    for p in PROBES:
        if only and only not in p.__name__:
            continue
        _safe(p.__name__, p)
    if only is None:
        _green_checks()
    return list(_results)


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    first = run_once(only)
    second = run_once(only)
    det = ([v for _, v, _ in first] == [v for _, v, _ in second])
    n_held = sum(1 for _, v, _ in first if v == "HELD")
    n_break = sum(1 for _, v, _ in first if v == "BREAK")
    n_err = sum(1 for _, v, _ in first if v == "ERROR")
    probe_lines.emit(first)
    ok, diags = probe_lines.check_coherence(first, n_break, n_held, n_err)
    if not ok:
        for d in diags:
            print("coherence-WARNING: %s" % d)
    print("----")
    print("w313_plancheck battery: %d BREAK / %d HELD / %d ERROR "
          "(deterministic across 2 runs: %s)"
          % (n_break, n_held, n_err, det))
    if not det:
        print("NON-DETERMINISTIC across runs -- do not trust")
        return 2
    if n_err:
        print("ERRORs present -- battery failed closed")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))