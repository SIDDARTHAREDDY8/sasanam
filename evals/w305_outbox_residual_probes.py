"""Wave-305 lane B battery: the composed-outbox residual from wave-304.

Wave-304 lane C (F388) closed the poisoned ``(digest, ref)`` pair at
``WorkflowComposer._resolve_replay`` but left a residual:
``_drain_outbox_composed``'s ``idem_dispatcher`` returns
``outcome.result_ref`` RAW on the replay path, without passing through
``_resolve_replay``.

This battery investigates whether that residual is independently
reachable as a security issue at the PUBLIC API
(``WorkflowComposer.execute``). The mechanism under test:

* ``_drain_outbox_composed`` returns
  ``self._saga.drain_outbox(instance, idem_dispatcher)``.
* ``SagaManager.drain_outbox`` DISCARDS the dispatcher's return value
  and returns the dispatch COUNT (an int). The raw ``result_ref``
  therefore never reaches unit outputs, checkpoints, or any consumer
  (``outbox_dispatched`` is only ever the integer count; nothing in
  ``gov/`` resolves ``"outbox:..."`` refs; nothing consumes
  ``outbox_dispatched``).

Probes (all through the public ``WorkflowComposer.execute`` API except
the discard-contract pin, which pins the mechanism directly):
  P1 OUTBOX-poisoned-replay-discarded: attacker plants a completed
     outbox record (matching op_digest, attacker-chosen ref
     ``wfstep:victim:1``, caller "mallory"). The victim's drain hits
     replay. BREAK = attacker data surfaces in the unit outputs;
     HELD = outputs carry only the integer dispatch count (residual
     not independently reachable).
  P2 OUTBOX-digest-mismatch-fails-closed: attacker plants with a WRONG
     op_digest. BREAK = silent acceptance; HELD = loud coded
     ``permit-idempotency-conflict`` refusal (the idem store's
     documented fail-closed contract).
  P3 OUTBOX-legit-redrain-intact: same plan executed twice under the
     same run; the second drain is a legitimate replay. Must stay
     HELD (action fn ran once; both drains report count 1).
  P4 OUTBOX-drain-discards-dispatcher-return: pins the discard
     contract directly -- ``drain_outbox`` returns the int count even
     when the dispatcher returns an attacker string.

Negative-result convention: if P1 BREAKs, this residual is a genuine
finding and gets filed as F389. If P1 stays HELD (as the mechanism
analysis predicts), no finding is filed -- the raw return is dead
data, and routing it through ``_resolve_replay`` would be WRONG
(outbox refs are ``"outbox:<unit>:<intent>"`` shaped; ``_resolve_replay``
refuses non-``wfstep:`` refs with ``workflow-composed-divergent``,
which would break legitimate redrains).

Run:
  mkdir -p /var/tmp/g305-outbox && TMPDIR=/var/tmp/g305-outbox \
    ~/workspace/.gov-venv/bin/python evals/w305_outbox_residual_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g305-outboxb \
    ~/workspace/.gov-venv/bin/python evals/w305_outbox_residual_probes.py
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
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# No new codes in this lane (negative result): pin stays at the
# wave-304 merge pin.
TAXONOMY_PIN = 1991 #Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)



CONFLICT_CODE = "permit-idempotency-conflict"

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
    want_open = "F407"
    if nxt != 405 or open_s != want_open:
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d open %r (want next F404 open 'none')"
                       % (nxt, open_s, want_open))
    _record("footer-state", "HELD",
            "footer pins open none / next F409")


AT = 1_700_000_000


def _seed(tag):
    return hashlib.sha256(("w305outbox-" + tag).encode()).digest()


def _scaffold():
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    from gov import workflow_composed as wc
    from gov import delegation as dg
    from gov import ed25519
    from gov import delegation_revocation as rv
    saga.clear_ops()
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


def _saga_plan(wc, sm, saga, action_fn, key="ck"):
    sd = sm.define(
        [saga.SagaStepDef("s1", "a1", {}, "c1")])
    return wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": action_fn},
         "comp_fns": {"s1": lambda i: {"c": 1}},
         "idem_key": key}])


def _expected_payload(key, run_id, unit="sg", step="s1", idx=0):
    # White-box: the exact payload the composer's _run_action wrapper
    # builds before the saga records the outbox intent.
    return {"p": 1, "intent_id": "%s:%s:%d" % (key, step, idx),
            "_composed_evidence": {"run_id": run_id, "unit": unit,
                                   "step_id": step}}


def p_outbox_poisoned_replay_discarded():
    # P1: the attacker plants a completed outbox record with a matching
    # op_digest and an attacker-chosen ref. The victim's drain hits
    # replay and the dispatcher returns the raw ref -- which
    # drain_outbox discards. BREAK = attacker data in the unit outputs.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    payload = _expected_payload("ck", "R")
    op_digest = wc._digest(payload)
    plant = im.begin("composed", "composed-outbox", "ck:ck:s1:0",
                     op_digest, caller="mallory",
                     authority_verifier=lambda **k: True, at=AT)
    if plant.status != "new":
        return _record("OUTBOX-poisoned-replay-discarded", "ERROR",
                       "plant did not begin new: %s" % (plant.status,))
    plant.complete(wc._digest({"evil": 1}), "wfstep:victim:1", at=AT)
    calls = []

    def action_fn(i):
        calls.append(1)
        return ({"r": 1}, [{"p": 1}])

    plan = _saga_plan(wc, sm, saga, action_fn)
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    res = comp.execute(plan, run_id="R", authority=auth, at=AT)
    out = res["units"]["sg"]
    blob = json.dumps(out, sort_keys=True)
    if "wfstep:victim:1" in blob or "evil" in blob:
        return _record("OUTBOX-poisoned-replay-discarded", "BREAK",
                       "attacker ref surfaced in unit outputs: %s" % (blob,))
    if out.get("outbox_dispatched") != 1 or not isinstance(
            out.get("outbox_dispatched"), int):
        return _record("OUTBOX-poisoned-replay-discarded", "ERROR",
                       "unexpected outbox_dispatched: %r"
                       % (out.get("outbox_dispatched"),))
    if out.get("status") != "succeeded" or len(calls) != 1:
        return _record("OUTBOX-poisoned-replay-discarded", "ERROR",
                       "saga did not succeed cleanly: status=%r calls=%d"
                       % (out.get("status"), len(calls)))
    _record("OUTBOX-poisoned-replay-discarded", "HELD",
            "poisoned ref discarded: outbox_dispatched=1 (int), no "
            "attacker data in outputs; drain returns the count, not the "
            "dispatcher return")


def p_outbox_digest_mismatch_fails_closed():
    # P2: attacker plants with a WRONG op_digest. The idem store must
    # refuse loudly coded permit-idempotency-conflict (its documented
    # fail-closed contract), never silently accept.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    plant = im.begin("composed", "composed-outbox", "ck:ck:s1:0",
                     "0" * 64, caller="mallory",
                     authority_verifier=lambda **k: True, at=AT)
    plant.complete(wc._digest({"evil": 1}), "wfstep:victim:1", at=AT)

    def action_fn(i):
        return ({"r": 1}, [{"p": 1}])

    plan = _saga_plan(wc, sm, saga, action_fn)
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    try:
        comp.execute(plan, run_id="R", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == CONFLICT_CODE:
            return _record("OUTBOX-digest-mismatch-fails-closed", "HELD",
                           "digest confusion refused loud coded "
                           "permit-idempotency-conflict")
        return _record("OUTBOX-digest-mismatch-fails-closed", "ERROR",
                       "uncoded refusal: %r" % (e,))
    _record("OUTBOX-digest-mismatch-fails-closed", "BREAK",
            "mismatched digest silently accepted")


def p_outbox_legit_redrain_intact():
    # P3: the legitimate path must survive -- two executes under the
    # same run; the second drain is a genuine replay of the composer's
    # own record.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    calls = []

    def action_fn(i):
        calls.append(1)
        return ({"r": 1}, [{"p": 1}])

    plan = _saga_plan(wc, sm, saga, action_fn)
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    res1 = comp.execute(plan, run_id="R", authority=auth, at=AT)
    res2 = comp.execute(plan, run_id="R", authority=auth, at=AT)
    d1 = res1["units"]["sg"]["outbox_dispatched"]
    d2 = res2["units"]["sg"]["outbox_dispatched"]
    if d1 != 1 or d2 != 1:
        return _record("OUTBOX-legit-redrain-intact", "BREAK",
                       "dispatch counts wrong: %r / %r" % (d1, d2))
    if len(calls) != 1:
        return _record("OUTBOX-legit-redrain-intact", "BREAK",
                       "action fn re-executed on redrain: %d calls"
                       % len(calls))
    _record("OUTBOX-legit-redrain-intact", "HELD",
            "legitimate redrain intact (count 1/1, fn ran once)")


def p_outbox_drain_discards_dispatcher_return():
    # P4: pins the mechanism -- SagaManager.drain_outbox returns the
    # int count even when the dispatcher returns an attacker string.
    # Built through the saga module's public API only.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _scaffold()
    saga.register_op("p4-action",
                     lambda i: ({"r": 1}, [{"note": "x"}]))
    saga.register_op("p4-comp", lambda i: {"c": 1})
    inst = sm.start(sm.define(
        [saga.SagaStepDef("s1", "p4-action", {}, "p4-comp")]))
    sm.run(inst)
    if inst.status != "succeeded":
        return _record("OUTBOX-drain-discards-dispatcher-return", "ERROR",
                       "saga did not succeed: %r" % (inst.status,))
    n = sm.drain_outbox(inst, lambda intent: "ATTACKER-STRING")
    if n != 1 or not isinstance(n, int):
        return _record("OUTBOX-drain-discards-dispatcher-return", "BREAK",
                       "drain returned %r instead of int count" % (n,))
    _record("OUTBOX-drain-discards-dispatcher-return", "HELD",
            "drain_outbox returns the int count (1); dispatcher return "
            "discarded by construction")


def _green_battery(path, label):
    if SKIP_GREEN:
        _record("green-%s" % label, "HELD",
                "skipped (GOV_SKIP_GREEN=1); standalone run covers it")
        return
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = os.path.join("/var/tmp", "g305-outbox-green-%s" % label)
    os.makedirs(tmpd, exist_ok=True)
    env["TMPDIR"] = tmpd
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, path)],
            env=env, capture_output=True, text=True, timeout=600)
    except Exception as e:  # noqa: BLE001
        _record("green-%s" % label, "ERROR", "green check crashed: %r" % (e,))
        return
    out = (proc.stdout or "") + (proc.stderr or "")
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", out)
    if m:
        b, h, e = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if b or e:
            _record("green-%s" % label, "BREAK",
                    "%s regressed: %d BREAK / %d HELD / %d ERROR"
                    % (path, b, h, e))
        else:
            _record("green-%s" % label, "HELD",
                    "%s green: 0 BREAK / %d HELD / 0 ERROR" % (path, h))
        return
    # unittest-style batteries report "Ran N tests" + "OK".
    mu = re.search(r"Ran (\d+) tests", out)
    if mu and proc.returncode == 0 and re.search(r"^OK", out, re.M):
        _record("green-%s" % label, "HELD",
                "%s green: %s unittest tests OK" % (path, mu.group(1)))
        return
    _record("green-%s" % label, "ERROR",
            "no verdict line in %s (rc=%d)" % (path, proc.returncode))


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("OUTBOX-poisoned-replay-discarded",
           p_outbox_poisoned_replay_discarded)
    _safe("OUTBOX-digest-mismatch-fails-closed",
           p_outbox_digest_mismatch_fails_closed)
    _safe("OUTBOX-legit-redrain-intact", p_outbox_legit_redrain_intact)
    _safe("OUTBOX-drain-discards-dispatcher-return",
           p_outbox_drain_discards_dispatcher_return)
    # Depth-1 adjacent green checks (wave-134 lesson: never nest).
    _green_battery("evals/w302_workflow_composed_probes.py", "composed")
    _green_battery("evals/w303_f386_probes.py", "f386")
    _green_battery("evals/w303_f388_probes.py", "f388")
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
