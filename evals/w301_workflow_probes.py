"""Wave-301 lane 3 battery: durable workflow step records.

Base: wave-300 merge 94bc43deb58ba78163f3ee61a59c2240cdd008f3
(verified via git rev-parse HEAD + ls-remote before work).

New product surface:
  gov/workflow.py -- durable execution as a library (STEAL from
  dbos-inc/dbos-transact-py): checkpoint every step (append-only JSONL
  step records with content digests), resume from the last completed
  step, exactly-once via idempotency keys (run-level and step-level),
  workflow state as queryable rows, durable sleep and durable
  notifications. Every resume re-proves authority: the delegation chain
  is re-verified AND re-checked against the revocation ledger; a
  revoked chain refuses workflow-authority-revoked.
  3 new workflow-* codes; pin 1802 -> 1812.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ImportError on the new module, and the pin probe sees 1812
literals); on the fixed tree they must HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g301-wf && TMPDIR=/var/tmp/g301-wf \
    ~/workspace/.gov-venv/bin/python evals/w301_workflow_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g301-wf2 \
    ~/workspace/.gov-venv/bin/python evals/w301_workflow_probes.py
"""

import hashlib
import json
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

TAXONOMY_PIN = 2131  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).


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
    """Import gov.workflow + build a delegation authority. Raises
    ImportError on the pristine base (the red-first BREAK)."""
    import gov.workflow as wf  # noqa: F401 -- ImportError is the signal
    from gov import delegation as dg
    from gov import delegation_revocation as drv
    from gov import ed25519
    seed_a = hashlib.sha256(b"w301wf-a").digest()
    pub_a = ed25519.publickey(seed_a).hex()
    pub_b = ed25519.publickey(hashlib.sha256(b"w301wf-b").digest()).hex()
    at = 1_700_000_000
    cons = {"expires_at": at + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root = dg.issue(seed_a, "agent-a", "agent-b", pub_b,
                    ("tool.invoke",), issued_at=at, constraints=cons)
    ledger = drv.DelegationRevoker(seed_a, "agent-a")
    auth = {"actor_id": "agent-b", "action": "tool.invoke", "chain": [root],
            "trust_roots": [pub_a], "revocation_ledger": ledger}
    return wf, at, auth, ledger, root


def _break_absent(pid, note="gov.workflow absent"):
    _record(pid, "BREAK", note)


def p_crash_resume():
    try:
        wf, at, auth, _, _ = _scaffold()
    except ImportError:
        return _break_absent("wf-crash-resume")
    tmp = tempfile.mkdtemp(prefix="wf-crash-")
    path = os.path.join(tmp, "wf.jsonl")
    store = wf.WorkflowStore(path=path)
    store.start_run("etl", run_id="r1", authority=auth, at=at)
    calls = []
    for seq in range(3):
        store.run_step("r1", seq, "s%d" % seq,
                       lambda i, s=seq: calls.append(s) or s,
                       inputs={"n": seq}, authority=auth, at=at)
    del store  # process death
    store2 = wf.WorkflowStore(path=path)
    out = store2.replay("r1", [
        {"seq": s, "name": "s%d" % s,
         "fn": lambda i, s=s: calls.append("re-%d" % s) or s,
         "inputs": {"n": s}} for s in range(4)
    ], authority=auth, at=at)
    replayed = [r for _, _, _, r, _ in out]
    if replayed != [True, True, True, False]:
        return _record("wf-crash-resume", "BREAK",
                       "replay flags wrong: %r" % (replayed,))
    if calls != [0, 1, 2, "re-3"]:
        return _record("wf-crash-resume", "BREAK",
                       "steps re-executed after crash: %r" % (calls,))
    _record("wf-crash-resume", "HELD",
            "crash resume: 3 replayed, step 4 executed once")


def p_revoked_resume():
    try:
        wf, at, auth, ledger, root = _scaffold()
    except ImportError:
        return _break_absent("wf-revoked-resume")
    tmp = tempfile.mkdtemp(prefix="wf-revoke-")
    path = os.path.join(tmp, "wf.jsonl")
    store = wf.WorkflowStore(path=path)
    store.start_run("etl", run_id="r1", authority=auth, at=at)
    store.run_step("r1", 0, "extract", lambda i: {"rows": 1},
                   inputs={}, authority=auth, at=at)
    ledger.revoke(root["receipt_id"], at + 10)
    del store
    store2 = wf.WorkflowStore(path=path)
    try:
        store2.run_step("r1", 1, "load", lambda i: {"ok": True},
                        inputs={}, authority=auth, at=at + 20)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-authority-revoked":
            return _record("wf-revoked-resume", "HELD",
                           "revoked chain on resume refused coded")
        return _record("wf-revoked-resume", "BREAK",
                       "wrong refusal code: %r" % (getattr(e, "code", None),))
    _record("wf-revoked-resume", "BREAK",
            "resumed step under revoked chain executed")


def p_idempotency():
    try:
        wf, at, auth, _, _ = _scaffold()
    except ImportError:
        return _break_absent("wf-idempotency")
    store = wf.WorkflowStore()
    r1 = store.start_run("etl", run_id="a", idempotency_key="evt-9",
                         authority=auth, at=at)
    r2 = store.start_run("etl", run_id="b", idempotency_key="evt-9",
                         authority=auth, at=at)
    if r1["run_id"] != r2["run_id"] or len(store.list_runs()) != 1:
        return _record("wf-idempotency", "BREAK",
                       "duplicate idempotency key started a second run")
    calls = []
    store.run_step("a", 0, "extract",
                   lambda i: calls.append(1) or {"rows": 3},
                   inputs={}, idempotency_key="sk",
                   authority=auth, at=at)
    # F383 closure (wave-303): the key path applies drift checks, so a
    # replay across seq slots requires the SAME step name and inputs;
    # a different name refuses workflow-step-unauthorized (see
    # evals/w303_f382f383_probes.py).
    out, replayed = store.run_step(
        "a", 5, "extract",
        lambda i: calls.append(1) or {"rows": 999},
        inputs={}, idempotency_key="sk", authority=auth, at=at)
    if out != {"rows": 3} or not replayed or len(calls) != 1:
        return _record("wf-idempotency", "BREAK",
                       "step idempotency key re-executed: %r" % (calls,))
    _record("wf-idempotency", "HELD",
            "run+step idempotency keys replay exactly-once")


def p_forged_checkpoint():
    try:
        wf, at, auth, _, _ = _scaffold()
    except ImportError:
        return _break_absent("wf-forged-checkpoint")
    tmp = tempfile.mkdtemp(prefix="wf-forge-")
    path = os.path.join(tmp, "wf.jsonl")
    store = wf.WorkflowStore(path=path)
    store.start_run("etl", run_id="r1", authority=auth, at=at)
    store.run_step("r1", 0, "extract", lambda i: {"rows": 1},
                   inputs={}, authority=auth, at=at)
    del store
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    rec = json.loads(lines[-1])
    rec["outputs"] = {"rows": 999999}
    lines[-1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    try:
        wf.WorkflowStore(path=path)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-checkpoint-tampered":
            return _record("wf-forged-checkpoint", "HELD",
                           "forged checkpoint refused coded on load")
        return _record("wf-forged-checkpoint", "BREAK",
                       "wrong refusal code: %r" % (getattr(e, "code", None),))
    _record("wf-forged-checkpoint", "BREAK",
            "tampered checkpoint loaded without refusal")


def p_no_authority():
    try:
        wf, at, auth, _, _ = _scaffold()
    except ImportError:
        return _break_absent("wf-no-authority")
    store = wf.WorkflowStore()
    try:
        store.start_run("etl", run_id="r1", authority=None, at=at)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-step-unauthorized":
            return _record("wf-no-authority", "HELD",
                           "authority-less start refused coded")
        return _record("wf-no-authority", "BREAK",
                       "wrong refusal code: %r" % (getattr(e, "code", None),))
    _record("wf-no-authority", "BREAK", "authority-less run started")


def p_actor_hijack():
    try:
        wf, at, auth, _, _ = _scaffold()
        from gov import delegation as dg
        from gov import delegation_revocation as drv
        from gov import ed25519
    except ImportError:
        return _break_absent("wf-actor-hijack")
    seed_c = hashlib.sha256(b"w301wf-c").digest()
    pub_c = ed25519.publickey(seed_c).hex()
    store = wf.WorkflowStore()
    store.start_run("etl", run_id="r1", authority=auth, at=at)
    evil_auth = dict(auth)
    evil_auth["actor_id"] = "agent-evil"
    try:
        store.run_step("r1", 0, "extract", lambda i: {"ok": True},
                       inputs={}, authority=evil_auth, at=at)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-step-unauthorized":
            return _record("wf-actor-hijack", "HELD",
                           "cross-actor resume refused coded")
        return _record("wf-actor-hijack", "BREAK",
                       "wrong refusal code: %r" % (getattr(e, "code", None),))
    _record("wf-actor-hijack", "BREAK", "foreign actor executed the step")


def p_sleep_durable():
    try:
        wf, at, auth, _, _ = _scaffold()
    except ImportError:
        return _break_absent("wf-sleep-durable")
    store = wf.WorkflowStore()
    store.start_run("etl", run_id="r1", authority=auth, at=at)
    awake, replayed = store.sleep_step("r1", 0, "wait", wake_at=at + 100,
                                       authority=auth, at=at, now=at)
    if awake or replayed:
        return _record("wf-sleep-durable", "BREAK",
                       "sleep completed before wake_at")
    awake2, _ = store.sleep_step("r1", 0, "wait", wake_at=at + 100,
                                 authority=auth, at=at + 100,
                                 now=at + 100)
    if not awake2:
        return _record("wf-sleep-durable", "BREAK",
                       "sleep did not complete at wake_at")
    _record("wf-sleep-durable", "HELD", "durable sleep pending->awake")


def p_notify_recv():
    try:
        wf, at, auth, _, _ = _scaffold()
    except ImportError:
        return _break_absent("wf-notify-recv")
    store = wf.WorkflowStore()
    store.start_run("etl", run_id="r1", authority=auth, at=at)
    payload, _ = store.recv_step("r1", 0, "wait-ev", "ev", authority=auth,
                                 at=at, now=at)
    if payload is not None:
        return _record("wf-notify-recv", "BREAK",
                       "recv returned payload with no notification")
    store.notify("r1", "ev", {"n": 1}, authority=auth, at=at + 1)
    store.notify("r1", "ev", {"n": 2}, authority=auth, at=at + 2)
    p1, _ = store.recv_step("r1", 0, "w1", "ev", authority=auth,
                            at=at + 3, now=at + 3)
    p2, r2 = store.recv_step("r1", 1, "w2", "ev", authority=auth,
                             at=at + 3, now=at + 3)
    if p1 != {"n": 1} or p2 != {"n": 2} or r2:
        return _record("wf-notify-recv", "BREAK",
                       "notification consumption wrong: %r %r" % (p1, p2))
    p1b, r1b = store.recv_step("r1", 0, "w1", "ev", authority=auth,
                               at=at + 3, now=at + 3)
    if p1b != {"n": 1} or not r1b:
        return _record("wf-notify-recv", "BREAK", "recv not replayable")
    _record("wf-notify-recv", "HELD",
            "durable notifications consumed exactly-once, replayable")


def p_definition_drift():
    try:
        wf, at, auth, _, _ = _scaffold()
    except ImportError:
        return _break_absent("wf-definition-drift")
    store = wf.WorkflowStore()
    store.start_run("etl", run_id="r1", authority=auth, at=at)
    store.run_step("r1", 0, "extract", lambda i: {"rows": 3},
                   inputs={"src": "db"}, authority=auth, at=at)
    try:
        store.run_step("r1", 0, "extract", lambda i: {"rows": 3},
                       inputs={"src": "other"}, authority=auth, at=at)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-step-unauthorized":
            return _record("wf-definition-drift", "HELD",
                           "definition drift refused coded")
        return _record("wf-definition-drift", "BREAK",
                       "wrong refusal code: %r" % (getattr(e, "code", None),))
    _record("wf-definition-drift", "BREAK",
            "checkpointed evidence overwritten")


def p_ed25519_contract():
    try:
        from gov import ed25519
    except ImportError:
        return _break_absent("wf-ed25519")
    seed = hashlib.sha256(b"w301wf-ed").digest()
    pub = ed25519.publickey(seed)
    msg = b"workflow-authority"
    sig = ed25519.sign(seed, msg)
    if ed25519.verify(pub, msg, sig) is not True:
        return _record("wf-ed25519", "BREAK", "good signature not True")
    bad = bytearray(sig)
    bad[0] ^= 1
    if ed25519.verify(pub, msg, bytes(bad)) is not False:
        return _record("wf-ed25519", "BREAK", "forged signature not False")
    _record("wf-ed25519", "HELD", "ed25519 True/False contract holds")


def p_codes_present():
    lits = set(_literals())
    want = {"workflow-authority-revoked", "workflow-checkpoint-tampered",
            "workflow-step-unauthorized"}
    missing = want - lits
    if missing:
        return _record("wf-codes-present", "BREAK",
                       "new codes missing: %r" % (missing,))
    _record("wf-codes-present", "HELD", "3 workflow-* codes present")


# ------------------------------------------------------------------
# Depth-1 green checks + runner
# ------------------------------------------------------------------

def _green_check(path, name, tolerate=()):
    if SKIP_GREEN:
        _record("green-%s" % name, "HELD", "skipped via GOV_SKIP_GREEN=1")
        return
    if not os.path.exists(path):
        _record("green-%s" % name, "HELD", "battery absent at base")
        return
    tmp = tempfile.mkdtemp(prefix="g301-green-")
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
        ("wf-crash-resume", p_crash_resume),
        ("wf-revoked-resume", p_revoked_resume),
        ("wf-idempotency", p_idempotency),
        ("wf-forged-checkpoint", p_forged_checkpoint),
        ("wf-no-authority", p_no_authority),
        ("wf-actor-hijack", p_actor_hijack),
        ("wf-sleep-durable", p_sleep_durable),
        ("wf-notify-recv", p_notify_recv),
        ("wf-definition-drift", p_definition_drift),
        ("wf-ed25519", p_ed25519_contract),
        ("wf-codes-present", p_codes_present),
    ]:
        _safe(pid, fn)
    _green_check(os.path.join(REPO, "evals", "w299_delegation_probes.py"),
                 "w299-delegation", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals", "w300_revoke_lease_probes.py"),
                 "w300-revoke-lease", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals",
                              "w300_delegation_approval_probes.py"),
                 "w300-delegation-approval", tolerate=("pin-taxonomy",))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w301_workflow: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, n_break, n_held, n_err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
