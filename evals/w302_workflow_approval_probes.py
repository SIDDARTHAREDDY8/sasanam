"""Wave-302 lane 6 battery: approval-gated workflow steps.

Base: wave-301 merge 962dbf4bc27c56351aaa52fbe955568aa1151298
(verified via git rev-parse HEAD + ls-remote before work).

New product surface:
  gov/workflow_approval.py -- approval-gated durable steps (ADAPT:
  composes gov/workflow.py + gov/delegation_approval.py +
  gov/approval_request.py, modifies none). Before a gated step
  executes, a delegated approval is requested binding the step's
  identity digest + input digest + delegation chain digest (digests,
  never raw chains). The step executes ONLY on a valid approval for
  exactly those digests; the approval packet digest is committed into
  the step's checkpoint record (inputs digest) with a
  step_approval_bound notification as the plaintext evidence trail.
  Revocation beats approval; expiry is enforced at execution AND
  resume time ("every resume re-proves its authority").
  2 new workflow-approval-* codes; pin 1812 -> 1814.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ImportError on the new module, and the pin probe sees 1812
literals); on the fixed tree they must HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g302-wa && TMPDIR=/var/tmp/g302-wa \
    ~/workspace/.gov-venv/bin/python evals/w302_workflow_approval_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g302-wa2 \
    ~/workspace/.gov-venv/bin/python evals/w302_workflow_approval_probes.py
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
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 1872  # Wave-301 merge pin 1812; wave-302 lane 6: pin 1812 -> 1814 (+2 workflow-approval-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

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
    _record("pin-taxonomy", "HELD", "1872/1872/0 sorted")


def _wa():
    """Import the module under test; None on pristine base (BREAK)."""
    try:
        from gov import workflow_approval as wa
        return wa
    except ImportError:
        return None


def _need(pid):
    wa = _wa()
    if wa is None:
        _record(pid, "BREAK", "gov.workflow_approval absent (pristine base)")
        return None
    return wa


def _seed(tag):
    return hashlib.sha256(("w302wa-" + tag).encode()).digest()


AT = 1_700_000_000


def _chain(wa_mod=None):
    """Single-hop delegation chain agent-a -> agent-b with tool.invoke."""
    from gov import delegation as dg
    from gov import ed25519
    sa, sb = _seed("a"), _seed("b")
    pa, pb = ed25519.publickey(sa).hex(), ed25519.publickey(sb).hex()
    cons = {"expires_at": AT + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root = dg.issue(sa, "agent-a", "agent-b", pb, ("tool.invoke",),
                    issued_at=AT, constraints=dict(cons))
    return {"sa": sa, "sb": sb, "pa": pa, "pb": pb,
            "chain": [root], "trust_roots": [pa]}


def _authority(fx, revoker=None):
    # F380 closure re-pin: the workflow store requires a revocation
    # ledger on every authority verification (fail closed when absent).
    # Mint a fresh (empty) revoker when the caller passes none.
    if revoker is None:
        from gov import delegation_revocation as rv
        revoker = rv.DelegationRevoker(fx["sa"], "agent-a")
    return {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": fx["chain"], "trust_roots": fx["trust_roots"],
            "revocation_ledger": revoker}


def _runner(wa, fx, store, revoker=None):
    return wa.ApprovalGatedWorkflow(store, trust_roots=fx["trust_roots"],
                                    revoker=revoker)


def _store():
    from gov import workflow as wf
    return wf.WorkflowStore()


def _pkg(wa, fx, run_id="run1", seq=0, name="step0", inputs=None,
         issued_at=AT, ttl=3600, chain=None, rseed=None, rid="agent-b"):
    from gov import ed25519
    seed = rseed or fx["sb"]
    return wa.request_approval(
        chain=chain or fx["chain"], delegation_right="tool.invoke",
        run_id=run_id, seq=seq, name=name,
        inputs={"x": 1} if inputs is None else inputs,
        requester_agent_id=rid, requester_principal="principal-" + rid,
        requester_pubkey_hex=ed25519.publickey(seed).hex(),
        requester_seed=seed, approver_schema=[], ttl_seconds=ttl,
        issued_at=issued_at)


def _expect_code(pid, fn, want):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == want:
            return _record(pid, "HELD", "refused coded %s" % (code,))
        return _record(pid, "BREAK",
                       "wrong code: got %r want %r (%r)" % (code, want, e))
    return _record(pid, "BREAK", "no refusal (wanted %s)" % (want,))


def p_importable():
    if _wa() is None:
        _record("importable", "BREAK", "gov.workflow_approval absent")
    else:
        _record("importable", "HELD", "module importable")


def p_happy_path():
    wa = _need("gated-happy-path")
    if wa is None:
        return
    fx = _chain()
    store = _store()
    auth = _authority(fx)
    store.start_run("wf", run_id="run1", authority=auth, at=AT)
    pkg = _pkg(wa, fx)
    r = _runner(wa, fx, store)
    out = r.run_gated_step("run1", 0, "step0", lambda i: {"y": i["x"] + 1},
                           {"x": 1}, approval_package=pkg,
                           authority=auth, at=AT)
    if out["outputs"] != {"y": 2} or out["replayed"]:
        return _record("gated-happy-path", "BREAK",
                       "bad execution result: %r" % (out,))
    # Replay with the same approval: outputs returned, fn not called.
    calls = []
    out2 = r.run_gated_step("run1", 0, "step0",
                            lambda i: calls.append(1) or {"y": 999},
                            {"x": 1}, approval_package=pkg,
                            authority=auth, at=AT + 10)
    if out2["outputs"] != {"y": 2} or not out2["replayed"] or calls:
        return _record("gated-happy-path", "BREAK",
                       "bad replay: %r calls=%r" % (out2, calls))
    # The step's checkpoint record commits the approval digest.
    step = store.get_step("run1", 0)
    aug = dict({"x": 1})
    aug["_gated_step"] = {"step_digest": out["step_digest"],
                          "approval_digest": out["approval_digest"]}
    want = hashlib.sha256(json.dumps(
        aug, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if step["inputs_digest"] != want:
        return _record("gated-happy-path", "BREAK",
                       "inputs_digest does not commit the approval digest")
    _record("gated-happy-path", "HELD",
            "executed + replayed; approval digest in checkpoint record")


def p_different_digests():
    wa = _need("approval-for-different-digests")
    if wa is None:
        return
    fx = _chain()
    store = _store()
    auth = _authority(fx)
    store.start_run("wf", run_id="run1", authority=auth, at=AT)
    pkg = _pkg(wa, fx, inputs={"x": 1})
    r = _runner(wa, fx, store)
    _expect_code(
        "approval-for-different-digests",
        lambda: r.run_gated_step("run1", 0, "step0", lambda i: {"y": 1},
                                 {"x": 2}, approval_package=pkg,
                                 authority=auth, at=AT),
        "workflow-approval-digest-mismatch")


def p_cross_step_replay():
    wa = _need("approval-replay-across-steps")
    if wa is None:
        return
    fx = _chain()
    store = _store()
    auth = _authority(fx)
    store.start_run("wf", run_id="run1", authority=auth, at=AT)
    pkg = _pkg(wa, fx, seq=0)
    r = _runner(wa, fx, store)
    _expect_code(
        "approval-replay-across-steps",
        lambda: r.run_gated_step("run1", 1, "step1", lambda i: {"y": 1},
                                 {"x": 1}, approval_package=pkg,
                                 authority=auth, at=AT),
        "workflow-approval-digest-mismatch")


def p_revoked_after_approval():
    wa = _need("revoked-after-approval")
    if wa is None:
        return
    from gov import delegation_revocation as rv
    fx = _chain()
    store = _store()
    auth = _authority(fx)
    store.start_run("wf", run_id="run1", authority=auth, at=AT)
    pkg = _pkg(wa, fx)
    revoker = rv.DelegationRevoker(fx["sa"], "agent-a")
    revoker.revoke(fx["chain"][0]["receipt_id"], AT + 5)
    r = _runner(wa, fx, store, revoker=revoker)
    _expect_code(
        "revoked-after-approval",
        lambda: r.run_gated_step("run1", 0, "step0", lambda i: {"y": 1},
                                 {"x": 1}, approval_package=pkg,
                                 authority=auth, at=AT + 10),
        "delegation-revoked")


def p_expired_approval():
    wa = _need("expired-approval")
    if wa is None:
        return
    fx = _chain()
    store = _store()
    auth = _authority(fx)
    store.start_run("wf", run_id="run1", authority=auth, at=AT)
    pkg = _pkg(wa, fx, issued_at=AT - 3600, ttl=60)
    r = _runner(wa, fx, store)
    _expect_code(
        "expired-approval",
        lambda: r.run_gated_step("run1", 0, "step0", lambda i: {"y": 1},
                                 {"x": 1}, approval_package=pkg,
                                 authority=auth, at=AT),
        "approval-request-expired")


def p_non_gated_approval():
    wa = _need("non-gated-approval")
    if wa is None:
        return
    from gov import delegation_approval as da
    from gov import ed25519
    fx = _chain()
    store = _store()
    auth = _authority(fx)
    store.start_run("wf", run_id="run1", authority=auth, at=AT)
    pkg = da.issue_delegated_request(
        chain=fx["chain"], delegation_right="tool.invoke",
        action={"tool": "shell", "args": {"cmd": "ls"}},
        requester_agent_id="agent-b", requester_principal="principal-agent-b",
        requester_pubkey_hex=fx["pb"], requester_seed=fx["sb"],
        approver_schema=[], ttl_seconds=3600, issued_at=AT)
    r = _runner(wa, fx, store)
    _expect_code(
        "non-gated-approval",
        lambda: r.run_gated_step("run1", 0, "step0", lambda i: {"y": 1},
                                 {"x": 1}, approval_package=pkg,
                                 authority=auth, at=AT),
        "workflow-approval-digest-mismatch")


def p_authority_chain_mismatch():
    wa = _need("authority-chain-mismatch")
    if wa is None:
        return
    from gov import delegation as dg
    from gov import ed25519
    fx = _chain()
    # A genuinely different chain for the same actor: wider rights make a
    # different receipt_id (issued_at is not receipt-id-committed), so the
    # chain digest differs from what the approval bound.
    cons = {"expires_at": AT + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root2 = dg.issue(fx["sa"], "agent-a", "agent-b", fx["pb"],
                     ("tool.invoke", "memory.read"), issued_at=AT,
                     constraints=dict(cons))
    store = _store()
    # F380 closure re-pin: the workflow store requires a revocation
    # ledger on every verification -- the different chain still carries
    # a fresh (empty) revoker so the probe reaches the chain-mismatch
    # check.
    from gov import delegation_revocation as rv
    auth2 = {"actor_id": "agent-b", "action": "tool.invoke",
             "chain": [root2], "trust_roots": fx["trust_roots"],
             "revocation_ledger": rv.DelegationRevoker(fx["sa"],
                                                       "agent-a")}
    store.start_run("wf", run_id="run1", authority=auth2, at=AT)
    pkg = _pkg(wa, fx)  # approved under chain 1
    r = _runner(wa, fx, store)
    _expect_code(
        "authority-chain-mismatch",
        lambda: r.run_gated_step("run1", 0, "step0", lambda i: {"y": 1},
                                 {"x": 1}, approval_package=pkg,
                                 authority=auth2, at=AT),
        "workflow-approval-digest-mismatch")


def p_resume_reproves():
    wa = _need("resume-reproves")
    if wa is None:
        return
    fx = _chain()
    store = _store()
    auth = _authority(fx)
    store.start_run("wf", run_id="run1", authority=auth, at=AT)
    pkg = _pkg(wa, fx, ttl=3600)
    r = _runner(wa, fx, store)
    r.run_gated_step("run1", 0, "step0", lambda i: {"y": i["x"] + 1},
                     {"x": 1}, approval_package=pkg, authority=auth, at=AT)
    # Resume inside the approval's time box: re-verified, replays.
    r2 = wa.ApprovalGatedWorkflow(store=store, trust_roots=fx["trust_roots"])
    out = r2.run_gated_step("run1", 0, "step0", lambda i: {"y": 999},
                            {"x": 1}, approval_package=pkg,
                            authority=auth, at=AT + 100)
    if out["outputs"] != {"y": 2} or not out["replayed"]:
        return _record("resume-reproves", "BREAK",
                       "resume inside time box did not replay: %r" % (out,))
    # Resume after the approval expired: refuses, never executes.
    _expect_code(
        "resume-reproves",
        lambda: r2.run_gated_step("run1", 0, "step0", lambda i: {"y": 1},
                                  {"x": 1}, approval_package=pkg,
                                  authority=auth, at=AT + 4000),
        "approval-request-expired")


def p_evidence_trail():
    wa = _need("evidence-trail")
    if wa is None:
        return
    import tempfile
    from gov import workflow as wf
    fx = _chain()
    tmp = tempfile.mkdtemp(prefix="g302-evidence-")
    store = wf.WorkflowStore(path=os.path.join(tmp, "store.jsonl"))
    auth = _authority(fx)
    store.start_run("wf", run_id="run1", authority=auth, at=AT)
    pkg = _pkg(wa, fx)
    r = wa.ApprovalGatedWorkflow(store=store, trust_roots=fx["trust_roots"])
    out = r.run_gated_step("run1", 0, "step0", lambda i: {"y": 1},
                           {"x": 1}, approval_package=pkg,
                           authority=auth, at=AT)
    found = []
    with open(os.path.join(tmp, "store.jsonl"), encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            if rec.get("type") == "notification" \
                    and rec.get("event") == "step_approval_bound":
                found.append(rec)
    if not found:
        return _record("evidence-trail", "BREAK",
                       "no step_approval_bound notification in the store")
    note = found[0]
    if note["payload"]["approval_digest"] != out["approval_digest"]:
        return _record("evidence-trail", "BREAK",
                       "notification approval digest does not match")
    if note["run_id"] != "run1" or note["payload"]["seq"] != 0:
        return _record("evidence-trail", "BREAK",
                       "notification not linked to the step")
    _record("evidence-trail", "HELD",
            "step_approval_bound notification links step to approval digest")


def p_codes_present():
    lits = _literals()
    missing = [c for c in ("workflow-approval-digest-mismatch",
                           "workflow-approval-binding-invalid")
               if c not in lits]
    if missing:
        _record("codes-present", "BREAK", "missing codes: %r" % (missing,))
    else:
        _record("codes-present", "HELD", "both workflow-approval-* codes")


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
    _safe("importable", p_importable)
    for pid, fn in [
        ("gated-happy-path", p_happy_path),
        ("approval-for-different-digests", p_different_digests),
        ("approval-replay-across-steps", p_cross_step_replay),
        ("revoked-after-approval", p_revoked_after_approval),
        ("expired-approval", p_expired_approval),
        ("non-gated-approval", p_non_gated_approval),
        ("authority-chain-mismatch", p_authority_chain_mismatch),
        ("resume-reproves", p_resume_reproves),
        ("evidence-trail", p_evidence_trail),
        ("codes-present", p_codes_present),
    ]:
        _safe(pid, fn)
    _green_check(os.path.join(REPO, "evals", "w301_workflow_probes.py"),
                 "w301-workflow", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals",
                              "w300_delegation_approval_probes.py"),
                 "w300-delegation-approval", tolerate=("pin-taxonomy",))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note.split("\n")[0]))
    print("== %d BREAK / %d HELD / %d ERROR ==" % (n_break, n_held, n_err))
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
