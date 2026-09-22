"""scenario_smoke: minimal full-loop proof for the realistic harness.

Exercises the complete governed path with REAL gov primitives (no
stubs): identity minting -> policy evaluation -> human approval queue
-> sandboxed execution -> hash-chained audit. Also asserts the run dir
landed inside the runner-provided private TMPDIR subdir (QA item 2).

Contract: run() returns a dict of checks on success, raises on failure.
Deterministic, $0 spend, synthetic data only.
"""

import os

SCENARIO = {
    "id": "smoke-full-loop",
    "title": "Full governed loop smoke: identity, policy, approval, "
             "sandboxed execution, audit",
}


def run():
    from gov.log import verify_chain
    from tests.harness import make_run, plant_file

    checks = {}
    ctx = make_run()
    run_dir = ctx["run_dir"]
    ex = ctx["executor"]
    queue = ctx["approvals"]
    ident = ctx["identities"]["researcher"]

    # (2) Private TMPDIR subdir: the hermetic run dir must live under it,
    # never directly under the bare /tmp/gov-run root.
    tmpdir = os.environ.get("TMPDIR", "")
    checks["run_dir_under_private_tmpdir"] = (
        tmpdir != "" and tmpdir != "/tmp/gov-run"
        and str(run_dir).startswith(tmpdir.rstrip("/") + "/"))
    assert checks["run_dir_under_private_tmpdir"], \
        "run dir %s not under private TMPDIR %r" % (run_dir, tmpdir)

    plant_file(ctx, "notes.txt",
               "Synthetic smoke notes. Nothing real here.\n")

    # identity -> policy -> sandboxed execution (allowed read).
    r = ex.call(ident, "read_file", path="notes.txt")
    checks["read_executed"] = r.get("status") == "executed"
    assert checks["read_executed"], "read_file not executed: %r" % (r,)

    # Outbound send after a read is tainted -> queued for human approval.
    r = ex.call(ident, "send_email", to="team@synthetic.local",
                subject="smoke", body="hello from the smoke scenario")
    checks["send_queued"] = (r.get("status") == "queued"
                             and bool(r.get("approval_id")))
    assert checks["send_queued"], "send_email not queued: %r" % (r,)
    approval_id = r["approval_id"]

    # Human approval -> approved execution (nothing runs unapproved).
    queue.decide(approval_id, True, "smoke scenario approval",
                 decided_by="human-operator")
    executed = ex.execute_approved()
    checks["approved_executed"] = any(
        (a.get("approval_id") == approval_id)
        if isinstance(a, dict) else False
        for a in (executed or []))
    if not checks["approved_executed"]:
        # Fall back to the audit log: the executed decision must be there.
        entries = ctx["read_log"]()
        checks["approved_executed"] = any(
            e.get("event") == "tool_call"
            and e.get("tool") == "send_email"
            and e.get("decision") == "approved_executed"
            for e in entries)
    assert checks["approved_executed"], "queued send was never executed"

    # Audit: the hash chain verifies end to end.
    ok, _broken, _n = verify_chain(run_dir / "actions.jsonl")
    checks["audit_chain_ok"] = bool(ok)
    assert checks["audit_chain_ok"], "audit chain failed to verify"

    return {"scenario": SCENARIO["id"], "checks": checks}
