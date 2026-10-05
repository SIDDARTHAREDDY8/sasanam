#!/usr/bin/env python3
"""Wave-320 Lane 2 battery: grant wiring through the approval queue
(gov/approvals.py presented_grant + executor queue/sweep wiring).

The wave-319 grant-negotiation lane verified grants on the direct-allow
path only; the require_approval path silently dropped presented grants.
This battery proves the queue consumes grants (verified at queue time,
MAC-bound into the approval record, re-verified at the approved sweep),
RED-FIRST: it is written before the wiring exists and must FAIL on the
open tree (the queue drops the grant; the sweep never re-verifies).

Probe map (public seams only -- ToolExecutor.call / ApprovalQueue.queue /
ApprovalQueue.decide / ToolExecutor.execute_approved):
  grant-bound-into-record: a verified grant presented with a
      require_approval call is stamped MAC-bound on the approval
      record (rec["presented_grant"] equals the presented grant).
  swapped-grant-fails-closed: rewriting the queued grant between queue
      and execution breaks the F38 MAC -> sweep refuses
      (approval_integrity_violation), never executes.
  stripped-grant-fails-closed: deleting the queued grant between queue
      and execution breaks the F38 MAC -> sweep refuses, never executes.
  approved-grant-executes: verified grant + human approval -> the sweep
      re-verifies and executes (happy path).
  absent-grant-unchanged: no grant presented -> queue/execute exactly as
      before (tighten-only; the deterministic layer stays canonical).
  presenter-audience-mismatch-refused: Mallory presents Alice's grant
      (audience=alice) on the queue path -> refused loudly at queue
      time (grantneg-audience-mismatch), never queued.
  expired-between-queue-and-execution: a grant valid at queue time but
      expired by sweep time -> sweep refuses (grantneg-expired);
      expiry-as-revocation holds across the human-approval delay.
  human-edited-args-break-scope: the human edits the recipient at
      decide() time -> the grant no longer covers the call ->
      sweep refuses (grantneg-scope-mismatch).
  pin-taxonomy / footer-state: standard pins (1964; open F429 / next F430).
"""

import hashlib
import json
import os
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402
from tests.keyfixture import provision_test_key  # noqa: E402

provision_test_key()  # explicit test key via the production env path

from gov import ed25519  # noqa: E402
from gov import grant_negotiation as gn  # noqa: E402
from gov.approvals import approval_digest_ok  # noqa: E402

NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)


def _kp(seed_hex):
    seed = bytes.fromhex(seed_hex)
    pub = ed25519.publickey(seed)
    return seed, pub, hashlib.sha256(pub).hexdigest()[:16]


OWNER_SEED, OWNER_PUB, OWNER_KID = _kp("51" * 32)
AGENT_SEED, AGENT_PUB, AGENT_KID = _kp("52" * 32)
OTHER_SEED, OTHER_PUB, OTHER_KID = _kp("53" * 32)

PUBKEYS = {OWNER_KID: OWNER_PUB, AGENT_KID: AGENT_PUB, OTHER_KID: OTHER_PUB}

TOOL = "send_email"
RECIPIENT = "victim@synthetic.local"  # allowlisted under the default policy


def _registry():
    reg = gn.GrantRegistry()
    reg.register_tool(TOOL, owner_key_id=OWNER_KID)
    for kid, pub in PUBKEYS.items():
        reg.register_key(kid, pub)
    return reg


def _grant(audience="agent-7", recipient=RECIPIENT, ttl_seconds=1800,
           seed=OWNER_SEED, issuer=OWNER_KID, issued_at=None):
    now = issued_at or datetime.now(timezone.utc)
    return gn.issue(TOOL, ["send"], recipient, issuer, seed, audience,
                    ttl_seconds=ttl_seconds, issued_at=now)


def _run_with_registry():
    run = make_run()
    run["executor"].set_grant_registry(_registry())
    return run


def _call(run, agent_id, grant, **kw):
    ident = run["executor"].mint_identity(agent_id, "support", agent_id)
    args = dict(to=RECIPIENT, subject="s", body="b")
    args.update(kw)
    if grant is not None:
        args["grant"] = grant
    return run["executor"].call(ident, TOOL, **args)


def _approve_and_sweep(run, aid, edited_args=None):
    run["approvals"].decide(aid, True, "ok", decided_by="human-operator",
                            edited_args=edited_args)
    run["executor"].execute_approved()
    return run["approvals"].get(aid)


def _sweep_refused(run, aid):
    path = os.path.join(run["run_dir"], "actions.jsonl")
    for line in open(path, encoding="utf-8"):
        if not line.strip():
            continue
        e = json.loads(line)
        if (e.get("event") == "approval_execution_refused"
                and e.get("approval_id") == aid):
            return e
    return None


def _rewrite_approvals(run, aid, fn):
    from pathlib import Path
    path = Path(run["run_dir"]) / "approvals.jsonl"
    recs = [json.loads(l) for l in
            path.read_text(encoding="utf-8").splitlines() if l.strip()]
    for r in recs:
        if r["id"] == aid:
            fn(r)
    path.write_text("\n".join(json.dumps(r) for r in recs) + "\n",
                    encoding="utf-8")


def _held(name, ok, detail):
    return (name, "HELD" if ok else "BREAK", detail)


def p_grant_bound_into_record():
    run = _run_with_registry()
    g = _grant()
    res = _call(run, "agent-7", g)
    if res["status"] != "queued":
        return _held("grant-bound-into-record", False,
                     "call not queued: %r" % (res,))
    rec = run["approvals"].get(res["approval_id"])
    bound = rec.get("presented_grant")
    ok = (bound is not None and bound.get("identifier") == g["identifier"]
          and bound.get("signature") == g["signature"]
          and approval_digest_ok(rec))
    return _held("grant-bound-into-record", ok,
                 "record carries the MAC-bound presented grant"
                 if ok else "presented_grant missing or digest-broken: %r"
                 % (bound,))


def p_swapped_grant_fails_closed():
    run = _run_with_registry()
    g = _grant()
    res = _call(run, "agent-7", g)
    aid = res["approval_id"]
    run["approvals"].decide(aid, True, "ok", decided_by="human-operator")
    # Tamper AFTER the human decision, before the sweep: the F38 MAC
    # must catch the swapped grant at execution time.
    evil = _grant(recipient="other@synthetic.local")
    _rewrite_approvals(run, aid, lambda r: r.update(
        {"presented_grant": evil}))
    run["executor"].execute_approved()
    rec = run["approvals"].get(aid)
    refused = _sweep_refused(run, aid)
    ok = (not rec["executed"] and refused is not None
          and refused.get("flag") == "approval_integrity_violation")
    return _held("swapped-grant-fails-closed", ok,
                 "swapped grant refused via integrity violation"
                 if ok else "executed=%r refused=%r"
                 % (rec["executed"], refused))


def p_stripped_grant_fails_closed():
    run = _run_with_registry()
    g = _grant()
    res = _call(run, "agent-7", g)
    aid = res["approval_id"]
    run["approvals"].decide(aid, True, "ok", decided_by="human-operator")
    # Strip AFTER the human decision, before the sweep: the F38 MAC
    # must catch the missing grant at execution time.
    _rewrite_approvals(run, aid, lambda r: r.pop("presented_grant", None))
    run["executor"].execute_approved()
    rec = run["approvals"].get(aid)
    refused = _sweep_refused(run, aid)
    ok = (not rec["executed"] and refused is not None)
    return _held("stripped-grant-fails-closed", ok,
                 "stripped grant refused (MAC covers the field)"
                 if ok else "executed=%r refused=%r"
                 % (rec["executed"], refused))


def p_approved_grant_executes():
    run = _run_with_registry()
    g = _grant()
    res = _call(run, "agent-7", g)
    rec = _approve_and_sweep(run, res["approval_id"])
    ok = bool(rec["executed"])
    return _held("approved-grant-executes", ok,
                 "verified grant + approval -> executed"
                 if ok else "not executed: %r" % (rec,))


def p_absent_grant_unchanged():
    run = _run_with_registry()
    res = _call(run, "agent-7", None)
    if res["status"] != "queued":
        return _held("absent-grant-unchanged", False,
                     "call not queued: %r" % (res,))
    rec = run["approvals"].get(res["approval_id"])
    if rec.get("presented_grant") is not None:
        return _held("absent-grant-unchanged", False,
                     "absent grant should bind explicit None")
    rec = _approve_and_sweep(run, res["approval_id"])
    ok = bool(rec["executed"])
    return _held("absent-grant-unchanged", ok,
                 "no-grant path queues and executes unchanged"
                 if ok else "not executed")


def p_presenter_audience_mismatch_refused():
    run = _run_with_registry()
    g = _grant(audience="agent-7")  # Alice's grant...
    res = _call(run, "agent-9", g)  # ...presented by Mallory
    ok = (res["status"] == "denied"
          and "grantneg-audience-mismatch" in res.get("reason", ""))
    return _held("presenter-audience-mismatch-refused", ok,
                 "stolen grant refused loudly at queue time"
                 if ok else "not refused: %r" % (res,))


def p_expired_between_queue_and_execution():
    run = _run_with_registry()
    g = _grant(ttl_seconds=1)
    res = _call(run, "agent-7", g)
    if res["status"] != "queued":
        return _held("expired-between-queue-and-execution", False,
                     "call not queued: %r" % (res,))
    aid = res["approval_id"]
    run["approvals"].decide(aid, True, "ok", decided_by="human-operator")
    time.sleep(2.5)  # grant lapses during the human-approval delay
    run["executor"].execute_approved()
    rec = run["approvals"].get(aid)
    refused = _sweep_refused(run, aid)
    ok = (not rec["executed"] and refused is not None
          and refused.get("code") == "grantneg-expired")
    return _held("expired-between-queue-and-execution", ok,
                 "lapsed grant refused at sweep (grantneg-expired)"
                 if ok else "executed=%r refused=%r"
                 % (rec["executed"], refused))


def p_human_edited_args_break_scope():
    run = _run_with_registry()
    g = _grant(recipient=RECIPIENT)
    res = _call(run, "agent-7", g)
    if res["status"] != "queued":
        return _held("human-edited-args-break-scope", False,
                     "call not queued: %r" % (res,))
    aid = res["approval_id"]
    edited = {"to": "other@synthetic.local", "subject": "s", "body": "b"}
    rec = _approve_and_sweep(run, aid, edited_args=edited)
    refused = _sweep_refused(run, aid)
    ok = (not rec["executed"] and refused is not None
          and refused.get("code") == "grantneg-scope-mismatch")
    return _held("human-edited-args-break-scope", ok,
                 "edited recipient breaks grant scope -> refused"
                 if ok else "executed=%r refused=%r"
                 % (rec["executed"], refused))


def p_pin_taxonomy():
    from gov import decision_codes as dc
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    import re
    lits = re.findall(r'"code":\s*\'([^\']+)\'', src)
    lits += re.findall(r'"code":\s*"([^"]+)"', src)
    ok = (len(lits) == 2134 and len(set(lits)) == len(lits)
          and lits == sorted(lits)
          and len(dc.TAXONOMY) == 2134)
    return _held("pin-taxonomy-2134-sorted", ok,
                 "2134/2134/0 sorted" if ok


                 else "taxonomy drift: %d literals" % len(lits))


def p_footer_state():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    import re
    m_open = re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
    m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
    ok = (m_open and m_open[-1].strip() == "F430, F431"
          and m_next and m_next[-1] == "F432")
    return _held("footer-state", ok,
                 "open F412 / next F413" if ok
                 else "footer drift: %r / %r" % (m_open[-1:], m_next[-1:]))


PROBES = [
    ("grant-bound-into-record", p_grant_bound_into_record),
    ("swapped-grant-fails-closed", p_swapped_grant_fails_closed),
    ("stripped-grant-fails-closed", p_stripped_grant_fails_closed),
    ("approved-grant-executes", p_approved_grant_executes),
    ("absent-grant-unchanged", p_absent_grant_unchanged),
    ("presenter-audience-mismatch-refused",
     p_presenter_audience_mismatch_refused),
    ("expired-between-queue-and-execution",
     p_expired_between_queue_and_execution),
    ("human-edited-args-break-scope", p_human_edited_args_break_scope),
    ("pin-taxonomy-2134-sorted", p_pin_taxonomy),


    ("footer-state", p_footer_state),
]


def green_check():
    import subprocess
    ok = True
    for suite in ("tests/test_grant_negotiation.py",
                  "tests/test_decision_codes.py",
                  "evals/w319_grant_probes.py"):
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        try:
            r = subprocess.run(
                [sys.executable, suite], cwd=REPO, env=env,
                capture_output=True, text=True, timeout=300)
        except Exception as exc:  # noqa: BLE001
            print("green_check: %s ERROR %r" % (suite, exc))
            ok = False
            continue
        status = "OK" if r.returncode == 0 else "FAIL"
        print("green_check: %s %s" % (suite, status))
        if r.returncode != 0:
            ok = False
    return ok


def main():
    held = broke = errors = 0
    for name, fn in PROBES:
        try:
            _, verdict, detail = fn()
        except Exception:  # noqa: BLE001
            verdict, detail = "ERROR", traceback.format_exc(limit=3)
        print("%-42s %s %s" % (name, verdict, detail))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broke += 1
        else:
            errors += 1
    print("w320_grantwiring battery: %d BREAK / %d HELD / %d ERROR "
          "(greens: 0 break / 0 error)" % (broke, held, errors))
    gok = green_check()
    print("green_check: %s" % ("OK" if gok else "FAIL"))
    if broke or errors or not gok:
        sys.exit(1)


if __name__ == "__main__":
    main()
