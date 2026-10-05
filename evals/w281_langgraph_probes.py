"""Wave-281 lane 6 battery: durable pending approvals (LangGraph ADAPT).

LangGraph's HITL story is two primitives -- a checkpointer and
``interrupt()``. This lane adapts the DURABILITY half (not the graph
framework):

* park(approval_id, proposal) writes a JSON snapshot to sqlite3 BEFORE
  the executor parks; restart recovery = re-list parked approvals.
* resume(approval_id, decision, edited_args=None) -- the human verdict
  becomes the executor's resume input (the Command(resume=value)
  shape).
* edit-before-approve: the reviewer rewrites tool args; the
  proposal -> edit -> execution diff is chained into the HMAC audit
  log as an approval_args_edited event (the HumanLayer contract
  shape, composed not duplicated).
* Fail-closed: tampered snapshot (digest mismatch) -> refuse-to-resume
  (pending-approval-snapshot-tampered); unknown id / already-decided /
  expired / malformed resume value -> pending-approval-resume-refused.
* Queries (list_parked, status) are read-only projections: zero writes.
* Expiry is computed from event timestamps at read time (check_at_use):
  no live timers.

Red-first: every capability probe BREAKs on the base (module absent)
and must HOLD on the implementation.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic (fixed inputs, short
sleeps only for the expiry probe); fresh unique /var/tmp/g281*
TMPDIR (`mkdir -p` first); depth-1 green checks honoring
GOV_SKIP_GREEN=1; no in-repo git subprocesses; stdlib only.
"""

import json
import hashlib
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TMP = tempfile.mkdtemp(prefix="g281-langgraph-%d-" % os.getpid(),
                        dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

try:
    from gov import pending_approvals as pa  # noqa: E402
    _HAVE_PA = True
except ImportError:
    pa = None
    _HAVE_PA = False

TAXONOMY_PIN = 2124 # Wave-280 merge pin 1541; this lane adds 2 codes.; Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []

_LEDGERS = []  # every ledger opened by a probe; closed after main()


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, note = ("ERROR", "%s: %s" % (type(exc).__name__, exc))
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))


def _held(note):
    return ("HELD", note)


def _broken(note):
    return ("BREAK", note)


def _need_pa(pid):
    """BREAK-shaped early exit when the module is absent (base)."""
    if not _HAVE_PA:
        return _broken("gov.pending_approvals absent on base")
    return None


def _fresh_ledger(log=None):
    d = tempfile.mkdtemp(prefix="g281_ledger_", dir=os.environ["TMPDIR"])
    db = os.path.join(d, "pending.db")
    ledger = pa.PendingApprovalLedger(db, log=log)
    _LEDGERS.append(ledger)
    return ledger, d, db


def _close_ledgers():
    for ledger in _LEDGERS:
        try:
            ledger.close()
        except Exception:  # noqa: BLE001
            pass
    del _LEDGERS[:]


def _fresh_log():
    d = tempfile.mkdtemp(prefix="g281_log_", dir=os.environ["TMPDIR"])
    from gov.log import ActionLog
    log = ActionLog(os.path.join(d, "audit.jsonl"))
    return log, os.path.join(d, "audit.jsonl")


def _log_events(log_path, event_name):
    out = []
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            if e.get("event") == event_name:
                out.append(e)
    return out


def _proposal(args=None):
    return {"tool": "write_file",
            "args": args if args is not None else {"path": "/tmp/x",
                                                  "mode": "w"},
            "run_id": "run-1",
            "agent_id": "agent-7",
            "policy_id": "human-approval-contract",
            "reason": "critical stakes write"}


# ---------------------------------------------------------------------------
# (1) park -> resume roundtrip: the basic durable-approval shape.
# ---------------------------------------------------------------------------

def p_park_resume_roundtrip():
    miss = _need_pa("p-park-resume-roundtrip")
    if miss:
        return miss
    ledger, _d, _db = _fresh_ledger()
    ledger.park("a1", _proposal(), ttl_s=3600)
    rv = ledger.resume("a1", "approved", decided_by="op1")
    if rv["decision"] != "approved":
        return _broken("resume decision wrong: %r" % (rv,))
    if rv["args"] != {"path": "/tmp/x", "mode": "w"}:
        return _broken("resume args wrong: %r" % (rv,))
    if rv["edited"] is not False:
        return _broken("edited must be False: %r" % (rv,))
    if not re.fullmatch(r"[0-9a-f]{64}", rv["proposal_digest"] or ""):
        return _broken("proposal_digest not digest-shaped: %r" % (rv,))
    st = ledger.status("a1")
    if st["status"] != "approved":
        return _broken("status not approved: %r" % (st,))
    return _held("park->resume approved; resume value carries "
                 "decision/args/digests")


# ---------------------------------------------------------------------------
# (2) Crash recovery: park, drop the ledger, reopen, resume.
# ---------------------------------------------------------------------------

def p_crash_recovery():
    miss = _need_pa("p-crash-recovery")
    if miss:
        return miss
    ledger, _d, db = _fresh_ledger()
    ledger.park("a1", _proposal(), ttl_s=3600)
    ledger.park("a2", _proposal({"path": "/tmp/y"}), ttl_s=3600)
    # Simulate the process dying mid-approval: close (don't just drop)
    # so the old connection is really gone; committed rows must survive.
    ledger.close()
    del ledger
    ledger2 = pa.PendingApprovalLedger(db)
    _LEDGERS.append(ledger2)
    parked = ledger2.list_parked()
    ids = sorted(p["approval_id"] for p in parked)
    if ids != ["a1", "a2"]:
        return _broken("restart lost parked approvals: %r" % (ids,))
    rec = ledger2.recover()
    if sorted(rec["parked"]) != ["a1", "a2"] or rec["tampered"]:
        return _broken("recover mismatch: %r" % (rec,))
    rv = ledger2.resume("a2", "denied", decided_by="op1")
    if rv["decision"] != "denied" or rv["args"] is not None:
        return _broken("denied resume value must carry args=None: %r"
                       % (rv,))
    return _held("restart recovery: 2 parked survive, resume works, "
                 "deny carries args=None")


# ---------------------------------------------------------------------------
# (3) Resume-value contract: the verdict becomes the executor's input.
# ---------------------------------------------------------------------------

def p_resume_value_contract():
    miss = _need_pa("p-resume-value-contract")
    if miss:
        return miss
    ledger, _d, _db = _fresh_ledger()
    ledger.park("a1", _proposal(), ttl_s=3600)
    rv = ledger.resume("a1", "approved", decided_by="op1")
    for key in ("approval_id", "decision", "args", "proposal_digest",
                "final_args_digest", "edited"):
        if key not in rv:
            return _broken("resume value missing key %r: %r" % (key, rv))
    if rv["approval_id"] != "a1":
        return _broken("approval_id mismatch: %r" % (rv,))
    if rv["final_args_digest"] != pa.args_digest(rv["args"]):
        return _broken("final_args_digest does not match args: %r" % (rv,))
    return _held("resume value is the executor's resume input: "
                 "id/decision/args/digests/edited")


# ---------------------------------------------------------------------------
# (4) Edit-before-approve: the reviewer rewrites the args.
# ---------------------------------------------------------------------------

def p_edit_before_approve():
    miss = _need_pa("p-edit-before-approve")
    if miss:
        return miss
    log, log_path = _fresh_log()
    ledger, _d, _db = _fresh_ledger(log=log)
    ledger.park("a1", _proposal(), ttl_s=3600)
    edited = {"path": "/tmp/y", "mode": "w"}
    rv = ledger.resume("a1", "approved", edited_args=edited,
                       decided_by="op1")
    if rv["args"] != edited:
        return _broken("execution must use the EDITED args: %r" % (rv,))
    if rv["edited"] is not True:
        return _broken("edited flag must be True: %r" % (rv,))
    evs = _log_events(log_path, "approval_args_edited")
    if len(evs) != 1:
        return _broken("expected 1 approval_args_edited event, got %d"
                       % len(evs))
    ev = evs[0]
    if ev.get("agent_id") != "human-operator":
        return _broken("edit event must blame human-operator: %r" % (ev,))
    if ev.get("approval_id") != "a1":
        return _broken("edit event approval_id wrong: %r" % (ev,))
    if ev.get("old_args_digest") == ev.get("new_args_digest"):
        return _broken("edit digests must differ: %r" % (ev,))
    if ev.get("edited_arg_keys") != ["path"]:
        return _broken("edited_arg_keys wrong: %r" % (ev,))
    if ev.get("new_args_digest") != pa.args_digest(edited):
        return _broken("new_args_digest mismatch: %r" % (ev,))
    return _held("edit-before-approve: edited args execute; "
                 "approval_args_edited chained with old/new digests")


# ---------------------------------------------------------------------------
# (5) Diff chain: proposal -> edit -> execution, digest-linked, in order.
# ---------------------------------------------------------------------------

def p_diff_chain():
    miss = _need_pa("p-diff-chain")
    if miss:
        return miss
    log, log_path = _fresh_log()
    ledger, _d, _db = _fresh_ledger(log=log)
    prop = _proposal()
    ledger.park("a1", prop, ttl_s=3600)
    edited = {"path": "/tmp/y", "mode": "w"}
    ledger.resume("a1", "approved", edited_args=edited, decided_by="op1")
    parked = _log_events(log_path, "pending_approval_parked")
    edits = _log_events(log_path, "approval_args_edited")
    resumed = _log_events(log_path, "pending_approval_resumed")
    if not (len(parked) == 1 and len(edits) == 1 and len(resumed) == 1):
        return _broken("triple incomplete: parked=%d edited=%d resumed=%d"
                       % (len(parked), len(edits), len(resumed)))
    if parked[0]["args_digest"] != edits[0]["old_args_digest"]:
        return _broken("park.args_digest != edit.old_args_digest")
    if edits[0]["new_args_digest"] != resumed[0]["final_args_digest"]:
        return _broken("edit.new_args_digest != resumed.final_args_digest")
    if resumed[0]["proposal_digest"] != parked[0]["proposal_digest"]:
        return _broken("proposal digest not carried through the triple")
    # File order = causal order.
    order = []
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                order.append(json.loads(line).get("event"))
    triple = [e for e in order if e in ("pending_approval_parked",
                                       "approval_args_edited",
                                       "pending_approval_resumed")]
    if triple != ["pending_approval_parked", "approval_args_edited",
                  "pending_approval_resumed"]:
        return _broken("triple out of causal order: %r" % (triple,))
    from gov.log import verify_chain
    ok, broken_seq, _n = verify_chain(log_path)
    if ok is not True:
        return _broken("HMAC chain does not verify: broken_seq=%r"
                       % (broken_seq,))
    return _held("proposal->edit->execution triple digest-linked, ordered, "
                 "HMAC-verified")


# ---------------------------------------------------------------------------
# (6) Tampered snapshot: refuse-to-resume, never execute.
# ---------------------------------------------------------------------------

def p_tampered_snapshot_refused():
    miss = _need_pa("p-tampered-snapshot-refused")
    if miss:
        return miss
    ledger, _d, db = _fresh_ledger()
    ledger.park("a1", _proposal(), ttl_s=3600)
    # Attacker rewrites the stored snapshot bytes out-of-band.
    evil = json.dumps({"tool": "write_file",
                       "args": {"path": "/etc/passwd", "mode": "w"}},
                      sort_keys=True)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE pending_approvals SET proposal_json=? "
                 "WHERE approval_id='a1'", (evil,))
    conn.commit()
    conn.close()
    try:
        ledger.resume("a1", "approved", decided_by="op1")
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        if code != "pending-approval-snapshot-tampered":
            return _broken("wrong code for tampered snapshot: %r" % (code,))
        st = ledger.status("a1")
        if st["status"] != "parked":
            return _broken("tampered record must stay parked: %r" % (st,))
    else:
        return _broken("resume on a tampered snapshot did NOT refuse")
    # Variant: unparseable bytes with a CONSISTENT recomputed digest
    # (store-level corruption the digest check alone cannot catch).
    # Must still refuse coded -- never a raw exception, never execute.
    ledger.park("a2", _proposal(), ttl_s=3600)
    bad_bytes = "{not valid json"
    bad_digest = hashlib.sha256(bad_bytes.encode("utf-8")).hexdigest()
    conn = sqlite3.connect(db)
    conn.execute("UPDATE pending_approvals SET proposal_json=?,"
                 " proposal_digest=? WHERE approval_id='a2'",
                 (bad_bytes, bad_digest))
    conn.commit()
    conn.close()
    try:
        ledger.resume("a2", "approved", decided_by="op1")
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        if code != "pending-approval-snapshot-tampered":
            return _broken("wrong code for unparseable snapshot: %r"
                           % (code,))
        st = ledger.status("a2")
        if not st.get("tampered") or st["status"] != "parked":
            return _broken("unparseable record must surface tampered "
                           "and stay parked: %r" % (st,))
        rec = ledger.recover()
        if "a2" not in rec["tampered"]:
            return _broken("recover() must report the unparseable "
                           "record as tampered: %r" % (rec,))
        return _held("tampered + unparseable snapshots refused coded; "
                     "never execute; queries surface tampered")
    return _broken("resume on an unparseable snapshot did NOT refuse")


# ---------------------------------------------------------------------------
# (7) Unknown approval id: refuse coded.
# ---------------------------------------------------------------------------

def p_unknown_id_refused():
    miss = _need_pa("p-unknown-id-refused")
    if miss:
        return miss
    ledger, _d, _db = _fresh_ledger()
    try:
        ledger.resume("no-such-id", "approved", decided_by="op1")
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", None) != "pending-approval-resume-refused":
            return _broken("wrong code: %r"
                           % (getattr(exc, "code", None),))
        return _held("unknown id refused coded")
    return _broken("resume of unknown id did NOT refuse")


# ---------------------------------------------------------------------------
# (8) Double resume: exactly one terminal decision.
# ---------------------------------------------------------------------------

def p_double_resume_refused():
    miss = _need_pa("p-double-resume-refused")
    if miss:
        return miss
    ledger, _d, db = _fresh_ledger()
    ledger.park("a1", _proposal(), ttl_s=3600)
    ledger.resume("a1", "approved", decided_by="op1")
    try:
        ledger.resume("a1", "denied", decided_by="op2")
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", None) != "pending-approval-resume-refused":
            return _broken("wrong code: %r"
                           % (getattr(exc, "code", None),))
        conn = sqlite3.connect(db)
        n = conn.execute("SELECT COUNT(*) FROM approval_events WHERE "
                         "approval_id='a1' AND event='resumed'").fetchone()[0]
        conn.close()
        if n != 1:
            return _broken("expected exactly 1 resumed event, got %d" % n)
        return _held("second resume refused; exactly one terminal decision")
    return _broken("double resume did NOT refuse")


# ---------------------------------------------------------------------------
# (9) Expiry is computed at read time (check_at_use): no live timers.
# ---------------------------------------------------------------------------

def p_expired_refused():
    miss = _need_pa("p-expired-refused")
    if miss:
        return miss
    ledger, _d, _db = _fresh_ledger()
    ledger.park("a1", _proposal(), ttl_s=0.5)
    st_before = ledger.status("a1")
    if st_before.get("expired"):
        return _broken("freshly parked record must not read expired")
    time.sleep(0.6)
    st_after = ledger.status("a1")
    if not st_after.get("expired"):
        return _broken("lapsed record must read expired (check_at_use)")
    try:
        ledger.resume("a1", "approved", decided_by="op1")
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", None) != "pending-approval-resume-refused":
            return _broken("wrong code: %r"
                           % (getattr(exc, "code", None),))
        return _held("expired resume refused coded; expiry read at use")
    return _broken("resume of an expired record did NOT refuse")


# ---------------------------------------------------------------------------
# (10) Queries are read-only projections: zero writes.
# ---------------------------------------------------------------------------

def p_query_readonly():
    miss = _need_pa("p-query-readonly")
    if miss:
        return miss
    ledger, _d, db = _fresh_ledger()
    ledger.park("a1", _proposal(), ttl_s=3600)
    mtime_before = os.stat(db).st_mtime_ns
    conn = sqlite3.connect(db)
    events_before = conn.execute(
        "SELECT COUNT(*) FROM approval_events").fetchone()[0]
    conn.close()
    for _ in range(5):
        ledger.list_parked()
        ledger.status("a1")
        ledger.status("missing")
        ledger.recover()
    mtime_after = os.stat(db).st_mtime_ns
    conn = sqlite3.connect(db)
    events_after = conn.execute(
        "SELECT COUNT(*) FROM approval_events").fetchone()[0]
    conn.close()
    if mtime_after != mtime_before:
        return _broken("queries modified the db file")
    if events_after != events_before:
        return _broken("queries appended events")
    return _held("list_parked/status/recover perform zero writes")


# ---------------------------------------------------------------------------
# (11) Malformed resume values refuse fail-closed, coded.
# ---------------------------------------------------------------------------

def p_malformed_resume_refused():
    miss = _need_pa("p-malformed-resume-refused")
    if miss:
        return miss
    ledger, _d, _db = _fresh_ledger()
    ledger.park("a1", _proposal(), ttl_s=3600)
    bad = 0
    for decision, edited in (("maybe", None), ("approved", ["not", "dict"]),
                             ("", None), ("approved", {"k": object()})):
        try:
            ledger.resume("a1", decision, edited_args=edited,
                          decided_by="op1")
        except Exception as exc:  # noqa: BLE001
            if getattr(exc, "code", None) ==\
                    "pending-approval-resume-refused":
                bad += 1
    if bad != 4:
        return _broken("only %d/4 malformed resumes refused coded" % bad)
    if ledger.status("a1")["status"] != "parked":
        return _broken("malformed resumes must not decide the record")
    return _held("4/4 malformed resume values refused coded; still parked")


# ---------------------------------------------------------------------------
# (12) Taxonomy pin: this lane adds exactly 2 decision codes.
# ---------------------------------------------------------------------------

def p_taxonomy_pin():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    literals = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if len(literals) != TAXONOMY_PIN:
        return _broken("taxonomy pin drift: %d literals, pin %d"
                       % (len(literals), TAXONOMY_PIN))
    if len(set(literals)) != len(literals):
        return _broken("duplicate code literals")
    if literals != sorted(literals):
        return _broken("code literals not sorted")
    return _held("%d/%d/0 sorted" % (len(literals), len(literals)))


# ---------------------------------------------------------------------------
# Depth-1 green checks (GOV_SKIP_GREEN=1 in the child env; no recursion).
# ---------------------------------------------------------------------------

def green_check():
    """Run the adjacent approval-path batteries depth-1.

    A parent battery's green check runs each adjacent suite's main with
    GOV_SKIP_GREEN=1 in the child env; the child records a skip note and
    returns without spawning (depth-1, never nested).
    """
    if GREEN_SKIP:
        return [("GOV_SKIP_GREEN=1: recorded, not recursing", "HELD",
                 "depth-1 boundary")]
    out = []
    checks = [
        (["evals/w280_humanlayer_probes.py"], "w280_humanlayer"),
        (["evals/w280_f305_probes.py"], "w280_f305"),
    ]
    for argv, name in checks:
        tmp = tempfile.mkdtemp(prefix="g281-langgraph-green-", dir="/var/tmp")
        env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmp)
        cmd = [sys.executable] + argv
        try:
            proc = subprocess.run(cmd, cwd=REPO, env=env,  # noqa: S603
                                  capture_output=True, text=True, timeout=600)
            tail = (proc.stdout + proc.stderr).strip().splitlines()[-3:]
            verdict = ("HELD" if proc.returncode == 0 else "BREAK")
            out.append((name, verdict,
                        "rc=%d; %s" % (proc.returncode, " | ".join(tail))))
        except Exception as exc:  # noqa: BLE001
            out.append((name, "ERROR", "%s: %s"
                        % (type(exc).__name__, exc)))
    return out


def main():
    probes = [
        ("p-park-resume-roundtrip", "HELD", p_park_resume_roundtrip),
        ("p-crash-recovery", "HELD", p_crash_recovery),
        ("p-resume-value-contract", "HELD", p_resume_value_contract),
        ("p-edit-before-approve", "HELD", p_edit_before_approve),
        ("p-diff-chain", "HELD", p_diff_chain),
        ("p-tampered-snapshot-refused", "HELD", p_tampered_snapshot_refused),
        ("p-unknown-id-refused", "HELD", p_unknown_id_refused),
        ("p-double-resume-refused", "HELD", p_double_resume_refused),
        ("p-expired-refused", "HELD", p_expired_refused),
        ("p-query-readonly", "HELD", p_query_readonly),
        ("p-malformed-resume-refused", "HELD", p_malformed_resume_refused),
        ("pin-taxonomy-1543", "HELD", p_taxonomy_pin),
    ]
    for pid, expected, fn in probes:
        _run(pid, expected, fn)
    _close_ledgers()
    for name, verdict, note in green_check():
        _RESULTS.append(("green:" + name, "HELD", verdict,
                         verdict == "HELD", note))
    n_ok = sum(1 for r in _RESULTS if r[3])
    n_bad = len(_RESULTS) - n_ok
    print("w281_langgraph: %d/%d HELD, %d BREAK/ERROR" % (n_ok,
                                                          len(_RESULTS),
                                                          n_bad))
    for pid, expected, verdict, ok, note in _RESULTS:
        print("%-32s %-5s %-5s %s" % (pid, expected, verdict, note))
    return 0 if n_bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
