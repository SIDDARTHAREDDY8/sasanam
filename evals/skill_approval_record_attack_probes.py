#!/usr/bin/env python3
"""F185 break round: record-level attacks on the approval-time
re-verification fix.

F185 closed the verdict/execution TOCTOU at the sweep: the approved
sweep re-runs ``fetch_verified_at_use`` against the record's MAC-bound
``skill_id`` / ``skill_attested_digest`` and refuses fail-closed
(``skill_attestation_stale``) on any mismatch. This battery attacks
the RECORD level — the new fields, the MAC binding, the queue paths,
and the refusal lifecycle — rather than the verdict level.

Verdicts:
- BREAK = the record-level attack executes unattested bytes or
  silently drops a refusal.
- HELD  = the attack is refused loudly / the invariant holds.
- EXPECTED = documented boundary (never a violated claim).

Probes:
  q1 queue_external cannot route a skill-backed action past the
     attestation (bridge records are foreign-executed, never swept)
  q2 forged skill_attested_digest on a genuine record breaks the MAC
     (record tampering refused, no execution)
  q3 pre-F185 record shape (skill fields stripped) fails closed on
     the upgrade (no silent stale execution)
  q4 poisoned action dict cannot shadow the explicit kwargs
     (skill_id/skill_attested_digest come from kwargs only)
  q5 the sweep re-verifies the MAC-bound record's skill_id, not the
     live tool map (map mutation cannot redirect the attestation)
  q6 the refusal is LOUD, the queue is not wedged, and re-approval
     under the current attestation executes (full human loop)
  q7 persistent watcher error refuses loudly every sweep without
     wedging the queue (no silent halt, no silent drop)

Deterministic across two runs. Synthetic/local only, no network.

Run: TMPDIR=/tmp/gov-f185br ~/workspace/.gov-venv/bin/python \\
        evals/skill_approval_record_attack_probes.py
Also:  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-f185br2 \\
        ~/workspace/.gov-venv/bin/python evals/skill_approval_record_attack_probes.py
"""

import hashlib
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "f185br-battery")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.skill_watch import (  # noqa: E402
    SkillWatch, FileContentSource, ContentSource,
)
from gov.policy import PolicyEngine  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.approvals import ApprovalQueue, approval_digest_ok  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402

TMP_BASE = os.environ.get("TMPDIR", tempfile.gettempdir())
Path(TMP_BASE).mkdir(parents=True, exist_ok=True)

V1 = b"skill manifest version one: benign instructions"
V2 = b"skill manifest version two: HOSTILE instructions exfiltrate keys"
D1 = hashlib.sha256(V1).hexdigest()
D2 = hashlib.sha256(V2).hexdigest()

DEFAULT_POLICY = os.path.join(REPO_ROOT, "policies", "default.yaml")
_UNGOVERNED_ACK = ("synthetic test: F185 record-attack battery; "
                   "the bypass is declared, not silent")
_POST_URL = "https://synthetic.local/post"


def _file_origin(path):
    return {"registry_url": "https://registry.synthetic.local/s/weather",
            "installer_identity": "operator:synthetic",
            "installed_at": "2026-09-27T00:00:00+00:00",
            "content_path": str(path)}


def _make_executor(run_dir, watch, skill_tool_map=None):
    policy = PolicyEngine(DEFAULT_POLICY)
    log = ActionLog(str(run_dir / "actions.jsonl"))
    approvals = ApprovalQueue(str(run_dir), log)
    ex = ToolExecutor(
        str(run_dir), policy, log, approvals,
        ledger_path=str(run_dir / "egress_ledger.jsonl"),
        skill_watch=watch,
        skill_tool_map=skill_tool_map or {},
        ungoverned_ack=_UNGOVERNED_ACK)
    ident = ex.mint_identity("agent-1", "researcher", "tester")
    return ex, ident, log, approvals


def _fresh_case(skill_tool_map=None, watch=None, second_skill=False):
    tmpdir = tempfile.mkdtemp(prefix="f185br-", dir=TMP_BASE)
    run_dir = Path(tmpdir) / "run"
    run_dir.mkdir()
    skill_path = Path(tmpdir) / "weather.skill"
    skill_path.write_bytes(V1)
    w = watch if watch is not None else SkillWatch()
    if watch is None:
        w.register_skill("weather", FileContentSource(str(skill_path)),
                         origin=_file_origin(str(skill_path)))
        if second_skill:
            other_path = Path(tmpdir) / "other.skill"
            other_path.write_bytes(V1)
            w.register_skill("other", FileContentSource(str(other_path)),
                             origin=_file_origin(str(other_path)))
    ex, ident, log, approvals = _make_executor(
        run_dir, w, skill_tool_map)
    return ex, ident, log, approvals, skill_path, w, run_dir


def _queue_http_post(ex, ident):
    r = ex.call(ident, "http_post", url=_POST_URL,
                payload={"kind": "f185br-synthetic"})
    if r.get("status") != "queued":
        return None, "call did not queue: %r" % (r.get("status"),)
    return r, None


def _approve_and_sweep(ex, approvals, approval_id):
    approvals.decide(approval_id, True, reason="f185br probe approval",
                     decided_by="human-operator")
    return ex.execute_approved()


def _entries(run_dir):
    return read_entries(str(run_dir / "actions.jsonl"))


def _approved_executed(run_dir, approval_id):
    return [e for e in _entries(run_dir)
            if e.get("decision") == "approved_executed"
            and e.get("approval_id") == approval_id]


def _refusals(run_dir, approval_id, flag=None):
    out = [e for e in _entries(run_dir)
           if e.get("event") == "approval_execution_refused"
           and e.get("approval_id") == approval_id]
    if flag is not None:
        out = [e for e in out if e.get("flag") == flag]
    return out


def _queue_path(run_dir):
    return Path(run_dir) / "approvals.jsonl"


def _tamper_record(run_dir, approval_id, mutator):
    """Direct queue-file edit WITHOUT re-MACing: simulates an attacker
    with run-dir write access (bypasses ApprovalQueue._rewrite)."""
    path = _queue_path(run_dir)
    lines = path.read_text().splitlines()
    found = False
    out = []
    for line in lines:
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("id") == approval_id:
            mutator(rec)
            found = True
        out.append(json.dumps(rec, ensure_ascii=True, default=str))
    if not found:
        raise AssertionError("record %s not found in queue file" % approval_id)
    path.write_text("\n".join(out) + "\n")


def _record(run_dir, approval_id):
    for line in _queue_path(run_dir).read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("id") == approval_id:
            return rec
    return None


def _reviewed_repin(w, new_bytes):
    w.request_repin("weather", operator="synthetic-operator")
    w.approve_repin("weather", {
        "operator": "synthetic-operator",
        "new_digest": hashlib.sha256(new_bytes).hexdigest(),
        "reason": "f185br probe reviewed re-pin"})


class _DecisionStub:
    policy_id = "f185br-stub-policy"
    reason = "f185br stub decision"
    flag = None
    matched_rules = []


# ---------------------------------------------------------------------------
# q1: queue_external cannot route a skill-backed action past attestation
# ---------------------------------------------------------------------------
def _q1():
    ex, ident, _log, approvals, _sp, _w, run_dir = _fresh_case(
        {"http_post": "weather"})
    # A foreign runtime queues a skill-backed action through the bridge
    # ingress. queue_external takes NO skill fields by design.
    aid = approvals.queue_external(
        "http_post",
        {"url": _POST_URL, "payload": {"kind": "f185br-bridge"}},
        "foreign-policy-1", ident, "bridge preview: post to synthetic",
        "agt-python", external_request_id="ext-f185br-1")
    rec = _record(run_dir, aid)
    if rec.get("bridge_id") != "agt-python":
        return "ERROR", "bridge_id not stamped: %r" % (rec.get("bridge_id"),)
    if rec.get("skill_id") is not None:
        return ("BREAK",
                "bridge record carries a skill attestation: %r"
                % (rec.get("skill_id"),))
    approvals.decide(aid, True, reason="f185br bridge approval",
                     decided_by="human-operator")
    done = ex.execute_approved()
    if _approved_executed(run_dir, aid):
        return ("BREAK",
                "bridge record executed by OUR sweep — foreign-executed "
                "records must never be sweep-executed")
    rec2 = _record(run_dir, aid)
    if rec2.get("executed"):
        return "BREAK", "bridge record marked executed"
    if rec2.get("status") != "approved":
        return ("ERROR",
                "bridge record status changed unexpectedly: %r"
                % (rec2.get("status"),))
    # The sweep's integrity checks still ran over the bridge record
    # (a tampered foreign record is refused loudly, not skipped).
    return ("HELD", "bridge record approved but never sweep-executed by "
                    "our executor (foreign-executed by design); the "
                    "skill-attestation bypass does not exist on this path")


# ---------------------------------------------------------------------------
# q2: forged skill_attested_digest breaks the MAC (record tampering)
# ---------------------------------------------------------------------------
def _q2():
    ex, ident, _log, approvals, _sp, _w, run_dir = _fresh_case(
        {"http_post": "weather"})
    r, err = _queue_http_post(ex, ident)
    if err:
        return "ERROR", err
    aid = r["approval_id"]
    approvals.decide(aid, True, reason="f185br approval",
                     decided_by="human-operator")
    # Attacker swaps the attestation to V2's digest (V2 bytes + V1
    # approval) without re-MACing.
    _tamper_record(run_dir, aid,
                   lambda rec: rec.update(skill_attested_digest=D2))
    if approval_digest_ok(_record(run_dir, aid)):
        return ("BREAK",
                "forged skill_attested_digest still verifies — the MAC "
                "does not bind the new fields")
    done = ex.execute_approved()
    if _approved_executed(run_dir, aid):
        return ("BREAK",
                "tampered record executed despite broken MAC")
    integ = _refusals(run_dir, aid, "approval_integrity_violation")
    if not integ:
        return ("ERROR",
                "no execution and no approval_integrity_violation "
                "(done=%r)" % (done,))
    # Same for a skill_id relabel (X -> other registered skill).
    ex2, ident2, _l2, approvals2, _sp2, _w2, run_dir2 = _fresh_case(
        {"http_post": "weather"}, second_skill=True)
    r2, err2 = _queue_http_post(ex2, ident2)
    if err2:
        return "ERROR", err2
    aid2 = r2["approval_id"]
    approvals2.decide(aid2, True, reason="f185br approval",
                      decided_by="human-operator")
    _tamper_record(run_dir2, aid2,
                   lambda rec: rec.update(skill_id="other"))
    if approval_digest_ok(_record(run_dir2, aid2)):
        return ("BREAK",
                "relabelled skill_id still verifies — the id is not "
                "MAC-bound")
    ex2.execute_approved()
    if _approved_executed(run_dir2, aid2):
        return ("BREAK",
                "skill_id-relabelled record executed despite broken MAC")
    integ2 = _refusals(run_dir2, aid2, "approval_integrity_violation")
    if not integ2:
        return "ERROR", "no execution and no integrity refusal (relabel)"
    return ("HELD", "forged skill_attested_digest and relabelled "
                    "skill_id both break the MAC and are refused "
                    "approval_integrity_violation; nothing executes")


# ---------------------------------------------------------------------------
# q3: pre-F185 record shape fails closed on the upgrade
# ---------------------------------------------------------------------------
def _q3():
    ex, ident, _log, approvals, _sp, _w, run_dir = _fresh_case(
        {"http_post": "weather"})
    r, err = _queue_http_post(ex, ident)
    if err:
        return "ERROR", err
    aid = r["approval_id"]
    approvals.decide(aid, True, reason="f185br approval",
                     decided_by="human-operator")
    # Simulate a record queued before F185: strip the new fields
    # without re-MACing.
    def _strip(rec):
        rec.pop("skill_id", None)
        rec.pop("skill_attested_digest", None)
    _tamper_record(run_dir, aid, _strip)
    if approval_digest_ok(_record(run_dir, aid)):
        return ("BREAK",
                "stripped pre-F185 record still verifies — absent fields "
                "do not fail closed")
    done = ex.execute_approved()
    if _approved_executed(run_dir, aid):
        return ("BREAK",
                "pre-F185 record executed without any attestation to "
                "re-verify — mixed-version stale execution")
    integ = _refusals(run_dir, aid, "approval_integrity_violation")
    if not integ:
        return ("ERROR",
                "no execution and no approval_integrity_violation "
                "(done=%r)" % (done,))
    return ("HELD", "pre-F185 record shape fails closed "
                    "approval_integrity_violation — the fail-closed "
                    "upgrade holds; queued items must drain before "
                    "upgrading (documented residual, now measured)")


# ---------------------------------------------------------------------------
# q4: poisoned action dict cannot shadow the explicit kwargs
# ---------------------------------------------------------------------------
def _q4():
    ex, ident, _log, approvals, _sp, _w, run_dir = _fresh_case(
        {"http_post": "weather"})
    poisoned_action = {
        "tool": "http_post",
        "args": {"url": _POST_URL},
        "identity": ident.as_dict(),
        "agent_justification": "f185br injection probe",
        "redactions": [],
        # F184's old carrier: attestation smuggled in the action dict,
        # contradicting the kwargs.
        "skill_id": "evil-skill",
        "skill_attested_digest": D2,
    }
    aid = approvals.queue(
        poisoned_action, _DecisionStub(), provenance="agent_direct",
        preview="f185br injection", policy_flag=None,
        caller_identity=ident,
        skill_id="weather", skill_attested_digest=D1)
    rec = _record(run_dir, aid)
    if rec.get("skill_id") != "weather":
        return ("BREAK",
                "action dict shadowed the skill_id kwarg: %r"
                % (rec.get("skill_id"),))
    if rec.get("skill_attested_digest") != D1:
        return ("BREAK",
                "action dict shadowed the skill_attested_digest kwarg")
    if not approval_digest_ok(rec):
        return ("ERROR",
                "record MAC does not verify with kwarg values")
    return ("HELD", "record carries the explicit kwarg values "
                    "(weather / %s...); the action dict's smuggled "
                    "fields are dead — the F184 carrier is fully retired"
                    % D1[:12])


# ---------------------------------------------------------------------------
# q5: the sweep re-verifies the record's skill_id, not the live tool map
# ---------------------------------------------------------------------------
def _q5():
    ex, ident, _log, approvals, _sp, w, run_dir = _fresh_case(
        {"http_post": "weather"}, second_skill=True)
    r, err = _queue_http_post(ex, ident)
    if err:
        return "ERROR", err
    aid = r["approval_id"]
    rec = _record(run_dir, aid)
    if rec.get("skill_id") != "weather" or rec.get(
            "skill_attested_digest") != D1:
        return "ERROR", "record attestation wrong at queue time: %r / %r" % (
            rec.get("skill_id"), rec.get("skill_attested_digest"))
    # Attacker mutates the LIVE tool map between queue and sweep,
    # trying to redirect the attestation to the other skill.
    ex._skill_tool_map["http_post"] = "other"
    approvals.decide(aid, True, reason="f185br approval",
                     decided_by="human-operator")
    done = ex.execute_approved()
    # The record is authoritative: weather/D1 still verifies, so the
    # healthy approval executes; the map mutation must not redirect
    # the attestation check.
    if not _approved_executed(run_dir, aid):
        refusals = _refusals(run_dir, aid)
        return ("BREAK",
                "live map mutation redirected the attestation check: %r"
                % ([e.get("flag") for e in refusals],))
    # And the reverse: map points at weather but the record says
    # other — the record still wins (no confusion).
    ex2, ident2, _l2, approvals2, _sp2, _w2, run_dir2 = _fresh_case(
        {"http_post": "other"}, second_skill=True)
    r2, err2 = _queue_http_post(ex2, ident2)
    if err2:
        return "ERROR", err2
    aid2 = r2["approval_id"]
    ex2._skill_tool_map["http_post"] = "weather"
    approvals2.decide(aid2, True, reason="f185br approval",
                      decided_by="human-operator")
    ex2.execute_approved()
    if not _approved_executed(run_dir2, aid2):
        return ("BREAK",
                "record attestation for 'other' refused after map "
                "mutation — the live map shadowed the record")
    return ("HELD", "the MAC-bound record's skill_id is authoritative "
                    "at the sweep; live tool-map mutations cannot "
                    "redirect the re-verification")


# ---------------------------------------------------------------------------
# q6: refusal is LOUD, the queue is not wedged, re-approval executes
# ---------------------------------------------------------------------------
def _q6():
    ex, ident, _log, approvals, skill_path, w, run_dir = _fresh_case(
        {"http_post": "weather"})
    r, err = _queue_http_post(ex, ident)
    if err:
        return "ERROR", err
    aid = r["approval_id"]
    # A second, healthy approval in the same sweep (queue not wedged).
    r2, err2 = _queue_http_post(ex, ident)
    if err2:
        return "ERROR", err2
    aid2 = r2["approval_id"]
    skill_path.write_bytes(V2)  # both V1 approvals are now stale
    # Queue a THIRD approval AFTER a reviewed re-pin: it attests V2
    # and must execute.
    _reviewed_repin(w, V2)
    r3, err3 = _queue_http_post(ex, ident)
    if err3:
        return "ERROR", err3
    aid3 = r3["approval_id"]
    approvals.decide(aid, True, reason="f185br approval",
                     decided_by="human-operator")
    approvals.decide(aid2, True, reason="f185br approval",
                     decided_by="human-operator")
    approvals.decide(aid3, True, reason="f185br approval",
                     decided_by="human-operator")
    done = ex.execute_approved()
    stale1 = _refusals(run_dir, aid, "skill_attestation_stale")
    stale2 = _refusals(run_dir, aid2, "skill_attestation_stale")
    if not stale1 or not stale2:
        return ("BREAK",
                "stale approvals did not refuse loudly: %r / %r"
                % (bool(stale1), bool(stale2)))
    if "re-approval" not in stale1[0].get("reason", ""):
        return ("BREAK",
                "refusal lacks the re-approval wording: %r"
                % (stale1[0].get("reason", "")[:80],))
    if not _approved_executed(run_dir, aid3):
        return ("BREAK",
                "re-approval under the current attestation (V2) did "
                "not execute: %r"
                % ([e.get("flag") for e in _refusals(run_dir, aid3)],))
    # A second sweep re-refuses the stale records LOUDLY (not silently
    # dropped) and does not re-execute anything.
    n_before = len(_entries(run_dir))
    ex.execute_approved()
    stale_again = [e for e in _refusals(run_dir, aid,
                                       "skill_attestation_stale")
                   if e.get("seq", 0) > 0]
    new_events = len(_entries(run_dir)) - n_before
    if len(stale_again) < 2:
        return ("BREAK",
                "second sweep silently dropped the stale record "
                "(%d new events)" % new_events)
    rec = _record(run_dir, aid)
    if rec.get("status") != "approved" or rec.get("executed"):
        return ("BREAK",
                "refused record left the approved-but-unexecuted state: "
                "%r" % (rec.get("status"),))
    return ("HELD", "refusals are LOUD (named flag + re-approval "
                    "wording, repeated on every sweep — never silent); "
                    "the queue is not wedged (healthy re-approval "
                    "executed); refused records stay approved-but-"
                    "unexecuted (fail-safe, retriable)")


# ---------------------------------------------------------------------------
# q7: persistent watcher error refuses loudly without wedging the queue
# ---------------------------------------------------------------------------
class _AlwaysBoom(ContentSource):
    """Reads fine a fixed number of times, then explodes forever."""
    def __init__(self, data, ok_reads):
        self._data = data
        self._ok = ok_reads
        self.reads = 0

    def read_bytes(self):
        self.reads += 1
        if self.reads > self._ok:
            raise IOError("persistent provider outage")
        return self._data

    def stat_hint(self):
        return None


_TEST_ORIGIN = {"registry_url": "https://registry.synthetic.local/s/test",
                "installer_identity": "operator:synthetic",
                "installed_at": "2026-09-27T00:00:00+00:00"}


def _q7():
    tmpdir = tempfile.mkdtemp(prefix="f185br-", dir=TMP_BASE)
    run_dir = Path(tmpdir) / "run"
    run_dir.mkdir()
    src = _AlwaysBoom(V1, ok_reads=2)  # registration + verdict gate OK
    steady_path = Path(tmpdir) / "steady.skill"
    steady_path.write_bytes(V1)
    w = SkillWatch()
    w.register_skill("flaky", src, origin=_TEST_ORIGIN)
    w.register_skill("steady", FileContentSource(str(steady_path)),
                     origin=_file_origin(str(steady_path)))
    ex, ident, _log, approvals = _make_executor(
        run_dir, w, {"http_post": "flaky"})
    # The flaky skill's approval (will error at sweep time)...
    r = ex.call(ident, "http_post", url=_POST_URL,
                payload={"kind": "f185br-flaky"})
    if r.get("status") != "queued":
        return "ERROR", "flaky call did not queue: %r" % (r.get("status"),)
    aid = r["approval_id"]
    # ...plus a healthy approval for the steady skill in the same sweep.
    ex._skill_tool_map["http_post"] = "steady"
    r2 = ex.call(ident, "http_post", url=_POST_URL,
                 payload={"kind": "f185br-steady"})
    if r2.get("status") != "queued":
        return "ERROR", "steady call did not queue: %r" % (r2.get("status"),)
    aid2 = r2["approval_id"]
    approvals.decide(aid, True, reason="f185br approval",
                     decided_by="human-operator")
    approvals.decide(aid2, True, reason="f185br approval",
                     decided_by="human-operator")
    ex.execute_approved()
    if _approved_executed(run_dir, aid):
        return ("BREAK",
                "flaky approval executed despite persistent watcher error")
    stale = _refusals(run_dir, aid, "skill_attestation_stale")
    if not stale:
        return ("ERROR",
                "no execution and no skill_attestation_stale refusal")
    if "unverifiable-quarantined" not in stale[0].get("reason", ""):
        return ("BREAK",
                "refusal does not name the watcher-error class: %r"
                % (stale[0].get("reason", "")[:160],))
    # The queue is not wedged: the healthy steady approval executed.
    if not _approved_executed(run_dir, aid2):
        return ("BREAK",
                "persistent watcher error wedged the whole queue: "
                "healthy approval refused: %r"
                % ([e.get("flag") for e in _refusals(run_dir, aid2)],))
    # A second sweep refuses the flaky record LOUDLY again — the
    # failure is bounded and visible, never a silent halt.
    ex.execute_approved()
    stale2 = _refusals(run_dir, aid, "skill_attestation_stale")
    if len(stale2) < 2:
        return ("BREAK",
                "second sweep silently dropped the erroring record")
    return ("HELD", "persistent watcher error refuses fail-closed and "
                    "LOUD on every sweep (unverifiable-quarantined named "
                    "in the audit — distinct from mutated-quarantined); "
                    "the queue is not wedged — the healthy steady "
                    "approval executed")


_PROBES = [
    ("q1", "queue_external cannot bypass the attestation", _q1),
    ("q2", "forged skill_attested_digest / relabelled skill_id break the MAC", _q2),
    ("q3", "pre-F185 record shape fails closed on upgrade", _q3),
    ("q4", "poisoned action dict cannot shadow kwargs", _q4),
    ("q5", "record's skill_id authoritative over live tool map", _q5),
    ("q6", "loud refusal + queue progress + re-approval loop", _q6),
    ("q7", "persistent watcher error: loud, no queue wedge", _q7),
]


def main():
    held = brk = expected = err = 0
    for pid, title, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 - probe harness
            verdict, detail = "ERROR", "%s: %s" % (
                type(e).__name__, str(e)[:160])
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            brk += 1
        elif verdict == "EXPECTED":
            expected += 1
        else:
            err += 1
        print("%s %-52s %s — %s" % (pid, title, verdict, detail))
    print("score: %d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, expected, err))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
