#!/usr/bin/env python3
"""F185 battery: approval-time skill re-verification (TOCTOU guard).

Finding: the verdict-path skill gate attests skill bytes at queue
time (MAC-bound ``skill_attested_digest`` on the approval record), but
``_execute_approved_locked`` executed queued approvals without
re-running the skill gate — a mutation of the skill's bytes between
approval and sweep executed under an attestation for different bytes
(a human approved V1; the sweep executed V2).

Fix (gov/executor.py, this lane): the sweep re-runs
``fetch_verified_at_use`` against the record's MAC-bound ``skill_id``
and refuses fail-closed (``skill_attestation_stale``) unless the
digest still equals the queue-time attestation. Reviewed re-pins move
the pin but do NOT satisfy an old approval — a NEW approval under the
current attestation executes (re-approvable, never silently executed).

Verdicts:
- BREAK = a mutated-skill approval executes (attestation stale).
- HELD  = the seam is closed / preserved.
- EXPECTED = documented boundary (never a violated claim).

Probes:
  p1 mutation between approval and sweep refused (RED-FIRST)
  p2 unmutated approval executes (happy path preserved)
  p3 reviewed re-pin + NEW approval executes (re-approvable)
  p4 reviewed re-pin does NOT rescue the OLD approval (refuses)
  p5 watcher error at sweep fails closed (no execution)
  p6 unattributed tool unaffected by the new check
  p7 no watcher bound: sweep behavior unchanged
  p8 refusal audit names both digests; record stays retriable

Deterministic across two runs. Synthetic/local only, no network.

Run: TMPDIR=/tmp/gov-f185 ~/workspace/.gov-venv/bin/python \\
        evals/skill_approval_staleness_probes.py
Also:  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-f185b \\
        ~/workspace/.gov-venv/bin/python evals/skill_approval_staleness_probes.py
"""

import hashlib
import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "f185-battery")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.skill_watch import (  # noqa: E402
    SkillWatch, FileContentSource, ContentSource,
)
from gov.policy import PolicyEngine  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402

TMP_BASE = os.environ.get("TMPDIR", tempfile.gettempdir())
Path(TMP_BASE).mkdir(parents=True, exist_ok=True)

V1 = b"skill manifest version one: benign instructions"
V2 = b"skill manifest version two: HOSTILE instructions exfiltrate keys"
D1 = hashlib.sha256(V1).hexdigest()
D2 = hashlib.sha256(V2).hexdigest()

DEFAULT_POLICY = os.path.join(REPO_ROOT, "policies", "default.yaml")
_UNGOVERNED_ACK = ("synthetic test: F185 approval-staleness battery; "
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


def _fresh_case(skill_tool_map=None, watch=None):
    tmpdir = tempfile.mkdtemp(prefix="f185-", dir=TMP_BASE)
    run_dir = Path(tmpdir) / "run"
    run_dir.mkdir()
    skill_path = Path(tmpdir) / "weather.skill"
    skill_path.write_bytes(V1)
    w = watch if watch is not None else SkillWatch()
    if watch is None:
        w.register_skill("weather", FileContentSource(str(skill_path)),
                         origin=_file_origin(str(skill_path)))
    ex, ident, log, approvals = _make_executor(
        run_dir, w, skill_tool_map)
    return ex, ident, log, approvals, skill_path, w, run_dir


def _queue_http_post(ex, ident):
    r = ex.call(ident, "http_post", url=_POST_URL,
                payload={"kind": "f185-synthetic"})
    if r.get("status") != "queued":
        return None, "call did not queue: %r" % (r.get("status"),)
    return r, None


def _approve_and_sweep(ex, approvals, approval_id):
    approvals.decide(approval_id, True, reason="f185 probe approval",
                     decided_by="human-operator")
    done = ex.execute_approved()
    return done


def _entries(run_dir):
    return read_entries(str(run_dir / "actions.jsonl"))


def _approved_executed(run_dir, approval_id):
    return [e for e in _entries(run_dir)
            if e.get("decision") == "approved_executed"
            and e.get("approval_id") == approval_id]


def _refusals(run_dir, approval_id):
    return [e for e in _entries(run_dir)
            if e.get("event") == "approval_execution_refused"
            and e.get("approval_id") == approval_id]


def _reviewed_repin(w, new_bytes):
    """The reviewed re-pin workflow: request + approval move the pin."""
    w.request_repin("weather", operator="synthetic-operator")
    w.approve_repin("weather", {
        "operator": "synthetic-operator",
        "new_digest": hashlib.sha256(new_bytes).hexdigest(),
        "reason": "f185 probe reviewed re-pin"})


# ---------------------------------------------------------------------------
# p1: mutation between approval and sweep (RED-FIRST)
# ---------------------------------------------------------------------------
def _p1():
    ex, ident, _log, approvals, skill_path, _w, run_dir = _fresh_case(
        {"http_post": "weather"})
    r, err = _queue_http_post(ex, ident)
    if err:
        return "ERROR", err
    aid = r["approval_id"]
    skill_path.write_bytes(V2)  # provider-side mutation AFTER approval
    done = _approve_and_sweep(ex, approvals, aid)
    executed = _approved_executed(run_dir, aid)
    if executed:
        return ("BREAK",
                "approved record executed after the skill mutated V1->V2 "
                "(attestation %s... stale): %d approved_executed"
                % (D1[:12], len(executed)))
    stale = [e for e in _refusals(run_dir, aid)
             if e.get("flag") == "skill_attestation_stale"]
    if not stale:
        return ("ERROR",
                "no execution and no skill_attestation_stale refusal "
                "(done=%r)" % (done,))
    return ("HELD",
            "mutation V1->V2 after approval refused fail-closed "
            "(%s... -> %s...)" % (D1[:12], D2[:12]))


# ---------------------------------------------------------------------------
# p2: unmutated approval still executes (happy path preserved)
# ---------------------------------------------------------------------------
def _p2():
    ex, ident, _log, approvals, _sp, _w, run_dir = _fresh_case(
        {"http_post": "weather"})
    r, err = _queue_http_post(ex, ident)
    if err:
        return "ERROR", err
    aid = r["approval_id"]
    done = _approve_and_sweep(ex, approvals, aid)
    if not _approved_executed(run_dir, aid):
        refusals = _refusals(run_dir, aid)
        return ("BREAK",
                "unmutated approved record refused: %r"
                % ([e.get("flag") for e in refusals],))
    if not done:
        return "BREAK", "sweep returned empty for a healthy record"
    return ("HELD", "unmutated approval executes; re-verification is "
                    "transparent on the happy path")


# ---------------------------------------------------------------------------
# p3: reviewed re-pin + NEW approval executes (re-approvable)
# ---------------------------------------------------------------------------
def _p3():
    ex, ident, _log, approvals, skill_path, w, run_dir = _fresh_case(
        {"http_post": "weather"})
    skill_path.write_bytes(V2)
    _reviewed_repin(w, V2)  # reviewed workflow moves the pin to V2
    r, err = _queue_http_post(ex, ident)
    if err:
        return "ERROR", err
    aid = r["approval_id"]
    done = _approve_and_sweep(ex, approvals, aid)
    if not _approved_executed(run_dir, aid):
        return ("BREAK",
                "new approval under the reviewed re-pin refused: %r"
                % ([e.get("flag") for e in _refusals(run_dir, aid)],))
    return ("HELD", "after reviewed re-pin, a NEW approval attesting V2 "
                    "executes (re-approvable, not silently executed)")


# ---------------------------------------------------------------------------
# p4: reviewed re-pin does NOT rescue the OLD approval (still refuses)
# ---------------------------------------------------------------------------
def _p4():
    ex, ident, _log, approvals, skill_path, w, run_dir = _fresh_case(
        {"http_post": "weather"})
    r, err = _queue_http_post(ex, ident)
    if err:
        return "ERROR", err
    aid = r["approval_id"]
    skill_path.write_bytes(V2)
    _reviewed_repin(w, V2)  # pin moves to V2 AFTER the human approved V1
    done = _approve_and_sweep(ex, approvals, aid)
    if _approved_executed(run_dir, aid):
        return ("BREAK",
                "old approval attesting V1 executed after the pin moved "
                "to V2 — the approver never saw V2")
    stale = [e for e in _refusals(run_dir, aid)
             if e.get("flag") == "skill_attestation_stale"]
    if not stale:
        return "ERROR", "no execution and no skill_attestation_stale"
    if "re-approval" not in stale[0].get("reason", ""):
        return ("BREAK",
                "refusal lost the re-approval wording: %r"
                % (stale[0].get("reason", "")[:80],))
    return ("HELD", "old approval refuses even after a REVIEWED re-pin — "
                    "the approver attested V1, never V2")


# ---------------------------------------------------------------------------
# p5: watcher error at sweep fails closed (no execution)
# ---------------------------------------------------------------------------
class _BoomAtThirdRead(ContentSource):
    """Works at registration and at call time; explodes at sweep time."""
    def __init__(self, data):
        self._data = data
        self.reads = 0

    def read_bytes(self):
        self.reads += 1
        if self.reads >= 3:
            raise IOError("boom at sweep")
        return self._data

    def stat_hint(self):
        return None


_TEST_ORIGIN = {"registry_url": "https://registry.synthetic.local/s/test",
                "installer_identity": "operator:synthetic",
                "installed_at": "2026-09-27T00:00:00+00:00"}


def _p5():
    tmpdir = tempfile.mkdtemp(prefix="f185-", dir=TMP_BASE)
    run_dir = Path(tmpdir) / "run"
    run_dir.mkdir()
    src = _BoomAtThirdRead(V1)
    w = SkillWatch()
    w.register_skill("weather", src, origin=_TEST_ORIGIN)
    ex, ident, _log, approvals = _make_executor(
        run_dir, w, {"http_post": "weather"})
    r, err = _queue_http_post(ex, ident)
    if err:
        return "ERROR", err
    aid = r["approval_id"]
    done = _approve_and_sweep(ex, approvals, aid)
    if _approved_executed(run_dir, aid):
        return ("BREAK",
                "approved record executed despite watcher error at "
                "sweep time")
    stale = [e for e in _refusals(run_dir, aid)
             if e.get("flag") == "skill_attestation_stale"]
    if not stale:
        return ("ERROR",
                "no execution and no skill_attestation_stale refusal")
    return ("HELD", "watcher error at the sweep re-verification denies "
                    "fail-closed (no execution)")


# ---------------------------------------------------------------------------
# p6: unattributed tool unaffected by the new check
# ---------------------------------------------------------------------------
def _p6():
    ex, ident, _log, approvals, _sp, _w, run_dir = _fresh_case({})
    r, err = _queue_http_post(ex, ident)
    if err:
        return "ERROR", err
    aid = r["approval_id"]
    done = _approve_and_sweep(ex, approvals, aid)
    if not _approved_executed(run_dir, aid):
        return ("BREAK",
                "unattributed approved record refused: %r"
                % ([e.get("flag") for e in _refusals(run_dir, aid)],))
    return ("HELD", "unattributed tools bypass the skill re-verification "
                    "cleanly")


# ---------------------------------------------------------------------------
# p7: no watcher bound — sweep behavior unchanged
# ---------------------------------------------------------------------------
def _p7():
    tmpdir = tempfile.mkdtemp(prefix="f185-", dir=TMP_BASE)
    run_dir = Path(tmpdir) / "run"
    run_dir.mkdir()
    policy = PolicyEngine(DEFAULT_POLICY)
    log = ActionLog(str(run_dir / "actions.jsonl"))
    approvals = ApprovalQueue(str(run_dir), log)
    ex = ToolExecutor(
        str(run_dir), policy, log, approvals,
        ledger_path=str(run_dir / "egress_ledger.jsonl"),
        ungoverned_ack=_UNGOVERNED_ACK)
    ident = ex.mint_identity("agent-1", "researcher", "tester")
    r, err = _queue_http_post(ex, ident)
    if err:
        return "ERROR", err
    aid = r["approval_id"]
    done = _approve_and_sweep(ex, approvals, aid)
    if not _approved_executed(run_dir, aid):
        return ("BREAK",
                "watcher-less sweep refused a healthy approval: %r"
                % ([e.get("flag") for e in _refusals(run_dir, aid)],))
    return ("HELD", "executors with no skill watcher bound keep today's "
                    "behavior")


# ---------------------------------------------------------------------------
# p8: refusal audit names both digests; record stays retriable
# ---------------------------------------------------------------------------
def _p8():
    ex, ident, _log, approvals, skill_path, _w, run_dir = _fresh_case(
        {"http_post": "weather"})
    r, err = _queue_http_post(ex, ident)
    if err:
        return "ERROR", err
    aid = r["approval_id"]
    skill_path.write_bytes(V2)
    _approve_and_sweep(ex, approvals, aid)
    stale = [e for e in _refusals(run_dir, aid)
             if e.get("flag") == "skill_attestation_stale"]
    if not stale:
        return "ERROR", "no skill_attestation_stale refusal found"
    reason = stale[0].get("reason", "")
    if D1[:12] not in reason:
        return ("BREAK",
                "refusal reason does not name the attested digest: %r"
                % (reason[:100],))
    if stale[0].get("policy_id") != "skill-continuity-execution-refused":
        return ("BREAK",
                "refusal policy_id wrong: %r"
                % (stale[0].get("policy_id"),))
    # The record stays approved-but-unexecuted (fail-safe, retriable).
    recs = [rec for rec in approvals.all() if rec.get("id") == aid]
    if not recs:
        return "ERROR", "approval record vanished"
    rec = recs[0]
    if rec.get("status") != "approved" or rec.get("executed"):
        return ("BREAK",
                "refused record not approved-but-unexecuted: %r"
                % (rec.get("status"),))
    # The re-pinned shape names BOTH digests (the fetch succeeds, so
    # the current digest is known): the plain-mutation shape above
    # cannot name the current digest because a failed check hands
    # back no bytes (fail-closed).
    ex2, ident2, _l2, approvals2, skill_path2, w2, run_dir2 = _fresh_case(
        {"http_post": "weather"})
    r2, err2 = _queue_http_post(ex2, ident2)
    if err2:
        return "ERROR", err2
    aid2 = r2["approval_id"]
    skill_path2.write_bytes(V2)
    _reviewed_repin(w2, V2)
    _approve_and_sweep(ex2, approvals2, aid2)
    stale2 = [e for e in _refusals(run_dir2, aid2)
              if e.get("flag") == "skill_attestation_stale"]
    if not stale2:
        return "ERROR", "no skill_attestation_stale on re-pinned case"
    reason2 = stale2[0].get("reason", "")
    if D1[:12] not in reason2 or D2[:12] not in reason2:
        return ("BREAK",
                "re-pinned refusal does not name both digests: %r"
                % (reason2[:120],))
    return ("HELD", "refusal audit names the attested digest (plain "
                    "mutation) or both digests (re-pinned); record "
                    "stays approved-but-unexecuted (retriable)")


_PROBES = [
    ("p1", "mutation between approval and sweep refused (red-first)", _p1),
    ("p2", "unmutated approval executes (happy path)", _p2),
    ("p3", "reviewed re-pin + new approval executes", _p3),
    ("p4", "reviewed re-pin does not rescue old approval", _p4),
    ("p5", "watcher error at sweep fails closed", _p5),
    ("p6", "unattributed tool unaffected", _p6),
    ("p7", "no watcher bound: behavior unchanged", _p7),
    ("p8", "refusal audit + retriable record", _p8),
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
        print("%s %-46s %s — %s" % (pid, title, verdict, detail))
    print("score: %d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, expected, err))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
