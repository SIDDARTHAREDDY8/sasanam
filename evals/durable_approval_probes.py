#!/usr/bin/env python3
"""Red-first break battery for wave-201: durable approval workflows.

The gap (pristine tree): the approval workflow is in-memory / wall-clock
driven. A kill -9 mid-decision loses the approval, duplicates the action,
or corrupts state; there is no journal, no replay, no determinism guard,
no durable timer. ``gov.durable_journal`` / ``gov.durable_approval`` /
``gov.release_approval`` do not exist on the pristine tree.

Pristine expectation: P0 BREAK (the gap), P1-P9 EXPECTED (cannot run
without the modules -- recorded, not faked green).
Fixed expectation: P0-P9 HELD.

Stdlib only. Sets GOV_DEPLOYMENT_MODE=staging at module level; verify
standalone under ``env -u GOV_DEPLOYMENT_MODE``. Honors GOV_SKIP_GREEN=1
(green check is depth-1: the adjacent unit suite only, never nested
battery mains).

Timing: uses real kill -9 and short sleeps; total runtime < 2 minutes.
"""

import importlib.util
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import probe_lines  # noqa: E402  (canonical probe-line form)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

_HAS_JOURNAL = importlib.util.find_spec("gov.durable_journal") is not None
_HAS_ENGINE = importlib.util.find_spec("gov.durable_approval") is not None
_HAS_RELEASE = importlib.util.find_spec("gov.release_approval") is not None

DRIVER_SRC = r'''
import os, sys, time
sys.path.insert(0, {repo!r})
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
from gov.durable_approval import Engine

def main():
    cmd, journal, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
    eng = Engine(journal, outdir)
    if cmd == "drive-once":
        eng.drive()
    elif cmd == "drive-block":
        while True:
            eng.drive()
            time.sleep(0.2)

main()
'''.replace("{repo!r}", repr(REPO))


def _fresh_env(tmp):
    d = os.path.join(tmp, "case")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(os.path.join(d, "out"), exist_ok=True)
    with open(os.path.join(d, "driver.py"), "w", encoding="utf-8") as f:
        f.write(DRIVER_SRC)
    return d, os.path.join(d, "j.journal"), os.path.join(d, "out")


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _drive_once(d, journal, out, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run(
        [sys.executable, os.path.join(d, "driver.py"),
         "drive-once", journal, out],
        env=e, capture_output=True, text=True, timeout=120)


def _start_block_driver(d, journal, out, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.Popen(
        [sys.executable, os.path.join(d, "driver.py"),
         "drive-block", journal, out],
        env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _kill9(proc):
    try:
        proc.kill()
        proc.wait(timeout=10)
    except Exception:
        pass


def _record_counts(journal_path):
    from gov.durable_journal import Journal
    counts = {}
    for rec in Journal(journal_path).records:
        counts[rec["type"]] = counts.get(rec["type"], 0) + 1
    return counts


# ------------------------------------------------------------------
# P0: the modules exist (the gap on pristine)
# ------------------------------------------------------------------
def p0_modules_exist(tmp):
    if not (_HAS_JOURNAL and _HAS_ENGINE and _HAS_RELEASE):
        return ("BREAK",
                "missing: journal=%s engine=%s release=%s"
                % (_HAS_JOURNAL, _HAS_ENGINE, _HAS_RELEASE))
    return ("HELD", "gov.durable_journal/durable_approval/release_approval "
                    "all importable")


# ------------------------------------------------------------------
# P1: kill -9 during pending approval -> restart -> pending exactly once
# ------------------------------------------------------------------
def p1_kill9_pending(tmp):
    if not _HAS_ENGINE:
        return ("EXPECTED", "no engine on this tree")
    from gov.durable_approval import Engine
    d, journal, out = _fresh_env(tmp)
    eng = Engine(journal, out)
    eng.request("appr-p1", requester="agent1", packet_digest="pkt-" + "0" * 60,
                action_kind="deploy", idempotency_key="idem-p1",
                ttl_seconds=3600)
    drv = _start_block_driver(d, journal, out)
    time.sleep(1.0)
    _kill9(drv)
    _drive_once(d, journal, out)  # restart: must be a no-op
    eng2 = Engine(journal, out)
    states = eng2.states()
    counts = _record_counts(journal)
    st = states.get("appr-p1", {})
    if st.get("status") != "pending":
        return ("BREAK", "status=%r after kill -9 + restart" % st.get("status"))
    if counts.get("ApprovalRequested") != 1:
        return ("BREAK", "ApprovalRequested=%r, want exactly 1" % counts)
    if counts.get("ActionExecuted", 0) != 0:
        return ("BREAK", "unexpected execution after kill -9")
    if counts.get("WorkflowStarted") != 1 or counts.get("TimerStarted") != 1:
        return ("BREAK", "request txn incomplete: %r" % counts)
    return ("HELD", "pending exactly once; 1 request txn; 0 executions")


# ------------------------------------------------------------------
# P2: kill -9 after grant, before execution -> executes exactly once
# ------------------------------------------------------------------
def p2_kill9_after_grant(tmp):
    if not _HAS_ENGINE:
        return ("EXPECTED", "no engine on this tree")
    from gov.durable_approval import Engine
    d, journal, out = _fresh_env(tmp)
    eng = Engine(journal, out)
    eng.request("appr-p2", requester="agent1", packet_digest="pkt-" + "1" * 60,
                action_kind="deploy", idempotency_key="idem-p2",
                ttl_seconds=3600)
    eng.grant("appr-p2", approver="human1")
    drv = _start_block_driver(d, journal, out)
    time.sleep(0.6)
    _kill9(drv)  # may or may not have executed yet; restart must converge
    _drive_once(d, journal, out)
    _drive_once(d, journal, out)  # second restart: must be a no-op
    counts = _record_counts(journal)
    runs_log = os.path.join(out, "side_effect_runs.log")
    runs = open(runs_log).read().strip().splitlines() if os.path.exists(runs_log) else []
    done_path = os.path.join(out, "idem-p2.done")
    if counts.get("ActionExecuted", 0) != 1:
        return ("BREAK", "ActionExecuted=%r, want 1" % counts.get("ActionExecuted"))
    if not os.path.exists(done_path):
        return ("BREAK", "idempotent outcome file missing")
    body = _read_json(done_path)
    if body.get("outcome") != "ACTION_PERFORMED" or body.get("idempotency_key") != "idem-p2":
        return ("BREAK", "outcome file not deterministic: %r" % body)
    # The side effect itself may have run 1x (at-least-once engine); the
    # OBSERVABLE outcome must be exactly-once.
    return ("HELD", "1 ActionExecuted; outcome file deterministic; "
                    "2nd restart no-op (side-effect runs: %d)" % len(runs))


# ------------------------------------------------------------------
# P3: crash between side effect and journal record -> re-executes,
#     observable outcome still exactly once (honest at-least-once)
# ------------------------------------------------------------------
def p3_crash_after_side_effect(tmp):
    if not _HAS_ENGINE:
        return ("EXPECTED", "no engine on this tree")
    from gov.durable_approval import Engine
    d, journal, out = _fresh_env(tmp)
    eng = Engine(journal, out)
    eng.request("appr-p3", requester="agent1", packet_digest="pkt-" + "2" * 60,
                action_kind="deploy", idempotency_key="idem-p3",
                ttl_seconds=3600)
    eng.grant("appr-p3", approver="human1")
    r = _drive_once(d, journal, out,
                    env={"DURABLE_CRASH_AFTER_SIDE_EFFECT": "1"})
    if r.returncode != 137:
        return ("BREAK", "no simulated crash (rc=%d)" % r.returncode)
    # Restart: journal honestly shows claimed-but-unexecuted; re-executes.
    _drive_once(d, journal, out)
    counts = _record_counts(journal)
    done_path = os.path.join(out, "idem-p3.done")
    if counts.get("ActionExecuted", 0) != 1:
        return ("BREAK", "ActionExecuted=%r after recovery" % counts)
    if not os.path.exists(done_path):
        return ("BREAK", "outcome file missing after recovery")
    body = _read_json(done_path)
    if body.get("idempotency_key") != "idem-p3":
        return ("BREAK", "outcome file corrupted: %r" % body)
    return ("HELD", "re-executed after crash; outcome exactly-once "
                    "(idempotent action); 1 ActionExecuted")

# ------------------------------------------------------------------
# P4: decision-code skew -> loud block, journal byte-identical
# ------------------------------------------------------------------
def p4_code_skew_blocked(tmp):
    if not _HAS_ENGINE:
        return ("EXPECTED", "no engine on this tree")
    from gov.durable_approval import Engine, NonDeterministicReplayError
    d, journal, out = _fresh_env(tmp)
    eng = Engine(journal, out)
    eng.request("appr-p4", requester="agent1", packet_digest="pkt-" + "3" * 60,
                action_kind="deploy", idempotency_key="idem-p4",
                ttl_seconds=3600)
    before = open(journal, "rb").read()
    before_sha = hashlib.sha256(before).hexdigest()
    # Simulate a deploy with different decision code: the pinned version
    # no longer matches. Must BLOCK loudly, journal untouched (read-only).
    os.environ["GOV_DURABLE_CODE_VERSION"] = "sha256:deadbeefdeadbeef"
    try:
        try:
            Engine(journal, out)
            return ("BREAK", "skewed replay NOT blocked")
        except NonDeterministicReplayError:
            pass
    finally:
        del os.environ["GOV_DURABLE_CODE_VERSION"]
    after_sha = hashlib.sha256(open(journal, "rb").read()).hexdigest()
    if after_sha != before_sha:
        return ("BREAK", "journal mutated by blocked replay")
    return ("HELD", "NonDeterministicReplayError; journal sha256 identical")


# ------------------------------------------------------------------
# P5: expiry timer fires across a restart; grant-after-expiry refused
# ------------------------------------------------------------------
def p5_timer_expiry_across_restart(tmp):
    if not _HAS_ENGINE:
        return ("EXPECTED", "no engine on this tree")
    from gov.durable_approval import Engine, GrantRefused
    d, journal, out = _fresh_env(tmp)
    eng = Engine(journal, out)
    eng.request("appr-p5", requester="agent1", packet_digest="pkt-" + "4" * 60,
                action_kind="deploy", idempotency_key="idem-p5",
                ttl_seconds=2)
    time.sleep(3.0)  # driver dead across the deadline
    _drive_once(d, journal, out)
    eng2 = Engine(journal, out)
    st = eng2.states().get("appr-p5", {})
    if st.get("status") != "expired":
        return ("BREAK", "status=%r after deadline, want expired"
                % st.get("status"))
    try:
        eng2.grant("appr-p5", approver="human1")
        return ("BREAK", "grant-after-expiry NOT refused")
    except GrantRefused:
        pass
    counts = _record_counts(journal)
    if counts.get("TimerFired") != 1:
        return ("BREAK", "TimerFired=%r, want 1" % counts)
    return ("HELD", "expired across restart; grant-after-expiry refused")


# ------------------------------------------------------------------
# P6: request + timer durable in ONE atomic transaction
# ------------------------------------------------------------------
def p6_request_timer_atomic(tmp):
    if not _HAS_JOURNAL:
        return ("EXPECTED", "no journal on this tree")
    from gov.durable_journal import Journal
    d, journal, out = _fresh_env(tmp)
    if _HAS_ENGINE:
        from gov.durable_approval import Engine
        eng = Engine(journal, out)
        eng.request("appr-p6", requester="agent1",
                    packet_digest="pkt-" + "5" * 60,
                    action_kind="deploy", idempotency_key="idem-p6",
                    ttl_seconds=3600)
    recs = Journal(journal).records
    types = [r["type"] for r in recs[:3]]
    if types != ["WorkflowStarted", "ApprovalRequested", "TimerStarted"]:
        return ("BREAK", "request records not atomic/ordered: %r" % types)
    txns = {r["txn"] for r in recs[:3]}
    if len(txns) != 1 or None in txns:
        return ("BREAK", "request records lack a shared txn id: %r" % txns)
    seqs = [r["seq"] for r in recs[:3]]
    if seqs != [0, 1, 2]:
        return ("BREAK", "request records not adjacent: %r" % seqs)
    return ("HELD", "request txn: 3 adjacent records, shared txn id")


# ------------------------------------------------------------------
# P7: torn final line -> TornTailError; explicit recovery restores
# ------------------------------------------------------------------
def p7_torn_tail_recovery(tmp):
    if not _HAS_JOURNAL:
        return ("EXPECTED", "no journal on this tree")
    from gov.durable_journal import (Journal, TornTailError,
                                     recover_torn_tail, verify_journal)
    d, journal, out = _fresh_env(tmp)
    j = Journal(journal)
    j.append("WorkflowStarted", {"approval_id": "t"})
    j.append("ApprovalRequested", {"approval_id": "t"})
    tip_before = j.tip
    # Simulate a crash mid-fsync: torn partial line, no trailing newline.
    with open(journal, "ab") as f:
        f.write(b'{"seq": 2, "prev": "abc')
        f.flush()
    try:
        Journal(journal)
        return ("BREAK", "torn tail NOT detected")
    except TornTailError as e:
        torn_tip = e.tip_hash
    if torn_tip != tip_before:
        return ("BREAK", "TornTailError carries wrong tip")
    # Operator recovery: verify-then-truncate, never silent.
    recovered_tip = recover_torn_tail(journal)
    if recovered_tip != tip_before:
        return ("BREAK", "recovery returned wrong tip")
    ok, count = verify_journal(journal)
    if not ok or count != 2:
        return ("BREAK", "post-recovery journal invalid: ok=%r n=%r"
                % (ok, count))
    return ("HELD", "torn tail detected; explicit recovery restored tip")


# ------------------------------------------------------------------
# P8: two drivers racing -> file locking serializes, no corruption
# ------------------------------------------------------------------
def p8_two_drivers_race(tmp):
    if not _HAS_ENGINE:
        return ("EXPECTED", "no engine on this tree")
    from gov.durable_approval import Engine
    from gov.durable_journal import verify_journal
    d, journal, out = _fresh_env(tmp)
    eng = Engine(journal, out)
    eng.request("appr-p8", requester="agent1", packet_digest="pkt-" + "6" * 60,
                action_kind="deploy", idempotency_key="idem-p8",
                ttl_seconds=3600)
    eng.grant("appr-p8", approver="human1")
    # True concurrency on the CLAIM path: launch both drivers BEFORE
    # either has executed. Both see approved + no ActionExecuted, both
    # journal an ActionClaimed, the latest-claim election picks the
    # runner. Honest at-least-once: the two drivers may BOTH run the
    # side effect in the overlap window — what must hold is exactly one
    # journaled ActionExecuted and one idempotent observable outcome.
    # (A previous version of this probe drove once first, so the race
    # below only ever saw an already-executed workflow and proved
    # nothing about the claim path.)
    p_a = subprocess.Popen(
        [sys.executable, os.path.join(d, "driver.py"),
         "drive-once", journal, out],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p_b = subprocess.Popen(
        [sys.executable, os.path.join(d, "driver.py"),
         "drive-once", journal, out],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p_a.wait(timeout=120)
    p_b.wait(timeout=120)
    if p_a.returncode != 0 or p_b.returncode != 0:
        return ("BREAK", "driver crashed under race: %r %r"
                % (p_a.returncode, p_b.returncode))
    ok, _ = verify_journal(journal)
    if not ok:
        return ("BREAK", "journal corrupted under concurrent drivers")
    counts = _record_counts(journal)
    if counts.get("ActionClaimed", 0) < 1:
        return ("BREAK", "no ActionClaimed journaled under race")
    if counts.get("ActionExecuted", 0) != 1:
        return ("BREAK", "ActionExecuted=%r under race (want exactly 1)"
                % counts.get("ActionExecuted"))
    done_path = os.path.join(out, "idem-p8.done")
    if not os.path.exists(done_path):
        return ("BREAK", "outcome file missing under race")
    try:
        with open(done_path, encoding="utf-8") as f:
            outcome = json.load(f)
    except Exception as e:  # noqa: BLE001
        return ("BREAK", "outcome file unreadable under race: %r" % e)
    if outcome.get("outcome") != "ACTION_PERFORMED" or \
            outcome.get("idempotency_key") != "idem-p8":
        return ("BREAK", "outcome file has wrong content under race")
    return ("HELD", "concurrent drivers raced the claim; 1 ActionExecuted; "
                    "journal verifies; idempotent outcome intact")


# ------------------------------------------------------------------
# P9: WorkflowStarted cross-references the audit log by digest
# ------------------------------------------------------------------
def p9_audit_cross_reference(tmp):
    if not (_HAS_ENGINE and _HAS_JOURNAL):
        return ("EXPECTED", "no engine/journal on this tree")
    from gov.durable_approval import Engine
    from gov.durable_journal import Journal
    d, journal, out = _fresh_env(tmp)
    appended = []

    def fake_audit_append(event):
        # Stand-in for ActionLog.append: returns the stored entry with
        # its chain hash, like the real log does.
        entry = dict(event)
        entry["hash"] = hashlib.sha256(
            json.dumps(entry, sort_keys=True).encode()).hexdigest()
        appended.append(entry)
        return entry

    eng = Engine(journal, out, audit_append=fake_audit_append)
    eng.request("appr-p9", requester="agent1", packet_digest="pkt-" + "7" * 60,
                action_kind="deploy", idempotency_key="idem-p9",
                ttl_seconds=3600)
    recs = Journal(journal).records
    started = [r for r in recs if r["type"] == "WorkflowStarted"][0]
    if len(appended) != 1 or appended[0].get("kind") != "durable_workflow_started":
        return ("BREAK", "audit log not appended at request time")
    if started["body"].get("audit_hash") != appended[0]["hash"]:
        return ("BREAK", "WorkflowStarted does not bind the audit digest")
    if started["body"].get("packet_digest") != "pkt-" + "7" * 60:
        return ("BREAK", "WorkflowStarted missing packet digest")
    return ("HELD", "audit entry digest bound in WorkflowStarted")


PROBES = [
    ("P0", "modules exist (the gap)", p0_modules_exist),
    ("P1", "kill -9 pending -> pending exactly once", p1_kill9_pending),
    ("P2", "kill -9 after grant -> executes exactly once", p2_kill9_after_grant),
    ("P3", "crash after side effect -> outcome exactly once", p3_crash_after_side_effect),
    ("P4", "code skew -> loud block, journal intact", p4_code_skew_blocked),
    ("P5", "expiry timer across restart; grant refused", p5_timer_expiry_across_restart),
    ("P6", "request+timer one atomic txn", p6_request_timer_atomic),
    ("P7", "torn tail -> TornTailError + recovery", p7_torn_tail_recovery),
    ("P8", "two drivers race -> serialized, no corruption", p8_two_drivers_race),
    ("P9", "audit-log cross-reference by digest", p9_audit_cross_reference),
]


def main():
    tmp = tempfile.mkdtemp(prefix="durable_probes_")
    results = []
    try:
        for pid, name, fn in PROBES:
            try:
                status, detail = fn(tmp)
            except Exception as exc:  # noqa: BLE001
                status, detail = ("ERROR", "%r" % exc)
            results.append((pid, name, status, detail))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    held = brk = expected = errors = 0
    mapped = []
    for pid, name, status, detail in results:
        # Wave-316 lane-3 decision (D1): EXPECTED -> HELD with an
        # "expected: " prefix (pinned limitation -- P1-P9 cannot run
        # their crash-recovery paths on this tree; exit-neutral here).
        note = "%s -- %s" % (name, detail)
        if status == "HELD":
            held += 1
            mapped.append((pid, "HELD", note))
        elif status == "BREAK":
            brk += 1
            mapped.append((pid, "BREAK", note))
        elif status == "EXPECTED":
            expected += 1
            mapped.append((pid, "HELD", "expected: " + note))
        else:
            errors += 1
            mapped.append((pid, "ERROR", note))
    probe_lines.emit(mapped)
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        mapped, brk, held + expected, errors)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR"
          % (brk, held + expected, errors))
    print("summary: %d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, expected, errors))
    green_ok = _green_check()
    if errors or not green_ok:
        return 1
    return 0


def _green_check():
    """Depth-1 green check: the adjacent unit suites only (never nested
    battery mains). Honors GOV_SKIP_GREEN by recording a skip; skips
    gracefully on trees where the wave-201 suite does not exist."""
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    suites = ["tests.test_durable_journal", "tests.test_durable_approval",
              "tests.test_durable_release"]
    missing = [s for s in suites
               if importlib.util.find_spec(s) is None]
    if missing:
        print("GREEN CHECK: skipped (absent on this tree: %s)"
              % ", ".join(missing))
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, "-m", "unittest"] + suites,
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
    tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
    print("GREEN CHECK unit suites: rc=%d %s"
          % (r.returncode, " | ".join(tail)))
    return r.returncode == 0


if __name__ == "__main__":
    sys.exit(main())
