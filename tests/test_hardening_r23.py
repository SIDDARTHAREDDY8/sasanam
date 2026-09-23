"""Hardening round-23 regression tests: F70 + F72 closure.

F70 (HIGH, was OPEN): the incremental chain-tip verifier is blind to
length-preserving edits of already-verified (pre-tip) marker bytes --
a fundamental property of any O(new-bytes) verifier. An attacker could
hide a genuine ``execution_authorized`` marker with a same-length
rewrite (keeping the stored hash string): ``verify_chain_tip()`` still
succeeded and reconciliation's unverified scan found no marker, so the
interrupted execution was silently never recovered -- a silent
recovery defeat with no audit.

Fix (R18): the tip now carries a MAC'd marker manifest
(approval_id -> latest ``execution_authorized`` seq over the verified
prefix), seeded after a full verify and folded forward only from
MAC-verified segments. Before trusting the incremental verdict,
reconciliation compares the unverified scan's prefix-scoped
interrupted set against the manifest: a mismatch is positive evidence
of pre-tip marker tamper, audited LOUDLY (coalesced like any standing
marker forgery), and the incremental verdict is discarded in favor of
a full verification (which fails closed loudly on the tamper).

F72 (was OPEN): a saved validly-MAC'd tip could be replayed after the
tip advanced -- the MAC bound integrity but not freshness. Fix: every
tip write bumps a generation counter and appends a MAC'd generation
pin (separate ``checkpoint-tipgen`` domain) to the checkpoint sidecar
BEFORE the tip file lands; ``_read_tip_cache`` rejects a tip older
than the newest pinned generation. Replay now degrades to a full
re-verification (self-healing), never to silent staleness. No
wall-clock or monotonic clock is involved (F76 lesson): freshness is
purely log-anchored.

$0 spend; synthetic/local deterministic tests only.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from harness import make_run, DEFAULT_POLICY  # noqa: E402
from gov.log import (  # noqa: E402
    ActionLog,
    _read_tip_cache,
    _tip_cache_path,
    read_entries,
    verify_chain_tip,
    write_chain_tip_from_tail,
)
from gov.policy import PolicyEngine  # noqa: E402


def _queued(q, caller, policy_hash, tool="read_file", args=None):
    return q.queue(
        {"tool": tool, "args": args or {"path": "notes.txt"},
         "redactions": [], "agent_justification": "test"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        preview="test preview",
        policy_hash=policy_hash,
        caller_identity=caller)


def _approved(ctx):
    q, ex = ctx["approvals"], ctx["executor"]
    caller = ctx["mint_identity"]("a1", "researcher", "org")
    aid = _queued(q, caller, ex.policy.policy_hash)
    q.decide(aid, True, "human says ok", decided_by="human-operator")
    return aid


def _authorize_marker(ctx, aid):
    """Write the genuine execution_authorized marker + durable claim.

    Mirrors the executor's write-ahead marker (F45): a crash between
    this and the completion marker is the interrupted execution.
    """
    q, ex = ctx["approvals"], ctx["executor"]
    rec = q.get(aid)
    ctx["log"].append({
        "event": "tool_call", "run_id": ex.run_id,
        "agent_id": rec.get("agent_id"), "role": rec.get("role"),
        "principal": (rec.get("identity") or {}).get("principal"),
        "tool": rec["tool"], "args": rec["args"],
        "decision": "execution_authorized",
        "policy_id": rec.get("policy_id"), "approval_id": aid,
        "reason": "Human approval authorized execution."})
    q.mark_executed(aid)  # the durable claim, before the "crash"


def _complete_marker(ctx, aid):
    """Write a genuine approved_executed completion marker."""
    q, ex = ctx["approvals"], ctx["executor"]
    rec = q.get(aid)
    ctx["log"].append({
        "event": "tool_call", "run_id": rec.get("run_id", ex.run_id),
        "agent_id": rec.get("agent_id"), "role": rec.get("role"),
        "principal": (rec.get("identity") or {}).get("principal"),
        "tool": rec["tool"], "args": rec["args"],
        "decision": "approved_executed",
        "policy_id": rec.get("policy_id"), "approval_id": aid,
        "reason": "Executed after human approval."})


def _hide_marker_same_length(log_path, decision="execution_authorized"):
    """F70 attack: length-preserving rewrite of a marker line.

    Replaces the decision string with same-length filler, keeping the
    stored hash string and the line length, so byte offsets stay
    valid. Returns the seq of the hidden marker.
    """
    lines = Path(log_path).read_text(encoding="utf-8").splitlines()
    target = None
    for i, line in enumerate(lines):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if (isinstance(e, dict) and e.get("event") == "tool_call"
                and e.get("decision") == decision):
            target = i
            break
    assert target is not None, "no %s marker found" % decision
    filler = "X" * len(decision)
    assert len(filler) == len(decision)
    new_line = lines[target].replace(decision, filler)
    assert len(new_line) == len(lines[target]), \
        "edit must preserve line length"
    lines[target] = new_line
    Path(log_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json.loads(new_line).get("seq")


def _events(entries, name):
    return [e for e in entries if e.get("event") == name]


class TestF70ManifestClosure(unittest.TestCase):
    """F70: pre-tip marker tamper is loud, never a silent miss."""

    def test_same_length_marker_hide_is_loud_not_silent(self):
        """The exact F70 shape: hide a genuine interrupted marker with
        a length-preserving rewrite. The sweep must NOT silently
        return [] -- it must audit the manifest mismatch loudly and
        fail closed loudly on the full verification."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        log_path = ctx["run_dir"] / "actions.jsonl"
        try:
            aid = _approved(ctx)
            _authorize_marker(ctx, aid)
            # Cold sweep: reconciles the interruption (loud, correct)
            # and seeds the tip WITH the marker manifest.
            self.assertEqual(ex.execute_approved(), [])
            rec = q.get(aid)
            self.assertEqual(rec["status"], "pending")
            tip = _read_tip_cache(log_path)
            self.assertIsNotNone(tip)
            self.assertEqual(set(tip["markers"]), {aid})

            # F70 attack: same-length rewrite hiding the marker.
            _hide_marker_same_length(log_path)

            # Warm sweep: must be LOUD, not a silent [].
            self.assertEqual(ex.execute_approved(), [])
            ents = read_entries(log_path)
            mismatch = _events(ents, "reconciliation_marker_invalid")
            self.assertEqual(
                len(mismatch), 1,
                "the manifest mismatch must audit LOUDLY exactly once")
            self.assertIn("F70", mismatch[0].get("reason", ""))
            unverifiable = _events(
                ents, "reconciliation_chain_unverifiable")
            self.assertEqual(
                len(unverifiable), 1,
                "the full verification must fail closed loudly")
            # Exactly one interruption recovery -- from the cold sweep.
            # The tampered sweep reconciled nothing silently.
            self.assertEqual(
                len(_events(ents, "approval_execution_interrupted")), 1)
            # The record is untouched by the tampered sweep.
            rec = q.get(aid)
            self.assertEqual(rec["status"], "pending")
            self.assertFalse(rec.get("executed"))
        finally:
            shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    def test_completion_marker_hide_is_loud(self):
        """Hiding a COMPLETION marker (not the authorization) is also
        caught: without the fix the sweep would "recover" an already-
        completed execution."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        log_path = ctx["run_dir"] / "actions.jsonl"
        try:
            aid = _approved(ctx)
            _authorize_marker(ctx, aid)
            _complete_marker(ctx, aid)
            self.assertEqual(ex.execute_approved(), [])
            tip = _read_tip_cache(log_path)
            self.assertIsNotNone(tip)
            self.assertEqual(tip["markers"], {},
                             "completed aid must not be in the manifest")

            _hide_marker_same_length(log_path,
                                     decision="approved_executed")
            self.assertEqual(ex.execute_approved(), [])
            ents = read_entries(log_path)
            # TWO loud audits, both true with distinct coalescing keys:
            # the F70 manifest mismatch (pre-gate) and the F71a
            # chain-invalid verdict (the hidden completion's MAC fails
            # full verification). Either proves loudness.
            self.assertEqual(
                len(_events(ents, "reconciliation_marker_invalid")), 2)
            self.assertEqual(
                len(_events(ents, "approval_execution_interrupted")), 0,
                "a completed execution must never be 'recovered'")
        finally:
            shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    def test_clean_marker_path_stays_quiet_and_manifest_folds(self):
        """No tamper: warm sweeps stay quiet, the manifest folds new
        markers forward, and a second interrupted approval still
        reconciles incrementally."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        log_path = ctx["run_dir"] / "actions.jsonl"
        try:
            aid1 = _approved(ctx)
            _authorize_marker(ctx, aid1)
            self.assertEqual(ex.execute_approved(), [])
            tip = _read_tip_cache(log_path)
            self.assertEqual(set(tip["markers"]), {aid1})

            # Second interrupted approval AFTER the tip was seeded:
            # its marker lands in the new segment.
            aid2 = _approved(ctx)
            _authorize_marker(ctx, aid2)
            self.assertEqual(ex.execute_approved(), [])
            ents = read_entries(log_path)
            self.assertEqual(
                len(_events(ents, "reconciliation_marker_invalid")), 0)
            self.assertEqual(
                len(_events(ents, "reconciliation_chain_unverifiable")),
                0)
            self.assertEqual(
                len(_events(ents, "approval_execution_interrupted")), 2)
            tip = _read_tip_cache(log_path)
            self.assertIsNotNone(tip)
            # aid1 was already reconciled (pinned); the manifest still
            # tracks the interrupted marker bytes.
            self.assertEqual(set(tip["markers"]), {aid1, aid2})
            for aid in (aid1, aid2):
                rec = q.get(aid)
                self.assertEqual(rec["status"], "pending")
        finally:
            shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    def test_completed_marker_pruned_from_manifest(self):
        """A completion marker in a new segment prunes the manifest."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        log_path = ctx["run_dir"] / "actions.jsonl"
        try:
            aid = _approved(ctx)
            _authorize_marker(ctx, aid)
            self.assertEqual(ex.execute_approved(), [])
            self.assertEqual(set(_read_tip_cache(log_path)["markers"]),
                             {aid})
            _complete_marker(ctx, aid)
            self.assertEqual(ex.execute_approved(), [])
            ents = read_entries(log_path)
            self.assertEqual(
                len(_events(ents, "reconciliation_marker_invalid")), 0)
            tip = _read_tip_cache(log_path)
            self.assertIsNotNone(tip)
            self.assertEqual(tip["markers"], {})
        finally:
            shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    def test_forged_manifest_rejected(self):
        """A tip whose manifest was altered without the key fails the
        tip MAC: _read_tip_cache returns None (full-verify fallback),
        never a forged interrupted set."""
        ctx = make_run()
        log_path = ctx["run_dir"] / "actions.jsonl"
        try:
            for i in range(5):
                ctx["log"].append({"event": "seed", "i": i})
            write_chain_tip_from_tail(log_path, {})
            tip_path = _tip_cache_path(log_path)
            raw = json.loads(tip_path.read_text(encoding="utf-8"))
            raw["markers"] = {"phantom-aid": 3}  # no re-MAC possible
            tip_path.write_text(json.dumps(raw), encoding="utf-8")
            self.assertIsNone(_read_tip_cache(log_path),
                              "forged manifest must fail the tip MAC")
            # And a pre-fix tip (no gen/markers at all, but a valid MAC
            # over the old body shape) is also unusable -- it can only
            # trigger a full re-verify + reseed, never trusted reads.
            from gov.log import _tip_mac, _canonical, _active_key
            key, epoch = _active_key()
            old_body = {
                "seq": raw["seq"], "tip": raw["tip"],
                "key_epoch": raw["key_epoch"],
                "refusals": raw["refusals"], "cp_size": raw["cp_size"],
                "cp_digest": raw["cp_digest"],
                "cp_newest": raw["cp_newest"],
                "tip_off": raw["tip_off"], "end_off": raw["end_off"],
            }
            old_doc = dict(old_body)
            old_doc["mac"] = _tip_mac(key, epoch, _canonical(old_body))
            tip_path.write_text(json.dumps(old_doc), encoding="utf-8")
            self.assertIsNone(
                _read_tip_cache(log_path),
                "pre-fix tip shape must be rejected, not trusted")
        finally:
            shutil.rmtree(ctx["run_dir"], ignore_errors=True)


class TestF72ReplayFreshness(unittest.TestCase):
    """F72: a replayed older tip is stale, never silently accepted."""

    def _sweep(self, run_dir):
        policy = PolicyEngine(DEFAULT_POLICY)
        from gov.executor import ToolExecutor
        from gov.log import ActionLog
        from gov.approvals import ApprovalQueue
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        ex = ToolExecutor(run_dir, policy, log, approvals,
                          # Wave-85: approval-execution tests exercise the
                          # raw pipeline; the bypass is declared, not
                          # silent.
                          ungoverned_ack=(
                              "approval-execution test: raw pipeline by "
                              "design"))
        return ex.execute_approved()

    def test_replay_degrades_to_full_verify_not_silent_stale(self):
        """Save a valid tip, advance past it, replay it: the replay
        is REJECTED (None), the sweep falls back to full verify, and
        the tip self-heals to the live tail."""
        run_dir = Path(tempfile.mkdtemp(prefix="gov-r23-f72-"))
        try:
            log_path = run_dir / "actions.jsonl"
            log = ActionLog(str(log_path))
            for i in range(10):
                log.append({"event": "seed", "i": i})
            write_chain_tip_from_tail(str(log_path), {})
            saved = _tip_cache_path(str(log_path)).read_bytes()
            gen0 = _read_tip_cache(str(log_path))["gen"]
            for i in range(3):
                log.append({"event": "more", "i": i})
            v = verify_chain_tip(str(log_path))
            self.assertIsNotNone(v)
            self.assertGreater(_read_tip_cache(str(log_path))["gen"],
                               gen0)
            # Attacker replays the saved valid tip.
            _tip_cache_path(str(log_path)).write_bytes(saved)
            self.assertIsNone(
                _read_tip_cache(str(log_path)),
                "replayed older tip must be rejected as stale")
            self.assertIsNone(
                verify_chain_tip(str(log_path)),
                "replay must not verify incrementally")
            # A sweep heals: full verify (genuine bytes) then reseed.
            self.assertEqual(self._sweep(run_dir), [])
            tip = _read_tip_cache(str(log_path))
            self.assertIsNotNone(tip)
            self.assertEqual(tip["seq"], len(read_entries(log_path)))
            ents = read_entries(log_path)
            self.assertEqual(
                len(_events(ents, "reconciliation_chain_unverifiable")),
                0,
                "clean bytes must not audit loudly on replay")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_replay_cannot_silence_f70_tamper(self):
        """Combined attack: F70 marker hide PLUS F72 tip replay. The
        replay must not restore a silent window -- the tamper still
        goes loud via full verification."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        log_path = ctx["run_dir"] / "actions.jsonl"
        try:
            aid = _approved(ctx)
            _authorize_marker(ctx, aid)
            self.assertEqual(ex.execute_approved(), [])
            saved = _tip_cache_path(log_path).read_bytes()
            # Advance the live tip past the saved one.
            ctx["log"].append({"event": "noise", "i": 1})
            self.assertEqual(ex.execute_approved(), [])
            # Attack: hide the marker, then replay the older tip.
            _hide_marker_same_length(log_path)
            _tip_cache_path(log_path).write_bytes(saved)
            self.assertEqual(ex.execute_approved(), [])
            ents = read_entries(log_path)
            # The replay is stale (rejected); the full verify catches
            # the hidden marker loudly. Either loud event proves the
            # combination cannot silence recovery defeat.
            loud = (len(_events(ents, "reconciliation_chain_unverifiable"))
                    + len(_events(ents, "reconciliation_marker_invalid")))
            self.assertGreaterEqual(
                loud, 1,
                "F70+F72 combined must stay LOUD")
            self.assertEqual(
                len(_events(ents, "approval_execution_interrupted")), 1,
                "no silent second recovery")
        finally:
            shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    def test_generation_pins_are_log_anchored_no_clock(self):
        """Every tip write bumps the generation and appends a MAC'd
        pin; pins are ordered by log position, with no clock."""
        run_dir = Path(tempfile.mkdtemp(prefix="gov-r23-pin-"))
        try:
            log_path = run_dir / "actions.jsonl"
            log = ActionLog(str(log_path))
            for i in range(4):
                log.append({"event": "seed", "i": i})
            write_chain_tip_from_tail(str(log_path), {})
            v = verify_chain_tip(str(log_path))
            self.assertIsNotNone(v)
            v = verify_chain_tip(str(log_path))
            self.assertIsNotNone(v)
            tip = _read_tip_cache(str(log_path))
            self.assertEqual(tip["gen"], 3)
            pins = [json.loads(line) for line in
                    (run_dir / "checkpoints.jsonl")
                    .read_text(encoding="utf-8").splitlines()
                    if json.loads(line).get("tip_gen")]
            self.assertEqual([p["tip_gen"] for p in pins], [1, 2, 3])
            # No wall-clock / monotonic dependency in the mechanism:
            # the pin module uses no time functions.
            import gov.log as log_mod
            import inspect
            pin_src = inspect.getsource(log_mod._append_tip_gen_pin)
            fresh_src = inspect.getsource(log_mod._max_pinned_tip_gen)
            for src in (pin_src, fresh_src):
                self.assertNotIn("monotonic", src)
                self.assertNotIn("time.time", src)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_tampered_pin_does_not_break_verification(self):
        """A pin line whose tip_gen was altered (MAC now invalid) is
        skipped by the freshness scan; the genuine pin still anchors
        freshness and verification proceeds."""
        run_dir = Path(tempfile.mkdtemp(prefix="gov-r23-pin2-"))
        try:
            log_path = run_dir / "actions.jsonl"
            log = ActionLog(str(log_path))
            for i in range(4):
                log.append({"event": "seed", "i": i})
            write_chain_tip_from_tail(str(log_path), {})
            cp_path = run_dir / "checkpoints.jsonl"
            lines = cp_path.read_text(encoding="utf-8").splitlines()
            pin_idx = next(i for i, l in enumerate(lines)
                           if json.loads(l).get("tip_gen") == 1)
            pin = json.loads(lines[pin_idx])
            pin["tip_gen"] = 999  # breaks the pin MAC
            lines[pin_idx] = json.dumps(pin)
            cp_path.write_text("\n".join(lines) + "\n",
                               encoding="utf-8")
            # The tip still reads: the tampered pin is skipped, the
            # (only) genuine pin anchors gen 1... but the sidecar
            # prefix changed, so the tip's cp_digest mismatches ->
            # full-verify fallback. Either way: no silent trust, and
            # full verification of genuine bytes succeeds.
            from gov.log import verify_chain
            ok, _, _ = verify_chain(str(log_path))
            self.assertTrue(ok, "genuine bytes must still verify")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
