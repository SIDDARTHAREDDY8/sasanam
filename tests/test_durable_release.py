"""Tests for the durable release workflow (gov.release_approval).

Red-first: written BEFORE the workflow was trusted (2026-09-29). The
ceremony reuses the existing digest/charset functions
(``release_digest``, ``compute_candidate``, ``validate_release_id``);
these tests pin the DURABLE behavior: crash survival, quorum folded
from the journal, exactly-once ship, and the fail-closed verifications.

Convention: stdlib unittest only (repo standard; discovered by
tests/run_tests.py).
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.durable_approval import GrantRefused  # noqa: E402
from gov.release_approval import (  # noqa: E402
    DurableReleaseWorkflow,
    VoteRefused,
    compute_candidate,
    validate_release_id,
)


class DurableReleaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dr-"))
        code = self.tmp / "code"
        code.mkdir()
        (code / "main.py").write_text("print('release')\n", encoding="utf-8")
        (code / "lib").mkdir()
        (code / "lib" / "x.py").write_text("X = 1\n", encoding="utf-8")
        self.candidate = {
            "code_dir": str(code),
            "eval_results_path": str(self.tmp / "eval.json"),
            "sar_path": str(self.tmp / "sar.md"),
        }
        (self.tmp / "eval.json").write_text(json.dumps({"ok": True}),
                                            encoding="utf-8")
        (self.tmp / "sar.md").write_text("# SAR\n", encoding="utf-8")
        self.wf = DurableReleaseWorkflow(str(self.tmp / "rel.journal"),
                                         str(self.tmp / "outcomes"))

    def _propose(self, release_id="r1", requester="relmgr"):
        return self.wf.propose(release_id, code_dir=self.candidate["code_dir"],
                               eval_results_path=self.candidate[
                                   "eval_results_path"],
                               sar_path=self.candidate["sar_path"],
                               requester=requester)

    def _quorum(self, approval_id, voters=("appr-a", "appr-b")):
        for v in voters:
            self.wf.vote(approval_id, v, True)

    def _kw(self, **over):
        kw = {"code_dir": self.candidate["code_dir"],
              "eval_results_path": self.candidate["eval_results_path"],
              "sar_path": self.candidate["sar_path"],
              "release_id": "r1"}
        kw.update(over)
        return kw

    def _ship_kw(self, **over):
        kw = self._kw(**over)
        kw["dest_parent"] = str(self.tmp / "dest")
        return kw

    def test_propose_votes_verify_ship(self):
        aid = self._propose()
        st = self.wf.states()[aid]
        self.assertEqual(st["status"], "pending")
        expect = compute_candidate(release_id="r1", **{
            k: self.candidate[k] for k in
            ("code_dir", "eval_results_path", "sar_path")})
        self.assertEqual(st["packet_digest"], expect["release_digest"],
                         "the journaled packet digest must be the v2 "
                         "release digest")
        self._quorum(aid)
        self.assertEqual(self.wf.states()[aid]["status"], "approved")
        ok, reason = self.wf.verify(aid, **self._kw())
        self.assertTrue(ok, reason)
        self.wf.ship(aid, **self._ship_kw())
        dest = self.tmp / "dest" / "r1"
        self.assertTrue((dest / "code" / "main.py").is_file())
        self.assertTrue((dest / "RELEASE_DIGEST").is_file())
        self.assertEqual(self.wf.states()[aid]["status"], "executed")

    def test_ship_is_idempotent(self):
        aid = self._propose()
        self._quorum(aid)
        self.wf.ship(aid, **self._ship_kw())
        self.wf.ship(aid, **self._ship_kw())  # second ship: no-op, still verified
        self.assertEqual(self.wf.states()[aid]["status"], "executed")
        self.assertTrue(
            (self.tmp / "dest" / "r1" / "RELEASE_DIGEST").is_file())

    def test_reship_noop_after_evidence_cleanup(self):
        # Ship, then delete the candidate evidence (retention cleanup).
        # Re-ship must be a journal-only no-op — it must NOT re-read
        # the (now missing) evidence and fail.
        import shutil
        aid = self._propose()
        self._quorum(aid)
        self.wf.ship(aid, **self._ship_kw())
        shutil.rmtree(self.candidate["code_dir"])
        os.unlink(self.candidate["eval_results_path"])
        os.unlink(self.candidate["sar_path"])
        out = self.wf.ship(aid, **self._ship_kw())
        self.assertEqual(out["did"], [])
        self.assertEqual(self.wf.states()[aid]["status"], "executed")

    def test_concurrent_duplicate_vote_refused(self):
        from gov.durable_journal import Journal
        from gov.release_approval import RELEASE_VOTE
        aid = self._propose()
        self.wf.vote(aid, "appr-a", True)
        # Another process journals the same voter's vote through its
        # own handle: this engine's in-memory fold is now stale.
        other = Journal(str(self.tmp / "rel.journal"))
        other.append(
            RELEASE_VOTE,
            {"approval_id": aid, "voter": "appr-b",
             "approve": True, "reason": ""})
        # The pre-check passes on the stale fold; the atomic check
        # under the mutation mutex must still refuse loudly and
        # journal nothing new.
        with self.assertRaises(VoteRefused):
            self.wf.vote(aid, "appr-b", True)
        votes = [r for r in Journal(str(self.tmp / "rel.journal")).records
                 if r["type"] == RELEASE_VOTE]
        self.assertEqual(
            sum(1 for r in votes
                if r["body"].get("voter") == "appr-b"), 1)

    def test_reship_after_destination_tamper_refused(self):
        aid = self._propose()
        self._quorum(aid)
        self.wf.ship(aid, **self._ship_kw())
        # Tamper with the shipped destination, then re-ship: the
        # idempotent activity must refuse loudly, not overwrite.
        (self.tmp / "dest" / "r1" / "RELEASE_DIGEST").write_text(
            "f" * 64 + "\n", encoding="utf-8")
        with self.assertRaises(GrantRefused):
            self.wf.ship(aid, **self._ship_kw())

    def test_reship_after_destination_deleted_refused(self):
        import shutil
        aid = self._propose()
        self._quorum(aid)
        self.wf.ship(aid, **self._ship_kw())
        shutil.rmtree(self.tmp / "dest" / "r1")
        # The journal says shipped but the world diverged: fail closed,
        # do not silently re-ship.
        with self.assertRaises(GrantRefused):
            self.wf.ship(aid, **self._ship_kw())

    def test_ship_refuses_changed_bits(self):
        aid = self._propose()
        self._quorum(aid)
        # Change the bits AFTER the quorum approved.
        with open(os.path.join(self.candidate["code_dir"], "main.py"), "a",
                   encoding="utf-8") as f:
            f.write("# backdoor\n")
        ok, reason = self.wf.verify(aid, **self._kw())
        self.assertFalse(ok)
        self.assertIn("digest mismatch", reason)
        with self.assertRaises(GrantRefused):
            self.wf.ship(aid, **self._ship_kw())

    def test_ship_refuses_occupied_destination(self):
        aid = self._propose()
        self._quorum(aid)
        dest = self.tmp / "dest" / "r1"
        dest.mkdir(parents=True)
        (dest / "RELEASE_DIGEST").write_text("0" * 64 + "\n",
                                             encoding="utf-8")
        with self.assertRaises(GrantRefused):
            self.wf.ship(aid, **self._ship_kw())

    def test_single_approver_cannot_ship(self):
        aid = self._propose()
        self.wf.vote(aid, "appr-a", True)
        ok, _ = self.wf.verify(aid, **self._kw())
        self.assertFalse(ok)
        with self.assertRaises(GrantRefused):
            self.wf.ship(aid, **self._ship_kw())

    def test_one_deny_vetoes(self):
        aid = self._propose()
        self.wf.vote(aid, "appr-a", True)
        self.wf.vote(aid, "appr-b", False, reason="not ready")
        self.assertEqual(self.wf.states()[aid]["status"], "denied")
        with self.assertRaises(GrantRefused):
            self.wf.ship(aid, **self._ship_kw())

    def test_requester_cannot_vote_own_release(self):
        aid = self._propose(requester="relmgr")
        with self.assertRaises(VoteRefused):
            self.wf.vote(aid, "relmgr", True)

    def test_double_vote_refused(self):
        aid = self._propose()
        self.wf.vote(aid, "appr-a", True)
        with self.assertRaises(VoteRefused):
            self.wf.vote(aid, "appr-a", True)

    def test_vote_on_unknown_or_settled_refused(self):
        with self.assertRaises(VoteRefused):
            self.wf.vote("release-nope", "appr-a", True)
        aid = self._propose()
        self._quorum(aid)
        with self.assertRaises(VoteRefused):
            self.wf.vote(aid, "appr-c", True)

    def test_unsafe_release_id_rejected(self):
        with self.assertRaises(ValueError):
            self._propose(release_id="../evil")
        with self.assertRaises(ValueError):
            self._propose(release_id="")
        self.assertEqual(validate_release_id("r1.ok-2_x"), "r1.ok-2_x")

    def test_missing_evidence_refuses_propose(self):
        with self.assertRaises(ValueError):
            self.wf.propose("r2", code_dir=self.candidate["code_dir"],
                            eval_results_path="/nonexistent/eval.json",
                            sar_path=self.candidate["sar_path"],
                            requester="relmgr")

    def test_quorum_survives_restart(self):
        aid = self._propose()
        self.wf.vote(aid, "appr-a", True)
        # "Restart": new workflow object over the same journal.
        wf2 = DurableReleaseWorkflow(str(self.tmp / "rel.journal"),
                                     str(self.tmp / "outcomes"))
        wf2.vote(aid, "appr-b", True)
        self.assertEqual(wf2.states()[aid]["status"], "approved")
        ok, reason = wf2.verify(aid, **self._kw())
        self.assertTrue(ok, reason)

    def test_expired_release_cannot_ship(self):
        aid = self._propose()
        fire_at = next(r["body"]["fire_at"]
                       for r in self.wf.engine.journal.records
                       if r["type"] == "TimerStarted")
        self.wf.engine.drive(now=fire_at + 10)
        self.assertEqual(self.wf.states()[aid]["status"], "expired")
        with self.assertRaises(GrantRefused):
            self.wf.ship(aid, **self._ship_kw())

    def test_quorum_minimum_two(self):
        with self.assertRaises(ValueError):
            DurableReleaseWorkflow(str(self.tmp / "x.journal"),
                                   str(self.tmp / "y"), quorum=1)


if __name__ == "__main__":
    unittest.main()
