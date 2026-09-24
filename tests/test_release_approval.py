"""Tests for the pre-release approval / licensing primitive.

Seams under test: gov.release_approval's public functions (digest
builders, propose_release, record_release_vote, verify_release,
ship_release) exercised through the REAL approval queue and audit log
via the test harness — no mocks of the queue or the log.

The break-first battery (evals/release_approval_break_battery.py)
covers the attack probes; these tests pin the durable behavior.
"""

import hashlib
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

from harness import make_run
from gov import release_approval as ra
from gov.log import read_entries

ELIGIBLE = ["ra-alice", "ra-bob", "ra-carol"]


def _candidate(tag, tamper=b""):
    root = Path(tempfile.mkdtemp(prefix="ra-cand-"))
    code = root / "code"
    code.mkdir()
    (code / "main.py").write_bytes(b"# %s\nprint('ship')\n" % tag.encode())
    (code / "lib.py").write_bytes(b"VERSION = %r\n" % tag + tamper)
    (root / "eval_results.json").write_text(
        json.dumps({"release": tag, "pass": True}), encoding="utf-8")
    (root / "sar.md").write_text("# SAR\n\nrelease %s: PASS\n" % tag,
                                 encoding="utf-8")
    return root


def _paths(cand, release_id="rel-t"):
    paths = {
        "code_dir": str(cand / "code"),
        "eval_results_path": str(cand / "eval_results.json"),
        "sar_path": str(cand / "sar.md"),
    }
    if release_id is not None:
        paths["release_id"] = release_id
    return paths


def _ship_kwargs(cand, anchor):
    # ship_release takes no release_id: the record's MAC-bound args are
    # authoritative; the caller never supplies one.
    return {
        "code_dir": str(cand / "code"),
        "eval_results_path": str(cand / "eval_results.json"),
        "sar_path": str(cand / "sar.md"),
        "dest_dir": str(anchor),
    }


class _Ctx:
    """One isolated run with a release approval proposed + 2 votes."""

    def __init__(self, tag="t", eligible=ELIGIBLE, release_id="rel-t"):
        self.ctx = make_run()
        self.queue = self.ctx["approvals"]
        self.executor = self.ctx["executor"]
        self.cand = _candidate(tag)
        self.approval_id = ra.propose_release(
            self.queue, self.executor,
            eligible_principals=eligible, **_paths(self.cand, release_id))

    def voter(self, principal):
        return self.executor.mint_identity("v-%s" % principal, "voter",
                                           principal)

    def vote(self, principal, approve=True):
        return ra.record_release_vote(
            self.queue, self.approval_id, self.voter(principal), approve,
            reason="reviewed evidence for %s" % principal)


class TestDigests(unittest.TestCase):
    def test_tree_digest_deterministic(self):
        cand = _candidate("det")
        self.assertEqual(ra.tree_digest(str(cand / "code")),
                         ra.tree_digest(str(cand / "code")))

    def test_tree_digest_matches_independent_recomputation(self):
        cand = _candidate("ind")
        files = {}
        for p in sorted((cand / "code").rglob("*")):
            if p.is_file() and not p.is_symlink():
                files[p.relative_to(cand / "code").as_posix()] = \
                    p.read_bytes()
        h = hashlib.sha256(b"agent-governance/release/v1\x00tree/v1\x00")
        for rel in sorted(files):
            rel_b = rel.encode("utf-8")
            h.update(len(rel_b).to_bytes(4, "big"))
            h.update(rel_b)
            h.update(hashlib.sha256(files[rel]).digest())
        h.update(len(files).to_bytes(4, "big"))
        self.assertEqual(ra.tree_digest(str(cand / "code")), h.hexdigest())

    def test_bit_flip_anywhere_changes_release_digest(self):
        cand = _candidate("flip")
        base = ra.compute_candidate(**_paths(cand, "flip"))
        # flip one bit in the code tree
        (cand / "code" / "lib.py").write_bytes(b"VERSION = 'tX'\n")
        changed_code = ra.compute_candidate(**_paths(cand, "flip"))
        self.assertNotEqual(base["release_digest"],
                            changed_code["release_digest"])
        # flip one bit in the eval results
        (cand / "eval_results.json").write_text(
            json.dumps({"release": "t", "pass": False}), encoding="utf-8")
        changed_eval = ra.compute_candidate(**_paths(cand, "flip"))
        self.assertNotEqual(changed_code["release_digest"],
                            changed_eval["release_digest"])
        # flip one bit in the SAR
        (cand / "sar.md").write_text("# SAR\n\nrelease t: FAIL\n",
                                     encoding="utf-8")
        changed_sar = ra.compute_candidate(**_paths(cand, "flip"))
        self.assertNotEqual(changed_eval["release_digest"],
                            changed_sar["release_digest"])

    def test_candidate_requires_all_three_inputs(self):
        cand = _candidate("req")
        with self.assertRaises(ValueError):
            ra.compute_candidate(str(cand / "code"),
                                 str(cand / "eval_results.json"),
                                 str(cand / "missing-sar.md"),
                                 release_id="req")


class TestPropose(unittest.TestCase):
    def test_refuses_sub_two_quorum(self):
        ctx = make_run()
        cand = _candidate("q1")
        with self.assertRaises(ValueError):
            ra.propose_release(ctx["approvals"], ctx["executor"],
                               release_id="r", eligible_principals=ELIGIBLE,
                               min_approvals=1, **_paths(cand, None))

    def test_refuses_requester_in_eligible_set(self):
        ctx = make_run()
        cand = _candidate("q2")
        with self.assertRaises(ValueError):
            ra.propose_release(ctx["approvals"], ctx["executor"],
                               release_id="r",
                               eligible_principals=["release-manager",
                                                    "ra-bob"],
                               **_paths(cand, None))

    def test_queued_record_is_quorum_collecting_with_bound_digest(self):
        c = _Ctx(tag="bound")
        rec = c.queue.get(c.approval_id)
        self.assertEqual(rec["decision_mode"], "quorum")
        self.assertEqual(rec["quorum"]["min_approvals"], 2)
        self.assertEqual(
            rec["args"]["release_digest"],
            ra.compute_candidate(**_paths(c.cand, "rel-t"))["release_digest"])


class TestCeremony(unittest.TestCase):
    def test_single_decide_refused_on_quorum_record(self):
        c = _Ctx(tag="sd")
        with self.assertRaises(ValueError):
            c.queue.decide(c.approval_id, True, "solo",
                           decided_by="ra-alice")

    def test_one_vote_leaves_pending(self):
        c = _Ctx(tag="ov")
        rec, finalized = c.vote("ra-alice")
        self.assertFalse(finalized)
        self.assertEqual(rec["status"], "pending")

    def test_two_votes_finalize_and_chain_log_entry(self):
        c = _Ctx(tag="tv")
        c.vote("ra-alice")
        rec, finalized = c.vote("ra-bob")
        self.assertTrue(finalized)
        self.assertEqual(rec["status"], "approved")
        want = ra.compute_candidate(**_paths(c.cand, "rel-t"))["release_digest"]
        granted = [e for e in read_entries(c.queue.log.path)
                   if e.get("event") == "release_approval_granted"
                   and e.get("approval_id") == c.approval_id]
        self.assertEqual(len(granted), 1)
        self.assertEqual(granted[0]["release_digest"], want)
        self.assertEqual(sorted(granted[0]["voters"]),
                         ["ra-alice", "ra-bob"])

    def test_deny_vetoes(self):
        c = _Ctx(tag="dv")
        c.vote("ra-alice", approve=False)
        rec = c.queue.get(c.approval_id)
        self.assertEqual(rec["status"], "rejected")


class TestVerify(unittest.TestCase):
    def _approved(self, tag="v"):
        c = _Ctx(tag=tag)
        c.vote("ra-alice")
        c.vote("ra-bob")
        return c

    def test_happy_path(self):
        c = self._approved()
        ok, reason = ra.verify_release(queue=c.queue,
                                       approval_id=c.approval_id,
                                       **_paths(c.cand))
        self.assertTrue(ok, reason)

    def test_votes_through_queue_native_path_still_verify(self):
        # Humans may vote via the queue's own surfaces (e.g. the
        # gov.approve CLI) instead of record_release_vote: the queue
        # still chains its native quorum_finalized entry, and the
        # digest binding rides the MACed record args.
        c = _Ctx(tag="native")
        for p in ("ra-alice", "ra-bob"):
            c.queue.cast_vote(c.approval_id, True,
                              "reviewed evidence for %s" % p, c.voter(p))
        ok, reason = ra.verify_release(queue=c.queue,
                                       approval_id=c.approval_id,
                                       **_paths(c.cand))
        self.assertTrue(ok, reason)

    def test_forged_record_fails_integrity(self):
        c = self._approved()
        path = Path(c.ctx["run_dir"]) / "approvals.jsonl"
        recs = [json.loads(l) for l in path.read_text(
            encoding="utf-8").splitlines() if l.strip()]
        for r in recs:
            if r["id"] == c.approval_id:
                r["args"]["release_digest"] = "ab" * 32  # post-queue tamper
        path.write_text("\n".join(json.dumps(r) for r in recs) + "\n",
                        encoding="utf-8")
        ok, reason = ra.verify_release(queue=c.queue,
                                       approval_id=c.approval_id,
                                       **_paths(c.cand))
        self.assertFalse(ok, reason)
        self.assertIn("integrity", reason)

    def test_wrong_digest_refused(self):
        c = self._approved()
        other = _candidate("other")
        ok, reason = ra.verify_release(queue=c.queue,
                                       approval_id=c.approval_id,
                                       **_paths(other))
        self.assertFalse(ok, reason)
        self.assertIn("mismatch", reason)

    def test_replay_against_changed_candidate_refused(self):
        c = self._approved()
        changed = _candidate("v", tamper=b"# changed after approval\n")
        ok, reason = ra.verify_release(queue=c.queue,
                                       approval_id=c.approval_id,
                                       **_paths(changed))
        self.assertFalse(ok, reason)

    def test_single_approver_refused(self):
        c = _Ctx(tag="single")
        c.vote("ra-alice")
        ok, reason = ra.verify_release(queue=c.queue,
                                       approval_id=c.approval_id,
                                       **_paths(c.cand))
        self.assertFalse(ok, reason)
        self.assertIn("not finalized", reason)

    def test_stale_approval_refused(self):
        c = self._approved()
        ok, reason = ra.verify_release(queue=c.queue,
                                       approval_id=c.approval_id,
                                       max_age_hours=0,
                                       **_paths(c.cand))
        self.assertFalse(ok, reason)
        self.assertIn("stale", reason)

    def test_unknown_approval_id_refused(self):
        c = self._approved()
        ok, reason = ra.verify_release(queue=c.queue,
                                       approval_id="nope1234",
                                       **_paths(c.cand))
        self.assertFalse(ok)

    def test_incomplete_candidate_refused_not_raised(self):
        c = self._approved()
        ok, reason = ra.verify_release(queue=c.queue,
                                       approval_id=c.approval_id,
                                       code_dir=str(c.cand / "code"),
                                       eval_results_path=str(
                                           c.cand / "missing-evals.json"),
                                       sar_path=str(c.cand / "sar.md"))
        self.assertFalse(ok)


class TestShip(unittest.TestCase):
    def test_ship_refuses_unverified(self):
        c = _Ctx(tag="ship-no")
        dest = Path(tempfile.mkdtemp(prefix="ra-ship-"))
        with self.assertRaises(ra.ReleaseNotApproved):
            ra.ship_release(queue=c.queue, approval_id=c.approval_id,
                            **_ship_kwargs(c.cand, dest))
        self.assertEqual(list(dest.iterdir()), [])

    def test_ship_copies_verified_release(self):
        c = _Ctx(tag="ship-yes")
        c.vote("ra-alice")
        c.vote("ra-bob")
        dest = Path(tempfile.mkdtemp(prefix="ra-ship-"))
        shipped = ra.ship_release(queue=c.queue, approval_id=c.approval_id,
                                  **_ship_kwargs(c.cand, dest))
        self.assertTrue((shipped / "code" / "main.py").is_file())
        self.assertTrue((shipped / "eval_results.json").is_file())
        self.assertTrue((shipped / "sar.md").is_file())
        with self.assertRaises(ra.ReleaseNotApproved):
            ra.ship_release(queue=c.queue, approval_id=c.approval_id,
                            **_ship_kwargs(c.cand, dest))


class TestF153ReleaseIdTraversal(unittest.TestCase):
    """F153: the release_id must be digest-bound and ship-contained.

    Red-first: on the unmodified tree, test_traversal_* FAIL because
    ship_release writes the quorum-approved bytes outside dest_dir;
    test_release_id_bound_into_digest FAILS because the digest ignores
    the id; the verify_release release_id-param tests FAIL because the
    seam does not exist yet. The legit-ship test is the control.
    """

    def _approved_with_id(self, tag, release_id):
        ctx = make_run()
        cand = _candidate(tag)
        approval_id = ra.propose_release(
            ctx["approvals"], ctx["executor"],
            eligible_principals=ELIGIBLE, **_paths(cand, release_id))
        for p in ("ra-alice", "ra-bob"):
            ident = ctx["executor"].mint_identity("v-%s" % p, "voter", p)
            ra.record_release_vote(ctx["approvals"], approval_id, ident,
                                   True, "reviewed evidence for %s" % p)
        return ctx, cand, approval_id

    def test_traversal_release_id_ship_refused_and_contained(self):
        ctx, cand, approval_id = self._approved_with_id(
            "f153a", "../f153-escape")
        anchor = Path(tempfile.mkdtemp(prefix="ra-f153-"))
        with self.assertRaises(ra.ReleaseNotApproved):
            ra.ship_release(queue=ctx["approvals"], approval_id=approval_id,
                            **_ship_kwargs(cand, anchor))
        # Nothing landed outside the anchor, and nothing landed inside it.
        self.assertFalse((anchor.parent / "f153-escape").exists())
        self.assertEqual(list(anchor.iterdir()), [])

    def test_nested_traversal_variant_refused(self):
        ctx, cand, approval_id = self._approved_with_id(
            "f153b", "a/../../f153-escape2")
        anchor = Path(tempfile.mkdtemp(prefix="ra-f153-"))
        with self.assertRaises(ra.ReleaseNotApproved):
            ra.ship_release(queue=ctx["approvals"], approval_id=approval_id,
                            **_ship_kwargs(cand, anchor))
        self.assertFalse((anchor.parent / "f153-escape2").exists())
        self.assertEqual(list(anchor.iterdir()), [])

    def test_release_id_bound_into_digest(self):
        cand = _candidate("f153c")
        d1 = ra.compute_candidate(
            **_paths(cand, "rel-one"))["release_digest"]
        d2 = ra.compute_candidate(
            **_paths(cand, "rel-two"))["release_digest"]
        self.assertNotEqual(d1, d2)

    def test_verify_release_rejects_mismatched_release_id(self):
        ctx, cand, approval_id = self._approved_with_id(
            "f153d", "rel-match")
        ok, reason = ra.verify_release(
            queue=ctx["approvals"], approval_id=approval_id,
            release_id="rel-other", **_paths(cand, None))
        self.assertFalse(ok)
        self.assertIn("release_id", reason)

    def test_verify_release_accepts_matching_release_id(self):
        ctx, cand, approval_id = self._approved_with_id(
            "f153e", "rel-ok")
        ok, reason = ra.verify_release(
            queue=ctx["approvals"], approval_id=approval_id,
            release_id="rel-ok", **_paths(cand, None))
        self.assertTrue(ok, reason)

    def test_legit_release_still_ships(self):
        # Control: passes before and after the fix.
        ctx, cand, approval_id = self._approved_with_id(
            "f153f", "rel-legit")
        anchor = Path(tempfile.mkdtemp(prefix="ra-f153-"))
        shipped = ra.ship_release(queue=ctx["approvals"],
                                  approval_id=approval_id,
                                  **_ship_kwargs(cand, anchor))
        self.assertEqual(shipped, anchor / "rel-legit")
        self.assertTrue((shipped / "code" / "main.py").is_file())
        self.assertTrue((shipped / "eval_results.json").is_file())
        self.assertTrue((shipped / "sar.md").is_file())


if __name__ == "__main__":
    unittest.main()
