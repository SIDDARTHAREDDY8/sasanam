"""Regression tests for F194 (wave-178): the approved sweep's execution-time
authority re-proof verdict is recorded in the chained audit log on success.

Close-when: after an approved sweep, the audit log contains the
execution-time proof verdict. The probe distinguishes the queue-time
proof from the execution-time re-proof by re-issuing the boundary with
a new version before the sweep: the recorded re-proof must carry the
CURRENT boundary version.

Tests target the public seam (call -> approve -> execute_approved ->
read_log); the deployment-mode line below is required because the
harness's declared ungoverned_ack is refused in production mode.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import authority_proof as ap  # noqa: E402
from harness import make_run  # noqa: E402


def _boundary(version, fs_write=()):
    return ap.boundary_from_dict({
        "boundary_id": "f194-boundary",
        "version": version,
        "fs_read_prefixes": [],
        "fs_write_prefixes": list(fs_write),
        "egress_hosts": [],
    })


def _proof_dicts(obj):
    if isinstance(obj, dict):
        if (obj.get("verdict") in ("within_boundary", "exceeds_boundary",
                                   "unsupported", "inconclusive")
                and "covered_domains" in obj):
            yield obj
        for v in obj.values():
            yield from _proof_dicts(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _proof_dicts(v)


def _queue_and_approve_outside_write(ex, approvals, target, boundary_v1):
    ident = ex.mint_identity("f194-agent", "coder", "f194-p")
    ex.set_authority_boundary(boundary_v1)
    r = ex.call(ident, "write_file", path=target, content="sweep-bytes")
    assert r.get("status") == "queued", r
    aid = r["approval_id"]
    approvals.decide(aid, True, reason="looks fine",
                     decided_by="human-operator")
    return aid


class TestSweepReproofRecorded(unittest.TestCase):
    def test_execution_time_reproof_is_audit_logged(self):
        """F194 close-when: the sweep appends a chained entry recording
        the execution-time proof verdict on success."""
        tmp = tempfile.mkdtemp(prefix="f194-")
        target = str(Path(tmp) / "sweep-outside.txt")
        ctx = make_run()
        ex = ctx["executor"]
        aid = _queue_and_approve_outside_write(
            ex, ctx["approvals"], target, _boundary("1", fs_write=(tmp,)))
        # Operator re-issues the boundary before the sweep (still
        # covering): the re-proof must run against v2.
        ex.set_authority_boundary(_boundary("2", fs_write=(tmp,)))
        done = ex.execute_approved()
        self.assertEqual(
            len([d for d in done if isinstance(d, dict)]), 1)

        entries = ctx["read_log"]()
        hits = [e for e in entries if isinstance(e, dict)
                and e.get("event") == "authority_proof_execution_reproof"
                and e.get("approval_id") == aid]
        self.assertTrue(hits, "no execution-time re-proof audit entry")
        for e in hits:
            # Chained into the audit log, not a sidecar.
            self.assertIsInstance(e.get("seq"), int)
            self.assertTrue(e.get("prev_hash"))
            proof = e.get("proof") or {}
            self.assertEqual(proof.get("verdict"), "within_boundary")
            self.assertEqual(proof.get("boundary_version"), "2")
            self.assertEqual(proof.get("boundary_id"), "f194-boundary")
        # Exactly one re-proof record per executed approval.
        self.assertEqual(len(hits), 1)

    def test_refused_sweep_records_no_reproof_success_entry(self):
        """Fail-closed direction unchanged: a boundary that no longer
        covers the target refuses, and no success re-proof entry is
        written for the refused approval."""
        tmp = tempfile.mkdtemp(prefix="f194-")
        target = str(Path(tmp) / "sweep-outside.txt")
        ctx = make_run()
        ex = ctx["executor"]
        aid = _queue_and_approve_outside_write(
            ex, ctx["approvals"], target, _boundary("1", fs_write=(tmp,)))
        # Tighten so the target is OUTSIDE the boundary: sweep refuses.
        ex.set_authority_boundary(_boundary("2", fs_write=("/nowhere",)))
        done = ex.execute_approved()
        self.assertEqual(len([d for d in done if isinstance(d, dict)]), 0)

        entries = ctx["read_log"]()
        refused = [e for e in entries if isinstance(e, dict)
                   and e.get("approval_id") == aid
                   and e.get("decision") == "refused"]
        self.assertTrue(refused, "expected a refusal audit entry")
        success_hits = [
            e for e in entries if isinstance(e, dict)
            and e.get("event") == "authority_proof_execution_reproof"
            and e.get("approval_id") == aid]
        self.assertEqual(success_hits, [])

    def test_advisory_mode_records_no_reproof_entry(self):
        """No declared boundary -> no re-proof runs -> nothing recorded.
        The fix must not invent evidence where no check ran."""
        tmp = tempfile.mkdtemp(prefix="f194-")
        target = str(Path(tmp) / "sweep-outside.txt")
        ctx = make_run()
        ex = ctx["executor"]
        ident = ex.mint_identity("f194-agent", "coder", "f194-p")
        # Advisory mode: no boundary declared at all.
        r = ex.call(ident, "write_file", path=target, content="sweep-bytes")
        self.assertEqual(r.get("status"), "queued", r)
        aid = r["approval_id"]
        ctx["approvals"].decide(aid, True, reason="looks fine",
                               decided_by="human-operator")
        done = ex.execute_approved()
        self.assertEqual(
            len([d for d in done if isinstance(d, dict)]), 1)
        entries = ctx["read_log"]()
        hits = [e for e in entries if isinstance(e, dict)
                and e.get("event") == "authority_proof_execution_reproof"]
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
