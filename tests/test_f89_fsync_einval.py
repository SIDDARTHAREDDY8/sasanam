"""F89 regression: F83 fsync must tolerate non-syncable fds (EINVAL).

The F83 durability fix added ``os.fsync`` after every queue append.
``os.fsync`` raises ``OSError(EINVAL)`` on file descriptors that do not
support synchronization (character devices like /dev/null, pipes,
sockets). The queue/ticket-store files live in the run dir, which the
documented F52 run-dir-writer residual allows an attacker to symlink —
the w11 sit64 probe pins the ``approvals.jsonl -> /dev/null`` shape
(the approval is "accepted" but silently vanishes). The unguarded
fsync turned that documented residual into an unhandled ``OSError``
crashing ``queue()``.

Fix: ``gov.approvals._fsync_syncable`` tolerates EINVAL only; every
other fsync error still propagates loud, so the F83 durability
guarantee for real files is unchanged.

Drives deterministic harness.make_run() fixtures (TMPDIR=/tmp/gov-run
private subdirs), like tests/test_approval_web_durability.py.
"""

import errno
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_TESTS_DIR)
for _p in (_TESTS_DIR, _REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402
from gov.approvals import _fsync_syncable  # noqa: E402
from gov.policy import PolicyDecision  # noqa: E402


def _queue_direct(q, policy, run_dir, ident):
    """Queue a benign allowlisted send_email straight through queue()."""
    from gov.executor import ToolExecutor
    args = {"to": "ops@synthetic.local", "subject": "weekly summary",
            "body": "customer rows: Alice 555-0101"}
    eb = ToolExecutor._egress_bytes_for("send_email", args)
    return q.queue(
        {"tool": "send_email", "args": args,
         "identity": {"agent_id": "adv-x", "role": "support",
                      "run_id": Path(run_dir).name,
                      "principal": "adversary-org"},
         "redactions": [], "agent_justification": "weekly summary"},
        PolicyDecision("require_approval", "r",
                       policy_id="approval-outbound-sends", flag=None),
        policy_hash=policy.policy_hash,
        policy_context={"domain_allowlisted": True},
        egress_bytes=eb,
        caller_identity=ident)


class TestF89FsyncEinval(unittest.TestCase):
    """F89: fsync EINVAL tolerance on the queue append path."""

    def test_queue_devnull_symlink_does_not_raise(self):
        # The documented F52 residual shape from the w11 sit64 probe:
        # approvals.jsonl symlinked to /dev/null. queue() must not
        # raise (pre-F83 behavior restored); the approval still
        # silently vanishes (residual documented, not fixed).
        ctx = make_run()
        try:
            q = ctx["approvals"]
            run_dir = Path(ctx["run_dir"])
            (run_dir / "approvals.jsonl").unlink(missing_ok=True)
            (run_dir / "approvals.jsonl").symlink_to("/dev/null")
            ident = ctx["mint_identity"]("adv-x", "support",
                                         "adversary-org")
            aid = _queue_direct(q, ctx["policy"], run_dir, ident)
            self.assertIsInstance(aid, str)
            self.assertIsNone(q.get(aid),
                              "residual: /dev/null swallows the record")
        finally:
            (Path(ctx["run_dir"]) / "approvals.jsonl").unlink(
                missing_ok=True)
            import shutil
            shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    def test_fsync_still_called_on_regular_file(self):
        # The F83 durability guarantee is unchanged for real files:
        # _fsync_syncable delegates to os.fsync.
        ctx = make_run()
        try:
            q = ctx["approvals"]
            ident = ctx["mint_identity"]("adv-x", "support",
                                         "adversary-org")
            seen = []
            real_fsync = os.fsync
            with mock.patch("gov.approvals.os.fsync",
                            side_effect=lambda fd: seen.append(fd)
                            or real_fsync(fd)):
                aid = _queue_direct(q, ctx["policy"],
                                    Path(ctx["run_dir"]), ident)
            self.assertEqual(len(seen), 1)
            self.assertIsNotNone(q.get(aid))
        finally:
            import shutil
            shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    def test_fsync_non_einval_errors_still_raise(self):
        # Only EINVAL is tolerated: EIO (real durability failure)
        # still propagates loud out of queue().
        ctx = make_run()
        try:
            q = ctx["approvals"]
            ident = ctx["mint_identity"]("adv-x", "support",
                                         "adversary-org")
            boom = OSError(errno.EIO, "simulated disk error")
            with mock.patch("gov.approvals.os.fsync", side_effect=boom):
                with self.assertRaises(OSError) as cm:
                    _queue_direct(q, ctx["policy"],
                                  Path(ctx["run_dir"]), ident)
            self.assertEqual(cm.exception.errno, errno.EIO)
        finally:
            import shutil
            shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    def test_fsync_syncable_unit(self):
        # Unit pin: EINVAL swallowed, other errnos re-raised.
        with mock.patch("os.fsync",
                        side_effect=OSError(errno.EINVAL,
                                            "Invalid argument")):
            _fsync_syncable(999)  # must not raise
        with mock.patch("os.fsync",
                        side_effect=OSError(errno.EBADF, "bad fd")):
            with self.assertRaises(OSError):
                _fsync_syncable(999)


if __name__ == "__main__":
    unittest.main()
