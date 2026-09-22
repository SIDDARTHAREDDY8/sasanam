"""Wave-35: symlink-swap TOCTOU on the write/read/delete path
(Docker CVE-2026-77179 / CVE-2026-79994 class, disclosed 2026-09-15).

CVE-2026-77179: virtio-fs followed symlinks when reopening a removed
file from a stored path -- a check-time path diverged from the
use-time path. CVE-2026-79994: a socket path was validated inside the
workspace, then reconnected by name -- a symlink swapped between
check and use redirected the host outside the workspace.

Our analog: ``ToolExecutor._context`` computes
``path_outside_sandbox`` (canonicalized with ``resolve()``) at
check time; ``_simulate`` then trusts ``ctx`` and operates on
``self._resolve(args["path"])`` WITHOUT re-resolving. If the
filesystem changes between check and use (symlink swap), the stale
verdict is honored.

Exploitability note (documented, not a finding): in the CURRENT
architecture no concurrent actor can win this race -- ``call()`` is
synchronous in-process, the agent has no symlink primitive, and the
sandbox child works in a different directory. This is a latent
defense-in-depth issue in the Docker class, fixed here by
re-verifying at use time (fail-closed). Filed as hardening, no
finding number: no demonstrated end-to-end evasion.

Fail-first: the swap tests below FAIL pre-fix (victim file
modified / secret bytes leaked) and PASS post-fix (quarantined /
simulated).
"""

import contextlib
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness  # noqa: E402


@contextlib.contextmanager
def _govrun():
    from gov import log as log_mod
    prev_env = os.environ.get("GOV_DEV_KEYS")
    prev = log_mod._dev_enabled
    os.environ["GOV_DEV_KEYS"] = "1"
    log_mod._dev_enabled = True
    try:
        yield
    finally:
        log_mod._dev_enabled = prev
        if prev_env is None:
            os.environ.pop("GOV_DEV_KEYS", None)
        else:
            os.environ["GOV_DEV_KEYS"] = prev_env


class TestSymlinkSwapTOCTOU(unittest.TestCase):
    def test_write_swap_between_check_and_use_is_quarantined(self):
        """Check-time: link -> inside. Swap. Use-time must re-verify
        and quarantine, not honor the stale 'inside' verdict."""
        with _govrun():
            ctx = harness.make_run()
            try:
                ex = ctx["executor"]
                ex.sandbox.mkdir(parents=True, exist_ok=True)

                inside_target = ex.sandbox / "real.txt"
                inside_target.write_text("inside", encoding="utf-8")
                victim = Path(ctx["run_dir"]) / "victim.txt"
                victim.write_text("ORIGINAL", encoding="utf-8")

                link = ex.sandbox / "swap.txt"
                link.symlink_to(inside_target)

                # Check time: the link points inside.
                args = {"path": "swap.txt", "content": "hello"}
                check_ctx = ex._context("write_file", args,
                                        principal="research-org")
                self.assertFalse(
                    check_ctx.get("path_outside_sandbox"),
                    "setup wrong: link should resolve inside at check")

                # THE SWAP: between check and use, the link is
                # repointed outside (the Docker CVE-2026-79994 shape).
                link.unlink()
                link.symlink_to(victim)

                # Use time: _simulate must re-verify, not trust ctx.
                result = ex._simulate("write_file", args, check_ctx)

                self.assertEqual(
                    victim.read_text(encoding="utf-8"), "ORIGINAL",
                    "TOCTOU: swapped symlink wrote OUTSIDE the sandbox")
                self.assertIn("quarantin", str(result.get("note", "")),
                              "swapped write not quarantined: %r" % (result,))
            finally:
                harness.cleanup_run_dirs(success=True)

    def test_read_swap_between_check_and_use_stays_simulated(self):
        """Same race on the read path: a swapped link must not leak
        outside bytes."""
        with _govrun():
            ctx = harness.make_run()
            try:
                ex = ctx["executor"]
                ex.sandbox.mkdir(parents=True, exist_ok=True)
                inside_target = ex.sandbox / "real.txt"
                inside_target.write_text("inside", encoding="utf-8")
                secret = Path(ctx["run_dir"]) / "secret.txt"
                secret.write_text("SECRET-BYTES", encoding="utf-8")
                link = ex.sandbox / "rswap.txt"
                link.symlink_to(inside_target)

                args = {"path": "rswap.txt"}
                check_ctx = ex._context("read_file", args,
                                        principal="research-org")
                self.assertFalse(check_ctx.get("path_outside_sandbox"))

                link.unlink()
                link.symlink_to(secret)

                result = ex._simulate("read_file", args, check_ctx)
                self.assertNotIn("SECRET-BYTES",
                                 str(result.get("content", "")),
                                 "TOCTOU: swapped symlink read outside bytes")
                self.assertEqual(result.get("source"), "simulated")
            finally:
                harness.cleanup_run_dirs(success=True)

    def test_no_swap_keeps_working(self):
        """Non-adversarial behavior unchanged: inside writes land."""
        with _govrun():
            ctx = harness.make_run()
            try:
                ex = ctx["executor"]
                ex.sandbox.mkdir(parents=True, exist_ok=True)
                args = {"path": "plain.txt", "content": "data"}
                c = ex._context("write_file", args,
                                principal="research-org")
                r = ex._simulate("write_file", args, c)
                self.assertEqual(
                    (ex.sandbox / "plain.txt").read_text(encoding="utf-8"),
                    "data")
                self.assertNotIn("quarantin", str(r.get("note", "")))
            finally:
                harness.cleanup_run_dirs(success=True)


if __name__ == "__main__":
    unittest.main()
