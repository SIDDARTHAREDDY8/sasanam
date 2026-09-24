"""F81/D10: Sandbox filtered-egress mode wired to the egress launcher.

Cage-mode wiring tests only (gov/sandbox.py). The sandbox's
``filtered-egress`` mode historically meant only an internal seccomp
profile; with an ``egress_launcher`` attached the spawn must go through
the wall (verify -> check -> wrap -> spawn -> audit) with the sandbox
preexec riding along as a preexec_chain entry.

Fog decision 2 (composition) pins:
- the wall helper is the network seccomp; the cage filter is NOT
  double-installed (it would KILL `ip netns exec`'s netlink syscalls);
- the sandbox's own netns unshare is skipped (the wall provides it);
- drop_privs / require_seccomp / require_netns with a launcher refuse
  fail-closed at run();
- STRICT mode never consults the launcher.

All tests use the sim provider (unprivileged, hermetic).
"""

import os
import sys
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.egress_launcher import (  # noqa: E402
    EgressLaunchRefused,
    FilteredEgressLauncher,
    SimulatedWallFixture,
    SimulatedWallProvider,
    WallStateReport,
    install_simulated_wall,
    repin_after_fixture_fixup,
)
from gov.sandbox import Sandbox, SandboxError  # noqa: E402


def _mk_tmp():
    tmp = tempfile.mkdtemp(prefix="gov-f81sbox-")
    return tmp


def _up_launcher(wall_id="f81sbox"):
    """An UP sim wall + launcher. Returns (launcher, events, inv, fix).

    The caller must register fix.__exit__ as cleanup (done here via a
    TestCase-friendly finalizer list is the caller's job; this helper
    returns the fixture for the caller to close).
    """
    tmp = _mk_tmp()
    sim = os.path.join(tmp, "wall")
    install_simulated_wall(sim, wall_id=wall_id)
    fix = SimulatedWallFixture(sim)
    fix.__enter__()
    inv = repin_after_fixture_fixup(sim)
    fix.inventory = inv
    events = []
    launcher = FilteredEgressLauncher(
        manifest_path=os.path.join(sim, "wall_pins.json"),
        receipt_path=os.path.join(sim, "wall_receipt.json"),
        wall_provider=fix.provider(), audit=events.append,
        trust=inv.trust)
    return launcher, events, inv, fix, tmp


def _child_env_map(text):
    env = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    return env


class LauncherModeWiringTests(unittest.TestCase):
    def _sandbox(self, launcher, **kw):
        kw.setdefault("timeout", 20)
        kw.setdefault("use_netns", False)
        kw.setdefault("use_pidns", False)
        kw.setdefault("cage_mode", "filtered-egress")
        kw.setdefault("use_seccomp", True)
        kw.setdefault("egress_launcher", launcher)
        return Sandbox(**kw)

    def test_launcher_mode_spawns_through_wall_and_audits(self):
        launcher, events, inv, fix, tmp = _up_launcher()
        self.addCleanup(fix.__exit__)
        s = self._sandbox(launcher)
        result = s.run(["/usr/bin/env"])
        self.assertEqual(result.returncode, 0, result.stderr)
        env = _child_env_map(result.stdout)
        # The launcher's wall env reached the child (the
        # WALL_ACTIVE_ENV constant's key is EGRESS_WALL_ACTIVE)...
        self.assertEqual(env.get("EGRESS_WALL_ACTIVE"), "1")
        # ...and exactly one wall launch was audited.
        launches = [e for e in events
                    if e["event"] == "egress_wall_launch"]
        self.assertEqual(len(launches), 1)
        self.assertIn("egress wall launcher", result.note)

    def test_launcher_mode_sandbox_env_flows_through(self):
        # Composition proof: the sandbox's env (marker) AND the wall's
        # env (WALL_ACTIVE_ENV) both reach the child; the wall's proxy
        # scrub still applies to sandbox-supplied vars.
        launcher, events, inv, fix, tmp = _up_launcher()
        self.addCleanup(fix.__exit__)
        s = self._sandbox(
            launcher, extra_env={"F81_SANDBOX_MARKER": "marker-yes",
                                 "HTTP_PROXY": "http://evil:9/"})
        result = s.run(["/usr/bin/env"])
        self.assertEqual(result.returncode, 0, result.stderr)
        env = _child_env_map(result.stdout)
        self.assertEqual(env.get("F81_SANDBOX_MARKER"), "marker-yes")
        self.assertEqual(env.get("EGRESS_WALL_ACTIVE"), "1")
        self.assertNotIn("HTTP_PROXY", env)
        self.assertNotIn("http_proxy", env)

    def test_launcher_mode_skips_cage_seccomp_without_double_install(self):
        launcher, events, inv, fix, tmp = _up_launcher()
        self.addCleanup(fix.__exit__)
        s = self._sandbox(launcher)
        result = s.run(["/usr/bin/true"])
        self.assertEqual(result.returncode, 0, result.stderr)
        # The cage filter was not installed by the sandbox...
        self.assertFalse(result.seccomp_active)
        # ...and the note says the wall helper owns network seccomp.
        self.assertIn("not double-installed", result.note)

    def test_launcher_mode_wall_down_refuses(self):
        tmp = _mk_tmp()
        sim = os.path.join(tmp, "wall")
        inv, paths = install_simulated_wall(sim, wall_id="f81sboxdown")

        class _DownProvider(SimulatedWallProvider):
            def check(self):
                return WallStateReport(
                    "DOWN", {"reason": "simulated-down"})

        events = []
        launcher = FilteredEgressLauncher(
            manifest_path=paths["manifest"],
            receipt_path=paths["receipt"],
            wall_provider=_DownProvider(sim, inv),
            audit=events.append, trust=inv.trust)
        s = self._sandbox(launcher)
        with self.assertRaises(EgressLaunchRefused):
            s.run(["/usr/bin/true"])
        refusals = [e for e in events
                    if e["event"] == "egress_wall_launch_refused"]
        self.assertTrue(refusals)
        self.assertFalse([e for e in events
                          if e["event"] == "egress_wall_launch"])

    def test_launcher_mode_refuses_drop_privs(self):
        launcher, events, inv, fix, tmp = _up_launcher()
        self.addCleanup(fix.__exit__)
        s = self._sandbox(launcher, drop_privs=True)
        with self.assertRaises(SandboxError):
            s.run(["/usr/bin/true"])

    def test_launcher_mode_refuses_require_seccomp(self):
        launcher, events, inv, fix, tmp = _up_launcher()
        self.addCleanup(fix.__exit__)
        s = self._sandbox(launcher, require_seccomp=True)
        with self.assertRaises(SandboxError):
            s.run(["/usr/bin/true"])

    def test_launcher_mode_refuses_require_netns(self):
        launcher, events, inv, fix, tmp = _up_launcher()
        self.addCleanup(fix.__exit__)
        s = self._sandbox(launcher, use_netns=True,
                           require_netns=True)
        with self.assertRaises(SandboxError):
            s.run(["/usr/bin/true"])

    def test_launcher_mode_reports_wall_not_sandbox_netns(self):
        # network_isolated reports what the SANDBOX established (False:
        # its unshare was skipped); the note attributes isolation to
        # the wall. No silent mislabeling.
        launcher, events, inv, fix, tmp = _up_launcher()
        self.addCleanup(fix.__exit__)
        s = self._sandbox(launcher)
        result = s.run(["/usr/bin/true"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(result.network_isolated)
        self.assertIn("provided by the wall", result.note)

    def test_strict_mode_rejects_launcher(self):
        # STRICT mode is untouched: attaching a launcher is a
        # fail-closed misconfiguration, not a silent ignore.
        launcher, events, inv, fix, tmp = _up_launcher()
        self.addCleanup(fix.__exit__)
        with self.assertRaises(ValueError):
            Sandbox(cage_mode="strict", egress_launcher=launcher,
                    timeout=20)

    def test_bare_filtered_egress_notes_internal_only(self):
        # The old silent meaning is gone: without a launcher the mode
        # loudly reports it is the internal profile only.
        s = Sandbox(cage_mode="filtered-egress", use_seccomp=True,
                    use_netns=False, use_pidns=False, timeout=20)
        result = s.run(["/usr/bin/true"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("internal cage seccomp profile only", result.note)
        self.assertNotIn("EGRESS_WALL_ACTIVE", result.stdout)

    def test_launcher_kwarg_defaults_off(self):
        # No launcher attached: existing behavior, zero change.
        s = Sandbox(cage_mode="strict", use_netns=False,
                    use_pidns=False, timeout=20)
        self.assertIsNone(s.egress_launcher)
        result = s.run(["/usr/bin/true"])
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
