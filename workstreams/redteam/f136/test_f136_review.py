"""unittest subset of the F136 independent review (stream 3, 2026-09-23).

Deterministic, fast probes against gov/egress_launcher.py (main tree,
imported read-only). The timing-sensitive probes (P5 port-scan, P7 live
tamper loop) live in f136_review_probes.py; this file pins the
deterministic properties:

  - fresh wall launches (control)
  - provider.check() re-verifies the full component digest chain and
    child_recheck() refuses after tamper (P6: preexec closes the
    verify->spawn component-tamper window)
  - the re-pin attack (P1): an attacker with pin-dir write access can
    widen the allowlist and re-run install(); the launcher accepts it
    (documents R10's procedural boundary)
  - wall death after launch does not kill the running child (P4: R7)
  - run_child deadlocks on >64KB child output with capture_output=True
    (P2: availability defect — this test FAILS while the bug is present)

Run: TMPDIR=/tmp/gov-run-f136 ~/workspace/.gov-venv/bin/python -m unittest \\
       workstreams.redteam.f136.test_f136_review -v
(cwd: the repo root)
"""

import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov.egress_launcher import (  # noqa: E402
    EgressLaunchRefused,
    FilteredEgressLauncher,
    SimulatedWallFixture,
    SimulatedWallProvider,
    WallComponentInventory,
    install_simulated_wall,
    repin_after_fixture_fixup,
)

_P2_MARKER = "F136P2PYTESTMARKER"


def _tmpdir():
    base = os.environ.get("TMPDIR", "/tmp")
    return tempfile.mkdtemp(prefix="f136t-", dir=base)


class F136ReviewTests(unittest.TestCase):
    def setUp(self):
        tmp = _tmpdir()
        self.sim = os.path.join(tmp, "wall")
        install_simulated_wall(self.sim, wall_id="f136test")
        self.events = []
        self.fix = SimulatedWallFixture(self.sim)
        self.fix.__enter__()
        self.inv = repin_after_fixture_fixup(self.sim)
        self.fix.inventory = self.inv
        self.launcher = FilteredEgressLauncher(
            manifest_path=os.path.join(self.sim, "wall_pins.json"),
            receipt_path=os.path.join(self.sim, "wall_receipt.json"),
            wall_provider=self.fix.provider(), audit=self.events.append)
        self._wall_torn_down = False

    def tearDown(self):
        subprocess.run(["pkill", "-f", _P2_MARKER],
                       capture_output=True, timeout=5)
        if not self._wall_torn_down:
            self.fix.__exit__()

    # -- P0 control -------------------------------------------------
    def test_control_fresh_launch(self):
        cp = self.launcher.run_child(
            [sys.executable, "-c", "print('hello-wall')"],
            capture_output=True, text=True)
        self.assertEqual(cp.returncode, 0)
        self.assertIn("hello-wall", cp.stdout)

    # -- P6: preexec re-verifies the component chain ----------------
    def test_preexec_reverifies_component_chain(self):
        """Tamper after verify(): check() must go DOWN via pin_verify
        and child_recheck() must refuse — the preexec re-assert covers
        the verify->spawn component-tamper window, not just liveness."""
        self.launcher.verify()
        allow = os.path.join(self.sim, "conf", "allowlist.txt")
        with open(allow, "a", encoding="utf-8") as f:
            f.write("evil.example:443\n")
        report = self.launcher.wall.check()
        self.assertNotEqual(report.state, "UP")
        self.assertIn("pin_verify", str(report.detail))
        with self.assertRaises(EgressLaunchRefused):
            self.launcher.wall.child_recheck()

    # -- P1: re-pin attack (documents R10) ---------------------------
    def test_repin_attack_documents_r10(self):
        """R10: receipt = sha256(manifest bytes) is self-consistent.
        Anyone who can write the pin dir can widen the allowlist and
        re-pin; the launcher verifies and launches. The trust anchor is
        procedural (receipt custody), not cryptographic."""
        allow = os.path.join(self.sim, "conf", "allowlist.txt")
        with open(allow, "a", encoding="utf-8") as f:
            f.write("evil.example:443\n")
        conf = os.path.join(self.sim, "conf")
        WallComponentInventory.install(
            {"nft_ruleset": os.path.join(conf, "agent0.nft.sim"),
             "proxy_allowlist": allow,
             "dns_config": os.path.join(conf, "dns_config.txt"),
             "dns_zone": os.path.join(conf, "dns_hosts.txt"),
             "proxy_impl": os.path.join(conf, "proxy_impl.txt"),
             "seccomp_config": os.path.join(conf, "seccomp_config.txt")},
            os.path.join(self.sim, "wall_pins.json"),
            os.path.join(self.sim, "wall_receipt.json"))
        launcher2 = FilteredEgressLauncher(
            manifest_path=os.path.join(self.sim, "wall_pins.json"),
            receipt_path=os.path.join(self.sim, "wall_receipt.json"),
            wall_provider=SimulatedWallProvider(
                self.sim, WallComponentInventory(
                    os.path.join(self.sim, "wall_pins.json"),
                    os.path.join(self.sim, "wall_receipt.json"))))
        launcher2.verify()  # passes: re-pin is self-consistent
        cp = launcher2.run_child(
            [sys.executable, "-c", "print('re-pinned')"],
            capture_output=True, text=True)
        self.assertEqual(cp.returncode, 0)

    # -- P4: wall death after launch (R7) ----------------------------
    def test_wall_death_child_survives_and_new_launch_refuses(self):
        """R7: no lifetime re-check — a running child survives wall
        death; new launches still refuse (fail-closed at launch time)."""
        sentinel = os.path.join(self.sim, "child_alive")
        proc = self.launcher.launch(
            [sys.executable, "-c",
             "import time; open(%r, 'w').write('up'); time.sleep(60)"
             % sentinel],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                if os.path.exists(sentinel):
                    break
                time.sleep(0.1)
            self.assertTrue(os.path.exists(sentinel))
            self.fix.__exit__()
            self._wall_torn_down = True
            time.sleep(3)
            self.assertIsNone(proc.poll(),
                              "child should survive wall death (R7)")
            with self.assertRaises(EgressLaunchRefused):
                self.launcher.run_child([sys.executable, "-c", "pass"],
                                        capture_output=True)
        finally:
            try:
                proc.kill()
            except OSError:
                pass

    # -- P2: run_child large-output deadlock (availability defect) ---
    def test_run_child_large_output_deadlock(self):
        """P2 availability defect: run_child pops 'capture_output' into
        `capture` but then branches on popen_kw.get('capture_output')
        (always None) -> proc.wait() with stdout=PIPE -> deadlock past
        the 64KB pipe buffer. This test FAILS while the defect is
        present and passes once fixed (200KB drained, rc 0)."""
        outcome = {}

        def _run():
            try:
                cp = self.launcher.run_child(
                    [sys.executable, "-c",
                     "import sys  # %s\nsys.stdout.write('X' * 200000)"
                     % _P2_MARKER],
                    capture_output=True, text=True)
                outcome["done"] = (cp.returncode, len(cp.stdout or ""))
            except Exception as e:  # noqa: BLE001
                outcome["exc"] = repr(e)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=20)
        if t.is_alive():
            self.fail(
                "BUG reproduced: run_child deadlocked on 200KB child "
                "output (wait()-before-communicate; the capture_output "
                "branch tests the popped kwarg). Fail-hung, not "
                "fail-open — availability defect in the launcher API.")
        self.assertEqual(outcome.get("done"), (0, 200000), outcome)


if __name__ == "__main__":
    unittest.main()
