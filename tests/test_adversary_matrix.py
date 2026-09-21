"""Adversary-team smoke test: matrix/harness wiring integrity.

Does NOT re-run every cell (that is evals/run_evals.py's job). It asserts
the structural invariants the ship-gate depends on:

1. matrix.py covers every situation x adapter x privilege cell.
2. Every situation has a playbook and a checker registered.
3. Every expected verdict is a known verdict string.
4. A spot-check cell (sit1/decorator/low) really executes and blocks.

Run:  python3 tests/run_tests.py   (picks up test_adversary_*.py)
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from evals.matrix import SITUATIONS, PRIVILEGES, PRIV_ROLE, ADAPTERS  # noqa: E402
from evals import run_evals as ev  # noqa: E402

VERDICTS = {"blocked", "queued", "allowed-with-audit", "blocked-or-queued"}


class TestMatrixIntegrity(unittest.TestCase):
    def test_every_cell_has_expectation(self):
        for sit_id, s in SITUATIONS.items():
            for ad in ADAPTERS:
                for priv in PRIVILEGES:
                    with self.subTest(sit=sit_id, adapter=ad, priv=priv):
                        self.assertIn((ad, priv), s["expected"])
                        verdict, why = s["expected"][(ad, priv)]
                        self.assertIn(verdict, VERDICTS)
                        self.assertTrue(why.strip())

    def test_every_situation_has_playbook_and_checker(self):
        for sit_id in SITUATIONS:
            with self.subTest(sit=sit_id):
                self.assertIn(sit_id, ev.PLAYBOOKS)
                self.assertIn(sit_id, ev.CHECKS)
                self.assertTrue(callable(ev.PLAYBOOKS[sit_id]))
                self.assertTrue(callable(ev.CHECKS[sit_id]))

    def test_privilege_roles_known(self):
        self.assertEqual(set(PRIVILEGES), {"low", "standard", "elevated"})
        self.assertEqual(set(PRIV_ROLE.values()), {"scout", "support",
                                                   "researcher"})

    def test_spot_check_cell_executes(self):
        # One real cell end-to-end, on BOTH harnesses: poisoned-doc exfil
        # at low privilege must be blocked by the role allowlist.
        for harness in ev.HARNESSES:
            with self.subTest(harness=harness):
                r = ev.run_cell("sit1", "decorator", "low", harness)
                self.assertTrue(r["passed"], r["notes"])
                self.assertEqual(r["expected_verdict"], "blocked")
                self.assertEqual(r["outcomes"]["exfil_email"], "denied")
                self.assertEqual(r["outcomes"]["exfil_post"], "denied")


if __name__ == "__main__":
    unittest.main()
