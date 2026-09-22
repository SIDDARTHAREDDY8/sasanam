"""Unit tests for the registry-gate oracle (evals/run_evals.py::_registry_oracle).

M2 lane (2026-09-22): the lead added a recognized closure value
``residual-accepted`` for break-by-design monitored residuals (F105
hex-entropy, F98 premise-error U+02B0 shape). The oracle must accept
observed=break for residual-accepted entries and report them in a
separate visible section -- never lumped silently with green.

Semantics pinned here:
  - green + observed=break        -> REJECT (gate RED; the closure holds)
  - residual-accepted + break     -> accept, reason "residual-accepted"
  - residual-accepted + stopped   -> also accept (a strict improvement),
    BUT the gate's ACCEPTED RESIDUALS section flags it ("no longer
    breaks: re-review") so a changed residual boundary never passes
    silently. Decision documented here per the lane task.
  - residual-accepted is not green: its accept set is disjoint from
    green's steady state (green can never accept break).
"""

import unittest

from evals.run_evals import _registry_oracle


def _entry(expected, closure):
    return {"expected": expected, "closure": closure, "tags": []}


class TestRegistryOracle(unittest.TestCase):
    def test_green_break_is_red(self):
        reason, accept = _registry_oracle(_entry("break", "green"))
        self.assertEqual(reason, "fix-verified")
        self.assertNotIn("break", accept)

    def test_green_accepts_stopped_and_flagged(self):
        _, accept = _registry_oracle(_entry("stopped", "green"))
        self.assertIn("stopped", accept)
        self.assertIn("flagged", accept)

    def test_residual_accepted_break(self):
        reason, accept = _registry_oracle(
            _entry("break", "residual-accepted"))
        self.assertEqual(reason, "residual-accepted")
        self.assertIn("break", accept)

    def test_residual_accepted_stopped_is_fine(self):
        # A residual that now stops is a strict improvement: the oracle
        # accepts it (still fine). The gate's ACCEPTED RESIDUALS section
        # reports it with an explicit "no longer breaks: re-review"
        # flag, so the boundary change stays visible.
        reason, accept = _registry_oracle(
            _entry("break", "residual-accepted"))
        self.assertEqual(reason, "residual-accepted")
        self.assertIn("stopped", accept)

    def test_residual_accepted_is_not_green(self):
        # The residual must never be lumped silently with green: reason
        # strings are distinct, and a green entry can never accept break
        # while a residual-accepted entry must.
        green_reason, green_accept = _registry_oracle(
            _entry("break", "green"))
        self.assertNotEqual(green_reason, "residual-accepted")
        self.assertNotIn("break", green_accept)
        _, res_accept = _registry_oracle(
            _entry("break", "residual-accepted"))
        self.assertIn("break", res_accept)


if __name__ == "__main__":
    unittest.main()
