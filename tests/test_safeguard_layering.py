"""F161 regression: the product layer must not import the eval harness.

Layering rule (fail-closed): ``gov/`` never imports ``evals/`` at module
scope. ``import gov.safeguard_bundle`` / ``import gov.safeguard_benchmark``
must succeed with ``evals`` made unimportable (wheel-install condition).

$0 spend, synthetic/local only.

Seams under test (pre-agreed): the module-import seam of
gov.safeguard_bundle and gov.safeguard_benchmark with evals blocked in
sys.modules.
Red-first: the blocked-import tests FAIL on the unfixed tree (ImportError
from the top-level ``from evals.safeguard_results import ...``), PASS
after the fix.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import importlib  # noqa: E402
import sys  # noqa: E402
import unittest  # noqa: E402


def _block_evals():
    """Make ``evals`` (and any already-imported ``evals.*``) unimportable.

    Mirrors the wheel-install condition where the harness package is not
    on the path. Returns a restore callable.
    """
    saved = {k: v for k, v in sys.modules.items()
             if k == "evals" or k.startswith("evals.")}
    for k in saved:
        del sys.modules[k]
    sys.modules["evals"] = None  # None -> "import of evals halted"
    return lambda: _restore_evals(saved)


def _restore_evals(saved):
    for k in list(sys.modules):
        if k == "evals" or k.startswith("evals."):
            del sys.modules[k]
    sys.modules.update(saved)


def _fresh_import(name):
    for mod in ("gov.safeguard_bundle", "gov.safeguard_benchmark"):
        if mod in sys.modules:
            del sys.modules[mod]
    return importlib.import_module(name)


class SafeguardLayeringTest(unittest.TestCase):
    def test_bundle_imports_without_evals(self):
        """F161: gov.safeguard_bundle imports with evals unimportable."""
        restore = _block_evals()
        try:
            mod = _fresh_import("gov.safeguard_bundle")
            self.assertTrue(hasattr(mod, "bundle_assemble"))
        finally:
            restore()

    def test_benchmark_imports_without_evals(self):
        """F161: gov.safeguard_benchmark imports with evals unimportable."""
        restore = _block_evals()
        try:
            mod = _fresh_import("gov.safeguard_benchmark")
            self.assertTrue(hasattr(mod, "SafeguardAssessment"))
        finally:
            restore()

    def test_taxonomy_values_byte_identical(self):
        """F161: the layering move changes no taxonomy value."""
        import gov.safeguard_taxonomy as tax

        self.assertEqual(
            tax.SEVERITY_WEIGHTS, {"S1": 4, "S2": 3, "S3": 2, "S4": 1})
        self.assertEqual(
            tax.UNCOVERED_CATEGORIES,
            frozenset({"covert_interagent_comms",
                       "identity_authentication"}))
        self.assertIn("sandbox_escape", tax.REQUIRED_CATEGORIES)
        self.assertEqual(tax.CATEGORY_SEVERITY["sandbox_escape"], "S1")
        self.assertEqual(tax.CATEGORY_SEVERITY["eval_integrity"], "S3")
        self.assertEqual(len(tax.CATEGORY_SEVERITY), 27)
        self.assertEqual(len(tax.REQUIRED_CATEGORIES), 11)

    def test_harness_reexport_is_not_a_fork(self):
        """The harness re-export is the same objects, not copies."""
        import evals.safeguard_results as harness
        import gov.safeguard_taxonomy as tax

        for name in ("CATEGORY_SEVERITY", "SEVERITY_WEIGHTS",
                     "UNCOVERED_CATEGORIES", "REQUIRED_CATEGORIES"):
            self.assertIs(getattr(harness, name), getattr(tax, name),
                          "%s diverged between gov and evals" % name)

    def test_harness_loader_still_importable(self):
        """load_battery_results stays canonical in the harness."""
        import evals.safeguard_results as harness

        self.assertTrue(callable(harness.load_battery_results))


if __name__ == "__main__":
    unittest.main()
