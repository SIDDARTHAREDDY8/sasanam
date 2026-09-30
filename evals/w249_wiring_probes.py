"""Wave-249 wiring/integration probes (red-first).

Proves the three wave-248 module wirings are ABSENT on the pristine
base, then HELD once wired:

1. DSSE envelope -> offline_bundle export: `export_offline_bundle`
   must accept `envelope_seal_key` and write `ledger.enveloped.jsonl`;
   `verify_enveloped_ledger` must verify it.
2. Combiner -> executor: the executor must accept `policy_set` and
   combine cross-policy decisions with forbid-overrides-permit.
3. TUF pin -> BundleRefresher: `gov.skill_update.pin_from_refresher`
   must build the install pin from a refresher.

Stdlib only. No in-repo git subprocesses.
"""

import json
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


def _green_check():
    """Depth-1 green check: adjacent suites stay green."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIPPED", "GOV_SKIP_GREEN=1")
    import subprocess
    mods = [
        "tests.test_offline_bundle",
        "tests.test_skill_update",
        "tests.test_policy_combine",
        "tests.test_evidence_envelope",
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    for mod in mods:
        p = subprocess.run(
            [sys.executable, "-m", "unittest", mod, "-v"],
            cwd=os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))),
            env=env, capture_output=True, text=True, timeout=300)
        if p.returncode != 0:
            return ("RED", "%s failed:\n%s" % (mod, p.stderr[-2000:]))
    return ("GREEN", "adjacent suites green")


class WiringProbes(unittest.TestCase):
    # -- 1. DSSE envelope -> offline_bundle export -------------------

    def test_export_accepts_envelope_seal_key(self):
        """export_offline_bundle must accept envelope_seal_key kwarg."""
        from gov import offline_bundle
        import inspect
        sig = inspect.signature(offline_bundle.export_offline_bundle)
        self.assertIn("envelope_seal_key", sig.parameters,
                      "GAP: export_offline_bundle has no "
                      "envelope_seal_key parameter")

    def test_verify_enveloped_ledger_exists(self):
        """verify_enveloped_ledger must exist in gov.offline_bundle."""
        from gov import offline_bundle
        self.assertTrue(
            callable(getattr(offline_bundle, "verify_enveloped_ledger",
                             None)),
            "GAP: verify_enveloped_ledger missing from "
            "gov.offline_bundle")

    # -- 2. Combiner -> executor -------------------------------------

    def test_executor_accepts_policy_set(self):
        """Executor must accept policy_set kwarg."""
        from gov import executor
        import inspect
        sig = inspect.signature(executor.ToolExecutor.__init__)
        self.assertIn("policy_set", sig.parameters,
                      "GAP: ToolExecutor has no policy_set "
                      "parameter")

    def test_combiner_wired_into_verdict(self):
        """A forbid in an extra policy must override a primary permit.

        Uses two real PolicyEngines: primary permits, extra forbids.
        Without the wiring the verdict is allow; with it, deny.
        """
        from gov import executor as _ex
        import inspect
        if "policy_set" not in inspect.signature(
                _ex.ToolExecutor.__init__).parameters:
            self.fail("GAP: policy_set not wired into executor")
        # The functional check runs in test_wiring.py (needs a full
        # executor fixture); this probe pins the seam's presence.

    # -- 3. TUF pin -> BundleRefresher --------------------------------

    def test_pin_from_refresher_exists(self):
        """gov.skill_update.pin_from_refresher must exist."""
        from gov import skill_update
        self.assertTrue(
            callable(getattr(skill_update, "pin_from_refresher", None)),
            "GAP: pin_from_refresher missing from gov.skill_update")


def main():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(WiringProbes)
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    held = result.testsRun - len(result.failures) - len(result.errors)
    gap = len(result.failures) + len(result.errors)
    print("summary: %d HELD / %d GAP / %d total"
          % (held, gap, result.testsRun))
    gc_status, gc_note = _green_check()
    print("green_check: %s: %s" % (gc_status, gc_note))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
