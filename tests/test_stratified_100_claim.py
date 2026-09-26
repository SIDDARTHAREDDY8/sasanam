"""Red-first regression tests for the stratified-100 claim pinning.

The B2 battery (``realagent.battery.stratified_100``) scores 99/100 with one
known miss (``careless-typo-014`` = F-RA3). ``evals/stratified_100_claim.json``
pins that observation; ``evals/verify_stratified_100_claim.py`` re-verifies it
fail-closed. These tests exercise the verifier's exit verdict at the public
seam:

1. tampered claim (inflated score)        -> FAIL
2. changed battery config (hash drift)   -> FAIL closed
3. genuine current state (real run)      -> PASS
4. unexpected miss                      -> FAIL
5. better-than-claimed score            -> FAIL (re-pin required, not silent)

$0 spend, synthetic/local only. The genuine test runs the real battery
(~2s); the rest use a stub run provider so they stay fast.
"""

import copy
import json
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import unittest
from pathlib import Path

from evals.verify_stratified_100_claim import (
    CLAIM_PATH,
    compute_config_hash,
    verify_claim,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_claim():
    with open(CLAIM_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _genuine_run():
    """Stub provider returning the documented genuine observation."""
    return {
        "passed": 99,
        "total": 100,
        "failed_ids": ["careless-typo-014"],
        "researchers_total": 32,
        "researchers_green": 32,
    }


class TestStratified100Claim(unittest.TestCase):
    def test_tampered_claim_score_inflated_fails(self):
        """A claim edited to 100/100 must FAIL against the real 99/100 run."""
        claim = _load_claim()
        tampered = copy.deepcopy(claim)
        tampered["observed"]["passed"] = 100
        tampered["observed"]["score"] = "100/100"
        tampered["observed"]["failed_profile_ids"] = []
        verdict = verify_claim(tampered, run=_genuine_run,
                               repo_root=REPO_ROOT)
        self.assertFalse(verdict.ok,
                         "inflated claim must not verify: %s" % verdict)
        self.assertTrue(
            any("score" in r.lower() for r in verdict.reasons),
            "failure reason must name the score mismatch: %s"
            % (verdict.reasons,))

    def test_changed_battery_config_fails_closed(self):
        """Perturbing one byte of the battery code must FAIL on hash drift."""
        claim = _load_claim()
        # Overlay: same file set, but run_batch.py with a single-byte change
        # in a scratch buffer — the real battery files are never touched.
        real = compute_config_hash(REPO_ROOT)
        target = None
        for f in real["files"]:
            if f["path"].endswith("profiles/run_batch.py"):
                target = f
                break
        self.assertIsNotNone(target, "run_batch.py must be a hashed input")
        perturbed = None
        from evals.verify_stratified_100_claim import _resolve
        for label, rel in _config_files_for_test():
            if rel == target["path"]:
                perturbed = _resolve(label, rel, REPO_ROOT).read_bytes() \
                    + b"# scratch perturbation\n"
        overlay = {target["path"]: perturbed}
        verdict = verify_claim(claim, run=_genuine_run,
                               repo_root=REPO_ROOT, overlay=overlay)
        self.assertFalse(verdict.ok,
                         "perturbed battery config must not verify: %s"
                         % verdict)
        self.assertTrue(
            any("config hash" in r.lower() for r in verdict.reasons),
            "failure reason must name the config-hash mismatch: %s"
            % (verdict.reasons,))
        self.assertTrue(
            any("run_batch.py" in r for r in verdict.reasons),
            "failure reason must name the drifted file: %s"
            % (verdict.reasons,))

    def test_genuine_current_state_passes(self):
        """The committed claim against the real battery run must PASS."""
        claim = _load_claim()
        verdict = verify_claim(claim, run=None, repo_root=REPO_ROOT)
        self.assertTrue(verdict.ok,
                        "genuine claim must verify: %s" % (verdict.reasons,))

    def test_unexpected_miss_fails(self):
        """A failure outside the documented known miss must FAIL."""
        claim = _load_claim()
        bad = _genuine_run()
        bad["passed"] = 98
        bad["failed_ids"] = ["careless-typo-014", "careless-typo-013"]
        verdict = verify_claim(claim, run=bad, repo_root=REPO_ROOT)
        self.assertFalse(verdict.ok,
                         "unexpected miss must not verify: %s" % verdict)

    def test_better_score_invalidates_claim(self):
        """100/100 observed against a 99/100 claim must FAIL (re-pin, not
        silent acceptance): a better score means the battery changed
        behaviour."""
        claim = _load_claim()
        better = _genuine_run()
        better["passed"] = 100
        better["failed_ids"] = []
        verdict = verify_claim(claim, run=better, repo_root=REPO_ROOT)
        self.assertFalse(verdict.ok,
                         "better score must invalidate the claim: %s"
                         % verdict)
        self.assertTrue(
            any("re-pin" in r.lower() or "repin" in r.lower()
                for r in verdict.reasons),
            "failure reason must demand a re-pin: %s" % (verdict.reasons,))


def _config_files_for_test():
    from evals.verify_stratified_100_claim import CONFIG_FILES
    return CONFIG_FILES


if __name__ == "__main__":
    unittest.main()
