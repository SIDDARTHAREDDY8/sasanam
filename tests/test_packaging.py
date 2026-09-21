"""Packaging invariants: the wheel ships the full package plus the policy.

Drift guard: ``gov/data/default.yaml`` (the copy shipped inside the wheel
via package-data) must be byte-identical to the canonical
``policies/default.yaml``. There is exactly one default policy.
"""

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class PackagingDriftTest(unittest.TestCase):
    def test_shipped_policy_is_byte_identical(self):
        canonical = REPO_ROOT / "policies" / "default.yaml"
        shipped = REPO_ROOT / "gov" / "data" / "default.yaml"
        self.assertTrue(canonical.is_file(), "missing canonical policy")
        self.assertTrue(
            shipped.is_file(),
            "gov/data/default.yaml missing: the wheel would ship no policy",
        )
        self.assertEqual(
            shipped.read_bytes(),
            canonical.read_bytes(),
            "gov/data/default.yaml drifted from policies/default.yaml: "
            "there is exactly one default policy",
        )

    def test_default_policy_path_resolves(self):
        from gov.policy import default_policy_path
        path = default_policy_path()
        self.assertTrue(
            Path(path).is_file(),
            "default_policy_path() does not resolve to a real file",
        )
        self.assertEqual(
            Path(path).read_bytes(),
            (REPO_ROOT / "policies" / "default.yaml").read_bytes(),
            "default_policy_path() must resolve to the canonical policy",
        )


if __name__ == "__main__":
    unittest.main()
