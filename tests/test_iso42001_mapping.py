"""H21: ISO/IEC 42001 mapping conformance gate.

``docs/iso42001-mapping.json`` is the provisional regulator-shaped
mapping; ``evals/iso42001_mapping_conformance.py`` checks every
control's cited product mechanisms and tests against the repo tree.
This wrapper wires that check into the canonical suite so mapping
drift fails the pre-push gates loudly (H21 acceptance).

$0 spend, synthetic/local. Deterministic (filesystem reads only).
"""

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from evals.iso42001_mapping_conformance import (  # noqa: E402
    MAPPING_PATH, check_conformance)


class TestISO42001MappingConformance(unittest.TestCase):
    def test_mapping_file_exists(self):
        self.assertTrue(
            MAPPING_PATH.exists(),
            "ISO 42001 mapping file missing: %s" % MAPPING_PATH)

    def test_every_control_resolves(self):
        ok, problems, stats = check_conformance()
        self.assertTrue(
            ok,
            "ISO 42001 mapping drift (%d problems) -- update the "
            "mapping or restore the mechanism; never delete the "
            "citation silently:\n%s"
            % (len(problems), "\n".join("  - " + p for p in problems)))
        # Tripwire against silent mapping shrinkage: the counts are
        # asserted, not just set inclusion.
        self.assertGreaterEqual(stats["controls"], 36)
        self.assertGreaterEqual(stats["mechanisms"], 1)
        self.assertGreaterEqual(stats["tests"], 1)


if __name__ == "__main__":
    unittest.main()
