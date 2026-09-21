"""Run the agent-governance red-team suite with stdlib unittest only.

Usage:
    cd ~/workspace/agent-governance && python3 tests/run_tests.py
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

loader = unittest.TestLoader()
suite = loader.discover(
    start_dir=str(ROOT / "tests"),
    pattern="test_*.py",
    top_level_dir=str(ROOT),
)
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
