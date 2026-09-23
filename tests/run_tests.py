"""Run the agent-governance red-team suite with stdlib unittest only.

Usage:
    cd ~/workspace/agent-governance && python3 tests/run_tests.py
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# F75 supply-chain gate: fail closed BEFORE test collection. If the
# environment contains an unlisted package (typosquat /
# dependency-confusion shape) or a version that drifted from the pinned
# lockfile, the suite must not run green on a poisoned venv.
try:
    from gov import supplychain
except ImportError as e:  # gov/ itself unreadable: also fail closed
    print("SUPPLY-CHAIN FAIL-CLOSED: cannot import gov.supplychain (%s)" % e)
    sys.exit(1)
try:
    _audit = supplychain.audit_environment()
except supplychain.SupplyChainError as e:
    print("SUPPLY-CHAIN FAIL-CLOSED: %s" % e)
    sys.exit(1)
print("supply-chain audit OK: %d distributions checked against "
      "requirements.lock" % _audit["checked"])

# Wave-24 run-dir hygiene: the suite creates thousands of temp run dirs
# (tests/harness.make_run "govred-*" at 344+ call sites, plus direct
# tempfile.mkdtemp scratch in ~28 test modules). Wave-23 showed these
# leaking run-over-run until the /tmp tmpfs filled (Errno 28). The
# snapshot + finally below removes everything the suite run created:
# the harness's explicit registry first, then a sweep for any new dirs
# (probe-internal scratch the registry never sees), with the same
# safety guards as evals/run_evals.py (strictly inside the process temp
# dir, no symlinks, /proc liveness veto). GOV_KEEP_RUN_DIRS=1 retains
# everything for debugging; a red suite retains too unless
# GOV_KEEP_RUN_DIRS=0 forces cleanup.
from tests import harness as _hygiene_harness

_tmpdir = tempfile.gettempdir()
try:
    _tmp_before = set(os.listdir(_tmpdir))
except OSError:
    _tmp_before = set()

loader = unittest.TestLoader()
suite = loader.discover(
    start_dir=str(ROOT / "tests"),
    pattern="test_*.py",
    top_level_dir=str(ROOT),
)
runner = unittest.TextTestRunner(verbosity=2)
try:
    result = runner.run(suite)
finally:
    ok = result.wasSuccessful() if "result" in dir() else False
    stats = _hygiene_harness.cleanup_run_dirs(success=ok)
    # Backstop sweep: entries that appeared during the run but were
    # never registered (direct mkdtemp / NamedTemporaryFile scratch in
    # test modules). Directories AND regular files: 42 scratch policy
    # YAMLs per green run were the only leftovers after the dir sweep.
    keep_env = os.environ.get("GOV_KEEP_RUN_DIRS")
    if keep_env != "1" and (ok or keep_env == "0"):
        try:
            _tmp_after = set(os.listdir(_tmpdir))
        except OSError:
            _tmp_after = set()
        for name in sorted(_tmp_after - _tmp_before):
            p = os.path.join(_tmpdir, name)
            if os.path.isdir(p) and not os.path.islink(p):
                _hygiene_harness._safe_remove_run_dir(p, stats)
            else:
                _hygiene_harness._safe_remove_run_file(p, stats)
    print("run-dir hygiene: removed=%d kept_in_use=%d kept_outside_tmp=%d "
          "kept_missing=%d errors=%d retained=%d (registered=%d) "
          "kept_foreign_owned=%d" % (
              stats["removed"], stats["kept_in_use"],
              stats["kept_outside_tmp"], stats["kept_missing"],
              stats["errors"], stats["retained"], stats["registered"],
              stats["kept_foreign_owned"]))
sys.exit(0 if result.wasSuccessful() else 1)
