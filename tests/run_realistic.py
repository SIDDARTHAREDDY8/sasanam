"""Run the realistic agent battery — SEPARATE from the unit gate.

QA gate-report coordination items implemented here:

(1) tests/run_tests.py discovers ``test_*.py`` RECURSIVELY via
    unittest discovery. Realistic battery files MUST therefore NOT be
    named ``test_*.py`` — they live in tests/realistic/ as
    ``scenario_*.py`` and are executed only by this runner. This module
    fails fast if a ``test_*.py`` file ever appears under
    tests/realistic/, so the unit gate can never silently absorb a
    realistic scenario.

(2) TMPDIR convention: every scenario run gets a PRIVATE SUBDIRECTORY
    under the mandated root — TMPDIR=/tmp/gov-run/<runid> — never the
    bare root concurrently. The subdir is created before the scenario,
    TMPDIR points at it for the scenario's duration (tempfile-based run
    dirs therefore land inside it), and it is removed afterwards. The
    runner also verifies nothing leaked directly under the bare root.

Scenario module contract (tests/realistic/scenario_*.py and
tests/realistic/scenarios_*.py):
    SCENARIO = {"id": "...", "title": "..."}   # optional metadata
    def run(): ...                             # required
``run()`` returns a dict of check results (or None) on success and
raises (AssertionError or anything else) on failure. Deterministic,
$0-spend, synthetic/local only — same rules as the unit suite.

Usage:
    TMPDIR=/tmp/gov-run python3 tests/run_realistic.py [--list]
"""

import importlib.util
import os
import shutil
import sys
import traceback
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REALISTIC_DIR = ROOT / "tests" / "realistic"
TMP_ROOT = Path(os.environ.get("GOV_RUN_ROOT", "/tmp/gov-run"))

sys.path.insert(0, str(ROOT))
# The agentkit prototype lives in workstreams/realagent (sibling of the
# repo root), not under tests/. Scenario packs import it directly; the
# runner owns sys.path setup so the packs stay clean.
_WS_REALAGENT = ROOT.parent / "workstreams" / "realagent"
if _WS_REALAGENT.is_dir():
    sys.path.insert(0, str(_WS_REALAGENT))


def _fail(msg):
    print("run_realistic: FATAL: %s" % msg, file=sys.stderr)
    sys.exit(2)


def _enforce_naming():
    """QA item (1): no test_*.py may live under tests/realistic/."""
    bad = sorted(p.name for p in REALISTIC_DIR.glob("test_*.py"))
    if bad:
        _fail(
            "tests/realistic/ contains test_*.py file(s) %s, which the "
            "unit gate (tests/run_tests.py, recursive discovery) would "
            "absorb. Rename them to scenario_*.py." % bad)


def _discover():
    # Both singular (scenario_smoke.py) and plural-pack
    # (scenarios_human_error.py, scenarios_swarm.py) names are run.
    seen = {}
    for pat in ("scenario_*.py", "scenarios_*.py"):
        for p in REALISTIC_DIR.glob(pat):
            seen[p.name] = p
    return sorted(seen.values(), key=lambda p: p.name)


def _load(path):
    mod_name = "realistic_" + path.stem
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    if spec is None or spec.loader is None:
        _fail("cannot load scenario module %s" % path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run_one(path):
    """Run one scenario with a private TMPDIR subdir (QA item 2)."""
    stem = path.stem
    mod = _load(path)
    meta = getattr(mod, "SCENARIO", {}) or {}
    label = meta.get("id", stem)
    if not hasattr(mod, "run") or not callable(mod.run):
        return (label, False, "scenario module defines no run() callable",
                None)
    runid = "realistic-%s-p%d-%s" % (stem, os.getpid(), uuid.uuid4().hex[:8])
    tmpdir = TMP_ROOT / runid
    # Private subdir per run; exist_ok=False so a collision is loud.
    tmpdir.mkdir(parents=True, exist_ok=False)
    before = set(TMP_ROOT.iterdir())
    old_tmpdir = os.environ.get("TMPDIR")
    os.environ["TMPDIR"] = str(tmpdir)
    # tempfile caches its directory choice per process: drop the cache so
    # tempfile-based run dirs land in THIS scenario's private subdir, not
    # in a previous scenario's (already removed) one.
    import tempfile as _tempfile
    _tempfile.tempdir = None
    ok, detail, result = True, "", None
    try:
        result = mod.run()
        if result is None:
            result = {}
        detail = "ok"
    except Exception as e:  # noqa: BLE001 - harness reports, never hides
        ok = False
        detail = "%s: %s\n%s" % (
            type(e).__name__, e,
            "".join(traceback.format_exception(e)).strip().splitlines()[-1]
            if traceback.format_exception(e) else "")
    finally:
        # Restore the caller's TMPDIR, then remove the private subdir.
        if old_tmpdir is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old_tmpdir
        shutil.rmtree(tmpdir, ignore_errors=True)
        # Nothing may leak directly under the bare root.
        leaked = [p.name for p in set(TMP_ROOT.iterdir()) - before
                  if p.name != runid]
        if leaked:
            ok = False
            detail = ("leaked entries under bare TMPDIR root /tmp/gov-run: "
                      "%s" % sorted(leaked))
    return (label, ok, detail, result)


def main(argv):
    if not REALISTIC_DIR.is_dir():
        _fail("tests/realistic/ not found")
    _enforce_naming()
    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    scenarios = _discover()
    if argv[1:] == ["--list"]:
        for p in scenarios:
            print(p.stem)
        return 0
    if not scenarios:
        print("run_realistic: no scenario_*.py files under tests/realistic/ "
              "(nothing to run)")
        return 0
    print("run_realistic: %d scenario(s), TMPDIR root %s"
          % (len(scenarios), TMP_ROOT))
    failures = 0
    for path in scenarios:
        label, ok, detail, _result = _run_one(path)
        status = "PASS" if ok else "FAIL"
        print("[%s] %s: %s" % (status, label, detail))
        if not ok:
            failures += 1
    print("run_realistic: %d passed, %d failed"
          % (len(scenarios) - failures, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
