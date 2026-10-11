#!/usr/bin/env python3
"""Round-78 attack battery: 26 new pins (expected miss/quiet).

Pins marked OPEN: verdict HELD while the payload still MISSES (finding open),
BREAK if the payload ever gets blocked (pin broken). New pins F1289-F1308
via their w410 red-first SHAPES (decoder seam, find_credential); F1309-F1314
via their w410 red-first SHAPES (provenance seam, instruction_shaped quiet).
Carries forward F1260-F1288 OPEN pins (must still MISS/QUIET) via their w409
red-first SHAPES.
$0-spend-by-construction (no harness/paid refs; model spend lives in the ledger).
"""
import importlib.util
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # wave-409 merge (no code-count change)

from gov import dlp
from gov.decision_codes import TAXONOMY
from gov.instruction_provenance import instruction_shaped

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _misses(payload):
    return dlp.find_credential(payload) is None


def _quiet(payload):
    return not instruction_shaped(payload)


def _redfirst_shapes(prefix, num):
    """Import a red-first module's SHAPES (import is side-effect free)."""
    path = os.path.join(REPO_ROOT, "evals", "%s_f%d_redfirst.py" % (prefix, num))
    spec = importlib.util.spec_from_file_location("%s_f%d_rf" % (prefix, num), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHAPES


@_t
def test_b0_footer_state():
    """Control: wave-410 attack footer (F1289-F1314 OPEN (26); next free F1315)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("F1289-F1314 filed OPEN (26" in text
          and "next free F1315" in text)
    print(("HELD " if ok else "BREAK") + " test_b0_footer_state")
    return ok


@_t
def test_b1_taxonomy_pin():
    """Control: pin unchanged (no decision-code change this round)."""
    ok = len(TAXONOMY) == TAXONOMY_PIN
    print(("HELD " if ok else "BREAK") + " test_b1_taxonomy_pin (%d)" % len(TAXONOMY))
    return ok


def _open_pin(prefix, num):
    """All red-first shapes for an OPEN decoder finding must still MISS."""
    @_t
    def _fn():
        shapes = _redfirst_shapes(prefix, num)
        bad = [name for name, payload in shapes if not _misses(payload)]
        ok = not bad
        print(("HELD " if ok else "BREAK") + " test_open_%s_f%d (%d shapes%s)" % (
            prefix, num, len(shapes), "" if ok else ": " + ",".join(bad)))
        return ok
    _fn.__name__ = "test_open_%s_f%d" % (prefix, num)
    return _fn


def _open_prov_pin(prefix, num):
    """All red-first shapes for an OPEN provenance finding must stay QUIET."""
    @_t
    def _fn():
        shapes = _redfirst_shapes(prefix, num)
        bad = [name for name, payload in shapes if not _quiet(payload)]
        ok = not bad
        print(("HELD " if ok else "BREAK") + " test_open_%s_f%d (%d shapes%s)" % (
            prefix, num, len(shapes), "" if ok else ": " + ",".join(bad)))
        return ok
    _fn.__name__ = "test_open_%s_f%d" % (prefix, num)
    return _fn


# New round-78 decoder pins (F1289-F1308) -- still OPEN.
for _n in range(1289, 1309):
    _open_pin("w410", _n)

# New round-78 provenance pins (F1309-F1314) -- still OPEN.
for _n in range(1309, 1315):
    _open_prov_pin("w410", _n)

# Round-77 pins carried forward: F1260-F1282 decoder (OPEN), F1283-F1288 provenance (OPEN).
for _n in range(1260, 1283):
    _open_pin("w409", _n)
for _n in range(1283, 1289):
    _open_prov_pin("w409", _n)


@_t
def test_c0_junk_quiet():
    """Control: junk stays quiet on both seams."""
    ok = _misses("The quarterly financial summary shows revenue growth.")
    ok = ok and _quiet("Hi team, please see the quarterly report summary below. Best, Alice")
    print(("HELD " if ok else "BREAK") + " test_c0_junk_quiet")
    return ok


@_t
def test_green_w409():
    """Depth-1 green check on w409's battery (carries F1260-F1288 OPEN pins)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("HELD  test_green_w409 (skipped: GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g410-attack-green-", dir="/var/tmp")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w409_attack_probes.py")],
        capture_output=True, text=True, timeout=600, env=env,
        cwd=os.path.join(REPO_ROOT, "evals"))
    ok = r.returncode == 0
    print(("HELD " if ok else "BREAK") + " test_green_w409")
    if not ok:
        print(r.stdout[-2000:] if r.stdout else "")
        print(r.stderr[-2000:] if r.stderr else "")
    return ok


def main():
    fails = []
    for fn in TESTS:
        try:
            ok = fn()
        except Exception as e:  # noqa: BLE001
            print("BREAK " + fn.__name__ + " (exception: %r)" % e)
            ok = False
        if not ok:
            fails.append(fn.__name__)
    print("%d tests, %d BREAK" % (len(TESTS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
