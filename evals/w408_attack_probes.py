#!/usr/bin/env python3
"""Round-76 attack battery: 31 new pins (expected miss/quiet).

Pins marked OPEN: verdict HELD while the payload still MISSES (finding open),
BREAK if the payload ever gets blocked (pin broken). New pins F1229-F1255 + F1259
via their w408 red-first SHAPES (decoder seam, find_credential); F1255-F1258
via their w408 red-first SHAPES (provenance seam, instruction_shaped quiet).
Carries forward F1199-F1227 OPEN pins (must still MISS).
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

TAXONOMY_PIN = 2143  # wave-407 merge (no code-count change)

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
    """Control: wave-408 attack footer (F1228-F1258 filed OPEN (31); F1228 renumbered to F1259 at merge (wave-272); next free F1260)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("F1229-F1259 filed OPEN (31," in text
          and "next free F1259" in text
          and "F1182-F1198 CLOSED (17)" in text
          and "F1199-F1227 OPEN (29)" in text)
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


# New round-76 decoder pins (F1229-F1254 + F1259) -- still OPEN. (F1228 renumbered to F1259; lane 4's F1228 CLOSED.)
for _n in range(1229, 1255):
    _open_pin("w408", _n)
_open_pin("w408", 1259)

# New round-76 provenance pins (F1255-F1258) -- still OPEN.
for _n in range(1255, 1259):
    _open_prov_pin("w408", _n)

# Round-75 pins carried forward (F1199-F1227) -- still OPEN.
for _n in range(1199, 1228):
    _open_pin("w407", _n)


@_t
def test_c0_junk_quiet():
    """Control: junk stays quiet on both seams."""
    ok = _misses("The quarterly financial summary shows revenue growth.")
    ok = ok and _quiet("Hi team, please see the quarterly report summary below. Best, Alice")
    print(("HELD " if ok else "BREAK") + " test_c0_junk_quiet")
    return ok


@_t
def test_green_w407():
    """Depth-1 green check on w407's battery (carries F1199-F1227 pins)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("HELD  test_green_w407 (skipped: GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g408m-attack-green-", dir="/var/tmp")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w407_attack_probes.py")],
        capture_output=True, text=True, timeout=600, env=env,
        cwd=os.path.join(REPO_ROOT, "evals"))
    ok = r.returncode == 0
    print(("HELD " if ok else "BREAK") + " test_green_w407")
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
