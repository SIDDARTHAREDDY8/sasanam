#!/usr/bin/env python3
"""Round-70 attack battery: 10 new pins (expected miss) + carried F1103-F1110.

Pins marked OPEN: verdict HELD while the payload still MISSES (finding open),
BREAK if the payload ever gets blocked (pin broken). New pins F1111-F1120 via
their w402 red-first SHAPES (decoder seam). F1103-F1110 carried via their
w401 red-first SHAPES (all still OPEN on this tree). $0-spend-by-construction
(no harness/paid refs; model spend lives in the ledger).
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

TAXONOMY_PIN = 2143  # wave-401 merge (no code-count change)

from gov import dlp
from gov.decision_codes import TAXONOMY

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _misses(payload):
    return dlp.find_credential(payload) is None


def _redfirst_shapes(prefix, num):
    """Import a red-first module's SHAPES (import is side-effect free)."""
    path = os.path.join(REPO_ROOT, "evals", "%s_f%d_redfirst.py" % (prefix, num))
    spec = importlib.util.spec_from_file_location("%s_f%d_rf" % (prefix, num), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHAPES


@_t
def test_b0_footer_state():
    """Control: wave-403 footer (F1111-F1122 CLOSED (12); F1123-F1141 OPEN (19);
    next free F1142)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("# Wave-403: F1111-F1122 CLOSED (12); F1123-F1141 OPEN (19); next free F1142" in text)
    print(("HELD " if ok else "BREAK") + " test_b0_footer_state")
    return ok


@_t
def test_b1_taxonomy_pin():
    """Control: pin unchanged (no decision-code change this round)."""
    ok = len(TAXONOMY) == TAXONOMY_PIN
    print(("HELD " if ok else "BREAK") + " test_b1_taxonomy_pin")
    return ok


def _open_pin(prefix, num):
    """All red-first shapes for an OPEN finding must still MISS."""
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

def _closed_pin(prefix, num):
    """All red-first shapes for a CLOSED finding must now BLOCK."""
    @_t
    def _fn():
        shapes = _redfirst_shapes(prefix, num)
        bad = [name for name, payload in shapes if _misses(payload)]
        ok = not bad
        print(("HELD " if ok else "BREAK") + " test_closed_%s_f%d (%d shapes%s)" % (
            prefix, num, len(shapes), "" if ok else ": " + ",".join(bad)))
        return ok
    _fn.__name__ = "test_closed_%s_f%d" % (prefix, num)
    return _fn


# Round-70 pins (F1111-F1120 decoder seam) -- CLOSED on the merged tree
# (wave-403 lanes 1-3), except F1119 which is partially closed (see below).
for _n in (1111, 1112, 1113, 1114, 1115, 1116, 1117, 1118, 1120):
    _closed_pin("w402", _n)


@_t
def test_partial_w402_f1119():
    """F1119 is now FULLY closed: the for-of and for-await (no trailing)
    shapes block, and the trailing-statement variants (F1141, closed
    wave-404 lane 4) also block.
    """
    shapes = _redfirst_shapes("w402", 1119)
    # The first 2 shapes (for-of, for-await no trailing) must block
    missed_head = [name for name, payload in shapes[:2] if _misses(payload)]
    # The last 2 shapes (trailing variants, F1141 CLOSED wave-404 lane 4)
    # must now also block
    missed_trailing = [name for name, payload in shapes[2:] if _misses(payload)]
    ok = (not missed_head) and (not missed_trailing)
    print(("HELD " if ok else "BREAK") + " test_partial_w402_f1119 "
          "(head-miss=%s, trailing-miss=%s)" % (missed_head, missed_trailing))
    return ok

# Wave-402 lane 3 self-files renumbered F1121/F1122 (F1091 residuals) -- CLOSED
# on the merged tree (wave-403 lane 4).
for _n in (1121, 1122):
    _closed_pin("w402", _n)

# Carried round-69 pins (F1103-F1110) -- CLOSED on the merged tree
# (wave-402 lanes 1-4).
for _n in (1103, 1104, 1105, 1106, 1107, 1108, 1110):
    _closed_pin("w401", _n)


@_t
def test_closed_w401_f1109_provenance():
    """F1109 carriers must now be flagged by the seam (CLOSED wave-402 lane 4;
    instruction_shaped harness, matching w401_f1109_redfirst.py)."""
    from gov.instruction_provenance import instruction_shaped
    shapes = _redfirst_shapes("w401", 1109)
    bad = [name for name, payload in shapes if not instruction_shaped(payload)]
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_closed_w401_f1109_provenance (%d carriers%s)" % (
        len(shapes), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_c0_junk_quiet():
    """Control: junk stays quiet."""
    ok = _misses("(function(){var s='ab';return s;})()")
    print(("HELD " if ok else "BREAK") + " test_c0_junk_quiet")
    return ok


@_t
def test_green_w401():
    """Depth-1 green check on w401's battery (carries F1093-F1110 pins)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("HELD  test_green_w401 (skipped: GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g402m-attack-green-", dir="/var/tmp")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w401_attack_probes.py")],
        capture_output=True, text=True, timeout=600, env=env,
        cwd=os.path.join(REPO_ROOT, "evals"))
    ok = r.returncode == 0
    print(("HELD " if ok else "BREAK") + " test_green_w401")
    if not ok:
        print((r.stdout or "")[-500:])
    return ok


def main():
    results = []
    for t in TESTS:
        try:
            results.append((t.__name__, bool(t())))
        except Exception as e:  # noqa: BLE001
            print("BREAK " + t.__name__ + " (exception: %s)" % str(e)[:120])
            results.append((t.__name__, False))
    n_break = sum(1 for _, ok in results if not ok)
    print("%d tests, %d BREAK" % (len(results), n_break))
    return 1 if n_break else 0


if __name__ == "__main__":
    sys.exit(main())
