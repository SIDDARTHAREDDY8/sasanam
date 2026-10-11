#!/usr/bin/env python3
"""Round-74 attack battery: 17 new pins (expected miss/quiet).

Pins marked OPEN: verdict HELD while the payload still MISSES (finding open),
BREAK if the payload ever gets blocked (pin broken). New pins F1182-F1195
via their w406 red-first SHAPES (decoder seam, find_credential);
F1196-F1198 via their w406 red-first SHAPES (provenance seam,
instruction_shaped QUIET). $0-spend-by-construction
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

TAXONOMY_PIN = 2143  # wave-405 merge (no code-count change)

from gov import dlp
from gov.instruction_provenance import instruction_shaped
from gov.decision_codes import TAXONOMY

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
    """Control: wave-406 round-74 footer (F1182-F1198 filed OPEN (17);
    next free F1199)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("F1182-F1198 filed OPEN (17" in text
          and "Next free finding: **F1199**" in text)
    print(("HELD " if ok else "BREAK") + " test_b0_footer_state")
    return ok


@_t
def test_b1_taxonomy_pin():
    """Control: pin unchanged (no decision-code change this round)."""
    ok = len(TAXONOMY) == TAXONOMY_PIN
    print(("HELD " if ok else "BREAK") + " test_b1_taxonomy_pin")
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
        print(("HELD " if ok else "BREAK") + " test_open_prov_%s_f%d (%d shapes%s)" % (
            prefix, num, len(shapes), "" if ok else ": " + ",".join(bad)))
        return ok
    _fn.__name__ = "test_open_prov_%s_f%d" % (prefix, num)
    return _fn


# New round-74 decoder pins (F1182-F1195) -- still OPEN.
for _n in range(1182, 1196):
    _open_pin("w406", _n)

# New round-74 provenance pins (F1196-F1198) -- still OPEN (QUIET).
for _n in range(1196, 1199):
    _open_prov_pin("w406", _n)

# Round-73 pins (F1159-F1181) are now CLOSED on the merged tree
# (wave-406 lanes 1-4); verified by w405_attack_probes.py
# (F1159-F1181 CLOSED). Not duplicated here.


@_t
def test_c0_junk_quiet():
    """Control: junk stays quiet."""
    ok = _misses("(function(){var s='ab';return s;})()")
    print(("HELD " if ok else "BREAK") + " test_c0_junk_quiet")
    return ok


@_t
def test_green_w405():
    """Depth-1 green check on w405's battery (carries F1159-F1181 pins)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("HELD  test_green_w405 (skipped: GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g406m-attack-green-", dir="/var/tmp")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w405_attack_probes.py")],
        capture_output=True, text=True, timeout=600, env=env,
        cwd=os.path.join(REPO_ROOT, "evals"))
    ok = r.returncode == 0
    print(("HELD " if ok else "BREAK") + " test_green_w405")
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
    n_bad = sum(1 for _, ok in results if not ok)
    print("w406_attack_probes: %d/%d HELD" % (len(results) - n_bad, len(results)))
    return 1 if n_bad else 0


if __name__ == "__main__":
    sys.exit(main())
