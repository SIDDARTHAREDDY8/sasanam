#!/usr/bin/env python3
"""Round-66 attack battery: 6 new pins (expected miss) + carried F1065-F1073.

Pins marked OPEN: verdict HELD while the payload still MISSES (finding open),
BREAK if the payload ever gets blocked (pin broken). F1065-F1073 carried via
their w397 red-first SHAPES (decoder seam) and the F1073 carrier shapes
(provenance seam, grant_check harness).
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

TAXONOMY_PIN = 2143  # wave-397 merge (no code-count change)

from gov import dlp
from gov.decision_codes import TAXONOMY
from gov.instruction_provenance import (
    ActionRequest, IngressLabeler, Label, grant_check,
)

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
    """Control: wave-398 merge footer (F1065-F1073 closed (9); F1074-F1079 open (6); next F1080)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("F1065-F1073 CLOSED (9" in text
          and "Next free finding: **F1080**" in text
          and "F1074-F1079 OPEN (6" in text)
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



# New round-66 pins (F1074-F1078 decoder seam).
for _n in (1074, 1075, 1076, 1077, 1078):
    _open_pin("w398", _n)

# Carried round-65 pins (F1065-F1072 decoder seam) -- CLOSED at the wave-398
# merge; must now BLOCK.
for _n in range(1065, 1073):
    _closed_pin("w397", _n)


def _prov_open(prefix, num):
    """Provenance carriers for an OPEN finding must still evade routing."""
    @_t
    def _fn():
        shapes = _redfirst_shapes(prefix, num)
        bad = []
        for name, body in shapes:
            lab = IngressLabeler()
            unit = lab.ingest(body, Label.RETRIEVED_UNTRUSTED,
                              carrier="inbox-msg#9(public)")
            req = ActionRequest(action="wire_transfer",
                                args={"to_account": "987654321", "amount": 48200},
                                consequential=True,
                                driving_units=[unit.unit_id])
            if grant_check(req, lab).routed_to_approval:
                bad.append(name)
        ok = not bad
        print(("HELD " if ok else "BREAK") + " test_open_%s_f%d_provenance (%d carriers%s)" % (
            prefix, num, len(shapes), "" if ok else ": " + ",".join(bad)))
        return ok
    _fn.__name__ = "test_open_%s_f%d_provenance" % (prefix, num)
    return _fn


_prov_open("w398", 1079)


def _prov_closed(prefix, num):
    """Provenance carriers for a CLOSED finding must now route to approval."""
    @_t
    def _fn():
        shapes = _redfirst_shapes(prefix, num)
        bad = []
        for name, body in shapes:
            lab = IngressLabeler()
            unit = lab.ingest(body, Label.RETRIEVED_UNTRUSTED,
                              carrier="inbox-msg#9(public)")
            req = ActionRequest(action="wire_transfer",
                                args={"to_account": "987654321", "amount": 48200},
                                consequential=True,
                                driving_units=[unit.unit_id])
            if not grant_check(req, lab).routed_to_approval:
                bad.append(name)
        ok = not bad
        print(("HELD " if ok else "BREAK") + " test_closed_%s_f%d_provenance (%d carriers%s)" % (
            prefix, num, len(shapes), "" if ok else ": " + ",".join(bad)))
        return ok
    _fn.__name__ = "test_closed_%s_f%d_provenance" % (prefix, num)
    return _fn

_prov_closed("w397", 1073)


@_t
def test_c0_junk_quiet():
    """Control: junk stays quiet."""
    ok = _misses("(function(){var s='ab';return s;})()")
    print(("HELD " if ok else "BREAK") + " test_c0_junk_quiet")
    return ok


@_t
def test_green_w397():
    """Depth-1 green check on w397's battery (carries F1048-F1073 pins)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("HELD  test_green_w397 (skipped: GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w397_attack_probes.py")],
        capture_output=True, text=True, timeout=600, env=env,
        cwd=os.path.join(REPO_ROOT, "evals"))
    ok = r.returncode == 0
    print(("HELD " if ok else "BREAK") + " test_green_w397")
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
