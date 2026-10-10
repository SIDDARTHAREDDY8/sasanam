#!/usr/bin/env python3
"""Round-67 attack battery (wave-399 merge reconciliation).

F-number reconciliation (wave-272 earliest-filing): lane 3's F1080-F1082
(11:25 UTC, CLOSED) keep their numbers; attack round 67's F1080/F1081/F1082
(11:33 UTC) renumbered to F1086/F1087/F1088; lane 1's F1080 (11:41 UTC)
renumbered to F1089; attack's F1083/F1084/F1085 keep their numbers.

Pins marked OPEN: verdict HELD while the payload still MISSES (finding open),
BREAK if the payload ever gets blocked (pin broken). F1074-F1079 were carried
as OPEN pins from round 66 but are CLOSED on the merged tree -- pinned here
as closed (must BLOCK). F1085 pinned via its red-first SHAPES (provenance
seam, instruction_shaped harness -- matches w399_f1085_redfirst.py).
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

TAXONOMY_PIN = 2143  # wave-398 merge (no code-count change)

from gov import dlp
from gov.decision_codes import TAXONOMY
from gov.instruction_provenance import (
    ActionRequest, IngressLabeler, Label, grant_check, instruction_shaped,
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
    """Control: wave-400 merge footer (F1083-F1092 CLOSED (10);
    F1093-F1102 OPEN (10); next free F1103)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("# Wave-400: F1083-F1092 CLOSED (10); F1093-F1102 OPEN (10); next free F1103" in text
          and "Next free finding: **F1103**" in text
          and "F1093-F1102 OPEN (10" in text)
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


def _open_pin_filtered(prefix, num, keep):
    """Subset of red-first shapes for an OPEN finding must still MISS."""
    @_t
    def _fn():
        shapes = [(n, p) for n, p in _redfirst_shapes(prefix, num) if keep(n)]
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


# Carried round-66 pins (F1074-F1077 decoder seam) -- CLOSED on the merged tree.
for _n in (1074, 1075, 1076, 1077):
    _closed_pin("w398", _n)

# Round-67 pins (decoder seam) -- CLOSED on the merged tree (wave-400 lanes 1-3).
# (F1086/F1087/F1088 are attack round 67's renumbered F1080/F1081/F1082;
# F1089 is lane 1's renumbered F1080.)
for _n in (1083, 1084, 1086, 1087, 1088, 1089):
    _closed_pin("w399", _n)


@_t
def test_closed_w399_f1078():
    """F1078 + its F1080/F1081/F1082 twins (all CLOSED wave-399 lane 3) must BLOCK."""
    shapes = _redfirst_shapes("w399", 1078)
    bad = [name for name, payload in shapes if _misses(payload)]
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_closed_w399_f1078 (%d shapes%s)" % (
        len(shapes), "" if ok else ": " + ",".join(bad)))
    return ok


def _prov_open(prefix, num):
    """Provenance carriers for an OPEN finding must still evade routing
    (grant_check harness)."""
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


@_t
def test_closed_w398_f1079_provenance():
    """F1079 carriers (CLOSED wave-399 lane 3) must now route to approval."""
    shapes = _redfirst_shapes("w398", 1079)
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
    print(("HELD " if ok else "BREAK") + " test_closed_w398_f1079_provenance (%d carriers%s)" % (
        len(shapes), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_closed_w399_f1085_provenance():
    """F1085 carriers must now be flagged by the seam (CLOSED wave-400 lane 3;
    instruction_shaped harness, matching w399_f1085_redfirst.py)."""
    shapes = _redfirst_shapes("w399", 1085)
    bad = [name for name, payload in shapes if not instruction_shaped(payload)]
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_closed_w399_f1085_provenance (%d carriers%s)" % (
        len(shapes), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_c0_junk_quiet():
    """Control: junk stays quiet."""
    ok = _misses("(function(){var s='ab';return s;})()")
    print(("HELD " if ok else "BREAK") + " test_c0_junk_quiet")
    return ok


@_t
def test_green_w398():
    """Depth-1 green check on w398's battery (carries F1065-F1079 pins).
    On the merged tree exactly the 6 now-closed pins must flip
    (F1074-F1078 decoder + F1079 provenance); anything else breaking is real.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("HELD  test_green_w398 (skipped: GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w398_attack_probes.py")],
        capture_output=True, text=True, timeout=600, env=env,
        cwd=os.path.join(REPO_ROOT, "evals"))
    expected_flips = {"test_open_w398_f1074", "test_open_w398_f1075",
                      "test_open_w398_f1076", "test_open_w398_f1077",
                      "test_open_w398_f1078", "test_open_w398_f1079_provenance"}
    flips, real = [], []
    for line in (r.stdout or "").split("\n"):
        s = line.strip()
        if s.startswith("BREAK "):
            nm = s.split(" ", 1)[1].split(" ", 1)[0]
            (flips if nm in expected_flips else real).append(nm)
    ok = (not real and set(flips) == expected_flips)
    print(("HELD " if ok else "BREAK") + " test_green_w398 "
          "(flips %d/6, real BREAK %s)" % (len(flips), real))
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
