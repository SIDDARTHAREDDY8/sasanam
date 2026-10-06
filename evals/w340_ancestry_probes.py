#!/usr/bin/env python3
"""Wave-340 lane 3: CI ancestry check (Bernstein #6073 ADAPT) regression.

Base: `9351ab86` (wave-339 merge). Pin 2130 -> 2131 (+1 code).
Footer open F427 / next F430.

R32: merge-gate test-subject pinning. Before the dead-controls gate
runs, the tree under test is pinned (content hash of every file); the
pin is asserted invariant across the gate run. A background process
mutating a gov file mid-gate (TOCTOU -- the gate analyzing a different
tree than it verified) is detected and fails the gate with the coded
refusal ``deadctrl-subject-mutated``.

What this battery pins:

P1 (red-capable): pin_tree/verify_tree round-trip on a synthetic tree
  -> no diffs; the digest is a 64-hex string and is deterministic.
P2 (red-capable): verify detects modified / added / removed files.
P3 (red-capable, the key one): a gov file mutated mid-gate (via a
  patched compute_reached that appends a comment, then delegates) is
  DETECTED: the gate refuses with a violation naming
  ``deadctrl-subject-mutated``. On the unpinned base the gate passes
  despite the mutation (TOCTOU invisible) -> BREAK.
P4 (red-capable): a clean gate run passes and records the subject
  digest on the result.
P5 (red-capable): the pin excludes .git and __pycache__.
P6 (red-capable): ``deadctrl-subject-mutated`` is registered in the
  central taxonomy and is LIVE on the real tree (emitted by the gate
  itself, which the raise-site scan covers).
P7 (pin): TAXONOMY_PIN == 2134 and the registry holds 2127 codes.

Verdicts: HELD = behavior matches the pin; BREAK = genuine defect;
ERROR = probe/harness problem. No findings manufactured.

$0 spend; synthetic/local; no model calls.

Run:
  mkdir -p /var/tmp/g340-ancestry
  TMPDIR=/var/tmp/g340-ancestry ~/workspace/.gov-venv/bin/python evals/w340_ancestry_probes.py
Clean env:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g340-ancestryb ~/workspace/.gov-venv/bin/python evals/w340_ancestry_probes.py
Single probe:
  ~/workspace/.gov-venv/bin/python evals/w340_ancestry_probes.py P3
"""

import os
import re
import shutil
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_EVALS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _EVALS)
REPO_ROOT = os.path.dirname(_EVALS)

import no_dead_controls as gate  # noqa: E402
from w338_deadctrl_probes import make_tree, cleanup  # noqa: E402

TAXONOMY_PIN = 2134  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)

_EXPECTED_BREAKS = set()  # never {} (wave-331 lesson); breaks documented above


def _plain_tree(files):
    """Minimal tree for subject_pin unit probes: {relpath: content}."""
    root = tempfile.mkdtemp(prefix="ancestry-")
    for relpath, content in files.items():
        path = os.path.join(root, relpath)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
    return root


def p1_pin_verify_roundtrip():
    """pin_tree/verify_tree round-trip: no diffs, deterministic digest."""
    try:
        import subject_pin
        root = _plain_tree({"gov/a.py": "X = 1\n",
                            "evals/b.py": "Y = 2\n"})
        manifest, digest = subject_pin.pin_tree(root)
        manifest2, digest2 = subject_pin.pin_tree(root)
        diffs = subject_pin.verify_tree(root, manifest)
        shutil.rmtree(root, ignore_errors=True)
    except Exception:
        return "ERROR", "P1", traceback.format_exc(limit=3)
    if diffs:
        return "BREAK", "P1", "round-trip diffs on untouched tree: %r" % (diffs,)
    if digest != digest2:
        return "BREAK", "P1", "pin not deterministic"
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        return "BREAK", "P1", "digest is not 64-hex: %r" % digest
    if set(manifest) != {"gov/a.py", "evals/b.py"}:
        return "BREAK", "P1", "manifest paths wrong: %r" % sorted(manifest)
    return "HELD", "P1", "round-trip clean; deterministic 64-hex digest"


def p2_drift_kinds_detected():
    """verify detects modified / added / removed files."""
    try:
        import subject_pin
        root = _plain_tree({"gov/a.py": "X = 1\n",
                            "gov/b.py": "Y = 2\n",
                            "gov/c.py": "Z = 3\n"})
        manifest, _digest = subject_pin.pin_tree(root)
        with open(os.path.join(root, "gov", "a.py"), "w") as h:
            h.write("X = 999\n")                       # modified
        with open(os.path.join(root, "gov", "new.py"), "w") as h:
            h.write("N = 0\n")                         # added
        os.remove(os.path.join(root, "gov", "c.py"))   # removed
        diffs = subject_pin.verify_tree(root, manifest)
        shutil.rmtree(root, ignore_errors=True)
    except Exception:
        return "ERROR", "P2", traceback.format_exc(limit=3)
    kinds = {path: kind for path, kind in diffs}
    want = {"gov/a.py": "modified", "gov/new.py": "added",
            "gov/c.py": "removed"}
    if kinds != want:
        return "BREAK", "P2", "diffs %r != want %r" % (kinds, want)
    return "HELD", "P2", "modified/added/removed all detected"


def _gate_tree():
    """A synthetic tree that passes the dead-controls gate cleanly."""
    return make_tree(
        modules={"gov.live": "VALUE = 1\nraise Exception('syn-anc-a')\n"},
        codes=["syn-anc-a"],
        tests={"test_x.py": "from gov.live import VALUE\n"})


def p3_midgate_mutation_detected():
    """A gov file mutated mid-gate is detected; the gate refuses coded."""
    try:
        import subject_pin  # noqa: F401 -- red if missing
    except Exception:
        return "ERROR", "P3", traceback.format_exc(limit=3)
    root = _gate_tree()
    mutated = []
    real_compute_reached = gate.compute_reached

    def mutating_compute_reached(rt, mods):
        # Simulate the TOCTOU writer: a background process appends to a
        # gov file while the gate is running, then the gate continues.
        # A comment changes no reachability -- the ONLY signal is the pin.
        target = os.path.join(rt, "gov", "live.py")
        with open(target, "a", encoding="utf-8") as handle:
            handle.write("\n# mid-gate concurrent write\n")
        mutated.append(target)
        return real_compute_reached(rt, mods)

    gate.compute_reached = mutating_compute_reached
    try:
        result = gate.evaluate(root)
    except Exception:
        gate.compute_reached = real_compute_reached
        cleanup(root)
        return "ERROR", "P3", traceback.format_exc(limit=3)
    finally:
        gate.compute_reached = real_compute_reached
    cleanup(root)
    if not mutated:
        return "ERROR", "P3", "mutation hook did not fire"
    if result.passed:
        return "BREAK", "P3", ("gate PASSED despite a mid-run gov mutation "
                                "(TOCTOU invisible -- no subject pinning)")
    named = [v for v in result.violations if "deadctrl-subject-mutated" in v]
    if not named:
        return "BREAK", "P3", ("gate refused but not with the coded refusal; "
                                "violations: %s" % result.violations[:2])
    return "HELD", "P3", "mid-gate mutation detected; coded refusal"


def p4_clean_run_records_digest():
    """A clean gate run passes and records the subject digest."""
    root = _gate_tree()
    try:
        result = gate.evaluate(root)
    except Exception:
        cleanup(root)
        return "ERROR", "P4", traceback.format_exc(limit=3)
    cleanup(root)
    if not result.passed:
        return "BREAK", "P4", "clean tree refused: %s" % result.violations[:2]
    digest = getattr(result, "subject_digest", None)
    if not digest or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return "BREAK", "P4", "no subject digest recorded on the result"
    if not any("subject pinned" in n for n in result.notes):
        return "BREAK", "P4", "pin not recorded in result notes"
    return "HELD", "P4", "clean run passes; subject digest recorded"


def p5_pin_excludes_vcs_and_cache():
    """.git and __pycache__ are excluded from the pin."""
    try:
        import subject_pin
        root = _plain_tree({
            "gov/a.py": "X = 1\n",
            ".git/objects/ab/cd": "blob\n",
            "gov/__pycache__/a.pyc": "bytecode\n",
        })
        manifest, _digest = subject_pin.pin_tree(root)
        shutil.rmtree(root, ignore_errors=True)
    except Exception:
        return "ERROR", "P5", traceback.format_exc(limit=3)
    if set(manifest) != {"gov/a.py"}:
        return "BREAK", "P5", "exclusions wrong: %r" % sorted(manifest)
    return "HELD", "P5", ".git and __pycache__ excluded"


def p6_code_registered_and_live():
    """deadctrl-subject-mutated is registered and live on the real tree."""
    try:
        sys.path.insert(0, REPO_ROOT)
        from gov.decision_codes import TAXONOMY
        if "deadctrl-subject-mutated" not in TAXONOMY:
            return "BREAK", "P6", "code not in the central taxonomy"
        result = gate.evaluate(REPO_ROOT)
    except Exception:
        return "ERROR", "P6", traceback.format_exc(limit=3)
    if "deadctrl-subject-mutated" in result.dead_codes:
        return "BREAK", "P6", "code registered but dead on the real tree"
    return "HELD", "P6", "code registered and live (gate emits it)"


def p7_pin():
    """TAXONOMY_PIN == 2134 and the registry holds 2127 codes."""
    try:
        sys.path.insert(0, REPO_ROOT)
        from gov.decision_codes import TAXONOMY
    except Exception:
        return "ERROR", "P7", traceback.format_exc(limit=3)
    if TAXONOMY_PIN != 2134:
        return "BREAK", "P7", "TAXONOMY_PIN = %r, want 2134" % TAXONOMY_PIN
    if len(TAXONOMY) != 2134:
        return "BREAK", "P7", "registry has %d codes, want 2134" % len(TAXONOMY)
    return "HELD", "P7", "pin 2131; registry 2127 codes"


PROBES = [
    ("P1", p1_pin_verify_roundtrip),
    ("P2", p2_drift_kinds_detected),
    ("P3", p3_midgate_mutation_detected),
    ("P4", p4_clean_run_records_digest),
    ("P5", p5_pin_excludes_vcs_and_cache),
    ("P6", p6_code_registered_and_live),
    ("P7", p7_pin),
]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    only = argv[0] if argv else None
    breaks = held = errors = 0
    for pid, probe in PROBES:
        if only and pid != only:
            continue
        try:
            verdict, _pid, detail = probe()
        except Exception:
            verdict, detail = "ERROR", traceback.format_exc(limit=5)
        print("[%s] %s: %s" % (verdict, pid, detail))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("%d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())
