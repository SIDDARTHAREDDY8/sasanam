"""Break-first battery for F225: per-control evidence-snapshot isolation.

F225 (LOW, wave-258 lane 4 red-team): gov/control_profiles.py
run_profile() deep-copied the evidence snapshot ONCE and passed the
SAME mutable object to every control's check, so a mutating check
poisoned later controls' evidence views (standing regression pin was
evals/w258_redteam_probes.py probe
profiles/cross-control-snapshot-contamination).

Fix (F225 close-when #1): each control's check evaluates against its
own pristine per-control deep copy of the snapshot (copy.deepcopy:
unbounded-depth, cycle-safe via its memo dict; non-copyable
snapshots are still refused fail-closed with
control-profile-evidence-malformed before any check runs).

Break-first discipline (diagnosing-bugs skill, Phase 1 loop): the
contamination probes below BREAK on the pre-fix code (a later control
observes / is verdict-flipped by an earlier control's mutation) and
HELD on the fixed code. Verified x2 deployment modes: staging (via
os.environ.setdefault at module level) and `env -u
GOV_DEPLOYMENT_MODE`.

Red-first provenance: this battery was written BEFORE the fix and
confirmed BREAK on the pre-fix tree; see the wave-259 F225 lane
report for the pre/post run evidence.

TAXONOMY_PIN = 1080 (wave-258 merge).
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import control_profiles as cp  # noqa: E402
from gov import decision_codes  # noqa: E402  (taxonomy pin below)

TAXONOMY_PIN = 1486  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _profile(checks):
    return {"id": "P1", "title": "t",
            "controls": [{"id": "C%d" % i, "impact": 0.9,
                          "title": "c", "desc": "d", "check": c}
                         for i, c in enumerate(checks)]}


def _status_of(res, control_id):
    for r in res["results"]:
        if r["control_id"] == control_id:
            return r["status"]
    raise AssertionError("no result for %s" % control_id)


# ---------------------------------------------------------------------------
# F225: per-control isolation
# ---------------------------------------------------------------------------

@probe("f225/mutating-check-flips-later-control-verdict")
def _p_verdict_flip():
    """Core break-first probe: C0 mutates the snapshot; C1's verdict
    depends on pristine evidence. Pre-fix: C1 observes the mutation
    and its verdict flips fail -> BREAK. Fixed: C1 sees a pristine
    copy and passes -> HELD."""
    seen = {}

    def mutator(snap):
        snap["poisoned"] = True
        return True, "mutator ok"

    def victim(snap):
        seen["poisoned"] = snap.get("poisoned", False)
        seen["evidence"] = snap.get("evidence")
        # Verdict semantics: fail iff the evidence view is poisoned.
        return not snap.get("poisoned", False), "victim verdict"

    res = cp.run_profile(_profile([mutator, victim]),
                         {"evidence": 1})
    c1 = _status_of(res, "C1")
    if seen.get("poisoned"):
        return _break("C1 observed C0's mutation (poisoned=%r); "
                      "C1 status=%s -- verdict flipped"
                      % (seen["poisoned"], c1))
    if c1 != "pass":
        return _break("C1 pristine but status=%s (unexpected)" % c1)
    if seen.get("evidence") != 1:
        return _break("C1 lost original evidence: %r"
                      % (seen.get("evidence"),))
    return _held("C1 saw a pristine snapshot; verdict unflipped "
                 "(status=pass)")


@probe("f225/nested-mutation-isolated")
def _p_nested():
    """A shallow per-control copy would still leak nested mutations.
    Pre-fix (shared deep copy): C1 sees the nested mutation -> BREAK.
    Fixed (per-control deep copy): C1 sees pristine nested state."""
    seen = {}

    def mutator(snap):
        snap["journal"]["entries"].append("forged")
        snap["journal"]["sealed"] = False
        return True

    def reader(snap):
        seen["entries"] = list(snap["journal"]["entries"])
        seen["sealed"] = snap["journal"]["sealed"]
        return True

    cp.run_profile(
        _profile([mutator, reader]),
        {"journal": {"entries": ["genuine"], "sealed": True}})
    if seen["entries"] != ["genuine"] or seen["sealed"] is not True:
        return _break("C1 observed nested mutation: entries=%r "
                      "sealed=%r" % (seen["entries"], seen["sealed"]))
    return _held("C1 saw pristine nested state")


@probe("f225/cycle-safe-copy-bound")
def _p_cycle():
    """Documents the copy bound: snapshots may contain reference
    cycles; copy.deepcopy is cycle-safe via its memo dict. A later
    control must see the cycle intact (view['self'] is view) and the
    run must terminate. HELDs on pre- and post-fix code -- this pins
    the bound, it is not a break-first probe."""
    seen = {}

    def first(snap):
        # Touch the cycle; if the copy were cycle-naive this would
        # hang or raise before any verdict exists.
        snap["marker"] = "touched"
        return True

    def second(snap):
        seen["intact"] = snap.get("self") is snap
        seen["marker"] = snap.get("marker", None)
        return True

    snap = {"n": 1}
    snap["self"] = snap
    res = cp.run_profile(_profile([first, second]), snap)
    if not res["success"]:
        return _break("run over cyclic snapshot failed: %r"
                      % ([r["status"] for r in res["results"]],))
    if not seen.get("intact"):
        return _break("cycle not preserved in per-control copy")
    if seen.get("marker") is not None:
        return _break("C2 observed C1's mutation through the cycle "
                      "(marker=%r)" % (seen["marker"],))
    return _held("cyclic snapshot copied cycle-safely; C2 isolated")


@probe("f225/caller-data-never-mutated")
def _p_caller():
    """F212 regression pin: the caller's own snapshot object is never
    mutated, even when a check mutates its per-control view."""

    def mutator(snap):
        snap["poisoned"] = True
        snap["nested"] = {"x": []}
        return True

    caller = {"evidence": 1, "keep": [1, 2]}
    before = {"evidence": 1, "keep": [1, 2]}
    cp.run_profile(_profile([mutator, lambda s: True]), caller)
    if caller != before:
        return _break("caller snapshot mutated: %r" % (caller,))
    return _held("caller snapshot untouched")


@probe("f225/noncopyable-snapshot-still-refused")
def _p_refusal():
    """Fail-closed pin: a snapshot that cannot be deep-copied is
    refused with control-profile-evidence-malformed BEFORE any check
    runs -- the per-control copy must not weaken the refusal."""
    import threading
    ran = []

    def check(snap):
        ran.append(True)
        return True

    try:
        cp.run_profile(_profile([check]), {"lock": threading.Lock()})
    except cp.ControlProfileError as e:
        if e.code != cp.EVIDENCE_MALFORMED:
            return _break("wrong refusal code: %s" % e.code)
        if ran:
            return _break("check ran despite refusal")
        return _held("non-copyable snapshot refused pre-check")
    return _break("non-copyable snapshot was not refused")


@probe("f225/fresh-copies-across-runs")
def _p_across_runs():
    """No cross-run leakage: a mutating check in run N must not be
    visible to a later control in run N+1 (guards against an
    implementation that caches per-control copies in module state)."""
    seen = {}

    def mutator(snap):
        snap["poisoned"] = True
        return True

    def reader(snap):
        seen["run"] = seen.get("run", 0) + 1
        seen["poisoned_%d" % seen["run"]] = snap.get("poisoned",
                                                    False)
        return True

    prof = _profile([mutator, reader])
    cp.run_profile(prof, {"evidence": 1})
    cp.run_profile(prof, {"evidence": 1})
    bad = [k for k in ("poisoned_1", "poisoned_2") if seen.get(k)]
    if bad:
        return _break("poison visible across controls/runs: %r"
                      % (bad,))
    return _held("both runs isolated; no cross-run leakage")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent control-profile suites still green. Honors
    GOV_SKIP_GREEN (records skip, never spawns)."""
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    td = "/var/tmp/g259f225-green"
    os.makedirs(td, exist_ok=True)
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=td)
    adj = [
        ([sys.executable, "-m", "unittest", "tests.test_control_profiles",
          "-v"], "tests.test_control_profiles"),
        ([sys.executable, "evals/w257_profiles_probes.py"],
         "evals/w257_profiles_probes.py"),
    ]
    for cmd, label in adj:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=600, env=env, cwd=repo)
            tail = (p.stdout or "").strip().splitlines()[-1:] or [""]
            notes.append((label, "exit=%d %s"
                          % (p.returncode, tail[0][:60])))
        except Exception as e:  # noqa: BLE001 -- green-check report
            notes.append((label, "ERROR %s" % e))
    return notes


def main():
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d"
              % (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
    held = breaks = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s"
                               % (type(e).__name__, str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        else:
            errors += 1
        print("%-8s %-48s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / ERROR %d over %d probes"
          % (held, breaks, errors, len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
