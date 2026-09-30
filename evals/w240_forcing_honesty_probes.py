"""Wave-240 FORCING-HONESTY mutation-honesty probes (W240-1, red-first).

probityai FORCING-HONESTY (Apache-2.0, mechanics re-derived): a
mutation-honesty gate over our own eval batteries. Mutate gov/*, replay
the relevant battery, classify each mutation KILLED / SILENT / DEAD /
INCONCLUSIVE. A SILENT mutation is a filed finding: the battery does
not observe what the condition claims to force.

This battery is the red-first harness for tools/forcing_honesty.py.
The demo campaigns run in-process against a tiny toy guard/battery
fixture (milliseconds), not the full tree -- the tool itself carries
the real campaign capability (tools/forcing_honesty.py run/sync/check).

Probes:
  forcing-emission-removal-is-silent -- removing the refusal *emission*
      (not the refusal) from the toy guard must classify SILENT, and
      the finding-filing hook must record an honesty-condition-silent
      finding. The toy battery observes the emission count but never
      verdicts on it -- the probityai weak case.
  forcing-tautology-probe-flagged -- a probe vector that kills nothing
      across the demo campaign must be flagged
      honesty-tautology-suspect (the vacuous toy-constant probe).
  forcing-baseline-tamper-refused -- a hand-edited baseline JSON (not
      written by --sync) must be refused by the gate with
      honesty-baseline-tampered.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import json
import os
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from tools import forcing_honesty as _fh
    HAVE_NEW_API = all(hasattr(_fh, n) for n in (
        "ForcingHarness", "Condition", "MutationResult",
        "enumerate_mutations", "classify", "sync_baseline",
        "load_baseline", "check_baseline", "file_silent_findings",
        "analyze_probe_coverage", "demo_condition", "HonestyError",
        "KILLED", "SILENT", "DEAD", "INCONCLUSIVE"))
except ImportError:
    _fh = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "forcing-emission-removal-is-silent",
    "forcing-tautology-probe-flagged",
    "forcing-baseline-tamper-refused",
]


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_emission_removal_is_silent():
    """Removing the refusal *emission* (not the refusal) -> SILENT."""
    tmp = tempfile.mkdtemp(prefix="fh-demo-")
    try:
        harness = _fh.ForcingHarness(repo_root=tmp, work_root=tmp)
        cond = _fh.demo_condition(tmp)
        src = open(os.path.join(tmp, cond.target)).read()
        muts = _fh.enumerate_mutations(src)
        mut = next(
            (m for m in muts
             if m.operator == "remove_call" and "EMISSIONS" in m.description),
            None)
        assert mut is not None, "no emission-removal mutation enumerated"
        res = harness.run_condition(cond, mut)
        assert res.classification == _fh.SILENT, \
            "expected SILENT, got %s (note=%s)" % (res.classification, res.note)
        findings = _fh.file_silent_findings([res])
        assert len(findings) == 1, findings
        assert findings[0]["code"] == "honesty-condition-silent", findings
        return ("emission removal -> SILENT; finding recorded "
                "(%s)" % findings[0]["code"])
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def _probe_tautology_probe_flagged():
    """A probe vector that kills nothing across the campaign is flagged."""
    tmp = tempfile.mkdtemp(prefix="fh-demo-")
    try:
        harness = _fh.ForcingHarness(repo_root=tmp, work_root=tmp)
        cond = _fh.demo_condition(tmp)
        src = open(os.path.join(tmp, cond.target)).read()
        muts = _fh.enumerate_mutations(src)
        emit_mut = next(
            m for m in muts
            if m.operator == "remove_call" and "EMISSIONS" in m.description)
        raise_mut = next(
            m for m in muts if m.operator == "remove_raise")
        results = [harness.run_condition(cond, emit_mut),
                   harness.run_condition(cond, raise_mut)]
        assert results[0].classification == _fh.SILENT, results[0]
        assert results[1].classification == _fh.KILLED, results[1]
        suspects = _fh.analyze_probe_coverage(results)
        names = [s["probe"] for s in suspects]
        assert "toy-constant" in names, \
            "vacuous probe not flagged: %r" % (suspects,)
        assert all(s["code"] == "honesty-tautology-suspect" for s in suspects)
        assert "toy-refuses" not in names, \
            "killing probe wrongly flagged: %r" % (suspects,)
        return "toy-constant flagged honesty-tautology-suspect; " \
            "toy-refuses not flagged"
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def _probe_baseline_tamper_refused():
    """A hand-edited baseline (not --sync-written) is refused by the gate."""
    tmp = tempfile.mkdtemp(prefix="fh-demo-")
    try:
        harness = _fh.ForcingHarness(repo_root=tmp, work_root=tmp)
        cond = _fh.demo_condition(tmp)
        src = open(os.path.join(tmp, cond.target)).read()
        muts = _fh.enumerate_mutations(src)
        emit_mut = next(
            m for m in muts
            if m.operator == "remove_call" and "EMISSIONS" in m.description)
        results = [harness.run_condition(cond, emit_mut)]
        path = os.path.join(tmp, "baseline.json")
        _fh.sync_baseline(results, [cond], path)
        # Hand-edit the baseline the way an attacker would: weaken it.
        with open(path) as fh:
            data = json.load(fh)
        data["conditions"][cond.id]["silent"] = 0
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        try:
            _fh.load_baseline(path)
        except _fh.HonestyError as exc:
            assert exc.code == "honesty-baseline-tampered", exc.code
            note = "load refused %s" % exc.code
        else:
            raise AssertionError("tampered baseline was accepted")
        try:
            _fh.check_baseline(results, path)
        except _fh.HonestyError as exc:
            assert exc.code == "honesty-baseline-tampered", exc.code
            note += "; check refused %s" % exc.code
        else:
            raise AssertionError("tampered baseline passed the gate")
        return note
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


_PROBES = {
    "forcing-emission-removal-is-silent": _probe_emission_removal_is_silent,
    "forcing-tautology-probe-flagged": _probe_tautology_probe_flagged,
    "forcing-baseline-tamper-refused": _probe_baseline_tamper_refused,
}


def _run_green_checks():
    """Adjacent-seam sanity: taxonomy mapping. Depth-1 only; honors
    GOV_SKIP_GREEN=1 (never spawns another battery's main)."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    if not HAVE_NEW_API:
        notes.append("new API absent; skipping taxonomy mapping check")
        return notes
    try:
        from gov import decision_codes as _dc
        for code in ("honesty-baseline-tampered",
                     "honesty-baseline-unforced",
                     "honesty-condition-silent",
                     "honesty-tautology-suspect",
                     "honesty-mutant-invalid",
                     "honesty-mutant-inconclusive"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-240 FORCING-HONESTY mutation-honesty probes (new API: %s)"
          % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, note in results:
        print("%-42s %s  %s" % (name, verdict, note))
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR"
          % (held, gap, brk, err))
    for note in _run_green_checks():
        print("GREEN:", note)
    if not HAVE_NEW_API:
        return 2  # genuine red: the capability does not exist
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
