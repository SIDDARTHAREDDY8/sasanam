"""Wave-285 red-first closure battery: F324 (campaign) + F316 (finding lifecycle).

F324 (MEDIUM): ``produces`` entries with ``on="always"`` must NOT fire on
ERROR verdicts -- an atomic that raised produced nothing, so writing the
static value fabricates evidence and can close ``objectives-met`` with
``breaks: 0``. The suppression must be recorded in the step record
(``produces_suppressed`` with the coded emission), never silent.

F316 (LOW): ``FindingRegistry.close_old_findings`` must refuse LOUD
(``FindingLifecycleError``) when a scan entry's ``reproduced`` is not an
explicit bool -- a missing/None/truthy-string verdict is not evidence of
anything, and the old fall-through fabricated a ``mitigated`` transition.
Closure evidence with empty ``battery``/``commit`` values is likewise
refused (key presence alone is not evidence).

Red-first: every defect probe BREAKs on the pristine wave-284 base and
HELDs after the lane fixes. Positive-path probes HELD on both.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/var/tmp/g285-f324-f316")

import re
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gov import battery_lang as bl
from gov import campaign as cp
from gov import decision_codes
from gov import finding_lifecycle as fl

from _w284_helpers import raising_spec

# Wave-285 lane 2: pin 1621 -> 1622 (+1 campaign-produces-suppressed).
TAXONOMY_PIN = 1715


def _check(name, fn):
    try:
        ok, note = fn()
    except Exception:  # noqa: BLE001 - a probe error is a BREAK, loud
        return (name, "BREAK", "probe raised: %s"
                % traceback.format_exc(limit=3).replace("\n", " | "))
    return (name, "HELD" if ok else "BREAK", note)


# ---------------------------------------------------------------------------
# Pin / taxonomy
# ---------------------------------------------------------------------------

def _pin():
    src = open(decision_codes.__file__).read()
    codes = re.findall(r'"code":\s*\'([^\']+)\'', src)
    raw, unique = len(codes), len(set(codes))
    ordered = codes == sorted(codes)
    ok = (raw == TAXONOMY_PIN and unique == TAXONOMY_PIN
          and raw - unique == 0 and ordered)
    return ok, ("raw=%d unique=%d sorted=%s" % (raw, unique, ordered))


# ---------------------------------------------------------------------------
# F324: produces on="always" must not fire on ERROR verdicts
# ---------------------------------------------------------------------------

def _f324_run(spec_name, produces, objectives):
    spec = raising_spec(spec_name)
    spec["produces"] = produces
    reg = {}
    cp.register_campaign_atomics(reg, [spec])
    d = tempfile.mkdtemp(prefix="w285-f324-")
    path = os.path.join(d, "e.jsonl")
    cp.CampaignRunner(reg).run(
        "f324", atomics=[spec_name],
        planner_id="minimize-to-first-break",
        objectives=objectives,
        seed_facts={}, args_map={}, evidence_path=path)
    recs = cp.read_campaign_records(path)
    close = [r for r in recs if r["record_type"] == "campaign-close"][0]
    steps = [r for r in recs if r["record_type"] == "campaign-step"]
    return close, steps


def _f324_always_not_on_error():
    # The defect: an ERROR step's on="always" produce closes
    # objectives-met with breaks=0. After the fix the fact must not be
    # set, the suppression must be recorded, and objectives stay unmet.
    close, steps = _f324_run(
        "errprobe",
        [{"fact": "goal.flag", "type": "bool", "value": True,
          "on": "always"}],
        [{"count": 1, "operator": "eq", "target": "goal.flag",
          "value": True}])
    if close.get("objectives_met") is True:
        return (False, "ERROR-step campaign closed objectives-met "
                       "(breaks=%s)" % (close.get("breaks"),))
    if not steps or not all(s["verdict"] == "ERROR" for s in steps):
        return (False, "no ERROR steps recorded: %r"
                % ([s.get("verdict") for s in steps],))
    snap = steps[0].get("facts_snapshot", {})
    if "goal.flag" in snap:
        return (False, "goal.flag fact set by an ERROR step")
    suppressed = steps[0].get("produces_suppressed", [])
    facts = [e.get("fact") for e in suppressed]
    codes = [e.get("code") for e in suppressed]
    if "goal.flag" not in facts:
        return (False, "suppression not recorded in the step record")
    if any(c != "campaign-produces-suppressed" for c in codes):
        return (False, "suppression lacks the coded emission: %r" % (codes,))
    return (True, "fact withheld on ERROR; suppression recorded with code")


def _held_spec(name, produces):
    def _run(ctx):
        return ("HELD", "fine")
    spec = {"name": name, "description": "held probe atomic",
            "input_arguments": {}, "dependencies": [],
            "executor": {"run": _run, "cleanup": None,
                        "elevation_required": False},
            "produces": produces}
    return spec


def _f324_parser_not_on_error():
    # Residual path (spec review): an ERROR step's fact_parser must not
    # fabricate facts either -- parser writes are gated on completed
    # verdicts and suppressed with the coded emission.
    def _parser(result):
        return [{"fact": "goal.flag", "value": True}]
    spec = raising_spec("errparse")
    spec["produces"] = [{"fact": "goal.flag", "type": "bool",
                         "value": True, "on": "always"}]
    spec["fact_parser"] = _parser
    reg = {}
    cp.register_campaign_atomics(reg, [spec])
    d = tempfile.mkdtemp(prefix="w285-f324-")
    path = os.path.join(d, "e.jsonl")
    cp.CampaignRunner(reg).run(
        "f324p", atomics=["errparse"],
        planner_id="minimize-to-first-break",
        objectives=[{"count": 1, "operator": "eq", "target": "goal.flag",
                     "value": True}],
        seed_facts={}, args_map={}, evidence_path=path)
    recs = cp.read_campaign_records(path)
    close = [r for r in recs if r["record_type"] == "campaign-close"][0]
    steps = [r for r in recs if r["record_type"] == "campaign-step"]
    if close.get("objectives_met") is True:
        return (False, "ERROR-step parser closed objectives-met")
    snap = steps[0].get("facts_snapshot", {}) if steps else {}
    if "goal.flag" in snap:
        return (False, "goal.flag fact set by an ERROR step's parser")
    suppressed = steps[0].get("produces_suppressed", []) if steps else []
    psrc = [e for e in suppressed if e.get("source") == "parser"]
    if (not psrc or any(e.get("code") != "campaign-produces-suppressed"
                        for e in psrc)):
        return (False, "parser suppression not recorded with code: %r"
                % (suppressed,))
    if "suppressed" not in steps[0].get("parser_note", ""):
        return (False, "parser_note does not record the suppression")
    return (True, "parser fact withheld on ERROR; suppression recorded")


def _f324_always_fires_on_completed():
    # Positive path: on="always" still fires for completed verdicts
    # (BREAK/HELD). "always" means "any completed verdict", not errors.
    spec = _held_spec("heldprobe", [
        {"fact": "goal.flag", "type": "bool", "value": True, "on": "always"}])
    reg = {}
    cp.register_campaign_atomics(reg, [spec])
    d = tempfile.mkdtemp(prefix="w285-f324-")
    path = os.path.join(d, "e.jsonl")
    cp.CampaignRunner(reg).run(
        "f324pos", atomics=["heldprobe"],
        planner_id="minimize-to-first-break",
        objectives=[{"count": 1, "operator": "eq", "target": "goal.flag",
                     "value": True}],
        seed_facts={}, args_map={}, evidence_path=path)
    recs = cp.read_campaign_records(path)
    close = [r for r in recs if r["record_type"] == "campaign-close"][0]
    steps = [r for r in recs if r["record_type"] == "campaign-step"]
    produced = steps[0].get("produced_facts", []) if steps else []
    if close.get("objectives_met") is not True:
        return (False, "HELD-step on='always' no longer meets objectives")
    if "goal.flag" not in produced:
        return (False, "produced_facts missing goal.flag: %r" % (produced,))
    if steps[0].get("produces_suppressed"):
        return (False, "completed step wrongly recorded a suppression")
    return (True, "on='always' fires on HELD as before")


def _f324_break_held_selectors_intact():
    # The pre-existing break/held selectors must keep their semantics.
    spec = _held_spec("heldprobe2", [
        {"fact": "a.one", "type": "bool", "value": True, "on": "break"},
        {"fact": "a.two", "type": "bool", "value": True, "on": "held"}])
    reg = {}
    cp.register_campaign_atomics(reg, [spec])
    d = tempfile.mkdtemp(prefix="w285-f324-")
    path = os.path.join(d, "e.jsonl")
    cp.CampaignRunner(reg).run(
        "f324sel", atomics=["heldprobe2"],
        planner_id="minimize-to-first-break",
        objectives=[], seed_facts={}, args_map={}, evidence_path=path)
    recs = cp.read_campaign_records(path)
    steps = [r for r in recs if r["record_type"] == "campaign-step"]
    produced = steps[0].get("produced_facts", []) if steps else []
    ok = ("a.two" in produced and "a.one" not in produced
          and steps[0].get("verdict") == "HELD")
    return (ok, "produced_facts=%r verdict=%r"
            % (produced, steps[0].get("verdict") if steps else None))


# ---------------------------------------------------------------------------
# F316: close_old_findings must refuse malformed scan entries loudly
# ---------------------------------------------------------------------------

def _fl_open(severity="high"):
    reg = fl.FindingRegistry(next_number=312)
    n, _ = reg.file_finding(title="f316t", seam="s", attack_shape="a",
                            close_when="c", severity=severity, reporter="r",
                            wave=285)
    return reg, n


def _f316_missing_reproduced_refused():
    # The defect: a scan entry without 'reproduced' fell through to the
    # mitigate path, closing OPEN -> mitigated with fabricated evidence.
    reg, n = _fl_open()
    try:
        reg.close_old_findings({n: {"battery": "b", "commit": "c"}},
                               wave=285, actor="sweep")
    except fl.FindingLifecycleError as e:
        ok = reg.get(n).state == "open"
        return (ok, "loud refusal: %s (state=%s)"
                % (e, reg.get(n).state))
    except Exception as e:
        return (False, "uncoded escape: %s: %s"
                % (type(e).__name__, e))
    return (False, "malformed scan ACCEPTED (state=%s); no loud refusal"
            % (reg.get(n).state,))


def _f316_none_reproduced_refused():
    reg, n = _fl_open()
    try:
        reg.close_old_findings(
            {n: {"reproduced": None, "battery": "b", "commit": "c"}},
            wave=285, actor="sweep")
    except fl.FindingLifecycleError as e:
        return (reg.get(n).state == "open", "loud refusal: %s" % (e,))
    return (False, "reproduced=None ACCEPTED (state=%s)"
            % (reg.get(n).state,))


def _f316_nonbool_reproduced_refused():
    # Truthy non-bools ("yes", 1) must not read as reproduced=True.
    reg, n = _fl_open()
    try:
        reg.close_old_findings(
            {n: {"reproduced": "yes", "battery": "b", "commit": "c"}},
            wave=285, actor="sweep")
    except fl.FindingLifecycleError as e:
        return (reg.get(n).state == "open", "loud refusal: %s" % (e,))
    return (False, "reproduced='yes' ACCEPTED (state=%s)"
            % (reg.get(n).state,))


def _f316_nondict_entry_refused():
    # A non-dict scan value must refuse LOUD with the coded lifecycle
    # error (never an uncoded AttributeError, never a closure).
    reg, n = _fl_open()
    try:
        reg.close_old_findings({n: None}, wave=285, actor="sweep")
    except fl.FindingLifecycleError as e:
        return (reg.get(n).state == "open", "loud refusal: %s" % (e,))
    except Exception as e:
        return (False, "uncoded escape: %s: %s"
                % (type(e).__name__, e))
    return (False, "non-dict scan entry ACCEPTED (state=%s)"
            % (reg.get(n).state,))


def _f316_false_still_mitigates():
    # Positive path: an explicit reproduced=False with real evidence
    # still transitions OPEN -> mitigated, carrying the scan evidence.
    reg, n = _fl_open(severity="low")
    closed = reg.close_old_findings(
        {n: {"reproduced": False, "battery": "evals/b.py",
             "probes": ["p1"], "commit": "abc"}},
        wave=285, actor="sweep")
    f = reg.get(n)
    ev = f.transitions[-1].evidence if f.transitions else {}
    ok = (closed == [n] and f.state == "mitigated"
          and ev.get("battery") == "evals/b.py"
          and ev.get("commit") == "abc")
    return (ok, "state=%s evidence battery=%r" % (f.state, ev.get("battery")))


def _f316_true_stays_open_with_note():
    # Positive path: reproduced=True records a scan note, never closes.
    reg, n = _fl_open()
    closed = reg.close_old_findings(
        {n: {"reproduced": True, "battery": "evals/b.py",
             "probes": ["p1"], "commit": "abc"}},
        wave=285, actor="sweep")
    f = reg.get(n)
    ok = (closed == [] and f.state == "open" and len(f.scan_notes) == 1)
    return (ok, "state=%s notes=%d" % (f.state, len(f.scan_notes)))


def _f316_none_evidence_refused():
    # _require_closure_evidence hardened: key presence with None values
    # is not evidence.
    reg, n = _fl_open(severity="low")
    try:
        reg.transition(n, "mitigated", wave=285, actor="x",
                       evidence={"battery": None, "commit": "abc"})
    except fl.FindingLifecycleError as e:
        return (reg.get(n).state == "open", "loud refusal: %s" % (e,))
    return (False, "None-valued closure evidence ACCEPTED (state=%s)"
            % (reg.get(n).state,))


def _f316_under_review_never_closed_on_malformed():
    # A malformed entry for an under_review finding must raise, never
    # silently override human triage.
    reg, n = _fl_open()
    reg.transition(n, "under_review", wave=285, actor="human",
                   evidence={"note": "investigating"})
    try:
        reg.close_old_findings({n: {"battery": "b"}}, wave=285,
                               actor="sweep")
    except fl.FindingLifecycleError:
        return (reg.get(n).state == "under_review",
                "malformed entry refused; triage intact")
    return (False, "malformed scan for under_review ACCEPTED (state=%s)"
            % (reg.get(n).state,))


PROBES = [
    ("pin-1622", _pin),
    ("f324-always-not-on-error", _f324_always_not_on_error),
    ("f324-parser-not-on-error", _f324_parser_not_on_error),
    ("f324-always-fires-on-completed", _f324_always_fires_on_completed),
    ("f324-break-held-selectors-intact", _f324_break_held_selectors_intact),
    ("f316-missing-reproduced-refused", _f316_missing_reproduced_refused),
    ("f316-none-reproduced-refused", _f316_none_reproduced_refused),
    ("f316-nonbool-reproduced-refused", _f316_nonbool_reproduced_refused),
    ("f316-nondict-entry-refused", _f316_nondict_entry_refused),
    ("f316-false-still-mitigates", _f316_false_still_mitigates),
    ("f316-true-stays-open-with-note", _f316_true_stays_open_with_note),
    ("f316-none-evidence-refused", _f316_none_evidence_refused),
    ("f316-under-review-never-closed-on-malformed",
     _f316_under_review_never_closed_on_malformed),
]


def _green_checks():
    # Depth-1 only: honor GOV_SKIP_GREEN; never spawn nested mains.
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-checks", "SKIP", "GOV_SKIP_GREEN=1")]
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    results = []
    for battery in ("w284_redteam_probes.py", "w283_defectdojo_probes.py"):
        path = os.path.join(here, battery)
        if not os.path.exists(path):
            results.append(("green:" + battery, "SKIP", "absent"))
            continue
        p = subprocess.run([sys.executable, path], capture_output=True,
                           text=True, env=env, timeout=600,
                           cwd=os.path.join(here, ".."))
        out = (p.stdout + p.stderr).replace("\n", " | ")
        verdict = "GREEN" if p.returncode == 0 else "RED"
        results.append(("green:" + battery, verdict,
                        "rc=%d %s" % (p.returncode, out[-300:])))
    return results


def main():
    results = [_check(name, fn) for name, fn in PROBES]
    results += _green_checks()
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    reds = sum(1 for _, v, _ in results if v == "RED")
    skips = sum(1 for _, v, _ in results if v == "SKIP")
    print("w285_f324_f316: %d BREAK / %d HELD / %d RED / %d SKIP"
          % (breaks, held, reds, skips))
    for name, verdict, note in results:
        print("  [%s] %s: %s" % (verdict, name, note))
    return 1 if (breaks or reds) else 0


if __name__ == "__main__":
    sys.exit(main())
