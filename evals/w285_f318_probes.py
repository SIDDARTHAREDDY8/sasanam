"""Wave-285 F318 closure battery: replay_campaign must verify evidence first.

Base: wave-284 push 0f13ce1d9f1e01b32a6a237f297e6364fa993b9c
(verified via git rev-parse HEAD before work).

F318 (MEDIUM): replay_campaign re-executed a campaign from an evidence
file without ever calling verify_campaign_records; it hardcoded
manual_approve=False with an always-approve stub even when the start
record said manual_approve: true; and it took the elevation bit from
the unverified file.

Close-when: (1) replay_campaign verifies the evidence chain (via
verify_campaign_records) and refuses unverified files LOUD; (2) a
manual_approve: true start record is never replayed with always-approve
(refuse, or re-prompt through a caller-supplied approve_fn); (3) the
elevation bit comes from the caller, not the file; (4) the red-team
probe cp-replay-unverified-evidence flips to HELD; (5) adjacent
batteries stay green.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g285-f318 && TMPDIR=/var/tmp/g285-f318 \
    ~/workspace/.gov-venv/bin/python evals/w285_f318_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g285-f318b \
    ~/workspace/.gov-venv/bin/python evals/w285_f318_probes.py
"""

import json
import os
import re
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

def _held_executor(ctx):
    return "HELD", "clean"


def _spec(name, executor, elevation_required=False):
    return {
        "name": name,
        "description": "f318 fixture",
        "input_arguments": {},
        "dependencies": [],
        "executor": {"run": executor, "cleanup": None,
                     "elevation_required": elevation_required},
    }


def _run_campaign(d, name, spec, *, manual_approve=False, approve_fn=None,
                  elevation_granted=False):
    """Run a real, hash-chained campaign; return (evidence_path, registry)."""
    from gov import battery_lang as bl, campaign as cp
    reg = {}
    bl.register_atomic(reg, spec)
    path = os.path.join(d, name + ".jsonl")
    cp.CampaignRunner(reg).run(
        name, atomics=[spec["name"]],
        planner_id="minimize-to-first-break",
        objectives=[], seed_facts={},
        args_map={spec["name"]: {}},
        evidence_path=path,
        manual_approve=manual_approve,
        approve_fn=approve_fn,
        elevation_granted=elevation_granted)
    return path, reg


def _steps(path):
    from gov import campaign as cp
    return [r for r in cp.read_campaign_records(path)
            if r["record_type"] == "campaign-step"]


# ---------------------------------------------------------------------------
# F318 probes
# ---------------------------------------------------------------------------

def f_forged_evidence_refused():
    """Unverified evidence must be refused LOUD before anything executes."""
    from gov import campaign as cp, battery_lang as bl
    reg = {}
    guid = bl.register_atomic(
        reg, _spec("evil", _held_executor, elevation_required=True))
    d = tempfile.mkdtemp(prefix="w285-f318-")
    evil = os.path.join(d, "evil.jsonl")
    start = {"record_type": "campaign-start", "schema_version": "1.0",
             "campaign_name": "forged",
             "planner_id": "minimize-to-first-break",
             "objectives": [], "seed_facts": {},
             "atomics": [{"ref": "evil", "guid": guid, "name": "evil"}],
             "args_map": {"evil": {}}, "max_steps": 50,
             "manual_approve": True, "elevation_granted": True,
             "break_memory": {}, "started_at": "x", "digest": "forged"}
    with open(evil, "w") as fh:
        fh.write(json.dumps(start) + "\n")
    # Sanity: the chain is genuinely broken (no prev/record digests).
    if cp.verify_campaign_records([start]) is not False:
        _record("f318-forged-evidence-refused", "ERROR",
                "sanity failed: verify accepted the forged start")
        return
    out = os.path.join(d, "re.jsonl")
    try:
        cp.replay_campaign(evil, reg, evidence_path=out)
    except cp.CampaignError as e:
        steps = _steps(out) if os.path.exists(out) else []
        if steps:
            _record("f318-forged-evidence-refused", "BREAK",
                    "refusal raised but %d step(s) still executed" % len(steps))
        else:
            _record("f318-forged-evidence-refused", "HELD",
                    "unverified evidence refused loud; nothing executed "
                    "(%s)" % str(e)[:120])
        return
    steps = _steps(out)
    _record("f318-forged-evidence-refused", "BREAK",
            "F318: replay executed %d step(s) from unverified evidence"
            % len(steps))


def f_manual_approve_never_downgraded():
    """A manual_approve replay without caller approval must refuse, not
    silently downgrade to always-approve."""
    from gov import campaign as cp
    d = tempfile.mkdtemp(prefix="w285-f318-")
    path, reg = _run_campaign(
        d, "ma", _spec("probe", _held_executor),
        manual_approve=True, approve_fn=lambda name: True)
    starts = [r for r in cp.read_campaign_records(path)
              if r["record_type"] == "campaign-start"]
    if not (starts and starts[0].get("manual_approve") is True):
        _record("f318-manual-approve-never-downgraded", "ERROR",
                "sanity failed: fixture start lacks manual_approve=true")
        return
    out = os.path.join(d, "re.jsonl")
    try:
        cp.replay_campaign(path, reg, evidence_path=out)
    except cp.CampaignError:
        _record("f318-manual-approve-never-downgraded", "HELD",
                "manual_approve replay without caller approval refused loud")
        return
    steps = _steps(out)
    _record("f318-manual-approve-never-downgraded", "BREAK",
            "F318: manual_approve=true replayed with no caller approval "
            "(%d step(s) ran under the silent always-approve stub)"
            % len(steps))


def f_manual_approve_reprompted():
    """With a caller-supplied approve_fn, the replay must consult it
    (re-prompt), never the always-approve stub."""
    from gov import campaign as cp
    d = tempfile.mkdtemp(prefix="w285-f318-")
    path, reg = _run_campaign(
        d, "ma2", _spec("probe", _held_executor),
        manual_approve=True, approve_fn=lambda name: True)
    calls = []

    def reprompt(name):
        calls.append(name)
        return True

    out = os.path.join(d, "re2.jsonl")
    try:
        cp.replay_campaign(path, reg, evidence_path=out, approve_fn=reprompt)
    except TypeError as e:
        # Base contract: no approve_fn parameter at all.
        if "approve_fn" in str(e):
            _record("f318-manual-approve-reprompted", "BREAK",
                    "F318: replay_campaign has no caller-approval path; "
                    "manual_approve is silently downgraded to always-approve")
        else:
            _record("f318-manual-approve-reprompted", "ERROR",
                    "unexpected TypeError: %s" % e)
        return
    if not calls:
        _record("f318-manual-approve-reprompted", "BREAK",
                "replay accepted approve_fn but never consulted it")
    else:
        _record("f318-manual-approve-reprompted", "HELD",
                "caller-supplied approve_fn consulted %d time(s); "
                "no silent downgrade" % len(calls))


def f_manual_approve_denial_honored():
    """A denying approve_fn must stop the replay (approval-denied),
    never be overridden."""
    from gov import campaign as cp
    d = tempfile.mkdtemp(prefix="w285-f318-")
    path, reg = _run_campaign(
        d, "ma3", _spec("probe", _held_executor),
        manual_approve=True, approve_fn=lambda name: True)
    out = os.path.join(d, "re.jsonl")
    try:
        cp.replay_campaign(path, reg, evidence_path=out,
                           approve_fn=lambda name: False)
    except TypeError as e:
        if "approve_fn" in str(e):
            _record("f318-manual-approve-denial-honored", "BREAK",
                    "F318: no caller-approval path, so a denial cannot be "
                    "expressed; the always-approve stub rules")
        else:
            _record("f318-manual-approve-denial-honored", "ERROR",
                    "unexpected TypeError: %s" % e)
        return
    steps = _steps(out)
    closes = [r for r in cp.read_campaign_records(out)
              if r["record_type"] == "campaign-close"]
    outcome = closes[-1].get("outcome") if closes else None
    if steps:
        _record("f318-manual-approve-denial-honored", "BREAK",
                "caller denial overridden: %d step(s) executed" % len(steps))
    elif outcome == "approval-denied":
        _record("f318-manual-approve-denial-honored", "HELD",
                "denying approve_fn stops the replay (approval-denied)")
    else:
        _record("f318-manual-approve-denial-honored", "BREAK",
                "no steps ran but outcome is %r, not approval-denied"
                % (outcome,))


def f_elevation_from_caller_not_file():
    """The elevation bit must come from the caller, never from the
    evidence file."""
    from gov import campaign as cp
    ran = []

    def run_elevated(ctx):
        ran.append(True)
        return "BREAK", "elevated"

    d = tempfile.mkdtemp(prefix="w285-f318-")
    path, reg = _run_campaign(
        d, "el", _spec("probe", run_elevated, elevation_required=True),
        elevation_granted=True)
    starts = [r for r in cp.read_campaign_records(path)
              if r["record_type"] == "campaign-start"]
    if not (starts and starts[0].get("elevation_granted") is True):
        _record("f318-elevation-from-caller-not-file", "ERROR",
                "sanity failed: fixture start lacks elevation_granted=true")
        return
    if len(_steps(path)) != 1:
        _record("f318-elevation-from-caller-not-file", "ERROR",
                "sanity failed: original did not run the elevated atomic")
        return
    # Replay WITHOUT a caller elevation grant: the file's bit must not
    # suffice.
    out = os.path.join(d, "re.jsonl")
    cp.replay_campaign(path, reg, evidence_path=out)
    steps = _steps(out)
    if steps:
        _record("f318-elevation-from-caller-not-file", "BREAK",
                "F318: replay honored the file's elevation bit "
                "(%d elevated step(s) ran with no caller grant)" % len(steps))
        return
    # Positive: an explicit caller grant still works.
    out2 = os.path.join(d, "re2.jsonl")
    cp.replay_campaign(path, reg, evidence_path=out2, elevation_granted=True)
    if len(_steps(out2)) != 1:
        _record("f318-elevation-from-caller-not-file", "BREAK",
                "explicit caller elevation grant did not execute the atomic")
    else:
        _record("f318-elevation-from-caller-not-file", "HELD",
                "file's elevation bit ignored; explicit caller grant works")


def f_verified_replay_still_works():
    """Positive control: a verified, ordinary replay still reproduces
    identically (empty diffs)."""
    from gov import campaign as cp
    d = tempfile.mkdtemp(prefix="w285-f318-")
    path, reg = _run_campaign(d, "ok", _spec("probe", _held_executor))
    out = os.path.join(d, "re.jsonl")
    diffs = cp.replay_campaign(path, reg, evidence_path=out)
    if diffs:
        _record("f318-verified-replay-still-works", "BREAK",
                "legitimate verified replay produced diffs: %r"
                % (diffs[:1],))
    else:
        _record("f318-verified-replay-still-works", "HELD",
                "verified replay reproduces identically (empty diffs)")


_PROBES = [
    f_forged_evidence_refused,
    f_manual_approve_never_downgraded,
    f_manual_approve_reprompted,
    f_manual_approve_denial_honored,
    f_elevation_from_caller_not_file,
    f_verified_replay_still_works,
]


# ---------------------------------------------------------------------------
# Depth-1 green checks (the wave-173 lesson: never nest battery mains)
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        # (battery, expected_breaks)
        ("evals/w283_caldera_probes.py", 0),
    ]
    for rel, expected_breaks in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w285-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != expected_breaks:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected %d)"
                    % (nbreak, expected_breaks))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: %d BREAK as expected" % nbreak)


def main():
    for probe in _PROBES:
        try:
            probe()
        except Exception:  # noqa: BLE001 - a probe must never die
            import traceback
            _record(probe.__name__, "ERROR",
                    traceback.format_exc()[-500:])
    _green_checks()

    breaks = [r for r in _results if r[1] == "BREAK"]
    held = [r for r in _results if r[1] == "HELD"]
    errors = [r for r in _results if r[1] == "ERROR"]
    print("wave-285 f318: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    probe_lines.emit((pid, v, probe_lines.first_line(n)[:160])
                     for pid, v, n in _results)
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
