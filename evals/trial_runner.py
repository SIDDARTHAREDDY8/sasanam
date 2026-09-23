"""Wave-54 Priority 2: statistical-trial layer for the adversary matrix.

RAMPART methodology import (NOT a pytest-harness clone — per the
wave-53 stop-duplicating list, RAMPART is a pytest-native harness on
PyRIT for *testing*; what we import is the *method*): N trials per
probe with fixed seeds, attack-success-rate (ASR) with confidence
intervals, automatic flakiness detection, and a report that
distinguishes deterministic holds from probabilistic ones.

Design: workstreams/evals/STATISTICAL_TRIALS_DESIGN.md.

Usage (pilot):
    TMPDIR=/tmp/gov-run ~/workspace/.gov-venv/bin/python \\
        evals/trial_runner.py --pilot --trials 25

A "trial" runs one probe once under a fixed seed and an isolated
TMPDIR. Two probe kinds are supported:
  matrix  sit_id,adapter,priv,harness  -> run_evals.run_cell()
  probe   module-path::func-name        -> registry-probe style

ASR framing: for matrix cells, "attack success" = the cell FAILS its
gate expectation (the control did not produce the expected verdict).
For registry probes, "attack success" = observed verdict outside the
registry oracle's accept set. pass_rate = 1 - ASR.

Verdict classes per target:
  DETERMINISTIC-HOLD    all trials pass   (ASR 0, CI upper bounded)
  DETERMINISTIC-FAIL    all trials fail   (stable; investigate the
                        control, not the trial)
  DETERMINISTIC-RESID   all trials "break" on a residual-accepted
                        probe (documented steady state, stable)
  FLAKY                 mixed outcomes    (SIGNAL, not noise — the
                        probe or the control is nondeterministic;
                        investigate, never average away)

Confidence: Wilson score interval (95%) on the pass rate. With n=25
and 25/25 passes, the CI is [0.87, 1.00] — i.e. "deterministic hold
within a 25-trial budget", never a proof of determinism.

Determinism hygiene per trial: random.seed(seed_base + trial_idx),
isolated per-trial TMPDIR (tempfile.tempdir cache reset, mirroring
the registry gate's wave-24 hygiene), and the cell's own F65 tmpdir
sweep. The matrix is a rule engine — determinism is EXPECTED; the
trial layer's job is to prove it per target and to catch the
timing/concurrency flakes documented under load (F86 entry:
sit105/sit117/sit132/sit64 moved between full-matrix runs).

$0, stdlib only. Never run concurrently with the canonical suite or
the full matrix gate (TMPDIR/load phantom flakes — standing rule).
"""

import argparse
import math
import os
import random
import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

os.environ.setdefault("GOV_DEV_KEYS", "1")
# Wave-69: synthetic trial runner, not production (wave-61 discipline).
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
from gov.log import enable_dev_keys  # noqa: E402
enable_dev_keys()

from evals import run_evals as R  # noqa: E402


def wilson_ci(k, n, z=1.96):
    """Wilson score interval for k successes in n trials."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1.0 + z * z / n
    center = p + z * z / (2.0 * n)
    delta = z * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n))
    lo = max(0.0, (center - delta) / denom)
    hi = min(1.0, (center + delta) / denom)
    return (lo, hi)


def _isolated_tmpdir(trial_idx):
    d = tempfile.mkdtemp(prefix="trial-%03d-" % trial_idx)
    old_env = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = d
    tempfile.tempdir = d
    return d, old_env, old_cached


def _restore_tmpdir(d, old_env, old_cached):
    if old_env is None:
        os.environ.pop("TMPDIR", None)
    else:
        os.environ["TMPDIR"] = old_env
    tempfile.tempdir = old_cached
    shutil.rmtree(d, ignore_errors=True)


def trial_matrix_cell(sit_id, adapter, priv, harness, seed):
    """One matrix cell, one trial. Returns True iff the cell passes
    its gate expectation."""
    random.seed(seed)
    d, old_env, old_cached = _isolated_tmpdir(seed)
    try:
        r = R.run_cell(sit_id, adapter, priv, harness)
        return bool(r.get("passed"))
    except Exception:  # noqa: BLE001 - a raising cell is a failed trial
        return False
    finally:
        _restore_tmpdir(d, old_env, old_cached)


def trial_registry_probe(mod_path, func_name, seed, accept):
    """One registry probe, one trial. Returns the observed verdict
    string ('stopped'/'break'/'flagged'/'error'). ``accept`` is the
    oracle accept set; pass = observed in accept."""
    import importlib
    random.seed(seed)
    d, old_env, old_cached = _isolated_tmpdir(seed)
    try:
        mod = importlib.import_module(mod_path.replace("/", "."))
        fn = getattr(mod, func_name)
        before = len(mod.RESULTS)
        fn()
        if len(mod.RESULTS) == before:
            return "error"
        return mod.RESULTS[-1].get("verdict", "error")
    except Exception:  # noqa: BLE001
        return "error"
    finally:
        _restore_tmpdir(d, old_env, old_cached)


def run_trials(targets, n_trials=25, seed_base=20260922):
    """targets: list of dicts with kind 'matrix' or 'probe'.

    matrix target: {kind, sit, adapter, priv, harness}
    probe target:  {kind, module, func, accept:set, residual:bool}
    Returns a report dict.
    """
    report = {"n_trials": n_trials, "seed_base": seed_base,
              "targets": []}
    for ti, t in enumerate(targets):
        passes = 0
        verdicts = []
        t0 = time.time()
        for i in range(n_trials):
            seed = seed_base + ti * 100003 + i
            if t["kind"] == "matrix":
                ok = trial_matrix_cell(t["sit"], t["adapter"],
                                       t["priv"], t["harness"], seed)
                verdicts.append("pass" if ok else "fail")
                passes += ok
            else:
                v = trial_registry_probe(t["module"], t["func"], seed,
                                         t["accept"])
                verdicts.append(v)
                passes += (v in t["accept"])
        fails = n_trials - passes
        lo, hi = wilson_ci(passes, n_trials)
        asr = 1.0 - passes / n_trials
        if t["kind"] == "probe" and t.get("residual"):
            # Residual probes: the documented steady state is "break";
            # stability of the verdict (not "hold") is what matters.
            # A flip to "stopped" is a strict improvement the gate
            # reports distinctly — here it surfaces as FLAKY so the
            # boundary move is never averaged away.
            cls = ("DETERMINISTIC-RESID" if len(set(verdicts)) == 1
                   else "FLAKY")
        elif passes == n_trials:
            cls = "DETERMINISTIC-HOLD"
        elif passes == 0:
            cls = "DETERMINISTIC-FAIL"
        else:
            cls = "FLAKY"
        label = (t.get("label") or
                 "%s/%s/%s/%s" % (t.get("sit"), t.get("adapter"),
                                  t.get("priv"), t.get("harness"))
                 if t["kind"] == "matrix"
                 else "%s::%s" % (t["module"], t["func"]))
        report["targets"].append({
            "label": label, "kind": t["kind"],
            "passes": passes, "fails": fails,
            "pass_rate": passes / n_trials, "asr": asr,
            "wilson95": (round(lo, 3), round(hi, 3)),
            "class": cls,
            "elapsed_s": round(time.time() - t0, 1),
        })
        print("[%s] %-52s pass %2d/%-2d  ASR %.2f  95%%CI %s  %s"
              % (cls.split("-")[0], label, passes, n_trials, asr,
                 (round(lo, 3), round(hi, 3)), cls))
    return report


PILOT_MATRIX_CELLS = [
    # (sit, adapter, priv, harness) — verdict-diverse, includes the
    # historically load-sensitive sits (sit64 TOCTOU, sit105 chain
    # cost) and the approval-binding sit10 (F124-adjacent surface).
    ("sit1", "decorator", "elevated", "provisional"),
    ("sit1", "openai-loop", "elevated", "real"),
    ("sit2", "mcp", "elevated", "provisional"),
    ("sit2", "mcp", "elevated", "real"),
    ("sit3", "langchain", "elevated", "provisional"),
    ("sit10", "decorator", "elevated", "provisional"),
    ("sit10", "decorator", "elevated", "real"),
    ("sit47", "decorator", "elevated", "provisional"),
    ("sit64", "decorator", "elevated", "real"),
    ("sit105", "decorator", "elevated", "provisional"),
]

PILOT_PROBES = [
    # (module, func, accept-set, residual?) — the 7 new RT21 pins.
    ("evals/w54_probes", "sit_close_approval_replay_stopped",
     {"stopped", "flagged"}, False),
    ("evals/w54_probes", "sit_close_approval_consumed_bound",
     {"stopped", "flagged"}, False),
    ("evals/w54_probes", "sit_fresh_approval_per_entry",
     {"stopped", "flagged"}, False),
    ("evals/w54_probes", "sit_failed_close_no_burn",
     {"stopped", "flagged"}, False),
    ("evals/w54_probes", "sit_late_attach_audited",
     {"stopped", "flagged"}, False),
    ("evals/w54_probes", "sit_expiry_pending_approval_asymmetry",
     {"break", "stopped"}, True),
    ("evals/w54_probes", "sit_human_close_pending_asymmetry",
     {"break", "stopped"}, True),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--trials", type=int, default=25)
    ap.add_argument("--seed-base", type=int, default=20260922)
    args = ap.parse_args()
    if not args.pilot:
        ap.error("--pilot is the only mode in this prototype")
    targets = []
    for sit, ad, priv, h in PILOT_MATRIX_CELLS:
        targets.append({"kind": "matrix", "sit": sit, "adapter": ad,
                        "priv": priv, "harness": h})
    for mod, func, accept, resid in PILOT_PROBES:
        targets.append({"kind": "probe", "module": mod, "func": func,
                        "accept": accept, "residual": resid})
    print("trial pilot: %d targets x %d trials (seed_base=%d)"
          % (len(targets), args.trials, args.seed_base))
    report = run_trials(targets, n_trials=args.trials,
                        seed_base=args.seed_base)
    from collections import Counter
    c = Counter(t["class"] for t in report["targets"])
    print("-" * 70)
    print("PILOT CLASSES:", dict(c))
    flaky = [t for t in report["targets"]
             if t["class"] == "FLAKY"]
    if flaky:
        print("FLAKY (signal, not noise — investigate):")
        for t in flaky:
            print("  %s pass %d/%d" % (t["label"], t["passes"],
                                       report["n_trials"]))
    else:
        print("No flaky targets in this pilot.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
