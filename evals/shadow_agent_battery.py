#!/usr/bin/env python3
"""Shadow-agent behavioral fingerprinting battery (prospecting R6 #1).

RED-first: on a tree WITHOUT the shadow-scan seam
(``discovery.scan_action_log`` missing) this battery FAILs — today's
``discovery.scan_directory`` never reads the action log, so an
unregistered machine-rate principal acting through the governed
executor is invisible to it. On the built tree it PASSes: the seam
flags exactly the unregistered machine-rate principal (and the
jittered-evasion variant), never the human, the benign cron, the
human burst, or the registered agent.

Deterministic: fixed epoch + seeded RNG, no wall clock, no network.
$0 spend, synthetic/local only.

Probes:
  p1 machine-rate unregistered agent -> FLAGGED (sighting in ledger)
  p2 registered agent (agent-like)    -> EXCLUDED (no finding)
  p3 bursty human                     -> NOT FLAGGED
  p4 benign cron (5 reads/hour)       -> NOT FLAGGED
  p5 human burst (40 reads / 2 min)   -> NOT FLAGGED (span gate)
  p6 jittered-evasion agent           -> FLAGGED (pattern survives)
  p7 determinism                      -> byte-identical findings x2
  p8 slow agent (<0.5/min)            -> NOT FLAGGED (documented
                                       honest residual, pinned)

Run:
  mkdir -p /tmp/gov-shadow
  TMPDIR=/tmp/gov-shadow ~/workspace/.gov-venv/bin/python \\
      evals/shadow_agent_battery.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-shadowb \\
      ~/workspace/.gov-venv/bin/python evals/shadow_agent_battery.py
"""

import json
import os
import random
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

BASE = 1_788_000_000  # fixed epoch: deterministic, no wall clock
rng = random.Random(20260928)


def ev(principal, t, tool, event):
    return {"seq": 0, "ts": t, "principal": principal,
            "tool": tool, "event": event}


def fixture_machine(t0, principal, cadence_s, n, reads_per_list=3):
    """Machine-rate list->read enumeration loops."""
    entries = []
    t = t0
    for _ in range(n):
        t += cadence_s
        entries.append(ev(principal, t, "list_documents", "enumerate"))
        for k in range(reads_per_list):
            entries.append(ev(principal, t + 1 + k, "read_document",
                              "read %d" % k))
    return entries


def main():
    try:
        from gov import discovery
        scan_action_log = discovery.scan_action_log
    except (ImportError, AttributeError) as e:
        print("BATTERY: FAIL — shadow-scan seam missing: %r" % (e,))
        print("(red-first: discovery.scan_directory never reads the "
              "action log)")
        return 1

    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))
        print("[%s] %s %s" % ("PASS" if cond else "FAIL", name,
                              ("— " + detail) if detail else ""))

    # --- p1: machine-rate unregistered agent is flagged ----------------
    entries = fixture_machine(BASE, "svc-indexer", 45, 60)
    with tempfile.TemporaryDirectory() as d:
        sigs = scan_action_log(entries, set())
        ledger = discovery.DiscoveryLedger(
            os.path.join(d, "ledger.jsonl"))
        ledger.note_signals(sigs)
        findings = discovery.unregistered_candidates(ledger)
        kinds = (findings[0]["signal_kinds"] if findings else [])
        srcs = (findings[0]["sources"] if findings else [])
    check("p1_machine_agent_flagged",
          len(findings) == 1 and srcs == ["principal:svc-indexer"],
          "findings=%d kinds=%s" % (len(findings), kinds))

    # --- p2: registered agent-like principal is excluded ---------------
    sigs = scan_action_log(entries, {"svc-indexer"})
    check("p2_registered_excluded", sigs == [],
          "signals=%d" % len(sigs))

    # --- p3: bursty human is not flagged --------------------------------
    entries = []
    t = BASE
    for _ in range(38):
        t += rng.choice([5, 12, 30, 90, 300, 900, 1800])
        entries.append(ev("human-op", t, "read_file", "operator action"))
    sigs = scan_action_log(entries, set())
    check("p3_human_not_flagged", sigs == [], "signals=%d" % len(sigs))

    # --- p4: benign cron (5 reads/hour, perfectly regular) -------------
    entries = []
    t = BASE
    for _ in range(40):  # 8h window, 0.083/min — below the machine band
        t += 720
        entries.append(ev("cron-backup", t, "read_file", "scheduled read"))
    sigs = scan_action_log(entries, set())
    check("p4_cron_not_flagged", sigs == [], "signals=%d" % len(sigs))

    # --- p5: human burst (40 reads in 2 min) — span gate ----------------
    entries = [ev("human-op", BASE + i * 3, "read_file", "paste burst")
               for i in range(40)]
    sigs = scan_action_log(entries, set())
    check("p5_human_burst_not_flagged", sigs == [],
          "signals=%d" % len(sigs))

    # --- p6: jittered-evasion agent is still flagged --------------------
    r2 = random.Random(777)
    entries = []
    t = BASE
    end = BASE + int(3.2 * 3600)
    while t < end:
        t += r2.choice([10, 25, 45, 80, 120])
        entries.append(ev("svc-jitter", t, "list_documents", "enumerate"))
        for k in range(3):
            entries.append(ev("svc-jitter", t + 1 + k, "read_document",
                              "read %d" % k))
    sigs = scan_action_log(entries, set())
    flagged = any(s["source"] == "principal:svc-jitter" for s in sigs)
    check("p6_jittered_evasion_flagged", flagged,
          "signals=%d actions=%d" % (len(sigs), len(entries)))

    # --- p7: determinism ------------------------------------------------
    entries = fixture_machine(BASE, "svc-indexer", 45, 60)
    a = scan_action_log(entries, set())
    b = scan_action_log(entries, set())
    strip = lambda ss: [{k: s[k] for k in ("kind", "source", "detail",
                                          "strength")} for s in ss]
    det = json.dumps(strip(a), sort_keys=True) == json.dumps(
        strip(b), sort_keys=True)
    check("p7_deterministic", det, "")

    # --- p8: slow agent (<0.5/min) evades — documented residual --------
    entries = []
    t = BASE
    for _ in range(60):  # 0.25/min over 4h — below the machine band
        t += 240
        entries.append(ev("svc-slow", t, "read_document", "slow read"))
    sigs = scan_action_log(entries, set())
    check("p8_slow_agent_misses_documented", sigs == [],
          "signals=%d (honest residual: <0.5/min evades by construction)"
          % len(sigs))

    failed = [n for n, ok, _ in results if not ok]
    print("BATTERY: %s (%d/%d)" % (
        "PASS" if not failed else "FAIL — " + ",".join(failed),
        len(results) - len(failed), len(results)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
