#!/usr/bin/env python3
"""Rate-independent enumeration-signal battery (prospecting R7 #5).

RED-first: on a tree WITHOUT gov/enumeration_signal this battery
FAILs (ImportError) -- the signal does not exist. On the built tree
it PASSes: slow AND bursty structured enumeration is flagged through
the public discovery.scan_action_log seam, while organic humans, the
benign cron, human bursts, list-less evasion, and diluted traffic are
not.

Deterministic: fixed epoch + seeded RNG, no wall clock, no network.
$0 spend, synthetic/local only.

Probes:
  p1 slow structured enumeration (0.25/min) -> FLAGGED
  p2 bursty structured enumeration (machine rate) -> FLAGGED
     (rate-independence: p1 and p2 carry identical structure)
  p3 organic human (repetition, low coverage) -> NOT FLAGGED
  p4 benign cron (5 reads/hour, one target)   -> NOT FLAGGED
  p5 human burst (40 reads / 2 min)           -> NOT FLAGGED
  p6 list-less evasion (distinct reads, no LIST) -> NOT FLAGGED
     (documented honest residual)
  p7 diluted enumeration (structured + organic) -> NOT FLAGGED
     (documented graceful degradation)
  p8 determinism -> byte-identical signals x2
  p9 p8 pin preserved: 60 unstructured slow reads -> no signals
  p10 very-slow enumeration (1 query/hour, 80h span) -> FLAGGED
     (no timing criterion anywhere in the signal)

Run:
  mkdir -p /tmp/gov-enum
  TMPDIR=/tmp/gov-enum ~/workspace/.gov-venv/bin/python \
      evals/enumeration_signal_battery.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-enumb \
      ~/workspace/.gov-venv/bin/python evals/enumeration_signal_battery.py
"""

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

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, cond, detail=""):
    results.append((name, PASS if cond else FAIL, detail))
    print("[%s] %s %s" % (PASS if cond else FAIL, name,
                          ("-- " + detail) if detail else ""))
    return bool(cond)


def ev(principal, t, tool, event, target=None):
    e = {"seq": 0, "ts": t, "principal": principal,
         "tool": tool, "event": event}
    if target is not None:
        e["target"] = target
    return e


def structured_enum(t0, principal, gap_s, loops=20, reads_per_loop=3):
    """List->read loops over distinct targets at a fixed cadence."""
    entries = []
    t = t0
    tid = 0
    for loop in range(loops):
        entries.append(ev(principal, t, "list_documents", "enumerate",
                          target="collection/%d" % loop))
        t += gap_s
        for _ in range(reads_per_loop):
            entries.append(ev(principal, t, "read_document", "read",
                              target="doc/%04d" % tid))
            tid += 1
            t += gap_s
    return entries


def kinds_for(entries, registered=frozenset()):
    from gov import discovery
    sigs = discovery.scan_action_log(entries, set(registered))
    by_src = {}
    for s in sigs:
        by_src.setdefault(s["source"], set()).add(s["kind"])
    return sigs, by_src


def main():
    try:
        from gov import enumeration_signal  # noqa: F401 (red-first seam)
        from gov import discovery  # noqa: F401
    except ImportError as e:
        print("BATTERY: FAIL -- enumeration-signal seam missing: %r" % (e,))
        print("(red-first: gov/enumeration_signal does not exist on the "
              "unmodified tree)")
        return 1

    # --- p1: slow structured enumeration is flagged -------------------
    entries = structured_enum(BASE, "svc-slow-enum", 240)  # 0.25/min
    sigs, by_src = kinds_for(entries)
    kinds = by_src.get("principal:svc-slow-enum", set())
    check("p1_slow_enum_flagged", "enumeration_structure" in kinds,
          "kinds=%s signals=%d" % (sorted(kinds), len(sigs)))

    # --- p2: bursty structured enumeration is flagged (same structure) --
    entries = structured_enum(BASE, "svc-fast-enum", 2)  # machine rate
    sigs, by_src = kinds_for(entries)
    kinds = by_src.get("principal:svc-fast-enum", set())
    check("p2_bursty_enum_flagged", "enumeration_structure" in kinds,
          "kinds=%s signals=%d (rate-independent: identical structure)"
          % (sorted(kinds), len(sigs)))

    # --- p3: organic human is not flagged -------------------------------
    entries = []
    t = BASE
    targets = ["notes/todo", "notes/ideas", "inbox", "drafts/plan",
               "archive/2025"]
    for _ in range(38):
        t += rng.choice([5, 12, 30, 90, 300, 900, 1800])
        if rng.random() < 0.15:
            entries.append(ev("human-op", t, "list_documents", "browse",
                              target="collection/shared"))
        else:
            entries.append(ev("human-op", t, "read_file", "operator action",
                              target=rng.choice(targets)))
    sigs, by_src = kinds_for(entries)
    kinds = by_src.get("principal:human-op", set())
    check("p3_human_not_flagged", "enumeration_structure" not in kinds,
          "kinds=%s" % sorted(kinds))

    # --- p4: benign cron is not flagged ----------------------------------
    entries = [ev("cron-backup", BASE + i * 720, "read_file",
                  "scheduled read", target="backup/snapshot")
               for i in range(40)]
    sigs, by_src = kinds_for(entries)
    kinds = by_src.get("principal:cron-backup", set())
    check("p4_cron_not_flagged", "enumeration_structure" not in kinds,
          "kinds=%s" % sorted(kinds))

    # --- p5: human burst is not flagged ----------------------------------
    entries = [ev("human-op", BASE + i * 3, "read_file", "paste burst",
                  target="notes/scratch")
               for i in range(40)]
    sigs, by_src = kinds_for(entries)
    kinds = by_src.get("principal:human-op", set())
    check("p5_human_burst_not_flagged", "enumeration_structure" not in kinds,
          "kinds=%s" % sorted(kinds))

    # --- p6: list-less evasion is not flagged (documented residual) ------
    # The enumerator already knows its targets: 60 distinct reads in
    # random order, no LIST actions at all. No loop structure exists to
    # detect; coverage alone deliberately does not fire.
    r2 = random.Random(4242)
    tgts = ["doc/%04d" % i for i in range(60)]
    r2.shuffle(tgts)
    entries = [ev("svc-evasive", BASE + i * 240, "read_document", "read",
                  target=tg)
               for i, tg in enumerate(tgts)]
    sigs, by_src = kinds_for(entries)
    kinds = by_src.get("principal:svc-evasive", set())
    check("p6_listless_evasion_misses_documented",
          "enumeration_structure" not in kinds,
          "kinds=%s (honest residual: no LIST, no loop structure)"
          % sorted(kinds))

    # --- p7: diluted enumeration degrades (documented) --------------------
    entries = structured_enum(BASE, "svc-diluted", 240)
    t = entries[-1]["ts"]
    for i in range(120):  # 120 organic re-reads of 5 targets
        t += 240
        entries.append(ev("svc-diluted", t, "read_document", "re-read",
                          target="notes/fav%d" % (i % 5)))
    sigs, by_src = kinds_for(entries)
    kinds = by_src.get("principal:svc-diluted", set())
    check("p7_dilution_degrades_documented",
          "enumeration_structure" not in kinds,
          "kinds=%s (honest residual: coverage 85/200 < 0.6)"
          % sorted(kinds))

    # --- p8: determinism --------------------------------------------------
    entries = structured_enum(BASE, "svc-slow-enum", 240)
    a, _ = kinds_for(entries)
    b, _ = kinds_for(entries)
    strip = lambda ss: sorted((s["kind"], s["source"]) for s in ss)
    check("p8_deterministic", strip(a) == strip(b), "")

    # --- p9: the p8 pin is preserved --------------------------------------
    entries = [ev("svc-slow", BASE + i * 240, "read_document", "slow read")
               for i in range(60)]
    from gov import discovery as _d
    check("p9_slow_unstructured_still_dark",
          _d.scan_action_log(entries, set()) == [],
          "no enumeration structure in 60 unstructured slow reads")

    # --- p10: very-slow enumeration is flagged (no timing anywhere) -------
    entries = structured_enum(BASE, "svc-glacial", 3600)  # 1 query/hour
    span_h = (entries[-1]["ts"] - entries[0]["ts"]) / 3600.0
    sigs, by_src = kinds_for(entries)
    kinds = by_src.get("principal:svc-glacial", set())
    check("p10_glacial_enum_flagged", "enumeration_structure" in kinds,
          "span=%.0fh kinds=%s (rate-independent by construction)"
          % (span_h, sorted(kinds)))

    failed = [n for n, ok, _ in results if ok == FAIL]
    print("BATTERY: %s (%d/%d)" % (
        "PASS" if not failed else "FAIL -- " + ",".join(failed),
        len(results) - len(failed), len(results)))
    return 0 if not failed else 1


def green_check():
    """Depth-1 green check: run the adjacent shadow-agent battery.

    Honors GOV_SKIP_GREEN=1 (a parent's green check sets it; this
    battery then records a skip instead of spawning). Never spawns
    another battery's full main without that guard. The shadow-agent
    battery has no green check of its own, so this stays depth-1.
    """
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check skipped (GOV_SKIP_GREEN=1)")
        return 0
    battery = os.path.join(REPO_ROOT, "evals", "shadow_agent_battery.py")
    print("green check: running %s" % battery)
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    r = subprocess.run([sys.executable, battery], env=env,
                       capture_output=True, text=True, timeout=600)
    tail = (r.stdout + r.stderr).strip().splitlines()[-3:]
    for line in tail:
        print("  | " + line)
    ok = r.returncode == 0
    print("green_check: %s" % ("HELD" if ok else "BROKEN"))
    return 0 if ok else 1


if __name__ == "__main__":
    import sys as _s
    rc = main()
    if rc == 0 and "--no-green" not in _s.argv:
        rc = green_check() or rc
    _s.exit(rc)
