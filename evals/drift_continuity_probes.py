"""Wave-148, row 9: cross-run drift continuity digest.

Row-9 residual: the pacing-aware adaptive budget (adaptation level,
paced-cycle rotation history, slow-burn accumulator) lives in the
executor's chained store. When the executor restarts with a fresh
store, that state is lost: paced bursts split across a restart never
tighten, and the attacker gets a clean budget for free. This battery
is RED-first: probes r1/r2/r3 run the restart scenario against the
continuity seam and go BREAK while it is missing; they flip to HELD
once ``BudgetStore.export_continuity`` / ``import_continuity`` land.

Continuity contract under test:
  - ``export_continuity(agent, policy, hmac_key)`` returns a compact
    MAC'd digest: adapt_level (tightness), paced_cycles (count),
    rot_history (paced-signature history), slow_accum/slow_runs.
  - ``import_continuity(agent, digest, hmac_key, run_seq)`` on a fresh
    store verifies the MAC, writes a chained ``continuity_restore``
    record, and emits LOUD ``drift_state_restored``; the restored
    tightness drives ``check()`` (effective limit/window).
  - A forged digest (tampered body or wrong key) is REFUSED: LOUD
    ``drift_digest_forgery_attempt``, no state change, and the run
    continues clean (benign runs still record and check ok).

  r1_restart_paced_bursts_tighten_and_trip: paced [~0.9, clean] bursts
     tighten executor 1 (level >= 1, no trip); after a restart with a
     fresh store, import restores tightness (LOUD drift_state_restored)
     and continued pacing trips (drift_budget_tripped).
  r2_forged_digest_refused_loud: tampered-body and wrong-key digests
     are refused with LOUD drift_digest_forgery_attempt; the store is
     unchanged and a benign run still records/checks clean.
  r3_benign_restart_no_false_trips: 200 benign restart sequences
     (import a clean digest, run benign bursts + clean defuses):
     zero trips, zero drift_budget_tripped events.
  r4_deterministic_x2: the whole battery runs twice; verdicts must be
     identical.

Known residuals (row 9 stays PARTIAL): many-shot/framing drift and
from-birth baseline poisoning are untouched by this seam; a stale but
MAC-valid digest replayed across a FULL store loss is refused only by
the operator's latest-wins handling of the digest path (documented in
gov/drift_budget.py); in-cycle streak/bucket counters restart at zero
across an import (level, rotation history, and the slow-burn
accumulator survive).

$0 spend, synthetic/local, deterministic. Stdlib only.
"""
import importlib.util
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_battery(fname, modname):
    spec = importlib.util.spec_from_file_location(
        modname, os.path.join(_HERE, fname))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_AD = _load_battery("adaptive_drift_probes.py", "_adaptdrift_src")
_BUDGET = _AD._budget

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-38s %-10s %s" % (name, verdict, detail))


_TEST_KEY = b"wave-148-continuity-test-key"
_AGENT = "agent-restart"


class _Ctx(_AD._Ctx):
    """Fresh store + event sink per executor incarnation."""

    def loud_events(self):
        return [e for e in self.events
                if e.get("severity") == "LOUD"]

    def event_names(self):
        return [e.get("event") for e in self.events]

    def adapt_levels(self, agent):
        return [r.get("adapt_level") for r in self.store.contributions(agent)
                if r.get("kind") == "adapt"
                and r.get("direction") == "tighten"]


def _has_seam(store):
    return (hasattr(store, "export_continuity")
            and hasattr(store, "import_continuity"))


def _calibrated_pacer():
    warn = _AD._calibrate()
    found = _AD._scan_below(warn)
    if found is None:
        return None, None, None
    x, ratio = found
    policy, _ = _AD._policy(warn, adaptive=True)
    return warn, x, policy


def r1_restart_paced_bursts_tighten_and_trip():
    """Paced bursts across an executor restart still tighten and trip."""
    name = "r1_restart_paced_bursts_tighten_and_trip"
    warn, x, policy = _calibrated_pacer()
    if warn is None:
        _record(name, "ERROR", "calibration scan found no ~0.9 shift")
        return
    # --- executor 1: two pacer cycles ([~0.9, clean] x2) ---
    ex1 = _Ctx("r1ex1", policy)
    if not _has_seam(ex1.store):
        _record(name, "BREAK", "no continuity seam "
                "(export_continuity/import_continuity missing)")
        return
    seq = 0
    for _ in range(2):
        seq += 1
        ex1.record(_AGENT, _AD._shifted(x), seq)
        seq += 1
        ex1.record(_AGENT, dict(_AD._BASE_TOOLS), seq)  # clean defuse
    chk1 = ex1.check(_AGENT)
    levels1 = ex1.adapt_levels(_AGENT)
    if chk1.status == "tripped":
        _record(name, "BREAK", "executor 1 already tripped before the "
                "restart (probe shape wrong, cumulative=%.3f)"
                % chk1.cumulative)
        return
    if not levels1:
        _record(name, "BREAK", "executor 1 never tightened "
                "(no adapt tightening records)")
        return
    digest = ex1.store.export_continuity(_AGENT, policy, _TEST_KEY)
    # --- executor 2: fresh store, import, continue pacing ---
    ex2 = _Ctx("r1ex2", policy)
    seq = digest["run_seq"] + 1
    ok = ex2.store.import_continuity(_AGENT, digest, _TEST_KEY, seq)
    if not ok:
        _record(name, "BREAK", "valid digest refused on import")
        return
    if "drift_state_restored" not in ex2.event_names():
        _record(name, "BREAK", "import did not emit LOUD "
                "drift_state_restored")
        return
    if not any(e.get("event") == "drift_state_restored"
               and e.get("severity") == "LOUD" for e in ex2.events):
        _record(name, "BREAK", "drift_state_restored not LOUD")
        return
    tripped_at = None
    for _ in range(3):
        seq += 1
        ex2.record(_AGENT, _AD._shifted(x), seq)
        chk = ex2.check(_AGENT)
        if chk.status == "tripped":
            tripped_at = seq
            break
        seq += 1
        ex2.record(_AGENT, dict(_AD._BASE_TOOLS), seq)
        chk = ex2.check(_AGENT)
        if chk.status == "tripped":
            tripped_at = seq
            break
    if tripped_at is None:
        _record(name, "BREAK", "continued pacing after restore never "
                "tripped (restored level=%s)" % levels1[-1])
        return
    if "drift_budget_tripped" not in ex2.event_names():
        _record(name, "BREAK", "trip had no drift_budget_tripped event")
        return
    _record(name, "HELD",
            "executor 1 tightened to level %s; restart restored it "
            "(LOUD drift_state_restored); continued pacing tripped at "
            "run %d" % (levels1[-1], tripped_at))


def r2_forged_digest_refused_loud():
    """A forged digest is refused LOUD; the run continues clean."""
    name = "r2_forged_digest_refused_loud"
    warn, x, policy = _calibrated_pacer()
    if warn is None:
        _record(name, "ERROR", "calibration scan found no ~0.9 shift")
        return
    ex1 = _Ctx("r2ex1", policy)
    if not _has_seam(ex1.store):
        _record(name, "BREAK", "no continuity seam "
                "(export_continuity/import_continuity missing)")
        return
    seq = 0
    for _ in range(2):
        seq += 1
        ex1.record(_AGENT, _AD._shifted(x), seq)
        seq += 1
        ex1.record(_AGENT, dict(_AD._BASE_TOOLS), seq)
    good = ex1.store.export_continuity(_AGENT, policy, _TEST_KEY)

    def _try_import(tag, digest, key):
        ex = _Ctx("r2%s" % tag, policy)
        ok = ex.store.import_continuity(_AGENT, digest, key,
                                        good["run_seq"] + 1)
        kinds = [r.get("kind") for r in ex.store.contributions(_AGENT)]
        return ok, ex, kinds

    # Case A: tampered body (level raised), original MAC.
    tampered = dict(good)
    tampered["adapt_level"] = int(good.get("adapt_level", 0)) + 5
    ok_a, ex_a, kinds_a = _try_import("a", tampered, _TEST_KEY)
    # Case B: valid body, wrong key.
    ok_b, ex_b, kinds_b = _try_import("b", dict(good), b"wrong-key")
    for tag, ok, ex, kinds in (("tampered-body", ok_a, ex_a, kinds_a),
                               ("wrong-key", ok_b, ex_b, kinds_b)):
        if ok:
            _record(name, "BREAK", "%s digest accepted" % tag)
            return
        if "drift_digest_forgery_attempt" not in ex.event_names():
            _record(name, "BREAK", "%s refusal had no LOUD "
                    "drift_digest_forgery_attempt" % tag)
            return
        if not any(e.get("event") == "drift_digest_forgery_attempt"
                   and e.get("severity") == "LOUD" for e in ex.events):
            _record(name, "BREAK", "%s forgery event not LOUD" % tag)
            return
        if "continuity_restore" in kinds:
            _record(name, "BREAK", "%s refusal still wrote a restore "
                    "record" % tag)
            return
    # The run continues clean: benign runs still record and check ok.
    seq = 0
    for _ in range(3):
        seq += 1
        ex_a.record(_AGENT, dict(_AD._BASE_TOOLS), seq)
    chk = ex_a.check(_AGENT)
    if chk.status == "tripped":
        _record(name, "BREAK", "post-refusal benign runs tripped")
        return
    _record(name, "HELD", "tampered-body and wrong-key digests refused "
            "(LOUD drift_digest_forgery_attempt, no state change); "
            "benign runs continue clean")


def r3_benign_restart_no_false_trips():
    """200 benign restart sequences: zero false trips.

    100 import a level-0 clean digest, 100 import a level-1 paced
    digest (tightness restored across the restart must not punish
    legitimate traffic either). The post-restore mix is alternating
    small benign drifts with clean defuses -- no false trips and no
    false tightenings are the bar in both cases.
    """
    name = "r3_benign_restart_no_false_trips"
    warn, x, policy = _calibrated_pacer()
    if warn is None:
        _record(name, "ERROR", "calibration scan found no ~0.9 shift")
        return
    src = _Ctx("r3src", policy)
    if not _has_seam(src.store):
        _record(name, "BREAK", "no continuity seam "
                "(export_continuity/import_continuity missing)")
        return
    # A clean digest: three benign runs, level 0.
    seq = 0
    for i in range(3):
        seq += 1
        tools = _AD._shifted(3) if i % 2 == 0 else _AD._shifted_rev(3)
        src.record(_AGENT, tools, seq)
    clean_digest = src.store.export_continuity(_AGENT, policy, _TEST_KEY)
    if int(clean_digest.get("adapt_level", -1)) != 0:
        _record(name, "BREAK", "benign export not level 0")
        return
    # A paced digest: two [~0.9, clean] cycles, level 1.
    psrc = _Ctx("r3psrc", policy)
    seq = 0
    for _ in range(2):
        seq += 1
        psrc.record(_AGENT, _AD._shifted(x), seq)
        seq += 1
        psrc.record(_AGENT, dict(_AD._BASE_TOOLS), seq)
    paced_digest = psrc.store.export_continuity(_AGENT, policy,
                                               _TEST_KEY)
    if int(paced_digest.get("adapt_level", -1)) != 1:
        _record(name, "BREAK", "paced export not level 1")
        return
    trips = 0
    false_tighten = 0
    restored = 0
    for i in range(200):
        digest = clean_digest if i % 2 == 0 else paced_digest
        ex = _Ctx("r3_%d" % i, policy)
        ok = ex.store.import_continuity(
            _AGENT, dict(digest), _TEST_KEY,
            int(digest["run_seq"]) + 1)
        if not ok:
            _record(name, "BREAK", "clean digest refused at iteration %d"
                    % i)
            return
        if "drift_state_restored" in ex.event_names():
            restored += 1
        s = int(digest["run_seq"]) + 1
        for j in range(6):
            s += 1
            if j % 3 == 2:
                tools = dict(_AD._BASE_TOOLS)  # clean defuse
            elif j % 2 == 0:
                tools = _AD._shifted(3)
            else:
                tools = _AD._shifted_rev(3)
            ex.record(_AGENT, tools, s)
            if ex.check(_AGENT).status == "tripped":
                trips += 1
        if "drift_budget_tripped" in ex.event_names():
            trips += 1
        if "drift_budget_adapted" in ex.event_names():
            false_tighten += 1
    if trips:
        _record(name, "BREAK", "%d false trips over 200 benign restart "
                "sequences" % trips)
        return
    if false_tighten:
        _record(name, "BREAK", "%d false tightenings over 200 benign "
                "restart sequences" % false_tighten)
        return
    _record(name, "HELD", "200 benign restart sequences, 0 false trips "
            "(%d/200 emitted LOUD drift_state_restored)" % restored)


def _run_all():
    global _RESULTS
    _RESULTS = []
    for fn in (r1_restart_paced_bursts_tighten_and_trip,
               r2_forged_digest_refused_loud,
               r3_benign_restart_no_false_trips):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - battery must report
            _record(fn.__name__, "ERROR", "raised %r" % (exc,))
    return list(_RESULTS)


def r4_deterministic_x2():
    name = "r4_deterministic_x2"
    first = [(n, v, d) for n, v, d in _run_all()]
    second = [(n, v, d) for n, v, d in _run_all()]
    if first != second:
        _record(name, "BREAK", "verdicts differ between runs: %r vs %r"
                % (first, second))
        return
    _record(name, "HELD", "%d probes identical verdicts+details across "
            "2 runs" % len(first))


def main():
    if "TMPDIR" not in os.environ:
        print("drift_continuity_probes: TMPDIR must be set "
              "(mkdir -p it first)")
        return 2
    _run_all()
    r4_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("drift_continuity_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
