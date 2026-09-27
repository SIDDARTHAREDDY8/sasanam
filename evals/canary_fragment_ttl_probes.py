#!/usr/bin/env python3
"""Wave-150 row 13: canary FRAGMENT TTL probes.

Break battery for the fragment time-to-live seam in gov/canary.py
(FRAGMENT_TTL_RUNS = 50, CanaryRegistry.advance_run).

PREMISE (measured, not assumed): CanaryRegistry.register() resets
the fragment seen-sets on every mint registration, so the
register-per-run pattern never had a staleness problem -- the brief's
"fragments persist forever" premise was REFUTED for that pattern
(see the design note in gov/canary.py). The seam targets the
LONG-LIVED pattern instead: register-once, advance_run() per run
boundary. There, fragment observations previously accumulated
forever, so two unrelated coincidences 58 runs apart could pair into
a false two-distinct-fragments trip. advance_run() expires any
fragment unobserved for more than FRAGMENT_TTL_RUNS runs.

Probes (RED-first: pre-seam the TTL API does not exist, so every
probe records BREAK "TTL API missing -- pre-seam RED"; a red-runner
also demonstrates the behavioral pre-seam break: without expiry the
stale pair TRIPS):
  t1_expiry_silences_stale_pair ... frag A observed run 1, frag B
     (same canary) in benign-looking egress run 60 -> SILENT (A
     expired at run 52); also asserts the expiry was logged at DEBUG
     with the canary label and no fragment string
  t1b_expiry_boundary ........... fragment observed run 1 is still
     active at exactly run 51 (50 runs elapsed) and expired at run 52
     (pins the off-by-one)
  t2_refresh_keeps_pair ......... A observed run 1, re-observed run
     40 (TTL refresh), B observed run 60 -> TRIPS
     (two_distinct_fragments)
  t3_whole_canary_unaffected ..... after 60 advance_run() calls the
     whole-value path still trips (canary_trip, not fragment)
  t4_ttl_bound_measured .......... seeded 60-run benign stream with
     coincidental fragment embeddings: measures false pair-trips at
     TTL=inf / 50 / 10, and the coverage side (slow 45-run campaign
     trips at TTL=50, lost at TTL=10) -- documents why 50 balances
     staleness vs coverage
  t5_deterministic_x2 ........... every probe byte-identical across
     two runs

$0, stdlib only, deterministic (seeded RNG for the corpus
measurement). New battery: sets GOV_DEPLOYMENT_MODE=staging at
module level; verified under `env -u GOV_DEPLOYMENT_MODE` too.
"""

import logging
import os
import random
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import gov.canary as _canary_mod  # noqa: E402
from gov.canary import (  # noqa: E402
    CanaryMint, CanaryRegistry, CanaryTripHalt, check_and_trip)

_RESULTS = []


def _record(name, verdict, detail):
    _RESULTS.append({"probe": name, "verdict": verdict,
                     "detail": detail})


def _ttl_api_present(reg):
    return (hasattr(reg, "advance_run")
            and hasattr(_canary_mod, "FRAGMENT_TTL_RUNS"))


def _pre_seam_break(name):
    _record(name, "BREAK", "TTL API missing -- pre-seam RED "
            "(no advance_run / FRAGMENT_TTL_RUNS)")


class _FakeLog(list):
    def append(self, event):
        super().append(event)


class _FakeApprovals(object):
    def pending(self):
        return []


class _FakePolicy(object):
    def decide(self, *a, **k):
        return None


class _FakeExecutor(object):
    def __init__(self, registry, run_id="run-ttl-1"):
        self.canary_registry = registry
        self.rare_token_tracker = None
        self.run_id = run_id
        self.log = _FakeLog()
        self.approvals = _FakeApprovals()
        self.policy = _FakePolicy()

    def _preview(self, tool, args):
        return {"tool": tool}


class _FakeIdentity(object):
    agent_id = "agent-1"
    principal = "op-1"
    role = "operator"

    def as_dict(self):
        return {"agent_id": self.agent_id}


def _mint_run(run_id="run-ttl-1"):
    mint = CanaryMint(run_id)
    reg = CanaryRegistry()
    reg.register(mint)
    return mint, reg


def _two_frags(reg):
    """Two non-overlapping derived fragments of one canary.

    Uses a canary longer than 2x the fragment length so that a single
    fragment can never trip via the half-span rule -- these probes
    exercise the pair rule only.
    """
    need = 2 * _canary_mod.FRAGMENT_LEN
    for value, frags in reg._fragments.items():
        if len(value) > need and len(frags) >= 3:
            return value, frags[0], frags[2]
    raise AssertionError("no long canary with >= 3 fragments")


def t1_expiry_silences_stale_pair():
    name = "t1_expiry_silences_stale_pair"
    _, reg = _mint_run()
    if not _ttl_api_present(reg):
        _pre_seam_break(name)
        return
    value, frag_a, frag_b = _two_frags(reg)

    records = []

    class _H(logging.Handler):
        def emit(self, r):
            records.append(r)

    logger = logging.getLogger("gov.canary")
    handler = _H()
    old_level = logger.level
    logger.setLevel(logging.DEBUG)  # DEBUG records are level-filtered
    logger.addHandler(handler)
    try:
        reg.advance_run()  # run 1
        assert reg.match_fragments("exfil attempt one: " + frag_a) \
            is None, "first fragment alone must not trip"
        for _ in range(59):
            reg.advance_run()  # runs 2..60; frag A expires at run 52
        hit = reg.match_fragments(
            "weekly rollup attached [pasted snippet " + frag_b + " end]")
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)

    if hit is not None:
        _record(name, "BREAK",
                "stale pair TRIPPED at run 60: fragment TTL did not "
                "expire the run-1 observation (hit=%r)" % (hit,))
        return
    # Expiry must be logged at DEBUG, with the label, never LOUD,
    # never with fragment strings (privacy discipline).
    debug_recs = [r for r in records
                  if r.levelno == logging.DEBUG
                  and "TTL expiry" in r.getMessage()]
    leaked = [r for r in records
              if frag_a in r.getMessage() or frag_b in r.getMessage()]
    label = reg._by_value[value]["label"]
    label_recs = [r for r in debug_recs if label in r.getMessage()]
    if not debug_recs:
        _record(name, "BREAK",
                "stale pair silent but no DEBUG expiry record was "
                "emitted")
    elif leaked:
        _record(name, "BREAK",
                "expiry log LEAKED a fragment string (%d records)"
                % len(leaked))
    elif not label_recs:
        _record(name, "BREAK",
                "DEBUG expiry records carry no canary label")
    else:
        _record(name, "HELD",
                "run-1 fragment expired; run-60 coincidence silent; "
                "expiry logged at DEBUG with label=%r, no fragment "
                "strings (%d expiry records)" % (label, len(debug_recs)))


def t1b_expiry_boundary():
    name = "t1b_expiry_boundary"
    _, reg = _mint_run("run-ttl-1b")
    if not _ttl_api_present(reg):
        _pre_seam_break(name)
        return
    value, frag_a, _frag_b = _two_frags(reg)
    reg.advance_run()  # run 1
    reg.match_fragments("exfil attempt one: " + frag_a)
    for _ in range(50):
        reg.advance_run()  # runs 2..51: exactly 50 runs elapsed
    alive_at_51 = (value, frag_a) in reg._fragment_last_seen
    reg.advance_run()  # run 52: 51 runs elapsed -- must expire
    expired_at_52 = (value, frag_a) not in reg._fragment_last_seen
    if alive_at_51 and expired_at_52:
        _record(name, "HELD",
                "fragment active at exactly 50 runs elapsed, expired "
                "at 51 (off-by-one pinned)")
    else:
        _record(name, "BREAK",
                "TTL boundary wrong: alive_at_51=%r expired_at_52=%r"
                % (alive_at_51, expired_at_52))


def t2_refresh_keeps_pair():
    name = "t2_refresh_keeps_pair"
    _, reg = _mint_run("run-ttl-2")
    if not _ttl_api_present(reg):
        _pre_seam_break(name)
        return
    _value, frag_a, frag_b = _two_frags(reg)
    reg.advance_run()  # run 1
    reg.match_fragments("exfil attempt one: " + frag_a)
    for _ in range(39):
        reg.advance_run()  # runs 2..40
    reg.match_fragments("exfil attempt two: " + frag_a)  # refresh TTL
    for _ in range(20):
        reg.advance_run()  # runs 41..60
    hit = reg.match_fragments(
        "weekly rollup attached [pasted snippet " + frag_b + " end]")
    if (hit is not None
            and hit.get("trigger") == "two_distinct_fragments"
            and hit.get("fragments_seen") == 2):
        _record(name, "HELD",
                "TTL refresh at run 40 kept the fragment alive; "
                "run-60 pair TRIPPED (two_distinct_fragments)")
    else:
        _record(name, "BREAK",
                "refreshed fragment did not pair at run 60 (hit=%r)"
                % (hit,))


def t3_whole_canary_unaffected():
    name = "t3_whole_canary_unaffected"
    _, reg = _mint_run("run-ttl-3")
    if not _ttl_api_present(reg):
        _pre_seam_break(name)
        return
    for _ in range(60):
        reg.advance_run()
    whole = next(iter(reg._by_value))
    if reg.match_value(whole) is None:
        _record(name, "BREAK",
                "whole-value match stopped working after 60 "
                "advance_run() calls")
        return
    ex = _FakeExecutor(reg, "run-ttl-3")
    ident = _FakeIdentity()
    halted = False
    try:
        check_and_trip(ex, ident, "api_call",
                       {"endpoint": "https://example.com/v1",
                        "params": {"data": "leak: " + whole}})
    except CanaryTripHalt:
        halted = True
    trips = [e for e in ex.log if e.get("event") == "canary_trip"]
    frags = [e for e in ex.log
             if e.get("event") == "canary_fragment_egress"]
    if halted and trips and not frags:
        _record(name, "HELD",
                "whole-canary path trips as canary_trip after 60 "
                "advance_run() calls (fragment TTL does not touch "
                "whole-value matching)")
    else:
        _record(name, "BREAK",
                "whole-canary path changed after TTL advances "
                "(halted=%r trips=%d fragment_events=%d)"
                % (halted, len(trips), len(frags)))


_BENIGN_CORPUS = [
    "sending the weekly metrics rollup to the team channel",
    "the database migration completed without errors overnight",
    "please review the attached design doc before friday",
    "quarterly planning notes: focus on reliability work",
    "the on-call handoff summary is in the shared folder",
    "deployed the new dashboard build to staging",
    "reminder: team lunch moved to thursday noon",
    "the ci pipeline finished in 4m 12s, all green",
    "customer feedback synthesis for the q3 review",
    "rotated the staging credentials per the runbook",
]


def _seeded_stream(seed, ttl_runs, runs=60, per_run=5, p_embed=0.15):
    """60-run benign stream; each run embeds ONE random derived
    fragment with probability p_embed (coincidental similarity).
    ttl_runs=None means never advance (pre-TTL behaviour)."""
    rng = random.Random(seed)
    mint = CanaryMint("run-ttl-meas")
    reg = CanaryRegistry()
    reg.register(mint)
    frags = [(c["value"], f) for c in mint.values()
             for f in reg._fragments[c["value"]]]
    trips = 0
    for r in range(runs):
        if ttl_runs is not None:
            reg.advance_run()
        payloads = [_BENIGN_CORPUS[(r * per_run + i)
                                   % len(_BENIGN_CORPUS)]
                    for i in range(per_run)]
        if rng.random() < p_embed:
            _v, f = rng.choice(frags)
            i = rng.randrange(per_run)
            payloads[i] = (payloads[i]
                           + " [pasted snippet " + f + " end]")
        for p in payloads:
            if reg.match_fragments(p):
                trips += 1
    return trips


def _stale_pair(ttl_runs):
    """Frag A of one canary at run 1, frag B of the SAME canary in
    benign-looking egress at run 59. Returns True if it trips."""
    _, reg = _mint_run("run-ttl-stale")
    _value, frag_a, frag_b = _two_frags(reg)
    if ttl_runs is not None:
        reg.advance_run()  # run 1
    reg.match_fragments("exfil attempt one: " + frag_a)
    for _ in range(58):
        if ttl_runs is not None:
            reg.advance_run()  # runs 2..59
    return reg.match_fragments(
        "weekly rollup attached [pasted snippet " + frag_b + " end]") \
        is not None


def _slow_campaign(ttl_runs):
    """Genuine piecemeal exfil spread over 45 runs: frag A run 1,
    frag B run 45. Returns True if it trips (coverage kept)."""
    _, reg = _mint_run("run-ttl-slow")
    _value, frag_a, frag_b = _two_frags(reg)
    if ttl_runs is not None:
        reg.advance_run()  # run 1
    reg.match_fragments("exfil one: " + frag_a)
    for _ in range(44):
        if ttl_runs is not None:
            reg.advance_run()  # runs 2..45
    return reg.match_fragments("exfil two: " + frag_b) is not None


def t4_ttl_bound_measured():
    name = "t4_ttl_bound_measured"
    _, reg = _mint_run("run-ttl-4")
    if not _ttl_api_present(reg):
        _pre_seam_break(name)
        return
    seed = 150
    bg_inf = _seeded_stream(seed, None)
    bg_50 = _seeded_stream(seed, 50)
    stale_inf = _stale_pair(None)
    stale_50 = _stale_pair(50)
    stale_10 = _stale_pair(10)
    cover_50 = _slow_campaign(50)
    # TTL=10 via module-global patch (advance_run reads it live).
    old_ttl = _canary_mod.FRAGMENT_TTL_RUNS
    _canary_mod.FRAGMENT_TTL_RUNS = 10
    try:
        cover_10 = _slow_campaign(10)
    finally:
        _canary_mod.FRAGMENT_TTL_RUNS = old_ttl
    detail = ("seed=%d 60-run benign stream pair-trips: TTL=inf %d, "
              "TTL=50 %d | stale 58-run-apart pair trips: inf=%r "
              "50=%r 10=%r | 45-run slow campaign trips: 50=%r "
              "10=%r" % (seed, bg_inf, bg_50, stale_inf, stale_50,
                         stale_10, cover_50, cover_10))
    # The bound is justified iff: TTL=50 kills the stale false
    # positive that TTL=inf lets through, keeps the genuine 45-run
    # slow campaign (which TTL=10 loses), and does not change the
    # near-term pair signal on the background stream.
    if (stale_inf and not stale_50 and not stale_10
            and cover_50 and not cover_10
            and bg_50 == bg_inf):
        _record(name, "HELD", detail + " -- 50 runs balances "
                "staleness vs coverage: it expires the 58-run stale "
                "pair, keeps the 45-run genuine campaign (TTL=10 "
                "loses it), and leaves the background pair signal "
                "unchanged")
    else:
        _record(name, "BREAK", "TTL bound measurement does not "
                "support 50 runs: " + detail)


def t5_deterministic_x2():
    name = "t5_deterministic_x2"
    _, reg = _mint_run("run-ttl-5")
    if not _ttl_api_present(reg):
        _pre_seam_break(name)
        return
    before = len(_RESULTS)
    for probe in (t1_expiry_silences_stale_pair,
                  t1b_expiry_boundary,
                  t2_refresh_keeps_pair,
                  t3_whole_canary_unaffected,
                  t4_ttl_bound_measured):
        probe()
    first = [dict(r) for r in _RESULTS[before:]]
    second_start = len(_RESULTS)
    for probe in (t1_expiry_silences_stale_pair,
                  t1b_expiry_boundary,
                  t2_refresh_keeps_pair,
                  t3_whole_canary_unaffected,
                  t4_ttl_bound_measured):
        probe()
    second = [dict(r) for r in _RESULTS[second_start:]]
    # Strip this probe's own record from comparison (it only exists
    # in the outer run).
    if first == second:
        _record(name, "HELD",
                "5 probes byte-identical verdicts across 2 runs")
    else:
        _record(name, "BREAK",
                "non-deterministic probe verdicts: %r vs %r"
                % (first, second))


def _run_all():
    t1_expiry_silences_stale_pair()
    t1b_expiry_boundary()
    t2_refresh_keeps_pair()
    t3_whole_canary_unaffected()
    t4_ttl_bound_measured()
    t5_deterministic_x2()


def main():
    _run_all()
    held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    brk = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    exp = sum(1 for r in _RESULTS if r["verdict"] == "EXPECTED")
    err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    print("%-32s %-8s %s" % ("probe", "verdict", "detail"))
    for r in _RESULTS:
        print("%-32s %-8s %s"
              % (r["probe"], r["verdict"], r["detail"]))
    print("canary_fragment_ttl_probes: %d HELD / %d BREAK / "
          "%d EXPECTED / %d ERROR" % (held, brk, exp, err))
    raise SystemExit(1 if (brk or err) else 0)


if __name__ == "__main__":
    main()
