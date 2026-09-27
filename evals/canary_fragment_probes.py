"""Wave-146 row 13: cumulative canary-fragment detection (break-first).

An attacker who exfiltrates a canary piecemeal -- one fragment per
egress -- defeats whole-value matching. The row-13 seam under test:
the registry derives overlapping fragments per planted canary and
tracks DISTINCT fragments of the same canary cumulatively across
egress attempts. It trips (LOUD ``canary_fragment_egress`` +
fail-closed ``CanaryTripHalt``) at the second distinct fragment at
the latest, or on a single fragment of at least half the canary.

RED-FIRST: run before the seam exists. Expected red:
  0 HELD / 9 BREAK / 0 EXPECTED / 0 ERROR
(the fragment scanner does not exist, so no fragment trip fires).

Probes (deterministic; mint is seeded by fixed run_id):
  c1_two_fragments_trip ......... two distinct 16-char fragments of
      the same canary across two egresses -> CanaryTripHalt +
      exactly one LOUD canary_fragment_egress on the SECOND egress
      (the first only accumulates, silently).
  c2_half_canary_trips_immediately .. one 20-char fragment of the
      40-char github token (>= half) -> immediate trip on egress 1.
  c3_cross_canary_no_accumulation .. one fragment each from TWO
      different canaries -> silent (no cross-canary accumulation).
  c4_whole_canary_existing_path ... whole canary value -> the
      EXISTING canary_trip path, and ZERO canary_fragment_egress
      events (no duplicate fragment event).
  c5_short_benign_fragment_silent  8-char benign substring of a
      canary ("AKIA"+4) in ordinary text -> silent.
  c6_single_fragment_below_half_silent .. one 16-char fragment of a
      40-char canary (< half, first distinct) -> silent.
  c7_same_fragment_twice_silent ... same 16-char fragment in two
      egresses -> silent (not distinct).
  c8_benign_corpus_no_fp ......... 40 benign egress payloads ->
      0 trips, 0 fragment events (measured false-positive rate).
  c9_deterministic_x2 ............. c1's sequence twice, fresh
      registries, same run_id -> byte-identical verdicts.

$0, stdlib-only, deterministic. Uses threshold-free direct calls
(no similarity pin here -- this is the canary seam, not the intent
seam, so the wave-145 record_intent lesson does not apply).
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov.canary import (CanaryMint, CanaryRegistry, CanaryTripHalt,
                        check_and_trip)

_RESULTS = []


def _record(name, verdict, note):
    _RESULTS.append((name, verdict, note))


class _FakeLog(list):
    def append(self, entry):
        super().append(dict(entry))


class _FakeApprovals(object):
    def __init__(self):
        self.queued = []

    def queue(self, action, decision, *a, **k):
        self.queued.append((action, decision, a, k))


class _FakePolicy(object):
    policy_hash = "test-policy-hash"


class _FakeExecutor(object):
    def __init__(self, registry, run_id="run-frag-1"):
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


def _mint_run(run_id="run-frag-1"):
    mint = CanaryMint(run_id)
    reg = CanaryRegistry()
    reg.register(mint)
    ex = _FakeExecutor(reg, run_id)
    ident = _FakeIdentity()
    return mint, reg, ex, ident


def _canary_by_label(reg, label):
    for meta in reg._by_value.values():
        if meta["label"] == label:
            return meta["value"]
    raise AssertionError("no canary labeled %r" % label)


def _fragment_events(ex):
    return [e for e in ex.log
            if e.get("event") == "canary_fragment_egress"]


def _trip_events(ex):
    return [e for e in ex.log if e.get("event") == "canary_trip"]


def _egress(ex, ident, text):
    """One egress attempt; returns (halted, fragment_events,
    trip_events) after the attempt."""
    halted = False
    try:
        check_and_trip(ex, ident, "api_call",
                       {"endpoint": "https://example.com/v1",
                        "params": {"data": text}})
    except CanaryTripHalt:
        halted = True
    return halted, _fragment_events(ex), _trip_events(ex)


def c1_two_fragments_trip():
    name = "c1_two_fragments_trip"
    _, reg, ex, ident = _mint_run()
    token = _canary_by_label(reg, "github-token")  # ghp_ + 36 = 40
    assert len(token) == 40, len(token)
    f1, f2 = token[0:16], token[20:36]  # distinct, non-overlapping
    h1, fe1, te1 = _egress(ex, ident, "exfil part one: " + f1)
    if h1 or fe1 or te1:
        _record(name, "BREAK",
                "first fragment should accumulate silently "
                "(halted=%r frag_events=%d trip_events=%d)"
                % (h1, len(fe1), len(te1)))
        return
    h2, fe2, te2 = _egress(ex, ident, "exfil part two: " + f2)
    if not h2:
        _record(name, "BREAK",
                "second distinct fragment did not trip "
                "(cumulative fragment detection absent)")
        return
    if len(fe2) != 1 or te2:
        _record(name, "BREAK",
                "expected exactly one canary_fragment_egress and no "
                "canary_trip (frag=%d trip=%d)"
                % (len(fe2), len(te2)))
        return
    ev = fe2[0]
    if ev.get("decision") != "halted" or ev.get("flag") \
            != "canary_fragment_egress":
        _record(name, "BREAK",
                "fragment event not LOUD/halted: %r" % (ev,))
        return
    _record(name, "HELD",
            "2nd distinct 16-char fragment tripped: LOUD "
            "canary_fragment_egress + CanaryTripHalt; 1st accumulated "
            "silently")


def c2_half_canary_trips_immediately():
    name = "c2_half_canary_trips_immediately"
    _, reg, ex, ident = _mint_run()
    token = _canary_by_label(reg, "github-token")
    half = token[:20]  # exactly half of the 40-char canary
    halted, fe, te = _egress(ex, ident, "single big chunk: " + half)
    if not halted or len(fe) != 1 or te:
        _record(name, "BREAK",
                "one fragment >= half the canary did not trip "
                "immediately (halted=%r frag=%d trip=%d)"
                % (halted, len(fe), len(te)))
        return
    _record(name, "HELD",
            "single 20-char fragment (>= half of 40-char canary) "
            "tripped on egress 1")


def c3_cross_canary_no_accumulation():
    name = "c3_cross_canary_no_accumulation"
    _, reg, ex, ident = _mint_run()
    tok_a = _canary_by_label(reg, "github-token")
    tok_b = _canary_by_label(reg, "slack-token")
    _egress(ex, ident, "piece a: " + tok_a[0:16])
    halted, fe, te = _egress(ex, ident, "piece b: " + tok_b[0:16])
    if halted or fe or te:
        _record(name, "BREAK",
                "fragments of DIFFERENT canaries accumulated "
                "together (halted=%r frag=%d trip=%d)"
                % (halted, len(fe), len(te)))
        return
    _record(name, "HELD",
            "one fragment each from two canaries stayed silent "
            "(no cross-canary accumulation)")


def c4_whole_canary_existing_path():
    name = "c4_whole_canary_existing_path"
    _, reg, ex, ident = _mint_run()
    token = _canary_by_label(reg, "github-token")
    halted, fe, te = _egress(ex, ident, "full exfil: " + token)
    if not halted:
        _record(name, "BREAK", "whole canary did not trip at all")
        return
    if len(te) != 1 or fe:
        _record(name, "BREAK",
                "whole canary must use the existing canary_trip path "
                "with no duplicate fragment event "
                "(trip=%d frag=%d)" % (len(te), len(fe)))
        return
    _record(name, "HELD",
            "whole canary stayed on canary_trip; zero "
            "canary_fragment_egress events")


def c5_short_benign_fragment_silent():
    name = "c5_short_benign_fragment_silent"
    _, reg, ex, ident = _mint_run()
    key = _canary_by_label(reg, "aws-key-0")  # AKIA + 16
    short = key[0:8]  # "AKIA" + 4 chars: fragment-like but short
    halted, fe, te = _egress(
        ex, ident,
        "our key prefix scheme %s is documented in the runbook" % short)
    if halted or fe or te:
        _record(name, "BREAK",
                "short benign fragment-like substring tripped "
                "(halted=%r frag=%d trip=%d)"
                % (halted, len(fe), len(te)))
        return
    _record(name, "HELD",
            "8-char benign fragment-like substring stayed silent")


def c6_single_fragment_below_half_silent():
    name = "c6_single_fragment_below_half_silent"
    _, reg, ex, ident = _mint_run()
    token = _canary_by_label(reg, "github-token")
    halted, fe, te = _egress(ex, ident, "one piece: " + token[4:20])
    if halted or fe or te:
        _record(name, "BREAK",
                "single 16-char fragment (< half, first distinct) "
                "tripped early (halted=%r frag=%d trip=%d)"
                % (halted, len(fe), len(te)))
        return
    _record(name, "HELD",
            "single 16-char fragment of 40-char canary accumulated "
            "silently (below both trip thresholds)")


def c7_same_fragment_twice_silent():
    name = "c7_same_fragment_twice_silent"
    _, reg, ex, ident = _mint_run()
    token = _canary_by_label(reg, "github-token")
    frag = token[8:24]
    _egress(ex, ident, "retry one: " + frag)
    halted, fe, te = _egress(ex, ident, "retry two: " + frag)
    if halted or fe or te:
        _record(name, "BREAK",
                "same fragment twice tripped (not distinct) "
                "(halted=%r frag=%d trip=%d)"
                % (halted, len(fe), len(te)))
        return
    _record(name, "HELD",
            "repeated identical fragment stayed silent "
            "(distinctness required)")


def c8_benign_corpus_no_fp():
    name = "c8_benign_corpus_no_fp"
    _, reg, ex, ident = _mint_run()
    corpus = [
        "sending the weekly metrics rollup to the team channel",
        "https://api.example.com/v2/reports?q=quarterly+summary",
        '{"status": "ok", "rows_processed": 1523, "took_ms": 41}',
        "the database migration completed without errors overnight",
        "please review the attached design doc before friday",
        "postgres://readonly@db-replica-02.internal:5432/opsdb",
        "api key rotation is scheduled for next tuesday",
        "AKIAIOSFODNN7EXAMPLE is the well-known documentation key",
        "ghp_example is not a real token prefix in this text",
        "the slack webhook posted 200 OK in 120ms",
        "Bearer realm=\"example\", charset=\"UTF-8\"",
        "xoxb-11" + "2" * 12 + "-" + "3" * 12 + "-" + "4" * 24,
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc is a stripe test key",
        "int_" + "ab12" * 10 + " looks tokenish but is synthetic",
        "db-primary-07.internal resolved in 3ms",
        "no canary material in this ordinary status update",
        "the quarterly report covers revenue, churn, and nps",
        "deploying build 4821 to staging-us-east now",
        "health check passed on all fourteen services",
        "latency p99 dropped from 840ms to 610ms after the fix",
        "the on-call rotation starts monday at 09:00",
        "backed up 4.2 GB to the nightly snapshot bucket",
        "feature flag checkout_redesign enabled for 5 percent",
        "the ci pipeline finished green in eleven minutes",
        "rotated the session signing secret per the runbook",
        "oauth callback returned code and state as expected",
        "the tls certificate renews automatically in 40 days",
        "paginated through 2300 audit rows without timeout",
        "the incident retro is scheduled for thursday",
        "added three indexes; query time fell by half",
        "the load balancer drained the old pool cleanly",
        "sdk version 2.14.1 pinned in the lockfile",
        "the webhook signature verified with the shared secret",
        "compacted the wal; disk usage back under 70 percent",
        "the cache hit ratio held at 96 percent all week",
        "dns propagation finished within the ttl window",
        "the dry run touched zero production rows",
        "signed the release bundle with the offline key",
        "the profiler points at json serialization overhead",
        "migrated the queue to the new region pair",
    ]
    trips = 0
    for text in corpus:
        halted, fe, te = _egress(ex, ident, text)
        if halted or fe or te:
            trips += 1
    if trips:
        _record(name, "BREAK",
                "%d/%d benign payloads tripped fragment detection"
                % (trips, len(corpus)))
        return
    _record(name, "HELD",
            "0/%d benign egress payloads tripped (measured FP 0.0)"
            % len(corpus))


def c9_deterministic_x2():
    name = "c9_deterministic_x2"
    verdicts = []
    for _ in range(2):
        _, reg, ex, ident = _mint_run()
        token = _canary_by_label(reg, "github-token")
        r1 = _egress(ex, ident, "p1: " + token[0:16])
        r2 = _egress(ex, ident, "p2: " + token[20:36])
        verdicts.append((r1[0], r2[0], len(r2[1]), len(r2[2])))
    if verdicts[0] != verdicts[1]:
        _record(name, "BREAK",
                "fragment verdicts differed across runs: %r" % verdicts)
        return
    if verdicts[0] != (False, True, 1, 0):
        _record(name, "BREAK",
                "unexpected verdict shape (want silent then "
                "fragment-trip): %r" % (verdicts[0],))
        return
    _record(name, "HELD",
            "c1 sequence byte-identical across 2 runs %r" % verdicts)


def _run_all():
    c1_two_fragments_trip()
    c2_half_canary_trips_immediately()
    c3_cross_canary_no_accumulation()
    c4_whole_canary_existing_path()
    c5_short_benign_fragment_silent()
    c6_single_fragment_below_half_silent()
    c7_same_fragment_twice_silent()
    c8_benign_corpus_no_fp()
    c9_deterministic_x2()


def _summary():
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    return "%d HELD / %d BREAK / %d EXPECTED / %d ERROR" % (
        held, brk, exp, err)


if __name__ == "__main__":
    print("canary_fragment_probes (wave-146, row 13):")
    try:
        _run_all()
    except Exception as exc:  # noqa: BLE001 -- battery must not die
        # on a probe bug; record and continue to the summary.
        _record("battery_harness", "ERROR", "%r" % (exc,))
    for name, verdict, note in _RESULTS:
        print("  %-34s %-10s %s" % (name, verdict, note))
    print("canary_fragment_probes: " + _summary())
