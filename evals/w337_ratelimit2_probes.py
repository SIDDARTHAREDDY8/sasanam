"""Wave-337 lane 5: rate-limit enhancements (R8 glob scoping + R12 per-tool budgets).

Base: 2f270987 (wave-336 merge). Footer: open F424, F425 / next F426
(no new findings in this lane). Pin: 2109 (+3 tool-budget-*).

R8 (AG2 TealTiger pattern adapted, Apache-2.0): tool_rate_limits:
keys may be exact tool names OR fnmatch glob families (``db.*``
bounds the whole family with one line). A tool matching several keys
charges every matching bucket -- exactly one timestamp per DISTINCT
bucket per call (the TealTiger double-count regression guard) -- and
the finest limit refuses first. No shadowing: an exact key never
exempts a tool from a family rule.

R12 (loopers-oss pattern adapted, MIT): the frequency axis bounds
velocity, not total volume (the wave-336 attack round-4 WATCH note:
an agent pacing http_post at exactly 10/60s accumulates unbounded
volume with no coded intervention). The new COST axis: policy
``tool_budgets:`` declares per-tool/family budgets in abstract cost
units; every execution charges its declared cost_per_call; exhaustion
refuses coded ``tool-budget-exhausted`` (atomic check-then-record: a
refused call records no spend). Strictly opt-in: absent section = no
budgets. Reset on F162 human-approved resume mirrors the rate wire.

P1  R8 red-first: a ``db.*`` (60,2) family rule bounds the family --
    the 3rd family-wide call refuses coded (the base tree treated
    the key as a literal name and charged nothing).
P2  TealTiger distinct-bucket regression: exact + glob matches record
    exactly one timestamp per bucket; the finer limit refuses first.
P3  No shadowing: an exact key cannot exempt a tool from its family.
P4  Policy end-to-end: a ``send_*`` family rule enforced at the
    executor call boundary.
P5  R12 red-first: the pacing attack is closed -- 30 paced http_posts
    pass (rate limit never fires), the 31st refuses coded
    tool-budget-exhausted.
P6  Budget atomicity: a refused call records no spend.
P7  cost_per_call: fractional costs accumulate correctly.
P8  Budget families: ``db.*`` budget shared across the family.
P9  Malformed budget config fails closed at load (coded) and at
    policy normalization (ValueError).
P10 Budget-wire failure fails closed: coded tool-budget-unavailable.
P11 Resume resets budgets: wire-level reset_tool zeroes spend;
    F162 human-approved resume resets the tripped class's budgets.
P12 The budget refusal is chained on the log (policy_id tool-budget).
P13 Ordering: the rate refusal fires before the budget refusal.
P14 Pin 2109 + footer state (open F424, F425 / next F426); taxonomy
    sorted-unique on raw literals; the 3 new codes centrally
    registered.
P15 Documented residuals: unlisted tools uncharged; absent
    tool_budgets section = no budgets, rate path unaffected.
P16 Green check (depth-1): honors GOV_SKIP_GREEN; otherwise runs
    evals/w335_ratelimit_probes.py as a child with GOV_SKIP_GREEN=1
    (fresh TMPDIR).

gov/ changes in this lane: gov/tool_rate_limit.py gains glob-family
scoping (is_pattern_key/matching_buckets shared helpers); new
gov/tool_budget.py (+3 tool-budget-* codes in gov/decision_codes.py,
pin 2106 -> 2124); policy tool_budgets: section normalized
fail-closed in gov/policy.py; executor _check_tool_budget hooked at
both F33 execution boundaries after _check_tool_rate, and the budget
wire reset on F162 resume alongside the rate wire.
"""

import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = "F469, F470, F471, F472"  # F426-F427 CLOSED (wave-340 lane 1); F428 OPEN (wave-341 lane C).; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)


FOOTER_NEXT = "F473"  # Next free finding number.; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)



_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    return (pid, "HELD", note)


def _break(pid, note):
    return (pid, "BREAK", note)


def probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _safe(pid, fn):
    try:
        _record(*fn())
    except Exception:
        _record(pid, "ERROR",
                traceback.format_exc(limit=2).replace("\n", " | ")[:500])


def _run_root():
    d = os.path.join(tempfile.gettempdir(), "w337ratelimit2")
    if not os.path.isdir(d):
        os.makedirs(d)
    return d


def _tmpd(prefix="w337rl2-"):
    return tempfile.mkdtemp(prefix=prefix, dir=_run_root())


from gov import tool_rate_limit as trl  # noqa: E402
from gov import tool_budget as tb  # noqa: E402
from gov import decision_codes as dc  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from tests.harness import make_run  # noqa: E402

_POLICY_TEMPLATE = """\
version: 2
roles:
  worker: [http_post, api_call, read_file, send_email]
rate_limit:
  max_sends_per_run: 10000
  max_egress_bytes_per_run: 104857600
egress:
  domain_allowlist: [synthetic.local, localhost]
tempo:
  window_secs: 60
  max_read: 300
  max_write: 60
  max_egress: 30
{rate_section}{budget_section}policies:
  - id: allow-worker-tools
    effect: allow
    match:
      tool: [http_post, api_call, read_file, send_email]
    reason: Battery allows worker tools.
"""


def _mkrun(rate_section="", budget_section=""):
    d = _tmpd()
    p = os.path.join(d, "policy.yaml")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(_POLICY_TEMPLATE.format(rate_section=rate_section,
                                         budget_section=budget_section))
    run = make_run(policy_path=p)
    ident = run["mint_identity"]("w1", "worker", "acme")
    return run, run["executor"], ident


def _post(ex, ident, i):
    return ex.call(ident, "http_post",
                   url="https://synthetic.local/x%d" % i, body="b%d" % i)


def _api(ex, ident, i):
    return ex.call(ident, "api_call",
                   endpoint="https://synthetic.local/x%d" % i)


def _expect_exceeded(pid, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except trl.ToolRateLimitExceeded as exc:
        if exc.code == "tool-rate-limit-exceeded":
            return _held(pid, "tool-rate-limit-exceeded as expected")
        return _break(pid, "want tool-rate-limit-exceeded, got %s"
                      % exc.code)
    return _break(pid, "want tool-rate-limit-exceeded, no refusal")


def _expect_exhausted(pid, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except tb.ToolBudgetExhausted as exc:
        if exc.code == "tool-budget-exhausted":
            return _held(pid, "tool-budget-exhausted as expected")
        return _break(pid, "want tool-budget-exhausted, got %s"
                      % exc.code)
    return _break(pid, "want tool-budget-exhausted, no refusal")


# ---------------------------------------------------------------------------
# P1 -- R8 red-first: glob families bound the family.
# ---------------------------------------------------------------------------

@probe("P1a-family-bucket-bounds-family")
def _p1a():
    pid = "P1a-family-bucket-bounds-family"
    now = [1000.0]
    wire = trl.ToolRateWire({"db.*": (60.0, 2)}, clock=lambda: now[0])
    wire.charge("db.query")
    wire.charge("db.execute")
    try:
        wire.charge("db.drop_table")  # 3rd family-wide hit
    except trl.ToolRateLimitExceeded as exc:
        if exc.code != "tool-rate-limit-exceeded":
            return _break(pid, "wrong code: %s" % exc.code)
        if "db.*" not in exc.detail:
            return _break(pid, "refusal does not name the bucket: %r"
                          % exc.detail)
        return _held(pid, "3rd family-wide call refused coded")
    return _break(pid, "3rd family-wide call not refused (base gap)")


@probe("P1b-base-gap-shape-now-refuses")
def _p1b():
    # The exact red-first shape: 10 calls per family member under a
    # (60,2) family rule -- the base tree charged nothing.
    pid = "P1b-base-gap-shape-now-refuses"
    now = [1000.0]
    wire = trl.ToolRateWire({"db.*": (60.0, 2)}, clock=lambda: now[0])
    refused = 0
    for tool in ("db.query", "db.execute", "db.drop_table"):
        for _ in range(10):
            try:
                wire.charge(tool)
            except trl.ToolRateLimitExceeded:
                refused += 1
    if refused == 0:
        return _break(pid, "30 family calls under (60,2): no refusal")
    return _held(pid, "%d family calls refused coded" % refused)


# ---------------------------------------------------------------------------
# P2 -- TealTiger distinct-bucket regression.
# ---------------------------------------------------------------------------

@probe("P2a-one-timestamp-per-distinct-bucket")
def _p2a():
    # Overlapping exact + glob matches must record exactly one
    # timestamp per DISTINCT bucket (the shipped TealTiger bug was two
    # policies sharing a key double-counting each call).
    pid = "P2a-one-timestamp-per-distinct-bucket"
    now = [1000.0]
    wire = trl.ToolRateWire({"send_email": (60.0, 5),
                             "send_*": (60.0, 50)},
                            clock=lambda: now[0])
    wire.charge("send_email")
    exact = len(wire._hits["send_email"])
    glob = len(wire._hits["send_*"])
    if (exact, glob) != (1, 1):
        return _break(pid, "double-count: exact=%d glob=%d, want 1/1"
                      % (exact, glob))
    wire.charge("send_email")
    if len(wire._hits["send_email"]) != 2 or \
            len(wire._hits["send_*"]) != 2:
        return _break(pid, "second call double-counted a bucket")
    return _held(pid, "one timestamp per distinct bucket per call")


@probe("P2b-finer-limit-refuses-first")
def _p2b():
    pid = "P2b-finer-limit-refuses-first"
    now = [1000.0]
    wire = trl.ToolRateWire({"send_email": (60.0, 5),
                             "send_*": (60.0, 50)},
                            clock=lambda: now[0])
    for _ in range(5):
        wire.charge("send_email")
    try:
        wire.charge("send_email")  # 6th: exact (5) trips, glob (50) fine
    except trl.ToolRateLimitExceeded as exc:
        if "'send_email'" not in exc.detail:
            return _break(pid, "refusal names wrong bucket: %r"
                          % exc.detail)
        return _held(pid, "finer (exact) refusal fired first")
    return _break(pid, "6th send_email not refused")


# ---------------------------------------------------------------------------
# P3 -- no shadowing: exact keys never exempt family rules.
# ---------------------------------------------------------------------------

@probe("P3-exact-key-cannot-exempt-family")
def _p3():
    pid = "P3-exact-key-cannot-exempt-family"
    now = [1000.0]
    wire = trl.ToolRateWire({"db.query": (60.0, 100),
                             "db.*": (60.0, 2)},
                            clock=lambda: now[0])
    wire.charge("db.query")
    wire.charge("db.execute")
    try:
        wire.charge("db.execute")  # 3rd family-wide hit
    except trl.ToolRateLimitExceeded:
        return _held(pid, "family bucket still bounds despite lax exact key")
    return _break(pid, "exact key shadowed the family rule (bypass)")


# ---------------------------------------------------------------------------
# P4 -- glob family enforced at the executor boundary.
# ---------------------------------------------------------------------------

@probe("P4-family-rule-at-executor-boundary")
def _p4():
    pid = "P4-family-rule-at-executor-boundary"
    rate = ("tool_rate_limits:\n"
            "  \"send_*\":\n"
            "    window_secs: 60\n"
            "    max_calls: 2\n")
    run, ex, ident = _mkrun(rate_section=rate)
    for i in range(2):
        res = ex.call(ident, "send_email", to="a%d@x.local" % i,
                      subject="s", body="b")
        if res["status"] != "executed":
            return _break(pid, "call %d not executed: %r" % (i, res))
    return _expect_exceeded(
        pid, ex.call, ident, "send_email",
        to="a@x.local", subject="s", body="b")


# ---------------------------------------------------------------------------
# P5 -- R12 red-first: the pacing attack is closed.
# ---------------------------------------------------------------------------

@probe("P5a-pacing-attack-now-refuses-coded")
def _p5a():
    # The base-tree gap: 600 http_posts paced at exactly 10/60s met
    # zero coded refusals. With a 30-unit budget (and the rate wire
    # quieted so only the budget can fire), the 31st refuses coded
    # even though the rate limit never fires.
    pid = "P5a-pacing-attack-now-refuses-coded"
    rate = ("tool_rate_limits:\n"
            "  http_post:\n"
            "    window_secs: 60\n"
            "    max_calls: 1000\n")
    budget = ("tool_budgets:\n"
              "  http_post:\n"
              "    budget: 30\n")
    run, ex, ident = _mkrun(rate_section=rate, budget_section=budget)
    for i in range(30):
        res = _post(ex, ident, i)
        if res["status"] != "executed":
            return _break(pid, "call %d not executed: %r" % (i, res))
    return _expect_exhausted(pid, _post, ex, ident, 30)


@probe("P5b-budget-wire-level-exhaustion")
def _p5b():
    pid = "P5b-budget-wire-level-exhaustion"
    wire = tb.ToolBudgetWire({"http_post": (30.0, 1.0)})
    for _ in range(30):
        wire.charge("http_post")
    try:
        wire.charge("http_post")
    except tb.ToolBudgetExhausted as exc:
        if exc.code != "tool-budget-exhausted":
            return _break(pid, "wrong code: %s" % exc.code)
        if "http_post" not in exc.detail or "30" not in exc.detail:
            return _break(pid, "refusal detail uninformative: %r"
                          % exc.detail)
        return _held(pid, "31st unit refused coded")
    return _break(pid, "31st unit not refused")


# ---------------------------------------------------------------------------
# P6 -- budget atomicity: a refused call records no spend.
# ---------------------------------------------------------------------------

@probe("P6-refused-call-records-no-spend")
def _p6():
    pid = "P6-refused-call-records-no-spend"
    wire = tb.ToolBudgetWire({"http_post": (5.0, 1.0),
                              "http_*": (100.0, 1.0)})
    for _ in range(5):
        wire.charge("http_post")
    try:
        wire.charge("http_post")  # exact bucket exhausted; glob fine
    except tb.ToolBudgetExhausted:
        pass
    else:
        return _break(pid, "6th unit not refused")
    state = wire.budget_state("http_post")
    if state["http_post"]["spent"] != 5.0:
        return _break(pid, "refused call recorded spend: %r"
                      % state["http_post"]["spent"])
    if state["http_*"]["spent"] != 5.0:
        return _break(pid, "atomicity broken across buckets: %r" % state)
    return _held(pid, "check-then-record: refused call spends nothing")


# ---------------------------------------------------------------------------
# P7 -- cost_per_call accumulates.
# ---------------------------------------------------------------------------

@probe("P7-cost-per-call-accumulates")
def _p7():
    pid = "P7-cost-per-call-accumulates"
    wire = tb.ToolBudgetWire({"snow_query": (1.0, 0.4)})
    wire.charge("snow_query")
    wire.charge("snow_query")  # 0.8 <= 1.0
    try:
        wire.charge("snow_query")  # 1.2 > 1.0
    except tb.ToolBudgetExhausted:
        spent = wire.budget_state("snow_query")["snow_query"]["spent"]
        if abs(spent - 0.8) > 1e-9:
            return _break(pid, "spent %r, want 0.8" % spent)
        return _held(pid, "fractional costs accumulate; 3rd refused")
    return _break(pid, "3rd fractional call not refused")


# ---------------------------------------------------------------------------
# P8 -- budget families share the bucket.
# ---------------------------------------------------------------------------

@probe("P8-budget-family-shared")
def _p8():
    pid = "P8-budget-family-shared"
    wire = tb.ToolBudgetWire({"db.*": (4.0, 2.0)})
    wire.charge("db.query")    # 2.0
    wire.charge("db.execute")  # 4.0
    try:
        wire.charge("db.drop_table")  # 6.0 > 4.0
    except tb.ToolBudgetExhausted as exc:
        if "db.*" not in exc.detail:
            return _break(pid, "refusal does not name bucket: %r"
                          % exc.detail)
        return _held(pid, "family budget shared; 3rd refuses coded")
    return _break(pid, "3rd family call not refused")


# ---------------------------------------------------------------------------
# P9 -- malformed budget config fails closed.
# ---------------------------------------------------------------------------

@probe("P9a-nan-budget-refused-coded")
def _p9a():
    pid = "P9a-nan-budget-refused-coded"
    try:
        tb.ToolBudgetWire({"x": (float("nan"), 1.0)})
    except tb.ToolBudgetConfigError as exc:
        if exc.code == "tool-budget-config-invalid":
            return _held(pid, "NaN budget refused coded")
        return _break(pid, "wrong code: %s" % exc.code)
    return _break(pid, "NaN budget accepted")


@probe("P9b-inf-cost-refused-coded")
def _p9b():
    pid = "P9b-inf-cost-refused-coded"
    try:
        tb.normalize_section({"x": {"budget": 5,
                                    "cost_per_call": float("inf")}})
    except tb.ToolBudgetConfigError as exc:
        if exc.code == "tool-budget-config-invalid":
            return _held(pid, "inf cost refused coded")
        return _break(pid, "wrong code: %s" % exc.code)
    return _break(pid, "inf cost accepted")


@probe("P9c-unknown-key-refused-coded")
def _p9c():
    pid = "P9c-unknown-key-refused-coded"
    try:
        tb.normalize_section({"x": {"budget": 5, "bogus": 1}})
    except tb.ToolBudgetConfigError as exc:
        if exc.code == "tool-budget-config-invalid":
            return _held(pid, "unknown key refused coded")
        return _break(pid, "wrong code: %s" % exc.code)
    return _break(pid, "unknown key accepted")


@probe("P9d-policy-level-malformed-refuses")
def _p9d():
    pid = "P9d-policy-level-malformed-refuses"

    def _policy_with(budgets_yaml):
        d = _tmpd()
        p = os.path.join(d, "policy.yaml")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(_POLICY_TEMPLATE.format(rate_section="",
                                             budget_section=budgets_yaml))
        return p

    try:
        PolicyEngine(_policy_with("tool_budgets:\n"
                                  "  x:\n"
                                  "    budget: -3\n"))
    except ValueError:
        pass
    else:
        return _break(pid, "negative budget accepted at policy load")
    try:
        PolicyEngine(_policy_with("tool_budgets:\n"
                                  "  - 1\n"
                                  "  - 2\n"))
    except ValueError:
        return _held(pid, "malformed tool_budgets refused at policy load")
    return _break(pid, "non-mapping tool_budgets accepted at policy load")


# ---------------------------------------------------------------------------
# P10 -- budget-wire failure fails closed.
# ---------------------------------------------------------------------------

@probe("P10-broken-budget-denies-coded")
def _p10():
    pid = "P10-broken-budget-denies-coded"

    class _BrokenWire(object):
        def charge(self, tool):
            raise RuntimeError("simulated wire failure")

    run, ex, ident = _mkrun()
    ex._tool_budget_wire = _BrokenWire()
    try:
        _post(ex, ident, 0)
    except tb.ToolBudgetUnavailable as exc:
        if exc.code != "tool-budget-unavailable":
            return _break(pid, "wrong code: %s" % exc.code)
    except Exception as exc:
        return _break(pid, "uncoded escape: %r" % exc)
    else:
        return _break(pid, "broken budget allowed the call")
    hits = [e for e in run["read_log"]()
            if e.get("flag") == "tool-budget-unavailable"]
    if not hits:
        return _break(pid, "no chained tool-budget-unavailable record")
    return _held(pid, "broken budget denies coded tool-budget-unavailable")


# ---------------------------------------------------------------------------
# P11 -- resume resets budgets.
# ---------------------------------------------------------------------------

@probe("P11a-wire-reset-zeroes-spend")
def _p11a():
    pid = "P11a-wire-reset-zeroes-spend"
    wire = tb.ToolBudgetWire({"http_post": (2.0, 1.0),
                              "http_*": (100.0, 1.0)})
    wire.charge("http_post")
    wire.charge("http_post")
    wire.reset_tool("http_post")
    state = wire.budget_state("http_post")
    if state["http_post"]["spent"] != 0.0:
        return _break(pid, "exact bucket not reset: %r" % state)
    if state["http_*"]["spent"] != 0.0:
        return _break(pid, "family bucket not reset: %r" % state)
    wire.charge("http_post")  # works again after reset
    return _held(pid, "reset_tool zeroes exact and family buckets")


@probe("P11b-executor-resume-resets-budget")
def _p11b():
    # Trip the F162 egress pause (31 api_calls), human-approve the
    # resume, and verify the tripped class's budget ledgers were
    # zeroed alongside the rate windows.
    pid = "P11b-executor-resume-resets-budget"
    budget = ("tool_budgets:\n"
              "  api_call:\n"
              "    budget: 100\n")
    run, ex, ident = _mkrun(budget_section=budget)
    import gov.velocity as _velocity
    for i in range(31):
        try:
            _api(ex, ident, i)
        except _velocity.VelocityTempoTripError:
            break
    if not ex._tempo_paused:
        return _break(pid, "tempo did not trip")
    spent_before = ex._tool_budget_wire._spent.get("api_call")
    if spent_before != 31.0:
        return _break(pid, "budget did not track executions: %r"
                      % spent_before)
    aid = ex._tempo_resume_aid
    run["approvals"].decide(aid, True, "reviewed: legit batch",
                            decided_by="human-operator")
    ex.resume_after_velocity_pause(aid)
    spent_after = ex._tool_budget_wire._spent.get("api_call")
    if spent_after != 0.0:
        return _break(pid, "resume did not reset budget: %r" % spent_after)
    res = _api(ex, ident, 1000)
    if res["status"] != "executed":
        return _break(pid, "post-resume call not executed: %r" % res)
    return _held(pid, "human-approved resume zeroes the tripped budget")


# ---------------------------------------------------------------------------
# P12 -- the budget refusal is chained on the log.
# ---------------------------------------------------------------------------

@probe("P12-budget-refusal-chained")
def _p12():
    pid = "P12-budget-refusal-chained"
    budget = ("tool_budgets:\n"
              "  http_post:\n"
              "    budget: 2\n")
    run, ex, ident = _mkrun(budget_section=budget)
    _post(ex, ident, 0)
    _post(ex, ident, 1)
    try:
        _post(ex, ident, 2)
    except tb.ToolBudgetExhausted:
        pass
    else:
        return _break(pid, "3rd unit not refused")
    hits = [e for e in run["read_log"]()
            if e.get("flag") == "tool-budget-exhausted"]
    if not hits:
        return _break(pid, "no chained tool-budget-exhausted record")
    e = hits[-1]
    if e.get("decision") != "tool_call_refused" or \
            e.get("policy_id") != "tool-budget" or \
            e.get("tool") != "http_post":
        return _break(pid, "refusal record malformed: %r" % (e,))
    if e.get("budget") != 2.0 or e.get("budget_spent") != 2.0:
        return _break(pid, "refusal record missing budget state: %r" % (e,))
    return _held(pid, "coded refusal chained with budget state")


# ---------------------------------------------------------------------------
# P13 -- ordering: rate refusal fires before budget refusal.
# ---------------------------------------------------------------------------

@probe("P13-rate-before-budget")
def _p13():
    pid = "P13-rate-before-budget"
    rate = ("tool_rate_limits:\n"
            "  http_post:\n"
            "    window_secs: 60\n"
            "    max_calls: 1\n")
    budget = ("tool_budgets:\n"
              "  http_post:\n"
              "    budget: 1\n")
    run, ex, ident = _mkrun(rate_section=rate, budget_section=budget)
    _post(ex, ident, 0)  # rate 1/1 ok; budget 1.0/1.0 ok
    try:
        _post(ex, ident, 1)  # both would trip
    except trl.ToolRateLimitExceeded as exc:
        if exc.code == "tool-rate-limit-exceeded":
            return _held(pid, "velocity refusal fires before spend refusal")
        return _break(pid, "wrong rate code: %s" % exc.code)
    except tb.ToolBudgetExhausted:
        return _break(pid, "budget fired before rate (ordering broken)")
    return _break(pid, "2nd call not refused at all")


# ---------------------------------------------------------------------------
# P14 -- pin + footer honesty.
# ---------------------------------------------------------------------------

@probe("P14a-pin-taxonomy-2135-sorted")
def _p14a():
    pid = "P14a-pin-taxonomy-2135-sorted"
    from gov.guac_graph import TAXONOMY_PIN as _pin
    if _pin != TAXONOMY_PIN:
        return _break(pid, "guac_graph pin %r != battery pin %r"
                      % (_pin, TAXONOMY_PIN))
    n = len(dc.TAXONOMY)
    if n != TAXONOMY_PIN:
        return _break(pid, "taxonomy %d != pin %d" % (n, TAXONOMY_PIN))
    codes = list(dc.TAXONOMY)
    if codes != sorted(codes) or len(set(codes)) != n:
        return _break(pid, "taxonomy not sorted/unique")
    # Raw-literal check (wave-260 lesson): count "code": literals.
    import gov.decision_codes as _dcsrc
    src = open(_dcsrc.__file__, encoding="utf-8").read()
    literals = re.findall(r"\"code\": '([^']+)'", src)
    if len(literals) != TAXONOMY_PIN or len(set(literals)) != TAXONOMY_PIN:
        return _break(pid, "raw literal count %d/%d != pin"
                      % (len(literals), len(set(literals))))
    return _held(pid, "2135/2135/0 sorted unique on raw source literals")


@probe("P14b-new-codes-centrally-registered")
def _p14b():
    pid = "P14b-new-codes-centrally-registered"
    for code in ("tool-budget-config-invalid", "tool-budget-exhausted",
                 "tool-budget-unavailable"):
        entry = dc.TAXONOMY.get(code)
        if entry is None:
            return _break(pid, "%s not in TAXONOMY" % code)
        if entry.get("domain") != "velocity":
            return _break(pid, "%s wrong domain: %r" % (code, entry))
        # code_for must resolve (the exception constructors rely on it).
        if dc.code_for(code)["code"] != code:
            return _break(pid, "code_for(%s) mismatch" % code)
    return _held(pid, "3 tool-budget-* codes centrally registered")


@probe("P14c-footer-state")
def _p14c():
    pid = "P14c-footer-state"
    # The footer is a prefix of one giant findings-history line, not
    # the file tail -- search the whole document.
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    if "Next free finding: **F473**" not in text:
        return _break(pid, "footer next != F427")
    if "Open findings: F469, F470, F471, F472F462, F463, F464, F465, F466, F467, F468." not in text:
        return _break(pid, "footer open != none")
    return _held(pid, "footer open none / next F430 (F426 closed)")


# ---------------------------------------------------------------------------
# P15 -- documented residuals.
# ---------------------------------------------------------------------------

@probe("P15a-unlisted-tool-uncharged")
def _p15a():
    pid = "P15a-unlisted-tool-uncharged"
    wire = tb.ToolBudgetWire({"http_post": (5.0, 1.0)})
    for _ in range(100):
        if wire.charge("api_call") != 0.0:
            return _break(pid, "unlisted tool charged")
    return _held(pid, "unlisted tools uncharged (documented residual)")


@probe("P15b-absent-section-no-budgets")
def _p15b():
    pid = "P15b-absent-section-no-budgets"
    run, ex, ident = _mkrun()  # no tool_budgets section
    if ex._tool_budget_wire.budgets:
        return _break(pid, "absent section created budgets")
    for i in range(10):
        res = _post(ex, ident, i)
        if res["status"] != "executed":
            return _break(pid, "call %d not executed: %r" % (i, res))
    # The rate path is unaffected: the 11th still refuses coded.
    return _expect_exceeded(pid, _post, ex, ident, 10)


# ---------------------------------------------------------------------------
# P16 -- green check (depth-1).
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # No expected BREAKs on the fixed tree.


def _run_child_output(path, timeout=900):
    d = _tmpd(prefix="w337rl2-green-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(
        [sys.executable, path], capture_output=True, text=True,
        timeout=timeout, env=env, cwd=REPO)
    return proc.stdout + proc.stderr


def _green_check():
    """Depth-1 green check: the wave-335 rate-limit battery as a child
    with GOV_SKIP_GREEN=1 (fresh TMPDIR). Honors GOV_SKIP_GREEN by
    recording a skip, never spawning.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    try:
        out = _run_child_output(
            os.path.join(REPO, "evals", "w335_ratelimit_probes.py"),
            timeout=900)
    except Exception as exc:
        _record("green-check", "ERROR", "w335_ratelimit: %s" % exc)
        return
    breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
    errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
    failed = ("FAILED" in out or "failures=" in out.lower())
    m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
    if m2:
        import ast as _ast
        try:
            breaks.update(_ast.literal_eval(m2.group(1)))
        except Exception:
            pass
    if breaks or errors or failed:
        _record("green-check", "BREAK",
                "w335_ratelimit non-green: %s" % sorted(breaks | errors)[:4])
    else:
        _record("green-check", "HELD", "w335_ratelimit green")


def main(argv):
    for pid, fn in _PROBES:
        _safe(pid, fn)
    _green_check()
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_breaks = {pid for pid, v, _ in _results
                    if v == "BREAK" and pid.startswith("P")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("w337_ratelimit2 battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the fixed tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
