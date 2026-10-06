"""Wave-335 per-tool rate-limit battery (F422 closure; filed as F421, renumbered at merge).

Base: 0fd4f736 (wave-334 merge). Footer at wave-335 merge: open F423 / next F424
(F422 filed as F421 then CLOSED here; renumbered at merge; F423 CLOSED 2026-10-05
wave-336 lane 1, footer now open F424, F425 / next F426). Pin: 2109 (+3 tool-rate-*).

P1  F422 red-first, now closed: the red script's burst -- 29 http_post
    executions inside 60s with no coded intervention on the base tree
    (/tmp/red_ratelimit.py) -- now refuses coded
    tool-rate-limit-exceeded at the 11th call (default 10/60s).
P2  Under-limit legitimate use passes: 10 http_posts execute.
P3  The refusal is finer than the F162 class trip: the run is NOT
    paused -- other tools keep executing after a per-tool refusal.
P4  Independent windows per tool: an http_post burst does not consume
    the read_file window (or the class-governed api_call); send_email
    has its own 5/60s limit.
P5  Limiter failure fails closed: a wire raising unexpectedly becomes
    a coded tool-rate-limiter-unavailable denial, never unlimited.
P6  Malformed deployment config fails closed: bad tool_rate_limits
    refuses at policy load; bad wire construction raises coded
    tool-rate-limit-config-invalid.
P7  Administrable without code changes: a policy tool_rate_limits
    section overrides a default (http_post 3/60s enforced).
P8  The window slides: with an injectable clock, calls older than the
    window stop counting.
P9  Approved-execution sweep is the second boundary: 11 queued +
    approved http_posts refuse coded on the sweep at the 11th.
P10 Pin 2106 + footer state (open none / next F430; F422 CLOSED);
    taxonomy sorted-unique on raw literals; the 3 new codes centrally
    registered.
P11 Green check (depth-1): honors GOV_SKIP_GREEN; otherwise runs the
    F162 velocity unit suite tests/test_velocity_f162.py as a child
    with GOV_SKIP_GREEN=1 (fresh TMPDIR).

gov/ changes in this lane: new gov/tool_rate_limit.py (+3 codes in
gov/decision_codes.py, pin 2100 -> 2103); policy tool_rate_limits:
section normalized fail-closed in gov/policy.py; executor
_check_tool_rate hooked at both F33 execution boundaries before
_charge_tempo. Findings: F422 (filed as F421) filed then CLOSED here.
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
FOOTER_OPEN = "F482, F483, F484, F485, F486, F487, F488"  # F422 (filed as F421) CLOSED 2026-10-05 wave-335 lane 2. F427 CLOSED (wave-340 lane 1); F428 OPEN (wave-341 lane C). F426 closed wave-338 lane 1.; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN


FOOTER_NEXT = "F489"  # Next free finding number.; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN



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
    d = os.path.join(tempfile.gettempdir(), "w335ratelimit")
    if not os.path.isdir(d):
        os.makedirs(d)
    return d


def _tmpd(prefix="w335ratelimit-"):
    return tempfile.mkdtemp(prefix=prefix, dir=_run_root())


from gov import tool_rate_limit as trl  # noqa: E402
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
{rate_section}policies:
{extra_rules}  - id: allow-worker-tools
    effect: allow
    match:
      tool: [http_post, api_call, read_file, send_email]
    reason: Battery allows worker tools.
"""

_QUEUE_HTTP = """\
  - id: queue-http-for-approval-boundary
    effect: require_approval
    match:
      tool: [http_post]
    reason: Battery queues http_post for approval.
"""


def _mkrun(rate_section="", extra_rules=""):
    d = _tmpd()
    p = os.path.join(d, "policy.yaml")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(_POLICY_TEMPLATE.format(rate_section=rate_section,
                                         extra_rules=extra_rules))
    run = make_run(policy_path=p)
    ident = run["mint_identity"]("w1", "worker", "acme")
    return run, run["executor"], ident


def _post(ex, ident, i):
    return ex.call(ident, "http_post",
                   url="https://synthetic.local/x%d" % i, body="b%d" % i)


def _expect_exceeded(pid, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except trl.ToolRateLimitExceeded as exc:
        if exc.code == "tool-rate-limit-exceeded":
            return _held(pid, "tool-rate-limit-exceeded as expected")
        return _break(pid, "want tool-rate-limit-exceeded, got %s"
                      % exc.code)
    return _break(pid, "want tool-rate-limit-exceeded, no refusal")


# ---------------------------------------------------------------------------
# P1 -- F422 red-first, now closed.
# ---------------------------------------------------------------------------

@probe("P1a-burst-refuses-coded-at-limit")
def _p1a():
    pid = "P1a-burst-refuses-coded-at-limit"
    run, ex, ident = _mkrun()
    for i in range(10):
        res = _post(ex, ident, i)
        if res["status"] != "executed":
            return _break(pid, "call %d not executed: %r" % (i, res))
    return _expect_exceeded(pid, _post, ex, ident, 10)


@probe("P1b-refusal-chained-on-log")
def _p1b():
    pid = "P1b-refusal-chained-on-log"
    run, ex, ident = _mkrun()
    for i in range(10):
        _post(ex, ident, i)
    try:
        _post(ex, ident, 10)
    except trl.ToolRateLimitExceeded:
        pass
    hits = [e for e in run["read_log"]()
            if e.get("flag") == "tool-rate-limit-exceeded"]
    if not hits:
        return _break(pid, "no chained tool-rate-limit-exceeded record")
    e = hits[-1]
    if e.get("decision") != "tool_call_refused" or e.get("tool") != "http_post":
        return _break(pid, "refusal record malformed: %r" % (e,))
    if e.get("rate_limit") != 10 or e.get("rate_windowed_count") != 11:
        return _break(pid, "refusal record counts wrong: %r" % (e,))
    return _held(pid, "chained tool_call_refused with limit 10 / count 11")


# ---------------------------------------------------------------------------
# P2 -- under-limit legitimate use passes.
# ---------------------------------------------------------------------------

@probe("P2a-under-limit-passes")
def _p2a():
    pid = "P2a-under-limit-passes"
    run, ex, ident = _mkrun()
    for i in range(10):
        res = _post(ex, ident, i)
        if res["status"] != "executed":
            return _break(pid, "under-limit call %d refused: %r" % (i, res))
    return _held(pid, "10/10 under-limit http_post executed")


# ---------------------------------------------------------------------------
# P3 -- refusal is finer than the F162 whole-run pause.
# ---------------------------------------------------------------------------

@probe("P3a-run-not-paused-by-tool-refusal")
def _p3a():
    pid = "P3a-run-not-paused-by-tool-refusal"
    run, ex, ident = _mkrun()
    for i in range(10):
        _post(ex, ident, i)
    try:
        _post(ex, ident, 10)
    except trl.ToolRateLimitExceeded:
        pass
    if ex._tempo_paused:
        return _break(pid, "per-tool refusal paused the run (F162-style)")
    res = ex.call(ident, "read_file", path="/tmp/x")
    if res["status"] != "executed":
        return _break(pid, "read_file refused after tool refusal: %r"
                      % (res,))
    return _held(pid, "run continues after per-tool refusal")


# ---------------------------------------------------------------------------
# P4 -- independent windows per tool.
# ---------------------------------------------------------------------------

@probe("P4a-windows-independent-across-tools")
def _p4a():
    pid = "P4a-windows-independent-across-tools"
    run, ex, ident = _mkrun()
    for i in range(10):
        _post(ex, ident, i)
    try:
        _post(ex, ident, 10)
    except trl.ToolRateLimitExceeded:
        pass
    # Two other tools have their own windows: the http_post burst must
    # not touch either (one limited, one class-governed).
    res = ex.call(ident, "api_call", endpoint="https://synthetic.local/y")
    if res["status"] != "executed":
        return _break(pid, "api_call affected by http_post burst: %r"
                      % (res,))
    res = ex.call(ident, "read_file", path="/tmp/independent")
    if res["status"] != "executed":
        return _break(pid, "read_file affected by http_post burst: %r"
                      % (res,))
    return _held(pid, "per-tool windows independent of http_post")


@probe("P4b-send-email-own-limit")
def _p4b():
    pid = "P4b-send-email-own-limit"
    run, ex, ident = _mkrun()
    for i in range(5):
        res = ex.call(ident, "send_email", to="a@synthetic.local",
                      subject="s%d" % i, body="b")
        if res["status"] != "executed":
            return _break(pid, "send_email %d refused early: %r" % (i, res))
    try:
        ex.call(ident, "send_email", to="a@synthetic.local",
                subject="s5", body="b")
    except trl.ToolRateLimitExceeded as exc:
        if exc.code == "tool-rate-limit-exceeded":
            return _held(pid, "send_email 5/60s limit enforced")
        return _break(pid, "wrong code %s" % exc.code)
    return _break(pid, "6th send_email executed (limit 5/60s)")


# ---------------------------------------------------------------------------
# P5 -- limiter failure fails closed.
# ---------------------------------------------------------------------------

@probe("P5a-limiter-failure-denies-coded")
def _p5a():
    pid = "P5a-limiter-failure-denies-coded"
    run, ex, ident = _mkrun()
    real_charge = ex._tool_rate_wire.charge

    def _boom(tool):
        raise RuntimeError("synthetic limiter explosion")
    ex._tool_rate_wire.charge = _boom
    try:
        try:
            _post(ex, ident, 0)
        except trl.ToolRateLimiterUnavailable as exc:
            if exc.code != "tool-rate-limiter-unavailable":
                return _break(pid, "wrong code %s" % exc.code)
        except trl.ToolRateLimitExceeded:
            return _break(pid, "limiter failure misreported as exceed")
        else:
            return _break(pid, "call executed despite limiter failure")
    finally:
        ex._tool_rate_wire.charge = real_charge
    # The limiter works again after the failure is repaired.
    res = _post(ex, ident, 1)
    if res["status"] != "executed":
        return _break(pid, "wire did not recover: %r" % (res,))
    return _held(pid, "limiter failure -> coded unavailable denial")


# ---------------------------------------------------------------------------
# P6 -- malformed config fails closed.
# ---------------------------------------------------------------------------

@probe("P6a-bad-policy-section-refused-at-load")
def _p6a():
    pid = "P6a-bad-policy-section-refused-at-load"
    d = _tmpd()
    p = os.path.join(d, "policy.yaml")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(_POLICY_TEMPLATE.format(
            rate_section="tool_rate_limits:\n  http_post: {window_secs: -5}\n",
            extra_rules=""))
    try:
        PolicyEngine(p)
    except ValueError:
        return _held(pid, "negative window refused at policy load")
    return _break(pid, "malformed tool_rate_limits loaded silently")


@probe("P6b-bad-wire-construction-coded")
def _p6b():
    pid = "P6b-bad-wire-construction-coded"
    try:
        trl.ToolRateWire({"http_post": (-1.0, 10)})
    except trl.ToolRateConfigError as exc:
        if exc.code == "tool-rate-limit-config-invalid":
            return _held(pid, "coded tool-rate-limit-config-invalid")
        return _break(pid, "wrong code %s" % exc.code)
    return _break(pid, "bad wire constructed silently")


@probe("P6c-normalize-section-coded")
def _p6c():
    pid = "P6c-normalize-section-coded"
    for bad in ({"http_post": {"window_secs": 60.0}},
                {"http_post": {"window_secs": 60.0, "max_calls": -1}},
                {"http_post": {"window_secs": 0, "max_calls": 5}},
                {"http_post": {"window_secs": 60.0, "max_calls": True}},
                {"": {"window_secs": 60.0, "max_calls": 5}},
                "not-a-mapping"):
        try:
            trl.normalize_section(bad)
        except trl.ToolRateConfigError as exc:
            if exc.code != "tool-rate-limit-config-invalid":
                return _break(pid, "wrong code for %r" % (bad,))
        else:
            return _break(pid, "accepted malformed %r" % (bad,))
    ok = trl.normalize_section(
        {"http_post": {"window_secs": 30, "max_calls": 7}})
    if ok != {"http_post": (30.0, 7)}:
        return _break(pid, "normalize mangled valid section: %r" % (ok,))
    if trl.normalize_section(None) != {}:
        return _break(pid, "None section did not normalize to {}")
    return _held(pid, "6 malformed shapes refused coded; valid kept")


# ---------------------------------------------------------------------------
# P7 -- administrable without code changes.
# ---------------------------------------------------------------------------

@probe("P7a-policy-override-enforced")
def _p7a():
    pid = "P7a-policy-override-enforced"
    run, ex, ident = _mkrun(
        rate_section="tool_rate_limits:\n"
                     "  http_post:\n"
                     "    window_secs: 60\n"
                     "    max_calls: 3\n")
    if ex._tool_rate_wire.limits["http_post"] != (60.0, 3):
        return _break(pid, "override not applied: %r"
                      % (ex._tool_rate_wire.limits.get("http_post"),))
    for i in range(3):
        res = _post(ex, ident, i)
        if res["status"] != "executed":
            return _break(pid, "call %d refused under override: %r"
                          % (i, res))
    return _expect_exceeded(pid, _post, ex, ident, 3)


@probe("P7b-defaults-apply-without-section")
def _p7b():
    pid = "P7b-defaults-apply-without-section"
    run, ex, ident = _mkrun()
    for tool in ("send_email", "http_post",
                 "write_file", "delete_file", "read_file"):
        if tool not in ex._tool_rate_wire.limits:
            return _break(pid, "no default limit for %s" % tool)
    return _held(pid, "built-in defaults enforced without policy section")


@probe("P7c-api-call-configurable-not-defaulted")
def _p7c():
    pid = "P7c-api-call-configurable-not-defaulted"
    run, ex, ident = _mkrun()
    if "api_call" in ex._tool_rate_wire.limits:
        return _break(pid, "api_call unexpectedly default-limited")
    # api_call bursts are governed by the egress class tripwire
    # instead (30/60s); the per-tool dial is opt-in per deployment.
    for i in range(5):
        res = ex.call(ident, "api_call",
                      endpoint="https://synthetic.local/y%d" % i)
        if res["status"] != "executed":
            return _break(pid, "default api_call refused: %r" % (res,))
    run2, ex2, ident2 = _mkrun(
        rate_section="tool_rate_limits:\n"
                     "  api_call:\n"
                     "    window_secs: 60\n"
                     "    max_calls: 2\n")
    for i in range(2):
        ex2.call(ident2, "api_call",
                 endpoint="https://synthetic.local/z%d" % i)
    return _expect_exceeded(pid, ex2.call, ident2, "api_call",
                            endpoint="https://synthetic.local/z2")


# ---------------------------------------------------------------------------
# P8 -- the window slides.
# ---------------------------------------------------------------------------

@probe("P8a-stale-hits-evict")
def _p8a():
    pid = "P8a-stale-hits-evict"
    now = [1000.0]
    wire = trl.ToolRateWire({"http_post": (60.0, 2)},
                            clock=lambda: now[0])
    wire.charge("http_post")
    wire.charge("http_post")
    try:
        wire.charge("http_post")
    except trl.ToolRateLimitExceeded:
        pass
    else:
        return _break(pid, "3rd call inside window not refused")
    now[0] += 61.0  # slide past the window
    if wire.windowed_count("http_post") != 0:
        return _break(pid, "stale hits not evicted")
    if wire.charge("http_post") != 1:
        return _break(pid, "post-window call not counted fresh")
    return _held(pid, "window slides; stale hits evicted")


# ---------------------------------------------------------------------------
# P9 -- approved-execution sweep is the second boundary.
# ---------------------------------------------------------------------------

@probe("P9a-sweep-charges-per-tool-wire")
def _p9a():
    pid = "P9a-sweep-charges-per-tool-wire"
    run, ex, ident = _mkrun(extra_rules=_QUEUE_HTTP)
    aids = []
    for i in range(11):
        q = _post(ex, ident, i)
        if q["status"] != "queued":
            return _break(pid, "call %d not queued: %r" % (i, q))
        aids.append(q["approval_id"])
    for aid in aids:
        run["approvals"].decide(aid, True, "battery approval",
                                decided_by="human-operator")
    try:
        ex.execute_approved()
    except trl.ToolRateLimitExceeded as exc:
        if exc.code != "tool-rate-limit-exceeded":
            return _break(pid, "wrong code on sweep: %s" % exc.code)
    else:
        return _break(pid, "sweep executed 11 approved http_posts")
    executed = [e for e in run["read_log"]()
                if e.get("decision") == "approved_executed"
                and e.get("tool") == "http_post"]
    if len(executed) != 10:
        return _break(pid, "want 10 approved_executed, got %d"
                      % len(executed))
    return _held(pid, "sweep refuses 11th approved http_post coded")


@probe("P9b-resume-forgives-per-tool-windows")
def _p9b():
    pid = "P9b-resume-forgives-per-tool-windows"
    d = _tmpd()
    p = os.path.join(d, "policy.yaml")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(_POLICY_TEMPLATE.format(
            rate_section="tool_rate_limits:\n"
                         "  http_post:\n"
                         "    window_secs: 60\n"
                         "    max_calls: 6\n"
                         "tempo:\n"
                         "  window_secs: 60\n"
                         "  max_read: 1000000\n"
                         "  max_write: 1000000\n"
                         "  max_egress: 5\n",
            extra_rules=""))
    run = make_run(policy_path=p)
    ident = run["mint_identity"]("w1", "worker", "acme")
    ex = run["executor"]
    for i in range(5):
        res = _post(ex, ident, i)
        if res["status"] != "executed":
            return _break(pid, "pre-trip call %d refused: %r" % (i, res))
    from gov import velocity as _velocity
    try:
        _post(ex, ident, 5)
    except _velocity.VelocityTempoTripError:
        pass
    else:
        return _break(pid, "6th http_post did not trip the class wire")
    aid = ex._tempo_resume_aid
    run["approvals"].decide(aid, True, "reviewed: legit batch",
                            decided_by="human-operator")
    ex.resume_after_velocity_pause(aid)
    # 5 more must execute: resume forgave the egress class AND the
    # per-tool windows (without the F422 reset, the per-tool wire
    # would refuse the very first post-resume call: pre-trip it
    # already holds 6 in-window hits, so count 7 > 6).
    for i in range(6, 11):
        res = _post(ex, ident, i)
        if res["status"] != "executed":
            return _break(pid, "post-resume call %d refused: %r" % (i, res))
    return _held(pid, "resume forgives tripped-class per-tool windows")


# ---------------------------------------------------------------------------
# P10 -- pin + footer.
# ---------------------------------------------------------------------------

@probe("P10-pin-2131-footer-f422")
def _p10():
    pid = "P10-pin-2131-footer-f422"
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    lits = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    n = len(dc.TAXONOMY)
    if n != TAXONOMY_PIN or len(lits) != TAXONOMY_PIN:
        return _break(pid, "taxonomy %d literals %d want %d"
                      % (n, len(lits), TAXONOMY_PIN))
    if lits != sorted(lits) or len(set(lits)) != len(lits):
        return _break(pid, "taxonomy not sorted/unique on raw literals")
    for c in ("tool-rate-limit-exceeded",
              "tool-rate-limiter-unavailable",
              "tool-rate-limit-config-invalid"):
        if c not in dc.TAXONOMY:
            return _break(pid, "code %r not centrally registered" % c)
    text = open(os.path.join(REPO, "evals", "FINDINGS.md")).read()
    # F422 CLOSED at merge (filed as F421 in this lane).
    f422 = text.split("## F422")[1]
    f422_body = re.split(r"\n## F\d+|\nNext free finding:", f422)[0]
    if "Status: CLOSED" not in f422_body:
        return _break(pid, "F422 not marked CLOSED in FINDINGS.md")
    ms = re.findall(r"Next free finding: \*\*(F\d+)\*\*\. "
                    r"\*\*Open findings: ([^*]+)\.\*\*", text)
    if not ms:
        return _break(pid, "footer line not found")
    next_free, open_now = ms[-1]  # the LAST footer is the live one
    if next_free != FOOTER_NEXT or open_now.strip() != FOOTER_OPEN:
        return _break(pid, "footer open %s / next %s, want open %s / next %s"
                      % (open_now.strip(), next_free, FOOTER_OPEN,
                         FOOTER_NEXT))
    return _held(pid, "taxonomy 2135/2135/0 sorted-unique; 3 codes "
                      "registered; F422 CLOSED; footer open F424, F425 / next F426")


# ---------------------------------------------------------------------------
# Green check (depth-1).
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # No expected BREAKs on the fixed tree.


def _run_child_output(path, timeout):
    d = _tmpd("w335ratelimit-green-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(
        [sys.executable, path],
        capture_output=True, text=True, timeout=timeout, env=env,
        cwd=REPO)
    return proc.stdout + proc.stderr


def _green_check():
    """Depth-1 green check: the F162 velocity unit suite as a child
    with GOV_SKIP_GREEN=1 (fresh TMPDIR). Honors GOV_SKIP_GREEN by
    recording a skip, never spawning.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    try:
        out = _run_child_output(
            os.path.join(REPO, "tests", "test_velocity_f162.py"),
            timeout=900)
    except Exception as exc:
        _record("green-check", "ERROR", "velocity_f162: %s" % exc)
        return
    breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
    errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
    # unittest-style failures surface as FAIL/ERROR lines instead.
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
                "velocity_f162 non-green: %s" % sorted(breaks | errors)[:4])
    else:
        _record("green-check", "HELD", "test_velocity_f162 green")


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
    print("w335_ratelimit battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the fixed tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
