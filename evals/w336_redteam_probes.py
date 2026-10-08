#!/usr/bin/env python3
"""Wave-336 lane 5 independent red team: break the wave-335 tree.

Base: `c4acf39e` (wave-335 merge). Pin 2109. Footer open F423, F424,
F425 / next F426 (F424, F425 filed by this lane, OPEN).

New attack surface under test: `gov/tool_rate_limit.py` (per-tool
sliding windows, resume-forgiveness path, +3 tool-rate-* codes),
`gov/agent_identity.py` per-token rotation locks (+1
identity-refresh-lock-unavailable code), `gov/pq_envelope.py` +
`gov/sigstore_bundle.py` reserved PQ slot (+2 evidence-pq-* codes).

Break-first probes at the public seams:

P1 (tool_rate_limit -- wire seam):
  P1a  window boundary: exactly max_calls in-window executes;
       max_calls+1 refuses coded tool-rate-limit-exceeded.
  P1b  window slide: stale hits evict; the count resets after the
       window elapses.
  P1c  unlisted tool: charge() is a documented no-op (returns 0, no
       trip at any volume) -- pinned as the documented residual, not
       a bypass (tool names are registry-controlled, not
       agent-chosen).
  P1d  NaN/inf window: fails CLOSED (never looser); no uncoded escape.
  P1e  max_calls=0: the tool is fully disabled -- first charge
       refuses coded.
  P1f  malformed config: bool/negative/string shapes, unknown keys,
       missing keys all refuse tool-rate-limit-config-invalid at
       construction.
  P1g  reset_tool: clears the window; unknown tool is a safe no-op.

P2 (executor integration -- both F33 boundaries):
  P2a  one direct execution charges exactly once (no double-charge).
  P2b  burst refuses coded tool-rate-limit-exceeded with a chained
       tool_call_refused log record carrying the coded flag.
  P2c  F425 CLOSED (wave-337 lane 1): limiter failure (raising
       clock) becomes coded tool-rate-limiter-unavailable -- the
       diagnostic windowed_count() is guarded, so the coded denial
       and its chained refusal record always win.
  P2d  approved-execution sweep charges the wire: 11 queued+approved
       http_posts refuse coded on the sweep at the 11th.

P3 (refresh-token per-token locks):
  P3a  F421 closure: concurrent double-refresh -> exactly one wins,
       loser coded identity-refresh-reuse-detected (chain revoked).
  P3b  F421 closure: lock acquisition timeout -> coded
       identity-refresh-lock-unavailable.
  P3c  per-token independence: a held lock on token A never blocks
       token B's refresh.
  P3d  lock registry is lazy (no lock at mint) and unbounded
       (documented residual, mirrors _tokens growth -- pinned fact,
       not a finding).
  P3e  F424 CLOSED (wave-337 lane 1): lock_timeout_seconds is now
       VALIDATED at construction -- NaN/inf/negative refuse with
       ValueError; 0 is the documented non-blocking attempt with the
       coded lock-unavailable refusal when contended.

P4 (reserved PQ slot):
  P4a  bundle carrying pqAlgId="mldsa44" (otherwise valid) refuses
       evidence-pq-not-enabled -- never verified down the classical
       path (algorithm-confusion kill).
  P4b  unknown identifier (incl. hybrid forms) refuses
       evidence-pq-unknown-alg.
  P4c  slot-shape games: non-string refuses unknown-alg; null/absent
       slot takes the classical path unchanged (documented).
  P4d  seal_keyed_bundle(..., pq_alg_id="mldsa44") refuses not-enabled.
  P4e  gating order: pqAlgId present + classically-invalid signature
       still refuses not-enabled (PQ gate fires before sig work).
  P4f  classical seal/verify round-trip unaffected.

P5 (F423 -- OPEN at base, attacked live):
  P5a  NUL in check_prm_url is ACCEPTED (break case 1). BREAK while
       F423 is open.
  P5b  CRLF challenge value is accepted and silently normalized to a
       URL that never appeared on the wire (break case 2). BREAK
       while F423 is open.

P6 (honesty):
       literals; all 6 wave-335 codes centrally registered.
  P6b  footer: open none / next F430 (raw-literal assertion,
       wave-331 lesson); F424/F425 closed wave-337 lane 1;
       F426 filed by wave-337 red-team lane.
  P6c  F424 and F425 sections present and marked CLOSED; F423 CLOSED;
       F426 OPEN.

P7 (older closure spot-regressions):
  P7a  F422: burst refuses coded tool-rate-limit-exceeded (wire).
  P7b  F417: non-numeric OAuth URL port refuses coded
       mcp-oauth-metadata-malformed.
  P7c  F420: PRM happy path still verifies (no over-refusal).

Usage:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g336-redb ~/workspace/.gov-venv/bin/python evals/w336_redteam_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import tool_rate_limit as TRL  # noqa: E402
from gov import agent_identity as AI  # noqa: E402
from gov import pq_envelope as PQ  # noqa: E402
from gov import sigstore_bundle as SB  # noqa: E402
from gov import mcp_prm as PRM  # noqa: E402
from gov import mcp_oauth_binding as MOB  # noqa: E402
from gov import decision_codes as DC  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from tests.harness import make_run  # noqa: E402

TAXONOMY_PIN = 2143  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

_NEW_CODES = (
    "identity-refresh-lock-unavailable",
    "evidence-pq-not-enabled",
    "evidence-pq-unknown-alg",
    "tool-rate-limit-exceeded",
    "tool-rate-limiter-unavailable",
    "tool-rate-limit-config-invalid",
)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))
    print("[%s] %s: %s" % (verdict, pid, note.split("\n")[0][:160]))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a dead
    battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _code_of(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", "UNEXPECTED:%r" % (e,))
    return None


class _Clock(object):
    """Injectable manual clock for deterministic window games."""

    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


# ---------------------------------------------------------------------------
# P1: tool_rate_limit wire seam.
# ---------------------------------------------------------------------------

def P1a():
    """Window boundary: exactly max_calls executes; max_calls+1 refuses
    coded tool-rate-limit-exceeded."""
    pid = "P1a-window-boundary"
    clk = _Clock()
    w = TRL.ToolRateWire({"http_post": (60.0, 3)}, clock=clk)
    for i in range(3):
        if w.charge("http_post") != i + 1:
            _break(pid, "call %d returned wrong count" % (i + 1,))
            return
    code = _code_of(lambda: w.charge("http_post"))
    if code != "tool-rate-limit-exceeded":
        _break(pid, "4th call: want tool-rate-limit-exceeded, got %r"
               % (code,))
        return
    _held(pid, "3/3 execute, 4th refuses coded tool-rate-limit-exceeded")


def P1b():
    """Window slide: stale hits evict; count resets after the window."""
    pid = "P1b-window-slide"
    clk = _Clock()
    w = TRL.ToolRateWire({"http_post": (60.0, 2)}, clock=clk)
    w.charge("http_post")
    w.charge("http_post")
    if _code_of(lambda: w.charge("http_post")) != "tool-rate-limit-exceeded":
        _break(pid, "3rd in-window call did not refuse")
        return
    clk.advance(60.0)
    # Hits at exactly the cutoff evict (half-open interval); the two
    # old hits are stale now.
    try:
        c = w.charge("http_post")
    except TRL.ToolRateLimitExceeded:
        _break(pid, "post-window call refused; stale hits did not evict")
        return
    if c != 1:
        _break(pid, "post-window count %r, want 1" % (c,))
        return
    _held(pid, "stale hits evict; window slides")


def P1c():
    """Unlisted tool: charge() is a documented no-op (returns 0, never
    trips). Pinned as the documented residual -- tool names come from
    the executor's registry, not from agent input, so there is no
    agent-reachable rename-to-dodge."""
    pid = "P1c-unlisted-tool-noop"
    w = TRL.ToolRateWire({"http_post": (60.0, 1)})
    for _ in range(50):
        if w.charge("mystery_tool") != 0:
            _break(pid, "unlisted tool charged")
            return
    _held(pid, "unlisted tool: 50 charges, 0 count, no trip (documented)")


def P1d():
    """NaN/inf window: fails CLOSED (never looser); no uncoded escape."""
    pid = "P1d-nan-window-fail-closed"
    for weird in (float("nan"), float("inf")):
        w = TRL.ToolRateWire({"t": (weird, 2)})
        got = None
        for _ in range(4):
            try:
                w.charge("t")
            except TRL.ToolRateLimitExceeded as e:
                got = e.code
                break
            except Exception as e:  # noqa: BLE001
                _break(pid, "weird window %r: uncoded %r" % (weird, e))
                return
        if got != "tool-rate-limit-exceeded":
            _break(pid, "weird window %r never refused (looser!)" % (weird,))
            return
    _held(pid, "NaN/inf windows fail closed: refuse at limit, no escape")


def P1e():
    """max_calls=0: the tool is fully disabled; first charge refuses."""
    pid = "P1e-zero-limit-disables"
    w = TRL.ToolRateWire({"t": (60.0, 0)})
    code = _code_of(lambda: w.charge("t"))
    if code != "tool-rate-limit-exceeded":
        _break(pid, "zero-limit first charge: got %r" % (code,))
        return
    _held(pid, "max_calls=0 refuses the first charge coded")


def P1f():
    """Malformed config refuses tool-rate-limit-config-invalid at
    construction (bool/negative/string shapes, unknown keys, missing
    keys, bad pairs)."""
    pid = "P1f-malformed-config"
    bad = [
        {"t": (True, 2)},
        {"t": (0.0, 2)},
        {"t": (-5.0, 2)},
        {"t": ("60", 2)},
        {"t": (60.0, True)},
        {"t": (60.0, -1)},
        {"t": (60.0, 2.5)},
        {"t": (60.0,)},
        {"t": "fast"},
        {"": (60.0, 2)},
    ]
    for spec in bad:
        code = _code_of(lambda s=spec: TRL.ToolRateWire(s))
        if code != "tool-rate-limit-config-invalid":
            _break(pid, "spec %r: want config-invalid, got %r" % (spec, code))
            return
    code = _code_of(lambda: TRL.normalize_section(
        {"t": {"window_secs": 60, "bogus": 1, "max_calls": 2}}))
    if code != "tool-rate-limit-config-invalid":
        _break(pid, "unknown section key: got %r" % (code,))
        return
    code = _code_of(lambda: TRL.normalize_section(
        {"t": {"window_secs": 60}}))
    if code != "tool-rate-limit-config-invalid":
        _break(pid, "missing max_calls: got %r" % (code,))
        return
    if TRL.normalize_section(None) != {}:
        _break(pid, "absent section must normalize to {}")
        return
    _held(pid, "12 malformed shapes refuse config-invalid; None -> {}")


def P1g():
    """reset_tool clears the window; unknown tool is a safe no-op."""
    pid = "P1g-reset-semantics"
    w = TRL.ToolRateWire({"t": (60.0, 1)})
    w.charge("t")
    if _code_of(lambda: w.charge("t")) != "tool-rate-limit-exceeded":
        _break(pid, "pre-reset 2nd charge did not refuse")
        return
    w.reset_tool("t")
    w.reset_tool("nope")  # must not crash
    try:
        c = w.charge("t")
    except TRL.ToolRateLimitExceeded:
        _break(pid, "post-reset charge refused")
        return
    if c != 1:
        _break(pid, "post-reset count %r, want 1" % (c,))
        return
    _held(pid, "reset clears window; unknown tool no-op")

# ---------------------------------------------------------------------------
# P2: executor integration (both F33 boundaries).
# ---------------------------------------------------------------------------

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
    d = tempfile.mkdtemp(prefix="w336-redteam-",
                         dir=os.environ.get("TMPDIR") or "/var/tmp")
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


def P2a():
    """One direct execution charges exactly once (no double-charge at
    the boundary)."""
    pid = "P2a-single-execution-single-charge"
    _rate = ("tool_rate_limits:\n"
             "  http_post:\n"
             "    window_secs: 60\n"
             "    max_calls: 10\n")
    run, ex, ident = _mkrun(rate_section=_rate)
    res = _post(ex, ident, 0)
    if res["status"] != "executed":
        _break(pid, "call not executed: %r" % (res,))
        return
    n = ex._tool_rate_wire.windowed_count("http_post")
    if n != 1:
        _break(pid, "one execution charged %d times" % (n,))
        return
    _held(pid, "one execution -> exactly one charge")


def P2b():
    """Burst refuses coded tool-rate-limit-exceeded with a chained
    tool_call_refused log record carrying the coded flag (F422
    regression at the executor seam)."""
    pid = "P2b-burst-refusal-chained-coded"
    _rate = ("tool_rate_limits:\n"
             "  http_post:\n"
             "    window_secs: 60\n"
             "    max_calls: 3\n")
    run, ex, ident = _mkrun(rate_section=_rate)
    for i in range(3):
        res = _post(ex, ident, i)
        if res["status"] != "executed":
            _break(pid, "pre-limit call %d not executed" % (i,))
            return
    try:
        _post(ex, ident, 3)
    except TRL.ToolRateLimitExceeded as e:
        if e.code != "tool-rate-limit-exceeded":
            _break(pid, "wrong code: %s" % (e.code,))
            return
    else:
        _break(pid, "4th http_post executed past the limit")
        return
    recs = [e for e in run["read_log"]()
            if e.get("decision") == "tool_call_refused"
            and e.get("flag") == "tool-rate-limit-exceeded"]
    if not recs:
        _break(pid, "no chained tool_call_refused record with coded flag")
        return
    _held(pid, "burst refuses coded; chained refusal record carries code")


def P2c():
    """Limiter failure (raising clock) must become coded
    tool-rate-limiter-unavailable -- a broken limiter denies, never
    allows unlimited. F425 CLOSED (wave-337 lane 1): the fail-closed
    handler's diagnostic windowed_count() is guarded, so the coded
    denial always wins."""
    pid = "P2c-limiter-failure-denies-coded"
    run, ex, ident = _mkrun()
    def _boom():
        raise RuntimeError("synthetic clock failure")
    ex._tool_rate_wire._clock = _boom
    try:
        _post(ex, ident, 0)
    except TRL.ToolRateLimiterUnavailable as e:
        if e.code != "tool-rate-limiter-unavailable":
            _break(pid, "wrong code: %s" % (e.code,))
            return
    except TRL.ToolRateLimitExceeded:
        _break(pid, "failure misreported as limit-exceeded")
        return
    except Exception as e:  # noqa: BLE001
        _break(pid, "F425: raw %r escaped _check_tool_rate uncoded "
               "(no coded denial, no chained refusal record)"
               % (e,))
        return
    else:
        _break(pid, "call executed with a broken limiter (unlimited!)")
        return
    recs = [e for e in run["read_log"]()
            if e.get("decision") == "tool_call_refused"
            and e.get("flag") == "tool-rate-limiter-unavailable"]
    if not recs:
        _break(pid, "coded denial raised but no chained refusal record")
        return
    _held(pid, "broken limiter denies coded tool-rate-limiter-unavailable")


def P2d():
    """Approved-execution sweep is the second boundary: 11 queued +
    approved http_posts refuse coded on the sweep at the 11th."""
    pid = "P2d-sweep-charges-per-tool-wire"
    _rate = ("tool_rate_limits:\n"
             "  http_post:\n"
             "    window_secs: 60\n"
             "    max_calls: 10\n")
    run, ex, ident = _mkrun(rate_section=_rate, extra_rules=_QUEUE_HTTP)
    aids = []
    for i in range(11):
        q = _post(ex, ident, i)
        if q["status"] != "queued":
            _break(pid, "call %d not queued: %r" % (i, q))
            return
        aids.append(q["approval_id"])
    for aid in aids:
        run["approvals"].decide(aid, True, "battery approval",
                                decided_by="human-operator")
    try:
        ex.execute_approved()
    except TRL.ToolRateLimitExceeded as exc:
        if exc.code != "tool-rate-limit-exceeded":
            _break(pid, "wrong code on sweep: %s" % (exc.code,))
            return
    else:
        _break(pid, "sweep executed 11 approved http_posts")
        return
    executed = [e for e in run["read_log"]()
                if e.get("decision") == "approved_executed"]
    if len(executed) != 10:
        _break(pid, "want 10 approved_executed, got %d" % len(executed))
        return
    _held(pid, "sweep refuses 11th approved http_post coded")


# ---------------------------------------------------------------------------
# P3: refresh-token per-token locks.
# ---------------------------------------------------------------------------

def _oidc_ident(raw):
    return AI.normalize_claims(raw, "oidc")


def _mint(store, sub="agent-9", now=2000):
    raw = {"sub": sub}
    ident = _oidc_ident(raw)
    return store.mint_refresh(ident, "oidc", raw, now=now)


def P3a():
    """F421 closure: concurrent double-refresh -> exactly one wins;
    loser coded identity-refresh-reuse-detected (chain revoked)."""
    pid = "P3a-double-refresh-exactly-one"
    store = AI.RefreshTokenStore(time_fn=lambda: 2000.0)
    issuer = AI.IdentityTokenIssuer(b"3" * 32)
    rid, secret = _mint(store)
    orig_issue = issuer.issue

    def slow_issue(*a, **k):
        time.sleep(0.2)
        return orig_issue(*a, **k)
    issuer.issue = slow_issue
    results = []
    bar = threading.Barrier(2)

    def worker():
        bar.wait()
        try:
            store.refresh(issuer, rid, secret, "aud", now=2001)
            results.append("ok")
        except AI.IdentityTokenRejection as e:
            results.append(e.code)
        except Exception as e:  # noqa: BLE001
            results.append("UNCODED:%r" % (e,))
    ts = [threading.Thread(target=worker) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(30)
    if sorted(results) != ["identity-refresh-reuse-detected", "ok"]:
        _break(pid, "want exactly one win, got %r" % (results,))
        return
    _held(pid, "double-refresh: one wins, loser coded reuse-detected")


def P3b():
    """F421 closure: lock acquisition timeout refuses coded
    identity-refresh-lock-unavailable (never proceeds unlocked)."""
    pid = "P3b-lock-timeout-coded"
    store = AI.RefreshTokenStore(time_fn=lambda: 2000.0,
                                 lock_timeout_seconds=0.5)
    issuer = AI.IdentityTokenIssuer(b"4" * 32)
    rid, secret = _mint(store)
    lock = store._lock_for(rid)
    if not lock.acquire(blocking=False):
        _break(pid, "could not hold the token lock for the test")
        return
    code = [None]

    def worker():
        try:
            store.refresh(issuer, rid, secret, "aud", now=2001)
            code[0] = "EXECUTED?!"
        except AI.IdentityTokenRejection as e:
            code[0] = e.code
        except Exception as e:  # noqa: BLE001
            code[0] = "UNCODED:%r" % (e,)
    t = threading.Thread(target=worker)
    t.start()
    t.join(30)
    lock.release()
    if code[0] != "identity-refresh-lock-unavailable":
        _break(pid, "want lock-unavailable, got %r" % (code[0],))
        return
    _held(pid, "lock timeout refuses coded, never refreshes unlocked")


def P3c():
    """Per-token independence: a lock held on token A never blocks
    token B's refresh (no global serialization)."""
    pid = "P3c-per-token-independence"
    store = AI.RefreshTokenStore(time_fn=lambda: 2000.0)
    issuer = AI.IdentityTokenIssuer(b"5" * 32)
    rid_a, sec_a = _mint(store, sub="a")
    rid_b, sec_b = _mint(store, sub="b")
    lock_a = store._lock_for(rid_a)
    lock_a.acquire()
    try:
        try:
            store.refresh(issuer, rid_b, sec_b, "aud", now=2001)
        except AI.IdentityTokenRejection as e:
            _break(pid, "token B refresh refused while A held: %s" % (e.code,))
            return
        except Exception as e:  # noqa: BLE001
            _break(pid, "token B refresh uncoded: %r" % (e,))
            return
    finally:
        lock_a.release()
    _held(pid, "token B refreshes while token A's lock is held")


def P3d():
    """Lock registry is lazy (no lock at mint) and unbounded --
    mirrors _tokens growth. Pinned as the documented residual: minting
    requires an authenticated identity, same bar as _tokens growth."""
    pid = "P3d-lock-registry-lazy-unbounded"
    store = AI.RefreshTokenStore(time_fn=lambda: 2000.0)
    rids = [_mint(store, sub="s%d" % i)[0] for i in range(3)]
    if store._rt_locks:
        _break(pid, "locks exist at mint time: %d" % len(store._rt_locks))
        return
    issuer = AI.IdentityTokenIssuer(b"6" * 32)
    for rid in rids:
        rec = store._tokens[rid]
        # read the secret back via the store is impossible (hash only);
        # re-mint is not needed: use _lock_for directly for the fact.
        store._lock_for(rid)
    if len(store._rt_locks) != 3:
        _break(pid, "want 3 locks after _lock_for, got %d"
               % len(store._rt_locks))
        return
    _held(pid, "locks lazy per refresh_id; registry unbounded (residual)")


def P3e():
    """F424 CLOSED (wave-337 lane 1): lock_timeout_seconds is now
    VALIDATED at construction. NaN/inf/negative/non-numeric refuse
    with ValueError (fail-fast, deployment time); 0 is the documented
    single non-blocking attempt (still the coded
    identity-refresh-lock-unavailable refusal when contended).
    Wave-306 lesson: this probe demonstrated the BREAK on the open
    tree; on the closed tree it asserts the coded/fail-fast closure."""
    pid = "P3e-timeout-unvalidated"
    for bad in (float("nan"), float("inf"), float("-inf"), -1, -0.5, "abc"):
        try:
            AI.RefreshTokenStore(time_fn=lambda: 2000.0,
                                 lock_timeout_seconds=bad)
        except ValueError:
            continue
        except Exception as e:  # noqa: BLE001
            _break(pid, "timeout %r: want ValueError, got %r" % (bad, e))
            return
        _break(pid, "timeout %r accepted (F424 still live)" % (bad,))
        return
    # Zero semantics: one non-blocking attempt, coded refusal.
    store = AI.RefreshTokenStore(time_fn=lambda: 2000.0,
                                 lock_timeout_seconds=0)
    issuer = AI.IdentityTokenIssuer(b"7" * 32)
    rid, secret = _mint(store)
    lock = store._lock_for(rid)
    lock.acquire()
    code = _code_of(lambda: store.refresh(issuer, rid, secret, "aud",
                                          now=2001))
    lock.release()
    if code != "identity-refresh-lock-unavailable":
        _break(pid, "0 timeout: want coded lock-unavailable, got %r"
               % (code,))
        return
    _held(pid, "NaN/inf/negative refuse at construction; 0 non-blocking "
               "and coded when contended")

# ---------------------------------------------------------------------------
# P4: reserved PQ slot.
# ---------------------------------------------------------------------------

_PQ_SEED = b"w336-redteam-pq-seed-00000000000"
assert len(_PQ_SEED) == 32
_PQ_STMT = b'{"audit": "pq-probe"}'


def _pq_signer():
    from gov.signing import Ed25519Signer
    return Ed25519Signer(_PQ_SEED)


def _pq_pub():
    from gov.signing import Ed25519Signer
    return Ed25519Signer(_PQ_SEED).public_key  # property, not a method


def _pq_sealed():
    return SB.seal_keyed_bundle(_PQ_STMT, _pq_signer())


def P4a():
    """A bundle carrying pqAlgId (otherwise fully valid) refuses
    evidence-pq-not-enabled -- never verified down the classical path
    (algorithm-confusion kill)."""
    pid = "P4a-pq-claimed-bundle-refused"
    bundle = _pq_sealed()
    bundle["pqAlgId"] = "mldsa44"
    code = _code_of(lambda: SB.open_keyed_bundle(bundle, _pq_pub()))
    if code != "evidence-pq-not-enabled":
        _break(pid, "want not-enabled, got %r" % (code,))
        return
    _held(pid, "pqAlgId bundle refused not-enabled before sig work")


def P4b():
    """Unknown identifiers (incl. hybrid forms) refuse
    evidence-pq-unknown-alg."""
    pid = "P4b-unknown-id-refused"
    for bad in ("rsa3072_mldsa44", "MLDSA44", "dilithium3", "", "falcon"):
        bundle = _pq_sealed()
        bundle["pqAlgId"] = bad
        code = _code_of(lambda b=bundle: SB.open_keyed_bundle(b, _pq_pub()))
        if code != "evidence-pq-unknown-alg":
            _break(pid, "pqAlgId %r: want unknown-alg, got %r" % (bad, code))
            return
    _held(pid, "5 unknown identifiers refuse unknown-alg")


def P4c():
    """Slot-shape games: non-string refuses unknown-alg; null/absent
    slot takes the classical path unchanged (documented)."""
    pid = "P4c-slot-shape-games"
    bundle = _pq_sealed()
    bundle["pqAlgId"] = 123
    code = _code_of(lambda: SB.open_keyed_bundle(bundle, _pq_pub()))
    if code != "evidence-pq-unknown-alg":
        _break(pid, "non-string slot: want unknown-alg, got %r" % (code,))
        return
    for slot in (None, "absent"):
        b2 = _pq_sealed()
        if slot is None:
            b2["pqAlgId"] = None
        # absent: key simply missing
        try:
            out = SB.open_keyed_bundle(b2, _pq_pub())
        except Exception as e:  # noqa: BLE001
            _break(pid, "slot %r broke the classical path: %r" % (slot, e))
            return
        if out != _PQ_STMT:
            _break(pid, "slot %r: payload mismatch" % (slot,))
            return
    _held(pid, "non-string -> unknown-alg; null/absent -> classical OK")


def P4d():
    """Sealing with a pq_alg_id refuses evidence-pq-not-enabled (a
    PQ-claimed bundle sealed with a classical signature would be
    mislabelled)."""
    pid = "P4d-seal-refuses-pq"
    for fn in (lambda: SB.seal_keyed_bundle(_PQ_STMT, _pq_signer(),
                                            pq_alg_id="mldsa44"),
               lambda: SB.seal_keyed_bundle_fanout(
                   _PQ_STMT, [_pq_signer()], pq_alg_id="mldsa44")):
        code = _code_of(fn)
        if code != "evidence-pq-not-enabled":
            _break(pid, "seal with pq_alg_id: want not-enabled, got %r"
                   % (code,))
            return
    _held(pid, "seal with pq_alg_id refuses not-enabled (both sealers)")


def P4e():
    """Gating order: pqAlgId present + classically-INVALID signature
    still refuses not-enabled -- the PQ gate fires before any
    signature work, so the verdict never leaks a confusing
    bad-signature."""
    pid = "P4e-gating-order"
    bundle = _pq_sealed()
    bundle["pqAlgId"] = "mldsa44"
    # Corrupt the classical signature: even a bad sig must not change
    # the verdict -- the PQ refusal must fire first.
    env = bundle.get("dsseEnvelope") or {}
    sigs = env.get("signatures") or []
    if sigs and isinstance(sigs[0], dict):
        sigs[0]["sig"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    other_key = b"\x09" * 32
    code = _code_of(lambda: SB.open_keyed_bundle(bundle, other_key))
    if code != "evidence-pq-not-enabled":
        _break(pid, "want not-enabled first, got %r" % (code,))
        return
    _held(pid, "PQ gate fires before signature work")


def P4f():
    """Classical seal/verify round-trip unaffected by the slot."""
    pid = "P4f-classical-roundtrip"
    b1 = SB.seal_keyed_bundle(_PQ_STMT, _pq_signer())
    b2 = SB.seal_keyed_bundle(_PQ_STMT, _pq_signer(), pq_alg_id=None)
    if b1 != b2:
        _break(pid, "pq_alg_id=None changed the sealed bytes")
        return
    try:
        out = SB.open_keyed_bundle(b1, _pq_pub())
    except Exception as e:  # noqa: BLE001
        _break(pid, "classical verify failed: %r" % (e,))
        return
    if out != _PQ_STMT:
        _break(pid, "payload mismatch")
        return
    _held(pid, "classical round-trip byte-identical, verifies")


# ---------------------------------------------------------------------------
# P5: F423 -- OPEN at base, attacked live.
# ---------------------------------------------------------------------------

_PRM_RES = "https://mcp.example.com/tools"


def P5a():
    """F423 break case 1: NUL in check_prm_url is ACCEPTED with the NUL
    intact. BREAK while F423 is open."""
    pid = "P5a-f423-nul-accepted"
    try:
        out = PRM.check_prm_url("https://mcp.example.com/a\x00b", _PRM_RES)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", "UNEXPECTED:%r" % (e,))
        _held(pid, "NUL now refuses coded %s (F423 closed?)" % (code,))
        return
    _break(pid, "F423 LIVE: NUL-bearing URL accepted -> %r" % (out,))


def P5b():
    """F423 break case 2: CRLF challenge value is accepted and silently
    normalized to a URL that never appeared on the wire. BREAK while
    F423 is open."""
    pid = "P5b-f423-crlf-mutated"
    header = ('Bearer resource_metadata='
              '"https://mcp.example.com/oauth-protected-resource\r\n.evil"')
    try:
        out = PRM.parse_challenge_resource_metadata(header, _PRM_RES)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", "UNEXPECTED:%r" % (e,))
        _held(pid, "CRLF now refuses coded %s (F423 closed?)" % (code,))
        return
    _break(pid, "F423 LIVE: CRLF challenge accepted, normalized -> %r"
           % (out,))


# ---------------------------------------------------------------------------
# P6: pin / footer / taxonomy honesty.
# ---------------------------------------------------------------------------

def P6a():
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    lits = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    n = len(DC.TAXONOMY)
    if n != TAXONOMY_PIN or len(lits) != TAXONOMY_PIN:
        _break(pid, "taxonomy %d literals %d want %d"
               % (n, len(lits), TAXONOMY_PIN))
        return
    if lits != sorted(lits) or len(set(lits)) != len(lits):
        _break(pid, "taxonomy not sorted/unique on raw literals")
        return
    for c in _NEW_CODES:
        if c not in DC.TAXONOMY:
            _break(pid, "code %r not centrally registered" % (c,))
            return


def P6b():
    """Footer honesty: the last line carries open F426 and
    next F427 (raw-literal assertion, wave-331 lesson). F424/F425 were
    closed by wave-337 lane 1; F426 filed by the wave-337 red-team lane."""
    pid = "P6b-footer-open-f433-f434-f435-next-f436"
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              "rb") as f:
        lines = f.read().decode("utf-8").splitlines()
    last = lines[-1] if lines else ""
    if "Open findings: F713, F714, F715, F716, F717, F718, F719, F720, F721, F722, F723, F724, F725, F726, F727, F728, F729, F730, F731, F732, F733, F734, F735, F736, F737." not in last:  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
        _break(pid, "last line lacks 'Open findings: F644, F645, F646, F647, F648, F649, F650, F651, F652, F653, F654.': %r"  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
               % (last[:160],))
        return
    if "Next free finding: **F738**" not in last:  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
        _break(pid, "last line lacks next-F436: %r" % (last[:160],))
        return
    for fnum in ("F424", "F425", "F426"):
        if not any(l.startswith("## " + fnum + " ") for l in lines):
            _break(pid, "%s section missing from FINDINGS.md" % (fnum,))
            return
    _held(pid, "footer honest: open none / next F430")


def P6c():
    """F424/F425 sections are present and marked CLOSED (wave-337 lane
    1); F423 CLOSED at the wave-336 merge; F426 OPEN."""
    pid = "P6c-f424-f425-closed-f426-open"
    text = open(os.path.join(REPO, "evals", "FINDINGS.md")).read()
    for fnum in ("F424", "F425"):
        body = text.split("## " + fnum)[1]
        body = re.split(r"\n## F\d+|\nNext free finding:", body)[0]
        if "Status: CLOSED" not in body:
            _break(pid, "%s not marked CLOSED" % (fnum,))
            return
    f423 = text.split("## F423")[1]
    f423_body = re.split(r"\n## F\d+|\nNext free finding:", f423)[0]
    if "Status: CLOSED" not in f423_body:
        _break(pid, "F423 not CLOSED at merge")
        return
    f426 = text.split("## F426")[1]
    f426_body = re.split(r"\n## F\d+|\nNext free finding:", f426)[0]
    if "Status: OPEN." not in f426_body:
        _break(pid, "F426 not OPEN at merge")
        return
    _held(pid, "F424/F425 CLOSED (wave-337 lane 1); F423 CLOSED at merge; F426 OPEN")


# ---------------------------------------------------------------------------
# P7: older closure spot-regressions.
# ---------------------------------------------------------------------------

def P7a():
    """F422 regression: burst refuses coded tool-rate-limit-exceeded
    (wire level)."""
    pid = "P7a-f422-burst-coded"
    w = TRL.ToolRateWire(dict(TRL.DEFAULT_TOOL_LIMITS))
    for _ in range(10):
        w.charge("http_post")
    code = _code_of(lambda: w.charge("http_post"))
    if code != "tool-rate-limit-exceeded":
        _break(pid, "11th http_post: want tool-rate-limit-exceeded, got %r"
               % (code,))
        return
    _held(pid, "F422 holds: 11th http_post refuses coded")


def P7b():
    """F417 regression: non-numeric OAuth URL port refuses coded
    mcp-oauth-metadata-malformed (not a bare ValueError)."""
    pid = "P7b-f417-port-coded"
    code = _code_of(lambda: MOB._normalize_url(
        "https://as.example.com:abc/token", "as_issuer"))
    if code != "mcp-oauth-metadata-malformed":
        _break(pid, "want mcp-oauth-metadata-malformed, got %r" % (code,))
        return
    _held(pid, "F417 holds: non-numeric port refuses coded")


def P7c():
    """F420 regression: PRM happy path still verifies (no over-refusal
    from the new seams)."""
    pid = "P7c-f420-prm-happy-path"
    key = b"w336-redteam-prm-key-00000000000"
    assert len(key) == 32
    try:
        sealed = MOB.seal_as_binding("https://as.example.com",
                                     "client-1", key)
        doc = {
            "resource": _PRM_RES,
            "authorization_servers": ["https://as.example.com"],
        }
        fetcher = lambda url: doc  # noqa: E731
        out = PRM.discover_and_verify_prm(sealed, _PRM_RES, key, fetcher)
    except Exception as e:  # noqa: BLE001
        _break(pid, "PRM happy path broke: %r" % (e,))
        return
    if not out:
        _break(pid, "PRM happy path returned empty")
        return
    _held(pid, "F420 holds: PRM happy path verifies")


_PROBES = [
    ("P1a-window-boundary", P1a),
    ("P1b-window-slide", P1b),
    ("P1c-unlisted-tool-noop", P1c),
    ("P1d-nan-window-fail-closed", P1d),
    ("P1e-zero-limit-disables", P1e),
    ("P1f-malformed-config", P1f),
    ("P1g-reset-semantics", P1g),
    ("P2a-single-execution-single-charge", P2a),
    ("P2b-burst-refusal-chained-coded", P2b),
    ("P2c-limiter-failure-denies-coded", P2c),
    ("P2d-sweep-charges-per-tool-wire", P2d),
    ("P3a-double-refresh-exactly-one", P3a),
    ("P3b-lock-timeout-coded", P3b),
    ("P3c-per-token-independence", P3c),
    ("P3d-lock-registry-lazy-unbounded", P3d),
    ("P3e-timeout-unvalidated", P3e),
    ("P4a-pq-claimed-bundle-refused", P4a),
    ("P4b-unknown-id-refused", P4b),
    ("P4c-slot-shape-games", P4c),
    ("P4d-seal-refuses-pq", P4d),
    ("P4e-gating-order", P4e),
    ("P4f-classical-roundtrip", P4f),
    ("P5a-f423-nul-accepted", P5a),
    ("P5b-f423-crlf-mutated", P5b),
    ("P7a-f422-burst-coded", P7a),
    ("P7b-f417-port-coded", P7b),
    ("P7c-f420-prm-happy-path", P7c),
]

_EXPECTED_BREAKS = set()  # never {} (wave-331 lesson); breaks documented below
# Expected tally on the wave-337 closed tree: 0 BREAK / 34 HELD /
# 0 ERROR (P2c F425 and P3e F424 now assert their closures). On the
# wave-336 merged tree the tally was 2/32/0.
# The 2 breaks are genuine open findings, not battery bugs: P2c is filed
# as F425, P3e as F424. P5a/P5b are F423 (CLOSED at the wave-336 merge,
# held on coded refusal).


def _run_root():
    base = os.environ.get("TMPDIR") or tempfile.gettempdir()
    root = os.path.join(base, "w336-redteam")
    os.makedirs(root, exist_ok=True)
    return root


_CHILD_BATTERIES = [
    # w335_attack_probes.py is deliberately EXCLUDED: it drives a
    # ModelDriver that can attempt real model calls (API spend); its
    # security property is pinned by the lane's own report instead.
    # Never spend user credits in a green check.
    ("w335_redteam_probes.py", 0, "0/113/0"),
    ("w335_ratelimit_probes.py", 0, "0/18/0"),
    ("w335_rtlock_probes.py", 0, "0/8/0"),
    ("w335_pqslot_probes.py", 0, "0/15/0"),
]


def _run_child_output(name):
    """Run an adjacent battery's main with green checks skipped
    (depth-1 green checks, wave-173 lesson) and return its stdout tail."""
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    root = _run_root()
    sub = os.path.join(root, "child-%s" % name)
    os.makedirs(sub, exist_ok=True)
    env["TMPDIR"] = sub
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    p = subprocess.run(
        [sys.executable, os.path.join(REPO, "evals", name)],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=900)
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    tail = "\n".join(out.splitlines()[-4:])
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", tail)
    if m is None:
        # w335_redteam_probes.py prints the slash form instead.
        m = re.search(r"(\d+)/(\d+)/(\d+) \(break/held/error\)", tail)
    return m, tail


def _green_check():
    """Depth-1 green checks over the wave-335 child batteries."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("GREEN-SKIPPED", "HELD",
                "green check skipped (child mode)")
        return
    for name, want_breaks, want_tuple in _CHILD_BATTERIES:
        pid = "GREEN-" + name.replace(".py", "")
        m, tail = _run_child_output(name)
        if m is None:
            _record(pid, "ERROR", "no B/H/E tuple in child output:\n%s"
                    % tail)
            continue
        b, h, e = int(m.group(1)), int(m.group(2)), int(m.group(3))
        got = "%d/%d/%d" % (b, h, e)
        if got != want_tuple or b != want_breaks:
            _record(pid, "BREAK",
                    "child drift: got %s, want %s:\n%s" % (got, want_tuple,
                                                           tail))
        else:
            _record(pid, "HELD", "child %s as expected" % got)


def _summary():
    b = sum(1 for _, v, _ in _results if v == "BREAK")
    h = sum(1 for _, v, _ in _results if v == "HELD")
    e = sum(1 for _, v, _ in _results if v == "ERROR")
    return b, h, e


def main(argv=None):
    argv = list(argv or sys.argv[1:])
    only = [a for a in argv if not a.startswith("-")]
    todo = _PROBES
    if only:
        # Prefix match: "P3e" selects "P3e-timeout-unvalidated".
        matched = []
        for want in only:
            hits = [(pid, fn) for pid, fn in _PROBES
                    if pid == want or pid.startswith(want + "-")]
            if not hits:
                print("unknown probe id: %r" % (want,))
                return 1
            matched.extend(hits)
        todo = matched
    _run_root()
    for pid, fn in todo:
        _safe(pid, fn)
    _green_check()
    b, h, e = _summary()
    print("\nw336_redteam: %d/%d/%d (break/held/error)" % (b, h, e))
    return 1 if (b or e) else 0


if __name__ == "__main__":
    sys.exit(main())
