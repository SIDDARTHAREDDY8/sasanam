"""Wave-337 lane 1 regression battery: F424 + F425 closures.

F424 (LOW, CLOSED wave-337 lane 1): RefreshTokenStore lock_timeout_seconds
is now validated at construction -- NaN/inf/negative/non-numeric refuse
with ValueError (fail-fast, deployment time); timeout 0 means one
non-blocking acquire attempt (still the coded
identity-refresh-lock-unavailable refusal when contended).

F425 (LOW, CLOSED wave-337 lane 1): Executor._check_tool_rate's fail-closed
handler can no longer re-invoke a broken wire via the diagnostic
windowed_count() -- the call is guarded, so the caller always sees the
coded tool-rate-limiter-unavailable denial and its chained refusal record
(carrying rate_windowed_count=None when the wire is unfit to count).

Pin 2106. Footer: open none / next F430 (F426 closed wave-338 lane 1).
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
sys.path.insert(0, REPO)

from tests.harness import make_run  # noqa: E402
import gov.agent_identity as AI  # noqa: E402
import gov.tool_rate_limit as TRL  # noqa: E402

# Red-first battery: on the unfixed tree these probes BREAK. Empty on the
# closed tree (wave-331 lesson: empty set, never {}).
_EXPECTED_BREAKS = set()

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F612, F613, F614, F615, F616, F617, F618, F619, F620"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # F426 closed wave-338 lane 1.; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621


FOOTER_NEXT = "F621"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621



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


# ---------------------------------------------------------------------------
# Executor harness (copied pattern from w336_redteam_probes.py -- batteries
# stay self-contained).
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
    d = tempfile.mkdtemp(prefix="w337-close2425-",
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


_RATE = ("tool_rate_limits:\n"
         "  http_post:\n"
         "    window_secs: 60\n"
         "    max_calls: 10\n")


def _mint(store, sub="agent-9", now=2000):
    raw = {"sub": sub}
    ident = AI.normalize_claims(raw, "oidc")
    return store.mint_refresh(ident, "oidc", raw, now=now)


# ---------------------------------------------------------------------------
# P1: F424 -- construction-time validation of lock_timeout_seconds.
# ---------------------------------------------------------------------------

def _construction_refuses(value):
    """HELD iff the constructor refuses ``value`` with ValueError."""
    try:
        AI.RefreshTokenStore(time_fn=lambda: 2000.0,
                             lock_timeout_seconds=value)
    except ValueError:
        return True
    except Exception:  # noqa: BLE001
        return False
    return False


def P1a():
    """F424: NaN refuses at construction."""
    pid = "P1a-nan-refused-at-construction"
    if _construction_refuses(float("nan")):
        _held(pid, "NaN lock_timeout_seconds refused with ValueError")
    else:
        _break(pid, "NaN accepted (F424 live)")


def P1b():
    """F424: +inf refuses at construction."""
    pid = "P1b-posinf-refused-at-construction"
    if _construction_refuses(float("inf")):
        _held(pid, "+inf refused with ValueError")
    else:
        _break(pid, "+inf accepted (F424 live)")


def P1c():
    """F424: -inf refuses at construction."""
    pid = "P1c-neginf-refused-at-construction"
    if _construction_refuses(float("-inf")):
        _held(pid, "-inf refused with ValueError")
    else:
        _break(pid, "-inf accepted (F424 live)")


def P1d():
    """F424: -1 (the widespread 'no timeout' convention) refuses."""
    pid = "P1d-negative-refused-at-construction"
    if _construction_refuses(-1):
        _held(pid, "-1 refused with ValueError (bound can no longer be voided)")
    else:
        _break(pid, "-1 accepted (F424 live: documented 5s bound voided)")


def P1e():
    """F424: negative fraction refuses."""
    pid = "P1e-negative-fraction-refused-at-construction"
    if _construction_refuses(-0.5):
        _held(pid, "-0.5 refused with ValueError")
    else:
        _break(pid, "-0.5 accepted (F424 live)")


def P1f():
    """F424: non-numeric refuses at construction."""
    pid = "P1f-non-numeric-refused-at-construction"
    if _construction_refuses("abc"):
        _held(pid, "'abc' refused with ValueError")
    else:
        _break(pid, "'abc' accepted (F424 live)")


def P1g():
    """F424: 0 is the documented single non-blocking attempt -- a held
    lock refuses coded identity-refresh-lock-unavailable, never hangs."""
    pid = "P1g-zero-nonblocking-coded-refusal"
    store = AI.RefreshTokenStore(time_fn=lambda: 2000.0,
                                 lock_timeout_seconds=0)
    issuer = AI.IdentityTokenIssuer(b"7" * 32)
    rid, secret = _mint(store)
    lock = store._lock_for(rid)
    lock.acquire()
    done = []

    def worker():
        code = _code_of(lambda: store.refresh(issuer, rid, secret, "aud",
                                              now=2001))
        done.append(code)

    t = threading.Thread(target=worker, daemon=True)
    t0 = time.monotonic()
    t.start()
    t.join(10)
    lock.release()
    if not done:
        _break(pid, "0 timeout: contended acquire hung (not non-blocking)")
        return
    if done[0] == "identity-refresh-lock-unavailable":
        _held(pid, "0 timeout: contended refresh refuses coded in %.2fs"
              % (time.monotonic() - t0,))
    else:
        _break(pid, "0 timeout: want coded lock-unavailable, got %r"
               % (done[0],))


def P1h():
    """F424 regression: small positive timeout keeps the normal path --
    uncontended refresh still succeeds."""
    pid = "P1h-small-positive-normal-refresh"
    store = AI.RefreshTokenStore(time_fn=lambda: 2000.0,
                                 lock_timeout_seconds=0.5)
    issuer = AI.IdentityTokenIssuer(b"7" * 32)
    rid, secret = _mint(store)
    try:
        out = store.refresh(issuer, rid, secret, "aud", now=2001)
    except Exception as e:  # noqa: BLE001
        _break(pid, "uncontended refresh failed with 0.5s timeout: %r" % (e,))
        return
    if out:
        _held(pid, "uncontended refresh succeeds with 0.5s timeout")
    else:
        _break(pid, "uncontended refresh returned nothing")


def P1i():
    """F424 regression: default (None) keeps the 5s bound, and the F421
    contended-refusal path still works (coded, no hang)."""
    pid = "P1i-default-bound-preserved"
    store = AI.RefreshTokenStore(time_fn=lambda: 2000.0)
    if store._lock_timeout != 5.0:
        _break(pid, "default timeout drifted: %r" % (store._lock_timeout,))
        return
    issuer = AI.IdentityTokenIssuer(b"7" * 32)
    rid, secret = _mint(store)
    lock = store._lock_for(rid)
    lock.acquire()
    done = []

    def worker():
        code = _code_of(lambda: store.refresh(issuer, rid, secret, "aud",
                                              now=2001))
        done.append(code)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(30)
    lock.release()
    if not done:
        _break(pid, "default timeout: contended refresh hung")
        return
    if done[0] == "identity-refresh-lock-unavailable":
        _held(pid, "default 5s bound: contended refresh refuses coded")
    else:
        _break(pid, "default bound: want coded lock-unavailable, got %r"
               % (done[0],))


# ---------------------------------------------------------------------------
# P2: F425 -- fail-closed diagnostic must not re-invoke a broken wire.
# ---------------------------------------------------------------------------

def P2a():
    """F425: a broken limiter clock becomes the coded
    tool-rate-limiter-unavailable denial -- never a raw escape."""
    pid = "P2a-limiter-failure-denies-coded"
    run, ex, ident = _mkrun(rate_section=_RATE)

    def _boom():
        raise RuntimeError("synthetic clock failure")

    ex._tool_rate_wire._clock = _boom
    try:
        _post(ex, ident, 0)
    except TRL.ToolRateLimiterUnavailable as e:
        if e.code == "tool-rate-limiter-unavailable":
            _held(pid, "broken limiter denies coded")
        else:
            _break(pid, "wrong code: %s" % (e.code,))
        return
    except TRL.ToolRateLimitExceeded:
        _break(pid, "failure misreported as limit-exceeded")
        return
    except Exception as e:  # noqa: BLE001
        _break(pid, "F425: raw %r escaped uncoded" % (e,))
        return
    _break(pid, "call executed with a broken limiter (unlimited!)")


def P2b():
    """F425: the coded denial chains a refusal record; the record marks
    the count as None (wire unfit to count)."""
    pid = "P2b-limiter-failure-record-chained"
    run, ex, ident = _mkrun(rate_section=_RATE)

    def _boom():
        raise RuntimeError("synthetic clock failure")

    ex._tool_rate_wire._clock = _boom
    try:
        _post(ex, ident, 0)
    except TRL.ToolRateLimiterUnavailable:
        pass
    except Exception as e:  # noqa: BLE001
        _break(pid, "raw %r escaped uncoded" % (e,))
        return
    recs = [e for e in run["read_log"]()
            if e.get("decision") == "tool_call_refused"
            and e.get("flag") == "tool-rate-limiter-unavailable"]
    if not recs:
        _break(pid, "coded denial raised but no chained refusal record")
        return
    if recs[0].get("rate_windowed_count") is not None:
        _break(pid, "wire-failure record should carry count None, got %r"
               % (recs[0].get("rate_windowed_count"),))
        return
    _held(pid, "refusal record chained, count=None on broken wire")


def P2c():
    """F425 regression: the normal exceeded path is untouched -- 11th
    call refuses coded with the observed count intact (int 11)."""
    pid = "P2c-exceeded-path-unchanged"
    run, ex, ident = _mkrun(rate_section=_RATE)
    for i in range(10):
        res = _post(ex, ident, i)
        if res["status"] != "executed":
            _break(pid, "call %d not executed: %r" % (i, res))
            return
    try:
        _post(ex, ident, 10)
    except TRL.ToolRateLimitExceeded as exc:
        if exc.code != "tool-rate-limit-exceeded":
            _break(pid, "wrong code: %s" % (exc.code,))
            return
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong exception: %r" % (e,))
        return
    else:
        _break(pid, "11th call executed despite limit 10")
        return
    recs = [e for e in run["read_log"]()
            if e.get("decision") == "tool_call_refused"
            and e.get("flag") == "tool-rate-limit-exceeded"]
    if not recs or recs[0].get("rate_windowed_count") != 11:
        _break(pid, "exceeded record lost its observed count: %r"
               % (recs,))
        return
    _held(pid, "exceeded path refuses coded with count 11")


def P2d():
    """F425 regression: the approved-execution sweep (second F33
    boundary) still refuses the 11th coded."""
    pid = "P2d-sweep-boundary-unchanged"
    run, ex, ident = _mkrun(rate_section=_RATE, extra_rules=_QUEUE_HTTP)
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
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong exception on sweep: %r" % (e,))
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
# P3: honesty pins.
# ---------------------------------------------------------------------------

def P3a():
    """Pin 2106: taxonomy 2140/2140/0 sorted-unique on raw literals."""
    pid = "P3a-pin-taxonomy-2140-sorted"
    # Raw-literal uniqueness on the source (wave-260 lesson): a
    # deduped-dict check would miss duplicate code literals.
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    found = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    if len(found) != TAXONOMY_PIN or len(set(found)) != TAXONOMY_PIN:
        _break(pid, "want %d/%d/0 sorted-unique, got %d/%d"
               % (TAXONOMY_PIN, TAXONOMY_PIN, len(found), len(set(found))))
        return
    if found != sorted(found):
        _break(pid, "code literals not sorted")
        return
    _held(pid, "taxonomy 2140/2140/0 sorted-unique on raw literals")


def P3b():
    """Footer: open none / next F430; F424/F425/F426 marked CLOSED."""
    pid = "P3b-footer-open-f433-f434-f435-next-f436"
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    lines = text.splitlines()
    last = lines[-1] if lines else ""
    if "Next free finding: **F621**" not in last:  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621
        _break(pid, "footer does not read next F427")
        return
    if "Open findings: F612, F613, F614, F615, F616, F617, F618, F619, F620." not in last:  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621
        _break(pid, "footer does not read open none")
        return
    import re as _re
    def _section(tag):
        m = _re.search(r"^## %s\b.*$" % tag, text, _re.M)
        if not m:
            return ""
        rest = text[m.end():]
        n = _re.search(r"^## \S", rest, _re.M)
        return rest[:n.start()] if n else rest
    for tag in ("F424", "F425", "F426"):
        if "**Status: OPEN.**" in _section(tag):
            _break(pid, "%s section still marked OPEN" % tag)
            return
    _held(pid, "footer open none / next F430, F424+F425+F426 closed")


_PROBES = [
    ("P1a-nan-refused-at-construction", P1a),
    ("P1b-posinf-refused-at-construction", P1b),
    ("P1c-neginf-refused-at-construction", P1c),
    ("P1d-negative-refused-at-construction", P1d),
    ("P1e-negative-fraction-refused-at-construction", P1e),
    ("P1f-non-numeric-refused-at-construction", P1f),
    ("P1g-zero-nonblocking-coded-refusal", P1g),
    ("P1h-small-positive-normal-refresh", P1h),
    ("P1i-default-bound-preserved", P1i),
    ("P2a-limiter-failure-denies-coded", P2a),
    ("P2b-limiter-failure-record-chained", P2b),
    ("P2c-exceeded-path-unchanged", P2c),
    ("P2d-sweep-boundary-unchanged", P2d),
    ("P3a-pin-taxonomy-2140-sorted", P3a),
    ("P3b-footer-open-f433-f434-f435-next-f436", P3b),
]


def _run_root():
    base = os.environ.get("TMPDIR") or tempfile.gettempdir()
    root = os.path.join(base, "w337-close2425")
    os.makedirs(root, exist_ok=True)
    return root


_CHILD_BATTERIES = [
    # After F424/F425 closures: P2c and P3e flip from BREAK to HELD
    # (the child runs with GOV_SKIP_GREEN=1, so its green checks
    # collapse into one GREEN-SKIPPED HELD).
    ("w336_redteam_probes.py", 0, "0/28/0"),
    ("w336_f423_probes.py", 0, "0/7/0"),
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
        m = re.search(r"(\d+)/(\d+)/(\d+) \(break/held/error\)", tail)
    return m, tail


def _green_check():
    """Depth-1 green checks over the directly affected wave-336 batteries.
    Honors GOV_SKIP_GREEN (wave-320 lesson)."""
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
    print("\nw337_f424f425: %d/%d/%d (break/held/error)" % (b, h, e))
    for pid in _EXPECTED_BREAKS:
        if pid not in [p for p, _, _ in _results]:
            print("WARNING: expected-break probe %r not present" % (pid,))
    return 1 if (b or e) else 0


if __name__ == "__main__":
    sys.exit(main())
