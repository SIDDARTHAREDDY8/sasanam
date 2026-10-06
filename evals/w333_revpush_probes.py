"""Wave-333 revocation-push battery (F417 closure).

Base: 43d539c7 (wave-332 merge). Footer at merge: open F417 / next F419
(F418 CLOSED = revpush F417 renumbered; F417 OPEN = redteam bare-port). Pin: 2100 (+15: 7 capability-token-* + 8 revocation-push-*).

P1  Mid-flight revocation terminates the bound session coded: a
    session registered against a credential subject executes step 1, a
    signed credential-revoked event is ingested, the kill callback
    fires, require_live refuses the next step coded
    revocation-push-session-terminated. (The F417 red-first scenario:
    on the base tree the session survived -- /tmp/red_revpush.py.)
P2  Revocation for an unrelated subject does not touch other
    sessions (exact subject matching, never class/prefix).
P3  Malformed events refuse coded revocation-push-event-malformed
    (non-record, bad event_id, unknown event_type, bad subject,
    non-numeric issued_at, far-future issued_at).
P4  Replayed event_ids are idempotent: duplicate ack coded
    revocation-push-event-replayed, terminate callback fires exactly
    once, no re-termination.
P5  Unsigned/forged events refuse coded
    revocation-push-event-unsigned when the hub requires signatures
    (default); opt-out hub accepts unsigned (documented).
P6  Fail-closed suspension: a raising on_terminate (or a liveness
    probe still reporting alive) suspends the session; require_live
    refuses coded revocation-push-session-suspended -- the session is
    never allowed to continue on an unconfirmed kill.
P7  Event for an unbound subject acks coded
    revocation-push-subject-unbound; nothing terminated.
P8  All three event types fan out (credential-revoked,
    mission-cancelled, agent-deauthorized).
P9  require_live semantics: live passes; terminated refuses coded;
    never-registered refuses coded revocation-push-session-unknown.
P10 Pin 2100 + footer state (open F417 / next F419; F418 CLOSED);
    taxonomy sorted-unique on raw literals; the 8 new codes centrally
    registered.
P11 Green check (depth-1): honors GOV_SKIP_GREEN; otherwise runs the
    revocation-adjacent battery w292_revocation_probes.py as a child
    with GOV_SKIP_GREEN=1 (fresh TMPDIR).

gov/ changes in this lane: new gov/revocation_push.py (+8 codes in
gov/decision_codes.py, pin 2062 -> 2100 at merge). Findings: F417 filed then
CLOSED here; renumbered F417->F418 at the wave-333 merge (redteam filed F417 first).
"""

import hashlib
import hmac
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
FOOTER_OPEN = "F478, F479"  # F417/F418/F423/F424/F425 CLOSED; F426 closed wave-338 lane 1.; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)


FOOTER_NEXT = "F480"  # Next free finding number.; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480



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
    d = os.path.join(tempfile.gettempdir(), "w333revpush")
    if not os.path.isdir(d):
        os.makedirs(d)
    return d


def _tmpd(prefix="w333revpush-"):
    return tempfile.mkdtemp(prefix=prefix, dir=_run_root())


from gov import revocation_push as rp  # noqa: E402
from gov import decision_codes as dc  # noqa: E402


_KEY = bytes(range(32))
_NOW = 1750000000.0


def _hub(**kw):
    kw.setdefault("hmac_key", _KEY)
    kw.setdefault("clock", lambda: _NOW)
    return rp.RevocationPushHub(**kw)


def _event(event_id="evt-00000001", event_type=rp.EVENT_TYPES[0],
           kind="credential", sid="cred-digest-1", reason="test"):
    return {"event_id": event_id, "event_type": event_type,
            "subject": {"kind": kind, "id": sid},
            "issued_at": _NOW, "reason": reason}


def _signed(event, key=_KEY):
    return rp.sign_event(key, event)


# ---------------------------------------------------------------------------
# P1 -- mid-flight revocation terminates coded (the F417 scenario).
# ---------------------------------------------------------------------------

@probe("P1-midflight-revocation-terminates-coded")
def _p1():
    pid = "P1-midflight-revocation-terminates-coded"
    hub = _hub()
    kills = []
    hub.register_session("sess-1", [{"kind": "credential", "id": "cred-A"}],
                         on_terminate=kills.append)
    # step 1 executes (session live)
    hub.require_live("sess-1")
    # revocation event arrives mid-flight
    receipt = hub.ingest(_signed(_event(event_id="evt-p1-0001",
                                       sid="cred-A")))
    if receipt["code"] != "revocation-push-session-terminated":
        return _break(pid, "receipt code %r" % receipt["code"])
    if receipt["terminated"] != ["sess-1"]:
        return _break(pid, "terminated list %r" % receipt["terminated"])
    if len(kills) != 1 or "evt-p1-0001" not in kills[0]:
        return _break(pid, "kill callback not fired once with reason")
    if hub.session_status("sess-1") != "terminated":
        return _break(pid, "status not terminated")
    # step 2 must NOT execute: require_live refuses coded
    try:
        hub.require_live("sess-1")
    except rp.RevocationPushError as exc:
        if exc.code == "revocation-push-session-terminated":
            return _held(pid, "mid-flight kill: callback fired, next step "
                              "refuses coded revocation-push-session-terminated")
        return _break(pid, "wrong code %r" % exc.code)
    return _break(pid, "session continued after revocation event")


# ---------------------------------------------------------------------------
# P2 -- unrelated subject untouched (exact matching).
# ---------------------------------------------------------------------------

@probe("P2-unrelated-subject-untouched")
def _p2():
    pid = "P2-unrelated-subject-untouched"
    hub = _hub()
    hub.register_session("sess-A", [{"kind": "agent", "id": "agent-1"}])
    hub.register_session("sess-B", [{"kind": "agent", "id": "agent-2"}])
    receipt = hub.ingest(_signed(_event(event_id="evt-p2-0001",
                                       event_type=rp.EVENT_TYPES[2],
                                       kind="agent", sid="agent-1")))
    if receipt["terminated"] != ["sess-A"]:
        return _break(pid, "terminated %r" % receipt["terminated"])
    if hub.session_status("sess-B") != "live":
        return _break(pid, "unrelated session touched")
    hub.require_live("sess-B")  # must not raise
    # near-miss ids must NOT match (no prefix/class semantics)
    hub2 = _hub()
    hub2.register_session("s", [{"kind": "agent", "id": "agent-1"}])
    r2 = hub2.ingest(_signed(_event(event_id="evt-p2-0002",
                                    event_type=rp.EVENT_TYPES[2],
                                    kind="agent", sid="agent-1X")))
    if r2["code"] != "revocation-push-subject-unbound":
        return _break(pid, "prefix-shaped id matched: %r" % r2["code"])
    return _held(pid, "exact (kind,id) matching; agent-2 session live")


# ---------------------------------------------------------------------------
# P3 -- malformed events refused coded.
# ---------------------------------------------------------------------------

@probe("P3-malformed-events-refused-coded")
def _p3():
    pid = "P3-malformed-events-refused-coded"
    hub = _hub()
    cases = []
    e = _event(event_id="x" * 7); cases.append(e)  # 7 chars < 8
    e = _event(event_id="evt-p3-a"); e["event_type"] = "nope"; cases.append(e)
    e = _event(event_id="evt-p3-b"); e["subject"] = {"kind": "user", "id": "u"}; cases.append(e)
    e = _event(event_id="evt-p3-c"); e["subject"] = {"kind": "agent", "id": ""}; cases.append(e)
    e = _event(event_id="evt-p3-d"); e["issued_at"] = "now"; cases.append(e)
    e = _event(event_id="evt-p3-e"); e["issued_at"] = True; cases.append(e)
    e = _event(event_id="evt-p3-f"); e["issued_at"] = _NOW + 3600.0; cases.append(e)
    cases.append("not-a-dict")
    for i, ev in enumerate(cases):
        try:
            hub.ingest(_signed(ev))
        except rp.RevocationPushEventMalformedError as exc:
            if exc.code != "revocation-push-event-malformed":
                return _break(pid, "case %d wrong code %r" % (i, exc.code))
            continue
        except rp.RevocationPushError as exc:
            return _break(pid, "case %d wrong error class %r"
                          % (i, exc.code))
        except Exception as exc:
            return _break(pid, "case %d uncoded %s" % (i, type(exc).__name__))
        return _break(pid, "case %d accepted" % i)
    return _held(pid, "8 malformed shapes refuse coded "
                      "revocation-push-event-malformed")


# ---------------------------------------------------------------------------
# P4 -- replay idempotent.
# ---------------------------------------------------------------------------

@probe("P4-replay-idempotent")
def _p4():
    pid = "P4-replay-idempotent"
    hub = _hub()
    kills = []
    hub.register_session("sess-1", [{"kind": "credential", "id": "cred-A"}],
                         on_terminate=kills.append)
    ev = _signed(_event(event_id="evt-p4-0001", sid="cred-A"))
    r1 = hub.ingest(ev)
    r2 = hub.ingest(ev)
    if r2["code"] != "revocation-push-event-replayed":
        return _break(pid, "replay code %r" % r2["code"])
    if not r2["duplicate"]:
        return _break(pid, "replay not flagged duplicate")
    if len(kills) != 1:
        return _break(pid, "callback fired %d times" % len(kills))
    if r1["terminated"] != r2["terminated"]:
        return _break(pid, "receipt mismatch on replay")
    return _held(pid, "duplicate ack coded; callback exactly once")


# ---------------------------------------------------------------------------
# P5 -- signature enforcement.
# ---------------------------------------------------------------------------

@probe("P5-unsigned-events-refused-coded")
def _p5():
    pid = "P5-unsigned-events-refused-coded"
    hub = _hub()  # signatures required by default
    for i, ev in enumerate([_event(event_id="evt-p5-0001"),
                            _signed(_event(event_id="evt-p5-0002"),
                                    key=bytes([9]) * 32)]):
        try:
            hub.ingest(ev)
        except rp.RevocationPushEventUnsignedError as exc:
            if exc.code != "revocation-push-event-unsigned":
                return _break(pid, "case %d wrong code %r" % (i, exc.code))
            continue
        except Exception as exc:
            return _break(pid, "case %d uncoded %s" % (i, type(exc).__name__))
        return _break(pid, "case %d accepted without valid sig" % i)
    # opt-out hub accepts unsigned (documented deployment choice)
    hub2 = _hub(require_signed_events=False, hmac_key=None)
    hub2.register_session("s", [{"kind": "agent", "id": "a1"}])
    r = hub2.ingest(_event(event_id="evt-p5-0003",
                           event_type=rp.EVENT_TYPES[2],
                           kind="agent", sid="a1"))
    if r["code"] != "revocation-push-session-terminated":
        return _break(pid, "opt-out hub did not terminate: %r" % r["code"])
    return _held(pid, "unsigned/forged refuse coded by default; "
                      "explicit opt-out terminates")


# ---------------------------------------------------------------------------
# P6 -- fail-closed suspension.
# ---------------------------------------------------------------------------

@probe("P6-kill-unconfirmed-suspends-fail-closed")
def _p6():
    pid = "P6-kill-unconfirmed-suspends-fail-closed"
    hub = _hub()

    def boom(reason):
        raise RuntimeError("kill failed")

    hub.register_session("sess-boom", [{"kind": "agent", "id": "a-boom"}],
                         on_terminate=boom)
    r = hub.ingest(_signed(_event(event_id="evt-p6-0001",
                                  event_type=rp.EVENT_TYPES[2],
                                  kind="agent", sid="a-boom")))
    if r["suspended"] != ["sess-boom"]:
        return _break(pid, "raising callback did not suspend: %r" % r)
    if hub.session_status("sess-boom") != "suspended":
        return _break(pid, "status not suspended")
    try:
        hub.require_live("sess-boom")
    except rp.RevocationPushError as exc:
        if exc.code != "revocation-push-session-suspended":
            return _break(pid, "wrong code %r" % exc.code)
    else:
        return _break(pid, "suspended session allowed to continue")

    # liveness probe still alive after on_terminate -> suspend
    hub2 = _hub()
    hub2.register_session("sess-live", [{"kind": "mission", "id": "m-1"}],
                          on_terminate=lambda reason: None,
                          liveness=lambda: True)
    r2 = hub2.ingest(_signed(_event(event_id="evt-p6-0002",
                                    event_type=rp.EVENT_TYPES[1],
                                    kind="mission", sid="m-1")))
    if r2["suspended"] != ["sess-live"]:
        return _break(pid, "alive-after-kill not suspended: %r" % r2)
    return _held(pid, "raising callback and alive-after-kill both "
                      "suspend; require_live refuses coded")


# ---------------------------------------------------------------------------
# P7 -- unbound subject ack.
# ---------------------------------------------------------------------------

@probe("P7-unbound-subject-acks-coded")
def _p7():
    pid = "P7-unbound-subject-acks-coded"
    hub = _hub()
    hub.register_session("sess-1", [{"kind": "agent", "id": "a-1"}])
    r = hub.ingest(_signed(_event(event_id="evt-p7-0001",
                                  event_type=rp.EVENT_TYPES[2],
                                  kind="agent", sid="nobody")))
    if r["code"] != "revocation-push-subject-unbound":
        return _break(pid, "code %r" % r["code"])
    if r["terminated"] or r["suspended"]:
        return _break(pid, "sessions touched: %r" % r)
    if hub.session_status("sess-1") != "live":
        return _break(pid, "registered session disturbed")
    return _held(pid, "no-match acks coded; registry untouched")


# ---------------------------------------------------------------------------
# P8 -- all three event types fan out.
# ---------------------------------------------------------------------------

@probe("P8-all-event-types-fan-out")
def _p8():
    pid = "P8-all-event-types-fan-out"
    hub = _hub()
    seen = []
    hub.register_session("s-cred", [{"kind": "credential", "id": "c1"}],
                         on_terminate=lambda r: seen.append("cred"))
    hub.register_session("s-mission", [{"kind": "mission", "id": "m1"}],
                         on_terminate=lambda r: seen.append("mission"))
    hub.register_session("s-agent", [{"kind": "agent", "id": "a1"}],
                         on_terminate=lambda r: seen.append("agent"))
    for i, (etype, kind, sid) in enumerate(
            [(rp.EVENT_TYPES[0], "credential", "c1"),
             (rp.EVENT_TYPES[1], "mission", "m1"),
             (rp.EVENT_TYPES[2], "agent", "a1")]):
        r = hub.ingest(_signed(_event(event_id="evt-p8-%04d" % i,
                                      event_type=etype, kind=kind, sid=sid)))
        if r["code"] != "revocation-push-session-terminated":
            return _break(pid, "%s -> %r" % (etype, r["code"]))
    if sorted(seen) != ["agent", "cred", "mission"]:
        return _break(pid, "callbacks %r" % seen)
    return _held(pid, "credential-revoked, mission-cancelled, "
                      "agent-deauthorized all terminate bound sessions")


# ---------------------------------------------------------------------------
# P9 -- require_live semantics.
# ---------------------------------------------------------------------------

@probe("P9-require-live-semantics")
def _p9():
    pid = "P9-require-live-semantics"
    hub = _hub()
    hub.register_session("s-live", [{"kind": "agent", "id": "a"}])
    if hub.require_live("s-live") is not True:
        return _break(pid, "live session did not pass")
    hub.register_session("s-dead", [{"kind": "agent", "id": "b"}])
    hub.ingest(_signed(_event(event_id="evt-p9-0001",
                              event_type=rp.EVENT_TYPES[2],
                              kind="agent", sid="b")))
    try:
        hub.require_live("s-dead")
    except rp.RevocationPushError as exc:
        if exc.code != "revocation-push-session-terminated":
            return _break(pid, "terminated wrong code %r" % exc.code)
    else:
        return _break(pid, "terminated session passed require_live")
    try:
        hub.require_live("never-registered")
    except rp.RevocationPushError as exc:
        if exc.code != "revocation-push-session-unknown":
            return _break(pid, "unknown wrong code %r" % exc.code)
    else:
        return _break(pid, "unknown session passed require_live")
    return _held(pid, "live passes; terminated/unknown refuse coded")


# ---------------------------------------------------------------------------
# P10 -- pin + footer.
# ---------------------------------------------------------------------------

@probe("P10-pin-2135-footer-f430-f431")
def _p10():
    pid = "P10-pin-2135-footer-f430-f431"
    import re as _re
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    lits = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    n = len(dc.TAXONOMY)
    if n != TAXONOMY_PIN or len(lits) != TAXONOMY_PIN:
        return _break(pid, "taxonomy %d literals %d want %d"
                      % (n, len(lits), TAXONOMY_PIN))
    if lits != sorted(lits) or len(set(lits)) != len(lits):
        return _break(pid, "taxonomy not sorted/unique on raw literals")
    for c in rp.registered_codes():
        if c not in dc.TAXONOMY:
            return _break(pid, "code %r not centrally registered" % c)
    text = open(os.path.join(REPO, "evals", "FINDINGS.md")).read()
    # F418 = revpush's finding, renumbered F417->F418 at the wave-333 merge.
    f418 = text.split("## F418")[1]
    # F418 section ends at the next "## F" heading or the footer line.
    f418_body = _re.split(r"\n## F\d+|\nNext free finding:", f418)[0]
    if "Status: CLOSED" not in f418_body:
        return _break(pid, "F418 not marked CLOSED in FINDINGS.md")
    if "RENUMBERED F417->F418" not in f418_body:
        return _break(pid, "F418 renumber note absent in FINDINGS.md")
    # F417 (redteam bare-port) CLOSED 2026-10-05 by wave-334 lane 1
    # (port guard: any ValueError refuses coded
    # mcp-oauth-metadata-malformed).
    f417 = text.split("## F417")[1]
    f417_body = _re.split(r"\n## F\d+|\nNext free finding:", f417)[0]
    if "**Status: CLOSED" not in f417_body:
        return _break(pid, "F417 not marked CLOSED in FINDINGS.md")
    ms = _re.findall(r"Next free finding: \*\*(F\d+)\*\*\. "
                     r"\*\*Open findings: ([^*]+)\.\*\*", text)
    if not ms:
        return _break(pid, "footer line not found")
    next_free, open_now = ms[-1]  # the LAST footer is the live one
    if next_free != FOOTER_NEXT or open_now.strip() != FOOTER_OPEN:
        return _break(pid, "footer open %s / next %s, want open %s / next %s"
                      % (open_now.strip(), next_free, FOOTER_OPEN,
                         FOOTER_NEXT))
    return _held(pid, "taxonomy 2135/2135/0 sorted-unique; 8 codes "
                      "registered; F418 CLOSED; F417 CLOSED; footer open none / next F430")


# ---------------------------------------------------------------------------
# Green check (depth-1).
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # No expected BREAKs on the fixed tree.


def _run_child_output(battery, timeout):
    d = _tmpd("w333revpush-green-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO, "evals", battery)],
        capture_output=True, text=True, timeout=timeout, env=env,
        cwd=REPO)
    return proc.stdout + proc.stderr


def _green_check():
    """Depth-1 green check: the revocation-adjacent battery
    w292_revocation_probes.py as a child with GOV_SKIP_GREEN=1 (fresh
    TMPDIR). Honors GOV_SKIP_GREEN by recording a skip, never spawning.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    try:
        out = _run_child_output("w292_revocation_probes.py", timeout=900)
    except Exception as exc:
        _record("green-check", "ERROR", "w292: %s" % exc)
        return
    breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
    errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
    m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
    if m2:
        import ast as _ast
        try:
            breaks.update(_ast.literal_eval(m2.group(1)))
        except Exception:
            pass
    if breaks or errors:
        _record("green-check", "BREAK",
                "w292 non-green: %s" % sorted(breaks | errors)[:4])
    else:
        _record("green-check", "HELD", "w292_revocation_probes green")


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
    print("w333_revpush battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the fixed tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
