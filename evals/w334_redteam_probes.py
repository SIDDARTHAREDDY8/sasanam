#!/usr/bin/env python3
"""Wave-334 lane 5 independent red team: break the wave-333 tree.

Base: `a40c2ef4` (wave-333 merge). Pin 2100. Footer open none / next F421.

New attack surface under test: `gov/capability_token.py`
(context-bound capability tokens, +7 codes) and `gov/revocation_push.py`
(CAEP/SSF-style revocation intake + session kill channel, +8 codes).

Break-first probes at the public seams:

P1 (capability tokens -- context confusion):
  P1a  0x00-injection in the digest join fields (agent/mission/tool/policy
       carrying raw NUL): roundtrip must hold AND the canonical bytes must
       never contain a raw 0x00 (the join-unambiguity claim).
  P1b  digest preimage confusion: neighboring tuples that would collide
       under a naive concatenation ("ab","c") vs ("a","bc") must bind
       distinct digests.
  P1c  JSON key-order games: reordered top-level / context / inner keys
       must still verify (canonical seal is order-independent by design).
  P1d  inner-token swap: token1's outer seal wrapped around token2's
       inner token must refuse capability-token-tampered.
  P1e  seal-strip / digest-tamper: missing mac -> malformed; edited
       context_digest or mac -> tampered.
  P1f  cross-context replay dead at the new seam: wrong agent / mission /
       widened tools / rotated policy each refuse with their own code.
  P1g  tool-set normalization edges: duplicates, tuple input, widened set,
       NUL inside a tool name binds distinctly.
  P1h  unicode-lookalike fields: Greek-Alpha agent, fullwidth-digit
       policy each refuse (distinct strings, no confusables collapse).

P2 (revocation push -- kill-channel attacks):
  P2a  unsigned event on the default hub refuses
       revocation-push-event-unsigned.
  P2b  forged signature (wrong key) refuses unsigned.
  P2c  replayed revocation: second ingest returns duplicate=True with
       revocation-push-event-replayed; the terminate callback fires once.
  P2d  subject confusion: prefix / case-variant / kind-swapped subjects
       never touch the bound session (exact (kind,id) matching).
  P2e  callback-exception escape: a raising on_terminate suspends
       fail-closed; require_live refuses revocation-push-session-suspended.
  P2f  liveness-probe spoofing: still-alive report or raising probe after
       the kill both suspend fail-closed.
  P2g  replay-cache eviction: after the bounded seen-set evicts an
       event_id, re-ingest must not re-fire the terminate callback.
  P2h  NaN issued_at: documented schema wart (accepted; signed-only, no
       security boundary crossed -- NOT a finding, pinned as observed).
  P2i  future issued_at beyond skew refuses malformed.
  P2j  require_live on a never-registered session refuses
       revocation-push-session-unknown.
  P2k  session re-registration refused (callback-swap neutering attempt).

P3 (F417 OPEN-state pin): the non-numeric-port shape still escapes
     _normalize_url as a bare ValueError -- F417 open as documented.
P4 (F418 CLOSED): revocation event terminates a bound in-flight session
     coded revocation-push-session-terminated.
P5 (honesty): pin 2100 taxonomy sorted-unique on raw literals; all 15 new
     codes centrally registered; footer open none / next F421.

Verdicts:
  HELD  = behavior matches the pin (attack refused coded / legitimate
          use accepted / documented state observed);
  BREAK = behavior changed vs the pin, or an unexpected miss;
  ERROR = probe/harness problem.

Genuine findings get F-numbers from F419; none are manufactured -- a
0-break battery is an honest result.

Deterministic across 2 runs; $0 spend; synthetic/local. Stdlib only
apart from gov/ (real product code, no stubs).

Run:
  mkdir -p /var/tmp/g334-red
  TMPDIR=/var/tmp/g334-red ~/workspace/.gov-venv/bin/python evals/w334_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g334-redb ~/workspace/.gov-venv/bin/python evals/w334_redteam_probes.py
Single-probe mode:
  ~/workspace/.gov-venv/bin/python evals/w334_redteam_probes.py P1d
"""

import copy
import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import capability_token as CT  # noqa: E402
from gov import revocation_push as RP  # noqa: E402
from gov import mcp_oauth_binding as mob  # noqa: E402

TAXONOMY_PIN = 2131  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).
_NOW = 1798765432
_AGENT = "agent-A"
_MISSION = "mission-X"
_TOOLS = ["send_email"]
_POLICY = "policy-v3"
_BENIGN = {"to": "teammate@synthetic.local", "body": "weekly report"}
_MKEY = b"w334-redteam-mcp-test-key-0001"
_RPKEY = b"w334-redteam-revpush-test-key-01"  # 32 bytes

assert len(_RPKEY) == 32, "revocation-push test key must be 32 bytes"

_NEW_CAP_CODES = (
    "capability-token-malformed",
    "capability-token-tampered",
    "capability-token-expired",
    "capability-token-agent-mismatch",
    "capability-token-mission-mismatch",
    "capability-token-tools-mismatch",
    "capability-token-policy-stale",
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


def _key():
    # Standalone battery runs do not import the tests package, so
    # provision a key here when absent. Test-only.
    if "GOV_LOG_KEY" not in os.environ:
        try:
            from tests.keyfixture import provision_test_key
        except ImportError:
            from keyfixture import provision_test_key
        provision_test_key()


def _code_of(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", "UNEXPECTED:%r" % (e,))
    return None


# ---------------------------------------------------------------------------
# P1: capability-token context confusion.
# ---------------------------------------------------------------------------

def _mint(**kw):
    base = {"agent_id": _AGENT, "mission_id": _MISSION,
            "tool_set": list(_TOOLS), "policy_version": _POLICY,
            "capability": "send_email",
            "argument_binding": {"mode": "exact", "args": dict(_BENIGN)},
            "issuer": "human-operator", "ttl_seconds": 3600,
            "issued_at": _NOW}
    base.update(kw)
    return CT.mint_context_token(**base)


def _verify(token, **kw):
    base = {"agent_id": _AGENT, "mission_id": _MISSION,
            "tool_set": list(_TOOLS), "policy_version": _POLICY,
            "capability": "send_email", "args": dict(_BENIGN),
            "now": _NOW}
    base.update(kw)
    return CT.verify_context_token(token, **base)


def P1a():
    """NUL bytes in the digest join fields: the join must stay
    unambiguous (canonical JSON escapes NUL as \\u0000), and mint/verify
    must round-trip."""
    _key()
    pid = "P1a-nul-in-join-fields"
    nul_agent = "agent\x00A"
    nul_tool = "t\x00ool"
    try:
        tok = _mint(agent_id=nul_agent, tool_set=[nul_tool])
    except Exception as e:  # noqa: BLE001
        _break(pid, "mint with NUL fields failed: %r" % (e,))
        return
    # The join-unambiguity claim: no canonical part may contain a raw
    # 0x00 byte, for adversarial inputs.
    for adv in (nul_agent, "m\x00ission", nul_tool, "p\x00olicy",
                " ", "a b"):
        raw = CT._canonical(adv)
        if b"\x00" in raw:
            _break(pid, "canonical bytes contain raw 0x00 for %r" % (adv,))
            return
    try:
        bound = _verify(tok, agent_id=nul_agent, tool_set=[nul_tool])
    except Exception as e:  # noqa: BLE001
        _break(pid, "NUL-field roundtrip failed: %r" % (e,))
        return
    if bound["agent_id"] != nul_agent or bound["tool_set"] != [nul_tool]:
        _break(pid, "roundtrip bound the wrong context: %r" % (bound,))
        return
    # And the NUL variant must NOT verify as the plain variant.
    code = _code_of(lambda: _verify(tok))
    if code != CT.AGENT_MISMATCH:
        _break(pid, "NUL-agent token verified as plain agent: %r" % (code,))
        return
    _held(pid, "NUL fields round-trip; canonical join has no raw 0x00; "
               "NUL/plain stay distinct")


def P1b():
    """Preimage confusion: tuples that collide under naive concatenation
    must bind distinct digests."""
    pid = "P1b-digest-preimage-confusion"
    d1 = CT._context_digest("ab", "c", ["t"], "v")
    d2 = CT._context_digest("a", "bc", ["t"], "v")
    d3 = CT._context_digest("ab", "c", ["t"], "v")
    if d1 == d2:
        _break(pid, "digest collision on ('ab','c') vs ('a','bc')")
        return
    if d1 != d3:
        _break(pid, "digest unstable for identical inputs")
        return
    # Tool-list vs string confusion: ["ab"] must differ from "ab" shape.
    d4 = CT._context_digest("a", "b", ["x", "y"], "v")
    d5 = CT._context_digest("a", "b", ["xy"], "v")
    if d4 == d5:
        _break(pid, "digest collision on ['x','y'] vs ['xy']")
        return
    _held(pid, "neighboring tuples bind distinct, stable digests")


def P1c():
    """JSON key-order games: the seal is over canonical bytes, so a
    reordered presentation must still verify (pinned by design)."""
    _key()
    pid = "P1c-key-order-games"
    tok = _mint()
    # Rebuild every level in a different insertion order.
    reordered = {
        "mac": tok["mac"],
        "key_epoch": tok["key_epoch"],
        "context_digest": tok["context_digest"],
        "context": {
            "policy_version": tok["context"]["policy_version"],
            "tool_set": tok["context"]["tool_set"],
            "mission_id": tok["context"]["mission_id"],
            "agent_id": tok["context"]["agent_id"],
        },
        "inner": {k: tok["inner"][k]
                  for k in reversed(list(tok["inner"].keys()))},
        "v": tok["v"],
    }
    try:
        _verify(reordered)
    except Exception as e:  # noqa: BLE001
        _break(pid, "reordered-but-identical token refused: %r" % (e,))
        return
    _held(pid, "key reorder verifies (canonical seal, order-independent)")


def P1d():
    """Inner-token swap: token1's outer seal around token2's inner token
    must refuse capability-token-tampered."""
    _key()
    pid = "P1d-inner-token-swap"
    t1 = _mint(capability="send_email")
    t2 = _mint(capability="delete_file",
               argument_binding={"mode": "exact",
                                 "args": {"path": "/tmp/x"}})
    swapped = dict(t1)
    swapped["inner"] = t2["inner"]
    code = _code_of(lambda: _verify(swapped, capability="delete_file",
                                   args={"path": "/tmp/x"}))
    if code != CT.TAMPERED:
        _break(pid, "swapped inner token not caught as tampered: %r"
               % (code,))
        return
    _held(pid, "inner swap refuses coded capability-token-tampered")


def P1e():
    """Seal-strip and digest-tamper."""
    _key()
    pid = "P1e-seal-strip-digest-tamper"
    tok = _mint()
    stripped = {k: v for k, v in tok.items() if k != "mac"}
    code = _code_of(lambda: _verify(stripped))
    if code != CT.MALFORMED:
        _break(pid, "stripped mac not malformed: %r" % (code,))
        return
    bad_digest = dict(tok)
    dg = bad_digest["context_digest"]
    bad_digest["context_digest"] = ("0" if dg[0] != "0" else "1") + dg[1:]
    code = _code_of(lambda: _verify(bad_digest))
    if code != CT.TAMPERED:
        _break(pid, "edited digest not tampered: %r" % (code,))
        return
    bad_mac = dict(tok)
    mc = bad_mac["mac"]
    bad_mac["mac"] = ("0" if mc[0] != "0" else "1") + mc[1:]
    code = _code_of(lambda: _verify(bad_mac))
    if code != CT.TAMPERED:
        _break(pid, "edited mac not tampered: %r" % (code,))
        return
    _held(pid, "strip->malformed; digest/mac edits->tampered")


def P1f():
    """Cross-context replay is dead at the new seam: each of the four
    bound dimensions refuses with its own code."""
    _key()
    pid = "P1f-cross-context-replay-dead"
    tok = _mint()
    cases = [
        ({"agent_id": "agent-B"}, CT.AGENT_MISMATCH, "agent"),
        ({"mission_id": "mission-Y"}, CT.MISSION_MISMATCH, "mission"),
        ({"tool_set": ["send_email", "delete_file"]}, CT.TOOLS_MISMATCH,
         "tools-widened"),
        ({"tool_set": []}, CT.MALFORMED, "tools-emptied"),
        ({"policy_version": "policy-v4"}, CT.POLICY_STALE, "policy"),
    ]
    for kw, want, label in cases:
        code = _code_of(lambda: _verify(tok, **kw))
        if code != want:
            _break(pid, "%s: got %r want %r" % (label, code, want))
            return
    _held(pid, "agent/mission/tools/policy replays each refuse coded")


def P1g():
    """Tool-set normalization edges: duplicates and tuple input
    normalize; a NUL inside a tool name binds distinctly."""
    _key()
    pid = "P1g-toolset-normalization-edges"
    tok = _mint(tool_set=("b_tool", "a_tool", "a_tool"))
    try:
        bound = _verify(tok, tool_set=["a_tool", "b_tool"])
    except Exception as e:  # noqa: BLE001
        _break(pid, "normalized set rejected: %r" % (e,))
        return
    if bound["tool_set"] != ["a_tool", "b_tool"]:
        _break(pid, "stored set not normalized: %r" % (bound["tool_set"],))
        return
    code = _code_of(lambda: _verify(tok, tool_set=["a_tool"]))
    if code != CT.TOOLS_MISMATCH:
        _break(pid, "narrowed set not refused: %r" % (code,))
        return
    nul_tok = _mint(tool_set=["t\x00ool"])
    code = _code_of(lambda: _verify(nul_tok, tool_set=["tool"]))
    if code != CT.TOOLS_MISMATCH:
        _break(pid, "NUL-tool confused with plain tool: %r" % (code,))
        return
    _held(pid, "dup/tuple normalize; narrowed refuses; NUL-tool distinct")


def P1h():
    """Unicode-lookalike fields must not collapse: Greek Alpha agent and
    fullwidth-digit policy are distinct strings and refuse."""
    _key()
    pid = "P1h-unicode-lookalike-fields"
    tok = _mint()
    code = _code_of(lambda: _verify(tok, agent_id="agent-\u0391"))
    if code != CT.AGENT_MISMATCH:
        _break(pid, "greek-alpha agent not mismatch: %r" % (code,))
        return
    code = _code_of(lambda: _verify(tok, policy_version="policy-v\uff13"))
    if code != CT.POLICY_STALE:
        _break(pid, "fullwidth-digit policy not stale: %r" % (code,))
        return
    _held(pid, "lookalike agent/policy refuse with their own codes")

# ---------------------------------------------------------------------------
# P2: revocation-push kill-channel attacks.
# ---------------------------------------------------------------------------

def _rphub(**kw):
    kw.setdefault("hmac_key", _RPKEY)
    kw.setdefault("clock", lambda: _NOW)
    return RP.RevocationPushHub(**kw)


def _rpevent(event_id="evt-00000001", event_type=None, kind="credential",
            sid="cred-digest-1", issued_at=_NOW, reason="test"):
    return {"event_id": event_id,
            "event_type": event_type or RP.EVENT_TYPES[0],
            "subject": {"kind": kind, "id": sid},
            "issued_at": issued_at, "reason": reason}


def P2a():
    """Unsigned event on the default hub refuses
    revocation-push-event-unsigned (raised, no state change)."""
    pid = "P2a-unsigned-event-refused"
    hub = _rphub()
    hub.register_session("s-1", [{"kind": "credential", "id": "cred-1"}],
                         on_terminate=lambda r: None)
    try:
        hub.ingest(_rpevent())
    except RP.RevocationPushEventUnsignedError as e:
        if e.code != "revocation-push-event-unsigned":
            _break(pid, "wrong code: %r" % (e.code,))
            return
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong exception type: %r" % (e,))
        return
    else:
        _break(pid, "unsigned event ingested without refusal")
        return
    if hub.session_status("s-1") != "live":
        _break(pid, "session state changed on refused event")
        return
    _held(pid, "unsigned event refused coded; session untouched")


def P2b():
    """Forged signature (wrong key) refuses unsigned."""
    pid = "P2b-forged-signature-refused"
    hub = _rphub()
    forged = RP.sign_event(b"0" * 32, _rpevent())
    try:
        hub.ingest(forged)
    except RP.RevocationPushEventUnsignedError as e:
        if e.code == "revocation-push-event-unsigned":
            _held(pid, "wrong-key signature refused coded unsigned")
            return
        _break(pid, "wrong code: %r" % (e.code,))
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong exception type: %r" % (e,))
    else:
        _break(pid, "forged signature ingested")


def P2c():
    """Replayed revocation: duplicate receipt, original code replaced by
    revocation-push-event-replayed, terminate callback fires exactly
    once."""
    pid = "P2c-replay-idempotent"
    hub = _rphub()
    calls = []
    hub.register_session("s-1", [{"kind": "credential", "id": "cred-1"}],
                         on_terminate=lambda r: calls.append(r))
    evt = RP.sign_event(_RPKEY, _rpevent(sid="cred-1"))
    r1 = hub.ingest(evt)
    r2 = hub.ingest(evt)
    if r1["code"] != "revocation-push-session-terminated":
        _break(pid, "first ingest code: %r" % (r1["code"],))
        return
    if not r2.get("duplicate") or \
            r2["code"] != "revocation-push-event-replayed":
        _break(pid, "replay not flagged: %r" % (r2,))
        return
    if len(calls) != 1:
        _break(pid, "callback fired %d times" % (len(calls),))
        return
    if hub.session_status("s-1") != "terminated":
        _break(pid, "session not terminated: %s"
               % hub.session_status("s-1"))
        return
    _held(pid, "replay idempotent; callback fired exactly once")


def P2d():
    """Subject confusion: prefix, case-variant, and kind-swapped
    subjects never touch the bound session (exact (kind,id) match)."""
    pid = "P2d-subject-confusion"
    hub = _rphub()
    killed = []
    hub.register_session("s-1", [{"kind": "agent", "id": "agent-007"}],
                         on_terminate=lambda r: killed.append(r))
    for label, kind, sid in [
            ("prefix", "agent", "agent-0071"),
            ("case", "agent", "AGENT-007"),
            ("kind-swap", "credential", "agent-007"),
            ("empty-ish", "agent", "agent-007 ")]:
        evt = RP.sign_event(_RPKEY, _rpevent(
            event_id="evt-%s-0001" % label.replace("-", ""), kind=kind,
            sid=sid))
        rcpt = hub.ingest(evt)
        if rcpt["code"] != "revocation-push-subject-unbound":
            _break(pid, "%s: unexpected receipt %r" % (label, rcpt["code"]))
            return
    if killed or hub.session_status("s-1") != "live":
        _break(pid, "confused subject touched the session")
        return
    # The exact subject DOES terminate.
    evt = RP.sign_event(_RPKEY, _rpevent(
        event_id="evt-exact-0001", kind="agent", sid="agent-007"))
    rcpt = hub.ingest(evt)
    if rcpt["code"] != "revocation-push-session-terminated" or not killed:
        _break(pid, "exact subject failed to terminate: %r" % (rcpt,))
        return
    _held(pid, "prefix/case/kind/whitespace confused nothing; exact kills")


def P2e():
    """Callback-exception escape: a raising on_terminate suspends
    fail-closed; require_live refuses revocation-push-session-suspended."""
    pid = "P2e-callback-exception-suspends"
    hub = _rphub()

    def boom(reason):
        raise RuntimeError("kill failed: actuator down")

    hub.register_session("s-1", [{"kind": "mission", "id": "m-9"}],
                         on_terminate=boom)
    evt = RP.sign_event(_RPKEY, _rpevent(
        event_id="evt-boom-0001", kind="mission", sid="m-9"))
    rcpt = hub.ingest(evt)
    if hub.session_status("s-1") != "suspended":
        _break(pid, "raising callback left session %s"
               % hub.session_status("s-1"))
        return
    if rcpt["suspended"] != ["s-1"]:
        _break(pid, "receipt missing suspension: %r" % (rcpt,))
        return
    try:
        hub.require_live("s-1")
    except RP.RevocationPushSessionSuspendedError as e:
        if e.code == "revocation-push-session-suspended":
            _held(pid, "raising callback suspends; require_live refuses "
                       "coded")
            return
        _break(pid, "wrong code: %r" % (e.code,))
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong exception: %r" % (e,))
    else:
        _break(pid, "suspended session passed require_live")


def P2f():
    """Liveness-probe spoofing: a still-alive report or a raising probe
    after the kill both suspend fail-closed."""
    pid = "P2f-liveness-spoof-suspends"
    for label, probe in [("still-alive", lambda: True),
                         ("raising", lambda: 1 / 0)]:
        hub = _rphub()
        hub.register_session("s-1", [{"kind": "credential", "id": "c-1"}],
                             on_terminate=lambda r: None, liveness=probe)
        evt = RP.sign_event(_RPKEY, _rpevent(
            event_id="evt-live-%s-01" % label, sid="c-1"))
        hub.ingest(evt)
        if hub.session_status("s-1") != "suspended":
            _break(pid, "%s probe: session %s, want suspended"
                   % (label, hub.session_status("s-1")))
            return
        try:
            hub.require_live("s-1")
        except RP.RevocationPushSessionSuspendedError:
            pass
        except Exception as e:  # noqa: BLE001
            _break(pid, "%s probe: wrong refusal %r" % (label, e))
            return
        else:
            _break(pid, "%s probe: suspended session passed gate" % label)
            return
    _held(pid, "still-alive and raising liveness both suspend fail-closed")


def P2g():
    """Replay-cache eviction: after the bounded seen-set evicts an
    event_id, re-ingest must not re-fire the terminate callback."""
    pid = "P2g-replay-cache-eviction"
    hub = _rphub(max_seen_events=2)
    calls = []
    hub.register_session("s-1", [{"kind": "credential", "id": "cred-1"}],
                         on_terminate=lambda r: calls.append(r))
    e1 = RP.sign_event(_RPKEY, _rpevent(event_id="evt-aaa-00001",
                                       sid="cred-1"))
    hub.ingest(e1)
    hub.ingest(RP.sign_event(_RPKEY, _rpevent(event_id="evt-bbb-00002",
                                              sid="unbound-1")))
    hub.ingest(RP.sign_event(_RPKEY, _rpevent(event_id="evt-ccc-00003",
                                              sid="unbound-2")))
    r = hub.ingest(e1)  # evicted: treated as new...
    if len(calls) != 1:
        _break(pid, "callback fired %d times after eviction" % len(calls))
        return
    if hub.session_status("s-1") != "terminated":
        _break(pid, "session state wrong: %s" % hub.session_status("s-1"))
        return
    _held(pid, "evicted re-ingest fires no second callback "
               "(receipt: %s)" % r["code"])


def P2h():
    """NaN issued_at: accepted (schema wart, pinned as observed). The
    schema says 'unix epoch, int/float, not bool' and NaN is a float;
    but events are HMAC-signed, so only the key-holder can mint one --
    no security boundary is crossed. NOT a finding; documented here."""
    pid = "P2h-nan-issued-at"
    hub = _rphub()
    evt = RP.sign_event(_RPKEY, _rpevent(event_id="evt-nan-00001",
                                        issued_at=float("nan")))
    try:
        rcpt = hub.ingest(evt)
    except Exception as e:  # noqa: BLE001
        _held(pid, "NaN issued_at refused: %r (stricter than expected; "
                   "documenting)" % (e,))
        return
    if rcpt["code"] not in ("revocation-push-subject-unbound",
                            "revocation-push-session-terminated"):
        _break(pid, "NaN event unexpected receipt: %r" % (rcpt,))
        return
    _held(pid, "NaN issued_at accepted on signed event (schema wart, "
               "signed-only, no boundary crossed -- not a finding)")


def P2i():
    """Future issued_at beyond the 300s skew refuses malformed."""
    pid = "P2i-future-issued-at"
    hub = _rphub()
    evt = RP.sign_event(_RPKEY, _rpevent(event_id="evt-fut-00001",
                                        issued_at=_NOW + 3600))
    try:
        hub.ingest(evt)
    except RP.RevocationPushEventMalformedError as e:
        if e.code == "revocation-push-event-malformed":
            _held(pid, "far-future issued_at refused coded malformed")
            return
        _break(pid, "wrong code: %r" % (e.code,))
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong exception: %r" % (e,))
    else:
        _break(pid, "far-future event ingested")


def P2j():
    """require_live on a never-registered session refuses
    revocation-push-session-unknown."""
    pid = "P2j-unknown-session-refused"
    hub = _rphub()
    try:
        hub.require_live("ghost-session")
    except RP.RevocationPushUnknownSessionError as e:
        if e.code == "revocation-push-session-unknown":
            _held(pid, "unknown session refuses coded session-unknown")
            return
        _break(pid, "wrong code: %r" % (e.code,))
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong exception: %r" % (e,))
    else:
        _break(pid, "ghost session passed require_live")


def P2k():
    """Session re-registration refused: a caller cannot swap in a no-op
    on_terminate to neuter the kill channel."""
    pid = "P2k-reregistration-refused"
    hub = _rphub()
    hub.register_session("s-1", [{"kind": "agent", "id": "a-1"}],
                         on_terminate=lambda r: None)
    try:
        hub.register_session("s-1", [{"kind": "agent", "id": "a-1"}],
                             on_terminate=lambda r: None)
    except RP.RevocationPushError as e:
        if "already registered" in str(e):
            _held(pid, "re-registration refused (no callback swap)")
            return
        _break(pid, "wrong refusal: %r" % (e,))
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong exception: %r" % (e,))
    else:
        _break(pid, "re-registration accepted: kill channel neuterable")


# ---------------------------------------------------------------------------
# P3: F417 OPEN-state pin. P4: F418 closure. P5: honesty pins.
# ---------------------------------------------------------------------------

def P3a():
    """F417 (CLOSED 2026-10-05, wave-334 lane 1): a non-numeric URL port
    is now guarded in _normalize_url and codes
    mcp-oauth-metadata-malformed. HELD = the coded refusal holds.
    BREAK = bare ValueError regresses or a different code."""
    pid = "P3a-f417-closed-coded"
    sealed = mob.seal_as_binding("https://as.example.com", "w334-client",
                                 _MKEY)
    try:
        mob.validate_authorization_response(
            sealed, {"iss": "https://as.example.com:badport"}, _MKEY)
    except mob.McpOAuthError as e:
        if e.code == "mcp-oauth-metadata-malformed":
            _held(pid, "F417 CLOSED: coded mcp-oauth-metadata-malformed")
        else:
            _break(pid, "wrong code: %r" % (e.code,))
    except ValueError as e:
        _break(pid, "bare ValueError regressed: %r" % (e,))
    except Exception as e:  # noqa: BLE001
        _break(pid, "unexpected exception type: %r" % (e,))
    else:
        _break(pid, "no refusal at all on bad port")


def P4a():
    """F418 (CLOSED wave-333 lane 4): a signed credential-revoked event
    terminates a bound in-flight session coded
    revocation-push-session-terminated."""
    pid = "P4a-f418-closure-holds"
    hub = _rphub()
    stopped = []
    hub.register_session("sess-1", [{"kind": "credential", "id": "cred-9"}],
                         on_terminate=lambda r: stopped.append(r))
    evt = RP.sign_event(_RPKEY, _rpevent(
        event_id="evt-f418-00001", event_type=RP.EVENT_TYPES[0],
        kind="credential", sid="cred-9", reason="key compromise"))
    rcpt = hub.ingest(evt)
    if rcpt["code"] != "revocation-push-session-terminated":
        _break(pid, "receipt code %r" % (rcpt["code"],))
        return
    if not stopped or hub.session_status("sess-1") != "terminated":
        _break(pid, "session not terminated")
        return
    try:
        hub.require_live("sess-1")
    except RP.RevocationPushSessionTerminatedError:
        _held(pid, "F418 closure holds: kill channel terminates coded")
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong refusal: %r" % (e,))
    else:
        _break(pid, "terminated session passed require_live")


def P5a():
    """Pin honesty: taxonomy is 2131/2131/0, sorted and unique on raw
    source literals (wave-260 lesson: assert on literals, not the
    deduped dict)."""
    pid = "P5a-pin-taxonomy-2131-sorted"
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    codes = re.findall(r'"code":\s*[\'"]([^\'"]+)[\'"]', src)
    if len(codes) != TAXONOMY_PIN:
        _break(pid, "literal count %d != pin %d" % (len(codes),
                                                   TAXONOMY_PIN))
        return
    if len(set(codes)) != TAXONOMY_PIN:
        _break(pid, "duplicate code literals present")
        return
    if sorted(codes) != codes:
        _break(pid, "literals not sorted")
        return
    _held(pid, "taxonomy 2131/2131/0 sorted unique on raw literals")


def P5b():
    """All 15 wave-333 codes centrally registered (wave-329 lesson:
    vocab-scan presence is not registration)."""
    pid = "P5b-new-codes-registered"
    from gov import decision_codes as dc
    missing = []
    for c in list(_NEW_CAP_CODES) + list(RP.registered_codes()):
        try:
            dc.code_for(c)
        except Exception:  # noqa: BLE001
            missing.append(c)
    if missing:
        _break(pid, "codes not centrally registered: %r" % (missing,))
        return
    _held(pid, "7 capability-token-* + 8 revocation-push-* registered")


def P5c():
    """Footer honesty: open none / next F430 (raw literals included --
    wave-331 lesson)."""
    pid = "P5c-footer-open-f429-next-f430"
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    m_open = re.findall(r"Open findings: ([^*]*)\.", text)
    ok = ("Next free finding: **F430**" in text
          and m_open and m_open[-1].strip() == "F429")
    if ok:
        _held(pid, "footer: open none / next F430")
    else:
        _break(pid, "footer mismatch vs open none / next F430")

_PROBES = [
    ("P1a-nul-in-join-fields", P1a),
    ("P1b-digest-preimage-confusion", P1b),
    ("P1c-key-order-games", P1c),
    ("P1d-inner-token-swap", P1d),
    ("P1e-seal-strip-digest-tamper", P1e),
    ("P1f-cross-context-replay-dead", P1f),
    ("P1g-toolset-normalization-edges", P1g),
    ("P1h-unicode-lookalike-fields", P1h),
    ("P2a-unsigned-event-refused", P2a),
    ("P2b-forged-signature-refused", P2b),
    ("P2c-replay-idempotent", P2c),
    ("P2d-subject-confusion", P2d),
    ("P2e-callback-exception-suspends", P2e),
    ("P2f-liveness-spoof-suspends", P2f),
    ("P2g-replay-cache-eviction", P2g),
    ("P2h-nan-issued-at", P2h),
    ("P2i-future-issued-at", P2i),
    ("P2j-unknown-session-refused", P2j),
    ("P2k-reregistration-refused", P2k),
    ("P3a-f417-closed-coded", P3a),
    ("P4a-f418-closure-holds", P4a),
    ("P5a-pin-taxonomy-2131-sorted", P5a),
    ("P5b-new-codes-registered", P5b),
    ("P5c-footer-open-f429-next-f430", P5c),
]

# No expected BREAKs on this tree: every attack shape above is refused
# coded (or pinned as a documented state). Never {} (wave-331 lesson).
_EXPECTED_BREAKS = set()


def _run_root():
    d = os.path.join(tempfile.gettempdir(), "w334red")
    if not os.path.isdir(d):
        os.makedirs(d)
    return d


def _run_child_output(battery, timeout=900):
    """Run a prior battery as a subprocess; return its raw stdout.

    GOV_SKIP_GREEN=1 in the child env (depth-1 green checks), fresh
    TMPDIR per child. Raises on timeout; returns text otherwise.
    """
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    tmpd = tempfile.mkdtemp(prefix="w334redchild-", dir=_run_root())
    env["TMPDIR"] = tmpd
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO, "evals", battery)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, cwd=REPO)
    return proc.stdout.decode("utf-8", "replace")


# Battery -> BREAK probe IDs that are NOT regressions on this tree.
# w333_redteam documents F417 OPEN (P1j expected break); its P7a already
# cascades the older batteries in child mode. The other two batteries
# are 0-break on this tree.
_CHILD_EXPECTED = {
    "w333_redteam_probes.py": {"P1j-oauth-malformed-port-uncoded"},
    "w333_captoken_probes.py": set(),
    "w333_revpush_probes.py": set(),
}


def _green_check():
    """Depth-1 green check on the adjacent batteries (fail-closed).

    Honors GOV_SKIP_GREEN (records a skip instead of spawning). Never
    spawns a battery that spawns another: depth-1 only (wave-95/row-12
    lesson).
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    for battery, expected in _CHILD_EXPECTED.items():
        try:
            out = _run_child_output(battery)
        except Exception as exc:  # noqa: BLE001
            _record("green-check", "ERROR", "%s: %s" % (battery, exc))
            continue
        breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
        if m2:
            try:
                import ast as _ast
                breaks.update(_ast.literal_eval(m2.group(1)))
            except Exception:  # noqa: BLE001
                pass
        outside = breaks - expected
        if errors or outside:
            _record("green-check", "BREAK",
                    "%s: non-expected %s" % (battery, sorted(outside | errors)[:4]))
        else:
            _record("green-check", "HELD",
                    "%s: %d breaks, all expected" % (battery, len(breaks)))


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    # Collect EVERY record each probe emits (probes record multiple
    # sub-results); tallying only the last record per probe would miss
    # a BREAK buried mid-probe.
    del _results[:]
    for pid, fn in _PROBES:
        if only and only not in pid:
            continue
        _safe(pid, fn)
    first = list(_results)
    green = None
    if only is None:
        _green_check()
        green = _results[-1]
    del _results[:]
    for pid, fn in _PROBES:
        if only and only not in pid:
            continue
        _safe(pid, fn)
    second = list(_results)
    # Determinism compares probe verdicts only; the green-check record
    # is a single-runner observation, not a probe.
    det = ([v for _, v, _ in first] == [v for _, v, _ in second])
    tallied = first + ([green] if green else [])
    n_break = sum(1 for _, v, _ in tallied if v == "BREAK")
    n_held = sum(1 for _, v, _ in tallied if v == "HELD")
    n_err = sum(1 for _, v, _ in tallied if v == "ERROR")
    probe_breaks = {pid for pid, v, _ in tallied
                    if v == "BREAK" and pid != "green-check"}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("----")
    print("w334_redteam battery: %d BREAK / %d HELD / %d ERROR "
          "(deterministic across 2 runs: %s)"
          % (n_break, n_held, n_err, det))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    if not det:
        print("NON-DETERMINISTIC across runs -- do not trust")
        return 2
    if n_err:
        print("ERRORs present -- battery failed closed")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
