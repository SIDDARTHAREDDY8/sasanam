"""Wave-243 obsigna attested-channel discipline probes (W243-6, red-first).

ADAPT, pattern only, prose re-derived: the daemon signs *emitter
claims*, not observations. It vouches only for what it can attest
itself: kernel-attested peer identity (uid/gid/pid/exe, supplied by
the admission layer, never the emitter), its own timestamp (never the
emitter's ``ts_emit``), the admission chain position (per-peer
sequence), and the canonical-byte digest of the admitted record.
Everything semantic is emitter-claimed and only structurally
validated. Tamper-evidence is emergent (chain position + canonical
digests). No upstream code is read, imported, or vendored
(Apache-2.0, disciplines only).

Probes:
  attested-admit-happy-path -- full admission: daemon timestamp is
      authoritative, divergence is recorded, the record separates
      observations (peer_identity, daemon_ts, seq, canonical_digest)
      from emitter claims.
  attested-unattested-principal-refused -- self-reported principal
      with NO attested peer identity refuses
      channel-identity-unattested (never downgraded).
  attested-peer-mismatch-refused -- attested peer block naming a
      different principal refuses channel-peer-mismatch.
  attested-timestamp-wins-and-recorded -- ts_emit 60s behind daemon
      time: admitted, daemon_ts wins, time_divergence_seconds == 60
      recorded (falsifies timestamp forgery without refusing skew).
  attested-forged-timestamp-refused -- ts_emit 90000s behind daemon
      time refuses channel-timestamp-divergence.
  attested-key-in-agent-process-refused -- declared key location
      "agent-process" refuses key-in-agent-process (architectural,
      not advisory).
  attested-sequence-break-refused -- replayed seq refuses
      channel-sequence-break; the next expected seq admits.
  attested-sink-verbatim-audit -- ForwardCompatSink stores verbatim
      bytes and verifies at audit time; a tampered stored blob
      refuses at audit (the sink never reinterprets).

Stdlib only. Deterministic: every clock injected. No in-repo git
subprocesses.
"""

import io
import json
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import attested_channel as _ac
    HAVE_NEW_API = all(hasattr(_ac, n) for n in (
        "ChannelAdmission", "ForwardCompatSink",
        "AttestedChannelError", "SKEW_TOLERANCE_SECONDS",
        "FORGERY_BOUND_SECONDS"))
except ImportError:
    _ac = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

NOW = 1700000000.0
PEER = {"uid": 1000, "gid": 1000, "pid": 4242, "exe": "/usr/bin/agent",
        "principal": "agent-7"}

PROBE_NAMES = [
    "attested-admit-happy-path",
    "attested-unattested-principal-refused",
    "attested-peer-mismatch-refused",
    "attested-timestamp-wins-and-recorded",
    "attested-forged-timestamp-refused",
    "attested-key-in-agent-process-refused",
    "attested-sequence-break-refused",
    "attested-sink-verbatim-audit",
]


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    """fn must raise AttestedChannelError with .code == code."""
    try:
        fn()
    except _ac.AttestedChannelError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


def _claim(principal="agent-7", ts_emit=NOW, seq=0, payload=None):
    return {"principal": principal, "ts_emit": ts_emit, "seq": seq,
            "payload": {"action": "read", "target": "file:///etc/x"}
            if payload is None else payload}


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_happy_path():
    adm = _ac.ChannelAdmission()
    rec = adm.admit(_claim(ts_emit=NOW - 60), dict(PEER), "daemon", NOW)
    assert rec["daemon_ts"] == NOW, "daemon time not authoritative"
    assert rec["time_divergence_seconds"] == 60, "divergence not recorded"
    assert rec["ts_emit"] == NOW - 60, "emitter claim time must be kept"
    for obs in ("peer_identity", "daemon_ts", "seq",
                "canonical_digest"):
        assert obs in rec["observations"], "observation %r missing" % obs
    assert rec["claims"] == {"action": "read",
                             "target": "file:///etc/x"}
    assert rec["principal"] == "agent-7"
    assert rec["peer_identity"]["pid"] == 4242
    digest = rec["canonical_digest"]
    assert isinstance(digest, str) and len(digest) == 64
    return "admitted; daemon time wins; divergence recorded; " \
        "observations separated from claims"


def _probe_unattested_refused():
    adm = _ac.ChannelAdmission()
    return _expect_refusal(
        lambda: adm.admit(_claim(), None, "daemon", NOW),
        "channel-identity-unattested")


def _probe_peer_mismatch_refused():
    adm = _ac.ChannelAdmission()
    other = dict(PEER)
    other["principal"] = "agent-9"
    return _expect_refusal(
        lambda: adm.admit(_claim(principal="agent-7"), other, "daemon",
                          NOW),
        "channel-peer-mismatch")


def _probe_timestamp_wins():
    adm = _ac.ChannelAdmission()
    rec = adm.admit(_claim(ts_emit=NOW - 60), dict(PEER), "daemon", NOW)
    assert rec["daemon_ts"] == NOW, "daemon timestamp must win"
    assert rec["time_divergence_seconds"] == 60, \
        "divergence of 60s must be recorded, not refused"
    return "daemon timestamp authoritative; 60s divergence recorded"


def _probe_forged_timestamp_refused():
    adm = _ac.ChannelAdmission()
    return _expect_refusal(
        lambda: adm.admit(_claim(ts_emit=NOW - 90000), dict(PEER),
                          "daemon", NOW),
        "channel-timestamp-divergence")


def _probe_key_in_agent_process_refused():
    adm = _ac.ChannelAdmission()
    note = _expect_refusal(
        lambda: adm.admit(_claim(), dict(PEER), "agent-process", NOW),
        "key-in-agent-process")
    # Accepted external locations admit fine.
    rec = adm.admit(_claim(), dict(PEER), "external-kms", NOW)
    assert rec["principal"] == "agent-7"
    return "%s; external-kms admits" % note


def _probe_sequence_break_refused():
    adm = _ac.ChannelAdmission()
    adm.admit(_claim(seq=0), dict(PEER), "daemon", NOW)
    note = _expect_refusal(
        lambda: adm.admit(_claim(seq=0), dict(PEER), "daemon", NOW),
        "channel-sequence-break")
    rec = adm.admit(_claim(seq=1), dict(PEER), "daemon", NOW)
    assert rec["seq"] == 1
    return "%s; next expected seq admits" % note


def _probe_sink_verbatim_audit():
    sink = _ac.ForwardCompatSink()
    raw = json.dumps(_claim(ts_emit=NOW - 10), sort_keys=True)
    sink.collect(raw)
    assert len(sink) == 1
    # The stored blob is byte-identical to what was presented.
    stored = sink._blobs[0]
    assert stored == raw.encode("utf-8"), "sink must store verbatim"
    by_principal = {"agent-7": dict(PEER)}
    records = sink.audit(lambda stored_rec: by_principal[
        stored_rec["principal"]], "daemon", NOW)
    assert len(records) == 1 and records[0]["daemon_ts"] == NOW
    # A tampered stored blob refuses at audit time (ingest digest
    # commitment: the sink committed to the exact bytes at ingest).
    sink2 = _ac.ForwardCompatSink()
    bad = json.dumps(_claim(ts_emit=NOW - 10), sort_keys=True)
    sink2.collect(bad)
    tampered = dict(json.loads(bad))
    tampered["payload"] = {"action": "delete", "target": "/"}
    sink2._blobs[0] = json.dumps(tampered,
                                 sort_keys=True).encode("utf-8")
    try:
        sink2.audit(lambda r: dict(PEER), "daemon", NOW)
    except _ac.AttestedChannelError as exc:
        assert exc.code == "channel-record-malformed", \
            "tampered blob must refuse, got %r" % exc.code
        return "verbatim store; audit admits honest blob, refuses " \
            "tampered blob"
    raise AssertionError("tampered blob did not refuse at audit")


_PROBES = {
    "attested-admit-happy-path": _probe_happy_path,
    "attested-unattested-principal-refused":
        _probe_unattested_refused,
    "attested-peer-mismatch-refused": _probe_peer_mismatch_refused,
    "attested-timestamp-wins-and-recorded": _probe_timestamp_wins,
    "attested-forged-timestamp-refused": _probe_forged_timestamp_refused,
    "attested-key-in-agent-process-refused":
        _probe_key_in_agent_process_refused,
    "attested-sequence-break-refused": _probe_sequence_break_refused,
    "attested-sink-verbatim-audit": _probe_sink_verbatim_audit,
}


def _run_green_checks():
    """Adjacent-seam sanity: no product-code regression. Depth-1 only;
    honors GOV_SKIP_GREEN=1 (never spawns another battery's main)."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import decision_codes as _dc
        for code in ("channel-record-malformed",
                     "channel-identity-unattested",
                     "channel-peer-mismatch", "key-in-agent-process",
                     "channel-timestamp-divergence",
                     "channel-sequence-break"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-243 attested-channel probes (new API: %s)" % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, status, _ in results if status == "HELD")
    gap = sum(1 for _, status, _ in results if status == "GAP")
    for name, status, note in results:
        print("%-42s %-6s %s" % (name, status, note))
    for note in _run_green_checks():
        print("green-check: %s" % note)
    print("held=%d gap=%d total=%d" % (held, gap, len(results)))
    if HAVE_NEW_API:
        if held != len(results):
            print("RED: not all probes held")
            return 1
    else:
        if gap != len(results):
            print("RED: expected all-GAP on pristine base")
            return 1
    print("GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
