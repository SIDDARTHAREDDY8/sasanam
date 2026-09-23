"""Wave-65 D5 probes (2026-09-22): acknowledgment audit trail pins.

Wave-64 shipped the Unvetted/Vetted marker as advisory-with-teeth; its
open question was whether acknowledge() sink records feed the
hash-chained audit log. Wave-65 answers yes via the standing drain
convention (sterile.py never owns the log; the log owner drains):
``AckAuditSink`` (flood-budgeted, count-preserving) + executor-stamped
``ack_context`` (window/run correlation through the JSON envelope) +
``ToolExecutor.drain_ack_sink`` (peek-confirm; reserved run keys win).

Pins registered here (registry.yaml, ``redteam.sterile_d5_ack.*``),
all closure: green (the control holds; probes assert it keeps
holding):
  flood_budget_holds            — 5000 distinct acks -> 256 records +
      one exact-count overflow summary; chain growth bounded; verifies
  injection_escaped             — newline/control-char consumer_id and
      window id cannot break the JSONL framing (single writer choke
      point); values round-trip identically
  forged_run_context_neutralized— forged run_id/agent_id/role in an ack
      record do not survive the drain (log-wins)
  record_unwrap_ordering        — record-then-unwrap: a raising sink
      withholds the payload; no record-without-unwrap via acknowledge()
  drain_failure_keeps_evidence  — LogFullError at drain leaves the
      record in the sink (peek-confirm); nothing silently dropped
  legit_ack_trail               — end-to-end no-regression: close ->
      envelope with ack_context -> downstream ack -> drain -> chain
      verifies; wave-64 contract fields unchanged

All runs synthetic/local, $0. Deterministic per probe run_id. Env
hygiene restores every mutated variable in finally.
"""

import contextlib
import json
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
# Import the test harness WITHOUT running tests/__init__.py (which flips
# on the dev-key opt-in process-wide); dev keys are enabled per-probe
# with _env()+_dev_keys() instead, and restored afterwards.
sys.path.insert(0, str(REPO_ROOT / "tests"))

import harness  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov import sterile as st_mod  # noqa: E402

RESULTS = []
SITUATIONS = {}


@contextlib.contextmanager
def _env(**pairs):
    saved = {k: os.environ.get(k) for k in pairs}
    had = {k: k in os.environ for k in pairs}
    for k, v in pairs.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k in pairs:
            if had[k]:
                os.environ[k] = saved[k]
            else:
                os.environ.pop(k, None)


@contextlib.contextmanager
def _dev_keys(enabled=True):
    """Wave-81: explicit test-key provisioning.

    Replaces the deleted gov.log dev-key opt-in. With enabled=True,
    yields with an explicit random GOV_LOG_KEY/GOV_LOG_KEY_EPOCH set
    and GOV_LOG_KEY_ARCHIVE cleared, restoring everything afterwards.
    enabled=False is a plain passthrough (no key provisioned).
    """
    if not enabled:
        yield
        return
    import secrets as _secrets
    _saved = {n: os.environ.get(n) for n in (
        "GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")}
    _had = {n: n in os.environ for n in _saved}
    os.environ["GOV_LOG_KEY"] = _secrets.token_hex(32)
    os.environ["GOV_LOG_KEY_EPOCH"] = "test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)
    try:
        yield
    finally:
        for _n in _saved:
            if _had[_n]:
                os.environ[_n] = _saved[_n]
            else:
                os.environ.pop(_n, None)
def _govrun():
    d = tempfile.mkdtemp(prefix="steriled5reg65-")
    old = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = d
    tempfile.tempdir = d
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old
        tempfile.tempdir = old_cached


_govrun = contextlib.contextmanager(_govrun)


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                with _govrun():
                    with _dev_keys(True):
                        detail = fn()
                if not isinstance(detail, dict):
                    detail = {"note": str(detail)}
                verdict = detail.pop("verdict", "stopped")
                RESULTS.append({"id": sid, "verdict": verdict,
                                "detail": detail})
            except Exception as e:  # noqa: BLE001 - probe must not die
                RESULTS.append({"id": sid, "verdict": "error",
                                "detail": {"error": "%s: %s"
                                           % (type(e).__name__, e)}})
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


class FakeLoop(st_mod.LoopContract):
    def freeze_context(self, snapshot_ref):
        return None

    def withhold(self, channel):
        return None

    def release(self, channel):
        return None

    def reissue_reads(self, reads):
        return [{"tool": t, "channel": c, "result_summary": "reissued",
                 "delta_vs_snapshot": False} for t, c in reads]


_POLICY = """\
version: 2
roles:
  researcher: [read_file, write_file, api_call, http_post, send_email]
approvals:
  ttl_hours: 24
critical_windows:
  - id: pay
    on_tools: ["http_post"]
    suspend: [web_fetch]
    close_policy: agent_declared
    max_duration_s: 300
    rationale: "test"
policies: []
"""


def _run_with_window():
    d = tempfile.mkdtemp(prefix="w65probe-")
    path = os.path.join(d, "policy.yaml")
    with open(path, "w") as f:
        f.write(_POLICY)
    run = harness.make_run(policy_path=path)
    ident = run["mint_identity"]("agent-1", "researcher", "op-1")
    return run, ident


def _drive_and_close():
    run, ident = _run_with_window()
    ex = run["executor"]
    ex.attach_loop_contract(FakeLoop())
    ex.call(ident, "http_post", url="https://synthetic.local/x", data="d")
    ex.call(ident, "api_call", endpoint="https://synthetic.local/v1",
            params={"q": 1})
    for rec in ex.approvals.pending():
        ex.approvals.decide(rec["id"], True, "test")
    out = ex.request_window_close(ident)
    assert out.get("closed"), "legitimate close failed: %r" % (out,)
    return run


@_sit("redteam.sterile_d5_ack.flood_budget_holds")
def sit_flood_budget_holds():
    """D5-ack pin: 5000 distinct acks collapse to 256 records + one
    exact-count overflow summary; nothing silently dropped; the drained
    trail verifies in the hash chain."""
    sink = st_mod.AckAuditSink(now=lambda: 1.0)
    n = 5000
    for i in range(n):
        st_mod.Unvetted([i]).acknowledge("c%d" % i, sink)
    if sink.pending() != 257:
        return {"verdict": "break",
                "note": "budget violated: pending=%d" % sink.pending()}
    summary = sink._records[-1]
    accounted = (sum(r.get("count", 1) for r in sink._records
                     if r["event"] == "unvetted_acknowledged")
                 + summary["dropped"])
    if summary["dropped"] != n - 256 or accounted != n:
        return {"verdict": "break",
                "note": "counts inexact: dropped=%r accounted=%d"
                        % (summary.get("dropped"), accounted)}
    run, _ = _run_with_window()
    ex = run["executor"]
    ex.drain_ack_sink(sink)
    v = log_mod._verify(run["log"].path)
    if not v["ok"]:
        return {"verdict": "break",
                "note": "chain failed after drain: %s" % v.get("error")}
    return {"verdict": "stopped",
            "note": "5000 acks -> 257 records, exact counts, verifies"}


@_sit("redteam.sterile_d5_ack.injection_escaped")
def sit_injection_escaped():
    """D5-ack pin: hostile consumer_id / window id (newlines, control
    chars) cannot break JSONL framing — one physical line per record,
    values round-trip identically, chain verifies."""
    evil_id = "dash\n{\"event\": \"forged\"}\nboard\x00\x1b[31m"
    evil_window = "w\nSEQ=999\r\n"
    sink = st_mod.AckAuditSink(now=lambda: 1.0)
    u = st_mod.Unvetted(["p"], ack_context={"window": evil_window,
                                            "run_id": "r1"})
    u.acknowledge(evil_id, sink)
    run, _ = _run_with_window()
    run["executor"].drain_ack_sink(sink)
    bad, found = 0, None
    for ln in open(run["log"].path, encoding="utf-8").read().splitlines():
        if not ln.strip():
            continue
        try:
            e = json.loads(ln)
        except ValueError:
            bad += 1
            continue
        if e.get("event") == "unvetted_acknowledged":
            found = e
    v = log_mod._verify(run["log"].path)
    if bad or not found or found["consumer"] != evil_id \
            or found["ack_context"]["window"] != evil_window \
            or not v["ok"]:
        return {"verdict": "break",
                "note": "bad=%d consumer=%r ok=%s"
                        % (bad, (found or {}).get("consumer"),
                           v["ok"])}
    return {"verdict": "stopped",
            "note": "injection escaped by the single writer choke point"}


@_sit("redteam.sterile_d5_ack.forged_run_context_neutralized")
def sit_forged_run_context_neutralized():
    """D5-ack pin: forged run_id/agent_id/role inside an ack record do
    not survive the drain — the executor re-stamps them (log-wins)."""
    run, _ = _run_with_window()
    ex = run["executor"]
    evil = {"event": "unvetted_acknowledged", "consumer": "mallory",
            "run_id": "evil-run", "agent_id": "evil-agent",
            "role": "evil-role", "origin": "reissue_reads",
            "ack_context": {}, "count": 1, "ts": 1.0}
    n = ex.drain_ack_sink([evil])
    entries = [e for e in log_mod.read_entries(run["log"].path)
               if e.get("event") == "unvetted_acknowledged"]
    if n != 1 or not entries or entries[0]["run_id"] != ex.run_id \
            or entries[0]["agent_id"] == "evil-agent" \
            or entries[0]["role"] == "evil-role":
        return {"verdict": "break",
                "note": "forged run context survived the drain"}
    return {"verdict": "stopped",
            "note": "drain re-stamps reserved run keys (log-wins)"}


@_sit("redteam.sterile_d5_ack.record_unwrap_ordering")
def sit_record_unwrap_ordering():
    """D5-ack pin: record-then-unwrap is atomic through acknowledge() —
    a sink whose append raises withholds the payload (no
    record-without-unwrap); a recording sink shows append-before-return."""
    order = []

    class Rec(list):
        def append(self, rec):
            order.append("record")
            super().append(rec)

    class Boom:
        def append(self, rec):
            raise IOError("boom")

    s = Rec()
    out = st_mod.Unvetted(["p"]).acknowledge("c", s)
    if order != ["record"] or out != ["p"] or len(s) != 1:
        return {"verdict": "break", "note": "ordering violated"}
    try:
        st_mod.Unvetted(["p"]).acknowledge("c", Boom())
        return {"verdict": "break",
                "note": "raising sink still returned payload"}
    except IOError:
        return {"verdict": "stopped",
                "note": "record implies unwrap; raising sink is loud"}


@_sit("redteam.sterile_d5_ack.drain_failure_keeps_evidence")
def sit_drain_failure_keeps_evidence():
    """D5-ack pin: a failed drain (LogFullError) leaves the record in
    the sink (peek-confirm) — evidence is never silently dropped; the
    run fails closed per F22."""
    run, _ = _run_with_window()
    ex = run["executor"]
    sink = st_mod.AckAuditSink(now=lambda: 1.0)
    st_mod.Unvetted(["p"]).acknowledge("c", sink)
    ex.log.configure_guard(1)  # next append must fail
    try:
        ex.drain_ack_sink(sink)
        return {"verdict": "break",
                "note": "drain did not fail closed on full log"}
    except log_mod.LogFullError:
        pass
    if sink.pending() != 1:
        return {"verdict": "break",
                "note": "record lost on failed drain"}
    ex.log.configure_guard(None)
    if ex.drain_ack_sink(sink) != 1 or sink.pending() != 0:
        return {"verdict": "break", "note": "retry drain failed"}
    return {"verdict": "stopped",
            "note": "peek-confirm keeps evidence; fail-closed loud"}


@_sit("redteam.sterile_d5_ack.legit_ack_trail")
def sit_legit_ack_trail():
    """D5-ack pin (no-regression + trail): close -> envelope carries
    executor-stamped ack_context -> downstream ack -> drain -> chain
    verifies; wave-64 contract fields unchanged; return shape intact."""
    run = _drive_and_close()
    ex = run["executor"]
    exits = [e for e in log_mod.read_entries(run["log"].path)
             if e.get("event") == "sterile_window_exit"]
    deltas = [e for e in exits if e.get("post_window_delta")]
    if len(deltas) != 1:
        return {"verdict": "break", "note": "no delta stashed"}
    u = st_mod.Unvetted.from_envelope(deltas[0]["post_window_delta"])
    if u._ack_context.get("window") != "pay":
        return {"verdict": "break",
                "note": "ack_context not stamped: %r" % (u._ack_context,)}
    sink = st_mod.AckAuditSink(now=lambda: 1.0)
    payload = u.acknowledge("review-dashboard", sink)
    n = ex.drain_ack_sink(sink)
    v = log_mod._verify(run["log"].path)
    acks = [e for e in log_mod.read_entries(run["log"].path)
            if e.get("event") == "unvetted_acknowledged"]
    if n != 1 or not v["ok"] or len(acks) != 1 \
            or acks[0]["consumer"] != "review-dashboard" \
            or acks[0]["ack_context"]["window"] != "pay" \
            or payload[0]["tool"] != "api_call":
        return {"verdict": "break",
                "note": "trail broken: n=%d ok=%s acks=%d"
                        % (n, v["ok"], len(acks))}
    return {"verdict": "stopped",
            "note": "end-to-end ack trail works; chain verifies"}
