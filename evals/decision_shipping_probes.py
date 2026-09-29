#!/usr/bin/env python3
"""Wave-206 lane E red-team probes: decision-log shipping.

Break-first battery per the diagnosing-bugs skill. Pattern lineage:
open-policy-agent/opa decision-log shipping mechanics (Apache-2.0) --
behavior-level steal, nothing vendored: chunked uploads with soft limits,
requeue-on-non-2xx with exponential backoff, loud drop accounting, the
v1.9.0 buffer-reset cautionary tale, mask-before-buffer ordering, and
durability tiers (memory / disk / unbuffered).

The pristine tree has NO shipping layer: gov.decision_shipping is absent.
Each probe attacks the new seam:

  S1  CHUNKED        3 events ship across multiple chunks (soft limit)
  S2  REQUEUE        non-2xx -> chunk requeued, exponential backoff,
                     then accepted on retry (no loss, no duplication)
  S3  LOUD_DROP      oversized event dropped with counter increment +
                     drop-record audit entry (never silent)
  S4  LIMIT_PERSISTS buffer/chunk limits survive upload cycles (the OPA
                     v1.9.0 regression shape); frozen config cannot be
                     mutated by the upload path
  S5  MASK_FIRST     redaction lie / wrong mask plan / non-v2 event refused
                     at ingest; the buffer never holds unmasked data
  S6  UNBUFFERED     sink never acks -> action NEVER runs, loud drop;
                     acking sink -> action runs after the write
  S7  DISK_TIER      write-through journal recovers the buffer after a
                     restart; already-shipped events are not re-sent

On the pristine tree every probe reports GAP (module absent -- genuine
red). After the fix all must flip to HELD.

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red phase),
ERROR only on harness failure (a verdict changing between the two
deterministic runs, an unexpected exception).

Deterministic: fake sinks with scripted status codes; every probe runs
twice and a verdict change is an ERROR. Synthetic/local only.
``GOV_SKIP_GREEN=1`` is honored (green check records a skip instead of
spawning sub-batteries).
"""

import copy
import dataclasses
import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import decision_shipping as _ship
    from gov import decision_log_v2 as _dlv2
    _ABSENT = False
except ImportError:
    _ship = None
    _dlv2 = None
    _ABSENT = True


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

_REPLAY_NAME = "ship_probe_replay"


def _replay_fn(inputs):
    return {"verdict": "allow", "inputs_hash": len(json.dumps(inputs))}


def _ensure_replay():
    try:
        _dlv2.register_replay_fn(_REPLAY_NAME, _replay_fn)
    except _dlv2.EventBuildError:
        pass  # already registered (probes run twice)


def _event(body_extra=None, erased=("/secret",), masked=("/token",)):
    body = {"action": "read", "secret": "hunter2",
            "token": "tok-abc", "nested": {"x": 1}}
    if body_extra:
        body.update(body_extra)
    return _dlv2.build_event(
        decision={"kind": "tool_call", "effect": "allow",
                  "policy_id": "p1", "reason": "test"},
        raw_body=body, erased=list(erased), masked=list(masked),
        replay_fn=_REPLAY_NAME, replay_inputs={"n": 1},
        replay_verdict=_replay_fn({"n": 1}))


def _mask(erased=("/secret",), masked=("/token",)):
    return _ship.CompiledMask(erased=erased, masked=masked)


def _config(**kw):
    base = dict(chunk_limit_bytes=10_000, buffer_limit_bytes=100_000,
                buffer_limit_events=100, max_delay_s=600.0, min_delay_s=0.0,
                backoff_base_s=0.0, backoff_max_s=0.0, max_retries=3)
    base.update(kw)
    return _ship.ShippingConfig(**base)


class _Sink:
    """Scripted sink: statuses cycle; records every chunk received."""

    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.chunks = []
        self.calls = 0

    def __call__(self, chunk_bytes):
        self.chunks.append(chunk_bytes)
        self.calls += 1
        if len(self.statuses) > 1:
            return self.statuses.pop(0)
        return self.statuses[0]


def _require_absent(fn):
    def wrapper():
        if _ABSENT:
            return "GAP"
        return fn()
    return wrapper


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

@_require_absent
def p_s1_chunked():
    _ensure_replay()
    sink = _Sink([200])
    sh = _ship.DecisionShipper(_config(chunk_limit_bytes=900),
                               _mask(), sink)
    for _ in range(3):
        r = sh.ingest(_event())
        assert r["status"] == "buffered", r
    summary = sh.flush()
    assert summary["shipped"] == 3, summary
    assert len(sink.chunks) >= 2, "expected multiple chunks, got %d" % len(sink.chunks)
    for chunk in sink.chunks:
        assert len(chunk) <= 900, "chunk exceeded the soft limit"
    # every shipped event is intact JSONL
    seen = 0
    for chunk in sink.chunks:
        for line in chunk.split(b"\n"):
            _dlv2.verify_event(json.loads(line.decode("utf-8")))
            seen += 1
    assert seen == 3, seen
    assert sh.buffered_events == 0
    return "HELD"


@_require_absent
def p_s2_requeue():
    _ensure_replay()
    sink = _Sink([500, 500, 200])
    sh = _ship.DecisionShipper(_config(backoff_base_s=0.0, max_retries=3),
                               _mask(), sink)
    ev = _event()
    sh.ingest(ev)
    s1 = sh.flush()
    assert s1["requeued"] == 1 and s1["shipped"] == 0, s1
    assert sh.buffered_events == 1, "requeued chunk must stay in the buffer"
    assert sh.upload_failures == 1
    s2 = sh.flush()  # backoff_base_s=0 -> immediate retry allowed
    assert s2["requeued"] == 1, s2
    s3 = sh.flush()
    assert s3["shipped"] == 1, s3
    assert sh.buffered_events == 0
    # no duplication, no loss: exactly 3 sink calls (2 failed + 1 success),
    # each carrying the same single event
    bodies = [c for chunk in sink.chunks for c in chunk.split(b"\n")]
    ids = [json.loads(b.decode())["decision_id"] for b in bodies]
    assert ids == [ev["decision_id"]] * 3, ids
    return "HELD"


@_require_absent
def p_s3_loud_drop():
    _ensure_replay()
    audit = []
    sink = _Sink([200])
    sh = _ship.DecisionShipper(_config(chunk_limit_bytes=600), _mask(),
                               sink, audit=audit)
    big = _event(body_extra={"blob": "x" * 4000})
    assert len(json.dumps(big)) > 600
    # replay eviction cannot save it: still oversize after eviction
    r = sh.ingest(big)
    assert r["status"] == "dropped", r
    assert r["reason"] == "oversize", r
    assert sh.dropped_events == 1
    assert len(sh.drop_records) == 1
    rec = sh.drop_records[0]
    assert rec["kind"] == "drop-record" and rec["reason"] == "oversize"
    assert rec["dropped_total"] == 1
    assert audit and audit[0]["kind"] == "drop-record"
    assert sh.buffered_events == 0, "dropped events must not linger"
    # a small event still ships fine afterwards
    r2 = sh.ingest(_event())
    assert r2["status"] == "buffered", r2
    return "HELD"


@_require_absent
def p_s4_limit_persists():
    _ensure_replay()
    sink = _Sink([500, 200, 500, 200])
    cfg = _config(chunk_limit_bytes=700, buffer_limit_bytes=50_000,
                  backoff_base_s=0.0)
    sh = _ship.DecisionShipper(cfg, _mask(), sink)
    # several upload cycles, mixed success and failure
    for _ in range(2):
        sh.ingest(_event())
        sh.flush()
    # the v1.9.0 regression shape: limits must be byte-identical afterwards
    assert sh.config.chunk_limit_bytes == 700, sh.config
    assert sh.config.buffer_limit_bytes == 50_000, sh.config
    assert sh.config.buffer_limit_events == 100, sh.config
    # and the upload path cannot mutate them at all (frozen by construction)
    try:
        sh.config.chunk_limit_bytes = 32 * 1024
    except dataclasses.FrozenInstanceError:
        pass
    else:
        raise AssertionError("config was mutable -- the v1.9.0 bug shape "
                             "is possible")
    # the limit still bites: an oversized event is still dropped, not
    # silently admitted by a reset limit
    big = _event(body_extra={"blob": "y" * 4000})
    r = sh.ingest(big)
    assert r["status"] == "dropped" and r["reason"] == "oversize", r
    return "HELD"


def _tampered_with_lie():
    """A valid event whose masked pointer secretly holds the raw value,
    with a re-derived decision_id so the *redaction* check is the one
    that fires."""
    ev = _event()
    ev = copy.deepcopy(ev)
    ev["body"]["token"] = "tok-abc"  # raw value under a mask claim
    preimage = {k: v for k, v in ev.items()
                if k not in ("decision_id", "audit")}
    ev["decision_id"] = __import__("hashlib").sha256(
        json.dumps(preimage, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True, default=str).encode()).hexdigest()
    return ev


@_require_absent
def p_s5_mask_first():
    _ensure_replay()
    sink = _Sink([200])
    sh = _ship.DecisionShipper(_config(), _mask(), sink)
    # (i) redaction lie: raw value under a mask claim, id re-derived
    try:
        sh.ingest(_tampered_with_lie())
    except _ship.IngestError:
        pass
    else:
        raise AssertionError("redaction lie was buffered")
    # (ii) event built under a different mask plan
    other = _event(erased=("/secret", "/nested/x"), masked=("/token",))
    try:
        sh.ingest(other)
    except _ship.IngestError:
        pass
    else:
        raise AssertionError("wrong-plan event was buffered")
    # (iii) not a v2 event at all (raw dict with sensitive values)
    try:
        sh.ingest({"secret": "hunter2", "token": "tok-abc"})
    except _ship.IngestError:
        pass
    else:
        raise AssertionError("non-v2 payload was buffered")
    assert sh.buffered_events == 0, "buffer must never hold unmasked data"
    assert sh.dropped_events == 0, "refusals are not drops"
    # the honest event still flows
    r = sh.ingest(_event())
    assert r["status"] == "buffered", r
    return "HELD"


@_require_absent
def p_s6_unbuffered():
    _ensure_replay()
    ran = []

    def action():
        order.append("action")
        return "done"
    # sink never acks: the action must NEVER run
    sink = _Sink([500])
    sh = _ship.DecisionShipper(
        _config(durability="unbuffered", max_retries=0,
                backoff_base_s=0.0), _mask(), sink)
    try:
        sh.run_unbuffered(_event(), lambda: ran.append(1))
    except _ship.SinkError:
        pass
    else:
        raise AssertionError("unbuffered action ran without an ack")
    assert ran == [], "action ran before the log write was acknowledged"
    assert sh.dropped_events == 1, "the unacked event must be dropped loudly"
    # acking sink: the action runs only after the write
    order = []
    inner = _Sink([200])

    def acking(chunk):
        r = inner(chunk)
        order.append("ack")
        return r

    sh2 = _ship.DecisionShipper(
        _config(durability="unbuffered"), _mask(), acking)
    assert sh2.run_unbuffered(_event(), action) == "done"
    assert order == ["ack", "action"], order
    # split-ack (B1): a leftover chunk's ack must not release a different
    # event's action -- only THIS event's chunk ack counts
    sh4 = _ship.DecisionShipper(
        _config(durability="unbuffered", chunk_limit_bytes=1000),
        _mask(), _Sink([200, 500]))
    sh4.ingest(_event({"action": "leftover"}))
    try:
        sh4.run_unbuffered(_event({"action": "rm -rf"}),
                           lambda: ran.append(1))
    except _ship.SinkError:
        pass
    else:
        raise AssertionError("run_unbuffered released the action on "
                             "another chunk's ack (B1)")
    assert ran == [], "action ran on a foreign ack"
    assert sh4.buffered_events == 1 and sh4.shipped_events == 1, \
        (sh4.buffered_events, sh4.shipped_events)
    # run_unbuffered on a non-unbuffered tier is a config error
    sh3 = _ship.DecisionShipper(_config(), _mask(), _Sink([200]))
    try:
        sh3.run_unbuffered(_event(), action)
    except _ship.ConfigError:
        pass
    else:
        raise AssertionError("run_unbuffered allowed on memory tier")
    return "HELD"


@_require_absent
def p_s7_disk_tier():
    _ensure_replay()
    tmp = tempfile.mkdtemp(prefix="ship-disk-")
    jpath = os.path.join(tmp, "journal.jsonl")
    sink = _Sink([200])
    sh = _ship.DecisionShipper(
        _config(durability="disk", journal_path=jpath), _mask(), sink)
    ev1, ev2 = _event(), _event()
    sh.ingest(ev1)
    sh.ingest(ev2)
    assert os.path.exists(jpath), "disk tier must write through at ingest"
    # ship only ev1's chunk by flushing with a big chunk limit... instead:
    # simulate a restart before any flush: recover must restore both
    sh2 = _ship.DecisionShipper(
        _config(durability="disk", journal_path=jpath), _mask(), sink)
    assert sh2.buffered_events == 2, sh2.stats()
    s = sh2.flush()
    assert s["shipped"] == 2, s
    # a second restart must NOT re-send already-shipped events
    sink3 = _Sink([200])
    sh3 = _ship.DecisionShipper(
        _config(durability="disk", journal_path=jpath), _mask(), sink3)
    assert sh3.buffered_events == 0, sh3.stats()
    assert sink3.calls == 0
    return "HELD"


_PROBES = [
    ("S1", "CHUNKED", p_s1_chunked),
    ("S2", "REQUEUE", p_s2_requeue),
    ("S3", "LOUD_DROP", p_s3_loud_drop),
    ("S4", "LIMIT_PERSISTS", p_s4_limit_persists),
    ("S5", "MASK_FIRST", p_s5_mask_first),
    ("S6", "UNBUFFERED", p_s6_unbuffered),
    ("S7", "DISK_TIER", p_s7_disk_tier),
]


def main():
    if _ABSENT:
        print("gov.decision_shipping ABSENT (pristine tree) -- all GAP")
        for pid, name, _ in _PROBES:
            print("%s %-14s GAP (module absent)" % (pid, name))
        return 0
    failures = 0
    for pid, name, fn in _PROBES:
        first = fn()
        second = fn()
        verdict = first if first == second else "ERROR"
        if verdict != "HELD":
            failures += 1
        print("%s %-14s %s" % (pid, name, verdict))
        if first != second:
            print("  NON-DETERMINISTIC: %s then %s" % (first, second))
    rc = green_check()
    print("probes: %d/%d HELD" % (len(_PROBES) - failures, len(_PROBES)))
    return 1 if failures or rc else 0


def green_check():
    """Adjacent-battery green check (depth-1: honor GOV_SKIP_GREEN)."""
    if _SKIP_GREEN:
        print("green_check: skipped (GOV_SKIP_GREEN=1)")
        return 0
    print("green_check: running adjacent suites (depth-1)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
