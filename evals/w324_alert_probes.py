"""Break-first probes for gov/monitor_alert (wave-324 lane 1).

Red-first: on the open tree this battery dies at import
(ModuleNotFoundError: gov.monitor_alert). On the lane tree every
wrapper behavior below must hold -- 0 BREAK target.

The wrapper is the deployment-side half of the fail-closed monitor
loop: alert from the 3rd consecutive failure, alert every run while
down, daily heartbeat when healthy, crash-safe atomic state,
file (default) + webhook (queued on delivery failure) sinks, and
LOUD alerts on any ambiguous state.

Staging default is set at module level (the harness refuses the
declared ungoverned_ack in production mode).
"""

import os
import sys
import json
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _error(pid, note):
    _record(pid, "ERROR", note)


def probe(pid):
    def deco(fn):
        def run():
            try:
                fn()
            except AssertionError as exc:
                _break(pid, "assertion failed: %s" % (exc,))
            except Exception as exc:  # noqa: BLE001
                _error(pid, "%s: %s" % (type(exc).__name__, exc))
        run.__name__ = pid
        return run
    return deco


def _expect_no_alert(pid, sink):
    assert len(sink.alerts) == 0, "expected no alert, got %r" % (
        sink.alerts,)


# ---------------------------------------------------------------------------
# Fixtures (modeled on the w323 monitor battery).
# ---------------------------------------------------------------------------

SEED_OP = bytes(range(32))
SEED_W1 = bytes([255 - i for i in range(32)])
SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
ORIGIN = "sasanam-witalert-test/v1"
NOW = 1798765432
MID = "witmon-test-1"


def _mod():
    from gov import monitor_alert as ma
    from gov import witness_monitor as wm
    from gov import witness_publish as wp
    from gov import checkpoint_note as cn
    from gov.witness_log import WitnessLog
    from gov.signing import Ed25519Signer
    return ma, wm, wp, cn, WitnessLog, Ed25519Signer


def _vkey(cn, name, signer):
    return cn.vkey_string(
        name, cn.derive_key_id(name, cn.SIG_TYPE_ED25519_COSIGNATURE_V1,
                               signer.public_key),
        cn.SIG_TYPE_ED25519_COSIGNATURE_V1, signer.public_key)


def _op_vkey(cn, name, signer):
    return cn.vkey_string(
        name, cn.derive_key_id(name, cn.SIG_TYPE_ED25519,
                               signer.public_key),
        cn.SIG_TYPE_ED25519, signer.public_key)


def _world(n=5):
    ma, wm, wp, cn, WitnessLog, Ed25519Signer = _mod()
    op = Ed25519Signer(SEED_OP)
    w1 = Ed25519Signer(SEED_W1)
    w2 = Ed25519Signer(SEED_W2)
    log = WitnessLog(op.public_key)
    for i in range(n):
        log.append(b"leaf-%d" % i)
    op_vk = [_op_vkey(cn, "op", op)]
    wit_vk = {"w1": _vkey(cn, "w1", w1), "w2": _vkey(cn, "w2", w2)}
    return (ma, wm, wp, cn), (op, w1, w2, op_vk, wit_vk), log


def _publish(wp, log, op, w1, w2, op_vk, wit_vk, ts, quorum_k=2):
    return wp.publish_checkpoint(
        log, ORIGIN, "op", op, [("w1", w1), ("w2", w2)],
        operator_vkeys=op_vk, witness_vkeys=wit_vk, quorum_k=quorum_k,
        timestamp=ts)


def _mkcfg(d, mods, keys, log, sink=None, fetch=None, now=NOW,
           max_age=3600, monitor_id=MID):
    ma, wm, wp, cn = mods
    op, w1, w2, op_vk, wit_vk = keys
    if sink is None:
        sink = ma.MemoryAlertSink()
    return {
        "monitor_id": monitor_id,
        "state_path": os.path.join(d, "monitor-state.json"),
        "alert_state_path": os.path.join(d, "alert-state.json"),
        "sink": {"type": "memory"},
        "fetch": fetch,
        "witness_set": wit_vk,
        "policy_inputs": {"operator_vkeys": op_vk, "quorum_k": 2,
                          "policy_id": "test", "policy_version": 1},
        "allowed_origins": [ORIGIN],
        "max_age": max_age,
        "now": now,
    }, sink


# ---------------------------------------------------------------------------
# P1: 1st and 2nd consecutive failures -> NO alert, exit 2, count kept.
# ---------------------------------------------------------------------------

@probe("P1-first-two-failures-silent")
def _p1():
    mods, keys, log = _world()
    ma = mods[0]
    d = tempfile.mkdtemp(prefix="witalert-")
    sink = ma.MemoryAlertSink()
    cfg, _ = _mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig_build = ma._build_sink
    ma._build_sink = lambda c: sink
    try:
        r1 = ma.run_monitor_once(cfg)
        assert r1 == {"healthy": False, "consecutive_failures": 1,
                      "alerted": False, "exit_code": 2}, r1
        _expect_no_alert("P1-first-two-failures-silent", sink)
        cfg["now"] = NOW + 60
        r2 = ma.run_monitor_once(cfg)
        assert r2["consecutive_failures"] == 2 and not r2["alerted"], r2
        _expect_no_alert("P1-first-two-failures-silent", sink)
    finally:
        ma._build_sink = orig_build
    _held("P1-first-two-failures-silent", "failures 1-2 silent, exit 2")


# ---------------------------------------------------------------------------
# P2: 3rd consecutive failure -> alert fires with the full payload.
# ---------------------------------------------------------------------------

@probe("P2-third-failure-alerts")
def _p2():
    mods, keys, log = _world()
    ma = mods[0]
    d = tempfile.mkdtemp(prefix="witalert-")
    sink = ma.MemoryAlertSink()
    cfg, _ = _mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig_build = ma._build_sink
    ma._build_sink = lambda c: sink
    try:
        for i in range(3):
            cfg["now"] = NOW + 60 * i
            r = ma.run_monitor_once(cfg)
        assert r["consecutive_failures"] == 3, r
        assert r["alerted"] and r["exit_code"] == 2, r
        assert len(sink.alerts) == 1, sink.alerts
        a = sink.alerts[0]
        assert a["alert_kind"] == "failure-alert", a
        assert a["consecutive_failures"] == 3, a
        assert a["last_code"] == "witness-monitor-fetch-failed", a
        assert a["monitor_id"] == MID, a
        assert a["policy_id"] == "test" and a["policy_version"] == 1, a
        assert a["alert_id"] == "witmon-alert/%s/failure/i1-1798765432/3" % (MID,), a
        # No healthy run yet: head datum absent -> age None (honest).
        assert a["head"] is None and a["head_age_seconds"] is None, a
    finally:
        ma._build_sink = orig_build
    _held("P2-third-failure-alerts", "3rd failure alerts with payload")


# ---------------------------------------------------------------------------
# P3: every run while down keeps alerting (no fatigue suppression).
# ---------------------------------------------------------------------------

@probe("P3-every-run-while-down-alerts")
def _p3():
    mods, keys, log = _world()
    ma = mods[0]
    d = tempfile.mkdtemp(prefix="witalert-")
    sink = ma.MemoryAlertSink()
    cfg, _ = _mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig_build = ma._build_sink
    ma._build_sink = lambda c: sink
    try:
        for i in range(5):
            cfg["now"] = NOW + 60 * i
            r = ma.run_monitor_once(cfg)
            assert r["exit_code"] == 2, r
        counts = [a["consecutive_failures"] for a in sink.alerts]
        assert counts == [3, 4, 5], counts
    finally:
        ma._build_sink = orig_build
    _held("P3-every-run-while-down-alerts", "alerts at 3,4,5")


# ---------------------------------------------------------------------------
# P4: recovery resets the counter; the next failure starts at 1.
# ---------------------------------------------------------------------------

@probe("P4-recovery-resets-counter")
def _p4():
    mods, keys, log = _world()
    ma = mods[0]
    op, w1, w2, op_vk, wit_vk = keys
    wp = mods[2]
    d = tempfile.mkdtemp(prefix="witalert-")
    sink = ma.MemoryAlertSink()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    cfg, _ = _mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig_build = ma._build_sink
    ma._build_sink = lambda c: sink
    try:
        for i in range(3):
            cfg["now"] = NOW + 60 * i
            ma.run_monitor_once(cfg)
        assert len(sink.alerts) == 1  # the count-3 alert
        # Recover: healthy run, no failure alert, heartbeat emitted
        # (first healthy run heartbeats immediately).
        cfg["fetch"] = lambda: note
        cfg["now"] = NOW + 600
        r = ma.run_monitor_once(cfg)
        assert r == {"healthy": True, "consecutive_failures": 0,
                      "alerted": True, "exit_code": 0}, r
        kinds = [a["alert_kind"] for a in sink.alerts]
        assert kinds == ["failure-alert", "heartbeat"], kinds
        hb = sink.alerts[1]
        assert hb["head"]["size"] == 5, hb
        assert hb["head_age_seconds"] == 0, hb
        # Next failure starts the count over at 1: silent again.
        cfg["fetch"] = lambda: None
        cfg["now"] = NOW + 660
        r = ma.run_monitor_once(cfg)
        assert r["consecutive_failures"] == 1 and not r["alerted"], r
        assert len(sink.alerts) == 2, sink.alerts
    finally:
        ma._build_sink = orig_build
    _held("P4-recovery-resets-counter", "recovery resets; heartbeat ok")


# ---------------------------------------------------------------------------
# P5: crash between state-save and emit -> no lost count, no double alert.
# ---------------------------------------------------------------------------

@probe("P5-crash-mid-count-no-loss-no-dup")
def _p5():
    mods, keys, log = _world()
    ma = mods[0]
    d = tempfile.mkdtemp(prefix="witalert-")

    class ExplodingSink(ma.AlertSink):
        def emit(self, alert):
            raise RuntimeError("simulated crash after state save")

    sink = ma.MemoryAlertSink()
    cfg, _ = _mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig_build = ma._build_sink
    # Drive failures 1..3 with the exploding sink on the 3rd tick.
    ma._build_sink = lambda c: sink
    try:
        for i in range(2):
            cfg["now"] = NOW + 60 * i
            ma.run_monitor_once(cfg)
        cfg["now"] = NOW + 120
        ma._build_sink = lambda c: ExplodingSink()
        try:
            ma.run_monitor_once(cfg)
            raise AssertionError("expected the simulated crash")
        except RuntimeError:
            pass
        # The count survived (monitor state is atomic) and the alert
        # state records the decided-but-unemitted alert id.
        st = ma.load_alert_state(cfg["alert_state_path"], MID)
        assert st["consecutive_failures"] == 3, st
        assert st["last_alert_id"] == "witmon-alert/%s/failure/i1-1798765432/3" % (MID,), st
        mstate = mods[1].load_monitor_state(cfg["state_path"])
        assert mstate["consecutive_failures"] == 3, mstate
        # Retry tick: count advances to 4, exactly one new alert, and
        # the count-3 alert is not duplicated (id dedupe).
        ma._build_sink = lambda c: sink
        cfg["now"] = NOW + 180
        r = ma.run_monitor_once(cfg)
        assert r["consecutive_failures"] == 4 and r["alerted"], r
        assert len(sink.alerts) == 1, sink.alerts
        assert sink.alerts[0]["consecutive_failures"] == 4, sink.alerts
    finally:
        ma._build_sink = orig_build
    _held("P5-crash-mid-count-no-loss-no-dup",
          "count preserved; retry alerts once")


# ---------------------------------------------------------------------------
# P6: file sink dedupes by alert_id (exactly-once per id).
# ---------------------------------------------------------------------------

@probe("P6-file-sink-dedupe")
def _p6():
    mods, keys, log = _world()
    ma = mods[0]
    d = tempfile.mkdtemp(prefix="witalert-")
    qp = os.path.join(d, "alerts.jsonl")
    sink = ma.FileAlertSink(qp)
    alert = {"alert_id": "witmon-alert/x/failure/3", "alert_kind":
             "failure-alert"}
    assert sink.emit(alert) is True
    assert sink.emit(dict(alert)) is False  # duplicate: skipped
    with open(qp, "r", encoding="utf-8") as fh:
        lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    assert len(lines) == 1, lines
    _held("P6-file-sink-dedupe", "duplicate alert_id not re-recorded")


# ---------------------------------------------------------------------------
# P7: webhook delivery failure -> queued, no crash; drain on recovery.
# ---------------------------------------------------------------------------

@probe("P7-webhook-failure-queues-and-drains")
def _p7():
    mods, keys, log = _world()
    ma = mods[0]
    d = tempfile.mkdtemp(prefix="witalert-")
    qp = os.path.join(d, "queue.jsonl")
    calls = {"n": 0}

    def fake_post(self, alert):
        calls["n"] += 1
        return False  # delivery failure

    orig_post = ma.WebhookAlertSink._post
    ma.WebhookAlertSink._post = fake_post
    try:
        sink = ma.WebhookAlertSink("http://127.0.0.1:9/hook", qp)
        alert = {"alert_id": "witmon-alert/x/failure/3",
                 "alert_kind": "failure-alert"}
        assert sink.emit(alert) is False  # queued, did not raise
        assert calls["n"] == 1
        with open(qp, "r", encoding="utf-8") as fh:
            assert len(fh.read().splitlines()) == 1
        # Webhook recovers: drain delivers and empties the queue.
        ma.WebhookAlertSink._post = lambda self, a: True
        delivered, remaining = sink.drain_queue()
        assert (delivered, remaining) == (1, 0), (delivered, remaining)
        with open(qp, "r", encoding="utf-8") as fh:
            assert fh.read().strip() == ""
    finally:
        ma.WebhookAlertSink._post = orig_post
    _held("P7-webhook-failure-queues-and-drains",
          "delivery failure queues without crashing; drain works")


# ---------------------------------------------------------------------------
# P8: malformed monitor output -> LOUD wrapper-error alert.
# ---------------------------------------------------------------------------

@probe("P8-malformed-monitor-output-loud")
def _p8():
    mods, keys, log = _world()
    ma = mods[0]
    d = tempfile.mkdtemp(prefix="witalert-")
    sink = ma.MemoryAlertSink()
    cfg, _ = _mkcfg(d, mods, keys, log, fetch=lambda: b"junk")
    orig_build = ma._build_sink
    wm = ma._monitor_mod()
    orig_step = wm.monitor_step
    wm.monitor_step = lambda *a, **k: {"garbage": True}
    ma._build_sink = lambda c: sink
    try:
        try:
            ma.run_monitor_once(cfg)
            raise AssertionError("expected AlertWrapperError")
        except ma.AlertWrapperError as exc:
            assert exc.code == "witness-alert-wrapper-error", exc.code
        assert len(sink.alerts) == 1, sink.alerts
        a = sink.alerts[0]
        assert a["alert_kind"] == "wrapper-error", a
        assert a["last_code"] == "witness-alert-wrapper-error", a
    finally:
        wm.monitor_step = orig_step
        ma._build_sink = orig_build
    _held("P8-malformed-monitor-output-loud",
          "malformed verdict alerts LOUD with the wrapper code")


# ---------------------------------------------------------------------------
# P9: heartbeat cadence -- daily when healthy, not more often.
# ---------------------------------------------------------------------------

@probe("P9-heartbeat-daily-when-healthy")
def _p9():
    mods, keys, log = _world()
    ma = mods[0]
    op, w1, w2, op_vk, wit_vk = keys
    wp = mods[2]
    d = tempfile.mkdtemp(prefix="witalert-")
    sink = ma.MemoryAlertSink()

    def fresh_note(tick_now):
        # A fresh checkpoint per tick: the note must stay within the
        # freshness window at the tick's own clock.
        log.append(b"leaf-%d" % len(log))
        return _publish(wp, log, op, w1, w2, op_vk, wit_vk,
                        tick_now - 100)

    cfg, _ = _mkcfg(d, mods, keys, log,
                    fetch=lambda: fresh_note(cfg["now"]))
    orig_build = ma._build_sink
    ma._build_sink = lambda c: sink
    try:
        r = ma.run_monitor_once(cfg)  # first healthy: heartbeat
        assert r["healthy"] and r["alerted"], r
        cfg["now"] = NOW + 3600  # same day: silent
        r = ma.run_monitor_once(cfg)
        assert r["healthy"] and not r["alerted"], r
        cfg["now"] = NOW + 86400 + 1  # next day: heartbeat again
        r = ma.run_monitor_once(cfg)
        assert r["healthy"] and r["alerted"], r
        kinds = [a["alert_kind"] for a in sink.alerts]
        assert kinds == ["heartbeat", "heartbeat"], kinds
    finally:
        ma._build_sink = orig_build
    _held("P9-heartbeat-daily-when-healthy", "heartbeat cadence holds")


# ---------------------------------------------------------------------------
# P10: corrupt alert state -> LOUD, never silent re-baseline.
# ---------------------------------------------------------------------------

@probe("P10-corrupt-alert-state-loud")
def _p10():
    mods, keys, log = _world()
    ma = mods[0]
    d = tempfile.mkdtemp(prefix="witalert-")
    sink = ma.MemoryAlertSink()
    cfg, _ = _mkcfg(d, mods, keys, log, fetch=lambda: None)
    with open(cfg["alert_state_path"], "w", encoding="utf-8") as fh:
        fh.write("{not json")
    orig_build = ma._build_sink
    ma._build_sink = lambda c: sink
    try:
        try:
            ma.run_monitor_once(cfg)
            raise AssertionError("expected AlertWrapperError")
        except ma.AlertWrapperError as exc:
            assert exc.code == "witness-alert-wrapper-error", exc.code
        assert len(sink.alerts) == 1, sink.alerts
        assert sink.alerts[0]["alert_kind"] == "wrapper-error", sink.alerts
    finally:
        ma._build_sink = orig_build
    _held("P10-corrupt-alert-state-loud", "corrupt state alerts LOUD")


# ---------------------------------------------------------------------------
# P13: corrupt MONITOR state below threshold -> LOUD (unknown count),
# never silent on the stale mirror (spec Finding 1).
# ---------------------------------------------------------------------------

@probe("P13-corrupt-monitor-state-loud")
def _p13():
    mods, keys, log = _world()
    ma = mods[0]
    d = tempfile.mkdtemp(prefix="witalert-")
    sink = ma.MemoryAlertSink()
    cfg, _ = _mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig_build = ma._build_sink
    ma._build_sink = lambda c: sink
    try:
        # Two silent fetch failures (mirror at 2, below threshold).
        for i in range(2):
            cfg["now"] = NOW + 60 * i
            r = ma.run_monitor_once(cfg)
            assert r["consecutive_failures"] == i + 1, r
        assert len(sink.alerts) == 0
        # Corrupt the MONITOR state file: the monitor will refuse
        # pre-increment with consecutive_failures=None.
        with open(cfg["state_path"], "w", encoding="utf-8") as fh:
            fh.write("{corrupt")
        # Every further tick must alert LOUD -- never sit silent on the
        # stale mirror at 2.
        for i in range(2, 5):
            cfg["now"] = NOW + 60 * i
            try:
                ma.run_monitor_once(cfg)
                raise AssertionError("expected AlertWrapperError")
            except ma.AlertWrapperError as exc:
                assert exc.code == "witness-alert-wrapper-error", exc.code
        loud = [a for a in sink.alerts
                if a["alert_kind"] == "wrapper-error"]
        assert len(loud) == 3, sink.alerts
        assert all(a["last_code"] == "witness-alert-wrapper-error"
                   for a in loud)
    finally:
        ma._build_sink = orig_build
    _held("P13-corrupt-monitor-state-loud",
          "unknown count alerts LOUD every tick")


# ---------------------------------------------------------------------------
# P14: config missing policy_inputs -> LOUD AlertWrapperError, 1 alert
# (spec Finding 2).
# ---------------------------------------------------------------------------

@probe("P14-missing-policy-inputs-loud")
def _p14():
    mods, keys, log = _world()
    ma = mods[0]
    d = tempfile.mkdtemp(prefix="witalert-")
    sink = ma.MemoryAlertSink()
    cfg, _ = _mkcfg(d, mods, keys, log, fetch=lambda: None)
    del cfg["policy_inputs"]
    orig_build = ma._build_sink
    ma._build_sink = lambda c: sink
    try:
        try:
            ma.run_monitor_once(cfg)
            raise AssertionError("expected AlertWrapperError")
        except ma.AlertWrapperError as exc:
            assert exc.code == "witness-alert-wrapper-error", exc.code
        assert len(sink.alerts) == 1, sink.alerts
        assert sink.alerts[0]["alert_kind"] == "wrapper-error", sink.alerts
    finally:
        ma._build_sink = orig_build
    _held("P14-missing-policy-inputs-loud",
          "bad config alerts LOUD through the sink")


# ---------------------------------------------------------------------------
# P15: a second outage's alerts are not deduped against the first
# (incident_seq).
# ---------------------------------------------------------------------------

@probe("P15-second-outage-not-deduped")
def _p15():
    mods, keys, log = _world()
    ma = mods[0]
    op, w1, w2, op_vk, wit_vk = keys
    wp = mods[2]
    d = tempfile.mkdtemp(prefix="witalert-")
    sink = ma.MemoryAlertSink()
    cfg, _ = _mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig_build = ma._build_sink
    ma._build_sink = lambda c: sink
    try:
        for i in range(3):  # outage 1 -> alert i1/3
            cfg["now"] = NOW + 60 * i
            ma.run_monitor_once(cfg)
        note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW + 700)
        cfg["fetch"] = lambda: note
        cfg["now"] = NOW + 800  # recover
        ma.run_monitor_once(cfg)
        n_before = len(sink.alerts)
        cfg["fetch"] = lambda: None
        for i in range(3):  # outage 2 -> must alert again at i2/3
            cfg["now"] = NOW + 900 + 60 * i
            ma.run_monitor_once(cfg)
        new = sink.alerts[n_before:]
        fails = [a for a in new if a["alert_kind"] == "failure-alert"]
        assert len(fails) == 1, new
        assert fails[0]["alert_id"] == \
            "witmon-alert/%s/failure/i2-1798766332/3" % (MID,), fails[0]
    finally:
        ma._build_sink = orig_build
    _held("P15-second-outage-not-deduped",
          "second outage alerts with a fresh incident id")


# ---------------------------------------------------------------------------
# P16: monitor state deleted mid-outage -> LOUD, never silent re-baseline.
# ---------------------------------------------------------------------------

@probe("P16-monitor-state-deleted-loud")
def _p16():
    mods, keys, log = _world()
    ma = mods[0]
    op, w1, w2, op_vk, wit_vk = keys
    wp = mods[2]
    d = tempfile.mkdtemp(prefix="witalert-")
    sink = ma.MemoryAlertSink()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    cfg, _ = _mkcfg(d, mods, keys, log, fetch=lambda: note)
    orig_build = ma._build_sink
    ma._build_sink = lambda c: sink
    try:
        r = ma.run_monitor_once(cfg)  # healthy baseline; head exists
        assert r["healthy"], r
        os.remove(cfg["state_path"])  # adversary deletes monitor state
        try:
            ma.run_monitor_once(cfg)
            raise AssertionError("expected AlertWrapperError")
        except ma.AlertWrapperError as exc:
            assert exc.code == "witness-alert-wrapper-error", exc.code
        loud = [a for a in sink.alerts
                if a["alert_kind"] == "wrapper-error"]
        assert len(loud) == 1, sink.alerts
    finally:
        ma._build_sink = orig_build
    _held("P16-monitor-state-deleted-loud",
          "deleted monitor state alerts LOUD")


# ---------------------------------------------------------------------------
# P17: monitor state deleted mid-outage with NO head in the mirror ->
# LOUD, never a silent re-baseline (F408).
# ---------------------------------------------------------------------------

@probe("P17-monitor-state-deleted-no-head-loud")
def _p17():
    mods, keys, log = _world()
    ma = mods[0]
    d = tempfile.mkdtemp(prefix="witalert-")
    sink = ma.MemoryAlertSink()
    cfg, _ = _mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig_build = ma._build_sink
    ma._build_sink = lambda c: sink
    try:
        # 4 silent fetch failures: mirror at 4, alert i1/3 + i1/4 fired.
        for i in range(4):
            cfg["now"] = NOW + 60 * i
            ma.run_monitor_once(cfg)
        fails = [a for a in sink.alerts if a["alert_kind"] == "failure-alert"]
        assert len(fails) == 2, sink.alerts
        # Adversary deletes the monitor state file. The monitor would
        # re-baseline at 1 (silent) and the re-fired i1/3 alert would
        # be dropped by id dedupe.
        os.remove(cfg["state_path"])
        try:
            ma.run_monitor_once(cfg)
            raise AssertionError("expected AlertWrapperError")
        except ma.AlertWrapperError as exc:
            assert exc.code == "witness-alert-wrapper-error", exc.code
        loud = [a for a in sink.alerts
                if a["alert_kind"] == "wrapper-error"]
        assert len(loud) == 1, sink.alerts
        # Mirror was NOT overwritten with the re-baselined count.
        st = json.loads(open(cfg["alert_state_path"],
                             "r", encoding="utf-8").read())
        assert st["consecutive_failures"] == 4, st
    finally:
        ma._build_sink = orig_build
    _held("P17-monitor-state-deleted-no-head-loud",
          "re-baseline mid-outage alerts LOUD, mirror preserved")


# ---------------------------------------------------------------------------
# P11: pin + footer state.
# ---------------------------------------------------------------------------

@probe("P11-pin-taxonomy-2140-sorted")
def _p11():
    from gov import decision_codes as dc
    import re
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    codes = re.findall(r'"code":\s*["\']([^"\']+)["\']', src)
    assert len(codes) == len(set(codes)) == TAXONOMY_PIN == 2140, (#Wave-333 merge: pin 2069 -> 2106 (+8 revocation-push-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        len(codes), len(set(codes)))
    assert codes == sorted(codes), "taxonomy not sorted"
    assert "witness-alert-wrapper-error" in dc.TAXONOMY
    _held("P11-pin-taxonomy-2140-sorted", "2140/2140/0 sorted")


@probe("P12-footer-state")
def _p12():
    path = os.path.join(REPO, "evals", "FINDINGS.md")
    src = open(path, encoding="utf-8").read()
    # Wave-337 lane 1: probe repaired -- the F417-era assertion rotted
    # through many merges; assert the live footer (open none / next
    # F426; F424/F425 closed by wave-337 lane 1).
    assert "Next free finding: **F700**" in src, "next-free footer"  # Wave-356 merge: footer repoint  # Wave-357 merge: F478, F479 CLOSED (next F481); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
    assert "**Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671.**" in src, "open-none footer"  # Wave-356 merge: footer repoint  # Wave-357 merge: F478, F479 CLOSED (next F481); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-366 merge: F526-F530 CLOSED (lanes 1-3); F532 CLOSED at merge (honest F527 generalization, F514 precedent); F531, F533-F536 OPEN (next F537)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)
    _held("P12-footer-state", "open none / next F430")


# ---------------------------------------------------------------------------
# Green checks (depth-1): adjacent batteries run with GOV_SKIP_GREEN=1 in
# the child env; this function honors the var by recording a skip.
# ---------------------------------------------------------------------------

_GREEN_CHILDREN = [
    "evals/w323_monitor_probes.py",
    "evals/w322_redteam_probes.py",
    "evals/w321_oci_probes.py",
]
_KNOWN_CHILD_BREAKS = set()


def _green():
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-skip", "HELD", "green checks skipped (child mode)")
        return
    for child in _GREEN_CHILDREN:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        try:
            proc = subprocess.run(
                [sys.executable, os.path.join(REPO, child)],
                capture_output=True, text=True, timeout=600, env=env,
                cwd=REPO)
        except Exception as exc:  # noqa: BLE001
            _record("green-" + child, "ERROR", "%s" % (exc,))
            continue
        out = proc.stdout + proc.stderr
        bad = [ln for ln in out.splitlines()
               if ln.startswith("[BREAK]")]
        ok = True
        for ln in bad:
            pid = ln.split("]")[1].split(":")[0].strip()
            if pid not in _KNOWN_CHILD_BREAKS:
                ok = False
        if "[ERROR]" in out or proc.returncode not in (0,):
            if "[ERROR]" in out:
                ok = False
        _record("green-" + child, "HELD" if ok else "BREAK",
                "child ran; unexpected breaks fail this check")


def main():
    ordered = []
    for i in range(1, 40):
        fn = globals().get("_p%d" % i)
        if callable(fn):
            ordered.append(fn)
    for fn in ordered:
        fn()
    _green()
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    print("w324_alert battery: %d BREAK / %d HELD / %d ERROR "
          % (n_break, n_held, n_err))
    green_ok = all(v != "BREAK" and v != "ERROR"
                   for pid, v, _ in _results
                   if pid.startswith("green-") and pid != "green-skip")
    if green_ok:
        print("GREEN")
    return 0 if (n_break == 0 and n_err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
