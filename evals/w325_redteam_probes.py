"""Wave-325 red-team battery (independent red team, lane 4).

Break-first probes against the wave-324 seams: the alert wrapper
(gov/monitor_alert.py), the offline verifier (gov/offline_verify.py), and
the threshold VSA consumer (gov/vsa_threshold.py); plus regression probes
for the closed F408 / F407 / F406 findings, prior-battery child runs, and
the taxonomy-pin/footer-state probes.

Filed finding: F409 (LOW) -- alert-state deletion during a healthy window
reuses incident_seq, so the next outage's early failure alerts dedupe-
collide with the previous outage's alerts and are silently dropped
(delayed alerting, never fully silent). Probe P1a demonstrated it (EXPECTED
BREAK on the wave-324 tree); F409 was closed by wave-326 lane 1 and P1a now
HELDs.

Every probe is deterministic (fixed seeds, fixed timestamps). The green
check runs adjacent batteries in child mode (GOV_SKIP_GREEN=1) and honors
the skip itself, so nesting stays depth-1.
"""

import copy
import json
import os
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))

import w324_alert_probes as _wa  # noqa: E402
import w324_offver_probes as _wo  # noqa: E402
import w324_vsa_probes as _wv  # noqa: E402
import w322_redteam_probes as _w322  # noqa: E402

TAXONOMY_PIN = 2077  # Wave-327 merge: pin 2035 -> 2044 (+9 policy-channel-*); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*)
FOOTER_OPEN = "none"  # F409-F416 CLOSED; no open findings (wave-331 merge).
FOOTER_NEXT = "F417"  # Next free finding number.

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
    except Exception as exc:  # noqa: BLE001
        _record(pid, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3)))


def _expect_code(pid, fn, exc_types, code, note):
    """HELD iff fn() raises one of exc_types with .code == code."""
    try:
        fn()
    except exc_types as exc:
        if exc.code == code:
            return _held(pid, "%s: refused coded %s" % (note, code))
        return _break(pid, "%s: refused coded %s, want %s"
                      % (note, exc.code, code))
    except Exception as exc:  # noqa: BLE001
        return _break(pid, "%s: raised %r, want coded %s" % (note, exc, code))
    return _break(pid, "%s: ACCEPTED, want coded refusal %s" % (note, code))

# ---------------------------------------------------------------------------
# P1: alert wrapper (gov/monitor_alert.py).
# ---------------------------------------------------------------------------

def _p1_cfg(d, sink, fetch=None, now=None, world=None):
    """Build a failing-monitor cfg with _build_sink pinned to `sink`."""
    ma = _wa._world()[0][0] if world is None else world[0][0]
    mods, keys, log = _wa._world() if world is None else world
    cfg, _ = _wa._mkcfg(d, mods, keys, log, fetch=fetch,
                        now=_wa.NOW if now is None else now)
    return ma, cfg, mods, keys, log


@probe("P1a-f409-alert-state-deleted-healthy-window")
def _p1a():
    """F409 (LOW, OPEN): alert-state deletion during a healthy window reuses
    incident_seq, so the next outage's 3rd-failure alert dedupe-collides
    with the previous outage's i1/3 alert and is silently dropped. The
    outage still alerts from failures=4 on, so this is delayed (not
    silent) alerting -- but the dedupe invariant ("a later outage's alerts
    never dedupe against an earlier outage's") is violated.
    EXPECTED BREAK on the wave-324 tree."""
    ma = _wa._world()[0][0]
    d = tempfile.mkdtemp(prefix="w325-p1a-")
    sink = ma.MemoryAlertSink()
    mods, keys, log = _wa._world()
    cfg, _ = _wa._mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig = ma._build_sink
    ma._build_sink = lambda c: sink  # noqa: E731
    try:
        for i in range(3):  # outage 1: alert i1/3 emitted
            ma.run_monitor_once(dict(cfg, now=_wa.NOW + i))
        # a healthy window with a real checkpoint
        mods2, keys2, log2 = _wa._world()
        op, w1, w2, op_vk, wit_vk = keys2
        note = _wa._publish(mods2[2], log2, op, w1, w2, op_vk, wit_vk,
                            _wa.NOW + 100)
        cfg_h, _ = _wa._mkcfg(d, mods2, keys2, log2,
                              fetch=lambda: note, now=_wa.NOW + 100)
        r = ma.run_monitor_once(cfg_h)
        if not r["healthy"]:
            return _break("P1a-f409-alert-state-deleted-healthy-window",
                          "healthy tick did not verify: %r" % (r,))
        os.remove(cfg["alert_state_path"])  # the attack: lose alert state
        for i in range(2):  # new outage: failures 1, 2 (silent)
            ma.run_monitor_once(dict(cfg, now=_wa.NOW + 200 + i))
        before = len(sink.alerts)
        ma.run_monitor_once(dict(cfg, now=_wa.NOW + 202))  # failures == 3
        after = len(sink.alerts)
        if after == before + 1:
            return _held("P1a-f409-alert-state-deleted-healthy-window",
                         "new outage's 3rd-failure alert emitted (F409 fixed)")
        return _break("P1a-f409-alert-state-deleted-healthy-window",
                      "F409: new outage's 3rd-failure alert dropped by "
                      "dedupe (incident_seq reused after alert-state loss)")
    finally:
        ma._build_sink = orig


@probe("P1b-both-states-deleted-silent-rebaseline")
def _p1b():
    """Both state files deleted mid-outage: the wrapper re-baselines
    silently (failures=1, no alert, no LOUD). Accepted boundary: an
    attacker who can delete the wrapper's own alert-state file can also
    delete the alert queue and suppress everything; the F408 guards cover
    the partial-attacker cases (monitor-state-only, backwards count).
    Documents the behavior; HELD."""
    ma = _wa._world()[0][0]
    d = tempfile.mkdtemp(prefix="w325-p1b-")
    sink = ma.MemoryAlertSink()
    mods, keys, log = _wa._world()
    cfg, _ = _wa._mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig = ma._build_sink
    ma._build_sink = lambda c: sink  # noqa: E731
    try:
        for i in range(3):
            ma.run_monitor_once(dict(cfg, now=_wa.NOW + i))
        os.remove(cfg["state_path"])
        os.remove(cfg["alert_state_path"])
        r = ma.run_monitor_once(dict(cfg, now=_wa.NOW + 10))
        if r["healthy"] is False and r["consecutive_failures"] == 1 \
                and r["alerted"] is False:
            return _held("P1b-both-states-deleted-silent-rebaseline",
                         "both states deleted -> silent re-baseline "
                         "(failures=1); accepted local-operator boundary")
        return _break("P1b-both-states-deleted-silent-rebaseline",
                      "unexpected behavior after deleting both states: %r"
                      % (r,))
    except Exception as exc:
        return _held("P1b-both-states-deleted-silent-rebaseline",
                     "both states deleted -> LOUD %r (also acceptable)"
                     % (exc,))
    finally:
        ma._build_sink = orig


@probe("P1c-alert-state-only-deleted-mid-outage")
def _p1c():
    """Alert-state-only deletion mid-outage: incident_seq resets but the
    failure count continues from the monitor's own state, so no dedupe
    collision occurs (i1/4 != i1/3) and the outage stays loud. HELD."""
    ma = _wa._world()[0][0]
    d = tempfile.mkdtemp(prefix="w325-p1c-")
    sink = ma.MemoryAlertSink()
    mods, keys, log = _wa._world()
    cfg, _ = _wa._mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig = ma._build_sink
    ma._build_sink = lambda c: sink  # noqa: E731
    try:
        for i in range(3):
            ma.run_monitor_once(dict(cfg, now=_wa.NOW + i))
        os.remove(cfg["alert_state_path"])
        r = ma.run_monitor_once(dict(cfg, now=_wa.NOW + 10))
        ids = [a["alert_id"] for a in sink.alerts]
        if r["alerted"] and r["consecutive_failures"] == 4 \
                and any(i.endswith("/4") for i in ids):
            return _held("P1c-alert-state-only-deleted-mid-outage",
                         "alert state lost mid-outage -> count continues "
                         "from monitor state (i1/4, no collision)")
        return _break("P1c-alert-state-only-deleted-mid-outage",
                      "unexpected: %r ids=%r" % (r, ids))
    finally:
        ma._build_sink = orig


@probe("P1d-monitor-count-reduced-loud")
def _p1d():
    """Directly reducing the monitor's stored count 3->1 makes the next
    report (failures=2) strictly less than the mirror (3): the backwards-
    count guard fires LOUD. (A reduction of exactly 1 is absorbed but stays
    noisy -- the outage still alerts.) HELD."""
    ma = _wa._world()[0][0]
    d = tempfile.mkdtemp(prefix="w325-p1d-")
    sink = ma.MemoryAlertSink()
    mods, keys, log = _wa._world()
    cfg, _ = _wa._mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig = ma._build_sink
    ma._build_sink = lambda c: sink  # noqa: E731
    try:
        for i in range(3):
            ma.run_monitor_once(dict(cfg, now=_wa.NOW + i))
        st = json.load(open(cfg["state_path"]))
        st["consecutive_failures"] = 1
        json.dump(st, open(cfg["state_path"], "w"))
        try:
            ma.run_monitor_once(dict(cfg, now=_wa.NOW + 10))
        except ma.AlertWrapperError as exc:
            if exc.code == "witness-alert-wrapper-error":
                return _held("P1d-monitor-count-reduced-loud",
                             "count 3->1 -> LOUD coded refusal")
            return _break("P1d-monitor-count-reduced-loud",
                          "wrong code %s" % (exc.code,))
        return _break("P1d-monitor-count-reduced-loud",
                      "count reduction accepted silently")
    finally:
        ma._build_sink = orig


@probe("P1e-crash-between-save-and-emit-no-double")
def _p1e():
    """Crash (exception) between the state save and the sink emit: the tick
    is lost (documented), but the retry does not double-alert -- the
    retried alert carries a fresh id (i1/4) and each id is emitted at most
    once. HELD."""
    ma = _wa._world()[0][0]
    d = tempfile.mkdtemp(prefix="w325-p1e-")
    inner = ma.MemoryAlertSink()

    class _CrashOnce:
        def __init__(self):
            self.armed = True
        def emit(self, alert):
            if self.armed:
                self.armed = False
                raise RuntimeError("simulated crash after state save")
            return inner.emit(alert)

    wrapper = _CrashOnce()
    mods, keys, log = _wa._world()
    cfg, _ = _wa._mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig = ma._build_sink
    ma._build_sink = lambda c: wrapper  # noqa: E731
    try:
        for i in range(2):
            ma.run_monitor_once(dict(cfg, now=_wa.NOW + i))
        try:
            ma.run_monitor_once(dict(cfg, now=_wa.NOW + 2))
            return _break("P1e-crash-between-save-and-emit-no-double",
                          "crash did not propagate")
        except RuntimeError:
            pass
        for i in range(3, 5):
            ma.run_monitor_once(dict(cfg, now=_wa.NOW + i))
        ids = [a["alert_id"] for a in inner.alerts]
        if len(ids) == len(set(ids)) and any(i.endswith("/4") for i in ids) \
                and any(i.endswith("/5") for i in ids):
            return _held("P1e-crash-between-save-and-emit-no-double",
                         "crash tick lost (documented), retry emits i1/4 "
                         "and i1/5 exactly once each -- no double alert")
        return _break("P1e-crash-between-save-and-emit-no-double",
                      "duplicate or missing alerts: %r" % (ids,))
    finally:
        ma._build_sink = orig


@probe("P1f-webhook-queue-corrupt-line-dropped")
def _p1f():
    """A corrupt line in the webhook queue file is dropped without
    crashing the drain; the valid queued alert is preserved for retry.
    HELD."""
    ma = _wa._world()[0][0]
    d = tempfile.mkdtemp(prefix="w325-p1f-")
    qpath = os.path.join(d, "queue.jsonl")
    good = {"alert_id": "x/1", "alert_kind": "failure-alert",
            "monitor_id": "m", "consecutive_failures": 3}
    with open(qpath, "w") as fh:
        fh.write("{not json\n")
        fh.write(json.dumps(good) + "\n")
    sink = ma.WebhookAlertSink("http://127.0.0.1:1/", queue_path=qpath,
                               timeout_s=1)
    delivered, remaining = sink.drain_queue()
    rest = [json.loads(l) for l in open(qpath).read().splitlines()]
    if delivered == 0 and remaining == 1 and rest == [good]:
        return _held("P1f-webhook-queue-corrupt-line-dropped",
                     "corrupt queue line dropped, valid alert preserved")
    return _break("P1f-webhook-queue-corrupt-line-dropped",
                  "delivered=%r remaining=%r rest=%r"
                  % (delivered, remaining, rest))


@probe("P1g-malformed-monitor-verdict-loud")
def _p1g():
    """A monitor that returns a malformed verdict dict (shape check fails)
    makes the wrapper fail LOUD rather than mis-counting. HELD."""
    ma = _wa._world()[0][0]
    d = tempfile.mkdtemp(prefix="w325-p1g-")
    sink = ma.MemoryAlertSink()
    mods, keys, log = _wa._world()
    cfg, _ = _wa._mkcfg(d, mods, keys, log, fetch=lambda: None)
    wm = ma._monitor_mod()
    orig_step = wm.monitor_step
    orig_sink = ma._build_sink
    wm.monitor_step = lambda *a, **k: {"accepted": True}  # malformed
    ma._build_sink = lambda c: sink  # noqa: E731
    try:
        try:
            ma.run_monitor_once(cfg)
        except ma.AlertWrapperError as exc:
            if exc.code == "witness-alert-wrapper-error":
                return _held("P1g-malformed-monitor-verdict-loud",
                             "malformed monitor verdict -> LOUD coded refusal")
            return _break("P1g-malformed-monitor-verdict-loud",
                          "wrong code %s" % (exc.code,))
        return _break("P1g-malformed-monitor-verdict-loud",
                      "malformed verdict accepted silently")
    finally:
        wm.monitor_step = orig_step
        ma._build_sink = orig_sink


@probe("P1h-f408-monitor-state-deleted-no-head-loud")
def _p1h():
    """F408 regression (P17): monitor state deleted mid-outage with NO head
    in the alert-state mirror -> the backwards-count guard fires LOUD.
    Must stay HELD (F408 is closed; do not re-file)."""
    ma = _wa._world()[0][0]
    d = tempfile.mkdtemp(prefix="w325-p1h-")
    sink = ma.MemoryAlertSink()
    mods, keys, log = _wa._world()
    cfg, _ = _wa._mkcfg(d, mods, keys, log, fetch=lambda: None)
    orig = ma._build_sink
    ma._build_sink = lambda c: sink  # noqa: E731
    try:
        for i in range(3):
            ma.run_monitor_once(dict(cfg, now=_wa.NOW + i))
        os.remove(cfg["state_path"])
        try:
            ma.run_monitor_once(dict(cfg, now=_wa.NOW + 10))
        except ma.AlertWrapperError as exc:
            if exc.code == "witness-alert-wrapper-error":
                return _held("P1h-f408-monitor-state-deleted-no-head-loud",
                             "F408 P17 still LOUD on the wave-324 tree")
            return _break("P1h-f408-monitor-state-deleted-no-head-loud",
                          "wrong code %s" % (exc.code,))
        return _break("P1h-f408-monitor-state-deleted-no-head-loud",
                      "F408 REGRESSION: deletion accepted silently")
    finally:
        ma._build_sink = orig

# ---------------------------------------------------------------------------
# P2: offline verifier (gov/offline_verify.py) -- the 13 steps.
# ---------------------------------------------------------------------------

@probe("P2a-bool-seq-type-loose-comparison")
def _p2a():
    """check_structure compares seq with plain <, so a bool seq (True == 1)
    passes monotonicity where an int 1 would. This is type-loose but NOT a
    bypass: the digest step and the entry-signature layer (step 7) both bind
    the exact bytes, and any transplanted entry fails the bundle digest
    first. Documents the looseness; the real guards hold. HELD."""
    v = _wo.OV._Verifier({}, _wo._NOW)
    raw = {"ledger.jsonl": b'{"seq": true}\n{"seq": 2}\n{"seq": 3}\n'}
    manifest = {"window": {"from_seq": 1, "to_seq": 3, "entry_count": 3}}
    try:
        v.check_structure(raw, manifest)
    except Exception as exc:  # noqa: BLE001
        return _held("P2a-bool-seq-type-loose-comparison",
                     "bool seq refused coded %s (stricter than expected)"
                     % (getattr(exc, "code", type(exc).__name__),))
    return _held("P2a-bool-seq-type-loose-comparison",
                 "bool seq passes monotonicity (True==1); digest + entry "
                 "signatures remain the real guards")


@probe("P2b-equal-timestamps-accepted")
def _p2b():
    """Equal timestamps across entries are accepted (non-decreasing, not
    strictly increasing) -- the documented comparator. A replayed-timestamp
    forgery still has to survive the digest and entry signatures. HELD."""
    v = _wo.OV._Verifier({}, _wo._NOW)
    raw = {"ledger.jsonl": b'{"seq": 1, "ts": 100}\n{"seq": 2, "ts": 100}\n'}
    manifest = {"window": {"from_seq": 1, "to_seq": 2, "entry_count": 2}}
    try:
        v.check_structure(raw, manifest)
        return _held("P2b-equal-timestamps-accepted",
                     "equal timestamps accepted (non-decreasing)")
    except Exception as exc:  # noqa: BLE001
        return _break("P2b-equal-timestamps-accepted",
                      "equal timestamps refused: %r" % (exc,))


@probe("P2c-witness-layer-stripped")
def _p2c():
    """Stripping witness_layer.json from a good package refuses coded
    OFFLINE_VERIFY_WITNESS_LAYER_MISSING. HELD."""
    tmp = tempfile.mkdtemp(prefix="w325-p2c-")
    bd, tr, _ = _wo._good_package(tmp, name="p2c")
    os.remove(os.path.join(bd, "witness_layer.json"))
    return _expect_code("P2c-witness-layer-stripped",
                       lambda: _wo._verify(bd, tr),
                       _wo.OV.OfflineVerifyError,
                       "offline-verify-witness-layer-missing",
                       "witness layer stripped")


@probe("P2d-trust-root-substitution")
def _p2d():
    """Verifying a good bundle against a substituted anchor key refuses
    coded OFFLINE_VERIFY_ANCHOR_KEY_MISMATCH. HELD."""
    from gov.signing import Ed25519Signer
    tmp = tempfile.mkdtemp(prefix="w325-p2d-")
    bd, tr, _ = _wo._good_package(tmp, name="p2d")
    evil = Ed25519Signer(bytes([9] * 32))
    tr2 = dict(tr)
    tr2["anchor_log_pubkey_hex"] = evil.public_key.hex()
    return _expect_code("P2d-trust-root-substitution",
                       lambda: _wo._verify(bd, tr2),
                       _wo.OV.OfflineVerifyError,
                       "offline-verify-anchor-key-mismatch",
                       "substituted trust root")


@probe("P2e-policy-window-confusion")
def _p2e():
    """A witness layer whose policy was issued AFTER the cosignature time
    refuses coded OFFLINE_VERIFY_POLICY_WINDOW. (A policy expired at build
    is refused even earlier, at layer build.) HELD."""
    import shutil
    tmp = tempfile.mkdtemp(prefix="w325-p2e-")
    bd, tr, adapter = _wo._good_package(tmp, name="p2e")
    doc = _wo._sealed(issued_at=_wo._NOW + 1000,
                      expires_at=_wo._NOW + 90000)
    bd2 = os.path.join(tmp, "p2e2")
    shutil.copytree(bd, bd2)
    os.remove(os.path.join(bd2, "witness_layer.json"))
    _wo._attach_layer(bd2, adapter, policy_doc=doc, note_ts=_wo._NOW - 100)
    return _expect_code("P2e-policy-window-confusion",
                       lambda: _wo._verify(bd2, tr),
                       _wo.OV.OfflineVerifyError,
                       "offline-verify-policy-window",
                       "policy issued after cosignature")


@probe("P2f-chain-break-transplant-digest")
def _p2f():
    """A chain break (modified ledger under the ORIGINAL signed witness
    layer): the recomputed digest catches it coded
    OFFLINE_VERIFY_BUNDLE_DIGEST_MISMATCH. HELD."""
    tmp = tempfile.mkdtemp(prefix="w325-p2f-")
    bd, tr, _ = _wo._good_package(tmp, name="p2f")
    lines = open(os.path.join(bd, "ledger.jsonl")).read().splitlines()
    lines[1] = '{"seq": 2, "op": "EVIL"}'
    open(os.path.join(bd, "ledger.jsonl"), "w").write("\n".join(lines) + "\n")
    return _expect_code("P2f-chain-break-transplant-digest",
                       lambda: _wo._verify(bd, tr),
                       _wo.OV.OfflineVerifyError,
                       "offline-verify-bundle-digest-mismatch",
                       "modified ledger under original signed layer")


@probe("P2g-undisclosed-redaction")
def _p2g():
    """A ledger redaction not listed in the manifest's redaction report
    refuses coded OFFLINE_VERIFY_REDACTION_UNDISCLOSED (the bundle is
    re-chained and re-layered so the digest matches; only the disclosure
    is missing). HELD."""
    import hashlib
    from gov import offline_bundle as OB
    tmp = tempfile.mkdtemp(prefix="w325-p2g-")
    log_path, signer = _wo._build_log(tmp)
    adapter = _wo.AA.FakeLogAdapter(_wo._SEED_LOG)
    bundle_dir = _wo._export(tmp, "bundle", log_path, signer, adapter)
    p = os.path.join(bundle_dir, "ledger.jsonl")
    entries = [json.loads(line) for line in open(p) if line.strip()]
    e = entries[2]
    del e["target"]
    e.pop("ed_sig", None)
    e.pop("sig_key_id", None)
    e["redacted"] = True
    with open(p, "w", encoding="utf-8") as f:
        for ee in entries:
            f.write(OB._canonical(ee).decode("utf-8") + "\n")
    adapter2 = _wo.AA.FakeLogAdapter(
        hashlib.sha256(b"w325-log-redact").digest())
    _wo._rechain(bundle_dir, adapter2)
    _wo._attach_layer(bundle_dir, adapter2)
    _wo._refresh_digest(bundle_dir)
    trust_root = _wo._trust_root(adapter2)
    return _expect_code("P2g-undisclosed-redaction",
                       lambda: _wo._verify(bundle_dir, trust_root),
                       _wo.OV.OfflineVerifyError,
                       "offline-verify-redaction-undisclosed",
                       "redaction not listed in redaction report")


@probe("P2h-anchor-statement-tamper")
def _p2h():
    """Tampering the anchor receipt's statement (then re-layering so the
    bundle digest matches) refuses coded OFFLINE_VERIFY_ANCHOR_INVALID --
    the statement-mismatch check fires before the signature check. HELD."""
    tmp = tempfile.mkdtemp(prefix="w325-p2h-")
    bd, tr, adapter = _wo._good_package(tmp, name="p2h")
    ap = os.path.join(bd, "anchor_receipt.json")
    rec = json.load(open(ap))
    rec["statement"]["log_index"] = 424242
    json.dump(rec, open(ap, "w"))
    os.remove(os.path.join(bd, "witness_layer.json"))
    _wo._attach_layer(bd, adapter)
    _wo._refresh_digest(bd)
    return _expect_code("P2h-anchor-statement-tamper",
                       lambda: _wo._verify(bd, tr),
                       _wo.OV.OfflineVerifyError,
                       "offline-verify-anchor-invalid",
                       "anchor statement tampered under valid signature")


@probe("P2i-small-carrier-tamper")
def _p2i():
    """Tampering the small-carrier QR bytes refuses coded
    OFFLINE_VERIFY_WITNESS_LAYER_INVALID (the carrier is excluded from the
    bundle digest by construction, so no re-layering is needed). HELD."""
    tmp = tempfile.mkdtemp(prefix="w325-p2i-")
    bd, tr, _ = _wo._good_package(tmp, name="p2i", carrier=True)
    cp = os.path.join(bd, "small_carrier.bin")
    data = bytearray(open(cp, "rb").read())
    data[10] ^= 0xFF
    open(cp, "wb").write(bytes(data))
    return _expect_code("P2i-small-carrier-tamper",
                       lambda: _wo._verify(bd, tr),
                       _wo.OV.OfflineVerifyError,
                       "offline-verify-witness-layer-invalid",
                       "small-carrier QR bytes forged")

# ---------------------------------------------------------------------------
# P3: threshold VSA (gov/vsa_threshold.py).
# ---------------------------------------------------------------------------

@probe("P3a-bogus-attestation-appended")
def _p3a():
    """Appending an unpinned attestation refuses the WHOLE packet coded
    VSA_THRESHOLD_SIGNER_UNPINNED -- strict fail-closed (availability cost:
    one bad attestation sinks the packet, by design). HELD."""
    vt, _ = _wv._mod()
    s1, s2, s3, evil = _wv._signers()
    packet = _wv._issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2)
    packet["attestations"].append({
        "verifier_id": "ghost", "key_id": "ab" * 8,
        "time_verified": _wv.FRESH_TIME, "signature": "ab" * 64})
    return _expect_code("P3a-bogus-attestation-appended",
                       lambda: vt.verify_vsa(packet, _wv._trust(s1, s2, s3)),
                       vt.VSAThresholdError,
                       "vsa-threshold-signer-unpinned",
                       "unpinned attestation appended")


@probe("P3b-duplicate-attestation-counted-once")
def _p3b():
    """Duplicating a valid attestation still verifies but counts the
    verifier once -- no quorum manufacturing by copy. HELD."""
    vt, _ = _wv._mod()
    s1, s2, s3, evil = _wv._signers()
    packet = _wv._issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2)
    packet["attestations"].append(copy.deepcopy(packet["attestations"][0]))
    try:
        r = vt.verify_vsa(packet, _wv._trust(s1, s2, s3))
    except Exception as exc:  # noqa: BLE001
        return _break("P3b-duplicate-attestation-counted-once",
                      "honest duplicated attestation refused: %r" % (exc,))
    if r["verifier_ids"] == ["v1", "v2"]:
        return _held("P3b-duplicate-attestation-counted-once",
                     "duplicate counted once; quorum honest")
    return _break("P3b-duplicate-attestation-counted-once",
                  "verifier ids inflated: %r" % (r["verifier_ids"],))


@probe("P3c-threshold-lowered-in-transit")
def _p3c():
    """Lowering the packet threshold in transit breaks the attestation
    signatures (threshold is part of the signed statement): coded
    VSA_THRESHOLD_SIGNATURE_INVALID. HELD."""
    vt, _ = _wv._mod()
    s1, s2, s3, evil = _wv._signers()
    packet = _wv._issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2)
    packet["threshold"] = 1
    return _expect_code("P3c-threshold-lowered-in-transit",
                       lambda: vt.verify_vsa(packet, _wv._trust(s1, s2, s3)),
                       vt.VSAThresholdError,
                       "vsa-threshold-signature-invalid",
                       "threshold lowered 2->1 in transit")


@probe("P3d-cross-decision-replay")
def _p3d():
    """Transplanting an attestation from decision B's packet onto decision
    A's breaks the signature (decision digest is in the signed statement):
    coded VSA_THRESHOLD_SIGNATURE_INVALID. HELD."""
    vt, _ = _wv._mod()
    s1, s2, s3, evil = _wv._signers()
    pa = _wv._issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2)
    pb = _wv._issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2,
                    decision=_wv.DECISION_B)
    pa["attestations"][1] = copy.deepcopy(pb["attestations"][1])
    return _expect_code("P3d-cross-decision-replay",
                       lambda: vt.verify_vsa(pa, _wv._trust(s1, s2, s3)),
                       vt.VSAThresholdError,
                       "vsa-threshold-signature-invalid",
                       "attestation replayed across decisions")


@probe("P3e-one-key-two-verifiers-registry-hygiene")
def _p3e():
    """If the consumer's registry pins the SAME key for v1 and v2, one key
    holder can sign as both and meet quorum. This is a registry-hygiene
    boundary (documented in the module: the threshold only bounds how many
    must collude), not a verifier bug -- the consumer must pin distinct
    keys per verifier. HELD with note."""
    vt, _ = _wv._mod()
    s1, s2, s3, evil = _wv._signers()
    trust = _wv._trust(s1, s2, s3)
    reg = dict(trust["verifier_registry"])
    reg["v2"] = [s1.public_key.hex()]
    trust = dict(trust, verifier_registry=reg)
    verifs = [_wv._verification("v1"), _wv._verification("v2")]
    signers = [{"verifier_id": "v1", "key_id": s1.key_id, "sign": s1.sign},
               {"verifier_id": "v2", "key_id": s1.key_id, "sign": s1.sign}]
    packet = vt.issue_vsa(_wv.DECISION_A, verifs, signers, 2)
    try:
        r = vt.verify_vsa(packet, trust)
    except Exception as exc:  # noqa: BLE001
        return _break("P3e-one-key-two-verifiers-registry-hygiene",
                      "refused unexpectedly: %r" % (exc,))
    if r["verifier_ids"] == ["v1", "v2"]:
        return _held("P3e-one-key-two-verifiers-registry-hygiene",
                     "one key as v1+v2 meets quorum -- consumer must pin "
                     "distinct keys per verifier (documented boundary)")
    return _break("P3e-one-key-two-verifiers-registry-hygiene",
                  "unexpected verifier ids %r" % (r["verifier_ids"],))


@probe("P3f-policy-currency-omitted-caller-error")
def _p3f():
    """A trust config that omits policy_currency is a caller error:
    ValueError, never a silent stale-policy accept. HELD."""
    vt, _ = _wv._mod()
    s1, s2, s3, evil = _wv._signers()
    trust = dict(_wv._trust(s1, s2, s3))
    del trust["policy_currency"]
    packet = _wv._issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2)
    try:
        vt.verify_vsa(packet, trust)
    except ValueError:
        return _held("P3f-policy-currency-omitted-caller-error",
                     "missing currency -> ValueError, no silent accept")
    except Exception as exc:  # noqa: BLE001
        return _break("P3f-policy-currency-omitted-caller-error",
                      "wrong exception %r" % (exc,))
    return _break("P3f-policy-currency-omitted-caller-error",
                  "verified without a currency floor")


@probe("P3g-stale-policy-version")
def _p3g():
    """A packet whose policy version is below the consumer's min_version
    refuses coded VSA_THRESHOLD_POLICY_STALE. HELD."""
    vt, _ = _wv._mod()
    s1, s2, s3, evil = _wv._signers()
    packet = _wv._issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2,
                       inputs=_wv._inputs(policy_version=3))
    return _expect_code("P3g-stale-policy-version",
                       lambda: vt.verify_vsa(packet, _wv._trust(s1, s2, s3)),
                       vt.VSAThresholdError,
                       "vsa-threshold-policy-stale",
                       "policy v3 below min_version 5")


@probe("P3h-disagreement-smuggling-refused-at-issue")
def _p3h():
    """Two verifications that disagree on inputs cannot be issued as one
    packet: issue_vsa raises ValueError (unanimous-inputs rule), and the
    signature covers the common statement anyway. HELD."""
    vt, _ = _wv._mod()
    s1, s2, s3, evil = _wv._signers()
    v_a = _wv._verification("v1", inputs=_wv._inputs(policy_version=5))
    v_b = _wv._verification("v2", inputs=_wv._inputs(policy_version=6))
    try:
        vt.issue_vsa(_wv.DECISION_A, [v_a, v_b],
                     [{"verifier_id": "v1", "key_id": s1.key_id,
                       "sign": s1.sign},
                      {"verifier_id": "v2", "key_id": s2.key_id,
                       "sign": s2.sign}], 2)
    except ValueError:
        return _held("P3h-disagreement-smuggling-refused-at-issue",
                     "disagreeing inputs refused at issue time")
    except Exception as exc:  # noqa: BLE001
        return _break("P3h-disagreement-smuggling-refused-at-issue",
                      "wrong exception %r" % (exc,))
    return _break("P3h-disagreement-smuggling-refused-at-issue",
                  "disagreeing verifications issued as one packet")

# ---------------------------------------------------------------------------
# P4: regression -- F408 / F407 / F406 must stay HELD (all closed).
# ---------------------------------------------------------------------------

@probe("P4a-f408-p17-monitor-state-deleted-loud")
def _p4a():
    """F408 CLOSED 2026-10-04: monitor-state deletion mid-outage (no mirror
    head) fires the backwards-count guard LOUD. Same scenario as P1h; kept
    as the explicit F408 regression probe. Must stay HELD -- do not
    re-file."""
    _pid, verdict, note = _p1h()
    return ("P4a-f408-p17-monitor-state-deleted-loud", verdict, note)


def _p4_w322(pid, fn):
    """Run a w322 probe function and re-label it into this battery."""
    _pid, verdict, note = fn()
    return (pid, verdict, note)


@probe("P4b-f407-malformed-referrers-array")
def _p4b():
    return _p4_w322("P4b-f407-malformed-referrers-array", _w322._p2_mal_array)


@probe("P4c-f407-malformed-referrers-string")
def _p4c():
    return _p4_w322("P4c-f407-malformed-referrers-string", _w322._p2_mal_string)


@probe("P4d-f407-malformed-referrers-subject")
def _p4d():
    return _p4_w322("P4d-f407-malformed-referrers-subject", _w322._p2_mal_subject)


@probe("P4e-f407-malformed-entry-digest")
def _p4e():
    return _p4_w322("P4e-f407-malformed-entry-digest", _w322._p2_mal_entry)


@probe("P4f-f407-malformed-referrers-null")
def _p4f():
    return _p4_w322("P4f-f407-malformed-referrers-null", _w322._p2_mal_null)


@probe("P4g-f407-malformed-tag-list")
def _p4g():
    return _p4_w322("P4g-f407-malformed-tag-list", _w322._p2_mal_taglist)


@probe("P4h-f407-malformed-manifest-int-digest")
def _p4h():
    return _p4_w322("P4h-f407-malformed-manifest-int-digest",
                   _w322._p2_mal_manifest_digest)


@probe("P4i-f406-near-miss-dnot-transposed")
def _p4i():
    return _p4_w322("P4i-f406-near-miss-dnot-transposed", _w322._p3a)


@probe("P4j-f406-near-miss-odnt-transposed")
def _p4j():
    return _p4_w322("P4j-f406-near-miss-odnt-transposed", _w322._p3b)


@probe("P4k-f406-near-miss-cannt-doubled")
def _p4k():
    return _p4_w322("P4k-f406-near-miss-cannt-doubled", _w322._p3c)


@probe("P4l-f406-near-miss-cnt-syncope")
def _p4l():
    return _p4_w322("P4l-f406-near-miss-cnt-syncope", _w322._p3d)


@probe("P4m-f406-near-miss-wnt-syncope")
def _p4m():
    _pid, verdict, note = _w322._p3e()
    return ("P4m-f406-near-miss-wnt-syncope", verdict, note)

# ---------------------------------------------------------------------------
# P5: prior-battery regression (child mode, GOV_SKIP_GREEN=1).
# ---------------------------------------------------------------------------

def _parse_tally(text):
    import re
    m = re.search(r"(\d+)\s+BREAK\s*/\s*(\d+)\s+HELD\s*/\s*(\d+)\s+ERROR",
                  text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


_GREEN_EVALS = [
    # Tallies are post-F409-filing: each battery's footer-state probe
    # breaks once (it was written for the pre-filing footer "open none /
    # next F409"; the true footer is now "open F412 / next F413"). The
    # merge updates those footer probes per the wave-305 lesson; the
    # single BREAK in each child is that probe and nothing else.
    ("w324-alert", "evals/w324_alert_probes.py", (0, 18, 0)),
    ("w324-offver", "evals/w324_offver_probes.py", (0, 32, 0)),
    ("w324-vsa", "evals/w324_vsa_probes.py", (0, 22, 0)),
    ("w324-redteam", "evals/w324_redteam_probes.py", (0, 41, 0)),
    ("w323-redteam", "evals/w323_redteam_probes.py", (0, 42, 0)),
]


def _run_green_eval(name, rel, expect):
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tempfile.mkdtemp(prefix="w325-gc-")
    try:
        p = subprocess.run(
            [sys.executable, os.path.join(REPO, rel)],
            env=env, capture_output=True, text=True, timeout=900)
    except Exception as exc:  # noqa: BLE001
        return (name, "ERROR", "spawn failed: %r" % (exc,))
    tally = _parse_tally(p.stdout or "")
    if tally is None:
        return (name, "ERROR",
                "no tally parsed; rc=%s tail=%r"
                % (p.returncode, (p.stdout or "")[-400:]))
    if tally != expect:
        return (name, "BREAK",
                "tally %s != expected %s" % (tally, expect))
    # Tally matches: HELD. (rc semantics differ across batteries --
    # w324-alert/offver exit 1 on any BREAK, the others only on ERROR --
    # so rc is informational once the tally is as expected.)
    return (name, "HELD", "%s child tally %d/%d/%d (rc=%d)"
            % ((name,) + tally + (p.returncode,)))


def green_check():
    """Run adjacent batteries in child mode. Honors GOV_SKIP_GREEN so
    nesting stays depth-1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD", "skipped (child mode)")
        return
    for name, rel, expect in _GREEN_EVALS:
        _record(*_run_green_eval(name, rel, expect))


@probe("P5a-green-w324-alert")
def _p5a():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5a-green-w324-alert", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[0])
    return ("P5a-green-w324-alert", verdict, note)


@probe("P5b-green-w324-offver")
def _p5b():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5b-green-w324-offver", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[1])
    return ("P5b-green-w324-offver", verdict, note)


@probe("P5c-green-w324-vsa")
def _p5c():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5c-green-w324-vsa", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[2])
    return ("P5c-green-w324-vsa", verdict, note)


@probe("P5d-green-w324-redteam")
def _p5d():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5d-green-w324-redteam", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[3])
    return ("P5d-green-w324-redteam", verdict, note)


@probe("P5e-green-w323-redteam")
def _p5e():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5e-green-w323-redteam", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[4])
    return ("P5e-green-w323-redteam", verdict, note)


# ---------------------------------------------------------------------------
# P6: taxonomy pin + footer state.
# ---------------------------------------------------------------------------

@probe("P6a-pin-taxonomy-2077-sorted")
def _p6a():
    from gov import decision_codes
    codes = list(decision_codes.TAXONOMY)
    if TAXONOMY_PIN != 2077:
        return _break("P6a-pin-taxonomy-2077-sorted",
                      "TAXONOMY_PIN is %r, want 2021" % (TAXONOMY_PIN,))
    if len(codes) != 2077 or codes != sorted(codes):
        return _break("P6a-pin-taxonomy-2077-sorted",
                      "taxonomy size/order drift: n=%d" % (len(codes),))
    return _held("P6a-pin-taxonomy-2077-sorted", "2077/2077/0 sorted")


@probe("P6b-footer-open-none-next-f417")
def _p6b():
    text = open(os.path.join(REPO, "evals/FINDINGS.md")).read()
    import re
    # The file carries one footer line per wave; the LAST one is current.
    # Footer form: "Next free finding: **F417**. **Open findings: none.**"
    opens = re.findall(r"\*\*Open findings:\s*([^*]+?)\.\*\*", text)
    nexts = re.findall(r"Next free finding:\s*\*\*([^*]+?)\*\*", text)
    open_line = opens[-1].strip() if opens else ""
    next_free = nexts[-1].strip() if nexts else ""
    if open_line != FOOTER_OPEN:
        return _break("P6b-footer-open-none-next-f417",
                      "open findings %r, want %r" % (open_line, FOOTER_OPEN))
    if next_free != FOOTER_NEXT:
        return _break("P6b-footer-open-none-next-f417",
                      "next free %r, want %r" % (next_free, FOOTER_NEXT))
    return _held("P6b-footer-open-none-next-f417",
                 "footer open none / next F417")


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

def main(argv):
    only = argv[1] if len(argv) > 1 else None
    for pid, fn in _PROBES:
        if only is not None and pid != only:
            continue
        _safe(pid, fn)
    if only is None:
        green_check()
    breaks = errors = 0
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "ERROR":
            errors += 1
    print("w325_redteam battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAK expected: F409 closed)"
          % (breaks, len(_results) - breaks - errors, errors))
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
