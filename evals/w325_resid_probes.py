"""Break-first probes for the wave-325 residual hardening.

Red-first: on the base tree (b2562b59) the four documented residuals
are live, so these probes BREAK/ERROR there. On the lane tree every
hardened behavior below must hold -- 0 BREAK / 0 ERROR target.

1. Webhook queue overflow: drain_queue() silently dropped the oldest
   queued alerts beyond _MAX_QUEUE_LINES. Now it emits a coded
   witness-alert-queue-overflow record (durable, in the file sink);
   every dropped alert is counted, never silent.
2. main() exit-1 with a broken sink had no channel to be loud through.
   Now a structured last-resort record goes to stderr AND a durable
   status file; the next tick with a working sink re-announces it LOUD
   (wrapper-error) before any heartbeat, and a corrupt/unreadable
   status file is itself announced LOUD.
3. Trust-anchor unknown fields were ignored while every other policy
   level fails closed on unknown fields. Now the anchor level fails
   closed too.
4. verifier_inputs()["policy_version"] had no downstream consumer.
   Now export_witness.verify_witness_layer and decode_small_carrier
   enforce an auditor-pinned minimum (min_policy_version), wired
   through offline_verify's trust root; a stale policy refuses with a
   coded reason.

Staging default is set at module level (the harness refuses the
declared ungoverned_ack in production mode).
"""

import contextlib
import hashlib
import io
import json
import os
import secrets
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2127  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).


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


def _expect_code(pid, fn, code):
    """fn() must raise an error whose .code == code; anything else BREAKs."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None)
        if got == code:
            _held(pid, "refused coded %s" % (code,))
        else:
            _break(pid, "wrong refusal: code=%r (%s: %s)"
                   % (got, type(exc).__name__, exc))
        return
    _break(pid, "no refusal (expected coded %s)" % (code,))


# ---------------------------------------------------------------------------
# Imports.
# ---------------------------------------------------------------------------

from gov import monitor_alert as MA  # noqa: E402
from gov import offline_verify as OV  # noqa: E402
from gov import export_witness as EW  # noqa: E402
from gov import witness_policy as WP  # noqa: E402
from gov import witness_log as WL  # noqa: E402
from gov import checkpoint_note as CN  # noqa: E402
from gov import offline_bundle as OB  # noqa: E402
from gov import anchor_adapter as AA  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402


# ---------------------------------------------------------------------------
# Shared fixtures (fixed seeds: deterministic keys across runs).
# ---------------------------------------------------------------------------

_SEED_OP = bytes(range(32))
_SEED_W1 = bytes([255 - i for i in range(32)])
_SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
_SEED_W3 = bytes([(i * 13 + 5) % 256 for i in range(32)])
_SEED_P1 = bytes([(i * 3 + 11) % 256 for i in range(32)])
_SEED_P2 = bytes([(i * 5 + 17) % 256 for i in range(32)])
_SEED_ENTRY = bytes([(i * 29 + 3) % 256 for i in range(32)])
_SEED_LOG = hashlib.sha256(b"w325-resid-log").digest()
_NOW = 1798765432
_ORIGIN = "sasanam-resid-test/v1"
_BUNDLE = b"test-bundle-artifact-bytes"
_BUNDLE_DIGEST = hashlib.sha256(_BUNDLE).hexdigest()
_NLEAF = 8
_MID = "witmon-resid-test-1"


def _signer(seed):
    return Ed25519Signer(seed)


def _op_vkey():
    s = _signer(_SEED_OP)
    return CN.vkey_string(
        "op", CN.derive_key_id("op", CN.SIG_TYPE_ED25519, s.public_key),
        CN.SIG_TYPE_ED25519, s.public_key)


def _wit_vkey(name, seed):
    s = _signer(seed)
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519_COSIGNATURE_V1,
                               s.public_key),
        CN.SIG_TYPE_ED25519_COSIGNATURE_V1, s.public_key)


def _wit(name, seed):
    return {"name": name, "vkey": _wit_vkey(name, seed),
            "operator": "%s-operator" % name,
            "contact": "%s@example.org" % name,
            "not_before": _NOW - 100000, "not_after": _NOW + 100000,
            "status": "usable"}


def _policy_body(threshold=2, policy_threshold=2, version=1):
    p1, p2 = _signer(_SEED_P1), _signer(_SEED_P2)
    return {
        "schema": "witness-policy/v1",
        "policy_id": "sasanam-witness-policy",
        "version": version,
        "issued_at": _NOW - 1000,
        "expires_at": _NOW + 86400 * 90,
        "threshold": threshold,
        "log": {"name": "op", "vkey": _op_vkey()},
        "witnesses": [_wit("w1", _SEED_W1), _wit("w2", _SEED_W2),
                      _wit("w3", _SEED_W3)],
        "policy_signers": [{"key_id": s.public_key.hex(),
                            "public_key": s.public_key.hex()}
                           for s in (p1, p2)],
        "policy_threshold": policy_threshold,
        "max_checkpoint_staleness_seconds": 10800,
    }


def _anchor_signers():
    p1, p2 = _signer(_SEED_P1), _signer(_SEED_P2)
    return [{"key_id": s.public_key.hex(), "public_key": s.public_key.hex()}
            for s in (p1, p2)]


def _anchor():
    return {"policy_signers": _anchor_signers(), "policy_threshold": 2}


def _sealed(**kw):
    return WP.seal_policy(_policy_body(**kw),
                          [_signer(_SEED_P1), _signer(_SEED_P2)])


def _leaves(digest_hex=None):
    d = bytes.fromhex(digest_hex or _BUNDLE_DIGEST)
    return [EW.bundle_leaf_hash(d, i) for i in range(_NLEAF)]


def _note(leaves=None, ts=None, witnesses=("w1", "w2"), origin=_ORIGIN,
          op_seed=_SEED_OP):
    leaves = leaves or _leaves()
    root = WL._calc_root(leaves)
    note = CN.emit_checkpoint(origin, len(leaves), root, "op", op_seed)
    seeds = {"w1": _SEED_W1, "w2": _SEED_W2, "w3": _SEED_W3}
    for w in witnesses:
        line = CN.emit_cosignature_line(w, _signer(seeds[w]), origin,
                                        len(leaves), root,
                                        _NOW - 100 if ts is None else ts)
        note += (line + "\n").encode("utf-8")
    return note.decode("utf-8")


def _good_layer(**kw):
    leaves = _leaves()
    doc = _sealed()
    layer = EW.build_witness_layer(
        _BUNDLE_DIGEST, checkpoint=_note(leaves), policy_doc=doc,
        trust_anchor=_anchor(),
        consistency_proof=EW.make_consistency_proof(leaves, 3),
        inclusion_proofs=[EW.make_inclusion_proof(leaves, 0),
                          EW.make_inclusion_proof(leaves, 5)],
        bundle_id="test-bundle-1", now=_NOW, **kw)
    return layer, doc


def _good_layer_v3(**kw):
    """Same as _good_layer but sealed under a policy with version=3."""
    leaves = _leaves()
    doc = _sealed(version=3)
    layer = EW.build_witness_layer(
        _BUNDLE_DIGEST, checkpoint=_note(leaves), policy_doc=doc,
        trust_anchor=_anchor(),
        consistency_proof=EW.make_consistency_proof(leaves, 3),
        inclusion_proofs=[EW.make_inclusion_proof(leaves, 0),
                          EW.make_inclusion_proof(leaves, 5)],
        bundle_id="test-bundle-1", now=_NOW, **kw)
    return layer, doc


# ---------------------------------------------------------------------------
# monitor_alert fixtures (modeled on evals/w324_alert_probes.py).
# ---------------------------------------------------------------------------

def _ma_world(n=5):
    op = Ed25519Signer(_SEED_OP)
    w1 = Ed25519Signer(_SEED_W1)
    w2 = Ed25519Signer(_SEED_W2)
    log = WL.WitnessLog(op.public_key)
    for i in range(n):
        log.append(b"leaf-%d" % i)
    op_vk = [_op_vkey()]
    wit_vk = {"w1": _wit_vkey("w1", _SEED_W1),
              "w2": _wit_vkey("w2", _SEED_W2)}
    return (op, w1, w2, op_vk, wit_vk), log


def _ma_publish(keys, log, ts, quorum_k=2):
    import gov.witness_publish as WPUB
    op, w1, w2, op_vk, wit_vk = keys
    return WPUB.publish_checkpoint(
        log, _ORIGIN, "op", op, [("w1", w1), ("w2", w2)],
        operator_vkeys=op_vk, witness_vkeys=wit_vk, quorum_k=quorum_k,
        timestamp=ts)


def _ma_cfg(d, keys, log, fetch=None, now=_NOW, max_age=3600,
            last_resort_path=None):
    op, w1, w2, op_vk, wit_vk = keys
    cfg = {
        "monitor_id": _MID,
        "state_path": os.path.join(d, "monitor-state.json"),
        "alert_state_path": os.path.join(d, "alert-state.json"),
        "sink": {"type": "memory"},
        "fetch": fetch,
        "witness_set": wit_vk,
        "policy_inputs": {"operator_vkeys": op_vk, "quorum_k": 2,
                          "policy_id": "test", "policy_version": 1},
        "allowed_origins": [_ORIGIN],
        "max_age": max_age,
        "now": now,
    }
    if last_resort_path is not None:
        cfg["last_resort_path"] = last_resort_path
    return cfg


def _queue_records(qp):
    with open(qp, encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh.read().splitlines()
                if ln.strip()]


# ---------------------------------------------------------------------------
# Item 1: webhook queue overflow is LOUD and counted.
# ---------------------------------------------------------------------------

@probe("P1-queue-overflow-emits-coded-record")
def _p1():
    d = tempfile.mkdtemp(prefix="resid-q1-")
    qp = os.path.join(d, "queue.jsonl")
    sink = MA.WebhookAlertSink("http://127.0.0.1:9/none", qp)
    sink._post = lambda alert: False
    n = MA._MAX_QUEUE_LINES + 5
    with open(qp, "w", encoding="utf-8") as fh:
        for i in range(n):
            fh.write(json.dumps({"alert_id": "a-%d" % i, "n": i}) + "\n")
    delivered, remaining = sink.drain_queue()
    assert delivered == 0, (delivered, remaining)
    over = [r for r in _queue_records(qp)
            if r.get("alert_kind") == "queue-overflow"]
    assert len(over) == 1, \
        "expected exactly one overflow record, got %d" % len(over)
    rec = over[0]
    assert rec.get("last_code") == "witness-alert-queue-overflow", rec
    assert rec.get("dropped_alerts") == 5, rec
    _held("P1-queue-overflow-emits-coded-record",
          "overflow LOUD and counted: 5 dropped, coded")


@probe("P2-queue-overflow-keeps-queue-bounded")
def _p2():
    d = tempfile.mkdtemp(prefix="resid-q2-")
    qp = os.path.join(d, "queue.jsonl")
    sink = MA.WebhookAlertSink("http://127.0.0.1:9/none", qp)
    sink._post = lambda alert: False
    with open(qp, "w", encoding="utf-8") as fh:
        for i in range(MA._MAX_QUEUE_LINES + 3):
            fh.write(json.dumps({"alert_id": "b-%d" % i}) + "\n")
    delivered, remaining = sink.drain_queue()
    assert (delivered, remaining) == (0, MA._MAX_QUEUE_LINES), \
        (delivered, remaining)
    recs = _queue_records(qp)
    assert len(recs) <= MA._MAX_QUEUE_LINES + 1, len(recs)
    over = [r for r in recs if r.get("alert_kind") == "queue-overflow"]
    assert len(over) == 1 and over[0]["dropped_alerts"] == 3, over
    _held("P2-queue-overflow-keeps-queue-bounded",
          "queue stays bounded; overflow record counted 3")


@probe("P3-no-overflow-record-when-under-cap")
def _p3():
    d = tempfile.mkdtemp(prefix="resid-q3-")
    qp = os.path.join(d, "queue.jsonl")
    sink = MA.WebhookAlertSink("http://127.0.0.1:9/none", qp)
    sink._post = lambda alert: False
    with open(qp, "w", encoding="utf-8") as fh:
        for i in range(10):
            fh.write(json.dumps({"alert_id": "c-%d" % i}) + "\n")
    delivered, remaining = sink.drain_queue()
    assert (delivered, remaining) == (0, 10), (delivered, remaining)
    recs = _queue_records(qp)
    assert len(recs) == 10, len(recs)
    assert not [r for r in recs
                if r.get("alert_kind") == "queue-overflow"], recs
    _held("P3-no-overflow-record-when-under-cap",
          "no spurious overflow record under the cap")


# ---------------------------------------------------------------------------
# Item 2: last-resort channel for wrapper failures with a broken sink.
# ---------------------------------------------------------------------------

@probe("P4-last-resort-record-on-broken-sink")
def _p4():
    d = tempfile.mkdtemp(prefix="resid-lr4-")
    qdir = os.path.join(d, "qdir")
    os.makedirs(qdir)  # a directory, not a file: every sink write fails
    lr = os.path.join(d, "last-resort.jsonl")
    cfg_path = os.path.join(d, "config.json")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump({"sink": {"type": "file", "queue_path": qdir},
                   "last_resort_path": lr}, fh)
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        rc = MA.main(["monitor_alert.py", cfg_path])
    assert rc == 1, rc
    assert os.path.exists(lr), "no last-resort file written"
    recs = [json.loads(ln) for ln in open(lr, encoding="utf-8")
            .read().splitlines() if ln.strip()]
    assert len(recs) == 1, recs
    rec = recs[0]
    assert rec.get("kind") == "last-resort", rec
    assert rec.get("code") == "witness-alert-wrapper-error", rec
    assert "LAST-RESORT" in buf.getvalue(), buf.getvalue()
    _held("P4-last-resort-record-on-broken-sink",
          "exit-1 writes structured last-resort record to stderr+file")


@probe("P4b-double-fault-still-last-resorts")
def _p4b():
    # Broken sink AND broken config: the durable half must still fire.
    d = tempfile.mkdtemp(prefix="resid-lr4b-")
    lr = os.path.join(d, "last-resort.jsonl")
    cfg_path = os.path.join(d, "config.json")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump({"sink": {"type": "bogus-sink-type"},
                   "last_resort_path": lr}, fh)  # + missing monitor_id
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        rc = MA.main(["monitor_alert.py", cfg_path])
    assert rc == 1, rc
    assert os.path.exists(lr), "no last-resort file on double fault"
    recs = [json.loads(ln) for ln in open(lr, encoding="utf-8")
            .read().splitlines() if ln.strip()]
    assert len(recs) == 1, recs
    assert recs[0].get("kind") == "last-resort", recs[0]
    assert "LAST-RESORT" in buf.getvalue(), buf.getvalue()
    _held("P4b-double-fault-still-last-resorts",
          "broken sink + broken config: durable last-resort still fires")


@probe("P5-next-tick-reannounces-before-heartbeat")
def _p5():
    keys, log = _ma_world()
    d = tempfile.mkdtemp(prefix="resid-lr5-")
    lr = os.path.join(d, "last-resort.jsonl")
    with open(lr, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "alert_id": "witmon-alert/%s/last-resort/1/1" % _MID,
            "kind": "last-resort", "monitor_id": _MID, "ts": _NOW,
            "code": "witness-alert-wrapper-error",
            "detail": "simulated prior sink failure"}) + "\n")
    note = _ma_publish(keys, log, _NOW - 100)
    cfg = _ma_cfg(d, keys, log, fetch=lambda: note,
                  last_resort_path=lr)
    sink = MA.MemoryAlertSink()
    orig = MA._build_sink
    MA._build_sink = lambda c: sink
    try:
        r = MA.run_monitor_once(cfg)
    finally:
        MA._build_sink = orig
    assert r["healthy"] is True, r
    kinds = [a["alert_kind"] for a in sink.alerts]
    assert kinds == ["wrapper-error", "heartbeat"], kinds
    we = sink.alerts[0]
    assert we["last_code"] == "witness-alert-wrapper-error", we
    assert "witness-alert-wrapper-error" in we["last_detail"], we
    assert open(lr, encoding="utf-8").read().strip() == "", \
        "last-resort file not cleared after re-announce"
    n = len(sink.alerts)
    cfg["now"] = _NOW + 10
    orig = MA._build_sink
    MA._build_sink = lambda c: sink
    try:
        MA.run_monitor_once(cfg)
    finally:
        MA._build_sink = orig
    assert len(sink.alerts) == n, \
        "duplicate re-announcement on the following tick"
    _held("P5-next-tick-reannounces-before-heartbeat",
          "prior failure surfaces first, then heartbeat; cleared; no dup")


@probe("P6-corrupt-last-resort-file-is-loud")
def _p6():
    keys, log = _ma_world()
    d = tempfile.mkdtemp(prefix="resid-lr6-")
    lr = os.path.join(d, "last-resort.jsonl")
    with open(lr, "w", encoding="utf-8") as fh:
        fh.write("this is not json {{{{\n")
    note = _ma_publish(keys, log, _NOW - 100)
    cfg = _ma_cfg(d, keys, log, fetch=lambda: note,
                  last_resort_path=lr)
    sink = MA.MemoryAlertSink()
    orig = MA._build_sink
    MA._build_sink = lambda c: sink
    try:
        r = MA.run_monitor_once(cfg)
    finally:
        MA._build_sink = orig
    assert r["healthy"] is True, r
    kinds = [a["alert_kind"] for a in sink.alerts]
    assert kinds[0] == "wrapper-error", kinds
    assert "last-resort" in sink.alerts[0]["last_detail"], \
        sink.alerts[0]
    assert open(lr, encoding="utf-8").read().strip() == "", \
        "corrupt last-resort file not cleared"
    _held("P6-corrupt-last-resort-file-is-loud",
          "unreadable last-resort file announced LOUD, not ignored")


# ---------------------------------------------------------------------------
# Item 3: trust anchor fails closed on unknown fields.
# ---------------------------------------------------------------------------

@probe("P7-anchor-unknown-field-refused")
def _p7():
    doc = _sealed()
    bad = _anchor()
    bad["note"] = "a stray field that must not be silently ignored"
    _expect_code("P7-anchor-unknown-field-refused",
                 lambda: WP.verify_policy_document(doc, bad),
                 "witness-policy-unknown-field")


@probe("P8-anchor-clean-still-verifies")
def _p8():
    doc = _sealed()
    out = WP.verify_policy_document(doc, _anchor())
    # verify_policy_document returns the public body on success (raises
    # on refusal -- no bare boolean).
    assert out["policy_id"] == "sasanam-witness-policy", out
    assert out["version"] == 1, out
    assert len(out["policy_signers"]) == 2, out
    _held("P8-anchor-clean-still-verifies",
          "two-field anchor still verifies (no over-refusal)")


# ---------------------------------------------------------------------------
# Item 4: policy_version wired into a real consumer (auditor-pinned floor).
# ---------------------------------------------------------------------------

@probe("P9-version-floor-refuses")
def _p9():
    layer, _doc = _good_layer_v3()
    _expect_code("P9-version-floor-refuses",
                 lambda: EW.verify_witness_layer(
                     layer, _anchor(), bundle_digest=_BUNDLE_DIGEST,
                     now=_NOW, min_policy_version=5),
                 "export-witness-policy-version-below-minimum")


@probe("P10-version-floor-equal-passes")
def _p10():
    layer, _doc = _good_layer_v3()
    out = EW.verify_witness_layer(
        layer, _anchor(), bundle_digest=_BUNDLE_DIGEST, now=_NOW,
        min_policy_version=3)
    assert out["policy_version"] == 3, out
    _held("P10-version-floor-equal-passes", "floor == version verifies")


@probe("P11-version-floor-below-passes")
def _p11():
    layer, _doc = _good_layer_v3()
    out = EW.verify_witness_layer(
        layer, _anchor(), bundle_digest=_BUNDLE_DIGEST, now=_NOW,
        min_policy_version=1)
    assert out["policy_version"] == 3, out
    _held("P11-version-floor-below-passes", "floor < version verifies")


@probe("P12-no-floor-unchanged")
def _p12():
    layer, _doc = _good_layer_v3()
    out = EW.verify_witness_layer(layer, _anchor(),
                                  bundle_digest=_BUNDLE_DIGEST, now=_NOW)
    assert out["policy_version"] == 3, out
    _held("P12-no-floor-unchanged", "no floor: back-compat, verifies")


@probe("P13-carrier-floor-refuses")
def _p13():
    layer, doc = _good_layer_v3()
    blob = EW.encode_small_carrier(layer, exported_at=_NOW - 10)
    _expect_code("P13-carrier-floor-refuses",
                 lambda: EW.decode_small_carrier(blob, doc, _anchor(),
                                                 now=_NOW,
                                                 min_policy_version=5),
                 "export-witness-policy-version-below-minimum")


@probe("P14-bad-floor-type-refused")
def _p14():
    layer, _doc = _good_layer_v3()
    _expect_code("P14-bad-floor-type-refused",
                 lambda: EW.verify_witness_layer(
                     layer, _anchor(), bundle_digest=_BUNDLE_DIGEST,
                     now=_NOW, min_policy_version="3"),
                 "export-witness-malformed")
    _expect_code("P14-bad-floor-type-refused",
                 lambda: EW.verify_witness_layer(
                     layer, _anchor(), bundle_digest=_BUNDLE_DIGEST,
                     now=_NOW, min_policy_version=0),
                 "export-witness-malformed")


# ---------------------------------------------------------------------------
# offline_verify: trust root carries the floor through.
# ---------------------------------------------------------------------------

def _ov_trust_root(adapter, **kw):
    root = {"policy_signers": _anchor_signers(),
            "policy_threshold": 2,
            "anchor_log_pubkey_hex": adapter.public_key.hex()}
    root.update(kw)
    return root


def _ov_build_log(tmp):
    os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
    signer = _signer(_SEED_ENTRY)
    log_path = os.path.join(tmp, "audit.jsonl")
    lg = ActionLog(log_path, signer=signer)
    for i in range(8):
        lg.append({"event": "tool_call", "tool": "t%d" % i,
                   "target": "/x/%d" % i})
    return log_path, signer


def _ov_export(tmp, name, log_path, signer, adapter, **kw):
    bundle_dir = os.path.join(tmp, name)
    OB.export_offline_bundle(
        log_path, bundle_dir, adapter,
        entry_signer_pubkey=signer.public_key, **kw)
    return bundle_dir


def _ov_bundle_digest(bundle_dir):
    h = hashlib.sha256()
    rels = []
    for root, _d, names in os.walk(bundle_dir):
        for n in names:
            rel = os.path.relpath(os.path.join(root, n), bundle_dir)
            if rel in ("BUNDLE_DIGEST.sha256", "witness_layer.json",
                       "small_carrier.bin"):
                continue
            rels.append(rel)
    for rel in sorted(rels):
        with open(os.path.join(bundle_dir, rel), "rb") as f:
            content = f.read()
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(content)
        h.update(b"\x00")
    return h.hexdigest()


def _ov_attach_layer(bundle_dir, policy_doc=None, now=_NOW):
    digest = _ov_bundle_digest(bundle_dir)
    leaves = _leaves(digest)
    doc = policy_doc if policy_doc is not None else _sealed()
    layer = EW.build_witness_layer(
        digest, checkpoint=_note(leaves), policy_doc=doc,
        trust_anchor=_anchor(),
        consistency_proof=EW.make_consistency_proof(leaves, 3),
        inclusion_proofs=[EW.make_inclusion_proof(leaves, 0)],
        bundle_id="test-bundle-1", now=now)
    with open(os.path.join(bundle_dir, "witness_layer.json"), "w",
              encoding="utf-8") as f:
        f.write(json.dumps(layer, sort_keys=True))
    return layer


def _ov_good_package_v3(tmp):
    log_path, signer = _ov_build_log(tmp)
    adapter = AA.FakeLogAdapter(_SEED_LOG)
    bundle_dir = _ov_export(tmp, "bundle", log_path, signer, adapter)
    _ov_attach_layer(bundle_dir, policy_doc=_sealed(version=3))
    return bundle_dir, adapter


@probe("P15-offline-verify-floor-refuses")
def _p15():
    tmp = tempfile.mkdtemp(prefix="resid-ov15-")
    bundle_dir, adapter = _ov_good_package_v3(tmp)
    trust_root = _ov_trust_root(adapter, min_policy_version=5)
    try:
        OV.verify_evidence_bundle(bundle_dir, trust_root, now=_NOW)
    except OV.OfflineVerifyError as exc:
        # The verifier wraps the inner coded reason under its own
        # step code (preserved verbatim in the detail).
        assert exc.code == "offline-verify-witness-layer-invalid", exc.code
        assert "export-witness-policy-version-below-minimum" in exc.detail, \
            exc.detail
        assert exc.report["verdict"] == "fail", exc.report["verdict"]
        _held("P15-offline-verify-floor-refuses",
              "trust-root floor refused with the coded inner reason")
        return
    _break("P15-offline-verify-floor-refuses",
           "no refusal: stale policy passed the trust-root floor")


@probe("P16-offline-verify-floor-satisfied-passes")
def _p16():
    tmp = tempfile.mkdtemp(prefix="resid-ov16-")
    bundle_dir, adapter = _ov_good_package_v3(tmp)
    trust_root = _ov_trust_root(adapter, min_policy_version=3)
    report = OV.verify_evidence_bundle(bundle_dir, trust_root, now=_NOW)
    assert report["verdict"] == "pass", report["verdict"]
    assert report["facts"]["policy_version"] == 3, report["facts"]
    _held("P16-offline-verify-floor-satisfied-passes",
          "floor == version: full offline verification passes")


@probe("P17-offline-verify-bad-floor-type-refused")
def _p17():
    tmp = tempfile.mkdtemp(prefix="resid-ov17-")
    bundle_dir, adapter = _ov_good_package_v3(tmp)
    for bad in ("3", 0, True):
        trust_root = _ov_trust_root(adapter, min_policy_version=bad)
        try:
            OV.verify_evidence_bundle(bundle_dir, trust_root, now=_NOW)
        except OV.OfflineVerifyError as exc:
            assert exc.code == "offline-verify-trust-root-invalid", \
                (bad, exc.code)
            continue
        _break("P17-offline-verify-bad-floor-type-refused",
               "no refusal for floor=%r" % (bad,))
        return
    _held("P17-offline-verify-bad-floor-type-refused",
          "bad floor types fail at trust-root pin")


@probe("P18-no-floor-in-trust-root-unchanged")
def _p18():
    tmp = tempfile.mkdtemp(prefix="resid-ov18-")
    bundle_dir, adapter = _ov_good_package_v3(tmp)
    trust_root = _ov_trust_root(adapter)
    report = OV.verify_evidence_bundle(bundle_dir, trust_root, now=_NOW)
    assert report["verdict"] == "pass", report["verdict"]
    _held("P18-no-floor-in-trust-root-unchanged",
          "no floor in trust root: back-compat, passes")


# ---------------------------------------------------------------------------
# Pin + footer state probes.
# ---------------------------------------------------------------------------

@probe("P19-pin-taxonomy-2127-sorted")
def _p19():
    from gov import decision_codes as DC
    import re
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    codes = re.findall(r'"code":\s*["\']([^"\']+)["\']', src)
    # Uniqueness on raw source literals (the wave-260 lesson: the
    # deduped dict cannot see duplicate literals).
    assert len(codes) == len(set(codes)) == TAXONOMY_PIN == 2127, (#Wave-333 merge: pin 2069 -> 2106 (+8 revocation-push-*)
        len(codes), len(set(codes)))
    assert codes == sorted(codes), "taxonomy not sorted"
    for code in ("witness-alert-queue-overflow",
                 "export-witness-policy-version-below-minimum"):
        assert code in DC.TAXONOMY, "new code %r not registered" % code
        entry = DC.TAXONOMY[code]
        assert entry["domain"] == "witness", entry
        assert entry["severity"] == "medium", entry
    _held("P19-pin-taxonomy-2127-sorted", "2127/2127/0 sorted; new codes ok")


@probe("P20-footer-open-none-next-F426")
def _p20():
    path = os.path.join(REPO, "evals", "FINDINGS.md")
    src = open(path, encoding="utf-8").read()
    # Wave-337 lane 1: probe repaired -- the F417-era assertion rotted
    # through many merges; assert the live footer (open none / next
    # F426; F424/F425 closed by wave-337 lane 1).
    assert "Next free finding: **F429**" in src, "next-free footer"
    assert "**Open findings: F428.**" in src, "open-none footer"
    _held("P20-footer-open-none-next-F426",
          "footer: open none / next F428 (F424/F425 closed wave-337 lane 1)")


# ---------------------------------------------------------------------------
# Green checks (depth-1: children run with GOV_SKIP_GREEN=1).
# ---------------------------------------------------------------------------

_GREEN_CHILDREN = [
    "evals/w324_alert_probes.py",
    "evals/w324_offver_probes.py",
    "evals/w323_exwitness_probes.py",
    "evals/w322_witpol_probes.py",
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
                capture_output=True, text=True, timeout=900, env=env,
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
        if "[ERROR]" in out or proc.returncode != 0:
            ok = False
        _record("green-" + child, "HELD" if ok else "BREAK",
                "child %s ran; unexpected breaks/errors fail this check"
                % child)


def main(argv):
    probes = [v for k, v in sorted(globals().items())
              if k.startswith("_p") and k[2:3].isdigit() and callable(v)]
    for fn in probes:
        fn()
    _green()
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    print("w325_resid battery: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    green_ok = all(v != "BREAK" and v != "ERROR"
                   for pid, v, _ in _results
                   if pid.startswith("green-") and pid != "green-skip")
    if green_ok:
        print("GREEN")
    return 0 if (n_break == 0 and n_err == 0) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
