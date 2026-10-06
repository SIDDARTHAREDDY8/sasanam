"""Break-first probes for gov/witness_monitor (wave-323 lane 2).

Red-first: on the open tree this battery dies at import
(ModuleNotFoundError: gov.witness_monitor). On the lane tree every
attack below must refuse with the coded reason -- 0 BREAK target.

The monitor consumes verify_published_checkpoint (fail-closed note
layer) and adds: durable-head state with hard-stop semantics, the
fixed missing-fringe edge (loud witness-monitor-stale instead of
silent non-advance), fetch-failure availability signals, and a
policy-version watermark.

Staging default is set at module level (the harness refuses the
declared ungoverned_ack in production mode).
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)


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
# Fixtures.
# ---------------------------------------------------------------------------

SEED_OP = bytes(range(32))
SEED_W1 = bytes([255 - i for i in range(32)])
SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
SEED_EVIL = bytes([(i * 29 + 5) % 256 for i in range(32)])
ORIGIN = "sasanam-witmon-test/v1"
NOW = 1798765432


def _mod():
    from gov import witness_monitor as wm
    from gov import witness_publish as wp
    from gov import witness_consistency as wc
    from gov import checkpoint_note as cn
    from gov.witness_log import WitnessLog
    from gov.signing import Ed25519Signer
    return wm, wp, wc, cn, WitnessLog, Ed25519Signer


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
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = _mod()
    op = Ed25519Signer(SEED_OP)
    w1 = Ed25519Signer(SEED_W1)
    w2 = Ed25519Signer(SEED_W2)
    log = WitnessLog(op.public_key)
    for i in range(n):
        log.append(b"leaf-%d" % i)
    op_vk = [_op_vkey(cn, "op", op)]
    wit_vk = {"w1": _vkey(cn, "w1", w1), "w2": _vkey(cn, "w2", w2)}
    mods = (wm, wp, wc, cn, WitnessLog, Ed25519Signer)
    keys = (op, w1, w2, op_vk, wit_vk)
    return mods, keys, log


def _publish(wp, log, op, w1, w2, op_vk, wit_vk, ts, quorum_k=2,
             signers=None):
    if signers is None:
        signers = [("w1", w1), ("w2", w2)]
    return wp.publish_checkpoint(
        log, ORIGIN, "op", op, signers, operator_vkeys=op_vk,
        witness_vkeys=wit_vk, quorum_k=quorum_k, timestamp=ts)


def _inputs(policy_version=1):
    return {"operator_vkeys": None, "quorum_k": 2, "policy_id": "test",
            "policy_version": policy_version}


def _step(wm, note, wit_vk, op_vk, last_seen, state_path=None,
          policy_version=1, **kw):
    pi = _inputs(policy_version)
    pi["operator_vkeys"] = op_vk
    return wm.monitor_step(note, witness_set=wit_vk, last_seen=last_seen,
                           policy_inputs=pi, allowed_origins=[ORIGIN],
                           now=kw.pop("now", NOW),
                           max_age=kw.pop("max_age", 3600),
                           state_path=state_path, **kw)


def _tmpdir():
    return tempfile.mkdtemp(prefix="witmon-")


# ---------------------------------------------------------------------------
# P1: happy path -- first-run baseline, advance, idempotent no-op.
# ---------------------------------------------------------------------------

@probe("P1-baseline-advance-noop")
def _p1():
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = _mod()
    mods, keys, log = _world(5)
    op, w1, w2, op_vk, wit_vk = keys
    d = _tmpdir()
    sp = os.path.join(d, "state.json")
    note5 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    # First run: no state, last_seen=None -> baseline established.
    r = _step(wm, note5, wit_vk, op_vk, None, state_path=sp)
    assert r["accepted"] and r["advanced"], r
    assert r["head"]["size"] == 5, r
    assert r["consecutive_failures"] == 0, r
    assert os.path.exists(sp), "state file must be written"
    # Grow the log; the monitor advances.
    for i in range(5, 8):
        log.append(b"leaf-%d" % i)
    note8 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 50)
    r = _step(wm, note8, wit_vk, op_vk, (5, r["head"]["root"]),
              state_path=sp)
    assert r["accepted"] and r["advanced"], r
    assert r["head"]["size"] == 8, r
    # Same note again: idempotent no-op, still accepted.
    r = _step(wm, note8, wit_vk, op_vk, (8, r["head"]["root"]),
              state_path=sp)
    assert r["accepted"] and not r["advanced"], r
    _held("P1-baseline-advance-noop", "baseline, advance, no-op all hold")


# ---------------------------------------------------------------------------
# P2: forged operator signature -> coded (witness-consistency-invalid).
# ---------------------------------------------------------------------------

@probe("P2-forged-operator-signature")
def _p2():
    import base64
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    body_root = base64.b64encode(log.root_hash()).decode("ascii")
    evil_root = base64.b64encode(bytes([9]) * 32).decode("ascii")
    forged = note.replace(body_root.encode("ascii"),
                          evil_root.encode("ascii"), 1)
    assert forged != note
    _expect_code("P2-forged-operator-signature",
                 lambda: _step(wm, forged, wit_vk, op_vk, None),
                 "witness-consistency-invalid")


# ---------------------------------------------------------------------------
# P3: below-threshold cosignatures -> witness-quorum-unmet.
# ---------------------------------------------------------------------------

@probe("P3-below-threshold-cosignatures")
def _p3():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    # One cosignature only, quorum_k=2: build the note manually so the
    # publish-side self-verification does not refuse first.
    note = wc.issue_checkpoint_note(log, ORIGIN, "op", op,
                                    timestamp=NOW - 100)
    note = wc.cosign_note_v1(note, "w1", w1, timestamp=NOW - 100)
    _expect_code("P3-below-threshold-cosignatures",
                 lambda: _step(wm, note, wit_vk, op_vk, None),
                 "witness-quorum-unmet")


# ---------------------------------------------------------------------------
# P4: rollback (smaller size than last_seen) -> witness-publish-rollback.
# ---------------------------------------------------------------------------

@probe("P4-rollback-refused")
def _p4():
    mods, keys, log = _world(8)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    note8 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    r = _step(wm, note8, wit_vk, op_vk, None)
    head = (8, r["head"]["root"])
    mods2, keys2, log3 = _world(3)
    op2, w1b, w2b, op_vk2, wit_vk2 = keys2
    note3 = _publish(wp, log3, op2, w1b, w2b, op_vk2, wit_vk2, NOW - 50)
    _expect_code("P4-rollback-refused",
                 lambda: _step(wm, note3, wit_vk2, op_vk2, head),
                 "witness-publish-rollback")


# ---------------------------------------------------------------------------
# P5: stale checkpoint -> witness-checkpoint-stale (staleness blocks).
# ---------------------------------------------------------------------------

@probe("P5-stale-checkpoint-blocks")
def _p5():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 7200)
    _expect_code("P5-stale-checkpoint-blocks",
                 lambda: _step(wm, note, wit_vk, op_vk, None,
                               now=NOW, max_age=3600),
                 "witness-checkpoint-stale")


# ---------------------------------------------------------------------------
# P6: equivocation across monitors (same size, different root) ->
# witness-consistency-fork-detected.
# ---------------------------------------------------------------------------

@probe("P6-equivocation-fork-detected")
def _p6():
    mods, keys, loga = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    note_a = _publish(wp, loga, op, w1, w2, op_vk, wit_vk, NOW - 100)
    r = _step(wm, note_a, wit_vk, op_vk, None)
    head = (5, r["head"]["root"])
    # A second log with different leaves, same size, same witnesses.
    mods_b, keys_b, logb = _world(5)
    for i in range(5):
        logb._entries[i] = b"evil-%d" % i
    assert logb.root_hash() != loga.root_hash()
    opb, w1b, w2b, op_vkb, wit_vkb = keys_b
    note_b = _publish(wp, logb, opb, w1b, w2b, op_vkb, wit_vkb, NOW - 50)
    _expect_code("P6-equivocation-fork-detected",
                 lambda: _step(wm, note_b, wit_vkb, op_vkb, head),
                 "witness-consistency-fork-detected")


# ---------------------------------------------------------------------------
# P7: THE missing-fringe edge -- require_consistency_proof=True, head
# advanced, no proof -> witness-monitor-stale LOUD (never silent).
# ---------------------------------------------------------------------------

@probe("P7-missing-fringe-loud-not-silent")
def _p7():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    note5 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    r = _step(wm, note5, wit_vk, op_vk, None)
    head = (5, r["head"]["root"])
    for i in range(5, 8):
        log.append(b"leaf-%d" % i)
    note8 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 50)
    _expect_code("P7-missing-fringe-loud-not-silent",
                 lambda: _step(wm, note8, wit_vk, op_vk, head,
                               require_consistency_proof=True),
                 "witness-monitor-stale")


# ---------------------------------------------------------------------------
# P8: valid consistency proof -> advances (the proof path works).
# ---------------------------------------------------------------------------

@probe("P8-valid-consistency-proof-advances")
def _p8():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    note5 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    r = _step(wm, note5, wit_vk, op_vk, None)
    head = (5, r["head"]["root"])
    for i in range(5, 8):
        log.append(b"leaf-%d" % i)
    note8 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 50)
    proof = log.consistency_proof(5, 8)["hashes"]
    r = _step(wm, note8, wit_vk, op_vk, head,
              consistency_proof=proof, require_consistency_proof=True)
    assert r["accepted"] and r["advanced"] and r["head"]["size"] == 8, r
    _held("P8-valid-consistency-proof-advances", "proof path advances")


# ---------------------------------------------------------------------------
# P9: tampered consistency proof -> coded (witness-log-consistency-invalid).
# ---------------------------------------------------------------------------

@probe("P9-tampered-proof-refused")
def _p9():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    note5 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    r = _step(wm, note5, wit_vk, op_vk, None)
    head = (5, r["head"]["root"])
    for i in range(5, 8):
        log.append(b"leaf-%d" % i)
    note8 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 50)
    proof = log.consistency_proof(5, 8)["hashes"]
    bad = list(proof)
    bad[0] = "00" * 32 if bad[0] != "00" * 32 else "ff" * 32
    _expect_code("P9-tampered-proof-refused",
                 lambda: _step(wm, note8, wit_vk, op_vk, head,
                               consistency_proof=bad),
                 "witness-log-consistency-invalid")


# ---------------------------------------------------------------------------
# P10: corrupt state file -> witness-monitor-state-corrupt (hard stop).
# ---------------------------------------------------------------------------

@probe("P10-corrupt-state-hard-stop")
def _p10():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    note5 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    d = _tmpdir()
    sp = os.path.join(d, "state.json")
    with open(sp, "w") as fh:
        fh.write("{not json")
    _expect_code("P10-corrupt-state-hard-stop",
                 lambda: _step(wm, note5, wit_vk, op_vk, None,
                               state_path=sp),
                 "witness-monitor-state-corrupt")


# ---------------------------------------------------------------------------
# P11: state missing but last_seen given -> witness-monitor-state-missing
# (never a silent re-baseline).
# ---------------------------------------------------------------------------

@probe("P11-missing-state-hard-stop")
def _p11():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    note5 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    r = _step(wm, note5, wit_vk, op_vk, None)
    head = (5, r["head"]["root"])
    d = _tmpdir()
    sp = os.path.join(d, "state.json")  # never created
    _expect_code("P11-missing-state-hard-stop",
                 lambda: _step(wm, note5, wit_vk, op_vk, head,
                               state_path=sp),
                 "witness-monitor-state-missing")


# ---------------------------------------------------------------------------
# P12: state-file replay -- durable head (8) vs caller last_seen (5) ->
# witness-monitor-state-mismatch; the refused run never advances state.
# ---------------------------------------------------------------------------

@probe("P12-state-replay-refused")
def _p12():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    d = _tmpdir()
    sp = os.path.join(d, "state.json")
    note5 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    r = _step(wm, note5, wit_vk, op_vk, None, state_path=sp)
    head5 = (5, r["head"]["root"])
    for i in range(5, 8):
        log.append(b"leaf-%d" % i)
    note8 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 50)
    r = _step(wm, note8, wit_vk, op_vk, head5, state_path=sp)
    assert r["head"]["size"] == 8, r
    # Now replay: caller claims the old head (5) while state says 8.
    _expect_code("P12-state-replay-refused",
                 lambda: _step(wm, note5, wit_vk, op_vk, head5,
                               state_path=sp),
                 "witness-monitor-state-mismatch")
    st = wm.load_monitor_state(sp)
    assert st["last_seen"]["size"] == 8, st
    _held("P12-state-replay-refused",
          "replay refused; durable head untouched")


# ---------------------------------------------------------------------------
# P13: fetch failure (checkpoint_bytes=None) -> witness-monitor-fetch-failed;
# the counter persists; the 3rd consecutive failure still refuses coded.
# ---------------------------------------------------------------------------

@probe("P13-fetch-failure-counter")
def _p13():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    d = _tmpdir()
    sp = os.path.join(d, "state.json")
    note5 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    _step(wm, note5, wit_vk, op_vk, None, state_path=sp)
    codes = []
    for _ in range(3):
        try:
            _step(wm, None, wit_vk, op_vk, None, state_path=sp)
        except Exception as exc:  # noqa: BLE001
            codes.append((getattr(exc, "code", None),
                          getattr(exc, "consecutive_failures", None)))
    assert codes == [("witness-monitor-fetch-failed", 1),
                     ("witness-monitor-fetch-failed", 2),
                     ("witness-monitor-fetch-failed", 3)], codes
    st = wm.load_monitor_state(sp)
    assert st["consecutive_failures"] == 3, st
    assert st["last_seen"]["size"] == 5, st  # head never moved
    # A good run resets the counter.
    r = _step(wm, note5, wit_vk, op_vk, (5, st["last_seen"]["root"]),
              state_path=sp)
    assert r["consecutive_failures"] == 0, r
    _held("P13-fetch-failure-counter", "fetch failures counted, reset on ok")


# ---------------------------------------------------------------------------
# P14: policy version replay -> witness-policy-version-rollback.
# ---------------------------------------------------------------------------

@probe("P14-policy-version-replay")
def _p14():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    d = _tmpdir()
    sp = os.path.join(d, "state.json")
    note5 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    _step(wm, note5, wit_vk, op_vk, None, state_path=sp,
          policy_version=2)
    _expect_code("P14-policy-version-replay",
                 lambda: _step(wm, note5, wit_vk, op_vk, None,
                               state_path=sp, policy_version=1),
                 "witness-policy-version-rollback")


# ---------------------------------------------------------------------------
# P15: policy upgrade updates the watermark (rotation composes).
# ---------------------------------------------------------------------------

@probe("P15-policy-upgrade-composes")
def _p15():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    d = _tmpdir()
    sp = os.path.join(d, "state.json")
    note5 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    _step(wm, note5, wit_vk, op_vk, None, state_path=sp,
          policy_version=1)
    r = _step(wm, note5, wit_vk, op_vk, None, state_path=sp,
              policy_version=2)
    assert r["accepted"] and r["policy_version"] == 2, r
    st = wm.load_monitor_state(sp)
    assert st["policy_version"] == 2, st
    _held("P15-policy-upgrade-composes", "watermark advanced to v2")


# ---------------------------------------------------------------------------
# P16: unknown origin -> coded.
# ---------------------------------------------------------------------------

@probe("P16-unknown-origin-refused")
def _p16():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    pi = _inputs()
    pi["operator_vkeys"] = op_vk
    _expect_code("P16-unknown-origin-refused",
                 lambda: wm.monitor_step(
                     note, witness_set=wit_vk, last_seen=None,
                     policy_inputs=pi, allowed_origins=["other/v1"],
                     now=NOW, max_age=3600),
                 "witness-checkpoint-unknown-origin")


# ---------------------------------------------------------------------------
# P19: first-run refusal with a state path -- the failure counter
# persists with a null head (regression: this used to crash on the
# missing state instead of refusing coded).
# ---------------------------------------------------------------------------

@probe("P19-first-run-refusal-persists")
def _p19():
    import base64
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    body_root = base64.b64encode(log.root_hash()).decode("ascii")
    evil_root = base64.b64encode(bytes([9]) * 32).decode("ascii")
    forged = note.replace(body_root.encode("ascii"),
                          evil_root.encode("ascii"), 1)
    d = _tmpdir()
    sp = os.path.join(d, "state.json")
    try:
        _step(wm, forged, wit_vk, op_vk, None, state_path=sp)
    except Exception as exc:  # noqa: BLE001
        assert getattr(exc, "code", None) == "witness-consistency-invalid", \
            "want coded refusal, got %r" % (exc,)
        assert getattr(exc, "consecutive_failures", None) == 1, \
            "counter must persist on first-run refusal"
    else:
        raise AssertionError("no refusal on forged first-run checkpoint")
    st = wm.load_monitor_state(sp)
    assert st["last_seen"] is None, st
    assert st["consecutive_failures"] == 1, st
    # The next good run establishes the baseline and resets the counter.
    r = _step(wm, note, wit_vk, op_vk, None, state_path=sp)
    assert r["accepted"] and r["advanced"], r
    assert r["consecutive_failures"] == 0, r
    _held("P19-first-run-refusal-persists",
          "first-run refusal coded; counter persists; baseline follows")


# ---------------------------------------------------------------------------
# P20: strict-mode first-run baseline -- require_consistency_proof=True
# with no prior head establishes the baseline from the authenticated
# checkpoint (regression: the missing-fringe condition used to refuse
# the baseline itself, a permanent self-inflicted stall).
# ---------------------------------------------------------------------------

@probe("P20-strict-first-run-baseline")
def _p20():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    note5 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    r = _step(wm, note5, wit_vk, op_vk, None,
              require_consistency_proof=True)
    assert r["accepted"] and r["advanced"], r
    assert r["head"]["size"] == 5, r
    _held("P20-strict-first-run-baseline",
          "strict-mode baseline established without a proof")


# ---------------------------------------------------------------------------
# P21: policy_id swap at same-or-higher version ->
# witness-policy-id-mismatch (the watermark pins the policy family).
# ---------------------------------------------------------------------------

@probe("P21-policy-id-swap-refused")
def _p21():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    d = _tmpdir()
    sp = os.path.join(d, "state.json")
    note5 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    _step(wm, note5, wit_vk, op_vk, None, state_path=sp)
    pi = _inputs(policy_version=1)
    pi["operator_vkeys"] = op_vk
    pi["policy_id"] = "other-family"
    _expect_code("P21-policy-id-swap-refused",
                 lambda: wm.monitor_step(
                     note5, witness_set=wit_vk, last_seen=None,
                     policy_inputs=pi, allowed_origins=[ORIGIN],
                     now=NOW, max_age=3600, state_path=sp),
                 "witness-policy-id-mismatch")


# ---------------------------------------------------------------------------
# P22: witness_vkeys riding in policy_inputs disagrees with witness_set
# -> witness-policy-malformed (fail closed, never guess).
# ---------------------------------------------------------------------------

@probe("P22-witness-set-disagreement")
def _p22():
    mods, keys, log = _world(5)
    wm, wp, wc, cn, WitnessLog, Ed25519Signer = mods
    op, w1, w2, op_vk, wit_vk = keys
    note5 = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    pi = _inputs()
    pi["operator_vkeys"] = op_vk
    pi["witness_vkeys"] = {"w1": wit_vk["w1"]}  # disagrees
    _expect_code("P22-witness-set-disagreement",
                 lambda: wm.monitor_step(
                     note5, witness_set=wit_vk, last_seen=None,
                     policy_inputs=pi, allowed_origins=[ORIGIN],
                     now=NOW, max_age=3600),
                 "witness-policy-malformed")


# ---------------------------------------------------------------------------
# P17: pin + footer state.
# ---------------------------------------------------------------------------

@probe("P17-pin-taxonomy-1981-sorted")
def _p17():
    import re as _re
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    codes = _re.findall(r'"code":\s*["\']([^"\']+)["\']', src)
    assert len(codes) == len(set(codes)) == TAXONOMY_PIN, \
        "want %d/%d/0 sorted, got %d/%d" % (TAXONOMY_PIN, TAXONOMY_PIN,
                                           len(codes), len(set(codes)))
    assert codes == sorted(codes), "taxonomy not sorted"
    _held("P17-pin-taxonomy-1981-sorted", "%d/%d/0 sorted"
          % (TAXONOMY_PIN, TAXONOMY_PIN))


@probe("P18-footer-state")
def _p18():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    # Wave-336 lane 1: repaired stale F412/F413-era assertion.
    assert "Next free finding: **F482**. **Open findings: F482, F483, F484, F485, F486, F487, F488.**" in text, \
        "footer mismatch"
    _held("P18-footer-state", "open F444, F445 / next F446")


# ---------------------------------------------------------------------------
# Green checks (depth-1): adjacent batteries run with GOV_SKIP_GREEN=1 in
# the child env; this function honors the var by recording a skip.
# A BREAK in a child is only acceptable when it is a pin-probe break
# (the merge repoint owns the pin) or a standing open-finding probe.
# ---------------------------------------------------------------------------

_KNOWN_CHILD_BREAKS = {
    "P2-malformed-referrers-array",
    "P2-malformed-referrers-string",
    "P2-malformed-referrers-subject",
    "P2-malformed-entry-digest",
}

_GREEN_CHILDREN = (
    "evals/w322_witpub_probes.py",
    "evals/w322_witpol_probes.py",
    "evals/w322_redteam_probes.py",
)


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
            if ("pin-taxonomy" not in pid
                    and pid not in _KNOWN_CHILD_BREAKS):
                ok = False
        if "[ERROR]" in out or proc.returncode not in (0,):
            # A nonzero return is tolerated only when every BREAK is
            # known (pin-probe / open-finding) and no ERROR line fired.
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
    print("w323_monitor battery: %d BREAK / %d HELD / %d ERROR "
          % (n_break, n_held, n_err))
    green_ok = all(v != "BREAK" and v != "ERROR"
                   for pid, v, _ in _results
                   if pid.startswith("green-") and pid != "green-skip")
    if green_ok:
        print("GREEN")
    return 0 if (n_break == 0 and n_err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
