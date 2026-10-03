"""Wave-293 lane 3 battery: key-succession ceremony.

Base: wave-292 merge 36176e5 (verified via git rev-parse HEAD before work).

New product surface:
  (a) gov/key_succession.py -- declared phased key-rotation ceremony
      (none -> preparing -> prepared -> completing -> completed),
      signed transition records (key-succession/1), union-of-trust
      during completing (mandatory bounded overlap window), old-key
      reuse after completed refuses LOUD keysuccession-retired-reuse
      (a revocation EVENT, never a silent failure);
  (b) additive RevocationRegistry key-rotation wiring
      (begin_key_rotation / advance_key_rotation /
      finalize_key_rotation + succession-aware credential verification);
  (c) 4 new decision codes at true sorted positions; pin 1723 -> 1727.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ImportError on the new module); on the fixed tree they must
HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g293-ksucc && TMPDIR=/var/tmp/g293-ksucc \
    ~/workspace/.gov-venv/bin/python evals/w293_key_succession_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g293-ksucc2 \
    ~/workspace/.gov-venv/bin/python evals/w293_key_succession_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 1878  # Wave-293 lane 3: pin 1726 -> 1730 (+4 keysuccession-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate code literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "code literals not sorted")
    for want in ("keysuccession-invalid-transition",
                 "keysuccession-phase-skipped",
                 "keysuccession-retired-reuse",
                 "keysuccession-window-missing"):
        if want not in lits:
            return _record("pin-taxonomy", "BREAK",
                           "missing expected code %r" % want)
    _record("pin-taxonomy", "HELD", "1878 raw literals, unique, sorted")


def _import_ks():
    try:
        from gov import key_succession
        return key_succession
    except ImportError as e:
        return e


def _need(pid):
    """On the pristine base every functional probe BREAKs (module
    absent). On the fixed tree the import succeeds."""
    ks = _import_ks()
    if isinstance(ks, Exception):
        _record(pid, "BREAK", "gov/key_succession.py absent: %r" % (ks,))
        return None
    return ks


_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))


def _pub(seed):
    from gov import ed25519
    return ed25519.publickey(seed).hex()


def p_import():
    ks = _need("ks-import")
    if ks is not None:
        _record("ks-import", "HELD", "gov/key_succession.py imports")


def p_begin():
    ks = _need("ks-begin")
    if ks is None:
        return
    c = ks.KeySuccession("authority-1", _pub(_SEED_A))
    rec = c.begin(_pub(_SEED_B), old_seed=_SEED_A, declared_at=1000)
    if c.phase != "preparing":
        return _record("ks-begin", "BREAK",
                       "phase is %r, want preparing" % (c.phase,))
    if rec.get("record", {}).get("record_format") != \
            "sasanam-key-succession/1":
        return _record("ks-begin", "BREAK", "record format not bound")
    # The transition record must verify under the OLD (authority) key.
    ok = c.verify_transition(rec)
    if ok is not True:
        return _record("ks-begin", "BREAK",
                       "begin record does not verify under old key")
    _record("ks-begin", "HELD",
            "preparing entered; begin record signed by old authority key")


def _ceremony_to_prepared(ks):
    c = ks.KeySuccession("authority-1", _pub(_SEED_A))
    c.begin(_pub(_SEED_B), old_seed=_SEED_A, declared_at=1000)
    c.announce(old_seed=_SEED_A, declared_at=1001)
    return c


def p_phase_skip():
    ks = _need("ks-phase-skip")
    if ks is None:
        return
    c = ks.KeySuccession("authority-1", _pub(_SEED_A))
    try:
        c.advance(old_seed=_SEED_A, declared_at=1000, overlap_window_seconds=3600)
    except Exception as e:
        if getattr(e, "code", None) == "keysuccession-phase-skipped":
            return _record("ks-phase-skip", "HELD",
                           "none->completing refused coded")
        return _record("ks-phase-skip", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("ks-phase-skip", "BREAK", "phase skip none->completing allowed")


def p_phase_skip2():
    ks = _need("ks-phase-skip2")
    if ks is None:
        return
    c = ks.KeySuccession("authority-1", _pub(_SEED_A))
    c.begin(_pub(_SEED_B), old_seed=_SEED_A, declared_at=1000)
    try:
        c.finalize(old_seed=_SEED_A, declared_at=1001)
    except Exception as e:
        if getattr(e, "code", None) == "keysuccession-phase-skipped":
            return _record("ks-phase-skip2", "HELD",
                           "preparing->completed refused coded")
        return _record("ks-phase-skip2", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("ks-phase-skip2", "BREAK", "phase skip preparing->completed allowed")


def p_window_missing():
    ks = _need("ks-window-missing")
    if ks is None:
        return
    for bad in (None, 0, -5):
        c = _ceremony_to_prepared(ks)
        try:
            c.advance(old_seed=_SEED_A, declared_at=1002, overlap_window_seconds=bad)
        except Exception as e:
            if getattr(e, "code", None) != "keysuccession-window-missing":
                return _record("ks-window-missing", "BREAK",
                               "window=%r refused uncoded: %r" % (bad, e))
            continue
        return _record("ks-window-missing", "BREAK",
                       "window=%r accepted: unbounded overlap" % (bad,))
    _record("ks-window-missing", "HELD",
            "completing without a bounded overlap window refused coded")


def p_forged_transition():
    ks = _need("ks-forged-transition")
    if ks is None:
        return
    c = ks.KeySuccession("authority-1", _pub(_SEED_A))
    c.begin(_pub(_SEED_B), old_seed=_SEED_A, declared_at=1000)
    # Forge an announce record signed by the ATTACKER's key, not the
    # old authority key.
    forged = {"record": c._build_record("preparing", "prepared", 1001),
              "signature": None, "keyid": "old-authority"}
    from gov import ed25519
    forged["signature"] = ed25519.sign(
        _SEED_C, ks._canonical(forged["record"])).hex()
    try:
        c.announce(record=forged)
    except Exception as e:
        if getattr(e, "code", None) == "keysuccession-invalid-transition":
            return _record("ks-forged-transition", "HELD",
                           "forged transition record refused coded")
        return _record("ks-forged-transition", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("ks-forged-transition", "BREAK",
            "forged transition record accepted")


def _full_ceremony(ks, window=3600):
    c = _ceremony_to_prepared(ks)
    c.advance(old_seed=_SEED_A, declared_at=1002, overlap_window_seconds=window)
    c.finalize(old_seed=_SEED_A, declared_at=1003)
    return c

def _mk_envelope(ks, seed, payload, keyid):
    """Envelope over the canonical payload, signed by seed."""
    from gov import ed25519
    sig = ed25519.sign(seed, ks._canonical(payload)).hex()
    return {"record": payload, "signature": sig, "keyid": keyid}


def p_retired_reuse():
    ks = _need("ks-retired-reuse")
    if ks is None:
        return
    c = _full_ceremony(ks)
    env = _mk_envelope(ks, _SEED_A, {"kind": "late-material"}, "old-key")
    try:
        c.verify_envelope(env, checked_at=2000)
    except Exception as e:
        if getattr(e, "code", None) == "keysuccession-retired-reuse":
            return _record("ks-retired-reuse", "HELD",
                           "old-key reuse after completed refuses LOUD "
                           "as a revocation event")
        return _record("ks-retired-reuse", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("ks-retired-reuse", "BREAK",
            "retired key still verifies after completed: silent failure")


def p_overlap_union():
    ks = _need("ks-overlap-union")
    if ks is None:
        return
    c = _ceremony_to_prepared(ks)
    c.advance(old_seed=_SEED_A, declared_at=1002, overlap_window_seconds=3600)
    captured = []
    original = ks._EMIT
    ks._EMIT = lambda event, fields: captured.append((event, fields))
    try:
        env_old = _mk_envelope(ks, _SEED_A, {"kind": "in-flight"}, "old-key")
        ok, detail = c.verify_envelope(env_old, checked_at=2000,
                                       overlap_note="in-flight-1")
    finally:
        ks._EMIT = original
    if not ok or detail.get("signed_by") != "old-key" or \
            not detail.get("during_overlap") or \
            detail.get("note_emitted") is not True:
        return _record("ks-overlap-union", "BREAK",
                       "old-key material in window: %r" % (detail,))
    if not any(e == "keysuccession-overlap-use" for e, _ in captured):
        return _record("ks-overlap-union", "BREAK",
                       "old-key use during overlap emitted no audit "
                       "event: tolerance was silent")
    env_new = _mk_envelope(ks, _SEED_B, {"kind": "new-issuance"}, "new-key")
    ok2, detail2 = c.verify_envelope(env_new, checked_at=2000)
    if not ok2 or detail2.get("signed_by") != "new-key":
        return _record("ks-overlap-union", "BREAK",
                       "new-key material refused during completing")
    _record("ks-overlap-union", "HELD",
            "union of trust during completing; old-key use recorded "
            "with a signed overlap note (tolerance never silent)")


def p_overlap_expired():
    ks = _need("ks-overlap-expired")
    if ks is None:
        return
    c = _ceremony_to_prepared(ks)
    c.advance(old_seed=_SEED_A, declared_at=1002, overlap_window_seconds=3600)
    env = _mk_envelope(ks, _SEED_A, {"kind": "late"}, "old-key")
    try:
        c.verify_envelope(env, checked_at=1002 + 3600 + 1)
    except Exception as e:
        if getattr(e, "code", None) == "keysuccession-retired-reuse":
            return _record("ks-overlap-expired", "HELD",
                           "old-key material past the window refuses "
                           "coded as a revocation event")
        return _record("ks-overlap-expired", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("ks-overlap-expired", "BREAK",
            "old-key material accepted past the overlap window")


def p_new_key_early():
    ks = _need("ks-new-key-early")
    if ks is None:
        return
    c = ks.KeySuccession("authority-1", _pub(_SEED_A))
    c.begin(_pub(_SEED_B), old_seed=_SEED_A, declared_at=1000)
    env = _mk_envelope(ks, _SEED_B, {"kind": "early"}, "new-key")
    try:
        c.verify_envelope(env, checked_at=2000)
    except Exception as e:
        if getattr(e, "code", None) == "keysuccession-invalid-transition":
            return _record("ks-new-key-early", "HELD",
                           "new key unauthorized before completing: "
                           "refused coded")
        return _record("ks-new-key-early", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("ks-new-key-early", "BREAK",
            "new key accepted while still in preparing")


def p_registry_rotation():
    ks = _need("ks-registry-rotation")
    if ks is None:
        return
    from gov import revocation_status
    reg = revocation_status.RevocationRegistry("reg-1", _SEED_A)
    reg.issue("cred-1", _pub(_SEED_C), 1000, 9999)
    succession = reg.begin_key_rotation(_SEED_B)
    if succession.phase != "prepared":
        return _record("ks-registry-rotation", "BREAK",
                       "registry rotation did not reach prepared "
                       "(begin + announce); phase=%r" % succession.phase)
    reg.advance_key_rotation(overlap_window_seconds=3600)
    # A status envelope signed by the NEW registry key must verify
    # through the succession during completing.
    status = reg.check_status("cred-1", checked_at=2000)
    ok, detail = succession.verify_envelope(status, checked_at=2000)
    if ok is not True or detail.get("signed_by") != "new-key":
        return _record("ks-registry-rotation", "BREAK",
                       "new-key status envelope refused during completing")
    _record("ks-registry-rotation", "HELD",
            "registry key rotation wires through the ceremony; "
            "new-key material verifies during completing")


def p_registry_retired():
    ks = _need("ks-registry-retired")
    if ks is None:
        return
    from gov import revocation_status
    reg = revocation_status.RevocationRegistry("reg-1", _SEED_A)
    reg.issue("cred-1", _pub(_SEED_C), 1000, 9999)
    succession = reg.begin_key_rotation(_SEED_B)
    reg.advance_key_rotation(overlap_window_seconds=3600)
    reg.finalize_key_rotation()
    # After finalize, an envelope signed by the OLD registry seed must
    # refuse as a revocation event through the succession seam.
    forged_old_status = {
        "status": {"response_format": "sasanam-revocation-status/1",
                   "rid": "cred-1", "state": "active",
                   "checked_at": 2000, "successor": None,
                   "revoked_at": None, "revoke_reason": None,
                   "registry_digest": "00" * 32},
        "keyid": "registry",
    }
    from gov import ed25519
    forged_old_status["signature"] = ed25519.sign(
        _SEED_A,
        ks._canonical(forged_old_status["status"])).hex()
    try:
        succession.verify_envelope(forged_old_status, checked_at=3000)
    except Exception as e:
        if getattr(e, "code", None) == "keysuccession-retired-reuse":
            return _record("ks-registry-retired", "HELD",
                           "old-registry-key material after finalize "
                           "refuses as a revocation event")
        return _record("ks-registry-retired", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("ks-registry-retired", "BREAK",
            "old-registry-key envelope still verifies after finalize")


def p_malformed_pubkey():
    ks = _need("ks-malformed-pubkey")
    if ks is None:
        return
    try:
        ks.KeySuccession("authority-1", "not-hex")
    except Exception as e:
        if getattr(e, "code", None) == "keysuccession-invalid-transition":
            return _record("ks-malformed-pubkey", "HELD",
                           "non-hex authority key refused coded")
        return _record("ks-malformed-pubkey", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("ks-malformed-pubkey", "BREAK", "non-hex authority key accepted")


def p_tampered_record():
    ks = _need("ks-tampered-record")
    if ks is None:
        return
    c = ks.KeySuccession("authority-1", _pub(_SEED_A))
    rec = c.begin(_pub(_SEED_B), old_seed=_SEED_A, declared_at=1000)
    rec["record"]["new_pubkey"] = _pub(_SEED_C)  # tamper after signing
    try:
        c.announce(record=rec)
    except Exception as e:
        if getattr(e, "code", None) == "keysuccession-invalid-transition":
            return _record("ks-tampered-record", "HELD",
                           "tampered transition record refused coded")
        return _record("ks-tampered-record", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("ks-tampered-record", "BREAK", "tampered record accepted")


def p_double_begin():
    ks = _need("ks-double-begin")
    if ks is None:
        return
    c = ks.KeySuccession("authority-1", _pub(_SEED_A))
    c.begin(_pub(_SEED_B), old_seed=_SEED_A, declared_at=1000)
    try:
        c.begin(_pub(_SEED_C), old_seed=_SEED_A, declared_at=1001)
    except Exception as e:
        if getattr(e, "code", None) == "keysuccession-invalid-transition":
            return _record("ks-double-begin", "HELD",
                           "second begin refused coded")
        return _record("ks-double-begin", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("ks-double-begin", "BREAK", "second begin accepted")


def p_sink_isolation():
    ks = _need("ks-sink-isolation")
    if ks is None:
        return
    def raising_sink(event, fields):
        raise RuntimeError("sink is down")
    original = ks._EMIT
    ks._EMIT = raising_sink
    try:
        c = _ceremony_to_prepared(ks)
        c.advance(old_seed=_SEED_A, declared_at=1002,
                  overlap_window_seconds=3600)
        env = _mk_envelope(ks, _SEED_A, {"kind": "in-flight-7"}, "old-key")
        ok, detail = c.verify_envelope(env, checked_at=2000,
                                       overlap_note="in-flight-7")
        # Verification succeeds; only the note emission degrades.
        if not ok or detail.get("note_emitted") is not False:
            return _record("ks-sink-isolation", "BREAK",
                           "broken sink changed verification outcome: "
                           "%r" % (detail,))
    finally:
        ks._EMIT = original
    _record("ks-sink-isolation", "HELD",
            "F345-class: broken audit sink never breaks verification; "
            "only the overlap-note emission degrades")


def p_replay_transition():
    ks = _need("ks-replay-transition")
    if ks is None:
        return
    c = ks.KeySuccession("authority-1", _pub(_SEED_A))
    c.begin(_pub(_SEED_B), old_seed=_SEED_A, declared_at=1000)
    rec = c.announce(old_seed=_SEED_A, declared_at=1001)
    try:
        c.announce(record=rec)  # replay the same transition record
    except Exception as e:
        if getattr(e, "code", None) == "keysuccession-invalid-transition":
            return _record("ks-replay-transition", "HELD",
                           "replayed transition record refused coded")
        return _record("ks-replay-transition", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("ks-replay-transition", "BREAK",
            "replayed announce record accepted")


def _green_check(path, name, tolerate=()):
    """Depth-1 green check: run the adjacent battery's main with
    GOV_SKIP_GREEN=1 (combinatorial-nesting lesson). ``tolerate`` is a
    tuple of probe-id prefixes whose BREAK is acceptable (expected-open
    findings and pin-drift from this lane's own new codes)."""
    if SKIP_GREEN:
        _record(name + "-green-skip", "HELD", "skipped (nested green check)")
        return
    td = tempfile.mkdtemp(prefix="g293-ksucc-green-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = td
    try:
        r = subprocess.run([sys.executable, path],
                           capture_output=True, text=True, env=env,
                           timeout=600, cwd=REPO)
    except Exception as e:  # noqa: BLE001
        _record(name, "ERROR", "green check failed to run: %r" % (e,))
        return
    out = r.stdout + r.stderr
    bad = []
    for line in out.splitlines():
        m = re.match(r"\s*\[?(BREAK|ERROR)\]?\s*([a-z0-9][a-z0-9_-]*)",
                     line.strip())
        if not m:
            continue
        pid = m.group(2)
        if not any(pid.startswith(t) for t in tolerate):
            bad.append(line.strip()[:160])
    if r.returncode != 0 and not bad and not tolerate:
        _record(name, "ERROR",
                "green check exited %d, output tail:\n%s"
                % (r.returncode, out[-600:]))
        return
    if bad:
        _record(name, "BREAK",
                "adjacent battery shows unexpected BREAKs:\n"
                + "\n".join(bad[:8]))
    else:
        _record(name, "HELD",
                "adjacent battery green (only tolerated BREAKs)")


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    for pid, fn in [
        ("ks-import", p_import),
        ("ks-begin", p_begin),
        ("ks-phase-skip", p_phase_skip),
        ("ks-phase-skip2", p_phase_skip2),
        ("ks-window-missing", p_window_missing),
        ("ks-forged-transition", p_forged_transition),
        ("ks-retired-reuse", p_retired_reuse),
        ("ks-overlap-union", p_overlap_union),
        ("ks-overlap-expired", p_overlap_expired),
        ("ks-new-key-early", p_new_key_early),
        ("ks-registry-rotation", p_registry_rotation),
        ("ks-registry-retired", p_registry_retired),
        ("ks-malformed-pubkey", p_malformed_pubkey),
        ("ks-tampered-record", p_tampered_record),
        ("ks-double-begin", p_double_begin),
        ("ks-sink-isolation", p_sink_isolation),
        ("ks-replay-transition", p_replay_transition),
    ]:
        _safe(pid, fn)
    _green_check(os.path.join(REPO, "evals", "w292_revocation_probes.py"),
                 "w292-revocation")
    # w292-redteam: F360 (4 ob-* probes) is expected-open; every other
    # BREAK it reports is pin-drift from this lane's 4 new codes
    # (1723 -> 1727) cascading through its re-pins -- the wave-281
    # merge-time re-pin situation, tolerated here and re-pinned at
    # merge.
    _green_check(os.path.join(REPO, "evals", "w292_redteam_probes.py"),
                 "w292-redteam",
                 tolerate=("ob-pubkey-hex-uncoded",
                           "ob-manifest-enveloped-uncoded",
                           "ob-ledger-line-uncoded",
                           "ob-manifest-json-uncoded",
                           "pin-taxonomy", "repin-"))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w293_key_succession: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, n_break, n_held, n_err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
