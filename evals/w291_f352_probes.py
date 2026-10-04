"""Wave-291 lane 1 closure battery: F352 (ceremony_binding audit-sink uncoded).

Base: wave-290 merge commit 9c12f9b4b0aec88746786e68e3f84ae7f04d2d16
(verified via git rev-parse HEAD before work).

F352: gov/ceremony_binding.py `_emit_event` unisolated in issue_binding --
a raising audit sink escapes as the sink's own exception type (code=None).
Same defect class as F345 (evidence_provenance, closed wave-289),
F346 (runtime_posture, closed wave-290), F347 (evidence_receipt, closed
wave-290): the documented timestamp_authority swallow trade-off -- a
broken audit sink must never break issuance or verification.

Close-when: (1) sink failures isolated (the F345-class mechanism);
(2) probe f352-issue-sink flips to HELD; (3) the FULL audit-sink
inventory re-verified (provenance, posture, receipt, ceremony);
(4) adjacent green.

$0 spend, synthetic/local, deterministic (fixed fixtures, secrets only
for fresh keys). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g291-f352 && TMPDIR=/var/tmp/g291-f352 \
    ~/workspace/.gov-venv/bin/python evals/w291_f352_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g291-f352b \
    ~/workspace/.gov-venv/bin/python evals/w291_f352_probes.py
"""

import os
import re
import secrets
import subprocess
import sys
import tempfile

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

# Wave-290 merge: pin 1706 -> 1710 (+4 provenance-rebuild-*). F352 lane
# mints no new decision codes.
TAXONOMY_PIN = 1933 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


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
    _record("pin-taxonomy", "HELD",
            "taxonomy pin 1820 holds (raw source literals)")


def _boom(ev):
    raise RuntimeError("sink exploded")


def _ceremony_parts():
    from gov import ceremony_binding as cb
    seed = secrets.token_bytes(32)
    rec = cb.issue_binding(
        operator_seed=seed, operator_keyid="op1",
        challenge_nonce=secrets.token_bytes(16),
        challenge_purpose="appraise",
        content_digest="ab" * 32)
    return rec, seed


def p_f352_issue_sink_isolated():
    """F352: raising sink must not escape ceremony issue_binding uncoded."""
    from gov import ceremony_binding as cb
    cb.set_emit(_boom)
    try:
        rec, seed = _ceremony_parts()
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f352-issue-sink", "BREAK",
                           "raising sink escaped issue_binding uncoded "
                           "(%s)" % type(e).__name__)
        return _record("f352-issue-sink", "HELD",
                       "sink failure refused coded: %s" % code)
    finally:
        cb.set_emit(None)
    if rec.get("ceremony_format"):
        return _record("f352-issue-sink", "HELD",
                       "sink failure isolated: issuance completed, no "
                       "raw sink exception at the seam (F345 mechanism)")
    _record("f352-issue-sink", "BREAK", "issuance misbehaved")


def p_f352_sink_ok():
    """Positive control: a healthy sink sees the binding-issued event."""
    from gov import ceremony_binding as cb
    seen = []
    cb.set_emit(seen.append)
    try:
        rec, seed = _ceremony_parts()
    finally:
        cb.set_emit(None)
    if seen and seen[0].get("event") == "binding-issued" \
            and seen[0].get("purpose") == "appraise":
        return _record("f352-sink-ok", "HELD",
                       "healthy sink receives binding-issued event")
    _record("f352-sink-ok", "BREAK", "sink saw nothing or payload wrong")


# ---------------------------------------------------------------------------
# Full audit-sink inventory (F345, F346, F347, F352): every _emit must hold
# under a raising sink.
# ---------------------------------------------------------------------------

def _provenance_parts():
    from gov import evidence_provenance as ep
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    claim = ep.make_provenance_claim(
        builder_id="builder-a", keyid="key-1",
        artifact_digest="ab" * 32,
        materials=[{"uri": "src/x", "digest": "cd" * 32,
                    "completeness": "verified"}])
    envelope = ep.seal_provenance(claim, seed)
    policy = ep.BuilderPolicy("pol-1", {"builder-a": pub})
    return envelope, policy


def p_inv_provenance_sink():
    """F345 inventory: verify_provenance emits under a raising sink."""
    from gov import evidence_provenance as ep
    envelope, policy = _provenance_parts()
    ep.set_emit(_boom)
    try:
        ok = ep.verify_provenance(envelope, policy)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("inv-provenance-sink", "BREAK",
                           "raising sink escaped verify_provenance "
                           "uncoded (%s)" % type(e).__name__)
        return _record("inv-provenance-sink", "HELD",
                       "sink failure refused coded: %s" % code)
    finally:
        ep.set_emit(None)
    if ok is True:
        return _record("inv-provenance-sink", "HELD",
                       "provenance verify completed under raising sink")
    _record("inv-provenance-sink", "BREAK", "verify misbehaved")


def _posture_parts():
    from gov import runtime_posture as rp
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    slot = {"log_id": "L", "log_index": 0, "expected_digest": "ef" * 32,
            "source_id": "log-op"}
    rec = rp.issue_posture(
        operator_seed=seed, operator_keyid="op1",
        eat_nonce=secrets.token_bytes(16),
        submods={"sbx": {"digest": "ab" * 32}},
        software_id="agent/1.0", config_digest="cd" * 32,
        endorsements={c: dict(slot) for c in
                      ("software_id", "config_digest", "submods")},
        producer_id="operator")
    return rec, seed, pub


def p_inv_posture_sink():
    """F346 inventory: issue + verify under a raising sink."""
    from gov import runtime_posture as rp
    rp.set_emit(_boom)
    try:
        rec, seed, pub = _posture_parts()
        payload = rp.verify_posture(rec, pub)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("inv-posture-sink", "BREAK",
                           "raising sink escaped issue/verify uncoded "
                           "(%s)" % type(e).__name__)
        return _record("inv-posture-sink", "HELD",
                       "sink failure refused coded: %s" % code)
    finally:
        rp.set_emit(None)
    if payload.get("software_id") == "agent/1.0":
        return _record("inv-posture-sink", "HELD",
                       "posture issue+verify completed under raising sink")
    _record("inv-posture-sink", "BREAK", "posture misbehaved")


def _anchor_parts():
    from gov import evidence_anchor as ea
    d = tempfile.mkdtemp(prefix="w291-f352-")
    seed = secrets.token_bytes(32)
    log = ea.TransparencyLog(d, origin="w291origin", signer_keyid="op1",
                             signer_seed=seed)
    anchored = ea.anchor(log, secrets.token_bytes(32).hex())
    return anchored, seed


def p_inv_receipt_sink():
    """F347 inventory: bind + offline-verify under a raising sink."""
    from gov import evidence_receipt as er
    from gov import ed25519
    anchored, seed = _anchor_parts()
    er.set_emit(_boom)
    try:
        receipt = er.bind_receipt(anchored, seed)
        ok = er.verify_receipt_offline(receipt, ed25519.publickey(seed))
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("inv-receipt-sink", "BREAK",
                           "raising sink escaped bind/verify uncoded "
                           "(%s)" % type(e).__name__)
        return _record("inv-receipt-sink", "HELD",
                       "sink failure refused coded: %s" % code)
    finally:
        er.set_emit(None)
    if ok is True:
        return _record("inv-receipt-sink", "HELD",
                       "receipt bind+verify completed under raising sink")
    _record("inv-receipt-sink", "BREAK", "receipt misbehaved")


def p_inv_ceremony_sink():
    """F352 inventory: ceremony issue + verify under a raising sink."""
    from gov import ceremony_binding as cb
    from gov import ed25519
    cb.set_emit(_boom)
    try:
        rec, seed = _ceremony_parts()
        ok = cb.verify_binding(
            rec, ed25519.publickey(seed).hex(),
            expected_nonce=None, expected_purpose="appraise")
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("inv-ceremony-sink", "BREAK",
                           "raising sink escaped ceremony issue/verify "
                           "uncoded (%s)" % type(e).__name__)
        return _record("inv-ceremony-sink", "HELD",
                       "sink failure refused coded: %s" % code)
    finally:
        cb.set_emit(None)
    if isinstance(ok, dict) and ok.get("challenge_purpose") == "appraise":
        return _record("inv-ceremony-sink", "HELD",
                       "ceremony issue+verify completed under raising "
                       "sink")
    _record("inv-ceremony-sink", "BREAK", "ceremony misbehaved")


def _green_checks():
    if SKIP_GREEN:
        return
    # Depth-1: w290_redteam's f352 probe flips HELD (F352 fix, wave-281
    # precedent): 6 BREAK -> 5 BREAK at lane time (F353/F354/F355 still open).
    # Wave-291 merge re-pin: F352-F355 ALL closed on the composed tree ->
    # 0 BREAK.
    checks = [
        ("evals/w290_redteam_probes.py", 0),
        ("evals/w289_ceremony_probes.py", 0),
    ]
    for rel, expected in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w291-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak != expected:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected %d)" % (nbreak,
                                                            expected))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: %d BREAK as expected" % expected)


def main():
    p_taxonomy_pin()
    p_f352_issue_sink_isolated()
    p_f352_sink_ok()
    p_inv_provenance_sink()
    p_inv_posture_sink()
    p_inv_receipt_sink()
    p_inv_ceremony_sink()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w291_f352: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
