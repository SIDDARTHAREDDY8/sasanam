"""Wave-290 lane 1 closure battery: F346 + F347 (audit-sink uncoded escapes).

Base: wave-289 push eb08e95ae9eb6862d689f9eede5489d0177a5ceb
(verified via git rev-parse HEAD before work).

F346: gov/runtime_posture.py `_emit_event` unisolated in issue_posture --
a raising sink escapes as the sink's own exception type (code=None).
F347: gov/evidence_receipt.py `_emit` unisolated at bind_receipt,
verify_receipt_offline, and denounce_fork.

Same defect class as F345 (filed against evidence_provenance, closed in
wave-289 via the timestamp_authority swallow trade-off: a broken audit
sink must never break issuance or verification -- the failure is
recorded in the docstring/comment, never the sink's raw type).

Close-when for both: sink failures isolated (swallowed with a recorded
failure mode, or refused coded) -- never the sink's raw exception type.

$0 spend, synthetic/local, deterministic (fixed fixtures, secrets only
for fresh keys). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g290-f346f347 && TMPDIR=/var/tmp/g290-f346f347 \
    ~/workspace/.gov-venv/bin/python evals/w290_f346_f347_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g290-f346f347b \
    ~/workspace/.gov-venv/bin/python evals/w290_f346_f347_probes.py
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

# Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*).
TAXONOMY_PIN = 2070 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2070 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*). # Wave-333 lane 4: pin 2062 -> 2070 (+8 revocation-push-*).



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


def _posture_parts(producer_id="operator"):
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
        producer_id=producer_id)
    return rec, seed, pub


def _anchor_parts():
    from gov import evidence_anchor as ea
    d = tempfile.mkdtemp(prefix="w290-f346f347-")
    seed = secrets.token_bytes(32)
    log = ea.TransparencyLog(d, origin="w290origin", signer_keyid="op1",
                             signer_seed=seed)
    anchored = ea.anchor(log, secrets.token_bytes(32).hex())
    return anchored, seed


def p_f346_sink_isolated():
    """F346: raising sink must not escape issue_posture uncoded."""
    from gov import runtime_posture as rp

    def _boom(ev):
        raise ValueError("sink boom")

    rp.set_emit(_boom)
    try:
        rec, seed, pub = _posture_parts()
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f346-posture-sink", "BREAK",
                           "raising sink escaped issue_posture uncoded "
                           "(%s)" % type(e).__name__)
        return _record("f346-posture-sink", "HELD",
                       "sink failure refused coded: %s" % code)
    finally:
        rp.set_emit(None)
    if rec.get("payload", {}).get("software_id") == "agent/1.0":
        return _record("f346-posture-sink", "HELD",
                       "sink failure isolated: issuance completed, no "
                       "raw sink exception at the seam (F345 mechanism)")
    _record("f346-posture-sink", "BREAK", "issuance misbehaved")


def p_f346_sink_ok():
    """Positive control: a well-behaved sink does not break issuance."""
    from gov import runtime_posture as rp
    seen = []
    rp.set_emit(seen.append)
    try:
        rec, seed, pub = _posture_parts()
        payload = rp.verify_posture(rec, pub)
    except Exception as e:  # noqa: BLE001
        return _record("f346-sink-ok", "BREAK",
                       "well-behaved sink broke issuance: %r"
                       % getattr(e, "code", type(e).__name__))
    finally:
        rp.set_emit(None)
    if seen and payload.get("software_id") == "agent/1.0":
        return _record("f346-sink-ok", "HELD",
                       "issuance + verify fine under a good sink")
    _record("f346-sink-ok", "BREAK", "sink saw nothing or payload wrong")


def p_f347_bind_sink_isolated():
    """F347: raising sink must not escape bind_receipt uncoded."""
    from gov import evidence_receipt as er

    def _boom(ev):
        raise ValueError("sink boom")

    anchored, seed = _anchor_parts()
    er.set_emit(_boom)
    try:
        receipt = er.bind_receipt(anchored, seed)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f347-bind-sink", "BREAK",
                           "raising sink escaped bind_receipt uncoded "
                           "(%s)" % type(e).__name__)
        return _record("f347-bind-sink", "HELD",
                       "sink failure refused coded: %s" % code)
    finally:
        er.set_emit(None)
    if receipt is not None:
        return _record("f347-bind-sink", "HELD",
                       "sink failure isolated: bind completed, no raw "
                       "sink exception at the seam (F345 mechanism)")
    _record("f347-bind-sink", "BREAK", "bind misbehaved")


def p_f347_verify_sink_isolated():
    """F347: raising sink must not escape verify_receipt_offline uncoded."""
    from gov import evidence_receipt as er
    from gov import ed25519

    def _boom(ev):
        raise ValueError("sink boom")

    anchored, seed = _anchor_parts()
    receipt = er.bind_receipt(anchored, seed)
    er.set_emit(_boom)
    try:
        ok = er.verify_receipt_offline(receipt, ed25519.publickey(seed))
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f347-verify-sink", "BREAK",
                           "raising sink escaped verify_receipt_offline "
                           "uncoded (%s)" % type(e).__name__)
        return _record("f347-verify-sink", "HELD",
                       "sink failure refused coded: %s" % code)
    finally:
        er.set_emit(None)
    if ok is True:
        return _record("f347-verify-sink", "HELD",
                       "sink failure isolated: offline verify completed, "
                       "no raw sink exception at the seam")
    _record("f347-verify-sink", "BREAK", "offline verify misbehaved")


def p_f347_denounce_sink_isolated():
    """F347: raising sink must not escape denounce_fork uncoded.

    A proven fork (same log origin, same tree size, two validly-signed
    disagreeing heads) is the only path that fires the fork-denounced
    audit event, so the fixture builds a real fork: two logs with the
    same origin, one anchor each (same size, different digests).
    """
    from gov import evidence_anchor as ea
    from gov import evidence_receipt as er
    from gov import ed25519

    def _boom(ev):
        raise ValueError("sink boom")

    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed)
    receipts = []
    for tag in ("a", "b"):
        d = tempfile.mkdtemp(prefix="w290-fork-%s-" % tag)
        log = ea.TransparencyLog(d, origin="w290forksame",
                                 signer_keyid="op1", signer_seed=seed)
        anchored = ea.anchor(log, secrets.token_bytes(32).hex())
        receipts.append(er.bind_receipt(anchored, seed))
    er.set_emit(_boom)
    try:
        denounced = er.denounce_fork(receipts[0], receipts[1], pub)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f347-denounce-sink", "BREAK",
                           "raising sink escaped denounce_fork uncoded "
                           "(%s)" % type(e).__name__)
        return _record("f347-denounce-sink", "HELD",
                       "sink failure refused coded: %s" % code)
    finally:
        er.set_emit(None)
    if denounced.get("fork") is True:
        return _record("f347-denounce-sink", "HELD",
                       "sink failure isolated: proven fork denounced, no "
                       "raw sink exception at the seam")
    _record("f347-denounce-sink", "BREAK",
            "fixture did not produce a fork (got %r)" % (denounced,))


def p_f347_bind_sink_ok():
    """Positive control: genuine bind works under a good sink."""
    from gov import evidence_receipt as er
    from gov import ed25519
    anchored, seed = _anchor_parts()
    seen = []
    er.set_emit(seen.append)
    try:
        receipt = er.bind_receipt(anchored, seed)
        ok = er.verify_receipt_offline(receipt, ed25519.publickey(seed))
    except Exception as e:  # noqa: BLE001
        return _record("f347-sink-ok", "BREAK",
                       "good sink broke bind: %r"
                       % getattr(e, "code", type(e).__name__))
    finally:
        er.set_emit(None)
    if ok is True and seen:
        return _record("f347-sink-ok", "HELD",
                       "bind + offline verify fine under a good sink")
    _record("f347-sink-ok", "BREAK", "bind/verify misbehaved")


def _green_checks():
    if SKIP_GREEN:
        return
    # Depth-1: w289_redteam now expects f346/f347 HELD (F345-class fix,
    # wave-281 precedent) with 7 remaining BREAKs (F348-F351).
    checks = [
        ("evals/w288_eat_probes.py", 0),
        ("evals/w285_tessera_probes.py", 0),
    ]
    for rel, expected in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w290-green-")
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
    p_f346_sink_isolated()
    p_f346_sink_ok()
    p_f347_bind_sink_isolated()
    p_f347_verify_sink_isolated()
    p_f347_denounce_sink_isolated()
    p_f347_bind_sink_ok()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w290_f346_f347: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
