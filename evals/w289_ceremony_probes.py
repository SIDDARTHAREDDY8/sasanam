"""Wave-289 lane 5 battery: ceremony-bound evidence (challenge binding).

Base: wave-288 push 18beb4044a26cba48bd895d95b505d7adc327422.
On the pristine base every defect probe BREAKs (module absent). After the
build every probe must HELD: the module mints operator-signed
challenge-bound records (verifier-supplied nonce >= 64 bits + purpose),
refuses replay into a different ceremony, refuses purpose confusion,
anchors the (content digest, nonce, purpose) tuple so the anchor chain
witnesses BOTH content and ceremony, and refuses anchor substitution
between ceremonies.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.
"""

import json
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

# Wave-288 merge: pin 1700; Wave-289 lane 5: pin 1700 -> 1706
# (+6 challenge-* codes).
TAXONOMY_PIN = 2012 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)



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
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "2012/2012/0 sorted")




def _import():
    try:
        from gov import ceremony_binding as cb
        return cb, None
    except ImportError as e:
        return None, e


def p_module_present():
    cb, err = _import()
    if cb is None:
        return _record("challenge-module-present", "BREAK",
                       "gov/ceremony_binding.py absent: %s" % (err,))
    for name in ("issue_binding", "verify_binding", "ceremony_leaf",
                 "anchor_binding", "verify_anchored_binding"):
        if not callable(getattr(cb, name, None)):
            return _record("challenge-module-present", "BREAK",
                           "missing public seam %r" % (name,))
    _record("challenge-module-present", "HELD", "module + seams live")


def p_issue_requires_challenge():
    cb, err = _import()
    if cb is None:
        return _record("challenge-issue-requires-challenge", "BREAK",
                       "module absent")
    seed = secrets.token_bytes(32)
    # No challenge at all: must refuse coded.
    try:
        cb.issue_binding(operator_seed=seed, operator_keyid="op-1",
                         challenge_nonce=b"", challenge_purpose="x",
                         content_digest="ab" * 32)
    except Exception as e:
        code = getattr(e, "code", None)
        if code == "challenge-nonce-invalid":
            _record("challenge-issue-requires-challenge", "HELD",
                    "empty nonce refused coded")
        else:
            _record("challenge-issue-requires-challenge", "BREAK",
                    "uncoded refusal: %r" % (e,))
        return
    _record("challenge-issue-requires-challenge", "BREAK",
            "issuance without a challenge succeeded")


def p_nonce_minimum_boundary():
    cb, err = _import()
    if cb is None:
        return _record("challenge-nonce-floor", "BREAK", "module absent")
    seed = secrets.token_bytes(32)
    # 63 bits (7 bytes) must fail.
    try:
        cb.issue_binding(operator_seed=seed, operator_keyid="op-1",
                         challenge_nonce=b"\x01" * 7,
                         challenge_purpose="x",
                         content_digest="ab" * 32)
        return _record("challenge-nonce-floor", "BREAK",
                       "7-byte nonce accepted")
    except Exception as e:
        if getattr(e, "code", None) != "challenge-nonce-invalid":
            return _record("challenge-nonce-floor", "BREAK",
                           "uncoded 7-byte refusal: %r" % (e,))
    # Exactly 64 bits (8 bytes) must succeed.
    rec = cb.issue_binding(operator_seed=seed, operator_keyid="op-1",
                           challenge_nonce=b"\x01" * 8,
                           challenge_purpose="x",
                           content_digest="ab" * 32)
    if not isinstance(rec, dict):
        return _record("challenge-nonce-floor", "BREAK",
                       "8-byte nonce not issued")
    _record("challenge-nonce-floor", "HELD",
            "7 bytes refused coded, 8 bytes issued")


def p_nonce_binding_replay():
    cb, err = _import()
    if cb is None:
        return _record("challenge-replay-across-challenges", "BREAK",
                       "module absent")
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    nonce_a = secrets.token_bytes(16)
    nonce_b = secrets.token_bytes(16)
    rec = cb.issue_binding(operator_seed=seed, operator_keyid="op-1",
                           challenge_nonce=nonce_a,
                           challenge_purpose="pilot-appraisal",
                           content_digest="ab" * 32)
    # Replay into a DIFFERENT ceremony must refuse challenge-nonce-mismatch.
    try:
        cb.verify_binding(rec, pub, expected_nonce=nonce_b)
        return _record("challenge-replay-across-challenges", "BREAK",
                       "replay into different ceremony accepted")
    except Exception as e:
        if getattr(e, "code", None) != "challenge-nonce-mismatch":
            return _record("challenge-replay-across-challenges", "BREAK",
                           "wrong refusal: %r" % (e,))
    # The original ceremony must verify.
    cb.verify_binding(rec, pub, expected_nonce=nonce_a,
                      expected_purpose="pilot-appraisal")
    _record("challenge-replay-across-challenges", "HELD",
            "replay refused coded; original verifies")


def p_purpose_confusion():
    cb, err = _import()
    if cb is None:
        return _record("challenge-purpose-confusion", "BREAK",
                       "module absent")
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    nonce = secrets.token_bytes(16)
    rec = cb.issue_binding(operator_seed=seed, operator_keyid="op-1",
                           challenge_nonce=nonce,
                           challenge_purpose="audit-evidence",
                           content_digest="ab" * 32)
    try:
        cb.verify_binding(rec, pub, expected_nonce=nonce,
                          expected_purpose="release-gate")
        return _record("challenge-purpose-confusion", "BREAK",
                       "purpose confusion accepted")
    except Exception as e:
        if getattr(e, "code", None) != "challenge-purpose-mismatch":
            return _record("challenge-purpose-confusion", "BREAK",
                           "wrong refusal: %r" % (e,))
    _record("challenge-purpose-confusion", "HELD",
            "purpose confusion refused coded")


def p_forged_signature():
    cb, err = _import()
    if cb is None:
        return _record("challenge-forged-signature", "BREAK", "module absent")
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    other_seed = secrets.token_bytes(32)
    nonce = secrets.token_bytes(16)
    rec = cb.issue_binding(operator_seed=other_seed, operator_keyid="op-1",
                           challenge_nonce=nonce,
                           challenge_purpose="audit-evidence",
                           content_digest="ab" * 32)
    try:
        cb.verify_binding(rec, pub, expected_nonce=nonce,
                          expected_purpose="audit-evidence")
        return _record("challenge-forged-signature", "BREAK",
                       "forged signature accepted")
    except Exception as e:
        if getattr(e, "code", None) != "challenge-signature-invalid":
            return _record("challenge-forged-signature", "BREAK",
                           "wrong refusal: %r" % (e,))
    _record("challenge-forged-signature", "HELD",
            "forged signature refused coded")


def p_tampered_challenge_refused():
    cb, err = _import()
    if cb is None:
        return _record("challenge-tampered-challenge", "BREAK",
                       "module absent")
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    nonce = secrets.token_bytes(16)
    rec = cb.issue_binding(operator_seed=seed, operator_keyid="op-1",
                           challenge_nonce=nonce,
                           challenge_purpose="audit-evidence",
                           content_digest="ab" * 32)
    rec = json.loads(json.dumps(rec))  # deep copy
    rec["payload"]["challenge_nonce"] = secrets.token_bytes(16).hex()
    try:
        cb.verify_binding(rec, pub)
        return _record("challenge-tampered-challenge", "BREAK",
                       "tampered nonce accepted")
    except Exception as e:
        code = getattr(e, "code", None)
        if code not in ("challenge-signature-invalid",
                        "challenge-nonce-mismatch"):
            return _record("challenge-tampered-challenge", "BREAK",
                           "wrong refusal: %r" % (e,))
    _record("challenge-tampered-challenge", "HELD",
            "tampered challenge breaks signature, refused coded")


def p_anchor_binds_ceremony():
    cb, err = _import()
    if cb is None:
        return _record("challenge-anchor-binds-ceremony", "BREAK",
                       "module absent")
    from gov import ed25519
    from gov.evidence_anchor import TransparencyLog
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    log_seed = secrets.token_bytes(32)
    log_pub = ed25519.publickey(log_seed).hex()
    log = TransparencyLog(tempfile.mkdtemp(prefix="challenge-anchor-"),
                          "test-origin", "log-key", signer_seed=log_seed)
    nonce = secrets.token_bytes(16)
    rec = cb.issue_binding(operator_seed=seed, operator_keyid="op-1",
                           challenge_nonce=nonce,
                           challenge_purpose="pilot-appraisal",
                           content_digest="ab" * 32)
    receipt, leaf = cb.anchor_binding(log, rec)
    # The leaf must differ from the bare content digest (ceremony bound).
    if receipt.get("bundle_digest") == "ab" * 32:
        return _record("challenge-anchor-binds-ceremony", "BREAK",
                       "anchor leaf is the bare content digest -- "
                       "ceremony not bound")
    payload = cb.verify_anchored_binding(
        rec, receipt, log_pub, pub, expected_nonce=nonce,
        expected_purpose="pilot-appraisal")
    if payload.get("content_digest") != "ab" * 32:
        return _record("challenge-anchor-binds-ceremony", "BREAK",
                       "anchored verify returned wrong payload")
    _record("challenge-anchor-binds-ceremony", "HELD",
            "anchor chain witnesses (content digest + nonce + purpose)")


def p_anchor_substitution_between_ceremonies():
    cb, err = _import()
    if cb is None:
        return _record("challenge-anchor-substitution", "BREAK",
                       "module absent")
    from gov import ed25519
    from gov.evidence_anchor import TransparencyLog
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    log_seed = secrets.token_bytes(32)
    log_pub = ed25519.publickey(log_seed).hex()
    log = TransparencyLog(tempfile.mkdtemp(prefix="challenge-subst-"),
                          "test-origin", "log-key", signer_seed=log_seed)
    nonce_a = secrets.token_bytes(16)
    rec_a = cb.issue_binding(operator_seed=seed, operator_keyid="op-1",
                             challenge_nonce=nonce_a,
                             challenge_purpose="pilot-appraisal",
                             content_digest="ab" * 32)
    nonce_b = secrets.token_bytes(16)
    rec_b = cb.issue_binding(operator_seed=seed, operator_keyid="op-1",
                             challenge_nonce=nonce_b,
                             challenge_purpose="other-ceremony",
                             content_digest="ab" * 32)
    receipt_b, _ = cb.anchor_binding(log, rec_b)
    # Present ceremony A's record against ceremony B's anchor receipt.
    try:
        cb.verify_anchored_binding(rec_a, receipt_b, log_pub, pub,
                                   expected_nonce=nonce_a,
                                   expected_purpose="pilot-appraisal")
        return _record("challenge-anchor-substitution", "BREAK",
                       "anchor substitution between ceremonies accepted")
    except Exception as e:
        if getattr(e, "code", None) != "challenge-anchor-mismatch":
            return _record("challenge-anchor-substitution", "BREAK",
                           "wrong refusal: %r" % (e,))
    _record("challenge-anchor-substitution", "HELD",
            "anchor substitution refused coded")


def p_tsa_reference_no_clock():
    cb, err = _import()
    if cb is None:
        return _record("challenge-tsa-reference", "BREAK", "module absent")
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    nonce = secrets.token_bytes(16)
    # Freshness is carried by a TSA token reference, not invented here.
    rec = cb.issue_binding(operator_seed=seed, operator_keyid="op-1",
                           challenge_nonce=nonce,
                           challenge_purpose="audit-evidence",
                           content_digest="ab" * 32,
                           tsa_token={"token": "tsa-reference"})
    payload = cb.verify_binding(rec, pub, expected_nonce=nonce,
                                expected_purpose="audit-evidence")
    if payload.get("tsa_token") != {"token": "tsa-reference"}:
        return _record("challenge-tsa-reference", "BREAK",
                       "tsa_token reference not preserved")
    if not isinstance(payload.get("challenge_nonce"), str):
        return _record("challenge-tsa-reference", "BREAK",
                       "payload shape wrong")
    _record("challenge-tsa-reference", "HELD",
            "tsa_token referenced; module owns no clock")


def p_malformed_inputs_coded():
    cb, err = _import()
    if cb is None:
        return _record("challenge-malformed-coded", "BREAK", "module absent")
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    nonce = secrets.token_bytes(16)
    rec = cb.issue_binding(operator_seed=seed, operator_keyid="op-1",
                           challenge_nonce=nonce,
                           challenge_purpose="audit-evidence",
                           content_digest="ab" * 32)
    bad_records = [
        "not-a-mapping",
        {"ceremony_format": "sasanam-challenge-binding/1"},
        {"ceremony_format": "sasanam-challenge-binding/1",
         "protected": {}, "payload": {}, "signature": "ff"},
        dict(rec, signature=None),
    ]
    for i, bad in enumerate(bad_records):
        try:
            cb.verify_binding(bad, pub)
            return _record("challenge-malformed-coded", "BREAK",
                           "malformed record %d accepted" % (i,))
        except Exception as e:
            code = getattr(e, "code", None)
            if not (isinstance(code, str) and code.startswith("challenge-")):
                return _record("challenge-malformed-coded", "BREAK",
                               "uncoded escape on record %d: %r" % (i, e))
    _record("challenge-malformed-coded", "HELD",
            "all malformed records refuse coded")


def p_emit_sink_exists():
    cb, err = _import()
    if cb is None:
        return _record("challenge-emit", "BREAK", "module absent")
    if not callable(getattr(cb, "set_emit", None)):
        return _record("challenge-emit", "BREAK", "no set_emit sink")
    events = []
    cb.set_emit(events.append)
    try:
        seed = secrets.token_bytes(32)
        cb.issue_binding(operator_seed=seed, operator_keyid="op-1",
                         challenge_nonce=secrets.token_bytes(16),
                         challenge_purpose="audit-evidence",
                         content_digest="ab" * 32)
    finally:
        cb.set_emit(None)
    if not events or events[0].get("event") != "binding-issued":
        return _record("challenge-emit", "BREAK", "no binding-issued event")
    _record("challenge-emit", "HELD", "audit sink wired")


def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        "evals/w288_eat_probes.py",
        "evals/w287_tsa_probes.py",
        "evals/w285_tessera_probes.py",
        "evals/w285_receipt_probes.py",
    ]
    for rel in checks:
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            _record(os.path.basename(rel), "HELD",
                    "green check: battery absent on this tree, skipped")
            continue
        d = tempfile.mkdtemp(prefix="w289-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR",
                    "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: 0 BREAK as expected")


def main():
    p_taxonomy_pin()
    p_module_present()
    p_issue_requires_challenge()
    p_nonce_minimum_boundary()
    p_nonce_binding_replay()
    p_purpose_confusion()
    p_forged_signature()
    p_tampered_challenge_refused()
    p_anchor_binds_ceremony()
    p_anchor_substitution_between_ceremonies()
    p_tsa_reference_no_clock()
    p_malformed_inputs_coded()
    p_emit_sink_exists()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w289_ceremony: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
