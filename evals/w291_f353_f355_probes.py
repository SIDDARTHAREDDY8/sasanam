"""Wave-291 closure battery: F353 + F355 (both LOW).

Base: wave-290 merge 9c12f9b4b0aec88746786e68e3f84ae7f04d2d16
(verified via git rev-parse HEAD before work).

F353 (LOW): gov/ceremony_binding.py ceremony_leaf / anchor_binding raise
uncoded KeyError on a shape-valid-but-keyless payload (F351/F342/F344
class: all-refusals-coded contract). Close-when: keyless payloads refuse
LOUD with a coded challenge-* refusal.

F355 (LOW): non-hex signature strings escape uncoded (ValueError,
code=None) from ceremony_binding.verify_binding and
runtime_posture.verify_posture. _require_record_shape only checks the
signature is a non-empty str; bytes.fromhex then raises raw. Close-when:
non-hex signatures refuse coded; forged-but-well-formed hex signatures
still refuse coded (positive control).

Red-first: at base, f353-ceremony-leaf, f353-anchor-binding,
f353-partial-payload, f355a-ceremony-sig, f355b-posture-sig BREAK.
Post-fix: 0 BREAK / 11+ HELD / 0 ERROR.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g291-f353-f355 && TMPDIR=/var/tmp/g291-f353-f355 \
    ~/workspace/.gov-venv/bin/python evals/w291_f353_f355_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g291-f353-f355b \
    ~/workspace/.gov-venv/bin/python evals/w291_f353_f355_probes.py
"""

import os
import re
import secrets
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

# Wave-290 merge: pin 1706 -> 1710 (+4 provenance-rebuild-*). No new
# codes minted here (existing challenge/posture codes reused).
TAXONOMY_PIN = 2035 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)



_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """An uncaught exception becomes ERROR, never a dead battery."""
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
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "2035/2035/0 sorted")




# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _ceremony_parts(nonce=None, purpose="appraise"):
    from gov import ceremony_binding as cb
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    rec = cb.issue_binding(
        operator_seed=seed, operator_keyid="op1",
        challenge_nonce=nonce or secrets.token_bytes(16),
        challenge_purpose=purpose,
        content_digest=secrets.token_bytes(32).hex())
    return rec, seed, pub


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


def _keyless_ceremony_record():
    return {"ceremony_format": "sasanam-challenge-binding/1",
            "protected": {}, "payload": {}, "signature": "00"}


# ---------------------------------------------------------------------------
# F353: uncoded KeyError on keyless payload (ceremony_leaf,
# anchor_binding).
# ---------------------------------------------------------------------------

def _f353_refused(rec):
    """True when the record refuses with a coded ceremony error."""
    from gov import ceremony_binding as cb
    try:
        cb.ceremony_leaf(rec)
    except KeyError:
        return (False, "KeyError (code=None)")
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is not None and code.startswith("challenge-"):
            return (True, "coded %r" % (code,))
        return (False, "%s (code=%r)" % (type(e).__name__, code))
    return (False, "leaf produced (unexpected)")


def p_f353_ceremony_leaf_keyerror():
    held, why = _f353_refused(_keyless_ceremony_record())
    if held:
        return _record("f353-ceremony-leaf", "HELD",
                       "keyless payload refused coded: %s" % (why,))
    _record("f353-ceremony-leaf", "BREAK",
            "keyless payload escapes ceremony_leaf: %s" % (why,))


def p_f353_anchor_binding_keyerror():
    from gov import ceremony_binding as cb
    from gov import evidence_anchor as ea
    d = tempfile.mkdtemp(prefix="w291-f353-")
    seed = secrets.token_bytes(32)
    log = ea.TransparencyLog(d, origin="w291f353", signer_keyid="op1",
                             signer_seed=seed)
    rec = _keyless_ceremony_record()
    try:
        cb.anchor_binding(log, rec)
    except KeyError:
        return _record("f353-anchor-binding", "BREAK",
                       "keyless payload escapes anchor_binding as "
                       "KeyError (code=None)")
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is not None and code.startswith("challenge-"):
            return _record("f353-anchor-binding", "HELD",
                           "keyless payload refused coded %r" % (code,))
        return _record("f353-anchor-binding", "BREAK",
                       "keyless payload escapes uncoded: %s (code=%r)"
                       % (type(e).__name__, code))
    _record("f353-anchor-binding", "BREAK",
            "keyless payload anchored (unexpected)")


def p_f353_partial_payload():
    """A payload missing just one of the three leaf keys must also
    refuse coded, not KeyError."""
    rec = _keyless_ceremony_record()
    rec["payload"] = {"content_digest": "ab" * 32,
                      "challenge_nonce": "cd" * 32}
    held, why = _f353_refused(rec)
    if held:
        return _record("f353-partial-payload", "HELD",
                       "partial payload refused coded: %s" % (why,))
    _record("f353-partial-payload", "BREAK",
            "partial payload escapes ceremony_leaf: %s" % (why,))


def p_f353_leaf_ok():
    """Positive control: a well-formed record leafs deterministically."""
    from gov import ceremony_binding as cb
    rec, seed, pub = _ceremony_parts()
    leaf1 = cb.ceremony_leaf(rec)
    leaf2 = cb.ceremony_leaf(rec)
    if leaf1 == leaf2 and len(leaf1) == 64:
        return _record("f353-leaf-ok", "HELD",
                       "well-formed record leafs deterministically")
    _record("f353-leaf-ok", "BREAK", "leaf unstable")


# ---------------------------------------------------------------------------
# F355: uncoded ValueError on non-hex signature (verify_binding,
# verify_posture).
# ---------------------------------------------------------------------------

def _nonhex_ceremony_record():
    return {"ceremony_format": "sasanam-challenge-binding/1",
            "protected": {"a": 1},
            "payload": {"challenge_nonce": "ab" * 16,
                        "challenge_purpose": "x",
                        "content_digest": "cd" * 32},
            "signature": "not-hex!!"}


def _nonhex_posture_record():
    slot = {"log_id": "L", "log_index": 0, "expected_digest": "ef" * 32,
            "source_id": "s"}
    return {"posture_format": "sasanam-runtime-posture/1",
            "protected": {"a": 1},
            "payload": {"eat_nonce": "ab" * 16,
                        "submods": {"s": {"digest": "cd" * 32}},
                        "software_id": "x", "config_digest": "cd" * 32,
                        "endorsements": {c: dict(slot) for c in
                                        ("software_id", "config_digest",
                                         "submods")}},
            "signature": "not-hex!!"}


def p_f355a_ceremony_nonhex_sig():
    from gov import ceremony_binding as cb
    rec = _nonhex_ceremony_record()
    try:
        cb.verify_binding(rec, "ef" * 32)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is not None:
            return _record("f355a-ceremony-sig", "HELD",
                           "non-hex signature refused coded %r" % (code,))
        return _record("f355a-ceremony-sig", "BREAK",
                       "non-hex signature escapes as %s (code=None)"
                       % type(e).__name__)
    _record("f355a-ceremony-sig", "BREAK",
            "non-hex signature verified (unexpected)")


def p_f355b_posture_nonhex_sig():
    from gov import runtime_posture as rp
    rec = _nonhex_posture_record()
    try:
        rp.verify_posture(rec, "ef" * 32)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is not None:
            return _record("f355b-posture-sig", "HELD",
                           "non-hex signature refused coded %r" % (code,))
        return _record("f355b-posture-sig", "BREAK",
                       "non-hex signature escapes as %s (code=None)"
                       % type(e).__name__)
    _record("f355b-posture-sig", "BREAK",
            "non-hex signature verified (unexpected)")


def p_f355_forged_ok():
    """Positive control: forged-but-well-formed hex signatures refuse
    CODED on both verify paths."""
    from gov import ceremony_binding as cb
    from gov import runtime_posture as rp
    rec, seed, pub = _ceremony_parts()
    rec["signature"] = "00" * 64
    try:
        cb.verify_binding(rec, pub)
        _record("f355-forged-ok", "BREAK", "forged ceremony verified")
        return
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "challenge-signature-invalid":
            _record("f355-forged-ok", "BREAK",
                    "forged ceremony refused with wrong code %r"
                    % (getattr(e, "code", None),))
            return
    prec, pseed, ppub = _posture_parts()
    prec["signature"] = "00" * 64
    try:
        rp.verify_posture(prec, ppub)
        _record("f355-forged-ok", "BREAK", "forged posture verified")
        return
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "posture-signature-invalid":
            _record("f355-forged-ok", "BREAK",
                    "forged posture refused with wrong code %r"
                    % (getattr(e, "code", None),))
            return
    _record("f355-forged-ok", "HELD",
            "forged signatures refuse coded on both paths")


def p_f355_valid_ok():
    """Positive control: genuinely valid records verify on both paths."""
    from gov import ceremony_binding as cb
    from gov import runtime_posture as rp
    rec, seed, pub = _ceremony_parts()
    try:
        cb.verify_binding(rec, pub)
    except Exception as e:  # noqa: BLE001
        _record("f355-valid-ok", "BREAK",
                "valid ceremony refused: %r" % (e,))
        return
    prec, pseed, ppub = _posture_parts()
    try:
        rp.verify_posture(prec, ppub)
    except Exception as e:  # noqa: BLE001
        _record("f355-valid-ok", "BREAK",
                "valid posture refused: %r" % (e,))
        return
    _record("f355-valid-ok", "HELD", "valid records verify on both paths")


def p_f355_short_hex_sig():
    """Edge: well-formed hex but wrong length must refuse CODED
    (ed25519.verify returns False), never crash."""
    from gov import ceremony_binding as cb
    from gov import runtime_posture as rp
    rec = _nonhex_ceremony_record()
    rec["signature"] = "ab"
    try:
        cb.verify_binding(rec, "ef" * 32)
        _record("f355-short-hex", "BREAK", "short hex verified")
        return
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "challenge-signature-invalid":
            _record("f355-short-hex", "BREAK",
                    "short hex: wrong code %r" % (getattr(e, "code", None),))
            return
    prec = _nonhex_posture_record()
    prec["signature"] = "ab"
    try:
        rp.verify_posture(prec, "ef" * 32)
        _record("f355-short-hex", "BREAK", "short hex verified")
        return
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "posture-signature-invalid":
            _record("f355-short-hex", "BREAK",
                    "short hex: wrong code %r" % (getattr(e, "code", None),))
            return
    _record("f355-short-hex", "HELD",
            "wrong-length hex refuses coded on both paths")


# ---------------------------------------------------------------------------
# Green checks (depth-1; skipped when GOV_SKIP_GREEN=1).
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    # (battery, expected_breaks, label). w290_redteam drops from 6 BREAK
    # at base to 2 post-fix at lane time (f352 and f354 remain genuinely
    # OPEN). Wave-291 merge re-pin: F352-F355 ALL closed -> 0 BREAK.
    checks = [
        ("evals/w290_redteam_probes.py", 0, "w290-redteam"),
        ("evals/w289_ceremony_probes.py", 0, "w289-ceremony"),
        ("evals/w288_eat_probes.py", 0, "w288-eat"),
    ]
    for rel, expected, label in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w291-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(label, "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak != expected:
            _record(label, "BREAK",
                    "green check: %d BREAK (expected %d)" % (nbreak,
                                                            expected))
        else:
            _record(label, "HELD",
                    "green check: %d BREAK as expected" % nbreak)


def main():
    _safe("pin", p_taxonomy_pin)
    _safe("f353", p_f353_ceremony_leaf_keyerror)
    _safe("f353b", p_f353_anchor_binding_keyerror)
    _safe("f353c", p_f353_partial_payload)
    _safe("f353-ok", p_f353_leaf_ok)
    _safe("f355a", p_f355a_ceremony_nonhex_sig)
    _safe("f355b", p_f355b_posture_nonhex_sig)
    _safe("f355-forged", p_f355_forged_ok)
    _safe("f355-valid", p_f355_valid_ok)
    _safe("f355-short", p_f355_short_hex_sig)
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w291_f353_f355: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
