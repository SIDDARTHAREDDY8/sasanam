"""Wave-287 lane 6 red-first battery: TSA-pattern timestamps.

Base: wave-286 push 8c811375. The gap under test is RFC 3161-pattern
timestamping for checkpoints and inclusion receipts: the wave-285/286
lane leaves mint operator-signed checkpoints and inclusion receipts,
but nothing binds a TRUSTED THIRD-PARTY time to them. An auditor cannot
tell when a checkpoint actually existed -- the operator's own
``issued_at`` is self-claimed, so backdating (minting a "proof of
existence" today for a bundle created months ago) and future-dating
are both silent. The TSA pattern supplies the mechanism: an
independent timestamp authority signs a (messageImprint, genTime, nonce)
token over the artifact's content identity, and verifiers enforce
skew, ordering, and freshness rules against it.

Red-first: on the pristine base (module absent) every capability probe
BREAKs. After the build, all HELD in staging and under
env -u GOV_DEPLOYMENT_MODE.

$0 spend, synthetic/local, deterministic (fixed seeds only, never
asserted on; explicit gen_time and now= everywhere). Stdlib only, no
in-repo git subprocesses.
"""

import copy
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# Fixed test key (deterministic: no secrets module in this battery).
os.environ.setdefault("GOV_LOG_KEY", "ab" * 32)
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w287-tsa")
os.environ.setdefault("TMPDIR", "/var/tmp/g287-tsa")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Wave-287 lane 6: pin 1660 -> 1667 (+7 tsa-* codes).; Wave-287 merge: pin 1667 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*)
TAXONOMY_PIN = 1827  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

_RESULTS = []

PLUGIN_META = ("tsa-timestamps", "direct", "held-vs-expected")
PROBE_METADATA = {}

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Fixed fixtures shared across probes (deterministic).
_TSA_SEED = b"T" * 32
_TSA_KEYID = "tsa-1"
_OP_SEED = b"O" * 32
_OPERATOR_SIG_HEX = "ab" * 64
_ORIGIN = "test-origin"
_SIZE = 7
_ROOT_HEX = "cd" * 32
_NONCE_HEX = "ef" * 16
_GEN_TIME = 1700000000  # 2023-11-14T22:13:20Z, fixed past fixture


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict,
                     "note": note})
    PROBE_METADATA.setdefault(probe_id, PLUGIN_META)


def _needs_tsa(probe_id):
    try:
        from gov import timestamp_authority as tsa
        return tsa
    except ImportError:
        _record(probe_id, "BREAK",
                "gov.timestamp_authority absent on base")
        return None


def _literals():
    with open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "gov", "decision_codes.py"),
            encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def _tsa_pubkey_hex():
    from gov import ed25519
    return ed25519.publickey(_TSA_SEED).hex()


def _op_pubkey_hex():
    from gov import ed25519
    return ed25519.publickey(_OP_SEED).hex()


def _valid_token(tsa):
    return tsa.issue_token(
        operator_sig_hex=_OPERATOR_SIG_HEX,
        origin=_ORIGIN, size=_SIZE, root_hex=_ROOT_HEX,
        nonce=_NONCE_HEX, tsa_seed=_TSA_SEED, tsa_keyid=_TSA_KEYID,
        gen_time=_GEN_TIME)


def _expect_code(fn, code, probe_id, ok_note):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 -- probe must not die
        got = getattr(exc, "code", "")
        if got == code:
            _record(probe_id, "HELD", ok_note)
        else:
            _record(probe_id, "BREAK",
                    "wrong code: %r (expected %r)" % (got, code))
        return
    _record(probe_id, "BREAK",
            "verified/silent -- expected refusal %r" % code)


# ---------------------------------------------------------------------------
# Capability probes (BREAK on base by missing module; HELD after the build)
# ---------------------------------------------------------------------------

def p_module_present():
    tsa = _needs_tsa("module-present")
    if tsa is None:
        return
    _record("module-present", "HELD",
            "gov.timestamp_authority importable; format=%s"
            % getattr(tsa, "TOKEN_FORMAT", "?"))


def p_token_happy_path():
    tsa = _needs_tsa("token-happy-path")
    if tsa is None:
        return
    try:
        tok = _valid_token(tsa)
        for field in ("token_format", "protected", "payload",
                      "signature"):
            assert field in tok, "missing %s" % field
        assert tok["token_format"] == tsa.TOKEN_FORMAT == \
            "gov/tsa-timestamped-checkpoint/1", "format tag"
        assert tok["protected"]["alg"] == "EdDSA", "alg"
        assert tok["protected"]["kid"] == _TSA_KEYID, "kid"
        assert isinstance(tok["signature"], str) and \
            len(tok["signature"]) == 128, "64-byte hex signature"
        payload = tsa.verify_token(tok, _tsa_pubkey_hex(),
                                   expected_nonce=_NONCE_HEX)
        assert payload["genTime"] == _GEN_TIME, "genTime roundtrip"
        assert payload["nonce"] == _NONCE_HEX, "nonce roundtrip"
        assert isinstance(payload["messageImprint"], str) and \
            re.fullmatch(r"[0-9a-f]{64}",
                         payload["messageImprint"]), \
            "messageImprint 64 hex"
        assert payload["root"] == _ROOT_HEX, "root bound"
    except Exception as exc:  # noqa: BLE001
        _record("token-happy-path", "BREAK", "raised: %r" % exc)
        return
    _record("token-happy-path", "HELD",
            "issue -> verify returns payload; genTime/nonce match; "
            "messageImprint 64 hex")


def p_tampered_gentime():
    tsa = _needs_tsa("tampered-gentime")
    if tsa is None:
        return
    tok = _valid_token(tsa)
    tok["payload"]["genTime"] += 100
    _expect_code(lambda: tsa.verify_token(tok, _tsa_pubkey_hex()),
                 "tsa-signature-invalid", "tampered-gentime",
                 "genTime +100 trips tsa-signature-invalid")


def p_future_gentime():
    tsa = _needs_tsa("future-gentime")
    if tsa is None:
        return
    now = int(time.time())
    tok = tsa.issue_token(
        operator_sig_hex=_OPERATOR_SIG_HEX,
        origin=_ORIGIN, size=_SIZE, root_hex=_ROOT_HEX,
        nonce=_NONCE_HEX, tsa_seed=_TSA_SEED, tsa_keyid=_TSA_KEYID,
        gen_time=now + 3600)
    _expect_code(lambda: tsa.verify_token(tok, _tsa_pubkey_hex(),
                                          now=now),
                 "tsa-gentime-in-future", "future-gentime",
                 "genTime now+3600 refuses tsa-gentime-in-future")


def p_backdated_gentime():
    tsa = _needs_tsa("backdated-gentime")
    if tsa is None:
        return
    ledger = tsa.FirstObservedLedger()
    ledger.record(_ORIGIN, _SIZE, observed_at=1700000100)
    tok = _valid_token(tsa)  # genTime 1700000000 < first-seen 1700000100
    _expect_code(lambda: tsa.verify_token(tok, _tsa_pubkey_hex(),
                                          ledger=ledger),
                 "tsa-gentime-backdated", "backdated-gentime",
                 "genTime before first-observed refuses "
                 "tsa-gentime-backdated")


def p_nonce_replay():
    tsa = _needs_tsa("nonce-replay")
    if tsa is None:
        return
    tok = _valid_token(tsa)
    _expect_code(lambda: tsa.verify_token(tok, _tsa_pubkey_hex(),
                                          expected_nonce="00" * 16),
                 "tsa-nonce-mismatch", "nonce-replay",
                 "wrong expected_nonce refuses tsa-nonce-mismatch")


def _checkpoint(root_hex):
    return {"origin": _ORIGIN, "size": _SIZE, "root": root_hex,
            "operator_sig": _OPERATOR_SIG_HEX}


def p_imprint_mismatch():
    tsa = _needs_tsa("imprint-mismatch")
    if tsa is None:
        return
    stamped_a = tsa.timestamp_checkpoint(
        _checkpoint(_ROOT_HEX), _TSA_SEED, _TSA_KEYID,
        gen_time=_GEN_TIME, nonce=_NONCE_HEX)
    # Checkpoint B has a different root but carries A's token:
    # the token's messageImprint no longer matches the content.
    b = _checkpoint("dc" * 32)
    b["tsa_token"] = stamped_a["tsa_token"]
    _expect_code(
        lambda: tsa.verify_timestamped_checkpoint(
            b, _op_pubkey_hex(), _tsa_pubkey_hex(),
            expected_nonce=_NONCE_HEX),
        "tsa-imprint-mismatch", "imprint-mismatch",
        "B-with-A-token refuses tsa-imprint-mismatch")


def p_checkpoint_roundtrip():
    tsa = _needs_tsa("checkpoint-roundtrip")
    if tsa is None:
        return
    try:
        stamped = tsa.timestamp_checkpoint(
            _checkpoint(_ROOT_HEX), _TSA_SEED, _TSA_KEYID,
            gen_time=_GEN_TIME, nonce=_NONCE_HEX)
        assert "tsa_token" in stamped, "token attached"
        payload = tsa.verify_timestamped_checkpoint(
            stamped, _op_pubkey_hex(), _tsa_pubkey_hex(),
            expected_nonce=_NONCE_HEX)
        assert payload["genTime"] == _GEN_TIME, "genTime match"
    except Exception as exc:  # noqa: BLE001
        _record("checkpoint-roundtrip", "BREAK", "raised: %r" % exc)
        return
    _record("checkpoint-roundtrip", "HELD",
            "timestamp -> verify returns payload; genTime matches")


def p_receipt_carries_token():
    tsa = _needs_tsa("receipt-carries-token")
    if tsa is None:
        return
    import hashlib
    from gov import ed25519
    from gov import evidence_anchor as ea
    from gov import evidence_receipt as er
    try:
        with tempfile.TemporaryDirectory() as tmp:
            log = ea.TransparencyLog(
                os.path.join(tmp, "tsa-log"), _ORIGIN, "op-1",
                signer_seed=_OP_SEED)
            log.add(b"bundle")
            log.await_publication(0)
            digest = hashlib.sha256(b"bundle").hexdigest()
            rcpt = er.issue_receipt(log, digest, _OP_SEED)
        stamped = tsa.timestamp_receipt(
            rcpt, _TSA_SEED, _TSA_KEYID,
            gen_time=_GEN_TIME, nonce=_NONCE_HEX)
        assert stamped["payload"]["tsa_token"], "tsa_token carried"
        op_pub_hex = ed25519.publickey(_OP_SEED).hex()
        out = tsa.verify_receipt_with_tsa(
            stamped, op_pub_hex, _tsa_pubkey_hex(),
            expected_nonce=_NONCE_HEX)
        assert isinstance(out, dict), "verify returns dict"
    except Exception as exc:  # noqa: BLE001
        _record("receipt-carries-token", "BREAK", "raised: %r" % exc)
        return
    _record("receipt-carries-token", "HELD",
            "anchor -> receipt -> TSA stamp -> verify dict")


def p_tampered_token_sig():
    tsa = _needs_tsa("tampered-token-sig")
    if tsa is None:
        return
    tok = _valid_token(tsa)
    sig = tok["signature"]
    tok["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    _expect_code(lambda: tsa.verify_token(tok, _tsa_pubkey_hex()),
                 "tsa-signature-invalid", "tampered-token-sig",
                 "flipped sig nibble refuses tsa-signature-invalid")


def p_malformed_token():
    tsa = _needs_tsa("malformed-token")
    if tsa is None:
        return
    tok = _valid_token(tsa)
    del tok["signature"]
    _expect_code(lambda: tsa.verify_token(tok, _tsa_pubkey_hex()),
                 "tsa-token-malformed", "malformed-token",
                 "missing signature refuses tsa-token-malformed")


def p_taxonomy_pin():
    lits = _literals()
    uniq = sorted(set(lits))
    if len(lits) != TAXONOMY_PIN or len(uniq) != TAXONOMY_PIN \
            or uniq != sorted(lits):
        _record("taxonomy-pin", "BREAK",
                "taxonomy %d raw / %d unique (pin %d)"
                % (len(lits), len(uniq), TAXONOMY_PIN))
        return
    for code in ("tsa-token-malformed", "tsa-signature-invalid",
                 "tsa-gentime-invalid", "tsa-gentime-in-future",
                 "tsa-gentime-backdated", "tsa-nonce-mismatch",
                 "tsa-imprint-mismatch"):
        if code not in uniq:
            _record("taxonomy-pin", "BREAK",
                    "missing new code %s" % code)
            return
    _record("taxonomy-pin", "HELD",
            "pin %d raw/unique/sorted; 7 tsa-* codes present"
            % TAXONOMY_PIN)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    for probe in (p_module_present, p_token_happy_path,
                  p_tampered_gentime, p_future_gentime,
                  p_backdated_gentime, p_nonce_replay,
                  p_imprint_mismatch, p_checkpoint_roundtrip,
                  p_receipt_carries_token, p_tampered_token_sig,
                  p_malformed_token, p_taxonomy_pin):
        try:
            probe()
        except Exception as exc:  # noqa: BLE001 -- battery never dies
            _record(probe.__name__, "ERROR", "probe crashed: %r" % exc)
    green_results = []
    if not SKIP_GREEN:
        green_results = _green_checks()
    breaks = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    helds = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    errors = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    print("w287_tsa: %d BREAK / %d HELD / %d ERROR"
          % (breaks, helds, errors))
    for r in _RESULTS:
        if r["verdict"] != "HELD":
            print("  %s %s: %s" % (r["verdict"], r["probe_id"],
                                   r["note"]))
    for g in green_results:
        print("  green %s: %s" % (g["battery"], g["summary"]))
    return 0 if (breaks == 0 and errors == 0) else 1


def _green_checks():
    """Depth-1 green checks: adjacent batteries with GOV_SKIP_GREEN=1.

    Expect 0 BREAK: the wave-285/286 batteries are green on base and the
    TSA lane must not regress them.
    """
    out = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    adj = ["evals/w286_receipts_probes.py",
           "evals/w285_tessera_probes.py"]
    for rel in adj:
        path = os.path.join(repo, rel)
        if not os.path.exists(path):
            out.append({"battery": rel, "summary": "missing, skipped"})
            continue
        d = tempfile.mkdtemp(prefix="g287-green-", dir="/var/tmp")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d))
        except subprocess.TimeoutExpired:
            out.append({"battery": rel, "summary": "TIMEOUT"})
            continue
        tail = (proc.stdout or "").strip().splitlines()
        tail = tail[-1] if tail else "(no output)"
        out.append({"battery": rel,
                    "summary": "rc=%d %s" % (proc.returncode, tail)})
    return out


if __name__ == "__main__":
    sys.exit(main())
