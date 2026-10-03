"""Wave-288 lane 8 battery: EAT JSON-profile (RFC 9711) posture.

Base: wave-287 push add3e92aa02e68daf6a2288c302a27fd3dfa4690.
On the pristine base every defect probe BREAKs (module absent). After the
build every probe must HELD: the module issues EAT-shaped posture records
with >=64-bit nonces, submod anti-substitution nesting, per-claim
endorsement slots, operator-signed envelopes, and fail-closed coded
verification.

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
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-287 merge: pin 1684 -> 1690 (+6 posture-* codes).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*)
TAXONOMY_PIN = 1826  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

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
    _record("pin-taxonomy", "HELD", "1700/1700/0 sorted")


def _import():
    try:
        from gov import runtime_posture as rp
    except ImportError:
        return None
    return rp


def _fixture(rp):
    """Build a valid posture record with 8-byte nonce and full slots."""
    seed = secrets.token_bytes(32)
    from gov import ed25519 as _ed
    pub = _ed.publickey(seed).hex()
    submods = {
        "sandbox": {"digest": "ab" * 32},
        "toolpolicy": {"digest": "cd" * 32},
        "keyset": {"digest": "ef" * 32},
    }
    endorsements = {
        "software_id": {"log_id": "log-1", "log_index": 3,
                        "expected_digest": "01" * 32, "source_id": "auditor"},
        "config_digest": {"log_id": "log-1", "log_index": 4,
                          "expected_digest": "02" * 32,
                          "source_id": "auditor"},
        "submods": {"log_id": "log-1", "log_index": 5,
                    "expected_digest": "03" * 32, "source_id": "auditor"},
    }
    rec = rp.issue_posture(operator_seed=seed, operator_keyid="op-1",
                           eat_nonce=secrets.token_bytes(8),
                           submods=submods,
                           software_id="sasanam-agent/1.0",
                           config_digest="aa" * 32,
                           endorsements=endorsements)
    return rp, seed, pub, rec


def p_module_present():
    rp = _import()
    if rp is None:
        return _record("eat-module-present", "BREAK",
                       "gov/runtime_posture.py absent on base")
    _record("eat-module-present", "HELD", "module importable")


def p_nonce_minimum():
    rp = _import()
    if rp is None:
        return _record("eat-nonce-minimum", "BREAK",
                       "module absent -- nonce floor unproven")
    seed = secrets.token_bytes(32)
    for bad in (b"", b"\x00" * 4, b"\x01" * 7):
        try:
            rp.issue_posture(
                operator_seed=seed, operator_keyid="op-1",
                eat_nonce=bad,
                submods={"sandbox": {"digest": "ab" * 32}},
                software_id="s", config_digest="aa" * 32,
                endorsements={
                    "software_id": {"log_id": "l", "log_index": 0,
                                    "expected_digest": "01" * 32,
                                    "source_id": "a"},
                    "config_digest": {"log_id": "l", "log_index": 0,
                                      "expected_digest": "01" * 32,
                                      "source_id": "a"},
                    "submods": {"log_id": "l", "log_index": 0,
                                "expected_digest": "01" * 32,
                                "source_id": "a"}})
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", type(e).__name__)
            if "nonce" not in code:
                return _record("eat-nonce-minimum", "BREAK",
                               "short nonce refused uncoded: %s" % (code,))
            continue
        return _record("eat-nonce-minimum", "BREAK",
                       "issue_posture accepted a %d-byte nonce "
                       "(RFC 9711 requires >= 64 bits)" % len(bad))
    _record("eat-nonce-minimum", "HELD",
            "nonces below 64 bits refused with coded refusal")


def p_forged_signature():
    rp = _import()
    if rp is None:
        return _record("eat-forged-signature", "BREAK",
                       "module absent -- signature check unproven")
    rp, seed, pub, rec = _fixture(rp)
    evil = json.loads(json.dumps(rec))
    evil["signature"] = "00" * 64
    try:
        rp.verify_posture(evil, pub,
                          expected_nonce=bytes.fromhex(
                              rec["payload"]["eat_nonce"]))
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if "signature" not in code:
            return _record("eat-forged-signature", "BREAK",
                           "forged signature refused uncoded: %s" % (code,))
        return _record("eat-forged-signature", "HELD",
                       "forged signature refused: %s" % (code,))
    _record("eat-forged-signature", "BREAK",
            "verify_posture accepted a forged signature")


def p_submod_substitution():
    rp = _import()
    if rp is None:
        return _record("eat-submod-substitution", "BREAK",
                       "module absent -- submod binding unproven")
    rp, seed, pub, rec = _fixture(rp)
    evil = json.loads(json.dumps(rec))
    evil["payload"]["submods"]["sandbox"]["digest"] = "ff" * 32
    try:
        rp.verify_posture(evil, pub,
                          expected_nonce=bytes.fromhex(
                              rec["payload"]["eat_nonce"]))
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        return _record("eat-submod-substitution", "HELD",
                       "submod substitution detected: %s" % (code,))
    _record("eat-submod-substitution", "BREAK",
            "swapped sandbox submod digest verified -- anti-substitution "
            "nesting broken")


def p_endorsement_slot_required():
    rp = _import()
    if rp is None:
        return _record("eat-endorsement-slot", "BREAK",
                       "module absent -- endorsement rule unproven")
    seed = secrets.token_bytes(32)
    endorsements = {
        "software_id": {"log_id": "l", "log_index": 0,
                        "expected_digest": "01" * 32, "source_id": "a"},
        "config_digest": {"log_id": "l", "log_index": 0,
                          "expected_digest": "01" * 32, "source_id": "a"},
        # "submods" slot deliberately missing
    }
    try:
        rp.issue_posture(
            operator_seed=seed, operator_keyid="op-1",
            eat_nonce=secrets.token_bytes(8),
            submods={"sandbox": {"digest": "ab" * 32}},
            software_id="s", config_digest="aa" * 32,
            endorsements=endorsements)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if "endorsement" not in code:
            return _record("eat-endorsement-slot", "BREAK",
                           "missing slot refused uncoded: %s" % (code,))
        return _record("eat-endorsement-slot", "HELD",
                       "missing endorsement slot refused: %s" % (code,))
    _record("eat-endorsement-slot", "BREAK",
            "issue_posture minted a record without the submods "
            "endorsement slot")


def p_nonce_binding_replay():
    rp = _import()
    if rp is None:
        return _record("eat-nonce-binding", "BREAK",
                       "module absent -- replay binding unproven")
    rp, seed, pub, rec = _fixture(rp)
    nonce = bytes.fromhex(rec["payload"]["eat_nonce"])
    try:
        rp.verify_posture(rec, pub, expected_nonce=secrets.token_bytes(8))
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if "nonce" not in code:
            return _record("eat-nonce-binding", "BREAK",
                           "wrong nonce refused uncoded: %s" % (code,))
    else:
        return _record("eat-nonce-binding", "BREAK",
                       "record verified against a different nonce -- "
                       "replay possible")
    # Right nonce must verify.
    try:
        rp.verify_posture(rec, pub, expected_nonce=nonce)
    except Exception as e:  # noqa: BLE001
        return _record("eat-nonce-binding", "BREAK",
                       "valid record refused with its own nonce: %r" % (e,))
    _record("eat-nonce-binding", "HELD",
            "nonce bound to the appraisal request; mismatch refused")


def p_unsigned_refused():
    rp = _import()
    if rp is None:
        return _record("eat-unsigned-refused", "BREAK",
                       "module absent -- unsigned handling unproven")
    fake = {"format": "sasanam-runtime-posture/1",
            "payload": {"software_id": "x"}}
    try:
        rp.verify_posture(fake, "00" * 32)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        return _record("eat-unsigned-refused", "HELD",
                       "unsigned/malformed record refused: %s" % (code,))
    _record("eat-unsigned-refused", "BREAK",
            "verify_posture accepted an unsigned record")


def p_trust_vector_seam():
    rp = _import()
    if rp is None:
        return _record("eat-trustvec-seam", "BREAK",
                       "module absent -- appraisal seam unproven")
    from gov import trust_vector as tv
    rp, seed, pub, rec = _fixture(rp)
    seam = rp.as_appraisal_evidence(rec, producer_id="operator")
    if not (isinstance(seam, tuple) and len(seam) == 3):
        return _record("eat-trustvec-seam", "BREAK",
                       "as_appraisal_evidence must return "
                       "(claim_digest, scheme_id, endorsements)")
    claim_digest, scheme_id, endorsements = seam
    if scheme_id not in tv.registered_schemes():
        return _record("eat-trustvec-seam", "BREAK",
                       "scheme %r not registered with trust_vector"
                       % (scheme_id,))
    if not (isinstance(claim_digest, str) and len(claim_digest) == 64):
        return _record("eat-trustvec-seam", "BREAK",
                       "claim_digest must be a 64-hex digest")
    _record("eat-trustvec-seam", "HELD",
            "narrow (claim_digest, scheme_id, endorsements) seam live; "
            "scheme %r registered" % (scheme_id,))


def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        "evals/w287_tsa_probes.py",
        "evals/w285_tessera_probes.py",
    ]
    for rel in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w288-green-")
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
    p_nonce_minimum()
    p_forged_signature()
    p_submod_substitution()
    p_endorsement_slot_required()
    p_nonce_binding_replay()
    p_unsigned_refused()
    p_trust_vector_seam()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note))
    print("w288_eat: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
