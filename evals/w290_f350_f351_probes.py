"""Wave-290 closure battery: F350 (posture producer binding at verify) +
F351 (coded refusals at wave-288 public seams).

Base: wave-289 push eb08e95ae9eb6862d689f9eede5489d0177a5ceb
(verified via git rev-parse HEAD before work).

F350: verify_posture passed producer_id=None into _check_endorsements,
so endorsement independence was issuance-only; a hand-built
operator-signed self-endorsed record verified cleanly, and the
producer identity was not bound in the signed payload. Fix: the
payload binds producer_id at issuance, and verify_posture enforces
independence against the BOUND producer on the verify path.

F351: four uncoded escapes (bytes(str) TypeError in bind_receipt;
AttributeError on list endorsements and non-dict payload in
as_appraisal_evidence; TypeError on non-JSON submod values;
TypeError from hmac.compare_digest on a non-string pin digest).
Fix: each refuses LOUD with an existing coded decision code.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g290-f350-f351 && TMPDIR=/var/tmp/g290-f350-f351 \\
    ~/workspace/.gov-venv/bin/python evals/w290_f350_f351_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g290-f350-f351-2 \\
    ~/workspace/.gov-venv/bin/python evals/w290_f350_f351_probes.py
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
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-290 lane 3: no new decision codes (all F350/F351 refusals reuse
# existing coded refusals) -- pin unchanged at 1706 (merge composition:
# the rebuild lane adds 4 provenance-rebuild-* codes, so the composed
# tree pins at 1710).
TAXONOMY_PIN = 1812  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)

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
    _record("pin-taxonomy", "HELD", "1812/1812/0 sorted")


# ---------------------------------------------------------------------------
# Fixtures (mirror evals/w289_redteam_probes.py)
# ---------------------------------------------------------------------------

def _posture_parts(producer_id="operator", slot_source="log-op"):
    from gov import runtime_posture as rp
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    slot = {"log_id": "L", "log_index": 0, "expected_digest": "ef" * 32,
            "source_id": slot_source}
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
    d = tempfile.mkdtemp(prefix="w290-rt-")
    seed = secrets.token_bytes(32)
    log = ea.TransparencyLog(d, origin="w290origin", signer_keyid="op1",
                             signer_seed=seed)
    anchored = ea.anchor(log, secrets.token_bytes(32).hex())
    return anchored, seed


def _admission_policy(**kw):
    from gov import evidence_admission as adm
    doc = {"format": "admission-policy/1", "policy_id": "p1",
           "scopes": [{"scope": "provenance", "level": "strict"}]}
    doc.update(kw)
    return adm.compile_policy(doc)


def _hand_record(producer_id=None, slot_source="mallory"):
    """Operator-signed record with attacker-chosen payload contents.

    producer_id=None means the payload carries no producer identity
    (the pre-F350-fix shape).
    """
    from gov import runtime_posture as rp
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    slot = {"log_id": "L", "log_index": 0, "expected_digest": "ef" * 32,
            "source_id": slot_source}
    protected = {"alg": "EdDSA", "kid": "op1",
                 "posture_format": rp.POSTURE_FORMAT}
    payload = {"v": 1, "eat_nonce": secrets.token_bytes(16).hex(),
               "submods": {"sbx": {"digest": "ab" * 32}},
               "software_id": "agent/1.0", "config_digest": "cd" * 32,
               "endorsements": {c: dict(slot) for c in
                                ("software_id", "config_digest", "submods")}}
    if producer_id is not None:
        payload["producer_id"] = producer_id
    sig = ed25519.sign(bytes(seed),
                       rp._sig_structure(protected, payload)).hex()
    record = {"posture_format": rp.POSTURE_FORMAT, "protected": protected,
              "payload": payload, "signature": sig}
    return record, pub


# ---------------------------------------------------------------------------
# F350: producer binding at verify
# ---------------------------------------------------------------------------

def p_f350_self_endorsed_no_producer():
    """Hand-built operator-signed record with NO producer identity and
    self-sourced endorsement slots must refuse coded."""
    from gov import runtime_posture as rp
    record, pub = _hand_record(producer_id=None, slot_source="mallory")
    try:
        rp.verify_posture(record, pub)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f350-no-producer", "BREAK",
                           "refused uncoded (%s)" % type(e).__name__)
        return _record("f350-no-producer", "HELD",
                       "refused coded: %s" % code)
    _record("f350-no-producer", "BREAK",
            "operator-signed producer-less record verified cleanly")


def p_f350_verify_enforces_independence():
    """Hand-built record WITH a bound producer_id but self-sourced
    endorsement slots must refuse posture-endorsement-not-independent
    on the VERIFY path."""
    from gov import runtime_posture as rp
    record, pub = _hand_record(producer_id="mallory", slot_source="mallory")
    try:
        rp.verify_posture(record, pub)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code != "posture-endorsement-not-independent":
            return _record("f350-verify-independence", "BREAK",
                           "wrong refusal: %r" % (code,))
        return _record("f350-verify-independence", "HELD",
                       "verify path enforces independence: %s" % code)
    _record("f350-verify-independence", "BREAK",
            "operator-signed self-endorsed record verified cleanly")


def p_f350_tampered_producer_refused():
    """Swapping the bound producer_id breaks the signature (it is part
    of the signed payload)."""
    from gov import runtime_posture as rp
    rec, _seed, pub = _posture_parts(producer_id="agent-1",
                                     slot_source="log-op")
    import json
    evil = json.loads(json.dumps(rec))
    evil["payload"]["producer_id"] = "mallory"
    try:
        rp.verify_posture(evil, pub)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code != "posture-signature-invalid":
            return _record("f350-tampered-producer", "BREAK",
                           "wrong refusal: %r" % (code,))
        return _record("f350-tampered-producer", "HELD",
                       "producer substitution breaks the signature: %s"
                       % code)
    _record("f350-tampered-producer", "BREAK",
            "producer_id substitution accepted")


def p_f350_issue_refuses_self_source():
    """Positive control: the module's own issuance still refuses
    self-sourced endorsements."""
    from gov import runtime_posture as rp
    try:
        _posture_parts(producer_id="mallory", slot_source="mallory")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "posture-endorsement-not-independent":
            return _record("f350-issue-refuses", "HELD",
                           "issuance refuses self-sourced endorsements")
        return _record("f350-issue-refuses", "BREAK",
                       "wrong code: %r" % getattr(e, "code", None))
    _record("f350-issue-refuses", "BREAK",
            "issuance accepted self-sourced endorsements")


def p_f350_honest_roundtrip():
    """Honest record (independent endorsements) verifies, with and
    without expected_nonce binding."""
    from gov import runtime_posture as rp
    rec, _seed, pub = _posture_parts(producer_id="agent-1",
                                     slot_source="log-op")
    nonce = bytes.fromhex(rec["payload"]["eat_nonce"])
    try:
        payload = rp.verify_posture(rec, pub, expected_nonce=nonce)
    except Exception as e:  # noqa: BLE001
        return _record("f350-honest-roundtrip", "BREAK",
                       "honest record refused: %r" % (e,))
    if payload.get("producer_id") != "agent-1":
        return _record("f350-honest-roundtrip", "BREAK",
                       "verified payload lost the bound producer_id")
    _record("f350-honest-roundtrip", "HELD",
            "honest record verifies; bound producer_id surfaced")


def p_f350_trustvec_seam():
    """The trust-vector narrow seam stays live (scheme registered,
    claim_digest is a digest)."""
    from gov import runtime_posture as rp
    from gov import trust_vector as tv
    rec, _seed, _pub = _posture_parts(producer_id="agent-1",
                                      slot_source="log-op")
    seam = rp.as_appraisal_evidence(rec, producer_id="agent-1")
    if not (isinstance(seam, tuple) and len(seam) == 3):
        return _record("f350-trustvec-seam", "BREAK",
                       "seam must return (claim_digest, scheme_id, "
                       "endorsements)")
    claim_digest, scheme_id, endorsements = seam
    if scheme_id not in tv.registered_schemes():
        return _record("f350-trustvec-seam", "BREAK",
                       "scheme %r not registered" % (scheme_id,))
    if not (isinstance(claim_digest, str) and len(claim_digest) == 64):
        return _record("f350-trustvec-seam", "BREAK",
                       "claim_digest must be a 64-hex digest")
    _record("f350-trustvec-seam", "HELD",
            "narrow seam live; scheme %r registered" % (scheme_id,))


# ---------------------------------------------------------------------------
# F351: coded refusals at wave-288 public seams
# ---------------------------------------------------------------------------

def p_f351a_receipt_str_seed():
    """bind_receipt with a str operator_seed: bytes(str) used to raise a
    raw TypeError. Must refuse coded inclusion-receipt-malformed."""
    from gov import evidence_receipt as er
    anchored, _seed = _anchor_parts()
    try:
        er.bind_receipt(anchored, "x" * 32)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f351a-str-seed", "BREAK",
                           "str operator_seed escaped uncoded (%s)"
                           % type(e).__name__)
        return _record("f351a-str-seed", "HELD",
                       "refused coded: %s" % code)
    _record("f351a-str-seed", "BREAK", "str seed was accepted")


def p_f351b_seam_list_endorsements():
    """as_appraisal_evidence with list endorsements used to raise a raw
    AttributeError. Must refuse coded."""
    from gov import runtime_posture as rp
    rec, _s, _p = _posture_parts()
    rec["payload"]["endorsements"] = ["not", "a", "dict"]
    try:
        rp.as_appraisal_evidence(rec, "operator")
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f351b-list-endorse", "BREAK",
                           "list endorsements escaped uncoded (%s)"
                           % type(e).__name__)
        return _record("f351b-list-endorse", "HELD",
                       "refused coded: %s" % code)
    _record("f351b-list-endorse", "BREAK", "list endorsements accepted")


def p_f351c_seam_nonjson():
    """as_appraisal_evidence with a set in submods used to raise a raw
    TypeError. Must refuse coded."""
    from gov import runtime_posture as rp
    rec, _s, _p = _posture_parts()
    rec["payload"]["submods"] = {"sbx": {"digest": set([1, 2, 3])}}
    try:
        rp.as_appraisal_evidence(rec, "operator")
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f351c-nonjson", "BREAK",
                           "non-JSON submods escaped uncoded (%s)"
                           % type(e).__name__)
        return _record("f351c-nonjson", "HELD",
                       "refused coded: %s" % code)
    _record("f351c-nonjson", "BREAK", "non-JSON submods accepted")


def p_f351d_nonstring_pin_digest():
    """admit() with a non-string pinned digest used to raise a raw
    TypeError in hmac.compare_digest. Must refuse coded."""
    from gov import evidence_admission as adm
    pol = _admission_policy()
    ev = {"kind": "provenance", "artifact_digest": "ab" * 32}
    outcomes = {c: True for c in adm.CHECKS}
    try:
        adm.admit(ev, pol, outcomes, pins={"p1": 12345})
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f351d-pin-digest", "BREAK",
                           "non-string pin digest escaped uncoded (%s)"
                           % type(e).__name__)
        return _record("f351d-pin-digest", "HELD",
                       "refused coded: %s" % code)
    _record("f351d-pin-digest", "BREAK", "non-string pin digest accepted")


def p_f351e_payload_not_dict():
    """as_appraisal_evidence with a non-dict payload used to raise a raw
    AttributeError. Must refuse coded (same class as f351b)."""
    from gov import runtime_posture as rp
    rec, _s, _p = _posture_parts()
    rec["payload"] = ["not", "a", "dict"]
    try:
        rp.as_appraisal_evidence(rec, "operator")
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f351e-payload-not-dict", "BREAK",
                           "non-dict payload escaped uncoded (%s)"
                           % type(e).__name__)
        return _record("f351e-payload-not-dict", "HELD",
                       "refused coded: %s" % code)
    _record("f351e-payload-not-dict", "BREAK", "non-dict payload accepted")


def p_f351f_slot_missing_source():
    """as_appraisal_evidence with a slot missing source_id used to raise
    a raw KeyError. Must refuse coded."""
    from gov import runtime_posture as rp
    rec, _s, _p = _posture_parts()
    del rec["payload"]["endorsements"]["software_id"]["source_id"]
    try:
        rp.as_appraisal_evidence(rec, "operator")
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f351f-slot-no-source", "BREAK",
                           "missing source_id escaped uncoded (%s)"
                           % type(e).__name__)
        return _record("f351f-slot-no-source", "HELD",
                       "refused coded: %s" % code)
    _record("f351f-slot-no-source", "BREAK",
            "slot without source_id accepted")


def p_f351g_cosign_str_seed():
    """bind_receipt with a witness cosign seed given as str used to raise
    a raw TypeError in _cosign. Must refuse coded."""
    from gov import evidence_receipt as er
    from gov import evidence_anchor as ea
    from gov import ed25519
    from gov import signing
    anchored, seed = _anchor_parts()
    wseed = ed25519.generate_seed()
    wpub = ed25519.publickey(bytes(wseed))
    kid = signing.ed25519_key_id(wpub)
    policy = ea.WitnessPolicy(policy_id="wp-1", witnesses={kid: wpub.hex()},
                              quorum=1)
    try:
        er.bind_receipt(anchored, seed, witness_policy=policy,
                        witness_seeds={kid: "x" * 32})
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f351g-cosign-str-seed", "BREAK",
                           "str witness seed escaped uncoded (%s)"
                           % type(e).__name__)
        return _record("f351g-cosign-str-seed", "HELD",
                       "refused coded: %s" % code)
    _record("f351g-cosign-str-seed", "BREAK", "str witness seed accepted")


# ---------------------------------------------------------------------------
# Depth-1 green checks (no recursive nesting): adjacent batteries must stay
# at their expected post-fix states. Wave-288 lesson: green checks are
# depth-1 -- the child runs with GOV_SKIP_GREEN=1.
# ---------------------------------------------------------------------------

_GREEN_CHECKS = [
    # (battery, expected_breaks, label)
    # Merge composition (wave-290): F346-F351 ALL CLOSED on the composed
    # tree (lanes 1+2+3), so w289_redteam runs 0 BREAK here.
    ("evals/w289_redteam_probes.py", 0, "w289_redteam"),
    ("evals/w288_eat_probes.py", 0, "w288_eat"),
    ("evals/w288_admission_probes.py", 0, "w288_admission"),
    ("evals/w285_tessera_probes.py", 0, "w285_tessera"),
    ("evals/w287_ear_probes.py", 0, "w287_ear"),
]


def _green_checks():
    if SKIP_GREEN:
        _record("green-checks", "HELD",
                "depth-1 green checks skipped (GOV_SKIP_GREEN=1)")
        return
    for rel, expected_breaks, label in _GREEN_CHECKS:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w290-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=900,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record("green-" + label, "ERROR",
                    "subprocess failed: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        # Wave-286 lesson: take the LAST "N BREAK" match (the footer).
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak == expected_breaks:
            _record("green-" + label, "HELD",
                    "%s: %d BREAK as expected" % (rel, nbreak))
        else:
            _record("green-" + label, "BREAK",
                    "%s: %d BREAK, expected %d"
                    % (rel, nbreak, expected_breaks))


def main():
    p_taxonomy_pin()
    p_f350_self_endorsed_no_producer()
    p_f350_verify_enforces_independence()
    p_f350_tampered_producer_refused()
    p_f350_issue_refuses_self_source()
    p_f350_honest_roundtrip()
    p_f350_trustvec_seam()
    p_f351a_receipt_str_seed()
    p_f351b_seam_list_endorsements()
    p_f351c_seam_nonjson()
    p_f351d_nonstring_pin_digest()
    p_f351e_payload_not_dict()
    p_f351f_slot_missing_source()
    p_f351g_cosign_str_seed()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note))
    print("w290_f350_f351: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
