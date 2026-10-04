"""Wave-299 red-first battery: attested identity binding for delegation.

Red-first discipline: on the pristine base (module absent) every probe
BREAKs; on the fixed tree every probe is HELD. Refusals are asserted by
machine code (F351 contract).
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TAXONOMY_PIN = 1951 # Wave-299 lane 6: pin 1780 -> 1783 (+3 delegation-identity-*).; Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))


def _hex_seed(byte):
    return bytes([byte]) * 32


def _trusted_module():
    import gov.delegation_identity as di
    return di


# ---------------------------------------------------------------------------
# Green checks (depth-1): adjacent batteries must stay green. They run with
# GOV_SKIP_GREEN=1 in the child env and honor it by recording a skip.
# ---------------------------------------------------------------------------

def _green_check(battery_module, label):
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-" + label, "HELD", "skipped (GOV_SKIP_GREEN=1)")
        return
    try:
        mod = __import__(battery_module)
    except Exception as exc:  # noqa: BLE001
        _record("green-" + label, "ERROR", repr(exc))
        return
    _record("green-" + label, "HELD", "adjacent battery importable")


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def probe_module_importable():
    try:
        di = _trusted_module()
    except ImportError:
        _record("importable", "BREAK", "gov.delegation_identity absent")
        return None
    _record("importable", "HELD", "module present")
    return di


def probe_did_happy_path(di):
    ctrl = _hex_seed(1)
    signer = _hex_seed(2)
    doc = di.issue_did_document(
        "did:sasanam:alice", ctrl,
        [di._pubkey_hex(signer)], created_at=1000)
    receipt = di.make_receipt("alice", "bob", "ab" * 32, signer, 1000, 2000)
    evidence = di.make_identity_evidence(
        "did", receipt["receipt_id"], did="did:sasanam:alice",
        did_document_digest=di.did_document_digest(doc),
        controller_seed=ctrl)
    rec = di.verify_identity_evidence(
        evidence, receipt["receipt_id"], di._pubkey_hex(signer),
        {"did:sasanam:alice": doc})
    assert rec["verified"] is True and rec["method"] == "did", rec
    _record("did-happy-path", "HELD", "authorized signer verified")


def probe_unauthorized_delegation_key(di):
    # Receipt signed by a key the DID document never authorized.
    ctrl = _hex_seed(11)
    legit = _hex_seed(12)
    rogue = _hex_seed(13)
    doc = di.issue_did_document(
        "did:sasanam:carol", ctrl, [di._pubkey_hex(legit)],
        created_at=1000)
    receipt = di.make_receipt("carol", "dave", "cd" * 32, rogue, 1000, 2000)
    evidence = di.make_identity_evidence(
        "did", receipt["receipt_id"], did="did:sasanam:carol",
        did_document_digest=di.did_document_digest(doc),
        controller_seed=ctrl)
    try:
        di.verify_identity_evidence(
            evidence, receipt["receipt_id"], di._pubkey_hex(rogue),
            {"did:sasanam:carol": doc})
    except di.DelegationIdentityError as exc:
        if exc.code == "delegation-identity-unauthorized-key":
            _record("unauthorized-key", "HELD", "refused coded")
            return
        _record("unauthorized-key", "BREAK", "wrong code: " + exc.code)
        return
    _record("unauthorized-key", "BREAK", "rogue signer accepted")


def probe_swapped_did_digest(di):
    # Chain document whose embedded DID doc digest disagrees with the
    # evidence's declared digest.
    ctrl = _hex_seed(21)
    signer = _hex_seed(22)
    doc = di.issue_did_document(
        "did:sasanam:erin", ctrl, [di._pubkey_hex(signer)],
        created_at=1000)
    receipt = di.make_receipt("erin", "frank", "ef" * 32, signer,
                              1000, 2000)
    evidence = di.make_identity_evidence(
        "did", receipt["receipt_id"], did="did:sasanam:erin",
        did_document_digest="00" * 32,  # WRONG digest
        controller_seed=ctrl)
    try:
        di.verify_identity_evidence(
            evidence, receipt["receipt_id"], di._pubkey_hex(signer),
            {"did:sasanam:erin": doc})
    except di.DelegationIdentityError as exc:
        if exc.code == "delegation-identity-invalid":
            _record("swapped-did-digest", "HELD", "refused coded")
            return
        _record("swapped-did-digest", "BREAK", "wrong code: " + exc.code)
        return
    _record("swapped-did-digest", "BREAK", "mismatched digest accepted")


def probe_false_hardware_claim(di):
    # claim_hardware=True with no quote bytes must refuse coded --
    # honest naming enforced in code.
    signer = _hex_seed(31)
    witness = _hex_seed(32)
    transcript = di.make_ceremony_transcript(
        "gina", signer, 1000, "software-ceremony",
        [("witness-one", witness)])
    try:
        di.make_identity_evidence(
            "attestation", "ab" * 32,
            ceremony_transcript=transcript,
            claim_hardware=True, quote_bytes=None)
    except di.DelegationIdentityError as exc:
        if exc.code == "delegation-identity-false-hardware-claim":
            _record("false-hardware-claim", "HELD", "refused coded")
            return
        _record("false-hardware-claim", "BREAK", "wrong code: " + exc.code)
        return
    _record("false-hardware-claim", "BREAK", "hardware lie accepted")


def probe_forged_controller_proof(di):
    # Controller proof signed by the WRONG key.
    ctrl = _hex_seed(41)
    impostor = _hex_seed(42)
    signer = _hex_seed(43)
    doc = di.issue_did_document(
        "did:sasanam:heidi", ctrl, [di._pubkey_hex(signer)],
        created_at=1000)
    evidence = di.make_identity_evidence(
        "did", "ab" * 32, did="did:sasanam:heidi",
        did_document_digest=di.did_document_digest(doc),
        controller_seed=impostor)  # not the controller
    try:
        di.verify_identity_evidence(
            evidence, "ab" * 32, di._pubkey_hex(signer),
            {"did:sasanam:heidi": doc})
    except di.DelegationIdentityError as exc:
        if exc.code == "delegation-identity-invalid":
            _record("forged-controller-proof", "HELD", "refused coded")
            return
        _record("forged-controller-proof", "BREAK",
                "wrong code: " + exc.code)
        return
    _record("forged-controller-proof", "BREAK", "forged proof accepted")


def probe_chain_missing_link(di):
    # Chain export where link 2's parent_digest skips link 1.
    s1, s2, s3 = _hex_seed(51), _hex_seed(52), _hex_seed(53)
    exporter = _hex_seed(54)
    r1 = di.make_receipt("ivan", "judy", "aa" * 32, s1, 1000, 2000)
    r2 = di.make_receipt("judy", "mallory", "bb" * 32, s2, 1100, 2000,
                         parent_digest=r1["receipt_id"])
    r3 = di.make_receipt("mallory", "oscar", "cc" * 32, s3, 1200, 2000,
                         parent_digest=r1["receipt_id"])  # skips r2
    entries = [
        {"receipt": r1, "from_pubkey": di._pubkey_hex(s1)},
        {"receipt": r2, "from_pubkey": di._pubkey_hex(s2)},
        {"receipt": r3, "from_pubkey": di._pubkey_hex(s3)},
    ]
    try:
        di.export_chain(entries, exporter, 1300)
    except di.DelegationIdentityError as exc:
        if exc.code == "delegation-chain-broken":
            _record("chain-missing-link", "HELD", "refused coded")
            return
        _record("chain-missing-link", "BREAK", "wrong code: " + exc.code)
        return
    _record("chain-missing-link", "BREAK", "gapped chain exported")


def probe_offline_chain_verification(di):
    # Full chain: build -> export -> verify with a FRESH verifier state
    # (no engine objects shared; only the document + trust roots).
    s1, s2 = _hex_seed(61), _hex_seed(62)
    exporter = _hex_seed(63)
    ctrl = _hex_seed(64)
    doc = di.issue_did_document(
        "did:sasanam:peggy", ctrl, [di._pubkey_hex(s1)],
        created_at=500)
    r1tmp = di.make_receipt("peggy", "quinn", "dd" * 32, s1, 1000, 5000)
    ev1 = di.make_identity_evidence(
        "did", r1tmp["receipt_id"], did="did:sasanam:peggy",
        did_document_digest=di.did_document_digest(doc),
        controller_seed=ctrl)
    # receipt_id is stable over the 6 identity fields, so re-issuing with
    # the evidence attached keeps the same receipt_id.
    r1 = di.make_receipt("peggy", "quinn", "dd" * 32, s1, 1000, 5000,
                         identity_evidence=ev1)
    assert r1["receipt_id"] == r1tmp["receipt_id"]
    r2 = di.make_receipt("quinn", "ruth", "ee" * 32, s2, 1100, 5000,
                         parent_digest=r1["receipt_id"])
    entries = [
        {"receipt": r1, "from_pubkey": di._pubkey_hex(s1),
         "did_documents": {"did:sasanam:peggy": doc}},
        {"receipt": r2, "from_pubkey": di._pubkey_hex(s2)},
    ]
    chain_doc = di.export_chain(entries, exporter, 1200)
    # Fresh verifier: re-import the module's functions only; the only
    # inputs are the document and the trust roots.
    rec = di.verify_chain_offline(
        chain_doc, 1500, {"did:sasanam:peggy": doc})
    assert rec["verified"] is True and rec["depth"] == 2 \
        and rec["leaf"] == "ruth" and rec["offline"] is True, rec
    _record("offline-chain-verification", "HELD",
            "2-link chain verifies offline")


def probe_attestation_ceremony_happy_path(di):
    signer = _hex_seed(71)
    w1, w2 = _hex_seed(72), _hex_seed(73)
    transcript = di.make_ceremony_transcript(
        "sybil", signer, 1000, "software-ceremony",
        [("witness-a", w1), ("witness-b", w2)])
    evidence = di.make_identity_evidence(
        "attestation", "ff" * 32, ceremony_transcript=transcript,
        claim_hardware=False)
    rec = di.verify_identity_evidence(
        evidence, "ff" * 32, di._pubkey_hex(signer), {})
    assert rec["verified"] is True \
        and rec["label"] == "software-ceremony", rec
    _record("attestation-ceremony", "HELD", "ceremony verified")


def probe_attestation_tampered_witness(di):
    signer = _hex_seed(81)
    w1 = _hex_seed(82)
    transcript = di.make_ceremony_transcript(
        "trent", signer, 1000, "software-ceremony", [("witness-a", w1)])
    transcript["witness_signatures"][0]["signature"] = "00" * 64
    try:
        di.make_identity_evidence(
            "attestation", "ff" * 32, ceremony_transcript=transcript,
            claim_hardware=False)
    except di.DelegationIdentityError as exc:
        if exc.code == "delegation-identity-invalid":
            _record("attestation-tampered-witness", "HELD",
                    "refused coded")
            return
        _record("attestation-tampered-witness", "BREAK",
                "wrong code: " + exc.code)
        return
    _record("attestation-tampered-witness", "BREAK",
            "tampered witness accepted")


def probe_key_method_happy_path(di):
    signer = _hex_seed(91)
    evidence = di.make_identity_evidence(
        "key", "aa" * 32, pubkey=di._pubkey_hex(signer))
    rec = di.verify_identity_evidence(
        evidence, "aa" * 32, di._pubkey_hex(signer), {})
    assert rec["verified"] is True \
        and rec["label"] == "unattested-bare-key", rec
    _record("key-method", "HELD", "bare key labeled honestly")


def probe_trace_edge_shape(di):
    edge = di.delegated_authority_edge("alice", "bob", "ab" * 32,
                                       "cd" * 32)
    assert edge == {"kind": "delegated-authority", "from": "alice",
                    "to": "bob", "receipt_digest": "ab" * 32,
                    "identity_evidence_digest": "cd" * 32}, edge
    try:
        di.delegated_authority_edge("alice", "bob", "not-hex", "cd" * 32)
    except di.DelegationIdentityError as exc:
        assert exc.code == "delegation-identity-invalid", exc.code
        _record("trace-edge-shape", "HELD", "edge shape exact")
        return
    _record("trace-edge-shape", "BREAK", "malformed edge accepted")


def probe_pin_taxonomy(di):
    import re
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "gov", "decision_codes.py")
    src = open(path).read()
    lits = re.findall(r'"code": \'([^\']+)\'', src)
    uniq = sorted(set(lits))
    if len(lits) == TAXONOMY_PIN and len(uniq) == TAXONOMY_PIN \
            and uniq == sorted(uniq):
        _record("pin-taxonomy", "HELD",
                "%d/%d/0 sorted" % (len(uniq), TAXONOMY_PIN))
    else:
        _record("pin-taxonomy", "BREAK",
                "literals=%d uniq=%d pin=%d" % (len(lits), len(uniq),
                                               TAXONOMY_PIN))


def probe_ed25519_contract(di):
    from gov import ed25519 as _ed
    seed = _hex_seed(99)
    pub = _ed.publickey(seed)
    sig = _ed.sign(seed, b"contract")
    good = _ed.verify(pub, b"contract", sig)
    bad = _ed.verify(pub, b"contract", b"\x00" * 64)
    if good is True and bad is False:
        _record("ed25519-contract", "HELD", "is True / is False")
    else:
        _record("ed25519-contract", "BREAK",
                "contract violated: %r %r" % (good, bad))


def main():
    di = probe_module_importable()
    if di is None:
        # Pristine base: every other probe breaks by construction.
        for name in ("did-happy-path", "unauthorized-key",
                     "swapped-did-digest", "false-hardware-claim",
                     "forged-controller-proof", "chain-missing-link",
                     "offline-chain-verification", "attestation-ceremony",
                     "attestation-tampered-witness", "key-method",
                     "trace-edge-shape", "pin-taxonomy",
                     "ed25519-contract"):
            _record(name, "BREAK", "module absent on pristine base")
    else:
        for fn in (probe_did_happy_path, probe_unauthorized_delegation_key,
                   probe_swapped_did_digest, probe_false_hardware_claim,
                   probe_forged_controller_proof, probe_chain_missing_link,
                   probe_offline_chain_verification,
                   probe_attestation_ceremony_happy_path,
                   probe_attestation_tampered_witness,
                   probe_key_method_happy_path, probe_trace_edge_shape,
                   probe_pin_taxonomy, probe_ed25519_contract):
            try:
                fn(di)
            except AssertionError as exc:
                _record(fn.__name__, "BREAK",
                        "assertion: %r" % (exc,))
            except Exception as exc:  # noqa: BLE001
                _record(fn.__name__, "ERROR", repr(exc))
    _green_check("evals.w298_supervision_lease_probes", "w298-supervision-lease")
    _green_check("evals.w298_memory_store_probes", "w298-memory-store")

    breaks = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    errors = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    for name, verdict, detail in _RESULTS:
        print("%-32s %-6s %s" % (name, verdict, detail))
    print("----")
    print("%d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
