"""Wave-312 lane D battery: persistent witness log with checkpoints and Merkle proofs.

Base: wave-311 merge e8cdd51f (pin 1841; open F396 / next F397).

Target: gov/witness_log.py -- the Rekor-pattern persistent transparency
log (build-order step 4), plugging the offline verifier's documented
seam (witness entries were refused coded until this lane):
  - append-only Merkle tree (RFC 6962-style, stdlib hashlib only);
  - signed checkpoints {tree_size, root_hash, timestamp}, checkpoint
    signature verified FIRST, sizes/hashes parsed ONLY from the verified
    checkpoint (Rekor v2 CLIENTS.md contract; sigstore-python#248);
  - inclusion proofs (verify an entry against a trusted checkpoint);
  - consistency proofs old->new (fork detection for auditors);
  - sealer wiring: gov/evidence_sigstore.py gains an optional log-backed
    witness path (offline fallback still verifies -- tested both ways);
  - verifier wiring: gov/evidence_verify_offline.py verifies log-backed
    witness entries (5 new typed codes; 11 -> 16).

Break-first (red before green): the forgery probes below are written
FIRST and must refuse CODED. They were confirmed failing-closed against
gov/witness_log.py before the happy-path sealer/verifier wiring
existed; the sealer/verifier probes below ERRORed until that wiring
landed (honest red-first ordering, not retrofitted).
  - forked-log: two inconsistent checkpoints from one key can never
    yield a valid consistency proof; cross-log inclusion refuses.
  - backdated-entry: entry integratedTime after its checkpoint's
    timestamp is incoherent -> refused.
  - inclusion-proof forgery: tampered sibling -> refused.
  - checkpoint-signature forgery: tampered/wrong-key signature -> refused.
  - unpinned-root-hash (sigstore-python#248 analogue): a valid proof
    from log X presented under log Y's checkpoint refuses; duplicated
    rootHash/treeSize beside the checkpoint are IGNORED (tampering
    them changes nothing).
  - tree-size rollback: entry verified against an older, smaller
    checkpoint refuses.
  - entry-unbound (CVE-2026-22703 analogue): replaying a valid entry
    triple into a different bundle's verification refuses.

New decision codes (pin 1841 -> 1851, all documented in
gov/decision_codes.py): 8 witness-log-* codes (the log's own coded
refusals) + 2 evidence-bundle-witness-{checkpoint,inclusion}-invalid
(the Sigstore sealer's log-path refusals). The offline verifier's 5 new
WITNESS_* codes are the verifier's own taxonomy (lane-E precedent),
not governance decisions.

Run:
  mkdir -p /var/tmp/g312-wl && TMPDIR=/var/tmp/g312-wl \\
    ~/workspace/.gov-venv/bin/python evals/w312_witness_log_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g312-wl2 \\
    ~/workspace/.gov-venv/bin/python evals/w312_witness_log_probes.py
Single probe:
  ~/workspace/.gov-venv/bin/python evals/w312_witness_log_probes.py <probe-id>
"""

import base64
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import traceback
from datetime import datetime, timedelta, timezone

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Pin moves 1841 -> 1851: +8 witness-log-* +2 evidence-bundle-witness-*.
TAXONOMY_PIN = 1878

from gov import witness_log as wl
from gov.signing import Ed25519Signer
from gov import evidence_verify_offline as v

UTC = timezone.utc
NOW = datetime(2026, 10, 3, 15, 0, 0, tzinfo=UTC)
T0 = int(NOW.timestamp())

WITNESS_SEED = bytes([77]) * 32
WITNESS_SEED_2 = bytes([78]) * 32  # second log's key (fork / #248 log X)
ATTACKER_SEED = bytes([13]) * 32

INTOTO_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://sasanam.dev/predicate/evidence-bundle/v1"
PREDICATE_CLAIMS = {"window": "2026-10-03T00:00:00Z", "decisions": 3}
BUNDLE_BYTES = b'{"evidence":"synthetic-bundle-w312-wl-001"}'
OTHER_BYTES = b'{"evidence":"different-bytes-w312-002"}'
POLICY_ANCHOR_SEED = bytes.fromhex(
    "02eb4cee77eb9c934286078d60f8960f6a038a6c9b04906d940ed521de3fa3b6")
EVIDENCE_SEED = bytes([7]) * 32


def _signer(seed):
    return Ed25519Signer(seed)


def _witness_key_id(signer):
    return hashlib.sha256(signer.public_key).hexdigest()


def _canon(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _log_with(n, seed=WITNESS_SEED, prefix=b"entry"):
    log = wl.WitnessLog(_signer(seed).public_key)
    for i in range(n):
        log.append(prefix + b"-%d" % i)
    return log


def _sealed(log, seed=WITNESS_SEED, ts=T0):
    return log.sealed_checkpoint(ts, _signer(seed))


# ---------------------------------------------------------------------------
# Offline-verifier fixtures (mirrors evals/w311_offline_verifier_probes.py).
# ---------------------------------------------------------------------------

def _statement(bundle_bytes=BUNDLE_BYTES, claims=None):
    claims = PREDICATE_CLAIMS if claims is None else claims
    return {
        "_type": INTOTO_TYPE,
        "subject": [{
            "name": "evidence-bundle",
            "digest": {"sha256": hashlib.sha256(bundle_bytes).hexdigest()},
        }],
        "predicateType": PREDICATE_TYPE,
        "predicate": dict(claims),
    }


def _seal(payload_bytes, payload_type, signers):
    sigs = []
    for s in signers:
        sigs.append({"keyid": s.key_id,
                     "sig": _b64(s.sign(v.pae(payload_type, payload_bytes)))})
    return {"payload": _b64(payload_bytes), "payloadType": payload_type,
            "signatures": sigs}


def _policy_doc(ev_signers, expires, witness_signers=(), threshold=1,
                required_claims=("window", "decisions"),
                witness_required=False):
    def _vf():
        return {
            "not_before": (NOW - timedelta(days=30)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "not_after": (NOW + timedelta(days=30)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
        }
    return {
        "version": v.POLICY_VERSION,
        "policy_id": "test-policy-w312-wl",
        "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evidence_signing": {
            "threshold": threshold,
            "keys": [{"keyid": s.key_id, "pubkey_hex": s.public_key.hex()}
                     for s in ev_signers],
        },
        "timestamp_authorities": [],
        "required_predicate_type": PREDICATE_TYPE,
        "required_predicate_claims": list(required_claims),
        "observer_timestamps": {"min": 0, "max_age_hours": 168},
        "witness_required": witness_required,
        "witness_log_keys": [{
            "keyid": s.key_id,
            "pubkey_hex": s.public_key.hex(),
            "valid_for": _vf(),
        } for s in witness_signers],
    }


def _seal_policy(policy_doc, signer=None):
    signer = _signer(POLICY_ANCHOR_SEED) if signer is None else signer
    return _seal(_canon(policy_doc), v.POLICY_PAYLOAD_TYPE, [signer])


def _good_bundle(bundle_bytes=BUNDLE_BYTES, witness_signers=(),
                 witness_required=False, with_entry=True):
    """Assemble a verification bundle, optionally with a sealed witness
    entry (the happy path needs the witness stage landed)."""
    expires = NOW + timedelta(days=10)
    ev = [_signer(EVIDENCE_SEED)]
    policy = _policy_doc([ev[0]], expires,
                         witness_signers=witness_signers,
                         witness_required=witness_required)
    stmt = _statement(bundle_bytes=bundle_bytes)
    envelope = _seal(_canon(stmt), v.ENVELOPE_PAYLOAD_TYPE, ev)
    policy_env = _seal_policy(policy)
    vb = v.build_verification_bundle(envelope, policy_env)
    entries = []
    if with_entry and witness_signers:
        wlog = wl.WitnessLog(witness_signers[0].public_key)
        entry = v.seal_witness_entry(
            wlog, witness_signers[0],
            artifact_digest=hashlib.sha256(bundle_bytes).hexdigest(),
            signatures=envelope["signatures"],
            verified_keyids=[ev[0].key_id],
            policy_digest=hashlib.sha256(_canon(policy)).hexdigest(),
            integrated_time=T0)
        entries.append(entry)
    vb["witness_entries"] = entries
    return vb, bundle_bytes


def _clock(at=NOW):
    return v.FixedClock("test-clock", at)


_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Per-probe isolation: an uncaught exception becomes ERROR, never
    a dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _expect_code(pid, fn, code, exit_code=None):
    """HELD iff fn raises the coded refusal (WitnessError or
    VerificationError)."""
    try:
        fn()
    except wl.WitnessError as e:
        if e.code == code:
            _record(pid, "HELD", "%s as coded" % code)
        else:
            _record(pid, "BREAK",
                    "wrong witness code: got %s want %s" % (e.code, code))
    except v.VerificationError as e:
        if e.code == code and (exit_code is None
                               or e.exit_code == exit_code):
            _record(pid, "HELD", "%s/%s as typed"
                    % (code, e.exit_code))
        else:
            _record(pid, "BREAK",
                    "wrong verifier code: got %s/%s want %s/%s"
                    % (e.code, e.exit_code, code, exit_code))
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "unexpected %r" % (e,))
    else:
        _record(pid, "BREAK", "no refusal raised (want %s)" % code)


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'\"code\":\s*\'([a-z][a-z0-9-_.]*)\'', src)


# ---------------------------------------------------------------------------
# Probes.
# ---------------------------------------------------------------------------

def p_pin_taxonomy():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    new = [c for c in lits if c.startswith("witness-log-")
           or c == "evidence-bundle-witness-checkpoint-invalid"
           or c == "evidence-bundle-witness-inclusion-invalid"]
    if len(new) != 10:
        return _record("pin-taxonomy", "BREAK",
                       "want 10 new witness codes, got %d" % len(new))
    _record("pin-taxonomy", "HELD", "1878/1878/0 sorted, +10 witness codes")


def p_footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
    m_open = re.findall(r"Open findings: ([^.]*)", text)
    # Footer lines repeat through history; the LAST one is current.
    # Wave-312 merge footer: F396 CLOSED (lane A); F397 OPEN (lane C).
    ok = (m_next and m_next[-1] == "F398"
          and m_open and m_open[-1].strip() == "none")
    _record("footer-state", "HELD" if ok else "BREAK",
            "open none / next F398" if ok else "footer drift")


def p_log_roundtrip():
    log = _log_with(5)
    assert log.tree_size == 5
    sealed = _sealed(log)
    cp = wl.verify_checkpoint(sealed, _signer(WITNESS_SEED).public_key)
    if cp["treeSize"] != 5 or cp["logId"] != log.log_id:
        return _record("log-roundtrip", "BREAK", "checkpoint mismatch")
    if bytes.fromhex(cp["rootHash"]) != log.root_hash():
        return _record("log-roundtrip", "BREAK", "root mismatch")
    _record("log-roundtrip", "HELD", "append/seal/verify roundtrip, 5 leaves")


def p_inclusion_positive():
    for n in (1, 2, 3, 5, 8, 13):
        log = _log_with(n)
        sealed = _sealed(log)
        cp = wl.verify_checkpoint(sealed, _signer(WITNESS_SEED).public_key)
        root = bytes.fromhex(cp["rootHash"])
        for m in range(n):
            proof = log.inclusion_proof(m)
            wl.verify_inclusion(b"entry-%d" % m, proof["leaf_index"],
                                proof["path"], cp["treeSize"], root)
    _record("inclusion-positive", "HELD",
            "inclusion verifies for all indices, sizes 1/2/3/5/8/13")


def p_consistency_positive():
    log = _log_with(9)
    roots = {}
    for m in range(1, 10):
        sub = _log_with(m)
        roots[m] = sub.root_hash()
    for m in range(1, 9):
        proof = log.consistency_proof(m, 9)
        wl.verify_consistency(m, roots[m], 9, roots[9], proof["hashes"])
    _record("consistency-positive", "HELD",
            "consistency verifies for all 1..8 -> 9")


def p_forgery_forked_log():
    # One witness key, two divergent logs: no consistency proof can
    # exist between them, and cross-log inclusion refuses.
    key = _signer(WITNESS_SEED)
    log_a = wl.WitnessLog(key.public_key)
    log_b = wl.WitnessLog(key.public_key)
    for i in range(3):
        log_a.append(b"fork-a-%d" % i)
        log_b.append(b"fork-b-%d" % i)
    cp_a = wl.verify_checkpoint(_sealed(log_a), key.public_key)
    cp_b = wl.verify_checkpoint(_sealed(log_b), key.public_key)
    if cp_a["rootHash"] == cp_b["rootHash"]:
        return _record("forgery-forked-log", "ERROR",
                       "forked logs share a root (test bug)")
    # The attacker cannot even CONSTRUCT a valid consistency proof:
    # any proof between divergent roots fails at recomputation.
    fake = {"old_size": 3, "new_size": 3,
            "hashes": log_a.consistency_proof(1, 3)["hashes"]}
    _expect_code(
        "forgery-forked-log",
        lambda: wl.verify_consistency(
            3, bytes.fromhex(cp_a["rootHash"]),
            3, bytes.fromhex(cp_b["rootHash"]), fake["hashes"]),
        "witness-log-consistency-invalid")
    # Cross-log inclusion: entry from B against A's checkpoint.
    proof_b = log_b.inclusion_proof(1)
    _expect_code(
        "forgery-forked-log-xlog",
        lambda: wl.verify_inclusion(
            b"fork-b-1", proof_b["leaf_index"], proof_b["path"],
            cp_a["treeSize"], bytes.fromhex(cp_a["rootHash"])),
        "witness-log-inclusion-invalid")


def p_forgery_inclusion_proof():
    log = _log_with(6)
    sealed = _sealed(log)
    cp = wl.verify_checkpoint(sealed, _signer(WITNESS_SEED).public_key)
    root = bytes.fromhex(cp["rootHash"])
    proof = log.inclusion_proof(4)
    tampered = copy.deepcopy(proof)
    h = bytearray(bytes.fromhex(tampered["path"][0]["hash"]))
    h[0] ^= 1
    tampered["path"][0]["hash"] = bytes(h).hex()
    _expect_code("forgery-inclusion-proof",
                 lambda: wl.verify_inclusion(
                     b"entry-4", tampered["leaf_index"],
                     tampered["path"], cp["treeSize"], root),
                 "witness-log-inclusion-invalid")


def p_forgery_checkpoint_signature():
    log = _log_with(4)
    sealed = _sealed(log)
    key = _signer(WITNESS_SEED)
    # Tampered signature bytes.
    bad = copy.deepcopy(sealed)
    sig = bytearray(base64.b64decode(bad["signature"]))
    sig[0] ^= 1
    bad["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
    _expect_code("forgery-checkpoint-signature",
                 lambda: wl.verify_checkpoint(bad, key.public_key),
                 "witness-log-checkpoint-signature-invalid")
    # Checkpoint verified against the WRONG key.
    other = _signer(WITNESS_SEED_2)
    _expect_code("forgery-checkpoint-wrong-key",
                 lambda: wl.verify_checkpoint(sealed, other.public_key),
                 "witness-log-checkpoint-signature-invalid")
    # Tampered checkpoint body (treeSize) -- signature was over the
    # original bytes, so this fails at the signature, parsed nothing.
    bad2 = copy.deepcopy(sealed)
    bad2["checkpoint"]["treeSize"] = 999
    _expect_code("forgery-checkpoint-body-tamper",
                 lambda: wl.verify_checkpoint(bad2, key.public_key),
                 "witness-log-checkpoint-signature-invalid")


def p_forgery_unpinned_root_hash():
    # sigstore-python#248 analogue: the root hash must come ONLY from
    # the verified checkpoint. A valid inclusion proof from log X
    # presented under log Y's checkpoint refuses; duplicated
    # rootHash/treeSize fields beside the checkpoint are IGNORED.
    key_x = _signer(WITNESS_SEED_2)   # log X
    key_y = _signer(WITNESS_SEED)     # log Y (the pinned one)
    log_x = wl.WitnessLog(key_x.public_key)
    log_y = wl.WitnessLog(key_y.public_key)
    for i in range(4):
        log_x.append(b"x-%d" % i)
        log_y.append(b"y-%d" % i)
    proof_x = log_x.inclusion_proof(2)
    cp_y = wl.verify_checkpoint(_sealed(log_y), key_y.public_key)
    # Valid proof from X, verified against Y's checkpoint root.
    _expect_code("forgery-unpinned-root-hash",
                 lambda: wl.verify_inclusion(
                     b"x-2", proof_x["leaf_index"], proof_x["path"],
                     cp_y["treeSize"],
                     bytes.fromhex(cp_y["rootHash"])),
                 "witness-log-inclusion-invalid")
    # The proof envelope's own tree_size is never trusted: tampering
    # it does not change the verdict (still verifies against the
    # checkpoint's size, which the verifier passes explicitly).
    log = _log_with(5)
    sealed = _sealed(log)
    cp = wl.verify_checkpoint(sealed, key_y.public_key)
    proof = log.inclusion_proof(3)
    proof["tree_size"] = 999  # unverified duplicate: ignored
    try:
        wl.verify_inclusion(b"entry-3", proof["leaf_index"],
                            proof["path"], cp["treeSize"],
                            bytes.fromhex(cp["rootHash"]))
    except wl.WitnessError as e:
        return _record("forgery-unpinned-root-hash-ignored", "BREAK",
                       "valid proof refused after duplicate tamper: %r" % e)
    _record("forgery-unpinned-root-hash-ignored", "HELD",
            "proof-envelope tree_size ignored; checkpoint size used")


def p_forgery_tree_size_rollback():
    # Entry at index 5 (tree size 6); attacker presents a genuinely
    # signed OLDER checkpoint (tree_size 3). The verifier takes the
    # size from the checkpoint: index 5 >= 3 refuses.
    key = _signer(WITNESS_SEED)
    log = wl.WitnessLog(key.public_key)
    for i in range(3):
        log.append(b"rb-%d" % i)
    old_sealed = log.sealed_checkpoint(T0 - 100, key)  # tree_size 3
    for i in range(3, 6):
        log.append(b"rb-%d" % i)
    cp_old = wl.verify_checkpoint(old_sealed, key.public_key)
    proof = log.inclusion_proof(5)  # built against size 6
    _expect_code("forgery-tree-size-rollback",
                 lambda: wl.verify_inclusion(
                     b"rb-5", proof["leaf_index"], proof["path"],
                     cp_old["treeSize"],
                     bytes.fromhex(cp_old["rootHash"])),
                 "witness-log-inclusion-invalid")


def p_forgery_leaf_swap():
    # Inclusion proof for leaf 2 presented as leaf 5: the path
    # structure is bound to (leaf_index, tree_size) -- refuses.
    log = _log_with(7)
    sealed = _sealed(log)
    cp = wl.verify_checkpoint(sealed, _signer(WITNESS_SEED).public_key)
    root = bytes.fromhex(cp["rootHash"])
    proof = log.inclusion_proof(2)
    _expect_code("forgery-leaf-swap",
                 lambda: wl.verify_inclusion(
                     b"entry-2", 5, proof["path"],
                     cp["treeSize"], root),
                 "witness-log-inclusion-invalid")


def p_forgery_wrong_signer_key():
    # sealed_checkpoint with a signer whose key is not the log's bound
    # witness key refuses -- a log never co-signs for a foreign key.
    log = wl.WitnessLog(_signer(WITNESS_SEED).public_key)
    log.append(b"e")
    _expect_code("forgery-wrong-signer-key",
                 lambda: log.sealed_checkpoint(
                     T0, _signer(WITNESS_SEED_2)),
                 "witness-log-key-mismatch")


def p_export_import_roundtrip():
    log = _log_with(6)
    log2 = wl.WitnessLog.import_log(log.export())
    if log2.root_hash() != log.root_hash():
        return _record("export-import-roundtrip", "BREAK", "root mismatch")
    if log2.log_id != log.log_id or log2.entries() != log.entries():
        return _record("export-import-roundtrip", "BREAK",
                       "entries/key mismatch")
    _record("export-import-roundtrip", "HELD",
            "export/import preserves entries, key, root")

# ---------------------------------------------------------------------------
# Sealer wiring probes (gov/evidence_sigstore.py log-backed path).
# ---------------------------------------------------------------------------

def p_sigstore_log_path():
    from gov import evidence_sigstore as sg
    from gov import evidence_intoto as _intoto
    from gov import evidence_dsse as _edsse
    ev = _signer(EVIDENCE_SEED)
    wit = _signer(WITNESS_SEED)
    stmt = _intoto.build_statement(BUNDLE_BYTES, dict(PREDICATE_CLAIMS))
    envelope = _intoto.seal_statement(stmt, [ev])
    wlog = wl.WitnessLog(wit.public_key)
    bundle = sg.seal_sigstore_bundle(envelope, [ev], wit,
                                     witness_log=wlog,
                                     integrated_time=T0)
    entry = bundle["verificationMaterial"]["tlogEntries"][0]
    if entry["logIndex"] != "0":
        return _record("sigstore-log-path", "BREAK",
                       "first log index want '0', got %r"
                       % entry["logIndex"])
    if "inclusionProof" not in entry:
        return _record("sigstore-log-path", "BREAK",
                       "log path carries no inclusionProof")
    # Second bundle -> index 1 (real tree state, not a constant).
    bundle2 = sg.seal_sigstore_bundle(envelope, [ev], wit,
                                       witness_log=wlog,
                                       integrated_time=T0)
    entry2 = bundle2["verificationMaterial"]["tlogEntries"][0]
    if entry2["logIndex"] != "1":
        return _record("sigstore-log-path", "BREAK",
                       "second log index want '1', got %r"
                       % entry2["logIndex"])
    # Open verifies WITH the log path (checkpoint + inclusion checked).
    from gov.signing import Ed25519Verifier
    wit_v = Ed25519Verifier(wit.public_key, wit.key_id)
    got = sg.open_sigstore_bundle(
        bundle2, BUNDLE_BYTES,
        [Ed25519Verifier(ev.public_key, ev.key_id)], wit_v,
        witness_validity=(T0 - 100, T0 + 100))
    if not got["witness"].get("log_backed"):
        return _record("sigstore-log-path", "BREAK",
                       "open did not verify the log path")
    _record("sigstore-log-path", "HELD",
            "log-backed seal/open; real indices; inclusionProof verified")


def p_sigstore_fallback_both_ways():
    # The offline fallback (no witness_log) must still verify: the
    # bundle verifies with AND without the log path.
    from gov import evidence_sigstore as sg
    from gov import evidence_intoto as _intoto
    from gov import evidence_dsse as _edsse
    from gov.signing import Ed25519Verifier
    ev = _signer(EVIDENCE_SEED)
    wit = _signer(WITNESS_SEED)
    stmt = _intoto.build_statement(BUNDLE_BYTES, dict(PREDICATE_CLAIMS))
    envelope = _intoto.seal_statement(stmt, [ev])
    wit_v = Ed25519Verifier(wit.public_key, wit.key_id)
    ev_v = Ed25519Verifier(ev.public_key, ev.key_id)
    # Without the log.
    b0 = sg.seal_sigstore_bundle(envelope, [ev], wit,
                                 integrated_time=T0)
    e0 = b0["verificationMaterial"]["tlogEntries"][0]
    if "inclusionProof" in e0 or e0["logIndex"] != "0":
        return _record("sigstore-fallback-both-ways", "BREAK",
                       "fallback entry shape changed")
    sg.open_sigstore_bundle(b0, BUNDLE_BYTES,
                            [ev_v], wit_v,
                            witness_validity=(T0 - 100, T0 + 100))
    # With the log.
    wlog = wl.WitnessLog(wit.public_key)
    b1 = sg.seal_sigstore_bundle(envelope, [ev], wit,
                                 witness_log=wlog,
                                 integrated_time=T0)
    sg.open_sigstore_bundle(b1, BUNDLE_BYTES,
                            [ev_v], wit_v,
                            witness_validity=(T0 - 100, T0 + 100))
    _record("sigstore-fallback-both-ways", "HELD",
            "fallback and log path both verify")


def p_sigstore_log_path_tamper():
    from gov import evidence_sigstore as sg
    from gov import evidence_intoto as _intoto
    from gov import evidence_dsse as _edsse
    from gov.signing import Ed25519Verifier
    ev = _signer(EVIDENCE_SEED)
    wit = _signer(WITNESS_SEED)
    stmt = _intoto.build_statement(BUNDLE_BYTES, dict(PREDICATE_CLAIMS))
    envelope = _intoto.seal_statement(stmt, [ev])
    wlog = wl.WitnessLog(wit.public_key)
    bundle = sg.seal_sigstore_bundle(envelope, [ev], wit,
                                     witness_log=wlog,
                                     integrated_time=T0)
    # A second entry so the tampered proof has a non-empty audit path
    # (a single-leaf proof is empty -- nothing to tamper).
    bundle = sg.seal_sigstore_bundle(envelope, [ev], wit,
                                     witness_log=wlog,
                                     integrated_time=T0)
    bundle = copy.deepcopy(bundle)
    path = (bundle["verificationMaterial"]["tlogEntries"][0]
            ["inclusionProof"]["auditPath"])
    h = bytearray(bytes.fromhex(path[0]["hash"]))
    h[0] ^= 1
    path[0]["hash"] = bytes(h).hex()
    wit_v = Ed25519Verifier(wit.public_key, wit.key_id)
    ev_v = Ed25519Verifier(ev.public_key, ev.key_id)
    try:
        sg.open_sigstore_bundle(bundle, BUNDLE_BYTES,
                                [ev_v], wit_v,
                                witness_validity=(T0 - 100, T0 + 100))
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "reason", "") or ""
        if code == "evidence-bundle-witness-inclusion-invalid":
            return _record("sigstore-log-path-tamper", "HELD",
                           "tampered auditPath refused coded")
        return _record("sigstore-log-path-tamper", "BREAK",
                       "wrong code: %r" % (code,))
    _record("sigstore-log-path-tamper", "BREAK",
            "tampered inclusion proof verified")


# ---------------------------------------------------------------------------
# Verifier wiring probes (gov/evidence_verify_offline.py witness stage).
# ---------------------------------------------------------------------------

def p_offline_witness_positive():
    wit = _signer(WITNESS_SEED)
    vb, bb = _good_bundle(witness_signers=[wit])
    try:
        rep = v.verify(bb, vb, time_source=_clock())
    except Exception as e:  # noqa: BLE001
        return _record("offline-witness-positive", "ERROR",
                       "valid witness entry refused: %r" % (e,))
    if rep.get("verificationResult") != "PASSED":
        return _record("offline-witness-positive", "BREAK", "not PASSED")
    steps = [c["step"] for c in rep.get("checks", [])]
    if "witness" not in steps:
        return _record("offline-witness-positive", "BREAK",
                       "no witness step in %r" % steps)
    w = rep.get("witness") or {}
    if w.get("tree_size") != 1 or w.get("log_index") != 0:
        return _record("offline-witness-positive", "BREAK",
                       "witness report wrong: %r" % w)
    text = v.render_transcript(rep)
    if "witness" not in text:
        return _record("offline-witness-positive", "BREAK",
                       "transcript omits witness")
    _record("offline-witness-positive", "HELD",
            "PASSED with witness step; checkpoint-first; entry bound")


def p_offline_witness_unknown_kind_still_refused():
    # The refused-coded path for malformed/unknown entries is NOT
    # weakened by the witness step landing.
    vb, bb = _good_bundle(witness_signers=[_signer(WITNESS_SEED)])
    vb2 = copy.deepcopy(vb)
    vb2["witness_entries"] = [{"kind": "rekor-v2-entry/v1",
                               "checkpoint": "..."}]
    _expect_code("offline-witness-unknown-kind-still-refused",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "UNSUPPORTED_BUNDLE_VERSION", 42)


def p_offline_witness_required_unmet():
    wit = _signer(WITNESS_SEED)
    vb, bb = _good_bundle(witness_signers=[wit], witness_required=True,
                          with_entry=False)
    _expect_code("offline-witness-required-unmet",
                 lambda: v.verify(bb, vb, time_source=_clock()),
                 "WITNESS_REQUIRED_UNMET", 44)


def p_offline_witness_no_key_in_policy():
    # Bundle carries a witness entry but the signed policy names no
    # witness_log_keys: refused coded (never silently unverifiable).
    wit = _signer(WITNESS_SEED)
    vb, bb = _good_bundle(witness_signers=[wit])
    vb2 = copy.deepcopy(vb)
    vb2["policy"] = _seal_policy(_policy_doc(
        [_signer(EVIDENCE_SEED)], NOW + timedelta(days=10),
        witness_signers=()))
    _expect_code("offline-witness-no-key-in-policy",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "WITNESS_KEY_UNAVAILABLE", 41)


def p_offline_forgery_checkpoint_signature():
    wit = _signer(WITNESS_SEED)
    vb, bb = _good_bundle(witness_signers=[wit])
    vb2 = copy.deepcopy(vb)
    entry = vb2["witness_entries"][0]
    sig = bytearray(base64.b64decode(entry["checkpoint_signature"]))
    sig[0] ^= 1
    entry["checkpoint_signature"] = base64.b64encode(bytes(sig)).decode(
        "ascii")
    _expect_code("offline-forgery-checkpoint-signature",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "WITNESS_CHECKPOINT_INVALID", 41)


def p_offline_forgery_checkpoint_wrong_key():
    # Checkpoint genuinely signed, but by a key the policy does not
    # pin (logId names no policy witness key).
    wit = _signer(WITNESS_SEED)
    other = _signer(WITNESS_SEED_2)
    vb, bb = _good_bundle(witness_signers=[wit])
    wlog = wl.WitnessLog(other.public_key)
    entry = v.seal_witness_entry(
        wlog, other,
        artifact_digest=hashlib.sha256(bb).hexdigest(),
        signatures=vb["envelope"]["signatures"],
        verified_keyids=[_signer(EVIDENCE_SEED).key_id],
        policy_digest="00" * 32,
        integrated_time=T0)
    vb2 = copy.deepcopy(vb)
    vb2["witness_entries"] = [entry]
    _expect_code("offline-forgery-checkpoint-wrong-key",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "WITNESS_CHECKPOINT_INVALID", 41)


def p_offline_forgery_inclusion_proof():
    wit = _signer(WITNESS_SEED)
    vb, bb = _good_bundle(witness_signers=[wit])
    vb2 = copy.deepcopy(vb)
    # A second entry in the same log gives a non-empty audit path to
    # tamper with (single-leaf proofs are empty).
    wlog = wl.WitnessLog(wit.public_key)
    e1 = v.seal_witness_entry(
        wlog, wit,
        artifact_digest=hashlib.sha256(bb).hexdigest(),
        signatures=vb["envelope"]["signatures"],
        verified_keyids=[_signer(EVIDENCE_SEED).key_id],
        policy_digest=hashlib.sha256(_canon(
            _policy_doc([_signer(EVIDENCE_SEED)],
                        NOW + timedelta(days=10),
                        witness_signers=[wit]))).hexdigest(),
        integrated_time=T0)
    e2 = v.seal_witness_entry(
        wlog, wit,
        artifact_digest=hashlib.sha256(OTHER_BYTES).hexdigest(),
        signatures=vb["envelope"]["signatures"],
        verified_keyids=[_signer(EVIDENCE_SEED).key_id],
        policy_digest="00" * 32,
        integrated_time=T0)
    vb2["witness_entries"] = [e2]
    path = vb2["witness_entries"][0]["inclusion_path"]
    h = bytearray(bytes.fromhex(path[0]["hash"]))
    h[0] ^= 1
    path[0]["hash"] = bytes(h).hex()
    _expect_code("offline-forgery-inclusion-proof",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "WITNESS_INCLUSION_INVALID", 43)


def p_offline_forgery_backdated_entry():
    # Backdated entry: the entry claims an integratedTime AFTER its
    # own checkpoint's timestamp -- incoherent for an honest log
    # (the checkpoint covers the entry, so it cannot predate it).
    wit = _signer(WITNESS_SEED)
    vb, bb = _good_bundle(witness_signers=[wit])
    wlog = wl.WitnessLog(wit.public_key)
    body = {
        "apiVersion": v.WITNESS_ENTRY_API_VERSION,
        "kind": v.WITNESS_ENTRY_BODY_KIND,
        "spec": {
            "artifactDigest": hashlib.sha256(bb).hexdigest(),
            "signatures": vb["envelope"]["signatures"],
            "verifiedKeyids": [_signer(EVIDENCE_SEED).key_id],
            "policyDigest": "00" * 32,
            "integratedTime": T0 + 3600,  # after the checkpoint below
        },
    }
    index = wlog.append(wl.canonical_bytes(body))
    sealed = wlog.sealed_checkpoint(T0, wit)  # checkpoint predates entry
    proof = wlog.inclusion_proof(index)
    entry = {
        "kind": v.WITNESS_ENTRY_KIND,
        "log_index": index,
        "entry_body": body,
        "checkpoint": sealed["checkpoint"],
        "checkpoint_signature": sealed["signature"],
        "inclusion_path": proof["path"],
    }
    vb2 = copy.deepcopy(vb)
    vb2["witness_entries"] = [entry]
    _expect_code("offline-forgery-backdated-entry",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "WITNESS_ENTRY_UNBOUND", 43)


def p_offline_forgery_entry_unbound():
    # CVE-2026-22703 analogue: a VALID entry triple (checkpoint +
    # proof + body) for bundle A replayed into bundle B's verification
    # must refuse -- the entry does not bind THIS bundle.
    wit = _signer(WITNESS_SEED)
    vb_a, bb_a = _good_bundle(bundle_bytes=BUNDLE_BYTES,
                              witness_signers=[wit])
    vb_b, _ = _good_bundle(bundle_bytes=OTHER_BYTES,
                           witness_signers=[wit])
    vb2 = copy.deepcopy(vb_b)
    vb2["witness_entries"] = vb_a["witness_entries"]  # replay A's entry
    _expect_code("offline-forgery-entry-unbound",
                 lambda: v.verify(OTHER_BYTES, vb2,
                                  time_source=_clock()),
                 "WITNESS_ENTRY_UNBOUND", 43)


def p_offline_forgery_future_checkpoint():
    # Checkpoint timestamp in the future vs the observed time refuses
    # (temporal), even with a valid signature.
    wit = _signer(WITNESS_SEED)
    vb, bb = _good_bundle(witness_signers=[wit])
    wlog = wl.WitnessLog(wit.public_key)
    entry = v.seal_witness_entry(
        wlog, wit,
        artifact_digest=hashlib.sha256(bb).hexdigest(),
        signatures=vb["envelope"]["signatures"],
        verified_keyids=[_signer(EVIDENCE_SEED).key_id],
        policy_digest=hashlib.sha256(_canon(
            _policy_doc([_signer(EVIDENCE_SEED)],
                        NOW + timedelta(days=10),
                        witness_signers=[wit]))).hexdigest(),
        integrated_time=T0)
    entry = copy.deepcopy(entry)
    # Re-seal the checkpoint at a future time (white-box: the witness
    # key is the test's; the verifier must still refuse).
    body = entry["entry_body"]
    wlog2 = wl.WitnessLog(wit.public_key)
    idx = wlog2.append(wl.canonical_bytes(body))
    future = int((NOW + timedelta(days=1)).timestamp())
    sealed = wlog2.sealed_checkpoint(future, wit)
    entry["checkpoint"] = sealed["checkpoint"]
    entry["checkpoint_signature"] = sealed["signature"]
    entry["log_index"] = idx
    entry["inclusion_path"] = wlog2.inclusion_proof(idx)["path"]
    vb2 = copy.deepcopy(vb)
    vb2["witness_entries"] = [entry]
    _expect_code("offline-forgery-future-checkpoint",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "TEMPORAL_UNSATISFIED", 44)


def p_offline_witness_steps_conditional():
    # Without entries and without witness_required, the transcript
    # keeps the original 9 steps (existing battery untouched).
    vb, bb = _good_bundle(witness_signers=[_signer(WITNESS_SEED)],
                          with_entry=False)
    rep = v.verify(bb, vb, time_source=_clock())
    steps = [c["step"] for c in rep.get("checks", [])]
    want = ["parse", "payloadType", "signature", "statement",
            "predicate", "digest", "subject", "policy", "transcript"]
    if steps != want:
        return _record("offline-witness-steps-conditional", "BREAK",
                       "steps want %r, got %r" % (want, steps))
    _record("offline-witness-steps-conditional", "HELD",
            "no entries -> 9 steps unchanged")


def p_witness_log_stdlib_only():
    # gov/witness_log.py must stay stdlib-only: no gov imports, no
    # network modules. It is loaded by file path by the standalone
    # verifier, so its import closure must be clean.
    import ast
    allowed = {"hashlib", "json", "base64", "binascii"}
    with open(os.path.join(REPO, "gov", "witness_log.py"),
              encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    bad = imported - allowed - {"__future__"}
    if bad:
        return _record("witness-log-stdlib-only", "BREAK",
                       "non-stdlib/pure imports: %r" % sorted(bad))
    _record("witness-log-stdlib-only", "HELD",
            "imports %r only" % sorted(imported))


def p_thirdparty_accept_witness():
    # Third-party acceptance: a stdlib-only script verifies a sealed
    # checkpoint + inclusion proof with NO Sasanam import (asserted via
    # sys.modules in the child). "Sell evidence, not the engine."
    key = _signer(WITNESS_SEED)
    log = _log_with(5)
    sealed = _sealed(log)
    proof = log.inclusion_proof(3)
    d = "/var/tmp/g312-wl/tp"
    os.makedirs(d, exist_ok=True)
    leaf_path = os.path.join(d, "leaf.bin")
    with open(leaf_path, "wb") as fh:
        fh.write(b"entry-3")
    cp_path = os.path.join(d, "checkpoint.json")
    with open(cp_path, "w", encoding="utf-8") as fh:
        json.dump(sealed, fh)
    proof_path = os.path.join(d, "proof.json")
    with open(proof_path, "w", encoding="utf-8") as fh:
        json.dump(proof, fh)
    script = os.path.join(REPO, "evals", "w312_thirdparty_witness_accept.py")
    env = {k: val for k, val in os.environ.items()
           if k not in ("PYTHONPATH", "PYTHONHOME")}
    env["GOV_SKIP_GREEN"] = "1"
    try:
        proc = subprocess.run(
            [sys.executable, script,
             "--checkpoint", cp_path,
             "--pubkey", key.public_key.hex(),
             "--leaf", leaf_path,
             "--proof", proof_path],
            cwd="/tmp", env=env, capture_output=True, text=True,
            timeout=120)
    except Exception as e:  # noqa: BLE001
        return _record("thirdparty-accept-witness", "ERROR", "%r" % (e,))
    if proc.returncode != 0:
        return _record("thirdparty-accept-witness", "BREAK",
                       "rc=%d stderr=%s" % (proc.returncode,
                                            proc.stderr[-500:]))
    if "THIRDPARTY_WITNESS_VALID" not in proc.stdout:
        return _record("thirdparty-accept-witness", "BREAK",
                       "acceptance marker missing")
    _record("thirdparty-accept-witness", "HELD",
            "stdlib-only checkpoint+inclusion, no Sasanam import")


def _green_checks():
    def _rec(pid, verdict, note):
        _record(pid, verdict, note)
    if SKIP_GREEN:
        _record("green-skipped", "HELD",
                "green check skipped (GOV_SKIP_GREEN=1)")
        return
    # Adjacent suites (depth-1): the new log, the Sigstore sealer, and
    # the offline verifier must stay green under this lane.
    green_check.check_unittest(
        _rec, "green-test_witness_log", "tests.test_witness_log",
        repo=REPO)
    green_check.check_unittest(
        _rec, "green-test_evidence_sigstore",
        "tests.test_evidence_sigstore", repo=REPO)
    green_check.check_unittest(
        _rec, "green-test_evidence_verify_offline",
        "tests.test_evidence_verify_offline", repo=REPO)


_PROBES = [
    ("pin-taxonomy", p_pin_taxonomy),
    ("footer-state", p_footer_state),
    ("log-roundtrip", p_log_roundtrip),
    ("inclusion-positive", p_inclusion_positive),
    ("consistency-positive", p_consistency_positive),
    ("forgery-forked-log", p_forgery_forked_log),
    ("forgery-forked-log-xlog", p_forgery_forked_log),  # runs both halves
    ("forgery-inclusion-proof", p_forgery_inclusion_proof),
    ("forgery-checkpoint-signature", p_forgery_checkpoint_signature),
    ("forgery-checkpoint-wrong-key", p_forgery_checkpoint_signature),
    ("forgery-checkpoint-body-tamper", p_forgery_checkpoint_signature),
    ("forgery-unpinned-root-hash", p_forgery_unpinned_root_hash),
    ("forgery-unpinned-root-hash-ignored", p_forgery_unpinned_root_hash),
    ("forgery-tree-size-rollback", p_forgery_tree_size_rollback),
    ("forgery-leaf-swap", p_forgery_leaf_swap),
    ("forgery-wrong-signer-key", p_forgery_wrong_signer_key),
    ("export-import-roundtrip", p_export_import_roundtrip),
    ("sigstore-log-path", p_sigstore_log_path),
    ("sigstore-fallback-both-ways", p_sigstore_fallback_both_ways),
    ("sigstore-log-path-tamper", p_sigstore_log_path_tamper),
    ("offline-witness-positive", p_offline_witness_positive),
    ("offline-witness-unknown-kind-still-refused",
     p_offline_witness_unknown_kind_still_refused),
    ("offline-witness-required-unmet", p_offline_witness_required_unmet),
    ("offline-witness-no-key-in-policy", p_offline_witness_no_key_in_policy),
    ("offline-forgery-checkpoint-signature",
     p_offline_forgery_checkpoint_signature),
    ("offline-forgery-checkpoint-wrong-key",
     p_offline_forgery_checkpoint_wrong_key),
    ("offline-forgery-inclusion-proof", p_offline_forgery_inclusion_proof),
    ("offline-forgery-backdated-entry", p_offline_forgery_backdated_entry),
    ("offline-forgery-entry-unbound", p_offline_forgery_entry_unbound),
    ("offline-forgery-future-checkpoint",
     p_offline_forgery_future_checkpoint),
    ("offline-witness-steps-conditional",
     p_offline_witness_steps_conditional),
    ("witness-log-stdlib-only", p_witness_log_stdlib_only),
    ("thirdparty-accept-witness", p_thirdparty_accept_witness),
]

# No open findings expected from this lane: every probe must HOLD.
_EXPECTED_BREAKS = frozenset()


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("probe", nargs="?", default=None,
                    help="run one probe by id")
    args = ap.parse_args()
    if args.probe:
        # Several probe ids share one function (it records each id it
        # covers); run the function once per requested id.
        for pid, fn in _PROBES:
            if pid == args.probe:
                _safe(pid, fn)
                break
        else:
            print("unknown probe", args.probe)
            sys.exit(2)
    else:
        seen_fn = set()
        for pid, fn in _PROBES:
            if fn not in seen_fn:
                seen_fn.add(fn)
                _safe(pid, fn)
        _green_checks()
    for pid, verdict, note in _results:
        first = note.splitlines()[0] if note else ""
        print("[VERDICT] %s: %s: %s" % (verdict, pid, first))
    brk = sum(1 for r in _results if r[1] == "BREAK")
    held = sum(1 for r in _results if r[1] == "HELD")
    err = sum(1 for r in _results if r[1] == "ERROR")
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    if args.probe:
        return 0
    unexpected = [pid for pid, v, _ in _results
                  if v == "BREAK" and pid not in _EXPECTED_BREAKS]
    if unexpected:
        print("unexpected BREAKs: %s" % (unexpected,))
        return 1
    missing = sorted(_EXPECTED_BREAKS - frozenset(
        pid for pid, v, _ in _results if v == "BREAK"))
    if missing:
        print("expected BREAKs missing: %s" % (missing,))
        return 1
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
