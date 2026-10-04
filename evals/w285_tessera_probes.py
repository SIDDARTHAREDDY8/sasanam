"""Wave-285 lane 7 red-first battery: tessera-pattern evidence anchoring.

Base: wave-284 push 0f13ce1. The gap under test is evidence anchoring for
the offline evidence bundle: bundles are sealed and signed (wave-284 SOPS
lane) but there is no verifiable append-only anchor -- an auditor cannot
tell whether a bundle existed at a claimed time, whether the bundle set
was tampered with, or whether a presented "anchor" is forged.
transparency-dev/tessera (Apache-2.0, pattern only -- clean-room stdlib
Python reimplementation, zero vendored Go code) supplies the mechanisms:
Add->Index append-only API, Merkle inclusion proofs, signed checkpoints,
witness cosigning, POSIX tlog-tile layout, PublicationAwaiter semantics.

Red-first: on the pristine base (module absent) every capability probe
BREAKs. After the build, all HELD in staging and under
env -u GOV_DEPLOYMENT_MODE.

$0 spend, synthetic/local, deterministic (secrets only for random
key material, never asserted on). Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g285-tessera && TMPDIR=/var/tmp/g285-tessera \
    ~/workspace/.gov-venv/bin/python evals/w285_tessera_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g285-tessera2 \
    ~/workspace/.gov-venv/bin/python evals/w285_tessera_probes.py
"""

import hashlib
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

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w285-tessera")
os.environ.setdefault("TMPDIR", "/var/tmp/g285-tessera")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Wave-285 lane 7: pin 1621 -> 1628 (+7 anchor-* codes).
TAXONOMY_PIN = 1945 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 3: pin 1933 -> 1945 (+12 quorum-*)

_RESULTS = []

PLUGIN_META = ("tessera-anchor", "direct", "held-vs-expected")
PROBE_METADATA = {}

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict,
                     "note": note})
    PROBE_METADATA.setdefault(probe_id, PLUGIN_META)


def _needs_module(probe_id):
    try:
        from gov import evidence_anchor as ea
        return ea
    except ImportError:
        _record(probe_id, "BREAK", "gov.evidence_anchor absent on base")
        return None


def _literals():
    with open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "gov", "decision_codes.py"),
            encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def _fresh_log(ea, tmp):
    from gov import ed25519
    seed = ed25519.generate_seed()
    root = os.path.join(tmp, "log-%s" % secrets.token_hex(4))
    log = ea.TransparencyLog(root, origin="test-log.example",
                             signer_keyid="op-1", signer_seed=seed)
    pub = ed25519.publickey(bytes(seed))
    return log, pub, root


def _witnesses(ea, quorum=2, n=3):
    from gov import ed25519
    from gov import signing
    wit = {}
    seeds = {}
    for i in range(n):
        seed = ed25519.generate_seed()
        pub = ed25519.publickey(bytes(seed))
        kid = signing.ed25519_key_id(pub)
        wit[kid] = pub.hex()
        seeds[kid] = seed
    pol = ea.WitnessPolicy(policy_id="wp-1", witnesses=wit, quorum=quorum)
    return pol, seeds


# ---------------------------------------------------------------------------
# Capability probes (BREAK on base by missing module; HELD after the build)
# ---------------------------------------------------------------------------

def p_module_present():
    ea = _needs_module("module-present")
    if ea is None:
        return
    _record("module-present", "HELD",
            "gov.evidence_anchor importable")


def p_taxonomy_pin():
    lits = _literals()
    uniq = sorted(set(lits))
    if len(lits) != TAXONOMY_PIN or len(uniq) != TAXONOMY_PIN\
            or uniq != sorted(lits):
        _record("taxonomy-pin", "BREAK",
                "taxonomy %d raw / %d unique (pin %d)"
                % (len(lits), len(uniq), TAXONOMY_PIN))
        return
    for code in ("anchor-checkpoint-invalid", "anchor-inclusion-mismatch",
                 "anchor-witness-quorum-failed", "anchor-index-unpublished",
                 "anchor-leaf-mismatch", "anchor-log-corrupt",
                 "anchor-no-signer"):
        if code not in uniq:
            _record("taxonomy-pin", "BREAK",
                    "missing anchor code %s" % code)
            return
    _record("taxonomy-pin", "HELD",
            "%d/%d/0 sorted, anchor-* codes present" % (len(lits),
                                                       len(uniq)))


def p_add_index_contiguous():
    ea = _needs_module("add-index-contiguous")
    if ea is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        idx = [log.add(hashlib.sha256(b"bundle-%d" % i).digest())
               for i in range(3)]
        if idx != [0, 1, 2]:
            _record("add-index-contiguous", "BREAK",
                    "indices not contiguous: %r" % (idx,))
            return
        # Durability: reopen; the next index must continue the sequence.
        log2 = ea.TransparencyLog(root, origin="test-log.example",
                                  signer_keyid="op-1",
                                  signer_seed=None)
        idx3 = log2.add(hashlib.sha256(b"bundle-3").digest())
        if idx3 != 3:
            _record("add-index-contiguous", "BREAK",
                    "index not durable across reopen: %r" % (idx3,))
            return
    _record("add-index-contiguous", "HELD",
            "Add->Index contiguous and durable")


def p_await_publication():
    ea = _needs_module("await-publication")
    if ea is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        digest = hashlib.sha256(b"evidence-bundle").hexdigest()
        receipt = ea.anchor(log, digest)
        # The receipt must carry a checkpoint covering the index.
        from gov import ed25519
        body, sigs = ea.parse_checkpoint(receipt["checkpoint_signature"])
        if body["size"] <= receipt["log_index"]:
            _record("await-publication", "BREAK",
                    "checkpoint size %d does not cover index %d"
                    % (body["size"], receipt["log_index"]))
            return
        if not ed25519.verify(pub, body["canonical"],
                              bytes.fromhex(sigs[0]["sig"])):
            _record("await-publication", "BREAK",
                    "checkpoint signature does not verify")
            return
    _record("await-publication", "HELD",
            "PublicationAwaiter publishes a signed checkpoint covering "
            "the index")


def p_receipt_shape():
    ea = _needs_module("receipt-shape")
    if ea is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        digest = hashlib.sha256(b"bundle-x").hexdigest()
        receipt = ea.anchor(log, digest)
        want = {"bundle_digest", "log_index", "inclusion_proof",
                "checkpoint_signature", "witness_policy_id"}
        got = set(receipt)
        if got != want:
            _record("receipt-shape", "BREAK",
                    "receipt keys %r != %r" % (sorted(got), sorted(want)))
            return
        if receipt["bundle_digest"] != digest:
            _record("receipt-shape", "BREAK", "bundle_digest not echoed")
            return
    _record("receipt-shape", "HELD",
            "anchor receipt = (bundle_digest, log_index, inclusion_proof, "
            "checkpoint_signature, witness_policy_id)")


def p_receipt_verifies():
    ea = _needs_module("receipt-verifies")
    if ea is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        pol, seeds = _witnesses(ea)
        digest = hashlib.sha256(b"honest-bundle").hexdigest()
        receipt = ea.anchor(log, digest, witness_policy=pol,
                            witness_seeds=seeds)
        try:
            ok = ea.verify_receipt(receipt, log_pubkey=pub,
                                   witness_policy=pol)
        except Exception as e:  # noqa: BLE001
            _record("receipt-verifies", "BREAK",
                    "honest receipt refused: %r" % (e,))
            return
        if ok is not True:
            _record("receipt-verifies", "BREAK",
                    "verify_receipt did not return True")
            return
    _record("receipt-verifies", "HELD",
            "honest anchor receipt verifies (incl. witness quorum)")


def p_forged_checkpoint_refused():
    ea = _needs_module("forged-checkpoint-refused")
    if ea is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        digest = hashlib.sha256(b"b1").hexdigest()
        receipt = ea.anchor(log, digest)
        # Forge: sign the checkpoint body with an unrelated key.
        from gov import ed25519
        evil = ed25519.generate_seed()
        evil_pub = ed25519.publickey(bytes(evil))
        body, sigs = ea.parse_checkpoint(receipt["checkpoint_signature"])
        forged_sig = ed25519.sign(bytes(evil), body["canonical"]).hex()
        receipt["checkpoint_signature"] = ea.render_checkpoint(
            body, [{"keyid": "op-1", "sig": forged_sig}])
        try:
            ea.verify_receipt(receipt, log_pubkey=pub,
                              witness_policy=None)
        except ea.AnchorError as e:
            if e.code == "anchor-checkpoint-invalid":
                _record("forged-checkpoint-refused", "HELD",
                        "forged checkpoint refused LOUD "
                        "(anchor-checkpoint-invalid)")
                return
            _record("forged-checkpoint-refused", "BREAK",
                    "wrong code %r" % (e.code,))
            return
        except Exception as e:  # noqa: BLE001
            _record("forged-checkpoint-refused", "BREAK",
                    "non-coded refusal %r" % (e,))
            return
        _record("forged-checkpoint-refused", "BREAK",
                "forged checkpoint ACCEPTED")


def p_tampered_proof_refused():
    ea = _needs_module("tampered-proof-refused")
    if ea is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        for i in range(5):
            log.add(hashlib.sha256(b"e%d" % i).digest())
        digest = hashlib.sha256(b"e2").hexdigest()
        idx = 2
        cp = log.await_publication(idx)
        proof = log.inclusion_proof(idx, cp["size"])
        receipt = {"bundle_digest": digest, "log_index": idx,
                   "inclusion_proof": proof,
                   "checkpoint_signature": cp["signed_note"],
                   "witness_policy_id": "none"}
        # Tamper: flip one bit of the first proof hash.
        bad = dict(proof)
        hashes = [bytearray(bytes.fromhex(h)) for h in proof["hashes"]]
        hashes[0][0] ^= 0x01
        bad["hashes"] = [bytes(h).hex() for h in hashes]
        receipt["inclusion_proof"] = bad
        try:
            ea.verify_receipt(receipt, log_pubkey=pub,
                              witness_policy=None)
        except ea.AnchorError as e:
            if e.code == "anchor-inclusion-mismatch":
                _record("tampered-proof-refused", "HELD",
                        "tampered inclusion proof refused LOUD")
                return
            _record("tampered-proof-refused", "BREAK",
                    "wrong code %r" % (e.code,))
            return
        except Exception as e:  # noqa: BLE001
            _record("tampered-proof-refused", "BREAK",
                    "non-coded refusal %r" % (e,))
            return
        _record("tampered-proof-refused", "BREAK",
                "tampered inclusion proof ACCEPTED")


def p_witness_quorum_enforced():
    ea = _needs_module("witness-quorum-enforced")
    if ea is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        pol, seeds = _witnesses(ea, quorum=2, n=3)
        digest = hashlib.sha256(b"w1").hexdigest()
        # Only ONE witness cosigns though quorum is 2: fail FAST at
        # issuance -- no dead-on-arrival receipt is minted.
        try:
            ea.anchor(log, digest, witness_policy=pol,
                      witness_seeds=dict(list(seeds.items())[:1]))
        except ea.AnchorError as e:
            if e.code != "anchor-witness-quorum-failed":
                _record("witness-quorum-enforced", "BREAK",
                        "wrong code %r" % (e.code,))
                return
        except Exception as e:  # noqa: BLE001
            _record("witness-quorum-enforced", "BREAK",
                    "non-coded refusal %r" % (e,))
            return
        else:
            _record("witness-quorum-enforced", "BREAK",
                    "under-quorum cosigning ISSUED")
            return
        # Verify-time quorum path: a 2-of-3 checkpoint verified
        # against a stricter 3-of-3 policy still refuses LOUD.
        receipt2 = ea.anchor(log, digest, witness_policy=pol,
                             witness_seeds=dict(list(seeds.items())[:2]))
        pol3 = ea.WitnessPolicy(policy_id="wp-1",
                                witnesses=pol.witnesses, quorum=3)
        try:
            ea.verify_receipt(receipt2, log_pubkey=pub,
                              witness_policy=pol3)
        except ea.AnchorError as e:
            if e.code != "anchor-witness-quorum-failed":
                _record("witness-quorum-enforced", "BREAK",
                        "wrong code %r" % (e.code,))
                return
        except Exception as e:  # noqa: BLE001
            _record("witness-quorum-enforced", "BREAK",
                    "non-coded refusal %r" % (e,))
            return
        else:
            _record("witness-quorum-enforced", "BREAK",
                    "under-quorum verification ACCEPTED")
            return
        # With satisfied quorum it verifies.
        if ea.verify_receipt(receipt2, log_pubkey=pub,
                             witness_policy=pol) is not True:
            _record("witness-quorum-enforced", "BREAK",
                    "quorum-satisfied receipt refused")
            return
    _record("witness-quorum-enforced", "HELD",
            "witness quorum enforced at issuance and verify time (2-of-3)")


def p_operator_keyid_collision_refused():
    # Misconfiguration: the operator's key id is pinned as a witness
    # with quorum 1, and the checkpoint carries ONLY the operator line.
    # The operator line must NOT count toward the witness quorum.
    ea = _needs_module("operator-keyid-collision-refused")
    if ea is None:
        return
    from gov import ed25519
    with tempfile.TemporaryDirectory() as tmp:
        op_seed = ed25519.generate_seed()
        op_pub = ed25519.publickey(bytes(op_seed))
        root = os.path.join(tmp, "log-collide")
        log = ea.TransparencyLog(root, origin="test-log.example",
                                 signer_keyid="op-1",
                                 signer_seed=op_seed)
        entry = b"collision-entry"
        idx = log.add(entry)
        cp = log.await_publication(idx)  # no witness policy; root R
        cbody, _sigs = ea.parse_checkpoint(cp["signed_note"])
        # Re-issue the same tree under a colliding witness policy,
        # operator line only (public API only: render dummy, parse for
        # canonical bytes, sign, re-render).
        evil_body = {"origin": cbody["origin"], "size": cbody["size"],
                     "root": cbody["root"],
                     "timestamp": cbody["timestamp"],
                     "witness_policy_id": "wp-collide"}
        dummy = ea.render_checkpoint(evil_body,
                                     [{"keyid": "op-1", "sig": "00" * 64}])
        _dbody, _dsigs = ea.parse_checkpoint(dummy)
        real = ed25519.sign(bytes(op_seed),
                            _dbody["canonical"]).hex()
        note = ea.render_checkpoint(evil_body,
                                    [{"keyid": "op-1", "sig": real}])
        pol = ea.WitnessPolicy(policy_id="wp-collide",
                               witnesses={"op-1": op_pub.hex()}, quorum=1)
        receipt = {"bundle_digest": hashlib.sha256(entry).hexdigest(),
                   "log_index": idx,
                   "inclusion_proof": log.inclusion_proof(idx,
                                                         cbody["size"]),
                   "checkpoint_signature": note,
                   "witness_policy_id": "wp-collide"}
        try:
            ea.verify_receipt(receipt, log_pubkey=op_pub,
                              witness_policy=pol)
        except ea.AnchorError as e:
            if e.code != "anchor-witness-quorum-failed":
                _record("operator-keyid-collision-refused", "BREAK",
                        "wrong code %r" % (e.code,))
                return
        except Exception as e:  # noqa: BLE001
            _record("operator-keyid-collision-refused", "BREAK",
                    "non-coded refusal %r" % (e,))
            return
        else:
            _record("operator-keyid-collision-refused", "BREAK",
                    "operator line counted toward witness quorum")
            return
    _record("operator-keyid-collision-refused", "HELD",
            "operator line never counts as a witness, even on key-id "
            "collision")


def p_unpublished_index_refused():
    ea = _needs_module("unpublished-index-refused")
    if ea is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        d0 = hashlib.sha256(b"first").hexdigest()
        d1 = hashlib.sha256(b"second").hexdigest()
        i0 = log.add(bytes.fromhex(d0))
        cp1 = log.await_publication(i0)  # checkpoint of size 1
        i1 = log.add(bytes.fromhex(d1))  # index 1 NOT covered by cp1
        # Receipt built on the STALE checkpoint: the genuine
        # anchor-index-unpublished path (idx >= checkpoint size).
        receipt = {"bundle_digest": d1, "log_index": i1,
                   "inclusion_proof": {"leaf_index": i1, "tree_size": 1,
                                       "hashes": []},
                   "checkpoint_signature": cp1["signed_note"],
                   "witness_policy_id": "none"}
        try:
            ea.verify_receipt(receipt, log_pubkey=pub,
                              witness_policy=None)
        except ea.AnchorError as e:
            if e.code != "anchor-index-unpublished":
                _record("unpublished-index-refused", "BREAK",
                        "wrong code %r" % (e.code,))
                return
            _record("unpublished-index-refused", "HELD",
                    "stale-checkpoint receipt refused LOUD "
                    "(anchor-index-unpublished)")
            return
        except Exception as e:  # noqa: BLE001
            _record("unpublished-index-refused", "BREAK",
                    "non-coded refusal %r" % (e,))
            return
        _record("unpublished-index-refused", "BREAK",
                "unpublished index ACCEPTED")


def p_leaf_mismatch_refused():
    ea = _needs_module("leaf-mismatch-refused")
    if ea is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        real = hashlib.sha256(b"real-bundle").hexdigest()
        receipt = ea.anchor(log, real)
        receipt["bundle_digest"] = hashlib.sha256(b"fake").hexdigest()
        try:
            ea.verify_receipt(receipt, log_pubkey=pub,
                              witness_policy=None, log_root=root)
        except ea.AnchorError as e:
            if e.code == "anchor-leaf-mismatch":
                _record("leaf-mismatch-refused", "HELD",
                        "receipt claiming the wrong bundle refused LOUD")
                return
            _record("leaf-mismatch-refused", "BREAK",
                    "wrong code %r" % (e.code,))
            return
        except Exception as e:  # noqa: BLE001
            _record("leaf-mismatch-refused", "BREAK",
                    "non-coded refusal %r" % (e,))
            return
        _record("leaf-mismatch-refused", "BREAK",
                "leaf-mismatched receipt ACCEPTED")


def p_tile_tamper_evident():
    ea = _needs_module("tile-tamper-evident")
    if ea is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        digest = hashlib.sha256(b"tamper-me").hexdigest()
        receipt = ea.anchor(log, digest)
        # Attacker with write access rewrites a data tile. The partial
        # tile lives at tile/data/xNNN.p/<n> (a directory holding the
        # count file); full tiles are plain files.
        tile_dir = os.path.join(root, "tile", "data")
        entries = sorted(os.listdir(tile_dir))
        if not entries:
            _record("tile-tamper-evident", "BREAK",
                    "no data tiles on disk")
            return
        first = os.path.join(tile_dir, entries[0])
        if os.path.isdir(first):
            kids = os.listdir(first)
            path = os.path.join(first, kids[0])
        else:
            path = first
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        lines[0] = hashlib.sha256(b"evil").hexdigest()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        try:
            ea.verify_receipt(receipt, log_pubkey=pub,
                              witness_policy=None, log_root=root)
        except ea.AnchorError as e:
            if e.code in ("anchor-log-corrupt",
                          "anchor-inclusion-mismatch",
                          "anchor-leaf-mismatch"):
                _record("tile-tamper-evident", "HELD",
                        "tile tampering detected LOUD (%s)" % e.code)
                return
            _record("tile-tamper-evident", "BREAK",
                    "wrong code %r" % (e.code,))
            return
        except Exception as e:  # noqa: BLE001
            _record("tile-tamper-evident", "BREAK",
                    "non-coded refusal %r" % (e,))
            return
        _record("tile-tamper-evident", "BREAK",
                "tile tampering NOT detected")


def p_bundle_composition():
    ea = _needs_module("bundle-composition")
    if ea is None:
        return
    try:
        from gov import bundle_envelope as be
    except ImportError:
        _record("bundle-composition", "BREAK",
                "gov.bundle_envelope missing")
        return
    with tempfile.TemporaryDirectory() as tmp:
        from gov import ed25519
        seed = ed25519.generate_seed()
        pol = be.make_recipient_policy(
            [{"id": "auditor", "type": "offline",
              "x25519_pub": be.x25519_pub(
                  bytes.fromhex(secrets.token_hex(32))).hex()}])
        env = be.seal_envelope(b"evidence-bytes", bundle_id="b-1",
                               policy=pol, signer_seed=seed)
        log, pub, root = _fresh_log(ea, tmp)
        receipt = ea.anchor_bundle(log, env)
        if receipt["bundle_digest"] != be.envelope_digest(env):
            _record("bundle-composition", "BREAK",
                    "anchor leaf != envelope_digest")
            return
        if ea.verify_receipt(receipt, log_pubkey=pub,
                             witness_policy=None) is not True:
            _record("bundle-composition", "BREAK",
                    "bundle-anchored receipt refused")
            return
    _record("bundle-composition", "HELD",
            "anchor_bundle: leaf = envelope_digest, receipt verifies")


def p_guac_composition():
    ea = _needs_module("guac-composition")
    if ea is None:
        return
    try:
        from gov import guac_graph as gg
    except ImportError:
        _record("guac-composition", "BREAK", "gov.guac_graph missing")
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        digest = hashlib.sha256(b"g-bundle").hexdigest()
        receipt = ea.anchor(log, digest)
        graph = gg.GuacGraph()
        ea.record_anchor_in_graph(graph, receipt, log_id="log-1")
        ev = "evidence:" + digest
        sw = "software:anchor-log/log-1@1"
        if not graph.has_node(ev) or not graph.has_node(sw):
            _record("guac-composition", "BREAK",
                    "anchor nodes missing from graph")
            return
        rows = graph.edges_with(gg.EdgeSpec(kind="HasSLSA"))
        if not any(r[0] == sw and r[2] == ev for r in rows):
            _record("guac-composition", "BREAK",
                    "HasSLSA anchor edge missing")
            return
    _record("guac-composition", "HELD",
            "anchor receipt recorded as HasSLSA evidence edge in the "
            "GUAC graph")


def p_no_silent_dedup():
    ea = _needs_module("no-silent-dedup")
    if ea is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        digest = hashlib.sha256(b"same").hexdigest()
        r1 = ea.anchor(log, digest)
        r2 = ea.anchor(log, digest)
        # Documented tessera-trap behavior: dedup is the personality's
        # job; the log must NOT silently collapse two Adds.
        if r1["log_index"] == r2["log_index"]:
            _record("no-silent-dedup", "BREAK",
                    "two Adds of the same digest collapsed silently")
            return
    _record("no-silent-dedup", "HELD",
            "no silent dedup: re-anchoring mints a new index")


def p_no_signer_refused():
    ea = _needs_module("no-signer-refused")
    if ea is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        idx = log.add(hashlib.sha256(b"ro").digest())
        ro = ea.TransparencyLog(root, origin="test-log.example",
                                signer_keyid="op-1", signer_seed=None)
        try:
            ro.await_publication(idx)
        except ea.AnchorError as e:
            if e.code == "anchor-no-signer":
                _record("no-signer-refused", "HELD",
                        "signerless handle refuses publication LOUD")
                return
            _record("no-signer-refused", "BREAK",
                    "wrong code %r" % (e.code,))
            return
        except Exception as e:  # noqa: BLE001
            _record("no-signer-refused", "BREAK",
                    "non-coded refusal %r" % (e,))
            return
        _record("no-signer-refused", "BREAK",
                "signerless publication ACCEPTED")


def p_key_substitution_refused():
    ea = _needs_module("key-substitution-refused")
    if ea is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        log, pub, root = _fresh_log(ea, tmp)
        digest = hashlib.sha256(b"ks").hexdigest()
        receipt = ea.anchor(log, digest)
        # Auditor pins the WRONG operator key: the honest receipt must
        # refuse -- key distribution is the out-of-band trust root.
        from gov import ed25519
        wrong_pub = ed25519.publickey(ed25519.generate_seed())
        try:
            ea.verify_receipt(receipt, log_pubkey=wrong_pub,
                              witness_policy=None)
        except ea.AnchorError as e:
            if e.code == "anchor-checkpoint-invalid":
                _record("key-substitution-refused", "HELD",
                        "receipt does not verify under a substituted key")
                return
            _record("key-substitution-refused", "BREAK",
                    "wrong code %r" % (e.code,))
            return
        except Exception as e:  # noqa: BLE001
            _record("key-substitution-refused", "BREAK",
                    "non-coded refusal %r" % (e,))
            return
        _record("key-substitution-refused", "BREAK",
                "receipt verified under the WRONG key")


# ---------------------------------------------------------------------------
# Depth-1 green checks (adjacent batteries; GOV_SKIP_GREEN honored)
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        ("evals/w284_sops_probes.py", 0),
        ("evals/w284_guac_probes.py", 0),
        ("evals/w284_tink_probes.py", 0),
    ]
    for rel, expected_breaks in checks:
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), rel)
        d = tempfile.mkdtemp(prefix="w285-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=900,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r"
                    % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != expected_breaks:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected %d)"
                    % (nbreak, expected_breaks))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: %d BREAK as expected" % nbreak)


_PROBES = [
    p_module_present,
    p_taxonomy_pin,
    p_add_index_contiguous,
    p_await_publication,
    p_receipt_shape,
    p_receipt_verifies,
    p_forged_checkpoint_refused,
    p_tampered_proof_refused,
    p_witness_quorum_enforced,
    p_operator_keyid_collision_refused,
    p_unpublished_index_refused,
    p_leaf_mismatch_refused,
    p_tile_tamper_evident,
    p_bundle_composition,
    p_guac_composition,
    p_no_silent_dedup,
    p_no_signer_refused,
    p_key_substitution_refused,
]


def main():
    for probe in _PROBES:
        try:
            probe()
        except Exception as e:  # noqa: BLE001
            _record(probe.__name__, "ERROR", "probe raised: %r" % (e,))
    _green_checks()
    nbreak = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    nheld = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    nerr = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    print("== w285_tessera_probes: %d BREAK / %d HELD / %d ERROR =="
          % (nbreak, nheld, nerr))
    for r in _RESULTS:
        if r["verdict"] != "HELD":
            print("  %s %s: %s" % (r["verdict"], r["probe_id"],
                                   r["note"]))
    return 1 if (nbreak or nerr) else 0


if __name__ == "__main__":
    sys.exit(main())
