"""Wave-82: the evidence demo + the independent verifier.

The verifier (demo/verify_evidence.py) is stdlib-only, holds no HMAC
key, and trusts nothing in the bundle. These tests build synthetic
bundles with gov's own signing code (a cross-implementation check: the
verifier's vendored Ed25519 must verify gov's signatures) and assert
the verifier's honest grades:

* rejects a forged Ed25519 statement (never ANCHORED),
* rejects a tampered receipt,
* labels an attested-only epoch OPERATOR-ATTESTED-ONLY (never verified),
* passes a clean bundle,
* the demo's one-command run completes end-to-end.

The demo itself uses only the provisioned key path — no dev fallback anywhere.

Wave-81 closed: the mid-flight shim described below was removed; the
demo and these tests run against the final wave-81 tree.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)  # .../agent-governance-demo-main
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)


from gov import anchor_backend as _ab  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402


def _load_verifier():
    path = os.path.join(_REPO_MAIN, "demo", "verify_evidence.py")
    spec = importlib.util.spec_from_file_location("verify_evidence", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ver = _load_verifier()

DEMO = os.path.join(_REPO_MAIN, "demo", "evidence_demo.py")

# RFC 8032 section 7.1 TEST 1 (empty message) and TEST 2 (0x72) — the
# same vectors gov/ed25519.py is validated against. The verifier's
# vendored Ed25519 must verify these byte-exact.
RFC8032_VECTORS = (
    {"pk": "d75a980182b10ab7d54bfed3c964073a"
           "0ee172f3daa62325af021a68f707511a",
     "msg": "",
     "sig": "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b"},
    {"pk": "3d4017c3e843895a92b70aa74d1b7ebc"
           "9c982ccf2ec4968cc0cd55f12af4660c",
     "msg": "72",
     "sig": "92a009a9f0d4cab8720e820b5f642540"
            "a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c"
            "387b2eaeb4302aeeb00d291612bb0c00"},
)


def _seed(n):
    return bytes([n & 0xFF]) * 32


def _anchor_keypair(n=7):
    seed = _seed(n)
    pub = _ab.anchor_pubkey(seed)
    return seed, pub


def _entries(n=6, trip_seq=4, approval_seq=None):
    """Synthetic chain segment, seqs 1..n, with a canary_trip at
    trip_seq and an approval_decision at approval_seq (default n).
    Hash fields are opaque strings to the verifier (it holds no HMAC
    key)."""
    if approval_seq is None:
        approval_seq = n
    out = []
    for i in range(1, n + 1):
        e = {"seq": i, "ts": "2026-09-23T00:00:%02d+00:00" % i,
             "hash": "hash-%02d" % i, "event": "tool_call",
             "agent_id": "a-01", "role": "r", "principal": "p",
             "tool": "read_file", "decision": "executed"}
        out.append(e)
    out[trip_seq - 1] = {"seq": trip_seq,
                         "ts": "2026-09-23T00:00:%02d+00:00" % trip_seq,
                         "hash": "hash-%02d" % trip_seq,
                         "event": "canary_trip", "agent_id": "a-01",
                         "role": "r", "principal": "p", "tool": "send_email",
                         "decision": "halted", "flag": "canary_trip"}
    if approval_seq != trip_seq:
        out[approval_seq - 1] = {
            "seq": approval_seq,
            "ts": "2026-09-23T00:00:%02d+00:00" % approval_seq,
            "hash": "hash-%02d" % approval_seq,
            "event": "approval_decision", "agent_id": "human-operator",
            "approval_id": "ap-1", "decision": "approved",
            "decided_by": "human-operator"}
    return out


def _signed_anchor(entries, witness, seed, pub, epoch_id="e00000001",
                   checkpoint=None, prev_anchor=None):
    """Sign an anchor statement over the entries with gov's own code
    and submit it to the witness. Returns the bundle anchor dict."""
    checkpoint = checkpoint or (len(entries) - 1)
    entry = entries[checkpoint - 1]
    stmt = _ab.build_statement(
        epoch_id=epoch_id, seq=checkpoint, start_seq=1,
        head_hash=entry["hash"], merkle_root=None,
        epoch_start_wall=entries[0]["ts"],
        epoch_close_wall=entries[checkpoint - 1]["ts"],
        key_id=_ab.anchor_key_id(pub), pubkey_hex=pub.hex(),
        prev_anchor=prev_anchor, log_id=witness.backend_id)
    signed = _ab.sign_statement(stmt, seed)
    anchor_hash = _ab.statement_hash(signed)
    receipt = witness.submit(anchor_hash)
    ok, reason = witness.verify_receipt(receipt, anchor_hash=anchor_hash)
    assert ok, reason
    return {"checkpoint_seq": checkpoint,
            "anchored_epoch_id": epoch_id,
            "anchor_hash": anchor_hash,
            "statement": signed, "receipt": receipt}


def _write_bundle(d, entries, anchors, witness, identities=None,
                  approvals=None, trip_record=None):
    bundle = {
        "bundle_version": 1,
        "run_id": "test-run",
        "exported_at": "2026-09-23T00:00:00+00:00",
        "chain_segment": {"from_seq": 1, "to_seq": len(entries),
                          "entries": entries},
        "anchors": anchors,
        "attribution": {
            "identities": identities if identities is not None else [
                {"agent_id": "a-01", "role": "r", "principal": "p"},
                {"agent_id": "human-operator", "role": "approver",
                 "principal": "human"}],
            "approvals": approvals if approvals is not None else [
                {"approval_id": "ap-1", "tool": "read_file",
                 "agent_id": "a-01", "decision": "approved",
                 "decided_by": "human-operator", "reason": "ok",
                 "seq": len(entries)}],
        },
        "stopped_attack": {"description": "test", "record": trip_record},
    }
    wit = {"backend": "fake-witness", "backend_id": witness.backend_id,
           "receipts": witness._receipts}
    with open(os.path.join(d, "bundle.json"), "w",
              encoding="utf-8") as f:
        json.dump(bundle, f)
    with open(os.path.join(d, "witness.json"), "w",
              encoding="utf-8") as f:
        json.dump(wit, f)
    return d


class VerifierCryptoTest(unittest.TestCase):
    def test_vendored_ed25519_matches_rfc8032_vectors(self):
        # The verifier's vendored Ed25519 is verify-only; it must be
        # byte-exact with the RFC on the same vectors gov/ed25519.py
        # is validated against. A wrong signature must fail.
        for v in RFC8032_VECTORS:
            self.assertTrue(ver.ed25519_verify(
                bytes.fromhex(v["pk"]), bytes.fromhex(v["msg"]),
                bytes.fromhex(v["sig"])))
        bad = bytearray.fromhex(RFC8032_VECTORS[0]["sig"])
        bad[0] ^= 1
        self.assertFalse(ver.ed25519_verify(
            bytes.fromhex(RFC8032_VECTORS[0]["pk"]), b"",
            bytes(bad)))

    def test_vendored_ed25519_verifies_gov_signatures(self):
        # Cross-implementation: gov signs, the verifier's vendored math
        # verifies (the same pairing the demo's bundle relies on).
        seed, pub = _anchor_keypair()
        sig = _ed.sign(seed, b"gov-anchor-statement/v2\x00hello")
        self.assertTrue(ver.ed25519_verify(pub, b"hello", sig) is False)
        self.assertTrue(ver.ed25519_verify(
            pub, b"gov-anchor-statement/v2\x00hello", sig))


class VerifierBundleTest(unittest.TestCase):
    def setUp(self):
        self.dirs = []
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for d in self.dirs:
            shutil.rmtree(d, ignore_errors=True)

    def fresh_dir(self):
        d = tempfile.mkdtemp(prefix="test-w82-")
        self.dirs.append(d)
        return d

    def clean_bundle(self, d):
        entries = _entries()
        witness = _ab.FakeWitness()
        seed, pub = _anchor_keypair()
        anchor = _signed_anchor(entries, witness, seed, pub,
                                checkpoint=5)
        trip = next(e for e in entries if e["event"] == "canary_trip")
        _write_bundle(d, entries, [anchor], witness, trip_record=trip)
        return d

    def test_clean_bundle_passes(self):
        d = self.clean_bundle(self.fresh_dir())
        report = ver.verify_bundle(d)
        self.assertTrue(report["bundle_ok"], report["bundle_errors"])
        self.assertEqual(len(report["epochs"]), 1)
        ep = report["epochs"][0]
        self.assertEqual(ep["grade"], "ANCHORED")
        self.assertTrue(all(v is True or v == "MATCH"
                            for v in ep["checks"].values()),
                        ep)
        self.assertEqual(report["attribution"]["verdict"], "PASS")
        self.assertEqual(report["stopped_attack"]["verdict"], "PASS")
        # The open epoch is honestly attested-only, never verified.
        self.assertEqual(report["open_epoch"]["grade"],
                         "OPERATOR-ATTESTED-ONLY")
        text = ver.render_report(report)
        self.assertIn(
            "Entries between anchors are operator-attested; only anchor "
            "heads are independently verified.", text)

    def test_rejects_forged_statement(self):
        # Forge: rewrite the statement's head_hash without re-signing
        # (the attacker lacks the anchor seed). The verifier must flag
        # the signature and must NOT grade the epoch ANCHORED.
        d = self.clean_bundle(self.fresh_dir())
        with open(os.path.join(d, "bundle.json"), encoding="utf-8") as f:
            bundle = json.load(f)
        bundle["anchors"][0]["statement"]["head_hash"] = "f" * 64
        with open(os.path.join(d, "bundle.json"), "w",
                  encoding="utf-8") as f:
            json.dump(bundle, f)
        report = ver.verify_bundle(d)
        ep = report["epochs"][0]
        self.assertNotEqual(ep["grade"], "ANCHORED")
        self.assertEqual(ep["grade"], "OPERATOR-ATTESTED-ONLY")
        self.assertFalse(ep["checks"]["statement_sig"])
        self.assertTrue(any("signature INVALID" in r
                            for r in ep["reasons"]), ep["reasons"])

    def test_rejects_statement_signed_by_wrong_key(self):
        # Statement signed by a different seed than the shipped pubkey
        # claims: signature invalid, epoch not ANCHORED.
        d = self.clean_bundle(self.fresh_dir())
        with open(os.path.join(d, "bundle.json"), encoding="utf-8") as f:
            bundle = json.load(f)
        other_seed, _ = _anchor_keypair(n=9)
        stmt = bundle["anchors"][0]["statement"]
        body = {k: v for k, v in stmt.items() if k != "sig"}
        forged_sig = _ed.sign(
            other_seed,
            b"gov-anchor-statement/v2\x00" + json.dumps(
                body, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, default=str).encode("utf-8")).hex()
        stmt["sig"] = forged_sig
        with open(os.path.join(d, "bundle.json"), "w",
                  encoding="utf-8") as f:
            json.dump(bundle, f)
        report = ver.verify_bundle(d)
        ep = report["epochs"][0]
        self.assertEqual(ep["grade"], "OPERATOR-ATTESTED-ONLY")
        self.assertFalse(ep["checks"]["statement_sig"])

    def test_rejects_tampered_receipt(self):
        # Tamper the receipt's log_root: the inclusion proof no longer
        # verifies. The receipt check must fail and the epoch must not
        # grade ANCHORED.
        d = self.clean_bundle(self.fresh_dir())
        with open(os.path.join(d, "bundle.json"), encoding="utf-8") as f:
            bundle = json.load(f)
        receipt = bundle["anchors"][0]["receipt"]
        root = receipt["log_root"]
        receipt["log_root"] = ("0" if root[0] != "0" else "1") + root[1:]
        with open(os.path.join(d, "bundle.json"), "w",
                  encoding="utf-8") as f:
            json.dump(bundle, f)
        report = ver.verify_bundle(d)
        ep = report["epochs"][0]
        self.assertEqual(ep["grade"], "OPERATOR-ATTESTED-ONLY")
        self.assertFalse(ep["checks"]["receipt"])
        self.assertTrue(any("inclusion proof does NOT verify" in r
                            for r in ep["reasons"]), ep["reasons"])

    def test_attested_only_epoch_labeled_not_verified(self):
        # A bundle with NO anchor records: every record is
        # operator-attested-only. The verifier must say exactly that —
        # never "verified".
        d = self.fresh_dir()
        entries = _entries()
        witness = _ab.FakeWitness()
        trip = next(e for e in entries if e["event"] == "canary_trip")
        _write_bundle(d, entries, [], witness, trip_record=trip)
        report = ver.verify_bundle(d)
        self.assertTrue(report["bundle_ok"])
        self.assertEqual(report["epochs"], [])
        self.assertEqual(report["open_epoch"]["grade"],
                         "OPERATOR-ATTESTED-ONLY")
        self.assertEqual(report["open_epoch"]["unanchored_records"],
                         len(entries))
        text = ver.render_report(report)
        self.assertIn("OPERATOR-ATTESTED-ONLY", text)
        self.assertNotIn("ANCHORED\n", text.replace(
            "OPERATOR-ATTESTED-ONLY", ""))

    def test_stopped_attack_after_last_anchor_is_attested_only(self):
        # The trip record exists but sits after the last anchored
        # checkpoint: present, but honestly ATTESTED-ONLY (not PASS).
        d = self.fresh_dir()
        entries = _entries(n=6, trip_seq=6, approval_seq=5)
        witness = _ab.FakeWitness()
        seed, pub = _anchor_keypair()
        anchor = _signed_anchor(entries, witness, seed, pub,
                                checkpoint=4)
        trip = next(e for e in entries if e["event"] == "canary_trip")
        _write_bundle(d, entries, [anchor], witness, trip_record=trip)
        report = ver.verify_bundle(d)
        self.assertEqual(report["epochs"][0]["grade"], "ANCHORED")
        self.assertEqual(report["stopped_attack"]["verdict"],
                         "ATTESTED-ONLY")


class DemoEndToEndTest(unittest.TestCase):
    def test_demo_runs_end_to_end(self):
        d = tempfile.mkdtemp(prefix="test-w82-demo-")
        self.addCleanup(shutil.rmtree, d, True)
        proc = subprocess.run(
            [sys.executable, DEMO],
            cwd=d, capture_output=True, text=True, timeout=180)
        self.assertEqual(
            proc.returncode, 0,
            "demo failed:\nSTDOUT:\n%s\nSTDERR:\n%s"
            % (proc.stdout[-4000:], proc.stderr[-4000:]))
        runs_dir = os.path.join(d, "runs")
        runs = [p for p in os.listdir(runs_dir)
                if os.path.isdir(os.path.join(runs_dir, p))]
        self.assertEqual(len(runs), 1)
        evidence = os.path.join(d, "runs", runs[0], "evidence")
        self.assertTrue(os.path.isfile(
            os.path.join(evidence, "bundle.json")))
        self.assertTrue(os.path.isfile(
            os.path.join(evidence, "witness.json")))
        # The one-command run prints the auditor story AND the
        # independent verifier's verdict with its honest boundaries.
        self.assertIn("STOPPED ATTACK: PASS", proc.stdout)
        self.assertIn("2 of 2 anchored epoch(s) verified ANCHORED",
                      proc.stdout)
        self.assertIn(
            "Entries between anchors are operator-attested; only anchor "
            "heads are independently verified.", proc.stdout)
        self.assertIn("RESULT: demo completed end-to-end", proc.stdout)


if __name__ == "__main__":
    unittest.main()
