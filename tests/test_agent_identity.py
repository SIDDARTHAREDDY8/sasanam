"""Unit tests for the Wave-246 lane 7 additions: did:key-style identity
(gov/agent_identity.py new section) and the reputation ledger
(gov/reputation_ledger.py).

Covers the product seams: resolve/parse/verify_binding contracts and the
ledger's append/import/recompute paths, including the fail-closed
refusals. The red-first break battery lives in
evals/w246_agent_identity_probes.py; these units pin the contracts.
"""

import hashlib
import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import agent_identity as ai
from gov import ed25519 as ed
from gov import reputation_ledger as rl


def _seed(label):
    return hashlib.sha256(("w246-lane7-unit:" + label).encode()).digest()


class DidKeyTest(unittest.TestCase):
    def test_resolve_shape(self):
        did = ai.resolve(ed.publickey(_seed("a")))
        self.assertTrue(did.startswith("did:key:z"), did)
        # 2-byte multicodec + 32-byte key -> fixed base58 length
        self.assertEqual(did, "did:key:z" + ai.b58encode(
            b"\xed\x01" + ed.publickey(_seed("a"))))

    def test_resolve_rejects_bad_key(self):
        for bad in (b"short", b"\x00" * 33, "not-bytes", None):
            with self.assertRaises(ai.DidKeyError) as ctx:
                ai.resolve(bad)
            self.assertEqual(ctx.exception.code, "did-key-malformed")

    def test_parse_round_trip(self):
        pub = ed.publickey(_seed("a"))
        self.assertEqual(ai.pubkey_from_did_key(ai.resolve(pub)), pub)

    def test_parse_wrong_method(self):
        with self.assertRaises(ai.DidKeyError) as ctx:
            ai.pubkey_from_did_key("did:example:abc")
        self.assertEqual(ctx.exception.code, "did-key-method-unsupported")

    def test_parse_malformed(self):
        for bad in ("did:key:z", "did:key:z!!!",
                    "did:key:" + ai.b58encode(b"\x00" * 5), 42, None):
            with self.assertRaises(ai.DidKeyError) as ctx:
                ai.pubkey_from_did_key(bad)
            self.assertEqual(ctx.exception.code, "did-key-malformed", bad)

    def test_verify_binding_contract(self):
        # bool contract pinned with `is True` / `is False` (wave-243).
        seed = _seed("a")
        did = ai.resolve(ed.publickey(seed))
        sig = ed.sign(seed, b"m")
        self.assertIs(ai.verify_binding(did, b"m", sig), True)
        self.assertIs(ai.verify_binding(did, b"m", ed.sign(
            _seed("b"), b"m")), False)
        self.assertIs(ai.verify_binding(did, b"other", sig), False)
        self.assertIs(ai.verify_binding(did, "m", sig), False)
        self.assertIs(ai.verify_binding(did, b"m", "sig"), False)
        self.assertIs(ai.verify_binding("bogus", b"m", sig), False)
        self.assertIs(ai.verify_binding(did, b"m", b"\x00" * 64), False)

    def test_b58_leading_zeros(self):
        # Regression: b"\x00" must encode as "1", not "11".
        self.assertEqual(ai.b58encode(b"\x00"), "1")
        self.assertEqual(ai.b58encode(b"\x00\x00"), "11")
        self.assertEqual(ai.b58encode(b""), "")
        for raw in (b"\x00", b"\x00\x00\x01\x02", bytes(range(64))):
            self.assertEqual(ai.b58decode(ai.b58encode(raw)), raw)


class ReputationLedgerTest(unittest.TestCase):
    def _ledger(self):
        seeds = {"alice": _seed("alice"), "bob": _seed("bob")}
        dids = {n: ai.resolve(ed.publickey(s)) for n, s in seeds.items()}
        ledger = rl.ReputationLedger()
        for subj, rep, kind in (("alice", "bob", "attestation-positive"),
                                ("alice", "bob", "incident-confirmed"),
                                ("bob", "alice", "recovery-verified")):
            ev = rl.make_event(ledger.next_seq(), dids[subj], dids[rep],
                               kind, "d", ledger.head_digest())
            ledger.append(rl.sign_event(ev, seeds[rep]))
        return ledger, seeds, dids

    def test_scores(self):
        ledger, _seeds, dids = self._ledger()
        self.assertEqual(ledger.reputation_for(dids["alice"]), 1 - 5)
        self.assertEqual(ledger.reputation_for(dids["bob"]), 3)
        self.assertEqual(ledger.reputation_for(dids["alice"]),
                         rl.compute_reputation(ledger.entries(),
                                               dids["alice"]))

    def test_score_clamp(self):
        entries = [{"subject": "did:key:zx", "kind": "incident-confirmed"}
                   for _ in range(100)]
        self.assertEqual(rl.compute_reputation(entries, "did:key:zx"), -100)

    def test_append_rejects_bad_sig(self):
        ledger, seeds, dids = self._ledger()
        ev = rl.make_event(ledger.next_seq(), dids["alice"], dids["bob"],
                           "attestation-positive", "d",
                           ledger.head_digest())
        signed = rl.sign_event(ev, seeds["bob"])
        signed["sig"] = "ff" * 64
        with self.assertRaises(rl.ReputationLedgerError) as ctx:
            ledger.append(signed)
        self.assertEqual(ctx.exception.code, "did-key-binding-invalid")

    def test_append_rejects_seq_gap(self):
        ledger, seeds, dids = self._ledger()
        ev = rl.make_event(ledger.next_seq() + 5, dids["alice"],
                           dids["bob"], "checkpoint", "d",
                           ledger.head_digest())
        with self.assertRaises(rl.ReputationLedgerError) as ctx:
            ledger.append(rl.sign_event(ev, seeds["bob"]))
        self.assertEqual(ctx.exception.code, "reputation-ledger-tampered")

    def test_sign_event_reporter_mismatch(self):
        ledger, seeds, dids = self._ledger()
        ev = rl.make_event(ledger.next_seq(), dids["alice"], dids["bob"],
                           "attestation-positive", "d",
                           ledger.head_digest())
        with self.assertRaises(rl.ReputationLedgerError) as ctx:
            rl.sign_event(ev, seeds["alice"])  # signed as alice, claims bob
        self.assertEqual(ctx.exception.code, "did-key-binding-invalid")

    def test_import_rejects_tamper(self):
        ledger, _seeds, _dids = self._ledger()
        blob = json.loads(ledger.export().decode())
        blob["entries"][1]["detail"] = "rewritten"
        with self.assertRaises(rl.ReputationLedgerError) as ctx:
            rl.ReputationLedger.import_bytes(json.dumps(
                blob, sort_keys=True, separators=(",", ":")).encode())
        self.assertEqual(ctx.exception.code, "reputation-ledger-tampered")

    def test_import_rejects_garbage(self):
        for bad in (b"not json", b'{"no": "entries"}', "str", None):
            with self.assertRaises(rl.ReputationLedgerError):
                rl.ReputationLedger.import_bytes(bad)

    def test_unknown_kind(self):
        ledger, seeds, dids = self._ledger()
        ev = rl.make_event(ledger.next_seq(), dids["alice"], dids["bob"],
                           "mega-vouch", "d", ledger.head_digest())
        with self.assertRaises(rl.ReputationLedgerError) as ctx:
            ledger.append(rl.sign_event(ev, seeds["bob"]))
        self.assertEqual(ctx.exception.code,
                         "reputation-event-kind-unknown")


if __name__ == "__main__":
    unittest.main()
