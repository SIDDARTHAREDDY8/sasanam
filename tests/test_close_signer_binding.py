"""Wave-236 lane A: close-record signer binding unit tests.

Boundary pins at the public seams of gov/close_signer_binding.py:
session-start pinning, digest binding, trust-id re-point, unsigned
scope reliance, close-record signature authentication against the
pinned root material, and the gov.log opt-in post-pass.
Deterministic, stdlib only, no network.
"""

import hashlib
import json
import os
import secrets
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w236-closebind-units")

from gov import close_signer_binding as cb  # noqa: E402
from gov import trust_material as tm  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402

# Real Ed25519 keypairs (deterministic seeds; fixtures only, never
# secrets). The trust root pins the PUBLIC keys; close records are
# signed with the seeds. SEED_C is the attacker's key.
_SEED_A = hashlib.sha256(b"w236-closebind-seed-a").digest()
_SEED_B = hashlib.sha256(b"w236-closebind-seed-b").digest()
_SEED_C = hashlib.sha256(b"w236-closebind-seed-c").digest()
_PUB_A = _ed.publickey(_SEED_A)
_PUB_B = _ed.publickey(_SEED_B)
_PUB_C = _ed.publickey(_SEED_C)


def _body_digest(body):
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _record(signer_id, seq, **kw):
    rec = {"signer_id": signer_id, "digest": _body_digest({"seq": seq}),
           "signed_fields": ("seq",)}
    rec.update(kw)
    return rec


def _chain(signer="key-a", n=3):
    return [_record(signer, i) for i in range(n)]


def _close(chain, signer="key-a", seed=_SEED_A, material=_PUB_A,
           fields=("seq",)):
    """A genuinely signed close record: ed_sig over the sig body."""
    rec = {"signer_id": signer, "key_material": material,
           "chain_digest": cb.canonical_chain_digest(chain),
           "signed_fields": tuple(fields)}
    rec["ed_sig"] = _ed.sign(seed, cb.close_sig_body(rec)).hex()
    return rec


def _root():
    return tm.TrustRoot({"key-a": _PUB_A, "key-b": _PUB_B})


class CloseSignerBindingTest(unittest.TestCase):
    def test_mismatch_names_expected_and_observed(self):
        chain = _chain("key-a")
        # key-b's signature is VALID; the binding still refuses by name.
        close = _close(chain, signer="key-b", seed=_SEED_B, material=_PUB_B)
        with self.assertRaises(cb.CloseSignerBindingError) as ctx:
            cb.verify_close_record(chain, close, trust_root=_root())
        self.assertEqual(ctx.exception.code, "close-signer-mismatch")
        self.assertIn("key-a", ctx.exception.detail)
        self.assertIn("key-b", ctx.exception.detail)

    def test_listed_key_does_not_excuse_mismatch(self):
        # key-b IS pinned in the trust root; the binding still refuses.
        chain = _chain("key-a")
        close = _close(chain, signer="key-b", seed=_SEED_B, material=_PUB_B)
        with self.assertRaises(cb.CloseSignerBindingError) as ctx:
            cb.verify_close_record(chain, close, trust_root=_root())
        self.assertEqual(ctx.exception.code, "close-signer-mismatch")

    def test_trust_id_repoint_refused(self):
        chain = _chain("key-a")
        close = _close(chain, signer="key-a", seed=_SEED_C, material=_PUB_C)
        with self.assertRaises(cb.CloseSignerBindingError) as ctx:
            cb.verify_close_record(chain, close, trust_root=_root())
        self.assertEqual(ctx.exception.code, "close-trust-repointed")

    def test_unsigned_scope_refused(self):
        chain = _chain("key-a")
        close = _close(chain, fields=("seq",))
        with self.assertRaises(cb.CloseSignerBindingError) as ctx:
            cb.verify_close_record(chain, close, trust_root=_root(),
                                   relied_scope_fields=("approval_limit",))
        self.assertEqual(ctx.exception.code, "close-unsigned-scope")

    def test_covered_scope_accepted(self):
        chain = _chain("key-a")
        close = _close(chain, fields=("seq", "approval_limit"))
        verdict = cb.verify_close_record(
            chain, close, trust_root=_root(),
            relied_scope_fields=("approval_limit",))
        self.assertTrue(verdict["ok"])

    def test_chain_digest_mismatch(self):
        chain = _chain("key-a")
        close = _close(chain)
        tampered = [dict(r) for r in chain]
        tampered[1] = _record("key-a", 1)
        tampered[1]["digest"] = "ff" * 32  # byte-different record
        with self.assertRaises(cb.CloseSignerBindingError) as ctx:
            cb.verify_close_record(tampered, close)
        self.assertEqual(ctx.exception.code, "close-chain-digest-mismatch")

    def test_legitimate_close_verifies(self):
        chain = _chain("key-a")
        close = _close(chain)
        verdict = cb.verify_close_record(chain, close, trust_root=_root())
        self.assertTrue(verdict["ok"])
        self.assertEqual(verdict["session_start_signer"], "key-a")
        self.assertEqual(verdict["close_signer"], "key-a")
        self.assertEqual(verdict["chain_digest"],
                         cb.canonical_chain_digest(chain))

    def test_legitimate_close_without_trust_root(self):
        # Trust binding is opt-in; without a root the identity checks
        # still hold (signature authentication is documented as
        # requiring the root).
        chain = _chain("key-a")
        close = _close(chain)
        self.assertTrue(cb.verify_close_record(chain, close)["ok"])

    def test_forged_close_signature_refused(self):
        # Forgery: claims "key-a" and carries the CORRECT pinned
        # material, but is signed by the attacker's key. The binding
        # authenticates against the root's pinned material, never the
        # record's self-assertion.
        chain = _chain("key-a")
        close = _close(chain, signer="key-a", seed=_SEED_C, material=_PUB_A)
        with self.assertRaises(cb.CloseSignerBindingError) as ctx:
            cb.verify_close_record(chain, close, trust_root=_root())
        self.assertEqual(ctx.exception.code, "close-signature-invalid")

    def test_missing_sig_with_root_is_malformed(self):
        chain = _chain("key-a")
        close = _close(chain)
        del close["ed_sig"]
        with self.assertRaises(cb.CloseSignerBindingError) as ctx:
            cb.verify_close_record(chain, close, trust_root=_root())
        self.assertEqual(ctx.exception.code, "close-record-malformed")

    def test_sig_body_excludes_ed_sig(self):
        # The signature never covers itself: the sig body of a signed
        # record verifies against the pinned pubkey.
        chain = _chain("key-a")
        close = _close(chain)
        body = cb.close_sig_body(close)
        self.assertTrue(
            _ed.verify(_PUB_A, body, bytes.fromhex(close["ed_sig"])))

    def test_empty_chain_malformed(self):
        with self.assertRaises(cb.CloseSignerBindingError) as ctx:
            cb.verify_close_record([], _close(_chain()))
        self.assertEqual(ctx.exception.code, "close-record-malformed")

    def test_absent_session_signer(self):
        chain = [_record(None, 0)]
        close = {"signer_id": "key-a",
                 "chain_digest": cb.canonical_chain_digest(chain),
                 "signed_fields": ()}
        with self.assertRaises(cb.CloseSignerBindingError) as ctx:
            cb.verify_close_record(chain, close)
        self.assertEqual(ctx.exception.code, "close-signer-absent")

    def test_malformed_close_record(self):
        chain = _chain("key-a")
        with self.assertRaises(cb.CloseSignerBindingError) as ctx:
            cb.verify_close_record(chain, {"signer_id": "key-a"})
        self.assertEqual(ctx.exception.code, "close-record-malformed")

    def test_unpinned_close_signer(self):
        chain = _chain("key-a")
        close = _close(chain)
        # Session signer matches; the EXTERNAL root knows no "key-a".
        root = tm.TrustRoot({"other": _PUB_B})
        with self.assertRaises(cb.CloseSignerBindingError) as ctx:
            cb.verify_close_record(chain, close, trust_root=root)
        self.assertEqual(ctx.exception.code, "untrusted-key")

    def test_session_start_is_positional(self):
        # First record unsigned while later records are signed: the
        # binding refuses absent-signer rather than skipping to a later
        # signed record.
        chain = [_record(None, 0)] + [_record("key-a", i) for i in (1, 2)]
        close = {"signer_id": "key-a",
                 "chain_digest": cb.canonical_chain_digest(chain),
                 "signed_fields": ()}
        with self.assertRaises(cb.CloseSignerBindingError) as ctx:
            cb.verify_close_record(chain, close)
        self.assertEqual(ctx.exception.code, "close-signer-absent")

    def test_digest_is_order_sensitive(self):
        a = _chain("key-a", n=2)
        b = list(reversed(a))
        self.assertNotEqual(cb.canonical_chain_digest(a),
                            cb.canonical_chain_digest(b))


class LogSeamTest(unittest.TestCase):
    def test_default_verify_chain_unchanged(self):
        from gov import log as _log
        import tempfile
        tmp = tempfile.mkdtemp(prefix="closebind-unit-")
        path = os.path.join(tmp, "audit.log")
        lg = _log.ActionLog(path)
        lg.append({"op": "u1"})
        before = _log.verify_chain(path)
        after = _log.verify_chain(path, require_close_binding=False)
        self.assertEqual(before, after)
        self.assertTrue(before[0])

    def test_optin_fails_closed_on_signerless_log(self):
        from gov import log as _log
        import tempfile
        tmp = tempfile.mkdtemp(prefix="closebind-unit-")
        path = os.path.join(tmp, "audit.log")
        lg = _log.ActionLog(path)
        lg.append({"op": "u1"})
        parsed = []
        with open(path, encoding="utf-8") as fh:
            parsed = [json.loads(l) for l in fh.read().splitlines()
                      if l.strip()]
        records = cb.adapt_log_entries(parsed)
        v = _log._verify(
            path, require_close_binding=True,
            close_record={"signer_id": "key-a",
                          "key_material": _PUB_A,
                          "chain_digest": cb.canonical_chain_digest(records),
                          "signed_fields": ()})
        self.assertFalse(v["ok"])
        self.assertIn("close-signer-absent", v["error"])


if __name__ == "__main__":
    unittest.main()
