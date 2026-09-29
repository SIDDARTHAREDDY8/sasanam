"""Unit tests for the deploy-time trust configuration layer
(wave-202 lane C).

Covers: strict body builders/validation, mint/activate roundtrip,
version floor, supersede chain, handoff ceremony (required/invalid),
revocation loudness, grace windows, class threshold, the
PackLoader guard closure, the unsigned opt-out ceremony and its
hash-chained audit log, and the manifest trust helper.

$0 spend, synthetic/local deterministic only. No network.
"""

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import deploy_trust_config as dtc  # noqa: E402
from gov import rule_pack as rp  # noqa: E402
from gov.keyset import (  # noqa: E402
    new_keyset,
    keyset_signer_for_version,
    rotate_keyset,
)

_SEED_ROOT = bytes.fromhex("51" * 32)
_SEED_PACK = bytes.fromhex("52" * 32)
_SEED_PACK2 = bytes.fromhex("53" * 32)

ISSUED = "2026-09-01T00:00:00+00:00"
EXPIRES = "2030-01-01T00:00:00+00:00"
NOW = "2026-10-01T00:00:00+00:00"
LATER = "2027-06-01T00:00:00+00:00"

MEMBERS = {"m.yml": b"m: 1\n"}


def _digests(members):
    return {mid: "sha256:" + hashlib.sha256(data).hexdigest()
            for mid, data in members.items()}


class TrustConfigTest(unittest.TestCase):
    def setUp(self):
        self.root_keyset, _ = new_keyset(
            _SEED_ROOT, purpose=dtc.KEYSET_PURPOSE_DEPLOY_TRUST)
        self.root_signer = keyset_signer_for_version(
            self.root_keyset, 1, _SEED_ROOT)
        self.pack_keyset, _ = new_keyset(
            _SEED_PACK, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
        self.pack_signer = keyset_signer_for_version(
            self.pack_keyset, 1, _SEED_PACK)
        self.kid = self.pack_signer.key_id
        self.pubhex = self.pack_signer.public_key.hex()

    # -- builders ------------------------------------------------------
    def _root(self, kid=None):
        return dtc.make_trust_root(kid or self.kid, 1, self.pubhex)

    def _class(self, **kw):
        kw.setdefault("policy", "signed-only")
        kw.setdefault("trust_roots", [self._root()])
        return dtc.make_class_config(**kw)

    def _body(self, **kw):
        kw.setdefault("config_version", 1)
        kw.setdefault("issued_at", ISSUED)
        kw.setdefault("expires_at", EXPIRES)
        kw.setdefault("classes", {"capability_rules": self._class()})
        return dtc.make_config_body(**kw)

    def _mint(self, body=None, version=None, **kw):
        body = body or self._body()
        version = body["config_version"] if version is None else version
        kw.setdefault("issued_at", ISSUED)
        kw.setdefault("expires_at", EXPIRES)
        kw.setdefault("threshold", 1)
        doc = dtc.mint_trust_config(
            self.root_keyset, [self.root_signer], body=body,
            pack_version=version, **kw)
        return doc, dtc.canonical_trust_config_json(body).encode("utf-8")

    def _registry(self, body=None, **kw):
        reg = dtc.TrustConfigRegistry(self.root_keyset)
        doc, body_bytes = self._mint(body, **kw)
        reg.activate(doc, body_bytes, now=NOW)
        return reg

    def _loader(self, registry, pack_class="capability_rules",
                keyset=None):
        return dtc.TrustedPackLoader(
            keyset or self.pack_keyset, "test-pack", registry=registry,
            pack_class=pack_class)

    def _pack_doc(self, keyset=None, signer=None, version=1,
                  members=MEMBERS):
        return rp.mint_rule_pack(
            keyset or self.pack_keyset, [signer or self.pack_signer],
            rules=_digests(members), pack_version=version,
            issued_at=ISSUED, expires_at=EXPIRES, threshold=1)

    # -- strict validation ----------------------------------------------
    def test_unknown_policy_refused(self):
        with self.assertRaises(dtc.TrustConfigError):
            self._class(policy="yolo")

    def test_empty_trust_roots_refused(self):
        with self.assertRaises(dtc.TrustConfigError):
            dtc.make_class_config(policy="signed-only", trust_roots=[])

    def test_bad_pubkey_refused(self):
        with self.assertRaises(dtc.TrustConfigError):
            dtc.make_trust_root(self.kid, 1, "not-hex")

    def test_unknown_body_field_refused(self):
        body = self._body()
        body["surprise"] = 1
        with self.assertRaises(dtc.TrustConfigError):
            dtc.validate_trust_config_body(body)

    def test_unknown_class_field_refused(self):
        cfg = self._class()
        cfg["surprise"] = 1
        with self.assertRaises(dtc.TrustConfigError):
            dtc.make_config_body(
                config_version=1, issued_at=ISSUED, expires_at=EXPIRES,
                classes={"capability_rules": cfg})

    def test_grace_without_until_refused(self):
        with self.assertRaises(dtc.TrustConfigError):
            dtc.make_class_config(
                policy="signed-only", trust_roots=[self._root()],
                grace_roots=[self._root()], grace_until=None)

    def test_threshold_above_roots_refused(self):
        with self.assertRaises(dtc.TrustConfigError):
            self._class(threshold=2)

    def test_pack_version_must_match_body(self):
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            self._mint(version=9)
        self.assertEqual(ctx.exception.code, "config-version-mismatch")

    def test_wrong_keyset_purpose_refused(self):
        with self.assertRaises(dtc.TrustConfigError):
            dtc.TrustConfigRegistry(self.pack_keyset)

    # -- registry ---------------------------------------------------------
    def test_activate_ok(self):
        reg = self._registry()
        self.assertEqual(reg.current.config_version, 1)
        self.assertEqual(reg.current.signing_kids,
                         [self.root_signer.key_id])

    def test_genesis_with_supersedes_refused(self):
        # The builder enforces it: supersedes must name an OLDER
        # version, so a genesis config cannot claim a predecessor.
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            self._body(supersedes=1)
        self.assertEqual(ctx.exception.code, "config-body-malformed")
        # And a fresh registry refuses a v2 naming a phantom
        # predecessor (genesis must be clean).
        body = self._body(config_version=2, supersedes=1)
        doc, body_bytes = self._mint(body, version=2)
        reg = dtc.TrustConfigRegistry(self.root_keyset)
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            reg.activate(doc, body_bytes, now=NOW)
        self.assertEqual(ctx.exception.code, "config-supersede-break")
        self.assertIsNone(reg.current)

    def test_supersede_chain_enforced(self):
        reg = self._registry()
        body2 = self._body(config_version=2, supersedes=1)
        doc2, body2_bytes = self._mint(body2, version=2)
        reg.activate(doc2, body2_bytes, now=NOW)
        self.assertEqual(reg.current.config_version, 2)
        # skipping the chain is refused
        body3 = self._body(config_version=3, supersedes=1)
        doc3, body3_bytes = self._mint(body3, version=3)
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            reg.activate(doc3, body3_bytes, now=NOW)
        self.assertEqual(ctx.exception.code, "config-supersede-break")
        self.assertEqual(reg.current.config_version, 2)

    def test_extra_member_in_config_pack_refused(self):
        body = self._body()
        body_bytes = dtc.canonical_trust_config_json(body).encode()
        rules = {dtc.TRUST_CONFIG_MEMBER:
                 "sha256:" + hashlib.sha256(body_bytes).hexdigest(),
                 "extra": "sha256:" + "00" * 32}
        doc = rp.mint_rule_pack(
            self.root_keyset, [self.root_signer], rules=rules,
            pack_version=1, issued_at=ISSUED, expires_at=EXPIRES,
            threshold=1, purpose=dtc.KEYSET_PURPOSE_DEPLOY_TRUST,
            format_tag=dtc.TRUST_CONFIG_FORMAT)
        reg = dtc.TrustConfigRegistry(self.root_keyset)
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            reg.activate(doc, body_bytes, now=NOW)
        self.assertEqual(ctx.exception.code, "config-extra-member")

    def test_handoff_cannot_cover_itself(self):
        # The handoff digest is over the body with handoff nulled.
        body = self._body()
        d1 = dtc.body_digest_for_handoff(body)
        body["handoff"] = {"prev_config_version": 1,
                           "new_body_digest": d1,
                           "authorized_by": [self.kid],
                           "signatures": []}
        d2 = dtc.body_digest_for_handoff(body)
        self.assertEqual(d1, d2)

    def test_handoff_wrong_body_digest_refused(self):
        reg = self._registry()
        body2 = self._body(config_version=2, supersedes=1,
                           classes={"capability_rules": self._class(
                               trust_roots=[dtc.make_trust_root(
                                   "other-kid", 1, "ab" * 32)])})
        handoff = dtc.sign_handoff(
            self.pack_signer, prev_config_version=1,
            new_body_digest="ab" * 32)  # wrong digest, valid shape
        body2["handoff"] = handoff
        doc2, body2_bytes = self._mint(body2, version=2)
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            reg.activate(doc2, body2_bytes, now=NOW)
        self.assertEqual(ctx.exception.code, "handoff-invalid")

    def test_handoff_by_non_root_refused(self):
        reg = self._registry()
        stranger, _ = new_keyset(bytes.fromhex("99" * 32),
                                 purpose=rp.KEYSET_PURPOSE_RULE_PACK)
        stranger_signer = keyset_signer_for_version(stranger, 1,
                                                    bytes.fromhex("99" * 32))
        body2 = self._body(config_version=2, supersedes=1,
                           classes={"capability_rules": self._class(
                               trust_roots=[dtc.make_trust_root(
                                   "other-kid", 1, "ab" * 32)])})
        handoff = dtc.sign_handoff(
            stranger_signer, prev_config_version=1,
            new_body_digest=dtc.body_digest_for_handoff(body2))
        body2["handoff"] = handoff
        doc2, body2_bytes = self._mint(body2, version=2)
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            reg.activate(doc2, body2_bytes, now=NOW)
        self.assertEqual(ctx.exception.code, "handoff-invalid")

    # -- loader -----------------------------------------------------------
    def test_present_ok(self):
        reg = self._registry()
        active = self._loader(reg).present(
            self._pack_doc(), dict(MEMBERS), now=NOW)
        self.assertEqual(active.member("m.yml"), MEMBERS["m.yml"])

    def test_class_threshold_enforced(self):
        # Two trust roots, class threshold 2: a pack signed by only
        # one of them is refused.
        ks2, signer2 = rotate_keyset(self.pack_keyset,
                                     _SEED_PACK2, _SEED_PACK)
        kid2 = signer2.key_id
        cls = dtc.make_class_config(
            policy="signed-only",
            trust_roots=[self._root(),
                         dtc.make_trust_root(
                             kid2, 2, signer2.public_key.hex())],
            threshold=2)
        body = self._body(classes={"capability_rules": cls})
        reg = self._registry(body)
        loader = self._loader(reg, keyset=ks2)
        doc = rp.mint_rule_pack(
            ks2, [self.pack_signer], rules=_digests(MEMBERS),
            pack_version=1, issued_at=ISSUED, expires_at=EXPIRES,
            threshold=1)
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            loader.present(doc, dict(MEMBERS), now=NOW)
        self.assertEqual(ctx.exception.code, "trust-threshold-unmet")

    def test_guard_closure_compatible_with_pack_loader(self):
        from gov.pack_loader import PackLoader
        reg = self._registry()
        inner = PackLoader(self.pack_keyset, "guard-probe")
        active = inner.present(
            self._pack_doc(), dict(MEMBERS),
            guard=reg.pack_guard("capability_rules", NOW), now=NOW)
        self.assertIsNotNone(active)
        # ...and denies a pack signed outside the trust roots
        ks2, signer2 = rotate_keyset(self.pack_keyset,
                                     _SEED_PACK2, _SEED_PACK)
        inner2 = PackLoader(ks2, "guard-probe-2")
        other = rp.mint_rule_pack(
            ks2, [signer2], rules=_digests(MEMBERS), pack_version=1,
            issued_at=ISSUED, expires_at=EXPIRES, threshold=1)
        from gov.pack_loader import PackActivationError
        with self.assertRaises(PackActivationError) as ctx:
            inner2.present(
                other, dict(MEMBERS),
                guard=reg.pack_guard("capability_rules", NOW), now=NOW)
        self.assertEqual(ctx.exception.code, "pack-activation-denied")
        self.assertIn("trust-root-unknown", ctx.exception.detail)

    def test_grace_window_honored(self):
        ks2, signer2 = rotate_keyset(self.pack_keyset,
                                     _SEED_PACK2, _SEED_PACK)
        kid2 = signer2.key_id
        cls = dtc.make_class_config(
            policy="signed-only",
            trust_roots=[dtc.make_trust_root(
                kid2, 2, signer2.public_key.hex())],
            grace_roots=[self._root()], grace_until=LATER)
        body = self._body(classes={"capability_rules": cls})
        reg = self._registry(body)
        loader = self._loader(reg, keyset=ks2)
        old_doc = self._pack_doc(keyset=ks2, signer=self.pack_signer,
                                 version=1)
        # inside the window: old root accepted
        loader.present(old_doc, dict(MEMBERS), now=NOW)
        # after the window: refused
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            loader.present(
                self._pack_doc(keyset=ks2, signer=self.pack_signer,
                               version=2),
                dict(MEMBERS), now="2028-01-01T00:00:00+00:00")
        self.assertEqual(ctx.exception.code, "trust-root-unknown")

    # -- unsigned opt-out ---------------------------------------------------
    def _opt_out_env(self, policy="loud-opt-out"):
        reg = self._registry(self._body(
            classes={"capability_rules": self._class(policy=policy)}))
        tmp = tempfile.TemporaryDirectory(prefix="g202c-ut-")
        self.addCleanup(tmp.cleanup)
        log = dtc.UnsignedOptOutLog(
            os.path.join(tmp.name, "optout.jsonl"))
        return reg, log

    def test_opt_out_log_chain(self):
        _, log = self._opt_out_env()
        log.record(pack_class="c", member_digests={"m": "sha256:" + "aa" * 32},
                   operators=["alice", "bob"], proposal_digest="bb" * 32,
                   outcome="allowed", at=NOW)
        log.record(pack_class="c", member_digests={"m": "sha256:" + "aa" * 32},
                   operators=["alice"], proposal_digest="cc" * 32,
                   outcome="refused:quorum-unmet", at=NOW)
        self.assertTrue(log.verify())
        records = log.read_all()
        self.assertEqual([r["seq"] for r in records], [1, 2])
        self.assertEqual(records[1]["prev_hash"],
                         records[0]["entry_hash"])

    def test_opt_out_log_tamper_detected(self):
        _, log = self._opt_out_env()
        log.record(pack_class="c", member_digests={}, operators=["a", "b"],
                   proposal_digest="bb" * 32, outcome="allowed", at=NOW)
        with open(log.path, "ab") as fh:
            fh.write(b'{"seq": 99, "bogus": true}\n')
        self.assertFalse(log.verify())

    def test_opt_out_ceremony_steps(self):
        reg, log = self._opt_out_env()
        ceremony = dtc.UnsignedOptOut(reg, "capability_rules", log,
                                      now=NOW)
        proposal = ceremony.propose(dict(MEMBERS))
        digest = proposal["proposal_digest"]
        ceremony.ack(digest, "alice")
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            ceremony.execute(digest)
        self.assertEqual(ctx.exception.code, "opt-out-quorum-unmet")
        ceremony.ack(digest, "bob")
        active = ceremony.execute(digest)
        self.assertEqual(active.member("m.yml"), MEMBERS["m.yml"])
        self.assertEqual(active.audit_seq, 2)  # refusal recorded first
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            ceremony.execute(digest)
        self.assertEqual(ctx.exception.code, "opt-out-consumed")

    def test_opt_out_unknown_proposal(self):
        reg, log = self._opt_out_env()
        ceremony = dtc.UnsignedOptOut(reg, "capability_rules", log,
                                      now=NOW)
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            ceremony.ack("00" * 64, "alice")
        self.assertEqual(ctx.exception.code, "opt-out-unknown-proposal")

    def test_opt_out_wrong_policy(self):
        reg, log = self._opt_out_env(policy="signed-only")
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            dtc.UnsignedOptOut(reg, "capability_rules", log, now=NOW)
        self.assertEqual(ctx.exception.code, "unsigned-refused")

    def test_present_unsigned_rejects_bare_string_operators(self):
        # A bare string must not splinter into one-letter operators
        # and quietly satisfy quorum.
        reg, log = self._opt_out_env()
        loader = dtc.TrustedPackLoader(
            self.pack_keyset, "test-pack", registry=reg,
            pack_class="capability_rules")
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            loader.present_unsigned(dict(MEMBERS), operators="alice",
                                    opt_out_log=log, now=NOW)
        self.assertEqual(ctx.exception.code, "bad-operators")

    # -- manifest helper ----------------------------------------------------
    def test_check_manifest_trust(self):
        reg = self._registry()
        self.assertIsNone(dtc.check_manifest_trust(
            reg, "capability_rules", [self.kid], now=NOW))
        with self.assertRaises(dtc.TrustConfigError) as ctx:
            dtc.check_manifest_trust(
                reg, "capability_rules", ["nope"], now=NOW)
        self.assertEqual(ctx.exception.code, "trust-root-unknown")


if __name__ == "__main__":
    unittest.main()
