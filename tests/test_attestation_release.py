#!/usr/bin/env python3
"""Unit tests for wave-198: attestation-conditioned credential release.

Public seams only:
  - gov.attestation_release: attest_release / verify_attestation /
    AttestationReleaseConfig / evaluate_release / operator-signed
    policy overrides / audit-event helpers
  - gov.sentinel_substitution: register (credential_class +
    release_policy), validate_sentinel_binding (attestation pre-check),
    substitute_for_execution (authoritative per-release evaluation)
  - gov.executor: attestation_config wiring, register_attestation,
    _resolve_attestation, attempt-path fail-closed integration

Stdlib only. $0 spend. Deterministic seeds and explicit at/now wherever
the seam accepts them; the two executor integration tests mint against
the wall clock (300s TTL, millisecond-scale runs).

The red-first battery (evals/attestation_release_probes.py) owns the
adversarial shapes; these tests pin the contract details.
"""

import hashlib
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import attestation_release as ar  # noqa: E402
from gov import sentinel_substitution as _sentinel  # noqa: E402
from gov.keyset import (  # noqa: E402
    Keyset,
    KeysetError,
    keyset_signer_for_version,
    new_keyset,
    rotate_keyset,
    revoke_version,
)
from gov.cosign_attest import keyset_hash_at_version  # noqa: E402

ISSUER = "attestation-service-1"
ROGUE_ISSUER = "rogue-issuer"
AGENT = "agent-1"
PRINCIPAL = "user-1"
RUN = "run-1"
CLASS = "db-password"
CRED_ID = "db-cred"
REAL_DB = "tok_synth_db_9f2c4a1b7e"  # DLP-clean synthetic credential
DB_HOST = "db.internal"

AT = 1_800_000_000  # fixed time anchor; tests pass now= explicitly


def _seed(tag):
    return hashlib.sha256(("wave198-ut-" + tag).encode()).digest()


def _keyset(tag="issuer"):
    ks, _ = new_keyset(_seed(tag), purpose=ar.ATTESTATION_PURPOSE)
    return ks


def _override_keyset(tag="override-op"):
    ks, _ = new_keyset(_seed(tag), purpose=ar.OVERRIDE_PURPOSE)
    return ks


def _config(ks=None, issuers=(ISSUER,)):
    return ar.AttestationReleaseConfig(
        keyset_doc=(ks or _keyset()).to_dict(),
        trusted_issuers=set(issuers))


def _mint(ks, seed_tag="issuer", **kw):
    params = dict(sub=AGENT, iss=ISSUER, agent_scope=[CLASS],
                  session={"agent_id": AGENT, "run_id": RUN},
                  status="affirming", ttl_seconds=300, at=AT)
    params.update(kw)
    return ar.attest_release(ks, _seed(seed_tag), **params)


def _resign(ks, seed_tag, body):
    """Re-sign a (possibly tampered) token body with the keyset's
    primary -- the white-box way to craft tokens minting refuses
    (over-long TTL, empty classes, wrong aud)."""
    signer = keyset_signer_for_version(ks, ks.primary_version,
                                       _seed(seed_tag))
    body = dict(body)
    body["attested_by"] = {
        "purpose": ar.ATTESTATION_PURPOSE,
        "keyset_key_id": signer.key_id,
        "keyset_version": signer.key_version,
        "keyset_hash": keyset_hash_at_version(ks, signer.key_version),
    }
    sig = signer.sign(ar.ATTESTATION_DOMAIN
                      + ar._canonical(body)).hex()
    body["envelope"] = {"sig_key_id": signer.key_id,
                        "sig_key_version": signer.key_version,
                        "sig": sig}
    return body


def _vault(policy="attested", cred_class=CLASS, cred_id=CRED_ID):
    vault = _sentinel.SentinelVault()
    sentinel = vault.register(cred_id, REAL_DB, [DB_HOST],
                              credential_class=cred_class,
                              release_policy=policy)
    return vault, sentinel


def _identity(agent_id=AGENT, run_id=RUN):
    return types.SimpleNamespace(agent_id=agent_id, principal=PRINCIPAL,
                                 role="agent", run_id=run_id)


def _release(vault, sentinel, token, *, config, now=AT + 10,
             agent_id=AGENT, run_id=RUN, audit=None, **kw):
    """Drive the execution-boundary seam. Returns
    (outcome, detail, audit)."""
    args = {"url": "https://%s/query" % DB_HOST, "api_key": sentinel}
    audit = [] if audit is None else audit
    try:
        new_args, _vals = _sentinel.substitute_for_execution(
            vault, "http_post", args, identity=_identity(agent_id, run_id),
            attestation=token, release_config=config, audit_log=audit,
            run_id=run_id, now=now, **kw)
    except _sentinel.SentinelError as e:
        return "denied", str(e), audit
    if new_args.get("api_key") == REAL_DB:
        return "allowed", new_args, audit
    return "denied", "no substitution (args unchanged)", audit


def _denied_loud(audit):
    return any(isinstance(e, dict)
               and e.get("event") == "attestation_release"
               and e.get("verdict") == "denied" for e in audit)


# ---------------------------------------------------------------------------
# AttestationReleaseConfig
# ---------------------------------------------------------------------------

class TestConfig(unittest.TestCase):
    def test_wrong_purpose_keyset_refused(self):
        ks, _ = new_keyset(_seed("audit"), purpose="audit-entry-signing")
        with self.assertRaises(ar.AttestationReleaseError):
            ar.AttestationReleaseConfig(keyset_doc=ks.to_dict(),
                                        trusted_issuers={ISSUER})

    def test_empty_issuers_refused(self):
        with self.assertRaises(ar.AttestationReleaseError):
            _config(issuers=set())

    def test_invalid_keyset_doc_refused(self):
        with self.assertRaises(ar.AttestationReleaseError):
            ar.AttestationReleaseConfig(keyset_doc={"bogus": 1},
                                        trusted_issuers={ISSUER})

    def test_register_lookup_revoke(self):
        ks = _keyset()
        cfg = _config(ks)
        self.assertIsNone(cfg.attestation_for(AGENT))
        tok = _mint(ks)
        cfg.register_attestation(AGENT, tok)
        self.assertEqual(cfg.attestation_for(AGENT), tok)
        self.assertTrue(cfg.revoke_attestation(AGENT))
        self.assertIsNone(cfg.attestation_for(AGENT))
        self.assertFalse(cfg.revoke_attestation(AGENT))

    def test_register_rejects_non_dict(self):
        cfg = _config()
        with self.assertRaises(ar.AttestationReleaseError):
            cfg.register_attestation(AGENT, "not-a-dict")

    def test_jti_cache(self):
        cfg = _config()
        self.assertFalse(cfg.jti_seen("j1"))
        cfg.mark_jti("j1")
        self.assertTrue(cfg.jti_seen("j1"))

    def test_set_override_verifies_at_install(self):
        cfg = _config()
        oks = _override_keyset()
        good = ar.mint_policy_override(oks, _seed("override-op"),
                                      agent_scope=[CLASS],
                                      window_seconds=600,
                                      reason="incident-7",
                                      at=AT)
        cfg.set_policy_override(good, oks.to_dict(), now=AT)
        self.assertIsNotNone(cfg.policy_override)
        # Tampered override is refused AT INSTALL, never consulted.
        bad = dict(good)
        env = dict(bad["envelope"])
        env["sig"] = "00" * 64
        bad["envelope"] = env
        with self.assertRaises(ar.AttestationReleaseError):
            cfg.set_policy_override(bad, oks.to_dict(), now=AT)
        cfg.clear_policy_override()
        self.assertIsNone(cfg.policy_override)


# ---------------------------------------------------------------------------
# Minting
# ---------------------------------------------------------------------------

class TestMint(unittest.TestCase):
    def test_round_trip(self):
        ks = _keyset()
        tok = _mint(ks)
        ok, details = ar.verify_attestation(tok, ks.to_dict())
        self.assertTrue(ok, details)
        self.assertEqual(details["sub"], AGENT)
        self.assertEqual(details["iss"], ISSUER)
        self.assertEqual(details["status"], "affirming")
        self.assertEqual(details["agent_scope"], [CLASS])
        self.assertEqual(details["session"],
                         {"agent_id": AGENT, "run_id": RUN})

    def test_wrong_purpose_keyset_cannot_mint(self):
        ks, _ = new_keyset(_seed("audit"), purpose="audit-entry-signing")
        with self.assertRaises(ar.AttestationReleaseError):
            ar.attest_release(ks, _seed("audit"), sub=AGENT, iss=ISSUER,
                              agent_scope=[CLASS],
                              session={"agent_id": AGENT, "run_id": RUN})

    def test_ttl_bound(self):
        ks = _keyset()
        with self.assertRaises(ar.AttestationReleaseError):
            _mint(ks, ttl_seconds=301)
        with self.assertRaises(ar.AttestationReleaseError):
            _mint(ks, ttl_seconds=0)
        tok = _mint(ks, ttl_seconds=300)  # boundary is inclusive
        self.assertEqual(tok["exp"] - tok["iat"], 300)

    def test_empty_classes_refused(self):
        ks = _keyset()
        with self.assertRaises(ar.AttestationReleaseError):
            _mint(ks, agent_scope=[])
        with self.assertRaises(ar.AttestationReleaseError):
            _mint(ks, agent_scope=[""])

    def test_bad_status_refused(self):
        ks = _keyset()
        with self.assertRaises(ar.AttestationReleaseError):
            _mint(ks, status="maybe")

    def test_bad_session_refused(self):
        ks = _keyset()
        with self.assertRaises(ar.AttestationReleaseError):
            _mint(ks, session={"agent_id": AGENT})  # missing run_id
        with self.assertRaises(ar.AttestationReleaseError):
            _mint(ks, session="not-a-dict")

    def test_verify_only_seed_cannot_mint(self):
        ks = _keyset("rot")
        ks2, _ = rotate_keyset(ks, _seed("rot-new"), _seed("rot"))
        # The old primary's seed no longer mints (verify-only now).
        with self.assertRaises(ar.AttestationReleaseError):
            ar.attest_release(ks2, _seed("rot"), sub=AGENT, iss=ISSUER,
                              agent_scope=[CLASS],
                              session={"agent_id": AGENT, "run_id": RUN},
                              version=1)
        # The new primary mints fine.
        tok = ar.attest_release(ks2, _seed("rot-new"), sub=AGENT,
                                iss=ISSUER, agent_scope=[CLASS],
                                session={"agent_id": AGENT, "run_id": RUN},
                                version=2)
        ok, _ = ar.verify_attestation(tok, ks2.to_dict())
        self.assertTrue(ok)

    def test_explicit_jti(self):
        ks = _keyset()
        tok = _mint(ks, jti="jti-1")
        self.assertEqual(tok["jti"], "jti-1")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

class TestVerify(unittest.TestCase):
    def test_exact_format_required(self):
        ks = _keyset()
        tok = _mint(ks)
        tok["format"] = "sasanam-attestation-release/v2"
        ok, reason = ar.verify_attestation(tok, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("format", reason)

    def test_unknown_fields_refused(self):
        ks = _keyset()
        tok = _mint(ks)
        tok["extra"] = "nope"
        ok, reason = ar.verify_attestation(tok, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("unknown fields", reason)

    def test_tampered_signature_refused(self):
        ks = _keyset()
        tok = _mint(ks)
        env = dict(tok["envelope"])
        env["sig"] = "00" * 64
        tok["envelope"] = env
        ok, reason = ar.verify_attestation(tok, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_tampered_claim_refused(self):
        ks = _keyset()
        tok = _mint(ks)
        tok["agent_scope"] = [CLASS, "root"]
        ok, _ = ar.verify_attestation(tok, ks.to_dict())
        self.assertFalse(ok)

    def test_unknown_kid_refused(self):
        ks = _keyset()
        other = _keyset("other")
        alien = _mint(other, seed_tag="other")
        ok, reason = ar.verify_attestation(alien, ks.to_dict())
        self.assertFalse(ok)
        # The keyset-hash pin fires before kid resolution here: the
        # alien token's attested hash names a different keyset. Either
        # refusal is fail-closed; the pin is the stronger check.
        self.assertTrue("keyset_hash" in reason or "lookup failed" in reason,
                        reason)

    def test_embedded_key_never_accepted(self):
        # The insecure_header_jwk lesson: even a correctly-signed token
        # whose envelope names a key the trusted keyset does not know
        # is refused -- keys resolve via kid from the keyset, never
        # from token material.
        ks = _keyset()
        other = _keyset("other")
        alien = _mint(other, seed_tag="other")
        ok, _ = ar.verify_attestation(alien, ks.to_dict())
        self.assertFalse(ok)

    def test_revoked_version_refused_standard_path(self):
        ks = _keyset("rev")
        ks2, _ = rotate_keyset(ks, _seed("rev-new"), _seed("rev"))
        tok = _mint(ks, seed_tag="rev")  # signed by old primary (v1)
        ok, _ = ar.verify_attestation(tok, ks2.to_dict())
        self.assertTrue(ok)  # v1 is verify-only: still verifies
        ks3 = revoke_version(ks2, 1, "compromised", _seed("rev-new"))
        ok, reason = ar.verify_attestation(tok, ks3.to_dict())
        self.assertFalse(ok)
        self.assertIn("lookup failed", reason)
        # Forensics carve-out: historical attribution still works.
        ok, details = ar.verify_attestation(tok, ks3.to_dict(),
                                            forensics=True)
        self.assertTrue(ok, details)
        self.assertEqual(details["keyset_version"], 1)

    def test_keyset_substitution_refused(self):
        ks = _keyset()
        tok = _mint(ks)
        twin = _keyset("twin")  # same purpose, different keys
        ok, reason = ar.verify_attestation(tok, twin.to_dict())
        self.assertFalse(ok)

    def test_purpose_mismatch_refused(self):
        ks = _keyset()
        tok = _mint(ks)
        tok["attested_by"] = dict(tok["attested_by"])
        tok["attested_by"]["purpose"] = "audit-entry-signing"
        ok, reason = ar.verify_attestation(tok, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("purpose", reason)

    def test_never_raises(self):
        ks = _keyset()
        for bad in (None, "x", [], {"format": ar.ATTESTATION_FORMAT}):
            ok, _ = ar.verify_attestation(bad, ks.to_dict())
            self.assertFalse(ok)
        tok = _mint(ks)
        for bad_doc in (None, "x", {}):
            ok, _ = ar.verify_attestation(tok, bad_doc)
            self.assertFalse(ok)


# ---------------------------------------------------------------------------
# The release predicate
# ---------------------------------------------------------------------------

class TestEvaluate(unittest.TestCase):
    def _ok(self, **kw):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks, **kw.pop("mint_kw", {}))
        cfg.register_attestation(AGENT, tok)
        return ar.evaluate_release(CRED_ID, CLASS, tok, config=cfg,
                                   agent_id=AGENT, run_id=RUN,
                                   now=AT + 10, **kw)

    def test_happy_path_consumes_jti(self):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks, jti="jti-happy")
        cfg.register_attestation(AGENT, tok)
        ok, reason, jti = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=cfg, agent_id=AGENT, run_id=RUN,
            now=AT + 10, consume=True)
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")
        self.assertEqual(jti, "jti-happy")
        self.assertTrue(cfg.jti_seen("jti-happy"))

    def test_precheck_does_not_consume(self):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks, jti="jti-pre")
        cfg.register_attestation(AGENT, tok)
        ok, _, _ = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=cfg, agent_id=AGENT, run_id=RUN,
            now=AT + 10, consume=False)
        self.assertTrue(ok)
        self.assertFalse(cfg.jti_seen("jti-pre"))

    def test_no_config_refuses_no_fallback(self):
        ks = _keyset()
        tok = _mint(ks)
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=None, agent_id=AGENT, run_id=RUN,
            now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("no attestation trust anchor", reason)
        self.assertIn("no silent fallback", reason)

    def test_no_token_refuses(self):
        cfg = _config()
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, None, config=cfg, agent_id=AGENT, run_id=RUN,
            now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("no attestation presented", reason)

    def test_replay_refuses(self):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks, jti="jti-replay")
        cfg.register_attestation(AGENT, tok)
        cfg.mark_jti("jti-replay")
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=cfg, agent_id=AGENT, run_id=RUN,
            now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("replay", reason)

    def test_expired_refuses(self):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks)
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=cfg, agent_id=AGENT, run_id=RUN,
            now=AT + 400)
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_overlong_ttl_refuses(self):
        ks = _keyset("ttl")
        cfg = _config(ks)
        good = _mint(ks, seed_tag="ttl")
        body = {k: v for k, v in good.items() if k != "envelope"}
        body["exp"] = body["iat"] + 301
        long_tok = _resign(ks, "ttl", body)
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, long_tok, config=cfg, agent_id=AGENT,
            run_id=RUN, now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("TTL", reason)

    def test_future_iat_refuses(self):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks, at=AT + 600)
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=cfg, agent_id=AGENT, run_id=RUN,
            now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("future", reason)

    def test_non_affirming_status_refuses(self):
        for status in ("warning", "contraindicated"):
            ks = _keyset()
            cfg = _config(ks)
            tok = _mint(ks, status=status)
            ok, reason, _ = ar.evaluate_release(
                CRED_ID, CLASS, tok, config=cfg, agent_id=AGENT,
                run_id=RUN, now=AT + 10)
            self.assertFalse(ok, status)
            self.assertIn("not affirming", reason)

    def test_wrong_audience_refuses(self):
        ks = _keyset("aud")
        cfg = _config(ks)
        good = _mint(ks, seed_tag="aud")
        body = {k: v for k, v in good.items() if k != "envelope"}
        body["aud"] = "something-else"
        bad = _resign(ks, "aud", body)
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, bad, config=cfg, agent_id=AGENT, run_id=RUN,
            now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("audience", reason)

    def test_sub_mismatch_refuses(self):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks)
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=cfg, agent_id="agent-2",
            run_id=RUN, now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("sub", reason)

    def test_untrusted_issuer_refuses(self):
        ks = _keyset()
        cfg = _config(ks)  # trusts ISSUER only
        tok = _mint(ks, iss=ROGUE_ISSUER)
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=cfg, agent_id=AGENT, run_id=RUN,
            now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("not trusted", reason)

    def test_wrong_class_refuses(self):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks, agent_scope=["other-class"])
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=cfg, agent_id=AGENT, run_id=RUN,
            now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("does not cover", reason)

    def test_empty_classes_refuses(self):
        ks = _keyset("ec")
        cfg = _config(ks)
        good = _mint(ks, seed_tag="ec")
        body = {k: v for k, v in good.items() if k != "envelope"}
        body["agent_scope"] = []
        bad = _resign(ks, "ec", body)
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, bad, config=cfg, agent_id=AGENT, run_id=RUN,
            now=AT + 10)
        self.assertFalse(ok)

    def test_session_binding(self):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks)  # bound to (AGENT, RUN)
        ok, _, _ = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=cfg, agent_id=AGENT,
            run_id="run-2", now=AT + 10)
        self.assertFalse(ok)
        ok, _, _ = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=cfg, agent_id="agent-2",
            run_id=RUN, now=AT + 10)
        self.assertFalse(ok)

    def test_deny_all_refuses(self):
        cfg = _config()
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, None, config=cfg, agent_id=AGENT, run_id=RUN,
            policy="deny_all", now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("deny_all", reason)

    def test_unknown_policy_refuses(self):
        cfg = _config()
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, None, config=cfg, agent_id=AGENT, run_id=RUN,
            policy="allow_all", now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("unknown release policy", reason)

    def test_never_raises(self):
        cfg = _config()
        ok, _reason, _jti = ar.evaluate_release(
            CRED_ID, CLASS, {"garbage": True}, config=cfg,
            agent_id=AGENT, run_id=RUN, now=AT + 10)
        self.assertFalse(ok)


# ---------------------------------------------------------------------------
# Operator-signed policy overrides
# ---------------------------------------------------------------------------

class TestOverride(unittest.TestCase):
    def _override(self, oks, **kw):
        params = dict(agent_scope=[CLASS], window_seconds=600,
                      reason="incident-7", at=AT)
        params.update(kw)
        return ar.mint_policy_override(oks, _seed("override-op"), **params)

    def test_verify_round_trip(self):
        oks = _override_keyset()
        ovr = self._override(oks)
        ok, details = ar.verify_policy_override(ovr, oks.to_dict(), now=AT)
        self.assertTrue(ok, details)
        self.assertEqual(details["agent_scope"], [CLASS])
        self.assertEqual(details["reason"], "incident-7")

    def test_wrong_purpose_keyset_cannot_mint(self):
        ks = _keyset()
        with self.assertRaises(ar.AttestationReleaseError):
            ar.mint_policy_override(ks, _seed("issuer"),
                                    agent_scope=[CLASS])

    def test_window_bound(self):
        oks = _override_keyset()
        with self.assertRaises(ar.AttestationReleaseError):
            self._override(oks, window_seconds=3601)
        ovr = self._override(oks, window_seconds=600)
        ok, _ = ar.verify_policy_override(ovr, oks.to_dict(), now=AT)
        self.assertTrue(ok)
        ok, reason = ar.verify_policy_override(ovr, oks.to_dict(),
                                               now=AT + 601
                                               + ar.CLOCK_SKEW_SECONDS + 1)
        self.assertFalse(ok)
        self.assertIn("window", reason)

    def test_tampered_override_refused(self):
        oks = _override_keyset()
        ovr = self._override(oks)
        ovr["agent_scope"] = [CLASS, "root"]
        ok, _ = ar.verify_policy_override(ovr, oks.to_dict(), now=AT)
        self.assertFalse(ok)

    def test_override_allows_without_token(self):
        ks = _keyset()
        cfg = _config(ks)
        oks = _override_keyset()
        ovr = self._override(oks)
        ok, reason, jti = ar.evaluate_release(
            CRED_ID, CLASS, None, config=cfg, agent_id=AGENT, run_id=RUN,
            override=ovr, override_keyset_doc=oks.to_dict(), now=AT + 10)
        self.assertTrue(ok)
        self.assertEqual(reason, "operator-override")
        self.assertIsNone(jti)

    def test_override_wrong_class_refuses(self):
        ks = _keyset()
        cfg = _config(ks)
        oks = _override_keyset()
        ovr = self._override(oks, agent_scope=["other"])
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, None, config=cfg, agent_id=AGENT, run_id=RUN,
            override=ovr, override_keyset_doc=oks.to_dict(), now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("does not cover", reason)

    def test_bad_override_keyset_refuses(self):
        ks = _keyset()
        cfg = _config(ks)
        oks = _override_keyset()
        ovr = self._override(oks)
        ok, reason, _ = ar.evaluate_release(
            CRED_ID, CLASS, None, config=cfg, agent_id=AGENT, run_id=RUN,
            override=ovr, override_keyset_doc={"bogus": 1}, now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("override", reason.lower())

    def test_override_via_config_store_is_loud(self):
        ks = _keyset()
        cfg = _config(ks)
        oks = _override_keyset()
        ovr = self._override(oks)
        cfg.set_policy_override(ovr, oks.to_dict(), now=AT)
        vault, sentinel = _vault()
        outcome, _detail, audit = _release(vault, sentinel, None,
                                           config=cfg)
        self.assertEqual(outcome, "allowed")
        loud = [e for e in audit
                if e.get("event") == "attestation_release"
                and e.get("via_override") is True]
        self.assertTrue(loud, audit)


# ---------------------------------------------------------------------------
# Vault registration
# ---------------------------------------------------------------------------

class TestRegister(unittest.TestCase):
    def test_class_and_policy_required_shape(self):
        vault = _sentinel.SentinelVault()
        # credential_class is a required positional: omitting it is a
        # loud TypeError, never a silent default.
        with self.assertRaises(TypeError):
            vault.register("c1", REAL_DB, [DB_HOST])  # no class
        with self.assertRaises(_sentinel.SentinelError):
            vault.register("c1", REAL_DB, [DB_HOST],
                           credential_class="")  # empty class
        with self.assertRaises(_sentinel.SentinelError):
            vault.register("c1", REAL_DB, [DB_HOST],
                           credential_class="x",
                           release_policy="allow_all")  # unknown policy

    def test_default_is_attested(self):
        vault, _ = _vault()
        rec = vault.lookup(vault.sentinel_for(CRED_ID))
        self.assertEqual(rec["release_policy"], "attested")
        self.assertEqual(rec["credential_class"], CLASS)

    def test_legacy_and_deny_all(self):
        vault = _sentinel.SentinelVault()
        vault.register("c1", REAL_DB, [DB_HOST], credential_class="x",
                       release_policy="legacy-host-only")
        vault.register("c2", REAL_DB, [DB_HOST], credential_class="x",
                       release_policy="deny_all")
        self.assertEqual(
            vault.lookup(vault.sentinel_for("c1"))["release_policy"],
            "legacy-host-only")
        self.assertEqual(
            vault.lookup(vault.sentinel_for("c2"))["release_policy"],
            "deny_all")


# ---------------------------------------------------------------------------
# Execution-boundary seam
# ---------------------------------------------------------------------------

class TestExecutionSeam(unittest.TestCase):
    def _wired(self, **mint_kw):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks, **mint_kw)
        cfg.register_attestation(AGENT, tok)
        vault, sentinel = _vault()
        return ks, cfg, tok, vault, sentinel

    def test_valid_token_substitutes_and_consumes(self):
        _ks, cfg, tok, vault, sentinel = self._wired(jti="jti-seam-1")
        outcome, _detail, audit = _release(vault, sentinel, tok,
                                           config=cfg)
        self.assertEqual(outcome, "allowed")
        allowed = [e for e in audit
                   if e.get("event") == "attestation_release"
                   and e.get("verdict") == "allowed"]
        self.assertTrue(allowed)
        # No secret material in the audit.
        self.assertNotIn(REAL_DB, repr(audit))
        # The jti is consumed: a second release refuses.
        outcome2, _, _ = _release(vault, sentinel, tok, config=cfg)
        self.assertEqual(outcome2, "denied")

    def test_no_config_refuses_loud_no_downgrade(self):
        _ks, _cfg, tok, vault, sentinel = self._wired()
        outcome, detail, audit = _release(vault, sentinel, tok, config=None)
        self.assertEqual(outcome, "denied")
        self.assertIn("no attestation trust anchor", detail)
        self.assertTrue(_denied_loud(audit))

    def test_no_token_refuses_loud(self):
        ks = _keyset()
        cfg = _config(ks)
        # NOTE: no attestation registered in the config -- a true
        # absent-token case (a registered token would be resolved via
        # the config lookup, which is the executor's normal path).
        vault, sentinel = _vault()
        outcome, _detail, audit = _release(vault, sentinel, None,
                                           config=cfg)
        self.assertEqual(outcome, "denied")
        self.assertTrue(_denied_loud(audit))

    def test_legacy_path_substitutes_with_loud_audit(self):
        vault, sentinel = _vault(policy="legacy-host-only")
        audit = []
        args = {"url": "https://%s/query" % DB_HOST, "api_key": sentinel}
        new_args, _ = _sentinel.substitute_for_execution(
            vault, "http_post", args, identity=_identity(),
            release_config=None, audit_log=audit, run_id=RUN, now=AT)
        self.assertEqual(new_args["api_key"], REAL_DB)
        legacy = [e for e in audit
                  if e.get("event") == "attestation_release_legacy"]
        self.assertTrue(legacy, audit)
        self.assertIn(ar.LEGACY_RELEASE_SUNSET, legacy[0]["warning"])
        self.assertNotIn(REAL_DB, repr(audit))

    def test_deny_all_refuses(self):
        vault, sentinel = _vault(policy="deny_all")
        outcome, detail, audit = _release(vault, sentinel, None,
                                          config=_config())
        self.assertEqual(outcome, "denied")
        self.assertIn("deny_all", detail)
        self.assertTrue(_denied_loud(audit))

    def test_no_partial_release(self):
        # One good credential + one bad: NOTHING substitutes.
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks)
        cfg.register_attestation(AGENT, tok)
        vault = _sentinel.SentinelVault()
        s1 = vault.register("good-cred", REAL_DB, [DB_HOST],
                            credential_class=CLASS,
                            release_policy="attested")
        s2 = vault.register("bad-cred", REAL_DB, [DB_HOST],
                            credential_class="other-class",
                            release_policy="attested")
        args = {"url": "https://%s/q" % DB_HOST,
                "a": s1, "b": s2}
        with self.assertRaises(_sentinel.SentinelError):
            _sentinel.substitute_for_execution(
                vault, "http_post", args, identity=_identity(),
                attestation=tok, release_config=cfg, audit_log=[],
                run_id=RUN, now=AT + 10)
        self.assertFalse(cfg.jti_seen(tok["jti"]))  # nothing consumed
        self.assertEqual(vault.substitution_log, [])  # nothing released

    def test_dict_identity_approved_path_shape(self):
        # The approved sweep passes a mapping identity; the seam must
        # resolve agent/run from it.
        _ks, cfg, tok, vault, sentinel = self._wired()
        approved_identity = {"agent_id": AGENT, "role": "researcher",
                             "principal": PRINCIPAL, "run_id": RUN}
        args = {"url": "https://%s/q" % DB_HOST, "api_key": sentinel}
        new_args, _ = _sentinel.substitute_for_execution(
            vault, "http_post", args, identity=approved_identity,
            attestation=tok, release_config=cfg, audit_log=[],
            now=AT + 10)
        self.assertEqual(new_args["api_key"], REAL_DB)

    def test_host_binding_still_anded(self):
        # Host mismatch refuses even with a valid attestation.
        _ks, cfg, tok, vault, sentinel = self._wired()
        args = {"url": "https://evil.example/x", "api_key": sentinel}
        with self.assertRaises(_sentinel.SentinelError):
            _sentinel.substitute_for_execution(
                vault, "http_post", args, identity=_identity(),
                attestation=tok, release_config=cfg, audit_log=[],
                run_id=RUN, now=AT + 10)


# ---------------------------------------------------------------------------
# Attempt-path pre-check
# ---------------------------------------------------------------------------

class _StubExecutor(object):
    def __init__(self, vault, config, run_id=RUN):
        self.sentinel_registry = vault
        self.attestation_config = config
        self.run_id = run_id
        self.log = []
        self._queued = []

    def _preview(self, tool, args):
        return "preview"

    @property
    def approvals(self):
        ex = self

        class Q(object):
            def queue(self, *a, **k):
                ex._queued.append((a, k))
        return Q()

    @property
    def policy(self):
        class P(object):
            policy_hash = "ph"
        return P()


class TestAttemptPrecheck(unittest.TestCase):
    def _wired(self, **mint_kw):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks, **mint_kw)
        cfg.register_attestation(AGENT, tok)
        vault, sentinel = _vault()
        return cfg, tok, vault, sentinel

    def _args(self, sentinel):
        return {"url": "https://%s/query" % DB_HOST, "api_key": sentinel}

    def test_precheck_passes_without_consuming(self):
        cfg, tok, vault, sentinel = self._wired(jti="jti-pre-1")
        ex = _StubExecutor(vault, cfg)
        ids = _sentinel.validate_sentinel_binding(
            ex, _identity(), "http_post", self._args(sentinel), now=AT + 10)
        self.assertEqual(ids, [CRED_ID])
        self.assertFalse(cfg.jti_seen("jti-pre-1"))

    def test_precheck_trips_when_no_attestation(self):
        cfg = _config()
        vault, sentinel = _vault()
        ex = _StubExecutor(vault, cfg)
        # No attestation registered at all -> trip.
        with self.assertRaises(_sentinel.SentinelTripHalt):
            _sentinel.validate_sentinel_binding(
                ex, _identity(), "http_post", self._args(sentinel),
                now=AT + 10)
        trips = [e for e in ex.log
                 if e.get("event") == "attestation_release_trip"]
        self.assertTrue(trips, ex.log)
        self.assertEqual(trips[0]["credential_id"], CRED_ID)
        self.assertEqual(trips[0]["decision"], "halted")

    def test_precheck_trips_on_expired_token(self):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks)  # iat=AT, exp=AT+300
        cfg.register_attestation(AGENT, tok)
        vault, sentinel = _vault()
        ex = _StubExecutor(vault, cfg)
        with self.assertRaises(_sentinel.SentinelTripHalt):
            _sentinel.validate_sentinel_binding(
                ex, _identity(), "http_post", self._args(sentinel),
                now=AT + 400)
        trips = [e for e in ex.log
                 if e.get("event") == "attestation_release_trip"]
        self.assertTrue(trips)
        self.assertIn("expired", trips[0]["reason"])

    def test_precheck_trips_without_config_no_downgrade(self):
        _cfg, _tok, vault, sentinel = self._wired()
        ex = _StubExecutor(vault, None)  # no trust anchor at all
        with self.assertRaises(_sentinel.SentinelTripHalt):
            _sentinel.validate_sentinel_binding(
                ex, _identity(), "http_post", self._args(sentinel))

    def test_precheck_trips_on_deny_all(self):
        cfg = _config()
        vault, sentinel = _vault(policy="deny_all")
        ex = _StubExecutor(vault, cfg)
        with self.assertRaises(_sentinel.SentinelTripHalt):
            _sentinel.validate_sentinel_binding(
                ex, _identity(), "http_post", self._args(sentinel))

    def test_precheck_ignores_legacy(self):
        cfg = _config()
        vault, sentinel = _vault(policy="legacy-host-only")
        ex = _StubExecutor(vault, cfg)
        ids = _sentinel.validate_sentinel_binding(
            ex, _identity(), "http_post", self._args(sentinel))
        self.assertEqual(ids, [CRED_ID])


# ---------------------------------------------------------------------------
# Executor integration
# ---------------------------------------------------------------------------

class TestExecutorIntegration(unittest.TestCase):
    def _executor(self, **kw):
        from gov.executor import ToolExecutor
        from gov.policy import PolicyEngine
        from gov.log import ActionLog
        from gov.approvals import ApprovalQueue
        run_dir = Path(tempfile.mkdtemp(prefix="govattrel-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            run_dir, ignore_errors=True))
        policy = PolicyEngine(str(
            Path(__file__).resolve().parent.parent / "policies"
            / "default.yaml"))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        kwargs = dict(ledger_path=run_dir / "egress_ledger.jsonl",
                      ungoverned_ack="test ack: synthetic run")
        kwargs.update(kw)
        return ToolExecutor(run_dir, policy, log, approvals, **kwargs)

    def test_config_wiring(self):
        cfg = _config()
        ex = self._executor(attestation_config=cfg)
        self.assertIs(ex.attestation_config, cfg)
        with self.assertRaises(ValueError):
            self._executor(attestation_config=object())

    def test_register_attestation_needs_config(self):
        ex = self._executor()
        with self.assertRaises(ar.AttestationReleaseError):
            ex.register_attestation(AGENT, {"x": 1})

    def test_register_and_resolve(self):
        cfg = _config()
        ex = self._executor(attestation_config=cfg)
        tok = {"token": "material"}
        ex.register_attestation(AGENT, tok)
        self.assertEqual(ex._resolve_attestation(AGENT), tok)
        self.assertIsNone(ex._resolve_attestation("nobody"))
        ex2 = self._executor()
        self.assertIsNone(ex2._resolve_attestation(AGENT))

    def test_attempt_without_attestation_trips(self):
        # Wall-clock minting (300s TTL; the executor path uses real
        # time in the pre-check).
        ks = _keyset()
        cfg = _config(ks)
        vault = _sentinel.SentinelVault()
        sentinel = vault.register(CRED_ID, REAL_DB, [DB_HOST],
                                  credential_class=CLASS,
                                  release_policy="attested")
        ex = self._executor(sentinel_registry=vault,
                            attestation_config=cfg)
        ident = ex.mint_identity(AGENT, "researcher", PRINCIPAL)
        with self.assertRaises(_sentinel.SentinelTripHalt):
            ex.call(ident, "http_post",
                    url="https://%s/query" % DB_HOST,
                    payload={"api_key": sentinel})

    def test_attempt_with_attestation_passes_precheck(self):
        ks = _keyset()
        cfg = _config(ks)
        now = int(time.time())
        vault = _sentinel.SentinelVault()
        sentinel = vault.register(CRED_ID, REAL_DB, [DB_HOST],
                                  credential_class=CLASS,
                                  release_policy="attested")
        ex = self._executor(sentinel_registry=vault,
                            attestation_config=cfg)
        # Bind the attestation session to THIS run.
        tok = ar.attest_release(
            ks, _seed("issuer"), sub=AGENT, iss=ISSUER,
            agent_scope=[CLASS],
            session={"agent_id": AGENT, "run_id": ex.run_id},
            ttl_seconds=300, at=now)
        cfg.register_attestation(AGENT, tok)
        ident = ex.mint_identity(AGENT, "researcher", PRINCIPAL)
        # The attempt path must not trip; the call proceeds to the
        # policy layer (queued or allowed -- either is past the seam).
        try:
            r = ex.call(ident, "http_post",
                        url="https://%s/query" % DB_HOST,
                        payload={"api_key": sentinel})
        except _sentinel.SentinelTripHalt as e:
            self.fail("attestation pre-check tripped on a valid "
                      "attestation: %s" % (e,))
        self.assertIn("status", r)


# ---------------------------------------------------------------------------
# Audit event helpers
# ---------------------------------------------------------------------------

class TestAuditEvents(unittest.TestCase):
    def test_release_event_has_no_secrets(self):
        e = ar.release_event(credential_id=CRED_ID, agent_id=AGENT,
                             run_id=RUN, verdict="denied",
                             reason="expired", policy="attested")
        self.assertEqual(e["event"], "attestation_release")
        blob = repr(e)
        self.assertNotIn(REAL_DB, blob)

    def test_legacy_event_names_sunset(self):
        e = ar.legacy_release_event(credential_id=CRED_ID, agent_id=AGENT,
                                    run_id=RUN, dest=DB_HOST)
        self.assertEqual(e["event"], "attestation_release_legacy")
        self.assertIn(ar.LEGACY_RELEASE_SUNSET, e["warning"])
        self.assertNotIn(REAL_DB, repr(e))

    def test_release_event_carries_counter_snapshot(self):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks)
        ar.evaluate_release(CRED_ID, CLASS, tok, config=cfg,
                            agent_id=AGENT, run_id=RUN, now=AT + 10)
        e = ar.release_event(credential_id=CRED_ID, agent_id=AGENT,
                             run_id=RUN, verdict="allowed", reason="ok",
                             policy="attested",
                             counters=cfg.counters_snapshot())
        self.assertEqual(
            e["counters"],
            {"evaluations": 1, "approvals": 1, "violations": 0, "errors": 0})


class TestTelemetryCounters(unittest.TestCase):
    def test_counters_start_at_zero(self):
        cfg = _config()
        self.assertEqual(cfg.counters_snapshot(),
                         {"evaluations": 0, "approvals": 0,
                          "violations": 0, "errors": 0})

    def test_approval_violation_error_classification(self):
        ks = _keyset()
        cfg = _config(ks)
        tok = _mint(ks)
        # Approval.
        ok, _reason, _jti = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=cfg, agent_id=AGENT, run_id=RUN,
            now=AT + 10)
        self.assertTrue(ok)
        # Violation: attestation presented but refused (replay).
        ok, reason, _jti = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=cfg, agent_id=AGENT, run_id=RUN,
            now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("replay", reason)
        # Error: operational misconfiguration (unknown policy).
        ok, reason, _jti = ar.evaluate_release(
            CRED_ID, CLASS, tok, config=cfg, agent_id=AGENT, run_id=RUN,
            policy="bogus", now=AT + 10)
        self.assertFalse(ok)
        self.assertIn("unknown release policy", reason)
        self.assertEqual(cfg.counters_snapshot(),
                         {"evaluations": 3, "approvals": 1,
                          "violations": 1, "errors": 1})

    def test_missing_anchor_counts_as_error_not_violation(self):
        ok, reason, _jti = ar.evaluate_release(
            CRED_ID, CLASS, None, config=None, agent_id=AGENT,
            run_id=RUN, now=AT + 10)
        self.assertFalse(ok)
        # No config object exists to count on -- and the refusal is a
        # loud error, not a silent pass.
        self.assertIn("no attestation trust anchor", reason)

    def test_counters_snapshot_is_a_copy(self):
        cfg = _config()
        snap = cfg.counters_snapshot()
        snap["evaluations"] = 99
        self.assertEqual(cfg.counters["evaluations"], 0)


class TestNoSilentDowngrade(unittest.TestCase):
    """A record missing release_policy (hand-built, older-shaped, or
    deserialized) is attestation-mandatory -- never host-only (R6)."""

    def _vault_missing_policy(self):
        ks = _keyset()
        cfg = _config(ks)
        vault = _sentinel.SentinelVault()
        sentinel = vault.register(CRED_ID, REAL_DB, [DB_HOST],
                                  credential_class=CLASS)
        del vault._entries[sentinel]["release_policy"]
        return ks, cfg, vault, sentinel

    def test_missing_policy_refuses_without_attestation(self):
        ks, cfg, vault, sentinel = self._vault_missing_policy()
        with self.assertRaises(_sentinel.SentinelError):
            _sentinel.substitute_for_execution(
                vault, "http_post", {"url": "https://db.internal:5432/x",
                                     "body": sentinel},
                identity=_identity(), attestation=None,
                release_config=cfg, audit_log=[], run_id=RUN, now=AT + 10)

    def test_missing_policy_allows_with_valid_attestation(self):
        ks, cfg, vault, sentinel = self._vault_missing_policy()
        tok = _mint(ks)
        audit = []
        _out, reals = _sentinel.substitute_for_execution(
            vault, "http_post", {"url": "https://db.internal:5432/x",
                                 "body": sentinel},
            identity=_identity(), attestation=tok,
            release_config=cfg, audit_log=audit, run_id=RUN, now=AT + 10)
        self.assertEqual(reals, (REAL_DB,))
        # Attested path audited -- not the legacy event.
        self.assertEqual(audit[0]["event"], "attestation_release")
        self.assertEqual(audit[0]["policy"], "attested")


if __name__ == "__main__":
    unittest.main()
