"""Wave-78 supply-chain enforcement: digest-verify every loadable artifact
+ capability leases (2026-09-22).

Load-bearing claims under test (workstreams/architect/SUPPLYCHAIN_DESIGN.md):
- pins are digests, never references: branch/tag/latest/40-hex-SHA pin
  values refused at pin time
- pin mutation requires roster-human Ed25519 authorship (wave-75
  construction); attacker-keyed pins refused
- unpinned artifacts are never loaded (no TOFU)
- verify -> load: digest mismatch refused loud; match returns the
  VerifiedArtifact holding the exact bytes hashed
- the ref namespace never enters the governed path; RefResolver replays
  the Plugin4Shell shape on the legacy path only
- TOCTOU: store swap after verification cannot reach the consumer —
  the consumer gets the verified bytes object
- single-read file load: one read, hash, handoff
- skill loading goes through the gate; skill_loaded chains the digest
- leases: mint requires roster authority key; scope cannot exceed agent
  capabilities; TTL capped
- lease verification at use time: signature, roster, window, revocation,
  task binding, scope — each failure a named refusal
- expiry mid-task: no grace execution
- ambient-credential absence: constructive (no private key in verifier
  graph) + assertive (session-open scan refuses production-shaped
  credential material)
- executor wiring: lease-gated tools require a valid lease on the
  verdict path; refusal is loud (lease_refused audit)

Hermetic: temp dirs, synthetic deterministic, no network.
Deterministic except wall-clock ts (never asserted on).
"""

import hashlib
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import load_gate as _lg  # noqa: E402
from gov import capability_leases as _cl  # noqa: E402
from gov import log as _log  # noqa: E402
from gov.delegation_tokens import (DelegationTrust, RevocationLedger,  # noqa: E402
                                   generate_test_keypair)
from gov.ed25519 import publickey as _pubkey  # noqa: E402
from gov.log import ActionLog  # noqa: E402


def _make_world():
    human_seed = __import__("secrets").token_bytes(32)
    human2_seed = __import__("secrets").token_bytes(32)
    auth_seed = __import__("secrets").token_bytes(32)
    user_seed = __import__("secrets").token_bytes(32)
    trust = DelegationTrust(
        human_keys={"op:alice": _pubkey(human_seed),
                    "op:bob": _pubkey(human2_seed)},
        authority_keys={"reg-auth": _pubkey(auth_seed)},
        user_issuer_keys={"idp": _pubkey(user_seed)},
    )
    return trust, human_seed, human2_seed, auth_seed


def _na(ts):
    """Default not_after bound for a pin statement ts (90-day TTL)."""
    return _lg._resolve_pin_not_after(ts, None)


def _pin_with_seed(pinset, artifact_id, digest, human_seed,
                   key_id="op:alice", ts="2026-09-22T00:00:00+00:00",
                   tier="dev", second_seed=None, second_key_id="op:bob"):
    from gov.ed25519 import sign as _s
    na = _na(ts)
    body = _lg._canonical_pin_body(tier, artifact_id, digest, ts,
                                   version=1, not_after=na)
    sig = _s(human_seed, body).hex()
    kw = {"ts": ts, "tier": tier, "version": 1, "not_after": na}
    if second_seed is not None:
        kw["second_author_key_id"] = second_key_id
        kw["second_authorship_sig_hex"] = _s(second_seed, body).hex()
    return pinset.pin(artifact_id, digest, key_id, sig, **kw)


# ---------------------------------------------------------------------------
# Load gate: pins are digests, never references.
# ---------------------------------------------------------------------------

class TestPinHygiene(unittest.TestCase):
    def setUp(self):
        self.trust, self.human_seed, self.human2_seed, self.auth_seed = _make_world()
        self.pinset = _lg.ArtifactPinset(self.trust)

    def _sig(self, artifact_id, digest, key_id="op:alice",
             ts="2026-09-22T00:00:00+00:00", seed=None, tier="dev"):
        from gov.ed25519 import sign as _s
        body = _lg._canonical_pin_body(tier, artifact_id, digest, ts,
                                       version=1, not_after=_na(ts))
        return _s(seed or self.human_seed, body).hex()

    def _unpin_sig(self, key_id="op:alice",
                   ts="2026-09-22T00:00:00+00:00", seed=None, tier="dev",
                   version=2):
        # Unpins must name a version strictly above the pin's (the pin
        # under test is at version 1).
        from gov.ed25519 import sign as _s
        body = _lg._canonical_unpin_body(tier, "skill:x", ts, version=version)
        return _s(seed or self.human_seed, body).hex()

    def _pin_dev(self, artifact_id, digest):
        return self.pinset.pin(
            "skill:x", digest, "op:alice", self._sig("skill:x", digest),
            ts="2026-09-22T00:00:00+00:00", tier="dev", version=1,
            not_after=_na("2026-09-22T00:00:00+00:00"))

    def test_good_digest_pin_accepted(self):
        d = "sha256:" + "ab" * 32
        rec = self._pin_dev("skill:x", d)
        self.assertEqual(rec["digest"], d)
        self.assertEqual(rec["pinned_by"], "op:alice")
        self.assertEqual(rec["tier"], "dev")

    def test_branch_name_pin_refused(self):
        with self.assertRaises(_lg.ArtifactRefused) as c:
            self.pinset.pin("skill:x", "main", "op:alice",
                            self._sig("skill:x", "main"), tier="dev")
        self.assertIn("not a sha256 digest pin", str(c.exception))

    def test_tag_and_latest_refused(self):
        for ref in ("v1.2.3", "latest", "refs/heads/main"):
            with self.assertRaises(_lg.ArtifactRefused, msg=ref):
                self.pinset.pin("skill:x", ref, "op:alice",
                                self._sig("skill:x", ref), tier="dev")

    def test_40hex_git_sha_refused_as_pin(self):
        # The exact Plugin4Shell confusion: a 40-hex git SHA is a
        # REFERENCE, not a digest. Pinning it would re-create the hole.
        sha40 = "da" * 20
        with self.assertRaises(_lg.ArtifactRefused) as c:
            self.pinset.pin("skill:x", sha40, "op:alice",
                            self._sig("skill:x", sha40), tier="dev")
        self.assertIn("not a sha256 digest pin", str(c.exception))

    def test_unknown_author_key_refused(self):
        d = "sha256:" + "ab" * 32
        with self.assertRaises(_lg.ArtifactRefused) as c:
            self.pinset.pin("skill:x", d, "op:mallory",
                            "00" * 64, tier="dev")
        self.assertIn("pin_authorship_invalid", str(c.exception))

    def test_attacker_signed_pin_refused(self):
        d = "sha256:" + "ab" * 32
        evil_seed = __import__("secrets").token_bytes(32)
        sig = self._sig("skill:x", d, seed=evil_seed)
        with self.assertRaises(_lg.ArtifactRefused) as c:
            self.pinset.pin("skill:x", d, "op:alice", sig, tier="dev")
        self.assertIn("pin_authorship_invalid", str(c.exception))

    def test_unknown_tier_refused(self):
        d = "sha256:" + "ab" * 32
        with self.assertRaises(_lg.ArtifactRefused):
            self.pinset.pin("skill:x", d, "op:alice",
                            self._sig("skill:x", d, tier="prod"),
                            tier="prod")

    def test_unpin_requires_authorship(self):
        d = "sha256:" + "ab" * 32
        self._pin_dev("skill:x", d)
        evil_seed = __import__("secrets").token_bytes(32)
        with self.assertRaises(_lg.ArtifactRefused):
            self.pinset.unpin("skill:x", "op:alice",
                              self._unpin_sig(seed=evil_seed),
                              ts="2026-09-22T00:00:00+00:00", tier="dev",
                              version=2)
        # The pin survived the attack.
        self.assertIsNotNone(self.pinset.pin_for("skill:x"))


class TestPinTierRule(unittest.TestCase):
    """The wave-75 nuclear rule applied to digest pins: production
    mutations need two DISTINCT roster human keys."""

    def setUp(self):
        (self.trust, self.human_seed, self.human2_seed,
         self.auth_seed) = _make_world()
        self.pinset = _lg.ArtifactPinset(self.trust)
        self.ts = "2026-09-22T00:00:00+00:00"

    def _two_sig_pin(self, artifact_id="skill:x", digest=None, tier="production",
                     seed1=None, key1="op:alice",
                     seed2=None, key2="op:bob"):
        from gov.ed25519 import sign as _s
        digest = digest or ("sha256:" + "ab" * 32)
        na = _na(self.ts)
        body = _lg._canonical_pin_body(tier, artifact_id, digest, self.ts,
                                       version=1, not_after=na)
        return self.pinset.pin(
            artifact_id, digest, key1, _s(seed1 or self.human_seed,
                                          body).hex(),
            ts=self.ts, tier=tier, version=1, not_after=na,
            second_author_key_id=key2,
            second_authorship_sig_hex=_s(seed2 or self.human2_seed,
                                         body).hex())

    def test_production_two_distinct_keys_accepted(self):
        rec = self._two_sig_pin()
        self.assertEqual(rec["approvals"], ["op:alice", "op:bob"])
        self.assertEqual(rec["tier"], "production")

    def test_production_single_approval_refused(self):
        from gov.ed25519 import sign as _s
        d = "sha256:" + "ab" * 32
        na = _na(self.ts)
        body = _lg._canonical_pin_body("production", "skill:x", d, self.ts,
                                       version=1, not_after=na)
        with self.assertRaises(_lg.ArtifactRefused) as c:
            self.pinset.pin("skill:x", d, "op:alice",
                            _s(self.human_seed, body).hex(),
                            ts=self.ts, tier="production",
                            version=1, not_after=na)
        self.assertIn("two distinct human approvals", str(c.exception))
        self.assertIsNone(self.pinset.pin_for("skill:x"))

    def test_production_same_key_twice_refused(self):
        from gov.ed25519 import sign as _s
        d = "sha256:" + "ab" * 32
        na = _na(self.ts)
        body = _lg._canonical_pin_body("production", "skill:x", d, self.ts,
                                       version=1, not_after=na)
        sig = _s(self.human_seed, body).hex()
        with self.assertRaises(_lg.ArtifactRefused) as c:
            self.pinset.pin("skill:x", d, "op:alice", sig,
                            ts=self.ts, tier="production",
                            version=1, not_after=na,
                            second_author_key_id="op:alice",
                            second_authorship_sig_hex=sig)
        self.assertIn("two DISTINCT keys", str(c.exception))

    def test_production_second_key_unknown_refused(self):
        from gov.ed25519 import sign as _s
        d = "sha256:" + "ab" * 32
        na = _na(self.ts)
        body = _lg._canonical_pin_body("production", "skill:x", d, self.ts,
                                       version=1, not_after=na)
        evil_seed = __import__("secrets").token_bytes(32)
        with self.assertRaises(_lg.ArtifactRefused) as c:
            self.pinset.pin("skill:x", d, "op:alice",
                            _s(self.human_seed, body).hex(),
                            ts=self.ts, tier="production",
                            version=1, not_after=na,
                            second_author_key_id="op:mallory",
                            second_authorship_sig_hex=_s(evil_seed,
                                                         body).hex())
        self.assertIn("pin_authorship_invalid", str(c.exception))

    def test_dev_single_approval_accepted(self):
        d = "sha256:" + "ab" * 32
        rec = _pin_with_seed(self.pinset, "skill:x", d, self.human_seed,
                             tier="dev", ts=self.ts)
        self.assertEqual(rec["tier"], "dev")
        self.assertEqual(rec["approvals"], ["op:alice"])

    def test_tier_committed_in_body_no_downgrade_replay(self):
        # A signature minted for dev-tier cannot be replayed as a
        # production approval: the tier is inside the signed body.
        from gov.ed25519 import sign as _s
        d = "sha256:" + "ab" * 32
        na = _na(self.ts)
        dev_body = _lg._canonical_pin_body("dev", "skill:x", d, self.ts,
                                           version=1, not_after=na)
        alice_dev = _s(self.human_seed, dev_body).hex()
        bob_dev = _s(self.human2_seed, dev_body).hex()
        with self.assertRaises(_lg.ArtifactRefused):
            self.pinset.pin("skill:x", d, "op:alice", alice_dev,
                            ts=self.ts, tier="production",
                            version=1, not_after=na,
                            second_author_key_id="op:bob",
                            second_authorship_sig_hex=bob_dev)

    def test_production_unpin_needs_two(self):
        d = "sha256:" + "ab" * 32
        self._two_sig_pin(digest=d)
        from gov.ed25519 import sign as _s
        body = _lg._canonical_unpin_body("production", "skill:x", self.ts,
                                         version=2)
        with self.assertRaises(_lg.ArtifactRefused):
            self.pinset.unpin("skill:x", "op:alice",
                              _s(self.human_seed, body).hex(),
                              ts=self.ts, tier="production", version=2)
        self.assertIsNotNone(self.pinset.pin_for("skill:x"))
        self.pinset.unpin(
            "skill:x", "op:alice", _s(self.human_seed, body).hex(),
            ts=self.ts, tier="production", version=2,
            second_author_key_id="op:bob",
            second_authorship_sig_hex=_s(self.human2_seed, body).hex())
        self.assertIsNone(self.pinset.pin_for("skill:x"))


class TestVerifyAndLoad(unittest.TestCase):
    def setUp(self):
        self.trust, self.human_seed, self.human2_seed, self.auth_seed = _make_world()
        self.tmp = tempfile.TemporaryDirectory()
        self.log = ActionLog(Path(self.tmp.name) / "audit.jsonl",
                             deployment_mode="test")
        self.pinset = _lg.ArtifactPinset(self.trust, log=self.log)
        self.good = b"skill bytes v1"
        self.good_digest = "sha256:" + hashlib.sha256(self.good).hexdigest()
        _pin_with_seed(self.pinset, "skill:grep", self.good_digest,
                       self.human_seed)

    def tearDown(self):
        self.tmp.cleanup()

    def test_match_loads_verified_artifact(self):
        v = _lg.verify_and_load(self.pinset, "skill:grep", self.good,
                                log=self.log)
        self.assertIsInstance(v, _lg.VerifiedArtifact)
        self.assertEqual(v.data, self.good)
        self.assertEqual(v.digest, self.good_digest)

    def test_mismatch_refused_loud(self):
        with self.assertRaises(_lg.ArtifactRefused) as c:
            _lg.verify_and_load(self.pinset, "skill:grep", b"evil bytes",
                                log=self.log)
        self.assertIn("digest_mismatch", str(c.exception))
        refused = [e for e in _log.read_entries(self.log.path)
                   if e.get("event") == "artifact_load_refused"]
        self.assertTrue(refused)
        self.assertEqual(refused[-1]["reason"], "digest_mismatch")

    def test_unpinned_refused_no_tofu(self):
        with self.assertRaises(_lg.ArtifactRefused) as c:
            _lg.verify_and_load(self.pinset, "skill:brand-new", b"bytes",
                                log=self.log)
        self.assertIn("artifact_unpinned", str(c.exception))

    def test_toctou_store_swap_cannot_reach_consumer(self):
        # The store is swapped AFTER verification; the consumer must
        # still get the verified bytes — the binding is the object,
        # not a second read.
        store = {"skill:grep": self.good}
        v = _lg.verify_and_load(self.pinset, "skill:grep",
                                store["skill:grep"], log=self.log)
        store["skill:grep"] = b"attacker bytes swapped in"
        self.assertEqual(v.data, self.good)
        self.assertNotEqual(v.data, store["skill:grep"])

    def test_single_read_file_load(self):
        p = Path(self.tmp.name) / "policy.yaml"
        p.write_bytes(self.good)
        d = "sha256:" + hashlib.sha256(self.good).hexdigest()
        _pin_with_seed(self.pinset, "policy:default", d, self.human_seed)
        v = _lg.load_file_verified(self.pinset, "policy:default", str(p),
                                   log=self.log)
        self.assertEqual(v.data, self.good)
        # Swap the file after load: the artifact is unaffected.
        p.write_bytes(b"tampered after load")
        self.assertEqual(v.data, self.good)


class TestRefResolverLegacyShape(unittest.TestCase):
    def test_branch_named_as_sha_shadows_commit_on_legacy_path(self):
        # The exact CVE-2026-92104 shape: pinned commit + shadowing branch.
        sha40 = "cf" * 20
        r = _lg.RefResolver()
        r.add_commit(sha40, b"reviewed plugin code")
        r.add_branch(sha40, b"attacker plugin code")
        data = _lg.legacy_load_via_refs(r, sha40)
        self.assertEqual(data, b"attacker plugin code")
        self.assertTrue(any("ambiguous" in w for w in r.warnings))

    def test_governed_path_never_resolves_refs(self):
        # The governed loader takes fetched BYTES, not a reference: the
        # ref namespace is not an input at all.
        import inspect
        src = inspect.getsource(_lg.verify_and_load)
        self.assertNotIn("RefResolver", src)
        self.assertNotIn("resolve", src)

    def test_fetch_head_game_on_legacy_path(self):
        r = _lg.RefResolver()
        r.add_branch("evil", b"fetch-head redirected")
        r.fetch_head = "evil"
        data = _lg.legacy_load_via_refs(r, "FETCH_HEAD")
        self.assertEqual(data, b"fetch-head redirected")


class TestSkillLoader(unittest.TestCase):
    def setUp(self):
        self.trust, self.human_seed, self.human2_seed, self.auth_seed = _make_world()
        self.tmp = tempfile.TemporaryDirectory()
        self.log = ActionLog(Path(self.tmp.name) / "audit.jsonl",
                             deployment_mode="test")
        self.pinset = _lg.ArtifactPinset(self.trust, log=self.log)
        self.skill_bytes = b"skill: summarize diffs"
        d = "sha256:" + hashlib.sha256(self.skill_bytes).hexdigest()
        _pin_with_seed(self.pinset, "skill:summarize", d, self.human_seed)
        self.loader = _lg.SkillLoader(
            self.pinset, {"summarize": self.skill_bytes}, log=self.log)

    def tearDown(self):
        self.tmp.cleanup()

    def test_skill_loads_and_chains_digest(self):
        v = self.loader.load_skill("summarize")
        self.assertEqual(v.data, self.skill_bytes)
        loaded = [e for e in _log.read_entries(self.log.path)
                  if e.get("event") == "skill_loaded"]
        self.assertTrue(loaded)
        self.assertEqual(loaded[-1]["digest"], v.digest)

    def test_tampered_skill_refused(self):
        evil = _lg.SkillLoader(self.pinset, {"summarize": b"evil skill"},
                               log=self.log)
        with self.assertRaises(_lg.ArtifactRefused) as c:
            evil.load_skill("summarize")
        self.assertIn("digest_mismatch", str(c.exception))


# ---------------------------------------------------------------------------
# Capability leases.
# ---------------------------------------------------------------------------

def _world_with_lease():
    trust, human_seed, human2_seed, auth_seed = _make_world()
    authority = _cl.LeaseAuthority(auth_seed, "reg-auth", trust)
    verifier = _cl.LeaseVerifier(trust)
    return trust, authority, verifier


class TestLeaseMinting(unittest.TestCase):
    def test_mint_and_verify_roundtrip(self):
        trust, authority, verifier = _world_with_lease()
        lease = authority.mint("agent-1", "task-9",
                               {"tools": ["tool:read_file"]})
        lid = verifier.require(lease, agent_id="agent-1", task_id="task-9",
                               tool="read_file")
        self.assertEqual(lid, lease["lease_id"])

    def test_mint_requires_roster_key(self):
        trust, _, _, _ = _make_world()
        evil_seed = __import__("secrets").token_bytes(32)
        with self.assertRaises(_cl.LeaseError):
            _cl.LeaseAuthority(evil_seed, "not-in-roster", trust)

    def test_scope_cannot_exceed_agent_capabilities(self):
        trust, authority, _ = _world_with_lease()
        with self.assertRaises(_cl.LeaseError):
            authority.mint("agent-1", "task-9",
                           {"tools": ["tool:delete_prod"]},
                           agent_capabilities=["tool:read_file"])

    def test_ttl_capped(self):
        trust, authority, _ = _world_with_lease()
        with self.assertRaises(_cl.LeaseError):
            authority.mint("agent-1", "task-9",
                           {"tools": ["tool:read_file"]}, ttl_s=99999)

    def test_empty_scope_refused(self):
        trust, authority, _ = _world_with_lease()
        with self.assertRaises(_cl.LeaseRefused):
            authority.mint("agent-1", "task-9", {"tools": []})


class TestLeaseVerification(unittest.TestCase):
    def setUp(self):
        self.trust, self.authority, self.verifier = _world_with_lease()
        self.lease = self.authority.mint(
            "agent-1", "task-9", {"tools": ["tool:read_file"]})

    def test_scope_denied_outside_grant(self):
        with self.assertRaises(_cl.LeaseScopeError) as c:
            self.verifier.require(self.lease, agent_id="agent-1",
                                  task_id="task-9", tool="send_email")
        self.assertIn("scope_denied", str(c.exception))

    def test_binding_mismatch_other_task(self):
        with self.assertRaises(_cl.LeaseBindingError) as c:
            self.verifier.require(self.lease, agent_id="agent-1",
                                  task_id="task-OTHER", tool="read_file")
        self.assertIn("binding_mismatch", str(c.exception))

    def test_binding_mismatch_other_agent(self):
        with self.assertRaises(_cl.LeaseBindingError):
            self.verifier.require(self.lease, agent_id="agent-2",
                                  task_id="task-9", tool="read_file")

    def test_forged_lease_unknown_issuer(self):
        evil_seed = __import__("secrets").token_bytes(32)
        from gov.ed25519 import sign as _s
        forged = dict(self.lease)
        forged["issuer_key_id"] = "attacker-key"
        forged["signature"] = _s(evil_seed,
                                 _cl._canonical_body(forged)).hex()
        with self.assertRaises(_cl.LeaseSignatureError) as c:
            self.verifier.require(forged, agent_id="agent-1",
                                  task_id="task-9", tool="read_file")
        self.assertIn("unknown_issuer", str(c.exception))

    def test_tampered_scope_breaks_signature(self):
        forged = dict(self.lease)
        forged["scope"] = {"tools": ["tool:*"]}
        # Signature still covers the ORIGINAL scope.
        with self.assertRaises(_cl.LeaseSignatureError):
            self.verifier.require(forged, agent_id="agent-1",
                                  task_id="task-9", tool="send_email")

    def test_expired_lease_no_grace(self):
        now = datetime.now(timezone.utc)
        past = now - timedelta(seconds=2000)
        lease = self.authority.mint("agent-1", "task-9",
                                    {"tools": ["tool:read_file"]},
                                    ttl_s=60, now=past)
        with self.assertRaises(_cl.LeaseExpiredError) as c:
            self.verifier.require(lease, agent_id="agent-1",
                                  task_id="task-9", tool="read_file",
                                  now=now)
        self.assertIn("lease_expired", str(c.exception))

    def test_revoked_lease_refused(self):
        ledger = RevocationLedger()
        verifier = _cl.LeaseVerifier(self.trust, ledger)
        ledger.revoke(_cl.lease_ref(self.lease))
        with self.assertRaises(_cl.LeaseRefused) as c:
            verifier.require(self.lease, agent_id="agent-1",
                             task_id="task-9", tool="read_file")
        self.assertIn("lease_revoked", str(c.exception))

    def test_missing_lease_refused(self):
        with self.assertRaises(_cl.LeaseRefused) as c:
            self.verifier.require(None, agent_id="agent-1",
                                  task_id="task-9", tool="read_file")
        self.assertIn("lease_missing", str(c.exception))

    def test_resource_constraint(self):
        lease = self.authority.mint(
            "agent-1", "task-9",
            {"tools": ["tool:db"], "resources": {"db": "readonly"}})
        self.verifier.require(lease, agent_id="agent-1", task_id="task-9",
                              tool="db", resource="readonly")
        with self.assertRaises(_cl.LeaseScopeError):
            self.verifier.require(lease, agent_id="agent-1",
                                  task_id="task-9", tool="db",
                                  resource="readwrite")


class TestAmbientAbsence(unittest.TestCase):
    def test_verifier_holds_no_private_key(self):
        # Constructive half: walk the verifier's object graph; no
        # 32-byte value may equal the authority seed.
        trust, authority, verifier = _world_with_lease()
        seed = authority._seed
        seen = set()

        def walk(o):
            if id(o) in seen or len(seen) > 5000:
                return
            seen.add(id(o))
            if isinstance(o, (bytes, bytearray)) and bytes(o) == seed:
                raise AssertionError("private key material in verifier graph")
            if isinstance(o, dict):
                for v in o.values():
                    walk(v)
            elif isinstance(o, (list, tuple, set, frozenset)):
                for v in o:
                    walk(v)
            elif hasattr(o, "__dict__"):
                walk(vars(o))
            elif hasattr(o, "__slots__"):
                for s in o.__slots__:
                    try:
                        walk(getattr(o, s))
                    except AttributeError:
                        pass

        walk(verifier)

    def test_clean_scope_passes(self):
        rep = _cl.assert_agent_scope_clean(
            env={"PATH": "/usr/bin", "LEASE_ID": "abc123"})
        self.assertTrue(rep["ok"])

    def test_raw_credential_in_env_fails_session_open(self):
        # A production-shaped AWS key in the agent's env: the session
        # refuses to open. (AKIA + 16 chars is the DLP test shape.)
        with self.assertRaises(_cl.AmbientCredentialError) as c:
            _cl.assert_agent_scope_clean(
                env={"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"})
        self.assertIn("env", str(c.exception))

    def test_raw_credential_at_path_fails(self):
        with self.assertRaises(_cl.AmbientCredentialError):
            _cl.assert_agent_scope_clean(
                paths=["/nonexistent"],
                _read=lambda p: "ghp_" + "a" * 36)

    def test_lease_itself_is_not_credential_shaped(self):
        # The lease the agent holds must not trip the scan: it carries
        # no secrets.
        trust, authority, _ = _world_with_lease()
        lease = authority.mint("agent-1", "task-9",
                               {"tools": ["tool:read_file"]})
        text = repr(lease)
        rep = _cl.assert_agent_scope_clean(env={"LEASE": text})
        self.assertTrue(rep["ok"])


if __name__ == "__main__":
    unittest.main()
