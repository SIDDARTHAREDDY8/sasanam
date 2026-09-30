"""Wave-245 "registry is the adversary" probes (W245-4, red-first).

Attacker shapes from the OpenInfra Europe ``artifactory.nordix.org``
breach (compromise window ~18 days, discovered 2026-09-15; ~406k
exploit attempts observed in a single day; blend-in admin accounts
named like legitimate distribution identities):
- A breached registry serves bytes whose signatures STILL VERIFY. A
  valid signature proves who signed, never that the registry is
  honest -- the signer may have been compromised inside the window.
- Trust placed in account NAMES (``jfrog-distribution``-class
  blend-in identities) is trust in attacker-controlled strings.
  Trust is by pinned key identity, never by name.

A. Adversarial-registry verifier inputs (NEW: extension of
   gov/registry_acceptance, additive only):
  adversary-compromised-key-refused -- a package whose signature
      VERIFIES with a trusted key, but that key is in the
      caller-supplied revocation set, refuses
      ``package-signer-compromised``. The refusal is
      revocation-driven: the same package with an empty (or
      non-matching) revocation set is accepted.
  adversary-name-trust-policy-refused -- a policy declaring trust by
      name (``trusted_names`` / ``trusted_accounts`` /
      ``trusted_publishers`` / ``*_allowlist``) refuses
      ``package-identity-name-untrusted`` LOUDLY, never silently
      ignored: a silently-ignored name-trust declaration is a
      fail-open misconfiguration.
  adversary-first-seen-digest-mismatch -- the verifier pins the
      package digest at first observation of a (name, version); a
      later observation of the same (name, version) with a different
      digest -- even with a valid signature -- refuses
      ``package-digest-first-seen-mismatch`` (silent substitution
      after first observation).
  adversary-revocation-input-malformed -- a non-mapping revocation
      input, or one whose ``revoked_keys`` is not a list, refuses
      ``verifier-input-malformed``: the revocation input itself
      fails closed.

B. Conformance pins (existing seams; already held on the pristine
   base):
  registry-publisher-name-ignored -- a manifest whose payload carries
      a blend-in publisher name is accepted iff the SIGNING KEY
      verifies (the name is display data, never evidence); the same
      name with an untrusted key still refuses
      ``package-signature-invalid``: a name never substitutes for a
      key.
  registry-accept-contract-unchanged -- ``accept_package`` accepts a
      fully valid package: the lane does not change the base
      contract.

Stdlib only (+ in-repo gov.ed25519 for signatures). Deterministic:
fixed seeds, fixed timestamps. No in-repo git subprocesses.
"""

import base64
import hashlib
import json
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_REGISTRY = False
try:
    from gov import registry_acceptance as _rg
    HAVE_REGISTRY = all(hasattr(_rg, n) for n in (
        "accept_package", "canonical_manifest_bytes",
        "RegistryAcceptanceError"))
except ImportError:
    _rg = None

HAVE_ADVERSARY = False
try:
    HAVE_ADVERSARY = HAVE_REGISTRY and all(hasattr(_rg, n) for n in (
        "accept_from_adversarial_registry",
        "PACKAGE_SIGNER_COMPROMISED",
        "PACKAGE_IDENTITY_NAME_UNTRUSTED",
        "PACKAGE_DIGEST_FIRST_SEEN_MISMATCH"))
except Exception:  # noqa: BLE001
    HAVE_ADVERSARY = False

HAVE_ED25519 = False
try:
    from gov import ed25519 as _e
    HAVE_ED25519 = all(hasattr(_e, n) for n in (
        "publickey", "sign", "verify"))
except ImportError:
    _e = None

T_FETCH = 1727731200
T_NOW = T_FETCH + 1800            # 30 min later: inside freshness windows

_SEEDS = [bytes([0xC0 + i]) * 32 for i in range(4)]
_PUBS = None


def _pubs():
    global _PUBS
    if _PUBS is None:
        _PUBS = [_e.publickey(s) for s in _SEEDS]
    return _PUBS


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _sign_manifest(payload, seed_idx):
    body = _rg.canonical_manifest_bytes(payload)
    return {"key": _b64(_pubs()[seed_idx]),
            "sig": _b64(_e.sign(_SEEDS[seed_idx], body))}


def _payload(name, version, package_bytes, extra=None):
    payload = {"name": name, "version": version,
               "digest": hashlib.sha256(package_bytes).hexdigest(),
               "issued_at": T_FETCH, "valid_until": T_FETCH + 3600}
    if extra:
        payload.update(extra)
    return payload


def _manifest(payload, seed_idx=0):
    return {"payload": payload,
            "signatures": [_sign_manifest(payload, seed_idx)]}


def _policy(**over):
    policy = {"threshold": 1,
              "trusted_keys": [_b64(p) for p in _pubs()]}
    policy.update(over)
    return policy


def _revocation(*b64_keys):
    return {"revoked_keys": list(b64_keys)}


def _run_probe(name, fn, have, pin=False):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, ("PIN" if pin else "HELD"), note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    try:
        fn()
    except _rg.RegistryAcceptanceError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


# ---------------------------------------------------------------------------
# A. Adversarial-registry inputs (need the lane's extension)
# ---------------------------------------------------------------------------

def _probe_compromised_key():
    # The signing key is trusted AND its signature verifies, but the
    # revocation input lists it as compromised: refuse, loudly.
    package_bytes = b"pkg-bytes-v1"
    manifest = _manifest(_payload("skill-pack", "1.0.0", package_bytes))
    policy = _policy()
    revoked = _revocation(_b64(_pubs()[0]))
    note = _expect_refusal(
        lambda: _rg.accept_from_adversarial_registry(
            manifest, package_bytes, policy, T_NOW, revoked),
        "package-signer-compromised")
    # Control: the SAME package with a revocation set that does not
    # name the signing key is accepted -- the refusal is
    # revocation-driven, not key-driven.
    res = _rg.accept_from_adversarial_registry(
        manifest, package_bytes, policy, T_NOW, _revocation())
    assert res["verdict"] == "accept", "got %r" % (res,)
    res2 = _rg.accept_from_adversarial_registry(
        manifest, package_bytes, policy, T_NOW,
        _revocation(_b64(_pubs()[3])))
    assert res2["verdict"] == "accept", "got %r" % (res2,)
    return "%s; revocation-driven (empty/non-matching set accepts)" % note


def _probe_name_trust_policy():
    # A policy that declares trust by NAME is refused loudly, even
    # when the package itself would verify: silently ignoring a
    # name-trust declaration is a fail-open misconfiguration.
    package_bytes = b"pkg-bytes-v1"
    manifest = _manifest(_payload("skill-pack", "1.0.0", package_bytes))
    for name_key in ("trusted_names", "trusted_accounts",
                     "trusted_publishers", "publisher_allowlist"):
        policy = _policy(**{name_key: ["jfrog-distribution"]})
        note = _expect_refusal(
            lambda p=policy: _rg.accept_from_adversarial_registry(
                manifest, package_bytes, p, T_NOW, _revocation()),
            "package-identity-name-untrusted")
    # Control: the same package with a name-free policy accepts.
    res = _rg.accept_from_adversarial_registry(
        manifest, package_bytes, _policy(), T_NOW, _revocation())
    assert res["verdict"] == "accept", "got %r" % (res,)
    return "%s (all four name-trust keys); name-free policy accepts" % note


def _probe_first_seen_digest():
    # First observation pins the digest; a later observation of the
    # same (name, version) with different bytes -- valid signature or
    # not -- is refused as a silent substitution.
    store = {}
    pkg_v1 = b"pkg-bytes-v1"
    manifest1 = _manifest(_payload("skill-pack", "1.0.0", pkg_v1))
    res = _rg.accept_from_adversarial_registry(
        manifest1, pkg_v1, _policy(), T_NOW, _revocation(),
        first_seen=store)
    assert res["verdict"] == "accept", "got %r" % (res,)
    assert store.get(("skill-pack", "1.0.0")) == \
        hashlib.sha256(pkg_v1).hexdigest(), \
        "first observation must pin the digest, got %r" % (store,)
    # Re-observing the IDENTICAL bytes is fine.
    res2 = _rg.accept_from_adversarial_registry(
        manifest1, pkg_v1, _policy(), T_NOW, _revocation(),
        first_seen=store)
    assert res2["verdict"] == "accept", "got %r" % (res2,)
    # Substituted bytes with a VALID fresh signature are refused.
    pkg_v2 = b"pkg-bytes-v1-TAMPERED"
    manifest2 = _manifest(_payload("skill-pack", "1.0.0", pkg_v2))
    note = _expect_refusal(
        lambda: _rg.accept_from_adversarial_registry(
            manifest2, pkg_v2, _policy(), T_NOW, _revocation(),
            first_seen=store),
        "package-digest-first-seen-mismatch")
    # The store still holds the original digest (refusal pins nothing).
    assert store[("skill-pack", "1.0.0")] == \
        hashlib.sha256(pkg_v1).hexdigest()
    # A DIFFERENT version is a different pin: accepted and recorded.
    pkg_other = b"pkg-bytes-other-version"
    manifest3 = _manifest(_payload("skill-pack", "2.0.0", pkg_other))
    res3 = _rg.accept_from_adversarial_registry(
        manifest3, pkg_other, _policy(), T_NOW, _revocation(),
        first_seen=store)
    assert res3["verdict"] == "accept", "got %r" % (res3,)
    return "%s; re-observe identical ok, new version pinned separately" % note


def _probe_revocation_malformed():
    # The revocation input itself fails closed.
    package_bytes = b"pkg-bytes-v1"
    manifest = _manifest(_payload("skill-pack", "1.0.0", package_bytes))
    policy = _policy()
    note1 = _expect_refusal(
        lambda: _rg.accept_from_adversarial_registry(
            manifest, package_bytes, policy, T_NOW, None),
        "verifier-input-malformed")
    note2 = _expect_refusal(
        lambda: _rg.accept_from_adversarial_registry(
            manifest, package_bytes, policy, T_NOW,
            {"revoked_keys": "not-a-list"}),
        "verifier-input-malformed")
    # A 32-byte-shaped but unparseable key entry is malformed too.
    note3 = _expect_refusal(
        lambda: _rg.accept_from_adversarial_registry(
            manifest, package_bytes, policy, T_NOW,
            {"revoked_keys": ["!!!not-base64!!!"]}),
        "verifier-input-malformed")
    return "%s; %s; %s" % (note1, note2, note3)


# ---------------------------------------------------------------------------
# B. Conformance pins (existing seams)
# ---------------------------------------------------------------------------

def _probe_publisher_name_ignored():
    # A blend-in publisher NAME is display data only: acceptance
    # turns on the signing KEY, never the name.
    package_bytes = b"pkg-bytes-v1"
    payload = _payload("skill-pack", "1.0.0", package_bytes,
                       extra={"publisher": "jfrog-distribution"})
    manifest = _manifest(payload)
    res = _rg.accept_package(manifest, package_bytes, _policy(),
                             now=T_NOW)
    assert res["verdict"] == "accept", "got %r" % (res,)
    # The same name with an UNTRUSTED signing key is still refused:
    # a name never substitutes for a key.
    rogue = bytes([0xFD]) * 32
    rogue_pub = _e.publickey(rogue)
    body = _rg.canonical_manifest_bytes(payload)
    bad = {"payload": payload,
           "signatures": [{"key": _b64(rogue_pub),
                           "sig": _b64(_e.sign(rogue, body))}]}
    note = _expect_refusal(
        lambda: _rg.accept_package(bad, package_bytes, _policy(),
                                   now=T_NOW),
        "package-signature-invalid")
    return "name ignored on trusted key (accept); %s on untrusted key" % note


def _probe_accept_contract_unchanged():
    package_bytes = b"pkg-bytes-v1"
    manifest = _manifest(_payload("skill-pack", "1.0.0", package_bytes))
    res = _rg.accept_package(manifest, package_bytes, _policy(),
                             now=T_NOW)
    assert res["verdict"] == "accept", "got %r" % (res,)
    assert res["name"] == "skill-pack" and res["version"] == "1.0.0"
    return "base contract untouched"


_PROBES = [
    # (name, fn, have-flag-name, is_conformance_pin)
    ("adversary-compromised-key-refused", _probe_compromised_key,
     "HAVE_ADVERSARY", False),
    ("adversary-name-trust-policy-refused", _probe_name_trust_policy,
     "HAVE_ADVERSARY", False),
    ("adversary-first-seen-digest-mismatch", _probe_first_seen_digest,
     "HAVE_ADVERSARY", False),
    ("adversary-revocation-input-malformed", _probe_revocation_malformed,
     "HAVE_ADVERSARY", False),
    ("registry-publisher-name-ignored", _probe_publisher_name_ignored,
     "HAVE_REGISTRY", True),
    ("registry-accept-contract-unchanged", _probe_accept_contract_unchanged,
     "HAVE_REGISTRY", True),
]


def main():
    # This battery spawns no nested green-check subprocesses, so there
    # is nothing to skip here -- the probes must always run. (Wave-244
    # merge lesson: a battery that returns early on GOV_SKIP_GREEN=1
    # is a vacuous pass when run depth-1.)
    if not HAVE_ED25519:
        print("ERROR: gov.ed25519 unavailable")
        return 1
    flags = {"HAVE_ADVERSARY": HAVE_ADVERSARY,
             "HAVE_REGISTRY": HAVE_REGISTRY}
    results = []
    for name, fn, flag, pin in _PROBES:
        results.append(_run_probe(name, fn, flags[flag], pin=pin))
    held = sum(1 for _, s, _ in results if s in ("HELD", "PIN"))
    total = len(results)
    for name, status, note in results:
        print("%-42s %-6s %s" % (name, status, note.split("\n")[0]))
    print("w245_registry_adversary: %d/%d HELD-or-PIN" % (held, total))
    return 0 if held == total else 2


if __name__ == "__main__":
    sys.exit(main())
