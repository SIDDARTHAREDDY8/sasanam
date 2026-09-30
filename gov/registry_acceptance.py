"""Tampered-registry acceptance (W243-10a, ADAPT -- pattern only, prose
re-derived).

Attacker shapes from the OpenInfra Europe ``artifactory.nordix.org``
breach (via CVE-2026-82329; compromise window 2026-08-28 -> 09-15):
a breached registry serves bytes whose signatures still verify, whose
thresholds are lowered, or whose bytes no longer match the signed
manifest. Acceptance must fail closed on every one of those shapes
*before any install*.

``accept_package(manifest, package_bytes, policy, *, now)`` checks, in
order:

1. Manifest shape (``package-manifest-malformed``).
2. Every signature verifies with a trusted key over the canonical
   manifest payload (``package-signature-invalid``).
3. The number of valid trusted signatures meets
   ``policy["threshold"]`` (``registry-threshold-unmet``) -- note this
   is a registry threshold, distinct from the quorum-domain
   ``threshold-unmet``.
4. Freshness: ``now`` is within ``[issued_at, valid_until]``
   (``package-stale``). A valid signature on a stale manifest is still
   refused -- signatures prove who signed, not that the manifest is
   current.
5. The package bytes digest to the manifest's claimed digest
   (``package-digest-mismatch``), checked BEFORE any install step.

Returns ``{"verdict": "accept", "valid_signatures", "manifest_digest",
"package_digest"}`` on success; otherwise raises.

Refusal vocabulary (domain ``registry-acceptance``, all fail-closed):

* ``package-manifest-malformed`` -- the manifest is not the expected
  shape (payload/signatures/types).
* ``package-signature-invalid`` -- a signature does not verify, is not
  from a trusted key, or is not Ed25519-shaped.
* ``registry-threshold-unmet`` -- fewer valid trusted signatures than
  the policy threshold.
* ``package-stale`` -- the manifest is outside its freshness window.
* ``package-digest-mismatch`` -- the package bytes do not digest to
  the signed manifest digest.

Honest boundaries
-----------------
* Thresholds are policy: this module cannot make a threshold-3 policy
  the deployment's choice -- it only refuses when the policy is not
  met.
* Freshness depends on a caller-supplied ``now``; the module has no
  clock and cannot detect a lying clock.
* Signature trust stops at the trusted-key list: key compromise or a
  malicious signer with a trusted key is outside this seam -- EXCEPT
  where the caller supplies a revocation input to
  ``accept_from_adversarial_registry`` (W245-4): that entry point
  treats the registry as adversarial and refuses keys the revocation
  input names, even though their signatures verify.

W245-4: adversarial-registry acceptance
---------------------------------------
``accept_from_adversarial_registry(manifest, package_bytes, policy,
now, revocation, *, first_seen=None)`` runs the same base checks as
``accept_package`` (same order, same refusals) and then applies the
adversarial additions, in order:

0. Name-trust scan: a policy declaring trust by NAME
   (``trusted_names``, ``trusted_accounts``, ``trusted_publishers``,
   ``publisher_allowlist``) refuses ``package-identity-name-untrusted``
   -- trust is by pinned key identity, never by name; a name-trust
   declaration is refused loudly, never silently ignored.
1. Base checks: shape, signatures, threshold, freshness, digest.
2. Revocation: every counted signature key found in
   ``revocation["revoked_keys"]`` refuses
   ``package-signer-compromised`` -- the signature verifies, but the
   signer is known-compromised (the 18-day tamper-window shape: the
   registry served bytes signed inside the compromise window).
3. First-seen pinning: ``first_seen`` is a caller-supplied mapping
   from ``(name, version)`` to digest. The first observation pins the
   digest; a later observation of the same (name, version) with a
   different digest refuses ``package-digest-first-seen-mismatch``,
   even when the new manifest's signature verifies (the registry
   substituted bytes after first observation).

``revocation`` is a REQUIRED mapping ``{"revoked_keys": [...]}``
(base64 Ed25519 pubkeys); a missing or malformed revocation input
refuses ``verifier-input-malformed`` (reused from the taxonomy) --
the revocation input itself fails closed, and protection is never
silently absent. ``first_seen`` is optional; ``None`` skips pinning.

Honest boundaries (adversarial entry point)
-------------------------------------------
* The revocation input is caller-supplied and deployment-vouched: the
  module checks binding and shape, it cannot make a revocation feed
  honest. A signed-advisory-backed revocation feed is the
  deployment's job (see ``gov.advisory_binding`` for the signed-input
  pattern).
* ``first_seen`` is in-memory; persistence and cross-node
  consistency are deployment-owned. A fresh process has no memory
  of prior observations.
* Pinning is on the manifest's claimed (name, version); a registry
  that bumps the version with new signed bytes is a different pin.


Stdlib only (+ in-repo gov.ed25519, pure-Python, per wave-241
precedent). Deterministic: the caller supplies ``now``.
"""

import base64
import hashlib
import json

from gov import ed25519 as _ed25519

PACKAGE_MANIFEST_MALFORMED = "package-manifest-malformed"
PACKAGE_SIGNATURE_INVALID = "package-signature-invalid"
REGISTRY_THRESHOLD_UNMET = "registry-threshold-unmet"
PACKAGE_STALE = "package-stale"
PACKAGE_DIGEST_MISMATCH = "package-digest-mismatch"

# W245-4: adversarial-registry vocabulary (domain registry-acceptance,
# all fail-closed). Additive only; the base vocabulary above is
# untouched.
PACKAGE_SIGNER_COMPROMISED = "package-signer-compromised"
PACKAGE_IDENTITY_NAME_UNTRUSTED = "package-identity-name-untrusted"
PACKAGE_DIGEST_FIRST_SEEN_MISMATCH = "package-digest-first-seen-mismatch"

# Reused from the existing taxonomy (not redefined here):
#   "verifier-input-malformed"
_VERIFIER_INPUT_MALFORMED = "verifier-input-malformed"

# Policy keys that declare trust by NAME. Any of these present in the
# acceptance policy refuses package-identity-name-untrusted: trust is
# by pinned key identity, never by name.
_NAME_TRUST_KEYS = ("trusted_names", "trusted_accounts",
                    "trusted_publishers", "publisher_allowlist")

_ED25519_SIG_LEN = 64
_ED25519_PUB_LEN = 32


class RegistryAcceptanceError(Exception):
    """Fail-closed registry acceptance refusal. ``code`` is the
    vocabulary."""

    def __init__(self, code, detail=""):
        super(RegistryAcceptanceError, self).__init__(
            "%s: %s" % (code, detail) if detail else code)
        self.code = code
        self.detail = detail


def _malformed(detail):
    raise RegistryAcceptanceError(PACKAGE_MANIFEST_MALFORMED, detail)


def canonical_manifest_bytes(payload):
    """Canonical bytes the signatures cover (JCS-like shape)."""
    try:
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        _malformed("payload not JSON-canonicalizable: %s" % (exc,))
    return text.encode("utf-8")


def _check_manifest(manifest):
    if not isinstance(manifest, dict):
        _malformed("manifest must be a mapping")
    payload = manifest.get("payload")
    if not isinstance(payload, dict):
        _malformed("manifest.payload must be a mapping")
    for field in ("name", "version", "digest"):
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, str) \
                or not value.strip():
            _malformed("payload.%s must be a non-empty string" % field)
    digest = payload["digest"]
    if len(digest) != 64 or any(c not in "0123456789abcdef"
                                for c in digest):
        _malformed("payload.digest must be 64 lowercase hex chars")
    for field in ("issued_at", "valid_until"):
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            _malformed("payload.%s must be a number" % field)
    sigs = manifest.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        _malformed("manifest.signatures must be a non-empty list")
    for i, sig in enumerate(sigs):
        if not isinstance(sig, dict):
            _malformed("signatures[%d] must be a mapping" % i)
        for field in ("key", "sig"):
            value = sig.get(field)
            if not isinstance(value, str) or not value.strip():
                _malformed("signatures[%d].%s must be a non-empty "
                           "string" % (i, field))
    return payload, sigs


def _b64decode(value, what, i=None):
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:  # noqa: BLE001
        label = "signatures[%d].%s" % (i, what) if i is not None else what
        raise RegistryAcceptanceError(
            PACKAGE_SIGNATURE_INVALID,
            "%s is not valid base64" % label)


def _check_policy(policy):
    if not isinstance(policy, dict):
        _malformed("policy must be a mapping")
    threshold = policy.get("threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, int) \
            or threshold < 1:
        raise RegistryAcceptanceError(
            REGISTRY_THRESHOLD_UNMET,
            "policy.threshold must be a positive int")
    trusted = policy.get("trusted_keys")
    if not isinstance(trusted, list) or not trusted or \
            any(not isinstance(k, str) or not k.strip() for k in trusted):
        raise RegistryAcceptanceError(
            PACKAGE_SIGNATURE_INVALID,
            "policy.trusted_keys must be a non-empty list of strings")
    trusted_raw = set()
    for k in trusted:
        raw = _b64decode(k, "trusted key")
        if len(raw) != _ED25519_PUB_LEN:
            raise RegistryAcceptanceError(
                PACKAGE_SIGNATURE_INVALID,
                "trusted key is not %d bytes" % _ED25519_PUB_LEN)
        trusted_raw.add(raw)
    return threshold, trusted_raw


def _valid_signature_keys(payload, sigs, trusted_raw):
    """Count valid trusted signatures; return the counted key set.

    Same refusals as before: any malformed/untrusted/reused/failing
    signature refuses package-signature-invalid fail-closed."""
    body = canonical_manifest_bytes(payload)
    seen_keys = set()
    for i, sig in enumerate(sigs):
        key_raw = _b64decode(sig["key"], "key", i)
        sig_raw = _b64decode(sig["sig"], "sig", i)
        if len(key_raw) != _ED25519_PUB_LEN or \
                len(sig_raw) != _ED25519_SIG_LEN:
            raise RegistryAcceptanceError(
                PACKAGE_SIGNATURE_INVALID,
                "signatures[%d] is not Ed25519-shaped" % i)
        if key_raw not in trusted_raw:
            raise RegistryAcceptanceError(
                PACKAGE_SIGNATURE_INVALID,
                "signatures[%d] is not from a trusted key" % i)
        if key_raw in seen_keys:
            raise RegistryAcceptanceError(
                PACKAGE_SIGNATURE_INVALID,
                "signatures[%d] reuses a key already counted" % i)
        try:
            ok = _ed25519.verify(key_raw, body, sig_raw)
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            raise RegistryAcceptanceError(
                PACKAGE_SIGNATURE_INVALID,
                "signatures[%d] does not verify" % i)
        seen_keys.add(key_raw)
    return seen_keys


def _valid_signatures(payload, sigs, trusted_raw):
    return len(_valid_signature_keys(payload, sigs, trusted_raw))


def accept_package(manifest, package_bytes, policy, now):
    """Accept a package for install, or refuse fail-closed.

    ``manifest`` is ``{"payload": {...}, "signatures": [...]}``;
    ``package_bytes`` the bytes to install; ``policy`` carries
    ``threshold`` and ``trusted_keys`` (base64 Ed25519 pubkeys);
    ``now`` is the caller-supplied time. Returns the acceptance
    record; raises :class:`RegistryAcceptanceError` otherwise.
    """
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        _malformed("now must be a number")
    if not isinstance(package_bytes, (bytes, bytearray)):
        _malformed("package_bytes must be bytes")
    payload, sigs = _check_manifest(manifest)
    threshold, trusted_raw = _check_policy(policy)
    valid = _valid_signatures(payload, sigs, trusted_raw)
    if valid < threshold:
        raise RegistryAcceptanceError(
            REGISTRY_THRESHOLD_UNMET,
            "%d valid trusted signatures, policy requires %d"
            % (valid, threshold))
    if not (payload["issued_at"] <= now <= payload["valid_until"]):
        raise RegistryAcceptanceError(
            PACKAGE_STALE,
            "manifest valid_until=%r is outside the freshness window "
            "at now=%r" % (payload["valid_until"], now))
    package_digest = hashlib.sha256(bytes(package_bytes)).hexdigest()
    if package_digest != payload["digest"]:
        raise RegistryAcceptanceError(
            PACKAGE_DIGEST_MISMATCH,
            "package bytes digest to %s..., manifest claims %s..."
            % (package_digest[:16], payload["digest"][:16]))
    return {
        "verdict": "accept",
        "valid_signatures": valid,
        "manifest_digest": _digest_bytes(canonical_manifest_bytes(payload)),
        "package_digest": package_digest,
        "name": payload["name"],
        "version": payload["version"],
    }


def _digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# W245-4: adversarial-registry acceptance (additive; accept_package
# above is untouched).
# ---------------------------------------------------------------------------

def _refuse_name_trust(policy):
    """Refuse a policy that declares trust by NAME.

    Trust is by pinned key identity, never by name: a policy asking
    for name trust is refused loudly (package-identity-name-untrusted),
    never silently ignored -- silent ignorance would be a fail-open
    misconfiguration the operator believes is enforced."""
    if not isinstance(policy, dict):
        _malformed("policy must be a mapping")
    for key in _NAME_TRUST_KEYS:
        if key in policy:
            raise RegistryAcceptanceError(
                PACKAGE_IDENTITY_NAME_UNTRUSTED,
                "policy[%r] declares trust by name; trust is by pinned "
                "key identity only" % key)


def _check_revocation(revocation):
    """Shape-check the revocation input; return the revoked key set.

    ``revocation`` is REQUIRED (deployment-vouched). A missing or
    malformed input refuses verifier-input-malformed: the compromised-
    key check is never silently absent."""
    if not isinstance(revocation, dict):
        raise RegistryAcceptanceError(
            _VERIFIER_INPUT_MALFORMED,
            "revocation must be a mapping with revoked_keys")
    entries = revocation.get("revoked_keys")
    if isinstance(entries, bool) or not isinstance(entries, list):
        raise RegistryAcceptanceError(
            _VERIFIER_INPUT_MALFORMED,
            "revocation.revoked_keys must be a list")
    revoked = set()
    for i, entry in enumerate(entries):
        if not isinstance(entry, str) or not entry.strip():
            raise RegistryAcceptanceError(
                _VERIFIER_INPUT_MALFORMED,
                "revoked_keys[%d] must be a non-empty string" % i)
        try:
            raw = base64.b64decode(entry.encode("ascii"), validate=True)
        except Exception:  # noqa: BLE001
            raise RegistryAcceptanceError(
                _VERIFIER_INPUT_MALFORMED,
                "revoked_keys[%d] is not valid base64" % i)
        if len(raw) != _ED25519_PUB_LEN:
            raise RegistryAcceptanceError(
                _VERIFIER_INPUT_MALFORMED,
                "revoked_keys[%d] is not %d bytes"
                % (i, _ED25519_PUB_LEN))
        revoked.add(raw)
    return revoked


def _check_first_seen(first_seen, name, version, package_digest):
    """Pin the package digest at first observation of (name, version).

    A later observation of the same (name, version) with a different
    digest refuses package-digest-first-seen-mismatch -- the registry
    substituted bytes after first observation. Re-observing identical
    bytes is fine; a refusal pins nothing."""
    if first_seen is None:
        return
    if not isinstance(first_seen, dict):
        raise RegistryAcceptanceError(
            _VERIFIER_INPUT_MALFORMED,
            "first_seen must be a dict or None")
    pin_key = (name, version)
    prior = first_seen.get(pin_key)
    if prior is None:
        first_seen[pin_key] = package_digest
        return
    if prior != package_digest:
        raise RegistryAcceptanceError(
            PACKAGE_DIGEST_FIRST_SEEN_MISMATCH,
            "digest for %s@%s differs from the first-seen digest "
            "(registry substituted bytes after first observation)"
            % (name, version))


def accept_from_adversarial_registry(manifest, package_bytes, policy,
                                     now, revocation, *, first_seen=None):
    """Accept a package from a registry treated as adversarial.

    Runs the same base checks as :func:`accept_package` (same order,
    same refusals: shape -> signatures -> threshold -> freshness ->
    digest), then applies the adversarial additions:

    0. policy name-trust scan (``package-identity-name-untrusted``);
    1. base checks;
    2. revocation: a counted signature key in the revocation set
       refuses ``package-signer-compromised`` even though the
       signature verifies;
    3. first-seen digest pinning
       (``package-digest-first-seen-mismatch``).

    ``revocation`` is a required ``{"revoked_keys": [...]}`` mapping;
    a missing/malformed one refuses ``verifier-input-malformed``.
    Returns the acceptance record with an ``adversarial_checks`` list;
    raises :class:`RegistryAcceptanceError` otherwise.
    """
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        _malformed("now must be a number")
    if not isinstance(package_bytes, (bytes, bytearray)):
        _malformed("package_bytes must be bytes")
    _refuse_name_trust(policy)
    revoked = _check_revocation(revocation)
    payload, sigs = _check_manifest(manifest)
    threshold, trusted_raw = _check_policy(policy)
    counted_keys = _valid_signature_keys(payload, sigs, trusted_raw)
    if len(counted_keys) < threshold:
        raise RegistryAcceptanceError(
            REGISTRY_THRESHOLD_UNMET,
            "%d valid trusted signatures, policy requires %d"
            % (len(counted_keys), threshold))
    if not (payload["issued_at"] <= now <= payload["valid_until"]):
        raise RegistryAcceptanceError(
            PACKAGE_STALE,
            "manifest valid_until=%r is outside the freshness window "
            "at now=%r" % (payload["valid_until"], now))
    package_digest = hashlib.sha256(bytes(package_bytes)).hexdigest()
    if package_digest != payload["digest"]:
        raise RegistryAcceptanceError(
            PACKAGE_DIGEST_MISMATCH,
            "package bytes digest to %s..., manifest claims %s..."
            % (package_digest[:16], payload["digest"][:16]))
    # The signature verifies -- and that is not enough. A signature
    # proves who signed, never that the registry is honest: a signer
    # compromised inside the tamper window signs bytes the registry
    # serves with a verifying signature.
    compromised = [k for k in counted_keys if k in revoked]
    if compromised:
        raise RegistryAcceptanceError(
            PACKAGE_SIGNER_COMPROMISED,
            "%d counted signature key(s) are in the revocation set; "
            "the signature verifies but the signer is known-compromised"
            % len(compromised))
    _check_first_seen(first_seen, payload["name"], payload["version"],
                      package_digest)
    record = {
        "verdict": "accept",
        "valid_signatures": len(counted_keys),
        "manifest_digest": _digest_bytes(canonical_manifest_bytes(payload)),
        "package_digest": package_digest,
        "name": payload["name"],
        "version": payload["version"],
        "adversarial_checks": ["name-trust", "revocation", "first-seen"],
    }
    return record
