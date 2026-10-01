#!/usr/bin/env python3
"""Short-lived evidence-signing certificate ceremony ("mini-Fulcio").

A CA that binds an ephemeral Ed25519 subject key to a human approval
for evidence signing, in the style of Sigstore's Fulcio (identity
assertion in, short-lived certificate out). The CA private key NEVER
leaves the KMS: issuance calls ``KmsProvider.sign(key_id, digest)``
and verifies the returned signature against the configured CA public
key before minting.

Honest limits (also embedded verbatim in every minted certificate):

* the certificate does NOT mean "the approval was independently
  investigated" -- it proves only that the subject key was bound to
  the named approval for the named principal at issuance;
* a verifying client learns the approval's principal identity
  (privacy consideration noted in the certificate's honest-limits
  text);
* a CA operator's issuance log could correlate principals to signing
  activity (anonymized-CA research is cited as future work).

Issuance checks run in a fixed order and each refusal carries a
machine-readable ``evcert-*`` code (see :class:`EvidenceCertError`
and ``gov/decision_codes.py``):

1. request shape (evcert-malformed-request)
2. issuer allowlist + assertion expiry
   (evcert-unknown-issuer, evcert-assertion-expired)
3. approval resolution + identity==decider
   (evcert-unknown-approval, evcert-identity-not-decider)
4. proof of possession (evcert-pop-invalid)
5. subject-key non-reuse registry (evcert-key-reused)
6. transparency-anchor reachability (evcert-anchor-unavailable;
   refuses -- there is deliberately NO bypass switch)
7. KMS signing capability + signature self-check
   (evcert-kms-cannot-sign; operational KMS failures raise
   gov.kms.KmsError, never a local-key fallback)

Lifetime discipline: default 10 minutes, deployment-capped at 60
minutes; anything over 24 hours requires a configured status-list
URL (otherwise refused at CA construction).

The legacy corroboration-receipt path (``gov/corroboration_receipt.py``)
is deliberately untouched: byte-identity is preserved by construction
and certificate binding composes by digest, never by mutation.

Stdlib only. No network except the KMS provider's own transport.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import tempfile

from .ed25519 import verify as _ed_verify
from .kms import KmsError, KmsProvider, provider_can_sign
from .signing import _canonical_body, ed25519_key_id

# ---------------------------------------------------------------------------
# Protocol constants (the battery pins these from the spec independently)
# ---------------------------------------------------------------------------

CERT_FORMAT = "sasanam-evidence-cert/v1"
CERT_EKU = "evidence-signing"
POP_DOMAIN = b"evcert-pop-v1"

DEFAULT_LIFETIME_S = 600          # 10 minutes
DEFAULT_MAX_LIFETIME_S = 3600     # 60 minutes
ABSOLUTE_MAX_LIFETIME_S = 86400   # 24 hours without a status-list URL
MIN_LIFETIME_S = 60
REGISTRY_SKEW_S = 300             # clock-skew bound for registry pruning
REGISTRY_FILE = "evcert-seen-keys.json"

HONEST_LIMITS_TEXT = (
    "This certificate proves only that the subject key was bound to the "
    "named approval for the named principal at issuance. It does not mean "
    "the approval was independently investigated. A verifying client learns "
    "the approval's principal identity; a CA operator's issuance log could "
    "correlate principals to signing activity. "
    "Short-lived by design: verify the validity window and the "
    "transparency anchor; do not trust a certificate past not_after."
)

# Expected top-level certificate fields (exact set enforced at verify).
_CERT_FIELDS = frozenset({
    "format", "subject_public_key", "subject_key_id", "issuer_key_id",
    "not_before", "not_after", "eku", "extensions", "honest_limits",
    "ca_signature",
})

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Single-label wildcard: https://*.suffix where suffix is a dotted host.
# The * binds exactly one DNS label ([-_a-zA-Z0-9]+) -- it can never span
# labels and the match is anchored, so "suffix.evil.com" and
# "a.b.suffix" both fail (GHSA-59jp-pj84-45mr class).
_WILDCARD_RE = re.compile(r"^https://\*\.([A-Za-z0-9]([A-Za-z0-9.-]*"
                           r"[A-Za-z0-9])?)$")
_ISS_RE = re.compile(r"^https://([A-Za-z0-9_-]+)\.([A-Za-z0-9]"
                     r"([A-Za-z0-9.-]*[A-Za-z0-9])?)$")


class EvidenceCertError(Exception):
    """Ceremony refusal. ``code`` is one of the machine-readable
    ``evcert-*`` codes; ``detail`` is human context only."""

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super(EvidenceCertError, self).__init__(
            "%s: %s" % (code, detail) if detail else code)


# ---------------------------------------------------------------------------
# Issuer allowlist
# ---------------------------------------------------------------------------

def _issuer_allows(pattern, iss):
    """True iff identity-issuer ``iss`` matches allowlist ``pattern``.

    ``pattern`` is either an exact URL or ``https://*.suffix`` (single
    label wildcard). Matching is anchored at both ends; the wildcard
    never spans labels and non-https schemes never match.
    """
    if not isinstance(pattern, str) or not isinstance(iss, str):
        return False
    if "*" not in pattern:
        return hmac.compare_digest(pattern, iss)
    m = _WILDCARD_RE.match(pattern)
    if not m:
        return False
    suffix = m.group(1)
    m2 = _ISS_RE.match(iss)
    if not m2:
        return False
    return hmac.compare_digest(m2.group(2), suffix)


def _pop_challenge(approval_id, ephemeral_pub):
    return (POP_DOMAIN + approval_id.encode("utf-8")
            + hashlib.sha256(ephemeral_pub).digest())


# ---------------------------------------------------------------------------
# Seen-key-id registry (persisted alongside the audit log)
# ---------------------------------------------------------------------------

def _registry_path(audit_log_path):
    return os.path.join(os.path.dirname(os.path.abspath(audit_log_path)),
                        REGISTRY_FILE)


def _load_registry(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        # A registry we cannot read cannot uphold the non-reuse
        # guarantee: fail closed. The registry is part of the
        # transparency substrate (persisted alongside the audit log),
        # so this is an anchor-substrate failure.
        raise EvidenceCertError(
            "evcert-anchor-unavailable",
            "seen-key-id registry unreadable (%s); refusing issuance "
            "until the registry is restored" % e)
    if not isinstance(doc, dict):
        raise EvidenceCertError(
            "evcert-anchor-unavailable",
            "seen-key-id registry malformed; refusing issuance")
    return doc


def _prune_registry(registry, now):
    """Drop entries whose certificates can no longer be valid: the
    non-reuse rule only needs to cover keys whose certs could still
    verify (R4: prune after not_after + clock-skew bound)."""
    cutoff = now - REGISTRY_SKEW_S
    for key_id in [k for k, v in registry.items()
                   if not isinstance(v, dict)
                   or not isinstance(v.get("not_after"), int)
                   or v["not_after"] <= cutoff]:
        del registry[key_id]
    return registry


def _save_registry(path, registry):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory or ".", prefix=".evcert-reg-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(registry, f, sort_keys=True)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

# ---------------------------------------------------------------------------
# The CA
# ---------------------------------------------------------------------------

class EvidenceCA(object):
    """Short-lived evidence-signing certificate authority.

    ``kms_provider`` must be a :class:`gov.kms.KmsProvider` whose
    backend can sign (``provider_can_sign`` is checked on every
    issuance); the CA key ``ca_key_id`` never leaves the KMS.

    ``approval_lookup(approval_id)`` returns
    ``{"decider": str, "state": str} | None`` and is consulted at
    issuance time. ``"state"`` must be exactly ``"pending"`` --
    resolved approvals are refused. This keeps the CA decoupled from
    any approval-queue implementation (the gate's decider field is
    honored by value, never by import).

    ``anchor_reachable()`` is a zero-arg callable returning bool; any
    exception propagates (never swallowed) and ``False`` refuses
    issuance -- there is deliberately no bypass switch (D8).

    ``oid_arc`` is the private-enterprise OID arc; the issuer and
    subject land at ``<arc>.1.8`` and ``<arc>.1.24``.
    """

    def __init__(self, *, kms_provider, ca_key_id, ca_public_key,
                 issuers, approval_lookup, audit_log_path,
                 anchor_reachable, oid_arc,
                 default_lifetime_s=DEFAULT_LIFETIME_S,
                 max_lifetime_s=DEFAULT_MAX_LIFETIME_S,
                 status_list_url=None, now=None):
        if not isinstance(kms_provider, KmsProvider):
            raise TypeError("kms_provider must be a gov.kms.KmsProvider")
        kms_provider._validate_key_id(ca_key_id)
        if not isinstance(ca_public_key, (bytes, bytearray)) \
                or len(ca_public_key) != 32:
            raise ValueError("ca_public_key must be 32 bytes")
        if not issuers or not all(isinstance(p, str) and p for p in issuers):
            raise ValueError("issuers must be a non-empty list of URL "
                             "patterns")
        if not callable(approval_lookup):
            raise TypeError("approval_lookup must be callable")
        if not audit_log_path:
            raise ValueError("audit_log_path is required")
        if not callable(anchor_reachable):
            raise TypeError("anchor_reachable must be callable")
        if not re.fullmatch(r"[0-9]+(\.[0-9]+)+", oid_arc or ""):
            raise ValueError("oid_arc must be a dotted-decimal OID arc")
        if not (isinstance(default_lifetime_s, int)
                and MIN_LIFETIME_S <= default_lifetime_s
                <= max_lifetime_s):
            raise ValueError("default_lifetime_s out of range")
        if not (isinstance(max_lifetime_s, int)
                and MIN_LIFETIME_S <= max_lifetime_s):
            raise ValueError("max_lifetime_s out of range")
        if max_lifetime_s > ABSOLUTE_MAX_LIFETIME_S and not status_list_url:
            # D9: anything over 24h requires revocation infrastructure.
            raise ValueError(
                "max_lifetime_s > 24h requires status_list_url")
        self._kms = kms_provider
        self._ca_key_id = ca_key_id
        self._ca_public_key = bytes(ca_public_key)
        self._issuers = list(issuers)
        self._approval_lookup = approval_lookup
        self._audit_log_path = audit_log_path
        self._anchor_reachable = anchor_reachable
        self._oid_arc = oid_arc
        self._default_lifetime_s = default_lifetime_s
        self._max_lifetime_s = max_lifetime_s
        self._status_list_url = status_list_url
        self._now = now or __import__("time").time

    # -- issuance ----------------------------------------------------------

    def _now_s(self):
        return int(self._now())

    def issue(self, *, identity_assertion, ephemeral_pub, pop_sig,
              approval_id, intent_digest, lifetime_s=None):
        """Run the issuance checks in order and mint a certificate.

        Returns ``(cert, audit_entry)``. Every refusal raises
        :class:`EvidenceCertError` with its machine code.
        """
        now = self._now_s()

        # (0) KMS capability -- fail fast, before any check that could
        # be mistaken for progress. Envelope-only backends fail closed
        # here; there is never a local-key fallback.
        if not provider_can_sign(self._kms):
            raise EvidenceCertError(
                "evcert-kms-cannot-sign",
                "KMS provider %r cannot sign; issuance refused rather "
                "than falling back to a local key"
                % (self._kms.provider_name,))

        # (1) request shape
        self._check_shape(identity_assertion, ephemeral_pub, pop_sig,
                          approval_id, intent_digest)
        lifetime = self._default_lifetime_s if lifetime_s is None \
            else lifetime_s
        if not isinstance(lifetime, int) \
                or not (MIN_LIFETIME_S <= lifetime <= self._max_lifetime_s):
            raise EvidenceCertError(
                "evcert-lifetime-exceeded",
                "requested lifetime %r outside [%d, %d]"
                % (lifetime_s, MIN_LIFETIME_S, self._max_lifetime_s))
        iss = identity_assertion["iss"]
        sub = identity_assertion["sub"]
        exp = identity_assertion.get("exp")

        # (2) issuer allowlist + assertion expiry
        if not any(_issuer_allows(p, iss) for p in self._issuers):
            raise EvidenceCertError("evcert-unknown-issuer",
                                    "issuer %r not in allowlist" % (iss,))
        if not isinstance(exp, int) or exp <= now:
            raise EvidenceCertError("evcert-assertion-expired",
                                    "assertion exp %r <= now %d"
                                    % (exp, now))

        # (3) approval resolution + identity == decider
        appr = self._approval_lookup(approval_id)
        if appr is None or not isinstance(appr, dict) \
                or appr.get("state") != "pending":
            raise EvidenceCertError(
                "evcert-unknown-approval",
                "approval %r is not a pending approval" % (approval_id,))
        if appr.get("decider") != sub:
            raise EvidenceCertError(
                "evcert-identity-not-decider",
                "assertion sub %r != approval decider %r"
                % (sub, appr.get("decider")))

        # (4) proof of possession
        challenge = _pop_challenge(approval_id, ephemeral_pub)
        if _ed_verify(bytes(ephemeral_pub), challenge,
                      bytes(pop_sig)) is not True:
            raise EvidenceCertError(
                "evcert-pop-invalid",
                "proof-of-possession signature does not verify against "
                "the presented subject key and approval-bound challenge")

        # (5) subject-key non-reuse
        key_id = ed25519_key_id(bytes(ephemeral_pub))
        reg_path = _registry_path(self._audit_log_path)
        registry = _prune_registry(_load_registry(reg_path), now)
        if key_id in registry:
            raise EvidenceCertError(
                "evcert-key-reused",
                "subject key id %s already bound to approval %s; "
                "ephemeral keys are single-use" % (key_id, registry[key_id]
                                                  .get("approval_id")))

        # (6) transparency anchor -- refuse, never bypass
        if not self._anchor_reachable():
            raise EvidenceCertError(
                "evcert-anchor-unavailable",
                "transparency anchor unreachable; issuance refused "
                "(no bypass switch exists by design)")

        # (7) mint via the KMS, self-check the signature
        not_before = now
        not_after = now + lifetime
        body = {
            "format": CERT_FORMAT,
            "subject_public_key": base64.b64encode(
                bytes(ephemeral_pub)).decode("ascii"),
            "subject_key_id": key_id,
            "issuer_key_id": self._ca_key_id,
            "not_before": not_before,
            "not_after": not_after,
            "eku": CERT_EKU,
            "extensions": {
                "approval_id": approval_id,
                "intent_digest": intent_digest,
                "principal": sub,
                self._oid_arc + ".1.8": iss,
                self._oid_arc + ".1.24": sub,
            },
            "honest_limits": HONEST_LIMITS_TEXT,
        }
        canonical = _canonical_body(body)
        digest = hashlib.sha256(canonical).digest()
        try:
            ca_sig = self._kms.sign(self._ca_key_id, digest)
        except KmsError:
            # Operational KMS failure: fail closed, loudly. This is not
            # a capability refusal (checked above) and is never mapped
            # to a local fallback.
            raise
        if not isinstance(ca_sig, (bytes, bytearray)) or len(ca_sig) != 64:
            raise EvidenceCertError(
                "evcert-chain-invalid",
                "KMS returned a malformed CA signature")
        # Mint-time self-check: the CA never mints an unverifiable cert.
        # The KMS signs the SHA-256 digest of the canonical body
        # (prehashed semantics), so verification runs over the digest.
        if _ed_verify(self._ca_public_key, digest,
                      bytes(ca_sig)) is not True:
            raise EvidenceCertError(
                "evcert-chain-invalid",
                "CA signature self-check failed; refusing to mint")
        cert = dict(body)
        cert["ca_signature"] = base64.b64encode(bytes(ca_sig)).decode("ascii")

        # Persist the non-reuse claim BEFORE the audit append, so a
        # crash between mint and audit cannot silently re-issue the key.
        registry[key_id] = {"not_after": not_after,
                            "approval_id": approval_id,
                            "principal": sub}
        _save_registry(reg_path, registry)

        # Audit-log append. If it fails, roll the registry claim back:
        # this issuance never happened, so the key must stay usable.
        attestation = {
            "kind": "evidence-cert-issued",
            "cert_digest": hashlib.sha256(canonical).hexdigest(),
            "cert": cert,
            "approval_id": approval_id,
            "principal": sub,
            "subject_key_id": key_id,
            "not_after": not_after,
            "anchor_status": "reachable",
        }
        from . import log as _audit_log
        try:
            stored = _audit_log.open_audit_log(
                self._audit_log_path).append(attestation)
        except Exception:
            del registry[key_id]
            _save_registry(reg_path, registry)
            raise
        return cert, stored

    @staticmethod
    def _check_shape(identity_assertion, ephemeral_pub, pop_sig,
                     approval_id, intent_digest):
        if not isinstance(identity_assertion, dict) \
                or not isinstance(identity_assertion.get("iss"), str) \
                or not identity_assertion["iss"] \
                or not isinstance(identity_assertion.get("sub"), str) \
                or not identity_assertion["sub"]:
            raise EvidenceCertError("evcert-malformed-request",
                                    "identity assertion must carry "
                                    "non-empty iss/sub strings")
        if not isinstance(ephemeral_pub, (bytes, bytearray)) \
                or len(ephemeral_pub) != 32:
            raise EvidenceCertError("evcert-malformed-request",
                                    "ephemeral_pub must be 32 bytes")
        if not isinstance(pop_sig, (bytes, bytearray)) \
                or len(pop_sig) != 64:
            raise EvidenceCertError("evcert-malformed-request",
                                    "pop_sig must be 64 bytes")
        if not isinstance(approval_id, str) \
                or not _HEX32.match(approval_id):
            raise EvidenceCertError("evcert-malformed-request",
                                    "approval_id must be 32 hex chars")
        if not isinstance(intent_digest, str) \
                or not _HEX64.match(intent_digest):
            raise EvidenceCertError("evcert-malformed-request",
                                    "intent_digest must be 64 hex chars")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _b64_cert_bytes(cert, field, expected_len, code="evcert-malformed-cert"):
    try:
        raw = base64.b64decode(cert[field], validate=True)
    except Exception:
        raise EvidenceCertError(code, "%s is not valid base64" % field)
    if len(raw) != expected_len:
        raise EvidenceCertError(code, "%s has wrong length" % field)
    return raw


def verify_cert_chain(cert, ca_public_key, now):
    """Verify a certificate: shape, validity window, then CA signature.

    Returns the normalized cert dict. Refusals:
    evcert-malformed-cert (shape), evcert-cert-expired (window),
    evcert-chain-invalid (signature). The verifier's clock is
    ``now`` (int epoch seconds).
    """
    if not isinstance(cert, dict) or set(cert.keys()) != _CERT_FIELDS:
        raise EvidenceCertError("evcert-malformed-cert",
                                "certificate fields %r != expected %r"
                                % (sorted(cert.keys()) if isinstance(
                                    cert, dict) else type(cert).__name__,
                                    sorted(_CERT_FIELDS)))
    if cert["format"] != CERT_FORMAT:
        raise EvidenceCertError("evcert-malformed-cert",
                                "unknown cert format %r" % (cert["format"],))
    if cert["eku"] != CERT_EKU:
        raise EvidenceCertError("evcert-malformed-cert",
                                "unexpected EKU %r" % (cert["eku"],))
    if not isinstance(cert["honest_limits"], str) \
            or not cert["honest_limits"]:
        raise EvidenceCertError("evcert-malformed-cert",
                                "honest_limits missing")
    if not isinstance(cert["not_before"], int) \
            or not isinstance(cert["not_after"], int) \
            or not cert["not_before"] <= cert["not_after"]:
        raise EvidenceCertError("evcert-malformed-cert",
                                "invalid validity window")
    if not (cert["not_before"] <= now <= cert["not_after"]):
        raise EvidenceCertError(
            "evcert-cert-expired",
            "now=%d outside [%d, %d]" % (now, cert["not_before"],
                                         cert["not_after"]))
    if not isinstance(ca_public_key, (bytes, bytearray)) \
            or len(ca_public_key) != 32:
        raise EvidenceCertError("evcert-malformed-cert",
                                "ca_public_key must be 32 bytes")
    subject_pub = _b64_cert_bytes(cert, "subject_public_key", 32)
    if not isinstance(cert["subject_key_id"], str) \
            or not hmac.compare_digest(cert["subject_key_id"],
                                       ed25519_key_id(subject_pub)):
        raise EvidenceCertError("evcert-malformed-cert",
                                "subject_key_id does not match "
                                "subject_public_key")
    if not isinstance(cert["issuer_key_id"], str) \
            or not cert["issuer_key_id"]:
        raise EvidenceCertError("evcert-malformed-cert",
                                "issuer_key_id missing")
    ext = cert["extensions"]
    if not isinstance(ext, dict):
        raise EvidenceCertError("evcert-malformed-cert",
                                "extensions must be a dict")
    if not isinstance(ext.get("approval_id"), str) \
            or not _HEX32.match(ext["approval_id"]):
        raise EvidenceCertError("evcert-malformed-cert",
                                "extensions.approval_id malformed")
    if not isinstance(ext.get("intent_digest"), str) \
            or not _HEX64.match(ext["intent_digest"]):
        raise EvidenceCertError("evcert-malformed-cert",
                                "extensions.intent_digest malformed")
    if not isinstance(ext.get("principal"), str) or not ext["principal"]:
        raise EvidenceCertError("evcert-malformed-cert",
                                "extensions.principal missing")
    oid_keys = [k for k in ext if re.fullmatch(r"[0-9]+(\.[0-9]+)+", k)]
    non_oid = {k for k in ext if k not in oid_keys}
    if non_oid != {"approval_id", "intent_digest", "principal"}:
        raise EvidenceCertError("evcert-malformed-cert",
                                "extensions carry unexpected fields %r"
                                % sorted(non_oid))
    if len(oid_keys) != 2 or not all(
            isinstance(ext[k], str) and ext[k] for k in oid_keys):
        raise EvidenceCertError("evcert-malformed-cert",
                                "extensions must carry exactly two OID "
                                "fields (issuer, subject)")
    body = {k: v for k, v in cert.items() if k != "ca_signature"}
    canonical = _canonical_body(body)
    ca_sig = _b64_cert_bytes(cert, "ca_signature", 64,
                            code="evcert-chain-invalid")
    # The CA signature is over the SHA-256 digest of the canonical body
    # (the KMS signs prehashed); verification recomputes that digest.
    ca_digest = hashlib.sha256(canonical).digest()
    if _ed_verify(bytes(ca_public_key), ca_digest, ca_sig) is not True:
        raise EvidenceCertError("evcert-chain-invalid",
                                "CA signature does not verify")
    return dict(cert)


def cert_digest(cert):
    """Join key between a certificate, its audit attestation, and an
    artifact-signature attestation: sha256 over the canonical body."""
    body = {k: v for k, v in cert.items() if k != "ca_signature"}
    return hashlib.sha256(_canonical_body(body)).hexdigest()


def verify_evidence_signature(*, cert, artifact_bytes, artifact_signature,
                              approval_id, intent_digest, ca_public_key,
                              verify_time):
    """Verify an evidence signature against a certificate.

    Order is fixed: chain first, then binding. Chain failures raise
    evcert-malformed-cert / evcert-cert-expired / evcert-chain-invalid;
    any binding failure (wrong key, approval mismatch, intent mismatch)
    raises evcert-binding-invalid. Returns a small verified record.
    """
    chain = verify_cert_chain(cert, ca_public_key, verify_time)
    ext = chain["extensions"]
    if not isinstance(artifact_bytes, (bytes, bytearray)):
        raise EvidenceCertError("evcert-binding-invalid",
                                "artifact_bytes must be bytes")
    if not isinstance(artifact_signature, (bytes, bytearray)) \
            or len(artifact_signature) != 64:
        raise EvidenceCertError("evcert-binding-invalid",
                                "artifact_signature must be 64 bytes")
    if not isinstance(approval_id, str) \
            or not hmac.compare_digest(ext["approval_id"], approval_id):
        raise EvidenceCertError("evcert-binding-invalid",
                                "certificate approval_id does not match "
                                "the evidence approval")
    if not isinstance(intent_digest, str) \
            or not hmac.compare_digest(ext["intent_digest"], intent_digest):
        raise EvidenceCertError("evcert-binding-invalid",
                                "certificate intent_digest does not match "
                                "the evidence intent")
    subject_pub = base64.b64decode(chain["subject_public_key"])
    if _ed_verify(subject_pub, bytes(artifact_bytes),
                  bytes(artifact_signature)) is not True:
        raise EvidenceCertError("evcert-binding-invalid",
                                "artifact signature does not verify "
                                "against the certificate subject key")
    return {"verified": True,
            "cert_digest": cert_digest(chain),
            "subject_key_id": chain["subject_key_id"],
            "approval_id": ext["approval_id"],
            "intent_digest": ext["intent_digest"],
            "principal": ext["principal"]}


def make_signature_attestation(cert, artifact_digest, signature):
    """Build the artifact-signature attestation record.

    This record carries ONLY the artifact digest, the certificate
    digest (the join key), and the signature -- never issuance
    metadata (approval id, principal, CA fields). The issuance
    attestation (audit log) carries the reverse split: no artifact
    signature material. Shape: artifact_digest is 64 hex chars,
    signature is base64 of 64 bytes.
    """
    if not isinstance(artifact_digest, str) \
            or not _HEX64.match(artifact_digest):
        raise EvidenceCertError("evcert-malformed-request",
                                "artifact_digest must be 64 hex chars")
    try:
        sig = base64.b64decode(signature, validate=True)
    except Exception:
        raise EvidenceCertError("evcert-malformed-request",
                                "signature is not valid base64")
    if len(sig) != 64:
        raise EvidenceCertError("evcert-malformed-request",
                                "signature must decode to 64 bytes")
    return {"artifact_digest": artifact_digest,
            "cert_digest": cert_digest(cert),
            "signature": signature}
