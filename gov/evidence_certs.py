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
1a. OIDC four-claim gate (``oidc-*``) -- when the CA configures an
    :class:`OidcGate`, the producer MUST present an OIDC token; the
    ``iss``/``aud``/``sub``/``exp`` claims are verified against the
    issuer's JWKS and the verified claims BECOME the identity
    assertion (the ``identity_assertion`` argument is ignored on this
    path). Missing token: ``oidc-token-required``. The certified
    producer identity is the verified (iss, sub) pair, recorded on the
    audit attestation as ``producer_identity``.
1b. provisioner-class resolution (evcert-malformed-request) -- when
    the CA configures provisioner classes, the request must name a
    known one; ambiguity fails closed
1c. lifetime: global bounds first (evcert-lifetime-exceeded), then the
    class's tightening bounds (evcert-provisioner-policy-violated) --
    the audit trail must tell a client bug from class enforcement
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

Honest OIDC boundary: the gate verifies Ed25519 (``"EdDSA"``) token
signatures against a deployment-supplied JWKS using only the stdlib
and the repo's vendored ``gov.ed25519``. RS256/ES256 (or any other
JWA) issuers are NOT verified in-process -- the live-path integration
seam is to subclass :class:`OidcGate` and override
:meth:`OidcGate._verify_signature`, or to supply a pre-fetched JWKS
from the deployment's own issuer discovery. There is no live OIDC
provider in the $0 test environment; ``evals/fixtures/
oidc_test_jwks.json`` is a TEST-ONLY fixture and must never be
configured on a production CA.

The gate is the identity half: it exposes the verified (iss, sub)
pair on the certificate (``principal`` + issuer OID fields, byte-
identical wire) and on the audit attestation (``producer_identity``).
Authorization decisions over that pair belong to the
producer-authorization mapping (a parallel wave-272 lane); the
existing provisioner-class binding consumes it through the
principal/class fields it already carries.


Lifetime discipline: default 10 minutes, deployment-capped at 60
minutes; anything over 24 hours requires a configured status-list
URL (otherwise refused at CA construction). Per-provisioner classes
(``provisioners``) supply their own ``{min_s, default_s, max_s}``
which tighten the global bounds only -- a class max may never exceed
the CA global max and a class min may never undercut the global
floor; widening policies are refused with ValueError at CA
construction, never silently clamped. A classed issuance records the
class id at ``<oid_arc>.1.40`` in the certificate extensions.

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

# Provisioner-class extension: <oid_arc>.1.40 carries the provisioner
# class id (string) on classed issuances. <arc>.1.8 is the issuer,
# <arc>.1.24 the subject.
_PROV_OID_SUFFIX = ".1.40"
# Wave-274 lane 3: attestor-plugin claim set. When an attestor is
# configured, the matched registration entry id is recorded at
# <arc>.1.41 (auditable on the certificate, like the provisioner
# class). No SPIFFE dependency, no JWT SVIDs, no bearer flows --
# the certified producer identity stays in the OIDC (iss, sub)
# ceremony; this is an environment binding on top.
_ATTESTOR_OID_SUFFIX = ".1.41"

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
# OIDC four-claim gate ceremony (wave-272)
#
# Fulcio-style ceremonies authenticate a valid OIDC token but establish
# no application-level producer authorization. This gate is the identity
# half: before issuance the producer MUST present an OIDC token whose
# iss/aud/sub/exp verify against the issuer's JWKS. The certified
# producer identity is the verified (iss, sub) pair.
# ---------------------------------------------------------------------------

OIDC_DEFAULT_CLOCK_SKEW_S = 300  # explicit clock-skew bound for exp
_OIDC_REQUIRED_CLAIMS = ("iss", "aud", "sub", "exp")
_OIDC_JWT_ALG = "EdDSA"  # Ed25519; the only JWA verified in-process
_OIDC_JWT_PARTS = 3  # header.payload.signature


def _b64u_decode(s):
    """Base64url-decode, unpadded. Raises ValueError on bad input."""
    if not isinstance(s, str) or not s:
        raise ValueError("not a base64url string")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _loads_no_dup(raw):
    """Parse a JSON object, reporting duplicate keys.

    Returns ``(obj, dups)`` where ``dups`` is the set of keys that
    appeared more than once. A non-object payload raises ValueError.
    Standard ``json.loads`` silently keeps the LAST duplicate, which
    would let an attacker smuggle a second ``sub`` claim past the
    gate -- ambiguity fails closed here instead.
    """
    pairs = json.loads(raw, object_pairs_hook=list)
    if not isinstance(pairs, list):
        raise ValueError("payload is not a JSON object")
    obj = {}
    dups = set()
    for pair in pairs:
        # A JSON object decodes (with object_pairs_hook=list) to a
        # list of [key, value] pairs; anything else is a non-object
        # payload smuggled past the top-level check (e.g. `[1,2,3]`
        # unpacks to a TypeError, `["ab"]` silently becomes {"a":"b"}).
        if not isinstance(pair, (list, tuple)) or len(pair) != 2 \
                or not isinstance(pair[0], str):
            raise ValueError("payload is not a JSON object")
        k, v = pair
        if k in obj:
            dups.add(k)
        obj[k] = v
    return obj, dups


class OidcGate(object):
    """Four-claim OIDC token gate for the evidence-cert ceremony.

    ``issuer`` is the single expected ``iss`` value (exact string
    match -- no allowlist patterns at this seam; the ceremony's own
    issuer allowlist still applies downstream). ``audience`` is this
    ceremony's ``aud`` value. ``jwks`` is the issuer's JSON Web Key
    Set as a dict (``{"keys": [...]}``); only ``kty="OKP"`` /
    ``crv="Ed25519"`` keys with a ``kid`` are loaded -- anything else
    is a deployment bug and raises ValueError at construction, never
    silently skipped. ``clock_skew_s`` bounds ``exp`` acceptance: a
    token is valid iff ``now <= exp + clock_skew_s``.

    :meth:`verify_token` returns the verified claims
    ``{"iss", "sub", "exp"}`` or raises :class:`EvidenceCertError`
    with an ``oidc-*`` code; it never raises anything else on hostile
    input. Verification order is fixed: token shape -> header -> key
    selection -> signature -> payload shape -> claim presence ->
    claim values.

    Live-path seam: only Ed25519 (``"EdDSA"``) signatures verify
    in-process (stdlib-only by design). A deployment whose issuer
    uses another JWA subclasses and overrides
    :meth:`_verify_signature`; the deployment obtains ``jwks`` from
    its own issuer's discovery document out of band.
    """

    def __init__(self, *, issuer, audience, jwks, clock_skew_s=None,
                 now=None):
        if not isinstance(issuer, str) or not issuer:
            raise ValueError("issuer must be a non-empty string")
        if not isinstance(audience, str) or not audience:
            raise ValueError("audience must be a non-empty string")
        if clock_skew_s is None:
            clock_skew_s = OIDC_DEFAULT_CLOCK_SKEW_S
        if not isinstance(clock_skew_s, int) or clock_skew_s < 0:
            raise ValueError("clock_skew_s must be a non-negative int")
        self._issuer = issuer
        self._audience = audience
        self._skew = clock_skew_s
        self._now = now or __import__("time").time
        self._keys = self._load_jwks(jwks)

    @staticmethod
    def _load_jwks(jwks):
        if not isinstance(jwks, dict) \
                or not isinstance(jwks.get("keys"), list) \
                or not jwks["keys"]:
            raise ValueError("jwks must be a dict with a non-empty "
                             "'keys' list")
        keys = {}
        for entry in jwks["keys"]:
            if not isinstance(entry, dict):
                raise ValueError("jwks keys must be objects")
            if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
                raise ValueError(
                    "only kty=OKP/crv=Ed25519 keys are supported "
                    "(got %r/%r); use the _verify_signature seam for "
                    "other JWAs" % (entry.get("kty"), entry.get("crv")))
            kid = entry.get("kid")
            if not isinstance(kid, str) or not kid:
                raise ValueError("jwks keys must carry a non-empty kid")
            try:
                x = _b64u_decode(entry.get("x"))
            except ValueError:
                raise ValueError("jwks key %r has malformed x" % (kid,))
            if len(x) != 32:
                raise ValueError("jwks key %r x must be 32 bytes" % (kid,))
            if kid in keys:
                raise ValueError("duplicate kid %r in jwks" % (kid,))
            keys[kid] = x
        return keys

    def _now_s(self):
        return int(self._now())

    def _verify_signature(self, signing_input, signature, key):
        """Verify an Ed25519 signature. The live-path seam: override
        for non-EdDSA issuers. Returns exact True/False (wave-243)."""
        return _ed_verify(key, signing_input, signature) is True

    def verify_token(self, token):
        """Verify the four claims. Returns ``{"iss","sub","exp"}``.

        Refusals: oidc-malformed-token, oidc-ambiguous-subject,
        oidc-missing-claim, oidc-issuer-mismatch,
        oidc-audience-mismatch, oidc-token-expired,
        oidc-signature-invalid. Never raises on hostile input.
        """
        # -- token shape ------------------------------------------------
        if not isinstance(token, str):
            raise EvidenceCertError("oidc-malformed-token",
                                    "token must be a string")
        parts = token.split(".")
        if len(parts) != _OIDC_JWT_PARTS or not all(parts):
            raise EvidenceCertError("oidc-malformed-token",
                                    "token must be three non-empty "
                                    "dot-separated parts")
        header_b64, payload_b64, sig_b64 = parts
        try:
            header = json.loads(_b64u_decode(header_b64).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise EvidenceCertError("oidc-malformed-token",
                                    "header is not valid JSON")
        if not isinstance(header, dict):
            raise EvidenceCertError("oidc-malformed-token",
                                    "header is not a JSON object")
        # -- algorithm allowlist (exact; "none" never verifies) ---------
        if header.get("alg") != _OIDC_JWT_ALG:
            raise EvidenceCertError(
                "oidc-signature-invalid",
                "unsupported alg %r; only %r verifies in-process"
                % (header.get("alg"), _OIDC_JWT_ALG))
        kid = header.get("kid")
        if not isinstance(kid, str) or kid not in self._keys:
            raise EvidenceCertError("oidc-signature-invalid",
                                    "unknown or missing kid %r" % (kid,))
        try:
            signature = _b64u_decode(sig_b64)
        except ValueError:
            raise EvidenceCertError("oidc-signature-invalid",
                                    "signature is not valid base64url")
        if len(signature) != 64:
            raise EvidenceCertError("oidc-signature-invalid",
                                    "signature must be 64 bytes")
        # -- signature BEFORE claims (never trust unverified claims) ---
        signing_input = (header_b64 + "." + payload_b64).encode("ascii")
        if not self._verify_signature(signing_input, signature,
                                      self._keys[kid]):
            raise EvidenceCertError("oidc-signature-invalid",
                                    "token signature does not verify "
                                    "against the JWKS key %r" % (kid,))
        # -- payload shape, duplicate-key detection ----------------------
        try:
            payload, dups = _loads_no_dup(
                _b64u_decode(payload_b64).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, TypeError):
            # TypeError is belt-and-braces: _loads_no_dup validates
            # pair shapes, but this boundary promises never to leak a
            # non-ceremony exception on hostile input.
            raise EvidenceCertError("oidc-malformed-token",
                                    "payload is not valid JSON")
        if "sub" in dups:
            raise EvidenceCertError(
                "oidc-ambiguous-subject",
                "payload carries duplicate 'sub' claims; the subject "
                "identity is ambiguous and fails closed")
        if dups:
            # Any other duplicate collapses last-wins under a plain
            # json.loads; fail closed rather than guessing which value
            # the signer meant.
            raise EvidenceCertError(
                "oidc-malformed-token",
                "payload carries duplicate claims %r" % sorted(dups))
        # -- claim presence ----------------------------------------------
        for claim in _OIDC_REQUIRED_CLAIMS:
            if claim not in payload:
                raise EvidenceCertError("oidc-missing-claim",
                                        "token is missing claim %r"
                                        % (claim,))
        iss, aud, sub, exp = (payload["iss"], payload["aud"],
                              payload["sub"], payload["exp"])
        # -- claim values --------------------------------------------------
        if not isinstance(iss, str) or not iss:
            raise EvidenceCertError("oidc-malformed-token",
                                    "iss must be a non-empty string")
        if not hmac.compare_digest(iss, self._issuer):
            raise EvidenceCertError("oidc-issuer-mismatch",
                                    "token iss %r != expected issuer"
                                    % (iss,))
        if isinstance(aud, str):
            aud_ok = hmac.compare_digest(aud, self._audience)
        elif isinstance(aud, list) and aud \
                and all(isinstance(a, str) for a in aud):
            aud_ok = any(hmac.compare_digest(a, self._audience)
                         for a in aud)
        else:
            raise EvidenceCertError("oidc-malformed-token",
                                    "aud must be a string or a non-empty "
                                    "list of strings")
        if not aud_ok:
            raise EvidenceCertError("oidc-audience-mismatch",
                                    "token aud does not include this "
                                    "ceremony's audience")
        if not isinstance(sub, str) or not sub:
            raise EvidenceCertError("oidc-malformed-token",
                                    "sub must be a non-empty string")
        if not isinstance(exp, int) or isinstance(exp, bool):
            raise EvidenceCertError("oidc-malformed-token",
                                    "exp must be an integer")
        if self._now_s() > exp + self._skew:
            raise EvidenceCertError(
                "oidc-token-expired",
                "token exp %d is past now + %ds skew"
                % (exp, self._skew))
        return {"iss": iss, "sub": sub, "exp": exp}


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
# Per-provisioner lifetime policies
# ---------------------------------------------------------------------------

_PROV_POLICY_FIELDS = frozenset({"min_s", "default_s", "max_s"})


def _validate_provisioners(provisioners, max_lifetime_s):
    """Normalize ``provisioners`` to {id: {min_s, default_s, max_s}}.

    Tightening-only: a class max may never exceed the CA's global
    ``max_lifetime_s`` and a class min may never undercut the global
    floor ``MIN_LIFETIME_S``. Violations raise ValueError at CA
    construction -- a widening policy is a deployment bug and is never
    silently clamped.
    """
    if provisioners is None:
        return {}
    if not isinstance(provisioners, dict):
        raise ValueError("provisioners must be a dict of "
                         "provisioner_id -> policy")
    normalized = {}
    for prov_id, policy in provisioners.items():
        if not isinstance(prov_id, str) or not prov_id:
            raise ValueError("provisioner ids must be non-empty strings")
        if not isinstance(policy, dict) \
                or set(policy.keys()) != _PROV_POLICY_FIELDS:
            raise ValueError(
                "provisioner %r policy must be exactly "
                "{min_s, default_s, max_s}" % (prov_id,))
        vals = policy["min_s"], policy["default_s"], policy["max_s"]
        if not all(isinstance(v, int) for v in vals):
            raise ValueError(
                "provisioner %r lifetimes must be ints" % (prov_id,))
        min_s, default_s, max_s = vals
        if not (MIN_LIFETIME_S <= min_s <= default_s <= max_s):
            raise ValueError(
                "provisioner %r needs %d <= min_s <= default_s <= max_s"
                % (prov_id, MIN_LIFETIME_S))
        if max_s > max_lifetime_s:
            raise ValueError(
                "provisioner %r max_s %d widens the CA global max %d; "
                "class policies tighten only"
                % (prov_id, max_s, max_lifetime_s))
        normalized[prov_id] = {"min_s": min_s, "default_s": default_s,
                               "max_s": max_s}
    return normalized


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
    subject land at ``<arc>.1.8`` and ``<arc>.1.24``, and a
    provisioner-class issuance additionally records the class id at
    ``<arc>.1.40`` (auditable on the certificate).

    ``provisioners`` is an optional dict of provisioner_id ->
    ``{"min_s", "default_s", "max_s"}``. Class policies tighten the CA
    global bounds only (class max <= global max, class min >= global
    floor); a widening or incoherent policy is refused with ValueError
    at construction. When provisioners are configured, ``issue()``
    requires a known ``provisioner`` class -- ambiguity fails closed.

    ``oidc_gate`` is an optional :class:`OidcGate`. When configured,
    ``issue()`` requires an ``oidc_token``: the verified (iss, sub,
    exp) claims BECOME the identity assertion (the
    ``identity_assertion`` argument is ignored on this path) and the
    certified producer identity -- the verified (iss, sub) pair -- is
    recorded on the audit attestation as ``producer_identity``.

    ``attestor`` / ``attested_registry`` are the optional
    attestor-plugin interface (``gov.attestors``; SPIFFE ADAPT,
    principle only). Both-or-neither at construction. When
    configured, ``issue()`` collects environment facts from the
    attestor, matches them against ceremony-backed registration
    entries, and requires the matched entry's producer to be the
    assertion sub; the entry id lands in the cert extensions at
    ``<arc>.1.41`` and the attested facts on the issuance
    attestation. Refusals are the ``attestor-*`` codes, raised as
    :class:`EvidenceCertError`.
    """

    def __init__(self, *, kms_provider, ca_key_id, ca_public_key,
                 issuers, approval_lookup, audit_log_path,
                 anchor_reachable, oid_arc,
                 default_lifetime_s=DEFAULT_LIFETIME_S,
                 max_lifetime_s=DEFAULT_MAX_LIFETIME_S,
                 status_list_url=None, now=None, provisioners=None,
                 claim_public_key=None, oidc_gate=None,
                 attestor=None, attested_registry=None):
        if not isinstance(kms_provider, KmsProvider):
            raise TypeError("kms_provider must be a gov.kms.KmsProvider")
        kms_provider._validate_key_id(ca_key_id)
        if not isinstance(ca_public_key, (bytes, bytearray)) \
                or len(ca_public_key) != 32:
            raise ValueError("ca_public_key must be 32 bytes")
        if claim_public_key is not None and (
                not isinstance(claim_public_key, (bytes, bytearray))
                or len(claim_public_key) != 32):
            raise ValueError("claim_public_key must be 32 bytes or None")
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
        provisioners = _validate_provisioners(provisioners, max_lifetime_s)
        if oidc_gate is not None and not isinstance(oidc_gate, OidcGate):
            raise TypeError("oidc_gate must be a gov.evidence_certs.OidcGate")
        # Wave-274 lane 3: attestor-plugin interface (SPIFFE ADAPT,
        # principle only). Both-or-neither: an attestor without a
        # registry to match against (or a registry with no attestor
        # to collect from) is a deployment bug, refused at
        # construction -- never silently unbound.
        if (attestor is None) != (attested_registry is None):
            raise ValueError("attestor and attested_registry must be "
                             "configured together or not at all")
        if attestor is not None:
            from gov.attestors import Attestor as _Attestor
            from gov.attestors import AttestedRegistry as _AttestedRegistry
            if not isinstance(attestor, _Attestor):
                raise TypeError("attestor must be a gov.attestors.Attestor")
            if not isinstance(attested_registry, _AttestedRegistry):
                raise TypeError("attested_registry must be a "
                                "gov.attestors.AttestedRegistry")
        self._kms = kms_provider
        self._ca_key_id = ca_key_id
        self._ca_public_key = bytes(ca_public_key)
        self._claim_public_key = None if claim_public_key is None \
            else bytes(claim_public_key)
        self._issuers = list(issuers)
        self._approval_lookup = approval_lookup
        self._audit_log_path = audit_log_path
        self._anchor_reachable = anchor_reachable
        self._oid_arc = oid_arc
        self._default_lifetime_s = default_lifetime_s
        self._max_lifetime_s = max_lifetime_s
        self._status_list_url = status_list_url
        self._provisioners = provisioners
        self._oidc_gate = oidc_gate
        self._attestor = attestor
        self._attested_registry = attested_registry
        self._now = now or __import__("time").time

    def _resolve_provisioner(self, provisioner):
        """Return the class policy dict, or None for the legacy path.

        Fail-closed on ambiguity: when classes are configured the
        requester must name a known one; when none are configured a
        named class is a shape error. Refusals are
        evcert-malformed-request.
        """
        if not self._provisioners:
            if provisioner is None:
                return None
            raise EvidenceCertError(
                "evcert-malformed-request",
                "provisioner %r named but the CA has no provisioner "
                "classes configured" % (provisioner,))
        if not isinstance(provisioner, str) \
                or provisioner not in self._provisioners:
            raise EvidenceCertError(
                "evcert-malformed-request",
                "unknown provisioner class %r; the CA requires a "
                "configured class" % (provisioner,))
        return self._provisioners[provisioner]

    def _bind_attested(self, sub):
        """Collect attestor facts and match a registration entry.

        Returns ``(entry_id, facts)``. Every refusal is an
        ``attestor-*`` EvidenceCertError -- the CA's refusal carrier
        is always EvidenceCertError, so the attestor seam never
        leaks a foreign exception type out of issuance.
        """
        from gov.attestors import AttestorError, _shape_facts
        try:
            collected = self._attestor.collect()
        except AttestorError as exc:
            raise EvidenceCertError(exc.code, exc.detail)
        except Exception as exc:
            raise EvidenceCertError(
                "attestor-facts-malformed",
                "attestor collect() raised %s; refusing rather than "
                "issuing unattested" % type(exc).__name__)
        if not isinstance(collected, dict):
            raise EvidenceCertError(
                "attestor-facts-malformed",
                "attestor collect() must return a dict, not %s"
                % type(collected).__name__)
        attestor_id = collected.get("attestor_id")
        # Shape to scalars with the registry's own shaping (the
        # attestation records the facts that were actually matched,
        # never unshaped input).
        try:
            shaped = _shape_facts(collected.get("facts"))
        except AttestorError as exc:
            raise EvidenceCertError(exc.code, exc.detail)
        try:
            entry = self._attested_registry.match(
                shaped, attestor_id=attestor_id)
        except AttestorError as exc:
            raise EvidenceCertError(exc.code, exc.detail)
        if entry.get("producer_sub") != sub:
            raise EvidenceCertError(
                "attestor-entry-unmatched",
                "matched registration entry %r is bound to producer "
                "%r, not the assertion sub %r; refusing to mint for "
                "the wrong identity"
                % (entry.get("entry_id"), entry.get("producer_sub"),
                   sub))
        return entry["entry_id"], shaped

    # -- issuance ----------------------------------------------------------

    def _now_s(self):
        return int(self._now())

    def issue(self, *, identity_assertion=None, ephemeral_pub, pop_sig,
              approval_id, intent_digest, lifetime_s=None,
              provisioner=None, producer_authz_claim=None,
              oidc_token=None):
        """Run the issuance checks in order and mint a certificate.

        Returns ``(cert, audit_entry)``. Every refusal raises
        :class:`EvidenceCertError` with its machine code.

        ``producer_authz_claim`` is the optional SLSA-shaped
        producer-authorization claim (see
        ``gov.evidence_bundle_v2.issue_producer_claim``): when
        present it is verified against the CA's ``claim_public_key``
        (signature, expiry, approval/subject-key join) and embedded
        byte-identically into the ``evidence-cert-issued`` attestation
        as ``producer_authz_claim``. A CA with no claim key configured
        refuses claim-carrying issuance rather than embedding an
        unverified claim. Deployments that never pass a claim keep the
        legacy behavior byte-identically.

        When the CA configures an :class:`OidcGate`, ``oidc_token`` is
        required and the verified (iss, sub, exp) claims become the
        identity assertion (``identity_assertion`` is ignored on that
        path). Without a gate, ``identity_assertion`` is required and a
        presented ``oidc_token`` is refused (never honored).
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

        # (1a) OIDC four-claim gate (when configured): the verified
        # token claims BECOME the identity assertion for the rest of
        # the lattice. The certified producer identity is the verified
        # (iss, sub) pair.
        oidc_verified = False
        producer_identity = None
        if self._oidc_gate is not None:
            if oidc_token is None:
                raise EvidenceCertError(
                    "oidc-token-required",
                    "this CA requires an OIDC token; none was presented")
            claims = self._oidc_gate.verify_token(oidc_token)
            identity_assertion = {"iss": claims["iss"],
                                  "sub": claims["sub"],
                                  "exp": claims["exp"]}
            oidc_verified = True
            producer_identity = {"iss": claims["iss"],
                                 "sub": claims["sub"]}
        elif oidc_token is not None:
            raise EvidenceCertError(
                "evcert-malformed-request",
                "oidc_token presented but this CA has no OIDC gate "
                "configured; the token is refused, never honored")

        # (1) request shape
        self._check_shape(identity_assertion, ephemeral_pub, pop_sig,
                          approval_id, intent_digest)
        # (1b) provisioner-class resolution (fail-closed on ambiguity)
        policy = self._resolve_provisioner(provisioner)
        eff_default = self._default_lifetime_s \
            if policy is None else policy["default_s"]
        lifetime = eff_default if lifetime_s is None else lifetime_s
        # (1c) lifetime, global bounds first (client bug), then the
        # class's tightening bounds (class-policy enforcement). A
        # class refusal is evcert-provisioner-policy-violated, never
        # the global code -- the audit trail must tell the two apart.
        if not isinstance(lifetime, int) \
                or not (MIN_LIFETIME_S <= lifetime <= self._max_lifetime_s):
            raise EvidenceCertError(
                "evcert-lifetime-exceeded",
                "requested lifetime %r outside [%d, %d]"
                % (lifetime_s, MIN_LIFETIME_S, self._max_lifetime_s))
        if policy is not None and not (
                policy["min_s"] <= lifetime <= policy["max_s"]):
            raise EvidenceCertError(
                "evcert-provisioner-policy-violated",
                "requested lifetime %r outside provisioner %r class "
                "bounds [%d, %d]"
                % (lifetime_s, provisioner,
                   policy["min_s"], policy["max_s"]))
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

        # (3b) attestor environment binding (when configured). The
        # attestor collects environment facts; the registry matches
        # them against ceremony-backed registration entries; the
        # matched entry's producer must BE the assertion sub -- a
        # cert is never minted for an unattested environment or for
        # the wrong identity under a matched environment. The
        # OIDC (iss, sub) ceremony remains the producer identity;
        # this is an environment binding on top (no SVIDs, no
        # bearer flows).
        attested_entry_id = None
        attested_facts = None
        if self._attestor is not None:
            attested_entry_id, attested_facts = self._bind_attested(
                sub)

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

        # (5b) producer-authorization claim (SLSA-shaped, optional
        # seam). The claim binds (producer, scope) to this issuance's
        # (approval_id, subject_key_id); verify signature, expiry,
        # and both joins here so the attestation never embeds an
        # unverified claim. A claim with no claim key configured is
        # refused -- never embedded on trust.
        self._check_producer_claim(producer_authz_claim, approval_id,
                                   key_id, now)

        # (6) transparency anchor -- refuse, never bypass
        if not self._anchor_reachable():
            raise EvidenceCertError(
                "evcert-anchor-unavailable",
                "transparency anchor unreachable; issuance refused "
                "(no bypass switch exists by design)")

        # (7) mint via the KMS, self-check the signature
        not_before = now
        not_after = now + lifetime
        extensions = {
            "approval_id": approval_id,
            "intent_digest": intent_digest,
            "principal": sub,
            self._oid_arc + ".1.8": iss,
            self._oid_arc + ".1.24": sub,
        }
        if provisioner is not None:
            # The provisioner class is auditable on the certificate.
            extensions[self._oid_arc + _PROV_OID_SUFFIX] = provisioner
        if attested_entry_id is not None:
            # The attested environment (registration entry id) is
            # auditable on the certificate. The full attested facts
            # live on the issuance attestation.
            extensions[self._oid_arc + _ATTESTOR_OID_SUFFIX] = \
                attested_entry_id
        body = {
            "format": CERT_FORMAT,
            "subject_public_key": base64.b64encode(
                bytes(ephemeral_pub)).decode("ascii"),
            "subject_key_id": key_id,
            "issuer_key_id": self._ca_key_id,
            "not_before": not_before,
            "not_after": not_after,
            "eku": CERT_EKU,
            "extensions": extensions,
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
            "oidc_verified": oidc_verified,
        }
        if producer_authz_claim is not None:
            # Byte-identical to the claim verified at (5b): the
            # attestation is the claim's anchor in the hash-chained
            # log. The key is absent on the legacy path (no claim),
            # keeping legacy attestations byte-identical.
            attestation["producer_authz_claim"] = producer_authz_claim
        if producer_identity is not None:
            # The certified producer identity is the verified (iss, sub)
            # pair -- the application-level authorization half the OIDC
            # token alone does not establish.
            attestation["producer_identity"] = producer_identity
        if attested_entry_id is not None:
            # The environment binding: which registration entry the
            # attestor's facts matched, and the matched facts
            # themselves (a verifier re-matches them against the
            # declared entry).
            attestation["attested_entry_id"] = attested_entry_id
            attestation["attested_facts"] = attested_facts
        from . import log as _audit_log
        try:
            stored = _audit_log.open_audit_log(
                self._audit_log_path).append(attestation)
        except Exception:
            del registry[key_id]
            _save_registry(reg_path, registry)
            raise
        return cert, stored

    def _check_producer_claim(self, claim, approval_id, key_id, now):
        """Verify the SLSA-shaped producer-authorization claim at
        issuance time (defense-in-depth; the claim path in
        ``gov.evidence_bundle_v2`` re-verifies at submission and at
        bundle-verify time). ``None`` means the legacy path -- no
        claim, no check. Refusals are the ``prodauth-*`` codes (they
        live in the global decision-code taxonomy):
        ``prodauth-claim-invalid`` (shape, signature, or no claim key
        configured), ``prodauth-claim-expired``,
        ``prodauth-claim-mismatch`` (approval/subject-key join).

        The format literals below mirror
        ``gov.evidence_bundle_v2``'s ``PRODAUTH_*`` constants; this
        module cannot import them (evidence_bundle_v2 imports
        evidence_certs).
        """
        if claim is None:
            return None
        if self._claim_public_key is None:
            raise EvidenceCertError(
                "prodauth-claim-invalid",
                "claim-carrying issuance refused: this CA has no "
                "claim_public_key configured (refusing rather than "
                "embedding an unverifiable claim)")
        if not isinstance(claim, dict) \
                or claim.get("format") != "prodauth-claim.v1" \
                or not isinstance(claim.get("statement"), dict) \
                or not isinstance(claim.get("signature"), str):
            raise EvidenceCertError(
                "prodauth-claim-invalid",
                "producer claim must be {format: 'prodauth-claim.v1', "
                "statement: dict, signature: str}")
        stmt = claim["statement"]
        if stmt.get("_type") != \
                "https://sasanam.dev/producer-authorization/v1" \
                or stmt.get("predicateType") != \
                "https://sasanam.dev/producer-authorization/" \
                "predicate/v1":
            raise EvidenceCertError(
                "prodauth-claim-invalid",
                "producer claim statement has wrong _type/predicateType")
        try:
            sig = base64.b64decode(claim["signature"], validate=True)
        except ValueError:
            raise EvidenceCertError(
                "prodauth-claim-invalid",
                "producer claim signature is not valid base64")
        if _ed_verify(self._claim_public_key, _canonical_body(stmt),
                      sig) is not True:
            raise EvidenceCertError(
                "prodauth-claim-invalid",
                "producer claim signature does not verify against the "
                "CA's claim key")
        pred = stmt.get("predicate")
        if not isinstance(pred, dict):
            raise EvidenceCertError(
                "prodauth-claim-invalid",
                "producer claim predicate must be a dict")
        exp = pred.get("expiresAt")
        if not isinstance(exp, int) or exp <= now:
            raise EvidenceCertError(
                "prodauth-claim-expired",
                "producer claim expired (expiresAt %r <= now %d)"
                % (exp, now))
        bound_key = None
        subjects = stmt.get("subject")
        if isinstance(subjects, list):
            for s in subjects:
                if isinstance(s, dict):
                    d = s.get("digest")
                    if isinstance(d, dict) \
                            and "sasanam-key-id-v1" in d:
                        bound_key = d["sasanam-key-id-v1"]
                        break
        if pred.get("approvalId") != approval_id \
                or bound_key != key_id:
            raise EvidenceCertError(
                "prodauth-claim-mismatch",
                "producer claim was minted for a different issuance "
                "(approval/subject-key join failed)")
        return claim

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


def verify_cert_chain(cert, ca_public_key, now, oid_arc=None):
    """Verify a certificate: shape, validity window, then CA signature.

    Returns the normalized cert dict. Refusals:
    evcert-malformed-cert (shape), evcert-cert-expired (window),
    evcert-chain-invalid (signature). The verifier's clock is
    ``now`` (int epoch seconds).

    ``oid_arc`` is optional for backward compatibility: without it the
    extensions must carry exactly the two issuer/subject OID fields
    (the pre-provisioner shape). With it, the provisioner-class OID
    ``<arc>.1.40`` is additionally accepted -- and only that key.
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
    if oid_arc is None:
        # Legacy shape: exactly the issuer and subject OID fields.
        if len(oid_keys) != 2 or not all(
                isinstance(ext[k], str) and ext[k] for k in oid_keys):
            raise EvidenceCertError("evcert-malformed-cert",
                                    "extensions must carry exactly two OID "
                                    "fields (issuer, subject)")
    else:
        # Arc-aware: the provisioner-class OID <arc>.1.40 and the
        # attestor-entry OID <arc>.1.41 are the only permitted extra
        # OID keys; issuer/subject remain required.
        required = {oid_arc + ".1.8", oid_arc + ".1.24"}
        allowed = required | {oid_arc + _PROV_OID_SUFFIX,
                              oid_arc + _ATTESTOR_OID_SUFFIX}
        if not required <= set(oid_keys) <= allowed or not all(
                isinstance(ext[k], str) and ext[k] for k in oid_keys):
            raise EvidenceCertError("evcert-malformed-cert",
                                    "extensions must carry the issuer and "
                                    "subject OID fields and at most the "
                                    "provisioner-class / attestor-entry "
                                    "OID fields")
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
                              verify_time, oid_arc=None):
    """Verify an evidence signature against a certificate.

    Order is fixed: chain first, then binding. Chain failures raise
    evcert-malformed-cert / evcert-cert-expired / evcert-chain-invalid;
    any binding failure (wrong key, approval mismatch, intent mismatch)
    raises evcert-binding-invalid. Returns a small verified record.
    ``oid_arc`` is passed through to :func:`verify_cert_chain` so
    provisioner-class certificates verify (default: legacy two-OID
    shape).
    """
    chain = verify_cert_chain(cert, ca_public_key, verify_time,
                              oid_arc=oid_arc)
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
