"""Short-lived SPIFFE-style workload identity documents (local TEST issuer).

Wave-259 lane 3 (identity-mesh: dex/SPIFFE/headscale follow-up). Stdlib
only.

ADAPT lineage (patterns only, no donor code):
  - SPIFFE SVID shape: {spiffe_id, trust_domain, issued_at,
    expires_at, public_key, issuer_key_id, issuer_signature}. The
    document binds a workload identity to its keypair for minutes, not
    months.
  - wave-258 prospectus D3 (headscale ADAPT): the mesh control plane is
    identity-bound -- namespaces are trust domains, and agent-to-agent
    admission is a default-deny ACL policy file carried as data. The
    identity is the keypair, not the IP.
  - wave-258 prospectus D3 (cfssl ADAPT): issuance is driven by profiles
    as data -- per-profile max TTL and usages -- and the trust bundle
    holds parallel trust roots (cfssl's multirootca shape) so keys
    rotate without flag days.

What this is: a TEST issuer plus a fail-closed verifier plus a
default-deny mesh admission gate. The issuer here is EXPLICITLY a
test issuer: production issuer wiring (SPIRE server, Vault PKI,
step-ca -- cfssl's `authsign` shows how to gate signing behind an
auth hook) stays deployment-owned and is documented in the residuals.
Nothing here talks to a network.

Machine codes (domain "svid", all registered in gov/decision_codes.py):

* ``svid-missing`` -- no SVID where identity is required; refused,
  never downgraded to a deployment-vouched identity.
* ``svid-malformed`` -- structural failure (also the F224
  ``_validate_now`` refusal for a non-finite/bool/non-numeric ``now``).
* ``svid-identity-malformed`` -- issuance-side: bad spiffe_id or
  workload public key.
* ``svid-ttl-unbounded`` -- issuance-side: missing, non-int, or
  non-positive TTL (unbounded leases are refused).
* ``svid-ttl-stretched`` -- issuance-side: TTL above the profile max;
  callers cannot mint longer-lived SVIDs than policy allows.
* ``svid-trust-domain-mismatch`` -- the SVID's trust domain is not
  the verifier's; a foreign trust domain is never accepted.
* ``svid-issuer-unknown`` -- issuer key id not in the pinned trust
  bundle.
* ``svid-signature-invalid`` -- issuer signature does not verify under
  the pinned root for that key id (forgery, transplant, tamper).
* ``svid-expired`` -- ``now >= expires_at``.
* ``svid-acl-denied`` -- verified SVID, but the spiffe id matches no
  allowlist prefix (default-deny).

Honest residuals (documented, not solved here):
  - The TEST issuer holds its signing seed in-process; production key
    custody (KMS/HSM/Vault-transit) is deployment-owned. Anyone holding
    the seed can mint SVIDs -- seed custody IS the trust root.
  - SVIDs are bearer identity documents: there is no revocation list;
    the short TTL (minutes, profile-capped) is the revocation. A
    compromised workload key is valid until expiry.
  - SVID IDs are normalized to lowercase at issuance and verification
    (a local-profile choice; SPIFFE paths are case-sensitive per spec).
  - No X.509 SVIDs, no SPIRE Workload API, no live SPIRE round trip
    ($0 spend): the break-first battery evals/w259_identity_probes.py
    is the acceptance gate.
"""

import hashlib
import json
import math
import os
import re
import secrets
import time

from . import ed25519 as _ed25519

__all__ = [
    "TestSvidIssuer",
    "SvidVerifier",
    "MeshControl",
    "SvidError",
    "PROFILES",
    "SVID_DOMAIN",
    "SVID_DOMAIN_STR",
    "SVID_MISSING_CODE",
    "SVID_MALFORMED_CODE",
    "SVID_IDENTITY_MALFORMED_CODE",
    "SVID_TTL_UNBOUNDED_CODE",
    "SVID_TTL_STRETCHED_CODE",
    "SVID_TRUST_DOMAIN_MISMATCH_CODE",
    "SVID_ISSUER_UNKNOWN_CODE",
    "SVID_SIGNATURE_INVALID_CODE",
    "SVID_EXPIRED_CODE",
    "SVID_ACL_DENIED_CODE",
]

# ---------------------------------------------------------------------------
# Machine codes
# ---------------------------------------------------------------------------

SVID_MISSING_CODE = "svid-missing"
SVID_MALFORMED_CODE = "svid-malformed"
SVID_IDENTITY_MALFORMED_CODE = "svid-identity-malformed"
SVID_TTL_UNBOUNDED_CODE = "svid-ttl-unbounded"
SVID_TTL_STRETCHED_CODE = "svid-ttl-stretched"
SVID_TRUST_DOMAIN_MISMATCH_CODE = "svid-trust-domain-mismatch"
SVID_ISSUER_UNKNOWN_CODE = "svid-issuer-unknown"
SVID_SIGNATURE_INVALID_CODE = "svid-signature-invalid"
SVID_EXPIRED_CODE = "svid-expired"
SVID_ACL_DENIED_CODE = "svid-acl-denied"

_SVID_FIELDS = ("spiffe_id", "trust_domain", "issued_at",
                "expires_at", "public_key", "issuer_key_id",
                "usage", "issuer_signature")

#: Domain separation for issuer signatures, mirroring the
#: attested-identity credential convention (domain || sha256(canonical)).
SVID_DOMAIN = b"sasanam-svid/v1:"
SVID_DOMAIN_STR = SVID_DOMAIN[:-1].decode("ascii")

#: Issuance profiles as data (cfssl shape): per-profile max TTL in
#: minutes and the usages the SVID may be presented for. Callers pick
#: a profile; they cannot stretch the TTL past the profile max.
PROFILES = {
    "workload": {"max_ttl_minutes": 30, "usages": ("workload-auth",)},
    "mesh-control": {"max_ttl_minutes": 15, "usages": ("mesh-control",)},
}

_SEED_ENV = "GOV_SVID_TEST_SEED"
_MAX_KEY_ID_LEN = 128

_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.\-_]*[a-z0-9])?$")
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~!$&'()*+,;=:@-]+$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SvidError(Exception):
    """Fail-closed SVID refusal. ``code`` is the machine vocabulary."""

    def __init__(self, code, detail=""):
        super(SvidError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _validate_now(now):
    """Validate the injectable wall-clock hook (F224 contract).

    ``None`` means "use time.time()". Otherwise ``now`` must be a
    finite int/float unix-epoch value. A bool is refused even though
    it is an int subclass; NaN/inf are refused: a NaN ``now`` would
    silently never trigger expiry (``nan >= expires_at`` is False)
    and an inf ``now`` would silently force expiry. A past numeric
    ``now`` is honored by design (documented test hook).
    """
    if now is None:
        return time.time()
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise SvidError(
            SVID_MALFORMED_CODE,
            "now must be a unix-epoch number, got %s"
            % type(now).__name__)
    if math.isnan(now) or math.isinf(now):
        raise SvidError(
            SVID_MALFORMED_CODE,
            "now must be a finite unix-epoch number")
    return now


def _parse_spiffe_id(spiffe_id):
    """Normalize and strictly parse a SPIFFE ID.

    Returns ``(trust_domain, path)``. The ID is lowercased first: this
    issuer's local profile defines IDs as case-normalized (documented
    deviation from the SPIFFE case-sensitive-path rule). Raises
    :class:`SvidError` (svid-identity-malformed) on anything else.
    """
    if not isinstance(spiffe_id, str) or not spiffe_id:
        raise SvidError(
            SVID_IDENTITY_MALFORMED_CODE,
            "spiffe_id must be a non-empty str")
    norm = spiffe_id.lower()
    if not norm.startswith("spiffe://"):
        raise SvidError(
            SVID_IDENTITY_MALFORMED_CODE,
            "spiffe_id must start with 'spiffe://', got %r"
            % (spiffe_id[:32],))
    rest = norm[len("spiffe://"):]
    if "/" not in rest:
        raise SvidError(
            SVID_IDENTITY_MALFORMED_CODE,
            "spiffe_id needs a trust domain and a non-empty path")
    trust_domain, path = rest.split("/", 1)
    if not trust_domain or len(trust_domain) > 255 or \
            not _TRUST_DOMAIN_RE.match(trust_domain):
        raise SvidError(
            SVID_IDENTITY_MALFORMED_CODE,
            "bad trust domain %r in spiffe_id" % (trust_domain,))
    if not path:
        raise SvidError(
            SVID_IDENTITY_MALFORMED_CODE,
            "spiffe_id needs a non-empty path")
    full_path = "/" + path
    segments = path.split("/")
    if any(not _PATH_SEGMENT_RE.match(seg) for seg in segments):
        raise SvidError(
            SVID_IDENTITY_MALFORMED_CODE,
            "bad path segment in spiffe_id %r" % (spiffe_id[:64],))
    return trust_domain, full_path


def _check_public_key(public_key):
    if not isinstance(public_key, str) or \
            not _HEX64_RE.match(public_key):
        raise SvidError(
            SVID_IDENTITY_MALFORMED_CODE,
            "public_key must be 64 lowercase hex chars (Ed25519)")
    return public_key


def _check_key_id(key_id, what="key_id"):
    if not isinstance(key_id, str) or not key_id or \
            len(key_id) > _MAX_KEY_ID_LEN:
        raise SvidError(
            SVID_MALFORMED_CODE,
            "%s must be a non-empty str (<= %d chars)"
            % (what, _MAX_KEY_ID_LEN))
    return key_id


def _resolve_seed(seed):
    if seed is None:
        env = os.environ.get(_SEED_ENV)
        if env:
            try:
                seed = bytes.fromhex(env.strip())
            except ValueError:
                raise SvidError(
                    SVID_MALFORMED_CODE,
                    "%s is not valid hex" % _SEED_ENV)
        else:
            seed = secrets.token_bytes(32)
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise SvidError(
            SVID_MALFORMED_CODE,
            "issuer seed must be exactly 32 bytes (Ed25519)")
    return bytes(seed)


def _validate_policy(policy):
    """Validate an issuance-policy mapping (cfssl profiles as data)."""
    if not isinstance(policy, dict) or not policy:
        raise SvidError(
            SVID_MALFORMED_CODE,
            "policy must be a non-empty mapping of profile names")
    out = {}
    for name, prof in policy.items():
        if not isinstance(name, str) or not name:
            raise SvidError(
                SVID_MALFORMED_CODE,
                "profile names must be non-empty strings")
        if not isinstance(prof, dict):
            raise SvidError(
                SVID_MALFORMED_CODE,
                "profile %r must be a dict" % (name,))
        max_ttl = prof.get("max_ttl_minutes")
        if isinstance(max_ttl, bool) or not isinstance(max_ttl, int) \
                or max_ttl <= 0:
            raise SvidError(
                SVID_MALFORMED_CODE,
                "profile %r needs a positive int max_ttl_minutes"
                % (name,))
        usages = prof.get("usages")
        if not isinstance(usages, (tuple, list)) or not usages or \
                any(not isinstance(u, str) or not u for u in usages):
            raise SvidError(
                SVID_MALFORMED_CODE,
                "profile %r needs a non-empty list of usage strings"
                % (name,))
        out[name] = {"max_ttl_minutes": max_ttl,
                     "usages": tuple(usages)}
    return out


def _signing_bytes(doc):
    """Bytes the issuer signs: domain || sha256(canonical(doc)).

    ``doc`` is the SVID body WITHOUT the issuer_signature field, so
    the signature covers every other field exactly once.
    """
    body = {k: v for k, v in doc.items() if k != "issuer_signature"}
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    return SVID_DOMAIN + digest.encode("ascii")


# ---------------------------------------------------------------------------
# The TEST issuer
# ---------------------------------------------------------------------------

class TestSvidIssuer(object):
    """Mint short-lived SVID-like workload identity documents.

    THIS IS A TEST ISSUER. The seed lives in-process; production
    issuer wiring (SPIRE server, Vault PKI, step-ca, or a cfssl-style
    authsign hook in front of signing) is deployment-owned. Anyone
    holding the seed can mint SVIDs -- seed custody is the trust root.

    Seed resolution: explicit ``issuer_seed`` kwarg > ``GOV_SVID_TEST_SEED``
    (hex) env > a fresh random 32-byte seed (single-process use only).
    """

    def __init__(self, issuer_seed=None, key_id="test-issuer-1",
                 policy=None):
        self._seed = _resolve_seed(issuer_seed)
        self._key_id = _check_key_id(key_id, "key_id")
        self._policy = _validate_policy(
            policy if policy is not None else PROFILES)
        self._pubkey = _ed25519.publickey(self._seed)

    @property
    def issuer_public_key(self):
        """The issuer's Ed25519 public key (32 bytes): pin this in the
        verifier's trust bundle."""
        return self._pubkey

    @property
    def key_id(self):
        return self._key_id

    def issue(self, spiffe_id, public_key, ttl_minutes,
              profile="workload", now=None):
        """Mint an SVID. TTL is in MINUTES and is profile-capped.

        Fail-closed: unbounded/malformed TTL, stretched TTL, malformed
        identity, or unknown profile refuse with machine codes.
        Returns the SVID dict (JSON-safe).
        """
        trust_domain, _path = _parse_spiffe_id(spiffe_id)
        _check_public_key(public_key)
        prof = self._policy.get(profile)
        if prof is None:
            raise SvidError(
                SVID_MALFORMED_CODE,
                "unknown issuance profile %r" % (profile,))
        if isinstance(ttl_minutes, bool) or \
                not isinstance(ttl_minutes, int) or ttl_minutes <= 0:
            raise SvidError(
                SVID_TTL_UNBOUNDED_CODE,
                "ttl_minutes is required: a positive int number of "
                "minutes; unbounded SVIDs are refused")
        if ttl_minutes > prof["max_ttl_minutes"]:
            raise SvidError(
                SVID_TTL_STRETCHED_CODE,
                "ttl_minutes %d exceeds profile %r max of %d minutes: "
                "callers cannot stretch SVID lifetimes"
                % (ttl_minutes, profile, prof["max_ttl_minutes"]))
        issued_at = int(_validate_now(now))
        expires_at = issued_at + ttl_minutes * 60
        doc = {
            "spiffe_id": spiffe_id.lower(),
            "trust_domain": trust_domain,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "public_key": public_key,
            "issuer_key_id": self._key_id,
            "usage": list(prof["usages"]),
        }
        doc["issuer_signature"] = _ed25519.sign(
            self._seed, _signing_bytes(doc)).hex()
        return doc


# ---------------------------------------------------------------------------
# The verifier (pinned trust roots, never fetched)
# ---------------------------------------------------------------------------

class SvidVerifier(object):
    """Verify SVIDs against pinned trust roots and a trust domain.

    ``trust_roots`` maps issuer key ids to 32-byte Ed25519 public keys
    (parallel roots: rotation without flag days). The keys are PINNED
    -- never fetched from metadata. A presented SVID carries no key.
    """

    def __init__(self, trust_roots, trust_domain):
        if not isinstance(trust_roots, dict) or not trust_roots:
            raise SvidError(
                SVID_MALFORMED_CODE,
                "trust_roots must be a non-empty mapping "
                "key_id -> 32-byte Ed25519 public key")
        roots = {}
        for key_id, pubkey in trust_roots.items():
            _check_key_id(key_id, "trust_roots key id")
            if not isinstance(pubkey, (bytes, bytearray)) or \
                    len(pubkey) != 32:
                raise SvidError(
                    SVID_MALFORMED_CODE,
                    "trust root %r must be a 32-byte Ed25519 public key"
                    % (key_id,))
            roots[key_id] = bytes(pubkey)
        self._roots = roots
        td = trust_domain.lower() if isinstance(trust_domain, str) \
            else trust_domain
        if not isinstance(td, str) or not _TRUST_DOMAIN_RE.match(td) or \
                len(td) > 255:
            raise SvidError(
                SVID_MALFORMED_CODE,
                "trust_domain must be a valid trust domain string")
        self._trust_domain = td

    def verify(self, svid, now=None):
        """Verify a presented SVID. Returns the identity claims dict.

        Fail-closed order: presence, structure, trust domain, issuer
        pinned, signature, expiry. A missing SVID, an expired SVID, a
        foreign trust domain, or a signature mismatch REFUSES -- the
        verifier never downgrades to a deployment-vouched identity.
        """
        if svid is None:
            raise SvidError(
                SVID_MISSING_CODE,
                "no SVID presented where identity is required")
        if not isinstance(svid, dict):
            raise SvidError(
                SVID_MALFORMED_CODE,
                "SVID must be a dict, got %s" % type(svid).__name__)
        for field in _SVID_FIELDS:
            if field not in svid:
                raise SvidError(
                    SVID_MALFORMED_CODE,
                    "SVID missing field %r" % (field,))
        spiffe_id = svid["spiffe_id"]
        trust_domain, _path = _parse_spiffe_id(spiffe_id)
        if trust_domain != self._trust_domain:
            raise SvidError(
                SVID_TRUST_DOMAIN_MISMATCH_CODE,
                "SVID trust domain %r is not this verifier's %r: "
                "a foreign trust domain is never accepted"
                % (trust_domain, self._trust_domain))
        if svid["trust_domain"] != trust_domain:
            raise SvidError(
                SVID_MALFORMED_CODE,
                "SVID trust_domain field disagrees with its spiffe_id")
        key_id = svid["issuer_key_id"]
        root = self._roots.get(key_id) if isinstance(key_id, str) \
            else None
        if root is None:
            raise SvidError(
                SVID_ISSUER_UNKNOWN_CODE,
                "issuer key id %r is not in the pinned trust bundle"
                % (key_id,))
        _check_public_key(svid["public_key"])
        for field in ("issued_at", "expires_at"):
            value = svid[field]
            if isinstance(value, bool) or not isinstance(value, int):
                raise SvidError(
                    SVID_MALFORMED_CODE,
                    "SVID %s must be an int epoch" % (field,))
        if not isinstance(svid["usage"], list) or not svid["usage"] or \
                any(not isinstance(u, str) or not u
                    for u in svid["usage"]):
            raise SvidError(
                SVID_MALFORMED_CODE,
                "SVID usage must be a non-empty list of strings")
        sig = svid["issuer_signature"]
        if not isinstance(sig, str) or len(sig) != 128:
            raise SvidError(
                SVID_MALFORMED_CODE,
                "SVID issuer_signature must be 128 hex chars "
                "(64-byte Ed25519 signature)")
        try:
            sig_bytes = bytes.fromhex(sig)
        except ValueError:
            raise SvidError(
                SVID_MALFORMED_CODE,
                "SVID issuer_signature is not hex")
        try:
            ok = bool(_ed25519.verify(root, _signing_bytes(svid),
                                      sig_bytes))
        except Exception:
            ok = False
        if not ok:
            raise SvidError(
                SVID_SIGNATURE_INVALID_CODE,
                "SVID issuer signature does not verify under the pinned "
                "root for key id %r" % (key_id,))
        at = _validate_now(now)
        if at >= svid["expires_at"]:
            raise SvidError(
                SVID_EXPIRED_CODE,
                "SVID for %r expired at %r"
                % (spiffe_id, svid["expires_at"]))
        return {
            "spiffe_id": spiffe_id,
            "trust_domain": trust_domain,
            "public_key": svid["public_key"],
            "issuer_key_id": key_id,
            "usage": list(svid["usage"]),
            "issued_at": svid["issued_at"],
            "expires_at": svid["expires_at"],
        }


# ---------------------------------------------------------------------------
# Mesh admission: default-deny ACL over verified SVIDs (headscale shape)
# ---------------------------------------------------------------------------

class MeshControl(object):
    """Admit mesh peers by verified SVID against a default-deny ACL.

    The policy is data (headscale's ACL-file shape): ``{"allow":
    [<spiffe-id prefixes>]}``. The SVID is verified FIRST -- an
    unverified, expired, or foreign-domain SVID never reaches the ACL.
    There is no flag, env var, or fallback that admits a peer without
    a verified SVID: the gate cannot be downgraded to a
    deployment-vouched identity.
    """

    def __init__(self, verifier, policy):
        if not isinstance(verifier, SvidVerifier):
            raise SvidError(
                SVID_MALFORMED_CODE,
                "verifier must be an SvidVerifier")
        if not isinstance(policy, dict):
            raise SvidError(
                SVID_MALFORMED_CODE,
                "policy must be a dict with an 'allow' list")
        allow = policy.get("allow", [])
        if not isinstance(allow, list) or any(
                not isinstance(p, str) or not p
                or not p.lower().startswith("spiffe://")
                for p in allow):
            raise SvidError(
                SVID_MALFORMED_CODE,
                "policy['allow'] must be a list of non-empty "
                "'spiffe://...' prefix strings")
        self._verifier = verifier
        # Normalize each allow entry to a path-prefix form: a trailing
        # "/" is stripped and matching happens on full path segments, so
        # an entry "spiffe://example.org/agent" admits
        # "spiffe://example.org/agent" and ".../agent/x" but never
        # ".../agents-evil/x" (prefix confusion refused by construction).
        self._allow = [p.lower().rstrip("/") for p in allow]

    def admit(self, svid, now=None):
        """Admit one peer. Returns the verified spiffe_id.

        Raises :class:`SvidError` with the SVID's refusal code when
        verification fails, or ``svid-acl-denied`` when the verified
        identity matches no allowlist prefix (default-deny).
        """
        claims = self._verifier.verify(svid, now=now)
        spiffe_id = claims["spiffe_id"]
        for prefix in self._allow:
            if spiffe_id == prefix or \
                    spiffe_id.startswith(prefix + "/"):
                return spiffe_id
        raise SvidError(
            SVID_ACL_DENIED_CODE,
            "peer %r matches no allowlist prefix (default-deny)"
            % (spiffe_id,))
