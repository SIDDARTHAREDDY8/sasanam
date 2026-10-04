"""Workload identity: SPIFFE-semantics attested identity documents.

The problem (wave-318 prospectus, section 5a): Sasanam agents act with
powerful tool grants, but the governance layer has no attested notion of
WHICH WORKLOAD is acting. ``gov/identity.py`` mints in-process identities
with no signing key; ``gov/agent_identity.py`` binds inter-agent message
senders to issued keys but says nothing about what binary or launch chain
holds the key; ``gov/attested_identity.py`` covers platform-bootstrap
ceremonies (TPM quotes, cloud instance documents) but defines no
workload-identity document format. A stolen key -- or a tampered binary
running under a borrowed ``agent_id`` -- makes every downstream record lie
about who acted.

What this module provides (STEAL of SPIFFE/SPIRE's attested-identity MODEL,
not its wire protocol -- wave-318 research):

* ``mint_document``: the deployment's launch path attests a workload's
  selectors (binary hash, invocation chain, deployment mode) against an
  explicit ``AttestationPolicy`` allowlist and mints a short-lived signed
  identity document shaped like a SPIFFE SVID:
  ``spiffe://<trust-domain>/<agent-path>``.
* ``DocumentVerifier.verify``: the standalone verifier. Fails closed with
  typed ``identity-*`` decision codes on forged signatures, expired or
  not-yet-valid documents, audience mismatch, selector mismatch against the
  re-attested facts, and foreign trust domains without an explicit
  federation record. Malformed documents refuse, never raise.
* Expiry-as-revocation: documents carry a short TTL (default 1h, hard max
  enforced at mint). There is no revocation list; expiry IS the revocation
  mechanism (K8s bound-token pattern).
* Audience binding on every document: a document minted for
  ``tool:email-sender`` refuses when presented to ``tool:file-writer`` --
  the no-token-passthrough doctrine (MCP OAuth 2.1 authorization profile,
  ADAPT) at the identity layer.
* Trust-domain federation as explicit policy: a foreign trust domain is
  accepted only under a ``FederationPolicy`` record pinning its issuer key
  and TTL bound. Trust is never implicit.

Signature primitive: Ed25519 via the repo's own RFC 8032 implementation
("Ed25519 everywhere, no PKI" -- same as delegation tokens and A2A card
verification). The signature covers the JCS-canonical encoding of the
document minus its own ``signature`` field.

RELATIONSHIP TO THE SIBLING MODULES: ``gov/attested_identity.py`` answers
"how does a platform prove itself" (TPM/cloud bootstrap ceremonies);
THIS module answers "what does the resulting workload-identity document
look like and how is it verified". A future lane may have the tier-1
bootstrap ceremony mint these documents; the document model stands alone.

UNIT42 NEGATIVE RULE (load-bearing design rule, wave-318 research): a
successful verification means "this document was minted by a trusted issuer
for a workload with these selectors, is unexpired, and is being presented
for its stated audience". It is NEVER evidence that the node or platform is
intact. Pin identity grants to strong selectors and short TTLs; record
"node compromise = all node-scoped identities compromised" in the threat
model.

HONEST RESIDUALS (never claimed away):

* The issuer's seed is the trust anchor: whoever holds it mints arbitrary
  identities ("who guards the minter?" is a deployment question -- the
  seed lives with the deployment's launch path, same trust model as the
  HMAC log key in ``gov/log.py``). Deployment guidance must name OpenBao
  (not HashiCorp Vault) for any shipped secrets backend (wave-318 lane 5
  license carve-out).
* Attestation is only as true as the launch path's observation: the issuer
  checks presented selectors against the policy, but the issuer cannot
  re-observe the workload itself. A compromised launch path attests lies.
* The verifier's caller supplies ``presented_selectors``: the check "the
  presenting workload matches the document" is only meaningful when the
  caller re-attests the presenting process (the governance proxy), not when
  the agent self-reports.
* No clock-skew allowance: verification uses the caller-supplied ``now``
  deterministically. Deployments with skewed clocks fail closed.
* This wave is advisory at the approval seam: the verification outcome is
  recorded MAC-bound on the approval record but never gates the decision.
  Gating is a later wave's decision, once the model has field evidence.
"""

import base64
import json
import re
import time

from . import ed25519 as _ed

SCHEMA = "workload-identity/v1"

# K8s bound-token pattern: sub-hour TTL, expiry is the revocation
# mechanism. The issuer enforces this hard max; documents asking for
# longer refuse at mint.
MAX_TTL_SECONDS = 3600
DEFAULT_TTL_SECONDS = 3600

# Closed deployment-mode vocabulary. Anything else refuses at mint --
# an unrecognized mode is not a mode we attested.
DEPLOYMENT_MODES = ("staging", "production", "test")

# The audience every approval-queue-bound document names. The queue's
# verifier is configured with this; documents minted for any other
# audience refuse at the queue (no token passthrough).
APPROVAL_QUEUE_AUDIENCE = "governance:approval-queue"

_SPIFFE_RE = re.compile(
    r"^spiffe://([a-z0-9]([a-z0-9\-.]*[a-z0-9])?)(/[^\s]*)?$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class MintRefusal(Exception):
    """Raised by ``mint_document`` when the request is not mintable.

    Carries ``code`` (always ``identity-mint-refused`` in this wave) and a
    human reason. A refusal is never a document.
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.code = "identity-mint-refused"
        self.reason = reason


class IdentityVerdict:
    """The outcome of ``DocumentVerifier.verify``.

    ``verified`` True means the document is accepted; False means refused
    with the typed ``code``. Verdicts never raise -- a hostile document is
    data, not an exception.
    """

    __slots__ = ("verified", "code", "spiffe_id", "trust_domain",
                 "audience", "expires_at", "detail")

    def __init__(self, verified, code, spiffe_id=None, trust_domain=None,
                 audience=None, expires_at=None, detail=""):
        self.verified = verified
        self.code = code
        self.spiffe_id = spiffe_id
        self.trust_domain = trust_domain
        self.audience = audience
        self.expires_at = expires_at
        self.detail = detail

    def to_dict(self):
        return {
            "verified": self.verified,
            "code": self.code,
            "spiffe_id": self.spiffe_id,
            "trust_domain": self.trust_domain,
            "audience": self.audience,
            "expires_at": self.expires_at,
            "detail": self.detail,
        }


class AttestationPolicy:
    """What the issuer may mint for.

    ``recognized``: the allowlisted (binary_hash, deployment_mode) pairs.
    ``trust_domain``: the domain minted documents carry. A mint request
    whose selectors are not recognized refuses -- the issuer never mints
    for an unrecognized workload.
    """

    def __init__(self, recognized, trust_domain):
        self.recognized = frozenset(tuple(p) for p in recognized)
        self.trust_domain = trust_domain


class FederationRecord:
    """Explicit cross-domain trust: pins a foreign trust domain's issuer
    key and the maximum TTL the local deployment will honor from it."""

    def __init__(self, issuer_pubkey, max_ttl_seconds):
        self.issuer_pubkey = bytes(issuer_pubkey)
        self.max_ttl_seconds = int(max_ttl_seconds)


class FederationPolicy:
    """The explicit federation table: foreign trust domain ->
    FederationRecord. Absent a record, the domain is untrusted."""

    def __init__(self, records):
        self.records = dict(records)


def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text):
    if not isinstance(text, str):
        raise ValueError("not a string")
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def _check_selectors(selectors):
    """Validate selector shape; returns a normalized dict or None."""
    if not isinstance(selectors, dict):
        return None
    keys = ("binary_hash", "invocation_chain", "deployment_mode")
    if set(selectors.keys()) != set(keys):
        return None
    bh = selectors["binary_hash"]
    chain = selectors["invocation_chain"]
    mode = selectors["deployment_mode"]
    if not isinstance(bh, str) or not _HEX64_RE.match(bh):
        return None
    if not isinstance(chain, str) or not chain or len(chain) > 256:
        return None
    if mode not in DEPLOYMENT_MODES:
        return None
    return {"binary_hash": bh, "invocation_chain": chain,
            "deployment_mode": mode}


def _check_agent_path(agent_path):
    return (isinstance(agent_path, str) and agent_path.startswith("/")
            and len(agent_path) > 1 and not any(c.isspace()
                                                for c in agent_path))


def mint_document(issuer_seed, agent_path, selectors, audience,
                  ttl_seconds, now, policy):
    """Mint a short-lived workload identity document.

    ``issuer_seed``: the deployment-held 32-byte Ed25519 seed (the trust
    anchor). ``agent_path``: e.g. ``/agent/scheduler-7`` -- becomes
    ``spiffe://<trust-domain><agent-path>``. ``selectors``: the
    launch-path-attested facts. ``audience``: mandatory, non-empty.
    ``ttl_seconds``: 1..MAX_TTL_SECONDS. ``now``: integer unix time.
    ``policy``: the ``AttestationPolicy``.

    Returns the document dict (JSON-serializable). Raises ``MintRefusal``
    (never a document) when the request is not mintable.
    """
    if not isinstance(issuer_seed, (bytes, bytearray)) \
            or len(issuer_seed) != 32:
        raise MintRefusal("issuer seed must be 32 bytes")
    if not _check_agent_path(agent_path):
        raise MintRefusal("agent_path must be a non-empty '/'-rooted path "
                          "without whitespace")
    norm = _check_selectors(selectors)
    if norm is None:
        raise MintRefusal("selectors malformed: need binary_hash (64 hex), "
                          "invocation_chain, and deployment_mode in %r"
                          % (DEPLOYMENT_MODES,))
    if (norm["binary_hash"], norm["deployment_mode"]) not in \
            policy.recognized:
        raise MintRefusal("selectors not in the attestation policy: the "
                          "issuer never mints for unrecognized workloads")
    if not isinstance(audience, str) or not audience:
        raise MintRefusal("audience is mandatory and non-empty: an "
                          "audience-less document is a passthrough "
                          "accident waiting to happen")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) \
            or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise MintRefusal("ttl_seconds must be an int in [1, %d]"
                          % MAX_TTL_SECONDS)
    if not isinstance(now, int) or isinstance(now, bool):
        raise MintRefusal("now must be an integer unix time")
    if not _SPIFFE_RE.match("spiffe://" + policy.trust_domain + agent_path):
        raise MintRefusal("trust_domain/agent_path do not form a valid "
                          "SPIFFE ID")

    body = {
        "schema": SCHEMA,
        "spiffe_id": "spiffe://%s%s" % (policy.trust_domain, agent_path),
        "trust_domain": policy.trust_domain,
        "selectors": norm,
        "audience": audience,
        "not_before": now,
        "not_after": now + ttl_seconds,
    }
    sig = _ed.sign(bytes(issuer_seed), _canonical_bytes(body))
    doc = dict(body)
    doc["signature"] = _b64e(sig)
    return doc


class DocumentVerifier:
    """Verify workload identity documents.

    ``issuer_pubkeys``: {trust_domain: 32-byte Ed25519 pubkey} for domains
    this verifier accepts directly (normally just its own).
    ``trust_domain``: this verifier's own domain. ``federation``: an
    optional ``FederationPolicy`` for explicit cross-domain trust.
    ``now``: integer unix time, or None for the real clock.
    """

    def __init__(self, issuer_pubkeys, trust_domain, federation=None,
                 now=None):
        self._keys = {d: bytes(k) for d, k in issuer_pubkeys.items()}
        self._domain = trust_domain
        self._federation = federation
        self._now = now

    def _now_int(self):
        if self._now is None:
            return int(time.time())
        return int(self._now)

    def verify(self, doc, audience, presented_selectors):
        """Verify a document. Never raises on hostile documents: every
        refusal is a typed ``IdentityVerdict``.

        ``audience``: the audience the document must name (exact match).
        ``presented_selectors``: the facts re-attested about the
        presenting workload by the caller -- the check only means
        something when the caller is the attesting path, not the agent.
        """
        now = self._now_int()
        if not isinstance(audience, str) or not audience:
            raise ValueError("audience must be a non-empty string")
        bad = self._refuse_malformed(doc)
        if bad is not None:
            return bad
        trust_domain = doc["trust_domain"]

        key = self._keys.get(trust_domain)
        federated = False
        max_ttl = MAX_TTL_SECONDS
        if trust_domain != self._domain:
            rec = (self._federation.records.get(trust_domain)
                   if self._federation is not None else None)
            if rec is None:
                return IdentityVerdict(
                    False, "identity-untrusted-domain",
                    spiffe_id=doc.get("spiffe_id"),
                    trust_domain=trust_domain,
                    detail="foreign trust domain with no federation "
                           "record: trust is never implicit")
            key = rec.issuer_pubkey
            federated = True
            max_ttl = rec.max_ttl_seconds
        if key is None or len(key) != 32:
            return IdentityVerdict(
                False, "identity-forged", spiffe_id=doc.get("spiffe_id"),
                trust_domain=trust_domain,
                detail="no issuer key for the claimed trust domain")

        try:
            sig = _b64d(doc["signature"])
        except Exception:  # noqa: BLE001
            sig = b""
        body = {k: v for k, v in doc.items() if k != "signature"}
        if not _ed.verify(key, _canonical_bytes(body), sig):
            return IdentityVerdict(
                False, "identity-forged", spiffe_id=doc.get("spiffe_id"),
                trust_domain=trust_domain,
                detail="signature does not verify under the domain's "
                       "issuer key")

        not_before = doc["not_before"]
        not_after = doc["not_after"]
        if now < not_before:
            return IdentityVerdict(
                False, "identity-not-yet-valid",
                spiffe_id=doc.get("spiffe_id"), trust_domain=trust_domain,
                detail="document not yet valid")
        if now >= not_after:
            return IdentityVerdict(
                False, "identity-expired", spiffe_id=doc.get("spiffe_id"),
                trust_domain=trust_domain,
                detail="document expired: expiry is the revocation "
                       "mechanism")
        if federated and (not_after - not_before) > max_ttl:
            return IdentityVerdict(
                False, "identity-untrusted-domain",
                spiffe_id=doc.get("spiffe_id"), trust_domain=trust_domain,
                detail="federated document TTL exceeds the federation "
                       "record's bound")
        if doc["audience"] != audience:
            return IdentityVerdict(
                False, "identity-audience-mismatch",
                spiffe_id=doc.get("spiffe_id"), trust_domain=trust_domain,
                audience=doc.get("audience"),
                detail="document names audience %r, presented for %r: "
                       "no token passthrough" % (doc.get("audience"),
                                                 audience))
        presented = _check_selectors(presented_selectors)
        if presented is None or presented != doc["selectors"]:
            return IdentityVerdict(
                False, "identity-selector-mismatch",
                spiffe_id=doc.get("spiffe_id"), trust_domain=trust_domain,
                detail="presented workload facts do not match the "
                       "document's selectors")
        return IdentityVerdict(
            True, "identity-attested", spiffe_id=doc["spiffe_id"],
            trust_domain=trust_domain, audience=doc["audience"],
            expires_at=not_after,
            detail="document minted by a trusted issuer for these "
                   "selectors, unexpired, presented for its audience -- "
                   "NOT evidence of node/platform integrity")

    @staticmethod
    def _refuse_malformed(doc):
        if not isinstance(doc, dict):
            return IdentityVerdict(False, "identity-forged",
                                   detail="document is not a dict")
        if doc.get("schema") != SCHEMA:
            return IdentityVerdict(False, "identity-forged",
                                   detail="unknown schema")
        spiffe_id = doc.get("spiffe_id")
        m = _SPIFFE_RE.match(spiffe_id) if isinstance(spiffe_id,
                                                      str) else None
        if m is None:
            return IdentityVerdict(False, "identity-forged",
                                   detail="malformed SPIFFE ID")
        if m.group(1) != doc.get("trust_domain"):
            return IdentityVerdict(False, "identity-forged",
                                   detail="SPIFFE ID domain does not match "
                                          "the document's trust_domain")
        if _check_selectors(doc.get("selectors")) is None:
            return IdentityVerdict(False, "identity-forged",
                                   detail="malformed selectors")
        if not isinstance(doc.get("audience"), str) \
                or not doc.get("audience"):
            return IdentityVerdict(False, "identity-forged",
                                   detail="malformed audience")
        nb, na = doc.get("not_before"), doc.get("not_after")
        if not isinstance(nb, int) or isinstance(nb, bool) \
                or not isinstance(na, int) or isinstance(na, bool) \
                or not na > nb:
            return IdentityVerdict(False, "identity-forged",
                                   detail="malformed validity window")
        if not isinstance(doc.get("signature"), str):
            return IdentityVerdict(False, "identity-forged",
                                   detail="malformed signature")
        return None
