"""Three-token identity + spawn lineage (wave-74, Part 4: Identity).

Implements the §7 delegation contract from
``workstreams/architect/PROVENANCE_DESIGN.md`` and the converged answer
from ``research/agent-governance-learnings-2026-09-22.md`` Part 4
(South et al., "Authenticated Delegation and Authorized AI Agents";
the SPIFFE two-layer split; per-hop scope attenuation).

The three tokens:

* **user token** — the user's identity + permissions. Issued by the
  identity-provider stand-in key (production: the deployment's IdP).
* **agent token** — the agent as native client: agent_id, role,
  principal, capabilities. Issued by the deployment's
  registration-authority key.
* **delegation token** — **issued and SIGNED BY THE HUMAN DELEGATOR**,
  referencing the SHA-256 hashes of the other two, carrying scope,
  expiry, revocation endpoint, audit URLs. Sub-agent (spawn) tokens are
  the same kind with ``delegation_depth >= 1``: signed by the PARENT
  AGENT's key, carrying a SUBSET of the parent's scope, chained to the
  parent's token by hash. This is the spawn-lineage mechanism and the
  swarm control in one.

Signature choice (justified in ``workstreams/architect/IDENTITY_DESIGN.md``
§2): **Ed25519 everywhere, no PKI.** The human-signature and
parent-signature properties are unforgeability-by-the-verifier
properties — HMAC would put the signing key in the verifier's hands,
making "human-signed" delegations forgeable by the agent (theater).
Public keys are registered out-of-band in a deployment-controlled
``DelegationTrust`` roster (the ``gov/signing.py`` offline-root trust
model). Reuses ``gov/ed25519.py`` / ``gov/signing.py`` — no new crypto.

SPIFFE two-layer split, as realized in this tree:

* transport layer (*who is calling*): the executor's
  deployment-provisioned session identity (F55) + the process boundary.
  There is no mTLS transport in this local model; that is the honest
  statement of what the layer is here.
* application layer (*on behalf of whom*): this module's three-token
  chain, verified here and enforced at the executor gate.

Enforcement: :func:`authorize_action` computes the permission
intersection (user permissions ∩ agent capabilities ∩ delegation
scope) and raises fail-closed. The executor calls
:func:`enforce_tool_call` BEFORE policy evaluation when a
:class:`DelegationContext` is installed — the check lives in code, not
policy text, so no policy YAML edit can disable it (the "agent without
delegation" case fails closed BY CONSTRUCTION; the construction-proof
probe pins this).

Honest boundaries (also in IDENTITY_DESIGN.md §4/§8):

* Audience (wave-86, F132): tokens MAY carry a signed ``aud`` claim
  (the deployment id) and a ``DelegationTrust`` MAY set
  ``audience``. When the verifier's audience is set, a missing or
  mismatched ``aud`` is refused — the cross-deployment confused
  deputy dies at verification. When it is NOT set (the default),
  verification discloses this loudly on stderr once per process:
  deployments sharing operator keys accept each other's tokens.
  Spawn inherits ``aud`` from the parent token — never a parameter —
  so a spawn cannot re-target a delegation at another deployment.
* Revocation: the token carries ``revocation_endpoint`` + the verifier
  exposes a ``revocation_checker`` seam (reference: ``RevocationLedger``).
  Default is TTL-only — short TTLs paper over revocation; true
  propagation is a STATED BOUNDARY, not a hidden gap.
* Resource (wave-278, RFC 8707 steal): delegation tokens MAY carry
  a signed ``resource`` claim (the canonical https URI of the intended
  MCP server / tool endpoint). The verifier declares the resource at
  the use seam (``authorize_action`` / ``enforce_tool_call`` /
  ``bind``); a missing or mismatched claim is refused fail-closed as
  ``DelegationBindingError`` — token passthrough is refused, not
  prevented by convention. Spawn inherits the parent's resource (never
  a parameter), mirroring the ``aud`` inheritance. When the verifier
  declares nothing, behavior is byte-identical to the pre-binding
  tree (verifier-declared, the wave-86 audience precedent). Honest
  residual: the executor's tool seam is tool-name based and carries no
  server URI today, so it cannot declare a resource — the binding is
  enforced at the seams that do declare one.
* The human-signature seam: in the local/test model the human's public
  key is provisioned by the deployment into the trust roster
  out-of-band; in production this is the deployer's identity key. The
  trust that the registered key belongs to the human is a deployment
  act, not a cryptographic proof.
* Scope language v1 is tool-granular (``"tool:<name>"`` / ``"tool:*"``);
  resource-scoped entries are future work.
* Single-use leases (wave-280, ``gov/ephemeral_grants.py``): a
  delegation minted with ``lease="single-use"`` requires per-invocation
  contextual tuples at the check seam and is refused on replay through
  an in-process spent-lease registry. Cross-process replay is a STATED
  BOUNDARY (same class as the revocation seam's boundary above).

$0 spend, synthetic/local only. No credentials, no network.
"""

import hashlib
import json
import secrets
import sys
from datetime import datetime, timedelta, timezone

from . import ed25519 as _ed
from . import signing as _signing
from . import ephemeral_grants as _eg

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOKEN_VERSION = 1
TOKENS_SCHEMA = "south-3token/v1"  # the prov-hop tokens slot marker (§7)

_TOKEN_DOMAIN = b"gov-delegation-token/v1\x00"

TOKEN_KINDS = frozenset({"user", "agent", "delegation"})

# Default delegation TTL: 1 hour (the SPIFFE SVID 1-hour grounding).
DEFAULT_TTL_S = 3600
# Hard cap: beyond a day is a standing privilege, not a delegation.
MAX_TTL_S = 86400
# Clock-skew acceptance, each direction (matches provenance _TIMING_SKEW).
CLOCK_SKEW_S = 300
# Spawn-lineage depth cap: deeper chains are a design smell (swarm control).
MAX_DELEGATION_DEPTH = 8


def _check_resource(resource, what="resource"):
    """Validate an RFC 8707 resource indicator (fail-fast at issuance).

    The resource is the canonical URI of the protected resource the
    credential is issued for (the MCP server / tool endpoint). None =
    unbound (legacy). A non-URI value is refused loudly at mint: a
    malformed binding minted into a token would be unverifiable
    theater. Comparison at verification is byte-for-byte on the
    canonical form validated here.
    """
    if resource is None:
        return None
    if not isinstance(resource, str) or not resource:
        raise ValueError("%s must be a canonical https URI or None"
                         % (what,))
    if not resource.startswith("https://") or len(resource) <= len("https://"):
        raise ValueError("%s must be a canonical https URI (RFC 8707 "
                         "discipline), got %r" % (what, resource))
    if any(ch.isspace() for ch in resource):
        raise ValueError("%s must not contain whitespace: %r"
                         % (what, resource))
    return resource


# ---------------------------------------------------------------------------
# Errors (all fail-closed)
# ---------------------------------------------------------------------------

class DelegationError(Exception):
    """Base: anything wrong with delegation identity fails closed."""


class DelegationRequiredError(DelegationError):
    """No delegation token where one is required — the agent-without-
    delegation case. Raised in CODE before policy evaluation, so policy
    text cannot re-enable it."""


class DelegationSignatureError(DelegationError):
    """Signature invalid, unknown issuer, or malformed token."""


class DelegationExpiredError(DelegationError):
    """Token outside its [not_before - skew, expires_at + skew] window."""


class DelegationBindingError(DelegationError):
    """Token presented in a session it was not issued for (replay)."""


class EphemeralGrantError(_eg.EphemeralGrantError, DelegationError):
    """Ephemeral-grant refusal raised at the delegation seam (wave-280).

    Multiple-inheritance bridge: catchable both as the pure module's
    ``ephemeral_grants.EphemeralGrantError`` (machine code
    ``delegation-ephemeral-grant-refused``) and as the seam's
    ``DelegationError`` — so the executor's ``except DelegationError``
    refusal path audit-logs the denial instead of crashing on a raw
    exception. The seam raises THIS class, never ``_eg``'s directly.
    """


class DelegationScopeError(DelegationError):
    """Action outside the permission intersection."""


class DelegationAttenuationError(DelegationError):
    """Spawn widened (or failed to narrow-to-subset) the parent scope."""


class DelegationRevokedError(DelegationError):
    """Token (or an ancestor) is revoked per the revocation seam."""


# ---------------------------------------------------------------------------
# Canonical form + refs
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _sign_body(signer, body):
    if not isinstance(signer, _signing.Signer):
        raise TypeError("signer must be a gov.signing.Signer")
    return signer.sign(_TOKEN_DOMAIN + _canonical(body)).hex()


def _verify_sig(pub, body, sig_hex):
    try:
        sig = bytes.fromhex(sig_hex)
    except (TypeError, ValueError):
        return False
    return _ed.verify(bytes(pub), _TOKEN_DOMAIN + _canonical(body), sig)


def token_ref(token):
    """The log-safe ref of a token: SHA-256 over the canonical FULL token
    (including the signature — a re-signed token is a different token).

    This is what fills the v2 prov-hop ``tokens`` slots: hashes, never
    secrets, in the agent-reachable log.
    """
    if not isinstance(token, dict):
        raise TypeError("token must be a dict")
    return hashlib.sha256(_canonical(token)).hexdigest()


# ---------------------------------------------------------------------------
# Time + scope helpers
# ---------------------------------------------------------------------------

def _now_dt(now):
    return now or datetime.now(timezone.utc)


def _iso(dt):
    if not isinstance(dt, datetime) or dt.tzinfo is None:
        raise ValueError("token times must be tz-aware datetimes")
    return dt.astimezone(timezone.utc).isoformat()


def _parse_time(value, what):
    if not isinstance(value, str) or not value:
        raise DelegationSignatureError("%s missing" % what)
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        raise DelegationSignatureError("%s not ISO-8601: %r" % (what, value))
    if dt.tzinfo is None:
        raise DelegationSignatureError("%s must be tz-aware" % what)
    return dt


def _check_scope_list(scope, what):
    """Fail-closed at issuance: scope is a non-empty list of
    ``tool:<name>`` / ``tool:*`` capability strings."""
    if not isinstance(scope, (list, tuple)) or not scope:
        raise ValueError("%s must be a non-empty list of capability "
                         "strings" % what)
    out = []
    for entry in scope:
        if not isinstance(entry, str) or not entry:
            raise ValueError("%s entries must be non-empty strings" % what)
        entry = entry.strip()
        if not entry.startswith("tool:") or len(entry) <= len("tool:"):
            raise ValueError(
                "%s entry %r malformed: v1 scope entries are "
                "'tool:<name>' or 'tool:*'" % (what, entry))
        out.append(entry)
    # De-duplicated, order-stable.
    return list(dict.fromkeys(out))


def _scope_allows(scope, action):
    """Does capability set ``scope`` allow ``action`` ("tool:<name>")?

    Exact entry or the ``tool:*`` wildcard. No other pattern language
    in v1 — anything fancier would be unverifiable theater.
    """
    return action in scope or "tool:*" in scope


def _scope_covers(parent_scope, child_scope):
    """Every child entry must be covered by a parent entry (exact or
    parent wildcard). This is the monotonic-narrowing check."""
    return all(_scope_allows(parent_scope, entry)
               for entry in child_scope)


# ---------------------------------------------------------------------------
# Issuance
# ---------------------------------------------------------------------------

def _base_token(token_kind, signer, subject, session_id, claims,
                ttl_s, now, *, audience=None, resource=None):
    if token_kind not in TOKEN_KINDS:
        raise ValueError("unknown token_kind %r" % (token_kind,))
    if not isinstance(subject, str) or not subject:
        raise ValueError("subject must be a non-empty string")
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("session_id must be a non-empty string")
    if not isinstance(claims, dict):
        raise ValueError("claims must be a dict")
    if audience is not None and (
            not isinstance(audience, str) or not audience):
        raise ValueError("audience must be a non-empty string (the "
                         "deployment id) or None")
    # Wave-278 (RFC 8707 steal): the resource indicator is validated
    # fail-fast at issuance so a malformed binding can never be minted.
    resource = _check_resource(resource)
    ttl_s = DEFAULT_TTL_S if ttl_s is None else ttl_s
    if (isinstance(ttl_s, bool) or not isinstance(ttl_s, (int, float))
            or ttl_s <= 0 or ttl_s > MAX_TTL_S):
        raise ValueError("ttl_s must be in (0, %d]" % MAX_TTL_S)
    issued = _now_dt(now)
    body = {
        "token_version": TOKEN_VERSION,
        "token_kind": token_kind,
        "issuer": signer.key_id,
        "subject": subject,
        "issued_at": _iso(issued),
        "not_before": _iso(issued),
        "expires_at": _iso(issued + timedelta(seconds=ttl_s)),
        "session_id": session_id,
        "claims": claims,
    }
    if audience is not None:
        # Wave-86 (F132): the audience/deployment claim. It sits in the
        # SIGNED body (top-level envelope, next to session_id — not
        # inside claims, because it binds the token to a deployment,
        # not to an authorization fact), so the signature covers it and
        # no re-signing can move a token across deployments.
        body["aud"] = audience
    if resource is not None:
        # Wave-278 (RFC 8707 steal): the resource indicator. Top-level
        # envelope like aud — it binds the token to the intended
        # protected resource (the MCP server / tool endpoint), not to
        # an authorization fact — so the signature covers it and no
        # re-signing can move a token across servers (token passthrough
        # is refused at verification, not prevented by convention).
        body["resource"] = resource
    body["sig"] = _sign_body(signer, body)
    return body


def issue_user_token(user_issuer_signer, user_id, permissions,
                     session_id, display_name=None, ttl_s=None, now=None,
                     audience=None):
    """Issue a user token (the IdP stand-in signs in the local model).

    ``permissions``: the user's entitlement set (capability strings).
    ``audience``: optional deployment id bound into the signed envelope
    (wave-86, F132) — the verifier refuses the token outside it.
    """
    claims = {
        "user_id": user_id,
        "display_name": display_name or user_id,
        "permissions": _check_scope_list(permissions, "permissions"),
    }
    return _base_token("user", user_issuer_signer, user_id, session_id,
                       claims, ttl_s, now, audience=audience)


def issue_agent_token(authority_signer, agent_id, role, principal,
                      capabilities, session_id, workload_id=None,
                      ttl_s=None, now=None, audience=None):
    """Issue an agent token (the agent as native client).

    Signed by the deployment's registration-authority key.
    ``capabilities``: what this agent build may do (capability strings).
    ``audience``: optional deployment id bound into the signed envelope
    (wave-86, F132).
    """
    for name, value in (("agent_id", agent_id), ("role", role),
                        ("principal", principal)):
        if not isinstance(value, str) or not value:
            raise ValueError("%s must be a non-empty string" % name)
    claims = {
        "agent_id": agent_id,
        "role": role,
        "principal": principal,
        "workload_id": workload_id or agent_id,
        "capabilities": _check_scope_list(capabilities, "capabilities"),
    }
    return _base_token("agent", authority_signer, agent_id, session_id,
                       claims, ttl_s, now, audience=audience)


def issue_delegation(human_signer, delegator_user_id, user_token,
                     agent_token, scope, session_id,
                     revocation_endpoint, audit_urls=None,
                     ttl_s=None, now=None, audience=None, card_kid=None,
                     resource=None, *, lease=None):
    """Issue the human-signed delegation token (depth 0).

    ``human_signer``: the HUMAN DELEGATOR's key (``gov.signing.Signer``).
    In the local/test model this is provisioned by the deployment; in
    production it is the deployer's identity key. The private key never
    enters the agent's reach — only this function (called by the
    human/deployment side) touches it.

    The token references the hashes of the other two tokens (South et
    al.'s binding) and carries scope, expiry, revocation endpoint, and
    audit URLs.

    ``audience``: optional deployment id bound into the signed envelope
    (wave-86, F132) — the verifier refuses the token outside it.

    ``resource``: optional RFC 8707 resource indicator (wave-278) — the
    canonical https URI of the protected resource (MCP server / tool
    endpoint) this delegation is issued for. Bound into the signed
    envelope; the verifier refuses the token when presented for a
    different resource (token passthrough refused fail-closed). None
    (default) = unbound: pre-binding behavior, byte-identical. A
    malformed URI is refused loudly here, at issuance — never minted.

    ``card_kid``: optional A2A Agent Card key id binding this delegation
    to a card-verified foreign-agent identity. The deployment sets this
    ONLY after ``gov.agent_cards.register_agent_card`` verified the
    card; ``verify_delegation_chain`` then enforces that the token's
    subject equals the card identity registered for this kid (the
    identity-proof layer). Local (non-card) delegations leave it None.
    The kid sits in the SIGNED claims, so no re-signing can swap it.

    ``lease``: optional ``"single-use"`` (wave-280, ephemeral grants).
    A single-use lease REQUIRES contextual tuples on every check
    request (``authorize_action(..., contextual_tuples=...)``) and is
    refused on replay through a spent-lease registry -- the concrete
    single-use-lease mechanism. None (default) = multi-use: the
    pre-lease behavior, byte-identical (the claim is absent from the
    signed claims unless set).
    """
    if lease not in (None, "single-use"):
        raise ValueError("lease must be None or 'single-use', got %r"
                         % (lease,))
    if not isinstance(delegator_user_id, str) or not delegator_user_id:
        raise ValueError("delegator_user_id must be a non-empty string")
    if not isinstance(revocation_endpoint, str) or not revocation_endpoint:
        raise ValueError("revocation_endpoint must be a non-empty string "
                         "(the revocation story is told honestly: a URI "
                         "identifying the authority's revocation source)")
    for tok, kind in ((user_token, "user"), (agent_token, "agent")):
        if not isinstance(tok, dict) or tok.get("token_kind") != kind:
            raise ValueError("expected a %r token" % kind)
        if tok.get("session_id") != session_id:
            raise ValueError("the %s token is bound to a different "
                             "session" % kind)
    audit_urls = list(audit_urls or [])
    if any(not isinstance(u, str) or not u for u in audit_urls):
        raise ValueError("audit_urls must be strings")
    if card_kid is not None and (
            not isinstance(card_kid, str) or not card_kid):
        raise ValueError("card_kid must be a non-empty key-id string "
                         "or None")
    claims = {
        "delegator": delegator_user_id,
        "user_token_hash": token_ref(user_token),
        "agent_token_hash": token_ref(agent_token),
        "scope": _check_scope_list(scope, "scope"),
        "revocation_endpoint": revocation_endpoint,
        "audit_urls": audit_urls,
        "delegation_depth": 0,
        "parent_token_hash": None,
        # A2A card identity binding (additive; None for local issuers).
        # Set by the deployment only after the card verified; the chain
        # verifier enforces subject == registered card identity.
        "card_kid": card_kid,
    }
    if lease is not None:
        # Single-use lease flag (wave-280): the claim is ABSENT unless
        # set, so default issuance stays byte-identical.
        claims["lease"] = lease
    return _base_token("delegation", human_signer, agent_token["subject"],
                       session_id, claims, ttl_s, now, audience=audience,
                       resource=resource)


# ---------------------------------------------------------------------------
# Trust roster (no PKI — deployment-controlled, out-of-band)
# ---------------------------------------------------------------------------

class DelegationTrust:
    """The verifier's public-key roster. NO PKI: keys are registered
    out-of-band by the deployment (the ``gov/signing.py`` offline-root
    trust model). Rotation = re-registration, an audited deployment act.

    * ``human_keys``: ``{key_id: 32-byte pub}`` — humans allowed to sign
      depth-0 delegation tokens (the deployer's identity keys).
    * ``authority_keys``: ``{key_id: pub}`` — the registration authority
      (agent-token issuer).
    * ``user_issuer_keys``: ``{key_id: pub}`` — the identity provider
      stand-in (user-token issuer).
    * ``agent_keys``: ``{agent_id: pub}`` — the session's agent key
      roster, for parent signatures on sub-delegation tokens (depth ≥ 1).
      Registered at session open, chained into the log with the session.
      A2A card-verified foreign agents are registered here by
      ``gov.agent_cards.register_agent_card`` keyed by the card's
      ``name`` (their Ed25519 card key doubles as their parent-signing
      key for their spawn lineage).
    * ``card_identities``: ``{identity: {"kids": {kid: {"pubkey",
      "alg"}}}}`` — the card-identity registry (the identity-PROOF
      layer). Populated ONLY by ``gov.agent_cards.register_agent_card``
      after full card verification; ``verify_delegation_chain``
      enforces the ``card_kid`` claim binding against this registry.
      Local (non-card) issuers never appear here.
    * ``audience`` (wave-86, F132): this deployment's id. When set,
      verification refuses any token whose signed ``aud`` claim is
      missing or different — the cross-deployment confused-deputy
      replay dies here. When None (default), no audience check runs
      and a loud one-time stderr disclosure says so: two deployments
      sharing operator keys then accept each other's tokens.
    """

    def __init__(self, *, human_keys, authority_keys, user_issuer_keys,
                 agent_keys=None, card_identities=None, audience=None):
        self.human_keys = _clean_keymap(human_keys, "human_keys")
        self.authority_keys = _clean_keymap(authority_keys,
                                            "authority_keys")
        self.user_issuer_keys = _clean_keymap(user_issuer_keys,
                                              "user_issuer_keys")
        self.agent_keys = {}
        for agent_id, pub in (agent_keys or {}).items():
            if not isinstance(agent_id, str) or not agent_id:
                raise ValueError("agent_keys keys must be non-empty "
                                 "agent_id strings")
            self.agent_keys[agent_id] = _clean_pub(pub, "agent_keys[%r]"
                                                   % agent_id)
        self.card_identities = {}
        for identity, rec in (card_identities or {}).items():
            if not isinstance(identity, str) or not identity:
                raise ValueError("card_identities keys must be non-empty "
                                 "identity strings")
            if not isinstance(rec, dict):
                raise ValueError("card_identities[%r]: must be a record "
                                 "dict" % identity)
            kids = rec.get("kids")
            if not isinstance(kids, dict) or not kids:
                raise ValueError("card_identities[%r]: kids must be a "
                                 "non-empty {kid: record} mapping"
                                 % identity)
            clean = {}
            for kid, krec in kids.items():
                if not isinstance(kid, str) or not kid:
                    raise ValueError("card_identities[%r]: kids must be "
                                     "non-empty strings" % identity)
                if not isinstance(krec, dict):
                    raise ValueError("card_identities[%r][%r]: must be a "
                                     "record dict" % (identity, kid))
                clean[kid] = {
                    "pubkey": _clean_pub(krec.get("pubkey"),
                                         "card_identities[%r][%r].pubkey"
                                         % (identity, kid)),
                    "alg": krec.get("alg") or "EdDSA",
                }
            self.card_identities[identity] = {"kids": clean}
        if audience is not None and (
                not isinstance(audience, str) or not audience):
            raise ValueError("audience must be a non-empty string (the "
                             "deployment id) or None")
        self.audience = audience

    def register_card_identity(self, identity, kid, pubkey, alg="EdDSA"):
        """Admit one verified card key into the identity-proof registry.

        Called ONLY by ``gov.agent_cards.register_agent_card`` after
        full card verification — never by agent-reachable code. ``pub``
        validation is fail-fast (ValueError); verification failures
        never reach here.
        """
        if not isinstance(identity, str) or not identity:
            raise ValueError("identity must be a non-empty string")
        if not isinstance(kid, str) or not kid:
            raise ValueError("kid must be a non-empty string")
        pub = _clean_pub(pubkey, "card_identities[%r][%r].pubkey"
                         % (identity, kid))
        rec = self.card_identities.setdefault(identity, {"kids": {}})
        rec["kids"][kid] = {"pubkey": pub, "alg": alg}

    def card_identity_for_kid(self, kid):
        """Reverse lookup: the verified identity bound to ``kid``, or
        None. Used by the chain verifier's card_kid binding check."""
        for identity, rec in self.card_identities.items():
            if kid in rec["kids"]:
                return identity
        return None

    def describe(self):
        """Safe public description — key ids only, never key material."""
        return {
            "human_keys": sorted(self.human_keys),
            "authority_keys": sorted(self.authority_keys),
            "user_issuer_keys": sorted(self.user_issuer_keys),
            "agent_keys": sorted(self.agent_keys),
            "card_identities": {
                identity: sorted(rec["kids"])
                for identity, rec in self.card_identities.items()
            },
            "audience": self.audience,
        }


# Wave-86 (F132): one-time loud disclosure that no audience is
# configured — same pattern as warn_self_asserted_identity_once in
# gov/identity.py. Per-process, resettable by tests (poke the module
# attribute).
_audience_unset_warned = False


def warn_audience_unset_once():
    """Print the audience-unset warning to stderr, once per process.

    Called by :func:`verify_delegation_chain` when the effective
    expected audience is None: cross-deployment confused-deputy replay
    is not prevented in this configuration.
    """
    global _audience_unset_warned
    if _audience_unset_warned:
        return
    _audience_unset_warned = True
    print(
        "GOVERNANCE WARNING: this DelegationTrust has no audience "
        "(deployment id) configured — delegation tokens carry no "
        "enforceable audience claim and cross-deployment confused-"
        "deputy replay is NOT prevented: a token issued for another "
        "deployment that shares these operator keys will verify here. "
        "Set DelegationTrust(audience=<deployment id>) and issue "
        "tokens with audience=<deployment id> for real deployments.",
        file=sys.stderr)


def _clean_pub(pub, what):
    if isinstance(pub, str):
        try:
            pub = bytes.fromhex(pub)
        except ValueError:
            raise ValueError("%s: not hex" % what)
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        raise ValueError("%s: must be a 32-byte Ed25519 public key" % what)
    return bytes(pub)


def _clean_keymap(mapping, what):
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("%s must be a non-empty {key_id: pubkey} mapping"
                         % what)
    out = {}
    for key_id, pub in mapping.items():
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("%s: key ids must be non-empty strings"
                             % what)
        out[key_id] = _clean_pub(pub, "%s[%r]" % (what, key_id))
    return out


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_token(token, trusted_keys, *, now=None, expected_kind=None,
                 expected_session=None, expected_audience=None,
                 expected_resource=None):
    """Verify one token against ``trusted_keys`` ({key_id: pub}).

    Checks: well-formed envelope, ``token_kind``, issuer in the roster,
    Ed25519 signature, the ``[not_before - skew, expires_at + skew]``
    window, session binding, and — when ``expected_audience`` is set —
    the signed ``aud`` claim (wave-86, F132): a token with a missing or
    mismatched audience is refused as :class:`DelegationBindingError`
    (cross-deployment replay). Returns the token's ``claims`` dict.
    Raises a :class:`DelegationError` subclass fail-closed.

    ``expected_resource`` (wave-278, RFC 8707): the canonical URI of the
    protected resource this verification is for. When set, the token's
    signed ``resource`` claim must equal it byte-for-byte — a missing
    or mismatched claim is refused as :class:`DelegationBindingError`
    (token passthrough: the token was not issued for this server).
    When None (default), no resource check runs — the aud precedent:
    binding is verifier-declared, and undeclared verifiers keep
    byte-identical behavior.
    """
    ref = _now_dt(now)
    if not isinstance(token, dict):
        raise DelegationSignatureError("token is not an object")
    if token.get("token_version") != TOKEN_VERSION:
        raise DelegationSignatureError(
            "unsupported token_version %r" % (token.get("token_version"),))
    kind = token.get("token_kind")
    if kind not in TOKEN_KINDS:
        raise DelegationSignatureError("unknown token_kind %r" % (kind,))
    if expected_kind is not None and kind != expected_kind:
        raise DelegationSignatureError(
            "expected a %r token, got %r" % (expected_kind, kind))
    issuer = token.get("issuer")
    pub = trusted_keys.get(issuer) if isinstance(trusted_keys, dict) \
        else None
    if pub is None:
        raise DelegationSignatureError(
            "issuer %r not in the trust roster" % (issuer,))
    body = {k: v for k, v in token.items() if k != "sig"}
    if not isinstance(token.get("sig"), str) or not _verify_sig(
            pub, body, token["sig"]):
        raise DelegationSignatureError(
            "token signature invalid (forgery, wrong key, or tampered "
            "claims)")
    if expected_audience is not None:
        aud = token.get("aud")
        if aud != expected_audience:
            raise DelegationBindingError(
                "token audience %r does not match this deployment %r "
                "(cross-deployment replay refused: the token was issued "
                "for a different deployment)" % (aud,
                                                 expected_audience))
    if expected_resource is not None:
        res = token.get("resource")
        if res != expected_resource:
            raise DelegationBindingError(
                "token resource %r does not match the declared resource "
                "%r (token passthrough refused: the token was not issued "
                "for this server)" % (res, expected_resource))
    nbf = _parse_time(token.get("not_before"), "not_before")
    exp = _parse_time(token.get("expires_at"), "expires_at")
    skew = timedelta(seconds=CLOCK_SKEW_S)
    if not (nbf - skew <= ref <= exp + skew):
        raise DelegationExpiredError(
            "token outside its validity window "
            "(skew ±%ds; use short TTLs, not long windows)" % CLOCK_SKEW_S)
    if expected_session is not None and \
            token.get("session_id") != expected_session:
        raise DelegationBindingError(
            "token bound to session %r, presented in %r (replay refused)"
            % (token.get("session_id"), expected_session))
    claims = token.get("claims")
    if not isinstance(claims, dict):
        raise DelegationSignatureError("token claims missing")
    return claims


def verify_delegation_chain(delegation_token, parent_chain, trust,
                            user_token, agent_token, *, now=None,
                            expected_session=None, expected_audience=None,
                            expected_resource=None):
    """Verify a full delegation chain, root (human) to leaf.

    ``parent_chain``: ancestor delegation tokens, root-first (may be
    empty for a depth-0 token). Every hop is signature-verified against
    the RIGHT roster (human keys at depth 0, the parent's
    session-registered key at depth ≥ 1); every hop's
    ``parent_token_hash`` must equal the actual parent's ref; scope must
    be monotonic non-increasing hop-to-hop; the leaf's
    ``user_token_hash``/``agent_token_hash`` must match the presented
    user/agent tokens (South et al.'s binding); every token is
    session-bound and in-window.

    Audience (wave-86, F132): ``expected_audience`` defaults to
    ``trust.audience`` (the verifier's deployment id). When set, every
    token in the chain — delegation hops AND the bound user/agent
    tokens — must carry the matching signed ``aud`` claim, else
    :class:`DelegationBindingError`. When unset, a loud one-time
    stderr disclosure states that cross-deployment confused-deputy
    replay is not prevented.

    Resource (wave-278, RFC 8707): ``expected_resource`` is the
    canonical URI of the protected resource this chain is presented
    for. When set, every delegation hop's signed ``resource`` claim
    must equal it — a hop minted for another server (or with no
    resource claim at all) fails the chain closed here, at
    verification. Spawn inherits the parent's resource (never a
    parameter), so a well-formed chain is resource-uniform; a
    hand-crafted mixed-resource chain is refused hop-by-hop. When
    unset, no resource check runs (verifier-declared, like audience).

    Depth (wave-86 defense-in-depth): the hop depth is re-checked
    against :data:`MAX_DELEGATION_DEPTH` at verification, not just at
    issuance — a smuggled deep token (valid signatures, depth past the
    cap) fails here too.

    A recipient VERIFIES the chain, never trusts its claims. Returns
    the leaf's claims. Raises fail-closed.
    """
    ref = _now_dt(now)
    if expected_audience is None:
        expected_audience = trust.audience
    if expected_audience is None:
        warn_audience_unset_once()
    session = expected_session or delegation_token.get("session_id")
    chain = list(parent_chain or []) + [delegation_token]
    prev = None
    for i, tok in enumerate(chain):
        claims = verify_token(
            tok, _roster_for_depth(trust, i, tok), now=ref,
            expected_kind="delegation", expected_session=session,
            expected_audience=expected_audience,
            expected_resource=expected_resource)
        depth = claims.get("delegation_depth")
        if depth != i:
            raise DelegationSignatureError(
                "hop %d claims delegation_depth %r (chain position "
                "mismatch — reordered or forged depth)" % (i, depth))
        if depth > MAX_DELEGATION_DEPTH:
            # Defense-in-depth (wave-86): issuance caps depth, but a
            # verifier must not trust the issuer to have enforced it —
            # a smuggled deep token with otherwise-valid signatures
            # fails closed HERE, at verification.
            raise DelegationAttenuationError(
                "hop %d claims delegation_depth %d exceeding the cap %d "
                "(swarm control enforced at verification, not just "
                "issuance)" % (i, depth, MAX_DELEGATION_DEPTH))
        # A2A card-identity binding: a hop carrying card_kid must name
        # the card-verified identity as its subject. The kid must
        # resolve in the deployment's card-identity registry (populated
        # ONLY by gov.agent_cards.register_agent_card after full card
        # verification) and the registered identity must equal this
        # hop's subject. A swapped kid (another identity's key) or a
        # subject that is not the verified identity fails closed here.
        # Hand-crafted pre-card tokens simply lack the claim (.get →
        # None) and are unaffected.
        card_kid = claims.get("card_kid")
        if card_kid is not None:
            card_identity = trust.card_identity_for_kid(card_kid)
            if card_identity is None:
                raise DelegationBindingError(
                    "hop %d carries card_kid %r which is not in the "
                    "card-identity registry (unverified card identity "
                    "refused)" % (i, card_kid))
            if card_identity != tok.get("subject"):
                raise DelegationBindingError(
                    "hop %d card_kid %r binds verified identity %r but "
                    "the token subject is %r (identity swap refused)"
                    % (i, card_kid, card_identity, tok.get("subject")))
        if i == 0:
            if claims.get("parent_token_hash") is not None:
                raise DelegationSignatureError(
                    "depth-0 token must not carry a parent_token_hash")
        else:
            expect_parent = token_ref(prev)
            if claims.get("parent_token_hash") != expect_parent:
                raise DelegationSignatureError(
                    "hop %d parent_token_hash does not match the "
                    "presented parent (truncated or spliced chain)"
                    % i)
            parent_scope = prev["claims"]["scope"]
            if not _scope_covers(parent_scope, claims.get("scope") or []):
                raise DelegationAttenuationError(
                    "hop %d scope exceeds its parent's (attenuation is "
                    "monotonic-decreasing)" % i)
        prev = tok
    leaf_claims = chain[-1]["claims"]
    # South et al.'s binding: the leaf commits to the other two tokens.
    if leaf_claims.get("user_token_hash") != token_ref(user_token):
        raise DelegationSignatureError(
            "delegation token's user_token_hash does not match the "
            "presented user token")
    if leaf_claims.get("agent_token_hash") != token_ref(agent_token):
        raise DelegationSignatureError(
            "delegation token's agent_token_hash does not match the "
            "presented agent token")
    # The user/agent tokens themselves verify (kinds, roster, window,
    # session, audience) — the delegation is only as good as what it
    # binds.
    verify_token(user_token, trust.user_issuer_keys, now=ref,
                 expected_kind="user", expected_session=session,
                 expected_audience=expected_audience)
    verify_token(agent_token, trust.authority_keys, now=ref,
                 expected_kind="agent", expected_session=session,
                 expected_audience=expected_audience)
    return leaf_claims


def _roster_for_depth(trust, depth, tok):
    """The right roster for a chain hop: human keys at depth 0, the
    parent agent's session-registered key below."""
    if depth == 0:
        return trust.human_keys
    claims = tok.get("claims") if isinstance(tok, dict) else None
    parent_id = (claims or {}).get("delegator")
    pub = trust.agent_keys.get(parent_id)
    if pub is None:
        raise DelegationSignatureError(
            "parent agent %r has no registered key in the session roster"
            % (parent_id,))
    issuer = tok.get("issuer")
    if _signing.ed25519_key_id(pub) != issuer:
        raise DelegationSignatureError(
            "hop issuer %r does not match the session roster key for "
            "parent %r (parent-signature swap refused)" % (issuer,
                                                           parent_id))
    return {issuer: pub}


# ---------------------------------------------------------------------------
# The session's delegation context + the intersection gate
# ---------------------------------------------------------------------------

class DelegationContext:
    """A session's three-token identity, verified at bind time.

    ``parent_chain``: ancestor delegation tokens, root-first (empty for
    the human-delegated root agent). :meth:`bind` verifies the whole
    chain (signatures, links, attenuation, bindings, windows) and the
    user/agent tokens — an UNBOUND context cannot authorize (fail
    closed). :meth:`authorize` enforces the permission intersection for
    one action.
    """

    def __init__(self, *, user_token, agent_token, delegation_token,
                 parent_chain, trust, session_id):
        self.user_token = user_token
        self.agent_token = agent_token
        self.delegation_token = delegation_token
        self.parent_chain = list(parent_chain or [])
        if not isinstance(trust, DelegationTrust):
            raise TypeError("trust must be a DelegationTrust")
        self.trust = trust
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id must be a non-empty string")
        self.session_id = session_id
        self._bound = False
        self._leaf_claims = None

    def bind(self, now=None, *, expected_resource=None):
        """Verify everything. Returns self. Raises fail-closed.

        ``expected_resource`` (wave-278, RFC 8707): the canonical URI
        of the protected resource this context is bound for. When set,
        every delegation hop's signed ``resource`` claim must match —
        a chain minted for another server (or with no resource claim)
        refuses to bind. When None (default), no resource check runs.
        """
        if self.delegation_token is None:
            # The agent-without-delegation case, caught HERE (not as a
            # confusing signature error deeper in): fail closed by
            # construction, with the error type the executor gate
            # documents.
            raise DelegationRequiredError(
                "agent presented no delegation token: an agent without "
                "delegation cannot act (fail closed by construction, not "
                "by policy text)")
        self._leaf_claims = verify_delegation_chain(
            self.delegation_token, self.parent_chain, self.trust,
            self.user_token, self.agent_token, now=now,
            expected_session=self.session_id,
            expected_audience=self.trust.audience,
            expected_resource=expected_resource)
        self._bound = True
        return self

    @property
    def bound(self):
        return self._bound

    def delegation_scope(self):
        if not self._bound:
            raise DelegationRequiredError(
                "unbound DelegationContext cannot authorize (bind first)")
        return list(self._leaf_claims["scope"])

    def receipt(self):
        """Mint this bound context's cross-app delegation receipt.

        See :func:`delegation_receipt`. Fail-closed on unbound
        contexts — an unverified chain mints no attribution.
        """
        return delegation_receipt(self)

    def authorize(self, action, resource=None, *, now=None,
                  revocation_checker=None, contextual_tuples=None,
                  check_conditions=None, spent_ledger=None,
                  consequential=False, decision_writer=None):
        """The permission intersection, enforced.

        Effective permission = user permissions ∩ agent capabilities ∩
        delegation scope, evaluated as a conjunction per action (intensional
        — wildcards make the set unlistable, so the gate is a predicate,
        not a list). ``action`` is ``"tool:<name>"``. ``resource`` is the
        RFC 8707 resource indicator (wave-278): when declared, the token
        chain's signed resource claim must match it (see
        :func:`authorize_action`).

        Raises :class:`DelegationRequiredError` (no/unbound context),
        :class:`DelegationExpiredError`,
        :class:`DelegationBindingError` (session/audience/resource
        mismatch — token passthrough refused), :class:`DelegationRevokedError`,
        or :class:`DelegationScopeError` — all fail-closed. Returns an
        audit dict on success.
        """
        return authorize_action(self, action, resource, now=now,
                                revocation_checker=revocation_checker,
                                contextual_tuples=contextual_tuples,
                                check_conditions=check_conditions,
                                spent_ledger=spent_ledger,
                                consequential=consequential,
                                decision_writer=decision_writer)

    def spawn(self, sub_agent_id, sub_scope, parent_signer, *,
              ttl_s=None, now=None):
        """Spawn a sub-agent: issue its parent-signed, attenuated
        delegation token and return its BOUND child context.

        ``parent_signer`` is THIS agent's private signing key (the
        parent's workload key, provisioned at the parent's spawn — never
        agent-reachable as data by anyone else). The child scope must be
        covered by this context's scope (monotonic-decreasing); the
        child is signed by the parent, chained by parent hash, depth+1.
        """
        child_token = spawn_sub_agent(self, sub_agent_id, sub_scope,
                                      parent_signer, ttl_s=ttl_s, now=now)
        child = DelegationContext(
            user_token=self.user_token,
            agent_token=self.agent_token,
            delegation_token=child_token,
            parent_chain=self.parent_chain + [self.delegation_token],
            trust=self.trust,
            session_id=self.session_id)
        return child.bind(now=now)


def authorize_action(ctx, action, resource=None, *, now=None,
                     revocation_checker=None, contextual_tuples=None,
                     check_conditions=None, spent_ledger=None,
                     consequential=False, decision_writer=None):
    """Enforce the permission intersection for one action.

    ``ctx``: a BOUND :class:`DelegationContext`. ``action``:
    ``"tool:<name>"``. ``resource`` (wave-278, RFC 8707): the canonical
    https URI of the protected resource (MCP server / tool endpoint)
    this action is presented to. When set, every delegation hop's
    signed ``resource`` claim must equal it — a token minted for
    another server (or with no resource claim) is refused as
    :class:`DelegationBindingError` (token passthrough refused
    fail-closed). When None (default), no resource check runs: binding
    is verifier-declared, and undeclared uses keep byte-identical
    behavior (the wave-86 audience precedent). The gate:

    1. context present, bound, and carrying a delegation token —
       otherwise :class:`DelegationRequiredError` (THE fail-closed-by-
       construction case: this function is called in code before policy
       evaluation, so policy text cannot waive it);
    2. the delegation token (and ancestors) still in-window and
       session-bound — and, when ``resource`` is declared,
       resource-bound to the declared resource;
    3. revocation seam: any revoked token in the chain (leaf or
       ancestor) → :class:`DelegationRevokedError`;
    4. the conjunction: user permissions AND agent capabilities AND
       delegation scope must each allow the action — otherwise
       :class:`DelegationScopeError`.
    5. (wave-280, ephemeral grants): the per-invocation contextual-tuple
       check. A single-use lease (``claims["lease"] == "single-use"``)
       REQUIRES ``contextual_tuples`` — without them the request is
       refused as :class:`EphemeralGrantError` (coded
       ``delegation-ephemeral-grant-refused``); the tuples must name the
       lease and satisfy their conditions, and the lease ref is spent
       through ``spent_ledger`` (replay refuses coded). A single-use
       lease with NO registry is refused too (fail closed: without a
       registry the single-use guarantee cannot be enforced, so the
       lease would silently degrade to multi-use). Callers may also
       pass tuples for multi-use tokens: they are an additional
       enforcement input, evaluated the same way. ``consequential``
       marks write-shaped actions so ``can_invoke_readonly`` tuples
       cannot authorize them. ``decision_writer`` (a
       ``ephemeral_grants.GrantDecisionWriter``) records the decision
       dict into the chained audit log AT DECISION TIME — allowed and
       coded-refused alike — before the verdict leaves this seam.

    Returns ``{"action", "allowed_by", "delegation_token_ref",
    "session_id", "receipt"}`` for the audit record — ``receipt`` is the
    cross-app delegation receipt (Row 18: distinct ``sub``/``act``
    attribution), minted from the bound context at authorization time.
    """
    ref = _now_dt(now)
    if ctx is None or not isinstance(ctx, DelegationContext):
        raise DelegationRequiredError(
            "no delegation context: agent actions require a bound "
            "three-token delegation (fail closed by construction)")
    if not ctx.bound:
        raise DelegationRequiredError(
            "unbound delegation context: bind (verify) before authorizing")
    if ctx.delegation_token is None:
        raise DelegationRequiredError(
            "agent presented no delegation token: an agent without "
            "delegation cannot act (fail closed by construction, not by "
            "policy text)")
    # Re-check window + binding at use time (bind() verified signatures;
    # time passes — expiry is checked per action). When the caller
    # declares the resource, every hop's signed resource claim must
    # match it: a delegation minted for another server presented here
    # is the confused-deputy shape, refused fail-closed.
    chain = ctx.parent_chain + [ctx.delegation_token]
    for tok in chain:
        verify_token(tok, _roster_for_depth(
            ctx.trust, tok["claims"]["delegation_depth"], tok),
            now=ref, expected_kind="delegation",
            expected_session=ctx.session_id,
            expected_resource=resource)
    # Revocation seam: leaf AND ancestors (a revoked parent invalidates
    # the chain — that is the point of propagation). A checker that
    # ERRORS fails closed as a revocation-system failure: without a
    # trustworthy non-revoked answer there is no authorization, and the
    # failure must be loud and catchable as a DelegationError (so the
    # executor gate audits it instead of crashing on a raw IOError).
    if revocation_checker is not None:
        for tok in chain:
            try:
                revoked = revocation_checker(token_ref(tok))
            except DelegationError:
                raise
            except Exception as e:
                raise DelegationRevokedError(
                    "revocation check failed (%s: %s): cannot prove "
                    "non-revocation — failing closed"
                    % (type(e).__name__, e))
            if revoked:
                raise DelegationRevokedError(
                    "token %s revoked (revocation seam)" % token_ref(tok))
    if not isinstance(action, str) or not action.startswith("tool:"):
        raise DelegationScopeError(
            "action %r malformed: v1 actions are 'tool:<name>'" % (action,))
    user_perms = ctx.user_token["claims"]["permissions"]
    agent_caps = ctx.agent_token["claims"]["capabilities"]
    scope = ctx._leaf_claims["scope"]
    allowed_by = {
        "user": _scope_allows(user_perms, action),
        "agent": _scope_allows(agent_caps, action),
        "delegation": _scope_allows(scope, action),
    }
    if not all(allowed_by.values()):
        denied = sorted(k for k, v in allowed_by.items() if not v)
        raise DelegationScopeError(
            "action %r denied by the permission intersection "
            "(user ∩ agent ∩ delegation scope); denied at: %s"
            % (action, ", ".join(denied)))
    # Wave-280 (ephemeral grants, OpenFGA-pattern contextual tuples):
    # per-invocation enforcement input. A single-use lease REQUIRES
    # tuples; multi-use callers may pass them as an additional input.
    lease = ctx._leaf_claims.get("lease")
    if lease == "single-use" or contextual_tuples is not None:
        if lease == "single-use" and not contextual_tuples:
            raise EphemeralGrantError(
                "single-use lease requires contextual_tuples on the "
                "check request (the tuple is the per-invocation grant)")
        if lease == "single-use" and spent_ledger is None:
            # Fail closed (the revocation seam applies the same rule:
            # without a trustworthy non-revoked answer there is no
            # authorization): without a registry the single-use
            # guarantee cannot be enforced, so a bare single-use lease
            # would silently degrade to multi-use (unlimited replays).
            raise EphemeralGrantError(
                "single-use lease requires a spent-lease registry "
                "(spent_ledger=...): without one, replay cannot be "
                "refused")
        principal = "agent:" + str(ctx.delegation_token.get("subject"))
        lease_ref = token_ref(ctx.delegation_token) \
            if lease == "single-use" else None
        decision = _eg.check_grant(
            principal, action, contextual_tuples or [],
            check_conditions,
            consequential=consequential,
            lease_ref=lease_ref,
            spent_ledger=spent_ledger)
        if decision_writer is not None:
            # Recorded AT DECISION TIME (never batched later): both
            # allowed and coded-refused decisions land in the chained
            # audit log before the verdict leaves this seam.
            decision_writer.record(decision, principal)
        if not decision["allowed"]:
            raise EphemeralGrantError(
                decision.get("code_detail") or "ephemeral grant refused")
    return {
        "action": action,
        "allowed_by": allowed_by,
        "delegation_token_ref": token_ref(ctx.delegation_token),
        "session_id": ctx.session_id,
        # Row 18 (borrowed-credential log-attribution gap): every
        # authorization verdict now carries the cross-app delegation
        # receipt — distinct sub (on whose behalf) / act (who acts) —
        # minted from the bound context. Additive key; consumers that
        # read specific fields are unaffected.
        "receipt": delegation_receipt(ctx),
    }


def enforce_tool_call(ctx, identity, tool, *, now=None,
                       revocation_checker=None, resource=None,
                       contextual_tuples=None, check_conditions=None,
                       spent_ledger=None, consequential=False,
                       decision_writer=None):
    """Executor-facing gate: one tool call through the identity layer.

    ``identity``: the ``AgentIdentity`` the executor is acting as (its
    run must match the context's session — cross-run token use is
    replay and is refused). ``resource`` (wave-278, RFC 8707): the
    canonical https URI of the protected resource (MCP server / tool
    endpoint) the call targets. When declared, the delegation chain's
    signed resource claim must match it — token passthrough refused
    fail-closed. When None (default), no resource check runs (the
    executor's tool seam is tool-name based and carries no server URI
    today; binding is verifier-declared). Raises
    :class:`DelegationError` fail-closed; returns the audit dict on
    success.
    """
    agent_id = getattr(identity, "agent_id", None)
    run_id = getattr(identity, "run_id", None)
    if ctx is not None and ctx.session_id != run_id:
        raise DelegationBindingError(
            "delegation context bound to session %r, executor run is %r "
            "(cross-run token use refused)" % (ctx.session_id, run_id))
    if ctx is not None and ctx.delegation_token is not None:
        # The leaf delegation names the agent it was issued to. The
        # ACTING identity must be that agent: a delegation issued to
        # agent-A cannot authorize agent-B's tool call, even in the
        # same run. Without this, any agent could borrow any sibling's
        # context.
        leaf_subject = ctx.delegation_token.get("subject")
        if leaf_subject != agent_id:
            raise DelegationBindingError(
                "acting identity %r does not match the delegation's "
                "subject %r (delegation issued to a different agent)"
                % (agent_id, leaf_subject))
    verdict = authorize_action(ctx, "tool:" + str(tool), resource,
                               now=now,
                               revocation_checker=revocation_checker,
                               contextual_tuples=contextual_tuples,
                               check_conditions=check_conditions,
                               spent_ledger=spent_ledger,
                               consequential=consequential,
                               decision_writer=decision_writer)
    verdict["agent_id"] = agent_id
    return verdict


# ---------------------------------------------------------------------------
# Spawn lineage
# ---------------------------------------------------------------------------

def spawn_sub_agent(parent_ctx, sub_agent_id, sub_scope, parent_signer,
                    *, ttl_s=None, now=None, lease=None):
    """Issue a sub-agent's delegation token (the spawn-lineage primitive).

    Signed by the PARENT agent's key; carries a SUBSET of the parent's
    scope (attenuation is monotonic-decreasing — widening is refused at
    issuance AND at chain verification); chained to the parent's token
    by ``parent_token_hash``; ``delegation_depth`` = parent + 1 (cap
    :data:`MAX_DELEGATION_DEPTH`, the swarm control).

    ``lease`` (wave-280): explicit override for the single-use flag.
    When None (default), the parent's lease flag is INHERITED — never a
    widening: a single-use delegation's child is single-use too (the
    wave-86 audience / wave-278 resource inheritance precedent).

    The user/agent token hashes are INHERITED from the parent — the
    chain records the full path back to the originating user (MongoDB
    Pattern 4). The audience (``aud``) is likewise INHERITED from the
    parent's token — it is deliberately NOT a parameter, so a spawn
    can never move a delegation across deployments (aud-swapping at
    spawn is impossible by construction). Returns the child delegation
    token (unsigned-context); :meth:`DelegationContext.spawn` wraps it
    in a bound child context.
    """
    if parent_ctx is None or not isinstance(parent_ctx, DelegationContext) \
            or not parent_ctx.bound:
        raise DelegationRequiredError(
            "spawn requires a BOUND parent DelegationContext")
    if not isinstance(sub_agent_id, str) or not sub_agent_id:
        raise ValueError("sub_agent_id must be a non-empty string")
    sub_scope = _check_scope_list(sub_scope, "sub_scope")
    parent_claims = parent_ctx._leaf_claims
    parent_scope = parent_claims["scope"]
    if not _scope_covers(parent_scope, sub_scope):
        raise DelegationAttenuationError(
            "sub-agent scope %r exceeds parent scope %r: attenuation is "
            "monotonic-decreasing (a hop that does not narrow scope "
            "re-broadens authority)" % (sub_scope, parent_scope))
    depth = parent_claims["delegation_depth"] + 1
    if depth > MAX_DELEGATION_DEPTH:
        raise DelegationAttenuationError(
            "delegation depth %d exceeds the cap %d (swarm control: "
            "re-delegate from the human instead)" % (depth,
                                                     MAX_DELEGATION_DEPTH))
    claims = {
        "delegator": parent_ctx.agent_token["claims"]["agent_id"],
        "user_token_hash": parent_claims["user_token_hash"],
        "agent_token_hash": parent_claims["agent_token_hash"],
        "scope": sub_scope,
        "revocation_endpoint":
            parent_claims["revocation_endpoint"],
        "audit_urls": list(parent_claims["audit_urls"]),
        "delegation_depth": depth,
        "parent_token_hash": token_ref(parent_ctx.delegation_token),
        # Strict card-identity semantics: the card_kid binding lives
        # ONLY on the token whose subject IS the card-verified identity
        # (the depth-0 delegation issued to the foreign agent). A spawn
        # is a different subject, so it never inherits the binding —
        # the parent hop's claims still carry it for lineage auditors.
        "card_kid": None,
    }
    # Wave-86 (F132): the audience is inherited from the parent's
    # token — never a parameter. A spawn that could set aud would let a
    # compromised parent re-target its delegation at another
    # deployment; inheritance makes that shape unrepresentable.
    parent_aud = parent_ctx.delegation_token.get("aud")
    # Wave-278 (RFC 8707): the resource indicator is likewise inherited
    # from the parent's token — never a parameter. A sub-agent cannot
    # re-target its delegation at another server; the spawn chain stays
    # resource-uniform by construction.
    parent_resource = parent_ctx.delegation_token.get("resource")
    # Wave-280: the single-use lease flag is inherited unless explicitly
    # overridden — a spawn can never widen a single-use lease into a
    # multi-use one.
    child_lease = parent_claims.get("lease") if lease is None else lease
    if child_lease not in (None, "single-use"):
        raise ValueError("lease must be None or 'single-use', got %r"
                         % (child_lease,))
    if child_lease is not None:
        # Signed-claims material: added BEFORE _base_token signs, so the
        # flag is covered by the parent's signature like aud/resource.
        claims["lease"] = child_lease
    return _base_token("delegation", parent_signer, sub_agent_id,
                       parent_ctx.session_id, claims, ttl_s, now,
                       audience=parent_aud, resource=parent_resource)


# ---------------------------------------------------------------------------
# Revocation seam (reference implementation; TTL-only is the default)
# ---------------------------------------------------------------------------

class RevocationLedger:
    """Reference revocation source (test-grade).

    Holds a set of revoked token refs; ``is_revoked(ref)`` is the
    ``revocation_checker`` seam that :func:`authorize_action` accepts.
    Revocation is idempotent; unknown refs revoke silently (no-op).
    Already-chained records are append-only history and are never
    rewritten — revocation fails FUTURE authorizations loud (the
    ConsumerRegistry wave-67 pattern). True propagation to already-
    issued offline verifiers is a STATED BOUNDARY (design §4).
    """

    def __init__(self):
        self._revoked = set()

    def revoke(self, token_or_ref):
        ref = token_or_ref if isinstance(token_or_ref, str) \
            else token_ref(token_or_ref)
        if not isinstance(ref, str) or not ref:
            raise TypeError("revoke() requires a token or ref string")
        self._revoked.add(ref)

    def is_revoked(self, ref):
        return ref in self._revoked

    def __call__(self, ref):
        # Usable directly as the revocation_checker seam.
        return self.is_revoked(ref)


# ---------------------------------------------------------------------------
# Provenance v2 slot fill (§7 contract)
# ---------------------------------------------------------------------------

def hop_token_refs(user_token, agent_token, delegation_token):
    """The v2 prov-hop ``tokens`` slot for one delegation hop.

    Refs only — SHA-256 hexes, never secrets, in the agent-reachable
    log. ``delegation_token_ref`` is the token authorizing THIS hop
    (the sub-agent's own token on sub-agent hops); user/agent refs are
    inherited from the session root.
    """
    for tok, kind in ((user_token, "user"), (agent_token, "agent"),
                      (delegation_token, "delegation")):
        if not isinstance(tok, dict) or tok.get("token_kind") != kind:
            raise ValueError("hop_token_refs: expected a %r token" % kind)
    return {
        "tokens_schema": TOKENS_SCHEMA,
        "user_token_ref": token_ref(user_token),
        "agent_token_ref": token_ref(agent_token),
        "delegation_token_ref": token_ref(delegation_token),
    }


def generate_test_keypair():
    """Test/dev keypair stand-in (``(signer, pub)``).

    The human delegator's key in the local model is provisioned by the
    deployment; tests use this explicitly-labeled stand-in — never
    presented as a production key.
    """
    seed = secrets.token_bytes(32)
    signer = _signing.Ed25519Signer(seed)
    return signer, _ed.publickey(seed)


# ---------------------------------------------------------------------------
# Cross-app delegation receipts (Row 18 residual: borrowed-credential
# log-attribution gap)
#
# The three-token stack authenticates (F132/F133/F135) but the
# authorization verdict carried only token REFS — an auditor could not
# read "agent X acted on behalf of user Y" without resolving hashes,
# and nothing could refuse a FORGED attribution claim. This is the
# Okta Cross-App-Access protocol shape (the two-hop ID-JAG exchange
# with an ``act`` claim naming the agent separately from the human):
# protocol IDEA only — no copied code, no encumbrance, no new crypto.
#
# The receipt is a DERIVED view, not a fourth token: it is minted from
# a BOUND context (everything already signature-verified at bind) and
# verified by re-derivation — :func:`verify_delegation_receipt`
# re-binds the presented tokens and re-mints, comparing canonical
# forms. Any tampering (swapped sub, widened scope, dropped/reordered
# hops, foreign session) fails closed. No new signatures: the tokens'
# Ed25519 signatures are the trust root; the receipt adds zero key
# material and embeds no token bodies or signatures (refs + ids only),
# so it is safe to stamp onto audit events.
# ---------------------------------------------------------------------------

RECEIPT_VERSION = 1
RECEIPT_SCHEMA = "delegation-receipt/v1"


def _receipt_hops(ctx):
    """Per-hop attribution for a bound context's chain, root-first.

    Each hop names its delegator (the HUMAN at depth 0, the parent
    agent below), its subject (who the hop authorizes), its scope, and
    its token ref — the full intending lineage an auditor needs.
    """
    hops = []
    chain = list(ctx.parent_chain) + [ctx.delegation_token]
    for tok in chain:
        claims = tok["claims"]
        hops.append({
            "depth": claims["delegation_depth"],
            "delegator": claims["delegator"],
            "subject": tok["subject"],
            "scope": list(claims["scope"]),
            "token_ref": token_ref(tok),
            "issued_at": tok["issued_at"],
        })
    return hops


def delegation_receipt(ctx):
    """Mint the cross-app delegation receipt for a BOUND context.

    Returns a plain dict (JSON-serializable):

    * ``sub`` — the user principal ON WHOSE BEHALF the action runs
      (the verified user token's ``user_id``; stable across spawns —
      a sub-agent still acts for the originating human).
    * ``act`` — the ACTING agent (the leaf delegation's subject).
    * ``delegator_chain`` — per-hop ``{depth, delegator, subject,
      scope, token_ref, issued_at}``, root-first.
    * ``scope`` — the leaf's effective delegation scope.
    * ``session_id``, ``audience`` (when the deployment binds one),
      and the three token refs (hashes only — no bodies, no
      signatures, no key material).
    * ``card_kid`` — the A2A Agent Card key id this receipt's ``act``
      was identity-proven under (None for local, non-card issuers).
      Additive key; the chain verifier enforces that a non-None kid
      resolves to the card identity equal to ``act``.

    Fail-closed: ``None``/non-context, unbound context, or a context
    with no delegation token raises :class:`DelegationRequiredError`;
    a verified-but-malformed user principal raises
    :class:`DelegationSignatureError`. An unverified chain mints no
    attribution, ever.
    """
    if ctx is None or not isinstance(ctx, DelegationContext):
        raise DelegationRequiredError(
            "no delegation context: a receipt requires a bound "
            "three-token delegation (fail closed by construction)")
    if not ctx.bound:
        raise DelegationRequiredError(
            "unbound DelegationContext cannot mint a receipt "
            "(bind (verify) first)")
    if ctx.delegation_token is None:
        raise DelegationRequiredError(
            "agent presented no delegation token: no receipt without "
            "delegation")
    user_claims = ctx.user_token.get("claims") \
        if isinstance(ctx.user_token, dict) else None
    sub = (user_claims or {}).get("user_id")
    if not isinstance(sub, str) or not sub:
        # Unreachable after a successful bind() (the user token is
        # verified there), but a receipt must never mint attribution
        # from a malformed principal — fail closed, not silent.
        raise DelegationSignatureError(
            "verified user token carries no user_id: cannot attribute "
            "a receipt without a principal")
    leaf = ctx.delegation_token
    act = leaf.get("subject")
    if not isinstance(act, str) or not act:
        raise DelegationSignatureError(
            "leaf delegation token carries no subject: cannot attribute "
            "a receipt without an acting agent")
    return {
        "receipt_version": RECEIPT_VERSION,
        "receipt_schema": RECEIPT_SCHEMA,
        "sub": sub,
        "act": act,
        "delegator_chain": _receipt_hops(ctx),
        "scope": list(ctx._leaf_claims["scope"]),
        "session_id": ctx.session_id,
        "audience": leaf.get("aud"),
        "card_kid": ctx._leaf_claims.get("card_kid"),
        "user_token_ref": token_ref(ctx.user_token),
        "agent_token_ref": token_ref(ctx.agent_token),
        "delegation_token_ref": token_ref(leaf),
    }


def verify_delegation_receipt(receipt, *, user_token, agent_token,
                              delegation_token, parent_chain, trust,
                              session_id, now=None):
    """Verify a delegation receipt by re-derivation.

    Binds a fresh :class:`DelegationContext` from the presented tokens
    — the FULL chain verification (signatures against the right
    roster per hop, parent-hash links, monotonic attenuation,
    South-et-al. token bindings, windows, session binding, audience)
    — mints the canonical receipt, and compares canonical forms.

    Forgery shapes refused: swapped ``sub`` (borrowed-credential
    attribution lie), swapped ``act``, widened ``scope``, dropped or
    reordered ``delegator_chain`` hops, foreign ``session_id``, wrong
    trust roster, expired/revoked chain. Returns the verified receipt
    dict (the re-derived canonical form). Raises a
    :class:`DelegationError` subclass fail-closed.

    ``receipt`` itself is never trusted: it is only the CLAIM being
    checked against the tokens. An auditor holding the three tokens
    (or their refs plus the chained log) can re-verify offline.
    """
    if not isinstance(receipt, dict):
        raise DelegationSignatureError("receipt is not an object")
    if receipt.get("receipt_version") != RECEIPT_VERSION:
        raise DelegationSignatureError(
            "unsupported receipt_version %r" % (
                receipt.get("receipt_version"),))
    if receipt.get("receipt_schema") != RECEIPT_SCHEMA:
        raise DelegationSignatureError(
            "receipt_schema mismatch: expected %r, got %r "
            "(no fourth receipt shape)" % (RECEIPT_SCHEMA,
                                           receipt.get("receipt_schema"),))
    ctx = DelegationContext(
        user_token=user_token, agent_token=agent_token,
        delegation_token=delegation_token,
        parent_chain=parent_chain, trust=trust,
        session_id=session_id).bind(now=now)
    expected = delegation_receipt(ctx)
    if _canonical(receipt) != _canonical(expected):
        raise DelegationSignatureError(
            "receipt does not match the verified delegation chain "
            "(forged or tampered attribution: sub/act/scope/chain/"
            "session/audience differs from what the tokens say)")
    return expected
