"""Inter-agent identity binding: sender identities bound to keys the
governance layer issued.

The problem (Stream 3): inter-agent messages carried the sender as a
plain string (``gov/messaging.py`` stamps it, ``gov/identity.py`` mints
in-process identities with no signing key), so nothing stopped agent B
from sending a message that claims to be from agent A, and a captured
message could be replayed with no detection at the identity layer.

What this module provides:

* ``KeyIssuanceRegistry``: the governance layer (deployment trust
  domain) mints one Ed25519 keypair per registered (principal, agent_id)
  and holds the private half. Agents never self-assert identity: they
  receive an ``AgentSigningHandle`` that can seal messages only as their
  own agent_id, and the handle exposes no seed material.
* Signed envelopes: sender identity + issued key id + nonce +
  per-sender sequence + body, with the signature covering the canonical
  encoding of ALL of them (body tampering invalidates the signature).
* ``verify_message``: the standalone verifier. Rejects unsigned
  envelopes, envelopes whose key is unknown to the registry, envelopes
  whose key is not bound to the claimed sender, bad signatures, replayed
  nonces, and stale sequences. Fail-closed: malformed input raises,
  never returns an accept; every rejection appends a chained
  ``identity_message_rejected`` audit event when a log is supplied.

INTEGRATION (for the messaging/executor owner -- Stream 1):
the messaging path calls exactly one function before delivering a
message to a recipient::

    from gov.agent_identity import verify_message, IdentityRejection

    try:
        accepted = verify_message(envelope, registry, replay_cache,
                                  log=run_log, run_id=run_id)
    except IdentityRejection:
        do_not_deliver()   # the rejection is already audit-chained

``registry`` is constructed once per deployment (or per run) in the
deployment trust domain and shared by reference; ``replay_cache`` is a
``ReplayCache`` owned by the messaging path (bounded, per-key
seen-nonce set + last sequence). This module never touches the
executor: the executor keeps minting in-process identities, and the
registry binds the agent_id strings it mints to issued keys.

HONEST RESIDUALS (never claimed away):

* The registry is itself a trust anchor: whoever can call
  ``register_agent`` can mint keys for arbitrary agent_ids ("who guards
  the minter?" is a deployment question -- registry construction and
  storage are out-of-band admin acts, same trust model as
  ``gov/identity.py``'s PrincipalRegistry).
* The replay cache is bounded: a nonce evicted by the bound could be
  replayed without tripping ``replayed_nonce``, but ``stale_sequence``
  still holds for in-order senders. Size the bound to the deployment's
  message volume.
* Private keys live in the registry process's memory (like the HMAC log
  key in ``gov/log.py``): process compromise = key compromise. The
  handle design only stops agents from *reaching* each other's keys,
  not from a compromised governance process leaking them.
* This covers the message path only. Shared-state side channels outside
  the message path (file channels, spawn lineage, tool-mediated
  channels) are an explicit boundary -- see ``gov/covert_channel.py``.

$0 spend, synthetic/local only. No credentials, no network.
"""

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import OrderedDict

from . import ed25519 as _ed
from .identity import UnregisteredPrincipalError

_DOMAIN = b"gov-agent-identity/v1\x00"
_ENVELOPE_VERSION = 1
_NONCE_BYTES = 16


class DuplicateAgentRegistrationError(Exception):
    """register_agent called twice for the same agent_id: the binding is
    one key per agent_id, and re-registration would let a second caller
    steal the identity."""


class IdentityRejection(Exception):
    """Raised by verify_message / ReplayCache on any rejection.

    ``reason`` is one of: unsigned, unknown_key, unbound_key,
    bad_signature, replayed_nonce, stale_sequence, malformed_envelope.
    Fail-closed: callers must treat this as "do not deliver".
    """

    def __init__(self, reason, detail=""):
        super().__init__("identity rejected (%s): %s" % (reason, detail))
        self.reason = reason
        self.detail = detail


def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _key_id_for_pubkey(pubkey):
    return "kid-" + hashlib.sha256(pubkey).hexdigest()[:16]


class KeyIssuanceRegistry(object):
    """Governance-layer key issuance: mints and holds per-agent Ed25519
    keys. Constructed in the deployment trust domain (operator side),
    never from agent input.

    ``principal_registry`` (optional): a ``gov/identity.py``
    ``PrincipalRegistry`` consulted at registration so key issuance
    respects the deployment's principal/role/agent_id authorizations.
    Without one, any (principal, agent_id) registers -- the same
    explicit deployment-trust residual as identity.py's dev mode.
    """

    def __init__(self, principal_registry=None):
        self._principal_registry = principal_registry
        self._keys = {}  # key_id -> {"agent_id", "principal", "seed", "pub"}

    def register_agent(self, principal, agent_id, role="agent"):
        """Mint a keypair for (principal, agent_id); returns the key_id.

        Refuses: unregistered principals (via the PrincipalRegistry),
        duplicate agent_id registration, malformed agent_id. The seed
        never leaves this object.
        """
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("agent_id must be a non-empty string")
        agent_id = agent_id.strip()
        if not isinstance(principal, str) or not principal.strip():
            raise ValueError("principal must be a non-empty string")
        if self._principal_registry is not None:
            self._principal_registry.check_identity(
                principal, role, agent_id)
        if any(rec["agent_id"] == agent_id for rec in self._keys.values()):
            raise DuplicateAgentRegistrationError(
                "agent_id %r is already registered to a key; "
                "re-registration is refused" % agent_id)
        seed = _ed.generate_seed()
        pub = _ed.publickey(seed)
        key_id = _key_id_for_pubkey(pub)
        self._keys[key_id] = {"agent_id": agent_id,
                              "principal": principal.strip(),
                              "seed": seed, "pub": pub}
        return key_id

    def key_handle(self, agent_id):
        """The signing handle for an agent: seals messages only as its
        own agent_id. Raises KeyError for unregistered agent_ids."""
        for key_id, rec in self._keys.items():
            if rec["agent_id"] == agent_id:
                return AgentSigningHandle(agent_id, key_id, self)
        raise KeyError("agent_id %r has no issued key" % (agent_id,))

    def public_key_for(self, key_id):
        """32-byte public key for a key_id, or None if unknown."""
        rec = self._keys.get(key_id)
        return rec["pub"] if rec else None

    def agent_for_key(self, key_id):
        """The agent_id a key_id is bound to, or None if unknown."""
        rec = self._keys.get(key_id)
        return rec["agent_id"] if rec else None

    def registered_key_ids(self):
        return set(self._keys)

    # Private seam: only AgentSigningHandle calls this. The handle
    # never sees seed material.
    def _sign_for(self, agent_id, data):
        for rec in self._keys.values():
            if rec["agent_id"] == agent_id:
                return _ed.sign(rec["seed"], data)
        raise KeyError("agent_id %r has no issued key" % (agent_id,))


class AgentSigningHandle(object):
    """What an agent holds: the ability to seal messages as its own
    agent_id, nothing more. ``sender`` is stamped from the binding, not
    from a caller argument, so a compromised agent process cannot sign
    as another agent through this handle. No seed/private-key
    attribute exists on this object by design."""

    def __init__(self, agent_id, key_id, registry):
        self._agent_id = agent_id
        self._key_id = key_id
        self._registry = registry

    @property
    def agent_id(self):
        return self._agent_id

    @property
    def key_id(self):
        return self._key_id

    def seal(self, body, seq, nonce=None):
        """Seal a message body into a signed envelope.

        ``body``: JSON-serializable dict (the full message). ``seq``:
        the sender's per-sender sequence int (>= 0). ``nonce``: optional
        32-hex-char freshness value; generated when omitted.
        """
        if not isinstance(body, dict):
            raise TypeError("body must be a dict")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise ValueError("seq must be a non-negative int")
        if nonce is None:
            nonce = secrets.token_bytes(_NONCE_BYTES).hex()
        if not isinstance(nonce, str):
            raise TypeError("nonce must be a hex string")
        payload = {"v": _ENVELOPE_VERSION,
                   "sender": self._agent_id,
                   "key_id": self._key_id,
                   "seq": seq,
                   "nonce": nonce,
                   "body": body}
        # Fail fast on non-serializable bodies before signing.
        _canonical_bytes(payload)
        sig = self._registry._sign_for(
            self._agent_id, _DOMAIN + _canonical_bytes(payload))
        payload["sig"] = sig.hex()
        return payload

    def __repr__(self):
        return "AgentSigningHandle(agent_id=%r, key_id=%r)" % (
            self._agent_id, self._key_id)


class ReplayCache(object):
    """Bounded per-key replay state: seen nonces + last sequence.

    ``check_and_record`` raises ``IdentityRejection`` for a repeated
    nonce (``replayed_nonce``) or a sequence at/below the last seen for
    that key (``stale_sequence``), and records fresh (nonce, seq)
    otherwise. The nonce set is bounded (oldest-first eviction); the
    eviction residual is documented in the module docstring.
    """

    def __init__(self, max_nonces_per_key=4096):
        if max_nonces_per_key < 1:
            raise ValueError("max_nonces_per_key must be >= 1")
        self._max = max_nonces_per_key
        self._nonces = {}   # key_id -> OrderedDict nonce -> None
        self._last_seq = {}  # key_id -> int

    def check_and_record(self, key_id, nonce, seq):
        seen = self._nonces.setdefault(key_id, OrderedDict())
        if nonce in seen:
            raise IdentityRejection(
                "replayed_nonce",
                "nonce %s... already seen for key %s"
                % (nonce[:8], key_id))
        last = self._last_seq.get(key_id)
        if last is not None and seq <= last:
            raise IdentityRejection(
                "stale_sequence",
                "seq %d <= last seen %d for key %s"
                % (seq, last, key_id))
        seen[nonce] = None
        while len(seen) > self._max:
            seen.popitem(last=False)
        self._last_seq[key_id] = seq


def _reject(reason, detail, envelope, log, run_id):
    claimed = envelope.get("sender") if isinstance(envelope, dict) \
        else None
    if log is not None:
        log.append({
            "event": "identity_message_rejected",
            "run_id": run_id,
            "agent_id": claimed,
            "decision": "rejected",
            "policy_id": "inter-agent-identity-binding",
            "reason": reason,
            "detail": detail,
            "key_id": envelope.get("key_id")
            if isinstance(envelope, dict) else None,
        })
    raise IdentityRejection(reason, detail)


def verify_message(envelope, registry, replay_cache, log=None, run_id=""):
    """Verify a sealed inter-agent envelope. Returns the accepted
    message dict ``{"agent_id", "key_id", "seq", "nonce", "body"}``.

    Rejections raise ``IdentityRejection`` with a machine-readable
    ``reason``; when ``log`` (a chained ActionLog) is supplied, every
    rejection first appends an ``identity_message_rejected`` audit event
    (fail-closed: a logging failure never converts a reject into an
    accept). Malformed envelopes raise with reason
    ``malformed_envelope`` -- never an accept.

    Check order is structural-first: malformed -> unsigned ->
    unknown_key -> unbound_key -> bad_signature -> replay/freshness.
    """
    if not isinstance(envelope, dict):
        _reject("malformed_envelope", "envelope is not a dict",
                envelope, log, run_id)
    body = {k: v for k, v in envelope.items() if k != "sig"}
    sender = envelope.get("sender")
    key_id = envelope.get("key_id")
    nonce = envelope.get("nonce")
    seq = envelope.get("seq")
    sig_hex = envelope.get("sig")
    msg_body = envelope.get("body")
    malformed = (
        envelope.get("v") != _ENVELOPE_VERSION
        or not isinstance(sender, str) or not sender
        or not isinstance(key_id, str) or not key_id
        or not isinstance(nonce, str) or not nonce
        or not isinstance(seq, int) or isinstance(seq, bool) or seq < 0
        or not isinstance(msg_body, dict)
    )
    if malformed:
        _reject("malformed_envelope",
                "envelope failed structural validation", envelope,
                log, run_id)
    if not isinstance(sig_hex, str) or not sig_hex:
        _reject("unsigned", "no signature present", envelope, log, run_id)
    pub = registry.public_key_for(key_id)
    if pub is None:
        _reject("unknown_key", "key_id %r not issued by this registry"
                % (key_id,), envelope, log, run_id)
    if registry.agent_for_key(key_id) != sender:
        _reject("unbound_key",
                "key %s is bound to %r, not to claimed sender %r"
                % (key_id, registry.agent_for_key(key_id), sender),
                envelope, log, run_id)
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        sig = None
    if sig is None or not _ed.verify(
            pub, _DOMAIN + _canonical_bytes(body), sig):
        _reject("bad_signature",
                "signature does not verify over the full envelope body",
                envelope, log, run_id)
    try:
        replay_cache.check_and_record(key_id, nonce, seq)
    except IdentityRejection as e:
        _reject(e.reason, e.detail, envelope, log, run_id)
    return {"agent_id": sender, "key_id": key_id, "seq": seq,
            "nonce": nonce, "body": msg_body}


# ---------------------------------------------------------------------------
# did:key-style self-sovereign identity (Wave-246 lane 7).
#
# The registry above is deployment-issued: the governance layer mints keys
# and binds agent_ids. This section is the complement, ADAPTED (patterns
# only) from the did:key shape: an identifier DERIVED FROM the public key
# itself, so an agent can present a stable, self-sovereign identity that
# any verifier can resolve to a key without a registry lookup:
#
#     did:key:z<base58btc(0xed01 || ed25519-pubkey)>
#
#   - ``0xed 0x01`` is the multicodec prefix for an Ed25519 public key.
#   - the leading ``z`` is the multibase tag for base58-btc.
#
# resolve() is key -> id and is deterministic. verify_binding() checks an
# (id, message, signature) triple and returns a bool -- never raises, and
# pins gov.ed25519.verify's bool contract with ``is True`` (wave-243
# lesson: never assume a verifier raises).
#
# HONEST RESIDUALS:
# * A did:key id proves key possession, not good behavior and not
#   uniqueness: one operator can mint arbitrarily many keys (Sybil).
#   Reputation (gov/reputation_ledger.py) is computed over signed
#   events, not over id scarcity.
# * This does not replace the deployment-issued registry above for the
#   messaging path; it is an additional, opt-in primitive for
#   cross-deployment identity.
# ---------------------------------------------------------------------------

_DID_KEY_METHOD = "did:key:"
_MULTIBASE_B58BTC = "z"
_ED25519_PUB_MULTICODEC = b"\xed\x01"
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class DidKeyError(Exception):
    """Malformed did:key input. Fail-closed: parse errors raise, never
    return a guessed key. ``code`` is the taxonomy refusal code."""

    def __init__(self, code, detail=""):
        super(DidKeyError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def b58encode(data):
    """base58-btc encode (stdlib). Leading zero bytes -> leading '1's."""
    if not isinstance(data, (bytes, bytearray)):
        raise DidKeyError(
            "did-key-malformed",
            "b58encode needs bytes, got %s" % type(data).__name__)
    data = bytes(data)
    num = int.from_bytes(data, "big") if data else 0
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = _B58_ALPHABET[rem] + out
    leading = 0
    for byte in data:
        if byte == 0:
            leading += 1
        else:
            break
    # NB: when data is all zero bytes, num == 0 and out == "": the
    # leading '1's carry the value. No extra fallback '1' -- b"\x00"
    # encodes as "1", not "11".
    return "1" * leading + out


def b58decode(text):
    """base58-btc decode (stdlib). Bad alphabet -> DidKeyError."""
    if not isinstance(text, str):
        raise DidKeyError("did-key-malformed",
                          "b58decode needs str, got %s" % type(text).__name__)
    num = 0
    for char in text:
        idx = _B58_ALPHABET.find(char)
        if idx < 0:
            raise DidKeyError("did-key-malformed",
                              "bad base58 character %r" % (char,))
        num = num * 58 + idx
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading = 0
    for char in text:
        if char == "1":
            leading += 1
        else:
            break
    return b"\x00" * leading + raw


def did_key_from_pubkey(pubkey):
    """Derive the did:key identifier for a 32-byte Ed25519 public key."""
    if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
        raise DidKeyError("did-key-malformed",
                          "pubkey must be 32 bytes, got %s"
                          % (type(pubkey).__name__ if not isinstance(
                              pubkey, (bytes, bytearray))
                             else "len %d" % len(pubkey)))
    payload = _ED25519_PUB_MULTICODEC + bytes(pubkey)
    return _DID_KEY_METHOD + _MULTIBASE_B58BTC + b58encode(payload)


def resolve(pubkey):
    """key -> did:key identifier. Deterministic: same key, same id."""
    return did_key_from_pubkey(pubkey)


def pubkey_from_did_key(did):
    """Parse a did:key identifier back to its 32-byte Ed25519 public key.

    Raises DidKeyError with a taxonomy code: ``did-key-method-unsupported``
    for a non-did:key method, ``did-key-malformed`` for anything else
    malformed (bad multibase, bad multicodec, wrong payload length).
    """
    if not isinstance(did, str):
        raise DidKeyError("did-key-malformed",
                          "did must be str, got %s" % type(did).__name__)
    if not did.startswith("did:"):
        raise DidKeyError("did-key-malformed",
                          "not a DID: %r" % (did[:24],))
    if not did.startswith(_DID_KEY_METHOD):
        raise DidKeyError("did-key-method-unsupported",
                          "only did:key is supported, got %r" % (did[:24],))
    body = did[len(_DID_KEY_METHOD):]
    if len(body) < 2 or not body.startswith(_MULTIBASE_B58BTC):
        raise DidKeyError("did-key-malformed",
                          "did:key body must use z/base58-btc multibase")
    payload = b58decode(body[1:])
    if not payload.startswith(_ED25519_PUB_MULTICODEC):
        raise DidKeyError("did-key-malformed",
                          "not an Ed25519 public-key multicodec payload")
    pubkey = payload[len(_ED25519_PUB_MULTICODEC):]
    if len(pubkey) != 32:
        raise DidKeyError("did-key-malformed",
                          "payload holds %d key bytes, need 32" % len(pubkey))
    return pubkey


def verify_binding(did, message, signature):
    """Verify an (id, message, signature) binding. Returns bool, never
    raises: malformed ids, wrong types, and bad signatures are False.

    Pins gov.ed25519.verify's contract with ``is True`` -- the verifier
    returns True/False and never raises on malformed input.
    """
    try:
        pubkey = pubkey_from_did_key(did)
    except DidKeyError:
        return False
    if not isinstance(message, (bytes, bytearray)):
        return False
    if not isinstance(signature, (bytes, bytearray)):
        return False
    return _ed.verify(pubkey, bytes(message), bytes(signature)) is True


# ---------------------------------------------------------------------------
# Federated agent identity: dex-shaped claim normalization + short-lived
# identity tokens (Wave-248 lane 5).
#
# ADAPTED (patterns only) from dex's connector model (dexidp/dex,
# Apache-2.0, CNCF, Go -- not vendored). The steals:
#   (1) connector abstraction: upstream IdPs normalize into ONE claim set
#       {subject, email, email_verified, groups, connector_id} regardless
#       of which upstream vouched for the agent;
#   (2) short-lived identity tokens + refresh-token rotation for
#       non-interactive agents (no long-lived agent secrets --
#       key-custody-friendly);
#   (3) the groups claim rides on the normalized identity so the grant
#       graph can consume it (wiring is the grant-graph owner's job).
# What is NOT stolen: the SAML connector is explicitly refused --
# upstream flags it unmaintained with a likely auth-bypass discussion
# open (dexidp/dex #1884). Unknown connectors fail closed too.
#
# HONEST RESIDUALS:
# * The connector inputs are deployment-supplied: this module normalizes
#   and refuses, it does not verify the upstream IdP's own signatures.
#   Trusting a lying connector is a deployment configuration question
#   (same trust model as the registry's deployment trust domain above).
# * Refresh secrets are bearer secrets: this module stores only their
#   sha256. Leak of live refresh secrets is issuance power until the
#   refresh token expires or its chain is revoked.
# * Identity tokens are stateless bearer tokens: revocation lands only
#   via short lifetimes. A stolen identity token is valid until exp --
#   the 5-minute default bounds the exposure, it does not eliminate it.
# ---------------------------------------------------------------------------

_IDENTITY_CLAIM_FIELDS = ("subject", "email", "email_verified",
                          "groups", "connector_id")

# Connector name -> claim-field mapping. subject_fields is ordered: the
# first present field wins; two present fields with DIFFERENT values is
# ambiguous and refuses (identity-claims-ambiguous) -- we never guess
# which upstream claim is authoritative.
_CONNECTORS = {
    "oidc": {"subject_fields": ("sub", "uid"),
             "email_field": "email",
             "email_verified_field": "email_verified",
             "groups_field": "groups"},
    "static": {"subject_fields": ("username", "user_id"),
               "email_field": "email",
               "email_verified_field": None,  # static never vouches email
               "groups_field": "groups"},
}

_DISABLED_CONNECTORS = {
    "saml": "the SAML connector is disabled (unmaintained upstream; "
            "see dexidp/dex #1884)",
}

_IDENTITY_TOKEN_VERSION = 1
_TOKEN_TYPE = "identity-token"
_TOKEN_DOMAIN = b"gov-identity-token/v1\x00"
_DEFAULT_IDENTITY_LIFETIME = 300
_MAX_IDENTITY_LIFETIME = 3600
_TOKEN_LEEWAY = 60
_DEFAULT_REFRESH_LIFETIME = 86400

# F421: bound on per-token rotation-lock acquisition in refresh(). A
# refresh that cannot serialize its check-then-set refuses fail-closed
# (identity-refresh-lock-unavailable) instead of proceeding unlocked or
# blocking forever. Deployments may override per-store via the
# lock_timeout_seconds constructor argument (tests inject short values).
_REFRESH_LOCK_TIMEOUT_SECONDS = 5.0


class ClaimNormalizationError(Exception):
    """Upstream claim set refused. ``code`` is the taxonomy refusal code."""

    def __init__(self, code, detail=""):
        super(ClaimNormalizationError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


class IdentityTokenRejection(Exception):
    """Identity token or refresh flow refused. ``code`` is the taxonomy
    refusal code. Fail-closed: callers must treat this as
    unauthenticated."""

    def __init__(self, code, detail=""):
        super(IdentityTokenRejection, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def normalize_claims(raw_claims, connector):
    """Normalize an upstream IdP claim set into one identity shape.

    Returns ``{"subject", "email", "email_verified", "groups",
    "connector_id"}`` -- the same shape regardless of which upstream
    vouched for the agent. Refuses (ClaimNormalizationError) on:
    unknown or disabled connector (identity-connector-unsupported),
    wrong-typed claims (identity-claims-malformed), missing subject
    (identity-claims-missing-subject), or two subject-candidate claims
    that disagree (identity-claims-ambiguous).
    """
    if connector in _DISABLED_CONNECTORS:
        raise ClaimNormalizationError(
            "identity-connector-unsupported",
            _DISABLED_CONNECTORS[connector])
    mapping = _CONNECTORS.get(connector)
    if mapping is None:
        raise ClaimNormalizationError(
            "identity-connector-unsupported",
            "unknown connector %r" % (connector,))
    if not isinstance(raw_claims, dict):
        raise ClaimNormalizationError(
            "identity-claims-malformed",
            "claims must be a dict, got %s" % type(raw_claims).__name__)
    subjects = []
    for field in mapping["subject_fields"]:
        if field in raw_claims:
            value = raw_claims[field]
            if not isinstance(value, str) or not value.strip():
                raise ClaimNormalizationError(
                    "identity-claims-malformed",
                    "subject field %r must be a non-empty string"
                    % (field,))
            subjects.append(value.strip())
    if not subjects:
        raise ClaimNormalizationError(
            "identity-claims-missing-subject",
            "no subject claim among %s"
            % (", ".join(mapping["subject_fields"]),))
    if len(set(subjects)) > 1:
        raise ClaimNormalizationError(
            "identity-claims-ambiguous",
            "subject candidates disagree: %r" % (sorted(set(subjects)),))
    subject = subjects[0]
    email = None
    email_field = mapping["email_field"]
    if email_field is not None and email_field in raw_claims:
        email = raw_claims[email_field]
        if email is not None and not isinstance(email, str):
            raise ClaimNormalizationError(
                "identity-claims-malformed",
                "email must be a string or absent")
    email_verified = False
    ev_field = mapping["email_verified_field"]
    if ev_field is not None and ev_field in raw_claims:
        email_verified = raw_claims[ev_field]
        if not isinstance(email_verified, bool):
            raise ClaimNormalizationError(
                "identity-claims-malformed",
                "email_verified must be a bool")
    groups = []
    groups_field = mapping["groups_field"]
    if groups_field in raw_claims:
        groups = raw_claims[groups_field]
        if not isinstance(groups, list) or not all(
                isinstance(g, str) for g in groups):
            raise ClaimNormalizationError(
                "identity-claims-malformed",
                "groups must be a list of strings")
        groups = list(groups)
    return {"subject": subject, "email": email,
            "email_verified": email_verified, "groups": groups,
            "connector_id": connector}


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode_token_part(text):
    if not isinstance(text, str) or not text:
        raise IdentityTokenRejection(
            "identity-token-malformed", "token part is not a string")
    try:
        padded = text + "=" * (-len(text) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeError):
        raise IdentityTokenRejection(
            "identity-token-malformed", "token part is not base64url")


class IdentityTokenIssuer(object):
    """Mints and verifies short-lived HMAC-SHA256 identity tokens.

    Constructed in the deployment trust domain with a 32+ byte secret --
    the key-custody-friendly pattern: agents hold only short-lived
    tokens, never long-lived secrets. Tokens are
    ``b64url(canonical JSON) + "." + b64url(HMAC)``; ``verify_token``
    raises IdentityTokenRejection on any problem and never returns a
    forged, expired, or mis-audienced identity.
    """

    def __init__(self, key, issuer="gov-identity",
                 max_lifetime_seconds=_MAX_IDENTITY_LIFETIME,
                 time_fn=None):
        if not isinstance(key, (bytes, bytearray)) or len(key) < 32:
            raise ValueError("key must be bytes of length >= 32")
        if max_lifetime_seconds < 1:
            raise ValueError("max_lifetime_seconds must be >= 1")
        self._key = bytes(key)
        self._issuer = issuer
        self._max_lifetime = int(max_lifetime_seconds)
        self._time_fn = time_fn or time.time

    def _now(self, now):
        return int(now) if now is not None else int(self._time_fn())

    def issue(self, identity, audience, lifetime_seconds=None,
              now=None, jti=None):
        """Mint a short-lived identity token for a normalized identity.

        ``identity`` is a ``normalize_claims`` dict. ``lifetime_seconds``
        defaults to 300 and is capped at ``max_lifetime_seconds`` --
        callers cannot mint a long-lived identity token through this
        path. ``now``/``jti`` are injectable for deterministic tests.
        """
        if not isinstance(identity, dict) or "subject" not in identity:
            raise ValueError("identity must be a normalize_claims dict")
        if not isinstance(audience, str) or not audience:
            raise ValueError("audience must be a non-empty string")
        if lifetime_seconds is None:
            lifetime_seconds = _DEFAULT_IDENTITY_LIFETIME
        lifetime = max(1, min(int(lifetime_seconds), self._max_lifetime))
        issued_at = self._now(now)
        claims = {"v": _IDENTITY_TOKEN_VERSION,
                  "typ": _TOKEN_TYPE,
                  "iss": self._issuer,
                  "sub": identity["subject"],
                  "aud": audience,
                  "iat": issued_at,
                  "exp": issued_at + lifetime,
                  "email": identity.get("email"),
                  "email_verified": bool(identity.get("email_verified")),
                  "groups": list(identity.get("groups") or []),
                  "connector_id": identity.get("connector_id"),
                  "jti": jti if jti is not None
                  else secrets.token_hex(16)}
        body = _b64url_encode(_canonical_bytes(claims))
        sig = hmac.new(self._key, _TOKEN_DOMAIN + body.encode("ascii"),
                       hashlib.sha256).digest()
        return body + "." + _b64url_encode(sig)

    def verify_token(self, token, audience, now=None, leeway=_TOKEN_LEEWAY):
        """Verify an identity token for an audience. Returns the identity
        dict ``{"subject", "email", "email_verified", "groups",
        "connector_id", "audience", "issuer", "iat", "exp", "jti"}``.

        Check order is structural-first: malformed -> tampered ->
        audience -> expiry -> not-yet-valid. Every refusal raises
        IdentityTokenRejection with a taxonomy code.
        """
        if not isinstance(token, str):
            raise IdentityTokenRejection(
                "identity-token-malformed", "token is not a string")
        parts = token.split(".")
        if len(parts) != 2:
            raise IdentityTokenRejection(
                "identity-token-malformed",
                "token must have exactly two dot-separated parts")
        raw_body = _b64url_decode_token_part(parts[0])
        raw_sig = _b64url_decode_token_part(parts[1])
        try:
            claims = json.loads(raw_body.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise IdentityTokenRejection(
                "identity-token-malformed", "token body is not JSON")
        if not isinstance(claims, dict) or \
                claims.get("v") != _IDENTITY_TOKEN_VERSION or \
                claims.get("typ") != _TOKEN_TYPE:
            raise IdentityTokenRejection(
                "identity-token-malformed",
                "token body is not an identity-token v1 envelope")
        expected = hmac.new(self._key, _TOKEN_DOMAIN + parts[0].encode(
            "ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, raw_sig):
            raise IdentityTokenRejection(
                "identity-token-tampered",
                "signature does not verify over the token body")
        if claims.get("aud") != audience:
            raise IdentityTokenRejection(
                "identity-token-audience-mismatch",
                "token is for audience %r, not %r"
                % (claims.get("aud"), audience))
        current = self._now(now)
        exp = claims.get("exp")
        iat = claims.get("iat")
        if not isinstance(exp, int) or isinstance(exp, bool):
            raise IdentityTokenRejection(
                "identity-token-malformed", "exp is not an int")
        if not isinstance(iat, int) or isinstance(iat, bool):
            raise IdentityTokenRejection(
                "identity-token-malformed", "iat is not an int")
        if current > exp:
            raise IdentityTokenRejection(
                "identity-token-expired",
                "token expired %d seconds ago" % (current - exp,))
        if iat > current + leeway:
            raise IdentityTokenRejection(
                "identity-token-not-yet-valid",
                "token claims iat %d seconds in the future" % (iat - current,))
        return {"subject": claims["sub"],
                "email": claims.get("email"),
                "email_verified": bool(claims.get("email_verified")),
                "groups": list(claims.get("groups") or []),
                "connector_id": claims.get("connector_id"),
                "audience": audience,
                "issuer": claims.get("iss"),
                "iat": iat, "exp": exp, "jti": claims.get("jti")}


class RefreshTokenStore(object):
    """Server-side refresh tokens with rotation and reuse detection.

    ``mint_refresh`` binds (identity, connector, raw claims) to an opaque
    (id, secret) pair and stores only the secret's sha256. ``refresh``
    re-normalizes the stored raw claims (a fresh identity, never the old
    token's), issues a SHORT identity token via the supplied issuer --
    the refresh call takes no lifetime parameter, so a refresh can never
    silently mint a long-lived identity token -- rotates to a new
    (id, secret), and invalidates the old one. Presenting a rotated token
    again is treated as theft: the whole chain is revoked
    (identity-refresh-reuse-detected, then identity-refresh-revoked).
    """

    def __init__(self, lifetime_seconds=_DEFAULT_REFRESH_LIFETIME,
                 time_fn=None, lock_timeout_seconds=None):
        if lifetime_seconds < 1:
            raise ValueError("lifetime_seconds must be >= 1")
        self._lifetime = int(lifetime_seconds)
        self._time_fn = time_fn or time.time
        self._tokens = {}  # refresh_id -> record
        # Per-token rotation locks (F421): the check-then-set on
        # ``rotated`` in refresh() must be serialized per token, never
        # globally -- a global lock would serialize all refreshes
        # deployment-wide. ``_rt_locks_guard`` protects only the lock
        # registry itself and is never held while acquiring a token lock.
        self._rt_locks = {}  # refresh_id -> threading.Lock
        self._rt_locks_guard = threading.Lock()
        self._lock_timeout = (
            _REFRESH_LOCK_TIMEOUT_SECONDS
            if lock_timeout_seconds is None
            else float(lock_timeout_seconds))

    def _now(self, now):
        return int(now) if now is not None else int(self._time_fn())

    @staticmethod
    def _secret_hash(secret):
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def mint_refresh(self, identity, connector_id, raw_claims,
                     lifetime_seconds=None, now=None):
        """Bind an identity to a new refresh token. Returns
        ``(refresh_id, secret)``; the secret is shown once -- only its
        hash is stored. The claims are re-normalized now (fail fast)."""
        if not isinstance(identity, dict) or "subject" not in identity:
            raise ValueError("identity must be a normalize_claims dict")
        # Fail fast: the stored claims must normalize today, or the
        # refresh would mint from a claim set we already refuse.
        normalize_claims(raw_claims, connector_id)
        if lifetime_seconds is None:
            lifetime_seconds = self._lifetime
        lifetime = max(1, int(lifetime_seconds))
        issued_at = self._now(now)
        refresh_id = "rt_" + secrets.token_hex(16)
        secret = secrets.token_hex(32)
        self._tokens[refresh_id] = {
            "secret_hash": self._secret_hash(secret),
            "subject": identity["subject"],
            "connector_id": connector_id,
            "raw_claims": dict(raw_claims),
            "exp": issued_at + lifetime,
            "rotated": False,
            "revoked": False,
            "chain_id": secrets.token_hex(16),
        }
        return refresh_id, secret

    def _revoke_chain(self, chain_id):
        # Snapshot: refresh() holds a per-token lock while this runs, and
        # a concurrent mint_refresh() on another thread may insert into
        # _tokens -- iterating the live dict would raise RuntimeError.
        for rec in list(self._tokens.values()):
            if rec["chain_id"] == chain_id:
                rec["revoked"] = True

    def _lock_for(self, refresh_id):
        """Return the per-token rotation lock, creating it if absent.

        Only the short-lived registry guard is held here; the returned
        token lock is always acquired AFTER the guard is released, so no
        lock-ordering deadlock is possible (a thread never holds two
        locks at once on this path).
        """
        with self._rt_locks_guard:
            return self._rt_locks.setdefault(refresh_id, threading.Lock())

    def refresh(self, issuer, refresh_id, secret, audience, now=None):
        """Exchange a refresh token for a new SHORT identity token plus a
        rotated refresh pair. Returns
        ``(identity_token, new_refresh_id, new_secret)``.

        The identity comes from re-normalizing the stored raw claims.
        The identity token always uses the issuer's short default
        lifetime -- there is no lifetime parameter here by design.

        F421: the rotated-flag check-then-set is serialized by a
        per-token lock. The unknown/secret pre-check stays outside the
        lock (read-only, no oracle change); everything from the
        rotated/revoked/expiry checks through ``rotated = True`` runs
        under the token's lock, so a concurrent double-refresh yields
        exactly one success and the loser hits the reuse-detection
        path. If the lock cannot be acquired within the timeout the
        refresh is refused fail-closed
        (``identity-refresh-lock-unavailable``) -- it never proceeds
        unlocked.
        """
        current = self._now(now)
        rec = self._tokens.get(refresh_id)
        if rec is None or not isinstance(secret, str) or not \
                hmac.compare_digest(rec["secret_hash"],
                                    self._secret_hash(secret)):
            # One code, no oracle: unknown id and wrong secret are
            # indistinguishable.
            raise IdentityTokenRejection(
                "identity-refresh-unknown",
                "refresh token unknown or secret mismatch")
        lock = self._lock_for(refresh_id)
        if not lock.acquire(timeout=self._lock_timeout):
            # Fail closed: serializing the rotation is a safety
            # property, not an optimization. Never refresh unlocked.
            raise IdentityTokenRejection(
                "identity-refresh-lock-unavailable",
                "could not serialize refresh-token rotation; "
                "refusing rather than refreshing unlocked")
        try:
            return self._refresh_locked(issuer, rec, audience, current)
        finally:
            lock.release()

    def _refresh_locked(self, issuer, rec, audience, current):
        """refresh() body: runs with the token's rotation lock held."""
        if current > rec["exp"]:
            raise IdentityTokenRejection(
                "identity-refresh-expired",
                "refresh token expired %d seconds ago"
                % (current - rec["exp"],))
        if rec["revoked"]:
            raise IdentityTokenRejection(
                "identity-refresh-revoked",
                "refresh token chain was revoked")
        if rec["rotated"]:
            # Reuse of a spent token: suspected theft. Revoke the whole
            # chain (dex reuse detection), then refuse.
            self._revoke_chain(rec["chain_id"])
            raise IdentityTokenRejection(
                "identity-refresh-reuse-detected",
                "rotated refresh token presented again; chain revoked")
        identity = normalize_claims(rec["raw_claims"], rec["connector_id"])
        token = issuer.issue(identity, audience)
        rec["rotated"] = True
        new_id, new_secret = self.mint_refresh(
            identity, rec["connector_id"], rec["raw_claims"],
            lifetime_seconds=rec["exp"] - current, now=current)
        self._tokens[new_id]["chain_id"] = rec["chain_id"]
        return token, new_id, new_secret
