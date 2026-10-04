"""Federated agent identity: the dex pattern, without the dex server.

The 2026-09-29 research verdict: "dex for real agent identity
(federated login issuing short-lived signed tokens; integration being
built)". This module IS that integration's token half.

The deployment's identity provider holds an Ed25519 issuer key and
issues SHORT-LIVED signed identity tokens to agents at login time.
This module implements both halves of the pattern:

* :class:`TokenIssuer` -- the IdP side. Holds the issuer private key;
  :meth:`issue_token` mints a token binding (agent_id, principal,
  role, agent public key, scopes) with a short TTL.
* :class:`TokenVerifier` -- the relying-party side. Holds PINNED
  issuer public keys (out-of-band trust, same model as the offline
  root in gov/signing.py); :meth:`verify_token` checks signature,
  issuer pinning, audience, expiry with clock-skew bound, a TTL
  ceiling, nonce replay, and key binding. Issuer key rotation with a
  grace overlap is supported; unknown issuers are never silently
  accepted.

What this is NOT: OIDC. There is no discovery document, no JWKS
fetch, no network, no refresh flow. Keys are pinned in deployment
configuration. The wire format is JWT-*shaped* (three dot-separated
base64url parts, ``alg: EdDSA``) for operator familiarity, but it is
not a JWT and must never be presented to a JWT library as one.

Composition: :meth:`TokenVerifier.verify_token` returns a verified
claim dict carrying exactly ``{iss, sub, aud, iat, exp, jti,
principal, role, agent_scope}`` -- the claim set
:func:`gov.decision_packet.check_token_claims` requires -- so the
output feeds ``ToolExecutor.mint_identity(token_claims=...)`` and the
decision-packet token seam UNCHANGED. Failures raise
:class:`FederatedIdentityError` (with a machine ``.code``); the
verifier NEVER returns False/None on failure, so a forgotten
return-value check cannot become an accept.

Trust model (explicit): whoever holds an issuer private key can mint
tokens for any identity. Issuer keys are deployment-held secrets with
the same custody requirements as the log signing key. Tokens are
bearer credentials within their TTL -- short TTLs (default 5 min)
bound the theft window. The nonce replay cache is per-verifier
instance; deployments needing cross-process replay protection must
share the cache (documented, not silently claimed).
"""

import base64
import binascii
import hashlib
import json
import secrets
import time

try:
    from . import ed25519 as _ed
except ImportError:  # standalone/offline: ed25519.py beside this file
    import ed25519 as _ed

try:
    from .signing import ed25519_key_id as _key_id
except ImportError:  # standalone/offline
    def _key_id(pub):
        if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
            raise ValueError("pub must be 32 bytes")
        return hashlib.sha256(bytes(pub)).hexdigest()[:16]

try:
    from .identity import (UnregisteredPrincipalError,
                           UnregisteredRoleError)
except ImportError:  # standalone/offline
    from identity import (UnregisteredPrincipalError,  # noqa: F401
                          UnregisteredRoleError)  # noqa: F401


# ---------------------------------------------------------------------------
# Wire format constants.
# ---------------------------------------------------------------------------

TOKEN_VERSION = 1
_TOKEN_ALG = "EdDSA"
_TOKEN_TYP = "sasanam-id-token"
_SIGN_DOMAIN = b"gov-federated-identity/v1\x00"

#: Default token lifetime: 5 minutes. Short-lived is the point.
DEFAULT_TTL_SECONDS = 300
#: Default ceiling on token lifetime enforced by verifiers.
DEFAULT_MAX_TTL_SECONDS = 3600
#: Default clock-skew allowance (matches TOKEN_SKEW_SECONDS).
DEFAULT_SKEW_SECONDS = 60
#: Default issuer-rotation grace: the retired key still verifies.
DEFAULT_ROTATION_GRACE_SECONDS = 3600

#: Claims the verifier returns on success (the check_token_claims set).
VERIFIED_CLAIMS = ("iss", "sub", "aud", "iat", "exp", "jti",
                   "principal", "role", "agent_scope")


class FederatedIdentityError(Exception):
    """A federated-identity operation failed, fail-closed.

    ``code`` is the machine decision code (one of the
    ``identity-token-*`` / ``identity-issuer-*`` taxonomy entries);
    ``detail`` is the human explanation. The verifier raises instead
    of returning False so a dropped return value cannot become an
    accept.
    """

    def __init__(self, code, detail):
        super().__init__("federated identity refused: [%s] %s"
                         % (code, detail))
        self.code = code
        self.detail = detail


def _b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(part):
    if not isinstance(part, str) or not part:
        raise FederatedIdentityError(
            "identity-token-malformed", "token part is not a string")
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except (binascii.Error, ValueError):
        raise FederatedIdentityError(
            "identity-token-malformed",
            "token part is not valid base64url")


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _nonempty_str(value, what):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("%s must be a non-empty string, got %r"
                         % (what, value))
    return value.strip()


# ---------------------------------------------------------------------------
# Issuer side.
# ---------------------------------------------------------------------------

class TokenIssuer:
    """The IdP side: mints short-lived signed identity tokens.

    ``seed`` is the 32-byte Ed25519 issuer private seed (deployment-held
    secret). ``issuer_id`` names this issuer (the ``iss`` claim).
    ``default_ttl`` / ``max_ttl`` bound token lifetimes; ``audience``
    is the default ``aud`` claim.
    """

    def __init__(self, seed, issuer_id, default_ttl=DEFAULT_TTL_SECONDS,
                 max_ttl=DEFAULT_MAX_TTL_SECONDS,
                 audience="sasanam-policy-engine"):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self._seed = bytes(seed)
        self._pub = _ed.publickey(self._seed)
        self._issuer_id = _nonempty_str(issuer_id, "issuer_id")
        if not isinstance(default_ttl, (int, float)) or default_ttl < 1:
            raise ValueError("default_ttl must be >= 1 second")
        if not isinstance(max_ttl, (int, float)) or max_ttl < 1:
            raise ValueError("max_ttl must be >= 1 second")
        if default_ttl > max_ttl:
            raise ValueError("default_ttl exceeds max_ttl")
        self._default_ttl = default_ttl
        self._max_ttl = max_ttl
        self._audience = _nonempty_str(audience, "audience")

    @property
    def issuer_id(self):
        return self._issuer_id

    @property
    def key_id(self):
        """Short key id of the issuer public key (kid claim)."""
        return _key_id(self._pub)

    @property
    def public_key_hex(self):
        return self._pub.hex()

    def issue_token(self, agent_id, principal, role, agent_pubkey_hex,
                    scopes, ttl_seconds=None, audience=None, now=None):
        """Mint a short-lived identity token. Returns the token string.

        ``agent_pubkey_hex`` binds the token to the agent's Ed25519
        key (holder-of-key binding claim). ``scopes`` is a non-empty
        collection of non-empty strings (the downstream seam requires
        a non-empty ``agent_scope``; fail fast here rather than issue
        a token that can never mint). ``ttl_seconds`` defaults to the
        issuer's default TTL and may not exceed its max TTL.
        ``now`` is injectable for tests (epoch seconds).

        Raises ValueError on doubtful inputs -- never issue over them.
        """
        agent_id = _nonempty_str(agent_id, "agent_id")
        principal = _nonempty_str(principal, "principal")
        role = _nonempty_str(role, "role")
        if not _is_hex64(agent_pubkey_hex):
            raise ValueError("agent_pubkey_hex must be 64 lowercase hex")
        if isinstance(scopes, str):
            scopes = [scopes]
        try:
            scopes = list(scopes)
        except TypeError:
            raise ValueError("scopes must be a non-empty collection of "
                             "strings, got %r" % (scopes,))
        if not scopes or any(not isinstance(s, str) or not s.strip()
                             for s in scopes):
            raise ValueError("scopes must be a non-empty collection of "
                             "non-empty strings")
        ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        if not isinstance(ttl, (int, float)) or isinstance(ttl, bool) \
                or ttl < 1 or ttl > self._max_ttl:
            raise ValueError("ttl_seconds must be within [1, max_ttl=%r], "
                             "got %r" % (self._max_ttl, ttl_seconds))
        aud = self._audience if audience is None else audience
        aud = _nonempty_str(aud, "audience")
        ref = time.time() if now is None else now
        if not isinstance(ref, (int, float)) or isinstance(ref, bool):
            raise ValueError("now must be epoch seconds")
        payload = {
            "v": TOKEN_VERSION,
            "iss": self._issuer_id,
            "kid": self.key_id,
            "sub": agent_id,
            "aud": aud,
            "iat": ref,
            "exp": ref + ttl,
            "jti": secrets.token_hex(16),
            "principal": principal,
            "role": role,
            "agent_scope": " ".join(s.strip() for s in scopes),
            "key_binding": agent_pubkey_hex,
        }
        header = {"alg": _TOKEN_ALG, "typ": _TOKEN_TYP, "v": TOKEN_VERSION}
        p1 = _b64u_encode(_canonical(header))
        p2 = _b64u_encode(_canonical(payload))
        sig = _ed.sign(self._seed, _SIGN_DOMAIN + (p1 + "." + p2).encode())
        return p1 + "." + p2 + "." + _b64u_encode(sig)


# ---------------------------------------------------------------------------
# Verifier side (rotation-aware).
# ---------------------------------------------------------------------------

class TokenVerifier:
    """The relying-party side: verifies tokens against PINNED issuers.

    Issuer keys are added out-of-band via :meth:`add_issuer` -- there
    is no fetch, no discovery, no network. :meth:`rotate_issuer`
    moves the current key to "previous" with a retirement timestamp;
    the previous key still verifies inside ``rotation_grace_seconds``
    (overlap), then refuses with ``identity-issuer-key-retired``.
    Unknown issuers refuse with ``identity-token-issuer-unknown`` --
    never silently accepted.
    """

    def __init__(self, audience,
                 skew_seconds=DEFAULT_SKEW_SECONDS,
                 max_ttl_seconds=DEFAULT_MAX_TTL_SECONDS,
                 rotation_grace_seconds=DEFAULT_ROTATION_GRACE_SECONDS):
        self._audience = _nonempty_str(audience, "audience")
        for name, val in (("skew_seconds", skew_seconds),
                          ("max_ttl_seconds", max_ttl_seconds),
                          ("rotation_grace_seconds",
                           rotation_grace_seconds)):
            if not isinstance(val, (int, float)) or isinstance(val, bool) \
                    or val < 0:
                raise ValueError("%s must be a non-negative number" % name)
        self._skew = skew_seconds
        self._max_ttl = max_ttl_seconds
        self._grace = rotation_grace_seconds
        # issuer_id -> {"current": (kid, pub), "previous": (kid, pub,
        # retired_at) or None}
        self._issuers = {}
        # jti -> exp (replay cache; expired entries evicted per call)
        self._seen_jtis = {}

    def add_issuer(self, issuer_id, pubkey_hex):
        """Pin an issuer public key (out-of-band trust establishment)."""
        issuer_id = _nonempty_str(issuer_id, "issuer_id")
        if not _is_hex64(pubkey_hex):
            raise ValueError("pubkey_hex must be 64 lowercase hex")
        if issuer_id in self._issuers:
            raise ValueError("issuer %r already pinned" % (issuer_id,))
        pub = bytes.fromhex(pubkey_hex)
        self._issuers[issuer_id] = {"current": (_key_id(pub), pub),
                                    "previous": None}

    def rotate_issuer(self, issuer_id, new_pubkey_hex, now=None):
        """Rotate an issuer key with overlap.

        The new key becomes current (it issues from now on); the old
        key becomes previous and still verifies inside the rotation
        grace window. Rotating an unknown issuer, or re-adding the
        current key, is a ValueError (deployment error, not a token
        refusal).
        """
        issuer_id = _nonempty_str(issuer_id, "issuer_id")
        if not _is_hex64(new_pubkey_hex):
            raise ValueError("new_pubkey_hex must be 64 lowercase hex")
        ring = self._issuers.get(issuer_id)
        if ring is None:
            raise ValueError("cannot rotate unknown issuer %r" % (
                issuer_id,))
        new_pub = bytes.fromhex(new_pubkey_hex)
        new_kid = _key_id(new_pub)
        if new_kid == ring["current"][0]:
            raise ValueError("new key is already the current key for %r"
                             % (issuer_id,))
        ref = time.time() if now is None else now
        if not isinstance(ref, (int, float)) or isinstance(ref, bool):
            raise ValueError("now must be epoch seconds")
        ring["previous"] = (ring["current"][0], ring["current"][1], ref)
        ring["current"] = (new_kid, new_pub)

    def _issuer_key(self, issuer_id, kid, now):
        ring = self._issuers.get(issuer_id)
        if ring is None:
            raise FederatedIdentityError(
                "identity-token-issuer-unknown",
                "issuer %r is not pinned by this deployment" % (issuer_id,))
        cur_kid, cur_pub = ring["current"]
        if kid == cur_kid:
            return cur_pub
        prev = ring["previous"]
        if prev is not None and kid == prev[0]:
            if now <= prev[2] + self._grace:
                return prev[1]
            raise FederatedIdentityError(
                "identity-issuer-key-retired",
                "issuer %r key %r retired %.0fs ago (grace %.0fs); "
                "refresh for a token from the current key"
                % (issuer_id, kid, now - prev[2], self._grace))
        raise FederatedIdentityError(
            "identity-token-issuer-unknown",
            "key %r is not a pinned key for issuer %r" % (kid, issuer_id))

    def verify_token(self, token, now=None, expected_key_binding=None):
        """Verify a token string. Returns the verified claim dict.

        Raises :class:`FederatedIdentityError` (with ``.code``) on any
        failure -- never returns a falsy "invalid" that a caller could
        forget to check. ``expected_key_binding`` (64-hex pubkey)
        additionally requires the token's ``key_binding`` claim to
        match (holder-of-key check by the caller).
        """
        ref = time.time() if now is None else now
        if not isinstance(ref, (int, float)) or isinstance(ref, bool):
            raise FederatedIdentityError(
                "identity-token-malformed", "now must be epoch seconds")
        parts = token.split(".") if isinstance(token, str) else None
        if parts is None or len(parts) != 3:
            raise FederatedIdentityError(
                "identity-token-malformed",
                "token must be three dot-separated parts")
        try:
            header = json.loads(_b64u_decode(parts[0]))
            payload = json.loads(_b64u_decode(parts[1]))
            sig = _b64u_decode(parts[2])
        except FederatedIdentityError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise FederatedIdentityError(
                "identity-token-malformed",
                "token parts do not decode: %s" % (exc,))
        if not isinstance(header, dict) or header.get("alg") != _TOKEN_ALG \
                or header.get("typ") != _TOKEN_TYP \
                or header.get("v") != TOKEN_VERSION:
            raise FederatedIdentityError(
                "identity-token-malformed",
                "token header is not a %s %s v%d envelope"
                % (_TOKEN_ALG, _TOKEN_TYP, TOKEN_VERSION))
        if not isinstance(payload, dict):
            raise FederatedIdentityError(
                "identity-token-malformed", "token payload is not an object")
        if payload.get("v") != TOKEN_VERSION:
            raise FederatedIdentityError(
                "identity-token-malformed", "unsupported token version")
        iss = payload.get("iss")
        kid = payload.get("kid")
        if not isinstance(iss, str) or not iss \
                or not isinstance(kid, str) or not kid:
            raise FederatedIdentityError(
                "identity-token-malformed",
                "token carries no usable iss/kid")
        pub = self._issuer_key(iss, kid, ref)
        if len(sig) != 64 or not _ed.verify(
                pub, _SIGN_DOMAIN + (parts[0] + "." + parts[1]).encode(),
                sig):
            raise FederatedIdentityError(
                "identity-token-tampered",
                "token signature did not verify (forged or corrupt)")
        claims = self._check_claims(payload, ref)
        self._check_replay(claims["jti"], claims["exp"], ref)
        kb = payload.get("key_binding")
        if not _is_hex64(kb):
            raise FederatedIdentityError(
                "identity-token-malformed",
                "key_binding claim is not a 64-hex Ed25519 pubkey")
        if expected_key_binding is not None:
            if not _is_hex64(expected_key_binding):
                raise FederatedIdentityError(
                    "identity-token-malformed",
                    "expected_key_binding is not 64-hex")
            if kb != expected_key_binding.lower():
                raise FederatedIdentityError(
                    "identity-token-key-binding-mismatch",
                    "token is bound to a different agent key")
        return {name: claims[name] for name in VERIFIED_CLAIMS}

    def _check_claims(self, payload, ref):
        for name in ("sub", "principal", "role", "jti", "agent_scope"):
            val = payload.get(name)
            if not isinstance(val, str) or not val:
                raise FederatedIdentityError(
                    "identity-token-malformed",
                    "claim %r missing or not a non-empty string" % (name,))
        aud = payload.get("aud")
        if isinstance(aud, str):
            aud = {aud} if aud else None
        elif isinstance(aud, (list, tuple)):
            aud = set(aud) if aud and all(
                isinstance(x, str) and x for x in aud) else None
        else:
            aud = None
        if aud is None:
            raise FederatedIdentityError(
                "identity-token-malformed",
                "aud claim must be a non-empty string or list")
        if self._audience not in aud:
            raise FederatedIdentityError(
                "identity-token-audience-mismatch",
                "token audience %r does not include %r"
                % (sorted(aud), self._audience))
        iat = payload.get("iat")
        exp = payload.get("exp")
        for name, val in (("iat", iat), ("exp", exp)):
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                raise FederatedIdentityError(
                    "identity-token-malformed",
                    "claim %r must be a number" % (name,))
        if exp < ref - self._skew:
            raise FederatedIdentityError(
                "identity-token-expired",
                "token expired %.0fs ago (skew %ds)"
                % (ref - exp, self._skew))
        if iat > ref + self._skew:
            raise FederatedIdentityError(
                "identity-token-not-yet-valid",
                "token issued %.0fs in the future (skew %ds)"
                % (iat - ref, self._skew))
        if iat > exp + self._skew:
            raise FederatedIdentityError(
                "identity-token-malformed",
                "iat is after exp (issued after expiry)")
        if exp - iat > self._max_ttl:
            raise FederatedIdentityError(
                "identity-token-ttl-exceeded",
                "token lifetime %.0fs exceeds verifier max %.0fs"
                % (exp - iat, self._max_ttl))
        return {"iss": payload["iss"], "sub": payload["sub"],
                "aud": payload["aud"], "iat": iat, "exp": exp,
                "jti": payload["jti"], "principal": payload["principal"],
                "role": payload["role"],
                "agent_scope": payload["agent_scope"]}

    def _check_replay(self, jti, exp, ref):
        # Evict expired entries first: the cache stays bounded by the
        # number of live tokens, never grows without bound.
        for seen, seen_exp in list(self._seen_jtis.items()):
            if seen_exp < ref - self._skew:
                del self._seen_jtis[seen]
        if jti in self._seen_jtis:
            raise FederatedIdentityError(
                "identity-token-replayed",
                "token jti %r has already been presented" % (jti,))
        self._seen_jtis[jti] = exp


# ---------------------------------------------------------------------------
# Token-backed PrincipalRegistry: the registry interface, with
# authorization coming from a VERIFIED token instead of static config.
# ---------------------------------------------------------------------------

class TokenBackedPrincipalRegistry:
    """A PrincipalRegistry whose trust anchor is a verified token.

    Interface parity with :class:`gov.identity.PrincipalRegistry`
    (``check``, ``check_identity``, ``allowed_roles``,
    ``registered``) so it drops into
    ``ToolExecutor(principal_registry=...)`` unchanged. Instead of a
    static principal->roles map, authorization comes from a token the
    deployment presents via :meth:`present_token`: the token's claims
    authorize exactly the (principal, role, agent_id) tuple they
    attest. A token that has expired as of the check authorizes
    nothing (fail-closed); :meth:`clear_token` drops the presentation.

    Refusals reuse ``UnregisteredPrincipalError`` /
    ``UnregisteredRoleError`` so the executor's existing audited
    ``identity_mint_refused`` handling keeps working.
    """

    def __init__(self, verifier):
        if not isinstance(verifier, TokenVerifier):
            raise ValueError("verifier must be a TokenVerifier")
        self._verifier = verifier
        self._presented = None

    def present_token(self, token, now=None):
        """Verify and cache the token authorizing subsequent mints.

        Returns the verified claim dict. Raises
        :class:`FederatedIdentityError` on any verification failure; a
        failed presentation does NOT replace the previously presented
        token (use :meth:`clear_token` to revoke -- a failed
        presentation must never let garbage tokens lock out the
        legitimate agent).
        """
        claims = self._verifier.verify_token(token, now=now)
        self._presented = claims
        return claims

    def clear_token(self):
        """Drop the presented token (fail closed from here on)."""
        self._presented = None

    def _live_claims(self, now):
        claims = self._presented
        if claims is None:
            raise UnregisteredPrincipalError(
                "no verified identity token presented to this "
                "deployment's registry; token-authenticated issuance "
                "requires present_token() first")
        ref = time.time() if now is None else now
        # The verifier enforces skew at presentation; here the token
        # must simply be unexpired -- a stale token authorizes nothing.
        if claims["exp"] < ref:
            raise UnregisteredPrincipalError(
                "the presented identity token expired; re-authenticate "
                "for a fresh token")
        return claims

    def check(self, principal):
        """Raise ``UnregisteredPrincipalError`` unless the presented
        token authorizes *principal*."""
        claims = self._live_claims(None)
        if claims["principal"] != principal:
            raise UnregisteredPrincipalError(
                "principal %r is not the token-authenticated principal "
                "%r" % (principal, claims["principal"]))
        return True

    def check_identity(self, principal, role, agent_id=None):
        """Authorize a full (principal, role[, agent_id]) mint against
        the presented token's claims."""
        claims = self._live_claims(None)
        if claims["principal"] != principal:
            raise UnregisteredPrincipalError(
                "principal %r is not the token-authenticated principal "
                "%r; fresh-principal rotation is not issuance"
                % (principal, claims["principal"]))
        if agent_id is not None and claims["sub"] != agent_id:
            raise UnregisteredPrincipalError(
                "agent_id %r is not the token-authenticated subject %r"
                % (agent_id, claims["sub"]))
        if claims["role"] != role:
            raise UnregisteredRoleError(
                "role %r is not the token-authenticated role %r; "
                "self-asserted roles are not issuance"
                % (role, claims["role"]))
        return True

    def allowed_roles(self, principal):
        """The role set authorized for *principal* by the presented
        token (a singleton), or raises for a mismatched principal."""
        self.check(principal)
        return {self._presented["role"]}

    def registered(self):
        """The token-authenticated principal set (singleton) or empty
        when no live token is presented."""
        try:
            return {self._live_claims(None)["principal"]}
        except UnregisteredPrincipalError:
            return set()
