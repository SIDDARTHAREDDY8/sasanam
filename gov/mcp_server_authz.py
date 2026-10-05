"""MCP server-side per-request bearer-token guard (token-passthrough ban).

W333 prospectus STEAL #1 (w333_prospectus.md section 1b): the wave-332
MCP OAuth hardening is client-side -- ``gov.mcp_oauth_binding``
refuses ``mcp-oauth-resource-misbound`` when *the client* is about to
present a token at the wrong server. Nothing on the serving side
validated a presented token per request (F419): no 401 path existed
in gov/, so any MCP server built on the stack accepted whatever
token-shaped bytes arrived. This module is the server-side half:
the per-request gate a deployment calls before dispatching a
tool call.

Model (MCP Authorization spec, "Access Token Usage / Token
Handling"): MCP servers MUST validate that access tokens were issued
specifically for them as the intended audience (RFC 8707 Section 2)
and MUST NOT accept or transit any other tokens. Invalid/expired
tokens -> HTTP 401; insufficient scope -> HTTP 403 with
``error="insufficient_scope"``. The access token MUST NOT travel in
the query string.

Entry point: ``validate_bearer_request(resource_server,
authorization_header, verify_fn, *, expected_issuer, ...)``.

* ``resource_server`` / ``expected_issuer`` are deployment-configured
  knowledge (like the client-side ``issuer_hint``): never derived
  from request metadata or from the token itself.
* ``verify_fn`` is the deployment's token authenticator:
  ``token_string -> dict`` of verified claims. It raises (or returns
  a non-dict) for a token whose signature it will not vouch for.
  This module never verifies signatures itself and never trusts
  unverified bytes -- the same authenticity-boundary contract as
  ``gov.mcp_oauth_binding.check_token_resource``: binding/issuer/
  expiry checks on attacker-chosen bytes are meaningless, so the
  verifier runs FIRST and every check below runs only on
  verifier-vouched claims.
* Per-request checks, in order: token-in-query (refused, the token
  must not travel in the query string), Authorization header shape,
  verifier acceptance, time window (exp/nbf), issuer, resource
  binding (RFC 8707, wired through ``check_token_resource``), scope.
* Every failure raises :class:`McpServerAuthzError` with a machine
  code; ``http_status_for(code)`` maps the code to 401 (all token
  faults) or 403 (insufficient scope only -- audience mismatch is
  never 403); ``www_authenticate_challenge(...)`` builds the RFC 6750
  ``WWW-Authenticate`` value; ``refusal_response(...)`` returns the
  ``(status, challenge)`` pair the deployment emits.
* Success returns :class:`ServerAuthzVerdict` (resource, issuer,
  scopes, subject, token_digest). ``token_digest`` is the sha256 of
  the token for audit logging -- the token itself is never logged.

Refusal vocabulary (domain ``mcp-server-auth``, all fail-closed):

* ``mcp-server-auth-missing-token`` -- no Authorization header, or a
  blank one; the request carries no bearer token.
* ``mcp-server-auth-malformed`` -- the header is not a well-formed
  ``Bearer <b64token>`` (wrong scheme, empty token, illegal token
  characters), or a token claim has an unparseable shape (exp/nbf/iat
  non-numeric, scope non-string).
* ``mcp-server-auth-token-in-query`` -- an access-token-shaped query
  parameter is present; tokens must not travel in the query string.
* ``mcp-server-auth-token-invalid`` -- the deployment's verifier
  rejected the token (bad signature) or returned a non-dict.
* ``mcp-server-auth-token-expired`` -- ``exp`` is at or before now.
* ``mcp-server-auth-token-not-yet-valid`` -- ``nbf`` is after now.
* ``mcp-server-auth-issuer-missing`` -- the token carries no ``iss``.
* ``mcp-server-auth-issuer-mismatched`` -- ``iss`` names a different
  issuer than the deployment-configured ``expected_issuer``.
* ``mcp-server-auth-resource-missing`` -- the token carries no RFC
  8707 resource indicator (nor RFC 9068 ``aud``) for this server.
* ``mcp-server-auth-resource-misbound`` -- the token names a
  different protected resource than this server (RFC 8707
  cross-server replay: a token minted for server A replayed at
  server B).
* ``mcp-server-auth-insufficient-scope`` -- the token is valid but
  its ``scope`` does not cover every required scope (HTTP 403).

Honest boundaries:
- Signature verification is deployment-owned (``verify_fn``); this
  module checks authorization, not authenticity.
- ``iss`` comparison is exact-string: the deployment configures the
  canonical issuer form; near-miss forms (trailing slash, case)
  refuse rather than fuzzy-match.
- ``exp`` is required: a token without an expiry is malformed for
  this guard (RFC 9068 REQUIRES exp); fail closed, never open-ended.
- The challenge's ``error_description`` carries only the machine code
  and a short detail -- never token bytes, never stack internals.
  Control characters and quotes are stripped (header-injection safe).
- Time source: pass ``now`` (epoch seconds) for determinism; when
  omitted the module reads ``time.time()`` once per call.

Stdlib only.
"""

import hashlib
import re
import time
from typing import Any, Callable, Dict, FrozenSet, Mapping, NamedTuple, Optional, Tuple
from urllib.parse import parse_qsl

from gov.mcp_oauth_binding import (
    McpOAuthError,
    check_token_resource,
    MCP_OAUTH_METADATA_MALFORMED,
    MCP_OAUTH_RESOURCE_MISBOUND,
    MCP_OAUTH_RESOURCE_MISSING,
)

MCP_SERVER_AUTH_MISSING_TOKEN = "mcp-server-auth-missing-token"
MCP_SERVER_AUTH_MALFORMED = "mcp-server-auth-malformed"
MCP_SERVER_AUTH_TOKEN_IN_QUERY = "mcp-server-auth-token-in-query"
MCP_SERVER_AUTH_TOKEN_INVALID = "mcp-server-auth-token-invalid"
MCP_SERVER_AUTH_TOKEN_EXPIRED = "mcp-server-auth-token-expired"
MCP_SERVER_AUTH_TOKEN_NOT_YET_VALID = "mcp-server-auth-token-not-yet-valid"
MCP_SERVER_AUTH_ISSUER_MISSING = "mcp-server-auth-issuer-missing"
MCP_SERVER_AUTH_ISSUER_MISMATCHED = "mcp-server-auth-issuer-mismatched"
MCP_SERVER_AUTH_RESOURCE_MISSING = "mcp-server-auth-resource-missing"
MCP_SERVER_AUTH_RESOURCE_MISBOUND = "mcp-server-auth-resource-misbound"
MCP_SERVER_AUTH_INSUFFICIENT_SCOPE = "mcp-server-auth-insufficient-scope"

CODES = (
    MCP_SERVER_AUTH_MISSING_TOKEN,
    MCP_SERVER_AUTH_MALFORMED,
    MCP_SERVER_AUTH_TOKEN_IN_QUERY,
    MCP_SERVER_AUTH_TOKEN_INVALID,
    MCP_SERVER_AUTH_TOKEN_EXPIRED,
    MCP_SERVER_AUTH_TOKEN_NOT_YET_VALID,
    MCP_SERVER_AUTH_ISSUER_MISSING,
    MCP_SERVER_AUTH_ISSUER_MISMATCHED,
    MCP_SERVER_AUTH_RESOURCE_MISSING,
    MCP_SERVER_AUTH_RESOURCE_MISBOUND,
    MCP_SERVER_AUTH_INSUFFICIENT_SCOPE,
)

# RFC 6750 Appendix A: b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" /
# "~" / "+" / "/" ) *"="
_B64TOKEN_RE = re.compile(r"^[A-Za-z0-9\-._~+/]+={0,2}$")

# Query parameter names that carry a token (RFC 6750 2.3 forbids all of
# them in the query string).
_QUERY_TOKEN_NAMES = ("access_token", "token")


class McpServerAuthzError(Exception):
    """Fail-closed server-side authorization refusal.

    ``code`` is the machine code; ``http_status`` is 401 except for
    ``mcp-server-auth-insufficient-scope`` (403).
    """

    def __init__(self, code, detail=""):
        super(McpServerAuthzError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail

    @property
    def http_status(self):
        return http_status_for(self.code)


def _refuse(code, detail=""):
    raise McpServerAuthzError(code, detail)


def http_status_for(code):
    """Map a refusal code to its HTTP status (401, or 403 for scope)."""
    if code == MCP_SERVER_AUTH_INSUFFICIENT_SCOPE:
        return 403
    return 401


def _clean_detail(detail):
    """Strip header-injection characters from challenge details."""
    return re.sub(r'[\r\n"]', "", detail or "")[:160]


def www_authenticate_challenge(code, detail="",
                               resource_metadata_url=None, scopes=()):
    """Build the RFC 6750 WWW-Authenticate challenge for a refusal.

    ``error`` is ``insufficient_scope`` only for the scope code;
    every other refusal is ``invalid_token`` (audience mismatch is
    never ``insufficient_scope``). ``error_description`` carries the
    sasanam machine code, never token bytes. ``resource_metadata``
    names the RFC 9728 protected-resource metadata URL when the
    deployment serves one.
    """
    if code == MCP_SERVER_AUTH_INSUFFICIENT_SCOPE:
        error = "insufficient_scope"
    else:
        error = "invalid_token"
    desc = code
    cleaned = _clean_detail(detail)
    if cleaned:
        desc = "%s: %s" % (code, cleaned)
    parts = ['Bearer error="%s"' % error,
             'error_description="%s"' % desc]
    if resource_metadata_url:
        parts.append('resource_metadata="%s"'
                     % _clean_detail(resource_metadata_url))
    if scopes:
        parts.append('scope="%s"'
                     % _clean_detail(" ".join(scopes)))
    return ", ".join(parts)


def refusal_response(code, detail="", resource_metadata_url=None,
                     scopes=()):
    """Return the ``(http_status, www_authenticate)`` pair to emit."""
    return (http_status_for(code),
            www_authenticate_challenge(code, detail,
                                       resource_metadata_url, scopes))


class ServerAuthzVerdict(NamedTuple):
    """A granted per-request authorization.

    ``token_digest`` is sha256(token) for audit logging without
    logging the token. ``scopes`` is the token's granted scope set.
    """
    resource: str
    issuer: str
    scopes: FrozenSet[str]
    subject: Optional[str]
    token_digest: str


def _parse_bearer_token(authorization_header):
    """Extract the bearer token or refuse coded."""
    if authorization_header is None:
        _refuse(MCP_SERVER_AUTH_MISSING_TOKEN,
                "no Authorization header present")
    if not isinstance(authorization_header, str):
        _refuse(MCP_SERVER_AUTH_MALFORMED,
                "Authorization header must be a string")
    header = authorization_header.strip()
    if not header:
        _refuse(MCP_SERVER_AUTH_MISSING_TOKEN,
                "Authorization header is blank")
    parts = header.split(None, 1)
    if len(parts) != 2:
        _refuse(MCP_SERVER_AUTH_MALFORMED,
                "Authorization header is not '<scheme> <credentials>'")
    scheme, token = parts
    if scheme.lower() != "bearer":
        _refuse(MCP_SERVER_AUTH_MALFORMED,
                "authorization scheme %r is not Bearer" % scheme[:32])
    token = token.strip()
    if not token or not _B64TOKEN_RE.match(token):
        _refuse(MCP_SERVER_AUTH_MALFORMED,
                "bearer token is empty or not b64token-shaped")
    return token


def _reject_token_in_query(query_string):
    """Refuse when a token travels in the query string (RFC 6750 2.3)."""
    if not isinstance(query_string, str):
        _refuse(MCP_SERVER_AUTH_MALFORMED,
                "query_string must be a string")
    if not query_string:
        return
    try:
        params = parse_qsl(query_string, keep_blank_values=True)
    except Exception:  # noqa: BLE001
        _refuse(MCP_SERVER_AUTH_MALFORMED,
                "query string is not parseable")
    for name, _value in params:
        if name.lower() in _QUERY_TOKEN_NAMES:
            _refuse(MCP_SERVER_AUTH_TOKEN_IN_QUERY,
                    "access token in query string %r; tokens must "
                    "travel in the Authorization header" % name[:32])


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _check_time_window(claims, now):
    exp = claims.get("exp")
    if not _is_number(exp):
        _refuse(MCP_SERVER_AUTH_MALFORMED,
                "token has no numeric exp claim")
    if exp <= now:
        _refuse(MCP_SERVER_AUTH_TOKEN_EXPIRED,
                "token expired")
    nbf = claims.get("nbf")
    if nbf is not None:
        if not _is_number(nbf):
            _refuse(MCP_SERVER_AUTH_MALFORMED,
                    "token nbf claim is not numeric")
        if nbf > now:
            _refuse(MCP_SERVER_AUTH_TOKEN_NOT_YET_VALID,
                    "token not yet valid")
    iat = claims.get("iat")
    if iat is not None and not _is_number(iat):
        _refuse(MCP_SERVER_AUTH_MALFORMED,
                "token iat claim is not numeric")


def _check_issuer(claims, expected_issuer):
    iss = claims.get("iss")
    if not isinstance(iss, str) or not iss:
        _refuse(MCP_SERVER_AUTH_ISSUER_MISSING,
                "token carries no iss claim")
    if iss != expected_issuer:
        _refuse(MCP_SERVER_AUTH_ISSUER_MISMATCHED,
                "token issuer does not match the trusted issuer")


def _check_resource(resource_server, claims):
    """Audience check via the client-side binding vocabulary, remapped
    into the server domain."""
    try:
        return check_token_resource(resource_server, claims)
    except McpOAuthError as exc:
        if exc.code == MCP_OAUTH_RESOURCE_MISSING:
            _refuse(MCP_SERVER_AUTH_RESOURCE_MISSING, exc.detail)
        if exc.code == MCP_OAUTH_RESOURCE_MISBOUND:
            _refuse(MCP_SERVER_AUTH_RESOURCE_MISBOUND, exc.detail)
        # MCP_OAUTH_METADATA_MALFORMED or anything unexpected.
        _refuse(MCP_SERVER_AUTH_MALFORMED, exc.detail)


def _check_scope(claims, required_scopes):
    granted = set()
    scope = claims.get("scope")
    if scope is not None:
        if not isinstance(scope, str):
            _refuse(MCP_SERVER_AUTH_MALFORMED,
                    "token scope claim is not a string")
        granted = set(scope.split())
    missing = [s for s in required_scopes if s not in granted]
    if missing:
        _refuse(MCP_SERVER_AUTH_INSUFFICIENT_SCOPE,
                "token scope does not cover: %s" % " ".join(missing)[:120])
    return frozenset(granted)


def validate_bearer_request(resource_server, authorization_header,
                             verify_fn, *, expected_issuer,
                             required_scopes=(), resource_metadata_url=None,
                             query_string="", now=None):
    """Validate one incoming request's bearer token, fail-closed.

    ``resource_server`` is this server's deployment-configured URI;
    ``expected_issuer`` is the deployment-configured trusted issuer;
    ``verify_fn`` authenticates the token (``str -> dict`` claims,
    raising on rejection). ``required_scopes`` gates the call on
    token scope (empty = no scope gate). ``query_string`` is the raw
    query component (a token there is refused outright). ``now`` is
    epoch seconds (defaults to ``time.time()``).

    Returns :class:`ServerAuthzVerdict` on success; raises
    :class:`McpServerAuthzError` on every failure. The deployment
    translates the error via :func:`refusal_response` into the HTTP
    401/403 + ``WWW-Authenticate`` it emits.
    """
    if not isinstance(expected_issuer, str) or not expected_issuer:
        _refuse(MCP_SERVER_AUTH_MALFORMED,
                "expected_issuer must be a non-empty string")
    _reject_token_in_query(query_string)
    token = _parse_bearer_token(authorization_header)
    try:
        claims = verify_fn(token)
    except McpServerAuthzError:
        raise
    except Exception as exc:  # noqa: BLE001
        _refuse(MCP_SERVER_AUTH_TOKEN_INVALID,
                "token verifier rejected the token (%s)"
                % type(exc).__name__)
    if not isinstance(claims, dict):
        _refuse(MCP_SERVER_AUTH_TOKEN_INVALID,
                "token verifier returned a non-dict")
    at = time.time() if now is None else now
    if not _is_number(at):
        _refuse(MCP_SERVER_AUTH_MALFORMED,
                "now must be numeric epoch seconds")
    _check_time_window(claims, at)
    _check_issuer(claims, expected_issuer)
    resource = _check_resource(resource_server, claims)
    scopes = _check_scope(claims, tuple(required_scopes))
    return ServerAuthzVerdict(
        resource=resource,
        issuer=claims["iss"],
        scopes=scopes,
        subject=claims.get("sub") if isinstance(
            claims.get("sub"), str) else None,
        token_digest=hashlib.sha256(token.encode("utf-8")).hexdigest(),
    )
