"""MCP OAuth binding: authorization-server-bound client credentials.

W245-1 ADAPT (threat model, patterns only) of the MCP Python SDK
server-to-client OAuth theft shape (GHSA-qx49-fqc8-xw99), as PROSE
ONLY: no advisory text is read, copied, imported, or vendored here.
The
shape: a malicious server steals *client* OAuth material (client
secret, authorization code, PKCE verifier) by routing token exchange
to an attacker endpoint while its metadata names the real IdP as
issuer. The SDK fix (1.30.0/2.2.0) is configuration-gated: providers
that need ``issuer=`` passed stay vulnerable when it is omitted
("patched but still vulnerable by configuration"). This module
enforces, at the client path, that credentials bound to one
authorization server (AS) are never presented to another's token
endpoint, and that ``issuer`` is validated on EVERY discovery path,
never inferred from server-controlled metadata.

Model:

1. The deployment seals an AS binding under HMAC: the canonical
   issuer URL, the client identity, and an optional deployment-declared
   list of alternate token-endpoint origins (for AS deployments whose
   token endpoint legitimately lives off-issuer). An agent can hold
   the sealed binding but can never rebind it.
2. Server metadata is an EMITTER CLAIM (the ``gov.attested_channel``
   separation): it names an issuer, but identity comes ONLY from the
   sealed binding, never from the metadata. Metadata that names the
   bound issuer while pointing the token endpoint elsewhere refuses
   ``mcp-oauth-issuer-unbound``.
3. The SDK's ``issuer=`` parameter (deployment-configured) is
   compared against the bound issuer on every exchange. Omission for
   a provider that requires it refuses ``mcp-oauth-fix-gap-refused``
   -- fail closed, never silent fallback (probe c).
4. Credential reuse is per-AS: a credential stored under AS-X's
   issuer presented at AS-Y's token endpoint refuses
   ``mcp-oauth-credential-misbound`` (probes b, e).

The choke point: ``run_bound_exchange(verdict, token_endpoint,
exchange_fn)`` executes ``exchange_fn`` only when the verdict was
granted for exactly that endpoint; a replayed verdict refuses
``mcp-oauth-verdict-mismatched``. The exchanger never sees the
binding, only the verdict.

Composition: the verdict carries ``issuer_digest``, the sha256 of the
canonical issuer. Downstream issuance (e.g. ``gov.token_scope_enforcement``
grants) can bind minted tokens to this issuer digest so a scope grant
minted off a stolen-credential exchange cannot be laundered into the
bound session. Scope enforcement itself is not duplicated here.

Refusal vocabulary (domain ``mcp-oauth``, all fail-closed):

* ``mcp-oauth-issuer-unbound`` -- the token endpoint's origin is not
  the bound issuer's origin nor a deployment-declared alternate.
* ``mcp-oauth-issuer-unverified`` -- the issuer hint / metadata
  issuer names a different issuer than the sealed binding.
* ``mcp-oauth-metadata-malformed`` -- a presented runtime input
  (binding wrapper, endpoint, issuer hint, metadata, flag) is
  malformed.
* ``mcp-oauth-credential-misbound`` -- credential stored under AS-X
  presented at AS-Y's token endpoint.
* ``mcp-oauth-fix-gap-refused`` -- ``issuer=`` omitted for a provider
  that requires it.
* ``mcp-oauth-key-missing`` -- no deployment key supplied; fails
  closed (no dev-key fallback).
* ``mcp-oauth-binding-tampered`` -- the sealed binding's MAC does not
  cover its bytes (tamper reported as tamper, never as a shape gap).
* ``mcp-oauth-verdict-mismatched`` -- a verdict presented for a
  different token endpoint than it was granted for.

Honest boundaries:
- Binding MACs prove shared-secret authenticity (HMAC), not
  non-repudiation; key custody is deployment-owned.
- Issuer canonicalization trusts DNS/URL normalization only as far
  as the string: https scheme is required (plain http is refused
  outright -- OAuth bearer material never travels over it).
- This layer does not fetch metadata over the network; discovery
  transport (TLS pinning, redirect behavior) is deployment-owned.
  Server metadata arrives as an already-fetched dict.
- The credential's own material (client secret, codes, verifiers)
  never passes through this layer; only the AS-issuer label it is
  stored under is checked.

Stdlib only. Deterministic: no I/O, no network, no clock reads.
"""

import hashlib
import hmac
import json
from typing import Any, Dict, List, Mapping, NamedTuple, Optional
from urllib.parse import urlsplit

MCP_OAUTH_ISSUER_UNBOUND = "mcp-oauth-issuer-unbound"
MCP_OAUTH_ISSUER_UNVERIFIED = "mcp-oauth-issuer-unverified"
MCP_OAUTH_METADATA_MALFORMED = "mcp-oauth-metadata-malformed"
MCP_OAUTH_CREDENTIAL_MISBOUND = "mcp-oauth-credential-misbound"
MCP_OAUTH_FIX_GAP_REFUSED = "mcp-oauth-fix-gap-refused"
MCP_OAUTH_KEY_MISSING = "mcp-oauth-key-missing"
MCP_OAUTH_BINDING_TAMPERED = "mcp-oauth-binding-tampered"
MCP_OAUTH_VERDICT_MISMATCHED = "mcp-oauth-verdict-mismatched"

CODES = (
    MCP_OAUTH_ISSUER_UNBOUND,
    MCP_OAUTH_ISSUER_UNVERIFIED,
    MCP_OAUTH_METADATA_MALFORMED,
    MCP_OAUTH_CREDENTIAL_MISBOUND,
    MCP_OAUTH_FIX_GAP_REFUSED,
    MCP_OAUTH_KEY_MISSING,
    MCP_OAUTH_BINDING_TAMPERED,
    MCP_OAUTH_VERDICT_MISMATCHED,
)

_BINDING_DOMAIN = b"gov-mcp-oauth-binding/v1\x00"
_BINDING_VERSION = 1


class McpOAuthError(Exception):
    """Fail-closed OAuth binding refusal. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        super(McpOAuthError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _refuse(code, detail=""):
    raise McpOAuthError(code, detail)


def _canonical_bytes(obj):
    """RFC-8785-shaped canonical bytes (sorted keys, minimal separators)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _mac(key, domain, body):
    return hmac.new(key, domain + _canonical_bytes(body),
                    hashlib.sha256).hexdigest()


def _require_nonempty_str(value, name):
    if not isinstance(value, str) or not value:
        _refuse(MCP_OAUTH_METADATA_MALFORMED,
                "%s must be a non-empty string" % (name,))
    return value


def _key_or_refuse(key):
    if not isinstance(key, bytes) or not key:
        _refuse(MCP_OAUTH_KEY_MISSING,
                "no deployment key supplied; failing closed "
                "(no dev-key fallback)")
    return key


def _normalize_url(value, name):
    """Canonicalize an issuer/endpoint URL. Fail closed on shape."""
    _require_nonempty_str(value, name)
    try:
        parts = urlsplit(value)
    except Exception:  # noqa: BLE001
        _refuse(MCP_OAUTH_METADATA_MALFORMED,
                "%s %r is not a parseable URL" % (name, value))
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    host = host.lower()
    if scheme != "https" or not host:
        _refuse(MCP_OAUTH_METADATA_MALFORMED,
                "%s %r must be an https URL with a host" % (name, value))
    port = parts.port
    netloc = host if port in (None, 443) else "%s:%d" % (host, port)
    path = parts.path.rstrip("/") if parts.path else ""
    if not isinstance(port, (int, type(None))):
        _refuse(MCP_OAUTH_METADATA_MALFORMED,
                "%s %r has an unparseable port" % (name, value))
    return "https://%s%s" % (netloc, path)


def _origin(canonical_url):
    parts = urlsplit(canonical_url)
    return "%s://%s" % (parts.scheme, parts.netloc)


class OAuthVerdict(NamedTuple):
    """Granted token-exchange authorization for one endpoint.

    ``issuer_digest`` is the sha256 of the canonical issuer: it binds
    the exchange to the exact AS so downstream issuance (e.g. scope
    grants) can chain to it. ``binding_digest`` binds the verdict to
    the exact sealed binding bytes.
    """
    issuer: str
    token_endpoint: str
    issuer_digest: str
    binding_digest: str


def seal_as_binding(as_issuer, client_id, key,
                    token_endpoint_allowlist=None):
    """Seal a deployment's AS binding under the deployment key.

    ``token_endpoint_allowlist`` is optional: a list of endpoint URLs
    whose origins are deployment-declared alternates for the token
    endpoint (an AS whose token endpoint legitimately lives
    off-issuer). It is sealed with the binding: an agent cannot add
    an attacker origin to it.
    """
    key = _key_or_refuse(key)
    issuer = _normalize_url(as_issuer, "as_issuer")
    _require_nonempty_str(client_id, "client_id")
    allowlist = []
    if token_endpoint_allowlist is not None:
        if not isinstance(token_endpoint_allowlist, (list, tuple)):
            _refuse(MCP_OAUTH_METADATA_MALFORMED,
                    "token_endpoint_allowlist must be a list")
        for endpoint in token_endpoint_allowlist:
            allowlist.append(_normalize_url(endpoint, "allowlist endpoint"))
    body = {"v": _BINDING_VERSION, "issuer": issuer,
            "client_id": client_id,
            "token_endpoint_allowlist": allowlist}
    return {"binding": body,
            "mac": _mac(key, _BINDING_DOMAIN, body)}


def _unseal_binding(sealed_binding, key):
    """Authenticate the sealed binding; return (binding, digest)."""
    key = _key_or_refuse(key)
    if not isinstance(sealed_binding, dict):
        _refuse(MCP_OAUTH_METADATA_MALFORMED,
                "sealed binding must be a dict")
    binding = sealed_binding.get("binding")
    mac = sealed_binding.get("mac")
    if not isinstance(binding, dict) or not isinstance(mac, str) or not mac:
        _refuse(MCP_OAUTH_METADATA_MALFORMED,
                "sealed binding must carry a binding dict and a MAC")
    if binding.get("v") != _BINDING_VERSION:
        _refuse(MCP_OAUTH_METADATA_MALFORMED,
                "unsupported binding version %r" % (binding.get("v"),))
    for field in ("issuer", "client_id", "token_endpoint_allowlist"):
        if field not in binding:
            _refuse(MCP_OAUTH_METADATA_MALFORMED,
                    "binding missing field %r" % (field,))
    if not hmac.compare_digest(_mac(key, _BINDING_DOMAIN, binding), mac):
        _refuse(MCP_OAUTH_BINDING_TAMPERED,
                "binding MAC does not cover the presented bytes")
    # Shape re-check: a binding that cannot be a binding is untrusted.
    _normalize_url(binding["issuer"], "binding issuer")
    _require_nonempty_str(binding["client_id"], "binding client_id")
    if not isinstance(binding["token_endpoint_allowlist"], list):
        _refuse(MCP_OAUTH_BINDING_TAMPERED,
                "binding allowlist is not a list")
    digest = hashlib.sha256(_canonical_bytes(binding)).hexdigest()
    return binding, digest


def _allowed_origins(binding):
    """Origins a token endpoint may live on: issuer origin plus any
    deployment-declared alternates."""
    origins = {_origin(binding["issuer"])}
    for endpoint in binding["token_endpoint_allowlist"]:
        origins.add(_origin(_normalize_url(endpoint, "allowlist endpoint")))
    return origins


def _issuer_digest(issuer):
    return hashlib.sha256(issuer.encode("utf-8")).hexdigest()


def _check_endpoint_origin(token_endpoint, binding):
    endpoint = _normalize_url(token_endpoint, "token_endpoint")
    if _origin(endpoint) not in _allowed_origins(binding):
        _refuse(MCP_OAUTH_ISSUER_UNBOUND,
                "token endpoint origin %r is not the bound AS origin "
                "nor a deployment-declared alternate"
                % (_origin(endpoint),))
    return endpoint


def authorize_token_exchange(sealed_binding, token_endpoint, key,
                             issuer_hint=None,
                             presented_as_issuer=None,
                             provider_requires_issuer=True):
    """Authorize one token exchange before client material is used.

    Check order (fixed): input shape -> key -> binding
    re-authentication -> fix-gap (issuer omitted where required) ->
    issuer-hint verification -> credential AS binding -> token-endpoint
    origin. Returns an :class:`OAuthVerdict` on success; raises
    :class:`McpOAuthError` otherwise.

    ``issuer_hint`` is the SDK's ``issuer=`` value
    (deployment-configured, never server-derived). ``None`` is
    allowed only when ``provider_requires_issuer`` is False.
    ``presented_as_issuer`` is the AS issuer the presented credential
    is stored under: a credential stored under AS-X presented at
    AS-Y's token endpoint refuses ``mcp-oauth-credential-misbound``.
    """
    if not isinstance(provider_requires_issuer, bool):
        _refuse(MCP_OAUTH_METADATA_MALFORMED,
                "provider_requires_issuer must be a bool")
    _require_nonempty_str(token_endpoint, "token_endpoint")
    if issuer_hint is not None:
        _require_nonempty_str(issuer_hint, "issuer_hint")
    if presented_as_issuer is not None:
        _require_nonempty_str(presented_as_issuer, "presented_as_issuer")

    binding, binding_digest = _unseal_binding(sealed_binding, key)

    # The 1.30.0 fix-gap: a provider that requires issuer= fails
    # closed when it is omitted, never silently falls back.
    if provider_requires_issuer and issuer_hint is None:
        _refuse(MCP_OAUTH_FIX_GAP_REFUSED,
                "provider requires an explicit issuer; none supplied "
                "(no silent fallback)")
    if issuer_hint is not None:
        hint = _normalize_url(issuer_hint, "issuer_hint")
        if hint != binding["issuer"]:
            _refuse(MCP_OAUTH_ISSUER_UNVERIFIED,
                    "issuer hint names %r; binding names %r"
                    % (hint, binding["issuer"]))

    # Credential reuse is per-AS: the label the credential is stored
    # under must equal the bound issuer.
    if presented_as_issuer is not None:
        stored = _normalize_url(presented_as_issuer,
                                "presented_as_issuer")
        if stored != binding["issuer"]:
            _refuse(MCP_OAUTH_CREDENTIAL_MISBOUND,
                    "credential stored under %r presented at %r's "
                    "token endpoint" % (stored, binding["issuer"]))

    endpoint = _check_endpoint_origin(token_endpoint, binding)
    issuer = binding["issuer"]
    return OAuthVerdict(issuer=issuer, token_endpoint=endpoint,
                        issuer_digest=_issuer_digest(issuer),
                        binding_digest=binding_digest)


def check_server_metadata(sealed_binding, metadata, key):
    """Check a server's discovery metadata against the sealed binding.

    ``metadata`` is an EMITTER CLAIM (server-supplied): it names an
    ``issuer`` and a ``token_endpoint``, but identity comes only from
    the sealed binding. A metadata issuer that differs from the bound
    issuer refuses ``mcp-oauth-issuer-unverified``; a token endpoint
    outside the bound origin refuses ``mcp-oauth-issuer-unbound``
    (the (a) attack shape: real IdP named as issuer, exchange routed
    to an attacker).
    """
    binding, binding_digest = _unseal_binding(sealed_binding, key)
    if not isinstance(metadata, dict):
        _refuse(MCP_OAUTH_METADATA_MALFORMED,
                "server metadata must be a dict")
    for field in ("issuer", "token_endpoint"):
        if field not in metadata:
            _refuse(MCP_OAUTH_METADATA_MALFORMED,
                    "metadata missing field %r" % (field,))
    claimed = _normalize_url(metadata["issuer"], "metadata issuer")
    if claimed != binding["issuer"]:
        _refuse(MCP_OAUTH_ISSUER_UNVERIFIED,
                "metadata names %r; binding names %r"
                % (claimed, binding["issuer"]))
    endpoint = _check_endpoint_origin(metadata["token_endpoint"], binding)
    issuer = binding["issuer"]
    return OAuthVerdict(issuer=issuer, token_endpoint=endpoint,
                        issuer_digest=_issuer_digest(issuer),
                        binding_digest=binding_digest)


def run_bound_exchange(verdict, token_endpoint, exchange_fn):
    """Execute ``exchange_fn`` only on an exact verdict match.

    The choke point: the exchange signature requires the verdict
    object. A verdict granted for another endpoint refuses
    ``mcp-oauth-verdict-mismatched`` and the exchange never runs.
    """
    if not isinstance(verdict, OAuthVerdict):
        _refuse(MCP_OAUTH_VERDICT_MISMATCHED,
                "no OAuth verdict presented to the exchanger")
    if verdict.token_endpoint != _normalize_url(token_endpoint,
                                                "token_endpoint"):
        _refuse(MCP_OAUTH_VERDICT_MISMATCHED,
                "verdict granted for %r, presented for %r"
                % (verdict.token_endpoint, token_endpoint))
    return exchange_fn()
