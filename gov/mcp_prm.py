"""RFC 9728 Protected Resource Metadata verification for MCP OAuth clients.

Wave-334 lane 3 (F419 closure). The base tree had no Protected
Resource Metadata verification primitive at all: a resource's PRM
document (RFC 9728 section 3.2) was never cross-checked against the
sealed authorization-server binding, so an integrator following RFC
9728 for AS discovery -- read the PRM, pick ``authorization_servers``,
including via a section 5.2 ``WWW-Authenticate`` rotation -- could be
steered to an attacker AS, and a mismatched ``resource`` value was
never refused. There was no code path taking ``(sealed_binding,
prm_document)``; the contradiction was silent by absence.

This module provides the verified primitive. Stdlib only. The
verification core is deterministic: no I/O, no network, no clock
reads. The only I/O is ``fetch_prm_document``'s caller-supplied
``fetcher`` callable (deployment-owned transport); ``fetcher=None``
refuses ``mcp-oauth-prm-fetch-refused`` -- this layer never performs
implicit network I/O.

Model (RFC 9728, verified against the primary source):

1. ``derive_prm_url(resource_server)`` -- pure section 3.1: insert
   ``/.well-known/oauth-protected-resource`` between the host and the
   path/query of the deployment-configured resource identifier (any
   terminating slash after the host is removed first; the resource
   identifier must not carry a query or fragment).
2. ``check_prm_url(prm_url, resource_server)`` -- pure SSRF/shape
   guards (section 7.7: clients SHOULD block internal ranges):
   https only, no userinfo, no fragment, the host must not be an IP
   literal in a special range (private/loopback/link-local/multicast/
   reserved/unspecified), and the URL must be same-origin as the
   resource server (the metadata URL is derived from the
   deployment-configured resource identifier; a cross-origin metadata
   URL refuses ``mcp-oauth-prm-cross-origin``).
3. ``parse_challenge_resource_metadata(header, resource_server)`` --
   pure section 5.1: extract the ``resource_metadata`` parameter from
   a ``WWW-Authenticate`` header and validate it through
   ``check_prm_url``.
4. ``verify_prm_document(sealed_binding, resource_server,
   prm_document, key)`` -- pure: shape-validates the PRM JSON
   (section 2/3.2), checks the ``resource`` value against the
   deployment-configured resource identifier (section 3.3
   impersonation shape: mismatch refuses
   ``mcp-oauth-prm-resource-mismatched``), and cross-checks
   ``authorization_servers`` against the sealed binding's issuer
   (section 4/7.6: a listed set that omits the bound issuer is the
   AS-substitution shape and refuses
   ``mcp-oauth-prm-issuer-unlisted``). Returns a ``PrmVerdict``.
5. ``fetch_prm_document(prm_url, resource_server, fetcher)`` -- thin
   shell: validates the URL via ``check_prm_url`` FIRST, then
   delegates transport to the caller-supplied ``fetcher(url)``.
6. ``discover_and_verify_prm(...)`` -- the end-to-end primitive:
   derive (or parse from a challenge) -> fetch -> verify.

Refusal vocabulary (domain ``mcp-oauth``, all fail-closed):

* ``mcp-oauth-prm-malformed`` -- a PRM document, PRM URL, or resource
  identifier is malformed (shape validation, RFC 9728 section 2/3.2).
* ``mcp-oauth-prm-resource-mismatched`` -- the PRM ``resource`` value
  is not the deployment-configured resource identifier (section 3.3
  impersonation shape).
* ``mcp-oauth-prm-issuer-unlisted`` -- ``authorization_servers`` is
  present but does not list the sealed binding's issuer
  (AS-substitution shape).
* ``mcp-oauth-prm-fetch-refused`` -- no fetcher supplied, fetcher not
  callable, fetcher raised, or the URL failed the SSRF guards: the
  fetch does not happen, fail-closed, never implicit network.
* ``mcp-oauth-prm-challenge-malformed`` -- the ``WWW-Authenticate``
  header is unparsable, carries no ``resource_metadata`` parameter,
  or carries contradictory ones.
* ``mcp-oauth-prm-cross-origin`` -- the ``resource_metadata`` URL is
  not same-origin as the resource server.

Honest boundaries:
- DNS-rebinding defense is deployment-owned: IP literals in special
  ranges are rejected, but a DNS name resolving to an internal
  address can only be stopped at connect time -- the fetcher should
  pin the resolved IP or use a hardened resolver. A deployment that
  legitimately serves PRM from an internal address should fetch via
  its own hardened path and feed the document to
  ``verify_prm_document`` directly (the pure verifier has no IP
  opinion).
- ``signed_metadata`` (JWT): accepted as a string and shape-checked;
  signature verification is out of scope -- it needs a
  deployment-owned trust root.
- URL comparison is on canonical forms (the ``mcp_oauth_binding``
  URL contract: lowercase host, default-port elision, trailing-slash
  strip); RFC 9728 section 6 forbids Unicode normalization, which is
  not performed here.
- A non-numeric port in a PRM-controlled URL is refused coded
  ``mcp-oauth-prm-malformed`` at this seam. The shared
  ``_normalize_url``'s bare ``ValueError`` on ports is F417 (OPEN)
  and is NOT closed here -- this wrapper only contains the defect at
  this module's seam.
"""

import hashlib
import ipaddress
import re
from typing import NamedTuple, Tuple
from urllib.parse import urlsplit

from gov import mcp_oauth_binding as _mob

MCP_OAUTH_PRM_MALFORMED = "mcp-oauth-prm-malformed"
MCP_OAUTH_PRM_RESOURCE_MISMATCHED = "mcp-oauth-prm-resource-mismatched"
MCP_OAUTH_PRM_ISSUER_UNLISTED = "mcp-oauth-prm-issuer-unlisted"
MCP_OAUTH_PRM_FETCH_REFUSED = "mcp-oauth-prm-fetch-refused"
MCP_OAUTH_PRM_CHALLENGE_MALFORMED = "mcp-oauth-prm-challenge-malformed"
MCP_OAUTH_PRM_CROSS_ORIGIN = "mcp-oauth-prm-cross-origin"

CODES = (
    MCP_OAUTH_PRM_MALFORMED,
    MCP_OAUTH_PRM_RESOURCE_MISMATCHED,
    MCP_OAUTH_PRM_ISSUER_UNLISTED,
    MCP_OAUTH_PRM_FETCH_REFUSED,
    MCP_OAUTH_PRM_CHALLENGE_MALFORMED,
    MCP_OAUTH_PRM_CROSS_ORIGIN,
)

_WELL_KNOWN = "/.well-known/oauth-protected-resource"

# key="value" (quoted-string, may contain commas) or key=token.
_CHALLENGE_PARAM_RE = re.compile(
    r"([A-Za-z0-9_-]+)\s*=\s*(\"[^\"]*\"|[^,\s]+)")


def _refuse(code, detail=""):
    raise _mob.McpOAuthError(code, detail)


def _safe_normalize(value, name):
    """Canonicalize a PRM-controlled URL.

    The shared ``_normalize_url`` raises a bare ``ValueError`` on a
    non-numeric port (F417, OPEN against that function). At this
    seam the defect is contained: the bare error becomes the coded
    ``mcp-oauth-prm-malformed`` refusal. F417 itself is not closed
    here.
    """
    try:
        return _mob._normalize_url(value, name)
    except ValueError:
        _refuse(MCP_OAUTH_PRM_MALFORMED,
                "%s %r is not a valid URL" % (name, value))


def _require_nonempty_str(value, name):
    if not isinstance(value, str) or not value:
        _refuse(MCP_OAUTH_PRM_MALFORMED,
                "%s must be a non-empty string" % (name,))
    return value


def _raw_url_guards(url, label):
    """Raw-parse guards shared by the PRM URL entry points.

    Userinfo and fragment are checked on the RAW parse because the
    canonicalizer silently drops them (hostname excludes userinfo).
    IPv6 literals are refused: the shared ``_normalize_url`` strips
    the brackets when reassembling (``https://[::1]/x`` becomes the
    corrupt ``https://::1/x``), so this seam refuses them coded
    rather than emitting a corrupt URL. That normalizer defect is in
    the F417 family (OPEN, against ``_normalize_url``) and is not
    closed here.
    """
    try:
        raw = urlsplit(url)
    except ValueError:
        _refuse(MCP_OAUTH_PRM_MALFORMED,
                "%s %r is not a parseable URL" % (label, url))
    if raw.username or raw.password:
        _refuse(MCP_OAUTH_PRM_FETCH_REFUSED,
                "%s carries userinfo" % (label,))
    if raw.fragment:
        _refuse(MCP_OAUTH_PRM_FETCH_REFUSED,
                "%s carries a fragment" % (label,))
    host = raw.hostname or ""
    if ":" in host:
        _refuse(MCP_OAUTH_PRM_MALFORMED,
                "%s carries an IPv6 literal, which the shared URL "
                "canonicalizer cannot reassemble (F417 family); "
                "refusing rather than emitting a corrupt URL" % (label,))
    return raw


def _reject_special_ip(host, url_label):
    """SSRF guard (RFC 9728 section 7.7): refuse IP literals in
    special ranges. DNS names pass through -- resolution-time
    defense is deployment-owned (documented above)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
        _refuse(MCP_OAUTH_PRM_FETCH_REFUSED,
                "%s host %r is an IP literal in a special range "
                "(SSRF guard, RFC 9728 section 7.7)" % (url_label, host))


def derive_prm_url(resource_server):
    """Derive the PRM URL from a resource identifier (RFC 9728 3.1).

    Inserts ``/.well-known/oauth-protected-resource`` between the
    host and the path of the deployment-configured resource
    identifier. The identifier must not carry a query or fragment
    (RFC 9728 section 1.2: the resource identifier SHOULD NOT include
    a query and MUST NOT include a fragment).
    """
    _require_nonempty_str(resource_server, "resource_server")
    raw = _raw_url_guards(resource_server, "resource_server")
    if raw.query:
        _refuse(MCP_OAUTH_PRM_MALFORMED,
                "resource_server %r must not carry a query "
                "(RFC 9728 resource identifier)" % (resource_server,))
    server = _safe_normalize(resource_server, "resource_server")
    parts = urlsplit(server)
    return "https://%s%s%s" % (parts.netloc, _WELL_KNOWN, parts.path)


def _origin_str(normalized_url):
    """Origin of a normalized URL via string parts only.

    Never touches ``.port``/``.hostname`` on a re-parsed normalized
    URL: the shared canonicalizer's IPv6 reassembly is corrupt
    (F417 family) and ``.port`` raises bare ``ValueError`` on it.
    """
    parts = urlsplit(normalized_url)
    return parts.scheme + "://" + parts.netloc


def check_prm_url(prm_url, resource_server):
    """SSRF/shape guards on a PRM URL. Returns the normalized URL.

    https only (a non-https URL fails the shared URL contract with
    ``mcp-oauth-metadata-malformed``), no userinfo, no fragment, the
    host must not be an IP literal in a special range
    (``mcp-oauth-prm-fetch-refused``), and the URL must be same-origin
    as the resource server (``mcp-oauth-prm-cross-origin``). Any
    violation refuses fail-closed.
    """
    _require_nonempty_str(prm_url, "prm_url")
    raw = _raw_url_guards(prm_url, "PRM URL")
    # SSRF guard before the origin check: a private/loopback/etc.
    # literal is the more specific threat signal.
    _reject_special_ip(raw.hostname or "", "PRM URL")
    meta = _safe_normalize(prm_url, "prm_url")
    server = _safe_normalize(resource_server, "resource_server")
    if _origin_str(meta) != _origin_str(server):
        _refuse(MCP_OAUTH_PRM_CROSS_ORIGIN,
                "PRM URL %r is not same-origin as the resource server "
                "%r" % (prm_url, resource_server))
    return meta


def parse_challenge_resource_metadata(challenge_header, resource_server):
    """Extract the RFC 9728 section 5.1 ``resource_metadata``
    parameter from a ``WWW-Authenticate`` header and validate it.

    Returns the normalized, SSRF-guarded metadata URL. A header with
    no ``resource_metadata`` parameter, an empty value, or
    contradictory values refuses ``mcp-oauth-prm-challenge-malformed``.
    """
    if not isinstance(challenge_header, str):
        _refuse(MCP_OAUTH_PRM_MALFORMED,
                "challenge_header must be a string")
    if not challenge_header:
        _refuse(MCP_OAUTH_PRM_CHALLENGE_MALFORMED,
                "empty WWW-Authenticate header: no challenge to parse")
    values = []
    for match in _CHALLENGE_PARAM_RE.finditer(challenge_header):
        key, value = match.group(1), match.group(2)
        if key == "resource_metadata":
            if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
                value = value[1:-1]
            values.append(value)
    if not values:
        _refuse(MCP_OAUTH_PRM_CHALLENGE_MALFORMED,
                "WWW-Authenticate carries no resource_metadata "
                "parameter (RFC 9728 section 5.1)")
    distinct = set(values)
    if len(distinct) > 1:
        _refuse(MCP_OAUTH_PRM_CHALLENGE_MALFORMED,
                "WWW-Authenticate carries contradictory "
                "resource_metadata values")
    if not values[0]:
        _refuse(MCP_OAUTH_PRM_CHALLENGE_MALFORMED,
                "resource_metadata parameter is empty")
    return check_prm_url(values[0], resource_server)


def _check_url_field(doc, field):
    value = doc[field]
    if not isinstance(value, str) or not value:
        _refuse(MCP_OAUTH_PRM_MALFORMED,
                "PRM field %r must be a non-empty string" % (field,))
    _safe_normalize(value, "PRM field %r" % (field,))


def _check_string_list_field(doc, field, allow_empty=False):
    value = doc[field]
    if (not isinstance(value, list) or (not allow_empty and not value)
            or not all(isinstance(s, str) and s for s in value)):
        _refuse(MCP_OAUTH_PRM_MALFORMED,
                "PRM field %r must be a non-empty array of non-empty "
                "strings" % (field,))


def _check_prm_shapes(doc):
    """Shape-check the security-relevant PRM fields (RFC 9728 2/3.2).

    Unknown fields are ignored per section 3.2. ``resource`` and
    ``authorization_servers`` are checked by the caller (they carry
    the binding semantics).
    """
    for field in ("jwks_uri", "resource_documentation",
                  "resource_policy_uri", "resource_tos_uri"):
        if field in doc:
            _check_url_field(doc, field)
    for field in ("scopes_supported",
                  "resource_signing_alg_values_supported",
                  "authorization_details_types_supported",
                  "dpop_signing_alg_values_supported"):
        if field in doc:
            _check_string_list_field(doc, field)
    if ("resource_signing_alg_values_supported" in doc
            and "none" in doc["resource_signing_alg_values_supported"]):
        _refuse(MCP_OAUTH_PRM_MALFORMED,
                "'none' MUST NOT appear in "
                "resource_signing_alg_values_supported "
                "(RFC 9728 section 2)")
    if "bearer_methods_supported" in doc:
        # The empty array is meaningful ("no Bearer <redacted> supported",
        # section 2); membership is the closed set.
        value = doc["bearer_methods_supported"]
        if (not isinstance(value, list)
                or not all(m in ("header", "body", "query")
                           for m in value)):
            _refuse(MCP_OAUTH_PRM_MALFORMED,
                    "PRM field 'bearer_methods_supported' must be an "
                    "array drawn from header/body/query")
    for field in ("tls_client_certificate_bound_access_tokens",
                  "dpop_bound_access_tokens_required"):
        if field in doc and not isinstance(doc[field], bool):
            _refuse(MCP_OAUTH_PRM_MALFORMED,
                    "PRM field %r must be a boolean" % (field,))
    if "signed_metadata" in doc:
        # Shape-checked only; signature verification needs a
        # deployment-owned trust root (documented boundary).
        value = doc["signed_metadata"]
        if not isinstance(value, str) or not value:
            _refuse(MCP_OAUTH_PRM_MALFORMED,
                    "PRM field 'signed_metadata' must be a non-empty "
                    "string")


class PrmVerdict(NamedTuple):
    """A verified PRM document.

    ``resource`` is the canonical deployment-configured resource
    identifier the document was verified against; ``issuer`` is the
    sealed binding's canonical issuer; ``issuer_digest`` correlates
    with ``OAuthVerdict.issuer_digest`` downstream;
    ``authorization_servers`` is the normalized listed set (empty
    when the document omits it -- omission is allowed by RFC 9728,
    the binding still governs).
    """
    resource: str
    issuer: str
    issuer_digest: str
    authorization_servers: Tuple[str, ...]


def verify_prm_document(sealed_binding, resource_server, prm_document, key):
    """Verify a PRM document against the sealed AS binding.

    Check order (fixed): resource identifier shape -> document shape
    -> binding re-authentication -> ``resource`` equality (section
    3.3) -> ``authorization_servers`` cross-check (section 4/7.6) ->
    remaining field shapes. Returns a :class:`PrmVerdict` on success;
    raises :class:`McpOAuthError` otherwise.
    """
    _require_nonempty_str(resource_server, "resource_server")
    try:
        raw = urlsplit(resource_server)
    except ValueError:
        _refuse(MCP_OAUTH_PRM_MALFORMED,
                "resource_server %r is not a parseable URL"
                % (resource_server,))
    if raw.query or raw.fragment:
        _refuse(MCP_OAUTH_PRM_MALFORMED,
                "resource_server %r must not carry a query or fragment"
                % (resource_server,))
    server = _safe_normalize(resource_server, "resource_server")
    if not isinstance(prm_document, dict):
        _refuse(MCP_OAUTH_PRM_MALFORMED,
                "PRM document must be a JSON object")

    # The binding is the trust anchor: unseal before any semantic
    # check so a tampered binding refuses binding-tampered, never a
    # PRM shape error.
    issuer = _mob.bound_issuer(sealed_binding, key)

    resource = prm_document.get("resource")
    if not isinstance(resource, str) or not resource:
        _refuse(MCP_OAUTH_PRM_MALFORMED,
                "PRM document is missing the required 'resource' "
                "parameter (RFC 9728 section 2)")
    claimed = _safe_normalize(resource, "PRM resource")
    if claimed != server:
        _refuse(MCP_OAUTH_PRM_RESOURCE_MISMATCHED,
                "PRM resource %r is not the configured resource %r "
                "(RFC 9728 section 3.3; data MUST NOT be used)"
                % (claimed, server))

    auth_servers = ()
    if "authorization_servers" in prm_document:
        listed = prm_document["authorization_servers"]
        if (not isinstance(listed, list) or not listed
                or not all(isinstance(s, str) and s for s in listed)):
            _refuse(MCP_OAUTH_PRM_MALFORMED,
                    "PRM 'authorization_servers' must be a non-empty "
                    "array of non-empty strings")
        auth_servers = tuple(_safe_normalize(s, "authorization_servers entry")
                             for s in listed)
        if issuer not in auth_servers:
            _refuse(MCP_OAUTH_PRM_ISSUER_UNLISTED,
                    "bound issuer %r is not listed in the PRM "
                    "authorization_servers %r (AS-substitution shape)"
                    % (issuer, auth_servers))

    _check_prm_shapes(prm_document)
    digest = hashlib.sha256(issuer.encode("utf-8")).hexdigest()
    return PrmVerdict(resource=server, issuer=issuer,
                      issuer_digest=digest,
                      authorization_servers=auth_servers)


def fetch_prm_document(prm_url, resource_server, fetcher):
    """Fetch a PRM document through a deployment-supplied fetcher.

    The URL is validated (SSRF/shape guards) BEFORE the fetcher
    runs. ``fetcher`` is deployment-owned transport:
    ``fetcher(url) -> dict``. ``fetcher=None`` (or a non-callable)
    refuses ``mcp-oauth-prm-fetch-refused`` -- this layer never
    performs implicit network I/O. A fetcher that raises refuses
    ``mcp-oauth-prm-fetch-refused`` (coded ``McpOAuthError`` from the
    fetcher propagates untouched).
    """
    url = check_prm_url(prm_url, resource_server)
    if fetcher is None:
        _refuse(MCP_OAUTH_PRM_FETCH_REFUSED,
                "no fetcher supplied; refusing implicit network fetch "
                "(fail-closed)")
    if not callable(fetcher):
        _refuse(MCP_OAUTH_PRM_FETCH_REFUSED,
                "fetcher must be callable")
    try:
        doc = fetcher(url)
    except _mob.McpOAuthError:
        raise
    except Exception as exc:  # noqa: BLE001
        _refuse(MCP_OAUTH_PRM_FETCH_REFUSED,
                "fetcher raised %r" % (exc,))
    return doc


def discover_and_verify_prm(sealed_binding, resource_server, key,
                            fetcher, challenge_header=None):
    """End-to-end PRM discovery and verification.

    Derives the PRM URL (RFC 9728 section 3.1), or parses it from a
    ``WWW-Authenticate`` challenge when one is supplied (section
    5.1), fetches through the deployment-supplied fetcher, and
    verifies the document against the sealed binding. Returns a
    :class:`PrmVerdict`.
    """
    if challenge_header is not None:
        prm_url = parse_challenge_resource_metadata(challenge_header,
                                                   resource_server)
    else:
        prm_url = derive_prm_url(resource_server)
    doc = fetch_prm_document(prm_url, resource_server, fetcher)
    return verify_prm_document(sealed_binding, resource_server, doc, key)
