#!/usr/bin/env python3
"""Client ID Metadata Document (CIMD) safe-subset validation.

Wave-337 lane 3 (builds w336 research prospectus R1/R2, section 1).

Implements the safe subset of ``draft-ietf-oauth-client-id-metadata-document-02``
(IETF draft, dated 2026-07-06; patterns only -- no draft text or code extracted).
Stdlib only. No network. The verification core never does implicit I/O: the
only I/O is the pre-registration intake's caller-supplied ``fetcher`` and
``resolver`` callables (deployment-owned transport and DNS); ``fetcher=None``
is a programming error (TypeError), never silent network.

Three surfaces:

A. EMISSION (client role). ``emit_document`` renders the static document for
   the deployment-configured endpoint ``https://<domain>/oauth/client`` and
   ``serve_document`` returns the serving contract (200, application/json,
   canonical bytes). Zero SSRF: the domain comes from deployment config,
   never from agent input.

B. URL SHAPE + DOCUMENT BINDING (pure, no fetch). ``validate_client_id_url``
   enforces the 9-row rule table (7 as-spec, 2 stricter fail-closed);
   ``check_document_binding`` enforces the draft section 4 binding rule
   (client_id string-equals the fetch URL -- simple string comparison per
   RFC 3986 section 6.2.1); ``validate_document_shape`` enforces the
   inbound document contract.

C. PRE-REGISTRATION INTAKE (draft section 7.2 pattern). ``onboard_cimd``
   fetches ONCE at operator-driven onboarding -- never at request time --
   with the full fetch control set, pins ``sha256(document_bytes)`` plus
   the jwks content hash, and ``reonboard_cimd`` detects key rotation and
   emits a revocation-shaped event into the deployment's revocation sink.
   ``verify_pinned`` is the request-time check (pinned copy only).

Refusal vocabulary (domain ``mcp-oauth``, all fail-closed, all registered in
gov/decision_codes.py):

* ``mcp-oauth-cimd-url-not-https`` -- the client_id URL is not a valid https
  URL per the section 3 shape (wrong scheme, invalid syntax, raw control
  characters -- the F423 lesson: controls are refused before parsing, never
  stripped).
* ``mcp-oauth-cimd-url-userinfo`` -- userinfo component present (section 3
  MUST NOT).
* ``mcp-oauth-cimd-url-dot-segment`` -- '.' or '..' path segment (section 3
  MUST NOT; percent-encoded forms included).
* ``mcp-oauth-cimd-url-query`` -- query component present (stricter than the
  draft SHOULD NOT).
* ``mcp-oauth-cimd-url-fragment`` -- fragment component present (section 3
  MUST NOT).
* ``mcp-oauth-cimd-url-root-path`` -- empty or '/' path (stricter than the
  draft NOT RECOMMENDED; also covers the section 3 "path MUST be present").
* ``mcp-oauth-cimd-binding-mismatch`` -- document client_id does not
  string-equal the fetch URL, or the presented document does not match the
  pinned bytes (the pin IS the document binding; a pin mismatch is a binding
  break -- this deliberately folds the prospectus's ``pin-mismatch`` case).
* ``mcp-oauth-cimd-document-malformed`` -- the document violates the
  emission/shape contract (not a record, bad client_id, private_key_jwt
  without a discoverable https jwks_uri, logo_uri not https, bad deployment
  domain at emission).
* ``mcp-oauth-cimd-credential-present`` -- a client_secret* member is
  present (credential smuggling via metadata; refused, never ignored).
* ``mcp-oauth-cimd-redirect-origin-mismatch`` -- a redirect_uri is not https
  or not same-origin with the document origin (the unconditional section 8.1
  restriction, applied symmetrically inbound).
* ``mcp-oauth-cimd-fetch-redirect`` -- the fetch returned a redirect
  (never followed, section 5).
* ``mcp-oauth-cimd-fetch-non200`` -- no 200 OK document was retrieved
  (non-200 status or transport failure).
* ``mcp-oauth-cimd-fetch-ssrf-range`` -- the fetch target is outside the
  deployment fetch trust: RFC 6890 special-use range, DNS-rebind IP
  mismatch, resolution failure, or domain outside the configured allowlist
  (section 8.6; the DNS-pin and allowlist are documented stricter-than-draft
  additions folded into this fetch-trust code).
* ``mcp-oauth-cimd-fetch-too-large`` -- document exceeded the 5 KB read cap
  (section 8.7).
* ``mcp-oauth-cimd-fetch-timeout`` -- the fetch exceeded the
  deployment-configured timeout.

Deliberate folds (documented, pinned by the battery):

* Fetch scheme: enforced once, at the shape gate (rule 1,
  ``mcp-oauth-cimd-url-not-https``), before any fetch -- the fetch path is
  unreachable with a non-https URL, so no separate fetch-scheme code exists.
* Pin mismatch: folded into ``mcp-oauth-cimd-binding-mismatch`` (see above).
* Key rotation: the prospectus's advisory ``mcp-oauth-cimd-key-rotated`` is
  realized as a typed ``credential-revoked`` revocation-push event for the
  rotated-out key material (semantically exact: rotation revokes the old
  key), delivered to the deployment's ``revocation_sink`` -- an advisory
  event, not a registered refusal code.
* logo_uri: never emitted (the draft's hostname-display fallback is used
  instead); inbound logo_uri is accepted only as https and is never fetched.
* No dev/test loopback exception (draft section 8.6 MAY): production-only
  rule; a dev override needs an explicit deployment opt-in, not a code path.
* No CIMD Service operation (draft appendix): explicitly out of scope.
* software_statement: never emitted; ignored inbound (MUST-ignore-unknown).

Stdlib only. $0 spend. No network.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import re
import socket
import time
import urllib.parse

__all__ = [
    "CIMDError",
    "MCP_OAUTH_CIMD_URL_NOT_HTTPS",
    "MCP_OAUTH_CIMD_URL_USERINFO",
    "MCP_OAUTH_CIMD_URL_DOT_SEGMENT",
    "MCP_OAUTH_CIMD_URL_QUERY",
    "MCP_OAUTH_CIMD_URL_FRAGMENT",
    "MCP_OAUTH_CIMD_URL_ROOT_PATH",
    "MCP_OAUTH_CIMD_BINDING_MISMATCH",
    "MCP_OAUTH_CIMD_DOCUMENT_MALFORMED",
    "MCP_OAUTH_CIMD_CREDENTIAL_PRESENT",
    "MCP_OAUTH_CIMD_REDIRECT_ORIGIN_MISMATCH",
    "MCP_OAUTH_CIMD_FETCH_REDIRECT",
    "MCP_OAUTH_CIMD_FETCH_NON200",
    "MCP_OAUTH_CIMD_FETCH_SSRF_RANGE",
    "MCP_OAUTH_CIMD_FETCH_TOO_LARGE",
    "MCP_OAUTH_CIMD_FETCH_TIMEOUT",
    "CIMD_CODES",
    "MAX_DOCUMENT_BYTES",
    "EMIT_PATH",
    "validate_client_id_url",
    "check_document_binding",
    "validate_document_shape",
    "emit_document",
    "canonical_document_bytes",
    "document_sha256",
    "serve_document",
    "default_resolver",
    "onboard_cimd",
    "reonboard_cimd",
    "verify_pinned",
    "build_key_rotation_event",
]

# ----------------------------------------------------------------------
# Error vocabulary. Every emitted machine code is registered in
# gov/decision_codes.py (domain ``mcp-oauth``).
# ----------------------------------------------------------------------


class CIMDError(Exception):
    """Base class for all CIMD refusals. ``code`` is machine-readable."""

    code = "mcp-oauth-cimd-document-malformed"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


MCP_OAUTH_CIMD_URL_NOT_HTTPS = "mcp-oauth-cimd-url-not-https"
MCP_OAUTH_CIMD_URL_USERINFO = "mcp-oauth-cimd-url-userinfo"
MCP_OAUTH_CIMD_URL_DOT_SEGMENT = "mcp-oauth-cimd-url-dot-segment"
MCP_OAUTH_CIMD_URL_QUERY = "mcp-oauth-cimd-url-query"
MCP_OAUTH_CIMD_URL_FRAGMENT = "mcp-oauth-cimd-url-fragment"
MCP_OAUTH_CIMD_URL_ROOT_PATH = "mcp-oauth-cimd-url-root-path"
MCP_OAUTH_CIMD_BINDING_MISMATCH = "mcp-oauth-cimd-binding-mismatch"
MCP_OAUTH_CIMD_DOCUMENT_MALFORMED = "mcp-oauth-cimd-document-malformed"
MCP_OAUTH_CIMD_CREDENTIAL_PRESENT = "mcp-oauth-cimd-credential-present"
MCP_OAUTH_CIMD_REDIRECT_ORIGIN_MISMATCH = (
    "mcp-oauth-cimd-redirect-origin-mismatch")
MCP_OAUTH_CIMD_FETCH_REDIRECT = "mcp-oauth-cimd-fetch-redirect"
MCP_OAUTH_CIMD_FETCH_NON200 = "mcp-oauth-cimd-fetch-non200"
MCP_OAUTH_CIMD_FETCH_SSRF_RANGE = "mcp-oauth-cimd-fetch-ssrf-range"
MCP_OAUTH_CIMD_FETCH_TOO_LARGE = "mcp-oauth-cimd-fetch-too-large"
MCP_OAUTH_CIMD_FETCH_TIMEOUT = "mcp-oauth-cimd-fetch-timeout"

#: The 15 registered refusal codes (pin 2121).
CIMD_CODES = (
    MCP_OAUTH_CIMD_URL_NOT_HTTPS,
    MCP_OAUTH_CIMD_URL_USERINFO,
    MCP_OAUTH_CIMD_URL_DOT_SEGMENT,
    MCP_OAUTH_CIMD_URL_QUERY,
    MCP_OAUTH_CIMD_URL_FRAGMENT,
    MCP_OAUTH_CIMD_URL_ROOT_PATH,
    MCP_OAUTH_CIMD_BINDING_MISMATCH,
    MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
    MCP_OAUTH_CIMD_CREDENTIAL_PRESENT,
    MCP_OAUTH_CIMD_REDIRECT_ORIGIN_MISMATCH,
    MCP_OAUTH_CIMD_FETCH_REDIRECT,
    MCP_OAUTH_CIMD_FETCH_NON200,
    MCP_OAUTH_CIMD_FETCH_SSRF_RANGE,
    MCP_OAUTH_CIMD_FETCH_TOO_LARGE,
    MCP_OAUTH_CIMD_FETCH_TIMEOUT,
)

#: Draft section 8.7 read cap.
MAX_DOCUMENT_BYTES = 5120

#: The deployment-configured document path.
EMIT_PATH = "/oauth/client"

_CONTROL_CHARS = frozenset(
    chr(c) for c in list(range(0x00, 0x20)) + [0x7F])

_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?"
                        r"(:[0-9]{1,5})?$")

#: RFC 6890 special-use ranges refused at fetch (draft section 8.6).
_SSRF_NETWORKS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "64:ff9b::/96", "100::/64", "2001::/32",
    "2001:10::/28", "2001:db8::/32", "fc00::/7", "fe80::/10",
]
_SSRF_NETS = [ipaddress.ip_network(n) for n in _SSRF_NETWORKS]


def _refuse(code, detail):
    raise CIMDError("%s: %s" % (code, detail), code=code)


def _reject_control_chars(url):
    # F423 lesson: refuse before urlsplit touches the value; never strip.
    for ch in url:
        if ch in _CONTROL_CHARS:
            _refuse(MCP_OAUTH_CIMD_URL_NOT_HTTPS,
                    "raw ASCII control character in client_id URL")


# ----------------------------------------------------------------------
# Part B -- URL shape validation (the 9-row rule table).
# ----------------------------------------------------------------------

def validate_client_id_url(url):
    """Enforce the draft section 3 client_id URL shape. Raises CIMDError
    coded on any violation. Pure: no I/O.

    Rule rows: 1 scheme==https / 2 no userinfo / 3 port MAY be present
    (allowed, no check) / 4 path present (folded into rule 5) / 5 path not
    empty or '/' (STRICTER) / 6 no '.'/'..' segments (percent-encoded forms
    included) / 7 no query (STRICTER) / 8 no fragment / 9 simple string
    comparison (enforced by check_document_binding).
    """
    if not isinstance(url, str):
        _refuse(MCP_OAUTH_CIMD_URL_NOT_HTTPS,
                "client_id URL is not a string")
    _reject_control_chars(url)
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        _refuse(MCP_OAUTH_CIMD_URL_NOT_HTTPS,
                "client_id URL does not parse: %s" % exc)
    # Rule 1: https only (this gate also makes a separate fetch-scheme
    # code unnecessary -- the fetch path is unreachable otherwise).
    if parts.scheme.lower() != "https":
        _refuse(MCP_OAUTH_CIMD_URL_NOT_HTTPS,
                "client_id URL scheme must be https")
    # F417 class: a non-numeric port raises bare ValueError on .port
    # access -- refuse coded instead of crashing uncoded.
    try:
        parts.port
    except ValueError as exc:
        _refuse(MCP_OAUTH_CIMD_URL_NOT_HTTPS,
                "client_id URL port is malformed: %s" % exc)
    # Rule 2: no userinfo.
    if parts.username or parts.password or "@" in parts.netloc:
        _refuse(MCP_OAUTH_CIMD_URL_USERINFO,
                "client_id URL must not carry userinfo")
    host = parts.hostname or ""
    if not host:
        _refuse(MCP_OAUTH_CIMD_URL_NOT_HTTPS,
                "client_id URL has no host")
    # Rules 4+5: path present and not empty or '/'.
    path = parts.path or ""
    if path in ("", "/"):
        _refuse(MCP_OAUTH_CIMD_URL_ROOT_PATH,
                "client_id URL path must be present and not '/'")
    # Rule 6: no dot segments (raw or percent-encoded).
    for seg in path.split("/"):
        if urllib.parse.unquote(seg).lower() in (".", ".."):
            _refuse(MCP_OAUTH_CIMD_URL_DOT_SEGMENT,
                    "client_id URL path contains a dot segment")
    # Rule 7: no query (stricter than the draft SHOULD NOT).
    if parts.query:
        _refuse(MCP_OAUTH_CIMD_URL_QUERY,
                "client_id URL must not carry a query")
    # Rule 8: no fragment.
    if parts.fragment:
        _refuse(MCP_OAUTH_CIMD_URL_FRAGMENT,
                "client_id URL must not carry a fragment")
    return url


def _origin_tuple(url):
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return (scheme, host, port)


def check_document_binding(document, fetch_url):
    """Draft section 4: document['client_id'] MUST string-equal the URL it
    was fetched from (RFC 3986 section 6.2.1 simple string comparison --
    'https://example.com/client' != 'https://example.com:443/client')."""
    validate_client_id_url(fetch_url)
    if not isinstance(document, dict):
        _refuse(MCP_OAUTH_CIMD_BINDING_MISMATCH,
                "document is not a record")
    client_id = document.get("client_id")
    if not isinstance(client_id, str) or client_id != fetch_url:
        _refuse(MCP_OAUTH_CIMD_BINDING_MISMATCH,
                "document client_id does not string-equal the fetch URL")
    return True


def validate_document_shape(document):
    """Inbound document contract. Raises CIMDError coded. Unknown fields
    are ignored (MUST-ignore-unknown -- document evolution)."""
    if not isinstance(document, dict):
        _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                "document is not a record")
    client_id = document.get("client_id")
    if not isinstance(client_id, str) or not client_id:
        _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                "client_id is required and must be a string")
    validate_client_id_url(client_id)  # propagates the url-* codes
    # Credential smuggling: any client_secret* member refuses, never ignored.
    for key in document:
        if isinstance(key, str) and key.startswith("client_secret"):
            _refuse(MCP_OAUTH_CIMD_CREDENTIAL_PRESENT,
                    "document carries %r" % key)
    # private_key_jwt without a discoverable key is a misbinding.
    if document.get("token_endpoint_auth_method") == "private_key_jwt":
        jwks_uri = document.get("jwks_uri")
        if not isinstance(jwks_uri, str):
            _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                    "private_key_jwt requires jwks_uri")
        _reject_control_chars(jwks_uri)
        try:
            jp = urllib.parse.urlsplit(jwks_uri)
        except ValueError as exc:
            _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                    "jwks_uri does not parse: %s" % exc)
        if jp.scheme.lower() != "https" or not jp.hostname:
            _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                    "jwks_uri must be an https URL")
    # redirect_uris: https AND same-origin as the document (the
    # unconditional section 8.1 restriction, symmetric inbound).
    redirects = document.get("redirect_uris")
    if redirects is not None:
        if not isinstance(redirects, list):
            _refuse(MCP_OAUTH_CIMD_REDIRECT_ORIGIN_MISMATCH,
                    "redirect_uris must be an array")
        want = _origin_tuple(client_id)
        for entry in redirects:
            if not isinstance(entry, str):
                _refuse(MCP_OAUTH_CIMD_REDIRECT_ORIGIN_MISMATCH,
                        "redirect_uri is not a string")
            _reject_control_chars(entry)
            try:
                ep = urllib.parse.urlsplit(entry)
            except ValueError:
                _refuse(MCP_OAUTH_CIMD_REDIRECT_ORIGIN_MISMATCH,
                        "redirect_uri does not parse")
            if ep.scheme.lower() != "https" or not ep.hostname:
                _refuse(MCP_OAUTH_CIMD_REDIRECT_ORIGIN_MISMATCH,
                        "redirect_uri must be https: %r" % entry[:64])
            if _origin_tuple(entry) != want:
                _refuse(MCP_OAUTH_CIMD_REDIRECT_ORIGIN_MISMATCH,
                        "redirect_uri not same-origin with the document")
    # logo_uri: https only; NEVER fetched (the draft's hostname-display
    # fallback is used instead -- documented deviation).
    logo = document.get("logo_uri")
    if logo is not None:
        if not isinstance(logo, str):
            _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                    "logo_uri must be a string")
        _reject_control_chars(logo)
        try:
            lp = urllib.parse.urlsplit(logo)
        except ValueError:
            _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                    "logo_uri does not parse")
        if lp.scheme.lower() != "https" or not lp.hostname:
            _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                    "logo_uri must be https")
    return True


# ----------------------------------------------------------------------
# Part A -- document emission (client role).
# ----------------------------------------------------------------------

def emit_document(deployment_domain, client_name, redirect_uris=(),
                  jwks_path="/.well-known/jwks.json"):
    """Render the static CIMD document for the deployment-configured
    endpoint. The domain comes from deployment config, never agent input.
    logo_uri is never emitted (documented deviation); client_secret*
    members are never emitted (vacuously -- the deployment handles no
    client secrets); software_statement is never emitted."""
    if not isinstance(deployment_domain, str) or not _DOMAIN_RE.match(
            deployment_domain):
        _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                "deployment_domain must be a bare host")
    if not isinstance(client_name, str) or not client_name:
        _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                "client_name must be a non-empty string")
    if not isinstance(jwks_path, str) or not jwks_path.startswith("/"):
        _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                "jwks_path must be an absolute path")
    client_id = "https://%s%s" % (deployment_domain, EMIT_PATH)
    jwks_uri = "https://%s%s" % (deployment_domain, jwks_path)
    document = {
        "client_id": client_id,
        "client_name": client_name,
        "redirect_uris": list(redirect_uris),
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks_uri": jwks_uri,
    }
    # Fail closed at construction: the emitted document must satisfy the
    # inbound contract too.
    validate_document_shape(document)
    return document


def canonical_document_bytes(document):
    """Byte-stable rendering (sorted keys, compact separators) so the
    sha256 pin is deterministic."""
    return json.dumps(document, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def document_sha256(document_or_bytes):
    if isinstance(document_or_bytes, (bytes, bytearray)):
        raw = bytes(document_or_bytes)
    else:
        raw = canonical_document_bytes(document_or_bytes)
    return hashlib.sha256(raw).hexdigest()


def serve_document(document):
    """Serving contract: 200 OK, application/json (draft section 5 --
    the document MUST be served with 200 OK; all other statuses are
    errors)."""
    validate_document_shape(document)
    return (200, {"Content-Type": "application/json"},
            canonical_document_bytes(document))


# ----------------------------------------------------------------------
# Part C -- pre-registration intake (draft section 7.2 pattern).
# ----------------------------------------------------------------------

def default_resolver(host):
    """Stdlib DNS resolver. Returns a list of IP strings."""
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def _ip_is_special(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable address: refuse as untrusted
    return any(ip in net for net in _SSRF_NETS)


def _domain_trusted(host, patterns):
    host = host.lower()
    return any(fnmatch.fnmatchcase(host, pat.lower()) for pat in patterns)


def _check_deployment(deployment):
    if not isinstance(deployment, dict):
        raise ValueError("deployment must be a record")
    patterns = deployment.get("trusted_domain_patterns")
    if (not isinstance(patterns, list) or not patterns
            or not all(isinstance(p, str) and p for p in patterns)):
        raise ValueError(
            "deployment['trusted_domain_patterns'] must be a non-empty "
            "list of domain patterns")
    timeout = deployment.get("timeout_seconds", 10)
    if isinstance(timeout, bool) or not isinstance(
            timeout, (int, float)) or not (timeout > 0):
        raise ValueError("deployment['timeout_seconds'] must be a "
                         "positive number")
    max_bytes = deployment.get("max_bytes", MAX_DOCUMENT_BYTES)
    if isinstance(max_bytes, bool) or not isinstance(
            max_bytes, int) or max_bytes <= 0:
        raise ValueError("deployment['max_bytes'] must be a positive int")
    return patterns, float(timeout), max_bytes


def _guarded_fetch(url, fetcher, deployment, resolver, what):
    """Fetch one URL under the full control set. Returns
    (body_bytes, pinned_ips). ``what`` labels the fetch in errors."""
    patterns, timeout, max_bytes = _check_deployment(deployment)
    validate_client_id_url(url)  # shape gate first: https-only etc.
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    # Domain trust lives in deployment config, never in fetched metadata
    # (section 8.9 composition) -- folded into the fetch-trust code.
    if not _domain_trusted(host, patterns):
        _refuse(MCP_OAUTH_CIMD_FETCH_SSRF_RANGE,
                "%s: domain outside the deployment allowlist" % what)
    resolve = resolver or default_resolver
    try:
        ips = resolve(host)
    except Exception as exc:
        _refuse(MCP_OAUTH_CIMD_FETCH_SSRF_RANGE,
                "%s: DNS resolution failed: %s" % (what, exc))
    if not isinstance(ips, list) or not ips:
        _refuse(MCP_OAUTH_CIMD_FETCH_SSRF_RANGE,
                "%s: DNS resolution returned no addresses" % what)
    pinned = set()
    for ip in ips:
        if not isinstance(ip, str) or _ip_is_special(ip):
            _refuse(MCP_OAUTH_CIMD_FETCH_SSRF_RANGE,
                    "%s: resolved address outside fetch trust" % what)
        pinned.add(ip)
    if fetcher is None or not callable(fetcher):
        raise TypeError("fetcher must be a callable(url, timeout_seconds)")
    try:
        result = fetcher(url, timeout)
    except TimeoutError as exc:
        _refuse(MCP_OAUTH_CIMD_FETCH_TIMEOUT,
                "%s: %s" % (what, exc))
    except Exception as exc:
        # No 200 document was retrieved (transport failure).
        _refuse(MCP_OAUTH_CIMD_FETCH_NON200,
                "%s: transport failure: %s" % (what, exc))
    if not isinstance(result, dict):
        _refuse(MCP_OAUTH_CIMD_FETCH_NON200,
                "%s: fetcher returned a non-record" % what)
    status = result.get("status")
    headers = result.get("headers") or {}
    # Never follow redirects (section 5): a redirect is a refusal.
    if (isinstance(status, int) and 300 <= status <= 399) or any(
            str(k).lower() == "location" for k in headers):
        _refuse(MCP_OAUTH_CIMD_FETCH_REDIRECT,
                "%s: redirect refused" % what)
    if status != 200:
        _refuse(MCP_OAUTH_CIMD_FETCH_NON200,
                "%s: status %r is not 200" % (what, status))
    body = result.get("body")
    if not isinstance(body, (bytes, bytearray)):
        _refuse(MCP_OAUTH_CIMD_FETCH_NON200,
                "%s: body is not bytes" % what)
    body = bytes(body)
    if len(body) > max_bytes:
        _refuse(MCP_OAUTH_CIMD_FETCH_TOO_LARGE,
                "%s: %d bytes over the %d cap" % (what, len(body),
                                                 max_bytes))
    # DNS-rebinding control: re-resolve and require the same set.
    try:
        ips2 = resolve(host)
    except Exception as exc:
        _refuse(MCP_OAUTH_CIMD_FETCH_SSRF_RANGE,
                "%s: re-resolution failed: %s" % (what, exc))
    if set(ips2 or []) != pinned:
        _refuse(MCP_OAUTH_CIMD_FETCH_SSRF_RANGE,
                "%s: DNS rebind detected" % what)
    return body, sorted(pinned)


def onboard_cimd(client_id_url, fetcher, deployment, resolver=None):
    """Operator-driven onboarding (section 7.2 pattern): fetch the CIMD
    document ONCE, validate it, pin sha256(document_bytes) and the jwks
    content hash. No agent-reachable API initiates a fetch. Returns an
    onboarding record; request-time checks use ``verify_pinned`` against
    the pinned copy only."""
    body, pinned = _guarded_fetch(client_id_url, fetcher, deployment,
                                 resolver, "cimd")
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                "cimd: document is not JSON: %s" % exc)
    validate_document_shape(document)
    check_document_binding(document, client_id_url)
    # Pin the jwks content hash too (needed for rotation detection).
    jwks_uri = document.get("jwks_uri")
    jwks_body, _ = _guarded_fetch(jwks_uri, fetcher, deployment, resolver,
                                 "jwks")
    try:
        json.loads(jwks_body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                "jwks: not JSON: %s" % exc)
    return {
        "client_id_url": client_id_url,
        "document": document,
        "document_sha256": hashlib.sha256(body).hexdigest(),
        "jwks_uri": jwks_uri,
        "jwks_sha256": hashlib.sha256(jwks_body).hexdigest(),
        "pinned_ips": pinned,
        "rotation": None,
    }


def build_key_rotation_event(prior_record, new_record, event_id,
                             issued_at=None):
    """Build the revocation-shaped advisory for a key rotation: rotation
    revokes the old key, so this is a ``credential-revoked`` event for the
    rotated-out key material. The deployment signs it with its
    revocation-hub key and ingests it (see ``revocation_sink``)."""
    return {
        "event_id": event_id,
        "event_type": "urn:sasanam:revocation-push:credential-revoked",
        "subject": {
            "kind": "credential",
            "id": "cimd-jwks:%s" % prior_record["jwks_sha256"][:32],
        },
        "issued_at": time.time() if issued_at is None else issued_at,
        "reason": "cimd key rotation for %s (jwks %s -> %s)" % (
            new_record["client_id_url"],
            prior_record["jwks_sha256"][:16],
            new_record["jwks_sha256"][:16]),
    }


def reonboard_cimd(client_id_url, fetcher, deployment, prior_record,
                   revocation_sink=None, event_id=None, resolver=None):
    """Re-onboarding (section 8.4.1 composition). Re-runs the full intake;
    if the jwks content hash differs from the pinned hash, the rotation is
    a revocation-shaped event: the event is delivered to
    ``revocation_sink`` (the deployment's signed ingest) and the returned
    record carries ``rotation`` with the receipt. Never a silent re-pin."""
    if not isinstance(prior_record, dict) or "jwks_sha256" not in \
            prior_record:
        raise ValueError("prior_record must be an onboarding record")
    new_record = onboard_cimd(client_id_url, fetcher, deployment,
                              resolver=resolver)
    if new_record["jwks_sha256"] != prior_record["jwks_sha256"]:
        event = build_key_rotation_event(
            prior_record, new_record,
            event_id or ("cimd-rot-%d" % int(time.time() * 1000)))
        receipt = None
        if revocation_sink is not None:
            if not callable(revocation_sink):
                raise TypeError("revocation_sink must be callable")
            receipt = revocation_sink(event)
        new_record["rotation"] = {
            "advisory": "key-rotated",
            "prior_jwks_sha256": prior_record["jwks_sha256"],
            "event": event,
            "receipt": receipt,
        }
    return new_record


def verify_pinned(client_id_url, presented_bytes, record):
    """Request-time check: compare against the pinned copy only. A
    mismatch is a binding break (the pin IS the document binding)."""
    if not isinstance(presented_bytes, (bytes, bytearray)):
        _refuse(MCP_OAUTH_CIMD_BINDING_MISMATCH,
                "presented document is not bytes")
    if not isinstance(record, dict) or "document_sha256" not in record:
        raise ValueError("record must be an onboarding record")
    if hashlib.sha256(bytes(presented_bytes)).hexdigest() != \
            record["document_sha256"]:
        _refuse(MCP_OAUTH_CIMD_BINDING_MISMATCH,
                "presented document does not match the pinned bytes")
    try:
        document = json.loads(bytes(presented_bytes).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        _refuse(MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                "pinned document is not JSON: %s" % exc)
    validate_document_shape(document)
    check_document_binding(document, client_id_url)
    return document
