"""JWKS fetch redirect-poisoning guard (W245-10).

Attacker shape: GHSA-9v7f-9g4p-ffgj / CVE-2026-102267 -- PyJWT 2.13.0
``PyJWKClient`` followed HTTP redirects while fetching a JWKS without
validating the redirect destination, so a configured trusted endpoint
could redirect the client to an attacker host and the redirected
response became authoritative key material (JWKS trust poisoning).

This module is a fetch-guard primitive, not a network client: the
transport is deployment-owned and injected, and the guard decides what
the transport may do. The rules mirror the upstream fix (PyJWT 2.14.0:
automatic redirects disabled for JWKS fetches):

  - ANY HTTP redirect response (3xx status) or ANY ``Location`` header
    on a JWKS response refuses ``jwks-redirect-refused``. The redirect
    is never followed and its destination is never contacted: the
    transport is called exactly once.
  - A request URL whose origin (scheme, host, port) does not match
    the pinned issuer origin refuses ``jwks-origin-mismatch`` BEFORE
    any transport call.
  - A malformed request URL (relative, non-http(s) scheme, userinfo,
    fragment) refuses ``jwks-url-malformed``; a missing pinned origin
    refuses ``jwks-issuer-unpinned``.
  - A deployment transport that raises, or returns a malformed /
    non-OK response, refuses ``jwks-transport-failed`` -- a transport
    failure is never treated as key material.

Stdlib only. No real network happens here: the guard never opens a
socket; it only calls the injected ``transport`` callable.
"""

import urllib.parse


REDIRECT_REFUSED = "jwks-redirect-refused"
ORIGIN_MISMATCH = "jwks-origin-mismatch"
URL_MALFORMED = "jwks-url-malformed"
ISSUER_UNPINNED = "jwks-issuer-unpinned"
TRANSPORT_FAILED = "jwks-transport-failed"

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_HTTP_SCHEMES = ("http", "https")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class JwksFetchError(Exception):
    """Fail-closed refusal from the JWKS fetch guard.

    ``code`` is the refusal string (one of the module-level constants);
    ``detail`` is a human-readable explanation that never carries
    secret material.
    """

    def __init__(self, code, detail):
        super(JwksFetchError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _normalize_host(host):
    # Case-insensitive DNS name: lowercase, strip a single trailing
    # dot, IDNA-encode so unicode labels compare correctly.
    host = host.lower().rstrip(".")
    return host.encode("idna").decode("ascii")


def _normalize_origin(scheme, host, port):
    scheme = scheme.lower()
    host = _normalize_host(host)
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    return (scheme, host, int(port))


def _parse_origin(origin):
    """Parse a pinned issuer origin like ``https://idp.example``.

    Returns the normalized (scheme, host, port) triple. Refuses
    ``jwks-issuer-unpinned`` when nothing is pinned and
    ``jwks-url-malformed`` for a malformed origin.
    """
    if not isinstance(origin, str) or not origin:
        raise JwksFetchError(
            ISSUER_UNPINNED,
            "no pinned issuer origin supplied; JWKS fetch refused "
            "rather than fetching unpinned")
    try:
        parts = urllib.parse.urlsplit(origin)
    except ValueError as exc:
        raise JwksFetchError(URL_MALFORMED,
                             "pinned origin unparsable: %s" % (exc,))
    if parts.scheme.lower() not in _HTTP_SCHEMES:
        raise JwksFetchError(URL_MALFORMED,
                             "pinned origin scheme must be http(s)")
    if not parts.hostname:
        raise JwksFetchError(URL_MALFORMED,
                             "pinned origin has no host")
    if "@" in parts.netloc:
        raise JwksFetchError(URL_MALFORMED,
                             "pinned origin must not carry userinfo")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise JwksFetchError(URL_MALFORMED,
                             "pinned origin must be bare (no path/query)")
    try:
        port = parts.port
    except ValueError as exc:
        raise JwksFetchError(URL_MALFORMED,
                             "pinned origin port invalid: %s" % (exc,))
    return _normalize_origin(parts.scheme, parts.hostname, port)


def _parse_request_url(url):
    """Parse and validate the JWKS request URL; fail closed."""
    if not isinstance(url, str) or not url:
        raise JwksFetchError(URL_MALFORMED, "request URL must be a string")
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise JwksFetchError(URL_MALFORMED,
                             "request URL unparsable: %s" % (exc,))
    if parts.scheme.lower() not in _HTTP_SCHEMES:
        raise JwksFetchError(URL_MALFORMED,
                             "request URL scheme must be http(s)")
    if not parts.hostname:
        raise JwksFetchError(URL_MALFORMED,
                             "request URL must be absolute with a host")
    if "@" in parts.netloc:
        raise JwksFetchError(URL_MALFORMED,
                             "request URL must not carry userinfo")
    if parts.fragment:
        raise JwksFetchError(URL_MALFORMED,
                             "request URL must not carry a fragment")
    try:
        port = parts.port
    except ValueError as exc:
        raise JwksFetchError(URL_MALFORMED,
                             "request URL port invalid: %s" % (exc,))
    return _normalize_origin(parts.scheme, parts.hostname, port)


def fetch_jwks(pinned_origin, url, transport, timeout_s=10.0):
    """Fetch a JWKS document under the redirect-poisoning guard.

    ``pinned_origin`` is the issuer origin the JWKS belongs to (e.g.
    ``"https://idp.example"``); ``url`` is the absolute JWKS URL;
    ``transport`` is a deployment-supplied callable taking
    ``(url, timeout_s)`` and returning ``(status, headers, body)``
    where ``status`` is an int, ``headers`` a list of
    ``(name, value)`` string pairs, and ``body`` bytes.

    Returns the response body bytes on success. Refuses fail-closed:

    - ``jwks-issuer-unpinned`` / ``jwks-url-malformed`` / 
      ``jwks-origin-mismatch``: raised before any transport call.
    - ``jwks-redirect-refused``: any 3xx status or any Location
      header. The redirect is never followed; the transport has been
      called exactly once and the destination is never contacted.
    - ``jwks-transport-failed``: the transport raised, returned a
      malformed response, or returned a non-2xx status.

    ``timeout_s`` must be a positive number (bool rejected: the
    ``True == 1`` trap); it is passed to the transport unchanged.
    """
    if isinstance(timeout_s, bool) or not isinstance(
            timeout_s, (int, float)) or not timeout_s > 0:
        raise JwksFetchError(URL_MALFORMED,
                             "timeout_s must be a positive number")
    if not callable(transport):
        raise JwksFetchError(URL_MALFORMED, "transport must be callable")

    pinned = _parse_origin(pinned_origin)
    requested = _parse_request_url(url)
    if requested != pinned:
        raise JwksFetchError(
            ORIGIN_MISMATCH,
            "request origin %r does not match pinned issuer origin %r; "
            "refused before any transport call" % (requested, pinned))

    try:
        response = transport(url, timeout_s)
    except JwksFetchError:
        raise
    except Exception as exc:  # noqa: BLE001 -- deployment transport failed
        raise JwksFetchError(TRANSPORT_FAILED,
                             "deployment transport raised %r" % (exc,))

    if (not isinstance(response, (list, tuple)) or len(response) != 3):
        raise JwksFetchError(TRANSPORT_FAILED,
                             "transport returned a malformed response")
    status, headers, body = response
    if isinstance(status, bool) or not isinstance(status, int):
        raise JwksFetchError(TRANSPORT_FAILED,
                             "transport returned a non-integer status")
    if not isinstance(headers, (list, tuple)) or any(
            not isinstance(h, (list, tuple)) or len(h) != 2
            or not isinstance(h[0], str) or not isinstance(h[1], str)
            for h in headers):
        raise JwksFetchError(TRANSPORT_FAILED,
                             "transport returned malformed headers")
    if isinstance(body, bytearray):
        body = bytes(body)
    if not isinstance(body, bytes):
        raise JwksFetchError(TRANSPORT_FAILED,
                             "transport returned a non-bytes body")

    # Redirect detection: a 3xx status OR any Location header. Like the
    # upstream fix, the redirect is rejected WITHOUT contacting its
    # destination -- we never issue a second transport call, and the
    # Location value is never dereferenced.
    if status in _REDIRECT_STATUSES or any(
            h[0].lower() == "location" for h in headers):
        raise JwksFetchError(
            REDIRECT_REFUSED,
            "JWKS fetch response carried a redirect (status %d); "
            "redirects are never followed and the destination is "
            "never contacted" % (status,))

    if not 200 <= status <= 299:
        raise JwksFetchError(TRANSPORT_FAILED,
                             "transport returned non-2xx status %d" % status)

    return body
