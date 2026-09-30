"""One canonical host normalization for every URI-consuming site.

W247-1. W246-4 proved the auth path and the IoC path normalized URIs
differently (executor lowercased only; canary stripped/lowered/
dot-stripped; jwks IDNA-encoded; none agreed). This module is the
single normalization point: ``executor``, ``simulator``, ``canary``,
``jwks_fetch``, ``egress_ledger``, and ``sentinel_substitution`` all
normalize through it, so the auth path and the IoC path always see the
byte-identical host string.

Canonical form: strip surrounding whitespace -> lowercase -> strip
trailing dots -> IDNA-encode to ASCII. Fail-closed: unparseable or
un-normalizable inputs raise :class:`UriNormalizeError` carrying a
taxonomy ``code`` (``uri-host-invalid`` / ``uri-host-unparseable``).

Explicit behavior changes vs. pre-W247 (all pinned by
``evals/w247_uri_normalize_probes.py``; none silent):
- Trailing-dot FQDNs (``trusted.example.``) now normalize to the bare
  name and ALLOW when allowlisted. DNS-correct: the trailing dot IS
  the same DNS name. Previously denied.
- Whitespace-padded hosts (`` trusted.example``) now strip and ALLOW
  when allowlisted. Previously denied. Safe: no DNS resolver maps a
  whitespace-padded name to a different host -- clients either strip
  (same host) or fail resolution (no egress).
- Unicode hosts now IDNA-encode everywhere (previously only jwks did).
  Allowlists are normalized through the same function, so
  unicode/unicode, punycode/punycode, and mixed pairs compare
  correctly. Previously a unicode request vs. a punycode allowlist
  was a false-negative deny.
- Allowlist entries are normalized too: a trailing-dot or
  mixed-case allowlist entry now matches its canonical form
  (previously a trailing-dot allowlist entry never matched).

What this module does NOT do: it never percent-decodes the host
(``%74rusted.example`` stays encoded -- fail-closed boundary pinned
by W246-4), never resolves DNS, never fetches. It is a pure function:
string in, canonical string out (or a coded refusal).

Stdlib only.
"""

from urllib.parse import urlparse


class UriNormalizeError(Exception):
    """Fail-closed refusal from host normalization.

    ``code`` is the taxonomy refusal string (``uri-host-invalid`` or
    ``uri-host-unparseable``); ``detail`` is a human-readable
    explanation that never carries secret material.
    """

    def __init__(self, code, detail):
        super(UriNormalizeError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def normalize_host(raw):
    """Return the canonical form of a hostname.

    Strip surrounding whitespace, lowercase, strip trailing dots,
    IDNA-encode to ASCII. Raises :class:`UriNormalizeError` when the
    input is not a string, is empty after stripping, or fails IDNA
    encoding. Idempotent: normalizing a canonical form is a no-op.
    """
    if not isinstance(raw, str):
        raise UriNormalizeError(
            "uri-host-invalid",
            "hostname must be a string, got %s" % type(raw).__name__)
    host = raw.strip().lower().rstrip(".")
    if not host:
        raise UriNormalizeError(
            "uri-host-invalid",
            "hostname is empty after stripping")
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as exc:
        raise UriNormalizeError(
            "uri-host-invalid",
            "hostname fails IDNA encoding: %s" % (exc,))
    if not host:
        raise UriNormalizeError(
            "uri-host-invalid",
            "hostname is empty after IDNA encoding")
    return host


def normalize_url_host(url):
    """Return the canonical host of a URL.

    Extracts ``urlparse(url).hostname`` and normalizes it. Raises
    :class:`UriNormalizeError` (``uri-host-unparseable``) when the URL
    has no parseable hostname; ``uri-host-invalid`` propagates from
    :func:`normalize_host` for un-normalizable hosts.
    """
    try:
        host = urlparse(url or "").hostname
    except Exception:
        host = None
    if not host:
        raise UriNormalizeError(
            "uri-host-unparseable",
            "URL has no parseable hostname")
    return normalize_host(host)


def normalize_email_host(addr):
    """Return the canonical host of an email address.

    Takes the part after the last ``@`` and normalizes it. Raises
    :class:`UriNormalizeError` (``uri-host-unparseable``) when there
    is no ``@``; ``uri-host-invalid`` propagates for un-normalizable
    domains.
    """
    if not isinstance(addr, str) or "@" not in addr:
        raise UriNormalizeError(
            "uri-host-unparseable",
            "address has no @ separator")
    return normalize_host(addr.rsplit("@", 1)[-1])
