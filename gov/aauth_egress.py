"""aauth-rs fail-closed egress primitives (W241-3 steal, patterns only).

nolabs-ai/aauth-rs is Apache-2.0 (file-level LICENSE read by the
wave-241 lane: full Apache License 2.0 text, Copyright 2026 nolabs,
inc). The five primitives below are re-derived in prose from the
mechanism descriptions in the wave-240 prospectus; NO upstream code
is read, copied, imported, or vendored here.

The primitives:

1. Policy-before-discovery (``aauth-scheme-not-allowed``). A scheme
   registry denies every scheme until explicitly allowed. Resolving
   a scheme without a policy -- or with a policy that never allowed
   it -- refuses. Discovery never precedes the policy decision.
2. Token ``aud`` binding (``aauth-aud-mismatch``). The presented
   audience must equal the expected audience; a missing or
   mismatched ``aud`` fails closed.
3. RFC 9421 ``created`` freshness (``aauth-stale-created``). A
   created timestamp more than ``FRESHNESS_WINDOW_SECONDS`` (60) from
   the verifier's clock -- past or future -- refuses.
4. ``default_deny()`` egress (``aauth-egress-blocked``). HTTPS only;
   loopback, RFC1918, link-local, and ``localhost`` targets are
   blocked. Non-HTTPS schemes are blocked.
5. Confused-deputy ``iss`` verification (``aauth-iss-mismatch``).
   The presented issuer must equal the expected issuer before any
   token exchange; a missing or mismatched ``iss`` fails closed.

Honest boundaries: egress checks run against the URL text at
check time. DNS rebinding -- the target IP changing between this
check and connection setup -- is a documented limitation of every
pre-connection egress check and is NOT claimed as solved here.
``check_freshness`` assumes the verifier's clock is trustworthy;
clock trust is deployment-owned. Issuer/audience comparisons are
exact-string; no claim normalization is attempted (conservative).
"""

import ipaddress
from urllib.parse import urlsplit

FRESHNESS_WINDOW_SECONDS = 60

_ALLOWED_URL_SCHEMES = ("https",)


class AauthEgressError(Exception):
    """Refusal raised by this module. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class SchemePolicy:
    """Deny-every-scheme-until-explicitly-allowed policy store."""

    def __init__(self):
        self._allowed = set()

    def allow_scheme(self, scheme):
        """Explicitly allow one scheme. Non-string schemes are
        rejected immediately (never stored)."""
        if not isinstance(scheme, str) or not scheme:
            raise AauthEgressError(
                "aauth-scheme-not-allowed",
                "policy only allows non-empty string schemes")
        self._allowed.add(scheme)
        return self

    def is_allowed(self, scheme):
        return isinstance(scheme, str) and scheme in self._allowed


def resolve_scheme(scheme, policy):
    """Resolve a scheme against its policy (discovery after policy).

    Refuses ``aauth-scheme-not-allowed`` when there is no policy,
    the policy is not a SchemePolicy, the scheme is not a string,
    or the scheme was never explicitly allowed.
    """
    if not isinstance(policy, SchemePolicy):
        raise AauthEgressError(
            "aauth-scheme-not-allowed",
            "scheme discovery without a policy is refused")
    if not isinstance(scheme, str) or not scheme:
        raise AauthEgressError(
            "aauth-scheme-not-allowed",
            "scheme must be a non-empty string")
    if not policy.is_allowed(scheme):
        raise AauthEgressError(
            "aauth-scheme-not-allowed",
            "scheme %r was never explicitly allowed" % (scheme,))
    return scheme


def check_audience(token_aud, expected_aud):
    """Bind a token to its expected audience.

    Refuses ``aauth-aud-mismatch`` when the presented audience is
    missing, the expected audience is missing, or they differ.
    """
    if not token_aud or not expected_aud:
        raise AauthEgressError(
            "aauth-aud-mismatch",
            "audience binding requires both a presented and an "
            "expected audience; failing closed")
    if token_aud != expected_aud:
        raise AauthEgressError(
            "aauth-aud-mismatch",
            "token audience %r does not match expected %r"
            % (token_aud, expected_aud))
    return True


def check_freshness(created_epoch, now_epoch):
    """Enforce RFC 9421 ``created`` freshness (60s window).

    Refuses ``aauth-stale-created`` when either timestamp is not a
    number or the absolute difference exceeds
    ``FRESHNESS_WINDOW_SECONDS`` (stale past or future).
    """
    for value, name in ((created_epoch, "created"),
                        (now_epoch, "now")):
        if isinstance(value, bool) or not isinstance(
                value, (int, float)):
            raise AauthEgressError(
                "aauth-stale-created",
                "%s timestamp %r is not a number; failing closed"
                % (name, value))
    if abs(now_epoch - created_epoch) > FRESHNESS_WINDOW_SECONDS:
        raise AauthEgressError(
            "aauth-stale-created",
            "created %r is more than %ds from now %r"
            % (created_epoch, FRESHNESS_WINDOW_SECONDS, now_epoch))
    return True


def _host_is_blocked(host):
    """True when the host must be refused egress."""
    if not host:
        return True
    lowered = host.lower()
    if lowered == "localhost" or lowered.endswith(".localhost"):
        return True
    try:
        addr = ipaddress.ip_address(lowered)
    except ValueError:
        return False  # a DNS name: resolved only by the connector
    return bool(addr.is_loopback or addr.is_private
                or addr.is_link_local)


def check_egress(url):
    """Egress gate: HTTPS only, no private/loopback/link-local.

    Refuses ``aauth-egress-blocked`` for non-https schemes,
    localhost, loopback, RFC1918, link-local, or unparseable URLs.
    DNS names that do not resolve here are left to the connector;
    DNS rebinding after this check is a documented limitation (see
    module docstring), not a solved problem.
    """
    if not isinstance(url, str) or not url:
        raise AauthEgressError(
            "aauth-egress-blocked",
            "egress target must be a non-empty string URL")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise AauthEgressError(
            "aauth-egress-blocked",
            "unparseable egress URL; failing closed: %r" % (exc,))
    if parts.scheme.lower() not in _ALLOWED_URL_SCHEMES:
        raise AauthEgressError(
            "aauth-egress-blocked",
            "egress scheme %r is not https" % (parts.scheme,))
    host = parts.hostname
    if _host_is_blocked(host):
        raise AauthEgressError(
            "aauth-egress-blocked",
            "egress to %r is loopback/private/link-local; blocked"
            % (host,))
    return True


def verify_issuer(token_iss, expected_iss):
    """Verify the token issuer before any exchange (confused deputy).

    Refuses ``aauth-iss-mismatch`` when the presented issuer is
    missing, the expected issuer is missing, or they differ. Exact
    string match; no normalization is attempted (conservative).
    """
    if not token_iss or not expected_iss:
        raise AauthEgressError(
            "aauth-iss-mismatch",
            "issuer verification requires both a presented and an "
            "expected issuer; failing closed")
    if token_iss != expected_iss:
        raise AauthEgressError(
            "aauth-iss-mismatch",
            "token issuer %r does not match expected %r"
            % (token_iss, expected_iss))
    return True
