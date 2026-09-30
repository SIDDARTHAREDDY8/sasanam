"""MCP discovery-trust gate (W246-9, ADAPT -- threat model only, prose
re-derived).

Threat model from draft-morrison-mcp-dns-discovery -07 ("Discovery of
Model Context Protocol Servers via DNS TXT Records" -- MCP server
discovery + operator identity via DNS): DNS is an UNTRUSTED discovery
plane. A DNS-discovered server must not be trusted without explicit
deployment pinning, and a forged DNS record claiming a pinned
server's identity must be refused loudly -- never silently trusted,
never silently ignored.

This module is NOT a DNS client: it performs no lookups, parses no
TXT records, and touches no network. ``check_discovery(discovery,
pins)`` is the pure trust decision at the seam where a
(deployment-parsed, caller-supplied, untrusted) discovery result
enters: the deployment pins server identities out-of-band, and the
gate admits only what the pins admit.

``discovery`` is a mapping::

    {"name": ..., "endpoint": ..., "identity": ..., "source": ...}

* ``name``: server name (non-empty str).
* ``endpoint``: server endpoint URL (non-empty str). A LOCATOR, not
  identity: a pinned identity at a new endpoint still accepts.
* ``identity``: the claimed server identity (non-empty str). Opaque
  to this gate; the deployment defines the format (key fingerprint,
  digest, ...). Equality against the pin is exact.
* ``source``: discovery-source label (str, e.g. ``"dns"``).
  INFORMATIONAL ONLY and never trusted: it is carried into the
  accept record for the auditor but never influences the verdict.

``pins`` is the deployment-owned mapping ``{name: pinned_identity}``.
An empty pin set pins nothing: every discovery refuses
``discovery-unpinned`` (fail closed).

Verdicts:

* accept ``{"verdict": "accept", "name": ..., "identity": ...,
  "source": ...}`` -- the name is pinned and the claimed identity
  equals the pin, exactly.
* ``discovery-unpinned`` -- the name has no deployment pin. The
  discovery plane is untrusted; explicit pinning is required.
* ``discovery-identity-mismatch`` -- the name is pinned but the
  claimed identity differs. This is the impersonation/forgery
  signal: a forged DNS record claiming a pinned name refuses here,
  loudly.
* ``discovery-result-malformed`` -- the discovery result or the pin
  set is malformed. Fail closed; never silently admitted.

Refusals raise :class:`McpDiscoveryTrustError` (code-first, like
``gov.mcp_surface_guard.McpSurfaceGuardError``); ``check_discovery``
never returns a refusal verdict and never raises on hostile input
shapes -- malformed input becomes ``discovery-result-malformed``.

Composition: this gate answers "may this discovered server be
trusted as this name". It does NOT replace the attested tool
registry (``gov.mcp_annotations.build_tool_registry`` -- keyset
attestations), the invocation-time mapping pin
(``gov.mcp_invocation_authz`` -- ``mapping-unpinned`` /
``mapping-drift``), or the ``server::tool`` allowlist
(``gov.authority_proof.check``). Use this gate first at the
discovery seam, then those at their seams.

Honest boundaries
-----------------
* Pins are deployment-owned and deployment-vouched: the gate checks
  binding and shape, it cannot make a pin set honest. A lying
  deployment can pin an attacker key.
* Identity equality is exact string equality on a
  deployment-defined format; the gate does not parse or validate
  fingerprint/digest formats.
* DNS TXT parsing, transport, and freshness are deployment-owned;
  this gate sees only the parsed, untrusted result.

Stdlib only. Deterministic: no clock, no I/O, no randomness, no
network.
"""

DISCOVERY_UNPINNED = "discovery-unpinned"
DISCOVERY_IDENTITY_MISMATCH = "discovery-identity-mismatch"
DISCOVERY_RESULT_MALFORMED = "discovery-result-malformed"

_ACCEPT = "accept"

__all__ = [
    "DISCOVERY_UNPINNED",
    "DISCOVERY_IDENTITY_MISMATCH",
    "DISCOVERY_RESULT_MALFORMED",
    "McpDiscoveryTrustError",
    "check_discovery",
]


class McpDiscoveryTrustError(Exception):
    """Fail-closed MCP discovery-trust refusal. ``code`` is the
    vocabulary."""

    def __init__(self, code, detail=""):
        super(McpDiscoveryTrustError, self).__init__(
            "%s: %s" % (code, detail) if detail else code)
        self.code = code
        self.detail = detail


def _refuse(code, detail=""):
    raise McpDiscoveryTrustError(code, detail)


def _nonempty_str(value):
    return isinstance(value, str) and bool(value.strip())


def _check_pins(pins):
    if not isinstance(pins, dict):
        _refuse(DISCOVERY_RESULT_MALFORMED,
                "pins must be a mapping, got %r" % (type(pins).__name__,))
    for name, identity in pins.items():
        if not _nonempty_str(name):
            _refuse(DISCOVERY_RESULT_MALFORMED,
                    "pin name must be a non-empty string")
        if not _nonempty_str(identity):
            _refuse(DISCOVERY_RESULT_MALFORMED,
                    "pin identity for %r must be a non-empty string" % (
                        name,))


def _check_discovery_shape(discovery):
    if not isinstance(discovery, dict):
        _refuse(DISCOVERY_RESULT_MALFORMED,
                "discovery must be a mapping, got %r" % (
                    type(discovery).__name__,))
    name = discovery.get("name")
    endpoint = discovery.get("endpoint")
    identity = discovery.get("identity")
    source = discovery.get("source")
    if not _nonempty_str(name):
        _refuse(DISCOVERY_RESULT_MALFORMED,
                "discovery.name must be a non-empty string")
    if not _nonempty_str(endpoint):
        _refuse(DISCOVERY_RESULT_MALFORMED,
                "discovery.endpoint must be a non-empty string")
    if not _nonempty_str(identity):
        _refuse(DISCOVERY_RESULT_MALFORMED,
                "discovery.identity must be a non-empty string")
    if not isinstance(source, str):
        _refuse(DISCOVERY_RESULT_MALFORMED,
                "discovery.source must be a string")
    return name, endpoint, identity, source


def check_discovery(discovery, pins):
    """Trust decision for one MCP server discovery result.

    ``discovery`` is the caller-supplied (untrusted) parsed result;
    ``pins`` is the deployment-owned ``{name: pinned_identity}``
    mapping. Returns the accept record on a pinned, matching
    identity; raises :class:`McpDiscoveryTrustError` otherwise.
    The ``source`` label is recorded, never trusted.
    """
    _check_pins(pins)
    name, _endpoint, identity, source = _check_discovery_shape(discovery)
    if name not in pins:
        _refuse(DISCOVERY_UNPINNED,
                "no deployment pin for discovered server %r; the "
                "discovery plane is untrusted" % (name,))
    if identity != pins[name]:
        _refuse(DISCOVERY_IDENTITY_MISMATCH,
                "discovered identity for %r does not match the "
                "deployment pin" % (name,))
    return {"verdict": _ACCEPT, "name": name, "identity": identity,
            "source": source}
