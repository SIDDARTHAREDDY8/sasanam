"""MCP-surface secure-defaults audit (W244-7, ADAPT -- patterns only).

Incident-derived attacker shape: two live clusters showed the same
class -- insecure by default, safe only when the operator opts in:

* ContextForge CVE-2026-78573 (9.8): a default-credentials MCP gateway
  reached unauthenticated admin. Placeholder/empty credentials shipped
  in the deploy config must refuse to go live.
* Langflow CVE-2026-85025 (CWE-863, 9.8): public MCP endpoints skipped
  the anonymous-execution guard. A public endpoint without an
  execution guard must be refused before it goes live.
* Langflow CVE-2026-81941 (8.8): stdio bypass of the auth path. A
  transport carrying agent traffic outside the mediated auth path
  must be refused unless it is explicitly mediated.

``audit_surface(config, issuer_key=...)`` walks a declared surface
config and fails closed on every insecure default. On success it
returns a signed attestation binding the sha256 of the canonical
config; ``verify_attestation`` recomputes both the digest and the
MAC, so post-attestation drift is detectable.

Refusal vocabulary (domain ``mcp-surface``, all fail-closed):

* ``surface-default-credentials`` -- gateway or endpoint credentials
  are missing, empty, or one of the well-known placeholder/default
  values. The refusal names the exact violated default.
* ``surface-admin-unauthenticated`` -- an admin endpoint declares no
  auth (or ``auth: "none"``).
* ``surface-public-unguarded`` -- a public endpoint has no execution
  guard / per-call authorization policy.
* ``surface-transport-bypass`` -- a stdio (or otherwise unmediated)
  transport carries traffic outside the mediated auth path.
* ``surface-config-malformed`` -- the config is not the expected
  shape (mapping with ``surface``/``endpoints``/``gateway`` types).
* ``surface-attestation-key-missing`` -- no deployment issuer key was
  supplied; attestation is impossible, so the audit refuses rather
  than issuing an unsigned attestation.

Deliberate non-goals (loud, never silent):

* The audit NEVER auto-remediates: no credential is replaced, no
  guard is enabled, no endpoint is rewritten. A silent fix hides
  operator error; the refusal names the violated default and the
  operator must explicitly declare the secure value.
* The default-credential list is a *known-placeholder* list, not a
  strength meter: a weak-but-not-listed password is not this
  module's refusal (credential policy is deployment-owned).

Honest boundaries
-----------------
* A passing audit attests the *declared* config only; it cannot
  observe the live surface. An operator who passes the audit and
  then deploys different bytes is caught by
  ``verify_attestation`` ONLY if the attestation is checked at
  deploy time -- the audit does not deploy.
* The HMAC attestation proves the config was audited and unaltered
  since, not that the config is wise: shared-secret authenticity,
  not non-repudiation.
* The issuer-key custody is deployment-owned: the key is required
  explicitly (fail closed when absent) and never derived in-repo.

Stdlib only. Deterministic: no clock, no network.
"""

import copy
import hashlib
import hmac
import json

SURFACE_DEFAULT_CREDENTIALS = "surface-default-credentials"
SURFACE_ADMIN_UNAUTHENTICATED = "surface-admin-unauthenticated"
SURFACE_PUBLIC_UNGUARDED = "surface-public-unguarded"
SURFACE_TRANSPORT_BYPASS = "surface-transport-bypass"
SURFACE_CONFIG_MALFORMED = "surface-config-malformed"
SURFACE_ATTESTATION_KEY_MISSING = "surface-attestation-key-missing"

_ATTESTATION_DOMAIN = b"gov-surface-attestation/v1\x00"

# Well-known placeholder/default credential VALUES (not a strength
# meter). Any credential equal to one of these, case-insensitively,
# is refused; so is a missing or empty credential.
_DEFAULT_CREDENTIAL_VALUES = frozenset({
    "", "admin", "administrator", "root", "password", "passwd",
    "changeme", "change-me", "default", "letmein", "secret",
    "passw0rd", "p@ssw0rd", "qwerty", "123456", "12345678",
    "guest", "mcp", "gateway", "token", "token123", "apikey",
    "api-key", "none", "null", "undefined", "test", "demo",
    "example", "password1", "admin123", "root123", "changethis",
})

# Credential FIELDS whose value is checked against the default list.
_CREDENTIAL_FIELDS = ("password", "secret", "token", "api_key",
                      "apikey", "bearer_token", "client_secret")


class SurfaceDefaultsError(Exception):
    """Fail-closed secure-defaults audit refusal. ``code`` is the
    vocabulary; ``detail`` names the exact violated default."""

    def __init__(self, code, detail=""):
        super(SurfaceDefaultsError, self).__init__(
            "%s: %s" % (code, detail) if detail else code)
        self.code = code
        self.detail = detail


def _malformed(detail):
    raise SurfaceDefaultsError(SURFACE_CONFIG_MALFORMED, detail)


def _refuse(code, detail):
    raise SurfaceDefaultsError(code, detail)


def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def config_digest(config):
    """sha256 (hex) of the canonical config bytes. Pure function."""
    return hashlib.sha256(_canonical_bytes(config)).hexdigest()


def _check_issuer_key(issuer_key):
    if not isinstance(issuer_key, (bytes, bytearray)) \
            or not issuer_key:
        _refuse(SURFACE_ATTESTATION_KEY_MISSING,
                "attestation requires a deployment issuer key supplied "
                "explicitly; refusing rather than issuing an unsigned "
                "attestation")
    if isinstance(issuer_key, bytearray):
        issuer_key = bytes(issuer_key)
    return issuer_key


def _attestation_mac(issuer_key, body_bytes):
    return hmac.new(issuer_key, _ATTESTATION_DOMAIN + body_bytes,
                    hashlib.sha256).hexdigest()


def _is_default_credential(value):
    if not isinstance(value, str):
        return True  # non-string credential material is malformed-by-default
    return value.strip().lower() in _DEFAULT_CREDENTIAL_VALUES


def _audit_credentials(config):
    gw = config["gateway"]
    creds = gw.get("credentials")
    if not isinstance(creds, dict) or not creds:
        _refuse(SURFACE_DEFAULT_CREDENTIALS,
                "gateway.credentials is missing or empty; declare explicit "
                "non-default credentials")
    fields = [f for f in _CREDENTIAL_FIELDS if f in creds]
    if not fields:
        # No recognizable credential field at all: treat as missing.
        fields_str = ", ".join(_CREDENTIAL_FIELDS)
        _refuse(SURFACE_DEFAULT_CREDENTIALS,
                "gateway.credentials declares none of (%s); declare an "
                "explicit non-default credential" % fields_str)
    for field in fields:
        value = creds[field]
        if _is_default_credential(value):
            _refuse(SURFACE_DEFAULT_CREDENTIALS,
                    "gateway.credentials.%s is a well-known default/empty "
                    "placeholder value %r; declare an explicit non-default "
                    "credential" % (field, value))
    # Endpoint-scoped credentials get the same treatment.
    for idx, ep in enumerate(config["endpoints"]):
        ecreds = ep.get("credentials")
        if ecreds is None:
            continue
        if not isinstance(ecreds, dict):
            _refuse(SURFACE_DEFAULT_CREDENTIALS,
                    "endpoint[%d] (%s) credentials must be a mapping" %
                    (idx, ep.get("name", "?")))
        for field in [f for f in _CREDENTIAL_FIELDS if f in ecreds]:
            value = ecreds[field]
            if _is_default_credential(value):
                _refuse(SURFACE_DEFAULT_CREDENTIALS,
                        "endpoint[%d] (%s) credentials.%s is a well-known "
                        "default/empty placeholder value %r; declare an "
                        "explicit non-default credential"
                        % (idx, ep.get("name", "?"), field, value))


def _audit_endpoints(config):
    for idx, ep in enumerate(config["endpoints"]):
        name = ep.get("name", "?")
        auth = ep.get("auth")
        auth_ok = isinstance(auth, str) and auth.strip() \
            and auth.strip().lower() != "none"
        if ep.get("admin") is True:
            if not auth_ok:
                _refuse(SURFACE_ADMIN_UNAUTHENTICATED,
                        "endpoint[%d] (%s) is admin and declares no auth "
                        "(auth=%r); declare an explicit auth mechanism" %
                        (idx, name, auth))
        if ep.get("public") is True:
            guard = ep.get("execution_guard")
            if guard is not True:
                _refuse(SURFACE_PUBLIC_UNGUARDED,
                        "endpoint[%d] (%s) is public and declares no "
                        "execution guard (execution_guard=%r); declare "
                        "execution_guard: true with a per-call "
                        "authorization policy" % (idx, name, guard))
            if not auth_ok:
                _refuse(SURFACE_ADMIN_UNAUTHENTICATED,
                        "endpoint[%d] (%s) is public and declares no auth "
                        "(auth=%r); public endpoints require an explicit "
                        "auth mechanism plus the execution guard" %
                        (idx, name, auth))
        transport = ep.get("transport")
        if isinstance(transport, str) and transport.strip().lower() == "stdio":
            mediated = ep.get("auth_mediation")
            if mediated is not True:
                _refuse(SURFACE_TRANSPORT_BYPASS,
                        "endpoint[%d] (%s) uses stdio transport without "
                        "mediated auth (auth_mediation=%r); stdio must be "
                        "explicitly mediated or the endpoint removed" %
                        (idx, name, mediated))


def audit_surface(config, issuer_key=None):
    """Audit a declared MCP-shaped surface config; fail closed on any
    insecure default. Never mutates ``config``.

    On success returns the signed attestation::

        {"v": 1, "verdict": "attested", "surface": <name>,
         "config_digest": <sha256 hex of canonical config>,
         "checks": ["credentials", "endpoints"],
         "mac": <hmac-sha256 hex, domain-separated>}
    """
    snapshot = copy.deepcopy(config)
    if not isinstance(config, dict):
        _malformed("surface config must be a mapping")
    name = config.get("surface")
    if isinstance(name, bool) or not isinstance(name, str) \
            or not name.strip():
        _malformed("surface.surface must be a non-empty string")
    gateway = config.get("gateway")
    if not isinstance(gateway, dict):
        _malformed("surface.gateway must be a mapping")
    endpoints = config.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        _malformed("surface.endpoints must be a non-empty list")
    for idx, ep in enumerate(endpoints):
        if not isinstance(ep, dict):
            _malformed("surface.endpoints[%d] must be a mapping" % idx)

    issuer_key = _check_issuer_key(issuer_key)

    _audit_credentials(config)
    _audit_endpoints(config)

    digest = config_digest(snapshot)
    body = _canonical_bytes({"v": 1, "surface": name,
                             "config_digest": digest})
    return {
        "v": 1,
        "verdict": "attested",
        "surface": name,
        "config_digest": digest,
        "checks": ["credentials", "endpoints"],
        "mac": _attestation_mac(issuer_key, body),
    }


def verify_attestation(attestation, config, issuer_key=None):
    """Recompute the digest and MAC for ``config``; return True only
    when both match the attestation. Any drift or wrong key -> False.
    Never raises on malformed input (returns False)."""
    try:
        issuer_key = _check_issuer_key(issuer_key)
    except SurfaceDefaultsError:
        return False
    try:
        if not isinstance(attestation, dict):
            return False
        if attestation.get("verdict") != "attested":
            return False
        name = attestation.get("surface")
        digest = attestation.get("config_digest")
        mac = attestation.get("mac")
        if not (isinstance(name, str) and isinstance(digest, str)
                and isinstance(mac, str)):
            return False
        if config_digest(config) != digest:
            return False
        body = _canonical_bytes({"v": 1, "surface": name,
                                 "config_digest": digest})
        return hmac.compare_digest(
            _attestation_mac(issuer_key, body), mac)
    except Exception:  # noqa: BLE001 -- fail closed on anything odd
        return False
