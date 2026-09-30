"""SPIFFE-attested KMS auth: short-lived Vault client tokens from JWT-SVIDs.

Wave-232 lane A. Stdlib only.

ADAPT of the wave-231 spike design (prose re-derived; no donor code was
lifted and no donor security claim was trusted): the static ``VAULT_TOKEN``
env bearer is the weakest credential in the KMS path -- long-lived,
env-scoped, usable by any process that can read the environment, with no
attestation of *which* workload is signing. This module supplies the
authentication half that KMS-resident signing lacks:

* :class:`CredentialProvider` -- injectable, stdlib-only source of
  *short-lived* Vault client tokens, acquired through workload
  attestation. Injected at channel setup (constructor), exactly like the
  ``transport`` already is. ``KmsSigner.sign``/``verify`` are untouched.
* :class:`FileJwtSvidCredentialProvider` -- reads a JWT-SVID from a file
  the SPIFFE CSI driver projects and rotates (deployment-owned rotation),
  checks 3-segment shape, ``exp``, ``aud`` and file permissions *before*
  any network call, then exchanges it via Vault/OpenBao's JWT auth method
  (``POST /v1/auth/jwt/login``). The client token is cached only to its
  ``lease_duration``. On a 403 the provider re-reads the SVID and
  re-logs-in **once**, then fails closed -- never a retry loop.
* :func:`vault_provider_from_spiffe_config` -- the ``provider:
  vault-spiffe`` branch of ``gov.kms.kms_provider_from_config``. This
  factory **never reads ``VAULT_TOKEN``** -- the no-static-fallback
  invariant is structural (this code path contains no reference to the
  env var), not operator discipline. A deployment that needs a break-glass
  reconfigures to ``provider: vault`` explicitly (an auditable config
  change), never an automatic downgrade.

Why file-based SVIDs and not the SPIRE Workload API: the Workload API is
gRPC over a Unix socket -- a stdlib-only client would mean hand-rolling
HTTP/2 framing, exactly the kind of bespoke crypto-adjacent code this
repo avoids. Reading a projected file with strict checks is stdlib and
keeps the no-network-in-unit-tests discipline (tests inject a fake
``CredentialProvider``, mirroring ``FakeVaultTransport``).

Why JWT-SVID first: JWT via the Vault JWT auth method is one more POST on
the existing transport. X.509 SVID client-cert mTLS needs server-side TLS
client-cert configuration -- a bigger deployment surface, left as a
hardening follow-on.

Machine refusal codes (domain ``spiffe``, all client-side pre-network
unless noted):

* ``spiffe-svid-unavailable`` -- SVID file absent/unreadable (SPIRE agent
  down or volume unmounted). Zero requests to Vault.
* ``spiffe-svid-expired`` -- ``exp`` passed (clock-skew allowance 60s).
  Zero requests to Vault.
* ``spiffe-svid-malformed`` -- not 3 segments, bad base64/JSON, missing or
  non-numeric ``exp``, missing ``aud``, untrustworthy clock (``nbf`` in the
  future), non-regular file, oversize file. Zero requests to Vault.
* ``spiffe-audience-mismatch`` -- SVID ``aud`` does not match the
  configured audience. The foreign SVID is never presented. Zero requests.
* ``spiffe-permission-invalid`` -- SVID file has group/other permission
  bits or is not owned by the process uid. Never read a secret other
  principals could have swapped.
* ``spiffe-auth-refused`` -- the JWT login itself failed (403 after one
  re-login, other HTTP errors, transport failure, malformed login
  response). Vault-side failures are never retried in a loop.

All exceptions subclass :class:`SpiffeError`, which subclasses
``gov.kms.KmsError`` so existing ``except KmsError`` fail-closed handlers
(including ``KmsSigner``) catch them; the machine ``code`` attribute
survives. Messages never carry key material, tokens, or SVID bytes.

Honest residuals (documented, not solved here):

* The Vault **server-side** JWT role binding (``bound_subject``,
  ``bound_audiences``, token TTLs/policies) is the actual security
  boundary; this client only guarantees *which* credential is presented
  and *when presentation is refused*. A misconfigured Vault role voids
  the whole thing -- server config is deployment-owned and must itself
  be audited.
* A JWT-SVID proves workload identity **at issuance**, not continuous
  process integrity; a compromised process holding a valid SVID can still
  authenticate until the SVID expires. This is why deployments must use
  minutes-scale SVID TTLs, not hours.
* This module never verifies the SVID's signature -- it is a bearer
  credential *presented to Vault*, and Vault validates it. Checking
  signature client-side would add a trust-bundle the client does not need.
* No live SPIRE/OpenBao round trip exists in this repo's tests ($0
  spend); the break-first battery ``evals/w232_spiffe_probes.py`` is the
  acceptance gate, using fakes.
"""

import abc
import base64
import json
import os
import stat
import threading
import time

from .kms import KmsError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Vault/OpenBao JWT auth login path (public-docs API shape, same citation
#: discipline as gov/kms_vault.py).
LOGIN_PATH = "/v1/auth/jwt/login"

#: Fail closed on SVID files larger than this (a JWT-SVID is ~1-2 KiB).
_MAX_SVID_BYTES = 8192

#: Clock-skew allowance for exp/nbf checks (seconds).
_CLOCK_SKEW_S = 60

#: Token-cache safety margin: stop using the cached client token this many
#: seconds before its lease ends.
_TOKEN_SKEW_S = 30

#: Group/other permission bits that must be zero on the SVID file.
_FORBIDDEN_MODE_BITS = 0o077


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SpiffeError(KmsError):
    """Base class for SPIFFE-attested KMS-auth refusals. ``code`` is
    machine-readable and is the taxonomy vocabulary; diagnostic detail
    lives in the human message. Never carries key material, tokens, or
    SVID bytes."""
    code = "spiffe-refused"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class SvidUnavailableError(SpiffeError):
    """The SVID file is absent or unreadable (SPIRE agent down, volume
    unmounted). Fail closed before any network call."""
    code = "spiffe-svid-unavailable"


class SvidExpiredError(SpiffeError):
    """The SVID's ``exp`` has passed (clock-skew allowance applied).
    Fail closed before any network call."""
    code = "spiffe-svid-expired"


class SvidMalformedError(SpiffeError):
    """The SVID is not a usable JWT (shape, encoding, claims) or the file
    itself is wrong (non-regular, oversize). Fail closed before any
    network call."""
    code = "spiffe-svid-malformed"


class AudienceMismatchError(SpiffeError):
    """The SVID's ``aud`` does not match the configured audience. A foreign
    SVID is never presented to Vault."""
    code = "spiffe-audience-mismatch"


class AuthRefusedError(SpiffeError):
    """The JWT login itself failed: 403 after exactly one re-login, other
    HTTP errors, transport failure, or a malformed login response."""
    code = "spiffe-auth-refused"


class PermissionInvalidError(SpiffeError):
    """The SVID file has group/other permission bits or is not owned by the
    process uid. Never read a secret other principals could have swapped."""
    code = "spiffe-permission-invalid"


# ---------------------------------------------------------------------------
# CredentialProvider ABC
# ---------------------------------------------------------------------------

class CredentialProvider(abc.ABC):
    """Injectable source of short-lived Vault client tokens.

    Implementations must be safe to call from multiple threads and must
    never fall back to a static token. ``current_token`` raises
    :class:`SpiffeError` (a ``KmsError``) on any refusal.
    """

    @abc.abstractmethod
    def current_token(self):
        """Return a currently-valid Vault client token (str).

        May perform network I/O (login). Raises :class:`SpiffeError` on
        any refusal -- never returns an empty or stale token.
        """

    def invalidate(self):
        """Drop any cached credential. The next :meth:`current_token`
        re-authenticates. Default: no cache to drop."""


# ---------------------------------------------------------------------------
# File-based JWT-SVID provider
# ---------------------------------------------------------------------------

def _b64url_decode(segment):
    try:
        padded = segment + "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        raise SvidMalformedError(
            "spiffe SVID payload is not valid base64url")


class FileJwtSvidCredentialProvider(CredentialProvider):
    """Read a JWT-SVID from a projected file and exchange it for a
    short-lived Vault client token via the JWT auth method.

    ``transport`` is any ``gov.kms_vault.VaultTransport`` (tests inject a
    fake; production injects ``UrllibVaultTransport``). ``now`` is the clock
    (epoch seconds); inject it in tests. No network happens at
    construction: misconfiguration fails closed at first use.
    """

    def __init__(self, svid_path, *, audience, role, transport,
                 now=None, clock_skew_s=_CLOCK_SKEW_S,
                 token_skew_s=_TOKEN_SKEW_S,
                 max_svid_bytes=_MAX_SVID_BYTES):
        if not isinstance(svid_path, str) or not svid_path:
            raise ValueError("svid_path must be a non-empty string")
        if not isinstance(audience, str) or not audience:
            raise ValueError("audience must be a non-empty string")
        if not isinstance(role, str) or not role:
            raise ValueError("role must be a non-empty string")
        if transport is None or not hasattr(transport, "request"):
            raise TypeError("transport must expose request(), got %r"
                            % type(transport).__name__)
        if not isinstance(clock_skew_s, (int, float)) or clock_skew_s < 0:
            raise ValueError("clock_skew_s must be a non-negative number")
        if not isinstance(token_skew_s, (int, float)) or token_skew_s < 0:
            raise ValueError("token_skew_s must be a non-negative number")
        if not isinstance(max_svid_bytes, int) or max_svid_bytes <= 0:
            raise ValueError("max_svid_bytes must be a positive int")
        self._svid_path = svid_path
        self._audience = audience
        self._role = role
        self._transport = transport
        self._now = now or time.time
        self._clock_skew_s = clock_skew_s
        self._token_skew_s = token_skew_s
        self._max_svid_bytes = max_svid_bytes
        self._lock = threading.Lock()
        self._cached_token = None
        self._token_expiry = 0.0

    # -- SVID acquisition (pre-network checks) ---------------------------

    def _read_svid(self):
        """Read and validate the SVID file. Every refusal here happens
        BEFORE any network call. Returns the raw JWT string."""
        try:
            st = os.stat(self._svid_path)
        except FileNotFoundError:
            raise SvidUnavailableError(
                "spiffe SVID file absent (SPIRE agent down or volume "
                "unmounted): %r" % (self._svid_path,))
        except NotADirectoryError:
            raise SvidUnavailableError(
                "spiffe SVID path not reachable: %r" % (self._svid_path,))
        except PermissionError:
            raise SvidUnavailableError(
                "spiffe SVID file not readable: %r" % (self._svid_path,))
        except OSError as e:
            raise SvidUnavailableError(
                "spiffe SVID file stat failed (%s): %r"
                % (type(e).__name__, self._svid_path))
        if not stat.S_ISREG(st.st_mode):
            raise SvidMalformedError(
                "spiffe SVID path is not a regular file")
        if st.st_mode & _FORBIDDEN_MODE_BITS:
            raise PermissionInvalidError(
                "spiffe SVID file has group/other permission bits "
                "(mode %o); refusing to read a secret other principals "
                "could have swapped" % (stat.S_IMODE(st.st_mode),))
        try:
            euid = os.geteuid()
        except AttributeError:
            euid = None  # non-POSIX: owner check not available; mode
            # check above is the enforced boundary there.
        if euid is not None and st.st_uid != euid:
            raise PermissionInvalidError(
                "spiffe SVID file not owned by the process uid")
        if st.st_size > self._max_svid_bytes:
            raise SvidMalformedError(
                "spiffe SVID file exceeds size bound (%d bytes)"
                % (st.st_size,))
        try:
            with open(self._svid_path, "rb") as fh:
                raw = fh.read(self._max_svid_bytes + 1)
        except OSError as e:
            raise SvidUnavailableError(
                "spiffe SVID file read failed (%s)" % type(e).__name__)
        if len(raw) > self._max_svid_bytes:
            raise SvidMalformedError(
                "spiffe SVID file exceeds size bound")
        try:
            return raw.decode("ascii")
        except UnicodeDecodeError:
            raise SvidMalformedError(
                "spiffe SVID file is not ASCII text")

    def _check_svid(self, raw, now):
        """Validate the JWT shape and claims. Returns the raw JWT on
        success. Raises before any network call."""
        segments = raw.strip().split(".")
        if len(segments) != 3 or not all(segments):
            raise SvidMalformedError(
                "spiffe SVID is not a three-segment JWT")
        payload_bytes = _b64url_decode(segments[1])
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            raise SvidMalformedError(
                "spiffe SVID payload is not valid JSON")
        if not isinstance(payload, dict):
            raise SvidMalformedError(
                "spiffe SVID payload is not a JSON object")
        exp = payload.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise SvidMalformedError(
                "spiffe SVID has no numeric exp claim")
        if now > exp + self._clock_skew_s:
            raise SvidExpiredError(
                "spiffe SVID expired (exp=%r)" % (exp,))
        nbf = payload.get("nbf")
        if nbf is not None:
            if isinstance(nbf, bool) or not isinstance(nbf, (int, float)):
                raise SvidMalformedError(
                    "spiffe SVID has non-numeric nbf claim")
            if nbf > now + self._clock_skew_s:
                # The clock is untrustworthy (or the SVID is from the
                # future): fail closed, do not sign when time is wrong.
                raise SvidMalformedError(
                    "spiffe SVID not yet valid (nbf=%r)" % (nbf,))
        aud = payload.get("aud")
        if aud is None:
            raise SvidMalformedError(
                "spiffe SVID has no aud claim")
        auds = [aud] if isinstance(aud, str) else aud
        if not isinstance(auds, list) or not all(
                isinstance(a, str) for a in auds):
            raise SvidMalformedError(
                "spiffe SVID aud claim is not a string or string list")
        if self._audience not in auds:
            raise AudienceMismatchError(
                "spiffe SVID audience does not match %r (a foreign SVID "
                "is never presented)" % (self._audience,))
        return raw.strip()

    # -- JWT login --------------------------------------------------------

    def _login_once(self, svid):
        """One JWT-login attempt. Returns ``(client_token, lease_duration)``
        or ``None`` on HTTP 403 (caller retries exactly once). Any other
        failure raises :class:`AuthRefusedError`."""
        body = json.dumps({"jwt": svid, "role": self._role}).encode("utf-8")
        # NOTE: no X-Vault-Token header -- this IS the login.
        headers = {"Content-Type": "application/json"}
        try:
            status, resp_body = self._transport.request(
                "POST", LOGIN_PATH, headers, body)
        except Exception as e:  # a transport that raises something else
            raise AuthRefusedError(
                "spiffe JWT login transport failure (%s)"
                % (type(e).__name__,))
        if status == 403:
            return None
        if status != 200:
            raise AuthRefusedError(
                "spiffe JWT login refused: HTTP %d" % (status,))
        try:
            doc = json.loads(resp_body.decode("utf-8"))
            auth = doc["auth"]
            token = auth["client_token"]
            lease = int(auth.get("lease_duration", 0))
        except Exception:
            raise AuthRefusedError(
                "spiffe JWT login: malformed response from server")
        if not isinstance(token, str) or not token:
            raise AuthRefusedError(
                "spiffe JWT login: empty client token in response")
        if lease < 0:
            raise AuthRefusedError(
                "spiffe JWT login: negative lease duration")
        return token, lease

    # -- CredentialProvider -----------------------------------------------

    def current_token(self):
        """Return a currently-valid Vault client token.

        Pre-network SVID checks run on every call (the projected file
        rotates under us). The client token is cached only to its lease
        expiry minus the safety margin. On a 403 the SVID is re-read and
        the login retried exactly once, then fail closed.
        """
        with self._lock:
            now = self._now()
            if (self._cached_token is not None
                    and now < self._token_expiry):
                return self._cached_token
            raw = self._read_svid()
            svid = self._check_svid(raw, now)
            result = self._login_once(svid)
            if result is None:
                # The SVID may have rotated between read and login:
                # re-read and retry exactly once, then fail closed.
                raw = self._read_svid()
                svid = self._check_svid(raw, self._now())
                result = self._login_once(svid)
                if result is None:
                    raise AuthRefusedError(
                        "spiffe JWT login refused (HTTP 403) after one "
                        "re-login; failing closed")
            token, lease = result
            self._cached_token = token
            self._token_expiry = (self._now() + lease
                                  - self._token_skew_s)
            return token

    def invalidate(self):
        """Drop the cached client token; the next call re-authenticates."""
        with self._lock:
            self._cached_token = None
            self._token_expiry = 0.0


# ---------------------------------------------------------------------------
# Factory: provider: vault-spiffe
# ---------------------------------------------------------------------------

def _factory_bool(mapping, key, default):
    value = mapping.get(key, default)
    if not isinstance(value, bool):
        raise KmsError(
            "vault-spiffe config: %r must be a strict bool, got %r"
            % (key, value))
    return value


def _factory_timeout_s(mapping, default=10):
    value = mapping.get("timeout_s", default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or value <= 0:
        raise KmsError(
            "vault-spiffe config: 'timeout_s' must be a positive number, "
            "got %r" % (value,))
    return value


def _factory_ca_bundle(mapping):
    value = mapping.get("ca_bundle")
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise KmsError(
            "vault-spiffe config: 'ca_bundle' must be a PEM path string, "
            "got %r" % (value,))
    if not os.path.isfile(value):
        raise KmsError(
            "vault-spiffe config: ca_bundle not found: %r" % (value,))
    return value


def vault_provider_from_spiffe_config(mapping):
    """Build a :class:`gov.kms_vault.VaultKmsProvider` from operator config
    -- the ``provider: vault-spiffe`` branch of
    ``gov.kms.kms_provider_from_config``.

    **This factory never reads ``VAULT_TOKEN``.** The no-static-fallback
    invariant is structural: this code path contains no reference to the
    env var, so a fallback cannot be "temporarily enabled" by an operator
    under pressure. The Vault address still comes from the environment
    (``VAULT_ADDR``), like ``provider: vault``.

    Mapping keys (all operator-controlled; missing/invalid ->
    :class:`KmsError`):

    * ``svid_path`` (required) -- projected JWT-SVID file path.
    * ``audience`` (required) -- expected SVID ``aud`` (e.g.
      ``"vault://<cluster>"``).
    * ``role`` (required) -- Vault JWT auth role bound to the SPIFFE ID.
    * ``mount`` -- transit mount (default ``"transit"``).
    * ``allow_http`` -- strict bool, default ``False``.
    * ``ca_bundle`` -- PEM CA-bundle path for HTTPS.
    * ``timeout_s`` -- positive seconds per request (default 10).

    Error-type contract: every failure caused by operator-controlled input
    raises :class:`KmsError` -- the factory boundary never leaks the
    transport's bare ``ValueError``.
    """
    # Lazy import: gov/kms_vault.py imports from .kms, and this module is
    # imported lazily from gov/kms.py; a top-level import here would be
    # circular.
    from .kms_vault import UrllibVaultTransport, VaultKmsProvider

    if not isinstance(mapping, dict):
        raise KmsError("vault-spiffe config must be a mapping, got %r"
                       % (type(mapping).__name__,))
    svid_path = mapping.get("svid_path")
    audience = mapping.get("audience")
    role = mapping.get("role")
    for name, value in (("svid_path", svid_path),
                        ("audience", audience), ("role", role)):
        if not isinstance(value, str) or not value:
            raise KmsError(
                "vault-spiffe config: %r is required and must be a "
                "non-empty string, got %r" % (name, value))
    addr = os.environ.get("VAULT_ADDR", "").strip()
    if not addr:
        raise KmsError(
            "kms provider 'vault-spiffe' requires VAULT_ADDR to be set "
            "(fail-closed: no Vault address, no provider)")
    mount = mapping.get("mount", "transit")
    allow_http = _factory_bool(mapping, "allow_http", False)
    ca_bundle = _factory_ca_bundle(mapping)
    timeout_s = _factory_timeout_s(mapping)
    try:
        transport = UrllibVaultTransport(addr, timeout_s=timeout_s,
                                         allow_http=allow_http,
                                         ca_bundle=ca_bundle)
        provider = FileJwtSvidCredentialProvider(
            svid_path, audience=audience, role=role, transport=transport)
        return VaultKmsProvider(transport, credential_provider=provider,
                                mount=mount)
    except (ValueError, TypeError) as e:
        raise KmsError(
            "kms provider 'vault-spiffe': unusable configuration (%s)"
            % (e,))
    except KmsError:
        raise
