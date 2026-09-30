"""Transit-managed Ed25519 audit signing (OpenBao / HashiCorp Vault).

The KMS seam (``gov/kms.py`` / ``gov/kms_vault.py``) covers envelope
encryption only; the audit-*signing* path had no KMS story. This module
is the missing adapter: :class:`TransitSigner` implements the
``gov.signing.Signer`` ABC by signing through the transit secrets
engine's Ed25519 keys (``POST /v1/<mount>/sign/<key>``), while
verification is ALWAYS local, against public keys exported from
transit (``GET /v1/<mount>/export/public-key/<key>/<version>``).

Threat model (from the wave-186 OpenBao spike): the transit server is
*not* fully trusted. A compromised or buggy server may lie -- in
particular its ``/verify`` endpoint can claim ``{"valid": true}`` for a
forgery. This adapter therefore NEVER calls the server's ``/verify``
endpoint; every signature is checked locally with ``gov.ed25519``
against an exported public key. A signature that does not verify
locally is rejected no matter what the server claims.

Version binding (consistent with the wave-185 keyset's
``sig_key_version`` story): transit signs with key *versions*; the
server embeds the version in the signature string (``vault:vN:...``)
and reports it as ``data.key_version``. :meth:`TransitSigner.sign`
returns the raw 64-byte signature; :meth:`TransitSigner.sign_versioned`
additionally returns the version the server actually used, and the
caller records it in the entry envelope as ``sig_key_version``.
:func:`verify_versioned` fails closed when no version is bound
(stripped) -- there is no silent "pick latest" fallback, because that
would let a rotated-out version keep verifying unattributed.

What this module does NOT do (deliberate, documented):

* key creation / rotation / revocation -- operator duties via the
  transit API (a separate, privileged identity; see the runbook).
  Transit rotation has no signed lineage; the wave-185 keyset's
  rotation records remain the attestation story.
* HMAC-per-entry -- transit has an ``hmac`` op, but the HMAC chains
  correctly use locally-held envelope-wrapped data keys.
* private-key export -- ``exportable: False`` is the custody posture;
  only public keys ever leave the server.

Transport mechanics (fail-closed HTTP: non-200 / I/O / malformed ->
``KmsError``) are composed from :class:`gov.kms_vault.VaultKmsProvider`'s
internals -- the same tested call path the envelope adapter uses, so
auth, TLS, timeout, and error-mapping behavior cannot drift between
the two seams. Unit tests run with zero network against an in-test
fake transit server.

Transit API shape used (public-docs knowledge only -- no credentials,
no network in this module)::

    POST /v1/<mount>/sign/<key>  {"input": "<base64>", "key_version": N}
      -> 200 {"data": {"signature": "vault:vN:<base64-sig>",
                       "key_version": N}}
    GET  /v1/<mount>/keys/<key>
      -> 200 {"data": {"name": ..., "type": "ed25519",
                       "latest_version": N, ...}}
    GET  /v1/<mount>/export/public-key/<key>/<version>
      -> 200 {"data": {"public_key": "-----BEGIN PUBLIC KEY-----\\n..."}}

Secrecy discipline: signatures, inputs, public keys (beyond the 32-byte
form needed for verification), and the token are NEVER logged and NEVER
embedded in exception messages. Logs carry only operation names, key
names, versions, and HTTP statuses.

License note: written against the OpenBao/Vault transit HTTP API shape
(MPL-2.0 for OpenBao; API-shape knowledge only -- no vendored code).
"""

import base64
import logging
import os
import re
import threading
import urllib.parse

from . import ed25519
from .kms import KmsError, _KEY_ID_RE
from .kms_vault import (
    VaultTransport,
    VaultTransportError,
    UrllibVaultTransport,
    VaultKmsProvider,
    _MOUNT_RE,
    _config_bool,
    _config_ca_bundle,
    _config_timeout_s,
)
from .signing import Signer, Verifier, ed25519_key_id

_log = logging.getLogger("gov.kms.transit_signer")

#: ``vault:vN:<base64>`` -- the versioned signature envelope transit
#: returns. The version prefix is cross-checked against the response's
#: ``key_version`` field; disagreement is a lying/misbehaving server.
_SIG_RE = re.compile(r"^vault:v(\d+):([A-Za-z0-9+/=]+)$")

#: Fixed SPKI DER prefix for an Ed25519 public key:
#: SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING }.
_SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")

_PEM_BEGIN = "-----BEGIN PUBLIC KEY-----"
_PEM_END = "-----END PUBLIC KEY-----"


def _parse_ed25519_spki_pem(pem_text):
    """Extract the 32-byte Ed25519 public key from a PEM SPKI block.

    Fails closed (:class:`KmsError`) on any deviation: missing armor,
    bad base64, wrong DER prefix, or a key that is not exactly 32
    bytes. Never echoes key material in the error.
    """
    bad = KmsError("transit signer: exported public key is malformed "
                   "(not a valid Ed25519 SPKI PEM)")
    try:
        if not isinstance(pem_text, str):
            raise ValueError("not a string")
        lines = [ln.strip() for ln in pem_text.strip().splitlines()]
        if not lines or lines[0] != _PEM_BEGIN or lines[-1] != _PEM_END:
            raise ValueError("bad armor")
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
        if not der.startswith(_SPKI_ED25519_PREFIX):
            raise ValueError("not Ed25519 SPKI")
        pub = der[len(_SPKI_ED25519_PREFIX):]
        if len(pub) != 32:
            raise ValueError("bad key length")
        return bytes(pub)
    except KmsError:
        raise
    except Exception:
        raise bad


def _check_version(version, what="key_version"):
    if isinstance(version, bool) or not isinstance(version, int) \
            or version < 1:
        raise ValueError("%s must be an integer >= 1, got %r"
                         % (what, version))
    return version


class TransitSigner(Signer):
    """Ed25519 :class:`~gov.signing.Signer` backed by a transit engine.

    Signs through ``POST /v1/<mount>/sign/<key_name>``; the private key
    never leaves the server. Verification is deliberately NOT provided
    by this class -- use :meth:`verifier_for`, which verifies LOCALLY
    against the exported public key for a version.

    ``key_version`` pins the signing version (``None`` = server's
    latest). The version actually used is reported by
    :meth:`sign_versioned` / :attr:`last_signed_version` and must be
    recorded by the caller (e.g. as the entry envelope's
    ``sig_key_version``); :func:`verify_versioned` refuses signatures
    with no bound version.

    No network happens at construction: misconfiguration of the server
    fails closed at first use, never silently.
    """

    def __init__(self, transport, *, token=None, key_name, mount="transit",
                 key_version=None, credential_provider=None):
        if not isinstance(transport, VaultTransport):
            raise TypeError("transport must be a VaultTransport, got %r"
                            % type(transport).__name__)
        if (token is None) == (credential_provider is None):
            raise ValueError(
                "exactly one of token / credential_provider is required")
        if token is not None and (not isinstance(token, str) or not token):
            raise ValueError("transit token must be a non-empty string")
        if not isinstance(key_name, str) or not _KEY_ID_RE.match(key_name):
            raise ValueError("invalid transit key name %r" % (key_name,))
        if not isinstance(mount, str) or not _MOUNT_RE.match(mount):
            raise ValueError("invalid transit mount %r" % (mount,))
        if key_version is not None:
            _check_version(key_version)
        # Internal composition: the envelope adapter's tested fail-closed
        # call path (auth header, TLS/timeout behavior, error mapping).
        # Only _api/_path are used; wrap/unwrap are never touched.
        self._vault = VaultKmsProvider(transport, token=token,
                                       credential_provider=credential_provider,
                                       mount=mount)
        self._key_name = key_name
        self._pinned_version = key_version
        self._lock = threading.Lock()
        self._cached_version = None   # resolved effective version
        self._cached_pub = None       # 32-byte pub for _cached_version
        self._last_signed_version = None

    # -- identity ---------------------------------------------------

    @property
    def key_name(self):
        return self._key_name

    @property
    def pinned_version(self):
        return self._pinned_version

    @property
    def last_signed_version(self):
        """Version used by the most recent :meth:`sign` (None before
        the first signature)."""
        with self._lock:
            return self._last_signed_version

    def _resolve_version(self):
        """Effective signing version: pinned, else the server's latest.

        Unpinned signers read ``latest_version`` from the server's key
        metadata on first use (fail-closed on outage/auth/malformed
        response) and cache it; :meth:`refresh` drops the cache so the
        next resolution re-reads (e.g. after a transit rotation). The
        resolved version is ALWAYS passed explicitly in the sign
        payload (see :meth:`_sign_call`), so the version stamped into
        an audit envelope and the version that actually signed can
        never diverge across a rotation -- even when ``gov.log`` reads
        :attr:`key_version` and then calls :meth:`sign`, both go
        through this one cached resolution.
        """
        if self._pinned_version is not None:
            return self._pinned_version
        with self._lock:
            if self._cached_version is not None:
                return self._cached_version
        doc = self._vault._api("describe_key", "GET",
                               self._vault._path("keys", self._key_name),
                               None)
        try:
            latest = doc["data"]["latest_version"]
        except (KeyError, TypeError):
            raise KmsError("transit signer: malformed key metadata "
                           "from server")
        _check_version(latest, "latest_version")
        with self._lock:
            self._cached_version = latest
            # The cached public key (if any) belongs to the previous
            # cached version -- never let a new version alias an old
            # key. The next _pub_for re-exports for this version.
            self._cached_pub = None
        return latest

    def _export_pub(self, version):
        _check_version(version)
        path = (self._vault._path("export/public-key", self._key_name)
                + "/%d" % version)
        doc = self._vault._api("export_public_key", "GET", path, None)
        try:
            pem = doc["data"]["public_key"]
        except (KeyError, TypeError):
            raise KmsError("transit signer: malformed export response "
                           "from server")
        return _parse_ed25519_spki_pem(pem)

    def _pub_for(self, version):
        """32-byte public key for ``version`` (cached when it is the
        effective version)."""
        if version == self._resolve_version():
            with self._lock:
                if self._cached_pub is not None:
                    return self._cached_pub
            pub = self._export_pub(version)
            with self._lock:
                # Re-check under the lock: another thread may have won.
                if (self._cached_pub is not None
                        and self._cached_version == version):
                    return self._cached_pub
                self._cached_pub = pub
            return pub
        return self._export_pub(version)

    @property
    def key_id(self):
        """``ed25519_key_id`` of the effective version's public key.

        The identity follows the key version: after an operator
        rotation, ``refresh()`` resolves the new latest version and the
        key id changes -- exactly like the wave-185 keyset versions.
        """
        return ed25519_key_id(self.public_key)

    @property
    def public_key(self):
        return self._pub_for(self._resolve_version())

    @property
    def key_version(self):
        """The transit key version this signer signs with.

        This is the seam ``gov.log`` uses: ``ActionLog.append`` reads
        ``getattr(signer, "key_version", None)`` and writes it into the
        entry envelope as ``sig_key_version`` BEFORE computing the v2
        signature body, so the version is cryptographically bound into
        what :meth:`sign` then signs. Because :meth:`sign` resolves
        through this same property and passes the version explicitly
        in the transit request, the envelope version and the signing
        version cannot diverge across a rotation.
        """
        return self._resolve_version()

    def refresh(self):
        """Drop cached version/public key (call after an operator
        rotation). The next use re-resolves from the server."""
        with self._lock:
            self._cached_version = None
            self._cached_pub = None

    # -- signing ------------------------------------------------------

    def _sign_call(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        data = bytes(data)
        if not data:
            raise KmsError("transit signer: refusing to sign empty input")
        # Resolve ONCE and pass the version explicitly in the request.
        # Letting the server pick "latest" would open a rotation race:
        # gov.log reads signer.key_version, writes it into the entry
        # envelope, then calls sign() -- a rotation between the two
        # calls would stamp one version and sign with another. The
        # explicit key_version makes the request atomic against
        # rotation: the server signs with exactly this version or the
        # response fails the cross-checks below.
        version = self._resolve_version()
        payload = {"input": base64.b64encode(data).decode("ascii"),
                   "key_version": version}
        doc = self._vault._api("sign", "POST",
                               self._vault._path("sign", self._key_name),
                               payload)
        try:
            sig_str = doc["data"]["signature"]
            reported = doc["data"]["key_version"]
        except (KeyError, TypeError):
            raise KmsError("transit signer: malformed sign response "
                           "from server")
        # LYING-SERVER CROSS-CHECK (S8): the version embedded in the
        # signature envelope must agree with the reported key_version.
        # A server that disagrees with itself is not trusted -- and the
        # signature is verified locally against the EXPORTED key anyway.
        m = _SIG_RE.match(sig_str) if isinstance(sig_str, str) else None
        if m is None:
            raise KmsError("transit signer: malformed signature envelope "
                           "from server")
        embedded = int(m.group(1))
        if not isinstance(reported, int) or isinstance(reported, bool) \
                or reported != embedded:
            raise KmsError(
                "transit signer: server's reported key_version %r "
                "disagrees with the signature envelope (v%d) -- refusing"
                % (reported, embedded))
        try:
            sig = base64.b64decode(m.group(2), validate=True)
        except Exception:
            raise KmsError("transit signer: malformed signature bytes "
                           "from server")
        if len(sig) != 64:
            raise KmsError("transit signer: signature is %d bytes, not "
                           "Ed25519" % len(sig))
        if embedded != version:
            # The server signed with a different version than the one
            # explicitly requested (rotation mid-request, or a server
            # that ignores key_version). The envelope and the signing
            # key would disagree downstream -- fail closed.
            raise KmsError(
                "transit signer: requested v%d but server signed with "
                "v%d -- refusing" % (version, embedded))
        with self._lock:
            self._last_signed_version = embedded
            # Opportunistic cache: the server just confirmed this
            # version exists. If the cached version moved, drop the
            # cached public key with it -- never let a new version
            # alias an old key.
            if self._pinned_version is None:
                if self._cached_version != embedded:
                    self._cached_pub = None
                self._cached_version = embedded
        _log.debug("transit signer sign ok (key=%r version=%d)",
                   self._key_name, embedded)
        return sig, embedded

    def sign(self, data):
        """Sign ``data`` via transit; returns the 64-byte signature.

        Raises :class:`KmsError` on any failure (outage, auth,
        malformed/lying server response). There is deliberately NO
        fallback: no local key exists to fall back to, and an unsigned
        "signature" is never returned.
        """
        sig, _ver = self._sign_call(data)
        return sig

    def sign_versioned(self, data):
        """Like :meth:`sign`, but also returns the key version used::

            sig, version = signer.sign_versioned(data)

        Record ``version`` alongside the signature (the entry
        envelope's ``sig_key_version``); :func:`verify_versioned`
        refuses signatures with no bound version.
        """
        return self._sign_call(data)

    def verifier_for(self, version):
        """A :class:`TransitVerifier` for ``version`` -- local-only
        verification against the exported public key. Never consults
        the server's /verify endpoint."""
        _check_version(version)
        return TransitVerifier(self._pub_for(version),
                               key_name=self._key_name, version=version)


class TransitVerifier(Verifier):
    """Local-only verifier for one transit key version.

    Holds the exported 32-byte public key; :meth:`verify` is pure
    ``gov.ed25519`` and never touches the network. The server's
    ``/verify`` endpoint is never called -- a compromised server
    claiming ``{"valid": true}`` for a forgery cannot influence this
    class.
    """

    def __init__(self, public_key, key_id=None, *, key_name=None,
                 version=None):
        if not isinstance(public_key, (bytes, bytearray)) \
                or len(public_key) != 32:
            raise ValueError("public_key must be 32 bytes")
        self._pub = bytes(public_key)
        self._key_id = key_id or ed25519_key_id(self._pub)
        self._key_name = key_name
        if version is not None:
            _check_version(version)
        self._version = version

    @property
    def key_id(self):
        return self._key_id

    @property
    def public_key(self):
        return self._pub

    @property
    def version(self):
        return self._version

    @property
    def key_name(self):
        return self._key_name

    def verify(self, data, sig):
        """True iff ``sig`` is a valid Ed25519 signature for ``data``
        under this version's key. Never raises; malformed inputs are
        False."""
        try:
            if not isinstance(data, (bytes, bytearray)):
                return False
            if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
                return False
            return ed25519.verify(self._pub, bytes(data), bytes(sig))
        except Exception:
            return False


def verify_versioned(data, sig, version, verifier_factory):
    """Verify a version-bound transit signature, fail-closed.

    ``verifier_factory`` is ``TransitSigner.verifier_for`` (or any
    ``version -> TransitVerifier``). A ``None`` (stripped) or otherwise
    invalid version raises :class:`KmsError` -- it is never verified
    against a silently chosen key. Returns the verifier's boolean
    otherwise.
    """
    if version is None:
        raise KmsError("transit signer: refusing to verify a signature "
                       "with no bound key version (stripped)")
    try:
        _check_version(version)
    except ValueError as e:
        raise KmsError("transit signer: invalid key version: %s" % (e,))
    try:
        verifier = verifier_factory(version)
    except KmsError:
        raise
    except Exception as e:
        raise KmsError("transit signer: verifier resolution failed "
                       "(%s)" % type(e).__name__)
    return bool(verifier.verify(data, sig))


def export_transit_public_key(transport, token, mount, key_name,
                              version=None):
    """Export a transit Ed25519 public key: returns ``(pub32, version)``.

    ``version=None`` resolves the server's latest version first. The
    PEM is strictly parsed as Ed25519 SPKI; anything else fails
    closed. Uses a throwaway :class:`TransitSigner` for the call path
    so auth/TLS/error behavior is identical to signing.
    """
    signer = TransitSigner(transport, token=token, key_name=key_name,
                           mount=mount,
                           key_version=version)
    ver = signer._resolve_version()
    return signer._pub_for(ver), ver


def transit_signer_from_config(mapping):
    """Build a :class:`TransitSigner` from operator config.

    ``mapping`` keys (all operator-controlled; missing/invalid ->
    :class:`KmsError`):

    * ``key_name`` (required) -- transit key name (an Ed25519 key).
    * ``key_version`` (optional) -- pin the signing version; ``None``
      (default) signs with the server's latest.
    * ``mount`` -- transit mount (default ``"transit"``).
    * ``allow_http`` -- strict bool, default ``False``.
    * ``ca_bundle`` -- PEM CA-bundle path for HTTPS.
    * ``timeout_s`` -- positive seconds per request (default 10).

    Address and token come from the environment (``VAULT_ADDR`` /
    ``VAULT_TOKEN``) -- never from the mapping; missing credentials
    fail closed. Same discipline as ``vault_provider_from_config``.
    """
    if not isinstance(mapping, dict):
        raise KmsError("transit signer config must be a mapping")
    key_name = mapping.get("key_name")
    if not isinstance(key_name, str) or not _KEY_ID_RE.match(key_name):
        raise KmsError("transit signer: 'key_name' is required and must "
                       "be a valid key name, got %r" % (key_name,))
    key_version = mapping.get("key_version")
    if key_version is not None:
        try:
            _check_version(key_version, "key_version")
        except ValueError as e:
            raise KmsError("transit signer: %s" % (e,))
    addr = os.environ.get("VAULT_ADDR", "").strip()
    token = os.environ.get("VAULT_TOKEN", "")
    if not addr:
        raise KmsError("transit signer requires VAULT_ADDR to be set "
                       "(fail-closed: no server address, no signer)")
    if not token:
        raise KmsError("transit signer requires VAULT_TOKEN to be set "
                       "(fail-closed: no token, no signer)")
    mount = mapping.get("mount", "transit")
    allow_http = _config_bool(mapping, "allow_http", False)
    ca_bundle = _config_ca_bundle(mapping)
    timeout_s = _config_timeout_s(mapping)
    try:
        transport = UrllibVaultTransport(addr, timeout_s=timeout_s,
                                         allow_http=allow_http,
                                         ca_bundle=ca_bundle)
        return TransitSigner(transport, token=token, key_name=key_name,
                             mount=mount, key_version=key_version)
    except (ValueError, TypeError) as e:
        raise KmsError("transit signer: unusable configuration (%s)"
                       % (e,))
