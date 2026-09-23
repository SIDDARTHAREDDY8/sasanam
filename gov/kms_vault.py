"""HashiCorp Vault transit-engine backend for the provider-neutral KMS seam.

Implements the ``KmsProvider`` ABC from ``gov/kms.py``
(``wrap_data_key`` / ``unwrap_data_key`` / ``describe_key``, all raising
``KmsError`` on failure, key-id binding on unwrap) against Vault's
transit secrets-engine HTTP API shape, with an injectable transport so
unit tests run with zero network against ``fake_vault.FakeVaultTransport``.
Never touch a real Vault server from tests.

Vault transit API shape used (public-docs knowledge only — no
credentials, no network in this module's tests)::

    POST /v1/<mount>/encrypt/<key>  {"plaintext": "<base64>"}
      -> 200 {"data": {"ciphertext": "vault:v1:<...>"}}
    POST /v1/<mount>/decrypt/<key>  {"ciphertext": "vault:v1:<...>"}
      -> 200 {"data": {"plaintext": "<base64>"}}
    GET  /v1/<mount>/keys/<key>
      -> 200 {"data": {"name": ..., "type": "aes256-gcm96",
                       "latest_version": N, ...}}

Auth is the ``X-Vault-Token`` header. Any non-200 status carries
``{"errors": [...]}``; every such failure (plus any transport, auth, or
parse failure) raises :class:`KmsError` — fail-closed, no fallback.

Key-id binding (Attack-2 hardening, cf. ``gov/kms.py`` module
docstring): a Vault transit ciphertext embeds the key *version*, not the
key *name*, so it cannot by itself prove which key id wrapped it. The
adapter therefore wraps the transit ciphertext in a local envelope that
binds the key id::

    blob = MAGIC || u16be(len(kid)) || kid_utf8 || u32be(len(ct)) || ct_utf8

``unwrap_data_key`` parses the envelope, compares the embedded key id to
the requested ``key_id`` with ``hmac.compare_digest``, and only then
calls transit decrypt. A blob wrapped under any other key id is rejected
even if its transit ciphertext is otherwise valid.

Secrecy discipline: plaintext data keys, transit ciphertexts, and the
Vault token are NEVER logged and NEVER embedded in exception messages.
Logs carry only operation names, key ids, and HTTP statuses.
"""

import abc
import base64
import hmac
import json
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .kms import KmsError, KmsProvider, KeyDescription

_log = logging.getLogger("gov.kms.vault")

_MOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$")
_ERROR_SUMMARY_LEN = 300


# ---------------------------------------------------------------------------
# Transport abstraction — the seam that keeps tests network-free.
# ---------------------------------------------------------------------------

class VaultTransportError(Exception):
    """I/O-level failure talking to Vault (connection refused, timeout,
    TLS error, broken pipe). The adapter converts these to
    :class:`KmsError`. Messages must not carry request/response bodies."""


class VaultTransport(abc.ABC):
    """One injectable HTTP call against the Vault API.

    ``request`` returns ``(status_code: int, response_body: bytes)``.
    HTTP error statuses are RETURNED (not raised) so the caller can map
    them to :class:`KmsError`; only I/O failures raise
    :class:`VaultTransportError`.
    """

    @abc.abstractmethod
    def request(self, method, path, headers, body):
        """Perform one request.

        ``method``/``path`` are strings (``path`` starts with ``/v1/``),
        ``headers`` is a dict, ``body`` is bytes (``b""`` for GET).
        """


class UrllibVaultTransport(VaultTransport):
    """Real stdlib transport (urllib). Production use only — never in
    unit tests. ``base_url`` looks like ``https://vault.internal:8200``.
    Plain HTTP is refused unless ``allow_http=True`` is passed
    explicitly (loopback/dev); tokens must not cross plaintext."""

    def __init__(self, base_url, *, timeout_s=10, allow_http=False,
                 ca_bundle=None):
        if not isinstance(base_url, str):
            raise TypeError("base_url must be a string")
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme == "http" and not allow_http:
            raise ValueError(
                "refusing plaintext http Vault URL without "
                "allow_http=True (token would cross the wire in clear)")
        if parts.scheme not in ("http", "https"):
            raise ValueError("base_url must be http(s), got %r"
                             % (parts.scheme,))
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self._ctx = (ssl.create_default_context(cafile=ca_bundle)
                     if parts.scheme == "https" else None)

    def request(self, method, path, headers, body):
        url = self._base_url + path
        req = urllib.request.Request(url, data=body if body else None,
                                     headers=dict(headers), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_s,
                                        context=self._ctx) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            # HTTP error statuses are data for the caller's error mapping.
            try:
                return e.code, e.read()
            except Exception:
                return e.code, b""
        except Exception as e:
            # I/O failure: never leak URL query/body material; the path
            # and exception type are enough for operators.
            raise VaultTransportError(
                "%s %s failed (%s: %s)"
                % (method, path, type(e).__name__, e))


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class VaultKmsProvider(KmsProvider):
    """``KmsProvider`` backed by Vault's transit secrets engine.

    ``transport`` is any :class:`VaultTransport` (tests inject
    ``fake_vault.FakeVaultTransport``; production injects
    ``UrllibVaultTransport``). ``token`` is the Vault token used on every
    call — it is held in memory and never logged.
    """

    provider_name = "vault"

    # Envelope magic: b"VAULTKMS1" || u16be(kid_len) || kid || u32be(ct_len) || ct
    _MAGIC = b"VAULTKMS1"

    def __init__(self, transport, *, token, mount="transit"):
        if not isinstance(transport, VaultTransport):
            raise TypeError("transport must be a VaultTransport, got %r"
                            % type(transport).__name__)
        if not isinstance(token, str) or not token:
            raise ValueError("vault token must be a non-empty string")
        if not isinstance(mount, str) or not _MOUNT_RE.match(mount):
            raise ValueError("invalid vault transit mount %r" % (mount,))
        self._transport = transport
        self._token = token
        self._mount = mount

    # -- internals ----------------------------------------------------

    def _path(self, op, key_id):
        # Key ids may contain '/', ':', etc. (per gov/kms.py's key-id
        # grammar) — quote the whole segment so one key id can never
        # escape into another path component.
        return "/v1/%s/%s/%s" % (self._mount, op,
                                 urllib.parse.quote(key_id, safe=""))

    def _api(self, op_label, method, path, payload):
        """One fail-closed Vault API call. Returns the decoded JSON
        document. Any failure raises :class:`KmsError`."""
        body = (json.dumps(payload).encode("utf-8")
                if payload is not None else b"")
        headers = {"X-Vault-Token": self._token,
                   "Content-Type": "application/json"}
        try:
            status, resp_body = self._transport.request(
                method, path, headers, body)
        except VaultTransportError as e:
            raise KmsError(
                "vault kms %s: transport failure (%s)" % (op_label, e))
        except Exception as e:  # a transport that raises something else
            raise KmsError(
                "vault kms %s: transport failure (%s)"
                % (op_label, type(e).__name__))
        if status != 200:
            _log.warning("vault kms %s failed: HTTP %d (path=%s)",
                         op_label, status, path)
            raise KmsError(
                "vault kms %s failed: HTTP %d: %s"
                % (op_label, status,
                   _safe_error_summary(resp_body)))
        try:
            doc = json.loads(resp_body.decode("utf-8"))
        except Exception:
            raise KmsError(
                "vault kms %s: malformed response from server" % op_label)
        if not isinstance(doc, dict):
            raise KmsError(
                "vault kms %s: malformed response from server" % op_label)
        _log.debug("vault kms %s ok (path=%s)", op_label, path)
        return doc

    @classmethod
    def _envelope(cls, key_id, ct_bytes):
        kid = key_id.encode("utf-8")
        return (cls._MAGIC + len(kid).to_bytes(2, "big") + kid
                + len(ct_bytes).to_bytes(4, "big") + ct_bytes)

    @classmethod
    def _parse_envelope(cls, blob, key_id):
        """Return ``(embedded_key_id, ciphertext_bytes)``. Any deviation
        raises :class:`KmsError` WITHOUT echoing blob bytes."""
        bad = KmsError(
            "vault kms: cannot unwrap blob for key id %r "
            "(malformed envelope)" % (key_id,))
        try:
            if not blob.startswith(cls._MAGIC):
                raise ValueError("bad magic")
            off = len(cls._MAGIC)
            klen = int.from_bytes(blob[off:off + 2], "big")
            off += 2
            if klen == 0 or klen > 256:
                raise ValueError("bad key-id length")
            kid = blob[off:off + klen].decode("utf-8")
            off += klen
            clen = int.from_bytes(blob[off:off + 4], "big")
            off += 4
            if clen == 0 or off + clen != len(blob):
                raise ValueError("bad ciphertext length")
            ct = blob[off:off + clen].decode("utf-8")  # strict
        except KmsError:
            raise
        except Exception:
            raise bad
        return kid, ct.encode("utf-8")

    # -- KmsProvider API -----------------------------------------------

    def wrap_data_key(self, key_id, plaintext):
        self._validate_key_id(key_id)
        plaintext = self._validate_plaintext(plaintext)
        _log.debug("vault kms wrap: key_id=%r bytes=%d",
                   key_id, len(plaintext))
        doc = self._api("wrap_data_key", "POST",
                        self._path("encrypt", key_id),
                        {"plaintext":
                         base64.b64encode(plaintext).decode("ascii")})
        try:
            ct = doc["data"]["ciphertext"]
        except (KeyError, TypeError):
            raise KmsError(
                "vault kms wrap_data_key: response missing "
                "data.ciphertext")
        if not isinstance(ct, str) or not ct:
            raise KmsError(
                "vault kms wrap_data_key: invalid ciphertext in response")
        return self._envelope(key_id, ct.encode("utf-8"))

    def unwrap_data_key(self, key_id, wrapped):
        self._validate_key_id(key_id)
        if (not isinstance(wrapped, (bytes, bytearray))
                or len(wrapped) == 0):
            raise KmsError(
                "vault kms: wrapped blob must be non-empty bytes")
        embedded_kid, ct_bytes = self._parse_envelope(bytes(wrapped),
                                                      key_id)
        # KEY-ID BINDING (Attack-2 hardening): the blob's embedded key id
        # must equal the requested one. A blob wrapped under any other
        # key id is rejected even if its transit ciphertext is valid —
        # decrypting it would hand the caller an attacker-chosen data key.
        if not hmac.compare_digest(embedded_kid.encode("utf-8"),
                                   key_id.encode("utf-8")):
            raise KmsError(
                "vault kms: key id mismatch: blob was wrapped under a "
                "different key id than %r" % (key_id,))
        _log.debug("vault kms unwrap: key_id=%r", key_id)
        doc = self._api("unwrap_data_key", "POST",
                        self._path("decrypt", key_id),
                        {"ciphertext": ct_bytes.decode("utf-8")})
        try:
            pt_b64 = doc["data"]["plaintext"]
        except (KeyError, TypeError):
            raise KmsError(
                "vault kms unwrap_data_key: response missing "
                "data.plaintext")
        try:
            pt = base64.b64decode(pt_b64, validate=True)
        except Exception:
            raise KmsError(
                "vault kms unwrap_data_key: invalid plaintext encoding "
                "in response")
        if not pt:
            raise KmsError(
                "vault kms unwrap_data_key: empty plaintext in response")
        return pt

    def describe_key(self, key_id):
        self._validate_key_id(key_id)
        doc = self._api("describe_key", "GET",
                        self._path("keys", key_id), None)
        try:
            data = doc["data"]
            name = data["name"]
        except (KeyError, TypeError):
            raise KmsError(
                "vault kms describe_key: malformed response from server")
        if not isinstance(name, str) or not name:
            raise KmsError(
                "vault kms describe_key: malformed response from server")
        _log.debug("vault kms describe_key: key_id=%r", key_id)
        # Vault transit keys expose no enabled/disabled flag; a key whose
        # read succeeds is usable. Metadata only — never key material.
        return KeyDescription(key_id, self.provider_name, enabled=True,
                              arn_or_name="vault:%s:%s"
                              % (self._mount, name))


def _safe_error_summary(resp_body):
    """Extract a short, safe operator summary from a Vault error body.

    Only the server's ``errors`` list is surfaced (never request or
    response bodies); unparseable bodies become a byte count."""
    try:
        doc = json.loads((resp_body or b"").decode("utf-8", "replace"))
        errs = doc.get("errors") if isinstance(doc, dict) else None
        if isinstance(errs, list) and errs:
            return "; ".join(str(e) for e in errs[:3])[:_ERROR_SUMMARY_LEN]
    except Exception:
        pass
    return "unparseable error body (%d bytes)" % len(resp_body or b"")
