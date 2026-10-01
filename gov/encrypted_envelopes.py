"""Recipient-based encrypted evidence envelopes. Stdlib only.

Age-pattern ADAPT (FiloSottile/age, BSD-3-Clause; pattern only -- no age
code is vendored): the evidence bundle is verifiable but plaintext.
Evidence routinely contains sensitive material (hostnames, agent IDs,
policy text, finding details) that must travel encrypted to specific
auditors. This module is the encryption half to cosign's signature
half: a sealed envelope opens only for a listed recipient, and the
envelope's tag proves the payload is exactly what was sealed.

Open wire format (``SASENV1``), all integers big-endian::

    magic         8s   b"SASENV1\\x00"
    version       u16  1
    flags         u8   bit0 = payload-signed claim (deployment-supplied)
    nrec          u16  recipient count (1..64)
    per recipient:
        id_len    u16  1..128
        id        bytes  UTF-8 recipient id
        wrap_len  u16  always 48
        wrap      bytes  16s nonce || 32s masked envelope key
    pnonce        16s  payload-encryption nonce
    ct_len        u64
    ct            bytes  payload XOR HMAC-CTR keystream
    tag           32s  HMAC-SHA256 over (domain || b"tag:" || header || ct)

Cryptographic construction (stdlib only -- AES-GCM is unavailable):

* A fresh 32-byte envelope key is generated per seal
  (``secrets.token_bytes``).
* Payload encryption: keystream blocks are
  ``HMAC-SHA256(enc_key, domain || b"stream:" || pnonce || ctr_be64)``
  with ``enc_key = KDF(envelope_key, b"payload-enc")``; ciphertext is
  payload XOR keystream (HMAC-CTR, HKDF-like counter mode).
* Authentication: encrypt-then-MAC.
  ``tag = HMAC-SHA256(mac_key, domain || b"tag:" || header || ct)``
  with ``mac_key = KDF(envelope_key, b"payload-mac")``; the tag covers
  the magic, version, flags, every recipient wrap, the nonce, and the
  ciphertext. Verified with ``hmac.compare_digest``.
* Recipient key wrap (default KEM ``symmetric-hmac-wrap/v1``):
  ``wrap_key = KDF(recipient_key_material,
  b"wrap:" || id_len_be16 || recipient_id)``;
  ``wrap = wrap_nonce || (envelope_key XOR keystream(wrap_key,
  wrap_nonce))``. Unwrapping with the wrong key yields 32 garbage
  bytes -- never an exception -- so authenticity is decided solely by
  the tag check.

Key-wrap contract (deployment seam)
-----------------------------------
Recipient key material arrives as opaque bytes the deployment
supplies; the envelope never parses private keys. The default KEM is
*symmetric*: the bytes used to seal for a recipient are the bytes that
open for that recipient. A deployment that needs true public-key
semantics replaces the wrap/unwrap pair with an X25519 KEM behind the
same ``(envelope_key, recipient_id, key_material) -> wrap`` contract
(seal takes public bytes, open takes private bytes) without changing
the wire format's shape. The contract is documented, not enforced, in
this module -- see :class:`KeyWrap`.

HONEST RESIDUALS (read before deploying)
----------------------------------------
* This is **not a reviewed AEAD**. It is a documented HMAC-CTR +
  encrypt-then-MAC construction from stdlib primitives, built to the
  age *pattern* (recipient-based, multi-recipient, open format), not
  to age's security review. Post-v1 replacement point: swap the
  payload cipher and the default KEM for a vetted library (e.g. an
  audited age/X25519 implementation) behind the documented seams.
* The envelope proves **confidentiality + integrity of what was
  sealed**, not authenticity of the payload's origin. ``payload_signed``
  is a deployment-supplied claim recorded in the flags byte
  (honest-boundary labeled); the tag binds it, but the envelope
  cannot attest who produced the payload.
* Failure hygiene: key-dependent failures (wrong key, unknown
  recipient, tampered tag/ciphertext/header) all raise the single
  code ``envelope-open-refused``. On every *refusal* path the work is
  data-independent -- every recipient wrap is tried, one
  ``compare_digest`` per wrap, no early exit -- so refusal causes are
  mutually indistinguishable. A *successful* open returns at the
  first verified wrap and then does the decrypt work; success vs
  refusal are therefore algorithmically distinguishable, but only a
  valid key holder ever observes a success. Structural failures
  (truncated, bad magic, bad lengths) and unknown versions raise
  distinct codes by design: they carry no key-dependent information.
  Microarchitectural timing is out of scope.
* Key custody is deployment-owned: recipient key material strength is
  the deployment's responsibility (minimum 16 bytes enforced; weak
  keys refused at seal).
* Recipient ids are wire-public and are logged in the audit journal
  by design: they name who may open an envelope and are not secret
  key material. The journal never carries payload plaintext or any
  key bytes -- digests only.
"""

import hashlib
import hmac
import secrets
import struct

from . import durable_journal as _dj

MAGIC = b"SASENV1\x00"
VERSION = 1
MAX_RECIPIENTS = 64
MAX_ID_LEN = 128
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
_WRAP_LEN = 48  # 16s nonce || 32s masked envelope key
_MIN_KEY_MATERIAL = 16

_DOMAIN = b"sasanam-envelope/v1/"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class EnvelopeError(Exception):
    """Base class for all envelope refusals. Carries ``code``."""

    def __init__(self, code, detail):
        super(EnvelopeError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class EnvelopeRefusal(EnvelopeError):
    """A policy refusal (seal refused, open refused). Fail closed."""


class EnvelopeMalformed(EnvelopeError):
    """The envelope bytes are structurally invalid. Fail closed."""


# ---------------------------------------------------------------------------
# Key derivation / stream cipher / wrap (documented seams)
# ---------------------------------------------------------------------------

def _kdf(key, info, length):
    """Counter-mode HMAC-SHA256 KDF. ``info`` is domain-separated."""
    out = bytearray()
    counter = 1
    while len(out) < length:
        out += hmac.new(key, _DOMAIN + info + struct.pack(">I", counter),
                        hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def _keystream(key, nonce, length):
    """HMAC-CTR keystream: block_i = HMAC(key, domain||b"stream:"||
    nonce||ctr_be64)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(key, _DOMAIN + b"stream:" + nonce +
                        struct.pack(">Q", counter),
                        hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _as_bytes(value):
    if isinstance(value, bytearray):
        return bytes(value)
    return value


class KeyWrap(object):
    """Default KEM contract: ``symmetric-hmac-wrap/v1``.

    ``wrap(envelope_key, recipient_id, key_material) -> bytes`` seals
    a fresh envelope key for one recipient; ``unwrap`` reverses it.
    ``unwrap`` NEVER raises on a wrong key -- it returns 32 bytes that
    are garbage unless the key material matches, so the tag check is
    the single authenticity decision. A deployment replaces this class
    with an X25519 KEM behind the same method shapes.
    """

    name = "symmetric-hmac-wrap/v1"

    @staticmethod
    def _wrap_key(recipient_id, key_material):
        return _kdf(key_material,
                    b"wrap:" + struct.pack(">H", len(recipient_id)) +
                    recipient_id, 32)

    def wrap(self, envelope_key, recipient_id, key_material):
        nonce = secrets.token_bytes(16)
        wk = self._wrap_key(recipient_id, key_material)
        return nonce + _xor(envelope_key, _keystream(wk, nonce, 32))

    def unwrap(self, wrapped, recipient_id, key_material):
        # Always 32 bytes; garbage on wrong key. Authenticity is
        # decided by the tag, never here.
        nonce, masked = wrapped[:16], wrapped[16:]
        wk = self._wrap_key(recipient_id, key_material)
        return _xor(masked, _keystream(wk, nonce, 32))


# ---------------------------------------------------------------------------
# Recipient descriptor
# ---------------------------------------------------------------------------

class Recipient(object):
    """A seal recipient: an id plus opaque deployment-supplied key
    material. Construction never raises; :meth:`EnvelopeVault.seal`
    validates and refuses with ``envelope-recipient-refused``."""

    def __init__(self, recipient_id, key_material):
        self.id = recipient_id
        self.key_material = key_material


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

class _Parsed(object):
    pass


def _parse(envelope):
    """Parse and structurally validate; returns _Parsed or raises."""
    p = _Parsed()
    if not isinstance(envelope, (bytes, bytearray)):
        raise EnvelopeMalformed("envelope-malformed",
                                "envelope is not bytes")
    env = bytes(envelope)
    need = 8 + 2 + 1 + 2 + 16 + 8 + 32
    if len(env) < need:
        raise EnvelopeMalformed("envelope-malformed",
                                "truncated header (%d bytes)" % len(env))
    if env[:8] != MAGIC:
        raise EnvelopeMalformed("envelope-malformed", "bad magic")
    version = struct.unpack(">H", env[8:10])[0]
    if version != VERSION:
        raise EnvelopeError("envelope-version-unknown",
                            "version %d not supported" % version)
    p.payload_signed = bool(env[10] & 0x01)
    nrec = struct.unpack(">H", env[11:13])[0]
    if nrec < 1 or nrec > MAX_RECIPIENTS:
        raise EnvelopeMalformed("envelope-malformed",
                                "bad recipient count %d" % nrec)
    off = 13
    recips = []
    for _ in range(nrec):
        if off + 2 > len(env):
            raise EnvelopeMalformed("envelope-malformed",
                                    "truncated recipient id_len")
        id_len = struct.unpack(">H", env[off:off + 2])[0]
        off += 2
        if id_len < 1 or id_len > MAX_ID_LEN or off + id_len > len(env):
            raise EnvelopeMalformed("envelope-malformed",
                                    "bad recipient id length")
        rid = env[off:off + id_len]
        off += id_len
        try:
            rid.decode("utf-8")
        except UnicodeDecodeError:
            raise EnvelopeMalformed("envelope-malformed",
                                    "recipient id not UTF-8")
        if off + 2 > len(env):
            raise EnvelopeMalformed("envelope-malformed",
                                    "truncated wrap_len")
        wrap_len = struct.unpack(">H", env[off:off + 2])[0]
        off += 2
        if wrap_len != _WRAP_LEN or off + wrap_len > len(env):
            raise EnvelopeMalformed("envelope-malformed",
                                    "bad wrap length")
        recips.append((rid, env[off:off + wrap_len]))
        off += wrap_len
    if off + 16 + 8 > len(env):
        raise EnvelopeMalformed("envelope-malformed",
                                "truncated nonce/ct_len")
    pnonce = env[off:off + 16]
    off += 16
    ct_len = struct.unpack(">Q", env[off:off + 8])[0]
    off += 8
    if ct_len > MAX_PAYLOAD_BYTES or off + ct_len + 32 != len(env):
        raise EnvelopeMalformed("envelope-malformed",
                                "bad ciphertext length")
    p.header = env[:off]
    p.ct = env[off:off + ct_len]
    p.tag = env[off + ct_len:]
    p.pnonce = pnonce
    p.recipients = recips
    return p


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------

class EnvelopeVault(object):
    """Seals envelopes and opens them, with a digest-only audit
    journal composed with ``gov.durable_journal``.

    The journal records digests only -- never payload plaintext, never
    key material. ``path`` is the journal file; it is created on first
    use.
    """

    def __init__(self, path, kem=None):
        self._path = path
        self._kem = kem if kem is not None else KeyWrap()
        self._journal = _dj.Journal(path)

    # -- internal ------------------------------------------------------

    @staticmethod
    def _digest(data):
        return hashlib.sha256(data).hexdigest()

    def _log(self, rtype, body):
        self._journal.append(rtype, body)

    @staticmethod
    def _require_payload(bundle_bytes):
        bundle_bytes = _as_bytes(bundle_bytes)
        if not isinstance(bundle_bytes, bytes):
            raise EnvelopeRefusal("envelope-seal-refused",
                                  "payload is not bytes")
        if len(bundle_bytes) == 0:
            raise EnvelopeRefusal("envelope-seal-refused",
                                  "empty payload")
        if len(bundle_bytes) > MAX_PAYLOAD_BYTES:
            raise EnvelopeRefusal("envelope-seal-refused",
                                  "payload exceeds %d bytes" %
                                  MAX_PAYLOAD_BYTES)
        return bundle_bytes

    @staticmethod
    def _require_recipients(recipients):
        if not isinstance(recipients, (list, tuple)) or not recipients:
            raise EnvelopeRefusal("envelope-seal-refused",
                                  "at least one recipient required")
        seen = set()
        out = []
        for r in recipients:
            if not isinstance(r, Recipient):
                raise EnvelopeRefusal("envelope-recipient-refused",
                                      "recipient is not a Recipient")
            if not isinstance(r.id, str) or not r.id:
                raise EnvelopeRefusal("envelope-recipient-refused",
                                      "recipient id must be a non-empty str")
            rid = r.id.encode("utf-8")
            if len(rid) > MAX_ID_LEN:
                raise EnvelopeRefusal("envelope-recipient-refused",
                                      "recipient id too long")
            km = _as_bytes(r.key_material)
            if not isinstance(km, bytes) or len(km) < _MIN_KEY_MATERIAL:
                raise EnvelopeRefusal("envelope-recipient-refused",
                                      "key material must be bytes >= %d" %
                                      _MIN_KEY_MATERIAL)
            if r.id in seen:
                raise EnvelopeRefusal("envelope-seal-refused",
                                      "duplicate recipient id %r" % r.id)
            seen.add(r.id)
            out.append((rid, km))
        if len(out) > MAX_RECIPIENTS:
            raise EnvelopeRefusal("envelope-seal-refused",
                                  "too many recipients")
        return out

    # -- public --------------------------------------------------------

    def seal(self, bundle_bytes, recipients, payload_signed=False):
        """Seal ``bundle_bytes`` for ``recipients``. Returns envelope
        bytes. ``payload_signed`` is a deployment-supplied claim
        recorded in the flags byte (honest boundary: the envelope
        proves confidentiality + integrity of what was sealed, not
        origin authenticity)."""
        payload = self._require_payload(bundle_bytes)
        recips = self._require_recipients(recipients)

        envelope_key = secrets.token_bytes(32)
        pnonce = secrets.token_bytes(16)
        enc_key = _kdf(envelope_key, b"payload-enc", 32)
        ct = _xor(payload, _keystream(enc_key, pnonce, len(payload)))

        header = MAGIC + struct.pack(">H", VERSION)
        header += b"\x01" if payload_signed else b"\x00"
        header += struct.pack(">H", len(recips))
        for rid, km in recips:
            wrap = self._kem.wrap(envelope_key, rid, km)
            header += (struct.pack(">H", len(rid)) + rid +
                       struct.pack(">H", len(wrap)) + wrap)
        header += pnonce + struct.pack(">Q", len(ct))

        mac_key = _kdf(envelope_key, b"payload-mac", 32)
        tag = hmac.new(mac_key, _DOMAIN + b"tag:" + header + ct,
                       hashlib.sha256).digest()
        envelope = header + ct + tag

        self._log("envelope-sealed", {
            "event": "sealed",
            "envelope_digest": self._digest(envelope),
            "payload_digest": self._digest(payload),
            "recipient_ids": [r.id for r in recipients],
            "payload_signed": bool(payload_signed),
        })
        return envelope

    def open(self, envelope_bytes, key_material):
        """Open ``envelope_bytes`` with one recipient's key material.

        Returns ``(payload_bytes, meta)`` where meta carries
        ``payload_digest``, ``envelope_digest``, ``recipient_id`` and
        ``payload_signed``. Any key-dependent failure -- wrong key,
        unknown recipient, tampered tag/ciphertext/header -- raises
        the single code ``envelope-open-refused`` after
        data-independent work on the refusal path (every wrap tried,
        one compare_digest per wrap, no early exit); a successful open
        returns at the first verified wrap. Structural failures raise
        ``envelope-malformed``; unknown versions raise
        ``envelope-version-unknown``. Every open attempt -- including
        structural refusals -- is journaled digest-only.
        """
        raw = _as_bytes(envelope_bytes)
        try:
            parsed = _parse(raw)
        except EnvelopeError as exc:
            # A malformed envelope is still an open attempt: journal the
            # digest-only refusal (no key material, no plaintext), then
            # re-raise. Attacker probing stays visible.
            if isinstance(raw, (bytes, bytearray)):
                digest_src = bytes(raw)
            else:
                digest_src = repr(raw).encode("utf-8", "replace")
            self._log("envelope-open-refused", {
                "event": "open_refused",
                "envelope_digest": self._digest(digest_src),
                "refusal_code": exc.code,
            })
            raise
        env_digest = self._digest(bytes(raw))

        km = _as_bytes(key_material)
        if not isinstance(km, bytes) or not km:
            self._log("envelope-open-refused",
                      {"event": "open_refused",
                       "envelope_digest": env_digest})
            raise EnvelopeRefusal("envelope-open-refused",
                                  "key material must be non-empty bytes")

        for rid, wrap in parsed.recipients:
            candidate = self._kem.unwrap(wrap, rid, km)
            mac_key = _kdf(candidate, b"payload-mac", 32)
            expect = hmac.new(mac_key, _DOMAIN + b"tag:" + parsed.header +
                              parsed.ct, hashlib.sha256).digest()
            if hmac.compare_digest(expect, parsed.tag):
                enc_key = _kdf(candidate, b"payload-enc", 32)
                payload = _xor(parsed.ct, _keystream(
                    enc_key, parsed.pnonce, len(parsed.ct)))
                recipient_id = rid.decode("utf-8")
                self._log("envelope-opened", {
                    "event": "opened",
                    "envelope_digest": env_digest,
                    "payload_digest": self._digest(payload),
                    "recipient_id": recipient_id,
                })
                return payload, {
                    "payload_digest": self._digest(payload),
                    "envelope_digest": env_digest,
                    "recipient_id": recipient_id,
                    "payload_signed": parsed.payload_signed,
                }
        self._log("envelope-open-refused",
                  {"event": "open_refused", "envelope_digest": env_digest})
        raise EnvelopeRefusal("envelope-open-refused",
                              "no recipient wrap verified")
