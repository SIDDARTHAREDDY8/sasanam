"""SOPS-style key groups for encrypted envelopes. Stdlib only.

SOPS ADAPT (pattern only -- no SOPS code is vendored): an envelope
declares multiple key groups; decryption succeeds if ANY one group
reaches its quorum (quorum-per-group, one-group-sufficient -- the SOPS
data-key-shares semantic). The payload cipher is unchanged: the
documented stdlib HMAC-CTR + encrypt-then-MAC construction from
:mod:`gov.encrypted_envelopes`. This module adds the group/policy layer
around data-key wrapping, not a new cipher.

Scope-bound wraps adapt the sealed-secrets scope-bound OAEP-label
lesson: each group entry binds ``key_id -> scope`` (purpose label)
into the wrap KDF, so a wrapped data key is only usable for its
declared purpose/scope. A share sealed for scope ``s1`` unwraps to
garbage under any other scope label, and the envelope's declared
scopes are tag-covered.

Open wire format (``SASKEYG1``), all integers big-endian::

    magic         8s   b"SASKEYG1"
    version       u16  1
    flags         u8   bit0 = payload-signed claim (deployment-supplied)
    ngroups       u16  1..16
    per group:
        nmembers  u16  1..64
        quorum    u16  1..nmembers
        per member:
            id_len    u16  1..128
            id        bytes  UTF-8 key id
            scope_len u16  1..128
            scope     bytes  UTF-8 scope/purpose label
            wrap_len  u16  always 48
            wrap      bytes  16s nonce || 32s masked data key
    pnonce        16s  payload-encryption nonce
    ct_len        u64
    ct            bytes  payload XOR HMAC-CTR keystream
    tag           32s  HMAC-SHA256 over (domain || b"tag:" || header || ct)

Cryptographic construction (same as :mod:`gov.encrypted_envelopes`):

* A fresh 32-byte data key is generated per seal
  (``secrets.token_bytes``).
* Payload encryption: keystream blocks are
  ``HMAC-SHA256(enc_key, domain || b"stream:" || pnonce || ctr_be64)``
  with ``enc_key = KDF(data_key, b"payload-enc")``; ciphertext is
  payload XOR keystream (HMAC-CTR).
* Authentication: encrypt-then-MAC.
  ``tag = HMAC-SHA256(mac_key, domain || b"tag:" || header || ct)``
  with ``mac_key = KDF(data_key, b"payload-mac")``; the tag covers the
  magic, version, flags, every group/member wrap (including each
  entry's scope label), the nonce, and the ciphertext. Verified with
  ``hmac.compare_digest``.
* Scope-bound group wrap (default KEM ``group-hmac-wrap/v1``):
  ``wrap_key = KDF(key_material, b"group-wrap:" || id_len_be16 ||
  key_id || b"scope:" || scope_len_be16 || scope)``;
  ``wrap = wrap_nonce || (data_key XOR keystream(wrap_key,
  wrap_nonce))``. Unwrapping with the wrong key material, the wrong
  key id, or the wrong scope label yields 32 garbage bytes -- never
  an exception -- so authenticity is decided solely by the tag check.

Key-wrap contract (deployment seam)
-----------------------------------
Key material arrives as opaque bytes the deployment supplies; the
vault never generates, stores, or parses private keys. The default
KEM is *symmetric*: the bytes used to seal for a key id are the bytes
that open for that key id. A deployment that needs true public-key
semantics replaces the wrap/unwrap pair with an X25519 KEM behind
the same ``(data_key, key_id, scope, key_material) -> wrap``
contract without changing the wire format's shape. The contract is
documented, not enforced, in this module -- see :class:`GroupKeyWrap`.

Failure hygiene: key-dependent failures (wrong material, sub-quorum,
tampered tag/ciphertext/header, scope-gated unusable) all raise the
single code ``keygroup-open-refused``. On every *refusal* path the
work is data-independent -- every usable member wrap is tried, one
``compare_digest`` per wrap, no early exit -- so refusal causes are
mutually indistinguishable. A *successful* open returns at the first
quorum-reaching group and then does the decrypt work; success vs
refusal are therefore algorithmically distinguishable, but only a
valid key holder ever observes a success. Structural failures raise
``keygroup-malformed``; unknown versions raise
``keygroup-version-unknown``; policy refusals with no key-dependent
content raise explicit codes (``keygroup-seal-refused``,
``keygroup-unknown-key-id``, ``keygroup-scope-mismatch``).
Microarchitectural timing is out of scope.

HONEST RESIDUALS (read before deploying)
----------------------------------------
* This is **not a reviewed AEAD**, and the group layer is **not a
  reviewed threshold scheme**. It is the documented HMAC-CTR +
  encrypt-then-MAC construction plus a policy layer that counts
  tag-verified data-key shares toward per-group quorums. Post-v1
  replacement point: swap the payload cipher and the default KEM for
  a vetted library behind the documented seams.
* The envelope proves **confidentiality + integrity of what was
  sealed**, not authenticity of the payload's origin.
  ``payload_signed`` is a deployment-supplied claim recorded in the
  flags byte (honest-boundary labeled); the tag binds it, but the
  envelope cannot attest who produced the payload.
* Key custody is deployment-owned: key material strength, storage,
  rotation, and revocation are the deployment's responsibility
  (minimum 16 bytes enforced; weak keys refused at seal). There is
  no external KMS dependency ($0 spend) -- and therefore no
  hardware-backed custody either.
* Key ids and scope labels are wire-public and are logged in the
  audit journal by design: they name who may open an envelope and
  for what purpose, and are not secret key material. The journal
  never carries payload plaintext or any key bytes -- digests only.
* Quorum counts *verified shares*, not distinct humans: two shares
  for the same key id in one group are refused at seal (quorum
  inflation), but nothing stops a deployment from issuing the same
  key material under two different key ids. Separation of duty is a
  deployment custody property, not a cryptographic one.
"""

import hashlib
import hmac
import secrets
import struct

from . import durable_journal as _dj

MAGIC = b"SASKEYG1"
VERSION = 1
MAX_GROUPS = 16
MAX_MEMBERS = 64
MAX_ID_LEN = 128
MAX_SCOPE_LEN = 128
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
_WRAP_LEN = 48  # 16s nonce || 32s masked data key
_MIN_KEY_MATERIAL = 16

_DOMAIN = b"sasanam-keygroup/v1/"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class KeyGroupError(Exception):
    """Base class for all key-group refusals. Carries ``code``."""

    def __init__(self, code, detail):
        super(KeyGroupError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class KeyGroupRefusal(KeyGroupError):
    """A policy refusal (seal refused, open refused). Fail closed."""


class KeyGroupMalformed(KeyGroupError):
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


class GroupKeyWrap(object):
    """Default KEM contract: ``group-hmac-wrap/v1``.

    ``wrap(data_key, key_id, scope, key_material) -> bytes`` seals a
    fresh data key for one group member; ``unwrap`` reverses it. The
    wrap key binds the key id AND the scope label, so a share sealed
    for one purpose unwraps to garbage under any other scope.
    ``unwrap`` NEVER raises on a wrong key/scope -- it returns 32
    bytes that are garbage unless key material, key id, and scope all
    match, so the tag check is the single authenticity decision. A
    deployment replaces this class with an X25519 KEM behind the same
    method shapes.
    """

    name = "group-hmac-wrap/v1"

    @staticmethod
    def _wrap_key(key_id, scope, key_material):
        return _kdf(key_material,
                    b"group-wrap:" + struct.pack(">H", len(key_id)) +
                    key_id + b"scope:" + struct.pack(">H", len(scope)) +
                    scope, 32)

    def wrap(self, data_key, key_id, scope, key_material):
        nonce = secrets.token_bytes(16)
        wk = self._wrap_key(key_id, scope, key_material)
        return nonce + _xor(data_key, _keystream(wk, nonce, 32))

    def unwrap(self, wrapped, key_id, scope, key_material):
        # Always 32 bytes; garbage on wrong key/id/scope. Authenticity
        # is decided by the tag, never here.
        nonce, masked = wrapped[:16], wrapped[16:]
        wk = self._wrap_key(key_id, scope, key_material)
        return _xor(masked, _keystream(wk, nonce, 32))


# ---------------------------------------------------------------------------
# Descriptors
# ---------------------------------------------------------------------------

class KeyShare(object):
    """One group member: a key id, opaque deployment-supplied key
    material, and an optional scope label. ``scope=None`` resolves to
    the envelope scope at seal time. Construction never raises;
    :meth:`GroupVault.seal` validates and refuses with
    ``keygroup-seal-refused``."""

    def __init__(self, key_id, key_material, scope=None):
        self.key_id = key_id
        self.key_material = key_material
        self.scope = scope


class KeyGroup(object):
    """A key group: members plus a quorum. ``quorum=None`` means every
    member must resolve (full quorum). Construction never raises;
    :meth:`GroupVault.seal` validates and refuses with
    ``keygroup-seal-refused``."""

    def __init__(self, members, quorum=None, name=""):
        self.members = members
        self.quorum = quorum
        self.name = name


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

class _Parsed(object):
    pass


def _parse(envelope):
    """Parse and structurally validate; returns _Parsed or raises."""
    p = _Parsed()
    if not isinstance(envelope, (bytes, bytearray)):
        raise KeyGroupMalformed("keygroup-malformed",
                                "envelope is not bytes")
    env = bytes(envelope)
    need = 8 + 2 + 1 + 2 + 16 + 8 + 32
    if len(env) < need:
        raise KeyGroupMalformed("keygroup-malformed",
                                "truncated header (%d bytes)" % len(env))
    if env[:8] != MAGIC:
        raise KeyGroupMalformed("keygroup-malformed", "bad magic")
    version = struct.unpack(">H", env[8:10])[0]
    if version != VERSION:
        raise KeyGroupError("keygroup-version-unknown",
                            "version %d not supported" % version)
    p.payload_signed = bool(env[10] & 0x01)
    ngroups = struct.unpack(">H", env[11:13])[0]
    if ngroups < 1 or ngroups > MAX_GROUPS:
        raise KeyGroupMalformed("keygroup-malformed",
                                "bad group count %d" % ngroups)
    off = 13
    groups = []
    for _ in range(ngroups):
        if off + 4 > len(env):
            raise KeyGroupMalformed("keygroup-malformed",
                                    "truncated group header")
        nmembers = struct.unpack(">H", env[off:off + 2])[0]
        quorum = struct.unpack(">H", env[off + 2:off + 4])[0]
        off += 4
        if nmembers < 1 or nmembers > MAX_MEMBERS:
            raise KeyGroupMalformed("keygroup-malformed",
                                    "bad member count %d" % nmembers)
        if quorum < 1 or quorum > nmembers:
            raise KeyGroupMalformed("keygroup-malformed",
                                    "bad quorum %d" % quorum)
        members = []
        for _ in range(nmembers):
            if off + 2 > len(env):
                raise KeyGroupMalformed("keygroup-malformed",
                                        "truncated key id_len")
            id_len = struct.unpack(">H", env[off:off + 2])[0]
            off += 2
            if (id_len < 1 or id_len > MAX_ID_LEN or
                    off + id_len > len(env)):
                raise KeyGroupMalformed("keygroup-malformed",
                                        "bad key id length")
            kid = env[off:off + id_len]
            off += id_len
            try:
                kid.decode("utf-8")
            except UnicodeDecodeError:
                raise KeyGroupMalformed("keygroup-malformed",
                                        "key id not UTF-8")
            if off + 2 > len(env):
                raise KeyGroupMalformed("keygroup-malformed",
                                        "truncated scope_len")
            scope_len = struct.unpack(">H", env[off:off + 2])[0]
            off += 2
            if (scope_len < 1 or scope_len > MAX_SCOPE_LEN or
                    off + scope_len > len(env)):
                raise KeyGroupMalformed("keygroup-malformed",
                                        "bad scope length")
            scope = env[off:off + scope_len]
            off += scope_len
            try:
                scope.decode("utf-8")
            except UnicodeDecodeError:
                raise KeyGroupMalformed("keygroup-malformed",
                                        "scope not UTF-8")
            if off + 2 > len(env):
                raise KeyGroupMalformed("keygroup-malformed",
                                        "truncated wrap_len")
            wrap_len = struct.unpack(">H", env[off:off + 2])[0]
            off += 2
            if wrap_len != _WRAP_LEN or off + wrap_len > len(env):
                raise KeyGroupMalformed("keygroup-malformed",
                                        "bad wrap length")
            members.append((kid, scope, env[off:off + wrap_len]))
            off += wrap_len
        groups.append((quorum, members))
    if off + 16 + 8 > len(env):
        raise KeyGroupMalformed("keygroup-malformed",
                                "truncated nonce/ct_len")
    pnonce = env[off:off + 16]
    off += 16
    ct_len = struct.unpack(">Q", env[off:off + 8])[0]
    off += 8
    if ct_len > MAX_PAYLOAD_BYTES or off + ct_len + 32 != len(env):
        raise KeyGroupMalformed("keygroup-malformed",
                                "bad ciphertext length")
    p.header = env[:off]
    p.ct = env[off:off + ct_len]
    p.tag = env[off + ct_len:]
    p.pnonce = pnonce
    p.groups = groups
    return p


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------

class GroupVault(object):
    """Seals key-group envelopes and opens them, with a digest-only
    audit journal composed with ``gov.durable_journal``.

    The journal records digests, key ids, and scope labels only --
    never payload plaintext, never key material. ``path`` is the
    journal file; it is created on first use.
    """

    def __init__(self, path, kem=None):
        self._path = path
        self._kem = kem if kem is not None else GroupKeyWrap()
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
            raise KeyGroupRefusal("keygroup-seal-refused",
                                  "payload is not bytes")
        if len(bundle_bytes) == 0:
            raise KeyGroupRefusal("keygroup-seal-refused",
                                  "empty payload")
        if len(bundle_bytes) > MAX_PAYLOAD_BYTES:
            raise KeyGroupRefusal("keygroup-seal-refused",
                                  "payload exceeds %d bytes" %
                                  MAX_PAYLOAD_BYTES)
        return bundle_bytes

    @staticmethod
    def _require_scope(scope):
        if not isinstance(scope, str) or not scope:
            raise KeyGroupRefusal("keygroup-seal-refused",
                                  "scope must be a non-empty str")
        sbytes = scope.encode("utf-8")
        if len(sbytes) > MAX_SCOPE_LEN:
            raise KeyGroupRefusal("keygroup-seal-refused",
                                  "scope too long")
        return sbytes

    def _require_groups(self, key_groups, default_scope):
        if (not isinstance(key_groups, (list, tuple)) or
                not key_groups):
            raise KeyGroupRefusal("keygroup-seal-refused",
                                  "at least one key group required")
        if len(key_groups) > MAX_GROUPS:
            raise KeyGroupRefusal("keygroup-seal-refused",
                                  "too many key groups")
        # key_id -> resolved scope: one key id binds to exactly one
        # scope per envelope (conflicting bindings refused below).
        bindings = {}
        out = []
        for gi, g in enumerate(key_groups):
            if not isinstance(g, KeyGroup):
                raise KeyGroupRefusal("keygroup-seal-refused",
                                      "group %d is not a KeyGroup" % gi)
            members = g.members
            if (not isinstance(members, (list, tuple)) or
                    not members):
                raise KeyGroupRefusal("keygroup-seal-refused",
                                      "group %d has no members" % gi)
            if len(members) > MAX_MEMBERS:
                raise KeyGroupRefusal("keygroup-seal-refused",
                                      "group %d too many members" % gi)
            quorum = (len(members) if g.quorum is None else g.quorum)
            if (not isinstance(quorum, int) or
                    isinstance(quorum, bool) or
                    quorum < 1 or quorum > len(members)):
                raise KeyGroupRefusal(
                    "keygroup-seal-refused",
                    "group %d bad quorum %r" % (gi, g.quorum))
            seen = set()
            resolved = []
            for mi, m in enumerate(members):
                if not isinstance(m, KeyShare):
                    raise KeyGroupRefusal(
                        "keygroup-seal-refused",
                        "group %d member %d is not a KeyShare" % (gi, mi))
                if not isinstance(m.key_id, str) or not m.key_id:
                    raise KeyGroupRefusal(
                        "keygroup-seal-refused",
                        "group %d member %d: key id must be a non-empty "
                        "str" % (gi, mi))
                kid = m.key_id.encode("utf-8")
                if len(kid) > MAX_ID_LEN:
                    raise KeyGroupRefusal(
                        "keygroup-seal-refused",
                        "group %d member %d: key id too long" % (gi, mi))
                km = _as_bytes(m.key_material)
                if (not isinstance(km, bytes) or
                        len(km) < _MIN_KEY_MATERIAL):
                    raise KeyGroupRefusal(
                        "keygroup-seal-refused",
                        "group %d member %d: key material must be bytes "
                        ">= %d" % (gi, mi, _MIN_KEY_MATERIAL))
                scope = (default_scope if m.scope is None
                         else self._require_scope(m.scope))
                if m.key_id in seen:
                    # Quorum inflation: one key's material must never
                    # count twice toward a group's quorum.
                    raise KeyGroupRefusal(
                        "keygroup-seal-refused",
                        "group %d duplicate key id %r" % (gi, m.key_id))
                seen.add(m.key_id)
                if (m.key_id in bindings and
                        bindings[m.key_id] != scope):
                    # One key id, two scope bindings: a share sealed
                    # for one purpose must never be usable as another.
                    raise KeyGroupRefusal(
                        "keygroup-seal-refused",
                        "key id %r bound to conflicting scopes" %
                        m.key_id)
                bindings[m.key_id] = scope
                resolved.append((kid, scope, km))
            out.append((quorum, resolved,
                        g.name if isinstance(g.name, str) else ""))
        return out

    # -- public --------------------------------------------------------

    def seal(self, bundle_bytes, key_groups, scope,
             payload_signed=False):
        """Seal ``bundle_bytes`` under ``key_groups`` for ``scope``.

        ``key_groups`` is a list of :class:`KeyGroup`; each member's
        wrap binds its key id to its resolved scope label (the
        member's own scope, or the envelope ``scope`` default).
        ``payload_signed`` is a deployment-supplied claim recorded in
        the flags byte (honest boundary: the envelope proves
        confidentiality + integrity of what was sealed, not origin
        authenticity). Returns envelope bytes.
        """
        payload = self._require_payload(bundle_bytes)
        default_scope = self._require_scope(scope)
        groups = self._require_groups(key_groups, default_scope)

        data_key = secrets.token_bytes(32)
        pnonce = secrets.token_bytes(16)
        enc_key = _kdf(data_key, b"payload-enc", 32)
        ct = _xor(payload, _keystream(enc_key, pnonce, len(payload)))

        header = MAGIC + struct.pack(">H", VERSION)
        header += b"\x01" if payload_signed else b"\x00"
        header += struct.pack(">H", len(groups))
        journal_groups = []
        for quorum, members, name in groups:
            header += struct.pack(">HH", len(members), quorum)
            jmembers = []
            for kid, mscope, km in members:
                wrap = self._kem.wrap(data_key, kid, mscope, km)
                header += (struct.pack(">H", len(kid)) + kid +
                           struct.pack(">H", len(mscope)) + mscope +
                           struct.pack(">H", len(wrap)) + wrap)
                jmembers.append({"key_id": kid.decode("utf-8"),
                                 "scope": mscope.decode("utf-8")})
            journal_groups.append({"name": name, "quorum": quorum,
                                   "members": jmembers})
        header += pnonce + struct.pack(">Q", len(ct))

        mac_key = _kdf(data_key, b"payload-mac", 32)
        tag = hmac.new(mac_key, _DOMAIN + b"tag:" + header + ct,
                       hashlib.sha256).digest()
        envelope = header + ct + tag

        self._log("keygroup-sealed", {
            "event": "sealed",
            "envelope_digest": self._digest(envelope),
            "payload_digest": self._digest(payload),
            "groups": journal_groups,
            "payload_signed": bool(payload_signed),
        })
        return envelope

    def open(self, envelope_bytes, key_materials, scope=None):
        """Open ``envelope_bytes`` with ``key_materials``.

        ``key_materials`` maps key id -> opaque deployment-supplied
        key bytes. Decryption succeeds iff ANY one group reaches its
        quorum of tag-verified shares. ``scope`` optionally gates
        resolution: when given, only entries whose declared scope
        equals it are usable; when ``None``, every entry is usable
        under its own declared scope.

        Returns ``(payload_bytes, meta)`` where meta carries
        ``payload_digest``, ``envelope_digest``, ``group_index``,
        ``key_ids`` (verified, wire order), ``scopes`` (the resolving
        group's declared scopes), and ``payload_signed``.

        Fail-closed: a key id not declared by the envelope raises
        ``keygroup-unknown-key-id``; a caller scope matching no entry
        raises ``keygroup-scope-mismatch``; every key-dependent
        failure (wrong material, sub-quorum, tampered
        tag/ciphertext/header) raises the single generic code
        ``keygroup-open-refused`` after data-independent work on the
        refusal path (every usable wrap tried, one compare_digest per
        wrap, no early exit). Structural failures raise
        ``keygroup-malformed``; unknown versions raise
        ``keygroup-version-unknown``. Every open attempt -- including
        structural refusals -- is journaled digest-only.
        """
        raw = _as_bytes(envelope_bytes)
        try:
            parsed = _parse(raw)
        except KeyGroupError as exc:
            if isinstance(raw, (bytes, bytearray)):
                digest_src = bytes(raw)
            else:
                digest_src = repr(raw).encode("utf-8", "replace")
            self._log("keygroup-open-refused", {
                "event": "open_refused",
                "envelope_digest": self._digest(digest_src),
                "refusal_code": exc.code,
            })
            raise
        env_digest = self._digest(bytes(raw))

        def _refuse(code, detail):
            self._log("keygroup-open-refused", {
                "event": "open_refused",
                "envelope_digest": env_digest,
                "refusal_code": code,
            })
            raise KeyGroupRefusal(code, detail)

        if not isinstance(key_materials, dict):
            _refuse("keygroup-open-refused",
                    "key materials must be a dict")
        materials = {}
        for kid, km in key_materials.items():
            if not isinstance(kid, str):
                _refuse("keygroup-open-refused",
                        "key id must be a str")
            km = _as_bytes(km)
            if not isinstance(km, bytes) or not km:
                _refuse("keygroup-open-refused",
                        "key material for %r must be non-empty bytes"
                        % kid)
            materials[kid] = km

        declared = set()
        for _quorum, members in parsed.groups:
            for kid, _scope, _wrap in members:
                declared.add(kid.decode("utf-8"))
        unknown = [k for k in materials if k not in declared]
        if unknown:
            # Fail closed: the caller operates with a key identity the
            # envelope never authorized. Never silently ignored.
            _refuse("keygroup-unknown-key-id",
                    "key id(s) not declared by the envelope: %s" %
                    ", ".join(sorted(unknown)))

        if scope is not None:
            if not isinstance(scope, str):
                _refuse("keygroup-scope-mismatch",
                        "scope must be a str")
            sbytes = scope.encode("utf-8")
            if not any(sbytes == mscope
                       for _q, members in parsed.groups
                       for _kid, mscope, _wrap in members):
                _refuse("keygroup-scope-mismatch",
                        "no entry declares scope %r" % scope)
        else:
            sbytes = None

        # Data-independent refusal path: try every usable wrap, one
        # compare_digest per wrap, no early exit. Usable = key id
        # supplied and (no caller scope, or entry scope matches).
        verified = []  # (group_index, key_id) in trial order
        for gi, (quorum, members) in enumerate(parsed.groups):
            for kid, mscope, wrap in members:
                kid_s = kid.decode("utf-8")
                if kid_s not in materials:
                    continue
                if sbytes is not None and mscope != sbytes:
                    continue
                candidate = self._kem.unwrap(wrap, kid, mscope,
                                             materials[kid_s])
                mac_key = _kdf(candidate, b"payload-mac", 32)
                expect = hmac.new(mac_key,
                                  _DOMAIN + b"tag:" + parsed.header +
                                  parsed.ct, hashlib.sha256).digest()
                if hmac.compare_digest(expect, parsed.tag):
                    verified.append((gi, kid_s, candidate))

        for gi, (quorum, members) in enumerate(parsed.groups):
            hits = [(kid_s, cand) for vgi, kid_s, cand in verified
                    if vgi == gi]
            if len(hits) >= quorum:
                data_key = hits[0][1]
                enc_key = _kdf(data_key, b"payload-enc", 32)
                payload = _xor(parsed.ct, _keystream(
                    enc_key, parsed.pnonce, len(parsed.ct)))
                key_ids = [kid_s for kid_s, _c in hits]
                scopes = sorted(set(
                    mscope.decode("utf-8")
                    for kid, mscope, _wrap in members))
                self._log("keygroup-opened", {
                    "event": "opened",
                    "envelope_digest": env_digest,
                    "payload_digest": self._digest(payload),
                    "group_index": gi,
                    "key_ids": key_ids,
                    "scopes": scopes,
                })
                return payload, {
                    "payload_digest": self._digest(payload),
                    "envelope_digest": env_digest,
                    "group_index": gi,
                    "key_ids": key_ids,
                    "scopes": scopes,
                    "payload_signed": parsed.payload_signed,
                }
        _refuse("keygroup-open-refused", "no group reached quorum")
