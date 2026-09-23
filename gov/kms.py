"""KMS envelope encryption for the governance log's data keys.

A provider-neutral envelope-encryption layer for the HMAC data keys that
authenticate the action log (``gov/log.py``). Each epoch's data key is
generated locally (``secrets.token_bytes(32)``) and stored only *wrapped*
(encrypted) under a KMS master key; plaintext exists only in memory after
an explicit, fail-closed ``unwrap`` via the KMS API. The persisted
keyring file (format version 2) holds wrapped blobs + metadata only —
file theft, backup exfiltration, or run-dir reads no longer yield key
material.

Design notes (public-docs knowledge only — no credentials, no network):

* The ``KmsProvider`` ABC is the common denominator of the real envelope
  APIs: AWS KMS ``GenerateDataKey``/``Decrypt`` (always pass ``KeyId`` —
  omitting it lets KMS infer the key from the blob and destroys key-id
  binding; that is exactly the impersonator vector hardened against
  below), GCP KMS ``encrypt``/``decrypt``, Azure Key Vault
  ``wrapKey``/``unwrapKey``.
* **Key-id binding.** ``unwrap_data_key(key_id, wrapped)`` MUST
  authenticate that ``wrapped`` was produced under ``key_id``. A provider
  that decrypts a blob wrapped under a *different* key id hands the
  caller an attacker-chosen data key — total forgery (red-team Attack 2,
  ``workstreams/kms/redteam/attack_kms_impersonator.py``).
* **Fail-closed.** Every KMS failure — outage, auth failure, unknown or
  disabled key, tampered blob, key-id mismatch — raises :class:`KmsError`.
  Callers must not catch-and-continue; there is no fallback key and no
  dev-key fallback on this path, ever.
* Epochs, rotation, retired-key retention, per-epoch verification, atomic
  0600 persistence, and the rotation lock are preserved from
  ``gov/keys.py``; only key *custody* changes. The v1 plaintext
  ``KeyRing`` remains the no-KMS/air-gapped backend (documented weaker
  custody); v1 and v2 files are never mis-parsed (explicit version
  rejection both ways).
* **Lazy materialization.** ``EnvelopeKeyRing.materialize()`` unwraps the
  ACTIVE epoch eagerly (it is needed immediately and constantly) and
  unwraps each RETIRED epoch lazily on first use, so the plaintext window
  during cross-epoch verification is minimal. ``activate()`` is the
  deliberate full-materialization path (it publishes every epoch to the
  process environment, same contract as ``KeyRing.activate``).

``FakeKmsProvider`` — honest limits
----------------------------------
Deterministic local test double: fixed wrap secret, counter nonces,
HMAC-SHA256-PRF counter-mode authenticated wrap. It exercises the envelope
*protocol* (key-id binding, blob tamper-evidence, outage fail-closed) with
zero network and byte-identical outputs across runs. It provides **no**
production security (fixed secret, no hardware backing) and the config
factory refuses it unconditionally — tests construct
``FakeKmsProvider`` directly in code instead. Real cloud wiring is
operator provider-config (``DESIGN.md`` §2, §9); no credentials ship here.
"""

import abc
import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
from pathlib import Path

from .keys import (
    KeyRing,
    KeyMaterial,
    _atomic_write_bytes,
    _epoch_pattern,
    _utcnow,
    rotation_lock,
)

FORMAT_VERSION = 2  # envelope keyring files; v1 (plaintext) rejected loudly
KEY_BYTES = 32
KEY_ID_LEN = 16

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")

# Wave-81: the dev opt-in variable gate for the fake KMS provider is
# DELETED from gov/ (the identifier may not appear here at all). The
# factory below refuses "provider: fake" unconditionally; tests
# construct FakeKmsProvider directly in code.


class KmsError(Exception):
    """Any KMS-side failure: outage, auth failure, unknown/disabled key,
    tampered wrapped blob, or key-id mismatch.

    ALWAYS fail-closed: callers must let this propagate. It never carries
    key material in its message."""


class KeyDescription:
    """Safe KMS key metadata — never key material."""

    def __init__(self, key_id, provider_name, enabled=True,
                 created_utc=None, arn_or_name=None):
        self.key_id = key_id
        self.provider_name = provider_name
        self.enabled = bool(enabled)
        self.created_utc = created_utc or _utcnow()
        self.arn_or_name = arn_or_name

    def describe(self):
        return {"key_id": self.key_id, "provider": self.provider_name,
                "enabled": self.enabled, "created_utc": self.created_utc,
                "arn_or_name": self.arn_or_name}


class KmsProvider(abc.ABC):
    """Provider-neutral envelope API. Real adapters (AWS/GCP/Azure) follow
    this shape; see the module docstring mapping table."""

    provider_name = "abstract"

    # -- contract helpers (concrete) ------------------------------------

    def _validate_key_id(self, key_id):
        if not isinstance(key_id, str) or not _KEY_ID_RE.match(key_id):
            raise KmsError("invalid KMS key id %r" % (key_id,))

    @staticmethod
    def _validate_plaintext(plaintext):
        if (not isinstance(plaintext, (bytes, bytearray))
                or len(plaintext) == 0):
            raise KmsError("plaintext data key must be non-empty bytes")
        return bytes(plaintext)

    # -- abstract operations --------------------------------------------

    @abc.abstractmethod
    def wrap_data_key(self, key_id, plaintext):
        """Encrypt ``plaintext`` under the KMS key ``key_id``.

        Returns the opaque wrapped blob (bytes). Any failure raises
        :class:`KmsError`."""

    @abc.abstractmethod
    def unwrap_data_key(self, key_id, wrapped):
        """Decrypt ``wrapped`` and return the plaintext data key.

        MUST authenticate that ``wrapped`` was produced under ``key_id``
        (impersonator binding). Any failure — including key-id mismatch —
        raises :class:`KmsError`."""

    @abc.abstractmethod
    def describe_key(self, key_id):
        """Return a :class:`KeyDescription` (metadata only). Raises
        :class:`KmsError` for unknown keys or provider failures."""


# ---------------------------------------------------------------------------
# FakeKmsProvider — deterministic local test double. TEST-ONLY.
# ---------------------------------------------------------------------------

_FAKE_MAGIC = b"FAKEKMS1"
# Fixed wrap secret: the entire reason this class is test-only. Documented
# as providing ZERO production security.
_FAKE_WRAP_SECRET = b"fake-kms-test-wrap-secret-v1::TEST-ONLY-DOUBLE"


class FakeKmsProvider(KmsProvider):
    """Deterministic, local, no-network KMS stand-in for tests.

    TEST-ONLY — must never be wired in production: the wrap secret is a
    fixed constant and there is no hardware backing.
    ``kms_provider_from_config`` refuses ``provider: fake``
    unconditionally (wave-81: no dev opt-in variable in gov/); tests
    construct this class directly in code.

    Determinism: counter nonces (not randomness) + fixed secret, so the
    same call sequence on a fresh instance yields byte-identical blobs —
    scripted tests are reproducible.

    Wrap construction (real crypto from the HMAC-SHA256 PRF, stdlib only):
      nonce      = 8-byte big-endian counter (per-instance, locked)
      keystream  = HMAC(secret, "fake-enc" || key_id || nonce || i) stream
      ciphertext = plaintext XOR keystream
      tag        = HMAC(secret, "fake-tag" || key_id || nonce || ciphertext)
      blob       = MAGIC || u16(len(key_id)) || key_id || nonce || ct || tag

    Unwrap authenticates the tag AND binds the embedded key id to the
    requested one (the Attack-2 hardening). Failure injection for
    fail-closed tests: ``outage = True`` (every op raises ``KmsError``)
    and ``disable_key(key_id)`` (describe shows disabled; wrap/unwrap
    reject). ``calls`` records an audit trail of (op, key_id, utc).
    """

    provider_name = "fake"

    def __init__(self, key_ids):
        ids = list(key_ids or [])
        if not ids:
            raise ValueError("FakeKmsProvider needs at least one key id")
        for kid in ids:
            self._validate_key_id(kid)
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate KMS key ids")
        self._key_ids = tuple(ids)
        self._counter = 0
        self._lock = threading.Lock()
        self.calls = []
        self.outage = False
        self.disabled = set()

    # -- test controls ---------------------------------------------------

    def disable_key(self, key_id):
        self._validate_key_id(key_id)
        self.disabled.add(key_id)

    def enable_key(self, key_id):
        self.disabled.discard(key_id)

    # -- internals ---------------------------------------------------------

    def _hmac(self, domain, *parts):
        h = hmac.new(_FAKE_WRAP_SECRET, digestmod=hashlib.sha256)
        h.update(domain)
        for p in parts:
            h.update(b"|")
            h.update(p if isinstance(p, bytes) else str(p).encode("utf-8"))
        return h

    def _keystream(self, key_id_b, nonce, nbytes):
        out = b""
        i = 0
        while len(out) < nbytes:
            out += self._hmac(b"fake-enc", key_id_b, nonce,
                              i.to_bytes(4, "big")).digest()
            i += 1
        return out[:nbytes]

    def _check_ready(self, op, key_id, allow_disabled=False):
        if self.outage:
            raise KmsError("FakeKMS simulated outage during %s" % op)
        self._validate_key_id(key_id)
        if key_id not in self._key_ids:
            raise KmsError("FakeKMS: unknown key id %r" % (key_id,))
        # describe_key is metadata (like AWS DescribeKey on a disabled key)
        # and stays available; wrap/unwrap require an enabled key.
        if not allow_disabled and key_id in self.disabled:
            raise KmsError("FakeKMS: key id %r is disabled" % (key_id,))

    # -- KmsProvider API -----------------------------------------------------

    def wrap_data_key(self, key_id, plaintext):
        self._check_ready("wrap_data_key", key_id)
        plaintext = self._validate_plaintext(plaintext)
        with self._lock:
            self._counter += 1
            nonce = self._counter.to_bytes(8, "big")
        kid_b = key_id.encode("utf-8")
        ks = self._keystream(kid_b, nonce, len(plaintext))
        ct = bytes(a ^ b for a, b in zip(plaintext, ks))
        tag = self._hmac(b"fake-tag", kid_b, nonce, ct).digest()
        blob = (_FAKE_MAGIC + len(kid_b).to_bytes(2, "big")
                + kid_b + nonce + ct + tag)
        self.calls.append(("wrap", key_id, _utcnow()))
        return blob

    def unwrap_data_key(self, key_id, wrapped):
        self._check_ready("unwrap_data_key", key_id)
        try:
            blob = bytes(wrapped)
            if not blob.startswith(_FAKE_MAGIC):
                raise ValueError("bad magic")
            off = len(_FAKE_MAGIC)
            klen = int.from_bytes(blob[off:off + 2], "big")
            off += 2
            embedded = blob[off:off + klen]
            off += klen
            nonce = blob[off:off + 8]
            off += 8
            if len(embedded) != klen or len(nonce) != 8 \
                    or len(blob) < off + 1 + 32:
                raise ValueError("truncated blob")
            ct, tag = blob[off:-32], blob[-32:]
            # KEY-ID BINDING (Attack-2 hardening): the blob's embedded key
            # id must equal the requested one. A blob wrapped under any
            # other key id is rejected even if its tag is valid.
            if not hmac.compare_digest(embedded, key_id.encode("utf-8")):
                raise ValueError(
                    "key id mismatch: blob is for %r, unwrap asked for %r"
                    % (embedded.decode("utf-8", "replace"), key_id))
            expect = self._hmac(b"fake-tag", embedded, nonce, ct).digest()
            if not hmac.compare_digest(tag, expect):
                raise ValueError("authentication tag mismatch")
        except KmsError:
            raise
        except Exception as e:  # never leak blob bytes in the message
            raise KmsError(
                "FakeKMS: cannot unwrap blob for key id %r (%s)"
                % (key_id, e))
        ks = self._keystream(embedded, nonce, len(ct))
        pt = bytes(a ^ b for a, b in zip(ct, ks))
        self.calls.append(("unwrap", key_id, _utcnow()))
        return pt

    def describe_key(self, key_id):
        self._check_ready("describe_key", key_id, allow_disabled=True)
        self.calls.append(("describe", key_id, _utcnow()))
        return KeyDescription(key_id, self.provider_name,
                              enabled=key_id not in self.disabled,
                              arn_or_name="fake:%s" % key_id)


# ---------------------------------------------------------------------------
# EnvelopeKeyRing — one locally generated data key per epoch, KMS-wrapped.
# ---------------------------------------------------------------------------

class WrappedDataKey:
    """One epoch's KMS-wrapped data key. ``key_id`` is
    ``sha256(plaintext)[:16]`` computed at wrap time and stored, so
    :meth:`describe` works without unwrapping."""

    def __init__(self, epoch, kms_key_id, wrapped_blob, key_id,
                 created_utc=None, status="active"):
        if not _epoch_pattern().match(epoch):
            raise ValueError("invalid epoch label %r" % (epoch,))
        if not isinstance(kms_key_id, str) or not _KEY_ID_RE.match(kms_key_id):
            raise ValueError("invalid kms_key_id %r" % (kms_key_id,))
        if (not isinstance(wrapped_blob, (bytes, bytearray))
                or len(wrapped_blob) == 0):
            raise ValueError("wrapped_blob must be non-empty bytes")
        if (not isinstance(key_id, str) or len(key_id) != KEY_ID_LEN
                or not all(c in "0123456789abcdef" for c in key_id)):
            raise ValueError("key_id must be %d hex chars" % KEY_ID_LEN)
        self.epoch = epoch
        self.kms_key_id = kms_key_id
        self.wrapped_blob = bytes(wrapped_blob)
        self.key_id = key_id
        self.created_utc = created_utc or _utcnow()
        self.status = status  # "active" | "retired"

    def to_dict(self):
        return {"epoch": self.epoch,
                "kms_key_id": self.kms_key_id,
                "wrapped_b64": base64.b64encode(
                    self.wrapped_blob).decode("ascii"),
                "key_id": self.key_id,
                "created_utc": self.created_utc,
                "status": self.status}

    @classmethod
    def from_dict(cls, d):
        return cls(d["epoch"], d["kms_key_id"],
                   base64.b64decode(d["wrapped_b64"]),
                   d["key_id"],
                   created_utc=d.get("created_utc"),
                   status=d.get("status", "active"))

    def describe(self):
        """Safe public description — never includes key material."""
        return {"epoch": self.epoch, "key_id": self.key_id,
                "kms_key_id": self.kms_key_id,
                "created_utc": self.created_utc, "status": self.status}


class MaterializedKeyRing(KeyRing):
    """An in-memory plaintext KeyRing materialized from an envelope ring.

    The ACTIVE epoch is unwrapped eagerly at construction (it is needed
    immediately and constantly); each RETIRED epoch is unwrapped via the
    KMS API on first :meth:`get` and then cached — the plaintext window
    during cross-epoch verification is minimal (Architect ruling on
    ``materialize()``).

    MEMORY ONLY: :meth:`save` and :meth:`to_dict` refuse — a materialized
    ring must never be persisted (re-wrap via ``EnvelopeKeyRing``). Any
    KMS failure during unwrap raises :class:`KmsError` (fail-closed).
    """

    def __init__(self, envelope, provider):
        super().__init__()
        self._envelope = envelope
        self._provider = provider
        self._active_epoch = envelope._active_epoch
        self._unwrap_epoch(self._active_epoch)  # eager; may raise KmsError

    def _unwrap_epoch(self, epoch):
        """Unwrap one epoch, adopt its KeyMaterial, return it."""
        wd = self._envelope.get(epoch)  # KeyError if unknown epoch
        pt = self._provider.unwrap_data_key(wd.kms_key_id, wd.wrapped_blob)
        # Canonical bytes: 32 raw bytes as 64 hex chars — identical to
        # keys._generate_key_bytes(), so gov/log.py MAC inputs agree.
        mat = KeyMaterial(epoch, pt.hex().encode("ascii"),
                          created_utc=wd.created_utc, status=wd.status)
        if mat.key_id != wd.key_id:
            raise KmsError(
                "unwrapped data key for epoch %r does not match the "
                "recorded key id" % (epoch,))
        self._adopt_material(mat)
        return mat

    def get(self, epoch):
        """Return the KeyMaterial for ``epoch``, unwrapping retired epochs
        on first use. Unknown epochs raise KeyError; KMS failures raise
        KmsError (fail-closed)."""
        try:
            return self._keys[epoch]
        except KeyError:
            pass
        if epoch not in self._envelope._wrapped:
            raise KeyError("unknown key epoch %r (known: %s)"
                           % (epoch, sorted(self._envelope._wrapped)))
        return self._unwrap_epoch(epoch)

    def epochs(self):
        return sorted(self._envelope._wrapped)

    def describe(self):
        return {"active_epoch": self._active_epoch,
                "lazy_materialized": True,
                "keys": [w.describe() for _, w in
                         sorted(self._envelope._wrapped.items())]}

    def save(self, path):
        raise RuntimeError(
            "refusing to persist a materialized (plaintext) key ring; "
            "re-wrap via EnvelopeKeyRing")

    def to_dict(self):
        raise RuntimeError(
            "refusing to serialize a materialized (plaintext) key ring; "
            "re-wrap via EnvelopeKeyRing")


class EnvelopeKeyRing:
    """Epoch -> WrappedDataKey. Plaintext data keys exist only in memory,
    produced by :meth:`materialize` via the KMS API (fail-closed). The
    persisted file (format v2) holds wrapped blobs + metadata only."""

    FORMAT_VERSION = FORMAT_VERSION

    def __init__(self):
        self._wrapped = {}  # epoch -> WrappedDataKey
        self._active_epoch = None

    # -- construction ---------------------------------------------------

    @classmethod
    def generate(cls, provider, kms_key_id, epoch="epoch-1"):
        """Create a ring with one wrapped data key. A KMS failure raises
        :class:`KmsError` and nothing is constructed."""
        ring = cls()
        ring._wrapped[epoch] = ring._wrap_new(provider, kms_key_id, epoch)
        ring._active_epoch = epoch
        return ring

    @staticmethod
    def _wrap_new(provider, kms_key_id, epoch):
        """Generate a data key and wrap it. The fallible KMS call happens
        BEFORE any ring state is touched (fail-closed ordering)."""
        data_key = secrets.token_bytes(KEY_BYTES)
        blob = provider.wrap_data_key(kms_key_id, data_key)  # may raise
        # key_id is over the CANONICAL key bytes (64 hex chars) — the exact
        # bytes fed to HMAC and stored in GOV_LOG_KEY — so it agrees with
        # KeyMaterial.key_id computed at materialize() time.
        key_id = hashlib.sha256(data_key.hex().encode("ascii")
                                ).hexdigest()[:KEY_ID_LEN]
        return WrappedDataKey(epoch, kms_key_id, blob, key_id,
                              status="active")

    def _next_epoch_label(self):
        import re
        nums = [int(m.group(1)) for ep in self._wrapped
                for m in [re.match(r"^epoch-(\d+)$", ep)] if m]
        return "epoch-%d" % (max(nums) + 1 if nums else 1)

    # -- accessors ------------------------------------------------------

    def active(self):
        return self._wrapped[self._active_epoch]

    def get(self, epoch):
        try:
            return self._wrapped[epoch]
        except KeyError:
            raise KeyError("unknown key epoch %r (known: %s)"
                           % (epoch, sorted(self._wrapped)))

    def epochs(self):
        return sorted(self._wrapped)

    def describe(self):
        return {"format_version": self.FORMAT_VERSION,
                "active_epoch": self._active_epoch,
                "keys": [w.describe()
                         for _, w in sorted(self._wrapped.items())]}

    # -- rotation -------------------------------------------------------

    def rotate(self, provider, kms_key_id=None, new_epoch=None):
        """New epoch, new locally generated data key, wrapped by KMS.

        The old wrapped key is RETAINED (status "retired") so history stays
        verifiable. ``kms_key_id=None`` keeps the current KMS key; pass a
        new one to rotate the KMS master key simultaneously. A wrap failure
        raises :class:`KmsError` with the ring unmutated."""
        new_epoch = new_epoch or self._next_epoch_label()
        if new_epoch in self._wrapped:
            raise ValueError("epoch %r already exists" % (new_epoch,))
        old = self.active()
        wrapped = self._wrap_new(provider, kms_key_id or old.kms_key_id,
                                 new_epoch)  # may raise; ring untouched
        old.status = "retired"
        self._wrapped[new_epoch] = wrapped
        self._active_epoch = new_epoch
        return new_epoch

    def rewrap(self, provider, new_kms_key_id):
        """Rotate the KMS master key WITHOUT changing epochs: unwrap every
        epoch under its current key id, re-wrap under the new one. All
        fallible KMS calls complete before any ring state is mutated."""
        plaintexts = {}
        for ep, wd in self._wrapped.items():
            plaintexts[ep] = provider.unwrap_data_key(wd.kms_key_id,
                                                      wd.wrapped_blob)
        re_wrapped = {}
        for ep, wd in self._wrapped.items():
            blob = provider.wrap_data_key(new_kms_key_id, plaintexts[ep])
            re_wrapped[ep] = WrappedDataKey(
                ep, new_kms_key_id, blob, wd.key_id,
                created_utc=wd.created_utc, status=wd.status)
        self._wrapped = re_wrapped

    # -- plaintext materialization (memory only, never persisted) --------

    def materialize(self, provider):
        """Unwrap the ACTIVE epoch eagerly and return a
        :class:`MaterializedKeyRing` whose retired epochs unwrap lazily on
        first use.

        Any unwrap failure raises :class:`KmsError` (fail-closed). The
        returned ring is memory-only: ``save``/``to_dict`` refuse.
        """
        return MaterializedKeyRing(self, provider)

    def _materialize_all(self, provider):
        """Eagerly unwrap EVERY epoch into a plain in-memory KeyRing.

        Used by :meth:`activate`, the deliberate full-materialization
        path — the only caller that needs retired-epoch plaintext.
        """
        ring = KeyRing()
        for ep in self._wrapped:
            wd = self._wrapped[ep]
            pt = provider.unwrap_data_key(wd.kms_key_id, wd.wrapped_blob)
            mat = KeyMaterial(ep, pt.hex().encode("ascii"),
                              created_utc=wd.created_utc, status=wd.status)
            if mat.key_id != wd.key_id:
                raise KmsError(
                    "unwrapped data key for epoch %r does not match the "
                    "recorded key id" % (ep,))
            ring._adopt_material(mat)
        ring._active_epoch = self._active_epoch
        return ring

    def activate(self, provider):
        """Publish this ring to the process environment (the documented
        gov/log.py integration point — same contract as
        ``KeyRing.activate``: ``GOV_LOG_KEY``/``GOV_LOG_KEY_EPOCH``/
        ``GOV_LOG_KEY_ARCHIVE``).

        This deliberately unwraps every epoch (retired keys are needed in
        the archive var); it is the full-materialization path — prefer
        :meth:`materialize` + :meth:`verify_log` (lazy) elsewhere.
        """
        return self._materialize_all(provider).activate()

    def verify_log(self, log_path, provider):
        """Cross-epoch verification: retired epochs unwrap lazily as the
        replay reaches them. KMS failure -> KmsError, never ok=True."""
        return self.materialize(provider).verify_log(log_path)

    # -- file backend (wrapped only) ------------------------------------

    def to_dict(self):
        return {"format_version": self.FORMAT_VERSION,
                "active_epoch": self._active_epoch,
                "keys": {ep: w.to_dict()
                         for ep, w in self._wrapped.items()}}

    @classmethod
    def from_dict(cls, d):
        if d.get("format_version") != cls.FORMAT_VERSION:
            raise ValueError(
                "unsupported envelope keyring format_version %r "
                "(this loader reads v2 wrapped-key files only; v1 "
                "plaintext files must use keys.KeyRing)"
                % (d.get("format_version"),))
        ring = cls()
        for ep, wd in d["keys"].items():
            ring._wrapped[ep] = WrappedDataKey.from_dict(wd)
        ring._active_epoch = d["active_epoch"]
        if ring._active_epoch not in ring._wrapped:
            raise ValueError("active_epoch %r not in keys"
                             % (ring._active_epoch,))
        return ring

    def save(self, path):
        """Persist atomically (same-dir temp + fsync + os.replace + dir
        fsync; 0600 throughout). The file holds ONLY wrapped blobs."""
        p = Path(path)
        data = (json.dumps(self.to_dict(), indent=2, sort_keys=True)
                + "\n").encode("utf-8")
        return _atomic_write_bytes(p, data)

    @classmethod
    def load(cls, path):
        """Load an envelope keyring. Fail-closed: refuses group/world-
        readable files; rejects v1 plaintext files explicitly."""
        p = Path(path)
        st = p.stat()
        if st.st_mode & 0o077:
            raise PermissionError(
                "refusing to load keyring %s: file is group/world-readable "
                "(mode %o); chmod 600 first" % (p, st.st_mode & 0o777))
        return cls.from_dict(json.loads(p.read_text(encoding="utf-8")))


def rotate_envelope_keyring(path, provider, kms_key_id=None, new_epoch=None,
                            log_path=None):
    """The KMS rotation ceremony (mirrors ``keys.rotate_keyring``).

    1. Load the envelope ring (wrapped only).
    2. If ``log_path`` is given, verify the existing log first — the old
       ring is materialized (lazy unwrap) and the replay runs with
       per-epoch keys. A KMS outage here means "cannot verify" and the
       ceremony REFUSES (never rotate blind on top of an unverifiable
       log).
    3. Rotate: fresh data key, KMS-wrapped, new epoch; old wrapped key
       retained as retired.
    4. Atomic backup ``<path>.bak``; atomic persist (0600).

    Serialized via the public rotation lock. Returns ``(ring, new_epoch)``.
    Call ``ring.activate(provider)`` afterwards to put the new epoch under
    ``gov/log.py``.
    """
    with rotation_lock(path):
        ring = EnvelopeKeyRing.load(path)
        if log_path is not None:
            verdict = ring.verify_log(log_path, provider)
            if not verdict["ok"]:
                raise RuntimeError(
                    "refusing to rotate: existing log failed verification: %s"
                    % verdict["error"])
        new_epoch = ring.rotate(provider, kms_key_id=kms_key_id,
                                new_epoch=new_epoch)
        p = Path(path)
        if p.exists():
            _atomic_write_bytes(Path(str(p) + ".bak"), p.read_bytes())
        ring.save(path)
        return ring, new_epoch


# ---------------------------------------------------------------------------
# Provider factory (config-driven wiring).
# ---------------------------------------------------------------------------

def kms_provider_from_config(mapping):
    """Build a :class:`KmsProvider` from operator config (see ``DESIGN.md``
    §9 for the schema).

    * ``provider: fake`` -> :class:`KmsError`, ALWAYS (test-only; the
      operator config surface never builds the fake KMS — tests
      construct :class:`FakeKmsProvider` directly in code). Wave-81:
      the old dev opt-in variable gate is deleted from ``gov/``.
    * ``provider: aws|gcp|azure`` -> :class:`KmsError`: real cloud adapters
      are not built in this repo ($0 spend, no credentials, no network).
    * anything else -> :class:`KmsError`.
    """
    if not isinstance(mapping, dict):
        raise KmsError("kms config must be a mapping, got %r"
                       % type(mapping).__name__)
    name = mapping.get("provider", "")
    if name == "fake":
        raise KmsError(
            "refusing KMS provider 'fake' from operator config: the fake "
            "KMS is test-only and is never wired from config (construct "
            "FakeKmsProvider directly in test code)")
    if name in ("aws", "gcp", "azure"):
        raise KmsError(
            "real cloud KMS adapters (%s) are not built in this repo: "
            "no credentials, no network, $0 spend. See the module "
            "docstring mapping table." % name)
    raise KmsError("unknown kms provider %r" % (name,))
