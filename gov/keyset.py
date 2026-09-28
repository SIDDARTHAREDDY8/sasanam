"""Versioned signing keysets for the audit/evidence signing path.

PATTERN LINEAGE: tink-crypto/tink-py (Apache-2.0) -- this module steals
Tink's *KeysetHandle* data-model and rotation ritual (every key carries a
version id; one primary signs new payloads; retired keys stay
verify-capable; rotation never invalidates old signatures) and
reimplements it in stdlib Python. **No Tink code is vendored here** --
only the pattern: versioned keys, a single primary, verify-only
retirement, and fail-closed status checks.

It is ALSO adapted to this repo's own idiom: like the A5 threshold
roster's ``prev_roster_hash`` chaining, every rotation is authorized by a
signature from the *previous primary*, so a keyset carries its own
verifiable lineage. Revocation (the compromise story Tink leaves to key
management) is explicit: a revoked version still verifies *historical*
signatures for forensics but can never mint a new signing handle.

Layout of a keyset document (``sasanam-keyset/v1``)::

    {"format": "sasanam-keyset/v1",
     "purpose": "audit-entry-signing",
     "versions": [{"version": 1, "key_id": "<sha256(pub)[:16] hex>",
                   "public_key_hex": "<32-byte ed25519 pub>",
                   "status": "active|verify-only|revoked"}, ...],
     "primary_version": 2,
     "rotation_lineage": [  # one record per version >= 2, signed by the
                            # previous primary
        {"from_version": 1, "to_version": 2, "from_key_id": ...,
         "to_key_id": ..., "to_public_key_hex": ...,
         "prev_keyset_hash": "<sha256 of the keyset before rotation>",
         "at": <unix ts>, "sig": "<hex ed25519 sig>"}],
     "revocations": [  # signed by the primary in office at revoke time
        {"version": 1, "key_id": ..., "reason": ...,
         "at": <unix ts>, "revoked_by_version": 2,
         "revoked_by_key_id": ..., "keyset_hash": ...,
         "sig": "<hex ed25519 sig>"}]}

Rules (all fail closed):
  * exactly one version is ``active`` and it is the ``primary_version``;
  * every other version is ``verify-only`` (historical signatures still
    verify) or ``revoked`` (historical signatures verify only when the
    verifier explicitly opts into forensics -- the standard
    ``find_verifying_key`` path refuses revoked versions);
  * a signing handle (``KeysetSigner``) can only be minted for the
    *active* version, and only by presenting that version's seed;
  * the primary can never be revoked directly -- rotate first, then
    revoke the retired version (so there is always exactly one key
    allowed to sign);
  * rotation is authorized by the previous primary's seed; the lineage
    record's signature is checked by ``Keyset.verify``;
  * a key's public material never changes across its lifetime, and key
    ids are never reused across versions (rotation always introduces
    fresh key material).

The keyset document itself is PUBLIC (it carries only public keys plus
authorization records). The seeds stay in process memory / the KMS
envelope exactly like ``gov.signing.Ed25519Signer`` today.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import copy
import hashlib
import json
import os
import time
from dataclasses import dataclass

from . import ed25519 as _ed
from .signing import Signer, Ed25519Signer, ed25519_key_id

__all__ = [
    "KEYSET_FORMAT",
    "KEYSET_PURPOSE_AUDIT_ENTRY_SIGNING",
    "STATUS_ACTIVE",
    "STATUS_VERIFY_ONLY",
    "STATUS_REVOKED",
    "STATUSES",
    "ROTATION_DOMAIN",
    "REVOKE_DOMAIN",
    "KeysetError",
    "KeyVersion",
    "Keyset",
    "KeysetSigner",
    "new_keyset",
    "rotate_keyset",
    "revoke_version",
    "keyset_signer_for_version",
    "keyset_signer_from_config",
    "rotation_statement",
    "revocation_statement",
]

KEYSET_FORMAT = "sasanam-keyset/v1"
KEYSET_PURPOSE_AUDIT_ENTRY_SIGNING = "audit-entry-signing"

STATUS_ACTIVE = "active"
STATUS_VERIFY_ONLY = "verify-only"
STATUS_REVOKED = "revoked"
STATUSES = frozenset({STATUS_ACTIVE, STATUS_VERIFY_ONLY, STATUS_REVOKED})

# Domain separators for the authorization records. The trailing NUL keeps
# them unambiguous against any future domain that merely extends the
# prefix (same idiom as gov/log.py's _ENTRY_SIG_DOMAIN).
ROTATION_DOMAIN = b"sasanam-keyset-rotation/v1\x00"
REVOKE_DOMAIN = b"sasanam-keyset-revoke/v1\x00"

_KEYSET_FILE_VAR = "GOV_AUDIT_KEYSET_FILE"
_SEED_VAR = "GOV_AUDIT_SIGNING_KEY"
_SEED_FILE_VAR = "GOV_AUDIT_SIGNING_KEY_FILE"

_ROTATION_STMT_FIELDS = ("from_version", "to_version", "from_key_id",
                         "to_key_id", "to_public_key_hex",
                         "prev_keyset_hash", "at")
_REVOKE_STMT_FIELDS = ("version", "key_id", "reason", "at",
                       "revoked_by_version", "revoked_by_key_id",
                       "keyset_hash")


class KeysetError(Exception):
    """Any keyset structural, authorization, or configuration failure."""


def _now():
    return int(time.time())


def _canonical_json(obj):
    """Deterministic JSON for hashing and signing (mirrors the recipe in
    gov/log.py::_canonical so future cross-module comparisons stay sane)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)


def _require_seed(seed, what="seed"):
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise KeysetError("%s must be 32 bytes" % what)
    return bytes(seed)


def _require_hex(value, nbytes, what):
    if not isinstance(value, str):
        raise KeysetError("%s must be a hex string" % what)
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise KeysetError("%s is not valid hex" % what)
    if len(raw) != nbytes:
        raise KeysetError("%s must be %d bytes, got %d"
                          % (what, nbytes, len(raw)))
    return raw


def rotation_statement(from_version, to_version, from_key_id, to_key_id,
                       to_public_key_hex, prev_keyset_hash, at=None):
    """Canonical bytes of a rotation authorization statement (the part of
    a lineage record covered by the previous primary's signature)."""
    return _canonical_json({
        "from_version": from_version,
        "to_version": to_version,
        "from_key_id": from_key_id,
        "to_key_id": to_key_id,
        "to_public_key_hex": to_public_key_hex,
        "prev_keyset_hash": prev_keyset_hash,
        "at": _now() if at is None else at,
    }).encode("utf-8")


def revocation_statement(version, key_id, reason, revoked_by_version,
                         revoked_by_key_id, keyset_hash, at=None):
    """Canonical bytes of a revocation authorization statement (the part
    of a revocation record covered by the revoking primary's signature)."""
    return _canonical_json({
        "version": version,
        "key_id": key_id,
        "reason": reason,
        "revoked_by_version": revoked_by_version,
        "revoked_by_key_id": revoked_by_key_id,
        "keyset_hash": keyset_hash,
        "at": _now() if at is None else at,
    }).encode("utf-8")


@dataclass(frozen=True)
class KeyVersion:
    """One versioned public key in a keyset."""
    version: int
    key_id: str
    public_key: bytes
    status: str

    def to_dict(self):
        return {"version": self.version,
                "key_id": self.key_id,
                "public_key_hex": self.public_key.hex(),
                "status": self.status}


def _parse_key_version(raw, where):
    if not isinstance(raw, dict):
        raise KeysetError("%s must be a mapping" % where)
    unknown = set(raw) - {"version", "key_id", "public_key_hex", "status"}
    if unknown:
        raise KeysetError("%s carries unknown fields: %s"
                          % (where, sorted(unknown)))
    version = raw.get("version")
    if isinstance(version, bool) or not isinstance(version, int) \
            or version < 1:
        raise KeysetError("%s.version must be an integer >= 1" % where)
    key_id = raw.get("key_id")
    # The repo's key-id convention (gov.signing.ed25519_key_id):
    # sha256(pub).hexdigest()[:16] -- 16 hex chars (8 bytes). The
    # keyset extends that binding; it does not invent a new one.
    _require_hex(key_id, 8, "%s.key_id" % where)
    pub = _require_hex(raw.get("public_key_hex"), 32,
                       "%s.public_key_hex" % where)
    if ed25519_key_id(pub) != key_id:
        raise KeysetError("%s.key_id does not match its public key" % where)
    status = raw.get("status")
    if status not in STATUSES:
        raise KeysetError("%s.status must be one of %s"
                          % (where, sorted(STATUSES)))
    return KeyVersion(version=version, key_id=key_id, public_key=pub,
                      status=status)


class Keyset:
    """A validated, immutable versioned signing keyset (public material)."""

    def __init__(self, doc):
        versions = [_parse_key_version(v, "versions[%d]" % i)
                    for i, v in enumerate(doc.get("versions", []))]
        if not versions:
            raise KeysetError("keyset must carry at least one version")
        seen_v, seen_kid = set(), set()
        for kv in versions:
            if kv.version in seen_v:
                raise KeysetError("duplicate version %d" % kv.version)
            if kv.key_id in seen_kid:
                raise KeysetError("key id reused across versions: %s"
                                  % kv.key_id)
            seen_v.add(kv.version)
            seen_kid.add(kv.key_id)
        if seen_v != set(range(1, len(versions) + 1)):
            raise KeysetError("versions must be dense 1..%d, got %s"
                              % (len(versions), sorted(seen_v)))
        primary = doc.get("primary_version")
        if isinstance(primary, bool) or not isinstance(primary, int):
            raise KeysetError("primary_version must be an integer")
        active = [kv for kv in versions if kv.status == STATUS_ACTIVE]
        if len(active) != 1:
            raise KeysetError("keyset must have exactly one active "
                              "version, found %d" % len(active))
        if active[0].version != primary:
            raise KeysetError("primary_version %d is not the active "
                              "version %d" % (primary, active[0].version))
        versions = tuple(sorted(versions, key=lambda kv: kv.version))
        self._versions = versions
        self._by_version = {kv.version: kv for kv in versions}
        self._by_key_id = {kv.key_id: kv for kv in versions}
        self._primary_version = primary
        self._purpose = doc.get("purpose")
        self._lineage = [dict(r) for r in doc.get("rotation_lineage", [])]
        self._revocations = [dict(r) for r in doc.get("revocations", [])]
        self._doc = {"format": KEYSET_FORMAT,
                     "purpose": self._purpose,
                     "versions": [kv.to_dict() for kv in versions],
                     "primary_version": primary,
                     "rotation_lineage": copy.deepcopy(self._lineage),
                     "revocations": copy.deepcopy(self._revocations)}

    @classmethod
    def from_dict(cls, doc):
        """Parse and structurally validate a keyset document (fail-closed)."""
        if not isinstance(doc, dict):
            raise KeysetError("keyset document must be a mapping")
        unknown = set(doc) - {"format", "purpose", "versions",
                              "primary_version", "rotation_lineage",
                              "revocations"}
        if unknown:
            raise KeysetError("keyset carries unknown top-level fields: %s"
                              % sorted(unknown))
        if doc.get("format") != KEYSET_FORMAT:
            raise KeysetError("unsupported keyset format: %r"
                              % (doc.get("format"),))
        purpose = doc.get("purpose")
        if not isinstance(purpose, str) or not purpose:
            raise KeysetError("keyset purpose must be a non-empty string")
        for field in ("versions", "rotation_lineage", "revocations"):
            if not isinstance(doc.get(field), list):
                raise KeysetError("keyset.%s must be a list" % field)
        return cls(doc)

    def to_dict(self):
        return copy.deepcopy(self._doc)

    @property
    def purpose(self):
        return self._purpose

    @property
    def primary_version(self):
        return self._primary_version

    @property
    def versions(self):
        return self._versions

    def version(self, n):
        """The KeyVersion for ``n`` (KeysetError when unknown)."""
        try:
            return self._by_version[n]
        except KeyError:
            raise KeysetError("unknown key version: %r" % (n,))

    def by_key_id(self, key_id):
        """The KeyVersion for ``key_id`` (None when unknown)."""
        return self._by_key_id.get(key_id)

    def keyset_hash(self):
        """Canonical SHA256 of this keyset document (lineage chaining)."""
        return hashlib.sha256(
            _canonical_json(self._doc).encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self):
        """Full verification: structure, rotation lineage, revocations.

        Returns ``(True, "")`` or ``(False, reason)``; never raises."""
        try:
            self._verify_lineage()
            self._verify_revocations()
        except KeysetError as e:
            return False, str(e)
        return True, ""

    def _verify_lineage(self):
        records = self._lineage
        by_to = {}
        for i, rec in enumerate(records):
            where = "rotation_lineage[%d]" % i
            if not isinstance(rec, dict):
                raise KeysetError("%s must be a mapping" % where)
            unknown = set(rec) - set(_ROTATION_STMT_FIELDS) - {"sig"}
            if unknown:
                raise KeysetError("%s carries unknown fields: %s"
                                  % (where, sorted(unknown)))
            for f in _ROTATION_STMT_FIELDS:
                if f not in rec:
                    raise KeysetError("%s missing %r" % (where, f))
            to_v = rec["to_version"]
            if isinstance(to_v, bool) or not isinstance(to_v, int) \
                    or to_v < 2:
                raise KeysetError("%s.to_version must be an integer >= 2"
                                  % where)
            if to_v in by_to:
                raise KeysetError("duplicate lineage record for version %d"
                                  % to_v)
            by_to[to_v] = rec
        # Every version >= 2 needs exactly one record, chained from v-1.
        for kv in self._versions:
            if kv.version < 2:
                continue
            rec = by_to.get(kv.version)
            if rec is None:
                raise KeysetError("version %d has no rotation lineage "
                                  "record" % kv.version)
            if rec["from_version"] != kv.version - 1 or \
                    isinstance(rec["from_version"], bool):
                raise KeysetError("version %d lineage must chain from "
                                  "version %d" % (kv.version,
                                                  kv.version - 1))
            prev = self._by_version[kv.version - 1]
            if rec["from_key_id"] != prev.key_id:
                raise KeysetError("version %d lineage from_key_id does not "
                                  "match version %d" % (kv.version,
                                                        prev.version))
            if rec["to_key_id"] != kv.key_id or \
                    rec["to_public_key_hex"] != kv.public_key.hex():
                raise KeysetError("version %d lineage does not name the "
                                  "version's key" % kv.version)
            at = rec["at"]
            if isinstance(at, bool) or not isinstance(at, int) or at < 0:
                raise KeysetError("rotation_lineage record has a bad 'at'")
            sig_hex = rec.get("sig")
            sig = _require_hex(sig_hex, 64, "rotation_lineage sig")
            body = ROTATION_DOMAIN + rotation_statement(
                rec["from_version"], rec["to_version"], rec["from_key_id"],
                rec["to_key_id"], rec["to_public_key_hex"],
                rec["prev_keyset_hash"], at=at)
            if not _ed.verify(prev.public_key, body, sig):
                raise KeysetError("version %d lineage signature does not "
                                  "verify under the previous primary"
                                  % kv.version)

    def _verify_revocations(self):
        for i, rec in enumerate(self._revocations):
            where = "revocations[%d]" % i
            if not isinstance(rec, dict):
                raise KeysetError("%s must be a mapping" % where)
            unknown = set(rec) - set(_REVOKE_STMT_FIELDS) - {"sig"}
            if unknown:
                raise KeysetError("%s carries unknown fields: %s"
                                  % (where, sorted(unknown)))
            for f in _REVOKE_STMT_FIELDS:
                if f not in rec:
                    raise KeysetError("%s missing %r" % (where, f))
            v = rec["version"]
            if isinstance(v, bool) or not isinstance(v, int):
                raise KeysetError("%s.version must be an integer" % where)
            kv = self._by_version.get(v)
            if kv is None:
                raise KeysetError("%s names unknown version %r"
                                  % (where, v))
            if kv.status != STATUS_REVOKED:
                raise KeysetError("version %d has a revocation record but "
                                  "is not revoked" % v)
            if rec["key_id"] != kv.key_id:
                raise KeysetError("%s.key_id does not match version %d"
                                  % (where, v))
            if v == self._primary_version:
                raise KeysetError("the primary version cannot be revoked")
            rb = rec["revoked_by_version"]
            if isinstance(rb, bool) or not isinstance(rb, int):
                raise KeysetError("%s.revoked_by_version must be an integer"
                                  % where)
            rbv = self._by_version.get(rb)
            if rbv is None:
                raise KeysetError("%s names unknown revoker %r" % (where,
                                                                   rb))
            if rbv.status == STATUS_REVOKED:
                raise KeysetError("revocation authorized by a revoked key")
            if rb == v:
                raise KeysetError("a version cannot revoke itself")
            if rec["revoked_by_key_id"] != rbv.key_id:
                raise KeysetError("%s.revoked_by_key_id mismatch" % where)
            reason = rec["reason"]
            if not isinstance(reason, str) or not reason.strip():
                raise KeysetError("%s needs a non-empty reason" % where)
            at = rec["at"]
            if isinstance(at, bool) or not isinstance(at, int) or at < 0:
                raise KeysetError("%s has a bad 'at'" % where)
            sig = _require_hex(rec.get("sig"), 64, "revocation sig")
            body = REVOKE_DOMAIN + revocation_statement(
                v, rec["key_id"], reason, rb, rec["revoked_by_key_id"],
                rec["keyset_hash"], at=at)
            if not _ed.verify(rbv.public_key, body, sig):
                raise KeysetError("revocation record for version %d does "
                                  "not verify under the revoking key" % v)

    # ------------------------------------------------------------------
    # Entry verification helper (the trust-directory lookup)
    # ------------------------------------------------------------------

    def find_verifying_key(self, entry):
        """Map a signed envelope to the KeyVersion that should verify it.

        Returns ``(KeyVersion|None, reason)``; never raises. Enforces:
          * the envelope's ``sig_key_id`` names a key in this keyset;
          * when ``sig_key_version`` is present it is an integer naming a
            version whose key id matches the envelope's (confusion fails
            closed);
          * revoked versions never verify here (historical forensics must
            opt in explicitly);
          * envelopes with no version take the legacy path (v1 signature
            body) so pre-keyset entries keep verifying.
        """
        if not isinstance(entry, dict):
            return None, "entry is not a mapping"
        kid = entry.get("sig_key_id")
        if not isinstance(kid, str) or not kid:
            return None, "envelope missing sig_key_id"
        ver = entry.get("sig_key_version")
        if ver is None:
            kv = self._by_key_id.get(kid)
            if kv is None:
                return None, "unknown key id (legacy entry)"
            if kv.status == STATUS_REVOKED:
                return None, "signing key revoked (legacy entry)"
            return kv, "legacy (no version bound)"
        if isinstance(ver, bool) or not isinstance(ver, int):
            return None, "sig_key_version is not an integer"
        if ver < 1:
            return None, "sig_key_version out of range"
        kv = self._by_version.get(ver)
        if kv is None:
            return None, "unknown key version %d" % ver
        if kv.key_id != kid:
            return None, ("version/key_id mismatch: envelope names version "
                           "%d but a different key id" % ver)
        if kv.status == STATUS_REVOKED:
            return None, "key version %d is revoked" % ver
        return kv, "ok"

    def find_verifying_key_for_forensics(self, entry):
        """Like :meth:`find_verifying_key`, but revoked versions are
        returned instead of refused.

        FORENSICS ONLY -- for attributing historical signatures after
        a compromise ("was this old entry signed by the now-revoked
        key?"). It answers attribution, never authorization: never use
        the returned key to trust new data, and never use this method
        in a verification path that gates access or acceptance.
        """
        if not isinstance(entry, dict):
            return None, "entry is not a mapping"
        kid = entry.get("sig_key_id")
        if not isinstance(kid, str) or not kid:
            return None, "envelope missing sig_key_id"
        ver = entry.get("sig_key_version")
        if ver is None:
            kv = self._by_key_id.get(kid)
            if kv is None:
                return None, "unknown key id (legacy entry)"
            return kv, "legacy (no version bound, forensics)"
        if isinstance(ver, bool) or not isinstance(ver, int):
            return None, "sig_key_version is not an integer"
        if ver < 1:
            return None, "sig_key_version out of range"
        kv = self._by_version.get(ver)
        if kv is None:
            return None, "unknown key version %d" % ver
        if kv.key_id != kid:
            return None, ("version/key_id mismatch: envelope names version "
                           "%d but a different key id" % ver)
        return kv, "ok (forensics: revoked versions included)"


class KeysetSigner(Signer):
    """A ``Signer`` bound to one keyset version.

    Satisfies the ``gov.signing.Signer`` ABC so it plugs into
    ``ActionLog`` unchanged; ``gov/log.py`` writes ``key_version`` into
    the entry's signature envelope (``sig_key_version``), which the v2
    signature body cryptographically binds.
    """

    def __init__(self, seed, version):
        if isinstance(version, bool) or not isinstance(version, int) \
                or version < 1:
            raise KeysetError("key version must be an integer >= 1")
        self._inner = Ed25519Signer(seed)  # validates the 32-byte seed
        self._version = version

    @property
    def key_id(self):
        return self._inner.key_id

    @property
    def public_key(self):
        return self._inner.public_key

    @property
    def key_version(self):
        """The keyset version this signer speaks for."""
        return self._version

    def sign(self, data):
        return self._inner.sign(data)


# ---------------------------------------------------------------------------
# Rituals
# ---------------------------------------------------------------------------

def _fresh_key_version(version, seed, status):
    seed = _require_seed(seed, "seed")
    pub = _ed.publickey(seed)
    return KeyVersion(version=version, key_id=ed25519_key_id(pub),
                      public_key=pub, status=status)


def new_keyset(seed, *, purpose=KEYSET_PURPOSE_AUDIT_ENTRY_SIGNING):
    """Genesis: a keyset with a single active version 1.

    Returns ``(Keyset, KeysetSigner)``. ``purpose`` is bound into the
    document so a keyset minted for one purpose cannot be silently
    reused for another."""
    if not isinstance(purpose, str) or not purpose:
        raise KeysetError("purpose must be a non-empty string")
    kv = _fresh_key_version(1, seed, STATUS_ACTIVE)
    ks = Keyset.from_dict({
        "format": KEYSET_FORMAT,
        "purpose": purpose,
        "versions": [kv.to_dict()],
        "primary_version": 1,
        "rotation_lineage": [],
        "revocations": [],
    })
    return ks, KeysetSigner(seed, 1)


def rotate_keyset(keyset, new_seed, old_primary_seed):
    """Tink-style rotation: version N+1 becomes the active primary,
    the old primary drops to verify-only (its old signatures still
    verify), and the rotation is authorized by the old primary's seed.

    Returns ``(new Keyset, KeysetSigner for the new primary)``.
    Fail-closed: the input keyset must verify, ``old_primary_seed``
    must authenticate as the current primary, and the new key material
    must be fresh to this keyset (no key reuse across versions).
    """
    ok, err = keyset.verify()
    if not ok:
        raise KeysetError("cannot rotate from an invalid keyset: %s" % err)
    old_v = keyset.primary_version
    old_kv = keyset.version(old_v)
    if old_kv.status != STATUS_ACTIVE:
        raise KeysetError("current primary version %d is not active"
                          % old_v)
    auth = KeysetSigner(_require_seed(old_primary_seed,
                                      "old_primary_seed"), old_v)
    if auth.key_id != old_kv.key_id:
        raise KeysetError("old_primary_seed does not authenticate as the "
                          "current primary (version %d)" % old_v)
    new_seed = _require_seed(new_seed, "new_seed")
    new_pub = _ed.publickey(new_seed)
    new_kid = ed25519_key_id(new_pub)
    if keyset.by_key_id(new_kid) is not None:
        raise KeysetError("new key material is already in the keyset -- "
                          "key reuse across versions is forbidden")
    new_v = max(kv.version for kv in keyset.versions) + 1
    prev_hash = keyset.keyset_hash()
    stmt = {"from_version": old_v, "to_version": new_v,
            "from_key_id": old_kv.key_id, "to_key_id": new_kid,
            "to_public_key_hex": new_pub.hex(),
            "prev_keyset_hash": prev_hash, "at": _now()}
    record = dict(stmt)
    record["sig"] = _ed.sign(old_primary_seed,
                             ROTATION_DOMAIN
                             + rotation_statement(
                                 old_v, new_v, old_kv.key_id, new_kid,
                                 new_pub.hex(), prev_hash,
                                 at=stmt["at"])).hex()
    doc = keyset.to_dict()
    for v in doc["versions"]:
        if v["version"] == old_v:
            v["status"] = STATUS_VERIFY_ONLY
    doc["versions"].append({"version": new_v, "key_id": new_kid,
                            "public_key_hex": new_pub.hex(),
                            "status": STATUS_ACTIVE})
    doc["primary_version"] = new_v
    doc["rotation_lineage"].append(record)
    new_ks = Keyset.from_dict(doc)
    ok, err = new_ks.verify()
    if not ok:  # pragma: no cover -- defensive; construction is canonical
        raise KeysetError("rotated keyset failed self-verification: %s"
                          % err)
    return new_ks, KeysetSigner(new_seed, new_v)


def revoke_version(keyset, version, reason, primary_seed):
    """Revoke a non-primary version (the compromise story).

    The revoked version's historical signatures remain attributable but
    ``find_verifying_key`` refuses them; no new signing handle can be
    minted for it. The primary can never be revoked directly -- rotate
    first so there is always exactly one key allowed to sign. The
    revocation record is signed by the primary in office.
    """
    ok, err = keyset.verify()
    if not ok:
        raise KeysetError("cannot revoke in an invalid keyset: %s" % err)
    if isinstance(version, bool) or not isinstance(version, int):
        raise KeysetError("version must be an integer")
    kv = keyset.version(version)  # KeysetError when unknown
    if version == keyset.primary_version:
        raise KeysetError("cannot revoke the primary version (v%d) -- "
                          "rotate first" % version)
    if kv.status == STATUS_REVOKED:
        raise KeysetError("version %d is already revoked" % version)
    if not isinstance(reason, str) or not reason.strip():
        raise KeysetError("a revocation needs a non-empty reason")
    reason = reason.strip()
    pv = keyset.primary_version
    pkv = keyset.version(pv)
    auth = KeysetSigner(_require_seed(primary_seed, "primary_seed"), pv)
    if auth.key_id != pkv.key_id:
        raise KeysetError("primary_seed does not authenticate as the "
                          "current primary (version %d)" % pv)
    stmt = {"version": version, "key_id": kv.key_id, "reason": reason,
            "at": _now(), "revoked_by_version": pv,
            "revoked_by_key_id": pkv.key_id,
            "keyset_hash": keyset.keyset_hash()}
    record = dict(stmt)
    record["sig"] = _ed.sign(primary_seed,
                             REVOKE_DOMAIN
                             + revocation_statement(
                                 version, kv.key_id, reason, pv,
                                 pkv.key_id, stmt["keyset_hash"],
                                 at=stmt["at"])).hex()
    doc = keyset.to_dict()
    for v in doc["versions"]:
        if v["version"] == version:
            v["status"] = STATUS_REVOKED
    doc["revocations"].append(record)
    new_ks = Keyset.from_dict(doc)
    ok, err = new_ks.verify()
    if not ok:  # pragma: no cover -- defensive; construction is canonical
        raise KeysetError("revoked keyset failed self-verification: %s"
                          % err)
    return new_ks


def keyset_signer_for_version(keyset, version, seed):
    """Mint a ``KeysetSigner`` for ``version`` -- only when that version
    is the active primary, and only when ``seed`` actually corresponds
    to the version's key. Anything else raises ``KeysetError`` (this is
    what makes verify-only and revoked keys unable to sign)."""
    ok, err = keyset.verify()
    if not ok:
        raise KeysetError("cannot mint a signer from an invalid keyset: "
                          "%s" % err)
    kv = keyset.version(version)  # KeysetError when unknown
    if kv.status != STATUS_ACTIVE:
        raise KeysetError("version %d is %s, not active -- no signing "
                          "handle" % (version, kv.status))
    signer = KeysetSigner(_require_seed(seed, "seed"), version)
    if signer.key_id != kv.key_id:
        raise KeysetError("seed does not match version %d's key" % version)
    return signer


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _resolve_primary_seed():
    """Resolve the primary seed from the audit-signing env vars.

    Mirrors the contract of ``gov.log.resolve_audit_signer`` (same
    variable names, same validation) without importing ``gov.log`` --
    this module must stay importable without the log layer (the
    dependency arrow is log -> keyset, never the reverse).
    """
    seed_hex = os.environ.get(_SEED_VAR)
    if seed_hex is None:
        path = os.environ.get(_SEED_FILE_VAR)
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    seed_hex = f.read().strip()
            except OSError as e:
                raise KeysetError("cannot read primary seed file %r: %s"
                                  % (path, e))
    if seed_hex is None:
        raise KeysetError(
            "GOV_AUDIT_KEYSET_FILE is set but no primary seed is "
            "configured (need GOV_AUDIT_SIGNING_KEY or "
            "GOV_AUDIT_SIGNING_KEY_FILE) -- refusing to continue "
            "HMAC-only")
    seed_hex = seed_hex.strip()
    try:
        seed = bytes.fromhex(seed_hex)
    except ValueError:
        raise KeysetError("primary seed is not valid hex")
    if len(seed) != 32:
        raise KeysetError("primary seed must be 32 bytes, got %d"
                          % len(seed))
    return seed


def keyset_signer_from_config():
    """Resolve ``(Keyset, KeysetSigner)`` from the environment.

    ``GOV_AUDIT_KEYSET_FILE`` names the keyset document (public
    material); the primary seed comes from ``GOV_AUDIT_SIGNING_KEY`` /
    ``GOV_AUDIT_SIGNING_KEY_FILE`` and MUST correspond to the keyset's
    primary version -- a mismatch (stale seed, wrong file) is a loud
    ``KeysetError``, never a silent key confusion.

    Returns ``(None, None)`` when ``GOV_AUDIT_KEYSET_FILE`` is unset so
    callers can fall back to the legacy single-seed path.
    """
    path = os.environ.get(_KEYSET_FILE_VAR)
    if not path:
        return None, None
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except OSError as e:
        raise KeysetError("cannot read keyset file %r: %s" % (path, e))
    except ValueError as e:
        raise KeysetError("keyset file %r is not valid JSON: %s"
                          % (path, e))
    ks = Keyset.from_dict(doc)  # structural validation, fail-closed
    ok, err = ks.verify()
    if not ok:
        raise KeysetError("keyset file %r failed verification: %s"
                          % (path, err))
    if ks.purpose != KEYSET_PURPOSE_AUDIT_ENTRY_SIGNING:
        raise KeysetError(
            "keyset file %r has purpose %r: refusing to use an "
            "entry-signing keyset minted for another purpose"
            % (path, ks.purpose))
    seed = _resolve_primary_seed()
    signer = keyset_signer_for_version(ks, ks.primary_version, seed)
    return ks, signer
