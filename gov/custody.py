"""Key custody for A5 threshold checkpoint signing (KMS workstream).

The Crypto Engineer owns threshold *signing* (``gov/signing.py``: k-of-n
multisig over checkpoints, offline-root-signed rosters, verification).
This module owns key *custody*: where the private halves live, how they
are wrapped, and the ceremonies that create and rotate them.

Custody backends (role separation, A5):

* **KMS envelope (production).** :class:`SignerShareStore` wraps each
  checkpoint-signer's 32-byte Ed25519 seed under a KMS data key via the
  ``KmsProvider`` API (``gov/kms.py``). The store file holds wrapped
  blobs + metadata only -- file theft yields no seed material. Seeds
  are unwrapped to memory at signing time (``signer_for``) and never
  persisted in plaintext. This is a *separate* artifact from the HMAC
  log keyring: checkpoint-signing keys != log HMAC keys != rotation
  authority (A5 role separation).
* **Manual custody (air-gapped).** No code path -- documented in
  ``workstreams/kms/CEREMONY_RUNBOOK.md``: seeds on encrypted removable
  media under dual control. The ceremony functions below work with
  either backend because rosters need only *public* keys.

The offline **root key** is never in any store: it lives only on the
offline ceremony machine (a 0600 seed file on encrypted removable
media -- :func:`save_root_seed` / :func:`load_root_seed`) and is used
in-memory during ceremonies to sign rosters. Verifiers trust exactly
one root public key, distributed out-of-band.

Ceremonies (all recorded to a hash-chained transcript):

* ``make_genesis_roster`` -- first roster, ``prev_roster_hash`` =
  ``"GENESIS"``.
* ``rotate_share`` + ``rotate_roster`` -- a keyholder's key is replaced;
  the new roster is root-signed with the previous roster's hash chained
  in. Retired seeds are RETAINED (old checkpoints must stay verifiable
  -- same argument as ``gov/keys.py``: deleting a key orphans
  everything it signed).
* ``rewrap`` -- KMS master-key rotation without touching signing keys
  (no roster change, no ceremony needed beyond the transcript entry).
* Root rotation (break-glass) is a *procedure* in the runbook: new root
  seed, re-signed roster, out-of-band root-pub redistribution.

F78 tip manifest: every ROOT ceremony (genesis, rotate-roster, and the
``update_tip_manifest`` tip-anchor ceremony) writes a root-signed tip
manifest binding ``(record_count, tip_record_hash)`` for the
transcript's current head, so tail truncation is detected by
:func:`verify_ceremony_chain` / :func:`verify_transcript_tip`.

Fail-closed: every KMS failure raises ``KmsError``; an unwrapped seed
whose pubkey does not match the recorded one raises ``KmsError``
(never silently adopts attacker-influenced material); store files
refuse group/world-readable permissions; malformed stores raise
instead of loading partial state.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import threading
from pathlib import Path

from .keys import _atomic_write_bytes, _utcnow
from .kms import KmsError
from .signing import (
    Signer,
    Ed25519Signer,
    Ed25519Verifier,
    ThresholdSigner,
    ed25519_key_id,
    make_roster,
    roster_hash,
    GENESIS_ROSTER,
)

SEED_BYTES = 32
STORE_FORMAT_VERSION = 1
STORE_KIND = "signer-share-store"

_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Guards the in-memory mutate step of rotate_share/rewrap (the fallible
# KMS calls all happen before this lock is taken, so a KMS failure can
# never leave the store half-mutated). File-level ceremony locking for
# the persisted store uses the same advisory rotation_lock(path)
# discipline as gov/kms.py when operators script ceremonies.
_share_mutation_lock = threading.Lock()


def generate_seed(rng=None):
    """Generate a 32-byte Ed25519 seed.

    ``rng`` is injectable for deterministic tests (any object with
    ``getrandbits``); production always uses ``secrets``.
    """
    if rng is None:
        return secrets.token_bytes(SEED_BYTES)
    return bytes(rng.getrandbits(8) for _ in range(SEED_BYTES))


def _check_label(label):
    if not isinstance(label, str) or not _LABEL_RE.match(label):
        raise ValueError("invalid share label %r" % (label,))


class PublicSigner(Signer):
    """Public-only :class:`Signer` handle for roster building.

    Ceremonies need only public keys -- keyholders bring their pubkeys
    to the ceremony and private seeds never leave their custody.
    ``sign()`` always raises: this handle can never sign.
    """

    def __init__(self, key_id, public_key):
        pub = bytes(public_key)
        if len(pub) != 32:
            raise ValueError("public_key must be 32 bytes")
        if ed25519_key_id(pub) != key_id:
            raise ValueError("key_id does not match public_key")
        self._key_id = key_id
        self._pub = pub

    @property
    def key_id(self):
        return self._key_id

    @property
    def public_key(self):
        return self._pub

    def sign(self, data):
        raise RuntimeError("PublicSigner holds no private seed")


class ShareRecord:
    """One keyholder's wrapped Ed25519 seed + public metadata."""

    def __init__(self, label, key_id, pub_hex, status, kms_key_id,
                 wrapped_blob, created_utc=None, retired_utc=None,
                 note=""):
        _check_label(label)
        self.label = label
        self.key_id = key_id
        self.pub_hex = pub_hex
        self.status = status  # "active" | "retired"
        self.kms_key_id = kms_key_id
        self.wrapped_blob = bytes(wrapped_blob)
        self.created_utc = created_utc or _utcnow()
        self.retired_utc = retired_utc
        self.note = note or ""

    def to_dict(self):
        return {
            "label": self.label,
            "key_id": self.key_id,
            "pub_hex": self.pub_hex,
            "status": self.status,
            "kms_key_id": self.kms_key_id,
            "wrapped_b64": base64.b64encode(self.wrapped_blob).decode(
                "ascii"),
            "created_utc": self.created_utc,
            "retired_utc": self.retired_utc,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, d):
        try:
            return cls(
                label=d["label"], key_id=d["key_id"],
                pub_hex=d["pub_hex"], status=d["status"],
                kms_key_id=d["kms_key_id"],
                wrapped_blob=base64.b64decode(d["wrapped_b64"]),
                created_utc=d.get("created_utc"),
                retired_utc=d.get("retired_utc"),
                note=d.get("note", ""))
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError("malformed share record: %s" % (e,))

    def describe(self):
        """Public metadata only -- safe to distribute to verifiers."""
        d = self.to_dict()
        d.pop("wrapped_b64")
        return d


class SignerShareStore:
    """KMS-envelope custody for checkpoint-signer seeds (A5).

    Maps keyholder ``label`` -> :class:`ShareRecord`. The persisted file
    (format v1) holds wrapped blobs + metadata only; plaintext seeds
    exist solely in memory after :meth:`signer_for`.
    """

    FORMAT_VERSION = STORE_FORMAT_VERSION

    def __init__(self):
        self._shares = {}  # label -> ShareRecord

    # -- construction ---------------------------------------------------

    def add_share(self, label, provider, kms_key_id, seed=None,
                  note=""):
        """Enroll a keyholder: wrap ``seed`` under ``kms_key_id``.

        The KMS wrap happens BEFORE any store state is touched: a wrap
        failure leaves the store unmutated (fail-closed ordering).
        Returns the Ed25519 key id.
        """
        _check_label(label)
        if label in self._shares:
            raise ValueError("share label %r already enrolled" % (label,))
        seed = bytes(seed) if seed is not None else generate_seed()
        if len(seed) != SEED_BYTES:
            raise ValueError("seed must be %d bytes" % SEED_BYTES)
        blob = provider.wrap_data_key(kms_key_id, seed)  # may raise
        pub = Ed25519Signer(seed).public_key
        rec = ShareRecord(label=label, key_id=ed25519_key_id(pub),
                          pub_hex=pub.hex(), status="active",
                          kms_key_id=kms_key_id, wrapped_blob=blob,
                          note=note)
        self._shares[label] = rec
        return rec.key_id

    def get(self, label):
        try:
            return self._shares[label]
        except KeyError:
            raise KeyError("unknown share label %r (known: %s)"
                           % (label, sorted(self._shares)))

    def labels(self):
        return sorted(self._shares)

    def active_labels(self):
        return sorted(l for l, r in self._shares.items()
                      if r.status == "active")

    def describe(self):
        """Public metadata for every share -- safe for auditors."""
        return {"format_version": self.FORMAT_VERSION,
                "kind": STORE_KIND,
                "shares": [self._shares[l].describe()
                           for l in self.labels()]}

    # -- signing-time materialization (memory only) ----------------------

    def signer_for(self, label, provider):
        """Unwrap ``label``'s seed to memory; return an Ed25519Signer.

        Fail-closed: KMS errors propagate as ``KmsError``; an unwrapped
        seed whose pubkey mismatches the recorded one raises
        ``KmsError`` (the store never adopts unauthenticated material).
        The signer is memory-only -- nothing here persists plaintext.
        """
        rec = self.get(label)
        seed = provider.unwrap_data_key(rec.kms_key_id, rec.wrapped_blob)
        if len(seed) != SEED_BYTES:
            raise KmsError("unwrapped seed for %r has bad length" % (
                label,))
        if ed25519_key_id(Ed25519Signer(seed).public_key) != rec.key_id:
            raise KmsError("unwrapped seed for %r does not match the "
                           "recorded key id" % (label,))
        return Ed25519Signer(seed)

    def threshold_signer(self, labels, threshold, provider):
        """Build a :class:`ThresholdSigner` over ``labels``.

        Each seed unwraps to memory at signing time; the returned
        object holds no persisted form. This is the signing-host entry
        point: k keyholders authorize the unwrap of their shares (per
        the runbook), the host collects k signatures per checkpoint.
        """
        signers = [self.signer_for(l, provider) for l in labels]
        return ThresholdSigner(signers, threshold)

    def active_signers(self, provider):
        """In-memory signers for every active share."""
        return [self.signer_for(l, provider) for l in self.active_labels()]

    def public_signers(self):
        """Public-only handles for the active set (roster building)."""
        return [PublicSigner(r.key_id, bytes.fromhex(r.pub_hex))
                for r in (self._shares[l] for l in self.active_labels())]

    # -- rotation ---------------------------------------------------------

    def rotate_share(self, label, provider, kms_key_id=None, seed=None,
                     note=""):
        """Replace a keyholder's signing key (share-rotation ceremony).

        Generates (or takes) a new seed, wraps it FIRST -- a KMS failure
        leaves the store unmutated -- then retires the old record
        (RETAINED: old checkpoints must stay verifiable). Returns
        ``(old_key_id, new_key_id)``.

        The roster does NOT update itself: follow with
        :func:`rotate_roster` in a root-key ceremony, otherwise the new
        key is not yet authorized to sign checkpoints.
        """
        with _share_mutation_lock:
            rec = self.get(label)
            if rec.status != "active":
                raise ValueError("share %r is not active" % (label,))
            new_seed = (bytes(seed) if seed is not None
                        else generate_seed())
            if len(new_seed) != SEED_BYTES:
                raise ValueError("seed must be %d bytes" % SEED_BYTES)
            blob = provider.wrap_data_key(kms_key_id or rec.kms_key_id,
                                          new_seed)  # may raise
            pub = Ed25519Signer(new_seed).public_key
            new_rec = ShareRecord(
                label=label, key_id=ed25519_key_id(pub),
                pub_hex=pub.hex(), status="active",
                kms_key_id=kms_key_id or rec.kms_key_id,
                wrapped_blob=blob, note=note)
            rec.status = "retired"
            rec.retired_utc = _utcnow()
            # Keep history: label -> list of records, newest last.
            hist = getattr(self, "_history", None)
            if hist is None:
                self._history = hist = {}
            hist.setdefault(label, []).append(rec)
            self._shares[label] = new_rec
            return rec.key_id, new_rec.key_id

    def retired_shares(self, label):
        """Retired records for ``label`` (oldest first)."""
        return list(getattr(self, "_history", {}).get(label, []))

    def rewrap(self, provider, new_kms_key_id):
        """Rotate the KMS master key WITHOUT changing signing keys.

        Unwraps every share under its current KMS key id and re-wraps
        under the new one. All fallible KMS calls complete before any
        store state is mutated. No roster change is needed (key ids are
        over the seeds, which are unchanged).
        """
        with _share_mutation_lock:
            plaintexts = {}
            for label, rec in self._shares.items():
                plaintexts[label] = provider.unwrap_data_key(
                    rec.kms_key_id, rec.wrapped_blob)
            histories = {}
            for label, hist in getattr(self, "_history", {}).items():
                histories[label] = [
                    provider.unwrap_data_key(r.kms_key_id, r.wrapped_blob)
                    for r in hist]
            new_shares, new_hist = {}, {}
            for label, rec in self._shares.items():
                blob = provider.wrap_data_key(new_kms_key_id,
                                              plaintexts[label])
                d = rec.to_dict()
                d.update(kms_key_id=new_kms_key_id,
                         wrapped_b64=base64.b64encode(blob).decode("ascii"))
                new_shares[label] = ShareRecord.from_dict(d)
            for label, hist in getattr(self, "_history", {}).items():
                rh = []
                for r, pt in zip(hist, histories[label]):
                    blob = provider.wrap_data_key(new_kms_key_id, pt)
                    d = r.to_dict()
                    d.update(kms_key_id=new_kms_key_id,
                             wrapped_b64=base64.b64encode(blob).decode(
                                 "ascii"))
                    rh.append(ShareRecord.from_dict(d))
                new_hist[label] = rh
            self._shares = new_shares
            self._history = new_hist

    # -- file backend (wrapped only) ---------------------------------------

    def to_dict(self):
        d = {"format_version": self.FORMAT_VERSION,
             "kind": STORE_KIND,
             "shares": {l: r.to_dict()
                        for l, r in self._shares.items()},
             "history": {l: [r.to_dict() for r in hist]
                         for l, hist in getattr(
                             self, "_history", {}).items()}}
        return d

    @classmethod
    def from_dict(cls, d):
        if d.get("format_version") != cls.FORMAT_VERSION:
            raise ValueError(
                "unsupported signer-share-store format_version %r"
                % (d.get("format_version"),))
        if d.get("kind") != STORE_KIND:
            raise ValueError("not a signer-share-store file")
        store = cls()
        for label, rd in d.get("shares", {}).items():
            store._shares[label] = ShareRecord.from_dict(rd)
        store._history = {l: [ShareRecord.from_dict(rd) for rd in hist]
                          for l, hist in d.get("history", {}).items()}
        return store

    def save(self, path):
        """Persist atomically (same-dir temp + fsync + os.replace, 0600
        throughout). The file holds ONLY wrapped blobs + metadata."""
        p = Path(path)
        data = (json.dumps(self.to_dict(), indent=2, sort_keys=True)
                + "\n").encode("utf-8")
        return _atomic_write_bytes(p, data)

    @classmethod
    def load(cls, path):
        """Load a share store. Fail-closed: refuses group/world-readable
        files."""
        p = Path(path)
        st = p.stat()
        if st.st_mode & 0o077:
            raise PermissionError(
                "refusing to load share store %s: file is "
                "group/world-readable (mode %o); chmod 600 first"
                % (p, st.st_mode & 0o777))
        return cls.from_dict(json.loads(p.read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------
# Offline root key custody
# ---------------------------------------------------------------------------

def save_root_seed(path, seed):
    """Write a root seed to ``path`` (raw 32 bytes, atomic, 0600).

    OFFLINE MACHINE ONLY: the root seed must never exist on a
    networked host. In production this file lives on encrypted
    removable media under dual control (see CEREMONY_RUNBOOK.md).
    """
    seed = bytes(seed)
    if len(seed) != SEED_BYTES:
        raise ValueError("root seed must be %d bytes" % SEED_BYTES)
    _atomic_write_bytes(Path(path), seed)


def load_root_seed(path):
    """Load a root seed. Refuses group/world-readable files."""
    p = Path(path)
    st = p.stat()
    if st.st_mode & 0o077:
        raise PermissionError(
            "refusing to load root seed %s: file is group/world-readable "
            "(mode %o)" % (p, st.st_mode & 0o777))
    seed = p.read_bytes()
    if len(seed) != SEED_BYTES:
        raise ValueError("root seed file %s has bad length" % (p,))
    return seed


def root_signer_from_seed(seed):
    """In-memory root signer for use DURING a ceremony only."""
    return Ed25519Signer(bytes(seed))


# ---------------------------------------------------------------------------
# Root-signed tip manifest (F78)
#
# The ceremony transcript is a hash chain: each record commits to its
# predecessor, so middle-tamper is evident -- but nothing binds the
# chain TIP. Dropping the latest record leaves a valid prefix, and
# verify_ceremony_chain() could not tell. The tip manifest closes that
# hole: at every ROOT ceremony the offline root key signs a manifest
# binding (record_count, tip_record_hash) for the transcript's current
# head. Verification fails closed when the transcript is shorter than
# the manifest says (tail truncation), longer (tail beyond the
# root-bound tip), or the head hash mismatches -- and when a
# manifest-scheme transcript has no (or a corrupt/forged) manifest.
#
# Trust model: the root key stays offline; it is used in-memory during
# ceremonies only (same as roster signing). The manifest carries the
# root public key and is bound to the transcript lineage by
# root_key_id: the manifest's root must equal the root_key_id of the
# transcript's newest root ceremony record (genesis / rotate-roster /
# tip-anchor), which is itself committed under the records' hashes. An
# attacker without the root seed cannot mint a manifest for the
# transcript's root identity; swapping in a foreign-root manifest is
# rejected by the lineage binding.
#
# Legacy transcripts (records written before the manifest scheme)
# carry no manifest_scheme marker and are still verified chain-only --
# a chain prefix was ALWAYS indistinguishable from a complete chain
# for data that predates the binding, so failing those closed would
# orphan history with no security gain. Migration: one
# update_tip_manifest() root ceremony re-chains the legacy records
# under the scheme marker (old head noted in the anchor record) and
# anchors the lineage; the migrated transcript is then
# indistinguishable from a native one, so a later-deleted manifest
# fails closed instead of downgrading to legacy mode.
#
# Residual (honest): the hash chain itself is unauthenticated --
# rewriting the ENTIRE transcript under a different root identity
# still verifies as a self-consistent chain (pre-existing property,
# not introduced here). Roster signatures are verified against the
# out-of-band trusted root public key, which a foreign-root rewrite
# cannot satisfy.
# ---------------------------------------------------------------------------

MANIFEST_SCHEME_VERSION = 1
TIP_MANIFEST_FORMAT_VERSION = 1
TIP_MANIFEST_KIND = "ceremony-tip-manifest"


def tip_manifest_path(transcript_path):
    """Conventional sidecar path for a transcript's tip manifest."""
    return "%s.tip.json" % transcript_path


def _manifest_sign_bytes(body):
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def write_tip_manifest(manifest_path, root_signer, record_count,
                       tip_record_hash, tip_ceremony="", utc=None):
    """Write a root-signed tip manifest (atomic, 0600).

    Binds ``(record_count, tip_record_hash)`` for the transcript head
    named by ``tip_ceremony``. ``root_signer`` is the OFFLINE root key
    in ceremony-time memory (never persisted here). Returns the
    manifest dict.
    """
    if (not isinstance(record_count, int)
            or isinstance(record_count, bool) or record_count < 1):
        raise ValueError("record_count must be a positive int")
    if not isinstance(tip_record_hash, str) or not re.fullmatch(
            r"[0-9a-f]{64}", tip_record_hash):
        raise ValueError("tip_record_hash must be a 64-hex digest")
    pub = bytes(root_signer.public_key)
    if len(pub) != 32:
        raise ValueError("root public key must be 32 bytes")
    body = {
        "format_version": TIP_MANIFEST_FORMAT_VERSION,
        "kind": TIP_MANIFEST_KIND,
        "record_count": record_count,
        "tip_record_hash": tip_record_hash,
        "tip_ceremony": tip_ceremony,
        "utc": utc or _utcnow(),
        "root_key_id": root_signer.key_id,
        "root_public_key": pub.hex(),
    }
    if ed25519_key_id(pub) != body["root_key_id"]:
        raise ValueError("root_signer key_id does not match its "
                         "public key")
    manifest = dict(body)
    manifest["sig"] = root_signer.sign(
        _manifest_sign_bytes(body)).hex()
    _atomic_write_bytes(
        Path(manifest_path),
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"))
    return manifest


def read_tip_manifest(manifest_path):
    """Read a tip manifest. Returns None when the sidecar is absent;
    raises ValueError when it is present but corrupt (fail-closed at
    the verifier)."""
    p = Path(manifest_path)
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ValueError("tip manifest %s is corrupt: %s" % (p, e))
    if not isinstance(d, dict):
        raise ValueError("tip manifest %s is not a JSON object" % (p,))
    return d


def verify_tip_manifest(manifest, trusted_root_pub=None):
    """Validate a parsed tip manifest: shape, root binding, signature.

    ``trusted_root_pub`` (optional, 32 bytes) pins the expected root;
    without it the manifest is self-describing and the caller must
    bind its root_key_id to the transcript lineage (done by
    verify_transcript_tip). Returns (ok, error); never raises on
    malformed input.
    """
    try:
        if not isinstance(manifest, dict):
            return False, "tip manifest is not an object"
        if manifest.get("format_version") != TIP_MANIFEST_FORMAT_VERSION:
            return False, "unsupported tip manifest format_version %r" % (
                manifest.get("format_version"),)
        if manifest.get("kind") != TIP_MANIFEST_KIND:
            return False, "not a ceremony-tip-manifest"
        count = manifest.get("record_count")
        if (not isinstance(count, int) or isinstance(count, bool)
                or count < 1):
            return False, "bad record_count %r" % (count,)
        tip = manifest.get("tip_record_hash")
        if not isinstance(tip, str) or not re.fullmatch(
                r"[0-9a-f]{64}", tip):
            return False, "bad tip_record_hash %r" % (tip,)
        try:
            pub = bytes.fromhex(manifest.get("root_public_key") or "")
        except (TypeError, ValueError):
            return False, "bad root_public_key"
        if len(pub) != 32:
            return False, "bad root_public_key length"
        if ed25519_key_id(pub) != manifest.get("root_key_id"):
            return False, ("tip manifest root_key_id does not match "
                           "its root_public_key")
        if trusted_root_pub is not None:
            if bytes(trusted_root_pub) != pub:
                return False, ("tip manifest root does not match the "
                               "trusted root public key")
        try:
            sig = bytes.fromhex(manifest.get("sig") or "")
        except (TypeError, ValueError):
            return False, "bad manifest sig"
        body = {k: v for k, v in manifest.items() if k != "sig"}
        if not Ed25519Verifier(pub).verify(
                _manifest_sign_bytes(body), sig):
            return False, ("tip manifest signature invalid "
                           "(forgery or corruption)")
        return True, None
    except Exception as e:  # fail-closed on anything unexpected
        return False, "tip manifest invalid: %s" % (e,)


def _check_tip_binding(records, mpath, trusted_root_pub, explicit):
    """Enforce the manifest binding for chain-verified ``records``.

    Fail-closed: missing manifest for a manifest-scheme lineage,
    corrupt/forged manifest, root-lineage mismatch, count or tip-hash
    mismatch in either direction. Legacy lineages (no marker, no
    manifest) keep chain-only verification.
    """
    try:
        manifest = read_tip_manifest(mpath)
    except ValueError as e:
        return False, str(e)
    lineage_claims = any(
        isinstance(r, dict)
        and r.get("manifest_scheme") == MANIFEST_SCHEME_VERSION
        for r in records)
    if manifest is None:
        if explicit:
            return False, "tip manifest %s not found" % (mpath,)
        if lineage_claims:
            return False, (
                "transcript claims the tip-manifest scheme "
                "(manifest_scheme=%d) but %s is missing: refusing to "
                "trust the tail (F78 tail-truncation protection)"
                % (MANIFEST_SCHEME_VERSION, mpath))
        return True, None  # legacy transcript: chain-only verification
    ok, err = verify_tip_manifest(manifest, trusted_root_pub)
    if not ok:
        return False, err
    # Bind the manifest to this transcript's root lineage: the newest
    # root ceremony record's root_key_id (committed under the chain).
    root_kid = None
    for rec in reversed(records):
        detail = rec.get("detail") if isinstance(rec, dict) else None
        kid = (detail.get("root_key_id")
               if isinstance(detail, dict) else None)
        if kid:
            root_kid = kid
            break
    if root_kid is None:
        return False, ("cannot bind tip manifest to the transcript "
                       "lineage: no root ceremony record found (was the "
                       "tail truncated?)")
    if manifest["root_key_id"] != root_kid:
        return False, ("tip manifest root_key_id does not match the "
                       "transcript's root lineage (manifest swap?)")
    n, mcount = len(records), manifest["record_count"]
    if n < mcount:
        return False, ("transcript shorter than the root-signed tip "
                       "manifest (%d < %d records): tail truncation?"
                       % (n, mcount))
    if n > mcount:
        return False, ("transcript longer than the root-signed tip "
                       "manifest (%d > %d records): the %d tail "
                       "record(s) are not root-bound; run a root "
                       "tip-manifest ceremony (update_tip_manifest)"
                       % (n, mcount, n - mcount))
    if not records:
        return False, ("tip manifest binds %d record(s) but the "
                       "transcript is empty" % mcount)
    if records[-1]["record_hash"] != manifest["tip_record_hash"]:
        return False, ("tip record hash does not match the root-signed "
                       "manifest (tip replaced?)")
    return True, None


def verify_transcript_tip(transcript_path, manifest_path=None,
                          trusted_root_pub=None):
    """Verify the transcript's hash chain plus its tip-manifest binding.

    ``manifest_path`` overrides the conventional sidecar
    (``<transcript>.tip.json``); ``trusted_root_pub`` pins the root.
    Returns (ok, error), fail-closed throughout.
    """
    ok, err, records = _verify_chain(transcript_path)
    if not ok:
        return False, err
    mpath = (Path(manifest_path) if manifest_path is not None
             else Path(tip_manifest_path(transcript_path)))
    return _check_tip_binding(records, mpath, trusted_root_pub,
                              explicit=manifest_path is not None)


def update_tip_manifest(transcript_path, root_seed, manifest_path=None,
                        utc=None, participants=()):
    """Root tip-anchor ceremony (F78): anchor the transcript's head.

    Verifies the hash chain (fail-closed), then:

    * **Legacy migration:** records written before the manifest scheme
      carry no ``manifest_scheme`` marker. They are re-chained in
      place -- the marker is added and record hashes recomputed, with
      the pre-migration head hash noted in the anchor record's detail
      for auditability -- so the migrated transcript is
      indistinguishable from a native manifest-scheme transcript. (A
      plain appended anchor would let an attacker delete the anchor
      record plus the manifest and silently downgrade the transcript
      back to legacy mode; re-chaining closes that.)
    * Appends a ``tip-anchor`` ceremony record carrying the marker and
      the root key id, and writes a fresh root-signed tip manifest.

    This is the migration path for legacy transcripts and the recovery
    step after non-root transcript appends (e.g. rewrap entries) or a
    crash between record-append and manifest-write: one root ceremony
    re-binds the tip. Returns ``(manifest, record)``. Raises
    ``ValueError`` on a broken chain (fail-closed: never anchors
    tampered history).
    """
    ok, err, records = _verify_chain(transcript_path)
    if not ok:
        raise ValueError("cannot anchor a broken transcript: %s" % err)
    root = root_signer_from_seed(root_seed)
    p = Path(transcript_path)
    old_head = records[-1]["record_hash"] if records else None
    re_chained = False
    if any(r.get("manifest_scheme") != MANIFEST_SCHEME_VERSION
           for r in records):
        prev = None
        lines = []
        for rec in records:
            body = {k: v for k, v in rec.items()
                    if k not in ("record_hash", "prev_record_hash")}
            body["manifest_scheme"] = MANIFEST_SCHEME_VERSION
            body["prev_record_hash"] = prev
            rh = _record_hash(body)
            body["record_hash"] = rh
            lines.append(json.dumps(body, sort_keys=True,
                                    separators=(",", ":")))
            prev = rh
        _atomic_write_bytes(p, ("\n".join(lines) + "\n").encode("utf-8"))
        re_chained = True
    mpath = (manifest_path if manifest_path is not None
             else tip_manifest_path(transcript_path))
    detail = {"root_key_id": root.key_id,
              "note": "root-signed tip anchor (F78)"}
    if re_chained:
        detail["migrated_legacy_head"] = old_head
        detail["note"] += "; re-chained %d legacy record(s)" % len(
            records)
    record = record_ceremony(
        transcript_path, "tip-anchor", participants, detail,
        utc=utc, root_signer=root, manifest_path=mpath)
    return read_tip_manifest(mpath), record


# ---------------------------------------------------------------------------
# Ceremonies
# ---------------------------------------------------------------------------

def _record_body(action, utc, participants, detail, prev_record_hash):
    return {
        "ceremony": action,
        "utc": utc,
        "participants": list(participants),
        "prev_record_hash": prev_record_hash,
        "detail": detail,
        # F78: every new record declares the tip-manifest scheme under
        # which it was written. The marker is committed by record_hash,
        # so a transcript whose records carry it can never be mistaken
        # for a legacy (pre-manifest) transcript -- deleting the tip
        # manifest sidecar fails closed instead of silently downgrading
        # to chain-only verification.
        "manifest_scheme": MANIFEST_SCHEME_VERSION,
    }


def _record_hash(body):
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True, default=str).encode("utf-8")
    ).hexdigest()


def record_ceremony(path, action, participants, detail, utc=None,
                    prev_record_hash=None, root_signer=None,
                    manifest_path=None):
    """Append a ceremony record to the transcript at ``path`` (JSONL).

    Each record carries ``prev_record_hash`` chaining to the previous
    record (``None`` for the first), so transcript tampering is evident
    via :func:`verify_ceremony_chain`. ``utc`` is injectable for
    deterministic tests.

    F78: when ``root_signer`` (the offline root key, in ceremony-time
    memory) is given, a root-signed tip manifest binding the new head
    ``(record_count, tip_record_hash)`` is (re)written to
    ``manifest_path`` (default: the conventional ``<path>.tip.json``
    sidecar). Root ceremonies (genesis, rotate-roster, tip-anchor)
    always pass it; non-root transcript entries cannot refresh the
    manifest, so verification fails closed until a root tip-anchor
    ceremony re-binds the tip (see :func:`update_tip_manifest`).
    """
    p = Path(path)
    if prev_record_hash is None and p.exists():
        prev_record_hash = _last_record_hash(p)
    body = _record_body(action, utc or _utcnow(), participants, detail,
                        prev_record_hash)
    body["record_hash"] = _record_hash(body)
    line = (json.dumps(body, sort_keys=True, separators=(",", ":"))
            + "\n").encode("utf-8")
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        with os.fdopen(fd, "ab") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        raise
    if root_signer is not None:
        mpath = (manifest_path if manifest_path is not None
                 else tip_manifest_path(p))
        write_tip_manifest(mpath, root_signer,
                           len(read_ceremonies(p)),
                           body["record_hash"],
                           tip_ceremony=action)
    return body


def _last_record_hash(path):
    records = read_ceremonies(path)
    return records[-1]["record_hash"] if records else None


def read_ceremonies(path):
    """Read the ceremony transcript (list of dicts, oldest first)."""
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _verify_chain(path):
    """Hash-chain check only. Returns (ok, error, records)."""
    records = read_ceremonies(path)
    prev = None
    for i, rec in enumerate(records):
        if rec.get("prev_record_hash") != prev:
            return False, "record %d breaks the chain" % i, records
        body = {k: v for k, v in rec.items() if k != "record_hash"}
        if _record_hash(body) != rec.get("record_hash"):
            return False, "record %d hash mismatch (tampered)" % i, records
        prev = rec["record_hash"]
    return True, None, records


def verify_ceremony_chain(path, trusted_root_pub=None):
    """Verify the transcript: hash chain plus root-signed tip binding.

    F78: after the chain check, the conventional tip-manifest sidecar
    (``<path>.tip.json``) is enforced -- see :func:`verify_transcript_tip`.
    Chain errors (broken link, tampered record) are reported first;
    then the tip binding fails closed on tail truncation, a replaced
    tip, a stale/forged/missing manifest for manifest-scheme
    transcripts. Legacy transcripts (pre-manifest records, no sidecar)
    keep chain-only verification. ``trusted_root_pub`` (optional, 32
    bytes) pins the expected root key. Returns (ok, error).
    """
    ok, err, records = _verify_chain(path)
    if not ok:
        return False, err
    return _check_tip_binding(records, Path(tip_manifest_path(path)),
                              trusted_root_pub, explicit=False)


def make_genesis_roster(store, threshold, root_seed, participants=(),
                        transcript_path=None, utc=None, manifest_path=None):
    """Genesis ceremony: first root-signed roster for the active shares.

    Runs wherever the ceremony is held (offline machine for the root
    half): needs only the store's PUBLIC metadata plus the root seed in
    memory. Returns ``(roster, ceremony_record)``.

    F78: the ceremony also writes the root-signed tip manifest for the
    transcript head (``manifest_path`` overrides the conventional
    ``<transcript>.tip.json`` sidecar).
    """
    signers = store.public_signers()
    if not signers:
        raise ValueError("no active shares to roster")
    root = root_signer_from_seed(root_seed)
    roster = make_roster(signers, threshold, root,
                         prev_roster_hash=None)  # GENESIS
    detail = {"threshold": threshold,
              "key_ids": [s.key_id for s in signers],
              "roster_hash": roster_hash(roster),
              "prev_roster_hash": GENESIS_ROSTER,
              "root_key_id": root.key_id}
    record = None
    if transcript_path is not None:
        record = record_ceremony(transcript_path, "genesis", participants,
                                 detail, utc=utc, root_signer=root,
                                 manifest_path=manifest_path)
    return roster, record


def rotate_roster(store, prev_roster, root_seed, threshold=None,
                  participants=(), transcript_path=None, utc=None,
                  manifest_path=None):
    """Share-rotation ceremony: root-sign a new roster chaining the old.

    ``threshold`` defaults to the previous roster's threshold. The new
    roster's ``prev_roster_hash`` binds it to the roster it supersedes,
    so verifiers see an unbroken, root-authorized lineage. Returns
    ``(roster, ceremony_record)``.

    F78: the ceremony also refreshes the root-signed tip manifest
    (``manifest_path`` overrides the conventional sidecar).
    """
    signers = store.public_signers()
    if not signers:
        raise ValueError("no active shares to roster")
    prev_hash = roster_hash(prev_roster)
    root = root_signer_from_seed(root_seed)
    roster = make_roster(signers,
                         prev_roster["threshold"] if threshold is None
                         else threshold,
                         root, prev_roster_hash=prev_hash)
    detail = {"threshold": roster["threshold"],
              "key_ids": [s.key_id for s in signers],
              "roster_hash": roster_hash(roster),
              "prev_roster_hash": prev_hash,
              "root_key_id": root.key_id}
    record = None
    if transcript_path is not None:
        record = record_ceremony(transcript_path, "rotate-roster",
                                 participants, detail, utc=utc,
                                 root_signer=root,
                                 manifest_path=manifest_path)
    return roster, record
