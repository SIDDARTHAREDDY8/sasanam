"""Rekor v2 (tile-backed) anchoring: the migration shape for Sasanam evidence.

Wave-207 lane B. ADAPT of the Rekor v2 migration shape (wave-205
prospecting §5): **dual-write anchors with a ``verification.source``
field on receipts, behind a flag**. Rekor v1 stays the default
anchor -- nothing about the v1 path changes.

Rekor v2 facts this module is built against (current contract,
primary source: ``sigstore/rekor-tiles`` ``CLIENTS.md`` at commit
``5e6ebbad``, read in full for wave-211 prospecting; this supersedes
the v2.0.1-era contract the wave-207 build encoded):

* v2 is GA (October 2025), tile-backed (C2SP ``tlog-tiles``) via
  Trillian-Tessera; v1 is in maintenance mode. The sigstore.dev
  public-good instance stays on v1 "for the foreseeable future"
  (Sigstore blog, 2026-06-28), so **v1 remains our default anchor**.
* v2 accepts **only ``hashedrekord``**
  (``HashedRekordLogEntryV002``). The older types ``rekord``,
  ``intoto``, ``jar``, ``alpine``, ``rpm``, ``cose`` -- and
  **``dsse``** -- are dropped. **DSSE attestations are NOT a v2 entry
  type.** The upstream-prescribed pattern: extract the DSSE
  Pre-Authentication Encoding (PAE) and signature from the envelope
  and include the PAE hash and the signature in a ``hashedrekord``
  request. Any native ``dsse`` entry kind is refused fail-closed here
  (F207, closed wave-212).
* Write API: single endpoint ``POST /api/v2/log/entries`` returning
  a protobuf ``TransparencyLogEntry``. The inclusion proof is
  **computed client-side from tiles at write time** -- there is **no
  online proof API**; reads are tile fetches per the tlog-tiles
  spec. This module's ``verify_inclusion`` recomputes the root from
  the receipt's proof: that IS the v2 verification story. Clients
  MUST parse ``spec`` by kind/version and gracefully fail on unknown
  kind/version.
* **Signed timestamps are removed from Rekor** -- they come from a
  separate TSA. This module carries a ``tsa`` field on every receipt
  that is **never folded into the transparency proof**
  (``verify_inclusion`` ignores it; it is carried evidence).
* **Search indexing is removed** -- Rekor will not answer "what did
  issuer X register". :class:`V2LocalIndex` is our own local index;
  it is the honest replacement for the removed search API.
* Sharding (``logYEAR-N.rekor.sigstore.dev``, rotated ~6 months)
  means URLs must be **discovered via TUF SigningConfig, never
  hardcoded**. This module takes a ``signing_config`` mapping
  (``log_url`` / ``log_id`` / ``tsa_url``) and has no defaults.

Layering (same contract as ``gov.rekor_anchor``):

1. A transparency-log entry is a DIGEST-EXISTENCE PROOF ONLY.
   Receipts carry ``evidentiary_grade="digest-existence-only"`` and
   ``authority_proof=False``.
2. SELF-HOSTED ONLY. The constructor refuses the pinned Sigstore
   production log values -- this module will not silently become a
   hosted-service trust dependency ($0, no external trust).
3. hashedrekord anchor signatures follow the F203-fixed shape
   (Ed25519ph-SHA512, ``sha512`` declared over ``sha512(anchor_hash)``);
   raw ``"ed25519"`` is refused fail-closed.

Hermetic by design: the v2 backend here is an in-process tile-backed
log fixture (``_V2TileLog``). No network is used anywhere in this
module -- v1 live POST already hangs from this network, so a live
v2 round-trip is an honest residual, not a hidden gap. When the
network path is proven, the seam to replace is
``HermeticRekorV2._submit_to_log`` (the transport), not the receipt
shape.

$0 spend, stdlib only, deterministic (injectable log + TSA + clock).
"""

import base64
import binascii
import hashlib
import json
import os
import time

from . import anchor_backend as _ab
from . import ed25519 as _ed
from .digest_ref import DigestRef

__all__ = [
    "SOURCE_V1",
    "SOURCE_V2",
    "SOURCE_DUAL",
    "V2_ENTRY_TYPES",
    "TILE_SIZE",
    "V2ConfigError",
    "V2AnchorError",
    "V2DownError",
    "HermeticRekorV2",
    "DualWriteAnchor",
    "V2LocalIndex",
    "TsaStub",
    "dual_write_enabled",
]

#: verification.source values -- every anchor receipt says which log
#: it came from. "rekor-v2-hermetic" (not "rekor-v2") because the v2
#: backend in this module is the hermetic fixture, stated plainly.
SOURCE_V1 = "rekor-v1"
SOURCE_V2 = "rekor-v2-hermetic"
SOURCE_DUAL = "dual-write"

#: Rekor v2 accepts ONLY these entry types. Everything else
#: (rekord, intoto, cose, dsse, ...) was removed in v2 and is refused
#: here. DSSE attestations are NOT a v2 entry type: the
#: upstream-prescribed pattern is to commit the DSSE PAE hash inside a
#: hashedrekord entry (see submit_dsse_as_hashedrekord). F207.
V2_ENTRY_TYPES = frozenset({"hashedrekord"})

#: tlog-tiles tile size. The real tlog-tiles spec uses 256-entry
#: tiles; the hermetic log uses the same framing so the receipt's
#: tile metadata is shape-honest.
TILE_SIZE = 256

#: v2 hashedrekord apiVersion (distinct from v1's 0.0.1).
_V2_HASHEDREKORD_VERSION = "0.0.2"

#: Anchor algorithms this module accepts on the hashedrekord path.
#: Raw "ed25519" is refused (F203: real hashedrekord rejects it).
_SUPPORTED_ANCHOR_ALGORITHMS = frozenset(
    {"ed25519ph-sha512", "ecdsa-p256-sha256"})

#: Sigstore production pins -- refused outright (self-hosted only).
_PROD_URL = "https://rekor.sigstore.dev"
_PROD_LOG_ID = ("c0d23d6ad406973f9559f3ba1d1ca01f84147d8ffc5b8445c"
                "2249c2cc77d6cd9d69")

_EVIDENTIARY_GRADE = "digest-existence-only"

_DSSE_ENVELOPE_FIELDS = frozenset({"payload", "payloadType",
                                   "signatures"})


# ---------------------------------------------------------------------------
# error taxonomy
# ---------------------------------------------------------------------------

class V2ConfigError(ValueError):
    """Bad v2 anchor configuration (pins, entry types, shapes)."""


class V2AnchorError(Exception):
    """The v2 anchor path failed (submit refused, stale proof, ...)."""


class V2DownError(V2AnchorError):
    """The v2 log (or TSA) was unreachable -- hermetic logs raise
    this only on programmer error; live transports raise it on I/O
    failure."""


# ---------------------------------------------------------------------------
# RFC 6962 Merkle helpers (same 0x00/0x01 domain as gov.rekor_anchor;
# deliberately NOT gov.merkle, whose domains are Sasanam-specific)
# ---------------------------------------------------------------------------

_R6962_LEAF_DOMAIN = b"\x00"
_R6962_NODE_DOMAIN = b"\x01"


def _leaf(data):
    return hashlib.sha256(_R6962_LEAF_DOMAIN + bytes(data)).digest()


def _node(left, right):
    return hashlib.sha256(
        _R6962_NODE_DOMAIN + bytes(left) + bytes(right)).digest()


def _root(leaf_hashes):
    level = [bytes(h) for h in leaf_hashes]
    for h in level:
        if len(h) != 32:
            raise ValueError("leaf hashes must be 32 bytes")
    if not level:
        raise ValueError("cannot hash an empty tree")
    while len(level) > 1:
        nxt = [_node(level[i], level[i + 1])
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def _inclusion_proof(leaf_hashes, index):
    """Sibling hashes from leaf to root for ``leaf_hashes[index]``."""
    if not 0 <= index < len(leaf_hashes):
        raise ValueError("leaf index out of range")
    proof = []
    level = [bytes(h) for h in leaf_hashes]
    idx = index
    while len(level) > 1:
        if idx % 2 == 1:
            proof.append(level[idx - 1])
        elif idx + 1 < len(level):
            proof.append(level[idx + 1])
        nxt = [_node(level[i], level[i + 1])
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
        idx //= 2
    return proof


def _verify_proof(leaf_hash, leaf_index, proof_hashes, tree_size):
    """Recompute the root a (leaf, proof) commits to.

    Models RFC 6962 leaf promotion exactly like :func:`_root` and
    :func:`_inclusion_proof`: on an odd-sized level the last leaf is
    promoted without hashing (consumes no proof hash); otherwise an
    odd index takes the proof hash as its LEFT sibling and an even
    index as its RIGHT sibling. The number of proof hashes must equal
    the number of hashed levels -- extras AND shortfalls are refused
    (no silent truncation, no silent padding).

    (F205: the previous version used index parity alone and never
    modeled promotion, so every proof for a promoted leaf -- e.g.
    leaf 2 of 3 -- failed to recompute.)
    """
    if not 0 <= leaf_index < tree_size:
        raise ValueError("leaf index out of range for tree size")
    h = bytes(leaf_hash)
    if len(h) != 32:
        raise ValueError("leaf hash must be 32 bytes")
    proof = [bytes(s) for s in proof_hashes]
    for sib in proof:
        if len(sib) != 32:
            raise ValueError("proof hash must be 32 bytes")
    it = iter(proof)
    idx = leaf_index
    n = tree_size
    while n > 1:
        if idx == n - 1 and n % 2 == 1:
            # Promoted leaf: carried up a level unhashed, exactly as
            # _root/_inclusion_proof do. Consumes no proof hash.
            pass
        elif idx % 2 == 1:
            try:
                sib = next(it)
            except StopIteration:
                raise ValueError("proof too short for the path")
            h = _node(sib, h)
        else:
            try:
                sib = next(it)
            except StopIteration:
                raise ValueError("proof too short for the path")
            h = _node(h, sib)
        idx //= 2
        n = (n + 1) // 2
    try:
        next(it)
    except StopIteration:
        return h
    raise ValueError("extra proof hashes refused")


def _canonical(obj):
    """Canonical JSON (sorted keys, compact separators). This is the
    byte form hashed into v2 leaves -- pinned and documented."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


# ---------------------------------------------------------------------------
# hermetic tile-backed v2 log fixture
# ---------------------------------------------------------------------------

class _V2TileLog:
    """In-process tile-backed transparency log (the hermetic v2).

    Leaves are appended in submission order; the tree root is plain
    RFC 6962. Tile framing follows tlog-tiles: ``TILE_SIZE``-entry
    tiles, ``tile_index = log_index // TILE_SIZE``. There is no
    network, no persistence, no witness cosigning here -- this is
    the fixture a live v2 transport would replace.
    """

    def __init__(self):
        self._leaves = []          # list of 32-byte leaf hashes
        self._entries = {}         # uuid -> entry bytes
        self._index_by_uuid = {}   # uuid -> log index

    @property
    def tree_size(self):
        return len(self._leaves)

    def root(self):
        if not self._leaves:
            raise V2DownError("cannot root an empty log")
        return _root(self._leaves)

    def append(self, entry_bytes):
        entry_bytes = bytes(entry_bytes)
        leaf = _leaf(entry_bytes)
        uuid = hashlib.sha256(leaf).hexdigest()[:32]
        if uuid in self._entries:
            # Same bytes re-submitted: idempotent, return the
            # existing index (no duplicate leaf).
            return uuid, self._index_by_uuid[uuid]
        index = len(self._leaves)
        self._leaves.append(leaf)
        self._entries[uuid] = entry_bytes
        self._index_by_uuid[uuid] = index
        return uuid, index

    def inclusion(self, uuid):
        """Tile-framed inclusion proof for ``uuid``."""
        if uuid not in self._entries:
            raise V2AnchorError("unknown entry uuid: %r" % (uuid,))
        index = self._index_by_uuid[uuid]
        proof = _inclusion_proof(self._leaves, index)
        tile_index = index // TILE_SIZE
        tile_start = tile_index * TILE_SIZE
        tile_leaves = self._leaves[tile_start:tile_start + TILE_SIZE]
        return {
            "hashes": [h.hex() for h in proof],
            "root_hash": self.root().hex(),
            "tree_size": len(self._leaves),
            "log_index": index,
            "tile": {
                "tile_size": TILE_SIZE,
                "tile_index": tile_index,
                "tile_leaf_count": len(tile_leaves),
                "partial": len(tile_leaves) < TILE_SIZE,
                "tile_root": _root(tile_leaves).hex(),
            },
        }

    def entry_bytes(self, uuid):
        try:
            return self._entries[uuid]
        except KeyError:
            raise V2AnchorError("unknown entry uuid: %r" % (uuid,))


# ---------------------------------------------------------------------------
# hermetic TSA stub (timestamps are separate from the transparency proof)
# ---------------------------------------------------------------------------

class TsaStub:
    """Hermetic RFC-3161-shaped timestamp client.

    Returns a timestamp TOKEN STRUCTURE -- it is carried evidence on
    the receipt, never an input to the transparency proof. Production
    needs a real RFC 3161 TSA; this stub is honest about being a
    stub (``hermetic: True`` on every token).
    """

    def __init__(self, tsa_url, clock=None):
        if not isinstance(tsa_url, str) or not tsa_url:
            raise V2ConfigError("tsa_url must be a non-empty string")
        self.tsa_url = tsa_url
        self._clock = clock or _utcnow

    def timestamp(self, data):
        digest = hashlib.sha256(bytes(data)).hexdigest()
        return {
            "tsa_url": self.tsa_url,
            "signed_time": self._clock(),
            "hash_alg": "sha256",
            "hashed_message": digest,
            "serial": hashlib.sha256(
                b"tsa-stub:" + bytes(data)).hexdigest()[:16],
            "hermetic": True,
        }


def _utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# the v2-shaped backend client
# ---------------------------------------------------------------------------

class HermeticRekorV2:
    """Hermetic Rekor v2 client (tile-backed, offline).

    ``signing_config`` is REQUIRED and has no defaults -- the v2
    discovery story is TUF SigningConfig, never hardcoded URLs::

        {"log_url": "https://<operator-v2-log>",
         "log_id": "<operator-pinned-log-id>",
         "tsa_url": "https://<operator-tsa>"}

    The pinned Sigstore production values are refused outright
    (self-hosted only, $0, no hosted-service trust dependency).

    ``log`` is an injectable tile log (default a fresh in-process
    one); ``tsa`` an injectable TSA client (default the hermetic
    stub); ``clock`` an injectable timestamp source.
    """

    def __init__(self, *, signing_config, log=None, tsa=None,
                 clock=None):
        if not isinstance(signing_config, dict):
            raise V2ConfigError("signing_config must be a mapping")
        url = signing_config.get("log_url")
        log_id = signing_config.get("log_id")
        tsa_url = signing_config.get("tsa_url")
        if not isinstance(url, str) or not url:
            raise V2ConfigError("signing_config needs log_url")
        if not isinstance(log_id, str) or not log_id:
            raise V2ConfigError("signing_config needs log_id")
        if not isinstance(tsa_url, str) or not tsa_url:
            raise V2ConfigError("signing_config needs tsa_url")
        norm = url.rstrip("/")
        if (norm == _PROD_URL.rstrip("/")
                or str(log_id).lower() == _PROD_LOG_ID.lower()):
            raise V2ConfigError(
                "refusing Sigstore production log pin: this module is "
                "self-hosted only (no hosted-service trust dependency)")
        self.url = norm
        self.log_id = log_id
        self._log = log if log is not None else _V2TileLog()
        self._tsa = tsa if tsa is not None else TsaStub(tsa_url)
        self._clock = clock or _utcnow

    # -- entry construction -------------------------------------------

    @staticmethod
    def _check_anchor_hash(anchor_hash):
        # Wave-199 convention: DigestRef (structural) preferred, bare
        # hex kept for the abstract contract -- converted at this
        # boundary, never implicitly.
        if isinstance(anchor_hash, DigestRef):
            return anchor_hash.hex
        if isinstance(anchor_hash, str) and len(anchor_hash) == 64:
            try:
                bytes.fromhex(anchor_hash)
            except ValueError:
                raise V2ConfigError(
                    "anchor_hash is not lowercase hex sha256")
            return anchor_hash.lower()
        raise V2ConfigError(
            "anchor_hash must be a 64-char lowercase hex sha256 or a "
            "DigestRef")

    def _submit_to_log(self, entry, leaf_bytes):
        """The transport seam. Hermetic: append ``leaf_bytes`` to the
        in-process tile log. A live v2 client would POST ``entry`` to
        ``self.url + "/api/v2/log/entries"`` here and parse the
        returned protobuf -- the receipt shape below is unchanged
        by that swap."""
        return self._log.append(bytes(leaf_bytes))

    def _receipt(self, entry_type, uuid, log_index, entry,
                 extra=None):
        entry_bytes = _canonical(entry)
        inclusion = self._log.inclusion(uuid)
        receipt = {
            "verification.source": SOURCE_V2,
            "backend": "rekor-v2-hermetic",
            "entry_type": entry_type,
            "url": self.url,
            "uuid": uuid,
            "log_index": log_index,
            "log_id": self.log_id,
            # --- the layering, in the receipt itself ---
            "evidentiary_grade": _EVIDENTIARY_GRADE,
            "authority_proof": False,
            # --- the transparency proof (client-computed tiles) ---
            "inclusion": {
                "hashes": inclusion["hashes"],
                "root_hash": inclusion["root_hash"],
                "tree_size": inclusion["tree_size"],
                "log_index": inclusion["log_index"],
            },
            "tile": inclusion["tile"],
            # --- the timestamp: separate TSA evidence, NEVER part of
            # --- the transparency proof ---
            "tsa": self._tsa.timestamp(entry_bytes),
            "submitted_at": self._clock(),
        }
        if extra:
            receipt.update(extra)
        return receipt

    # -- public submit seams ------------------------------------------

    def submit_hashedrekord(self, anchor_hash, *, signature_b64,
                            pubkey_pem,
                            algorithm="ed25519ph-sha512"):
        """Submit a digest-existence entry (v2 ``hashedrekord``).

        Same F203-fixed envelope discipline as the v1 path:
        Ed25519ph-SHA512, ``sha512`` declared over
        ``sha512(anchor_hash)``; raw ``"ed25519"`` refused
        fail-closed. Only the digest crosses the transparency
        boundary -- never record contents.
        """
        ahash = self._check_anchor_hash(anchor_hash)
        if algorithm not in _SUPPORTED_ANCHOR_ALGORITHMS:
            if algorithm == "ed25519":
                raise V2ConfigError(
                    "raw ed25519 anchor signatures are rejected by "
                    "hashedrekord (F203: Ed25519ph required); use "
                    "'ed25519ph-sha512'")
            raise V2ConfigError(
                "unsupported anchor algorithm %r (supported: %s)"
                % (algorithm, sorted(_SUPPORTED_ANCHOR_ALGORITHMS)))
        if not isinstance(signature_b64, str) or not signature_b64:
            raise V2ConfigError("signature_b64 must be non-empty")
        try:
            base64.b64decode(signature_b64, validate=True)
        except (binascii.Error, ValueError):
            raise V2ConfigError("signature_b64 is not valid base64")
        if not isinstance(pubkey_pem, str) \
                or "BEGIN PUBLIC KEY" not in pubkey_pem:
            raise V2ConfigError("pubkey_pem must be a PEM public key")
        entry = {
            "kind": "hashedrekord",
            "apiVersion": _V2_HASHEDREKORD_VERSION,
            "spec": {
                "signature": {
                    "content": signature_b64,
                    "publicKey": {
                        "content": base64.b64encode(
                            pubkey_pem.encode("ascii")).decode("ascii"),
                    },
                },
                "data": {
                    "hash": {
                        "algorithm": "sha512",
                        "value": hashlib.sha512(
                            bytes.fromhex(ahash)).hexdigest(),
                    },
                },
            },
        }
        uuid, log_index = self._submit_to_log(entry,
                                                 _canonical(entry))
        return self._receipt("hashedrekord", uuid, log_index, entry,
                             extra={"anchor_hash": ahash,
                                    "anchor_algorithm": algorithm})

    def submit_dsse_as_hashedrekord(self, envelope):
        """Commit a DSSE envelope as its PAE hash inside a hashedrekord
        entry (F207: the upstream-prescribed v2 pattern -- DSSE is NOT
        a v2 entry type).

        The envelope is strict-parsed (unknown fields refused); the
        entry's ``spec.data.hash`` is ``sha256(PAE)`` -- the PAE is the
        signed bytes that bind the payload type -- and
        ``spec.signature`` carries the envelope's own first signature
        (the log is digest-existence evidence only; signature
        verification is the auditor's job against the pinned keyset,
        not the log's). The leaf commits to the canonicalized
        hashedrekord body, exactly as on the plain hashedrekord path:
        there is exactly ONE v2 entry shape in this module.

        The receipt carries ``payload_type``, ``payload_sha256`` and
        ``pae_sha256`` so an auditor can recompute the commitment, plus
        ``dsse_routing="pae-hash-in-hashedrekord"`` naming the routing
        explicitly.
        """
        if not isinstance(envelope, dict):
            raise V2ConfigError("envelope must be a dict")
        extra = set(envelope) - _DSSE_ENVELOPE_FIELDS
        if extra:
            raise V2ConfigError(
                "unknown envelope field(s) refused: %s" % sorted(extra))
        missing = _DSSE_ENVELOPE_FIELDS - set(envelope)
        if missing:
            raise V2ConfigError(
                "envelope missing field(s): %s" % sorted(missing))
        payload_type = envelope["payloadType"]
        if not isinstance(payload_type, str) or not payload_type:
            raise V2ConfigError("payloadType must be a non-empty str")
        try:
            payload = base64.b64decode(
                envelope["payload"].encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError, ValueError,
                AttributeError) as e:
            raise V2ConfigError("envelope payload is not valid base64: "
                                "%s" % (e,))
        sigs = envelope["signatures"]
        if not isinstance(sigs, list) or not sigs:
            raise V2ConfigError("envelope needs a non-empty signatures "
                                "list")
        if not all(isinstance(s, dict) for s in sigs):
            raise V2ConfigError("envelope signatures must be objects")
        # The committed digest is the PAE hash -- the payload type rides
        # inside the signed bytes by construction.
        type_b = payload_type.encode("utf-8")
        pae = (b"DSSEv1 " + str(len(type_b)).encode("ascii") + b" "
               + type_b + b" " + str(len(payload)).encode("ascii")
               + b" " + payload)
        pae_sha256 = hashlib.sha256(pae).hexdigest()
        first = sigs[0]
        entry = {
            "kind": "hashedrekord",
            "apiVersion": _V2_HASHEDREKORD_VERSION,
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": pae_sha256,
                    },
                },
                "signature": {
                    "content": first.get("sig"),
                    "keyid": first.get("keyid"),
                },
            },
        }
        uuid, log_index = self._submit_to_log(entry,
                                              _canonical(entry))
        # The exact bytes the leaf was computed over, carried so an
        # offline auditor (e.g. the SCITT receipt check, which has no
        # live log) can recompute the leaf identically. The receipt is
        # the TS's signed statement about what it committed.
        committed_body_b64 = base64.b64encode(
            _canonical(entry)).decode("ascii")
        return self._receipt(
            "hashedrekord", uuid, log_index, entry,
            extra={"payload_type": payload_type,
                   "payload_sha256": hashlib.sha256(payload).hexdigest(),
                   "pae_sha256": pae_sha256,
                   "dsse_routing": "pae-hash-in-hashedrekord",
                   "committed_body_b64": committed_body_b64})

    def submit(self, entry_type, entry):
        """Generic submit. ``entry_type`` MUST be in
        :data:`V2_ENTRY_TYPES` -- v2 removed every other type and so
        does this seam (fail-closed). In particular a native ``dsse``
        entry kind is refused: route DSSE envelopes through
        :meth:`submit_dsse_as_hashedrekord` (F207)."""
        if entry_type not in V2_ENTRY_TYPES:
            raise V2ConfigError(
                "rekor v2 accepts only %s; %r refused"
                % (sorted(V2_ENTRY_TYPES), entry_type))
        if not isinstance(entry, dict):
            raise V2ConfigError(
                "hashedrekord entry must be a mapping of "
                "anchor_hash/signature_b64/pubkey_pem[/algorithm]")
        return self.submit_hashedrekord(
            entry.get("anchor_hash"),
            signature_b64=entry.get("signature_b64"),
            pubkey_pem=entry.get("pubkey_pem"),
            algorithm=entry.get("algorithm", "ed25519ph-sha512"))

    # -- verification ---------------------------------------------------

    def entry_bytes_for_receipt(self, receipt):
        """The exact bytes the log committed for ``receipt``."""
        if not isinstance(receipt, dict) or not receipt.get("uuid"):
            raise V2ConfigError("receipt has no uuid")
        return self._log.entry_bytes(receipt["uuid"])

    def current_root(self):
        """The log's CURRENT root -- the freshness anchor for the
        stale-proof guard."""
        return {"tree_size": self._log.tree_size,
                "root_hash": self._log.root().hex()}

    def verify_inclusion(self, receipt, entry_bytes):
        """Verify a v2 receipt against the CURRENT log state.

        Recomputes the leaf from ``entry_bytes`` and the root from
        the receipt's proof; the proof must commit to the CURRENT
        log root (stale-proof guard -- same discipline as the v1
        module). The ``tsa`` field is carried evidence and is NOT
        consulted here: timestamps are separate from the
        transparency proof. Returns True; raises
        :class:`V2AnchorError` on any failure.
        """
        if not isinstance(receipt, dict):
            raise V2AnchorError("receipt is not a mapping")
        if receipt.get("verification.source") != SOURCE_V2:
            raise V2AnchorError(
                "not a %s receipt" % (SOURCE_V2,))
        # Every v2 entry is hashedrekord-kind (F207): the committed
        # bytes are the canonicalized entry body -- DSSE submissions
        # commit sha256(PAE) as spec.data.hash.value, so the leaf rule
        # is uniform. The caller supplies the bytes (e.g. via
        # entry_bytes_for_receipt).
        leaf = _leaf(bytes(entry_bytes))
        inclusion = receipt.get("inclusion") or {}
        try:
            proof = [bytes.fromhex(h)
                     for h in inclusion.get("hashes", [])]
            claimed_root = bytes.fromhex(inclusion["root_hash"])
            tree_size = int(inclusion["tree_size"])
            leaf_index = int(inclusion["log_index"])
        except (KeyError, ValueError, TypeError) as e:
            raise V2AnchorError("malformed inclusion proof: %s" % (e,))
        try:
            recomputed = _verify_proof(leaf, leaf_index, proof,
                                       tree_size)
        except ValueError as e:
            raise V2AnchorError("proof rejected: %s" % (e,))
        if recomputed != claimed_root:
            raise V2AnchorError(
                "proof does not recompute to the receipt's root")
        current = self.current_root()
        if (current["root_hash"] != inclusion["root_hash"]
                or current["tree_size"] != tree_size):
            raise V2AnchorError(
                "stale inclusion proof: receipt root is not the "
                "current log root")
        return True


# ---------------------------------------------------------------------------
# local v2 index (v2 drops search indexing -- we keep our own)
# ---------------------------------------------------------------------------

class V2LocalIndex:
    """The search-index replacement Rekor v2 removed.

    Maps ``anchor_hash -> receipt`` locally. Optional JSONL
    persistence (``path``); without it the index is in-memory only
    (honestly documented as lossy-on-restart).
    """

    def __init__(self, path=None):
        self._by_digest = {}
        self._path = path
        if path is not None:
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        rec = json.loads(line)
                        digest = rec.get("anchor_hash")
                        receipt = rec.get("receipt")
                        if digest and isinstance(receipt, dict):
                            self._by_digest[digest] = receipt
            except FileNotFoundError:
                pass
            except (ValueError, OSError) as e:
                raise V2ConfigError(
                    "unreadable v2 index at %r: %s" % (path, e))

    def record(self, anchor_hash, receipt):
        if not isinstance(anchor_hash, str) or not anchor_hash:
            raise V2ConfigError("anchor_hash must be a non-empty str")
        if not isinstance(receipt, dict):
            raise V2ConfigError("receipt must be a mapping")
        self._by_digest[anchor_hash] = dict(receipt)
        if self._path is not None:
            line = json.dumps({"anchor_hash": anchor_hash,
                               "receipt": receipt},
                              sort_keys=True)
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def lookup(self, anchor_hash):
        """The receipt for ``anchor_hash``, or None on a miss."""
        return self._by_digest.get(anchor_hash)


# ---------------------------------------------------------------------------
# dual-write: v1 + v2 behind a flag
# ---------------------------------------------------------------------------

def dual_write_enabled(explicit=None):
    """Resolve the dual-write flag.

    ``explicit`` wins when given; otherwise ``GOV_REKOR_V2_DUAL_WRITE``
    ("1"/"true"/"yes", case-insensitive) enables it. The CLI spelling
    for wiring is ``--rekor-v2-dual-write``. Default: False -- v1-only
    behavior is unchanged unless the operator opts in.
    """
    if explicit is not None:
        return bool(explicit)
    return os.environ.get("GOV_REKOR_V2_DUAL_WRITE", "").lower() in (
        "1", "true", "yes")


class DualWriteAnchor:
    """Anchor to v1 AND the v2-shaped backend behind a flag.

    ``v1_submit`` is ``fn(anchor_hash, *, signature_b64, pubkey_pem,
    algorithm) -> v1 receipt dict`` (e.g. a bound
    ``SelfHostedRekor.submit``). ``v2_client`` is a
    :class:`HermeticRekorV2` -- required when dual-write is enabled
    (refusing to silently skip the v2 write), optional otherwise.

    With ``dual_write=False`` (the default) the v1 receipt is
    returned with ``verification.source: "rekor-v1"`` stamped on a
    copy -- the v1 path's behavior is otherwise unchanged, and no
    v2 fields appear. With dual-write enabled the combined receipt
    carries both entries, each with its own ``verification.source``::

        {"verification.source": "dual-write",
         "entries": {"rekor-v1": {...}, "rekor-v2-hermetic": {...}},
         "anchored_at": ...}
    """

    def __init__(self, *, v1_submit, v2_client=None, dual_write=None,
                 clock=None):
        if not callable(v1_submit):
            raise V2ConfigError("v1_submit must be callable")
        self._v1_submit = v1_submit
        self._v2 = v2_client
        self._dual = dual_write_enabled(dual_write)
        if self._dual and v2_client is None:
            raise V2ConfigError(
                "dual-write enabled but no v2_client: refusing to "
                "silently skip the v2 write")
        self._clock = clock or _utcnow

    @property
    def dual_write(self):
        return self._dual

    @staticmethod
    def _stamp_v1(receipt):
        stamped = dict(receipt)
        stamped["verification.source"] = SOURCE_V1
        return stamped

    def anchor(self, anchor_hash, *, signature_b64, pubkey_pem,
               algorithm="ed25519ph-sha512", dsse_envelope=None):
        v1_receipt = self._stamp_v1(self._v1_submit(
            anchor_hash, signature_b64=signature_b64,
            pubkey_pem=pubkey_pem, algorithm=algorithm))
        if not self._dual:
            return v1_receipt
        if dsse_envelope is not None:
            # F207: DSSE is not a v2 entry type -- the envelope's PAE
            # hash is committed inside a hashedrekord entry.
            v2_receipt = self._v2.submit_dsse_as_hashedrekord(
                dsse_envelope)
        else:
            v2_receipt = self._v2.submit_hashedrekord(
                anchor_hash, signature_b64=signature_b64,
                pubkey_pem=pubkey_pem, algorithm=algorithm)
        return {
            "verification.source": SOURCE_DUAL,
            "entries": {
                SOURCE_V1: v1_receipt,
                SOURCE_V2: v2_receipt,
            },
            "anchored_at": self._clock(),
        }
