"""Self-hosted Rekor v1 transparency anchoring for Sasanam evidence.

Wave-194 lane D. Anchors Sasanam artifacts -- signed checkpoint STHs
(``gov.log.write_checkpoint`` format-2) and sealed evidence-bundle
manifests -- in an OPERATOR-RUN Rekor v1 log (``hashedrekord:0.0.1``
entries, stdlib ``urllib`` only, no new dependencies).

Layering contract (from the wave-193 spike, ENFORCED in code, not just
documented):

1. A Rekor entry is a DIGEST-EXISTENCE PROOF ONLY. Sasanam's own
   checkpoint/witness signatures stay the authoritative layer.
   :func:`present_as_authority` always raises
   :class:`RekorLayeringError`; receipts carry
   ``evidentiary_grade="digest-existence-only"`` and
   ``authority_proof=False``.
2. Auditors verify via verify-semantics or leaf recomputation -- NEVER
   raw GET-entry inclusion proofs. The wave-193 spike observed Rekor
   returning STALE inclusion proofs (``rootHash`` != current checkpoint
   ``rootHash``) while ``rekor-cli verify`` succeeded.
   :func:`verify_inclusion` fetches a fresh checkpoint and enforces the
   stale-proof guard: the proof's root must equal the CURRENT log root.
3. SELF-HOSTED ONLY. The operator pins their own ``log_id`` + server
   URL. Constructor refuses the pinned Sigstore production values --
   this module will not silently become a hosted-service trust
   dependency ($0, no external trust).
4. Anchor signature: ``hashedrekord:0.0.1`` entries carry an
   operator-supplied signature over the artifact digest. F203 tracks
   the live-proven incompatibility of raw Ed25519 in
   ``gov.anchor_backend.RekorBackend.submit`` (real Rekor v1.5.4
   rejects it: ``unsupported hash algorithm: "SHA-256" not in
   [SHA-512]`` -- hashedrekord only accepts Ed25519ph). This module
   therefore takes the anchor signature as operator-supplied bytes
   (the anchor-key ceremony lives in ``docs/REKOR_RUNBOOK.md``) and
   REFUSES the known-incompatible ``"ed25519"`` (raw) algorithm label
   fail-closed.

What this module does NOT do (honest boundaries):

* It does not replace Sasanam's checkpoint/witness authority model.
  The wave-183 witness design (independent Merkle consistency +
  N-of-M Ed25519 cosigning) is what detects operator equivocation;
  :class:`RekorWitness` productizes that ritual for Rekor checkpoints.
* The Rekor checkpoint's operator ECDSA signature is CARRIED, not
  cryptographically verified -- there is no ECDSA in this tree (same
  boundary as wave-72's SET handling). The verified core is:
  proof-internal RFC 6962 recomputation + fresh-checkpoint root
  agreement (stale-proof guard) + pinned log_id.
* No HA, no KMS, no TLS, no auth in the dev path. Production
  requirements are documented honestly in ``docs/REKOR_RUNBOOK.md``.

$0, stdlib only, deterministic (injectable transport + clock).
"""

import base64
import binascii
import calendar
import hashlib
import json
import time
import urllib.request
import urllib.error

from . import anchor_backend as _ab
from . import ed25519 as _ed
from . import evidence_bundle as _eb

# ---------------------------------------------------------------------------
# RFC 6962 Merkle tree (the transparency log's hash domain)
#
# NOTE: deliberately NOT gov.merkle. gov.merkle uses Sasanam-specific
# domains (gov-merkle-leaf/v1, gov-merkle-node/v1) for the internal
# audit log; Rekor/Trillian speak plain RFC 6962 (0x00 / 0x01).
# Mixing the domains would make the witness recompute a wrong root
# and refuse every honest checkpoint (fail-closed but useless).
# ---------------------------------------------------------------------------

_R6962_LEAF_DOMAIN = b"\x00"
_R6962_NODE_DOMAIN = b"\x01"


def _r6962_leaf(data):
    """RFC 6962 leaf hash: SHA256(0x00 || data)."""
    return hashlib.sha256(_R6962_LEAF_DOMAIN + bytes(data)).digest()


def _r6962_node(left, right):
    """RFC 6962 node hash: SHA256(0x01 || left || right)."""
    return hashlib.sha256(
        _R6962_NODE_DOMAIN + bytes(left) + bytes(right)).digest()


def _r6962_root(leaf_hashes):
    """RFC 6962 Merkle tree hash over 32-byte leaf hashes.

    Pairwise fold with odd-carry-up, which equals the RFC's recursive
    split on the largest power of two < n.
    """
    level = [bytes(l) for l in leaf_hashes]
    for l in level:
        if len(l) != 32:
            raise ValueError("leaf hashes must be 32 bytes")
    if not level:
        raise ValueError("cannot hash an empty tree")
    while len(level) > 1:
        nxt = [_r6962_node(level[i], level[i + 1])
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def _r6962_inclusion_proof(leaf_hashes, index):
    """Inclusion proof in Rekor's ``hashes`` order (leaf-level first).

    Cross-checked against ``gov.anchor_backend._rfc6962_root``: feeding
    this proof back recomputes the same root.
    """
    n = len(leaf_hashes)
    if not (0 <= index < n):
        raise ValueError("index out of range")
    if n == 1:
        return []
    # RFC 6962 split: largest power of two < n.
    k = 1
    while 2 * k < n:
        k *= 2
    if index < k:
        sub = _r6962_inclusion_proof(leaf_hashes[:k], index)
        return sub + [_r6962_root(leaf_hashes[k:])]
    sub = _r6962_inclusion_proof(leaf_hashes[k:], index - k)
    return sub + [_r6962_root(leaf_hashes[:k])]


def _r6962_verify_proof(leaf_data, leaf_index, proof_hashes, tree_size):
    """Recompute an RFC 6962 root from a single inclusion proof.

    ``leaf_data``: raw leaf bytes (not pre-hashed). ``proof_hashes``:
    sibling hashes, leaf level first (Rekor's ``hashes`` order); each
    may be 32 bytes or a 64-char hex string. Returns the 32-byte root.
    Raises ValueError on malformed input. Local to this module (no
    cross-module private reach); cross-checked against
    ``gov.anchor_backend._rfc6962_root`` in the unit tests.
    """
    leaf = bytes(leaf_data)
    index = int(leaf_index)
    size = int(tree_size)
    proof = []
    for p in proof_hashes:
        if isinstance(p, str):
            try:
                p = bytes.fromhex(p)
            except ValueError:
                raise ValueError("proof element is not hex")
        p = bytes(p)
        if len(p) != 32:
            raise ValueError("bad proof element length")
        proof.append(p)
    if not (0 <= index < size):
        raise ValueError("bad index/size")
    leaf_node = _r6962_leaf(leaf)

    def rec(i, n, end):
        # Root of the size-n subtree containing leaf i. The proof is
        # leaf-level-first (Rekor's ``hashes`` order), so the sibling
        # at this (top) split is the LAST element of ``proof[:end]``;
        # the recursion consumes the proof top-down and combines on
        # the way back up.
        if n == 1:
            return leaf_node, end
        k = 1
        while 2 * k < n:
            k *= 2
        if end <= 0:
            raise ValueError("proof too short")
        sib = proof[end - 1]
        if i < k:
            left, nxt = rec(i, k, end - 1)
            return _r6962_node(left, sib), nxt
        right, nxt = rec(i - k, n - k, end - 1)
        return _r6962_node(sib, right), nxt

    root, remaining = rec(index, size, len(proof))
    if remaining != 0:
        raise ValueError("proof length mismatch")
    return root

# ---------------------------------------------------------------------------
# Layering
# ---------------------------------------------------------------------------

EVIDENTIARY_GRADE = "digest-existence-only"

RECEIPT_BACKEND = "rekor-v1-selfhosted"

# Algorithm labels this module will put into a hashedrekord envelope.
# Raw "ed25519" is deliberately ABSENT: real Rekor v1.5.4 rejects it
# (F203 -- hashedrekord only accepts Ed25519ph with SHA-512 for
# Ed25519 keys). The operator supplies the signature bytes; this
# module only labels and transports them.
SUPPORTED_ANCHOR_ALGORITHMS = frozenset({
    "ecdsa-p256-sha256",   # spike-proven live against Rekor v1.5.4
    "ed25519ph-sha512",    # hashedrekord's Ed25519 shape (prehashed)
})

_WITNESS_SIG_DOMAIN = b"sasanam-rekor-witness/v1\x00"
_WITNESS_BODY_DOMAIN = b"sasanam-rekor-witness-body/v1\x00"

# Sigstore production pins, imported for REFUSAL (never defaulted to).
_PROD_URL = _ab.REKOR_URL
_PROD_LOG_ID = _ab.REKOR_LOG_ID


def _normalize_url(url):
    """Canonicalize a URL for pin comparison.

    Lowercases scheme+host, drops default ports (:443/:80), strips
    trailing slashes -- so case-variants (``REKOR.SIGSTORE.DEV``) or
    port-qualified forms (``:443``) of the production pin still match.
    """
    u = (url or "").strip().lower().rstrip("/")
    if "://" in u:
        scheme, rest = u.split("://", 1)
        if scheme == "https" and rest.endswith(":443"):
            rest = rest[:-4]
        elif scheme == "http" and rest.endswith(":80"):
            rest = rest[:-3]
        u = scheme + "://" + rest
    return u


class RekorLayeringError(Exception):
    """A Rekor entry was presented as something it is not.

    Raised whenever code attempts to use a transparency-log receipt as
    an authority proof. The receipt is a digest-existence proof; the
    authority stays with Sasanam's own signed checkpoints and witness
    cosignatures.
    """


class RekorConfigError(ValueError):
    """Bad self-hosted Rekor configuration (programmer/operator error)."""


class RekorDownError(Exception):
    """The self-hosted Rekor server is unreachable or misbehaving."""


def _check_anchor_hash(anchor_hash):
    if not isinstance(anchor_hash, str):
        raise RekorConfigError("anchor_hash must be a hex string")
    try:
        raw = bytes.fromhex(anchor_hash)
    except ValueError:
        raise RekorConfigError("anchor_hash is not hex")
    if len(raw) != 32:
        raise RekorConfigError("anchor_hash must be 32 bytes (sha256 hex)")
    return anchor_hash.lower()


def _utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _clock_epoch(clock):
    """Epoch seconds from the injectable clock (fail-closed).

    The clock's native shape is an ISO-8601 UTC string (as used for
    ``submitted_at``); epoch numbers are also accepted so tests can
    inject skew directly.
    """
    v = clock()
    if isinstance(v, bool):
        raise RekorConfigError("clock returned an unparsable value")
    if isinstance(v, (int, float)):
        return int(v)
    try:
        return calendar.timegm(
            time.strptime(str(v), "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError, OverflowError):
        raise RekorConfigError("clock returned an unparsable value")


# ---------------------------------------------------------------------------
# Self-hosted Rekor client
# ---------------------------------------------------------------------------

class SelfHostedRekor:
    """Anchor client for an operator-run Rekor v1 log.

    ``url`` and ``log_id`` are REQUIRED operator pins -- there are no
    defaults, and the pinned Sigstore production values are refused
    outright (``RekorConfigError``): this module must never silently
    become a hosted-service trust dependency.

    ``transport`` is an injectable
    ``fn({"method","url","headers","body"}) -> {"status","body"}``;
    the default is real ``urllib`` HTTP. The deterministic suite
    injects a fake; nothing here touches the network otherwise.
    """

    def __init__(self, url, log_id, *, transport=None, clock=None):
        if not isinstance(url, str) or not url:
            raise RekorConfigError("url must be a non-empty string")
        if not isinstance(log_id, str) or not log_id:
            raise RekorConfigError("log_id must be a non-empty string "
                                   "(operator-pinned; no default)")
        norm = url.rstrip("/")
        if (_normalize_url(norm) == _normalize_url(_PROD_URL)
                or log_id.lower() == _PROD_LOG_ID.lower()):
            raise RekorConfigError(
                "refusing Sigstore production log pin: this module is "
                "self-hosted only (no hosted-service trust dependency)")
        self.url = norm
        self.log_id = log_id
        self._transport = transport or self._urllib_transport
        self._clock = clock or _utcnow

    # -- transport ------------------------------------------------------
    @staticmethod
    def _urllib_transport(request):
        data = request["body"].encode("utf-8")
        req = urllib.request.Request(
            request["url"], data=data, headers=request["headers"],
            method=request.get("method", "POST"))
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return {"status": resp.status,
                        "body": resp.read().decode("utf-8")}
        except urllib.error.HTTPError as e:
            try:
                detail = e.read().decode("utf-8", "replace")[:500]
            except Exception:
                detail = ""
            raise RekorDownError(
                "rekor HTTP %s: %s" % (e.code, detail))
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise RekorDownError("rekor unreachable: %s" % (e,))

    def _get(self, path):
        return self._transport({
            "method": "GET",
            "url": self.url + path,
            "headers": {"Accept": "application/json"},
            "body": "",
        })

    # -- submit ----------------------------------------------------------
    def submit(self, anchor_hash, *, signature_b64, pubkey_pem,
               algorithm="ecdsa-p256-sha256"):
        """Submit a digest-existence entry. Returns the receipt dict.

        ``anchor_hash``: sha256 hex of the canonical artifact bytes.
        ``signature_b64`` / ``pubkey_pem``: operator-supplied anchor
        signature over the 32-byte digest and its public key (the
        anchor-key ceremony is documented in docs/REKOR_RUNBOOK.md).
        The signature is a RAW sign over the digest bytes -- Rekor
        verifies it with the digest pre-computed, so ``openssl dgst
        -sha256 -sign`` over the digest DOUBLE-hashes and is rejected;
        use ``openssl pkeyutl -sign`` (or the KMS raw-sign equivalent).
        ``algorithm`` must be in ``SUPPORTED_ANCHOR_ALGORITHMS``;
        raw ``"ed25519"`` is refused fail-closed (F203).
        """
        ahash = _check_anchor_hash(anchor_hash)
        if algorithm not in SUPPORTED_ANCHOR_ALGORITHMS:
            if algorithm == "ed25519":
                raise RekorConfigError(
                    "raw ed25519 anchor signatures are rejected by real "
                    "Rekor v1 (F203: hashedrekord requires Ed25519ph); "
                    "use 'ed25519ph-sha512' or 'ecdsa-p256-sha256'")
            raise RekorConfigError(
                "unsupported anchor algorithm %r (supported: %s)"
                % (algorithm, sorted(SUPPORTED_ANCHOR_ALGORITHMS)))
        if not isinstance(signature_b64, str) or not signature_b64:
            raise RekorConfigError("signature_b64 must be non-empty")
        if not isinstance(pubkey_pem, str) \
                or "BEGIN PUBLIC KEY" not in pubkey_pem:
            raise RekorConfigError("pubkey_pem must be a PEM public key")
        try:
            base64.b64decode(signature_b64, validate=True)
        except (binascii.Error, ValueError):
            raise RekorConfigError("signature_b64 is not valid base64")
        # Privacy pin, structural: the ONLY artifact-derived input is the
        # digest. Record contents never cross the transparency boundary.
        proposed = {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "content": signature_b64,
                    "publicKey": {
                        "content": base64.b64encode(
                            pubkey_pem.encode("ascii")).decode("ascii"),
                    },
                },
                "data": {
                    "hash": {"algorithm": "sha256", "value": ahash},
                },
            },
        }
        resp = self._transport({
            "method": "POST",
            "url": self.url + "/api/v1/log/entries",
            "headers": {"Content-Type": "application/json",
                        "Accept": "application/json"},
            "body": json.dumps(proposed, separators=(",", ":")),
        })
        if resp["status"] not in (200, 201):
            raise RekorDownError(
                "rekor rejected the entry: HTTP %s" % (resp["status"],))
        try:
            entries = json.loads(resp["body"])
            uuid, entry = next(iter(entries.items()))
        except (ValueError, StopIteration) as e:
            raise RekorDownError("unparseable rekor response: %s" % (e,))
        return self._receipt_from_entry(uuid, entry, ahash, algorithm)

    def _receipt_from_entry(self, uuid, entry, ahash, algorithm):
        verification = entry.get("verification", {})
        proof = verification.get("inclusionProof", {})
        return {
            "backend": RECEIPT_BACKEND,
            "url": self.url,
            "uuid": uuid,
            "log_index": entry.get("logIndex"),
            "log_id": entry.get("logID"),
            # --- the layering, in the receipt itself ---
            "evidentiary_grade": EVIDENTIARY_GRADE,
            "authority_proof": False,
            # --- the anchor ---
            "anchor_hash": ahash,
            "anchor_algorithm": algorithm,
            "integrated_time": entry.get("integratedTime"),
            "inclusion_proof": {
                "hashes": list(proof.get("hashes", [])),
                "root_hash": proof.get("rootHash"),
                "tree_size": proof.get("treeSize"),
                "log_index": proof.get("logIndex"),
            },
            "body": verification.get("body", entry.get("body", "")),
            "signed_entry_timestamp":
                verification.get("signedEntryTimestamp", ""),
            "submitted_at": self._clock(),
        }

    # -- checkpoint ------------------------------------------------------
    def fetch_checkpoint(self):
        """Fetch the log's current checkpoint (tree head).

        Returns ``{"tree_id","tree_size","root_hash","signed_tree_head"}``
        or raises :class:`RekorDownError`.
        """
        resp = self._get("/api/v1/log")
        if resp["status"] != 200:
            raise RekorDownError(
                "rekor log info HTTP %s" % (resp["status"],))
        try:
            info = json.loads(resp["body"])
            return {
                "tree_id": str(info["treeID"]),
                "tree_size": int(info["treeSize"]),
                "root_hash": str(info["rootHash"]).lower(),
                "signed_tree_head": str(info.get("signedTreeHead", "")),
            }
        except (ValueError, KeyError, TypeError) as e:
            raise RekorDownError("unparseable log info: %s" % (e,))

    def get_entry(self, uuid):
        """Re-fetch one entry by UUID (fresh inclusion proof).

        Auditor flow for a STALE receipt: re-GET the entry, rebuild
        the receipt's ``inclusion_proof`` from the fresh entry, then
        :func:`verify_inclusion`. Returns the raw entry dict.
        """
        if not isinstance(uuid, str) or not uuid:
            raise RekorConfigError("uuid must be a non-empty string")
        resp = self._get("/api/v1/log/entries/" + uuid)
        if resp["status"] != 200:
            raise RekorDownError(
                "rekor entry fetch HTTP %s" % (resp["status"],))
        try:
            entries = json.loads(resp["body"])
            _uuid, entry = next(iter(entries.items()))
        except (ValueError, StopIteration) as e:
            raise RekorDownError("unparseable entry response: %s" % (e,))
        return entry

    @staticmethod
    def proof_of(entry):
        """Extract the ``inclusion_proof`` receipt-shape from an entry."""
        proof = entry.get("verification", {}).get("inclusionProof", {})
        return {
            "hashes": list(proof.get("hashes", [])),
            "root_hash": proof.get("rootHash"),
            "tree_size": proof.get("treeSize"),
            "log_index": proof.get("logIndex"),
        }


# ---------------------------------------------------------------------------
# Layering enforcement
# ---------------------------------------------------------------------------

def present_as_authority(receipt):
    """ALWAYS raises. A Rekor entry is not an authority proof.

    This function exists so the refusal is IN CODE, not just in prose:
    any caller that tries to present a transparency-log receipt as an
    authority proof gets a loud, typed failure instead of a silent
    misgrading. The authority stays with Sasanam's own signed
    checkpoints and witness cosignatures.
    """
    _ = receipt
    raise RekorLayeringError(
        "a Rekor entry is a digest-existence proof "
        "(evidentiary_grade=%r), not an authority proof; authority "
        "stays with Sasanam's signed checkpoints and witness "
        "cosignatures" % EVIDENTIARY_GRADE)


def grade_receipt(receipt):
    """The evidentiary grade of a Rekor receipt. Never "authority"."""
    if not isinstance(receipt, dict):
        return "malformed"
    if receipt.get("backend") != RECEIPT_BACKEND:
        return "not-a-rekor-receipt"
    return EVIDENTIARY_GRADE


# ---------------------------------------------------------------------------
# Auditor verification: verify-semantics, never raw GET proofs
# ---------------------------------------------------------------------------

def verify_inclusion(receipt, anchor_hash, *, client):
    """Verify a receipt's inclusion claim. Returns (ok, reason).

    Never raises on malformed input (fail-closed for auditors).

    Verification path (the stale-proof guard is step 3):

    1. Receipt shape: backend label, anchor_hash match, pinned log_id.
    2. Entry body: ``data.hash.value`` == anchor_hash.
    3. STALE-PROOF GUARD: fetch the CURRENT checkpoint; require
       ``proof.root_hash == checkpoint.root_hash``,
       ``proof.tree_size <= checkpoint.tree_size``,
       ``0 <= proof.log_index < proof.tree_size``. A proof that is
       internally consistent but stale (the wave-193 spike's live
       observation) is REFUSED here.
    4. Recompute the RFC 6962 root from the leaf (canonical entry
       body) + proof hashes; require == proof.root_hash.
    5. ``integrated_time`` sane (int, > 0, not in the future).

    Honest residual (documented, not hidden): the checkpoint's
    operator ECDSA signature is CARRIED, not cryptographically
    verified -- no ECDSA in this tree (same boundary as wave-72's
    SET handling). Operator equivocation is detected by the witness
    layer (:class:`RekorWitness`), not here.
    """
    try:
        if not isinstance(receipt, dict):
            return False, "receipt is not an object"
        if receipt.get("backend") != RECEIPT_BACKEND:
            return False, "not a %s receipt" % RECEIPT_BACKEND
        if receipt.get("evidentiary_grade") != EVIDENTIARY_GRADE:
            return False, "receipt lacks the digest-existence grade"
        if receipt.get("authority_proof"):
            return False, "receipt claims authority (layering violation)"
        ahash = _check_anchor_hash(anchor_hash)
        if receipt.get("anchor_hash") != ahash:
            return False, "receipt is for a different anchor"
        if receipt.get("log_id") != client.log_id:
            return False, "receipt is from a different transparency log"
        # Entry body binds the digest.
        body = base64.b64decode(receipt["body"])
        entry = json.loads(body.decode("utf-8"))
        try:
            value = entry["spec"]["data"]["hash"]["value"]
        except (KeyError, TypeError):
            return False, "entry body has no data.hash.value"
        if value != ahash:
            return False, "entry body hash != anchor_hash"
        # Fresh checkpoint: the stale-proof guard.
        try:
            checkpoint = client.fetch_checkpoint()
        except RekorDownError as e:
            return False, "cannot fetch log checkpoint: %s" % (e,)
        proof = receipt["inclusion_proof"]
        if proof.get("root_hash") != checkpoint["root_hash"]:
            return False, (
                "STALE inclusion proof: proof root != current log root "
                "(never trust raw GET-entry proofs)")
        tree_size = proof.get("tree_size")
        log_index = proof.get("log_index")
        if not isinstance(tree_size, int) or tree_size <= 0:
            return False, "proof tree_size malformed"
        if tree_size > checkpoint["tree_size"]:
            return False, "proof tree_size exceeds current log size"
        if not isinstance(log_index, int) \
                or not (0 <= log_index < tree_size):
            return False, "proof log_index out of range"
        # RFC 6962 recomputation from the leaf (local verifier; the
        # injectable clock keeps skew tests deterministic).
        root = _r6962_verify_proof(
            body, log_index, proof["hashes"], tree_size)
        if root.hex() != proof["root_hash"]:
            return False, "inclusion proof does not verify"
        it = receipt["integrated_time"]
        if not isinstance(it, int) or it <= 0:
            return False, "integrated_time malformed"
        if it > _clock_epoch(client._clock) + 300:
            return False, "integrated_time is in the future"
        if not receipt.get("uuid") \
                or not receipt.get("signed_entry_timestamp"):
            return False, "receipt missing uuid/SET"
        return True, None
    except (KeyError, TypeError, ValueError,
            binascii.Error) as e:
        return False, "malformed receipt: %s" % (e,)


# ---------------------------------------------------------------------------
# Witness: independent Merkle consistency + N-of-M Ed25519 cosigning
# ---------------------------------------------------------------------------

def _witness_body(checkpoint):
    """Canonical bytes a witness cosigns: the checkpoint claim.

    ``signed_tree_head`` is EXCLUDED (it carries the operator's own
    signature, which is not part of the witnessed claim -- the claim
    is (tree_id, tree_size, root_hash)); cosigning the operator's
    signature would bind the witness to the operator's key rather
    than to the tree state.
    """
    claim = {
        "tree_id": checkpoint["tree_id"],
        "tree_size": checkpoint["tree_size"],
        "root_hash": checkpoint["root_hash"],
    }
    return _WITNESS_BODY_DOMAIN + _eb.canonical(claim)


def _witness_id_for_pubkey(pubkey):
    return hashlib.sha256(pubkey).hexdigest()[:16]


class RekorWitness:
    """Third-party witness for Rekor checkpoints (wave-183 ritual).

    The witness never holds the log. Before cosigning it RECOMPUTES
    the Merkle root from the supplied leaves (canonical entry bodies)
    and requires equality with the checkpoint's root. A checkpoint at
    an already-seen size with a DIFFERENT root is equivocation: loud
    refusal, recorded in ``equivocations_seen``.

    Signature validity of the checkpoint (the operator's ECDSA key)
    is explicitly NOT sufficient -- the wave-193 spike proved an
    attacker holding the real operator key can forge a same-size
    checkpoint with a different root whose signature VERIFIES. Only
    independent Merkle consistency detects it.
    """

    def __init__(self, seed):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise RekorConfigError("witness seed must be 32 bytes")
        self._seed = bytes(seed)
        self._pubkey = _ed.publickey(self._seed)
        self.witness_id = _witness_id_for_pubkey(self._pubkey)
        self.equivocations_seen = []

    @property
    def pubkey_hex(self):
        return self._pubkey.hex()

    def cosign_checkpoint(self, checkpoint, leaves):
        """Witness one checkpoint. Returns (cosig|None, reason|None).

        ``checkpoint``: ``{"tree_id","tree_size","root_hash",...}``.
        ``leaves``: canonical entry bodies (bytes) for indices
        ``0..tree_size-1``. On root mismatch: (None, "EQUIVOCATION:
        ...") and the attempt is recorded. Never raises on malformed
        input.
        """
        try:
            tree_id = str(checkpoint["tree_id"])
            tree_size = int(checkpoint["tree_size"])
            root_hash = str(checkpoint["root_hash"]).lower()
            leaf_list = list(leaves)
            if tree_size <= 0:
                return None, "refusing to witness an empty tree"
            if len(leaf_list) != tree_size:
                return None, (
                    "leaf count %d != checkpoint tree_size %d; "
                    "witness never advances blind" % (
                        len(leaf_list), tree_size))
            leaf_hashes = [_r6962_leaf(bytes(l)) for l in leaf_list]
            recomputed = _r6962_root(leaf_hashes).hex()
            if recomputed != root_hash:
                record = {
                    "tree_id": tree_id,
                    "tree_size": tree_size,
                    "claimed_root": root_hash,
                    "recomputed_root": recomputed,
                }
                self.equivocations_seen.append(record)
                return None, (
                    "EQUIVOCATION: checkpoint root does not match the "
                    "leaves (claimed %s, recomputed %s) -- signature "
                    "validity is not honesty" % (root_hash, recomputed))
            digest = hashlib.sha256(_witness_body({
                "tree_id": tree_id,
                "tree_size": tree_size,
                "root_hash": root_hash,
            })).hexdigest()
            sig = _ed.sign(
                self._seed, _WITNESS_SIG_DOMAIN + bytes.fromhex(digest))
            return {
                "witness_id": self.witness_id,
                "checkpoint_digest": digest,
                "sig": sig.hex(),
            }, None
        except (KeyError, TypeError, ValueError) as e:
            return None, "malformed checkpoint/leaves: %s" % (e,)


def verify_witness_cosignatures(checkpoint, cosigs, registry, quorum):
    """Auditor-side: verify N-of-M witness cosignatures.

    ``registry``: ``{witness_id: pubkey_hex}`` distributed out-of-band.
    ``quorum``: minimum distinct registered witnesses. Returns
    ``(ok, reason)``; all failure modes fail closed, never raise.
    """
    try:
        digest = hashlib.sha256(_witness_body({
            "tree_id": str(checkpoint["tree_id"]),
            "tree_size": int(checkpoint["tree_size"]),
            "root_hash": str(checkpoint["root_hash"]).lower(),
        })).hexdigest()
        if not isinstance(quorum, int) or quorum <= 0:
            return False, "quorum malformed"
        seen = set()
        for c in cosigs or []:
            try:
                wid = c["witness_id"]
                if wid in seen:
                    continue
                pubkey = bytes.fromhex(registry[wid])
                if len(pubkey) != 32:
                    continue
                if _witness_id_for_pubkey(pubkey) != wid:
                    continue  # registry binding broken; not this witness
                if c.get("checkpoint_digest") != digest:
                    continue  # cosig is for a different checkpoint
                sig = bytes.fromhex(c["sig"])
                if not _ed.verify(
                        pubkey,
                        _WITNESS_SIG_DOMAIN + bytes.fromhex(digest), sig):
                    continue
                seen.add(wid)
            except (KeyError, TypeError, ValueError):
                continue
        if len(seen) >= quorum:
            return True, None
        return False, "only %d/%d witness cosignatures valid" % (
            len(seen), quorum)
    except (KeyError, TypeError, ValueError) as e:
        return False, "malformed input: %s" % (e,)


# ---------------------------------------------------------------------------
# Offline receipt bundle: the server is availability, not truth
# ---------------------------------------------------------------------------

def build_offline_bundle(*, anchor_hash, receipt, checkpoint, leaves,
                         witness_cosigs=()):
    """Build the regulator-visible offline proof bundle.

    Everything an auditor needs with the log server DOWN:
    the artifact digest, the Rekor entry (body + inclusion proof),
    the checkpoint, the leaves needed to recompute the root, the
    pinned log_id, and any witness cosignatures. ``leaves`` are the
    canonical entry bodies for ``0..checkpoint.tree_size-1``.
    """
    ahash = _check_anchor_hash(anchor_hash)
    return {
        "bundle_version": "sasanam-rekor-offline/v1",
        "evidentiary_grade": EVIDENTIARY_GRADE,
        "anchor_hash": ahash,
        "log_id": receipt.get("log_id"),
        "receipt": receipt,
        "checkpoint": checkpoint,
        "leaves_b64": [base64.b64encode(bytes(l)).decode("ascii")
                       for l in leaves],
        "witness_cosigs": list(witness_cosigs),
    }


def verify_offline_bundle(bundle, *, witness_registry=None, quorum=1):
    """Verify an offline bundle with zero server contact.

    Recomputes the Merkle root from the bundled leaves (never trusts
    a stored proof), checks the checkpoint root agrees, verifies the
    entry's inclusion, and checks witness quorum. Witness quorum is
    REQUIRED (``quorum >= 1`` and a non-empty registry): this is the
    regulator-facing path, and a quorum-less acceptance would let a
    forged bundle pass on recomputation alone. Returns ``(ok,
    reason)``; never raises on malformed input.
    """
    try:
        if not isinstance(bundle, dict):
            return False, "bundle is not an object"
        if not isinstance(quorum, int) or quorum < 1:
            return False, "witness quorum is required (>= 1)"
        if not witness_registry:
            return False, "witness registry is required"
        if bundle.get("bundle_version") != "sasanam-rekor-offline/v1":
            return False, "unknown bundle version"
        if bundle.get("evidentiary_grade") != EVIDENTIARY_GRADE:
            return False, "bundle lacks the digest-existence grade"
        receipt = bundle["receipt"]
        checkpoint = bundle["checkpoint"]
        ahash = _check_anchor_hash(bundle["anchor_hash"])
        if receipt.get("anchor_hash") != ahash:
            return False, "receipt is for a different anchor"
        if receipt.get("log_id") != bundle.get("log_id"):
            return False, "bundle log_id mismatch"
        # Note: checkpoint.tree_id (the trillian tree id) and log_id
        # (the rekor logical log id) are different namespaces; no
        # cross-check between them here by design.
        leaves = [base64.b64decode(l) for l in bundle["leaves_b64"]]
        tree_size = int(checkpoint["tree_size"])
        if len(leaves) != tree_size:
            return False, "bundled leaf count != checkpoint tree_size"
        leaf_hashes = [_r6962_leaf(l) for l in leaves]
        recomputed = _r6962_root(leaf_hashes).hex()
        if recomputed != str(checkpoint["root_hash"]).lower():
            return False, (
                "bundled leaves do not reproduce the checkpoint root")
        # Entry inclusion from the bundled leaves.
        body = base64.b64decode(receipt["body"])
        entry = json.loads(body.decode("utf-8"))
        try:
            value = entry["spec"]["data"]["hash"]["value"]
        except (KeyError, TypeError):
            return False, "entry body has no data.hash.value"
        if value != ahash:
            return False, "entry body hash != anchor_hash"
        try:
            idx = int(entry.get("logIndex",
                                receipt["inclusion_proof"]["log_index"]))
        except (KeyError, TypeError, ValueError):
            return False, "entry log index unknown"
        proof = _r6962_inclusion_proof(leaf_hashes, idx)
        if _r6962_verify_proof(
                body, idx, proof, tree_size).hex() != recomputed:
            return False, "entry inclusion does not verify"
        ok, reason = verify_witness_cosignatures(
            checkpoint, bundle.get("witness_cosigs", ()),
            witness_registry, quorum)
        if not ok:
            return False, "witness quorum: %s" % (reason,)
        return True, None
    except (KeyError, TypeError, ValueError,
            binascii.Error) as e:
        return False, "malformed bundle: %s" % (e,)


# ---------------------------------------------------------------------------
# Artifact-class conveniences
# ---------------------------------------------------------------------------

def _anchor_canonical(obj, *, client, sign):
    """Shared anchor path: canonical digest -> operator sign -> submit.

    Returns ``(anchor_hash_hex, receipt)``.
    """
    digest = hashlib.sha256(_eb.canonical(obj)).digest()
    signature_b64, pubkey_pem, algorithm = sign(digest)
    receipt = client.submit(
        digest.hex(), signature_b64=signature_b64,
        pubkey_pem=pubkey_pem, algorithm=algorithm)
    return digest.hex(), receipt


def anchor_checkpoint_sth(checkpoint_sth, *, client, sign):
    """Anchor a Sasanam signed checkpoint STH dict.

    Canonical bytes: ``gov.evidence_bundle.canonical`` over the
    checkpoint dict (the same canonical form the standalone verifier
    uses). ``sign(digest_bytes)`` is the operator-supplied anchor
    signer returning ``(signature_b64, pubkey_pem, algorithm)``.
    Returns ``(anchor_hash, receipt)``.
    """
    if not isinstance(checkpoint_sth, dict):
        raise RekorConfigError("checkpoint_sth must be a dict")
    if checkpoint_sth.get("format_version") != 2:
        raise RekorConfigError(
            "only signed (format-2) checkpoints are anchored; "
            "unsigned checkpoints carry no operator authority")
    return _anchor_canonical(checkpoint_sth, client=client, sign=sign)


def anchor_bundle_manifest(manifest, *, client, sign):
    """Anchor a sealed evidence-bundle manifest dict.

    Canonical bytes: ``gov.evidence_bundle.canonical``. The manifest
    must be sealed (carry a receipt/signature envelope) -- anchoring
    an unsealed manifest proves nothing about integrity.
    Returns ``(anchor_hash, receipt)``.
    """
    if not isinstance(manifest, dict):
        raise RekorConfigError("manifest must be a dict")
    if not manifest.get("sealed") and "receipt" not in manifest \
            and "signatures" not in manifest:
        raise RekorConfigError(
            "refusing to anchor an unsealed bundle manifest")
    return _anchor_canonical(manifest, client=client, sign=sign)
