"""Evidence anchoring: a tessera-pattern transparency log (clean-room).

Pattern lineage: transparency-dev/tessera (Apache-2.0). Tessera is a Go
library; this module is a clean-room stdlib-only Python reimplementation
of the PROTOCOL and API SHAPE -- tlog-tiles Merkle layout, C2SP
signed-note checkpoints, witness cosigning, Merkle inclusion proofs, the
Add->Index API, and PublicationAwaiter semantics. No tessera code is
vendored, imported, or translated line-by-line.

What this is: the anchoring backend for the offline evidence bundle
(the wave-284 SOPS lane seals and signs bundles; this lane anchors them).
An anchor receipt is::

    (bundle_digest, log_index, inclusion_proof, checkpoint_signature,
     witness_policy_id)

An auditor holding a receipt, the operator's public key, and the pinned
witness policy can verify -- offline, without this engine -- that a
bundle digest was appended to the log at a given index and committed to
by a signed, witness-cosigned checkpoint.

THREAT MODEL (read this before trusting an anchor):

* The local POSIX log store is TAMPER-EVIDENT, not tamper-proof. An
  attacker with write access to ``log_root`` can rewrite tiles and
  history. Such tampering is DETECTABLE (the stored leaves no longer
  hash to the signed checkpoint root; ``verify_receipt`` refuses
  ``anchor-log-corrupt`` / ``anchor-inclusion-mismatch``) but NOT
  prevented. Detection requires the auditor to hold an authentic
  checkpoint -- a checkpoint obtained from the operator over an
  authenticated channel, or carried inside the receipt itself and
  signature-checked against pinned keys.
* Forging a checkpoint that verifies under ``verify_receipt`` requires
  EITHER (a) the log operator's Ed25519 signing key AND ``quorum``
  witness signing keys (when a witness policy is pinned), OR (b)
  substituting the auditor's pinned key set out-of-band (the auditor
  must pin operator/witness key ids through a channel the attacker
  does not control -- this module cannot solve key distribution).
* Witnesses cosign the checkpoint BODY (origin, size, root, timestamp);
  they do not see individual bundle digests. Witness cosigning proves
  "quorum witnesses saw this tree root", not "witnesses reviewed your
  evidence".
* Inclusion proofs are self-verifying given an authentic checkpoint
  root (RFC 6962 Merkle semantics, stdlib sha256).
* Single-writer log. No consensus, no BFT, no fork detection beyond
  "the checkpoint I hold". Concurrent writers to one ``log_root`` are
  unsupported: there is no locking, and a lost-update interleave of a
  partial tile leaves ``state.json`` and the tiles mutually consistent,
  so reopen does NOT necessarily trip -- the corruption surfaces at
  receipt-verification time as ``anchor-leaf-mismatch`` /
  ``anchor-inclusion-mismatch``. Single writer only.
* Sequencing != publishing (the tessera trap, stated explicitly):
  ``add()`` durably assigns an index, but the entry has NO inclusion
  proof until ``await_publication()`` integrates it and publishes a
  signed checkpoint covering it. A receipt built without publication is
  refused as ``anchor-index-unpublished``. There is no silent dedup: two
  ``add()`` calls for the same digest mint two indices; idempotent
  re-anchoring is the caller's (personality's) job.

Entries are bundle digests (32 bytes); the log never stores raw evidence
(tlog-tiles entries are capped at 64KB; digests keep tiles tiny and the
log content-free).
"""

import base64
import binascii
import hashlib
import json
import os
import re

from gov import ed25519 as _ed25519

# ---------------------------------------------------------------------------
# Decision codes (domain: anchor). Registered in gov/decision_codes.py.
# ---------------------------------------------------------------------------

CHECKPOINT_INVALID = "anchor-checkpoint-invalid"
INCLUSION_MISMATCH = "anchor-inclusion-mismatch"
WITNESS_QUORUM_FAILED = "anchor-witness-quorum-failed"
INDEX_UNPUBLISHED = "anchor-index-unpublished"
LEAF_MISMATCH = "anchor-leaf-mismatch"
LOG_CORRUPT = "anchor-log-corrupt"
NO_SIGNER = "anchor-no-signer"


class AnchorError(Exception):
    """Base class; carries the machine ``code``."""

    code = CHECKPOINT_INVALID

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise AnchorError(detail, code=code)


# ---------------------------------------------------------------------------
# Audit sink (deployment chains these into the HMAC audit log).
# Digests and ids only -- key material NEVER reaches the sink.
# ---------------------------------------------------------------------------

_EMIT = None


def set_emit(emit):
    """Install (or clear, with None) the audit-event sink."""
    global _EMIT
    _EMIT = emit


def _emit(event):
    if _EMIT is not None:
        _EMIT(dict(event))


# ---------------------------------------------------------------------------
# Merkle tree (RFC 6962 / C2SP tlog-tiles hash semantics, stdlib sha256).
# ---------------------------------------------------------------------------

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
TILE_WIDTH = 256
MAX_ENTRY_BYTES = 65536  # tlog-tiles entry cap


def _hash_leaf(data):
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def _hash_node(left, right):
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _split(n):
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def _tree_root_hashes(hashes):
    """Root hash of the tree whose leaves hash to ``hashes``."""
    n = len(hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashes[0]
    k = _split(n)
    return _hash_node(_tree_root_hashes(hashes[:k]),
                      _tree_root_hashes(hashes[k:]))


def _inclusion_proof_hashes(hashes, m):
    """Sibling hashes from the leaf level up, for leaf ``m``."""
    n = len(hashes)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return _inclusion_proof_hashes(hashes[:k], m) + \
            [_tree_root_hashes(hashes[k:])]
    return _inclusion_proof_hashes(hashes[k:], m - k) + \
        [_tree_root_hashes(hashes[:k])]


def _verify_level(m, n, h, sibs):
    """Recursive verification mirroring _inclusion_proof_hashes.

    Consumes ``sibs`` (leaf-level-up) and returns ``(root, rest)``.
    The recursion structure is identical to proof construction, so
    correctness follows by construction.
    """
    if n == 1:
        return h, sibs
    k = _split(n)
    if not sibs:
        _fail(INCLUSION_MISMATCH, "proof too short for tree size")
    if m < k:
        sub, rest = _verify_level(m, k, h, sibs)
        if not rest:
            _fail(INCLUSION_MISMATCH, "proof too short for tree size")
        return _hash_node(sub, rest[0]), rest[1:]
    sub, rest = _verify_level(m - k, n - k, h, sibs)
    if not rest:
        _fail(INCLUSION_MISMATCH, "proof too short for tree size")
    return _hash_node(rest[0], sub), rest[1:]


def verify_inclusion(leaf_hash, proof, root):
    """Recompute the root from ``leaf_hash`` and ``proof``.

    ``proof`` is ``{"leaf_index": m, "tree_size": n, "hashes": [...]}``
    with hashes ordered leaf-level-up. Returns True iff the recomputed
    root equals ``root``. Pure function; raises AnchorError on malformed
    proof shape (fail-closed).
    """
    try:
        m = proof["leaf_index"]
        n = proof["tree_size"]
        siblings = [bytes.fromhex(h) for h in proof["hashes"]]
    except (KeyError, TypeError, ValueError, binascii.Error):
        _fail(INCLUSION_MISMATCH, "malformed inclusion proof shape")
    if not isinstance(m, int) or isinstance(m, bool) \
            or not isinstance(n, int) or isinstance(n, bool):
        _fail(INCLUSION_MISMATCH, "malformed inclusion proof shape")
    if n < 1 or m < 0 or m >= n:
        _fail(INCLUSION_MISMATCH, "proof index out of range")
    if any(len(s) != 32 for s in siblings):
        _fail(INCLUSION_MISMATCH, "proof hash is not 32 bytes")
    try:
        h = bytes(leaf_hash)
    except (TypeError, ValueError):
        _fail(INCLUSION_MISMATCH, "leaf hash is not bytes")
    if len(h) != 32:
        _fail(INCLUSION_MISMATCH, "leaf hash is not 32 bytes")
    try:
        root_bytes = bytes(root)
    except (TypeError, ValueError):
        _fail(INCLUSION_MISMATCH, "proof root is not bytes")
    computed, rest = _verify_level(m, n, h, siblings)
    if rest:
        _fail(INCLUSION_MISMATCH, "proof longer than tree size allows")
    return computed == root_bytes


# ---------------------------------------------------------------------------
# Checkpoint: C2SP tlog-checkpoint in signed-note format.
#
#   <origin>\n<size>\n<base64 root>\n<timestamp>\n
#   witness_policy: <policy id | "none">\n
#   \n
#   \u2014 <keyid> <base64 sig>\n   (one line per signer)
#
# Signatures cover the body bytes exactly (through the witness_policy
# line's trailing newline). The blank separator line is envelope, not
# signed content.
# ---------------------------------------------------------------------------

# Non-raw string so \u2014 is the em-dash escape (in a raw string it
# would read as a literal backslash sequence).
_SIG_RE = re.compile("^\u2014 ([A-Za-z0-9._/-]{1,128}) ([A-Za-z0-9+/=]+)$")
_ORIGIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}$")


def _render_body(body):
    # Public-seam validation lives in render_checkpoint; _render_body is
    # also called internally with machine-built bodies. Keep the helper
    # strict so any caller-supplied garbage fails coded, not raw.
    try:
        root_bytes = bytes(body["root"])
    except (TypeError, ValueError):
        _fail(CHECKPOINT_INVALID, "checkpoint body root is not bytes")
    wpid = body["witness_policy_id"]
    if not isinstance(wpid, str):
        _fail(CHECKPOINT_INVALID, "checkpoint witness_policy_id is not "
                                  "a string")
    lines = [body["origin"], str(body["size"]),
             base64.b64encode(root_bytes).decode("ascii"),
             str(body["timestamp"]),
             "witness_policy: " + wpid]
    return "\n".join(lines) + "\n"


def render_checkpoint(body, sigs):
    """Render a checkpoint body plus signature lines as a signed note."""
    for field in ("origin", "size", "root", "timestamp",
                  "witness_policy_id"):
        if field not in body:
            _fail(CHECKPOINT_INVALID,
                  "checkpoint body missing field %r" % field)
    note = _render_body(body) + "\n"
    for sig in sigs:
        # C2SP signed-note lines carry base64 signatures. Every
        # caller-supplied sig entry is validated LOUD: non-hex,
        # non-dict, or missing keys refuse anchor-checkpoint-invalid
        # instead of escaping raw ValueError/KeyError/TypeError (F331).
        try:
            if not isinstance(sig, dict):
                raise TypeError("sig entry must be a dict")
            kid = sig["keyid"]
            shex = sig["sig"]
            if not isinstance(kid, str) or not isinstance(shex, str):
                raise TypeError("sig keyid/sig must be strings")
            raw = base64.b64encode(bytes.fromhex(shex)).decode("ascii")
        except (TypeError, KeyError, ValueError, binascii.Error):
            _fail(CHECKPOINT_INVALID,
                  "checkpoint signature entry malformed")
        note += "\u2014 %s %s\n" % (kid, raw)
    return note


def parse_checkpoint(note):
    """Strict-parse a signed-note checkpoint.

    Returns ``(body, sigs)`` where body carries ``canonical`` (the exact
    signed bytes), ``origin``, ``size`` (int), ``root`` (32 bytes),
    ``timestamp`` (int), ``witness_policy_id``. Malformed notes refuse
    ``anchor-checkpoint-invalid`` -- never lenient.
    """
    if not isinstance(note, str) or not note:
        _fail(CHECKPOINT_INVALID, "checkpoint note must be a non-empty "
                                  "string")
    lines = note.split("\n")
    # Find the blank separator line: exactly 5 body lines precede it.
    if len(lines) < 7 or lines[5] != "":
        _fail(CHECKPOINT_INVALID, "checkpoint note has no body/signature "
                                  "separator")
    body_lines = lines[:5]
    sig_lines = [ln for ln in lines[6:] if ln != ""]
    if len(sig_lines) < 1:
        _fail(CHECKPOINT_INVALID, "checkpoint carries no signatures")
    origin = body_lines[0]
    if not _ORIGIN_RE.match(origin):
        _fail(CHECKPOINT_INVALID, "checkpoint origin fails grammar")
    try:
        size = int(body_lines[1])
        timestamp = int(body_lines[3])
    except ValueError:
        _fail(CHECKPOINT_INVALID, "checkpoint size/timestamp not "
                                  "integers")
    if size < 0 or timestamp < 0:
        _fail(CHECKPOINT_INVALID, "checkpoint size/timestamp negative")
    try:
        root = base64.b64decode(body_lines[2], validate=True)
    except (binascii.Error, ValueError):
        _fail(CHECKPOINT_INVALID, "checkpoint root is not base64")
    if len(root) != 32:
        _fail(CHECKPOINT_INVALID, "checkpoint root is not 32 bytes")
    wp = body_lines[4]
    if not wp.startswith("witness_policy: "):
        _fail(CHECKPOINT_INVALID, "checkpoint witness_policy line "
                                  "malformed")
    witness_policy_id = wp[len("witness_policy: "):]
    if witness_policy_id != "none" and not _ORIGIN_RE.match(
            witness_policy_id):
        _fail(CHECKPOINT_INVALID, "witness_policy_id fails grammar")
    sigs = []
    for ln in sig_lines:
        m = _SIG_RE.match(ln)
        if not m:
            _fail(CHECKPOINT_INVALID,
                  "checkpoint signature line malformed: %r" % ln[:40])
        try:
            sig = base64.b64decode(m.group(2), validate=True)
        except (binascii.Error, ValueError):
            _fail(CHECKPOINT_INVALID, "signature is not base64")
        if len(sig) != 64:
            _fail(CHECKPOINT_INVALID, "signature is not 64 bytes")
        sigs.append({"keyid": m.group(1), "sig": sig.hex()})
    canonical = ("\n".join(body_lines) + "\n").encode("utf-8")
    body = {"origin": origin, "size": size, "root": root,
            "timestamp": timestamp,
            "witness_policy_id": witness_policy_id,
            "canonical": canonical}
    return body, sigs


def _check_signature(canonical, keyid, sig_hex, pubkey_bytes):
    ok = _ed25519.verify(bytes(pubkey_bytes), bytes(canonical),
                         bytes.fromhex(sig_hex))
    # Wave-243 lesson: gov.ed25519.verify returns True/False -- the
    # return must be checked, never assumed.
    if ok is not True:
        _fail(CHECKPOINT_INVALID,
              "checkpoint signature by %r does not verify" % keyid)


# ---------------------------------------------------------------------------
# Witness policy: the trust anchor for multi-party attestation.
# ---------------------------------------------------------------------------

_POLICY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")


class WitnessPolicy:
    """A pinned witness cosigning policy.

    ``witnesses`` maps witness key id -> Ed25519 public key (hex, 64
    chars). ``quorum`` is the number of DISTINCT witnesses that must
    cosign a checkpoint for it to verify. Key ids are pinned by the
    AUDITOR out-of-band; this module cannot distribute them (see the
    threat model in the module docstring). Duplicate public keys across
    key ids are refused LOUD (``anchor-witness-quorum-failed``): one key
    pinned twice must not satisfy a quorum of 2.
    """

    def __init__(self, policy_id, witnesses, quorum):
        if not isinstance(policy_id, str) or \
                not _POLICY_ID_RE.match(policy_id):
            _fail(WITNESS_QUORUM_FAILED,
                  "witness policy id fails grammar")
        if not isinstance(witnesses, dict) or not witnesses:
            _fail(WITNESS_QUORUM_FAILED,
                  "witness policy needs a non-empty witness map")
        seen_keys = set()
        for kid, pub in witnesses.items():
            if not isinstance(kid, str) or not _POLICY_ID_RE.match(kid):
                _fail(WITNESS_QUORUM_FAILED,
                      "witness key id fails grammar: %r" % (kid,))
            try:
                raw = bytes.fromhex(pub)
            except (TypeError, ValueError, binascii.Error):
                _fail(WITNESS_QUORUM_FAILED,
                      "witness %r public key is not hex" % (kid,))
            if len(raw) != 32:
                _fail(WITNESS_QUORUM_FAILED,
                      "witness %r public key is not 32 bytes" % (kid,))
            # F333: a quorum of DISTINCT witnesses requires DISTINCT keys.
            # The same public key pinned under two key ids let one
            # compromised key satisfy a quorum of 2. Refuse LOUD instead
            # of letting a misconfigured (or attacker-influenced) policy
            # silently void the quorum's compromise-threshold promise.
            if pub in seen_keys:
                _fail(WITNESS_QUORUM_FAILED,
                      "witness public key is pinned under more than one "
                      "key id (%r): quorum requires distinct keys"
                      % (kid,))
            seen_keys.add(pub)
        if not isinstance(quorum, int) or isinstance(quorum, bool) \
                or quorum < 1 or quorum > len(witnesses):
            _fail(WITNESS_QUORUM_FAILED,
                  "quorum must be in [1, %d]" % len(witnesses))
        self.policy_id = policy_id
        self.witnesses = dict(witnesses)
        self.quorum = quorum


def check_witness_quorum(note, policy, operator_keyid=None):
    """Verify witness cosignatures on a checkpoint note.

    The operator's own signature line is NOT counted toward the quorum;
    only key ids pinned in ``policy.witnesses`` count, each at most
    once. ``operator_keyid`` names the operator's signature line to
    skip: when the operator's key id is (mis)configured as a pinned
    witness, its line still never counts -- key ids are expected to be
    distinct, and a collision fails closed against the quorum. Refuses
    ``anchor-witness-quorum-failed`` LOUD when fewer than
    ``policy.quorum`` distinct witnesses verify. Returns the count of
    verifying witnesses.
    """
    body, sigs = parse_checkpoint(note)
    if body["witness_policy_id"] != policy.policy_id:
        _fail(WITNESS_QUORUM_FAILED,
              "checkpoint names witness policy %r, expected %r"
              % (body["witness_policy_id"], policy.policy_id))
    seen = set()
    for sig in sigs:
        kid = sig["keyid"]
        if operator_keyid is not None and kid == operator_keyid:
            continue  # the operator's line never counts as a witness
        if kid not in policy.witnesses or kid in seen:
            continue
        pub = bytes.fromhex(policy.witnesses[kid])
        ok = _ed25519.verify(pub, body["canonical"],
                             bytes.fromhex(sig["sig"]))
        if ok is True:
            seen.add(kid)
    if len(seen) < policy.quorum:
        _fail(WITNESS_QUORUM_FAILED,
              "%d of %d required witnesses cosigned"
              % (len(seen), policy.quorum))
    return len(seen)


# ---------------------------------------------------------------------------
# POSIX tlog-tile log store.
#
#   <log_root>/tile/data/x{index:03d}        full data tile (256 hex leaf
#                                            hashes, one per line)
#   <log_root>/tile/data/x{index:03d}.p/{n}  partial data tile, n entries
#   <log_root>/checkpoint                    latest signed checkpoint note
#   <log_root>/state.json                    {"origin","size"} (fsync'd;
#                                            cross-checked against tiles
#                                            on open -- tamper-evident)
#
# This is a documented SUBSET of the C2SP tlog-tiles layout: data tiles
# and leaf hashing match the spec bit-for-bit; hash tiles are omitted
# because inclusion proofs are recomputed from content-addressed data
# tiles and checked against the signed checkpoint root (the checkpoint
# signature -- not the tile serving path -- is the trust anchor here).
# ---------------------------------------------------------------------------

_STATE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}$")


def _scan_tiles(root):
    """Return the sorted list of leaf hashes (hex) on disk.

    Refuses ``anchor-log-corrupt`` on any structural inconsistency
    (gaps, short full tiles, overfull tiles, stray files).
    """
    data_dir = os.path.join(root, "tile", "data")
    if not os.path.isdir(data_dir):
        return []
    full = {}
    partial = {}
    for name in sorted(os.listdir(data_dir)):
        if re.fullmatch(r"x\d{3}", name):
            full[int(name[1:])] = os.path.join(data_dir, name)
        elif re.fullmatch(r"x\d{3}\.p", name):
            # Partial tile: xNNN.p/<n> is a directory holding the count.
            sub = os.path.join(data_dir, name)
            if not os.path.isdir(sub):
                _fail(LOG_CORRUPT,
                      "partial tile %r is not a directory" % name)
            kids = os.listdir(sub)
            if len(kids) != 1 or not re.fullmatch(r"\d+", kids[0]):
                _fail(LOG_CORRUPT,
                      "partial tile %r has no single count" % name)
            partial[int(name[1:4])] = (sub, int(kids[0]))
        else:
            _fail(LOG_CORRUPT, "stray file in tile dir: %r" % name)
    if full and partial and max(full) >= min(partial):
        _fail(LOG_CORRUPT, "full tile overlaps partial tile")
    leaves = []
    for ti in sorted(full):
        if ti != len([t for t in full if t < ti]):
            _fail(LOG_CORRUPT, "gap in full tiles at x%03d" % ti)
        with open(full[ti], "r", encoding="utf-8") as fh:
            lines = fh.read().split()
        if len(lines) != TILE_WIDTH:
            _fail(LOG_CORRUPT, "full tile x%03d has %d entries"
                  % (ti, len(lines)))
        leaves.extend(lines)
    if partial:
        ti = min(partial)
        if full and ti != len(full):
            _fail(LOG_CORRUPT, "partial tile at wrong position")
        sub, n = partial[ti]
        path = os.path.join(sub, str(n))
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().split()
        if len(lines) != n or n >= TILE_WIDTH or n < 0:
            _fail(LOG_CORRUPT, "partial tile count mismatch")
        leaves.extend(lines)
        if len(partial) > 1:
            _fail(LOG_CORRUPT, "more than one partial tile")
    for lh in leaves:
        if not re.fullmatch(r"[0-9a-f]{64}", lh):
            _fail(LOG_CORRUPT, "tile holds a non-hex leaf hash")
    return leaves


def _write_partial(root, tile_index, leaf_hashes):
    """Atomically replace the partial tile for ``tile_index``."""
    data_dir = os.path.join(root, "tile", "data")
    # Remove any older partial tile for this index first.
    stale = os.path.join(data_dir, "x%03d.p" % tile_index)
    if os.path.isdir(stale):
        for kid in os.listdir(stale):
            os.unlink(os.path.join(stale, kid))
        os.rmdir(stale)
    n = len(leaf_hashes)
    if n >= TILE_WIDTH:
        # Tile is full: promote to a full tile file.
        final = os.path.join(data_dir, "x%03d" % tile_index)
        tmp = final + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(leaf_hashes) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.rename(tmp, final)
    else:
        sub = os.path.join(data_dir, "x%03d.p" % tile_index)
        os.makedirs(sub, exist_ok=True)
        tmp = os.path.join(sub, str(n) + ".tmp")
        final = os.path.join(sub, str(n))
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(leaf_hashes) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.rename(tmp, final)
    _fsync_dir(data_dir)


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class TransparencyLog:
    """A single-writer, append-only transparency log (tessera shape).

    ``add`` assigns a durable index (sequencing). ``await_publication``
    integrates pending entries and publishes a signed checkpoint covering
    the index (PublicationAwaiter semantics). A log opened with
    ``signer_seed=None`` is read/add-only: ``await_publication`` refuses
    ``anchor-no-signer`` LOUD.
    """

    def __init__(self, log_root, origin, signer_keyid, signer_seed=None):
        if not isinstance(log_root, str) or not log_root:
            _fail(LOG_CORRUPT, "log_root must be a non-empty path")
        if not isinstance(origin, str) or not _STATE_RE.match(origin):
            _fail(LOG_CORRUPT, "origin fails grammar")
        if not isinstance(signer_keyid, str) or \
                not _POLICY_ID_RE.match(signer_keyid):
            _fail(CHECKPOINT_INVALID, "signer key id fails grammar")
        seed = None
        if signer_seed is not None:
            seed = bytes(signer_seed)
            if len(seed) != 32:
                _fail(CHECKPOINT_INVALID, "signer seed is not 32 bytes")
        try:
            os.makedirs(os.path.join(log_root, "tile", "data"), exist_ok=True)
        except NotADirectoryError:
            _fail(LOG_CORRUPT,
                  "log_root %r is not a directory" % (log_root,))
        except OSError:
            # Environmental (permissions, read-only fs): still refuse
            # coded rather than let a platform exception escape the
            # public constructor (F331).
            _fail(LOG_CORRUPT,
                  "log_root %r is not usable" % (log_root,))
        self._root = log_root
        self._origin = origin
        self._keyid = signer_keyid
        self._seed = seed
        leaves = _scan_tiles(log_root)  # fail-closed on tampering
        state_path = os.path.join(log_root, "state.json")
        if os.path.exists(state_path):
            with open(state_path, "r", encoding="utf-8") as fh:
                try:
                    state = json.load(fh)
                except ValueError:
                    _fail(LOG_CORRUPT, "state.json is not JSON")
            if not isinstance(state, dict) or \
                    state.get("origin") != origin or \
                    state.get("size") != len(leaves):
                _fail(LOG_CORRUPT, "state.json disagrees with tiles "
                                   "(tamper-evident trip)")
        else:
            self._write_state(len(leaves))
        self._size = len(leaves)

    def _write_state(self, size):
        state_path = os.path.join(self._root, "state.json")
        tmp = state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"origin": self._origin, "size": size}, fh,
                      sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.rename(tmp, state_path)
        _fsync_dir(self._root)

    def add(self, entry):
        """Durably assign the next index to ``entry`` (Add->Index).

        Returns the index. The entry is NOT published yet: it has no
        inclusion proof until ``await_publication`` covers it (the
        tessera sequencing-vs-publishing trap, enforced by refusing
        unpublished receipts at verify time).
        """
        if not isinstance(entry, (bytes, bytearray)):
            _fail(LOG_CORRUPT, "log entry must be bytes")
        entry = bytes(entry)
        if not 1 <= len(entry) <= MAX_ENTRY_BYTES:
            _fail(LOG_CORRUPT, "log entry must be 1..65536 bytes")
        idx = self._size
        ti, off = divmod(idx, TILE_WIDTH)
        # Rebuild this tile's current leaf list from disk, append, write.
        if off == 0:
            current = []
        else:
            sub = os.path.join(self._root, "tile", "data",
                               "x%03d.p" % ti, str(off))
            with open(sub, "r", encoding="utf-8") as fh:
                current = fh.read().split()
            if len(current) != off:
                _fail(LOG_CORRUPT, "partial tile disagrees with state")
        current.append(_hash_leaf(entry).hex())
        _write_partial(self._root, ti, current)
        self._size += 1
        self._write_state(self._size)
        _emit({"event": "anchor-added", "origin": self._origin,
               "index": idx, "leaf": current[-1]})
        return idx

    def _leaf_hashes(self, size):
        data_dir = os.path.join(self._root, "tile", "data")
        out = []
        remaining = size
        ti = 0
        while remaining > 0:
            take = min(remaining, TILE_WIDTH)
            if take == TILE_WIDTH:
                path = os.path.join(data_dir, "x%03d" % ti)
            else:
                path = os.path.join(data_dir, "x%03d.p" % ti,
                                    str(take))
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.read().split()
            if len(lines) != take:
                _fail(LOG_CORRUPT, "tile x%03d changed underfoot" % ti)
            out.extend(bytes.fromhex(lh) for lh in lines)
            remaining -= take
            ti += 1
        return out

    def _sign_checkpoint(self, size, witness_policy_id):
        import time
        root = _tree_root_hashes(self._leaf_hashes(size))
        body = {"origin": self._origin, "size": size, "root": root,
                "timestamp": int(time.time()),
                "witness_policy_id": witness_policy_id}
        canonical = _render_body(body).encode("utf-8")
        op_sig = {"keyid": self._keyid,
                  "sig": _ed25519.sign(self._seed, canonical).hex()}
        return body, op_sig

    def _store_checkpoint(self, note):
        path = os.path.join(self._root, "checkpoint")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(note)
            fh.flush()
            os.fsync(fh.fileno())
        os.rename(tmp, path)
        _fsync_dir(self._root)

    def await_publication(self, index, witness_policy=None,
                          witness_seeds=None):
        """Integrate pending entries; publish a signed checkpoint.

        PublicationAwaiter semantics: blocks (here, synchronously)
        until ``index`` is committed to by a published checkpoint, then
        returns ``{"size","root","timestamp","origin","signed_note",
        "witness_policy_id"}``. Refuses ``anchor-index-unpublished``
        when ``index`` was never added, ``anchor-no-signer`` when this
        handle has no operator key.
        """
        if not isinstance(index, int) or isinstance(index, bool) \
                or index < 0:
            _fail(INDEX_UNPUBLISHED, "index must be a non-negative int")
        if index >= self._size:
            _fail(INDEX_UNPUBLISHED,
                  "index %d was never added (log size %d)"
                  % (index, self._size))
        if self._seed is None:
            _fail(NO_SIGNER, "await_publication needs the operator "
                             "signer key")
        wp_id = witness_policy.policy_id if witness_policy else "none"
        body, op_sig = self._sign_checkpoint(self._size, wp_id)
        sigs = [op_sig]
        if witness_policy is not None:
            sigs = self._cosign(body, op_sig, witness_policy,
                                witness_seeds or {})
        note = render_checkpoint(body, sigs)
        self._store_checkpoint(note)
        _emit({"event": "anchor-published", "origin": self._origin,
               "size": body["size"], "root": body["root"].hex(),
               "witness_policy": wp_id})
        return {"size": body["size"], "root": body["root"].hex(),
                "timestamp": body["timestamp"], "origin": body["origin"],
                "signed_note": note, "witness_policy_id": wp_id}

    def _cosign(self, body, op_sig, policy, seeds):
        canonical = _render_body(body).encode("utf-8")
        # The operator signature is always first; witnesses append.
        out = [op_sig]
        for kid, seed in seeds.items():
            if kid not in policy.witnesses:
                _fail(WITNESS_QUORUM_FAILED,
                      "cosigning key %r is not a pinned witness" % (kid,))
            raw = bytes(seed)
            if len(raw) != 32:
                _fail(WITNESS_QUORUM_FAILED,
                      "witness seed for %r is not 32 bytes" % (kid,))
            # Defense in depth: the seed must actually match the pinned
            # witness key, otherwise a wrong seed mints a signature no
            # auditor will accept (loud now, not at verify time).
            if _ed25519.publickey(raw).hex() != policy.witnesses[kid]:
                _fail(WITNESS_QUORUM_FAILED,
                      "witness seed does not match pinned key %r"
                      % (kid,))
            out.append({"keyid": kid,
                        "sig": _ed25519.sign(raw, canonical).hex()})
        # Fail fast: the operator's own key id never counts toward the
        # witness quorum (see check_witness_quorum), so an under-quorum
        # witness set refuses here instead of minting a receipt that is
        # dead on arrival at verify time.
        counted = [s for s in out[1:]
                   if s["keyid"] != self._keyid]
        if len(counted) < policy.quorum:
            _fail(WITNESS_QUORUM_FAILED,
                  "only %d witness seed(s) supplied for quorum %d"
                  % (len(counted), policy.quorum))
        return out

    def checkpoint(self):
        """Return the latest published checkpoint, or None."""
        path = os.path.join(self._root, "checkpoint")
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as fh:
            note = fh.read()
        body, sigs = parse_checkpoint(note)  # strict; tampering refuses
        return {"size": body["size"], "root": body["root"].hex(),
                "timestamp": body["timestamp"], "origin": body["origin"],
                "signed_note": note,
                "witness_policy_id": body["witness_policy_id"]}

    def inclusion_proof(self, index, tree_size):
        """Merkle inclusion proof for ``index`` in a tree of
        ``tree_size`` leaves, as ``{"leaf_index","tree_size","hashes"}``
        with sibling hashes hex-encoded leaf-level-up."""
        if not isinstance(index, int) or isinstance(index, bool) \
                or index < 0 or index >= tree_size:
            _fail(INCLUSION_MISMATCH, "proof index out of range")
        if tree_size > self._size:
            _fail(INCLUSION_MISMATCH,
                  "tree size %d exceeds log size %d"
                  % (tree_size, self._size))
        hashes = self._leaf_hashes(tree_size)
        sibs = _inclusion_proof_hashes(hashes, index)
        return {"leaf_index": index, "tree_size": tree_size,
                "hashes": [s.hex() for s in sibs]}


# ---------------------------------------------------------------------------
# Anchor receipts.
# ---------------------------------------------------------------------------

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_LOG_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$")


def _check_digest(digest):
    if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
        _fail(LEAF_MISMATCH, "bundle_digest must be 64 lowercase hex "
                             "chars")


def anchor(log, bundle_digest, witness_policy=None, witness_seeds=None,
           provenance_gate=None):
    """Anchor a bundle digest; return the anchor receipt.

    The receipt is ``{"bundle_digest","log_index","inclusion_proof",
    "checkpoint_signature","witness_policy_id"}``. This performs the
    full Add -> await_publication -> proof sequence: the receipt is
    only valid once a signed checkpoint covers the index (the tessera
    PublicationAwaiter requirement). Witness cosigning is applied when
    ``witness_policy`` is given; ``witness_seeds`` maps witness key id
    -> 32-byte seed.

    ``provenance_gate`` is an optional callable ``gate(bundle_digest)``
    invoked AFTER digest validation and BEFORE the entry is sequenced:
    it raises (loudly, with its own machine code) when the bundle may
    not be anchored -- e.g. gov/evidence_provenance.py's
    provenance-gated anchor. A refused bundle leaves no log entry. The
    gate is additive: callers without one see no behavior change.
    """
    _check_digest(bundle_digest)
    if provenance_gate is not None:
        if not callable(provenance_gate):
            _fail(CHECKPOINT_INVALID,
                  "provenance_gate must be callable")
        provenance_gate(bundle_digest)  # raises LOUD on refusal
    if witness_policy is not None and \
            not isinstance(witness_policy, WitnessPolicy):
        _fail(WITNESS_QUORUM_FAILED, "witness_policy must be a "
                                     "WitnessPolicy")
    idx = log.add(bytes.fromhex(bundle_digest))
    cp = log.await_publication(idx, witness_policy=witness_policy,
                               witness_seeds=witness_seeds)
    proof = log.inclusion_proof(idx, cp["size"])
    receipt = {"bundle_digest": bundle_digest, "log_index": idx,
               "inclusion_proof": proof,
               "checkpoint_signature": cp["signed_note"],
               "witness_policy_id": cp["witness_policy_id"]}
    _emit({"event": "anchor-receipt", "leaf": bundle_digest,
           "index": idx, "size": cp["size"]})
    return receipt


def anchor_bundle(log, envelope, witness_policy=None,
                  witness_seeds=None, provenance_gate=None):
    """Anchor a sealed bundle envelope (gov/bundle_envelope.py).

    The anchor leaf is ``envelope_digest(envelope)`` -- the bundle's
    content identity -- so the receipt binds the exact sealed bytes.
    ``provenance_gate`` is passed through to ``anchor`` (see there).
    """
    from gov import bundle_envelope as _be
    if not isinstance(envelope, dict):
        _fail(LEAF_MISMATCH, "envelope must be a dict")
    return anchor(log, _be.envelope_digest(envelope),
                  witness_policy=witness_policy,
                  witness_seeds=witness_seeds,
                  provenance_gate=provenance_gate)


def verify_receipt(receipt, log_pubkey, witness_policy=None,
                   log_root=None):
    """Verify an anchor receipt LOUD. Returns True.

    Checks, in order: receipt shape -> checkpoint parses -> checkpoint
    covers the index -> operator signature verifies under ``log_pubkey``
    -> witness quorum (when a policy is pinned) -> the claimed bundle
    digest is the leaf anchored at the index (``anchor-leaf-mismatch``;
    needs ``log_root`` to read the tile, otherwise a wrong digest fails
    as ``anchor-inclusion-mismatch``) -> the inclusion proof chains the
    leaf to the checkpoint root. Any failure raises AnchorError with its
    machine code. ``log_pubkey`` is 32 raw bytes.
    """
    if not isinstance(receipt, dict):
        _fail(CHECKPOINT_INVALID, "receipt must be a dict")
    for field in ("bundle_digest", "log_index", "inclusion_proof",
                  "checkpoint_signature", "witness_policy_id"):
        if field not in receipt:
            _fail(CHECKPOINT_INVALID,
                  "receipt missing field %r" % field)
    _check_digest(receipt["bundle_digest"])
    idx = receipt["log_index"]
    if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
        _fail(INDEX_UNPUBLISHED, "receipt log_index malformed")
    body, sigs = parse_checkpoint(receipt["checkpoint_signature"])
    if idx >= body["size"]:
        _fail(INDEX_UNPUBLISHED,
              "checkpoint of size %d does not cover index %d"
              % (body["size"], idx))
    if not isinstance(log_pubkey, (bytes, bytearray)) or \
            len(bytes(log_pubkey)) != 32:
        _fail(CHECKPOINT_INVALID, "log_pubkey must be 32 bytes")
    op = sigs[0]
    _check_signature(body["canonical"], op["keyid"], op["sig"],
                     bytes(log_pubkey))
    if witness_policy is not None:
        if receipt["witness_policy_id"] != witness_policy.policy_id:
            _fail(WITNESS_QUORUM_FAILED,
                  "receipt names witness policy %r, expected %r"
                  % (receipt["witness_policy_id"],
                     witness_policy.policy_id))
        check_witness_quorum(receipt["checkpoint_signature"],
                             witness_policy,
                             operator_keyid=op["keyid"])
    elif receipt["witness_policy_id"] != "none":
        _fail(WITNESS_QUORUM_FAILED,
              "receipt carries witness policy %r but no policy was "
              "pinned for verification"
              % (receipt["witness_policy_id"],))
    # Bind the receipt to the checkpoint's own policy claim: an auditor
    # who pins no policy still gets a loud signal when the checkpoint
    # names a witness policy the receipt does not claim (or vice
    # versa).
    if body["witness_policy_id"] != receipt["witness_policy_id"]:
        _fail(WITNESS_QUORUM_FAILED,
              "checkpoint names witness policy %r but receipt claims %r"
              % (body["witness_policy_id"],
                 receipt["witness_policy_id"]))
    if log_root is not None:
        leaves = _scan_tiles(log_root)  # fail-closed on tampering
        if idx >= len(leaves):
            _fail(LOG_CORRUPT, "log has %d leaves; receipt claims "
                               "index %d" % (len(leaves), idx))
        want_leaf = _hash_leaf(bytes.fromhex(receipt["bundle_digest"]))
        if not _constant_time_eq(bytes.fromhex(leaves[idx]), want_leaf):
            _fail(LEAF_MISMATCH,
                  "tile leaf at index %d is not the claimed bundle "
                  "digest" % idx)
    proof = receipt["inclusion_proof"]
    if not isinstance(proof, dict):
        _fail(INCLUSION_MISMATCH, "inclusion proof must be a dict")
    if proof.get("leaf_index") != idx or \
            proof.get("tree_size") != body["size"]:
        _fail(INCLUSION_MISMATCH,
              "proof (index,size) does not match the checkpoint")
    leaf_hash = _hash_leaf(bytes.fromhex(receipt["bundle_digest"]))
    if verify_inclusion(leaf_hash, proof, body["root"]) is not True:
        _fail(INCLUSION_MISMATCH,
              "inclusion proof does not chain to the checkpoint root")
    _emit({"event": "anchor-verified", "leaf": receipt["bundle_digest"],
           "index": idx, "ok": True})
    return True


def _constant_time_eq(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# ---------------------------------------------------------------------------
# GUAC composition: anchor receipts as evidence nodes.
# ---------------------------------------------------------------------------

def record_anchor_in_graph(graph, receipt, log_id):
    """Record an anchor receipt in a GUAC evidence graph.

    Adds ``evidence:<bundle_digest>`` and
    ``software:anchor-log/<log_id>@1`` nodes plus a structural
    ``HasSLSA`` edge (the log attests the digest). Claim edges are not
    used: anchoring is a structural attestation here, corroboration of
    the *evidence content* stays in the claim layer.
    """
    from gov import guac_graph as _gg
    if not isinstance(receipt, dict) or \
            "bundle_digest" not in receipt:
        _fail(CHECKPOINT_INVALID, "receipt must carry bundle_digest")
    _check_digest(receipt["bundle_digest"])
    if not isinstance(log_id, str) or not _LOG_ID_RE.match(log_id):
        _fail(CHECKPOINT_INVALID, "log_id fails grammar")
    ev = graph.add_node("evidence", receipt["bundle_digest"])
    sw = graph.add_node("software", "anchor-log/%s@1" % log_id)
    graph.add_edge(sw, "HasSLSA", ev)
    _emit({"event": "anchor-graphed", "leaf": receipt["bundle_digest"],
           "log": log_id})
    return {"evidence_node": ev, "log_node": sw}
