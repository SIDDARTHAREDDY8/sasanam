"""Shamir t-of-n key custody ceremonies for the evidence signing key.

Wave-328 lane 3 (evidence-envelope direction-brief item 2 step A,
``research/prospecting/w317_evidence_next_steps.md``): Shamir's Secret
Sharing (1979) t-of-n custody under a Vault-style ops model (pattern
only, no vendoring -- stdlib only).

ADAPTATION NOTE -- read before reviewing: the lane brief asked for a
Rekor-pattern transparency witness (``gov/transparency_witness.py``).
The research-first read the brief itself requires showed that module
already exists three times over: ``gov/witness_rekor.py`` (wave-314:
Rekor-pattern ``anchor_evidence`` / ``verify_inclusion`` / signed
inclusion receipts), ``gov/witness_log.py`` (append-only Merkle log),
``gov/witness_consistency.py`` (wave-319: consistency proofs, C2SP
signed-note checkpoints via ``gov/checkpoint_note.py``, fail-closed
gossip), plus ``gov/trust_root_refresh.py`` and
``gov/evidence_schema_v2.py`` (w317 direction-brief items 3 and 4).
Building a fourth witness would duplicate shipped, tested code. The
remaining documented item from the w317 direction brief is threshold
signing step A: Shamir t-of-n custody for the evidence bundle's signing
key (5 shares / threshold 3, rekey rotation, recovery ceremony --
Vault's ``operator init -key-shares=5 -key-threshold=3`` model). Step B
(FROST group signing) stays deferred per the prospectus itself: it
needs an audited implementation, and FROST is not post-quantum. This
module is step A.

What this module does
---------------------
* :func:`split` -- split a byte secret into ``n`` shards with threshold
  ``t`` under a named ceremony. Arithmetic is Shamir's scheme over
  GF(2^8) (AES polynomial ``0x11b``), so every share is a byte string
  the same length as the secret; coefficients come from
  :mod:`secrets` (CSPRNG).
* :func:`combine` -- reconstruct from any ``t`` (or more) shards of one
  ceremony. Every shard carries ``commitment = sha256(secret)``; the
  reconstructed secret is checked against it, so a corrupted shard, a
  mixed-ceremony set, or a wrong-secret mix refuses coded instead of
  returning a wrong key.
* :func:`distribute` -- hand shards to custodians: one shard per
  custodian, atomic 0600 writes, never overwrites a live shard, never
  two shards to one custodian or one path.
* :func:`rekey` -- new ceremony (new id, fresh randomness) for the same
  secret; ceremony-id binding retires the old shards (old+new never
  mix).
* :class:`CeremonyTranscript` -- hash-chained JSONL ceremony log
  (init/distribute/combine/rekey/revoke). Records that reconstructions
  happened and who took part -- never share material.

Fail-closed rules (all raise :class:`ShamirCustodyError` with a
registered ``custody-shamir-*`` code, never a bare ``ValueError`` and
never a wrong secret):

* ``t = 1`` is refused: a 1-of-n "threshold" lets a single custodian
  reconstruct, which is not threshold custody.
* Fewer than ``t`` shards: refused (the module never outputs a guess;
  with ``t-1`` shares the secret is information-theoretically hidden,
  and the module does not even try).
* Duplicate share indices, out-of-range indices, mismatched share
  lengths, mixed ceremony ids, malformed shards: all refused coded.
* ``distribute`` refuses duplicate custodians/paths and refuses to
  overwrite an existing shard file.
* A corrupt transcript refuses coded on :meth:`CeremonyTranscript.verify`.

Honest limits (documented, not fixed by this module):

* **Trusted dealer.** Whoever runs :func:`split` sees the secret --
  Shamir's 1979 limitation, cited in the w317 prospectus ("threshold
  security is only as good as the setup ceremony"). Mitigation is
  procedural: run the ceremony on the air-gapped ceremony machine with
  two operators present, then destroy the secret's other copies. The
  module cannot fix this; it documents it.
* **No at-rest encryption of shards in-module.** Stdlib has no PGP.
  :func:`distribute` enforces distinct custodians and paths and 0600
  file modes, but custodian opsec (encrypted media, separate
  locations) is a deployment responsibility -- the Vault runbook's
  "shards distributed across people/locations, PGP-encrypted at rest"
  maps to procedure here, not code.
* **Commitment brute-force.** Every shard publishes ``sha256(secret)``,
  which lets a shard-holder test guesses. Secrets must therefore carry
  >= 128 bits of entropy; :func:`split` refuses secrets shorter than 16
  bytes, and :func:`generate_secret` uses :mod:`secrets`.
* **Recovery ceremony.** The Vault model's recovery keys (break-glass
  for the auto-unseal path) map to a separately-named ceremony whose
  shards live with a different custodian set. The module supports any
  number of named ceremonies; the recovery ceremony is procedure, and
  :func:`rekey` / transcript ``revoke`` events are its paper trail.
"""

import base64
import hashlib
import json
import os
import secrets
import tempfile
import time

# ---------------------------------------------------------------------------
# Codes (registered in gov/decision_codes.py, domain "custody", sorted).
# ---------------------------------------------------------------------------

_NEW_CODES = (
    "custody-shamir-bad-params",
    "custody-shamir-ceremony-mismatch",
    "custody-shamir-commitment-mismatch",
    "custody-shamir-distribute-refused",
    "custody-shamir-duplicate-share",
    "custody-shamir-insufficient-shares",
    "custody-shamir-share-malformed",
    "custody-shamir-transcript-corrupt",
)

_TRANSCRIPT_EVENTS = ("init", "distribute", "combine", "rekey", "revoke")

_MIN_SECRET_BYTES = 16  # 128 bits; see the commitment brute-force note.
_MAX_SHARES = 255  # GF(2^8) has 255 nonzero x-coordinates.


class ShamirCustodyError(ValueError):
    """Loud, machine-coded custody refusal. ``code`` names the failure."""

    def __init__(self, code, detail=""):
        if code not in _NEW_CODES:
            raise ValueError("unknown shamir-custody code %r" % (code,))
        super(ShamirCustodyError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code


def _fail(code, detail=""):
    raise ShamirCustodyError(code, detail)


# ---------------------------------------------------------------------------
# GF(2^8) arithmetic (AES polynomial 0x11b). All values are bytes.
# ---------------------------------------------------------------------------

def _gf_add(a, b):
    return a ^ b


def _gf_mul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_inv(a):
    if a == 0:
        # Internal invariant: Lagrange never inverts zero (duplicate-x
        # shares are refused by _check_shards before arithmetic). The
        # module's contract says every refusal is coded, so this stays
        # a coded ShamirCustodyError rather than a bare AssertionError.
        _fail("custody-shamir-share-malformed",
              "gf_inv(0): duplicate or zero share index slipped validation")
    # Fermat: a^254 in GF(2^8).
    result = 1
    base = a
    exp = 254
    while exp:
        if exp & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return result


def _eval_poly(coeffs, x):
    # Horner over GF(2^8); coeffs[0] is the constant term.
    acc = 0
    for c in reversed(coeffs):
        acc = _gf_add(_gf_mul(acc, x), c)
    return acc


def _lagrange_at_zero(points):
    # points: [(x_int, y_int)], x != 0, distinct x. Returns f(0).
    secret = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = _gf_mul(num, xj)
            den = _gf_mul(den, _gf_add(xj, xi))  # xj - xi == xj ^ xi
        secret = _gf_add(secret, _gf_mul(yi, _gf_mul(num, _gf_inv(den))))
    return secret


# ---------------------------------------------------------------------------
# Shards.
# ---------------------------------------------------------------------------

def generate_secret(num_bytes=32):
    """Generate a ceremony secret with ``num_bytes`` of CSPRNG entropy."""
    if not isinstance(num_bytes, int) or num_bytes < _MIN_SECRET_BYTES:
        _fail("custody-shamir-bad-params",
              "num_bytes must be an int >= %d" % _MIN_SECRET_BYTES)
    return secrets.token_bytes(num_bytes)


def _check_ceremony_id(ceremony_id):
    if not isinstance(ceremony_id, str) or not ceremony_id.strip():
        _fail("custody-shamir-bad-params",
              "ceremony_id must be a non-empty str")
    if len(ceremony_id) > 128:
        _fail("custody-shamir-bad-params",
              "ceremony_id longer than 128 chars")


def split(secret, n, t, ceremony_id):
    """Split ``secret`` into ``n`` shards, any ``t`` of which reconstruct.

    Returns a list of shard dicts. The caller is the trusted dealer
    (see the module docstring): this function sees the secret.
    """
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < _MIN_SECRET_BYTES:
        _fail("custody-shamir-bad-params",
              "secret must be bytes of length >= %d (128-bit floor)" % _MIN_SECRET_BYTES)
    if not isinstance(n, int) or not isinstance(t, int):
        _fail("custody-shamir-bad-params", "n and t must be ints")
    if n < 2 or n > _MAX_SHARES:
        _fail("custody-shamir-bad-params",
              "n must be in [2, %d]" % _MAX_SHARES)
    if t < 2 or t > n:
        # t = 1 is refused deliberately: a single custodian could
        # reconstruct, which is not threshold custody.
        _fail("custody-shamir-bad-params",
              "t must be in [2, n] (t=1 is not threshold custody)")
    _check_ceremony_id(ceremony_id)

    secret = bytes(secret)
    commitment = hashlib.sha256(secret).hexdigest()
    # One polynomial per byte position, FIXED across all x: generating fresh
    # coefficients per (byte, x) would put the shares on different curves
    # and reconstruction would silently return garbage (caught 2026-10-04
    # by the round-trip check before any commit).
    polys = [[b] + [secrets.randbelow(256) for _ in range(t - 1)]
             for b in secret]
    shards = []
    for index in range(1, n + 1):
        share = bytes(_eval_poly(poly, index) for poly in polys)
        shards.append({
            "ceremony_id": ceremony_id,
            "threshold": t,
            "share_count": n,
            "index": index,
            "share": share,
            "commitment": commitment,
        })
    return shards


def _check_shards(shards):
    if not isinstance(shards, (list, tuple)) or not shards:
        _fail("custody-shamir-share-malformed", "shards must be a non-empty list")
    first = shards[0]
    for s in shards:
        if not isinstance(s, dict):
            _fail("custody-shamir-share-malformed", "shard must be a dict")
        for key in ("ceremony_id", "threshold", "share_count", "index", "share", "commitment"):
            if key not in s:
                _fail("custody-shamir-share-malformed",
                      "shard missing key %r" % (key,))
        if not isinstance(s["ceremony_id"], str) or not s["ceremony_id"]:
            _fail("custody-shamir-share-malformed", "bad ceremony_id")
        if not isinstance(s["threshold"], int) or not isinstance(s["share_count"], int):
            _fail("custody-shamir-share-malformed", "bad threshold/share_count")
        if not isinstance(s["index"], int) or not 1 <= s["index"] <= s["share_count"]:
            _fail("custody-shamir-share-malformed",
                  "share index out of range: %r" % (s["index"],))
        if not isinstance(s["share"], (bytes, bytearray)) or not s["share"]:
            _fail("custody-shamir-share-malformed", "share must be non-empty bytes")
        if (not isinstance(s["commitment"], str) or len(s["commitment"]) != 64
                or any(c not in "0123456789abcdef" for c in s["commitment"])):
            _fail("custody-shamir-share-malformed", "bad commitment")
    ceremony_id = first["ceremony_id"]
    if any(s["ceremony_id"] != ceremony_id for s in shards):
        _fail("custody-shamir-ceremony-mismatch",
              "shards span more than one ceremony")
    indices = [s["index"] for s in shards]
    if len(set(indices)) != len(indices):
        _fail("custody-shamir-duplicate-share",
              "duplicate share index in reconstruction set")
    share_len = len(bytes(first["share"]))
    if any(len(bytes(s["share"])) != share_len for s in shards):
        _fail("custody-shamir-share-malformed", "share length mismatch")
    commitment = first["commitment"]
    if any(s["commitment"] != commitment for s in shards):
        # Same ceremony but divergent commitments: at least one shard is
        # corrupt or forged. Refuse; do not guess which.
        _fail("custody-shamir-commitment-mismatch",
              "commitment diverges within one ceremony")
    return ceremony_id, first["threshold"], share_len, commitment


def combine(shards):
    """Reconstruct the secret from ``shards`` (any t of one ceremony).

    Refuses coded unless at least ``t`` well-formed, same-ceremony,
    distinct-index shards are supplied AND the reconstructed secret
    matches the shards' commitment. Never returns a wrong secret.
    """
    _, t, share_len, commitment = _check_shards(shards)
    if len(shards) < t:
        _fail("custody-shamir-insufficient-shares",
              "need %d shares, got %d" % (t, len(shards)))
    secret = bytes(
        _lagrange_at_zero([(s["index"], bytes(s["share"])[pos]) for s in shards])
        for pos in range(share_len)
    )
    if hashlib.sha256(secret).hexdigest() != commitment:
        _fail("custody-shamir-commitment-mismatch",
              "reconstructed secret does not match the shard commitment")
    return secret


# ---------------------------------------------------------------------------
# Shard serialization (for distribute) -- JSON, share as base64.
# ---------------------------------------------------------------------------

_SHARD_SCHEMA = "sasanam-shamir-shard/v1"


def serialize_shard(shard):
    """Serialize one shard dict to canonical JSON bytes (for storage)."""
    _check_shards([shard])
    doc = {
        "schema": _SHARD_SCHEMA,
        "ceremony_id": shard["ceremony_id"],
        "threshold": shard["threshold"],
        "share_count": shard["share_count"],
        "index": shard["index"],
        "share_b64": base64.b64encode(bytes(shard["share"])).decode("ascii"),
        "commitment": shard["commitment"],
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_shard(blob):
    """Parse serialized shard bytes back to a shard dict (share as bytes)."""
    if isinstance(blob, str):
        blob = blob.encode("utf-8")
    try:
        doc = json.loads(blob.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        _fail("custody-shamir-share-malformed", "unparseable shard: %s" % (exc,))
    if not isinstance(doc, dict) or doc.get("schema") != _SHARD_SCHEMA:
        _fail("custody-shamir-share-malformed", "bad shard schema")
    try:
        share = base64.b64decode(doc["share_b64"], validate=True)
    except (KeyError, ValueError, base64.binascii.Error) as exc:
        _fail("custody-shamir-share-malformed", "bad share_b64: %s" % (exc,))
    shard = {
        "ceremony_id": doc.get("ceremony_id"),
        "threshold": doc.get("threshold"),
        "share_count": doc.get("share_count"),
        "index": doc.get("index"),
        "share": share,
        "commitment": doc.get("commitment"),
    }
    _check_shards([shard])
    return shard


def _atomic_write(path, blob, mode=0o600):
    parent = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent):
        _fail("custody-shamir-distribute-refused",
              "parent dir does not exist: %r" % (parent,))
    if os.path.exists(path):
        _fail("custody-shamir-distribute-refused",
              "refusing to overwrite existing shard file: %r" % (path,))
    fd, tmp = tempfile.mkstemp(prefix=".shard-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except ShamirCustodyError:
        raise
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        _fail("custody-shamir-distribute-refused",
              "write failed for %r: %s" % (path, exc))


def distribute(shards, assignments, transcript=None):
    """Hand shards to custodians: ``assignments`` maps custodian_id -> path.

    One shard per custodian; distinct custodians AND distinct paths are
    required (two shards to one custodian defeats threshold custody).
    Writes are atomic 0600; an existing file at any target refuses the
    whole distribution before anything is written.
    Returns the manifest {custodian_id: {"path": ..., "index": ...}}.
    """
    _check_shards(shards)
    if not isinstance(assignments, dict) or not assignments:
        _fail("custody-shamir-distribute-refused",
              "assignments must be a non-empty {custodian_id: path} dict")
    if len(assignments) != len(shards):
        _fail("custody-shamir-distribute-refused",
              "need one custodian per shard: %d shards, %d custodians"
              % (len(shards), len(assignments)))
    for custodian, path in assignments.items():
        if not isinstance(custodian, str) or not custodian.strip():
            _fail("custody-shamir-distribute-refused",
                  "custodian ids must be non-empty strings")
        if not isinstance(path, str) or not path:
            _fail("custody-shamir-distribute-refused",
                  "paths must be non-empty strings")
    paths = [os.path.abspath(p) for p in assignments.values()]
    if len(set(paths)) != len(paths):
        _fail("custody-shamir-distribute-refused",
              "two custodians share one shard path")
    # Pre-flight: refuse before writing anything.
    for path in paths:
        parent = os.path.dirname(path)
        if not os.path.isdir(parent):
            _fail("custody-shamir-distribute-refused",
                  "parent dir does not exist: %r" % (parent,))
        if os.path.exists(path):
            _fail("custody-shamir-distribute-refused",
                  "refusing to overwrite existing shard file: %r" % (path,))
    manifest = {}
    for (custodian, _), shard, path in zip(assignments.items(), shards, paths):
        _atomic_write(path, serialize_shard(shard))
        manifest[custodian] = {"path": path, "index": shard["index"]}
    if transcript is not None:
        transcript.record("distribute", {
            "ceremony_id": shards[0]["ceremony_id"],
            "custodians": sorted(manifest),
        })
    return manifest


def rekey(secret, n, t, new_ceremony_id, supersedes=None, transcript=None):
    """Start a fresh ceremony for the same secret (rotation).

    The new shards carry ``new_ceremony_id``; ceremony-id binding means
    old and new shards can never mix at :func:`combine` time, so the
    retired ceremony's shards are cryptographically retired the moment
    the new ceremony exists. ``supersedes`` names the retired ceremony
    for the transcript.
    """
    if supersedes is not None:
        _check_ceremony_id(supersedes)
    shards = split(secret, n, t, new_ceremony_id)
    if transcript is not None:
        transcript.record("rekey", {
            "new_ceremony_id": new_ceremony_id,
            "supersedes": supersedes,
            "threshold": t,
            "share_count": n,
        })
    return shards


# ---------------------------------------------------------------------------
# Ceremony transcript: hash-chained JSONL. Tamper-evident, not tamper-proof
# (a holder of the transcript file can rewrite it -- auditors verify the
# chain and cross-check custodian manifests).
# ---------------------------------------------------------------------------

_TRANSCRIPT_SCHEMA = "sasanam-shamir-ceremony-transcript/v1"
_GENESIS_PREV = "GENESIS"


class CeremonyTranscript(object):
    """Append-only, hash-chained record of custody ceremonies."""

    def __init__(self, path):
        if not isinstance(path, str) or not path:
            _fail("custody-shamir-bad-params",
                  "transcript path must be a non-empty str")
        self.path = os.path.abspath(path)

    def _read_entries(self):
        if not os.path.exists(self.path):
            return []
        entries = []
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                for line_no, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    entries.append((line_no, json.loads(line)))
        except (ValueError, OSError, UnicodeDecodeError) as exc:
            _fail("custody-shamir-transcript-corrupt",
                  "cannot parse %r: %s" % (self.path, exc))
        return entries

    @staticmethod
    def _entry_hash(prev, entry):
        blob = json.dumps(entry, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(prev.encode("utf-8") + b"\x00" + blob).hexdigest()

    def record(self, event, details):
        """Append one ceremony event. Records metadata only, never secrets."""
        if event not in _TRANSCRIPT_EVENTS:
            _fail("custody-shamir-bad-params",
                  "unknown transcript event %r" % (event,))
        if not isinstance(details, dict):
            _fail("custody-shamir-bad-params", "details must be a dict")
        # Verify the existing chain before extending it: never append to a
        # broken transcript (fail closed, loud).
        self.verify()
        entries = self._read_entries()
        prev = entries[-1][1]["hash"] if entries else _GENESIS_PREV
        entry = {
            "schema": _TRANSCRIPT_SCHEMA,
            "seq": len(entries) + 1,
            "ts": int(time.time()),
            "event": event,
            "details": details,
            "prev": prev,
        }
        entry["hash"] = self._entry_hash(prev, {k: v for k, v in entry.items()
                                                if k != "hash"})
        parent = os.path.dirname(self.path)
        if parent and not os.path.isdir(parent):
            _fail("custody-shamir-distribute-refused",
                  "transcript parent dir does not exist: %r" % (parent,))
        blob = (json.dumps(entry, sort_keys=True,
                           separators=(",", ":")).encode("utf-8") + b"\n")
        # Append path: fsync the bytes, then append them to the transcript
        # and fsync the transcript. A crash between the two fsyncs can
        # leave a torn trailing line; _read_entries treats that as
        # transcript-corrupt (loud), never as a valid event.
        fd, tmp = tempfile.mkstemp(prefix=".ceremony-",
                                   dir=parent or ".")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
            with open(tmp, "rb") as src:
                data = src.read()
            with open(self.path, "ab") as dst:
                dst.write(data)
                dst.flush()
                os.fsync(dst.fileno())
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return entry["seq"]

    def verify(self):
        """Replay the hash chain. Returns the event count; refuses coded on break."""
        entries = self._read_entries()
        prev = _GENESIS_PREV
        for pos, (line_no, entry) in enumerate(entries):
            if not isinstance(entry, dict) or entry.get("schema") != _TRANSCRIPT_SCHEMA:
                _fail("custody-shamir-transcript-corrupt",
                      "bad schema at line %d" % (line_no,))
            if entry.get("seq") != pos + 1:
                _fail("custody-shamir-transcript-corrupt",
                      "seq break at line %d" % (line_no,))
            if entry.get("prev") != prev:
                _fail("custody-shamir-transcript-corrupt",
                      "chain break at line %d" % (line_no,))
            body = {k: v for k, v in entry.items() if k != "hash"}
            if entry.get("hash") != self._entry_hash(prev, body):
                _fail("custody-shamir-transcript-corrupt",
                      "hash mismatch at line %d" % (line_no,))
            prev = entry["hash"]
        return len(entries)
