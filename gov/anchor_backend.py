"""Haber-Stornetta anchoring: witness backends for audit-chain checkpoints.

Wave-72. The HMAC chain proves ordering + outsider tamper-evidence, but the
key-holder can rewrite from genesis and nothing binds wall-clock time. This
module publishes signed chain-head statements to an external witness the
operator cannot rewrite, per ``workstreams/architect/ANCHOR_DESIGN.md``.

Load-bearing guarantee: "no undetected rewrite of history prior to the last
anchor" -- history after the last anchor is soft, and the anchor cadence is
the security parameter.

Contents:

* :class:`AnchorBackend` -- the interface: ``submit(anchor_hash) -> receipt``
  / ``verify_receipt(receipt, anchor_hash=...) -> (ok, reason)``. A receipt
  is an inclusion proof + witness time (+ backend identity).
* Anchor statements (v2, hash-only): :func:`build_statement`,
  :func:`sign_statement`, :func:`statement_hash`,
  :func:`verify_statement_sig`. ONLY hashes (+ the anchor pubkey, key id,
  and epoch wall window) exist in a statement -- never record contents.
* :class:`FakeWitness` -- deterministic in-process test double (same role
  as ``FakeKmsProvider``): proves the anchor FORMAT and the verification
  PATH, not a remote service. Controllable clock and down-mode for the
  failure-semantics tests. $0 spend, no network.
* :class:`LocalAnchorLog` -- file-backed, hash-chained anchor log behind
  the interface. HONESTLY NOT A WITNESS: same trust domain as the operator;
  for airgapped deployments that want the anchor format without a public log.
* :class:`RekorBackend` -- the real backend: Sigstore Rekor v1,
  ``hashedrekord`` 0.0.1 entries over stdlib ``urllib``. No new dependencies.
  The Rekor production-shard key is pinned (captured 2026-09-22); the log id
  is cross-checked at import against the published id.

Privacy: the only bytes that cross the witness boundary are the anchor hash,
the Ed25519 signature, and the anchor public key (all inside the hashedrekord
envelope). The statement itself never leaves -- only its hash does.
"""

import abc
import base64
import hashlib
import json
import os
import time
import urllib.request
from datetime import datetime, timezone

from . import ed25519 as _ed
from . import merkle as _merkle
from .digest_ref import DigestRef

ANCHOR_STATEMENT_VERSION = 2
GENESIS_ANCHOR = "GENESIS"

_STMT_DOMAIN = b"gov-anchor-statement/v2\x00"
_WITNESS_LEAF_DOMAIN = b"gov-anchor-witness-leaf/v1\x00"

# The statement fields that may appear in a signed anchor statement
# (statement hygiene: sign/verify reject anything outside this set, so no
# record content can smuggle into an anchor statement). The witness
# boundary itself is hash-only -- see AnchorBackend.submit.
_STATEMENT_FIELDS = frozenset({
    "anchor_version", "epoch_id", "seq", "start_seq", "head_hash",
    "merkle_root", "epoch_start_wall", "epoch_close_wall",
    "key_id", "pubkey_hex", "prev_anchor", "log_id", "sig",
})
_STATEMENT_REQUIRED = frozenset(_STATEMENT_FIELDS - {"merkle_root", "sig"})

# Pinned Rekor production shard (rekor.sigstore.dev, v1 API). Captured
# 2026-09-22 via GET /api/v1/log/publicKey (HTTP 200). If Sigstore rotates
# the shard key this constant must be re-captured; a mismatch fails closed
# (receipts rejected, the local chain unaffected).
REKOR_URL = "https://rekor.sigstore.dev"
# F203: the anchor signature shape RekorBackend emits and the only
# shape verify_receipt accepts -- Ed25519ph (RFC 8032 5.1, SHA-512
# prehash, empty context) over the 32-byte anchor hash, with the
# envelope declaring data.hash = sha512(anchor_hash). One constant so
# the emit label and the refuse-pin can never skew apart.
ANCHOR_ALGORITHM_ED25519PH_SHA512 = "ed25519ph-sha512"
REKOR_PUBKEY_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n"
    "kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n"
    "-----END PUBLIC KEY-----\n"
)
# Published log id (base64 sha256 of the SPKI DER), cross-checked at import.
REKOR_LOG_ID = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"


def _rekor_spki_der():
    b64 = "".join(
        ln.strip() for ln in REKOR_PUBKEY_PEM.splitlines()
        if ln and "BEGIN" not in ln and "END" not in ln)
    import base64 as _b64
    return _b64.b64decode(b64)


_computed_log_id = hashlib.sha256(_rekor_spki_der()).hexdigest()
if _computed_log_id != REKOR_LOG_ID:  # fail fast: the pin was edited
    raise ImportError(
        "pinned Rekor public key does not match REKOR_LOG_ID "
        "(key rotated or pin edited?)")

# Ed25519 SPKI DER prefix (RFC 8410): SEQUENCE { SEQUENCE { OID 1.3.101.112 }
# } ‖ BIT STRING. The 32-byte raw key is appended.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class WitnessError(Exception):
    """The witness refused or could not process a submission."""


class WitnessDownError(WitnessError):
    """The witness is unreachable (drives the async failure semantics)."""


def _utcnow():
    return datetime.now(timezone.utc).isoformat()


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def anchor_key_id(pubkey):
    """Key id for an anchor Ed25519 public key: sha256 hex (log_id idiom)."""
    return hashlib.sha256(bytes(pubkey)).hexdigest()


def anchor_pubkey(seed):
    """Ed25519 public key (32 bytes) for a 32-byte anchor seed."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("anchor seed must be 32 bytes")
    return _ed.publickey(bytes(seed))


def anchor_spki_pem(pubkey):
    """RFC 8410 SPKI PEM for a 32-byte Ed25519 public key (stdlib only)."""
    if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
        raise ValueError("anchor pubkey must be 32 bytes")
    der = _ED25519_SPKI_PREFIX + bytes(pubkey)
    b64 = base64.b64encode(der).decode("ascii")
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return "-----BEGIN PUBLIC KEY-----\n" + lines + "\n-----END PUBLIC KEY-----\n"


def build_statement(*, epoch_id, seq, start_seq, head_hash, merkle_root,
                    epoch_start_wall, epoch_close_wall, key_id, pubkey_hex,
                    prev_anchor=None, log_id):
    """Build the unsigned v2 anchor statement (hash-only, privacy-safe).

    Binds (epoch_id, seq, head_hash, epoch wall window) -- the fields the
    auditor needs. ``merkle_root`` may be None (unsigned/HMAC-only
    checkpoint). ``prev_anchor`` chains statements; None means GENESIS.
    """
    for name, value in (("epoch_id", epoch_id), ("head_hash", head_hash),
                        ("key_id", key_id), ("pubkey_hex", pubkey_hex),
                        ("log_id", log_id)):
        if not isinstance(value, str) or not value:
            raise ValueError("statement field %r must be a non-empty str"
                             % (name,))
    if not isinstance(seq, int) or not isinstance(start_seq, int):
        raise ValueError("seq/start_seq must be ints")
    return {
        "anchor_version": ANCHOR_STATEMENT_VERSION,
        "epoch_id": epoch_id,
        "seq": seq,
        "start_seq": start_seq,
        "head_hash": head_hash,
        "merkle_root": merkle_root,
        "epoch_start_wall": epoch_start_wall,
        "epoch_close_wall": epoch_close_wall,
        "key_id": key_id,
        "pubkey_hex": pubkey_hex,
        "prev_anchor": prev_anchor or GENESIS_ANCHOR,
        "log_id": log_id,
    }


def _sig_body(statement):
    body = {k: v for k, v in statement.items() if k != "sig"}
    return _STMT_DOMAIN + _canonical(body)


def sign_statement(statement, seed):
    """Ed25519-sign the statement with the 32-byte anchor seed.

    Returns a NEW dict with ``"sig"`` (hex). The signature covers the
    domain-separated canonical statement (minus ``sig``).
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("anchor seed must be 32 bytes")
    extra = set(statement) - _STATEMENT_FIELDS
    if extra:
        raise ValueError("statement carries non-allowlisted fields: %r"
                         % (sorted(extra),))
    missing = _STATEMENT_REQUIRED - set(statement)
    if missing:
        raise ValueError("statement missing required fields: %r"
                         % (sorted(missing),))
    if statement.get("anchor_version") != ANCHOR_STATEMENT_VERSION:
        raise ValueError("unsupported anchor_version")
    sig = _ed.sign(bytes(seed), _sig_body(statement)).hex()
    signed = dict(statement)
    signed["sig"] = sig
    return signed


def statement_hash(statement):
    """``anchor_hash``: sha256 over the domain-separated canonical statement
    (the ``sig`` field excluded -- the hash commits to the content, the
    signature is verified separately)."""
    return hashlib.sha256(_sig_body(statement)).hexdigest()


def verify_statement_sig(statement):
    """Verify the statement's Ed25519 signature under its ``pubkey_hex``.

    Returns (ok, reason); never raises on malformed input.
    """
    try:
        if not isinstance(statement, dict):
            return False, "statement is not an object"
        extra = set(statement) - _STATEMENT_FIELDS
        if extra:
            return False, "non-allowlisted statement fields: %r" % (
                sorted(extra),)
        if statement.get("anchor_version") != ANCHOR_STATEMENT_VERSION:
            return False, "unsupported anchor_version"
        pubkey = bytes.fromhex(statement["pubkey_hex"])
        sig = bytes.fromhex(statement["sig"])
        if len(pubkey) != 32 or len(sig) != 64:
            return False, "malformed pubkey/sig lengths"
        if _ed.verify(pubkey, _sig_body(statement), sig):
            return True, None
        return False, "statement signature invalid"
    except (KeyError, TypeError, ValueError) as e:
        return False, "malformed statement: %s" % (e,)


class AnchorBackend(abc.ABC):
    """A witness the operator cannot rewrite.

    ``submit`` takes the anchor hash (64-char hex) and returns the witness
    receipt (inclusion proof + witness time + backend identity). The
    backend NEVER sees the statement: the only bytes crossing the witness
    boundary are the anchor hash (+ the protocol-minimum signature and
    public key for Rekor's hashedrekord envelope). The full signed
    statement stays local, chained in the HMAC log's receipt record.
    ``verify_receipt`` answers: is this receipt a valid attestation FOR
    ``anchor_hash``? Returns ``(ok, reason)``; never raises on malformed
    input (fail-closed for auditors).
    """

    @abc.abstractmethod
    def submit(self, anchor_hash):
        """Submit an anchor hash; return the receipt dict.

        ``anchor_hash`` is a :class:`gov.digest_ref.DigestRef`
        (preferred -- a tag is unrepresentable as one) or a bare-hex
        ``str`` (strictly validated). Implementations must accept
        both.
        """

    @abc.abstractmethod
    def verify_receipt(self, receipt, *, anchor_hash):
        """(ok, reason): valid witness attestation for ``anchor_hash``?"""


def _check_anchor_hash(value):
    if not isinstance(value, str):
        raise WitnessError("anchor_hash must be a hex string")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise WitnessError("anchor_hash is not hex")
    if len(raw) != 32:
        raise WitnessError("anchor_hash must be 32 bytes (64 hex chars)")
    return value.lower()


def _coerce_anchor_hash(value, *, where):
    """Accept a :class:`DigestRef` or a bare-hex ``str`` anchor hash.

    Wave-199: DigestRef is the preferred (structural) form -- a tag is
    unrepresentable as one. The ``str`` form is kept for the abstract
    ``AnchorBackend`` contract (fake/file test doubles and existing
    callers); it goes through the same strict 32-byte-hex validation
    as before, so no new string shape is admitted. Returns the
    lowercase 64-hex string.
    """
    if isinstance(value, DigestRef):
        return value.hex
    if not isinstance(value, str):
        raise WitnessError(
            "%s: anchor_hash must be a DigestRef or hex str, got %s"
            % (where, type(value).__name__))
    return _check_anchor_hash(value)


def _verify_anchor_hash(value, *, where):
    """Coerce an anchor hash for the ``verify_receipt`` (auditor) path.

    Same :class:`DigestRef` | ``str`` contract as
    :func:`_coerce_anchor_hash`, but never raises: returns
    ``(True, hex)`` on success, ``(False, reason)`` on malformed
    input. The auditor path must stay fail-closed, not exceptional.
    """
    try:
        return True, _coerce_anchor_hash(value, where=where)
    except WitnessError as e:
        return False, "malformed anchor_hash: %s" % (e,)


def _witness_leaf(anchor_hash_hex):
    return hashlib.sha256(
        _WITNESS_LEAF_DOMAIN + bytes.fromhex(anchor_hash_hex)).digest()


class FakeWitness(AnchorBackend):
    """Deterministic in-process witness -- TEST DOUBLE.

    Owns an append-only Merkle tree over submitted anchor hashes (built with
    ``gov.merkle``). ``submit`` takes ONLY the anchor hash (the backend
    never sees the statement -- that is the privacy pin) and returns a
    receipt ``{backend, backend_id, anchor_hash, log_index, tree_size,
    inclusion_proof, log_root, witness_time}``. Re-submission of an
    identical hash is idempotent (checked FIRST, so a retry after a lost
    response returns the original receipt, never a duplicate leaf).

    ``clock``: zero-arg callable returning an ISO-8601 UTC string (inject a
    deterministic clock in tests). ``down``: when True, ``submit`` raises
    ``WitnessDownError`` (drives the async failure-semantics tests).

    Statement chaining (``prev_anchor``) is NOT enforced here -- the witness
    sees only hashes by design; the chain is enforced by the anchorer and
    verified by the auditor over the signed statements.

    This is NOT a network service and MUST NOT be mistaken for one: it
    proves the anchor FORMAT and the verification PATH, not a remote
    witness. A production deployment points at :class:`RekorBackend`.
    """

    def __init__(self, clock=None):
        self._clock = clock or _utcnow
        self._leaves = []
        self._receipts = []       # receipts in submission order
        self._by_hash = {}        # anchor_hash -> receipt (idempotency)
        self.down = False
        self.backend_id = hashlib.sha256(
            b"gov-fake-witness/v1\x00").hexdigest()

    def __len__(self):
        return len(self._receipts)

    def submit(self, anchor_hash):
        if self.down:
            raise WitnessDownError("fake witness is down")
        # Wave-199: same DigestRef|str contract as RekorBackend.
        ahash = _coerce_anchor_hash(anchor_hash, where="fake submit")
        if ahash in self._by_hash:  # idempotent re-submission FIRST
            return self._by_hash[ahash]
        self._leaves.append(_witness_leaf(ahash))
        log_index = len(self._receipts)
        proof = _merkle.inclusion_proof(self._leaves, log_index)
        receipt = {
            "backend": "fake-witness",
            "backend_id": self.backend_id,
            "anchor_hash": ahash,
            "log_index": log_index,
            "tree_size": log_index + 1,
            "inclusion_proof": [p.hex() for p in proof],
            "log_root": _merkle.tree_root(self._leaves).hex(),
            "witness_time": self._clock(),
        }
        self._receipts.append(receipt)
        self._by_hash[ahash] = receipt
        return receipt

    def verify_receipt(self, receipt, *, anchor_hash):
        # NOTE: the proof is verified against the receipt's OWN log_root
        # (self-contained), not this instance's tree: the fake witness is
        # a test double, so this proves the receipt FORMAT and the
        # verification PATH, not third-party attestation. The real
        # witness binding (pinned log id + TLS) lives in RekorBackend.
        # Wave-199: same DigestRef|str contract as submit; the
        # verify path never raises (auditor path).
        ok, ahash = _verify_anchor_hash(anchor_hash, where="fake verify")
        if not ok:
            return False, ahash
        try:
            if not isinstance(receipt, dict):
                return False, "receipt is not an object"
            if receipt.get("backend") != "fake-witness":
                return False, "receipt is not from the fake witness"
            if receipt.get("backend_id") != self.backend_id:
                return False, "receipt is from a different witness"
            if receipt.get("anchor_hash") != ahash:
                return False, "receipt is for a different anchor"
            proof = [bytes.fromhex(p)
                     for p in receipt["inclusion_proof"]]
            root = bytes.fromhex(receipt["log_root"])
            if not _merkle.verify_inclusion(
                    _witness_leaf(ahash), receipt["log_index"],
                    proof, root, receipt["tree_size"]):
                return False, "inclusion proof does not verify"
            # Witness-time sanity: parseable, not absurdly in the future.
            wt = datetime.fromisoformat(receipt["witness_time"])
            now = datetime.now(timezone.utc)
            if wt.tzinfo is None:
                wt = wt.replace(tzinfo=timezone.utc)
            if (wt - now).total_seconds() > 300:
                return False, "witness_time is in the future"
            return True, None
        except (KeyError, TypeError, ValueError) as e:
            return False, "malformed receipt: %s" % (e,)


class LocalAnchorLog(AnchorBackend):
    """File-backed, hash-chained anchor log -- HONESTLY NOT A WITNESS.

    Same trust domain as the operator: the operator can rewrite it, so it
    proves the anchor FORMAT and the verification PATH only. For airgapped
    deployments that want anchor-shaped evidence without a public log.
    Never present its receipts as third-party attestation.
    """

    def __init__(self, path):
        from pathlib import Path
        self.path = Path(path)

    def _chain(self):
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out

    def submit(self, anchor_hash):
        # Wave-199: same DigestRef|str contract as RekorBackend.
        ahash = _coerce_anchor_hash(anchor_hash, where="file submit")
        entries = self._chain()
        for e in entries:  # idempotent re-submission
            if e["anchor_hash"] == ahash:
                return e["receipt"]
        prev = entries[-1]["chain_hash"] if entries else GENESIS_ANCHOR
        chain_hash = hashlib.sha256(
            ("local-anchor/v1\x00%s|%s" % (prev, ahash)
             ).encode("utf-8")).hexdigest()
        receipt = {
            "backend": "local-anchor-log",
            "path": str(self.path),
            "index": len(entries),
            "anchor_hash": ahash,
            "witness_time": _utcnow(),
            "witness": "local-operator-clock (NOT an independent witness)",
            "chain_hash": chain_hash,
        }
        # The signed statement is NOT stored here: it lives in the HMAC
        # log's receipt record. This log holds hashes + receipts only.
        record = {"anchor_hash": ahash,
                  "receipt": receipt, "chain_hash": chain_hash,
                  "prev": prev}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=True, default=str)
                    + "\n")
            f.flush()
            os.fsync(f.fileno())
        return receipt

    def verify_receipt(self, receipt, *, anchor_hash):
        # Wave-199: same DigestRef|str contract as submit; the
        # verify path never raises (auditor path).
        ok, ahash = _verify_anchor_hash(anchor_hash, where="file verify")
        if not ok:
            return False, ahash
        try:
            if not isinstance(receipt, dict):
                return False, "receipt is not an object"
            if receipt.get("backend") != "local-anchor-log":
                return False, "not a local-anchor-log receipt"
            if receipt.get("anchor_hash") != ahash:
                return False, "receipt is for a different anchor"
            prev = GENESIS_ANCHOR
            found = False
            for line in self.path.read_text(
                    encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                expect = hashlib.sha256(
                    ("local-anchor/v1\x00%s|%s"
                     % (prev, e["anchor_hash"])).encode("utf-8")).hexdigest()
                if e["chain_hash"] != expect or e["prev"] != prev:
                    return False, "local anchor chain broken at index %r" % (
                        e["receipt"].get("index"),)
                prev = e["chain_hash"]
                if e["anchor_hash"] == ahash:
                    found = True
                    if e["receipt"] != receipt:
                        return False, "receipt does not match the log entry"
            if not found:
                return False, "anchor not present in the local log"
            return True, None
        except (OSError, KeyError, TypeError, ValueError) as e:
            return False, "malformed receipt/log: %s" % (e,)


def _rfc6962_root(leaf_data, leaf_index, proof_hashes, tree_size):
    """Recompute an RFC 6962 Merkle root from an inclusion proof.

    ``leaf_data``: the raw leaf bytes (NOT pre-hashed). ``proof_hashes``:
    sibling hashes, leaf level first (Rekor's ``hashes`` order); each may be
    32 bytes or a 64-char hex string. Returns the 32-byte root. Raises
    ValueError on malformed input.
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
    node = hashlib.sha256(b"\x00" + leaf).digest()

    def rec(i, n, end):
        # Root of the size-n subtree containing leaf i. The proof
        # hashes are leaf-level-first (Rekor's ``hashes`` order), so the
        # sibling at THIS (top) split is the LAST element of the
        # remaining slice ``proof[:end]`` -- the recursion consumes the
        # proof bottom-up. (The previous revision consumed it top-down,
        # which mis-paired siblings for every tree with size > 2 --
        # caught by the wave-72 closeout battery.)
        if n == 1:
            return node, end  # the leaf itself; consumes nothing
        # Largest power of two < n (RFC 6962 split point).
        k = 1
        while 2 * k < n:
            k *= 2
        if end <= 0:
            raise ValueError("proof too short")
        sib = proof[end - 1]
        if i < k:
            left, nxt = rec(i, k, end - 1)
            return (hashlib.sha256(b"\x01" + left + sib).digest(), nxt)
        right, nxt = rec(i - k, n - k, end - 1)
        return (hashlib.sha256(b"\x01" + sib + right).digest(), nxt)

    root, remaining = rec(index, size, len(proof))
    if remaining != 0:
        raise ValueError("proof length mismatch")
    return root


class RekorBackend(AnchorBackend):
    """Sigstore Rekor v1 backend (``hashedrekord`` 0.0.1), stdlib only.

    Submits the anchor hash (never the statement, never record contents)
    with the anchor key's Ed25519ph signature over the 32-byte digest --
    hashedrekord exists for exactly this shape -- and the anchor pubkey as
    PEM SPKI. ``transport`` is an injectable
    ``fn({"method","url","headers","body"}) -> {"status","body"}`` for the
    deterministic suite (which never touches the network); the default
    transport is real ``urllib`` HTTPS.

    Anchor signature shape (F203, closed 2026-09-29, wave-198): Ed25519ph
    (RFC 8032 section 5.1) with SHA-512 as the prehash, empty context --
    the ONLY Ed25519 shape real Rekor v1.5.x's hashedrekord accepts
    (its verifier is built with sigstore's WithED25519ph()). Raw
    Ed25519 is dead against the real service (HTTP 400
    ``unsupported hash algorithm: "SHA-256" not in [SHA-512]``) and is
    no longer emitted anywhere on this path.
    """

    def __init__(self, url=REKOR_URL, transport=None, clock=None,
                 rekor_pubkey_pem=REKOR_PUBKEY_PEM, log_id=REKOR_LOG_ID,
                 anchor_seed=None, anchor_pubkey=None):
        self.url = url.rstrip("/")
        self._transport = transport or self._urllib_transport
        self._clock = clock or _utcnow
        self.rekor_pubkey_pem = rekor_pubkey_pem
        self.log_id = log_id
        # The anchor Ed25519 seed + public key (executor-side custody, same
        # trust domain as the anchorer that constructed this backend).
        # Hashedrekord needs a signature over the digest and the public key
        # in the envelope, so both live here -- the SUBMIT interface still
        # takes only the anchor hash; the statement never crosses.
        if anchor_seed is not None and (
                not isinstance(anchor_seed, (bytes, bytearray))
                or len(anchor_seed) != 32):
            raise ValueError("anchor_seed must be 32 bytes")
        self._anchor_seed = bytes(anchor_seed) if anchor_seed else None
        if anchor_pubkey is not None:
            if isinstance(anchor_pubkey, str):
                try:
                    anchor_pubkey = bytes.fromhex(anchor_pubkey)
                except ValueError:
                    raise ValueError("anchor_pubkey hex is malformed")
            if not isinstance(anchor_pubkey, (bytes, bytearray)) \
                    or len(anchor_pubkey) != 32:
                raise ValueError("anchor_pubkey must be 32 bytes")
            anchor_pubkey = bytes(anchor_pubkey)
        self._anchor_pubkey = anchor_pubkey

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
            raise WitnessDownError(
                "rekor HTTP %s: %s" % (e.code, detail))
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise WitnessDownError("rekor unreachable: %s" % (e,))

    def _entries_url(self):
        return self.url + "/api/v1/log/entries"

    def submit(self, anchor_hash):
        # Privacy pin, structural: the ONLY inputs are the anchor hash and
        # the construction-time key material. The statement (epoch
        # metadata, wall times) is never in scope here -- it stays local,
        # chained in the HMAC log's receipt record.
        #
        # Wave-199: anchor_hash is a DigestRef (preferred -- a tag is
        # unrepresentable as one) or a bare-hex str (kept for the
        # abstract contract; strictly validated, no new shape admitted).
        ahash = _coerce_anchor_hash(anchor_hash, where="rekor submit")
        if self._anchor_seed is None or self._anchor_pubkey is None:
            raise WitnessError(
                "rekor submit needs anchor_seed + anchor_pubkey "
                "(executor-side custody)")
        # The hashedrekord signature is over the 32-byte anchor hash (the
        # type exists for digest-only artifacts) -- a protocol-minimum
        # envelope field, not statement content. Ed25519ph (prehashed,
        # SHA-512, empty context): the only Ed25519 shape Rekor v1.5.x
        # accepts for hashedrekord (F203 -- raw Ed25519 is rejected
        # with HTTP 400).
        #
        # Envelope-hash subtlety (measured live against Rekor v1.5.4,
        # 2026-09-29): the entry's verifier is built with sigstore's
        # WithED25519ph() and called with WithDigest(decoded) +
        # WithCryptoSignerOpts(artifactAlg). The ph verifier allow-lists
        # ONLY SHA-512 as the hash, so the envelope MUST declare
        # data.hash.algorithm = "sha512" (a "sha256" declaration dies
        # with `unsupported hash algorithm: "SHA-256" not in [SHA-512]`
        # before any signature math). The declared digest is
        # SHA-512(anchor_hash); the SIGNATURE is Ed25519ph over the
        # 32-byte anchor hash itself -- the verifier treats the passed
        # digest as the already-computed PH(M) (no double hash), so
        # sign_ph(seed, anchor_hash) is the shape that verifies
        # (sign_ph(seed, sha512(anchor_hash)) is rejected as invalid).
        digest = bytes.fromhex(ahash)
        d512 = hashlib.sha512(digest).hexdigest()
        digest_sig = _ed.sign_ph(self._anchor_seed, digest)
        proposed = {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "content": base64.b64encode(digest_sig).decode("ascii"),
                    "publicKey": {
                        "content": base64.b64encode(
                            anchor_spki_pem(
                                self._anchor_pubkey).encode("ascii")
                        ).decode("ascii"),
                    },
                },
                "data": {
                    "hash": {"algorithm": "sha512", "value": d512},
                },
            },
        }
        resp = self._transport({
            "method": "POST",
            "url": self._entries_url(),
            "headers": {"Content-Type": "application/json",
                        "Accept": "application/json"},
            "body": json.dumps(proposed, separators=(",", ":")),
        })
        if resp["status"] not in (200, 201):
            raise WitnessDownError(
                "rekor rejected the entry: HTTP %s" % (resp["status"],))
        try:
            entries = json.loads(resp["body"])
            uuid, entry = next(iter(entries.items()))
        except (ValueError, StopIteration) as e:
            raise WitnessError("unparseable rekor response: %s" % (e,))
        return self._receipt_from_entry(uuid, entry, ahash)

    def _receipt_from_entry(self, uuid, entry, ahash):
        verification = entry.get("verification", {})
        proof = verification.get("inclusionProof", {})
        return {
            "backend": "rekor-v1",
            "url": self.url,
            "uuid": uuid,
            "log_index": entry.get("logIndex"),
            "log_id": entry.get("logID"),
            "anchor_hash": ahash,
            # The anchor signature shape that produced this entry.
            # Descriptive (the inclusion proof is the verified core);
            # verify_receipt refuses receipts claiming an unknown shape.
            "anchor_algorithm": ANCHOR_ALGORITHM_ED25519PH_SHA512,
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
            # Boundary (wave-72): the SET's ECDSA P-256 signature is
            # CARRIED, not verified -- no ECDSA in the tree. The verified
            # core is the inclusion proof + pinned log_id + TLS. Wave-73
            # question: P-256 SET verification or the v2 Ed25519 shard.
            "set_verified": False,
            "submitted_at": self._clock(),
        }

    def verify_receipt(self, receipt, *, anchor_hash):
        # Wave-199: accept DigestRef or bare-hex str (same coercion
        # as submit); the receipt stores the lowercase hex form. The
        # verify path never raises (auditor path).
        ok, ahash = _verify_anchor_hash(anchor_hash, where="rekor verify")
        if not ok:
            return False, ahash
        try:
            if not isinstance(receipt, dict):
                return False, "receipt is not an object"
            if receipt.get("backend") != "rekor-v1":
                return False, "not a rekor-v1 receipt"
            if receipt.get("anchor_hash") != ahash:
                return False, "receipt is for a different anchor"
            if receipt.get("log_id") != self.log_id:
                return False, "receipt is from a different transparency log"
            # Anchor-shape pin: a receipt with no label is accepted iff
            # its body carries the F203 shape (sha512 declaration
            # below); a receipt CLAIMING an unknown shape is refused
            # (fail-closed on what we don't understand). Pre-F203
            # receipts (sha256-declared bodies) are refused by the
            # shape check below -- the raw-Ed25519 path is repaired
            # throughout, not kept alive for old receipts.
            algo = receipt.get("anchor_algorithm")
            if algo is not None and \
                    algo != ANCHOR_ALGORITHM_ED25519PH_SHA512:
                return False, "receipt claims unknown anchor algorithm"
            body = base64.b64decode(receipt["body"])
            entry = json.loads(body.decode("utf-8"))
            try:
                halg = entry["spec"]["data"]["hash"]["algorithm"]
                value = entry["spec"]["data"]["hash"]["value"]
            except (KeyError, TypeError):
                return False, "entry body has no data.hash"
            # F203 shape: the envelope declares the SHA-512 of the
            # 32-byte anchor hash (the only declaration Rekor v1.5.x's
            # Ed25519ph verifier accepts).
            if halg != "sha512":
                return False, "entry body hash algorithm != sha512"
            if value != hashlib.sha512(
                    bytes.fromhex(ahash)).hexdigest():
                return False, "entry body hash != sha512(anchor_hash)"
            # The envelope signature binds the anchor key to the entry:
            # Ed25519ph over the 32-byte anchor hash (the shape Rekor
            # itself verified at submission; re-checked here so the
            # receipt is self-contained and does not rely transitively
            # on the server's past verification).
            try:
                sig = base64.b64decode(
                    entry["spec"]["signature"]["content"])
            except (KeyError, TypeError, ValueError):
                return False, "entry body has no signature"
            if not _ed.verify_ph(self._anchor_pubkey,
                                 bytes.fromhex(ahash), sig):
                return False, "anchor signature does not verify"
            proof = receipt["inclusion_proof"]
            root = _rfc6962_root(
                body, proof["log_index"], proof["hashes"],
                proof["tree_size"])
            if root.hex() != proof["root_hash"]:
                return False, "inclusion proof does not verify"
            it = receipt["integrated_time"]
            if not isinstance(it, int) or it <= 0:
                return False, "integrated_time malformed"
            if it > int(time.time()) + 300:
                return False, "integrated_time is in the future"
            if not receipt.get("uuid") or not receipt.get(
                    "signed_entry_timestamp"):
                return False, "receipt missing uuid/SET"
            return True, None
        except (KeyError, TypeError, ValueError) as e:
            return False, "malformed receipt: %s" % (e,)
