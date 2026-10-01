"""Static transparency log for evidence-bundle digests.

Adapted from the certificate-transparency pattern
(google/certificate-transparency-go, Apache-2.0 -- pattern only, no
code copied): an append-only Merkle-chained log of bundle digests
with inclusion proofs any auditor can check offline, signed tree
heads (STH), and consistency proofs for the append-only guarantee.
Built on ``gov/merkle.py`` (RFC 6962 history tree) and
``gov/ed25519.py`` (pure-Python RFC 8032); stdlib only, no network,
no external keys.

Static means there is no log server. The log is a directory of flat
files (``leaves.jsonl`` + ``heads.jsonl`` + ``LOG_ID``) that can sit
on object storage, mirroring the wave-257 sunlight static-log
architecture: the operator appends locally and publishes new signed
tree heads; auditors verify inclusion and consistency offline from a
head, a proof, and the log's public key.

Public seam::

    TransparencyLog(path, signing_key=None, public_key=None)
      .append(bundle_digest_hex, appended_at=None) -> signed tree head
      .inclusion_proof(bundle_digest_hex, tree_size=None) -> proof dict
      .consistency_proof(old_size, new_size=None) -> proof dict
      .latest_head() -> head dict
      .heads() -> [head dict]
      .verify_log(expected_size=None, expected_head=None)
          -> (ok, detail)
      .detect_equivocation(heads=None, strict=False) -> [conflict dicts]
    verify_tree_head(tree_head, log_pubkey_hex) -> bool
    verify_inclusion(bundle_digest_hex, proof, tree_head,
                     log_pubkey_hex=None) -> bool
    verify_consistency(old_head, new_head, proof,
                       log_pubkey_hex=None) -> bool

The module-level ``verify_*`` functions are stdlib-only and import
nothing beyond this file's two stdlib-only siblings (``gov/merkle.py``,
``gov/ed25519.py``). An auditor without the engine copies those three
files flat into one directory and runs the documented offline recipe
(see ``OFFLINE_RECIPE``): the ``try/except ImportError`` below falls
back to flat imports when there is no ``gov`` package.

What the log proves (and does not prove) -- the same honesty
standard as the Rekor note in our conventions:

* PROVES: a bundle digest was appended at a numbered position in an
  append-only sequence; a signed tree head commits to every digest up
  to its tree size; inclusion of a digest at tree size N is checkable
  offline from the digest, the proof, the head, and the log's public
  key; a newer head extends an older one (consistency proof).
* DOES NOT PROVE:
  - Authorization: the log records that a digest was submitted, not
    that the submitter was allowed to submit it.
  - Truth: a verified inclusion proves the digest was logged, not
    that the bundle's claims are correct ("integrity is not truth",
    same as the offline evidence bundle).
  - Publication: inclusion proves the digest is in the operator's
    log, not that anyone else has ever seen it.
  - A single view: a malicious operator can sign two different heads
    at the same tree size (equivocation / split view). This module
    DETECTS equivocation among the heads it is shown
    (:meth:`TransparencyLog.detect_equivocation`, signature-verified
    heads only) but cannot prevent it: witnesses must compare signed
    heads out-of-band, e.g. via
    :meth:`TransparencyLog.verify_log`'s ``expected_head`` /
    ``expected_size`` witnessed-state comparison. There is
    deliberately no in-repo gossip protocol (cf. ``gov/merkle.py``);
    claiming otherwise would overstate the design.
  - Tail truncation: with no witnessed state, ``verify_log()`` is a
    self-consistency check only -- a truncated-but-internally-
    consistent log verifies True. Shrinking the log below a
    previously witnessed size IS detectable, keylessly, with
    ``verify_log(expected_head=...)`` / ``expected_size=...``.
* Timestamps are operator wall-clock. Monotonicity is enforced on
  append (backdated appends are refused) but the clock itself is
  trusted -- a lying clock is outside this module's threat model.
* Duplicate digests are legal (CT semantics); ``inclusion_proof``
  returns the FIRST index. v1 writes one signed head per append (no
  batching); head tree sizes therefore run 1..n.

$0 spend, synthetic/local only. No network.
"""

import json
import os
from datetime import datetime, timezone

try:  # in-repo: package-relative imports
    from . import ed25519 as _ed
    from . import merkle as _merkle
except ImportError:  # standalone: the three files copied flat, no gov package
    import ed25519 as _ed  # noqa: F401
    import merkle as _merkle  # noqa: F401


LEAVES_FILE = "leaves.jsonl"
HEADS_FILE = "heads.jsonl"
LOG_ID_FILE = "LOG_ID"

#: Domain separation for the leaf record preimage (nested inside
#: gov/merkle.py's own leaf domain via merkle.leaf_hash).
LEAF_RECORD_DOMAIN = b"transparency-log-leaf/v1\x00"
#: Domain separation for the signed-tree-head signature body.
STH_SIGN_DOMAIN = b"transparency-log-sth/v1\x00"

OFFLINE_RECIPE = """\
Offline verification without the engine (auditor side):
  1. Copy gov/transparency_log.py, gov/merkle.py, gov/ed25519.py flat
     into one directory (all three are stdlib-only).
  2. Obtain out-of-band: the log's public key (LOG_ID, 64 hex chars),
     a signed tree head (one JSON object from heads.jsonl), and an
     inclusion proof JSON for the bundle digest.
  3. Recompute the bundle digest exactly as the anchorer did
     (gov/safeguard_bundle.compute_bundle_digest: sha256 over sorted
     relative paths as rel + NUL + content + NUL).
  4. verify_tree_head(head, log_pubkey_hex) must be True.
  5. verify_inclusion(digest_hex, proof, head, log_pubkey_hex) must
     be True -- this re-checks the head signature and the Merkle
     audit path. No log access, no engine, no network.
"""


class TransparencyLogError(Exception):
    """The transparency log cannot honestly do what was asked.

    Plain human messages (no machine codes): this module adds no
    entries to the decision-code taxonomy.
    """


def _canonical(obj):
    """JCS-shaped canonical bytes (same form as gov/offline_bundle.py)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _check_digest(digest):
    if not isinstance(digest, str) or len(digest) != 64:
        raise TransparencyLogError(
            "bundle digest must be 64 hex chars, got %r" % (digest,))
    try:
        raw = bytes.fromhex(digest)
    except ValueError:
        raise TransparencyLogError(
            "bundle digest is not valid hex: %r" % (digest,))
    if digest != digest.lower():
        raise TransparencyLogError(
            "bundle digest must be lowercase hex: %r" % (digest,))
    return raw


def _utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ts(value):
    if not isinstance(value, str):
        raise TransparencyLogError(
            "appended_at must be an ISO-8601 string, got %r" % (value,))
    text = value.strip()
    try:
        dt = datetime.fromisoformat(
            text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError:
        raise TransparencyLogError(
            "appended_at is not parseable ISO-8601: %r" % (value,))
    if dt.tzinfo is None:
        raise TransparencyLogError(
            "appended_at must carry a timezone: %r" % (value,))
    return dt


def _leaf_record(index, digest, appended_at):
    return {"index": index, "digest": digest, "appended_at": appended_at}


def _leaf_hash(index, digest, appended_at):
    """Leaf hash committing to position, digest, and timestamp."""
    _check_digest(digest)
    if not isinstance(index, int) or index < 0:
        raise TransparencyLogError(
            "leaf index must be a non-negative int, got %r" % (index,))
    _parse_ts(appended_at)  # fail fast on unparseable timestamps
    return _merkle.leaf_hash(
        LEAF_RECORD_DOMAIN + _canonical(
            _leaf_record(index, digest, appended_at)))


def _sth_body(head):
    """The exact bytes the STH signature covers (head minus signature)."""
    return STH_SIGN_DOMAIN + _canonical({
        "log_id": head["log_id"],
        "tree_size": head["tree_size"],
        "root_hash": head["root_hash"],
        "timestamp": head["timestamp"],
    })


class TransparencyLog(object):
    """An append-only static log of bundle digests.

    ``path`` is the log directory. ``signing_key`` is the 32-byte
    Ed25519 seed of the log operator (operator mode: append allowed).
    ``public_key`` is the 32-byte Ed25519 public key (auditor mode:
    append refused). With neither, the log opens read-only.
    """

    def __init__(self, path, signing_key=None, public_key=None):
        self._path = str(path)
        self._seed = None
        if signing_key is not None:
            seed = bytes(signing_key)
            if len(seed) != 32:
                raise TransparencyLogError(
                    "signing_key is not a 32-byte Ed25519 seed")
            self._seed = seed
            expect_pub = bytes(_ed.publickey(seed))
        elif public_key is not None:
            expect_pub = bytes(public_key)
            if len(expect_pub) != 32:
                raise TransparencyLogError(
                    "public_key is not 32 bytes")
        else:
            expect_pub = None

        log_id_path = os.path.join(self._path, LOG_ID_FILE)
        if not os.path.isfile(log_id_path):
            # Fresh log (or an empty directory): initializing a log is
            # an operator act -- it requires the signing key.
            if self._seed is None:
                raise TransparencyLogError(
                    "no log at %r and no signing_key: refusing to "
                    "create a log nobody can append to" % (self._path,))
            if not os.path.isdir(self._path):
                try:
                    os.makedirs(self._path)
                except OSError as e:
                    raise TransparencyLogError(
                        "cannot create log directory %r: %s"
                        % (self._path, e))
            try:
                with open(log_id_path, "w",
                          encoding="utf-8") as f:
                    f.write(expect_pub.hex() + "\n")
            except OSError as e:
                raise TransparencyLogError(
                    "cannot write %s: %s" % (LOG_ID_FILE, e))
        try:
            with open(log_id_path, encoding="utf-8") as f:
                log_id = f.read().strip()
        except OSError as e:
            raise TransparencyLogError(
                "cannot read %s: %s" % (LOG_ID_FILE, e))
        _check_digest(log_id)
        if expect_pub is not None and expect_pub.hex() != log_id:
            raise TransparencyLogError(
                "key does not match this log's identity: refusing to "
                "mix logs under one directory (key confusion)")
        self._log_id = log_id

        self._leaves = []
        leaves_path = os.path.join(self._path, LEAVES_FILE)
        if os.path.lexists(leaves_path) and not os.path.isfile(
                leaves_path):
            raise TransparencyLogError(
                "%s exists but is not a regular file: storage is "
                "corrupt" % (LEAVES_FILE,))
        if os.path.isfile(leaves_path):
            try:
                with open(leaves_path, encoding="utf-8") as f:
                    leaf_lines = f.read().splitlines()
            except OSError as e:
                raise TransparencyLogError(
                    "cannot read %s: %s" % (LEAVES_FILE, e))
            for lineno, line in enumerate(leaf_lines, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    raise TransparencyLogError(
                        "leaves.jsonl line %d is not JSON: "
                        "storage is corrupt" % (lineno,))
                self._leaves.append(rec)
        self._stack = _merkle.MerkleStack()
        for rec in self._leaves:
            try:
                self._stack.append(_leaf_hash(
                    rec["index"], rec["digest"], rec["appended_at"]))
            except (KeyError, TypeError, TransparencyLogError) as e:
                raise TransparencyLogError(
                    "leaves.jsonl entry %r is malformed: %s "
                    "(storage is corrupt)" % (rec, e))

        self._heads = []
        heads_path = os.path.join(self._path, HEADS_FILE)
        if os.path.lexists(heads_path) and not os.path.isfile(
                heads_path):
            raise TransparencyLogError(
                "%s exists but is not a regular file: storage is "
                "corrupt" % (HEADS_FILE,))
        if os.path.isfile(heads_path):
            try:
                with open(heads_path, encoding="utf-8") as f:
                    head_lines = f.read().splitlines()
            except OSError as e:
                raise TransparencyLogError(
                    "cannot read %s: %s" % (HEADS_FILE, e))
            for lineno, line in enumerate(head_lines, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    head = json.loads(line)
                except ValueError:
                    raise TransparencyLogError(
                        "heads.jsonl line %d is not JSON: storage "
                        "is corrupt" % (lineno,))
                if not isinstance(head, dict):
                    raise TransparencyLogError(
                        "heads.jsonl line %d is not an object: "
                        "storage is corrupt" % (lineno,))
                self._heads.append(head)

    # -- operator ----------------------------------------------------

    def append(self, bundle_digest, appended_at=None):
        """Append one bundle digest; return the new signed tree head.

        ``appended_at`` defaults to now (UTC, operator wall-clock).
        Timestamps must be monotonically non-decreasing: a backdated
        append is refused. Duplicate digests are legal (CT semantics).
        """
        if self._seed is None:
            raise TransparencyLogError(
                "this log was opened without the signing key: append "
                "is refused")
        _check_digest(bundle_digest)
        ts = appended_at if appended_at is not None else _utcnow()
        _parse_ts(ts)
        if self._leaves:
            last_ts = _parse_ts(self._leaves[-1]["appended_at"])
            if _parse_ts(ts) < last_ts:
                raise TransparencyLogError(
                    "refusing backdated append: appended_at %r is "
                    "older than the log tip %r"
                    % (ts, self._leaves[-1]["appended_at"]))
        index = len(self._leaves)
        rec = _leaf_record(index, bundle_digest, ts)
        try:
            with open(os.path.join(self._path, LEAVES_FILE), "a",
                      encoding="utf-8") as f:
                f.write(_canonical(rec).decode("utf-8") + "\n")
        except OSError as e:
            raise TransparencyLogError(
                "cannot append to %s: %s" % (LEAVES_FILE, e))
        self._leaves.append(rec)
        self._stack.append(_leaf_hash(index, bundle_digest, ts))

        head = {
            "log_id": self._log_id,
            "tree_size": index + 1,
            "root_hash": self._stack.root().hex(),
            "timestamp": _utcnow(),
        }
        sig = _ed.sign(self._seed, _sth_body(head))
        head["signature"] = bytes(sig).hex()
        try:
            with open(os.path.join(self._path, HEADS_FILE), "a",
                      encoding="utf-8") as f:
                f.write(_canonical(head).decode("utf-8") + "\n")
        except OSError as e:
            raise TransparencyLogError(
                "cannot append to %s: %s" % (HEADS_FILE, e))
        self._heads.append(head)
        return dict(head)

    # -- proofs (prover side; fail-fast on misuse) --------------------

    def _leaf_hashes(self, size):
        return [_leaf_hash(r["index"], r["digest"], r["appended_at"])
                for r in self._leaves[:size]]

    def inclusion_proof(self, bundle_digest, tree_size=None):
        """Build the inclusion proof for a digest (first index on
        duplicates). ``tree_size`` defaults to the current log size;
        the proof is bound to that size -- it verifies only against a
        head with the same tree size."""
        _check_digest(bundle_digest)
        index = None
        for r in self._leaves:
            if r["digest"] == bundle_digest:
                index = r["index"]
                break
        if index is None:
            raise TransparencyLogError(
                "digest %s... is not in this log: no proof to build"
                % (bundle_digest[:16],))
        size = len(self._leaves) if tree_size is None else tree_size
        if (not isinstance(size, int) or isinstance(size, bool)
                or not (0 < size <= len(self._leaves))):
            raise TransparencyLogError(
                "tree_size out of range: %r" % (tree_size,))
        if not (index < size):
            raise TransparencyLogError(
                "digest is at index %d which is not covered by tree "
                "size %d" % (index, size))
        path = _merkle.inclusion_proof(self._leaf_hashes(size), index)
        return {"leaf_index": index,
                "tree_size": size,
                "appended_at": self._leaves[index]["appended_at"],
                "path": [p.hex() for p in path]}

    def consistency_proof(self, old_size, new_size=None):
        """Build the proof that the tree at ``old_size`` is a prefix of
        the tree at ``new_size`` (default: current size) -- the
        append-only guarantee."""
        n = len(self._leaves)
        new = n if new_size is None else new_size
        for name, v in (("old_size", old_size), ("new_size", new)):
            if (not isinstance(v, int) or isinstance(v, bool)
                    or not (0 <= v <= n)):
                raise TransparencyLogError(
                    "%s out of range: %r" % (name, v))
        if not (old_size <= new):
            raise TransparencyLogError(
                "old_size %d is newer than new_size %d"
                % (old_size, new))
        nodes = _merkle.consistency_proof(self._leaf_hashes(new),
                                          old_size)
        return {"old_size": old_size, "new_size": new,
                "nodes": [x.hex() for x in nodes]}

    # -- reads ---------------------------------------------------------

    def latest_head(self):
        if not self._heads:
            raise TransparencyLogError("the log is empty: no tree head")
        return dict(self._heads[-1])

    def heads(self):
        return [dict(h) for h in self._heads]

    # -- audit ---------------------------------------------------------

    def verify_log(self, expected_size=None, expected_head=None):
        """Full self-audit: recompute everything from leaves.jsonl.

        Checks leaf indexes are 0..n-1, digests well-formed,
        timestamps parse and are monotonic, every head's tree size
        runs 1..n with the recomputed root, every head signature
        verifies under the log key, and every head's log_id matches.

        Witnessed-state comparison (the tail-truncation detector):
        pass a previously witnessed ``expected_head`` (a signed tree
        head seen out-of-band) or a witnessed ``expected_size``. The
        witnessed head's signature is re-verified under this log's
        key -- keyless, since the log_id IS the public key, so an
        auditor needs no signing key. Returns (False, reason) when
        the current log is shorter than the witnessed state (the tail
        was deleted, or the witness saw a divergent view), when the
        witnessed head does not verify, or when the witnessed head's
        root disagrees with the current log's prefix at that size
        (history rewritten or forked view). An unverifiable witnessed
        head is never treated as witnessed state.

        Honest residual: with no witnessed state this is a
        self-consistency check only -- a truncated-but-internally-
        consistent log verifies True. Detecting shrinkage needs a
        witness.

        Returns (True, detail) / (False, reason); never raises on
        corrupt data. Misuse of the witnessed-state arguments (a
        non-int/negative ``expected_size``, or ``expected_size``
        disagreeing with the witnessed head's tree size) raises
        TransparencyLogError.
        """
        witness = self._check_witness_args(expected_size,
                                           expected_head)
        try:
            return self._verify_log_inner(witness)
        except TransparencyLogError as e:
            return False, str(e)
        except (OSError, ValueError, KeyError, TypeError) as e:
            return False, "log unreadable: %s: %s" % (
                type(e).__name__, e)

    def _check_witness_args(self, expected_size, expected_head):
        """Validate witnessed-state arguments for verify_log.

        Argument misuse (programming error) raises
        TransparencyLogError. An unverifiable witnessed head is
        *data*, not misuse: it is reported in the verdict, never
        treated as witnessed state. Returns None when no witnessed
        state was given, else a dict with keys ``verified`` (bool),
        ``size`` (int) and ``root`` (hex str or None).
        """
        head_ok = True
        head_size = head_root = None
        if expected_head is not None:
            # verify_tree_head never raises; a bad witness is data.
            if verify_tree_head(expected_head, self._log_id):
                head_size = expected_head["tree_size"]
                head_root = expected_head["root_hash"]
            else:
                head_ok = False
        size = head_size
        if expected_size is not None:
            if (not isinstance(expected_size, int)
                    or isinstance(expected_size, bool)
                    or expected_size < 0):
                raise TransparencyLogError(
                    "expected_size must be a non-negative int, got %r"
                    % (expected_size,))
            if head_size is not None and expected_size != head_size:
                raise TransparencyLogError(
                    "expected_size %d disagrees with the witnessed "
                    "head's tree_size %d"
                    % (expected_size, head_size))
            size = expected_size
        if expected_head is None and expected_size is None:
            return None
        return {"verified": head_ok, "size": size, "root": head_root}

    def _witness_check(self, witness, n):
        """Compare the current log against witnessed state.

        Returns None when there is nothing to report, else the
        (False, reason) verdict. Only called after the internal
        self-audit passed, so the leaves are well-formed.
        """
        if witness is None:
            return None
        if not witness["verified"]:
            return (False,
                    "the witnessed head does not verify under this "
                    "log's key: refusing to compare against "
                    "unverifiable witnessed state")
        m = witness["size"]
        if n < m:
            return (False,
                    "log holds %d leaves but the witnessed state "
                    "commits to tree size %d: the log shrank (tail "
                    "deleted) or the witness saw a divergent view"
                    % (n, m))
        if witness["root"] is not None:
            prefix = _merkle.MerkleStack()
            for h in self._leaf_hashes(m):
                prefix.append(h)
            prefix_root = prefix.root().hex()
            if prefix_root != witness["root"]:
                return (False,
                        "witnessed head at tree size %d commits to "
                        "root %s... but the current log's prefix at "
                        "that size recomputes %s...: history was "
                        "rewritten or the witness saw a forked view"
                        % (m, witness["root"][:16],
                           prefix_root[:16]))
        return None

    def _verify_log_inner(self, witness=None):
        n = len(self._leaves)
        prev_ts = None
        for pos, rec in enumerate(self._leaves):
            if not isinstance(rec, dict):
                return False, "leaf %d is not an object" % pos
            if rec.get("index") != pos:
                return False, (
                    "leaf %d has index %r: not contiguous 0..n-1"
                    % (pos, rec.get("index")))
            try:
                _check_digest(rec["digest"])
                ts = _parse_ts(rec["appended_at"])
            except TransparencyLogError as e:
                return False, "leaf %d malformed: %s" % (pos, e)
            if prev_ts is not None and ts < prev_ts:
                return False, (
                    "leaf %d timestamp goes backwards" % pos)
            prev_ts = ts
        if len(self._heads) != n:
            return False, (
                "expected one head per append (%d leaves, %d heads)"
                % (n, len(self._heads)))
        check = _merkle.MerkleStack()
        for i, head in enumerate(self._heads):
            size = i + 1
            rec = self._leaves[i]
            check.append(_leaf_hash(rec["index"], rec["digest"],
                                   rec["appended_at"]))
            if not isinstance(head, dict):
                return False, "head %d is not an object" % size
            if head.get("tree_size") != size:
                return False, (
                    "head %d claims tree_size %r"
                    % (size, head.get("tree_size")))
            if head.get("root_hash") != check.root().hex():
                return False, (
                    "head at tree size %d commits to a different root "
                    "than the leaves recompute: history was rewritten"
                    % size)
            if head.get("log_id") != self._log_id:
                return False, (
                    "head at tree size %d carries a foreign log_id"
                    % size)
            if not verify_tree_head(head, self._log_id):
                return False, (
                    "head at tree size %d has a bad signature" % size)
        witness_verdict = self._witness_check(witness, n)
        if witness_verdict is not None:
            return witness_verdict
        if n == 0:
            return True, "empty log: nothing to check"
        return True, "ok: %d leaves, %d heads verify" % (n, n)

    def detect_equivocation(self, heads=None, strict=False):
        """Detect equivocation among a set of signed heads.

        Only heads whose STH signature verifies under this log's key
        (log_id-bound: the signature must cover this log's identity)
        participate in conflict grouping. Unsigned, forged,
        foreign-key, or malformed heads are skipped: they can never
        become operator-misbehavior evidence, so a JSON object handed
        to the detector cannot manufacture a false accusation
        (alarm-fatigue vector). With ``strict=True`` the detector
        instead refuses to adjudicate when any head is unverifiable,
        raising TransparencyLogError naming them as invalid input --
        reported distinctly, never as equivocation evidence.

        Groups the verified heads by tree_size; any size with more
        than one distinct root_hash is a conflicting view of the log
        at that size -- durable evidence of operator misbehavior (the
        CT split-view). Returns a list of conflict dicts (empty = none
        detected). Only sees the heads it is given: collecting heads
        from independent witnesses is out-of-band by design.
        """
        heads = self._heads if heads is None else heads
        verified = []
        invalid = 0
        for h in heads:
            # verify_tree_head never raises: it is the False-gate for
            # non-dicts, malformed heads, bad signatures, and foreign
            # log_ids alike.
            if verify_tree_head(h, self._log_id):
                verified.append(h)
            else:
                invalid += 1
        if strict and invalid:
            raise TransparencyLogError(
                "%d head(s) did not verify under this log's key: "
                "refusing to adjudicate unverifiable input as "
                "equivocation evidence (invalid input, not a "
                "conflict)" % (invalid,))
        by_size = {}
        for h in verified:
            size = h["tree_size"]
            root = h["root_hash"]
            by_size.setdefault(size, set()).add(root)
        conflicts = []
        for size in sorted(by_size):
            roots = sorted(by_size[size])
            if len(roots) > 1:
                conflicts.append({
                    "tree_size": size,
                    "root_hashes": roots,
                    "note": "equivocation: %d distinct roots signed "
                            "for tree size %d" % (len(roots), size),
                })
        return conflicts


# -- module-level verifiers (offline; never raise, fail closed) --------

def verify_tree_head(tree_head, log_pubkey_hex):
    """True iff the STH is well-formed and its Ed25519 signature
    verifies under the log's public key. Never raises."""
    try:
        if not isinstance(tree_head, dict):
            return False
        for field in ("log_id", "tree_size", "root_hash",
                      "timestamp", "signature"):
            if field not in tree_head:
                return False
        _check_digest(tree_head["log_id"])
        _check_digest(tree_head["root_hash"])
        size = tree_head["tree_size"]
        if (not isinstance(size, int) or isinstance(size, bool)
                or size <= 0):
            return False
        _parse_ts(tree_head["timestamp"])
        sig = bytes.fromhex(tree_head["signature"])
        if len(sig) != 64:
            return False
        pub = bytes.fromhex(log_pubkey_hex)
        if len(pub) != 32:
            return False
        if pub.hex() != tree_head["log_id"]:
            return False
        return bool(_ed.verify(pub, _sth_body(tree_head), sig))
    except (TransparencyLogError, ValueError, TypeError, KeyError):
        return False


def verify_inclusion(bundle_digest_hex, proof, tree_head,
                     log_pubkey_hex=None):
    """True iff the digest is in the log at the head's tree size.

    Recomputes the leaf hash from (digest, proof leaf_index,
    proof appended_at) and checks the Merkle audit path against the
    head's root. When ``log_pubkey_hex`` is given the head's
    signature is verified first (fail-closed on forgery); without it
    the head's root is trusted as given -- verify the STH signature
    separately with :func:`verify_tree_head`. Never raises.
    """
    try:
        if log_pubkey_hex is not None:
            if not verify_tree_head(tree_head, log_pubkey_hex):
                return False
        if not isinstance(tree_head, dict) or not isinstance(proof, dict):
            return False
        _check_digest(bundle_digest_hex)
        index = proof["leaf_index"]
        size = proof["tree_size"]
        if (not isinstance(index, int) or isinstance(index, bool)
                or not isinstance(size, int) or isinstance(size, bool)):
            return False
        if tree_head.get("tree_size") != size:
            return False
        _check_digest(tree_head["root_hash"])
        leaf = _leaf_hash(index, bundle_digest_hex,
                          proof["appended_at"])
        path = proof["path"]
        if not isinstance(path, list):
            return False
        sibs = [bytes.fromhex(p) for p in path]
        return bool(_merkle.verify_inclusion(
            leaf, index, sibs, bytes.fromhex(tree_head["root_hash"]),
            size))
    except (TransparencyLogError, ValueError, TypeError, KeyError):
        return False


def verify_consistency(old_head, new_head, proof, log_pubkey_hex=None):
    """True iff the old head's tree is a prefix of the new head's --
    the log only appended between them. When ``log_pubkey_hex`` is
    given both head signatures are verified first. Never raises."""
    try:
        if log_pubkey_hex is not None:
            if not verify_tree_head(old_head, log_pubkey_hex):
                return False
            if not verify_tree_head(new_head, log_pubkey_hex):
                return False
        if (not isinstance(old_head, dict)
                or not isinstance(new_head, dict)
                or not isinstance(proof, dict)):
            return False
        old_size = old_head["tree_size"]
        new_size = new_head["tree_size"]
        if (proof.get("old_size") != old_size
                or proof.get("new_size") != new_size):
            return False
        _check_digest(old_head["root_hash"])
        _check_digest(new_head["root_hash"])
        nodes = proof["nodes"]
        if not isinstance(nodes, list):
            return False
        sibs = [bytes.fromhex(x) for x in nodes]
        return bool(_merkle.verify_consistency(
            bytes.fromhex(old_head["root_hash"]),
            bytes.fromhex(new_head["root_hash"]),
            old_size, new_size, sibs))
    except (TransparencyLogError, ValueError, TypeError, KeyError):
        return False
