"""Witness checkpoint publication (the log-side publish half).

Wave-322 lane 3 (evidence-envelope direction-brief item 2,
``research/prospecting/w321_witness_monitor.md``): the PUBLICATION
layer for transparency-log checkpoints. It stands on (none are
re-built):

* ``gov/witness_consistency.py`` -- C2SP checkpoint notes, cosigning,
  quorum counting, freshness (``issue_checkpoint_note``,
  ``cosign_note_v1``, ``require_cosignatures``, ``check_freshness``).
* ``gov/witness_log.py`` -- the append-only Merkle log
  (``WitnessLog``: ``len()`` + ``root_hash()``).

What it adds:

1. **Publisher** -- :func:`publish_checkpoint`: issue the operator
   note for the log's current head, collect witness cosignatures
   synchronously at publish time -- each a cosignature/v1 (0x04)
   76-byte ``keyID(4) || u64BE timestamp(8) || sig(64)`` line over
   the domain-separated cosignature statement, the Rekor v2
   production witness format -- then SELF-VERIFY the result against
   the pinned sets before it is ever written. A checkpoint that
   would not verify is never published
   (``witness-publish-quorum-unmet``) -- fail-closed at the source,
   where Tessera today is fail-open.
2. **Static-file writer** -- :func:`write_checkpoint_file`: atomic
   (tmp + fsync + ``os.replace``) write of the checkpoint bytes to
   the static endpoint path. :func:`endpoint_contract` documents the
   production endpoint shape (``GET /checkpoint``,
   ``content-type: text/plain; charset=utf-8``,
   ``cache-control: no-cache`` + etag, object-store-backed static
   file -- the live Rekor v2 capture in the prospectus). The
   registry/CDN is untrusted storage; serving is deploy config, this
   module defines the bytes and the headers.
3. **Offline client verifier** -- :func:`verify_published_checkpoint`:
   parse the note, verify the operator signature, verify >= ``quorum_k``
   cosignatures from the pinned witness set, freshness against
   caller-supplied ``now``/``max_age``, and monotonicity against the
   caller's ``last_seen``. Fail-closed throughout: nothing
   warns-and-accepts.

**Witness-set seam (wave-322 lane 2).** The verifier takes the pinned
witness set as a plain ``{name: vkey}`` map plus ``quorum_k`` -- the
same shape ``require_cosignatures`` consumes. The signed
witness-policy artifact (lane 2, ``gov/witness_policy.py``) will
produce exactly this map (plus ``quorum_k`` and validity windows)
from the signed policy document; when it lands, callers replace the
literal map with ``policy.witness_vkeys()`` and nothing else in this
module changes. This module never imports the policy module (it does
not exist on this base), so the seam stays a parameter, not a
dependency.

Coded refusals new to this module (registered in
``gov/decision_codes.py``): ``witness-publish-quorum-unmet``,
``witness-publish-rollback``, ``witness-checkpoint-unknown-origin``.
Verification verdicts already named by the witness layer are reused
(``witness-note-malformed``, ``witness-consistency-invalid``,
``witness-cosignature-invalid``, ``witness-quorum-unmet``,
``witness-checkpoint-stale``, ``witness-consistency-fork-detected``,
``witness-policy-malformed``) -- no code proliferation.

Stdlib only. $0 spend, synthetic/local. Dependencies are loaded by
file path (the ``gov/trust_root_refresh.py`` /
``gov/witness_consistency.py`` pattern): ``from gov import ...``
would execute ``gov/__init__.py``, and this module is loadable by the
offline verifier, whose contract is zero network.
"""

import hashlib
import importlib.util
import os
import time

__all__ = [
    "WITNESS_PUBLISH_CODES",
    "WitnessPublishError",
    "publish_checkpoint",
    "write_checkpoint_file",
    "endpoint_contract",
    "verify_published_checkpoint",
]

# ---------------------------------------------------------------------------
# Coded refusals (also registered in gov/decision_codes.py -- pin moves
# 1964 -> 1967).
# ---------------------------------------------------------------------------

WITNESS_PUBLISH_QUORUM_UNMET = "witness-publish-quorum-unmet"
WITNESS_PUBLISH_ROLLBACK = "witness-publish-rollback"
WITNESS_CHECKPOINT_UNKNOWN_ORIGIN = "witness-checkpoint-unknown-origin"

WITNESS_PUBLISH_CODES = (
    WITNESS_CHECKPOINT_UNKNOWN_ORIGIN,
    WITNESS_PUBLISH_QUORUM_UNMET,
    WITNESS_PUBLISH_ROLLBACK,
)


class WitnessPublishError(Exception):
    """A coded witness-publication failure. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("[%s] %s" % (code, detail) if detail else
                         "[%s]" % (code,))


def _refuse(code, detail=""):
    raise WitnessPublishError(code, detail)


# ---------------------------------------------------------------------------
# Dependency loading (file path, socket-free -- see module docstring).
# ---------------------------------------------------------------------------

def _load_dep(filename, standalone_name):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        filename)
    try:
        spec = importlib.util.spec_from_file_location(standalone_name,
                                                      path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except WitnessPublishError:
        raise
    except Exception as exc:  # noqa: BLE001
        # A dependency that cannot be loaded is a broken deployment, not
        # a verification verdict: raise, never refuse-with-a-code (the
        # code would misname the failure).
        raise RuntimeError(
            "cannot load %s from %r: %s" % (filename, path, exc))
    return module


_wc = None


def _wc_mod():
    global _wc
    if _wc is None:
        _wc = _load_dep("witness_consistency.py",
                        "sasanam_standalone_witness_consistency_wp")
    return _wc


# ---------------------------------------------------------------------------
# 1. Publisher.
# ---------------------------------------------------------------------------

def _check_witness_signers(witness_signers):
    if (not isinstance(witness_signers, (list, tuple))
            or not all(isinstance(p, (list, tuple)) and len(p) == 2
                       and isinstance(p[0], str) and p[0]
                       for p in witness_signers)):
        raise ValueError(
            "witness_signers must be a list of (name, signer) pairs")
    return list(witness_signers)


def publish_checkpoint(log, origin, log_key_name, log_signer,
                       witness_signers, *, operator_vkeys, witness_vkeys,
                       quorum_k, timestamp=None):
    """Issue, cosign, and self-verify a checkpoint note for publication.

    ``log`` exposes ``root_hash()`` (32 bytes) and ``__len__`` (the
    tree size) -- the shape of ``gov.witness_log.WitnessLog``.
    ``witness_signers`` is a list of ``(name, signer)`` pairs; each
    signer exposes ``public_key`` (32 bytes) and ``sign(bytes)`` (the
    shape of ``gov.signing.Ed25519Signer``). Witnesses cosign
    synchronously with cosignature/v1 (0x04) 76-byte lines over the
    domain-separated cosignature statement (the Rekor v2 production
    witness format); the cosignature timestamp is the checkpoint
    timestamp, so emission stays deterministic. ``witness_vkeys``
    pins the witnesses as 0x04 vkeys (``name+hexID+base64(0x04 ||
    pubkey)``) -- the vkey pin format from the prospectus.

    The result is self-verified against ``operator_vkeys`` /
    ``witness_vkeys`` / ``quorum_k`` BEFORE it is returned: a
    checkpoint that would not verify is never published. Publish-side
    quorum failure refuses ``witness-publish-quorum-unmet``
    (fail-closed at the source). Deterministic for identical inputs
    (same timestamp).

    All refusals surface as :class:`WitnessPublishError` (the witness
    layer's own error class is mapped at this layer's boundary, the
    ``witness_consistency`` pattern -- the dependency is loaded by
    file path, so its class object differs from ``gov``'s).
    """
    wc = _wc_mod()
    pairs = _check_witness_signers(witness_signers)
    # One timestamp for the whole publication: the note's ``timestamp``
    # extension and every cosignature's embedded time are identical, so
    # emission is deterministic and the cosignature's "as of" matches
    # the checkpoint it witnesses.
    ts = int(time.time()) if timestamp is None else int(timestamp)
    try:
        note = wc.issue_checkpoint_note(log, origin, log_key_name,
                                        log_signer, timestamp=ts)
        for name, signer in pairs:
            note = wc.cosign_note_v1(note, name, signer, timestamp=ts)
        wc.require_cosignatures(note, operator_vkeys=operator_vkeys,
                                witness_vkeys=witness_vkeys,
                                quorum_k=quorum_k)
    except wc.WitnessConsistencyError as exc:
        if exc.code == wc.WITNESS_QUORUM_UNMET:
            _refuse(WITNESS_PUBLISH_QUORUM_UNMET,
                    "publish-time cosigning below quorum: %s"
                    % (exc.detail,))
        _refuse(exc.code, exc.detail)
    return note


# ---------------------------------------------------------------------------
# 2. Static-file writer + endpoint contract.
# ---------------------------------------------------------------------------

def write_checkpoint_file(note, path):
    """Atomically write checkpoint ``note`` bytes to the static path.

    tmp + fsync + ``os.replace``: readers never observe a half-written
    checkpoint (the GCS-backed static-file semantics from the
    prospectus). IO failures propagate as ``OSError`` -- a broken
    deployment, never a verification verdict.
    """
    data = bytes(note)
    directory = os.path.dirname(os.path.abspath(path))
    tmp = os.path.join(directory, ".checkpoint-%d.tmp" % (os.getpid(),))
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def endpoint_contract(note):
    """The static endpoint contract for a checkpoint note.

    The production shape (prospectus live capture): ``GET /checkpoint``
    serving the note bytes as ``text/plain; charset=utf-8`` with
    ``cache-control: no-cache`` and an etag over the note bytes. The
    registry/CDN is untrusted storage -- the bytes verify client-side
    against the pinned keys, always. Serving is deploy config; this is
    the contract the deployment must honor.
    """
    digest = hashlib.sha256(bytes(note)).hexdigest()
    return {
        "method": "GET",
        "path": "/checkpoint",
        "content_type": "text/plain; charset=utf-8",
        "cache_control": "no-cache",
        "etag": '"%s"' % (digest,),
        "note_sha256": digest,
        "storage": "object-store-backed static file; the CDN is "
                   "untrusted storage",
    }


# ---------------------------------------------------------------------------
# 3. Offline client verifier.
# ---------------------------------------------------------------------------

def _check_allowed_origins(allowed_origins):
    if (not isinstance(allowed_origins, (list, tuple, set, frozenset))
            or not allowed_origins
            or not all(isinstance(o, str) and o
                       for o in allowed_origins)):
        raise ValueError(
            "allowed_origins must be a non-empty collection of str")
    return set(allowed_origins)


def _check_last_seen(last_seen):
    if last_seen is None:
        return None
    if (not isinstance(last_seen, (list, tuple)) or len(last_seen) != 2):
        raise ValueError("last_seen must be (tree_size, root_hash)")
    size, root = last_seen
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise ValueError("last_seen tree_size must be a positive int")
    root = bytes(root)
    if len(root) != 32:
        raise ValueError("last_seen root_hash must be 32 bytes")
    return (size, root)


def verify_published_checkpoint(note, *, operator_vkeys, witness_vkeys,
                                quorum_k, allowed_origins, now=None,
                                max_age=None, last_seen=None):
    """Verify a published checkpoint note, fail-closed, offline-capable.

    Steps, in order: (1) the operator signature and >= ``quorum_k``
    witness cosignatures verify against the pinned sets (unknown
    signature lines are ignored per the signed-note collision rules --
    the rotation enabler); (2) the note's origin is in
    ``allowed_origins`` (``witness-checkpoint-unknown-origin``); (3)
    freshness against caller-supplied ``now``/``max_age``
    (``witness-checkpoint-stale``; there is no trusted-now by
    default -- pass both or neither); (4) monotonicity against the
    caller's ``last_seen`` ``(tree_size, root_hash)``: a smaller size
    refuses ``witness-publish-rollback``; the same size with a
    different root refuses ``witness-consistency-fork-detected``
    (equivocation is cryptographic proof of log misbehavior).

    ``witness_vkeys`` is the plain ``{name: vkey}`` map -- the seam
    where the signed witness-policy artifact (wave-322 lane 2) plugs
    in: replace the literal map with ``policy.witness_vkeys()``.

    Returns the verified checkpoint fields on success. All refusals
    raise :class:`WitnessPublishError` with the witness layer's code
    (mapped at this layer's boundary) -- never a soft False, never a
    bare dependency exception.
    """
    wc = _wc_mod()
    origins = _check_allowed_origins(allowed_origins)
    seen = _check_last_seen(last_seen)
    if (now is None) != (max_age is None):
        raise ValueError("now and max_age must be given together")
    try:
        result = wc.require_cosignatures(
            note, operator_vkeys=operator_vkeys,
            witness_vkeys=witness_vkeys, quorum_k=quorum_k)
    except wc.WitnessConsistencyError as exc:
        _refuse(exc.code, exc.detail)
    fields = result["fields"]
    origin = fields["origin"]
    if origin not in origins:
        _refuse(WITNESS_CHECKPOINT_UNKNOWN_ORIGIN,
                "note origin %r not in pinned origins" % (origin,))
    freshness = None
    if now is not None:
        try:
            freshness = wc.check_freshness(fields, now=now,
                                           max_age=max_age)
        except wc.WitnessConsistencyError as exc:
            _refuse(exc.code, exc.detail)
    if seen is not None:
        size = fields["tree_size"]
        root = bytes(fields["root_hash"])
        if size < seen[0]:
            _refuse(WITNESS_PUBLISH_ROLLBACK,
                    "checkpoint size %d older than last seen %d"
                    % (size, seen[0]))
        if size == seen[0] and root != seen[1]:
            _refuse(wc.WITNESS_CONSISTENCY_FORK_DETECTED,
                    "same tree size %d with different root from one log "
                    "key: cryptographic proof of log misbehavior" % (size,))
    return {
        "origin": origin,
        "tree_size": fields["tree_size"],
        "root_hash": bytes(fields["root_hash"]).hex(),
        "timestamp": (freshness["timestamp"] if freshness is not None
                      else None),
        "witnesses": result["witnesses"],
        "cosignatures": result["cosignatures"],
        "quorum_k": result["quorum_k"],
        "freshness": freshness,
    }
