"""Witness consistency + fail-closed gossip for the transparency log.

Wave-319 lane 3 (evidence-envelope direction-brief item 1,
``research/prospecting/w317_evidence_next_steps.md``): consistency
proofs + gossip. This module is the WITNESS-CONSISTENCY LAYER -- what an
auditor does with the primitives. It stands on (none are re-built):

* ``gov/witness_log.py`` -- the append-only Merkle log, signed
  checkpoints, inclusion proofs, and ``verify_consistency``.
* ``gov/checkpoint_note.py`` -- C2SP tlog-checkpoint signed notes
  (emission, parsing, verifier-key strings, key-ID collision rules).
* ``gov/witness_rekor.py`` -- Rekor-pattern inclusion receipts
  (checkpoint-first, digest-bound).

What it adds:

1. **Checkpoint-to-checkpoint consistency** --
   :func:`verify_checkpoint_consistency`: verify both notes' signatures
   against the pinned operator key (signature first, sizes/roots ONLY
   from the verified documents), then run the log's consistency proof.
   Two notes from one key at the same size with different roots refuse
   ``witness-consistency-fork-detected`` -- RFC 6962's gossip rule:
   conflicting STHs are cryptographic proof of log misbehavior.
2. **Witness cosignatures (C2SP pattern)** -- :func:`cosign_note` lets a
   third-party witness countersign the same checkpoint note bytes
   (``-- <key name> base64(keyID || signature)`` lines, signature type
   0x01 over the note text); :func:`require_cosignatures` accepts the
   log head only with >=k distinct valid cosignatures from the
   policy-pinned witness set. Unknown keys are ignored per the
   signed-note collision rules; a CONFIGURED witness's bad signature
   refuses ``witness-cosignature-invalid``, never an accept.
3. **Checkpoint freshness** -- :func:`check_freshness`: the note carries
   its issuance time as a ``timestamp <unix>`` extension line
   (spec-allowed; surfaced explicitly by the parser). A missing/
   malformed timestamp, a timestamp in the future vs the observed time,
   or an age beyond the freshness window refuses
   ``witness-checkpoint-stale``. No trusted-now by default: the caller
   supplies ``now``.
4. **Fail-closed gossip** -- :func:`gossip` consumes the configured
   witnesses' reported STH views. Conflicting views (same size,
   different roots) refuse ``witness-gossip-conflict``. A configured
   witness that reports NO view refuses ``witness-unreachable`` -- the
   TesseraCT fail-open caveat (a checkpoint still publishes when the
   witness is offline) is the documented anti-pattern this module
   inverts: silence refuses, never passes.
5. **Policy mode** -- :func:`verify_witness_policy`: the optional-but-
   fail-closed mode the offline verifier runs when the signed policy
   configures it. A configured mode with missing evidence refuses
   ``witness-consistency-missing`` (configured means required).

All failures raise :class:`WitnessConsistencyError` with a machine
``code`` (registered in ``gov/decision_codes.py``, domain ``witness``).
Verify functions never return soft False -- they return the verified
values or raise.

Receipt binding (CVE-2026-22703): :func:`verify_consistency_chain`
binds the consistency proof to the anchored receipt's checkpoint -- a
proof presented for a different tree refuses
``witness-consistency-invalid``; a valid proof alone is never enough.

Stdlib only. $0 spend, synthetic/local. The module loads its gov
dependencies (``checkpoint_note``, ``witness_log``) by file path (the
``gov/trust_root_refresh.py`` pattern): ``from gov import ...`` would
execute ``gov/__init__.py`` and pull urllib into the import closure,
and this module is loaded by file path by the offline verifier, whose
contract is zero network.
"""

import base64
import binascii
import hashlib
import importlib.util
import os
import re
import time

__all__ = [
    "WITNESS_CODES",
    "WitnessConsistencyError",
    "note_text",
    "issue_checkpoint_note",
    "cosign_note",
    "require_cosignatures",
    "verify_checkpoint_consistency",
    "verify_consistency_chain",
    "check_freshness",
    "gossip",
    "verify_witness_policy",
]

# ---------------------------------------------------------------------------
# Coded refusals (also registered in gov/decision_codes.py -- pin moves
# 1906 -> 1916).
# ---------------------------------------------------------------------------

WITNESS_CONSISTENCY_FORK_DETECTED = "witness-consistency-fork-detected"
WITNESS_CONSISTENCY_INVALID = "witness-consistency-invalid"
WITNESS_CONSISTENCY_MISSING = "witness-consistency-missing"
WITNESS_QUORUM_UNMET = "witness-quorum-unmet"
WITNESS_COSIGNATURE_INVALID = "witness-cosignature-invalid"
WITNESS_UNREACHABLE = "witness-unreachable"
WITNESS_GOSSIP_CONFLICT = "witness-gossip-conflict"
WITNESS_CHECKPOINT_STALE = "witness-checkpoint-stale"
WITNESS_POLICY_MALFORMED = "witness-policy-malformed"
WITNESS_NOTE_MALFORMED = "witness-note-malformed"

WITNESS_CODES = (
    WITNESS_CONSISTENCY_FORK_DETECTED,
    WITNESS_CONSISTENCY_INVALID,
    WITNESS_CONSISTENCY_MISSING,
    WITNESS_QUORUM_UNMET,
    WITNESS_COSIGNATURE_INVALID,
    WITNESS_UNREACHABLE,
    WITNESS_GOSSIP_CONFLICT,
    WITNESS_CHECKPOINT_STALE,
    WITNESS_POLICY_MALFORMED,
    WITNESS_NOTE_MALFORMED,
)


class WitnessConsistencyError(Exception):
    """A coded witness-consistency failure. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("[%s] %s" % (code, detail) if detail else
                         "[%s]" % (code,))


def _refuse(code, detail=""):
    raise WitnessConsistencyError(code, detail)


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
    except WitnessConsistencyError:
        raise
    except Exception as exc:  # noqa: BLE001
        # A dependency that cannot be loaded is a broken deployment, not
        # a verification verdict: raise, never refuse-with-a-code (the
        # code would misname the failure; the verifier mirrors this with
        # InternalError).
        raise RuntimeError(
            "cannot load %s from %r: %s" % (filename, path, exc))
    return module


_checkpoint_note = None
_witness_log = None


def _cn():
    global _checkpoint_note
    if _checkpoint_note is None:
        _checkpoint_note = _load_dep("checkpoint_note.py",
                                     "sasanam_standalone_checkpoint_note_wc")
    return _checkpoint_note


def _wl():
    global _witness_log
    if _witness_log is None:
        _witness_log = _load_dep("witness_log.py",
                                 "sasanam_standalone_witness_log_wc")
    return _witness_log


# ---------------------------------------------------------------------------
# Note construction.
# ---------------------------------------------------------------------------

_TIMESTAMP_RE = re.compile(r"^timestamp ([0-9]+)$")
# The em-dash separator lives in checkpoint_note (single source of truth);
# use sites reference it via the lazily loaded dependency (_cn().EM_DASH).

# Mirrors checkpoint_note's emission rules: the origin is a checkpoint
# field (bad origin is a product refusal); the key name is signer
# configuration (bad key name is a programming error).
_ORIGIN_BAD_CHARS = re.compile(r"[\s+]")


def _check_origin(origin):
    if (not isinstance(origin, str) or not origin
            or _ORIGIN_BAD_CHARS.search(origin)):
        _refuse(WITNESS_NOTE_MALFORMED,
                "origin must be a non-empty string without spaces/plus")
    return origin


def _check_key_name(key_name):
    if (not isinstance(key_name, str) or not key_name
            or _ORIGIN_BAD_CHARS.search(key_name)):
        raise ValueError("key_name must be a non-empty string without "
                         "spaces/plus")
    return key_name


def _check_root(root_hash):
    root = bytes(root_hash)
    if len(root) != 32:
        _refuse(WITNESS_NOTE_MALFORMED, "root_hash must be 32 bytes")
    return root


def _check_timestamp_value(value, where):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _refuse(WITNESS_NOTE_MALFORMED,
                "%s: timestamp must be a non-negative int unix time"
                % (where,))
    return value


def _check_signer(signer, where):
    pub = getattr(signer, "public_key", None)
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        _refuse(WITNESS_NOTE_MALFORMED,
                "%s: signer public_key must be 32 bytes" % (where,))
    if not callable(getattr(signer, "sign", None)):
        _refuse(WITNESS_NOTE_MALFORMED,
                "%s: signer needs .sign(bytes)" % (where,))
    return bytes(pub)


def note_text(origin, tree_size, root_hash, timestamp):
    """The canonical checkpoint note text (bytes) that keys sign.

    ``<origin>\\n<tree size>\\n<base64 root>\\ntimestamp <unix>\\n`` --
    the C2SP tlog-checkpoint 3-line body plus a ``timestamp`` extension
    line (spec-allowed; the parser surfaces extensions explicitly).
    Third-party witnesses sign exactly these bytes when cosigning
    without this module.
    """
    _check_origin(origin)
    if isinstance(tree_size, bool) or not isinstance(tree_size, int):
        _refuse(WITNESS_NOTE_MALFORMED,
                "tree_size must be an int")
    if tree_size < 1:
        _refuse(WITNESS_NOTE_MALFORMED,
                "tree_size must be >= 1 (an empty tree has no RFC 6962 "
                "root)")
    root = _check_root(root_hash)
    ts = _check_timestamp_value(timestamp, "note_text")
    return ("%s\n%d\n%s\ntimestamp %d\n"
            % (origin, tree_size,
               base64.b64encode(root).decode("ascii"), ts)).encode("utf-8")


def _signature_line(key_name, signer, text):
    """A C2SP signature line for ``text`` (no trailing newline)."""
    cn = _cn()
    pub = _check_signer(signer, "cosign")
    key_id = cn.derive_key_id(key_name, cn.SIG_TYPE_ED25519, pub)
    try:
        sig = signer.sign(text)
    except WitnessConsistencyError:
        raise
    except Exception as exc:  # noqa: BLE001
        _refuse(WITNESS_NOTE_MALFORMED,
                "signer failed: %s" % (exc,))
    if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
        _refuse(WITNESS_NOTE_MALFORMED,
                "signer must return a 64-byte Ed25519 signature")
    return "%s %s %s" % (
        _cn().EM_DASH, key_name,
        base64.b64encode(bytes(key_id) + bytes(sig)).decode("ascii"))


def issue_checkpoint_note(log, origin, key_name, signer, *, timestamp=None):
    """Issue a C2SP checkpoint note for the log's current tree head.

    ``log`` exposes ``root_hash()`` (32 bytes) and ``__len__`` (the
    tree size) -- the shape of ``gov.witness_log.WitnessLog``. The note
    text is :func:`note_text`; the operator's signature line is
    appended after the blank separator. Deterministic for identical
    inputs (same timestamp).
    """
    _check_origin(origin)
    _check_key_name(key_name)
    try:
        size = len(log)
        root = bytes(log.root_hash())
    except WitnessConsistencyError:
        raise
    except Exception as exc:  # noqa: BLE001
        _refuse(WITNESS_NOTE_MALFORMED,
                "log.root_hash()/len(log) failed: %s" % (exc,))
    if size < 1 or len(root) != 32:
        _refuse(WITNESS_NOTE_MALFORMED,
                "log has no checkpointable tree head")
    ts = int(time.time()) if timestamp is None else _check_timestamp_value(
        timestamp, "issue_checkpoint_note")
    text = note_text(origin, size, root, ts)
    line = _signature_line(key_name, signer, text)
    return text + b"\n" + line.encode("utf-8") + b"\n"


def _note_text_of(note):
    """Split a note into its signed text (bytes); the C2SP rule: the
    note text is separated from the signatures by the LAST empty line.
    """
    if isinstance(note, str):
        note = note.encode("utf-8")
    data = bytes(note)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        _refuse(WITNESS_NOTE_MALFORMED, "note is not valid UTF-8")
    if not text.endswith("\n"):
        _refuse(WITNESS_NOTE_MALFORMED,
                "note text must end with a newline")
    lines = text.split("\n")[:-1]  # drop the trailing empty string
    empties = [i for i, ln in enumerate(lines) if ln == ""]
    if not empties:
        _refuse(WITNESS_NOTE_MALFORMED,
                "note has no signature section (no blank separator line)")
    sep = empties[-1]
    return ("\n".join(lines[:sep]) + "\n").encode("utf-8")


def cosign_note(note, key_name, signer):
    """Append a witness cosignature line to a checkpoint note.

    The witness signs the SAME note text (the bytes before the blank
    separator) -- every signature on the note, operator and witnesses
    alike, is over the identical text, the C2SP cosigning model.
    Returns the new note bytes.
    """
    _check_key_name(key_name)
    text = _note_text_of(note)
    line = _signature_line(key_name, signer, text)
    data = bytes(note if not isinstance(note, str) else note.encode("utf-8"))
    if not data.endswith(b"\n"):
        _refuse(WITNESS_NOTE_MALFORMED,
                "note text must end with a newline")
    return data + line.encode("utf-8") + b"\n"


# ---------------------------------------------------------------------------
# Verification helpers.
# ---------------------------------------------------------------------------

def _parse_vkeys(vkeys, where):
    """Parse verifier-key strings into their parsed forms; config
    errors refuse ``witness-policy-malformed`` (loud, never defaulted)."""
    cn = _cn()
    if not isinstance(vkeys, (list, tuple)) or not vkeys:
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: must be a non-empty list of verifier-key strings"
                % (where,))
    out = []
    for v in vkeys:
        try:
            out.append(cn.parse_vkey(v))
        except ValueError as exc:
            _refuse(WITNESS_POLICY_MALFORMED,
                    "%s: bad verifier key: %s" % (where, exc))
    return out


def _verified_fields(note, vkeys, *, role):
    """Verify a note under ``vkeys`` (verifier-key strings); return the
    parsed fields.

    Maps checkpoint_note's refusals onto the witness vocabulary:
    unparseable notes -> ``witness-note-malformed``; bad verifier-key
    configuration -> ``witness-policy-malformed``; a note that does not
    verify under the expected key -> ``witness-consistency-invalid``
    (forged evidence -- it is not this log's note).
    """
    cn = _cn()
    if isinstance(note, str):
        note = note.encode("utf-8")
    if not isinstance(note, (bytes, bytearray)):
        _refuse(WITNESS_NOTE_MALFORMED,
                "%s: note must be bytes" % (role,))
    if (not isinstance(vkeys, (list, tuple)) or not vkeys
            or not all(isinstance(v, str) for v in vkeys)):
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: verifier keys must be a non-empty list of str"
                % (role,))
    try:
        return cn.verify_checkpoint(bytes(note), list(vkeys))
    except ValueError as exc:
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: bad verifier key: %s" % (role, exc))
    except cn.CheckpointNoteError as exc:
        if exc.code in (cn.CHECKPOINT_NOTE_MALFORMED, cn.CHECKPOINT_NOT_C2SP,
                        cn.CHECKPOINT_ORIGIN_EMPTY,
                        cn.CHECKPOINT_SIZE_MALFORMED,
                        cn.CHECKPOINT_ROOT_MALFORMED,
                        cn.CHECKPOINT_EXTENSION_EMPTY):
            _refuse(WITNESS_NOTE_MALFORMED,
                    "%s: [%s] %s" % (role, exc.code, exc.detail))
        # A KNOWN key's bad signature, or no trusted signature at all:
        # this is not the log's note -- forged evidence.
        _refuse(WITNESS_CONSISTENCY_INVALID,
                "%s: [%s] %s" % (role, exc.code, exc.detail))


def _head_of(fields):
    return {"tree_size": fields["tree_size"],
            "root_hash": bytes(fields["root_hash"]).hex()}


# ---------------------------------------------------------------------------
# 1. Checkpoint-to-checkpoint consistency.
# ---------------------------------------------------------------------------

def verify_checkpoint_consistency(old_note, new_note, proof_hashes, *,
                                  operator_vkeys):
    """Verify the log only grew from the old checkpoint to the new one.

    Both notes are verified against ``operator_vkeys`` (signature
    first); sizes and roots come ONLY from the verified documents
    (checkpoint-first, sigstore-python#248). ``proof_hashes`` is the
    wire consistency proof (border-decomposition subtree roots).

    * same size, equal roots -> consistent (no proof needed);
    * same size, different roots -> ``witness-consistency-fork-detected``
      (two STHs from one key = proof of log misbehavior);
    * old < new -> the proof must recompute both roots, else
      ``witness-consistency-invalid``.
    """
    old = _verified_fields(old_note, operator_vkeys, role="old_note")
    new = _verified_fields(new_note, operator_vkeys, role="new_note")
    old_size, new_size = old["tree_size"], new["tree_size"]
    old_root, new_root = bytes(old["root_hash"]), bytes(new["root_hash"])
    if old_size == new_size:
        if old_root == new_root:
            return {"old_size": old_size, "new_size": new_size,
                    "old_root": old_root.hex(),
                    "new_root": new_root.hex(),
                    "consistent": True}
        _refuse(WITNESS_CONSISTENCY_FORK_DETECTED,
                "same tree size %d with different roots from one log "
                "key: cryptographic proof of log misbehavior"
                % (old_size,))
    if old_size > new_size:
        _refuse(WITNESS_CONSISTENCY_INVALID,
                "need old_size < new_size, got %d > %d"
                % (old_size, new_size))
    if not isinstance(proof_hashes, list) or not proof_hashes:
        _refuse(WITNESS_CONSISTENCY_INVALID,
                "consistency proof must be a non-empty list of hex roots")
    try:
        _wl().verify_consistency(old_size, old_root, new_size, new_root,
                                 proof_hashes)
    except Exception as exc:  # noqa: BLE001 -- WitnessError subclasses
        code = getattr(exc, "code", "")
        _refuse(WITNESS_CONSISTENCY_INVALID,
                "consistency proof rejected: [%s] %s"
                % (code, getattr(exc, "detail", exc)))
    return {"old_size": old_size, "new_size": new_size,
            "old_root": old_root.hex(), "new_root": new_root.hex(),
            "consistent": True}


def verify_consistency_chain(receipt_checkpoint, old_note, new_note,
                             proof_hashes, *, operator_vkeys):
    """Bind the consistency proof to the anchored receipt's checkpoint.

    ``receipt_checkpoint`` is the VERIFIED dict checkpoint from the
    bundle's inclusion receipt (``treeSize``/``rootHash`` -- the sizes
    and hashes the receipt proved). The consistency proof's old note
    must name exactly that (size, root); otherwise the proof is for a
    different tree and refuses ``witness-consistency-invalid``
    (CVE-2026-22703: never accept a valid proof alone -- it must bind
    the same bundle digest the receipt names, via the receipt's
    checkpoint).
    """
    cp = receipt_checkpoint
    if not isinstance(cp, dict):
        _refuse(WITNESS_CONSISTENCY_INVALID,
                "receipt_checkpoint must be the verified dict checkpoint")
    tree_size = cp.get("treeSize")
    root_hex = cp.get("rootHash")
    if (isinstance(tree_size, bool) or not isinstance(tree_size, int)
            or tree_size < 1 or not isinstance(root_hex, str)
            or len(root_hex) != 64
            or any(c not in "0123456789abcdefABCDEF" for c in root_hex)):
        _refuse(WITNESS_CONSISTENCY_INVALID,
                "receipt_checkpoint has a bad treeSize/rootHash")
    old = _verified_fields(old_note, operator_vkeys, role="old_note")
    if (old["tree_size"] != tree_size
            or bytes(old["root_hash"]).hex().lower() != root_hex.lower()):
        _refuse(WITNESS_CONSISTENCY_INVALID,
                "consistency old checkpoint (size %d) does not match the "
                "anchored receipt checkpoint (size %d)"
                % (old["tree_size"], tree_size))
    return verify_checkpoint_consistency(old_note, new_note, proof_hashes,
                                         operator_vkeys=operator_vkeys)


# ---------------------------------------------------------------------------
# 2. Witness cosignatures (C2SP pattern).
# ---------------------------------------------------------------------------

def require_cosignatures(note, *, operator_vkeys, witness_vkeys,
                         quorum_k):
    """Accept the log head only with >=quorum_k witness cosignatures.

    ``witness_vkeys`` maps witness name -> verifier-key string (the
    policy-pinned set). The note must verify under the operator key
    first; then each configured witness's signature is checked --
    unknown signatures are ignored per the signed-note collision rules,
    a CONFIGURED witness's bad signature refuses
    ``witness-cosignature-invalid``, and fewer than ``quorum_k``
    distinct verified witness names refuses ``witness-quorum-unmet``.
    The operator's own name never counts toward the witness quorum.
    """
    if (isinstance(quorum_k, bool) or not isinstance(quorum_k, int)
            or quorum_k < 1):
        _refuse(WITNESS_POLICY_MALFORMED,
                "quorum_k must be a positive int")
    if (not isinstance(witness_vkeys, dict) or not witness_vkeys
            or not all(isinstance(k, str) and k for k in witness_vkeys)):
        _refuse(WITNESS_POLICY_MALFORMED,
                "witness_vkeys must be a non-empty {name: vkey} map")
    op_parsed = _parse_vkeys(operator_vkeys, "operator_vkeys")
    for name, v in witness_vkeys.items():
        _parse_vkeys([v], "witness_vkeys[%s]" % name)
    op_names = {v["name"] for v in op_parsed}
    # Pass 1: the operator's signature must verify (unknown/witness
    # signature lines are ignored here by the collision rules).
    op_fields = _verified_fields(note, list(operator_vkeys),
                                 role="operator_note")
    # Pass 2: the witnesses.
    cn = _cn()
    data = bytes(note) if not isinstance(note, str) else note.encode("utf-8")
    try:
        wit_fields = cn.verify_checkpoint(
            data, [witness_vkeys[name] for name in sorted(witness_vkeys)])
    except cn.CheckpointNoteError as exc:
        if exc.code == cn.CHECKPOINT_KNOWN_SIGNATURE_INVALID:
            _refuse(WITNESS_COSIGNATURE_INVALID,
                    "a configured witness's signature failed: %s"
                    % (exc.detail,))
        if exc.code == cn.CHECKPOINT_NO_TRUSTED_SIGNATURE:
            _refuse(WITNESS_QUORUM_UNMET,
                    "no configured witness cosigned the note "
                    "(quorum_k=%d)" % (quorum_k,))
        _refuse(WITNESS_NOTE_MALFORMED,
                "witness pass: [%s] %s" % (exc.code, exc.detail))
    names = sorted(set(wit_fields["verified_by"]) - op_names)
    if len(names) < quorum_k:
        _refuse(WITNESS_QUORUM_UNMET,
                "%d witness cosignature(s) verified, quorum_k=%d"
                % (len(names), quorum_k))
    return {"cosignatures": len(names), "witnesses": names,
            "quorum_k": quorum_k, "fields": op_fields}


# ---------------------------------------------------------------------------
# 3. Checkpoint freshness.
# ---------------------------------------------------------------------------

def check_freshness(fields, *, now, max_age):
    """Refuse a stale (or future-dated, or timeless) checkpoint.

    ``fields`` is the output of ``checkpoint_note.verify_checkpoint``
    (the note is already verified by the caller). The issuance time
    comes from the ``timestamp <unix>`` extension line; a missing/
    malformed/duplicate timestamp refuses ``witness-checkpoint-stale``
    fail-closed -- a note with no issuance time cannot be
    freshness-checked. ``now`` is the observed unix time (caller-
    supplied; there is no trusted-now by default).
    """
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        _refuse(WITNESS_POLICY_MALFORMED, "now must be a non-negative int")
    if isinstance(max_age, bool) or not isinstance(max_age, int):
        _refuse(WITNESS_POLICY_MALFORMED, "max_age must be an int")
    if max_age < 0:
        _refuse(WITNESS_POLICY_MALFORMED, "max_age must be non-negative")
    stamps = []
    for ext in fields.get("extensions", ()):
        m = _TIMESTAMP_RE.match(ext)
        if m:
            stamps.append(int(m.group(1)))
    if len(stamps) != 1:
        _refuse(WITNESS_CHECKPOINT_STALE,
                "note carries %d timestamp extensions, want exactly 1"
                % (len(stamps),))
    ts = stamps[0]
    age = now - ts
    if age < 0:
        _refuse(WITNESS_CHECKPOINT_STALE,
                "checkpoint timestamp %d is in the future vs observed "
                "time %d" % (ts, now))
    if age > max_age:
        _refuse(WITNESS_CHECKPOINT_STALE,
                "checkpoint age %d exceeds the freshness window %d"
                % (age, max_age))
    return {"timestamp": ts, "age": age}


# ---------------------------------------------------------------------------
# 4. Fail-closed gossip.
# ---------------------------------------------------------------------------

def gossip(views, *, witness_vkeys, now=None, max_view_age=None):
    """Exchange STH views with the configured witnesses, fail-closed.

    ``views`` is a list of ``{"witness_name": str, "note": bytes}`` --
    each witness's reported signed tree head for one log.
    ``witness_vkeys`` maps witness name -> verifier-key string (the
    configured set; the authority).

    * every configured witness must report exactly one view -- a
      silent witness refuses ``witness-unreachable`` (the TesseraCT
      fail-open anti-pattern, inverted: silence refuses, never passes);
    * a view from an UNCONFIGURED witness refuses
      ``witness-policy-malformed`` (loud, never silently ignored);
    * a view that does not verify under its witness's key refuses
      ``witness-cosignature-invalid`` (it is not that witness's view);
    * two views at the same tree size with different roots refuse
      ``witness-gossip-conflict`` -- RFC 6962: conflicting STHs are
      cryptographic proof of log misbehavior;
    * with ``max_view_age`` set, each view is freshness-checked
      (``witness-checkpoint-stale``).

    Returns ``{"views": {name: {tree_size, root_hash, timestamp}},
    "max_tree_size": n}``.
    """
    if (not isinstance(witness_vkeys, dict) or not witness_vkeys
            or not all(isinstance(k, str) and k for k in witness_vkeys)):
        _refuse(WITNESS_POLICY_MALFORMED,
                "witness_vkeys must be a non-empty {name: vkey} map")
    for name, v in witness_vkeys.items():
        _parse_vkeys([v], "witness_vkeys[%s]" % name)
    if not isinstance(views, list):
        _refuse(WITNESS_POLICY_MALFORMED, "views must be a list")
    by_name = {}
    for i, view in enumerate(views):
        where = "views[%d]" % i
        if not isinstance(view, dict):
            _refuse(WITNESS_POLICY_MALFORMED,
                    "%s must be an object" % (where,))
        name = view.get("witness_name")
        note = view.get("note")
        if not isinstance(name, str) or not name:
            _refuse(WITNESS_POLICY_MALFORMED,
                    "%s.witness_name must be a non-empty str" % (where,))
        if name not in witness_vkeys:
            _refuse(WITNESS_POLICY_MALFORMED,
                    "view from unconfigured witness %r" % (name,))
        if name in by_name:
            _refuse(WITNESS_POLICY_MALFORMED,
                    "duplicate view from witness %r" % (name,))
        if not isinstance(note, (bytes, bytearray)) or not note:
            _refuse(WITNESS_NOTE_MALFORMED,
                    "%s.note must be non-empty bytes" % (where,))
        by_name[name] = bytes(note)
    for name in witness_vkeys:
        if name not in by_name:
            _refuse(WITNESS_UNREACHABLE,
                    "configured witness %r reported no view" % (name,))
    cn = _cn()
    seen = {}
    out = {}
    for name in sorted(by_name):
        try:
            fields = cn.verify_checkpoint(by_name[name],
                                          [witness_vkeys[name]])
        except cn.CheckpointNoteError as exc:
            if exc.code in (cn.CHECKPOINT_KNOWN_SIGNATURE_INVALID,
                            cn.CHECKPOINT_NO_TRUSTED_SIGNATURE):
                _refuse(WITNESS_COSIGNATURE_INVALID,
                        "view from %r does not verify under its key: "
                        "[%s] %s" % (name, exc.code, exc.detail))
            _refuse(WITNESS_NOTE_MALFORMED,
                    "view from %r: [%s] %s"
                    % (name, exc.code, exc.detail))
        if max_view_age is not None:
            if now is None:
                _refuse(WITNESS_POLICY_MALFORMED,
                        "max_view_age needs now")
            check_freshness(fields, now=now, max_age=max_view_age)
        size = fields["tree_size"]
        root = bytes(fields["root_hash"]).hex()
        if size in seen and seen[size] != root:
            _refuse(WITNESS_GOSSIP_CONFLICT,
                    "witnesses disagree at tree size %d: %s vs a prior "
                    "view" % (size, root[:16]))
        seen[size] = root
        stamps = [int(m.group(1)) for m in
                  (_TIMESTAMP_RE.match(e) for e in fields["extensions"])
                  if m]
        out[name] = {"tree_size": size, "root_hash": root,
                     "timestamp": stamps[0] if stamps else None}
    return {"views": out,
            "max_tree_size": max(v["tree_size"] for v in out.values())}


# ---------------------------------------------------------------------------
# 5. Policy mode (the offline verifier's optional-but-fail-closed stage).
# ---------------------------------------------------------------------------

def _policy_shape(policy):
    """Strict-shape the witness_consistency policy section; config
    problems refuse ``witness-policy-malformed`` (loud, never
    defaulted)."""
    if not isinstance(policy, dict):
        _refuse(WITNESS_POLICY_MALFORMED,
                "witness_consistency policy must be an object")
    op_vkeys = policy.get("operator_vkeys")
    if (not isinstance(op_vkeys, list) or not op_vkeys
            or not all(isinstance(v, str) and v for v in op_vkeys)):
        _refuse(WITNESS_POLICY_MALFORMED,
                "operator_vkeys must be a non-empty list of str")
    wit_vkeys = policy.get("witness_vkeys")
    if (not isinstance(wit_vkeys, dict) or not wit_vkeys
            or not all(isinstance(k, str) and k
                       and isinstance(v, str) and v
                       for k, v in wit_vkeys.items())):
        _refuse(WITNESS_POLICY_MALFORMED,
                "witness_vkeys must be a non-empty {name: vkey} map")
    quorum_k = policy.get("quorum_k")
    if (isinstance(quorum_k, bool) or not isinstance(quorum_k, int)
            or quorum_k < 1):
        _refuse(WITNESS_POLICY_MALFORMED,
                "quorum_k must be a positive int")
    max_age = policy.get("max_checkpoint_age")
    if (isinstance(max_age, bool) or not isinstance(max_age, int)
            or max_age <= 0):
        _refuse(WITNESS_POLICY_MALFORMED,
                "max_checkpoint_age must be a positive int")
    head = policy.get("accepted_head")
    # accepted_head is OPTIONAL (spec): the pinned previous checkpoint
    # for growth proofs. Absent -> the mode still enforces quorum and
    # freshness, but there is no growth to prove.
    accepted_head = None
    if head is not None:
        if (not isinstance(head, dict)
                or not isinstance(head.get("note"), (bytes, bytearray))
                or not head["note"]):
            _refuse(WITNESS_POLICY_MALFORMED,
                    "accepted_head.note must be non-empty bytes")
        accepted_head = bytes(head["note"])
    _parse_vkeys(op_vkeys, "operator_vkeys")
    for name, v in wit_vkeys.items():
        _parse_vkeys([v], "witness_vkeys[%s]" % name)
    return {"operator_vkeys": op_vkeys, "witness_vkeys": wit_vkeys,
            "quorum_k": quorum_k, "max_checkpoint_age": max_age,
            "accepted_head": accepted_head}


def verify_witness_policy(policy, evidence, *, now, receipt_checkpoint=None):
    """Run the policy's witness-consistency mode, fail-closed.

    ``policy`` is the signed policy's ``witness_consistency`` section
    (strict-shaped by :func:`_policy_shape`); ``evidence`` carries
    ``head_note`` (the cosigned checkpoint note for the current head)
    and, when the policy pins an ``accepted_head``, ``consistency_proof``
    (the wire proof from the accepted head). A configured mode with
    missing evidence refuses ``witness-consistency-missing`` --
    configured means required.

    ``receipt_checkpoint`` is the VERIFIED dict checkpoint the bundle's
    inclusion receipt proved (``treeSize``/``rootHash``); when given
    with a pinned ``accepted_head`` the growth check runs through
    :func:`verify_consistency_chain`, binding the proof to the receipt
    (CVE-2026-22703: a proof for a different digest/checkpoint refuses).

    Order: quorum -> freshness -> growth (growth skipped when the policy
    pins no ``accepted_head`` -- steady state needs no proof). Returns
    the verified summary.
    """
    shaped = _policy_shape(policy)
    if not isinstance(evidence, dict):
        _refuse(WITNESS_CONSISTENCY_MISSING,
                "no consistency evidence presented")
    head_note = evidence.get("head_note")
    if not isinstance(head_note, (bytes, bytearray)) or not head_note:
        _refuse(WITNESS_CONSISTENCY_MISSING,
                "bundle carries no cosigned head_note")
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        _refuse(WITNESS_POLICY_MALFORMED, "now must be a non-negative int")
    q = require_cosignatures(bytes(head_note),
                             operator_vkeys=shaped["operator_vkeys"],
                             witness_vkeys=shaped["witness_vkeys"],
                             quorum_k=shaped["quorum_k"])
    fresh = check_freshness(q["fields"], now=now,
                            max_age=shaped["max_checkpoint_age"])
    growth = None
    if shaped["accepted_head"] is not None:
        proof = evidence.get("consistency_proof")
        # The proof may be empty only when the heads are identical
        # (steady state); verify_checkpoint_consistency decides --
        # growth from a smaller head with no proof refuses.
        if receipt_checkpoint is not None:
            growth = verify_consistency_chain(
                receipt_checkpoint, shaped["accepted_head"],
                bytes(head_note), proof,
                operator_vkeys=shaped["operator_vkeys"])
        else:
            growth = verify_checkpoint_consistency(
                shaped["accepted_head"], bytes(head_note), proof,
                operator_vkeys=shaped["operator_vkeys"])
    head = _head_of(q["fields"])
    return {"head": dict(head, timestamp=fresh["timestamp"],
                         age=fresh["age"]),
            "cosignatures": q["cosignatures"],
            "witnesses": q["witnesses"],
            "growth": growth}
