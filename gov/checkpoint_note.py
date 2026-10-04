"""C2SP tlog-checkpoint signed notes for evidence-bundle anchoring (wave-238).

Steals the C2SP tlog-checkpoint wire format (c2sp.org/tlog-checkpoint
and the signed-note spec c2sp.org/signed-note, both fetched 2026-09-30):
a checkpoint is a signed note whose body is exactly

    <origin>
    <tree size>
    <base64 root hash>

followed by a blank line and one or more signature lines

    \\u2014 <key name> <base64(4-byte key ID || signature)>

Our hermetic log (``gov/rekor_v2_anchor.py``) emits these checkpoints so
that a THIRD PARTY -- not just our own verifier -- can parse and verify
them. A checkpoint format only our own code can parse is self-attestation
wearing a transparency costume; byte-compat with C2SP is the fix. The
battery ``evals/w238_checkpoint_probes.py`` proves it with an
independently written reader.

Key-ID collision rules (signed-note spec, enforced in
:func:`verify_checkpoint`): the tuple (key name, key ID) identifies the
key. A signature line matching a known key's name but NOT its key ID --
or its ID but not its name -- is an UNKNOWN signature and is IGNORED,
never a verification failure and never an accept. Key IDs are 4-byte
identifiers, not a security boundary: a name+ID collision against an
attacker's key simply fails verification against the configured public
key.

Emission is strict: :func:`emit_checkpoint` produces EXACTLY the three
body lines -- there is no parameter for extension lines or bespoke
content, so bespoke serializations cannot be smuggled into a checkpoint.
Parsing accepts extension lines (the spec allows them) but surfaces them
explicitly; they are NOT RECOMMENDED and not auditable by monitors.

Machine refusals (all vocabulary-bound to ``gov/decision_codes.py``,
domain ``checkpoint``):

- ``checkpoint-origin-empty`` -- origin missing, empty, or carrying
  spaces/plus (our emission; the spec only RECOMMENDs the shape).
- ``checkpoint-size-malformed`` -- tree size not ASCII decimal without
  leading zeros.
- ``checkpoint-root-malformed`` -- root hash not base64 of 32 bytes.
- ``checkpoint-extension-empty`` -- an extension line is empty (the
  spec requires extension lines to be non-empty).
- ``checkpoint-note-malformed`` -- the bytes are not a valid signed
  note at all (bad UTF-8, control characters, no signature section,
  malformed signature line).
- ``checkpoint-not-c2sp`` -- a validly-signed note whose body is NOT
  the checkpoint 3-line format. Bespoke signed notes stay internal;
  the checkpoint path refuses them.
- ``checkpoint-known-signature-invalid`` -- a signature from a KNOWN
  key (name AND key ID match) failed verification: the whole note is
  rejected.
- ``checkpoint-no-trusted-signature`` -- no signature from a known key
  verified (unknown signatures are ignored per the collision rules).
- ``checkpoint-log-empty`` -- a log with tree size 0 cannot emit a
  checkpoint: our hermetic log's RFC 6962 tree has no defined root for
  the empty tree, so we refuse instead of inventing one.
- ``checkpoint-inconsistent`` -- the :class:`CheckpointJournal`
  refused to sign a different root for an already-signed
  (origin, size): the log MUST NOT sign checkpoints inconsistent with
  ones it already signed.

Stdlib only (Ed25519 via the vendored ``gov.ed25519``). Deterministic:
no clock, no randomness, no I/O, no env reads.

What this does NOT do (honest boundaries):

- Parseability is a format property, not a truth property. A
  third-party-verifiable checkpoint proves the log SIGNED this tree
  head; it does not prove the tree commits to real entries. A log can
  checkpoint a fabricated tree -- monitors must demand consistency
  proofs between checkpoints, which this module does not verify.
- The journal's equivocation guard is in-memory. Persistence is
  deployment-owned: a fresh journal forgets history, and a log that
  restarts with a fresh journal can re-sign what it already signed
  (identical bytes -- harmless) but loses the cross-restart
  equivocation tripwire.
- Consistency proofs are not checked here. The journal only refuses
  same-(origin, size)-different-root; full consistency-proof
  verification between checkpoints of different sizes is the
  monitor's job.
- Only Ed25519 (signature type 0x01) is implemented. Other C2SP
  signature types are refused at verifier-key parse time.
"""

import base64
import hashlib
import importlib.util
import os
import re

# Lazy Ed25519 (wave-319 lane 3): ``from gov import ed25519`` would
# execute ``gov/__init__.py``, whose transitive imports include
# ``urllib`` -- network-capable code in the import closure. This module
# is loaded by file path by ``gov/witness_consistency.py``, which is
# itself loaded by file path by the offline verifier, whose contract is
# zero network (the ``gov/trust_root_refresh.py`` pattern). The vendored
# primitive is loaded directly from the sibling file instead; it imports
# only hashlib+secrets, so the true import closure stays socket-free.
# Behavior is identical: the same ``gov/ed25519.py`` code, cross-tested
# by ``tests/test_checkpoint_note.py``.
_ed25519 = None


def _ed():
    global _ed25519
    if _ed25519 is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "ed25519.py")
        try:
            spec = importlib.util.spec_from_file_location(
                "sasanam_standalone_ed25519_checkpoint", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001
            raise CheckpointNoteError(
                CHECKPOINT_NOTE_MALFORMED,
                "cannot load ed25519 from %r: %s" % (path, exc))
        _ed25519 = module
    return _ed25519

SIG_TYPE_ED25519 = 0x01
EM_DASH = "\u2014"

CHECKPOINT_ORIGIN_EMPTY = "checkpoint-origin-empty"
CHECKPOINT_SIZE_MALFORMED = "checkpoint-size-malformed"
CHECKPOINT_ROOT_MALFORMED = "checkpoint-root-malformed"
CHECKPOINT_EXTENSION_EMPTY = "checkpoint-extension-empty"
CHECKPOINT_NOTE_MALFORMED = "checkpoint-note-malformed"
CHECKPOINT_NOT_C2SP = "checkpoint-not-c2sp"
CHECKPOINT_KNOWN_SIGNATURE_INVALID = "checkpoint-known-signature-invalid"
CHECKPOINT_NO_TRUSTED_SIGNATURE = "checkpoint-no-trusted-signature"
CHECKPOINT_LOG_EMPTY = "checkpoint-log-empty"
CHECKPOINT_INCONSISTENT = "checkpoint-inconsistent"

CHECKPOINT_CODES = (
    CHECKPOINT_ORIGIN_EMPTY,
    CHECKPOINT_SIZE_MALFORMED,
    CHECKPOINT_ROOT_MALFORMED,
    CHECKPOINT_EXTENSION_EMPTY,
    CHECKPOINT_NOTE_MALFORMED,
    CHECKPOINT_NOT_C2SP,
    CHECKPOINT_KNOWN_SIGNATURE_INVALID,
    CHECKPOINT_NO_TRUSTED_SIGNATURE,
    CHECKPOINT_LOG_EMPTY,
    CHECKPOINT_INCONSISTENT,
)

_SIZE_RE = re.compile(r"^(0|[1-9][0-9]*)$")


class CheckpointNoteError(Exception):
    """Product refusal carrying the machine code as the first arg."""

    def __init__(self, code, detail):
        super(CheckpointNoteError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Key IDs and verifier keys (c2sp.org/signed-note).
# ---------------------------------------------------------------------------

def derive_key_id(key_name, signature_type, public_key):
    """key ID = SHA-256(key name || 0x0A || sig type || pubkey)[:4].

    Raises ValueError on malformed inputs (programming error, not a
    product refusal: key material is caller configuration).
    """
    if not isinstance(key_name, str) or not key_name:
        raise ValueError("key_name must be a non-empty string")
    if not isinstance(signature_type, int) or not 0 <= signature_type <= 255:
        raise ValueError("signature_type must be a byte value")
    pub = bytes(public_key)
    if not pub:
        raise ValueError("public_key must be non-empty bytes")
    return hashlib.sha256(
        key_name.encode("utf-8") + b"\x0a" + bytes([signature_type])
        + pub).digest()[:4]


def vkey_string(key_name, key_id, signature_type, public_key):
    """Verifier-key text: ``name+hex(keyID)+base64(sigtype||pubkey)``."""
    if not isinstance(key_name, str) or not key_name:
        raise ValueError("key_name must be a non-empty string")
    kid = bytes(key_id)
    if len(kid) != 4:
        raise ValueError("key_id must be 4 bytes")
    blob = bytes([signature_type]) + bytes(public_key)
    return "%s+%s+%s" % (
        key_name, kid.hex(), base64.b64encode(blob).decode("ascii"))


def parse_vkey(vkey):
    """Parse a verifier-key string, strictly.

    The embedded key ID MUST recompute from (name, sig type, pubkey);
    a vkey that does not is corrupt configuration. Only Ed25519
    (0x01) is supported. Raises ValueError on any failure.
    """
    if not isinstance(vkey, str):
        raise ValueError("vkey must be a string")
    # Key names cannot contain plus and key IDs are hex, but the
    # base64 key material CAN contain plus: split at most twice.
    parts = vkey.split("+", 2)
    if len(parts) != 3:
        raise ValueError("vkey must be name+hexID+base64")
    name, kid_hex, rest = parts
    if not name:
        raise ValueError("vkey name is empty")
    try:
        key_id = bytes.fromhex(kid_hex)
    except ValueError:
        raise ValueError("vkey key ID is not hex")
    if len(key_id) != 4:
        raise ValueError("vkey key ID must be 4 bytes")
    try:
        blob = base64.b64decode(rest, validate=True)
    except Exception:
        raise ValueError("vkey key material is not base64")
    if len(blob) < 2:
        raise ValueError("vkey key material too short")
    sig_type, pubkey = blob[0], blob[1:]
    if sig_type != SIG_TYPE_ED25519:
        raise ValueError("unsupported signature type 0x%02x" % sig_type)
    if len(pubkey) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    if derive_key_id(name, sig_type, pubkey) != key_id:
        raise ValueError("vkey key ID does not recompute from key material")
    return {"name": name, "key_id": key_id,
            "signature_type": sig_type, "public_key": pubkey}


# ---------------------------------------------------------------------------
# Signed-note parsing (c2sp.org/signed-note).
# ---------------------------------------------------------------------------

def _has_forbidden_name_char(name):
    return "+" in name or any(ch.isspace() for ch in name)


def _split_note(note):
    """Split signed-note bytes into (note text, signature records).

    The note text includes the final newline but not the separating
    blank line; the text is separated from the signatures by the LAST
    empty line. Anything structurally wrong refuses
    ``checkpoint-note-malformed``.
    """
    if isinstance(note, str):
        note = note.encode("utf-8")
    data = bytes(note)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise CheckpointNoteError(
            CHECKPOINT_NOTE_MALFORMED,
            "note is not valid UTF-8")
    for ch in text:
        if ord(ch) < 0x20 and ch != "\n":
            raise CheckpointNoteError(
                CHECKPOINT_NOTE_MALFORMED,
                "note contains ASCII control characters")
    if not text.endswith("\n"):
        raise CheckpointNoteError(
            CHECKPOINT_NOTE_MALFORMED,
            "note text must end with a newline")
    lines = text.split("\n")
    body = lines[:-1]  # drop the mandatory trailing empty string
    empties = [i for i, ln in enumerate(body) if ln == ""]
    if not empties:
        raise CheckpointNoteError(
            CHECKPOINT_NOTE_MALFORMED,
            "note has no signature section (no blank separator line)")
    sep = empties[-1]
    # The note text includes its final newline but NOT the blank
    # separator line: the text is body[:sep], re-joined with the
    # trailing newline restored.
    note_text = ("\n".join(body[:sep]) + "\n").encode("utf-8")
    sig_lines = body[sep + 1:]
    if not sig_lines or any(ln == "" for ln in sig_lines):
        raise CheckpointNoteError(
            CHECKPOINT_NOTE_MALFORMED,
            "signature section is empty or has empty lines")
    sigs = []
    for ln in sig_lines:
        parts = ln.split(" ")
        if len(parts) != 3 or parts[0] != EM_DASH:
            raise CheckpointNoteError(
                CHECKPOINT_NOTE_MALFORMED,
                "malformed signature line")
        name, b64sig = parts[1], parts[2]
        if not name or _has_forbidden_name_char(name):
            raise CheckpointNoteError(
                CHECKPOINT_NOTE_MALFORMED,
                "signature key name is empty or carries spaces/plus")
        try:
            raw = base64.b64decode(b64sig, validate=True)
        except Exception:
            raise CheckpointNoteError(
                CHECKPOINT_NOTE_MALFORMED,
                "signature is not valid base64")
        if len(raw) < 5:  # 4-byte key ID + at least 1 signature byte
            raise CheckpointNoteError(
                CHECKPOINT_NOTE_MALFORMED,
                "signature too short for key ID + signature")
        sigs.append({"key_name": name, "key_id": raw[:4],
                     "signature": raw[4:]})
    return note_text, sigs


# ---------------------------------------------------------------------------
# Checkpoint body grammar (c2sp.org/tlog-checkpoint).
# ---------------------------------------------------------------------------

def _parse_checkpoint_body(note_text):
    text = note_text.decode("utf-8")
    lines = text.split("\n")
    body = lines[:-1]  # note_text always ends with exactly one newline
    if len(body) < 3:
        raise CheckpointNoteError(
            CHECKPOINT_NOT_C2SP,
            "checkpoint body needs origin/size/root-hash lines")
    origin, size_s, root_s = body[0], body[1], body[2]
    if origin == "":
        raise CheckpointNoteError(
            CHECKPOINT_ORIGIN_EMPTY,
            "checkpoint origin line is empty")
    if _SIZE_RE.match(size_s) is None:
        raise CheckpointNoteError(
            CHECKPOINT_SIZE_MALFORMED,
            "tree size is not ASCII decimal without leading zeros")
    try:
        root = base64.b64decode(root_s, validate=True)
    except Exception:
        raise CheckpointNoteError(
            CHECKPOINT_ROOT_MALFORMED,
            "root hash is not valid base64")
    if len(root) != 32:
        raise CheckpointNoteError(
            CHECKPOINT_ROOT_MALFORMED,
            "root hash must decode to 32 bytes")
    extensions = body[3:]
    for ext in extensions:
        if ext == "":
            raise CheckpointNoteError(
                CHECKPOINT_EXTENSION_EMPTY,
                "extension lines must be non-empty")
    return {"origin": origin, "tree_size": int(size_s),
            "root_hash": root, "extensions": tuple(extensions)}


def parse_checkpoint(note):
    """Parse a checkpoint note strictly; returns its fields.

    Refuses ``checkpoint-note-malformed`` (not a signed note),
    ``checkpoint-not-c2sp`` (a signed note, but not the checkpoint
    format), or the field-specific codes. Extension lines are
    returned explicitly -- their presence is a flag to the caller,
    since monitors cannot audit them.
    """
    note_text, sigs = _split_note(note)
    fields = _parse_checkpoint_body(note_text)
    fields["signatures"] = sigs
    return fields


# ---------------------------------------------------------------------------
# Emission.
# ---------------------------------------------------------------------------

def _check_emission_name(label, name):
    # The origin is a checkpoint field: a bad origin is a product
    # refusal. The key name is signer configuration: a bad key name
    # is a programming error (ValueError), the same convention as
    # derive_key_id / vkey_string / parse_vkey.
    if not isinstance(name, str) or name == "":
        if label == "origin":
            raise CheckpointNoteError(
                CHECKPOINT_ORIGIN_EMPTY,
                "origin must be a non-empty string")
        raise ValueError("key_name must be a non-empty string")
    if _has_forbidden_name_char(name):
        if label == "origin":
            raise CheckpointNoteError(
                CHECKPOINT_ORIGIN_EMPTY,
                "origin must not contain spaces or plus")
        raise ValueError("key_name must not contain spaces or plus")


def emit_checkpoint(origin, tree_size, root_hash, key_name, seed):
    """Emit a C2SP tlog-checkpoint signed note (bytes).

    The body is EXACTLY the three checkpoint lines -- this function
    takes no extension or bespoke-content parameter, so bespoke
    serializations cannot be smuggled into a checkpoint. ``root_hash``
    is the 32-byte RFC 6962 tree root; ``seed`` is the 32-byte
    Ed25519 seed that signs. Deterministic: same inputs, same bytes.
    """
    _check_emission_name("origin", origin)
    _check_emission_name("key_name", key_name)
    if (not isinstance(tree_size, int) or isinstance(tree_size, bool)
            or tree_size < 0):
        raise CheckpointNoteError(
            CHECKPOINT_SIZE_MALFORMED,
            "tree_size must be a non-negative int")
    root = bytes(root_hash)
    if len(root) != 32:
        raise CheckpointNoteError(
            CHECKPOINT_ROOT_MALFORMED,
            "root_hash must be 32 bytes")
    if not isinstance(seed, (bytes, bytearray)) or len(bytes(seed)) != 32:
        raise ValueError("seed must be 32 bytes")
    seed = bytes(seed)
    text = "%s\n%d\n%s\n" % (
        origin, tree_size, base64.b64encode(root).decode("ascii"))
    text_bytes = text.encode("utf-8")
    public = _ed().publickey(seed)
    key_id = derive_key_id(key_name, SIG_TYPE_ED25519, public)
    sig = _ed().sign(seed, text_bytes)
    sig_line = "%s %s %s\n" % (
        EM_DASH, key_name,
        base64.b64encode(key_id + sig).decode("ascii"))
    return text_bytes + b"\n" + sig_line.encode("utf-8")


# ---------------------------------------------------------------------------
# Verification.
# ---------------------------------------------------------------------------

def verify_checkpoint(note, vkeys):
    """Verify a checkpoint note against verifier keys.

    ``vkeys`` is an iterable of verifier-key strings (the verifier's
    own configuration, e.g. ``name+hexID+base64(type||pubkey)``).
    Unknown signatures -- including name-only or ID-only collisions --
    are IGNORED per the signed-note collision rules; they are never a
    failure and never an accept. A KNOWN key's signature that fails
    verification rejects the whole note. If no known key's signature
    verifies, the note is rejected.

    Returns the parsed checkpoint fields plus ``verified_by`` (the key
    names that verified). Extension lines, if present, are returned
    under ``extensions`` for the caller to flag.
    """
    parsed_vkeys = [parse_vkey(v) for v in vkeys]  # config errors: ValueError
    note_text, sigs = _split_note(note)
    fields = _parse_checkpoint_body(note_text)
    known = []
    for sig in sigs:
        for vkey in parsed_vkeys:
            if (sig["key_name"] == vkey["name"]
                    and sig["key_id"] == vkey["key_id"]):
                known.append((vkey, sig))
                break
    if not known:
        raise CheckpointNoteError(
            CHECKPOINT_NO_TRUSTED_SIGNATURE,
            "no signature from a known key verifies")
    verified_by = []
    for vkey, sig in known:
        try:
            good = _ed().verify(vkey["public_key"], note_text,
                                   sig["signature"])
        except Exception:
            good = False
        if not good:
            raise CheckpointNoteError(
                CHECKPOINT_KNOWN_SIGNATURE_INVALID,
                "signature from known key %r failed; note rejected"
                % (vkey["name"],))
        verified_by.append(vkey["name"])
    fields["signatures"] = sigs
    fields["verified_by"] = verified_by
    return fields


# ---------------------------------------------------------------------------
# Log adapter + equivocation journal.
# ---------------------------------------------------------------------------

class CheckpointJournal(object):
    """In-memory record of checkpoints this log has signed.

    Guards the C2SP rule that a log MUST NOT sign a checkpoint
    inconsistent with one it already signed: signing a DIFFERENT root
    for an already-signed (origin, size) refuses
    ``checkpoint-inconsistent``. Re-issuing the identical checkpoint
    is idempotent. Persistence is deployment-owned: a fresh journal
    forgets history (documented residual).
    """

    def __init__(self):
        self._signed = {}

    def issue(self, origin, tree_size, root_hash, key_name, seed):
        root = bytes(root_hash)
        key = (origin, int(tree_size))
        prev = self._signed.get(key)
        if prev is not None and prev != root:
            raise CheckpointNoteError(
                CHECKPOINT_INCONSISTENT,
                "a different root was already signed for %r at size %d"
                % (origin, tree_size))
        note = emit_checkpoint(origin, tree_size, root, key_name, seed)
        self._signed[key] = root
        return note


def checkpoint_for_log(log, origin, key_name, seed):
    """Emit a checkpoint binding a log's current tree head.

    ``log`` exposes ``current_root()`` returning
    ``{"tree_size": int, "root_hash": hex}`` -- the shape of
    ``gov/rekor_v2_anchor.HermeticRekorV2.current_root``. Additive:
    ``gov/rekor_v2_anchor.py`` is not modified. A tree of size 0 has
    no defined RFC 6962 root in our log, so it refuses
    ``checkpoint-log-empty`` instead of inventing one.
    """
    try:
        state = log.current_root()
        size = int(state["tree_size"])
        root = bytes.fromhex(state["root_hash"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CheckpointNoteError(
            CHECKPOINT_NOTE_MALFORMED,
            "log current_root() is malformed: %s" % (exc,))
    if size <= 0 or len(root) != 32:
        raise CheckpointNoteError(
            CHECKPOINT_LOG_EMPTY,
            "a log with an empty or rootless tree cannot checkpoint")
    return emit_checkpoint(origin, size, root, key_name, seed)
