"""Wave-238 C2SP tlog-checkpoint probes (W238-1, red-first).

Steals the C2SP tlog-checkpoint wire format (c2sp.org/tlog-checkpoint,
signed-note spec c2sp.org/signed-note, both fetched 2026-09-30) for
Sasanam's evidence-bundle anchoring checkpoints: our hermetic log emits
byte-exact C2SP signed notes so a THIRD PARTY can parse and verify them,
not just our own code.

The attack class: a checkpoint format that only our own verifier can
parse is self-attestation wearing a transparency costume. The fix is
byte-compat: emit the exact C2SP wire format (origin/size/root-hash
lines + signed-note envelope + key-ID collision rules) and prove a
reader written independently from the spec text accepts our notes.

Probes:
  checkpoint-third-party-reader-accepts -- an independent reader,
      written from the spec text in this file (own vkey parse, own
      key-ID derivation, own signature-line parse; only the raw
      Ed25519 primitive is shared), accepts and verifies a checkpoint
      our module emitted. Byte-compat proof, not self-attestation.
  checkpoint-one-byte-mutation-refuses -- one flipped body byte makes
      verify_checkpoint refuse checkpoint-known-signature-invalid.
  checkpoint-bespoke-note-refused -- a validly-signed note whose body
      is NOT the checkpoint 3-line format is refused
      checkpoint-not-c2sp by the checkpoint path, and emit_checkpoint
      exposes no parameter for bespoke/extension content (it cannot
      be smuggled).
  checkpoint-keyid-collision-ignored -- a signature line carrying the
      KNOWN key name but a WRONG key ID (attacker's colliding key)
      is IGNORED as unknown per the signed-note collision rules; with
      no other known signature the note refuses
      checkpoint-no-trusted-signature (never "invalid").
  checkpoint-unknown-signature-alone-refuses -- a note signed only by
      an unknown key refuses checkpoint-no-trusted-signature.
  checkpoint-known-sig-failure-rejects-note -- corrupting the
      signature bytes of a known key's signature (name+ID intact)
      rejects the whole note: checkpoint-known-signature-invalid.
  checkpoint-inconsistent-root-refused -- the checkpoint journal
      refuses to sign a different root for an already-signed
      (origin, size): checkpoint-inconsistent (C2SP: a log MUST NOT
      sign checkpoints inconsistent with ones it already signed).
  checkpoint-empty-log-refused -- a log with tree_size 0 cannot emit
      a checkpoint: checkpoint-log-empty.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import base64
import hashlib
import inspect
import os
import sys
import time
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import checkpoint_note as _cn
    from gov import ed25519 as _ed
    HAVE_NEW_API = all(hasattr(_cn, n) for n in (
        "emit_checkpoint", "parse_checkpoint", "verify_checkpoint",
        "derive_key_id", "vkey_string", "parse_vkey",
        "CheckpointNoteError", "CheckpointJournal",
        "checkpoint_for_log", "SIG_TYPE_ED25519"))
except ImportError:
    _cn = None
    _ed = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "checkpoint-third-party-reader-accepts",
    "checkpoint-one-byte-mutation-refuses",
    "checkpoint-bespoke-note-refused",
    "checkpoint-keyid-collision-ignored",
    "checkpoint-unknown-signature-alone-refuses",
    "checkpoint-known-sig-failure-rejects-note",
    "checkpoint-inconsistent-root-refused",
    "checkpoint-empty-log-refused",
]

EM_DASH = "\u2014"


# ---------------------------------------------------------------------------
# Independent third-party reader (written from the spec text, this file only).
#
# Implements c2sp.org/signed-note + c2sp.org/tlog-checkpoint from scratch:
#   note      = text "\n" ... "\n" "\n" sigline "\n" ...
#   sigline   = "\u2014" " " name " " base64(keyID32 || sig) "\n"
#   vkey      = name "+" hex(keyID) "+" base64(sigtype || pubkey)
#   keyID     = SHA-256(name || 0x0A || sigtype || pubkey)[:4]
# Shares NOTHING with gov/checkpoint_note except the raw Ed25519
# signature primitive (the algorithm, not the format logic).
# ---------------------------------------------------------------------------

def _reader_split(note_bytes):
    text = note_bytes.decode("utf-8")  # raises: not a note
    lines = text.split("\n")
    if not lines or lines[-1] != "":
        raise ValueError("note does not end with newline")
    # The text is separated from the signatures by the LAST empty line.
    body = lines[:-1]
    idx = max(i for i, ln in enumerate(body) if ln == "")
    text_lines = body[:idx + 1]
    sig_lines = body[idx + 1:]
    note_text = ("\n".join(text_lines)).encode("utf-8")
    return note_text, sig_lines


def _reader_key_id(name, sigtype, pubkey):
    return hashlib.sha256(
        name.encode("utf-8") + b"\x0a" + bytes([sigtype]) + pubkey
    ).digest()[:4]


def _reader_parse_vkey(vkey):
    # Names cannot contain plus and IDs are hex, but standard base64
    # CAN contain plus: split at most twice (same rule as the product
    # parser -- a reader that cannot parse our vkeys is a reader bug).
    name, kid_hex, rest = vkey.split("+", 2)
    kid = bytes.fromhex(kid_hex)
    blob = base64.b64decode(rest)
    sigtype, pubkey = blob[0], blob[1:]
    expect = _reader_key_id(name, sigtype, pubkey)
    if expect != kid:
        raise ValueError("vkey key-ID does not recompute")
    return name, kid, sigtype, pubkey


def _third_party_verify(note_bytes, vkey):
    """True iff the note carries a verifying signature from vkey."""
    note_text, sig_lines = _reader_split(note_bytes)
    name, kid, _sigtype, pubkey = _reader_parse_vkey(vkey)
    ok = False
    for line in sig_lines:
        if not line:
            continue
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != EM_DASH:
            return False  # malformed signature section
        sname, sblob = parts[1], parts[2]
        sig = base64.b64decode(sblob)
        # (name, key ID) BOTH identify the key: name-only or ID-only
        # matches are unknown keys and MUST be ignored.
        if sname != name or sig[:4] != kid:
            continue
        if _ed.verify(pubkey, note_text, sig[4:]):
            ok = True
    # Checkpoint body grammar check: origin / size / root-hash.
    text = note_text.decode("utf-8")
    body_lines = text.split("\n")[:-1]  # drop trailing newline
    if len(body_lines) < 3 or not body_lines[0]:
        return False
    size = body_lines[1]
    if not size.isdigit() or (len(size) > 1 and size[0] == "0"):
        return False
    root = base64.b64decode(body_lines[2])
    if len(root) != 32:
        return False
    return ok


# ---------------------------------------------------------------------------
# Probe fixtures (local helpers; need gov.checkpoint_note only for emit).
# ---------------------------------------------------------------------------

def _fixture_keypair():
    seed = _ed.generate_seed()
    return seed, _ed.publickey(seed)


def _fixture_log_state(nleaves=3):
    leaves = [hashlib.sha256(b"\x00leaf-%d" % i).digest()
              for i in range(nleaves)]

    def node(l, r):
        return hashlib.sha256(b"\x01" + l + r).digest()
    level = list(leaves)
    while len(level) > 1:
        nxt = [node(level[i], level[i + 1])
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return {"tree_size": nleaves, "root": level[0]}


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return (name, "GAP", "module absent on base")
    t0 = time.time()
    try:
        verdict, note = fn()
    except Exception:  # noqa: BLE001
        return (name, "ERROR", traceback.format_exc(limit=3).strip())
    return (name, "HELD" if verdict else "BREAK",
            "%s (%.1fms)" % (note, 1000 * (time.time() - t0)))


def probe_third_party_reader_accepts():
    # Byte-compat proof: an INDEPENDENT reader (above) accepts and
    # verifies a checkpoint our module emitted. If only our own
    # verifier can parse it, this is self-attestation, not a
    # transparency checkpoint.
    seed, pub = _fixture_keypair()
    st = _fixture_log_state()
    origin = "sasanam.test/hermetic-log"
    note = _cn.emit_checkpoint(origin, st["tree_size"], st["root"],
                               "sasanam.test/hermetic-log", seed)
    key_id = _cn.derive_key_id("sasanam.test/hermetic-log",
                               _cn.SIG_TYPE_ED25519, pub)
    vkey = _cn.vkey_string("sasanam.test/hermetic-log", key_id,
                           _cn.SIG_TYPE_ED25519, pub)
    ok = _third_party_verify(note, vkey)
    return ok, "independent reader %s our note" % (
        "accepted" if ok else "REJECTED")


def probe_one_byte_mutation_refuses():
    seed, _pub = _fixture_keypair()
    st = _fixture_log_state()
    origin = "sasanam.test/hermetic-log"
    note = _cn.emit_checkpoint(origin, st["tree_size"], st["root"],
                               origin, seed)
    pub = _ed.publickey(seed)
    key_id = _cn.derive_key_id(origin, _cn.SIG_TYPE_ED25519, pub)
    vkey = _cn.vkey_string(origin, key_id, _cn.SIG_TYPE_ED25519, pub)
    # Flip one byte of the checkpoint BODY (the tree-size line).
    lines = note.split(b"\n")
    mutated = lines[1][:-1] + (b"9" if lines[1][-1:] != b"9" else b"8")
    evil = b"\n".join([lines[0], mutated] + lines[2:])
    try:
        _cn.verify_checkpoint(evil, [vkey])
    except _cn.CheckpointNoteError as exc:
        ok = exc.code == "checkpoint-known-signature-invalid"
        return ok, "refused %s" % exc.code
    return False, "mutated body was ACCEPTED"


def probe_bespoke_note_refused():
    # A validly-signed signed note whose body is NOT the checkpoint
    # 3-line format must be refused by the checkpoint path: bespoke
    # serializations stay internal, never emitted/verified as
    # checkpoints.
    seed, pub = _fixture_keypair()
    origin = "sasanam.test/hermetic-log"
    text = b"this is a bespoke signed note, not a checkpoint\n"
    key_id = _cn.derive_key_id(origin, _cn.SIG_TYPE_ED25519, pub)
    line = EM_DASH.encode("utf-8") + b" " + origin.encode() + b" " + \
        base64.b64encode(key_id + _ed.sign(seed, text)) + b"\n"
    bespoke = text + b"\n" + line
    vkey = _cn.vkey_string(origin, key_id, _cn.SIG_TYPE_ED25519, pub)
    try:
        _cn.verify_checkpoint(bespoke, [vkey])
    except _cn.CheckpointNoteError as exc:
        ok_code = exc.code == "checkpoint-not-c2sp"
    else:
        return False, "bespoke note was ACCEPTED as checkpoint"
    # And the emit path must offer no smuggling hatch: no extensions
    # parameter, no bespoke-content parameter.
    params = set(inspect.signature(_cn.emit_checkpoint).parameters)
    ok_params = params == {"origin", "tree_size", "root_hash",
                           "key_name", "seed"}
    ok = ok_code and ok_params
    return ok, "bespoke refused=%s no-smuggle-param=%s" % (
        ok_code, ok_params)


def probe_keyid_collision_ignored():
    # Key-ID collision rule (signed-note spec): the tuple (name,
    # key ID) identifies the key. A signature line carrying the KNOWN
    # name but a WRONG key ID (attacker's colliding key) is an
    # UNKNOWN signature and MUST be ignored -- never a verification
    # failure, never an accept.
    seed, _pub = _fixture_keypair()
    origin = "sasanam.test/hermetic-log"
    st = _fixture_log_state()
    note = _cn.emit_checkpoint(origin, st["tree_size"], st["root"],
                               origin, seed)
    true_pub = _ed.publickey(seed)
    true_id = _cn.derive_key_id(origin, _cn.SIG_TYPE_ED25519, true_pub)
    # Attacker key with a forged key ID sharing the name only.
    evil_seed = _ed.generate_seed()
    evil_pub = _ed.publickey(evil_seed)
    evil_id = _cn.derive_key_id("attacker.example/evil",
                               _cn.SIG_TYPE_ED25519, evil_pub)
    assert evil_id != true_id
    # Rebuild the note with the attacker's key ID on OUR name line.
    lines = note.decode("utf-8").split("\n")
    sig_idx = next(i for i, ln in enumerate(lines)
                   if ln.startswith(EM_DASH))
    body, _oldline = lines[:sig_idx], lines[sig_idx]
    text = ("\n".join(body) + "\n").encode("utf-8")
    forged = (EM_DASH + " " + origin + " " +
              base64.b64encode(evil_id + _ed.sign(evil_seed,
                                                 text)).decode())
    collided = ("\n".join(body + [forged, ""])).encode("utf-8")
    vkey = _cn.vkey_string(origin, true_id, _cn.SIG_TYPE_ED25519,
                           true_pub)
    try:
        _cn.verify_checkpoint(collided, [vkey])
    except _cn.CheckpointNoteError as exc:
        ok = exc.code == "checkpoint-no-trusted-signature"
        return ok, "name-collision sig ignored, refused %s" % exc.code
    return False, "collided-name note was ACCEPTED"


def probe_unknown_signature_alone_refuses():
    seed, _pub = _fixture_keypair()
    origin = "sasanam.test/hermetic-log"
    st = _fixture_log_state()
    note = _cn.emit_checkpoint(origin, st["tree_size"], st["root"],
                               origin, seed)
    # A verifier that trusts NOBODY must reject: unknown sigs ignored,
    # none verified.
    stranger_seed = _ed.generate_seed()
    stranger_pub = _ed.publickey(stranger_seed)
    stranger_id = _cn.derive_key_id("stranger.example/log",
                                   _cn.SIG_TYPE_ED25519, stranger_pub)
    stranger_vkey = _cn.vkey_string("stranger.example/log", stranger_id,
                                   _cn.SIG_TYPE_ED25519, stranger_pub)
    try:
        _cn.verify_checkpoint(note, [stranger_vkey])
    except _cn.CheckpointNoteError as exc:
        ok = exc.code == "checkpoint-no-trusted-signature"
        return ok, "refused %s" % exc.code
    return False, "unknown-key note was ACCEPTED"


def probe_known_sig_failure_rejects_note():
    # A signature from a KNOWN key that fails verification rejects the
    # WHOLE note (signed-note spec: SHOULD reject).
    seed, pub = _fixture_keypair()
    origin = "sasanam.test/hermetic-log"
    st = _fixture_log_state()
    note = _cn.emit_checkpoint(origin, st["tree_size"], st["root"],
                               origin, seed)
    key_id = _cn.derive_key_id(origin, _cn.SIG_TYPE_ED25519, pub)
    vkey = _cn.vkey_string(origin, key_id, _cn.SIG_TYPE_ED25519, pub)
    lines = note.decode("utf-8").split("\n")
    sig_idx = next(i for i, ln in enumerate(lines)
                   if ln.startswith(EM_DASH))
    name, b64sig = lines[sig_idx].split(" ")[1:3]
    raw = bytearray(base64.b64decode(b64sig))
    raw[10] ^= 0xFF  # corrupt signature bytes, keep name+key ID
    lines[sig_idx] = EM_DASH + " " + name + " " + \
        base64.b64encode(bytes(raw)).decode()
    corrupted = ("\n".join(lines)).encode("utf-8")
    try:
        _cn.verify_checkpoint(corrupted, [vkey])
    except _cn.CheckpointNoteError as exc:
        ok = exc.code == "checkpoint-known-signature-invalid"
        return ok, "refused %s" % exc.code
    return False, "corrupted known signature was ACCEPTED"


def probe_inconsistent_root_refused():
    # C2SP: a log MUST NOT sign a checkpoint inconsistent with one it
    # already signed. Same (origin, size), different root = refused.
    journal = _cn.CheckpointJournal()
    seed, _pub = _fixture_keypair()
    origin = "sasanam.test/hermetic-log"
    st = _fixture_log_state()
    note1 = journal.issue(origin, st["tree_size"], st["root"],
                          origin, seed)
    ok_parse = _cn.parse_checkpoint(note1)["root_hash"] == st["root"]
    evil_root = hashlib.sha256(b"forged").digest()
    try:
        journal.issue(origin, st["tree_size"], evil_root, origin, seed)
    except _cn.CheckpointNoteError as exc:
        ok = ok_parse and exc.code == "checkpoint-inconsistent"
        return ok, "equivocating root refused %s" % exc.code
    return False, "equivocating root was SIGNED"


def probe_empty_log_refused():
    class _EmptyLog:
        def current_root(self):
            return {"tree_size": 0, "root_hash": "00" * 32}

    seed, _pub = _fixture_keypair()
    try:
        _cn.checkpoint_for_log(_EmptyLog(), "sasanam.test/hermetic-log",
                               "sasanam.test/hermetic-log", seed)
    except _cn.CheckpointNoteError as exc:
        ok = exc.code == "checkpoint-log-empty"
        return ok, "refused %s" % exc.code
    return False, "empty-log checkpoint was EMITTED"


_PROBES = {
    "checkpoint-third-party-reader-accepts": probe_third_party_reader_accepts,
    "checkpoint-one-byte-mutation-refuses": probe_one_byte_mutation_refuses,
    "checkpoint-bespoke-note-refused": probe_bespoke_note_refused,
    "checkpoint-keyid-collision-ignored": probe_keyid_collision_ignored,
    "checkpoint-unknown-signature-alone-refuses":
        probe_unknown_signature_alone_refuses,
    "checkpoint-known-sig-failure-rejects-note":
        probe_known_sig_failure_rejects_note,
    "checkpoint-inconsistent-root-refused": probe_inconsistent_root_refused,
    "checkpoint-empty-log-refused": probe_empty_log_refused,
}


def _run_green_checks():
    """Adjacent-seam sanity: no product-code regression. Depth-1 only;
    honors GOV_SKIP_GREEN=1 (never spawns another battery's main)."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import decision_codes as _dc
        for code in ("checkpoint-origin-empty",
                     "checkpoint-size-malformed",
                     "checkpoint-root-malformed",
                     "checkpoint-extension-empty",
                     "checkpoint-note-malformed",
                     "checkpoint-not-c2sp",
                     "checkpoint-known-signature-invalid",
                     "checkpoint-no-trusted-signature",
                     "checkpoint-log-empty",
                     "checkpoint-inconsistent"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-238 C2SP tlog-checkpoint probes (new API: %s)"
          % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, note in results:
        print("%-48s %s  %s" % (name, verdict, note))
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR"
          % (held, gap, brk, err))
    for note in _run_green_checks():
        print("GREEN:", note)
    if not HAVE_NEW_API:
        return 2  # genuine red: the capability does not exist
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
