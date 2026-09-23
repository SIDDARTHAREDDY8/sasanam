"""Prototype fix for audit finding G1 (stream 2, custody-harden).

Uniform fail-closed permission posture for key files.

Today four key-loading paths in ``gov/`` refuse group/world-readable
files with ``PermissionError`` (``KeyRing.load``,
``EnvelopeKeyRing.load``, ``ShareStore.load``, ``load_root_seed``), but
two do not:

* ``gov/anchorer.py::resolve_anchor_key`` — a ``GOV_ANCHOR_KEY_FILE``
  with mode 0644 gets a stderr WARNING and loads anyway;
* ``gov/lineage.py::LineageTracker._load_or_create_key`` — no permission
  check at all on an existing run-key file.

This module is a REFERENCE IMPLEMENTATION for central integration — it
does not modify ``gov/``. It imports ``gov`` read-only (the anchor key
derivation helpers) and provides:

* :func:`require_private_key_file` — the uniform check every key-file
  load should apply: the path must exist, must be a regular file (not a
  symlink, not a directory/fifo/socket), and must have no group/world
  permission bits. Anything else raises ``PermissionError`` (or
  ``FileNotFoundError`` for a missing path) — fail-closed, never
  warn-and-continue.
* :func:`load_anchor_seed_strict` — the ``GOV_ANCHOR_KEY_FILE`` branch
  of ``resolve_anchor_key`` with warn-only replaced by refuse. Returns
  the same dict shape (``seed`` / ``key_id`` / ``pubkey_hex`` /
  ``dev=False``) so it is a drop-in for the file branch.
* :func:`load_or_create_lineage_key_strict` — the lineage run-key
  loader with the missing permission check added: an existing key file
  with group/world bits is refused (never silently loaded); a
  degenerate (<16 byte) file is rotated; creation is atomic 0600.

Fail-closed ordering is preserved everywhere: the permission check
happens BEFORE any key bytes are read.

$0 spend, synthetic/local only. No credentials, no network.
"""

import os
import stat
from pathlib import Path

# Read-only use of gov/: key derivation only, no behavior changes.
from gov.anchor_backend import anchor_key_id, anchor_pubkey

__all__ = [
    "require_private_key_file",
    "load_anchor_seed_strict",
    "load_or_create_lineage_key_strict",
]

_MIN_KEY_BYTES = 16  # parity with lineage._load_or_create_key
_LINEAGE_KEY_NAME = "run.key"  # illustrative; mirrors lineage._KEY_NAME


def require_private_key_file(path):
    """Fail-closed permission gate for key files.

    Raises ``FileNotFoundError`` if the path does not exist,
    ``PermissionError`` if it is not a regular file, is a symlink, or
    carries any group/world permission bit. Returns the resolved
    :class:`pathlib.Path` on success — the caller may then read it
    knowing no weaker posture was silently accepted.
    """
    p = Path(path)
    try:
        st = p.stat()  # follows symlinks for the mode check below
    except FileNotFoundError:
        raise FileNotFoundError(
            "key file %s does not exist (fail-closed: refusing to "
            "continue without key material)" % (p,))
    # Refuse symlinks outright: a symlink can point at an
    # attacker-readable target while the link itself looks private.
    if p.is_symlink():
        raise PermissionError(
            "refusing to load key file %s: symlinks are not accepted "
            "for key material" % (p,))
    if not stat.S_ISREG(st.st_mode):
        raise PermissionError(
            "refusing to load key file %s: not a regular file "
            "(mode %o)" % (p, st.st_mode & 0o7777))
    if st.st_mode & 0o077:
        raise PermissionError(
            "refusing to load key file %s: file is group/world-readable "
            "or writable (mode %o); chmod 600 first" % (p, st.st_mode & 0o777))
    return p


def load_anchor_seed_strict(path):
    """Strict variant of the ``GOV_ANCHOR_KEY_FILE`` branch of
    ``gov.anchorer.resolve_anchor_key``.

    Identical semantics except the permission posture: where
    ``resolve_anchor_key`` warns on group/world-accessible files and
    loads anyway, this refuses with ``PermissionError`` (G1 fix).
    Returns ``{"seed", "key_id", "pubkey_hex", "dev": False}``.
    """
    p = require_private_key_file(path)  # fail-closed BEFORE reading
    try:
        seed_hex = p.read_text(encoding="utf-8").strip()
        seed = bytes.fromhex(seed_hex)
    except (OSError, ValueError) as e:
        raise ValueError("cannot read anchor key file %s: %s" % (p, e))
    if len(seed) != 32:
        raise ValueError("anchor key file %s must hold 32 bytes hex" % (p,))
    pub = anchor_pubkey(seed)
    return {"seed": seed,
            "key_id": anchor_key_id(pub),
            "pubkey_hex": pub.hex(),
            "dev": False}


def load_or_create_lineage_key_strict(tracker_dir,
                                      key_name=_LINEAGE_KEY_NAME):
    """Strict variant of ``LineageTracker._load_or_create_key``.

    Adds the missing permission check (G1 fix): an existing key file
    with group/world bits is refused, never silently loaded. Degenerate
    (<16 byte) files are rotated rather than run weak, matching the
    existing behavior. Creation is atomic 0600.
    """
    d = Path(tracker_dir)
    key_path = d / key_name
    if key_path.is_file() and not key_path.is_symlink():
        # Existing file: enforce the uniform posture BEFORE reading.
        require_private_key_file(key_path)
        key = key_path.read_bytes()
        if len(key) >= _MIN_KEY_BYTES:
            return key
        # Degenerate key file: rotate rather than run weak.
    elif key_path.is_symlink() or key_path.exists():
        # Symlink or non-regular existing path: refuse outright.
        require_private_key_file(key_path)  # raises PermissionError
    key = os.urandom(32)
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return key
