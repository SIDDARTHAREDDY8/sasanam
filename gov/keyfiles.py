"""Uniform fail-closed permission gate for key files (wave-91, G1).

Custody-harden audit (stream 2) found an inconsistent permission
posture across key-loading paths: ``KeyRing.load``,
``EnvelopeKeyRing.load``, ``ShareStore.load`` and ``load_root_seed``
all refuse group/world-readable files, but
``gov/anchorer.py::resolve_anchor_key`` warned on a 0644 anchor key
file and loaded it anyway, and
``gov/lineage.py::LineageTracker._load_or_create_key`` performed no
permission check at all on an existing run-key file.

Every key-file load in ``gov/`` should apply
:func:`require_private_key_file` BEFORE reading any key bytes:
missing -> ``FileNotFoundError``; symlink, non-regular file, or any
group/world permission bit -> ``PermissionError``. Fail-closed, never
warn-and-continue.

Behavior change (migration note): operators whose key files are
group/world-readable (e.g. 0644) will now get a loud refusal instead
of a warning. Remediation is ``chmod 600 <keyfile>``.
"""

import os
import stat
from pathlib import Path

__all__ = ["require_private_key_file"]


def require_private_key_file(path):
    """Fail-closed permission gate for key files.

    Raises ``FileNotFoundError`` if the path does not exist and
    ``PermissionError`` if it is a symlink, is not a regular file, or
    carries any group/world permission bit. Returns the resolved
    :class:`pathlib.Path` on success — the caller may then read it
    knowing no weaker posture was silently accepted.

    The check happens BEFORE any key bytes are read; callers must
    invoke this first.
    """
    p = Path(path)
    try:
        st = p.stat()  # follows symlinks; the symlink test below is separate
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
