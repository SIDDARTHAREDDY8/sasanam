"""Mint-once random per-install host identity (W241-1).

Mechanism re-derived from treeship N-41 (v0.31.12, Apache-2.0 -- the
actual LICENSE file was read at pin time, 2026-09-30; no upstream
code reused, no imports, no vendoring). treeship's merged commit
``5bdef3c`` (stale title: "host digest") ships a *random per-install
id*, not a digest:

- ``host_`` + 16 hex from OS randomness, minted once per install,
  persisted with mode 0600;
- never through a symlink (``O_CREAT|O_EXCL|O_NOFOLLOW``); the loser
  of a mint race reads the winner's id;
- hostname, hostname-digest, per-run UUID, env-only and race-unsafe
  were all rejected with reasons -- "a digest with no secret reverses
  from a short guess list of common machine names."

Steal the mechanism, adapted to Sasanam:

- ``mint_host_id`` mints once, 0600, no-symlink, race-safe;
- ``validate_host_identity`` refuses hostnames and hostname-digests
  (sha256/sha1 of the current hostname) as host identity;
- ``assert_receipt_host_identity``: evidence receipts that name a host
  identity MUST carry the random id; receipts that name none yield the
  explicit ``host_unknown`` fallback, which can never validate as a
  minted id.

Honest residuals (deployment-owned, not silently solved):

- no env-var override is honored (treeship has TREESHIP_HOST_ID);
  deployments that need a pinned id must pre-place the file with the
  same shape and mode;
- the hostname-digest check covers the *current* machine's hostname
  only; a digest of another machine's hostname is not detectable
  locally and is refused as malformed, not as a digest;
- the id names an install, not a machine: cloning a disk image clones
  the id. Identity stability across clones is deployment-owned.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import errno
import hashlib
import os
import re
import socket
import stat
import time

__all__ = [
    "HOST_ID_PATTERN",
    "HOST_UNKNOWN",
    "DEFAULT_DIR_NAME",
    "HostIdentityError",
    "default_id_path",
    "mint_host_id",
    "read_host_id",
    "validate_host_identity",
    "assert_receipt_host_identity",
]

#: Canonical shape: ``host_`` + 16 lowercase hex chars (8 bytes entropy).
HOST_ID_PATTERN = re.compile(r"^host_[0-9a-f]{16}$")

#: Explicit fallback for receipts that name no host identity. It is not
#: a valid minted id and can never pass validation.
HOST_UNKNOWN = "host_unknown"

#: Install-level storage directory under the user's home.
DEFAULT_DIR_NAME = ".sasanam"

_ID_FILE_NAME = "host_id"

# Bounded settle: the loser of a mint race may open the id file in the
# tiny window between the winner's O_EXCL create and its write. Retry
# briefly rather than reporting corruption for a race we caused.
_SETTLE_ATTEMPTS = 50
_SETTLE_DELAY_S = 0.001

# How many bytes to read from the id file: id shape plus slack.
_READ_LIMIT = 64


class HostIdentityError(Exception):
    """Raised for every host-identity refusal. Carries the refusal code."""

    def __init__(self, code, detail=""):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def default_id_path():
    """Install-level id path: ``~/.sasanam/host_id`` (computed per call
    so HOME changes in tests take effect)."""
    return os.path.join(os.path.expanduser("~"), DEFAULT_DIR_NAME,
                         _ID_FILE_NAME)


def _is_host_identity(value):
    return isinstance(value, str) and HOST_ID_PATTERN.match(value) is not None


def _refuse(code, detail=""):
    raise HostIdentityError(code, detail)


def _open_existing(path):
    """Open an existing id file for reading; never follow symlinks."""
    try:
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            _refuse("hostid-symlink-at-id-path",
                    "id path %r is a symlink; refusing to follow" % path)
        if exc.errno == errno.ENOENT:
            _refuse("hostid-id-file-corrupt",
                    "id file %r does not exist; mint first" % path)
        raise


def _validated_read(path):
    """Read and shape-validate an existing id file (no symlink follow).

    Retries briefly when the content is not yet a valid id, to absorb
    the mint-race settle window before declaring corruption.
    """
    last = ""
    for _ in range(_SETTLE_ATTEMPTS):
        fd = _open_existing(path)
        try:
            raw = os.read(fd, _READ_LIMIT)
        finally:
            os.close(fd)
        value = raw.decode("ascii", errors="replace").strip()
        if _is_host_identity(value):
            return value
        last = value
        time.sleep(_SETTLE_DELAY_S)
    _refuse("hostid-id-file-corrupt",
            "id file %r holds %r, not a valid host identity" % (path, last))


def read_host_id(path=None):
    """Return the persisted host id; refuse on symlink or corrupt file.

    The lstat pre-check is a fast-fail for directories and special
    files; the O_NOFOLLOW open in _open_existing is the authoritative
    no-symlink check (it also covers a symlink swapped in between).
    """
    path = path if path is not None else default_id_path()
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        _refuse("hostid-id-file-corrupt",
                "id file %r does not exist; mint first" % path)
    if stat.S_ISLNK(st.st_mode):
        _refuse("hostid-symlink-at-id-path",
                "id path %r is a symlink; refusing to follow" % path)
    if not stat.S_ISREG(st.st_mode):
        _refuse("hostid-id-file-corrupt",
                "id path %r is not a regular file" % path)
    return _validated_read(path)


def mint_host_id(path=None):
    """Mint the host id once; return the id on every call.

    First caller wins the race: ``O_CREAT|O_EXCL|O_NOFOLLOW`` creates
    the file 0600; the race loser reads the winner's id. Both callers
    see the identical id.
    """
    path = path if path is not None else default_id_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)

    new_id = "host_" + os.urandom(8).hex()
    payload = new_id.encode("ascii")
    try:
        fd = os.open(path,
                     os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                     0o600)
    except FileExistsError:
        # Race loser (or later caller): read the winner's id.
        return _validated_read(path)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            _refuse("hostid-symlink-at-id-path",
                    "id path %r is a symlink; refusing to mint" % path)
        raise

    try:
        # Single write: atomic for this size under O_EXCL ownership.
        written = os.write(fd, payload)
        if written != len(payload):
            _refuse("hostid-id-file-corrupt",
                    "short write minting id file %r" % path)
        os.fsync(fd)
    finally:
        os.close(fd)

    # Paranoia: confirm what landed is a 0600 regular file, not a symlink.
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600:
        _refuse("hostid-id-file-corrupt",
                "minted id file %r has unexpected mode/shape" % path)
    return new_id


def _current_hostname():
    return socket.gethostname()


def _hostname_digests(hostname):
    blob = hostname.encode("utf-8", errors="replace")
    return {
        hashlib.sha256(blob).hexdigest(),
        hashlib.sha1(blob).hexdigest(),
    }


def validate_host_identity(value, *, hostname=None):
    """Validate a claimed host identity; return it, or refuse.

    Refusals:
    - ``hostid-hostname-not-identity``: the claim is the machine
      hostname itself;
    - ``hostid-hostname-digest-not-identity``: the claim is a
      (sha256/sha1) hex digest of the machine hostname -- a digest
      with no secret reverses from a short guess list;
    - ``hostid-malformed-identity``: anything else that is not
      ``host_[0-9a-f]{16}``.
    """
    host = _current_hostname() if hostname is None else hostname
    if isinstance(value, str) and value == host:
        _refuse("hostid-hostname-not-identity",
                "hostname %r is not a host identity" % value)
    if isinstance(value, str) and value in _hostname_digests(host):
        _refuse("hostid-hostname-digest-not-identity",
                "digest of hostname %r is not a host identity" % host)
    if not _is_host_identity(value):
        _refuse("hostid-malformed-identity",
                "expected host_[0-9a-f]{16}, got %r" % (value,))
    return value


def assert_receipt_host_identity(receipt, *, hostname=None):
    """Validate the ``host_identity`` a receipt names.

    Receipts that name a host identity must carry the random minted id.
    Receipts that name none yield the explicit ``host_unknown``
    fallback (which can never validate as a minted id).
    """
    if not isinstance(receipt, dict):
        _refuse("hostid-malformed-identity",
                "receipt is not a mapping: %r" % (receipt,))
    value = receipt.get("host_identity", HOST_UNKNOWN)
    if value is None:
        value = HOST_UNKNOWN
    if value == HOST_UNKNOWN:
        return HOST_UNKNOWN
    return validate_host_identity(value, hostname=hostname)
