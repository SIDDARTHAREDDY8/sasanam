"""Key management for the HMAC-authenticated action log (``gov/log.py``).

This module owns the **key lifecycle**; ``gov/log.py`` owns the **chain
mechanics** and is intentionally not modified. The two meet through
environment variables (``GOV_LOG_KEY`` / ``GOV_LOG_KEY_EPOCH`` /
``GOV_LOG_KEY_ARCHIVE``), which ``KeyRing.activate()`` sets — that is the
documented integration point (see ``INTEGRATION_WIRING.md``).

Design notes (research-grounded):

* **Epochs, not just keys.** Every key carries an epoch label that is bound
  into every log-entry MAC and checkpoint MAC (``key_epoch`` field, already
  enforced by ``gov/log.py``). This mirrors how transparency-log systems
  handle key changes: Rekor's signed checkpoints (STHs, RFC 6962-style) are
  only meaningful if a verifier knows *which* key signed *which* checkpoint,
  and Sigstore's TUF root metadata exists precisely to distribute "which key
  is current" safely. Here the epoch label is the in-log key identifier, and
  ``KeyRing.verify_log`` replays the chain selecting the key *per entry*,
  so logs spanning rotations still verify.
* **Key IDs.** ``key_id = sha256(key).hexdigest()[:16]`` identifies a key
  without exposing it — useful in audit output and rotation logs.
* **Symmetric keys, honest limits.** HMAC gives integrity but *no*
  non-repudiation between key holders: anyone holding the key could have
  written any entry. Ed25519 log signatures are the P2 upgrade for the day
  an external auditor must verify without holding the key.

Key compromise — what an attacker WITH the key can and cannot do
---------------------------------------------------------------
CAN:
  * Forge arbitrary *future* entries with valid MACs (indistinguishable
    from genuine operator-written entries).
  * Rewrite history and recompute a fully valid chain, and mint valid
    checkpoints — total integrity loss of the log from that point on.
  * Read the log (but the log store is already assumed readable).
CANNOT:
  * Forge entries under an epoch whose key they do *not* hold. After a
    rotation, the attacker's old key buys them nothing for new entries —
    this is why rotation, not just revocation, is the response.
  * Recover the key from MACs, checkpoints, or key_ids (HMAC-SHA256 and
    SHA-256 preimage resistance).
  * Alter history *undetectably* if an independent checkpoint copy exists
    off-machine: comparing the newest checkpoint hash defeats silent
    rewrites (the Rekor/external-anchoring argument; the off-machine copy
    is an operator procedure, not code in this repo).
RESPONSE (``rotate_keyring`` implements the ceremony):
  1. Detect (checkpoint mismatch against the off-machine copy, or an
     unexpected epoch appearing in the log).
  2. Verify the existing log with the *old* ring first — fail closed if it
     is already tampered; do not rotate on top of a compromised log.
  3. Rotate: new epoch, new random 256-bit key. The old key is RETAINED
     (status ``retired``) so history remains verifiable — deleting it
     would orphan every entry it signed.
  4. Epoch binding gives the blast-radius boundary: entries under the
     compromised epoch after the compromise time are suspect; entries
     under the new epoch are clean.

Dev keys
--------
There is **no silent dev-key fallback on the production path**. A key is
used only if (a) it is configured via the file or env backend, or (b) the
operator explicitly opts in with ``GOV_DEV_KEYS=1``, in which case a loud
multi-line warning is printed to stderr on every resolution. The dev key is
publicly documented and provides **zero** integrity.
"""

import hashlib
import hmac
import json
import os
import secrets
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl  # POSIX advisory locks; absent on Windows
except ImportError:  # pragma: no cover
    fcntl = None

from . import log as _logmod  # chain primitives live in gov/log.py (read-only)

FORMAT_VERSION = 1
KEY_BYTES = 32  # 256-bit HMAC keys
KEY_ID_LEN = 16  # hex chars of sha256(key) used as the public key identifier

# Publicly documented development key. Canonical bytes are identical to
# gov.log._DEV_KEY so MACs agree if both paths are ever mixed.
_DEV_KEY_CANONICAL = b"agent-governance-dev-key-v1::NOT-FOR-PRODUCTION"
_DEV_EPOCH = "dev"

_ENV_KEY = "GOV_LOG_KEY"
_ENV_EPOCH = "GOV_LOG_KEY_EPOCH"
_ENV_ARCHIVE = "GOV_LOG_KEY_ARCHIVE"  # JSON {epoch: key_string}
_ENV_DEV_OPT_IN = "GOV_DEV_KEYS"

_EPOCH_RE = None  # compiled lazily to keep import cheap


def _epoch_pattern():
    global _EPOCH_RE
    if _EPOCH_RE is None:
        import re
        _EPOCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    return _EPOCH_RE


def _utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _warn_loud(message):
    banner = ("=" * 70 + "\n"
              "GOVERNANCE KEY WARNING\n"
              "%s\n" % message +
              "=" * 70 + "\n")
    print(banner, file=sys.stderr)


class NoKeyConfiguredError(RuntimeError):
    """Raised when no production key is configured and dev keys are not
    explicitly opted in. Fail-closed: callers must not proceed."""


class KeyMaterial:
    """One key version. ``key`` is the EXACT byte string fed to HMAC — the
    same bytes ``gov/log.py`` uses (env value UTF-8 encoded)."""

    def __init__(self, epoch, key, created_utc=None, status="active"):
        if not _epoch_pattern().match(epoch):
            raise ValueError("invalid epoch label %r" % (epoch,))
        if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
            raise ValueError("key must be non-empty bytes")
        self.epoch = epoch
        self.key = bytes(key)
        self.key_id = hashlib.sha256(self.key).hexdigest()[:KEY_ID_LEN]
        self.created_utc = created_utc or _utcnow()
        self.status = status  # "active" | "retired" | "dev"

    def to_dict(self):
        # Generated keys are 64 ASCII hex chars (32 random bytes hex-encoded);
        # store that exact string so from_dict restores byte-identical keys.
        # Non-hex (legacy env) keys round-trip via key_raw instead.
        return {"epoch": self.epoch,
                "key_hex": self.key.decode("ascii")
                           if self._is_hex_key() else None,
                "key_raw": None if self._is_hex_key() else self.key.decode(
                    "utf-8", errors="replace"),
                "key_id": self.key_id,
                "created_utc": self.created_utc,
                "status": self.status}

    def _is_hex_key(self):
        # Keys we generated are hex encodings of 32 random bytes.
        return (len(self.key) == KEY_BYTES * 2 and
                all(c in b"0123456789abcdef" for c in self.key.lower()))

    @classmethod
    def from_dict(cls, d):
        if d.get("key_hex"):
            key = d["key_hex"].encode("ascii")
        else:
            key = d["key_raw"].encode("utf-8")
        return cls(d["epoch"], key,
                   created_utc=d.get("created_utc"),
                   status=d.get("status", "active"))

    def describe(self):
        """Safe public description — never includes key material."""
        return {"epoch": self.epoch, "key_id": self.key_id,
                "created_utc": self.created_utc, "status": self.status}


def _generate_key_bytes():
    # Canonical form: 32 random bytes rendered as 64 hex chars, UTF-8
    # encoded — identical to what activate() writes to GOV_LOG_KEY, so
    # gov/log.py and this module always agree on the MAC input.
    return secrets.token_bytes(KEY_BYTES).hex().encode("ascii")


def _atomic_write_bytes(path, data):
    """Write ``data`` to ``path`` atomically: same-directory temp file
    (O_CREAT|O_EXCL, 0600), file fsync, ``os.replace()``, directory fsync.

    A crash or SIGKILL at any point leaves either the old content or the
    new content — never a truncated file. Refuses to operate when the
    parent directory does not exist. ``os.replace`` renames over a
    same-name symlink rather than following it, so a planted symlink at
    ``path`` cannot redirect the write elsewhere.
    """
    p = Path(path)
    parent = p.parent
    if not parent.is_dir():
        raise FileNotFoundError("directory does not exist: %s" % parent)
    fd = None
    tmp = None
    for attempt in range(10):
        tmp = parent / (".%s.tmp-%d-%d" % (p.name, os.getpid(), attempt))
        try:
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600)
        except FileExistsError:
            continue
        break
    if fd is None:
        raise OSError("could not create temp file for %s" % p)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise
    try:
        os.chmod(str(tmp), 0o600)
    except OSError:
        pass
    os.replace(str(tmp), str(p))
    dir_fd = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return p


class KeyRing:
    """An ordered set of key versions: one active epoch plus retired ones.

    Backends:
      * file: :meth:`save` / :meth:`load` a JSON keyring (0600 enforced).
      * env:  :meth:`from_env` / :meth:`activate` via GOV_LOG_KEY[_EPOCH|_ARCHIVE].
    """

    def __init__(self):
        self._keys = {}  # epoch -> KeyMaterial
        self._active_epoch = None

    # -- construction ---------------------------------------------------

    @classmethod
    def generate(cls, epoch="epoch-1"):
        ring = cls()
        mat = KeyMaterial(epoch, _generate_key_bytes(), status="active")
        ring._keys[epoch] = mat
        ring._active_epoch = epoch
        return ring

    @classmethod
    def dev(cls):
        """Dev key ring. ONLY when GOV_DEV_KEYS=1, with loud warnings."""
        if os.environ.get(_ENV_DEV_OPT_IN) != "1":
            raise NoKeyConfiguredError(
                "No production key configured (GOV_LOG_KEY unset and no "
                "keyring file), and dev keys are not opted in. Set "
                "GOV_DEV_KEYS=1 to explicitly allow the public development "
                "key (zero integrity), or configure a real key.")
        _warn_loud(
            "GOV_DEV_KEYS=1: using the PUBLIC development key.\n"
            "This log is NOT tamper-evident against anyone who has read the\n"
            "source. Never use for real audit data.")
        ring = cls()
        ring._keys[_DEV_EPOCH] = KeyMaterial(
            _DEV_EPOCH, _DEV_KEY_CANONICAL, status="dev")
        ring._active_epoch = _DEV_EPOCH
        return ring

    @classmethod
    def from_env(cls):
        """Env backend: current key from GOV_LOG_KEY, epoch from
        GOV_LOG_KEY_EPOCH (default "env"), retired epochs from
        GOV_LOG_KEY_ARCHIVE (JSON {epoch: key_string})."""
        raw = os.environ.get(_ENV_KEY)
        if not raw:
            raise NoKeyConfiguredError(
                "GOV_LOG_KEY is not set.")
        epoch = os.environ.get(_ENV_EPOCH, "env")
        ring = cls()
        ring._keys[epoch] = KeyMaterial(epoch, raw.encode("utf-8"),
                                        status="active")
        ring._active_epoch = epoch
        archive = os.environ.get(_ENV_ARCHIVE)
        if archive:
            try:
                mapping = json.loads(archive)
            except ValueError as e:
                raise NoKeyConfiguredError(
                    "GOV_LOG_KEY_ARCHIVE is not valid JSON: %s" % e)
            if not isinstance(mapping, dict):
                raise NoKeyConfiguredError(
                    "GOV_LOG_KEY_ARCHIVE must be a JSON object {epoch: key}.")
            for ep, kval in mapping.items():
                if ep == epoch:
                    continue
                ring._keys[ep] = KeyMaterial(ep, str(kval).encode("utf-8"),
                                             status="retired")
        return ring

    # -- accessors ------------------------------------------------------

    def active(self):
        return self._keys[self._active_epoch]

    def get(self, epoch):
        try:
            return self._keys[epoch]
        except KeyError:
            raise KeyError("unknown key epoch %r (known: %s)"
                           % (epoch, sorted(self._keys)))

    def epochs(self):
        return sorted(self._keys)

    def describe(self):
        return {"active_epoch": self._active_epoch,
                "keys": [m.describe() for _, m in sorted(self._keys.items())]}

    # -- rotation -------------------------------------------------------

    def _next_epoch_label(self):
        import re
        nums = [int(m.group(1)) for ep in self._keys
                for m in [re.match(r"^epoch-(\d+)$", ep)] if m]
        return "epoch-%d" % (max(nums) + 1 if nums else 1)

    def rotate(self, new_epoch=None):
        """Generate a fresh key under a new epoch; retire the old active key.

        Old keys are RETAINED (status "retired") so history stays verifiable.
        Returns the new epoch label."""
        new_epoch = new_epoch or self._next_epoch_label()
        if new_epoch in self._keys:
            raise ValueError("epoch %r already exists" % (new_epoch,))
        old = self.active()
        old.status = "retired"
        mat = KeyMaterial(new_epoch, _generate_key_bytes(), status="active")
        self._keys[new_epoch] = mat
        self._active_epoch = new_epoch
        return new_epoch

    # -- file backend ---------------------------------------------------

    def to_dict(self):
        return {"format_version": FORMAT_VERSION,
                "active_epoch": self._active_epoch,
                "keys": {ep: m.to_dict() for ep, m in self._keys.items()}}

    @classmethod
    def from_dict(cls, d):
        if d.get("format_version") != FORMAT_VERSION:
            raise ValueError("unsupported keyring format_version %r"
                             % (d.get("format_version"),))
        ring = cls()
        for ep, md in d["keys"].items():
            ring._keys[ep] = KeyMaterial.from_dict(md)
        ring._active_epoch = d["active_epoch"]
        if ring._active_epoch not in ring._keys:
            raise ValueError("active_epoch %r not in keys"
                             % (ring._active_epoch,))
        return ring

    def save(self, path):
        """Persist the keyring atomically (same-dir temp + fsync +
        ``os.replace`` + dir fsync; 0600 throughout). A crash mid-write can
        never leave a truncated keyring behind. The directory must already
        exist (operator-created with safe perms)."""
        p = Path(path)
        data = (json.dumps(self.to_dict(), indent=2, sort_keys=True)
                + "\n").encode("utf-8")
        return _atomic_write_bytes(p, data)

    @classmethod
    def load(cls, path):
        """Load a keyring. Fail-closed: refuses group/world-readable files."""
        p = Path(path)
        st = p.stat()
        if st.st_mode & 0o077:
            raise PermissionError(
                "refusing to load keyring %s: file is group/world-readable "
                "(mode %o); chmod 600 first" % (p, st.st_mode & 0o777))
        return cls.from_dict(json.loads(p.read_text(encoding="utf-8")))

    # -- env activation (the gov/log.py integration point) ---------------

    def activate(self):
        """Publish this ring to the process environment so ``gov/log.py``
        picks it up: GOV_LOG_KEY=<active key>, GOV_LOG_KEY_EPOCH=<epoch>,
        GOV_LOG_KEY_ARCHIVE=<retired epochs JSON>.

        This is the ONLY supported way to put keys under the log on the
        production path. Returns the dict of variables set."""
        active = self.active()
        archive = {ep: m.key.decode("utf-8", errors="replace")
                   for ep, m in self._keys.items() if ep != active.epoch}
        os.environ[_ENV_KEY] = active.key.decode("utf-8")
        os.environ[_ENV_EPOCH] = active.epoch
        if archive:
            os.environ[_ENV_ARCHIVE] = json.dumps(archive, sort_keys=True)
        else:
            os.environ.pop(_ENV_ARCHIVE, None)
        return {_ENV_KEY: "<redacted>", _ENV_EPOCH: active.epoch,
                _ENV_ARCHIVE: sorted(archive)}

    # -- verification across rotations -----------------------------------

    def verify_log(self, log_path):
        """Replay a log that may span multiple key epochs.

        Selects the HMAC key per entry from the entry's ``key_epoch`` —
        this is what makes "rotate, then re-verify old logs with old epoch
        keys" work. ``gov/log.py``'s own verifier uses a single key and
        cannot verify mixed-epoch logs; use this instead after rotation.

        Returns a verdict dict like gov.log._verify, plus ``epochs_seen``.
        """
        p = Path(log_path)
        if not p.exists():
            return {"ok": False, "entries": 0, "broken_seq": None,
                    "epochs_seen": [], "checkpoints_checked": 0,
                    "error": "log file does not exist"}
        entries = []
        epochs_seen = []
        prev = _logmod.GENESIS
        for lineno, line in enumerate(
                p.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                # F28: corrupt log JSON fails closed, never raises.
                return {"ok": False, "entries": len(entries),
                        "broken_seq": None, "epochs_seen": epochs_seen,
                        "checkpoints_checked": 0,
                        "error": "log line %d is not valid JSON (corrupt "
                                 "log); failing closed" % lineno}
            entries.append(entry)
            seq = entry.get("seq")
            if entry.get("format_version") != _logmod.FORMAT_VERSION:
                return {"ok": False, "entries": len(entries),
                        "broken_seq": seq, "epochs_seen": epochs_seen,
                        "checkpoints_checked": 0,
                        "error": "unsupported format_version %r at seq %s"
                                 % (entry.get("format_version"), seq)}
            if entry.get("prev_hash") != prev:
                return {"ok": False, "entries": len(entries),
                        "broken_seq": seq, "epochs_seen": epochs_seen,
                        "checkpoints_checked": 0,
                        "error": "chain link broken at seq %s" % seq}
            epoch = entry.get("key_epoch")
            try:
                key = self.get(epoch).key
            except KeyError:
                return {"ok": False, "entries": len(entries),
                        "broken_seq": seq, "epochs_seen": epochs_seen,
                        "checkpoints_checked": 0,
                        "error": "unknown key epoch %r at seq %s; key not in "
                                 "ring (cannot verify)" % (epoch, seq)}
            mac = _logmod._compute_mac(key, epoch, prev,
                                       _logmod._canonical(entry))
            if not hmac.compare_digest(entry.get("hash", ""), mac):
                return {"ok": False, "entries": len(entries),
                        "broken_seq": seq, "epochs_seen": epochs_seen,
                        "checkpoints_checked": 0,
                        "error": "MAC mismatch at seq %s (epoch %r): history "
                                 "rewritten or wrong key" % (seq, epoch)}
            if epoch not in epochs_seen:
                epochs_seen.append(epoch)
            prev = entry["hash"]

        # Checkpoint comparison defeats tail truncation (same argument as
        # gov/log.py, but per-epoch keys). F27/F28: a non-empty log with a
        # missing, corrupt, or empty sidecar fails CLOSED — never ok=True
        # on the strength of zero checked checkpoints.
        cp_path = p.parent / "checkpoints.jsonl"
        checked = 0
        cps, n_bad = [], 0
        sidecar_missing = not cp_path.exists()
        if not sidecar_missing:
            try:
                text = cp_path.read_text(encoding="utf-8")
            except OSError as e:
                return {"ok": False, "entries": len(entries),
                        "broken_seq": None, "epochs_seen": epochs_seen,
                        "checkpoints_checked": 0,
                        "error": "checkpoint sidecar %s unreadable: %s; "
                                 "failing closed" % (cp_path.name, e)}
            cps, n_bad = _logmod._parse_sidecar_lines(text.splitlines())
        if entries:
            if sidecar_missing:
                return {"ok": False, "entries": len(entries),
                        "broken_seq": None, "epochs_seen": epochs_seen,
                        "checkpoints_checked": 0,
                        "error": "checkpoint sidecar %s is MISSING for a "
                                 "non-empty log (%d entries): tail "
                                 "truncation cannot be ruled out; failing "
                                 "closed" % (cp_path.name, len(entries))}
            if n_bad:
                return {"ok": False, "entries": len(entries),
                        "broken_seq": None, "epochs_seen": epochs_seen,
                        "checkpoints_checked": 0,
                        "error": "checkpoint sidecar %s is CORRUPT (%d "
                                 "unparseable line(s)); failing closed"
                                 % (cp_path.name, n_bad)}
            if not cps:
                return {"ok": False, "entries": len(entries),
                        "broken_seq": None, "epochs_seen": epochs_seen,
                        "checkpoints_checked": 0,
                        "error": "checkpoint sidecar %s is EMPTY for a "
                                 "non-empty log (%d entries): no truncation "
                                 "anchor; failing closed"
                                 % (cp_path.name, len(entries))}
        if cps:
                latest = max(cps, key=lambda c: c["seq"])
                checked = len(cps)
                try:
                    cp_key = self.get(latest.get("key_epoch")).key
                except KeyError:
                    return {"ok": False, "entries": len(entries),
                            "broken_seq": None, "epochs_seen": epochs_seen,
                            "checkpoints_checked": checked,
                            "error": "checkpoint at seq %s uses unknown key "
                                     "epoch %r" % (latest["seq"],
                                                   latest.get("key_epoch"))}
                expect = _logmod._checkpoint_mac(
                    cp_key, latest.get("key_epoch"),
                    latest["seq"], latest["hash"])
                if not hmac.compare_digest(latest.get("mac", ""), expect):
                    return {"ok": False, "entries": len(entries),
                            "broken_seq": None, "epochs_seen": epochs_seen,
                            "checkpoints_checked": checked,
                            "error": "checkpoint MAC invalid (checkpoint "
                                     "tampered or wrong key)"}
                if len(entries) < latest["seq"]:
                    return {"ok": False, "entries": len(entries),
                            "broken_seq": None, "epochs_seen": epochs_seen,
                            "checkpoints_checked": checked,
                            "error": "tail truncation: log has %d entries but "
                                     "newest checkpoint is at seq %d"
                                     % (len(entries), latest["seq"])}
                if entries[latest["seq"] - 1]["hash"] != latest["hash"]:
                    return {"ok": False, "entries": len(entries),
                            "broken_seq": latest["seq"],
                            "epochs_seen": epochs_seen,
                            "checkpoints_checked": checked,
                            "error": "checkpoint mismatch at seq %d (log "
                                     "rewritten after checkpoint)"
                                     % latest["seq"]}
        return {"ok": True, "entries": len(entries), "broken_seq": None,
                "epochs_seen": epochs_seen, "checkpoints_checked": checked,
                "error": None}


def require_key():
    """Fail-closed production key resolution.

    Prefers configured keys (env backend); dev keys only with explicit
    ``GOV_DEV_KEYS=1`` opt-in (loud warning). Raises
    :class:`NoKeyConfiguredError` otherwise — the production path must not
    silently fall back to a public key.
    """
    try:
        return KeyRing.from_env()
    except NoKeyConfiguredError:
        pass
    return KeyRing.dev()  # raises unless GOV_DEV_KEYS=1


@contextmanager
def _rotation_lock(path):
    """Serialize concurrent rotations of the same keyring.

    Advisory exclusive lock on ``<path>.lock`` (POSIX ``flock``). Without
    this, two concurrent ceremonies both load the pre-rotation ring and the
    loser silently discards the winner's epoch — losing a key epoch breaks
    verification of everything signed under it. With the lock, rotations
    compose: each sees the previous rotation's key. Degrades to no locking
    where ``fcntl`` is unavailable.
    """
    if fcntl is None:  # pragma: no cover
        yield
        return
    lock_path = str(path) + ".lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def rotate_keyring(path, new_epoch=None, log_path=None):
    """The rotation ceremony.

    1. Load the ring from ``path``.
    2. If ``log_path`` is given, verify the existing log with the OLD ring
       first — fail closed if it is already tampered; never rotate on top
       of a compromised log.
    3. Rotate to a fresh epoch/key; old key retained as ``retired``.
    4. Back up the pre-rotation keyring to ``<path>.bak`` (operator safety
       net: losing the old file orphans every entry the old key signed).
    5. Persist the ring (0600).

    The whole ceremony holds an exclusive lock on ``<path>.lock`` so
    concurrent rotations serialize instead of silently dropping epochs.

    Returns ``(ring, new_epoch)``. Call ``ring.activate()`` afterwards to
    put the new epoch under ``gov/log.py``.
    """
    with _rotation_lock(path):
        ring = KeyRing.load(path)
        if log_path is not None:
            verdict = ring.verify_log(log_path)
            if not verdict["ok"]:
                raise RuntimeError(
                    "refusing to rotate: existing log failed verification: %s"
                    % verdict["error"])
        new_epoch = ring.rotate(new_epoch)
        p = Path(path)
        if p.exists():
            # Atomic too: a torn backup is as bad as a torn keyring.
            _atomic_write_bytes(Path(str(p) + ".bak"), p.read_bytes())
        ring.save(path)
        return ring, new_epoch


def record_rotation(log, ring, new_epoch, actor="operator"):
    """Append a tamper-evident record of the rotation to an ActionLog.

    Only key *identifiers* are logged (epoch labels + key_ids), never key
    material. ``log`` is a ``gov.log.ActionLog`` (already active under the
    new epoch via ``ring.activate()``).
    """
    new_mat = ring.get(new_epoch)
    retired = [m.describe() for ep, m in sorted(ring._keys.items())
               if ep != new_epoch]
    return log.append({
        "event": "key_rotation",
        "actor": actor,
        "new_epoch": new_epoch,
        "new_key_id": new_mat.key_id,
        "retired_epochs": retired,
    })
