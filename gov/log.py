"""Append-only, HMAC-authenticated action log.

Each entry is one JSON line. Integrity comes from two layers:

1. **HMAC chain.** Every entry stores ``hash = HMAC-SHA256(key,
   key_epoch || prev_hash || canonical_json(entry))``. Without the key an
   attacker cannot recompute a valid chain after altering history, so
   truncate-and-rebuild and history-rewrite attacks are detected by
   :func:`verify_chain`. The legacy unkeyed :func:`_entry_hash` is kept only
   as the documented attacker primitive used by the red-team tests.

2. **Signed checkpoints (STH-style).** After every append, a checkpoint
   ``{seq, hash}`` authenticated with the same key is written to
   ``checkpoints.jsonl`` next to the log. ``verify_chain`` requires the log
   to be at least as long as the newest checkpoint and to agree with it at
   that sequence number, which defeats silent tail truncation. A non-empty
   log whose checkpoint sidecar is missing, empty, or corrupt fails
   verification CLOSED (F27/F28): ``ok=True`` is never reported on the
   strength of zero checked checkpoints, and corrupt content is a verdict,
   never an exception.

Key custody: the HMAC key comes from the ``GOV_LOG_KEY`` environment
variable (``GOV_LOG_KEY_EPOCH`` optionally names the key version and is
bound into every MAC). If unset, a documented, publicly-known development
key is used and a warning is printed: the dev key provides **zero**
integrity against anyone who has read this source. Production deployments
MUST set ``GOV_LOG_KEY``. ``key_epoch`` is stored on every entry and
checkpoint so key rotations are visible in the log.

``format_version`` is frozen at 1; the verifier rejects anything else,
fail-closed.
"""

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

GENESIS = "GENESIS"
FORMAT_VERSION = 1

# F25: how long an append waits for the log's exclusive lock before
# failing closed. A crashed lock holder's flock is released by the
# kernel on process death, so a timeout means a LIVE process is stuck
# mid-append — refusing to write unlocked is the safe direction.
APPEND_LOCK_TIMEOUT_SECS = 30
_APPEND_LOCK_POLL_SECS = 0.02


class AppendLockError(OSError):
    """F25: the action-log append lock could not be acquired in time.

    Fail-closed: the entry was NOT written and the caller must not treat
    the action as logged. Raised instead of writing unlocked, which is
    what forked the HMAC chain under concurrent writers (W7-3).
    """


class LogUnverifiableError(Exception):
    """Fail-closed: the action log (or its checkpoint sidecar) cannot be
    authenticated — corrupt, tampered, truncated, or missing its
    checkpoint anchor.

    Raised by :func:`require_verified`; the dict-returning :func:`_verify`
    reports the same conditions as ``{"ok": False, "error": ...}``
    instead of raising, so audit tooling (e.g. report generators) never
    crashes on a corrupt file (F28). Never treat the log as verified
    when this is raised."""


@contextlib.contextmanager
def _append_locked(path):
    """Hold an exclusive flock on *path* across the critical section.

    F25: serializes ``ActionLog.append`` across processes (POSIX
    ``fcntl.flock``), so concurrent appends linearize — no two writers
    can assign the same sequence number or fork ``prev_hash``. Waits up
    to ``APPEND_LOCK_TIMEOUT_SECS`` for the lock, then raises
    ``AppendLockError``: the write never happens unlocked.
    """
    f = open(path, "a", encoding="utf-8")
    try:
        deadline = time.monotonic() + APPEND_LOCK_TIMEOUT_SECS
        while True:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (OSError, BlockingIOError):
                if time.monotonic() >= deadline:
                    raise AppendLockError(
                        "could not acquire the append lock on %s within "
                        "%ds; refusing to write unlocked" % (path,
                        APPEND_LOCK_TIMEOUT_SECS))
                time.sleep(_APPEND_LOCK_POLL_SECS)
        try:
            yield f
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    finally:
        f.close()

# Publicly documented development key. Provides NO security; it exists so
# the synthetic demo and test suite run with zero configuration. The first
# use in a process prints a warning to stderr.
_DEV_KEY = b"agent-governance-dev-key-v1::NOT-FOR-PRODUCTION"
_dev_warned = False


def _active_key():
    """Return (key_bytes, key_epoch). Warn once when falling back to dev key."""
    global _dev_warned
    env = os.environ.get("GOV_LOG_KEY")
    if env:
        epoch = os.environ.get("GOV_LOG_KEY_EPOCH", "env")
        return env.encode("utf-8"), epoch
    if not _dev_warned:
        _dev_warned = True
        print(
            "WARNING: GOV_LOG_KEY is not set; using the public development "
            "key. This log is NOT tamper-evident against anyone who read the "
            "docs. Set GOV_LOG_KEY for real integrity.",
            file=sys.stderr,
        )
    return _DEV_KEY, "dev"


def _utcnow():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _canonical(entry):
    payload = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)


def _entry_hash(prev_hash, canonical):
    """Legacy UNKEYED SHA-256 chain primitive.

    Kept for compatibility and as the documented attacker primitive: the
    red-team suite uses it to model an attacker who knows the algorithm but
    not the HMAC key. New code must use :func:`_compute_mac`.
    """
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def _compute_mac(key, key_epoch, prev_mac, canonical):
    msg = ("%s|%s|%s" % (key_epoch, prev_mac, canonical)).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _checkpoint_mac(key, key_epoch, seq, entry_hash):
    msg = ("checkpoint|%s|%d|%s" % (key_epoch, seq, entry_hash)).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


class LogFullError(Exception):
    """Raised when the audit log reached its configured size cap.

    F22 fail-closed: once the cap is hit, no further entry may be
    appended — the executor refuses to act rather than act unlogged.
    Operators archive the full log (``gov verify --keyring`` still
    verifies archives) and start a fresh one; the rotation procedure is
    documented in the policy file's ``log_limits`` comment.
    """


class ActionLog:
    """Append-only JSONL log with HMAC chaining and signed checkpoints."""

    def __init__(self, path, max_bytes=None):
        self.path = Path(path)
        self.checkpoint_path = self.path.parent / "checkpoints.jsonl"
        self._max_bytes = None
        if max_bytes is not None:
            self.configure_guard(max_bytes)
        self._known_sig = None  # (size, mtime_ns) the cached tail matches
        self.refresh()

    def configure_guard(self, max_bytes):
        """F22: install the audit-log size guard (bytes); None disables."""
        if max_bytes is not None:
            try:
                max_bytes = int(max_bytes)
            except (TypeError, ValueError):
                raise ValueError("max_bytes must be an integer or None")
            if max_bytes <= 0:
                raise ValueError("max_bytes must be > 0")
        self._max_bytes = max_bytes

    def _file_sig(self):
        """O(1) (size, mtime) signature of the log file, None if absent."""
        try:
            st = self.path.stat()
        except OSError:
            return None
        return (st.st_size, st.st_mtime_ns)

    def _refresh_if_changed(self):
        """Re-read the tail only when another writer changed the file.

        F22: ``append`` used to call ``refresh()`` — a full O(n) scan —
        every time, making n appends O(n^2) (measured: 2000 appends took
        ~9s). The cached (size, mtime_ns) signature makes the common
        case O(1): any write by another process (e.g. the approval CLI)
        changes the signature and triggers exactly one rescan.

        Concurrency note (F25): ``append`` holds an exclusive flock
        across refresh + seq assignment + write + fsync, so the
        read-modify-write above is atomic across processes — concurrent
        writers linearize instead of forking the chain. A bare
        ``refresh()`` from a non-append path can still observe a torn
        read only if some writer bypasses ``append`` (none in this
        codebase); all governed writes go through ``append``.
        """
        sig = self._file_sig()
        if sig is not None and sig == self._known_sig:
            return
        self.refresh()

    def refresh(self):
        """Re-read the file tail so this instance sees entries written by
        other processes (e.g. the approval CLI)."""
        self._seq = 0
        self._prev = GENESIS
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                self._seq = int(entry["seq"])
                self._prev = entry["hash"]
        self._known_sig = self._file_sig()

    @property
    def checkpoints(self):
        """All signed checkpoints, oldest first.

        F28: unparseable sidecar lines are skipped (counted by
        ``_parse_sidecar_lines``) instead of crashing the reader —
        corruption is a verifier verdict (fail closed), not an
        exception, for in-process readers.
        """
        out = []
        if self.checkpoint_path.exists():
            cps, _ = _parse_sidecar_lines(
                self.checkpoint_path.read_text(
                    encoding="utf-8").splitlines())
            out.extend(cps)
        return out

    def write_checkpoint(self, seq=None, entry_hash=None):
        """Append a key-authenticated checkpoint for (seq, entry_hash).

        Defaults to the current tail. Returns the checkpoint dict.
        """
        key, epoch = _active_key()
        seq = self._seq if seq is None else seq
        entry_hash = self._prev if entry_hash is None else entry_hash
        cp = {
            "seq": seq,
            "hash": entry_hash,
            "key_epoch": epoch,
            "format_version": FORMAT_VERSION,
            "mac": _checkpoint_mac(key, epoch, seq, entry_hash),
        }
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.checkpoint_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(cp, ensure_ascii=True, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return cp

    def append(self, event):
        """Append an event dict; returns the stored entry.

        Fail-closed: if the entry or its checkpoint cannot be written, an
        exception propagates and the caller must not treat the action as
        logged.

        Reserved chain metadata (seq, ts, prev_hash, format_version,
        key_epoch) is always set by the log itself: same-named keys in
        ``event`` are dropped, so a caller can never forge or clobber the
        chain bookkeeping.

        F22: appends are O(1) amortized — the tail is re-scanned only when
        another writer changed the file (see ``_refresh_if_changed``).
        When the configured size guard is reached, raises
        ``LogFullError``: fail-closed, no unlogged actions.

        F25: the whole append — tail refresh, seq assignment, write,
        fsync, checkpoint — runs under an exclusive OS file lock
        (POSIX ``fcntl.flock``), so concurrent processes linearize and
        the HMAC chain cannot fork (W7-3). Lock acquisition failure
        raises ``AppendLockError`` instead of writing unlocked.
        """
        if not isinstance(event, dict):
            raise TypeError("event must be a dict")
        key, epoch = _active_key()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _append_locked(self.path) as f:
            # Re-check the tail UNDER the lock: another process may have
            # appended between our last stat and lock acquisition; the
            # lock is what makes the read-modify-write atomic.
            self._refresh_if_changed()
            # Build the entry (but do not commit chain state yet): the
            # size guard is enforced on the PROJECTED byte size before
            # anything is written or mutated, so a refusal leaves no gap
            # in the chain.
            new_seq = self._seq + 1
            entry = {}
            entry.update(event)
            # Reserved metadata wins over anything the caller supplied.
            entry.update({
                "seq": new_seq,
                "ts": _utcnow(),
                "prev_hash": self._prev,
                "format_version": FORMAT_VERSION,
                "key_epoch": epoch,
            })
            entry["hash"] = _compute_mac(key, epoch, self._prev,
                                         _canonical(entry))
            line = json.dumps(entry, ensure_ascii=True, default=str) + "\n"
            if self._max_bytes is not None:
                # True size via fstat on the locked fd (f.tell() in
                # append mode reports the stream position, not EOF).
                size = os.fstat(f.fileno()).st_size
                if size + len(line.encode("utf-8")) > self._max_bytes:
                    raise LogFullError(
                        "audit log %s would exceed its size cap (%d bytes "
                        "projected): archive the log and start a fresh one; "
                        "refusing to append so no action goes unlogged"
                        % (self.path, self._max_bytes))
            self._seq = new_seq
            self._prev = entry["hash"]
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
            # F22: the file changed under us — record the new signature so
            # the next append skips the rescan.
            self._known_sig = self._file_sig()
            # Checkpoint under the same lock: the (seq, hash) pair it
            # anchors cannot be interleaved with another writer's.
            self.write_checkpoint()
        return entry


def read_entries(path):
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _parse_sidecar_lines(lines):
    """Parse checkpoint sidecar lines. Returns (checkpoints, n_bad).

    Never raises: unparseable or malformed lines are counted, not
    trusted. ``_verify`` fails closed on any bad line for a non-empty
    log (F28) — mirroring the egress ledger's fail-closed twin.
    """
    cps, n_bad = [], 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            cp = json.loads(line)
        except ValueError:
            n_bad += 1
            continue
        if isinstance(cp, dict) and isinstance(cp.get("seq"), int):
            cps.append(cp)
        else:
            n_bad += 1
    return cps, n_bad


def _verify(path):
    """Full verification. Returns a verdict dict.

    Never raises on file CONTENT problems (F28): corrupt log lines and
    corrupt checkpoint sidecars are reported as
    ``{"ok": False, "error": ...}``, never as an uncaught exception and
    never as ``ok=True``.

    F27: checkpointing is always enabled for ActionLog (every append
    writes a checkpoint), so a NON-EMPTY log with a missing, empty, or
    corrupt sidecar fails CLOSED — the egress ledger's rule (non-empty
    ledger + no sidecar -> unverifiable) now has an action-log twin.
    ``ok=True`` is never reported on the strength of zero checked
    checkpoints for a non-empty log; a truncated log never verifies
    clean.

    F32 (HARDENING-R8): the verifier additionally BINDS every entry's
    ``key_epoch`` label to the CONFIGURED epoch. In single-key mode there
    is no label->key registry, so a label that is not the configured epoch
    is either a label forgery (e.g. production labels HMAC'd under the
    public dev key) or a misconfigured epoch — either way the verifier
    fails closed with a label-mismatch error rather than blessing it. The
    newest checkpoint's label is bound the same way. A log that spans a
    key rotation does NOT verify here by design (fail-closed): use
    KeyRing.verify_log for those (each label selects its own key there,
    so a forged label fails the per-epoch MAC instead).
    """
    key, epoch = _active_key()
    p = Path(path)

    def _fail(entries, error, broken_seq=None, checked=0):
        return {"ok": False, "entries": len(entries),
                "broken_seq": broken_seq, "checkpoints_checked": checked,
                "key_epoch": epoch, "format_version": FORMAT_VERSION,
                "error": error}

    if not p.exists():
        return _fail([], "log file does not exist")
    entries = []
    prev = GENESIS
    for lineno, line in enumerate(
            p.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            return _fail(entries,
                         "log line %d is not valid JSON (corrupt log); "
                         "failing closed" % lineno)
        entries.append(entry)
        seq = entry.get("seq")
        # F27: the full chain walk from genesis runs even when no
        # checkpoint exists; any seq gap fails verification here.
        if seq != len(entries):
            return _fail(entries,
                         "sequence gap at log line %d: expected seq %d, "
                         "got %r (entries deleted or reordered); failing "
                         "closed" % (lineno, len(entries), seq),
                         broken_seq=seq)
        if entry.get("format_version") != FORMAT_VERSION:
            return _fail(entries,
                         "unsupported format_version %r at seq %s"
                         % (entry.get("format_version"), seq),
                         broken_seq=seq)
        if entry.get("prev_hash") != prev:
            return _fail(entries, "chain link broken at seq %s" % seq,
                         broken_seq=seq)
        # F32 (HARDENING-R8): bind the self-declared label to the
        # configured key. The MAC was already computed over the label,
        # but nothing stopped a forger from HMAC'ing production labels
        # under the public dev key and verifying clean. Now any entry
        # whose label is not the configured epoch fails closed here.
        label = entry.get("key_epoch")
        if label != epoch:
            return _fail(entries,
                         "key_epoch label mismatch at seq %s: entry claims "
                         "%r but the configured key epoch is %r — possible "
                         "label forgery or misconfigured epoch; refusing "
                         "to verify (failing closed)" % (seq, label, epoch),
                         broken_seq=seq)
        mac = _compute_mac(key, label, prev, _canonical(entry))
        if not hmac.compare_digest(entry.get("hash", ""), mac):
            return _fail(entries,
                         "MAC mismatch at seq %s (history rewritten or "
                         "wrong GOV_LOG_KEY)" % seq, broken_seq=seq)
        prev = entry["hash"]

    # Checkpoint comparison defeats tail truncation: the log must reach the
    # newest checkpoint and agree with it there.
    cp_path = p.parent / "checkpoints.jsonl"
    checked = 0
    cps, n_bad = [], 0
    sidecar_missing = not cp_path.exists()
    if not sidecar_missing:
        try:
            text = cp_path.read_text(encoding="utf-8")
        except OSError as e:
            return _fail(entries, "checkpoint sidecar %s unreadable: %s; "
                                  "failing closed" % (cp_path.name, e))
        cps, n_bad = _parse_sidecar_lines(text.splitlines())
    if entries:
        # F27: non-empty log, so checkpointing anchored every entry.
        if sidecar_missing:
            return _fail(entries,
                         "checkpoint sidecar %s is MISSING for a non-empty "
                         "log (%d entries): the tail-truncation anchor is "
                         "gone — truncation cannot be ruled out; failing "
                         "closed" % (cp_path.name, len(entries)))
        if n_bad:
            return _fail(entries,
                         "checkpoint sidecar %s is CORRUPT (%d unparseable "
                         "line(s)): refusing to verify — failing closed; "
                         "restore the sidecar from backup" % (cp_path.name,
                                                              n_bad))
        if not cps:
            return _fail(entries,
                         "checkpoint sidecar %s is EMPTY for a non-empty "
                         "log (%d entries): no truncation anchor — "
                         "failing closed" % (cp_path.name, len(entries)))
    elif n_bad:
        # Empty log: nothing to truncate, but a corrupt sidecar is never
        # acceptable — fail closed rather than bless it.
        return _fail(entries,
                     "checkpoint sidecar %s is CORRUPT (%d unparseable "
                     "line(s)); failing closed" % (cp_path.name, n_bad))
    if cps:
        latest = max(cps, key=lambda c: c["seq"])
        checked = len(cps)
        # F32 (HARDENING-R8): bind the checkpoint label too — a checkpoint
        # is a signed claim about the chain, and its self-declared label
        # must equal the configured epoch just like every entry's.
        cp_label = latest.get("key_epoch")
        if cp_label != epoch:
            return _fail(entries,
                         "checkpoint key_epoch label mismatch: checkpoint "
                         "claims %r but the configured key epoch is %r — "
                         "refusing to verify (failing closed)"
                         % (cp_label, epoch), checked=checked)
        expect = _checkpoint_mac(key, cp_label,
                                 latest["seq"], latest["hash"])
        if not hmac.compare_digest(latest.get("mac", ""), expect):
            return _fail(entries,
                         "checkpoint MAC invalid (checkpoint tampered "
                         "or wrong GOV_LOG_KEY)", checked=checked)
        if len(entries) < latest["seq"]:
            return _fail(entries,
                         "tail truncation: log has %d entries but "
                         "newest checkpoint is at seq %d"
                         % (len(entries), latest["seq"]), checked=checked)
        if entries[latest["seq"] - 1]["hash"] != latest["hash"]:
            return _fail(entries,
                         "checkpoint mismatch at seq %d "
                         "(log rewritten after checkpoint)"
                         % latest["seq"], broken_seq=latest["seq"],
                         checked=checked)
    return {"ok": True, "entries": len(entries), "broken_seq": None,
            "checkpoints_checked": checked, "key_epoch": epoch,
            "format_version": FORMAT_VERSION, "error": None}


def require_verified(path):
    """Raise :class:`LogUnverifiableError` unless the log fully verifies.

    F27/F28: the programmatic fail-closed twin of the egress ledger's
    ``require_verified`` — use before trusting a log's contents.
    Returns the verdict dict on success.
    """
    v = _verify(path)
    if not v["ok"]:
        raise LogUnverifiableError(v["error"] or "log failed verification")
    return v


def verify_chain(path):
    """Replay the chain. Returns (ok, broken_seq_or_None, entry_count)."""
    v = _verify(path)
    return v["ok"], v["broken_seq"], v["entries"]
