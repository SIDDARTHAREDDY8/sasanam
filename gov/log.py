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


def _approval_record_mac(key, key_epoch, canonical):
    """F34: domain-separated HMAC for approval-queue integrity digests.

    Approval records live outside the action log's hash chain (they are
    queued before the approving decision is logged), so the log's MAC
    cannot cover them. They get their own domain-separated MAC under the
    SAME active log key: a forger with run-dir access but without the key
    cannot mint a valid record digest, which closes F34's record-forgery
    vector. ``key_epoch`` is bound into the MAC and verified against the
    keyring, so rotation is explicit. Under the PUBLIC development key this
    gives no forgery resistance to anyone who read the docs — the report
    says so (F34/F29 residual).
    """
    msg = ("approval-record|%s|%s" % (key_epoch, canonical)).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _break_glass_ticket_mac(key, key_epoch, canonical):
    """F49: domain-separated HMAC for human-provisioned break-glass tickets.

    Tickets are provisioned out-of-band by the human operator BEFORE the
    run starts and verified (never trusted) at run start. Same key as the
    log, distinct domain string, so a ticket MAC cannot be confused with
    an approval-record MAC. Under the PUBLIC development key this gives no
    forgery resistance — the honest residual is documented at the F49
    entry: the boundary is key custody (same trust anchor as GOV_LOG_KEY).
    """
    msg = ("break-glass-ticket|%s|%s" % (key_epoch, canonical)).encode("utf-8")
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
        other processes (e.g. the approval CLI).

        F52 (R12): lines that are not valid chained entries
        (unparseable JSON, or forged/planted lines missing ``seq`` /
        ``hash`` — e.g. a planted execution_authorized marker written
        without the HMAC key) are SKIPPED, not trusted and not
        crashed on. In-process readers never bless log content; the
        verifier (``_verify``) is the component that fails closed on
        corrupt lines (F28). Skipping keeps ``append`` chaining onto
        the last GOOD entry, so a forgery in the file cannot deny the
        audit trail itself — the refusal audit entry the forgery
        triggers must itself be appendable.
        """
        self._seq = 0
        self._prev = GENESIS
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                try:
                    seq = int(entry["seq"])
                    chain_hash = entry["hash"]
                except (KeyError, TypeError, ValueError):
                    continue
                self._seq = seq
                self._prev = chain_hash
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


def read_entries_with_stats(path):
    """Read action-log entries, counting malformed physical lines.

    Returns ``(entries, malformed_count)``. Malformed = a non-blank
    line that is not valid JSON, or valid JSON that is not an object
    (F63: the latter used to crash ``_verify`` with AttributeError —
    see below). Malformed lines are SKIPPED, never trusted.

    Never raises on file CONTENT problems (F28): only real I/O
    failures (OSError) propagate.
    """
    p = Path(path)
    if not p.exists():
        return [], 0
    out = []
    malformed = 0
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        if not isinstance(entry, dict):
            malformed += 1
            continue
        out.append(entry)
    return out, malformed


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


def _verify(path, _skip_malformed=False):
    """Full verification. Returns a verdict dict.

    Never raises on file CONTENT problems (F28): corrupt log lines and
    corrupt checkpoint sidecars are reported as
    ``{"ok": False, "error": ...}``, never as an uncaught exception and
    never as ``ok=True``.

    ``_skip_malformed=True`` (F63) is a TOLERANT mode for
    reconciliation only: malformed physical lines (non-JSON, or valid
    JSON that is not an object) are skipped and counted in
    ``verdict["malformed_skipped"]`` instead of failing the whole
    verification — while the SIGNED chain (seq continuity, prev_hash
    links, key_epoch labels, MACs, checkpoints) of every VALID entry
    is still verified exactly as strictly as the default mode. A
    malformed line carries no seq and no chain link, so skipping it
    cannot launder tampering: any alteration of a VALID entry still
    fails closed. The default (``False``) is unchanged and stays
    fail-closed on any malformed line, preserving F28.

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
                "malformed_skipped": n_skipped,
                "key_epoch": epoch, "format_version": FORMAT_VERSION,
                "error": error}

    n_skipped = 0
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
            if _skip_malformed:
                n_skipped += 1
                continue
            return _fail(entries,
                         "log line %d is not valid JSON (corrupt log); "
                         "failing closed" % lineno)
        if not isinstance(entry, dict):
            # F63: valid JSON that is not an object (e.g. "[1,2]").
            # The old code fell through to entry.get() and raised
            # AttributeError — a latent F28 never-raise hole. Default
            # mode fails closed on it; tolerant mode skips and counts.
            if _skip_malformed:
                n_skipped += 1
                continue
            return _fail(entries,
                         "log line %d is valid JSON but not an object "
                         "(corrupt log); failing closed" % lineno)
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
            "checkpoints_checked": checked, "malformed_skipped": n_skipped,
            "key_epoch": epoch,
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


# ---------------------------------------------------------------------------
# F69 (HARDENING-R16): incremental chain-tip verification.
#
# The R15 F60 fix requires a full verify_chain() + full log re-read on
# every refused sweep while the lock-refusal coalescing sidecar is
# missing/corrupt -- O(n) per sweep, unbounded in log size. A run-dir
# writer can hold that state with one cheap sidecar-corruption write per
# sweep, turning every legitimate sweep into a CPU burn (availability
# only; the sweep still refuses fail-closed).
#
# The chain-tip cache makes the repeated case O(new entries): after any
# successful verification, the (seq, tip hash) of the verified tail is
# cached next to the log in ``<log>.tip.json``, MAC-authenticated under
# the log's own HMAC key. The next sweep re-verifies ONLY the entries
# appended since the cached tip. Anything the cache cannot vouch for --
# missing/corrupt tip, log shrunk, tip entry mismatch, segment failure --
# falls back to a FULL verify_chain() (fail-loud, never silent
# suppression).
#
# Soundness notes (why the cached prefix is never blindly trusted):
#
# 1. The tip cache is MAC'd (domain-separated "log-tip") under the log
#    key, so the F52 run-dir writer cannot forge or alter a tip: any
#    tampering fails the MAC and degrades to full verification.
# 2. The cached tip only vouches the prefix up to its seq; the sweep's
#    suppression decision additionally caches the newest verified
#    ``approval_sweep_refused`` timestamp per flag ("refusals") INSIDE
#    the MAC'd tip body, and each sweep scans ONLY the freshly
#    MAC-verified new segment. Prefix entries are never re-read for the
#    decision, so post-tip content swaps in the prefix (which keep the
#    hash strings intact) cannot influence it -- and any future full
#    verification still catches them loudly.
# 3. The tip entry itself IS re-authenticated every sweep (its MAC is
#    recomputed), anchoring the new segment's prev_hash chain to
#    genuinely verified content, not just a matching hash string.
# 4. The checkpoint (tail-truncation) anchor is re-checked every sweep:
#    the sidecar prefix bytes are hash-pinned in the tip, new sidecar
#    lines are fully parsed, and the newest checkpoint's MAC, label,
#    and log agreement are verified exactly as in _verify.
# 5. A corrupted tip degrades to full-verify (slower but safe), never
#    to unverified trust. Residual: an attacker who corrupts the tip
#    cache itself on every sweep (one extra cheap write) still forces
#    the full path per sweep -- the tip must live in the attacker-
#    writable run dir, so this variant is documented, not fixed.
#
# Concurrency: tip writes are atomic (temp file + os.replace). Races
# between concurrent verifiers resolve to last-writer-wins; a stale tip
# is still a VALID tip (it vouches a genuine prefix), so the next sweep
# simply verifies a longer segment. Never unsafe, at most slower.

_TIP_CACHE_SUFFIX = ".tip.json"


def _tip_cache_path(path):
    return Path(str(path) + _TIP_CACHE_SUFFIX)


def _tip_mac(key, key_epoch, body_canonical):
    """Domain-separated MAC over the canonical tip body.

    The body covers seq, tip hash, cached refusals, AND the checkpoint
    anchor state -- every field the incremental decision depends on is
    authenticated, so none of it is attacker-malleable without the key.
    """
    msg = ("log-tip|%s|%s" % (key_epoch, body_canonical)).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _tip_body(tip):
    """The MAC-covered fields of a tip dict (everything but ``mac``).

    ``tip_off``/``end_off`` are byte offsets into the action log at
    tip time: the tip line starts at ``tip_off`` and the file ended at
    ``end_off``. They are authenticated so a run-dir writer cannot
    make the sweep read a different window than the verified one.
    """
    return {
        "seq": tip["seq"],
        "tip": tip["tip"],
        "key_epoch": tip["key_epoch"],
        "refusals": tip["refusals"],
        "cp_size": tip["cp_size"],
        "cp_digest": tip["cp_digest"],
        "cp_newest": tip["cp_newest"],
        "tip_off": tip["tip_off"],
        "end_off": tip["end_off"],
    }


def _read_tip_cache(path):
    """Return the validated tip dict, or None.

    Never raises and never returns an unvalidated tip: a missing file,
    unparseable JSON, wrong shape, epoch mismatch, or MAC failure all
    yield None (the caller falls back to full verification -- slower
    but safe, never unverified trust).
    """
    try:
        raw = json.loads(
            _tip_cache_path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    try:
        tip = {
            "seq": int(raw["seq"]),
            "tip": raw["tip"],
            "key_epoch": raw["key_epoch"],
            "refusals": raw["refusals"],
            "cp_size": int(raw["cp_size"]),
            "cp_digest": raw["cp_digest"],
            "cp_newest": raw["cp_newest"],
            "tip_off": int(raw["tip_off"]),
            "end_off": int(raw["end_off"]),
            "mac": raw["mac"],
        }
    except (KeyError, TypeError, ValueError):
        return None
    if not isinstance(tip["tip"], str):
        return None
    if not isinstance(tip["key_epoch"], str):
        return None
    if not isinstance(tip["mac"], str):
        return None
    if not isinstance(tip["refusals"], dict):
        return None
    if not isinstance(tip["cp_digest"], str):
        return None
    if tip["cp_newest"] is not None and not isinstance(
            tip["cp_newest"], dict):
        return None
    if isinstance(tip["cp_newest"], dict):
        _cpn = tip["cp_newest"]
        if not isinstance(_cpn.get("seq"), int):
            return None
        if not isinstance(_cpn.get("hash"), str):
            return None
        if not isinstance(_cpn.get("mac"), str):
            return None
        if not isinstance(_cpn.get("key_epoch"), str):
            return None
    if tip["seq"] < 0:
        return None
    if tip["tip_off"] < 0 or tip["end_off"] < tip["tip_off"]:
        return None
    key, active_epoch = _active_key()
    if tip["key_epoch"] != active_epoch:
        # Key rotation (or a foreign tip): the cached prefix was
        # verified under a different key -- do not extend it.
        return None
    expect = _tip_mac(key, active_epoch, _canonical(_tip_body(tip)))
    if not hmac.compare_digest(tip["mac"], expect):
        return None
    return tip


def _write_tip_cache(path, tip):
    """Atomically persist a tip dict (temp file + os.replace + fsync).

    Raises OSError on I/O failure (callers treat this as best-effort:
    verification already succeeded; the next sweep just re-verifies a
    longer segment).
    """
    key, epoch = _active_key()
    if tip["key_epoch"] != epoch:
        raise ValueError("tip key_epoch does not match the active key")
    doc = _tip_body(tip)
    doc["mac"] = _tip_mac(key, epoch, _canonical(doc))
    cache_path = _tip_cache_path(path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = cache_path.with_name(cache_path.name + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(doc, ensure_ascii=True, sort_keys=True,
                           default=str))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, cache_path)


def _parse_checkpoint_newest(cps):
    """Newest checkpoint dict from parsed sidecar lines, or None."""
    if not cps:
        return None
    return max(cps, key=lambda c: c["seq"])


def verify_chain_tip(path, flags=()):
    """Incrementally verify the chain from the cached tip.

    Returns ``{"ok": True, "entries": n, "refusals": {flag: ts|None}}``
    when the new segment (entries after the cached tip) fully verifies
    -- the same per-entry checks as :func:`_verify` (seq continuity,
    format_version, prev_hash links, key_epoch binding, MACs) plus the
    checkpoint tail-truncation anchor -- and rewrites the tip cache to
    the new tail.

    Per-sweep cost: the action-log read is O(new bytes) via the tip's
    MAC-authenticated byte offsets (seek to the tip line, read only
    the tail) -- the full-file read that made the old F60 fallback
    O(log size) is gone. The checkpoint sidecar is still re-read and
    hash-pinned in full each sweep (O(sidecar), ~0.6ms/1k measured):
    its prefix hash is what keeps an already-verified sidecar byte
    from being rewritten silently, and there is no sublinear way to
    re-assert that. New sidecar lines are parsed incrementally.

    Returns None when incremental verification is impossible: tip
    missing/corrupt/foreign (MAC or epoch), log shrunk below the tip,
    tip entry mismatch, any segment or checkpoint-anchor failure. The
    caller MUST fall back to full verify_chain() (fail-loud), never
    treat the log as verified.

    Never returns ok=True on unverified data; never raises on file
    CONTENT problems (mirrors _verify's F28 contract: content anomalies
    become None, i.e. "do the loud full verification"). OSError from
    the log/sidecar reads propagates (callers fail loud on those).
    """
    tip = _read_tip_cache(path)
    if tip is None:
        return None
    key, epoch = _active_key()
    p = Path(path)
    seq = tip["seq"]
    tip_off = tip["tip_off"]
    end_off = tip["end_off"]

    # Byte-window read: the log bytes are O(new) per sweep, not
    # O(log size). The tip's offsets are MAC-authenticated, so a
    # run-dir writer cannot aim the window at forged content: any
    # insertion/deletion before the tip shifts the bytes at tip_off
    # (tip-line re-auth fails -> full verify), any shrink below
    # end_off is truncation (-> full verify), and any content swap
    # that keeps offsets+hashes is the invisible class of soundness
    # note 2 (it cannot alter the verified decision inputs).
    # OSError from stat/read propagates: callers fail loud on those.
    st_size = p.stat().st_size
    if st_size < end_off:
        # Log shrank below the cached tip: truncation (or rotation).
        # Do not extend the tip -- full verification decides loudly.
        return None
    with open(p, "rb") as f:
        if seq == 0:
            tip_raw = None
        else:
            f.seek(tip_off)
            tip_raw = f.readline()
            if not tip_raw.endswith(b"\n"):
                # Torn tip line (concurrent rotation/truncate):
                # full verification decides loudly.
                return None
        f.seek(end_off)
        tail = f.read()
    if seq > 0 and tip_raw is None:
        return None
    seg_lines = [ln for ln in tail.splitlines() if ln.strip()]
    count = seq + len(seg_lines)

    if seq == 0:
        if tip["tip"] != GENESIS:
            return None
        prev = GENESIS
    else:
        # Re-authenticate the tip entry: its stored hash must match the
        # cached tip AND recompute to the same value, so the new
        # segment chains onto genuinely verified content (a content
        # swap that keeps the hash string is caught here).
        try:
            tl = json.loads(tip_raw)
        except (TypeError, ValueError):
            return None
        if not isinstance(tl, dict):
            return None
        if tl.get("seq") != seq:
            return None
        if tl.get("hash") != tip["tip"]:
            return None
        if tl.get("key_epoch") != epoch:
            return None
        try:
            prev_hash = tl["prev_hash"]
            recomputed = _compute_mac(key, epoch, prev_hash,
                                      _canonical(tl))
        except (KeyError, TypeError):
            return None
        if not hmac.compare_digest(tip["tip"], recomputed):
            return None
        prev = tip["tip"]

    # Strict per-entry verification of the new segment -- the same
    # checks _verify applies, so a planted/forged/reordered line in the
    # segment degrades to full verification (loud), never to trust.
    new_entries = []
    expected_seq = seq + 1
    for raw in seg_lines:
        try:
            entry = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(entry, dict):
            return None
        if entry.get("seq") != expected_seq:
            return None
        if entry.get("format_version") != FORMAT_VERSION:
            return None
        if entry.get("prev_hash") != prev:
            return None
        if entry.get("key_epoch") != epoch:
            return None
        mac = _compute_mac(key, epoch, prev, _canonical(entry))
        if not hmac.compare_digest(entry.get("hash", ""), mac):
            return None
        new_entries.append(entry)
        prev = entry["hash"]
        expected_seq += 1

    # Checkpoint tail-truncation anchor, exactly as strict as _verify:
    # the sidecar prefix is hash-pinned in the tip (any rewrite of
    # already-verified sidecar bytes -> full verify), new sidecar lines
    # are fully parsed (any bad line -> full verify), and the newest
    # checkpoint's MAC, label, and agreement with the log are checked.
    cp_path = p.parent / "checkpoints.jsonl"
    try:
        cp_bytes = cp_path.read_bytes()
    except OSError:
        cp_bytes = None
    if count > 0 and cp_bytes is None:
        # F27 twin: non-empty log with no truncation anchor -- never
        # bless it incrementally.
        return None
    if cp_bytes is None:
        new_cp_lines = []
    else:
        if len(cp_bytes) < tip["cp_size"]:
            # Sidecar shrank: checkpoints were pruned. Do not trust the
            # remaining anchor incrementally -- full verify decides.
            return None
        if (hashlib.sha256(cp_bytes[:tip["cp_size"]]).hexdigest()
                != tip["cp_digest"]):
            # Already-verified sidecar bytes were rewritten.
            return None
        new_cp_lines = cp_bytes[tip["cp_size"]:].splitlines()
    new_cps, n_bad = _parse_sidecar_lines(new_cp_lines)
    if n_bad:
        # F28: a corrupt sidecar line is a verdict, never trust.
        return None
    newest = _parse_checkpoint_newest(new_cps)
    stored_newest = tip["cp_newest"]
    if newest is None:
        newest = stored_newest
    elif stored_newest is not None and stored_newest["seq"] > newest["seq"]:
        newest = stored_newest
    if newest is not None:
        cp_label = newest.get("key_epoch")
        if cp_label != epoch:
            return None
        expect_cp = _checkpoint_mac(key, cp_label, newest["seq"],
                                    newest["hash"])
        if not hmac.compare_digest(newest.get("mac", ""), expect_cp):
            return None
        if count < newest["seq"]:
            # Tail truncation past the newest anchor.
            return None
        if newest["seq"] > seq:
            # The anchor sits inside the freshly verified segment:
            # check agreement against the verified entries.
            anchor_entry = new_entries[newest["seq"] - seq - 1]
            if anchor_entry["hash"] != newest["hash"]:
                return None
        # (newest["seq"] <= seq: agreement was established when the tip
        # was written; the tip's induction covers the prefix.)
    elif count > 0:
        # Non-empty log, no checkpoints at all (empty sidecar): the
        # F27 twin -- never bless incrementally.
        return None

    # The suppression decision inputs: cached newest-refusal timestamps
    # (MAC'd in the tip, computed over verified entries) extended with
    # the freshly verified segment. Prefix entries are never re-read
    # for the decision (soundness note 2).
    refusals = {flag: tip["refusals"].get(flag) for flag in flags}
    for e in new_entries:
        if e.get("event") == "approval_sweep_refused":
            fl = e.get("flag")
            if fl in refusals and isinstance(e.get("ts"), str):
                refusals[fl] = e["ts"]

    # Advance the tip to the new tail (best-effort: a failed write only
    # costs the next sweep a longer segment, never safety). The byte
    # offsets make the next sweep's read O(new bytes): the tip line
    # starts at tip_off and the file ended at end_off.
    all_cp = cp_bytes if cp_bytes is not None else b""
    if count == 0:
        new_tip_off = 0
        new_end_off = 0
    elif seg_lines:
        # The new tip line is the last non-blank line of the freshly
        # verified tail window; locate its start exactly.
        new_end_off = end_off + len(tail)
        body = tail.rstrip(b"\n")
        new_tip_off = end_off + body.rfind(b"\n") + 1
    else:
        # No new entries: the tip line and file end are unchanged.
        new_tip_off = tip_off
        new_end_off = end_off
    # The stored newest-checkpoint keeps its key_epoch: the re-check
    # below MACs (epoch, seq, hash), so a cross-epoch anchor is
    # rejected even when no new sidecar lines arrived this sweep.
    new_cp_newest = None
    if newest is not None:
        new_cp_newest = {"seq": newest["seq"], "hash": newest["hash"],
                         "mac": newest.get("mac"),
                         "key_epoch": newest.get("key_epoch")}
    new_tip = {
        "seq": count,
        "tip": prev,
        "key_epoch": epoch,
        "refusals": refusals,
        "cp_size": len(all_cp),
        "cp_digest": hashlib.sha256(all_cp).hexdigest(),
        "cp_newest": new_cp_newest,
        "tip_off": new_tip_off,
        "end_off": new_end_off,
    }
    try:
        _write_tip_cache(path, new_tip)
    except OSError:
        pass
    return {"ok": True, "entries": count, "refusals": refusals}


def newest_refusal_ts_per_flag(path, flags):
    """Full-log scan: newest ``approval_sweep_refused`` ts per flag.

    O(n): used only by the full-verification fallback (and tip seeding)
    after the chain has verified. Entries are chronological, so the
    first match in reverse is the newest; entries with unparseable or
    missing timestamps are skipped (fail-loud: they never suppress),
    mirroring the executor's historical scan semantics.
    """
    entries, _malformed = read_entries_with_stats(path)
    out = {flag: None for flag in flags}
    remaining = set(flags)
    for e in reversed(entries):
        if not remaining:
            break
        if not isinstance(e, dict):
            continue
        if e.get("event") != "approval_sweep_refused":
            continue
        fl = e.get("flag")
        if fl not in remaining:
            continue
        ts = e.get("ts")
        if not isinstance(ts, str):
            continue
        try:
            datetime.fromisoformat(ts)
        except ValueError:
            continue
        out[fl] = ts
        remaining.discard(fl)
    return out


def _tail_line_offsets(p):
    """(tip_off, end_off, last_line_bytes) for the log's last line.

    Walks back from EOF in chunks, so finding the tail is O(tail),
    not O(log size). Returns (0, 0, None) for an empty/blank log.
    """
    with open(p, "rb") as f:
        f.seek(0, 2)
        end_off = f.tell()
        buf = b""
        pos = end_off
        # Walk back until we hold at least two newlines (the last
        # line plus its terminator) or reach BOF.
        while pos > 0 and buf.count(b"\n") < 2:
            step = min(65536, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
    body = buf.rstrip(b"\n")
    if not body.strip():
        return 0, 0, None
    ls = body.rfind(b"\n")
    tip_off = pos + ls + 1
    return tip_off, end_off, body[ls + 1:]


def write_chain_tip_from_tail(path, refusals):
    """Seed the tip cache from the current tail after a FULL verify.

    Reads the last log entry (seq, hash) and the checkpoint sidecar,
    then writes the MAC'd tip. Raises OSError on I/O failure (callers
    treat seeding as best-effort). Must only be called when the chain
    has JUST fully verified -- the tip vouches the whole prefix.
    """
    key, epoch = _active_key()
    p = Path(path)
    tip_off, end_off, last_raw = _tail_line_offsets(p)
    last_seq, last_hash = 0, GENESIS
    if last_raw is not None:
        entry = json.loads(last_raw)
        last_seq = int(entry["seq"])
        last_hash = entry["hash"]
    cp_path = p.parent / "checkpoints.jsonl"
    try:
        cp_bytes = cp_path.read_bytes()
    except OSError:
        cp_bytes = b""
    cps, _n_bad = _parse_sidecar_lines(cp_bytes.splitlines())
    newest = _parse_checkpoint_newest(
        [c for c in cps if isinstance(c.get("seq"), int)])
    new_tip = {
        "seq": last_seq,
        "tip": last_hash,
        "key_epoch": epoch,
        "refusals": {flag: refusals.get(flag) for flag in refusals},
        "cp_size": len(cp_bytes),
        "cp_digest": hashlib.sha256(cp_bytes).hexdigest(),
        "cp_newest": ({"seq": newest["seq"], "hash": newest["hash"],
                       "mac": newest.get("mac"),
                       "key_epoch": newest.get("key_epoch")}
                      if newest is not None else None),
        "tip_off": tip_off,
        "end_off": end_off,
    }
    _write_tip_cache(path, new_tip)


def refusal_ts_within_window(ts, window_secs):
    """True when an ISO refusal timestamp is genuinely recent.

    Future-dated or unparseable timestamps never count (fail-loud:
    at most one extra audit entry), mirroring the executor's
    historical scan semantics.
    """
    if not isinstance(ts, str):
        return False
    try:
        age = time.time() - datetime.fromisoformat(ts).timestamp()
    except (TypeError, ValueError):
        return False
    return 0 <= age <= window_secs
