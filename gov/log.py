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
   that sequence number, which defeats silent tail truncation.

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

import hashlib
import hmac
import json
import os
import sys
from datetime import datetime
from pathlib import Path

GENESIS = "GENESIS"
FORMAT_VERSION = 1

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

        Concurrency note: same-process sequential writers are always
        correct (each append re-stats). Two processes appending at the
        exact same instant can interleave at the byte level — the JSONL
        lines themselves stay intact (single write() syscalls), but a
        deployment with truly concurrent writers should serialize
        appends externally (flock); that is out of scope for this demo.
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
        """All signed checkpoints, oldest first."""
        out = []
        if self.checkpoint_path.exists():
            for line in self.checkpoint_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    out.append(json.loads(line))
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
        """
        if not isinstance(event, dict):
            raise TypeError("event must be a dict")
        self._refresh_if_changed()
        key, epoch = _active_key()
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
        entry["hash"] = _compute_mac(key, epoch, self._prev, _canonical(entry))
        line = json.dumps(entry, ensure_ascii=True, default=str) + "\n"
        if self._max_bytes is not None:
            try:
                size = self.path.stat().st_size
            except OSError:
                size = 0
            if size + len(line.encode("utf-8")) > self._max_bytes:
                raise LogFullError(
                    "audit log %s would exceed its size cap (%d bytes "
                    "projected): archive the log and start a fresh one; "
                    "refusing to append so no action goes unlogged"
                    % (self.path, self._max_bytes))
        self._seq = new_seq
        self._prev = entry["hash"]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line)
        # F22: the file changed under us — record the new signature so
        # the next append skips the rescan.
        self._known_sig = self._file_sig()
        # Checkpoint every entry: cheap at this scale, and it is what makes
        # tail truncation detectable.
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


def _verify(path):
    """Full verification. Returns a verdict dict."""
    key, epoch = _active_key()
    p = Path(path)
    if not p.exists():
        return {"ok": False, "entries": 0, "broken_seq": None,
                "checkpoints_checked": 0, "key_epoch": epoch,
                "format_version": FORMAT_VERSION,
                "error": "log file does not exist"}
    entries = []
    prev = GENESIS
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        entries.append(entry)
        seq = entry.get("seq")
        if entry.get("format_version") != FORMAT_VERSION:
            return {"ok": False, "entries": len(entries), "broken_seq": seq,
                    "checkpoints_checked": 0, "key_epoch": epoch,
                    "format_version": FORMAT_VERSION,
                    "error": "unsupported format_version %r at seq %s"
                             % (entry.get("format_version"), seq)}
        if entry.get("prev_hash") != prev:
            return {"ok": False, "entries": len(entries), "broken_seq": seq,
                    "checkpoints_checked": 0, "key_epoch": epoch,
                    "format_version": FORMAT_VERSION,
                    "error": "chain link broken at seq %s" % seq}
        mac = _compute_mac(key, entry.get("key_epoch", epoch), prev,
                           _canonical(entry))
        if not hmac.compare_digest(entry.get("hash", ""), mac):
            return {"ok": False, "entries": len(entries), "broken_seq": seq,
                    "checkpoints_checked": 0, "key_epoch": epoch,
                    "format_version": FORMAT_VERSION,
                    "error": "MAC mismatch at seq %s (history rewritten or "
                             "wrong GOV_LOG_KEY)" % seq}
        prev = entry["hash"]

    # Checkpoint comparison defeats tail truncation: the log must reach the
    # newest checkpoint and agree with it there.
    cp_path = p.parent / "checkpoints.jsonl"
    checked = 0
    if cp_path.exists():
        cps = [json.loads(l) for l in cp_path.read_text(encoding="utf-8").splitlines()
               if l.strip()]
        if cps:
            latest = max(cps, key=lambda c: c["seq"])
            checked = len(cps)
            expect = _checkpoint_mac(key, latest.get("key_epoch", epoch),
                                     latest["seq"], latest["hash"])
            if not hmac.compare_digest(latest.get("mac", ""), expect):
                return {"ok": False, "entries": len(entries),
                        "broken_seq": None, "checkpoints_checked": checked,
                        "key_epoch": epoch, "format_version": FORMAT_VERSION,
                        "error": "checkpoint MAC invalid (checkpoint tampered "
                                 "or wrong GOV_LOG_KEY)"}
            if len(entries) < latest["seq"]:
                return {"ok": False, "entries": len(entries),
                        "broken_seq": None, "checkpoints_checked": checked,
                        "key_epoch": epoch, "format_version": FORMAT_VERSION,
                        "error": "tail truncation: log has %d entries but "
                                 "newest checkpoint is at seq %d"
                                 % (len(entries), latest["seq"])}
            if entries[latest["seq"] - 1]["hash"] != latest["hash"]:
                return {"ok": False, "entries": len(entries),
                        "broken_seq": latest["seq"],
                        "checkpoints_checked": checked,
                        "key_epoch": epoch, "format_version": FORMAT_VERSION,
                        "error": "checkpoint mismatch at seq %d "
                                 "(log rewritten after checkpoint)"
                                 % latest["seq"]}
    return {"ok": True, "entries": len(entries), "broken_seq": None,
            "checkpoints_checked": checked, "key_epoch": epoch,
            "format_version": FORMAT_VERSION, "error": None}


def verify_chain(path):
    """Replay the chain. Returns (ok, broken_seq_or_None, entry_count)."""
    v = _verify(path)
    return v["ok"], v["broken_seq"], v["entries"]
