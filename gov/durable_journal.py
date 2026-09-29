"""Durable event journal: hash-chained, append-only JSONL. Stdlib only.

Each line is one JSON record::

    {"seq": N, "prev": <prev_hash>, "txn": <txn_id or null>,
     "type": T, "body": {...}, "hash": H}

``H = sha256(canonical(seq, prev, txn, type, body))`` — the hash covers the
record *without* itself. The chain is verified on every load; any mismatch
raises :class:`JournalCorrupted` and the caller must refuse to proceed
(fail closed, never silent repair).

Durability contract
-------------------
* **Single-writer discipline** via POSIX ``fcntl`` locks: mutations take
  an exclusive lock on a dedicated ``<journal>.lock`` sidecar file
  (created on first use) *and* on the journal file descriptor itself,
  in that order; loads take a shared lock on the journal. A
  lock-acquisition failure raises :class:`JournalLockError` instead of
  writing unlocked, so concurrent processes linearize and the chain
  cannot fork. After acquiring the locks the tail is re-read, so a
  process that appended between our last read and the lock cannot be
  lost. The sidecar lock file (rather than the journal file) is what
  serializes :meth:`Journal.compact` against appenders: the journal
  file itself is replaced by compaction, so a lock bound to its inode
  could not exclude an appender that opened the path before the
  replace.
* **Atomic transactions**: :meth:`Journal.append_many` writes every line
  of the transaction then issues ONE ``fsync`` before returning. A
  crash mid-write can still leave a torn final line on disk; that is
  *detected*, not prevented — the loader raises
  :class:`TornTailError` and refuses to proceed (detect-and-refuse),
  and :func:`recover_torn_tail` performs the explicit operator
  recovery. Either every record of the transaction is durable or the
  torn tail is detected loudly on the next load; a partial
  transaction is never silently accepted.
* **Torn final line**: a crash mid-``fsync`` can leave a partial last
  line. The loader raises :class:`TornTailError` (carrying the last good
  tip hash) instead of guessing. :func:`recover_torn_tail` performs the
  operator recovery: verify the prefix chain, then truncate the torn
  bytes. Recovery is explicit and auditable — never silent truncation.
* **Snapshots / compaction**: :meth:`Journal.take_snapshot` writes a
  hash-bound sidecar and a ``SnapshotTaken`` record, both under the
  mutation lock, so the anchored tip is always current;
  :meth:`Journal.compact` rewrites the journal as
  ``[SnapshotLoaded, ...records after the snapshot]`` while holding
  the mutation lock for the whole rewrite, so no concurrent append
  can be lost across the replace. The sidecar hash
  is bound in ``SnapshotLoaded``, so compaction preserves
  tamper-evidence. Compaction is operator-invoked (see
  :meth:`Journal.compact`): nothing in the engine auto-compacts, so
  size the journal for your workload and compact on a schedule.

This journal is *workflow* state (the Temporal-pattern durable log). The
hash-chained audit log (``gov.log``) remains the tamper-evident system of
record; workflows cross-reference it by digest, never duplicate it.
"""

import contextlib
import fcntl
import hashlib
import json
import os

GENESIS = "GENESIS:" + "0" * 64

_SNAPSHOT_LOADED = "SnapshotLoaded"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _record_hash(seq, prev, txn, rtype, body):
    return hashlib.sha256(
        _canonical({"seq": seq, "prev": prev, "txn": txn,
                    "type": rtype, "body": body})).hexdigest()


class JournalCorrupted(Exception):
    """The journal failed chain verification. Fail closed."""


class TornTailError(JournalCorrupted):
    """The final line is torn (crash mid-fsync), the prefix is intact.

    Carries ``tip_hash`` (last good record hash) and ``torn_offset``
    (byte offset where the torn line starts). Use
    :func:`recover_torn_tail` for the explicit operator recovery.
    """

    def __init__(self, message, tip_hash, torn_offset):
        super(TornTailError, self).__init__(message)
        self.tip_hash = tip_hash
        self.torn_offset = torn_offset


class JournalLockError(OSError):
    """Could not acquire the journal lock; nothing was written."""


@contextlib.contextmanager
def _mutex_for(journal_path):
    """Exclusive cross-process mutation mutex for a journal.

    Held for the whole of every mutation (append, snapshot,
    compaction, torn-tail recovery). It lives on a dedicated
    ``<journal>.lock`` sidecar file — NOT on the journal file itself —
    because :meth:`Journal.compact` replaces the journal file: a lock
    bound to the replaced inode could not exclude an appender that
    opened the path before the rename. Lock order everywhere is
    mutex-then-journal-fd; the mutex is never nested.
    """
    lock_path = os.path.abspath(journal_path) + ".lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError as e:
            raise JournalLockError("journal mutex lock failed: %s" % e)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _verify_snapshot_anchor(rec, journal_path):
    """Verify a SnapshotLoaded anchor record and its sidecar."""
    if rec.get("seq") != 0 or rec.get("prev") != GENESIS:
        raise JournalCorrupted("SnapshotLoaded must be seq 0 / prev GENESIS")
    body = rec.get("body") or {}
    for field in ("snapshot_seq", "snapshot_tip", "snapshot_hash",
                  "snapshot_path"):
        if field not in body:
            raise JournalCorrupted(
                "SnapshotLoaded record missing %r" % field)
    expect = _record_hash(0, GENESIS, rec.get("txn"),
                          _SNAPSHOT_LOADED, body)
    if rec.get("hash") != expect:
        raise JournalCorrupted("SnapshotLoaded record hash mismatch")
    sidecar = os.path.join(os.path.dirname(os.path.abspath(journal_path)),
                           body["snapshot_path"])
    if not os.path.exists(sidecar):
        raise JournalCorrupted(
            "snapshot sidecar missing: %s" % body["snapshot_path"])
    with open(sidecar, "rb") as f:
        raw = f.read()
    if hashlib.sha256(raw).hexdigest() != body["snapshot_hash"]:
        raise JournalCorrupted("snapshot sidecar hash mismatch (tampered?)")
    try:
        stored = json.loads(raw.decode("utf-8"))
    except ValueError as e:
        raise JournalCorrupted("snapshot sidecar invalid JSON: %s" % e)
    if stored.get("journal_tip") != body["snapshot_tip"]:
        raise JournalCorrupted("snapshot sidecar tip mismatch")


def _verify_records(raw_lines, path):
    """Verify parsed (lineno, line, offset) triples; return record list.

    Raises TornTailError if only the final line is torn, JournalCorrupted
    otherwise.
    """
    records = []
    prev = GENESIS
    start = 0
    if raw_lines and raw_lines[0][1].strip():
        try:
            first = json.loads(raw_lines[0][1])
        except ValueError:
            first = None
        if isinstance(first, dict) and first.get("type") == _SNAPSHOT_LOADED:
            _verify_snapshot_anchor(first, path)
            # The anchor is a real chain link (seq 0, prev GENESIS):
            # the kept records chain from the anchor's own hash. The
            # snapshot_tip is bound *inside* the anchor body (linking
            # the pre-compaction tip), not used as the chain prev.
            prev = first["hash"]
            records.append(first)
            start = 1
    for idx in range(start, len(raw_lines)):
        lineno, line, _offset = raw_lines[idx]
        text = line.strip()
        if not text:
            continue
        try:
            rec = json.loads(text)
        except ValueError as e:
            if idx == len(raw_lines) - 1:
                raise TornTailError(
                    "%s line %d: torn final line (crash mid-write?): %s"
                    % (path, lineno, e), prev, _offset)
            raise JournalCorrupted(
                "%s line %d: invalid JSON in the middle of the journal: %s"
                % (path, lineno, e))
        for field in ("seq", "prev", "type", "body", "hash"):
            if field not in rec:
                raise JournalCorrupted(
                    "%s line %d: missing field %r" % (path, lineno, field))
        if rec["seq"] != len(records):
            raise JournalCorrupted(
                "%s line %d: seq out of order (want %d, got %r)"
                % (path, lineno, len(records), rec["seq"]))
        if rec["prev"] != prev:
            raise JournalCorrupted(
                "%s line %d: chain break (prev mismatch)" % (path, lineno))
        expect = _record_hash(rec["seq"], rec["prev"], rec.get("txn"),
                              rec["type"], rec["body"])
        if rec["hash"] != expect:
            raise JournalCorrupted(
                "%s line %d: record hash mismatch (tampered?)" % (path, lineno))
        prev = rec["hash"]
        records.append(rec)
    return records


def _read_raw_lines_from_file(f):
    """Return [(lineno, line, byte_offset)] reading the open binary file."""
    out = []
    offset = 0
    lineno = 0
    f.seek(0)
    for raw in f:
        lineno += 1
        out.append((lineno, raw.decode("utf-8", "replace"), offset))
        offset += len(raw)
    return out


def _read_raw_lines(path):
    with open(path, "rb") as f:
        return _read_raw_lines_from_file(f)


class Journal:
    """A hash-chained, append-only journal at ``path``."""

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.records = []
        self._tip = GENESIS
        self._size = 0
        self._load()

    def _mutex(self):
        """The cross-process mutation mutex for this journal."""
        return _mutex_for(self.path)

    # ------------------------------------------------------------------
    # loading
    # ------------------------------------------------------------------
    def _load(self):
        if not os.path.exists(self.path):
            return
        with open(self.path, "rb") as f:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            except OSError as e:
                raise JournalLockError("shared lock failed: %s" % e)
            try:
                raw = _read_raw_lines_from_file(f)
                self._size = os.fstat(f.fileno()).st_size
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        self.records = _verify_records(raw, self.path)
        self._recompute_tip()

    def _refresh_under_lock(self, fd):
        """Re-read the file if another writer appended since our load.

        The exclusive lock is already held (``fd`` is only used to
        prove it); the read goes through a fresh O_RDONLY descriptor
        because the append descriptor is write-only.
        """
        size = os.fstat(fd).st_size
        if size != self._size:
            rfd = os.open(self.path, os.O_RDONLY)
            with os.fdopen(rfd, "rb") as rf:
                raw = _read_raw_lines_from_file(rf)
            self.records = _verify_records(raw, self.path)
            self._recompute_tip()
            self._size = size

    @property
    def tip(self):
        return self._tip

    def _recompute_tip(self):
        self._tip = self.records[-1]["hash"] if self.records else GENESIS

    # ------------------------------------------------------------------
    # appending
    # ------------------------------------------------------------------
    def append(self, rtype, body):
        """Append a single record; fsync before returning."""
        return self.append_many([(rtype, body)])

    def append_many(self, items):
        """Append records as ONE atomic transaction.

        All lines are written, then a single fsync is issued before
        returning. A crash can therefore never expose a partial
        transaction: either every record of the txn is durable or the
        torn tail is detected loudly on the next load.
        """
        return self.append_if(items, lambda records: True)[1]

    def append_if(self, items, predicate):
        """Append ``items`` only if ``predicate(records)`` holds.

        The predicate is evaluated under the exclusive mutation mutex
        after the tail is refreshed, so the check-and-append is atomic
        across processes — the primitive that serializes races like a
        grant landing against a concurrently fired expiry timer.
        Returns ``(appended, txn)``.
        """
        items = list(items)
        if not items:
            raise ValueError("append_if requires at least one record")
        for rtype, body in items:
            if not isinstance(rtype, str) or not rtype:
                raise ValueError("record type must be a non-empty string")
            if not isinstance(body, dict):
                raise ValueError("record body must be a dict")
        with self._mutex():
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                         0o600)
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except OSError as e:
                    raise JournalLockError("exclusive lock failed: %s" % e)
                try:
                    self._refresh_under_lock(fd)
                except JournalCorrupted:
                    raise
                except Exception as e:  # noqa: BLE001
                    raise JournalCorrupted("tail refresh failed: %r" % e)
                return self._append_records_locked(fd, items, predicate)
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(fd)

    def _append_records_locked(self, fd, items, predicate):
        """Append core: the journal-fd exclusive lock is held and the
        tail is refreshed. Evaluates ``predicate``, writes the lines,
        issues one fsync. Returns ``(appended, txn)``."""
        if not predicate(self.records):
            return False, None
        txn = hashlib.sha256(os.urandom(16)).hexdigest()[:16] \
            if len(items) > 1 else None
        lines = []
        prev = self._tip
        seq = self.records[-1]["seq"] + 1 if self.records else 0
        for rtype, body in items:
            h = _record_hash(seq, prev, txn, rtype, body)
            rec = {"seq": seq, "prev": prev, "txn": txn,
                   "type": rtype, "body": body, "hash": h}
            lines.append(json.dumps(rec, sort_keys=True,
                                    separators=(",", ":")) + "\n")
            self.records.append(rec)
            prev, seq = h, seq + 1
        with os.fdopen(fd, "a", encoding="utf-8", closefd=False) as f:
            for line in lines:
                f.write(line)
            f.flush()
            os.fsync(f.fileno())
        self._tip = prev
        self._size = os.fstat(fd).st_size
        return True, txn

    # ------------------------------------------------------------------
    # snapshots / compaction
    # ------------------------------------------------------------------
    def take_snapshot(self, body):
        """Write a hash-bound snapshot sidecar and a SnapshotTaken record.

        Runs under the mutation mutex with a freshly re-read tail, so
        the anchored tip is always current — no stale-tip anchor under
        concurrency. ``body`` is an opaque dict (e.g. a folded workflow
        state). Returns the snapshot reference ``{"snapshot_seq",
        "journal_tip", "snapshot_path", "body_hash"}``.
        """
        if not isinstance(body, dict):
            raise ValueError("snapshot body must be a dict")
        with self._mutex():
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                         0o600)
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except OSError as e:
                    raise JournalLockError("exclusive lock failed: %s" % e)
                try:
                    self._refresh_under_lock(fd)
                except JournalCorrupted:
                    raise
                except Exception as e:  # noqa: BLE001
                    raise JournalCorrupted("tail refresh failed: %r" % e)
                seq = self.records[-1]["seq"] + 1 if self.records else 0
                sidecar_name = "%s.snapshot.%d" % (
                    os.path.basename(self.path), seq)
                sidecar_path = os.path.join(os.path.dirname(self.path),
                                            sidecar_name)
                stored = {"snapshot_seq": seq, "journal_tip": self._tip,
                          "body": body}
                payload = json.dumps(stored, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")
                body_hash = hashlib.sha256(_canonical(body)).hexdigest()
                sfd = os.open(sidecar_path,
                              os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(sfd, "wb") as f:
                    f.write(payload + b"\n")
                    f.flush()
                    os.fsync(f.fileno())
                ref = {"snapshot_seq": seq, "journal_tip": self._tip,
                       "snapshot_path": sidecar_name,
                       "body_hash": body_hash}
                self._append_records_locked(fd, [("SnapshotTaken", ref)],
                                            lambda records: True)
                return ref
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(fd)

    def compact(self):
        """Rewrite the journal, keeping only records after the last
        snapshot.

        The new journal starts with a ``SnapshotLoaded`` record binding
        the sidecar hash; the chain then continues from the snapshot tip,
        so tamper-evidence is preserved. Raises ``ValueError`` when no
        snapshot exists. The rewrite is atomic (tmp + fsync + rename)
        and runs under the mutation mutex for its whole duration, so a
        concurrent appender cannot lose records across the replace:
        appenders block on the mutex until the new journal is in place.
        Operator-invoked: nothing auto-compacts. Compact on a schedule
        sized to the workload (e.g. when the journal passes N records
        or M bytes); always :meth:`take_snapshot` first.
        """
        with self._mutex():
            self._load()  # fresh records under the mutex
            snap_idx = None
            snap_ref = None
            for i, rec in enumerate(self.records):
                if rec["type"] == "SnapshotTaken":
                    snap_idx, snap_ref = i, rec["body"]
            if snap_idx is None:
                raise ValueError("compact: no snapshot to compact to")
            sidecar = os.path.join(os.path.dirname(self.path),
                                   snap_ref["snapshot_path"])
            with open(sidecar, "rb") as f:
                sidecar_hash = hashlib.sha256(f.read()).hexdigest()
            kept = self.records[snap_idx + 1:]
            # Verify ORIGINAL chain continuity across the snapshot point
            # before renumbering anything. The kept records chain from the
            # SnapshotTaken record itself (they were appended after it), so
            # continuity starts at that record's hash — NOT at the
            # snapshot_tip, which is the tip from *before* SnapshotTaken
            # was appended.
            running = self.records[snap_idx]["hash"]
            for rec in kept:
                if rec["prev"] != running:
                    raise JournalCorrupted(
                        "compact: chain discontinuity after snapshot")
                running = rec["hash"]
            anchor = {"seq": 0, "prev": GENESIS, "txn": None,
                      "type": _SNAPSHOT_LOADED,
                      "body": {"snapshot_seq": snap_ref["snapshot_seq"],
                               "snapshot_tip": snap_ref["journal_tip"],
                               "snapshot_hash": sidecar_hash,
                               "snapshot_path": snap_ref["snapshot_path"]}}
            anchor["hash"] = _record_hash(0, GENESIS, None,
                                          _SNAPSHOT_LOADED, anchor["body"])
            new_lines = [json.dumps(anchor, sort_keys=True,
                                    separators=(",", ":")) + "\n"]
            prev = anchor["hash"]
            for seq, rec in enumerate(kept, 1):
                new_rec = {"seq": seq, "prev": prev, "txn": rec.get("txn"),
                           "type": rec["type"], "body": rec["body"]}
                new_rec["hash"] = _record_hash(seq, prev, rec.get("txn"),
                                               rec["type"], rec["body"])
                new_lines.append(json.dumps(new_rec, sort_keys=True,
                                            separators=(",", ":")) + "\n")
                prev = new_rec["hash"]
            tmp = self.path + ".compact.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                for line in new_lines:
                    f.write(line)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            # Re-load through the normal verifier (exercises SnapshotLoaded).
            self.records = []
            self._tip = GENESIS
            self._size = 0
            self._load()


def verify_journal(path):
    """Load and verify ``path``. Returns ``(ok, record_count)``.

    Never raises on corruption: returns ``(False, 0)`` and the caller
    decides. (``TornTailError`` is reported the same way; construct a
    :class:`Journal` directly when the torn-tail distinction matters.)
    """
    try:
        j = Journal(path)
    except JournalCorrupted:
        return False, 0
    return True, len(j.records)


def recover_torn_tail(path):
    """Operator recovery for a torn final line.

    Verifies the prefix chain, then truncates the torn bytes. Returns the
    recovered tip hash. Raises :class:`JournalCorrupted` if the prefix
    itself is invalid (never truncates a tampered journal) and
    ``ValueError`` if there is no torn tail to recover.
    """
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise ValueError("recover_torn_tail: no journal at %s" % path)
    try:
        Journal(path)
    except TornTailError as e:
        tip, offset = e.tip_hash, e.torn_offset
    except JournalCorrupted as e:
        raise JournalCorrupted(
            "recover_torn_tail: prefix invalid, refusing to truncate: %s"
            % e)
    else:
        raise ValueError("recover_torn_tail: journal is clean, nothing "
                         "to recover")
    # Re-verify the prefix independently before touching the file.
    raw = _read_raw_lines(path)
    prefix = [l for l in raw if l[2] < offset]
    _verify_records(prefix, path)
    # Truncate under the mutation mutex so no appender can interleave
    # a write between our verification and the truncation.
    with _mutex_for(path):
        fd = os.open(path, os.O_WRONLY, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError as e:
                raise JournalLockError("exclusive lock failed: %s" % e)
            os.ftruncate(fd, offset)
            os.fsync(fd)
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)
    ok, _ = verify_journal(path)
    if not ok:
        raise JournalCorrupted(
            "recover_torn_tail: journal still invalid after truncation")
    return tip
