"""Exchange-access ledger (F163): bulk trace/exchange harvest control.

Field pattern (Anthropic Sept-2026 "Illicit distillation"): agents or
compromised harnesses bulk-READ reasoning traces / tool exchanges --
Alibaba at 3M exchanges/day via 3,500 fraudulent accounts, cross-
session replay defeating reasoning-signature protections. The chained
log records agent *actions*; it never recorded *reads*, so the harvest
pattern was invisible to the audit layer.

This module is the guard at the exchange-read seam
(``gov.log.read_entries`` / ``read_entries_with_stats`` -- the actual
in-tree read path for run exchange files). Every read of *another
run's* traces/exchanges is a logged, policy-checked event; bulk-
extraction patterns trip a fail-closed control (deny, never warn-and-
continue).

What counts as an exchange read: a ``.jsonl`` path under a ``runs/``
directory (target run = the dir under ``runs/``), or a file named
``transcript.jsonl`` anywhere (eval/benchmark traces, target = parent
dir name). Everything else skips the guard.

Policy (fail-closed):
  1. Own run (bound reader run_id == target) -> ALLOW, silent: the
     agent's working memory stays frictionless.
  2. Allowlisted (GOV_EXCHANGE_READ_ALLOW "principal:run,...",
     "principal:*", "*:run") -> ALLOW + extraction record.
  3. Strict posture (GOV_EXCHANGE_STRICT_CROSS_PRINCIPAL=1): any
     cross-run read without an allowlist hit -> DENY. Unknown
     (unbound) readers are denied too: the principal is unverifiable.
  4. Default posture: cross-run read -> ALLOW + extraction record,
     subject to the bulk tripwire.

Bulk tripwire (per reader key = principal or "unknown", sliding
window GOV_EXCHANGE_WINDOW_SEC, default 900s):
  - distinct target runs read in window > GOV_EXCHANGE_MAX_RUNS
    (default 50) -> DENY (cross-session replay tempo);
  - one read returning > GOV_EXCHANGE_MAX_SINGLE_READ entries
    (default 250000) -> DENY (full-trace pull at scale).

Denial appends an ``exchange_read_denied`` record and raises
``ExchangeAccessDenied``; the caller never receives the entries.
Allowed cross-run reads append ``exchange_read``. When the reader
bound a governed ActionLog, the event is mirrored there too, so the
extraction record inherits hash-chain integrity.

Fail-closed on ledger failure: if the ledger cannot be read or
appended, cross-run reads are denied (own-run reads unaffected).

Robustness hardening (Wave-110: F165, F166, F170):

- F165: the tempo window config is validated fail-closed at read time.
  A parsed non-positive ``GOV_EXCHANGE_WINDOW_SEC`` denies window-
  dependent (default-posture) cross-run reads with an
  ``exchange_read_denied`` record naming the bad value -- it never
  silently collapses the window. Unparseable values keep the documented
  default 900 (already the safe direction). Own-run reads and the
  allowlist/strict paths (which never consult the window) are unaffected.
- F166: tempo accounting is keyed on ``time.monotonic()``, not the wall
  clock. Each record carries ``mono`` (monotonic stamp) and ``boot``
  (boot-epoch id, so monotonic stamps stay comparable). Same-epoch
  records are gated on monotonic time only -- a forward wall-clock jump
  (NTP step, VM restore) cannot empty the window. Cross-epoch and legacy
  (pre-fix, field-less) records keep counting by wall-clock ``ts``: the
  fail-closed direction, so a process restart does not launder the
  budget either. ``ts`` remains the human-readable audit timestamp.
- F170: reads are bounded -- ``_read_window`` scans at most a tail byte
  budget sized for the window, and append-time compaction drops
  window-irrelevant records once the file exceeds a size cap (atomic
  temp-file + replace, fsync discipline, stale-fd retry; any failure
  degrades to deny, never to unbounded growth). If the tail had to be
  truncated and the tripwire did not fire from the visible records, the
  read is denied fail-closed: the allow case cannot be proven.

Stdlib only. No gov imports (gov.log imports this module at the
seam; an import cycle here would be fatal).
"""

import contextlib
import fcntl
import json
import os
import tempfile
import threading
import time
from pathlib import Path

__all__ = [
    "ExchangeAccessDenied",
    "bind_reader",
    "check_exchange_read",
    "exchange_target_for_path",
]

READ_EVENT = "exchange_read"
DENIED_EVENT = "exchange_read_denied"
UNKNOWN_PRINCIPAL = "unknown"

# Serializes appends (including compaction's read-modify-replace)
# across threads of this process. fcntl locks do not exclude threads,
# and without this two threads compacting at once could lose records
# through the shared temp file / replace window. Cross-process
# exclusion is still the fcntl EX lock.
_APPEND_LOCK = threading.Lock()


class ExchangeAccessDenied(Exception):
    """Fail-closed denial of a trace/exchange read. Never raised for
    own-run reads; always accompanied by an exchange_read_denied
    ledger record (best effort)."""


# -- reader context (thread-local) ---------------------------------

_state = threading.local()


def _current_reader():
    """(principal, run_id, action_log) of the ambient reader."""
    return (getattr(_state, "principal", UNKNOWN_PRINCIPAL),
            getattr(_state, "run_id", None),
            getattr(_state, "action_log", None))


@contextlib.contextmanager
def bind_reader(principal, run_id, action_log=None):
    """Bind the ambient exchange reader for a scope.

    ``principal``: reader identity string. ``run_id``: the reader's
    own run (reads of this run's exchanges stay frictionless).
    ``action_log``: optional governed ActionLog receiving mirrored
    exchange_read / exchange_read_denied events.
    """
    prev = (getattr(_state, "principal", None),
            getattr(_state, "run_id", None),
            getattr(_state, "action_log", None))
    _state.principal = principal or UNKNOWN_PRINCIPAL
    _state.run_id = run_id
    _state.action_log = action_log
    try:
        yield
    finally:
        if prev[0] is None:
            for attr in ("principal", "run_id", "action_log"):
                if hasattr(_state, attr):
                    delattr(_state, attr)
        else:
            _state.principal, _state.run_id, _state.action_log = prev


# -- path -> target run ---------------------------------------------

def exchange_target_for_path(path):
    """Target run id for an exchange-file path, or None if the path
    is not a trace/exchange file covered by this control."""
    p = Path(path)
    if p.suffix != ".jsonl":
        return None
    parts = p.parts
    if "runs" in parts:
        idx = len(parts) - 1 - parts[::-1].index("runs")
        if idx + 1 < len(parts) - 1:
            return parts[idx + 1]
        return None
    if p.name == "transcript.jsonl":
        return p.parent.name or None
    return None


# -- env config (read at call time: batteries override per case) ----

def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _validated_window_sec():
    """Fail-closed validation of the tempo window config (F165).

    Returns ``(ok, value, raw)``. Unparseable values fall back to the
    documented default 900 -- the already-safe direction the audit
    confirmed (a typo gets the default, never a collapsed window). A
    *parsed* non-positive value is fail-open (it would collapse
    ``_read_window`` so the tripwire can never fire), so ``ok`` is
    False and the caller must deny window-dependent reads loudly.
    """
    raw = os.environ.get("GOV_EXCHANGE_WINDOW_SEC", "900")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return (True, 900, raw)
    if value <= 0:
        return (False, value, raw)
    return (True, value, raw)


def _env_bytes(name, default):
    """Positive-int byte knob with safe fallback (F170).

    These are performance knobs, not security thresholds: a too-small
    value can only move toward deny (tail truncation denies), never
    toward allow -- so garbage falls back to the default instead of
    denying loudly.
    """
    try:
        value = int(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


# -- boot epoch (F166): monotonic clocks reset on reboot, so a raw
# monotonic stamp is meaningless across restarts. Every record carries
# the id of the boot epoch its monotonic stamp belongs to; the window
# predicate only compares monotonic stamps within one epoch.

_BOOT_EPOCH = None


def _read_boot_epoch():
    """Stable id for the current CLOCK_MONOTONIC epoch (system boot).

    Linux: /proc/sys/kernel/random/boot_id, stable per boot and
    readable unprivileged. Fallback (non-Linux): a per-process id --
    conservative, because other processes' records then take the
    cross-epoch (wall-clock, fail-closed-counting) arm instead of the
    monotonic arm. Fork-safe: a child inherits the cached value, and a
    fork does not reset the monotonic epoch.
    """
    try:
        with open("/proc/sys/kernel/random/boot_id",
                  "r", encoding="utf-8") as f:
            boot = f.read().strip()
            if boot:
                return boot
    except OSError:
        pass
    return "local-%d-%d" % (os.getpid(), time.monotonic_ns())


def _boot_epoch():
    global _BOOT_EPOCH
    if _BOOT_EPOCH is None:
        _BOOT_EPOCH = _read_boot_epoch()
    return _BOOT_EPOCH


def _record_in_window(rec, now_mono, now_wall, window_sec, cur_boot):
    """Fail-closed window-relevance predicate (F166).

    Same boot epoch: monotonic only -- immune to wall-clock jumps in
    either direction. Different epoch, or legacy records without
    mono/boot fields: wall-clock ``ts`` -- the fail-closed direction,
    so neither a clock jump nor a process restart grants a fresh
    budget. Records with unparseable stamps are excluded (they are
    also dropped by compaction); only records this module writes gate
    the tripwire, and those are always well-formed.
    """
    if rec.get("boot") is not None and rec.get("mono") is not None:
        if rec.get("boot") == cur_boot:
            try:
                return float(rec["mono"]) >= now_mono - window_sec
            except (TypeError, ValueError):
                return False
        # Cross-epoch: fall through to the wall-clock arm (counted).
    try:
        return float(rec.get("ts", 0)) >= now_wall - window_sec
    except (TypeError, ValueError):
        return False


def _strict_posture():
    return os.environ.get("GOV_EXCHANGE_STRICT_CROSS_PRINCIPAL",
                          "0").strip() == "1"


def _allowlisted(principal, target):
    raw = os.environ.get("GOV_EXCHANGE_READ_ALLOW", "")
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        who, what = entry.split(":", 1)
        who, what = who.strip(), what.strip()
        if (who in (principal, "*")) and (what in (target, "*")):
            return True
    return False


def _ledger_path_for(path):
    override = os.environ.get("GOV_EXCHANGE_LEDGER_PATH")
    if override:
        return Path(override)
    p = Path(path)
    parts = p.parts
    if "runs" in parts:
        idx = len(parts) - 1 - parts[::-1].index("runs")
        return Path(*parts[:idx + 1]) / "exchange_access.jsonl"
    return Path(tempfile.gettempdir()) / "gov_exchange_access.jsonl"


# -- ledger I/O (file-locked; failure is fail-closed) ----------------

def _tail_budget(window_sec):
    """Max bytes ``_read_window`` scans from the file tail (F170).

    Records older than the window are irrelevant to tempo, so a read
    never needs more than a window's worth of records. The default
    covers ~2MB (thousands of records -- orders of magnitude above the
    trip threshold) and scales mildly with operator-configured windows.
    """
    return _env_bytes("GOV_EXCHANGE_LEDGER_TAIL_BYTES",
                      max(2_000_000, window_sec * 512))


def _read_window_full(ledger_path, reader_key, window_sec):
    """Recent exchange_read records for this reader inside the window.

    Returns ``(records, truncated)``. Only the tail up to
    ``_tail_budget`` is scanned (F170): ``truncated`` is True when the
    file is larger than the budget and the head was skipped. Raises
    ExchangeAccessDenied when the ledger cannot be read: fail-closed,
    never warn-and-continue.
    """
    tail_bytes = _tail_budget(window_sec)
    now_mono = time.monotonic()
    now_wall = time.time()
    cur_boot = _boot_epoch()
    try:
        with open(ledger_path, "r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                start = max(0, size - tail_bytes)
                f.seek(start)
                data = f.read()
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except FileNotFoundError:
        return ([], False)
    except OSError as e:
        raise ExchangeAccessDenied(
            "exchange-access ledger unreadable (%s): denying "
            "cross-run trace read fail-closed" % (ledger_path,)) from e
    truncated = start > 0
    lines = data.splitlines()
    if truncated and lines:
        # The first line may be a partial record; drop it rather than
        # parse a torn write.
        lines = lines[1:]
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        if rec.get("event") != READ_EVENT:
            continue
        if rec.get("reader_key") != reader_key:
            continue
        if not _record_in_window(rec, now_mono, now_wall,
                                 window_sec, cur_boot):
            continue
        out.append(rec)
    return (out, truncated)


def _read_window(ledger_path, reader_key, window_sec):
    """Recent exchange_read records for this reader inside the window.

    Raises ExchangeAccessDenied when the ledger cannot be read:
    fail-closed, never warn-and-continue.
    """
    return _read_window_full(ledger_path, reader_key, window_sec)[0]


def _append_record(ledger_path, record):
    """Append one record under an exclusive lock. Raises
    ExchangeAccessDenied on failure: fail-closed.

    F170: when the file exceeds the compaction threshold, it is first
    compacted (window-irrelevant records dropped) via an atomic
    temp-file + replace, so the ledger stays bounded. Any compaction
    failure degrades to deny, never to unbounded growth.
    """
    line = json.dumps(record, ensure_ascii=True, default=str) + "\n"
    try:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with _APPEND_LOCK:
            _append_locked(ledger_path, line)
    except OSError as e:
        raise ExchangeAccessDenied(
            "exchange-access ledger unwritable (%s): denying "
            "cross-run trace read fail-closed" % (ledger_path,)) from e


def _compact_threshold(window_sec):
    """File size past which an append triggers compaction (F170)."""
    return _env_bytes("GOV_EXCHANGE_LEDGER_COMPACT_BYTES",
                      max(1_000_000, window_sec * 256))


def _same_file(fileno, path):
    """True when the open fd still refers to ``path`` (F170).

    Guards the replace-vs-concurrent-appender race: another process may
    have compacted (temp-file + os.replace) between our open() and our
    lock acquisition, leaving our fd on the unlinked old inode. Writes
    through a stale fd would be silently lost.
    """
    try:
        fst = os.fstat(fileno)
        pst = os.stat(path)
    except OSError:
        return False
    return (fst.st_ino, fst.st_dev) == (pst.st_ino, pst.st_dev)


def _compact_and_append(ledger_path, line, compact_window):
    """Rewrite the ledger keeping only window-relevant records (F170).

    Crash-safe: the compacted content (plus the new record) goes to a
    temp file in the same directory, fsync'd, then os.replace() swaps
    it atomically; the directory is fsync'd for rename durability. A
    crash can only ever leave the old complete file or the new complete
    file -- never a truncated ledger.
    """
    with open(ledger_path, "r", encoding="utf-8") as rf:
        content = rf.read()
    now_mono = time.monotonic()
    now_wall = time.time()
    cur_boot = _boot_epoch()
    kept = []
    for raw in content.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        if _record_in_window(rec, now_mono, now_wall,
                             compact_window, cur_boot):
            kept.append(raw)
    kept.append(line.rstrip("\n"))
    tmp = ledger_path.parent / (
        "%s.compact-%d-%d.tmp"
        % (ledger_path.name, os.getpid(), threading.get_ident()))
    try:
        with open(tmp, "w", encoding="utf-8") as wf:
            wf.write("\n".join(kept) + "\n")
            wf.flush()
            os.fsync(wf.fileno())
        dirfd = os.open(str(ledger_path.parent), os.O_DIRECTORY)
        try:
            os.replace(tmp, ledger_path)
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        # A failed compaction must not leave a temp file behind to
        # confuse a later run; missing_ok: it may already be replaced.
        with contextlib.suppress(OSError):
            os.unlink(tmp)


def _append_locked(ledger_path, line):
    """Append ``line`` under an exclusive lock, compacting first when
    the file exceeds the threshold (F170). Raises ExchangeAccessDenied
    when the append cannot be completed safely."""
    window_ok, window_sec, _raw = _validated_window_sec()
    # Compaction bounds size, not tripwire sensitivity: with a broken
    # window config the tripwire path is denied separately (F165), so
    # compaction falls back to the documented default here.
    compact_window = window_sec if window_ok else 900
    threshold = _compact_threshold(compact_window)
    for _attempt in range(3):
        with open(ledger_path, "a", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                if not _same_file(f.fileno(), ledger_path):
                    # Lost the replace race: reopen on the new inode.
                    continue
                size = os.fstat(f.fileno()).st_size
                if size <= threshold:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
                    return
                _compact_and_append(ledger_path, line, compact_window)
                return
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    raise ExchangeAccessDenied(
        "exchange-access ledger append raced compaction repeatedly "
        "(%s): denying cross-run trace read fail-closed"
        % (ledger_path,))


def _record(ledger_path, event, principal, reader_run_id, target,
            path_tail, n_entries, window_stats, reason, mirror_log):
    record = {
        "event": event,
        "ts": time.time(),
        # F166: monotonic stamp + boot epoch gate the tempo window (the
        # wall-clock ts stays for audit readability only).
        "mono": time.monotonic(),
        "boot": _boot_epoch(),
        "reader_principal": principal,
        "reader_key": principal,
        "reader_run_id": reader_run_id,
        "target_run_id": target,
        "path_tail": path_tail,
        "n_entries": n_entries,
        "window_distinct_runs": window_stats[0],
        "window_reads": window_stats[1],
        "decision": "allow" if event == READ_EVENT else "deny",
        "reason": reason,
    }
    _append_record(ledger_path, record)
    if mirror_log is not None:
        # Mirror onto the reader's chained log: the extraction
        # record inherits hash-chain integrity. A mirror failure
        # must not convert an allowed read into a denial, but it
        # must not pass silently either.
        try:
            mirror_log.append({k: v for k, v in record.items()
                               if k != "reader_key"})
        except Exception as e:  # noqa: BLE001 - never break the seam
            raise ExchangeAccessDenied(
                "exchange-read mirror to chained log failed: "
                "denying read fail-closed (%s)" % (e,)) from e
    return record


def _path_tail(path):
    parts = Path(path).parts
    return "/".join(parts[-2:]) if len(parts) >= 2 else str(path)


# -- the guard -------------------------------------------------------

def check_exchange_read(path, n_entries=None):
    """Fail-closed policy gate for trace/exchange reads.

    Called at the public log seam before the file is read
    (``n_entries=None``: policy + replay-tempo check) and after
    parsing (``n_entries`` known: full-trace size check + extraction
    record). Raises ``ExchangeAccessDenied`` on denial; returns None
    on allow. Paths that are not exchange files return immediately.
    """
    target = exchange_target_for_path(path)
    if target is None:
        return None
    principal, run_id, mirror_log = _current_reader()
    if run_id is not None and run_id == target:
        # Own working memory: frictionless, no record, no accounting.
        return None

    ledger_path = _ledger_path_for(path)
    window_ok, window_sec, window_raw = _validated_window_sec()
    max_runs = _env_int("GOV_EXCHANGE_MAX_RUNS", 50)
    max_single = _env_int("GOV_EXCHANGE_MAX_SINGLE_READ", 250000)
    path_tail = _path_tail(path)

    if _allowlisted(principal, target):
        if n_entries is not None:
            _record(ledger_path, READ_EVENT, principal, run_id, target,
                    path_tail, n_entries, (0, 0), "allowlisted",
                    mirror_log)
        return None

    if _strict_posture():
        reason = ("strict cross-principal posture: reader %r has no "
                  "allowlist entry for run %r" % (principal, target))
        _record(ledger_path, DENIED_EVENT, principal, run_id, target,
                path_tail, n_entries, (0, 0), reason, mirror_log)
        raise ExchangeAccessDenied(reason)

    # Default posture: allow + record, subject to the bulk tripwire.
    # F165: this is the only path that consults the window, so a
    # misconfigured (non-positive) window denies here -- loudly, with
    # an audited denied-record -- instead of silently collapsing the
    # tripwire. Own-run reads returned above; allowlisted and strict
    # reads never consult the window and are unaffected.
    if not window_ok:
        reason = ("misconfigured GOV_EXCHANGE_WINDOW_SEC=%r: denying "
                  "cross-run trace read fail-closed" % (window_raw,))
        _record(ledger_path, DENIED_EVENT, principal, run_id, target,
                path_tail, n_entries, (0, 0), reason, mirror_log)
        raise ExchangeAccessDenied(reason)
    recent, truncated = _read_window_full(ledger_path, principal,
                                          window_sec)
    distinct = {r.get("target_run_id") for r in recent}
    distinct.add(target)
    window_stats = (len(distinct), len(recent) + 1)
    if len(distinct) > max_runs:
        reason = ("bulk-extraction tempo: %d distinct run transcripts "
                  "read inside %ds window (limit %d)"
                  % (len(distinct), window_sec, max_runs))
        _record(ledger_path, DENIED_EVENT, principal, run_id, target,
                path_tail, n_entries, window_stats, reason, mirror_log)
        raise ExchangeAccessDenied(reason)
    if truncated:
        # F170: the bounded tail scan could not cover the whole file,
        # so the allow case cannot be proven from the visible records.
        # Deny fail-closed rather than warn-and-continue.
        reason = ("exchange-access ledger exceeds the bounded tempo "
                  "read (%d distinct runs visible, scan truncated): "
                  "denying cross-run trace read fail-closed"
                  % (len(distinct),))
        _record(ledger_path, DENIED_EVENT, principal, run_id, target,
                path_tail, n_entries, window_stats, reason, mirror_log)
        raise ExchangeAccessDenied(reason)
    if n_entries is not None and n_entries > max_single:
        reason = ("full-trace read at scale: %d exchanges in one read "
                  "(limit %d)" % (n_entries, max_single))
        _record(ledger_path, DENIED_EVENT, principal, run_id, target,
                path_tail, n_entries, window_stats, reason, mirror_log)
        raise ExchangeAccessDenied(reason)
    if n_entries is not None:
        _record(ledger_path, READ_EVENT, principal, run_id, target,
                path_tail, n_entries, window_stats,
                "cross-run read recorded", mirror_log)
    return None
