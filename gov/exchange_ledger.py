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

def _read_window(ledger_path, reader_key, window_sec):
    """Recent exchange_read records for this reader inside the window.

    Raises ExchangeAccessDenied when the ledger cannot be read:
    fail-closed, never warn-and-continue.
    """
    cutoff = time.time() - window_sec
    try:
        with open(ledger_path, "r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                lines = f.read().splitlines()
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except FileNotFoundError:
        return []
    except OSError as e:
        raise ExchangeAccessDenied(
            "exchange-access ledger unreadable (%s): denying "
            "cross-run trace read fail-closed" % (ledger_path,)) from e
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
        try:
            if float(rec.get("ts", 0)) < cutoff:
                continue
        except (TypeError, ValueError):
            continue
        out.append(rec)
    return out


def _append_record(ledger_path, record):
    """Append one record under an exclusive lock. Raises
    ExchangeAccessDenied on failure: fail-closed."""
    line = json.dumps(record, ensure_ascii=True, default=str) + "\n"
    try:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with open(ledger_path, "a", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except OSError as e:
        raise ExchangeAccessDenied(
            "exchange-access ledger unwritable (%s): denying "
            "cross-run trace read fail-closed" % (ledger_path,)) from e


def _record(ledger_path, event, principal, reader_run_id, target,
            path_tail, n_entries, window_stats, reason, mirror_log):
    record = {
        "event": event,
        "ts": time.time(),
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
    window_sec = _env_int("GOV_EXCHANGE_WINDOW_SEC", 900)
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
    recent = _read_window(ledger_path, principal, window_sec)
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
