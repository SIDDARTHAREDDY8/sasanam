"""Per-principal egress ledger: tamper-evident cross-run record of outbound
``api_call`` shapes (F10).

Per-run guards cannot see a low-and-slow campaign: three fresh runs, each
sending one innocent-looking credential fragment, are each individually
clean. This ledger gives the engine content-aware cross-run memory: every
``api_call`` attempt that passes DLP is recorded (endpoint, param
count/size/entropy bucket, timestamp, principal, run) in a hash-chained
JSONL file — the same tamper-evidence pattern as the action log
(``gov/log.py``), minus the HMAC key (the ledger is a heuristic signal,
not an authorization artifact; a forged ledger entry can only cause a
spurious approval QUEUE, never an execution).

The ledger lives NEXT TO the runs directory (e.g. ``runs/``), shared by
all runs of a deployment; the path is configurable and tests point it at
temp dirs. A deployment that wants no cross-run memory can point it at a
per-run path (the test harness default).

The campaign rule itself is heuristic and FAIL-SAFE: K small
high-entropy-ish fragments to the SAME registered domain from the SAME
principal across >= 2 distinct runs within a time window ->
``require_approval`` (flag ``cross_run_campaign``). It never denies. See
``ToolExecutor._check_cross_run_campaign`` for the thresholds.

F13: the campaign KEY normalizes the endpoint to its registered domain
(last two hostname labels), so subdomain rotation
(shard0/shard1/shard2.collector.example) lands in ONE bucket. The exact
endpoint string stays in the ledger record for forensics.

F14: a STRUCTURAL campaign signal sits alongside the fragment-shape
signal: same principal + same registered domain + same param KEY SET
across >= K distinct runs inside the window -> ``require_approval``
(flag ``structural_campaign``), regardless of payload size or entropy.
Thin-spread only: a run that repeats the structure K+ times in one run
is bursty repetition (the loop guard's territory), not low-and-slow.

F15: principal-scoped sensitive-read taint. A ``sensitive_read`` entry
records that a principal's run ingested DLP-sensitive content; a fresh
executor for the SAME principal inherits the taint while the mark is
unexpired (24h TTL). Different principals never share taint.

F17 (Round 5): the ledger is now a first-class authenticated record, not
an unkeyed chain. Every entry carries an HMAC computed with the SAME
key epochs as the action log (``GOV_LOG_KEY`` / ``GOV_LOG_KEY_ARCHIVE`` —
historically also the dev key, deleted wave-81; see ``gov/log.py``), plus a sequence number, and every
append writes an HMAC'd checkpoint to a sidecar file
(``<ledger>.checkpoints``). All reads verify before trusting: a tampered
or truncated ledger raises ``LedgerUnverifiableError`` instead of
silently dropping taint — the old behavior failed open, so trimming the
last taint mark defeated the cross-run control. The executor verifies
the ledger at the top of every ``call()`` and refuses to proceed when
it cannot verify.

F23 (Round 6): the F17 verification fast path — a (size, mtime_ns)
stat-signature cache — was defeated by W7-1 (rewrite at identical byte
length + ``os.utime`` mtime restore blinds the campaign detector even
with a real ``GOV_LOG_KEY``, because the cache short-circuits before
any MAC check). Two closures: (a) the signature now includes
``st_ctime_ns`` per file — ``os.utime`` cannot restore ctime (the
kernel bumps it to "now" on every content/metadata change, including
the utime call itself, and no userspace API sets it to the past), so
the filed evasion deterministically misses the cache and falls through
to full HMAC verification; (b) the cache is NEVER trusted without a
verified integrity anchor — historically, when only the public dev key
was configured (``GOV_LOG_KEY`` unset) there was no anchor at all (a T6
attacker who read the docs knew the dev key and could forge MACs), so
``require_verified`` bypassed the cache and re-read + fully verified on
every decision. The dev key was deleted in wave-81; today an unset
``GOV_LOG_KEY`` refuses to start rather than falling back, so this
branch is unreachable in practice. Residuals: (a) filesystems with coarse timestamp
granularity weaken the ctime freshness argument — a rewrite inside the
same ctime tick could still collide; (b) entries written by pre-Round-5
builds have no MAC and do not verify (fail-closed: start a fresh
ledger); (c) fresh-principal rotation remains a deployment trust
boundary — see ``gov/identity.py`` ``PrincipalRegistry``; (d) historically, under the dev key a re-MAC'd forgery was undetectable —
the pre-existing, documented dev-key limitation (``gov/log.py``) at the
time, not a silent cache trust. The dev key was deleted in wave-81;
no dev-key path exists anymore.

F20 (Round 5): ``registered_domain`` no longer uses the naive
last-two-labels heuristic. IP literals are returned unchanged (never
bucketed), and a built-in common multi-label public-suffix table keeps
one registrable label above known suffixes (``evil.co.uk`` and
``good.co.uk`` are different tenants again). The table is intentionally
small — not a full public-suffix list — and rotating the registered
domain itself still evades (F13 residual).

F74 (Round 18): concurrency. ``EgressLedger.append`` was an unlocked
read-modify-write: concurrent writers sharing one ledger (threads in
one process, e.g. N agent threads sharing a run dir doing ``api_call``
bursts) read the same tail and appended the same next sequence number
with divergent hashes -- the chain forked, and every later ``call()``
failed closed with ``LedgerUnverifiableError`` (F-RA1 independently
confirmed the read side: concurrent ``require_verified()`` torn-reads
fail-closed legitimate calls). The fix mirrors the F25 ``ActionLog``
flock discipline: a reentrant per-path read/write lock
(``_ledger_read_locked`` / ``_ledger_write_locked``) combining an
in-process RW guard with POSIX ``fcntl.flock`` -- LOCK_SH for readers,
LOCK_EX across the whole append critical section (verify, tail
re-read, seq assignment, write, checkpoint). Lock acquisition is
bounded (``LEDGER_LOCK_TIMEOUT_SECS``); timeout raises
``LedgerLockError`` and nothing is written or trusted unlocked.

Locking discipline -- scope contract (read before adding locks):
- ONE lock per absolute ledger path, process-wide (``_ledger_lock_for``),
  so separate ``EgressLedger`` instances (one per executor thread)
  serialize on the same lock. The checkpoint sidecar
  (``<ledger>.checkpoints``) is covered TRANSITIVELY: every sidecar
  read/write happens under the ledger lock; never lock the sidecar
  separately.
- Readers (``require_verified`` and every query method) hold the READ
  lock across verify+scan, so no reader observes a torn append --
  in-process (thread guard) or cross-process (flock SH). Readers never
  block each other.
- Reentrancy: a write hold implies read (``append`` calls
  ``require_verified`` under its write hold); read-under-read nests.
  Read->write UPGRADE is refused with ``LedgerLockError`` rather than
  deadlocking -- no current code path upgrades.
- S5 / future work: REUSE ``_ledger_read_locked`` /
  ``_ledger_write_locked``. Do NOT add a second lock around ledger
  I/O -- competing locks on the same bytes reintroduce the fork.
"""

import contextlib
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from . import log as _logmod

_LEDGER_VERSION = 1
_GENESIS_HASH = "0" * 64

# Campaign thresholds (see _check_cross_run_campaign in gov/executor.py).
# A "fragment" is a small, information-dense payload: total string param
# bytes <= _FRAGMENT_MAX_BYTES with at least one string value at
# _FRAGMENT_MIN_ENTROPY bits/char. K fragments from >= 2 distinct runs to
# the same registered domain within the window queue the K-th attempt.
FRAGMENT_MAX_BYTES = 64
FRAGMENT_MIN_ENTROPY = 1.8
CAMPAIGN_K = 3
CAMPAIGN_WINDOW_SECS = 24 * 3600

# F15: how long a principal-scoped sensitive-read mark keeps fresh runs
# of the same principal tainted. Documented, not tuned: long enough to
# cover a confederate two-hop inside one operator session, short enough
# that a stale mark cannot taint the principal forever. Out-of-band
# exfil the engine never sees is still out of scope.
SENSITIVE_TAINT_TTL_SECS = 24 * 3600

# Common multi-label public suffixes (F20). Intentionally small — a
# deployment that needs full coverage should vendor the public suffix
# list; this table only stops the naive last-two-labels heuristic from
# merging unrelated tenants (evil.co.uk vs good.co.uk -> co.uk). IP
# literals are handled separately in registered_domain (never bucketed).
_PUBLIC_SUFFIXES = frozenset(
    """
    co.uk org.uk me.uk net.uk sch.uk ac.uk gov.uk nhs.uk police.uk
    com.au net.au org.au asn.au id.au edu.au gov.au
    co.jp or.jp ne.jp ac.jp go.jp ad.jp
    co.in net.in org.in firm.in gen.in ind.in gov.in ac.in edu.in nic.in
    com.br net.br org.br gov.br edu.br
    co.kr or.kr ne.kr go.kr ac.kr
    co.nz net.nz org.nz govt.nz ac.nz
    com.cn net.cn org.cn gov.cn edu.cn
    com.sg net.sg org.sg edu.sg gov.sg
    com.hk net.hk org.hk edu.hk gov.hk idv.hk
    com.tw net.tw org.tw idv.tw
    co.za net.za org.za gov.za ac.za
    com.mx net.mx org.mx edu.mx gob.mx
    com.ar net.ar org.ar gov.ar edu.ar int.ar
    com.tr net.tr org.tr gov.tr edu.tr
    com.pl net.pl org.pl edu.pl gov.pl
    co.il org.il net.il ac.il gov.il
    com.ph net.ph org.ph edu.ph gov.ph
    com.my net.my org.my edu.my gov.my
    com.vn net.vn org.vn edu.vn gov.vn
    co.th or.th go.th ac.th net.th in.th
    com.eg net.eg org.eg edu.eg gov.eg
    """.split()
)


def registered_domain(endpoint):
    """Registered domain of an endpoint URL (F13/F20 campaign key).

    F20 hardened: IP literals are returned unchanged (``10.0.0.1`` stays
    ``10.0.0.1`` — never bucketed with anything else), and hosts under a
    known multi-label public suffix keep one registrable label above the
    suffix (``a.example.co.uk`` -> ``example.co.uk``; ``evil.co.uk`` and
    ``good.co.uk`` are different tenants). Anything else falls back to
    the last two labels, so ``shard0.collector.example`` and
    ``shard1.collector.example`` both key as ``collector.example``. A bare
    public suffix (or a host with fewer than two labels) passes through
    unchanged. Only the campaign KEY normalizes; the exact endpoint
    string stays in the ledger record for forensics. Residual: the
    built-in suffix table is small, not a full public-suffix list.
    """
    try:
        host = (urlparse(endpoint or "").hostname or "")
    except Exception:
        host = ""
    host = host.strip().lower().rstrip(".")
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host  # IP literal: its own bucket, never merged.
    except ValueError:
        pass
    labels = host.split(".")
    for i in range(len(labels)):
        if ".".join(labels[i:]) in _PUBLIC_SUFFIXES:
            if i == 0:
                return host  # the host IS a public suffix
            return ".".join(labels[i - 1 :])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


class LedgerUnverifiableError(Exception):
    """Raised when the egress ledger cannot be authenticated.

    F17 fail-closed: callers must treat an unverifiable ledger as taint
    ACTIVE (or refuse the action), never as "no taint". The executor
    raises this from ``call()`` before any policy evaluation when the
    ledger is corrupt, forged, or truncated past its newest checkpoint.
    """


def _ledger_keyring():
    """{key_epoch: key_bytes}: active key plus archived epochs.

    F17: the SAME key epochs as the action log (``gov/log.py``) —
    ``GOV_LOG_KEY`` / ``GOV_LOG_KEY_ARCHIVE``. The ledger inherits
    ``gov.log._active_key()``'s process-level resolution (wave-71:
    deliberately no ``deployment_mode=`` kwarg — a per-ledger mode
    declaration could fork the ledger's key epochs away from the
    log's, breaking this contract; one process-level declaration
    moves both together). Wave-69: there is no silent dev-key
    fallback — dev keys require the double opt-in and refuse in
    production mode, exactly as on the log path. Verification
    therefore survives the same rotations the action log does.
    """
    key, epoch = _logmod._active_key()
    keys = {epoch: key}
    archive = os.environ.get("GOV_LOG_KEY_ARCHIVE")
    if archive:
        try:
            mapping = json.loads(archive)
        except ValueError:
            mapping = {}
        if isinstance(mapping, dict):
            for ep, kval in mapping.items():
                keys.setdefault(ep, str(kval).encode("utf-8"))
    return keys


def _real_key_available():
    """True when an HMAC key is explicitly configured (``GOV_LOG_KEY``).

    F23: the stat-signature cache is only ever trusted when a verified
    integrity anchor exists. Wave-81 deleted the public dev key from
    ``gov/`` entirely: with no key configured the action log refuses to
    start (``NoKeyConfiguredError``), so the cache can never be built
    on attacker-known key material.
    """
    return bool(os.environ.get("GOV_LOG_KEY"))


def _ledger_mac(key, key_epoch, prev_hash, canonical):
    """HMAC over one ledger entry (domain-separated from the action log)."""
    return hmac.new(
        key,
        ("ledger|%s|%s|%s" % (key_epoch, prev_hash, canonical)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _checkpoint_mac(key, key_epoch, seq, entry_hash):
    """HMAC over one checkpoint record."""
    return hmac.new(
        key,
        ("ledger-checkpoint|%s|%d|%s" % (key_epoch, seq, entry_hash)).encode(
            "utf-8"
        ),
        hashlib.sha256,
    ).hexdigest()


# ---------------------------------------------------------------------------
# F74 locking: reentrant per-path read/write lock (F25 flock discipline)
# ---------------------------------------------------------------------------

# F74: how long a ledger-lock acquisition waits before failing closed.
# Mirrors F25's APPEND_LOCK_TIMEOUT_SECS (gov/log.py): a crashed lock
# holder's flock is released by the kernel on process death, so a timeout
# means a LIVE holder is stuck -- refusing to proceed unlocked is the
# safe direction.
LEDGER_LOCK_TIMEOUT_SECS = 30
_LEDGER_LOCK_POLL_SECS = 0.02


class LedgerLockError(OSError):
    """F74: the egress-ledger lock could not be acquired in time.

    Fail-closed: the caller must not write to or trust the ledger
    unlocked. ``append`` lets this propagate (nothing is written);
    ``require_verified`` converts it to ``LedgerUnverifiableError``
    (refuse to act). Mirrors F25's ``AppendLockError`` for the action
    log.
    """


class _LedgerMissing(Exception):
    """F74: the ledger path is missing or unusable (parent missing,
    not-a-directory, ...), so there is no file to lock.

    Internal sentinel only: every public reader converts it to its
    missing-ledger default -- exactly the pre-F74 behavior, where
    readers checked ``path.exists()`` and treated an unusable path as
    "no ledger" (fail open for the heuristic signal). An EXISTING but
    unreadable ledger still fails closed (``LedgerLockError`` ->
    ``LedgerUnverifiableError``), never as "clean".
    """


class _LedgerRWLock:
    """Reentrant read/write lock for one ledger path (F74).

    Two layers, one acquisition:
    - In-process: a condition-variable RW guard with writer preference.
      Reentrant for the owning thread: a write hold implies read (so
      ``append`` can call ``require_verified`` under its write hold),
      read-under-read nests. Read->write upgrade is REFUSED with
      ``LedgerLockError`` instead of deadlocking -- no current code path
      upgrades; fail closed on the programming error.
    - Cross-process: POSIX ``fcntl.flock`` -- LOCK_SH for readers
      (readers never block each other, in or across processes, so the
      hot ``require_verified`` path does not convoy), LOCK_EX for the
      append critical section (appends linearize across processes; no
      two writers can assign the same sequence number or fork the
      chain).

    Each outermost acquisition opens its OWN fd and flocks it; the fd is
    closed on outermost release. The condition variable is never held
    across the blocking flock poll, so a stuck flock cannot wedge the
    in-process guard. All waits are bounded by
    ``LEDGER_LOCK_TIMEOUT_SECS``: acquisition failure raises
    ``LedgerLockError`` -- never proceed unlocked.
    """

    def __init__(self, path):
        self._path = path
        self._cond = threading.Condition(threading.Lock())
        self._depths = {}      # thread ident -> reentrant hold depth
        self._readers = set()  # idents holding an outermost read
        self._writer = None    # ident holding the write, if any
        self._writers_waiting = 0
        self._fds = {}         # ident -> [fd] (one per outermost hold)

    def _acquire_flock(self, fd, exclusive, deadline, what):
        op = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        while True:
            try:
                fcntl.flock(fd, op | fcntl.LOCK_NB)
                return
            except (OSError, BlockingIOError):
                if time.monotonic() >= deadline:
                    raise LedgerLockError(
                        "could not acquire the %s ledger lock on %s "
                        "within %ds; refusing to proceed unlocked"
                        % (what, self._path, LEDGER_LOCK_TIMEOUT_SECS))
                time.sleep(_LEDGER_LOCK_POLL_SECS)

    def acquire_read(self):
        me = threading.get_ident()
        deadline = time.monotonic() + LEDGER_LOCK_TIMEOUT_SECS
        with self._cond:
            if me in self._depths:
                # Reentrant: already hold read or write; write implies
                # read, so no flock work is needed.
                self._depths[me] += 1
                return
            # Writer preference: once a writer is waiting, new readers
            # queue behind it (bounded by the deadline).
            while self._writer is not None or self._writers_waiting:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LedgerLockError(
                        "timed out waiting for the ledger read lock on "
                        "%s; refusing to trust the ledger unlocked"
                        % (self._path,))
                self._cond.wait(timeout=remaining)
            self._depths[me] = 1
            self._readers.add(me)
        # The condition is NOT held across the blocking flock poll.
        # Read mode opens "r": readers never create the file (pre-F74
        # readers didn't either). An unusable path reads as missing
        # (_LedgerMissing -> the caller's missing-ledger default); an
        # EXISTING but unopenable path fails closed via LedgerLockError.
        try:
            fd = open(self._path, "r", encoding="utf-8")
        except OSError:
            with self._cond:
                del self._depths[me]
                self._readers.discard(me)
                self._cond.notify_all()
            if not os.path.exists(self._path):
                raise _LedgerMissing(self._path)
            raise LedgerLockError(
                "could not open the ledger for a shared lock: %s; "
                "refusing to trust the ledger unlocked" % (self._path,))
        try:
            self._acquire_flock(fd, False, deadline, "shared")
        except BaseException:
            with self._cond:
                del self._depths[me]
                self._readers.discard(me)
                self._cond.notify_all()
            fd.close()
            raise
        with self._cond:
            self._fds.setdefault(me, []).append(fd)

    def acquire_write(self):
        me = threading.get_ident()
        deadline = time.monotonic() + LEDGER_LOCK_TIMEOUT_SECS
        with self._cond:
            if self._writer == me:
                self._depths[me] += 1  # reentrant write
                return
            if me in self._depths:
                # Read->write upgrade would deadlock against other
                # readers; refuse instead of hanging. No caller does this.
                raise LedgerLockError(
                    "read->write ledger lock upgrade is not supported "
                    "for %s; release the read hold first" % (self._path,))
            self._writers_waiting += 1
            try:
                while self._writer is not None or self._readers:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise LedgerLockError(
                            "timed out waiting for the ledger write lock "
                            "on %s; refusing to write unlocked"
                            % (self._path,))
                    self._cond.wait(timeout=remaining)
                self._writer = me
                self._depths[me] = 1
            finally:
                self._writers_waiting -= 1
        # The condition is NOT held across the blocking flock poll.
        try:
            fd = open(self._path, "a", encoding="utf-8")
        except OSError as e:
            with self._cond:
                del self._depths[me]
                self._writer = None
                self._cond.notify_all()
            raise LedgerLockError(
                "could not open the ledger for the exclusive lock: %s "
                "(%s); refusing to write unlocked" % (self._path, e))
        try:
            self._acquire_flock(fd, True, deadline, "exclusive")
        except BaseException:
            with self._cond:
                del self._depths[me]
                self._writer = None
                self._cond.notify_all()
            fd.close()
            raise
        with self._cond:
            self._fds.setdefault(me, []).append(fd)

    def release(self):
        me = threading.get_ident()
        with self._cond:
            depth = self._depths.get(me, 0)
            if not depth:
                raise LedgerLockError(
                    "release of unheld ledger lock for %s" % (self._path,))
            if depth > 1:
                self._depths[me] = depth - 1
                return
            del self._depths[me]
            self._readers.discard(me)
            if self._writer == me:
                self._writer = None
            fds = self._fds.get(me)
            fd = fds.pop() if fds else None
            if not fds:
                self._fds.pop(me, None)
            self._cond.notify_all()
        if fd is not None:
            try:
                fd.close()  # releases the flock
            except OSError:
                pass


_ledger_locks_guard = threading.Lock()
_ledger_locks = {}


def _ledger_lock_for(path):
    """The process-wide ``_LedgerRWLock`` for one ledger path (F74).

    Keyed by absolute path so separate ``EgressLedger`` instances (e.g.
    one per ``ToolExecutor`` thread sharing a run dir) serialize on the
    same lock. Lazily created under a guard; entries are small and
    bounded by the number of distinct ledger paths in the process.
    """
    key = os.path.abspath(os.path.expanduser(str(path)))
    with _ledger_locks_guard:
        lock = _ledger_locks.get(key)
        if lock is None:
            lock = _LedgerRWLock(key)
            _ledger_locks[key] = lock
        return lock


def _reset_ledger_locks_after_fork():
    # A forked child inherits the registry with lock state belonging to
    # the parent's threads; drop it so the child rebuilds clean locks.
    # (The flock itself lives on the parent's fds, which the child no
    # longer references -- the child re-opens and contends normally.)
    with _ledger_locks_guard:
        _ledger_locks.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_ledger_locks_after_fork)


@contextlib.contextmanager
def _ledger_read_locked(path):
    """Hold the F74 read lock (flock LOCK_SH) across the critical section.

    F74/F-RA1: readers verify and scan under a shared lock, so no reader
    observes a torn append -- in-process (thread guard) or cross-process
    (flock). Readers never block each other.
    """
    lock = _ledger_lock_for(path)
    lock.acquire_read()
    try:
        yield
    finally:
        lock.release()


@contextlib.contextmanager
def _ledger_write_locked(path):
    """Hold the F74 write lock (flock LOCK_EX) across the critical section.

    F74: serializes ``EgressLedger.append`` across threads and processes
    (the F25 ``ActionLog`` discipline), so concurrent appends linearize
    -- no two writers can assign the same sequence number or fork the
    hash chain. Bounded wait; ``LedgerLockError`` on timeout: the write
    never happens unlocked.
    """
    lock = _ledger_lock_for(path)
    lock.acquire_write()
    try:
        yield
    finally:
        lock.release()


class EgressLedger:
    """Append-only HMAC-authenticated JSONL of outbound api_call shapes.

    F17: every entry is HMAC'd with the active ledger key epoch and
    carries a sequence number; every append writes an HMAC'd checkpoint
    to the ``<ledger>.checkpoints`` sidecar. All reads verify before
    trusting (``require_verified``): tampering or tail truncation raises
    ``LedgerUnverifiableError`` instead of silently dropping taint.

    F74: ``append`` holds the exclusive ledger lock
    (``_ledger_write_locked``) across the whole read-modify-write --
    verify, tail re-read, seq assignment, entry write, checkpoint --
    so concurrent writers linearize and the chain cannot fork. Readers
    (``require_verified`` and every query method) hold the shared lock
    across verify+scan, so no torn reads (F-RA1). ``self._seq`` /
    ``self._prev`` are per-instance caches only: ``append`` re-reads the
    tail UNDER the write lock, so a stale instance cache can never fork
    the chain.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.checkpoint_path = Path(str(self.path) + ".checkpoints")
        self._seq, self._prev = self._tail_state()
        self._verified_sig = None  # (size, mtime_ns, ctime_ns) x2 of the
        # last good verify; F23: trusted ONLY when a real HMAC key is
        # configured (see _real_key_available) — never under the dev key.

    def _sig(self):
        """Stat signature of the ledger *and* its checkpoint sidecar.

        F23: the signature is (size, mtime_ns, ctime_ns) per file. ctime
        is the load-bearing component against the W7-1 evasion:
        ``os.utime`` can restore atime/mtime, but the kernel always
        bumps ctime to "now" on ANY content or metadata change —
        including the utime call itself — and no userspace API can set
        ctime to an arbitrary past value. An in-place rewrite at
        identical byte length therefore cannot reproduce the cached
        ctime_ns: the evasion deterministically misses the cache and
        falls through to full HMAC verification. A cache hit still
        means "unchanged since the last HMAC-anchored verification".
        """
        def _one(p):
            try:
                st = p.stat()
            except OSError:
                return None
            return (st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        return (_one(self.path), _one(self.checkpoint_path))

    # -- authenticated chaining (F17) ----------------------------------

    def _tail_state(self):
        """(seq, entry_hash) of the last ledger entry, O(tail).

        Reads at most the last 8 KiB: ledger entries are bounded shape
        records (no payload values), so one entry always fits. A missing
        file is (0, genesis); an unparseable tail yields (0, genesis) but
        ``require_verified`` refuses the file before any append can fork
        the chain, so this fallback is unreachable for corrupt files.
        """
        seq, prev = 0, _GENESIS_HASH
        if not self.path.exists():
            return seq, prev
        try:
            with open(self.path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 8192))
                tail = f.read().decode("utf-8", "replace")
        except OSError:
            return seq, prev
        lines = [ln for ln in tail.splitlines() if ln.strip()]
        if not lines:
            return seq, prev
        try:
            entry = json.loads(lines[-1])
            seq = int(entry.get("seq", 0))
            prev = entry.get("entry_hash") or prev
        except (ValueError, TypeError):
            pass
        return seq, prev

    def _read_checkpoints(self):
        """All parseable checkpoint records, oldest first."""
        out = []
        if not self.checkpoint_path.exists():
            return out
        try:
            text = self.checkpoint_path.read_text(encoding="utf-8")
        except OSError:
            return out
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                cp = json.loads(line)
            except ValueError:
                continue
            if isinstance(cp, dict) and isinstance(cp.get("seq"), int):
                out.append(cp)
        return out

    def _write_checkpoint(self, seq, entry_hash, key_epoch, end_offset, key):
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        cp = {
            "v": _LEDGER_VERSION,
            "seq": seq,
            "hash": entry_hash,
            "key_epoch": key_epoch,
            "end_offset": end_offset,
            "mac": _checkpoint_mac(key, key_epoch, seq, entry_hash),
        }
        with open(self.checkpoint_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(cp, sort_keys=True) + "\n")

    def append(self, shape):
        """Record one api_call shape; returns the chained record.

        F17: verifies the ledger BEFORE appending — a tampered ledger
        refuses new writes (fail-closed) — then HMACs the entry with the
        active key epoch and writes an HMAC'd checkpoint.

        F74: the whole read-modify-write runs under the exclusive ledger
        lock (``_ledger_write_locked``) — the F25 ``ActionLog``
        discipline. The tail is re-read UNDER the lock, so concurrent
        writers (threads or processes) linearize: no duplicate sequence
        numbers, no forked chain. ``LedgerLockError`` on lock timeout:
        nothing is written unlocked.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _ledger_write_locked(self.path):
            self.require_verified()  # nested: write implies read
            key, epoch = _logmod._active_key()
            # Re-read the tail UNDER the lock: another writer may have
            # appended since this instance last looked; the lock is what
            # makes the read-modify-write atomic.
            self._seq, self._prev = self._tail_state()
            seq = self._seq + 1
            body = dict(shape)
            body["v"] = _LEDGER_VERSION
            body["seq"] = seq
            body["key_epoch"] = epoch
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
            mac = _ledger_mac(key, epoch, self._prev, canonical)
            entry_hash = hashlib.sha256(
                (self._prev + canonical).encode("utf-8")
            ).hexdigest()
            record = dict(body)
            record["prev_hash"] = self._prev
            record["entry_hash"] = entry_hash
            record["mac"] = mac
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")
                f.flush()
                end_offset = f.tell()
            self._write_checkpoint(seq, entry_hash, epoch, end_offset, key)
            self._seq, self._prev = seq, entry_hash
            # We verified before writing and know exactly the bytes we
            # appended, so the new stat signature is known-good: the next
            # require_verified() stays O(1) without re-reading.
            self._verified_sig = self._sig()
            return record

    def require_verified(self):
        """Raise ``LedgerUnverifiableError`` unless the ledger verifies.

        F17 fail-closed reads. The executor calls this at the top of
        every ``call()``; the ledger's own readers (``taint_active``,
        ``fragments``, ``structural_campaign_hit``, ``append``) call it
        too. A missing ledger is vacuously fine (nothing to trust yet).
        Corruption, forgery, or truncation past the newest checkpoint all
        raise — the caller must then treat taint as ACTIVE or refuse the
        action, never as "no taint".

        Soundness (F23): whenever the file's stat signature changed since
        the last successful verification, the ledger is re-verified from
        genesis (O(n)) — a checkpoint alone never vouches for bytes it
        did not re-read, so same-size modifications before the newest
        checkpoint cannot slip through. The signature now includes
        ``st_ctime_ns`` per file, which ``os.utime`` cannot restore, so
        the W7-1 rewrite+utime evasion deterministically misses the
        cache. And the cache is NEVER trusted without a verified
        integrity anchor: when no real HMAC key is configured
        (``GOV_LOG_KEY`` unset — only the public dev key, which a T6
        attacker knows), the cache is bypassed entirely and the ledger
        is re-read and fully verified on every decision. No
        silent-trust path remains: under a real key a cache hit means
        "no status change since the last HMAC-anchored verification"
        (ctime freshness); under the dev key every decision re-verifies
        the bytes (the remaining dev-key forgery residual is the
        documented dev-key limitation, not a silent trust).

        F74/F-RA1: the verify runs under the shared ledger lock
        (``_ledger_read_locked``), so a concurrent append cannot tear
        the read mid-verify -- the F-RA1 fail-closed refusal of
        legitimate calls is fixed for threads and processes alike. A
        read-lock timeout fails closed as ``LedgerUnverifiableError``
        (refuse to trust), never as "clean".
        """
        if not self.path.exists():
            return
        try:
            with _ledger_read_locked(self.path):
                self._require_verified_locked()
        except _LedgerMissing:
            # Unusable path (parent missing, not-a-directory, ...):
            # pre-F74 readers treated this exactly like a missing ledger
            # (fail open for the heuristic signal).
            return
        except LedgerLockError as e:
            raise LedgerUnverifiableError(
                "could not acquire the ledger read lock for %s: %s -- "
                "refusing to trust the ledger" % (self.path, e))

    def _require_verified_locked(self):
        """Verify assuming the read (or write) ledger lock is held."""
        sig = self._sig()
        if sig[0] is None:
            raise LedgerUnverifiableError("cannot stat ledger: %s"
                                          % (self.path,))
        # F23: the O(1) cache fast path is allowed ONLY with a real key.
        # Under the dev key there is no integrity anchor, so the cache
        # is bypassed and the file is re-read + fully verified below.
        if _real_key_available() and sig == self._verified_sig:
            return
        if not self._verify_full(_ledger_keyring()):
            raise LedgerUnverifiableError(
                "ledger verification failed for %s: the ledger was "
                "tampered with, forged, or truncated — treating taint "
                "as ACTIVE" % (self.path,)
            )
        self._verified_sig = sig

    def _verify_full(self, keys):
        """Full from-genesis authentication, O(n)."""
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError:
            return False
        prev = _GENESIS_HASH
        seq = 0
        hash_at_seq = {}
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                return False
            seq += 1
            if entry.get("seq") != seq or entry.get("prev_hash") != prev:
                return False
            epoch = entry.get("key_epoch")
            key = keys.get(epoch)
            if key is None:
                return False
            body = {
                k: v
                for k, v in entry.items()
                if k not in ("prev_hash", "entry_hash", "mac")
            }
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
            if not hmac.compare_digest(
                str(entry.get("mac") or ""), _ledger_mac(key, epoch, prev, canonical)
            ):
                return False
            # Unkeyed chain kept as defense-in-depth (as before F17).
            unkeyed = hashlib.sha256((prev + canonical).encode("utf-8")).hexdigest()
            if unkeyed != entry.get("entry_hash"):
                return False
            prev = entry["entry_hash"]
            hash_at_seq[seq] = prev
        # Checkpoints on disk must agree with the file they anchor:
        # a checkpoint ahead of the file, or disagreeing on the hash at
        # its seq, means the tail was trimmed.  The checkpoint sidecar is
        # the tail-truncation anchor: a non-empty ledger with NO sidecar
        # fails closed (deleted sidecar, or a crash between the entry
        # write and the checkpoint write in append()).
        cps = self._read_checkpoints()
        if seq > 0 and not cps:
            return False
        for cp in cps:
            epoch = cp.get("key_epoch")
            key = keys.get(epoch)
            if key is None:
                return False
            try:
                cseq = int(cp.get("seq"))
            except (TypeError, ValueError):
                return False
            if not hmac.compare_digest(
                str(cp.get("mac") or ""),
                _checkpoint_mac(key, epoch, cseq, str(cp.get("hash") or "")),
            ):
                return False
            if cseq > seq:
                return False
            if hash_at_seq.get(cseq) != cp.get("hash"):
                return False
        return True

    def verify(self):
        """True iff the whole ledger authenticates (O(n), from genesis).

        F17: checks every entry's HMAC (under its recorded key epoch),
        the unkeyed chain linkage, and the sequence numbers, then
        requires every checkpoint on disk to agree with the file. A
        missing ledger verifies True (nothing to distrust). Entries
        without a MAC (pre-Round-5 builds) do NOT verify — fail-closed;
        start a fresh ledger. A non-empty ledger whose checkpoint
        sidecar is missing also does NOT verify: the sidecar is the
        tail-truncation anchor, and its absence is treated as tampering.

        F74: runs under the shared ledger lock, so the scan cannot tear
        against a concurrent append.
        """
        if not self.path.exists():
            return True
        try:
            with _ledger_read_locked(self.path):
                return self._verify_full(_ledger_keyring())
        except _LedgerMissing:
            return True

    # -- campaign query --------------------------------------------------

    @staticmethod
    def _entry_domain(entry):
        """Registered domain for one ledger entry (F13).

        New entries carry ``campaign_domain`` (written by
        ``ToolExecutor._api_call_shape``); older entries fall back to
        normalizing their exact ``endpoint`` string, so the rotation fix
        applies to history already on disk.
        """
        domain = entry.get("campaign_domain")
        if domain:
            return domain
        return registered_domain(entry.get("endpoint") or "")

    def fragments(self, principal, endpoint, window_secs=CAMPAIGN_WINDOW_SECS,
                  now=None):
        """Fragment-shaped entries for principal+endpoint inside the window.

        F13: the endpoint is normalized to its registered domain before
        keying, so ``shard0.collector.example`` and
        ``shard1.collector.example`` land in the SAME campaign bucket.

        F74: the verify+scan runs under the shared ledger lock, so the
        scan cannot tear against a concurrent append (F-RA1).
        """
        if not self.path.exists():
            return []
        try:
            with _ledger_read_locked(self.path):
                self.require_verified()  # nested: reentrant under read hold
                now = time.time() if now is None else now
                domain = registered_domain(endpoint)
                out = []
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    if (entry.get("principal") == principal
                            and self._entry_domain(entry) == domain
                            and entry.get("fragment") is True
                            and now - float(entry.get("ts", 0)) <= window_secs):
                        out.append(entry)
                return out
        except _LedgerMissing:
            return []

    def campaign_hit(self, principal, endpoint,
                     window_secs=CAMPAIGN_WINDOW_SECS, now=None,
                     k=CAMPAIGN_K):
        """True when >= k fragments from >= 2 distinct runs are in window.

        The K-th fragment (counting the just-recorded current attempt) is
        what queues. Requiring >= 2 distinct runs keeps single-run
        identical-call bursts (the loop guard's territory) out of this
        rule's reach. F13: keying is on the registered domain, not the
        exact endpoint string.
        """
        frags = self.fragments(principal, endpoint, window_secs, now)
        if len(frags) < k:
            return False
        return len({f.get("run_id") for f in frags}) >= 2

    def structural_campaign_hit(self, principal, domain, param_keys,
                                window_secs=CAMPAIGN_WINDOW_SECS, now=None,
                                k=CAMPAIGN_K):
        """F14: True when >= k api_call entries share (principal, domain,
        param_keys) across >= k distinct runs inside the window.

        The STRUCTURAL campaign signal: it does not look at payload size
        or entropy at all, so oversize padding and sub-entropy encodings
        (unary) still trip it — the attacks it was built for repeat the
        same call structure thinly across runs. A run counts only when
        it contributed FEWER than k matching calls: a single run that
        repeats the structure k+ times is bursty repetition (the loop
        guard's territory), not low-and-slow. Empty key sets never match
        (a param-less call carries no exfil payload). Heuristic,
        queue-only, fail-safe — same contract as campaign_hit.

        F74: the verify+scan runs under the shared ledger lock (F-RA1).
        """
        if not self.path.exists():
            return False
        try:
            with _ledger_read_locked(self.path):
                self.require_verified()  # nested: reentrant under read hold
                if not principal or not domain or not param_keys:
                    return False
                now = time.time() if now is None else now
                wanted = sorted(param_keys)
                per_run = {}
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    if entry.get("tool") != "api_call":
                        continue
                    if entry.get("principal") != principal:
                        continue
                    if self._entry_domain(entry) != domain:
                        continue
                    keys = entry.get("param_keys")
                    if not keys or sorted(keys) != wanted:
                        continue
                    try:
                        ts = float(entry.get("ts", 0))
                    except (TypeError, ValueError):
                        continue
                    if now - ts > window_secs:
                        continue
                    run_id = entry.get("run_id")
                    per_run.setdefault(run_id, 0)
                    per_run[run_id] += 1
                thin_runs = [r for r, n in per_run.items() if n < k]
                return len(thin_runs) >= k
        except _LedgerMissing:
            return False

    @staticmethod
    def _shape_sketch(shape):
        """F36: privacy-preserving content/shape sketch for
        cross-principal correlation. Deterministic and PARAM-NAME-BLIND:
        (registered domain, parameter count, coarse total-string-byte
        bucket, coarse entropy bucket, fragment classification). No raw
        values and no parameter names enter the sketch, so the ledger
        cannot become an exfil store and key rotation does not change
        the sketch."""
        n = shape.get("n_params") or 0
        try:
            sb = int(shape.get("str_bytes") or 0)
        except (TypeError, ValueError):
            sb = 0
        try:
            ent = float(shape.get("max_entropy") or 0.0)
        except (TypeError, ValueError):
            ent = 0.0
        return (
            shape.get("campaign_domain") or "",
            n,
            min(max(sb, 0) // 32, 8),
            min(max(int(ent * 2), 0), 8),
            bool(shape.get("fragment")),
        )

    def cross_principal_campaign_hit(self, shape,
                                     window_secs=CAMPAIGN_WINDOW_SECS,
                                     now=None, k=CAMPAIGN_K,
                                     principal_registry=None):
        """F36: True when >= k DISTINCT principals emit fragment-shaped
        api_call entries sharing the same content/shape SKETCH inside
        the window.

        The principal-ROTATION campaign signal: the per-principal
        detectors never reach K when the attacker mints a fresh
        principal per run, so the shape is correlated ACROSS principals
        instead — and the correlation is param-name-blind (see
        ``_shape_sketch``), so rotating param KEY sets alongside the
        principal does not evade it. Only fragment-shaped entries
        count (small + high-entropy — the campaign shape): this keeps
        benign fleet traffic with large or low-entropy payloads out.
        Thin-spread only, mirroring ``structural_campaign_hit``: each
        (principal, run) may contribute FEWER than k matching calls.
        Param-less calls never match (no exfil payload). Heuristic,
        queue-only, fail-safe — same contract as the other campaign
        detectors.

        F41 (R10): throwaway-planted quorum. A fresh principal per run
        is cheap, so a bare distinct-principal count lets an attacker
        plant two throwaway look-alikes and have the VICTIM's next
        same-shaped call be the Kth — queueing a benign call (a
        false-positive weapon). The quorum now ALSO requires at least
        K-1 ESTABLISHED principals.

        F46 (R11): establishment is now MULTI-RUN continuity — a
        principal counts as established only with matching
        observations across >= 2 DISTINCT RUN IDs in the window. The
        F41 rule (>= 2 observations) let ONE run's two calls prime a
        throwaway into "established" (same-run four-call priming);
        that no longer establishes. When a deployment principal
        registry is passed (registry mode), establishment is
        registry-backed instead: a registered principal is
        deployment-vetted out-of-band, so it counts as established
        without behavioral history — throwaways cannot register,
        which is what made the F41 plant attack possible in
        permissive mode. In both modes the quorum needs k distinct
        principals AND k-1 established ones.

        Residual (documented, not solved): an attacker rotating
        principal AND content shape per run (fresh identity, fresh
        shape) is indistinguishable from distinct legitimate users —
        that is an identity-layer problem (principal registry
        binding), not a shape-layer one. Patient throwaways that emit
        in TWO runs each before joining the quorum can still poison
        it in permissive mode — the cost is raised (distinct runs over
        time, not one burst) but behavioral history is still not
        identity trust. In registry mode the residual is a compromised
        REGISTERED principal: quorum still needs k distinct
        principals, so one compromised principal alone cannot fire it.

        F74: the verify+scan runs under the shared ledger lock (F-RA1).
        """
        if not self.path.exists():
            return False
        try:
            with _ledger_read_locked(self.path):
                return self._cross_principal_campaign_hit_locked(
                    shape, window_secs, now, k, principal_registry)
        except _LedgerMissing:
            return False

    def _cross_principal_campaign_hit_locked(self, shape, window_secs, now,
                                             k, principal_registry):
        """Scan assuming the read ledger lock is held (F74)."""
        self.require_verified()  # nested: reentrant under the read hold
        if not self.path.exists():
            return False
        if not isinstance(shape, dict):
            return False
        if not shape.get("fragment"):
            return False
        if (shape.get("n_params") or 0) < 1:
            return False
        now = time.time() if now is None else now
        wanted = self._shape_sketch(shape)
        if not wanted[0]:
            return False
        per_principal_run = {}
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if entry.get("tool") != "api_call":
                continue
            if not entry.get("fragment"):
                continue
            if self._shape_sketch(entry) != wanted:
                continue
            try:
                ts = float(entry.get("ts", 0))
            except (TypeError, ValueError):
                continue
            if now - ts > window_secs:
                continue
            principal = entry.get("principal")
            run_id = entry.get("run_id")
            if not principal or not run_id:
                continue
            per_principal_run.setdefault((principal, run_id), 0)
            per_principal_run[(principal, run_id)] += 1
        # Thin-spread: drop (principal, run) buckets with >= k calls,
        # then count the DISTINCT principals that remain — and the
        # distinct RUN IDs each principal was seen in.
        thin_principal_runs = {}
        for (p, r), n in per_principal_run.items():
            if n < k:
                thin_principal_runs.setdefault(p, set()).add(r)
        # F46 (R11): establishment — multi-run continuity. A principal
        # counts as established only with matching observations across
        # >= 2 DISTINCT RUN IDs in the window; same-run priming (two
        # calls in one run) no longer establishes. Counted over the
        # same thin-spread-filtered observations as the quorum, so a
        # single-run flood cannot manufacture history. In registry mode
        # the deployment registry backs establishment: registered
        # principals are deployment-vetted, so they count as
        # established without behavioral history (permissive mode falls
        # back to the multi-run rule). The quorum needs k distinct
        # principals AND k-1 established ones.
        if principal_registry is not None:
            registered = principal_registry.registered()
            established = sum(1 for p in thin_principal_runs
                              if p in registered)
        else:
            established = sum(1 for runs in thin_principal_runs.values()
                              if len(runs) >= 2)
        return (len(thin_principal_runs) >= k
                and established >= max(1, k - 1))

    # -- principal-scoped sensitive-read taint (F15) ------------------------

    def taint_mark(self, principal, run_id, now=None):
        """Persist a sensitive-read mark for *principal* (F15).

        Records that this principal's run ingested DLP-sensitive
        content. A fresh executor for the SAME principal inherits the
        taint while the mark is unexpired (see ``taint_active``);
        different principals never share taint. F17: the mark rides the
        HMAC-authenticated chain, so a forged mark is rejected by
        ``require_verified`` instead of being trusted.
        """
        if not principal:
            return None
        return self.append({
            "kind": "sensitive_read",
            "ts": time.time() if now is None else now,
            "principal": principal,
            "run_id": run_id,
        })

    def taint_active(self, principal, ttl_secs=SENSITIVE_TAINT_TTL_SECS,
                     now=None):
        """True when *principal* has an unexpired sensitive-read mark.

        F17: verifies the ledger first — a tampered ledger raises
        ``LedgerUnverifiableError`` instead of returning False, so a
        trimmed taint mark fails CLOSED, never open.

        F74: the verify+scan runs under the shared ledger lock (F-RA1).
        """
        if not self.path.exists() or not principal:
            return False
        try:
            with _ledger_read_locked(self.path):
                self.require_verified()  # nested: reentrant under read hold
                now = time.time() if now is None else now
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    if (entry.get("kind") == "sensitive_read"
                            and entry.get("principal") == principal):
                        try:
                            ts = float(entry.get("ts", 0))
                        except (TypeError, ValueError):
                            continue
                        if now - ts <= ttl_secs:
                            return True
                return False
        except _LedgerMissing:
            return False
