"""Async Haber-Stornetta anchorer: epochs, checkpoint policy, receipts.

Wave-72. Drives :mod:`gov.anchor_backend` witnesses from the executor side.
Never in the enforcement path, never from inside the sandbox (deny-all
egress -- the anchor client lives here only).

* :class:`AnchorPolicy` -- checkpoint cadence (the security parameter).
* :class:`Anchorer` -- closes epochs per the policy, submits statements on
  a daemon worker thread, chains ``anchor_receipt`` /
  ``anchor_epoch_unanchored`` records, retries with bounds.
* :func:`resolve_anchor_key` -- anchor-signing key resolution
  (keyprovider idiom: ``GOV_ANCHOR_KEY`` / ``GOV_ANCHOR_KEY_FILE`` /
  non-production double opt-in / production refuses loud).
* :func:`audit_anchors` -- the auditor walk: checkpoint -> receipt ->
  witness, per-epoch grades ``anchored`` vs ``operator-attested-only``.

Load-bearing guarantee: "no undetected rewrite of history prior to the last
anchor" -- history after the last anchor is soft, and the anchor cadence is
the security parameter.
"""

import json
import os
import sys
import threading
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from . import anchor_backend as _ab
from . import evidence_fanout as _fanout
from . import log as _log
from .digest_ref import DigestRef

ANCHOR_RECEIPT_EVENT = "anchor_receipt"
ANCHOR_UNANCHORED_EVENT = "anchor_epoch_unanchored"

GRADE_ANCHORED = "anchored"
GRADE_OPERATOR_ONLY = "operator-attested-only"

# The load-bearing guarantee, stated once and quoted verbatim everywhere.
GUARANTEE = ('"no undetected rewrite of history prior to the last anchor" '
             "-- history after the last anchor is soft, and the anchor "
             "cadence is the security parameter.")


class AnchorerError(Exception):
    """Fatal (non-retryable) anchorer failure."""


# Wave-219 unsafe-path registry: gov.anchorer.unconfigured_anchoring_disabled
class NoAnchorKeyError(AnchorerError):
    """No anchor-signing key configured (production refuses loud)."""


class AnchorPolicy:
    """Checkpoint cadence: every N records and/or T seconds and/or run close.

    Defaults: 100 records, 3600 s, anchor on close. The cadence IS the
    security parameter: shorter = smaller soft window (stronger guarantee)
    + more witness traffic. Documented tradeoffs in ANCHOR_DESIGN.md.
    """

    def __init__(self, records_per_epoch=100, seconds_per_epoch=3600,
                 anchor_on_close=True):
        if not isinstance(records_per_epoch, int) or records_per_epoch < 1:
            raise ValueError("records_per_epoch must be a positive int")
        if seconds_per_epoch is not None and (
                not isinstance(seconds_per_epoch, (int, float))
                or seconds_per_epoch <= 0):
            raise ValueError(
                "seconds_per_epoch must be a positive number or None")
        self.records_per_epoch = records_per_epoch
        self.seconds_per_epoch = seconds_per_epoch
        self.anchor_on_close = bool(anchor_on_close)

    def describe(self):
        parts = ["every %d records" % self.records_per_epoch]
        if self.seconds_per_epoch is not None:
            parts.append("or every %ds" % self.seconds_per_epoch)
        if self.anchor_on_close:
            parts.append("or run close")
        return "An epoch closes " + ", ".join(parts) + "."


# Wave-81: the dev anchor-key double opt-in (the in-code enabler plus
# the dev opt-in environment variable) was DELETED from gov/.
# Anchoring requires an explicitly configured Ed25519 seed in every
# mode; unconfigured anchoring raises NoAnchorKeyError loudly — the
# chain continues as operator-attested-only, never silently unanchored.


def resolve_anchor_key(explicit=None):
    """Resolve the Ed25519 anchor-signing key (keyprovider idiom).

    Precedence: explicit hex seed > ``GOV_ANCHOR_KEY`` (hex) >
    ``GOV_ANCHOR_KEY_FILE`` (0600 file, hex). Nothing configured raises
    :class:`NoAnchorKeyError` -- anchoring stays disabled and the chain
    continues as ``operator-attested-only``, never silently unanchored.
    Wave-81 deleted the dev anchor-key fallback: there is no
    non-production ephemeral key anymore; every deployment that wants
    anchors configures a seed explicitly.

    Returns ``{"seed", "key_id", "pubkey_hex", "dev"}`` (``"dev"`` is
    always ``False`` now — the field is kept for API shape).
    """
    seed_hex = (explicit or os.environ.get("GOV_ANCHOR_KEY", "")).strip()
    if seed_hex:
        try:
            seed = bytes.fromhex(seed_hex)
        except ValueError:
            raise NoAnchorKeyError("GOV_ANCHOR_KEY is not hex")
        if len(seed) != 32:
            raise NoAnchorKeyError("GOV_ANCHOR_KEY must be 32 bytes")
        pub = _ab.anchor_pubkey(seed)
        return {"seed": seed, "key_id": _ab.anchor_key_id(pub),
                "pubkey_hex": pub.hex(), "dev": False}
    key_file = os.environ.get("GOV_ANCHOR_KEY_FILE", "").strip()
    if key_file:
        # Wave-91 (G1): uniform fail-closed permission posture. The
        # permission gate runs BEFORE any key bytes are read; a
        # group/world-accessible file is refused, not warned about.
        # Migration note: chmod 600 the file. The refusal surfaces as
        # NoAnchorKeyError so anchoring stays disabled and the chain
        # continues operator-attested-only — never silently unanchored.
        from .keyfiles import require_private_key_file
        try:
            require_private_key_file(key_file)
        except (FileNotFoundError, PermissionError) as e:
            raise NoAnchorKeyError(
                "refusing GOV_ANCHOR_KEY_FILE %s: %s" % (key_file, e))
        try:
            seed_hex = Path(key_file).read_text(
                encoding="utf-8").strip()
            seed = bytes.fromhex(seed_hex)
        except (OSError, ValueError) as e:
            raise NoAnchorKeyError(
                "cannot read GOV_ANCHOR_KEY_FILE: %s" % (e,))
        if len(seed) != 32:
            raise NoAnchorKeyError("anchor key file must hold 32 bytes hex")
        pub = _ab.anchor_pubkey(seed)
        return {"seed": seed, "key_id": _ab.anchor_key_id(pub),
                "pubkey_hex": pub.hex(), "dev": False}
    # Wave-81: the dev double opt-in branch is DELETED. Unconfigured
    # anchoring refuses loudly in every mode. The mode is still resolved
    # (and validated) for the refusal message.
    from . import keyprovider as _kp
    mode = _kp.resolve_deployment_mode()
    raise NoAnchorKeyError(
        # Wave-219 unsafe-path registry: gov.anchorer.unconfigured_anchoring_disabled
        "no anchor-signing key configured (GOV_ANCHOR_KEY / "
        "GOV_ANCHOR_KEY_FILE); refusing to anchor in %r mode "
        "[gov.anchorer.unconfigured_anchoring_disabled]" % (mode,))


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


def _parse_wall(value):
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (TypeError, ValueError):
        return None


class Anchorer:
    """Executor-side async anchorer. Owns epochs; never blocks append.

    ``log``: the :class:`gov.log.ActionLog`. ``backend``: an
    :class:`AnchorBackend`. ``anchor_key``: ``resolve_anchor_key()`` dict
    (resolved automatically when None -- raises :class:`NoAnchorKeyError`
    loudly instead of anchoring under nothing). If the backend is a
    :class:`RekorBackend` without a seed, the resolved seed is injected.

    ``maybe_anchor()`` is the ONLY drive point: call it from run close or
    a timer tick -- never from the enforcement path, never from inside the
    sandbox. It closes the epoch and enqueues; a daemon worker does all
    backend I/O. The enqueue goes through a BOUNDED, loss-accounted
    fan-out queue (:mod:`gov.evidence_fanout`): on full the job is
    refused and counted (``maybe_anchor`` returns ``"dropped"``), an
    unanchored record is chained, and :meth:`recover` can requeue it --
    drops are counted, never silently lost. ``close()`` anchors on close
    per the policy and drains.
    """

    def __init__(self, log, backend, policy=None, anchor_key=None,
                 clock=None, warn=None, max_attempts=5, backoff_base=2.0,
                 backoff_cap=60.0, fanout_maxsize=1024,
                 fanout_policy=_fanout.FanoutQueue.COUNTED_DROP):
        self._log = log
        self._backend = backend
        self._policy = policy or AnchorPolicy()
        key = anchor_key or resolve_anchor_key()
        self._seed = key["seed"]
        self._key_id = key["key_id"]
        self._pubkey_hex = key["pubkey_hex"]
        self._dev_key = bool(key.get("dev"))
        if self._dev_key:
            sys.stderr.write(
                "WARNING: Anchorer running under a dev anchor key -- "
                "receipts are format-only, not evidence.\n")
        # RekorBackend needs the seed + pubkey for the hashedrekord digest
        # signature; inject the resolved key material when it has none.
        # (Verification-only uses never need them.)
        if isinstance(backend, _ab.RekorBackend):
            if backend._anchor_seed is None:
                backend._anchor_seed = bytes(self._seed)
            if backend._anchor_pubkey is None:
                backend._anchor_pubkey = bytes.fromhex(self._pubkey_hex)
        self._clock = clock or _utcnow_iso
        self._warn = warn or (lambda m: sys.stderr.write(
            "anchorer: %s\n" % (m,)))
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base
        self._backoff_cap = backoff_cap
        # Loss-accounted fan-out (wave-273): the anchor job queue is
        # BOUNDED and every refused item is counted, never silently
        # lost. Dropped anchor jobs are recoverable: the durable
        # evidence (chained log + checkpoint) already exists before
        # enqueue, and _on_fanout_drop chains an unanchored record so
        # recover() can requeue them. counted-drop is the default
        # because maybe_anchor must never raise into the enforcement
        # path; fail-closed is the operator's explicit opt-in.
        self._queue = _fanout.FanoutQueue(
            maxsize=fanout_maxsize, policy=fanout_policy,
            on_drop=self._on_fanout_drop)
        self._outcome_lock = threading.Lock()
        self._completed = 0
        self._failed = 0
        self._retried = 0
        self._abandoned = 0
        self._closed = False
        self._timers = []
        # Idempotence guard: the highest end_seq ever closed by this
        # instance. close_epoch() is in-memory only, and refresh() can
        # reset _epoch_id to the tail's stamp -- without this guard a
        # second maybe_anchor before the worker's receipt lands would
        # re-close (and re-anchor) the same epoch.
        self._last_closed_end = 0
        self._last_anchor = self._scan_last_anchor()
        self._thread = threading.Thread(
            target=self._worker, daemon=True, name="gov-anchorer")
        self._thread.start()

    # -- state ---------------------------------------------------------
    def _scan_last_anchor(self):
        """Newest anchored hash from chained receipts (GENESIS if none)."""
        last = _ab.GENESIS_ANCHOR
        newest = -1
        try:
            for line in Path(self._log.path).read_text(
                    encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if isinstance(e, dict) and e.get("event") == \
                        ANCHOR_RECEIPT_EVENT:
                    cs = e.get("checkpoint_seq")
                    if isinstance(cs, int) and cs > newest:
                        newest = cs
                        last = e.get("anchor_hash", last)
        except OSError:
            pass
        return last

    def _entry_at(self, seq):
        for line in Path(self._log.path).read_text(
                encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if isinstance(e, dict) and e.get("seq") == seq:
                return e
        raise AnchorerError("no log entry at seq %r" % (seq,))

    def _checkpoint_at(self, seq):
        cp_path = Path(self._log.checkpoint_path)
        try:
            lines = cp_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            raise AnchorerError("checkpoint sidecar missing")
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                cp = json.loads(line)
            except ValueError:
                continue
            if isinstance(cp, dict) and cp.get("seq") == seq:
                return cp
        raise AnchorerError("no checkpoint at seq %r" % (seq,))

    @staticmethod
    def _backend_log_id(backend):
        lid = _witness_log_id(backend)
        # Custom backends: fall back to the type name (the auditor cannot
        # check the witness binding for these -- see audit_anchors).
        return lid if lid is not None else type(backend).__name__

    # -- drive points --------------------------------------------------
    def maybe_anchor(self, force=False):
        """Close the epoch per the policy and enqueue the anchor job.

        Returns "queued" | "dropped" | "not-due" | "empty" | "closed" |
        "already-closed". Under the opt-in fail-closed fan-out policy a
        full queue RAISES FanoutFullError instead of returning "dropped".
        Performs no network I/O and never blocks the enforcement path: the
        checkpoint it anchors already exists (every append writes one).
        """
        if self._closed:
            return "closed"
        # The worker thread appends receipts through this same log object,
        # but another process may also have appended: refresh the tail so
        # the epoch math below sees the true end of the chain.
        self._log.refresh()
        epoch_id = self._log.epoch_id
        start_seq = int(epoch_id[1:])
        tail = self._log.tail_seq
        if tail < start_seq:
            return "empty"
        if tail <= self._last_closed_end:
            # This epoch was already closed by this instance (the receipt
            # may still be in flight): never double-close / double-anchor.
            return "already-closed"
        records = tail - start_seq + 1
        due = force or records >= self._policy.records_per_epoch
        if not due and self._policy.seconds_per_epoch is not None:
            try:
                start_wall = _parse_wall(
                    self._entry_at(start_seq).get("ts"))
            except AnchorerError:
                start_wall = None
            if start_wall is not None:
                age = (datetime.now(timezone.utc) - start_wall
                       ).total_seconds()
                due = age >= self._policy.seconds_per_epoch
        if not due:
            return "not-due"
        closed_id, s, e = self._log.close_epoch()
        self._last_closed_end = e
        # "dropped" is an honest signal: the epoch's evidence is durable
        # (chained log + checkpoint) and the drop is counted in
        # fanout_stats() with an unanchored record chained, so the
        # caller can decide (retry later, run recover()).
        return self._enqueue_job(closed_id, s, e, self._clock())

    def _enqueue_job(self, epoch_id, start_seq, end_seq, close_wall,
                     attempts=0, unanchored_recorded=False, priority=False):
        """Enqueue an anchor job. Returns "queued" or "dropped".

        A dropped job is counted in the fan-out stats and its epoch is
        chained as unanchored (via the queue's on_drop hook) so
        recover() can requeue it -- a drop is never silent and never a
        loss of the underlying evidence.

        ``priority=True`` bypasses the bound (never drops): reserved for
        recover(), where requeueing an already-unanchored epoch must be
        reliable -- a bounded requeue could drop it again and defeat the
        healing. Never set on the hot producer path.
        """
        job = {
            "epoch_id": epoch_id, "start_seq": start_seq,
            "end_seq": end_seq, "close_wall": close_wall,
            "attempts": attempts,
            "unanchored_recorded": unanchored_recorded,
        }
        if priority:
            verdict = self._queue.submit_priority(job, reason="recover")
        else:
            verdict = self._queue.submit(job, reason="anchor-job")
        return "queued" if verdict == "accepted" else "dropped"

    def _on_fanout_drop(self, job, reason):
        """Chain an unanchored record for a queue-full dropped job.

        Best-effort: the durable unanchored record is what makes the
        drop recoverable. Exceptions are swallowed with a warning (the
        hook must never break the producer).
        """
        try:
            self._log.append({
                "event": ANCHOR_UNANCHORED_EVENT,
                "anchored_epoch_id": job.get("epoch_id"),
                "checkpoint_seq": job.get("end_seq"),
                "reason": "fanout-full",
                "detail": "anchor job refused by the bounded fan-out "
                          "queue (%s); recover() can requeue" % (reason,),
                "grade": GRADE_OPERATOR_ONLY,
            })
        except Exception as exc:
            self._warn("could not chain the fanout-drop record: %r"
                       % (exc,))

    def close(self, timeout=30):
        """Anchor on close per the policy, then drain the worker.

        Bounded: in-flight retries are abandoned after ``timeout`` (their
        unanchored records are already chained -- durable honest state;
        :meth:`recover` requeues them later).
        """
        if self._policy.anchor_on_close and not self._closed:
            try:
                self.maybe_anchor(force=True)
            except Exception as exc:  # anchoring must never break run close
                self._warn("anchor-on-close failed: %r" % (exc,))
        self._closed = True
        for t in self._timers:
            t.cancel()
        # Control-channel enqueue: the stop sentinel bypasses the
        # fan-out bound so close() can never deadlock on a full queue.
        self._queue.submit_control(None)
        self._thread.join(timeout=timeout)

    def recover(self):
        """Requeue epochs that have an unanchored record but no receipt.

        Explicit operator action (e.g. after a restart with a recovered
        backend). Requeues bypass the fan-out bound (priority channel):
        an epoch that already has a chained unanchored record must be
        requeued reliably -- a bounded requeue could drop it again and
        defeat the healing. Returns the number of requeued epochs.
        """
        unanchored = {}
        receipted = set()
        try:
            lines = Path(self._log.path).read_text(
                encoding="utf-8").splitlines()
        except OSError:
            return 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if not isinstance(e, dict):
                continue
            cs = e.get("checkpoint_seq")
            if e.get("event") == ANCHOR_UNANCHORED_EVENT \
                    and isinstance(cs, int):
                # Closed-epoch id (legacy records used reserved epoch_id).
                unanchored[cs] = (e.get("anchored_epoch_id")
                                  or e.get("epoch_id"))
            elif e.get("event") == ANCHOR_RECEIPT_EVENT \
                    and isinstance(cs, int):
                receipted.add(cs)
        n = 0
        for cs in sorted(unanchored):
            if cs in receipted:
                continue
            epoch_id = unanchored[cs]
            if not _log._valid_epoch_id(epoch_id):
                continue
            self._enqueue_job(epoch_id, int(epoch_id[1:]), cs,
                              self._clock(), priority=True)
            n += 1
        return n

    def _note_outcome(self, which):
        """Bump a worker-side outcome counter (completed/failed/retried/
        abandoned) under the outcome lock."""
        with self._outcome_lock:
            setattr(self, "_" + which, getattr(self, "_" + which) + 1)

    # -- worker --------------------------------------------------------
    def _worker(self):
        while True:
            job = self._queue.get()
            try:
                if job is None:
                    return
                self._do_anchor(job)
            except Exception as exc:
                self._note_outcome("failed")
                try:
                    self._on_failure(job, exc)
                except Exception as exc2:
                    self._warn(
                        "anchor failure handler failed: %r" % (exc2,))
            else:
                self._note_outcome("completed")
            finally:
                self._queue.task_done()

    def _do_anchor(self, job):
        epoch_id = job["epoch_id"]
        start_seq, end_seq = job["start_seq"], job["end_seq"]
        cp = self._checkpoint_at(end_seq)
        head_hash = cp["hash"]
        entry_start = self._entry_at(start_seq)
        statement = _ab.build_statement(
            epoch_id=epoch_id, seq=end_seq, start_seq=start_seq,
            head_hash=head_hash, merkle_root=cp.get("merkle_root"),
            epoch_start_wall=entry_start.get("ts"),
            epoch_close_wall=job["close_wall"],
            key_id=self._key_id, pubkey_hex=self._pubkey_hex,
            prev_anchor=self._last_anchor,
            log_id=self._backend_log_id(self._backend))
        signed = _ab.sign_statement(statement, self._seed)
        # Fail fast: never anchor a statement whose own signature does
        # not verify (local bug, not witness-down -- non-retryable).
        ok, reason = _ab.verify_statement_sig(signed)
        if not ok:
            raise AnchorerError(
                "own statement signature invalid: %s" % (reason,))
        anchor_hash = _ab.statement_hash(signed)
        # Privacy pin: the backend receives ONLY the anchor hash. The
        # signed statement (epoch metadata, wall times) stays local,
        # chained in the receipt record below.
        # Wave-199: the anchor hash crosses the backend seam as a
        # DigestRef -- a tag is unrepresentable as one.
        anchor_ref = DigestRef.from_hex(anchor_hash)
        receipt = self._backend.submit(anchor_ref)
        ok, reason = self._backend.verify_receipt(
            receipt, anchor_hash=anchor_ref)
        if not ok:
            raise AnchorerError(
                "backend returned an unverifiable receipt: %s" % (reason,))
        # NOTE: "epoch_id" is RESERVED chain metadata (the open epoch at
        # append time, stamped by ActionLog.append). The CLOSED epoch this
        # receipt anchors travels in "anchored_epoch_id".
        self._log.append({
            "event": ANCHOR_RECEIPT_EVENT,
            "anchored_epoch_id": epoch_id,
            "checkpoint_seq": end_seq,
            "head_hash": head_hash,
            "anchor_hash": anchor_hash,
            "statement": signed,
            "receipt": receipt,
            "backend": receipt.get("backend"),
            "grade": GRADE_ANCHORED,
        })
        self._last_anchor = anchor_hash

    def _on_failure(self, job, exc):
        attempts = job["attempts"] + 1
        retryable = isinstance(exc, _ab.WitnessDownError)
        self._warn("anchor of epoch %s failed (attempt %d): %s: %s" % (
            job["epoch_id"], attempts, type(exc).__name__, exc))
        # Loudly mark the epoch unanchored (chained record) on FIRST
        # failure -- the ledger shows the honest unanchored->anchored
        # sequence when a retry later succeeds.
        if not job["unanchored_recorded"]:
            try:
                self._log.append({
                    "event": ANCHOR_UNANCHORED_EVENT,
                    # "epoch_id" is reserved (open epoch at append time);
                    # the closed epoch travels in "anchored_epoch_id".
                    "anchored_epoch_id": job["epoch_id"],
                    "checkpoint_seq": job["end_seq"],
                    "reason": ("backend-down" if retryable
                               else "anchor-failed"),
                    "detail": "%s: %s" % (type(exc).__name__, exc),
                    "grade": GRADE_OPERATOR_ONLY,
                })
            except Exception as exc2:
                self._warn("could not chain the unanchored record: %r"
                           % (exc2,))
            job["unanchored_recorded"] = True
        if retryable and attempts < self._max_attempts and not self._closed:
            delay = min(self._backoff_base * (2 ** (attempts - 1)),
                        self._backoff_cap)
            t = threading.Timer(delay, self._requeue, args=(job, attempts))
            t.daemon = True
            self._timers.append(t)
            t.start()
            self._note_outcome("retried")
        elif retryable:
            self._note_outcome("abandoned")
            self._warn("epoch %s: retries exhausted; grade stays %s until "
                       "an operator runs recover()" % (
                           job["epoch_id"], GRADE_OPERATOR_ONLY))

    def _requeue(self, job, attempts):
        if self._closed:
            return
        job["attempts"] = attempts
        # Retries also pass through the bounded queue: a refused retry
        # is counted (reason "retry") and its epoch already has a
        # chained unanchored record, so recover() can requeue it later.
        self._queue.submit(job, reason="retry")

    def fanout_stats(self):
        """Operator-visible loss accounting for the anchor fan-out.

        Submit-side counters come from the bounded queue; worker-side
        outcome counters from this Anchorer. All counters are monotonic
        within the process lifetime; the durable loss record is the
        chained unanchored entries, which recover() reads.
        """
        st = self._queue.stats()
        with self._outcome_lock:
            st["completed"] = self._completed
            st["failed"] = self._failed
            st["retried"] = self._retried
            st["abandoned"] = self._abandoned
        return st


def _read_entries(log_path):
    entries = []
    for line in Path(log_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        entries.append(json.loads(line))
    return entries


def audit_anchors(log_path, backend, *, key=None, key_epoch=None,
                  keyring=None, skew_seconds=300):
    """Auditor walk: checkpoint -> receipt -> witness, per epoch.

    Checks per closed epoch: (i) internal chain integrity (needs the HMAC
    key -- without it, marked ``needs-key``, never claimed); (ii) receipt
    inclusion proofs against the witness; (iii) anchored head == chain head
    at the checkpoint; (iv) witness time within the claimed epoch window.

    ``key``/``key_epoch``: single-key chain. ``keyring``: a
    ``gov.keys.KeyRing`` for rotation-spanning logs (per-entry labels).
    ``backend``: one :class:`AnchorBackend`, or a callable
    ``fn(receipt) -> AnchorBackend`` for logs with mixed backends
    (see :func:`backend_for_receipt`).
    Returns a report dict with per-epoch ``grade`` (``anchored`` vs
    ``operator-attested-only``) and check details.
    """
    report = {"generated_at": _utcnow_iso(), "chain_ok": False,
              "chain_error": None, "epochs": [], "open_epoch": None}
    try:
        entries = _read_entries(log_path)
    except (OSError, ValueError) as e:
        report["chain_error"] = "cannot read log: %s" % (e,)
        return report

    # (i) internal chain integrity + per-seq heads.
    heads = {}
    chain_ok, chain_error = True, None
    resolved = _resolve_audit_key(key, key_epoch, keyring)
    if resolved is None:
        chain_ok, chain_error = False, "needs-key"
    else:
        prev = _log.GENESIS
        for e in entries:
            if not isinstance(e, dict) or e.get("seq") != len(heads) + 1:
                chain_ok, chain_error = False, "sequence gap/corrupt entry"
                break
            k, kep = resolved(e)
            if k is None:
                chain_ok, chain_error = False, "needs-key"
                break
            mac = _log._compute_mac(k, kep, prev, _log._canonical(e))
            import hmac as _hmac
            if not _hmac.compare_digest(mac, e.get("hash", "")):
                chain_ok, chain_error = False, \
                    "chain link broken at seq %s" % e.get("seq")
                break
            prev = mac
            heads[e["seq"]] = mac
    report["chain_ok"] = chain_ok
    report["chain_error"] = chain_error

    # Group anchor records by checkpoint seq.
    receipts, unanchored = {}, {}
    for e in entries:
        if not isinstance(e, dict):
            continue
        cs = e.get("checkpoint_seq")
        if not isinstance(cs, int):
            continue
        if e.get("event") == ANCHOR_RECEIPT_EVENT:
            receipts[cs] = e
        elif e.get("event") == ANCHOR_UNANCHORED_EVENT:
            unanchored[cs] = e
    closed = sorted(set(receipts) | set(unanchored))

    # Statement-chain expectation: each sig-valid statement must chain
    # from the previous sig-valid statement's anchor (GENESIS first).
    expect_prev = _ab.GENESIS_ANCHOR
    for cs in closed:
        ep = {"checkpoint_seq": cs, "grade": GRADE_OPERATOR_ONLY,
              "checks": {}, "reasons": []}
        rec = receipts.get(cs)
        if rec is None:
            ep["reasons"].append("no anchor receipt chained")
            ep["epoch_id"] = ((unanchored[cs].get("anchored_epoch_id")
                               or unanchored[cs].get("epoch_id"))
                              if cs in unanchored else None)
            report["epochs"].append(ep)
            continue
        stmt = rec.get("statement", {})
        # "anchored_epoch_id" is the closed epoch; reserved "epoch_id" is
        # the open epoch at append time (legacy records lack the former).
        ep["epoch_id"] = (rec.get("anchored_epoch_id")
                          or rec.get("epoch_id"))
        ep["backend"] = rec.get("backend")
        ep["anchor_hash"] = rec.get("anchor_hash")
        # (iii) anchored head == chain head at the checkpoint.
        if not chain_ok:
            ep["checks"]["head_match"] = "needs-key"
            ep["reasons"].append("chain not verified (%s)" % chain_error)
        elif heads.get(cs) != stmt.get("head_hash"):
            ep["checks"]["head_match"] = False
            ep["reasons"].append(
                "anchored head != chain head at seq %d" % cs)
        else:
            ep["checks"]["head_match"] = True
        # (viii) the record's anchor_hash really is the statement's hash
        # (binds the receipt to the exact signed bytes).
        try:
            recomputed = _ab.statement_hash(stmt)
        except (ValueError, TypeError, KeyError):
            recomputed = None
        if recomputed is None or recomputed != rec.get("anchor_hash"):
            ep["checks"]["anchor_hash_bind"] = False
            ep["reasons"].append(
                "record anchor_hash != hash of the stored statement")
        else:
            ep["checks"]["anchor_hash_bind"] = True
        # Statement signature (non-repudiation layer).
        ok, reason = _ab.verify_statement_sig(stmt)
        ep["checks"]["statement_sig"] = ok
        if not ok:
            ep["reasons"].append("statement sig: %s" % reason)
        # (vii) statement-chain continuity (only over sig-valid
        # statements; a break means a statement outside the true anchor
        # history, e.g. a forked/alternate branch).
        if ok:
            if stmt.get("prev_anchor") != expect_prev:
                ep["checks"]["statement_chain"] = False
                ep["reasons"].append(
                    "statement prev_anchor breaks the anchor chain")
            else:
                ep["checks"]["statement_chain"] = True
            expect_prev = rec.get("anchor_hash")
        # (ii) receipt inclusion proof against the witness.
        be = backend(rec.get("receipt", {})) if callable(backend) \
            else backend
        ok, reason = be.verify_receipt(
            rec.get("receipt", {}), anchor_hash=rec.get("anchor_hash"))
        ep["checks"]["receipt"] = ok
        if not ok:
            ep["reasons"].append("receipt: %s" % reason)
        # (vi) the statement is addressed to the witness the receipt
        # claims (binds the signed statement to the witness identity).
        expected_log = _witness_log_id(
            be, (rec.get("receipt") or {}).get("path"))
        if expected_log is None:
            ep["reasons"].append(
                "witness binding not checkable for this backend")
        elif stmt.get("log_id") != expected_log:
            ep["checks"]["witness_binding"] = False
            ep["reasons"].append(
                "statement not addressed to the receipt's witness")
        else:
            ep["checks"]["witness_binding"] = True
        # (iv) witness time within the claimed epoch window.
        wt = _receipt_witness_time(rec.get("receipt", {}))
        start_w = _parse_wall(stmt.get("epoch_start_wall"))
        close_w = _parse_wall(stmt.get("epoch_close_wall"))
        if wt is None or start_w is None or close_w is None:
            ep["checks"]["witness_time_window"] = False
            ep["reasons"].append("witness/epoch wall times unparseable")
        else:
            lo = (start_w.timestamp() - skew_seconds)
            hi = (close_w.timestamp() + skew_seconds)
            in_window = lo <= wt.timestamp() <= hi
            ep["checks"]["witness_time_window"] = in_window
            if not in_window:
                ep["reasons"].append(
                    "witness time outside the epoch window")
        ep["witness_time"] = (wt.isoformat() if wt is not None else None)
        if not ep["reasons"] and all(
                v is True for v in ep["checks"].values()):
            ep["grade"] = GRADE_ANCHORED
        report["epochs"].append(ep)

    # The open epoch: the soft window (the residual, stated numerically).
    last_close = closed[-1] if closed else 0
    tail = len(entries)
    report["open_epoch"] = {
        "epoch_id": "e%08d" % (last_close + 1),
        "start_seq": last_close + 1,
        "tail_seq": tail,
        "unanchored_records": max(0, tail - last_close),
        "grade": "open (soft window)",
    }
    return report


def _resolve_audit_key(key, key_epoch, keyring):
    """Return a per-entry ``fn(entry) -> (key_bytes, epoch_label)`` or None."""
    if keyring is not None:
        def via_ring(entry):
            label = entry.get("key_epoch")
            try:
                mat = keyring.get(label)
            except Exception:
                return None, None
            if mat is None or getattr(mat, "key", None) is None:
                return None, None
            return bytes(mat.key), label
        return via_ring
    if key is not None:
        kep = key_epoch
        if kep is None:
            try:
                _, kep = _log._active_key()
            except Exception:
                return None
        return lambda entry: (bytes(key), kep)
    try:
        k, kep = _log._active_key()
    except Exception:
        return None
    return lambda entry: (bytes(k), kep)


def backend_for_receipt(receipt):
    """Instantiate the verification-side backend named by a receipt.

    Verification needs no anchor seed: FakeWitness verifies self-contained
    receipts, RekorBackend verifies against the pinned log id, and
    LocalAnchorLog replays its file. Unknown backend tags raise
    :class:`AnchorerError` (fail-closed: never verify against a backend
    the receipt does not name).
    """
    tag = (receipt or {}).get("backend")
    if tag == "fake-witness":
        return _ab.FakeWitness()
    if tag == "rekor-v1":
        return _ab.RekorBackend()
    if tag == "local-anchor-log":
        path = (receipt or {}).get("path")
        if not path:
            raise AnchorerError(
                "local-anchor-log receipt has no path")
        return _ab.LocalAnchorLog(path)
    raise AnchorerError("unknown anchor backend %r" % (tag,))


def _witness_log_id(backend, path=None):
    """Witness identity bound into anchor statements.

    Rekor: the pinned log id. FakeWitness: its backend id. LocalAnchorLog:
    a hash of the log path (the auditor reconstructs it from the
    receipt's ``path``). Unknown backends: None (binding not checkable).
    """
    if isinstance(backend, _ab.RekorBackend):
        return backend.log_id
    if isinstance(backend, _ab.FakeWitness):
        return backend.backend_id
    if isinstance(backend, _ab.LocalAnchorLog):
        p = path if path is not None else str(backend.path)
        return "local-anchor-log:" + hashlib.sha256(
            p.encode("utf-8")).hexdigest()[:32]
    return None


def _receipt_witness_time(receipt):
    """Witness time as an aware datetime, or None."""
    if not isinstance(receipt, dict):
        return None
    wt = receipt.get("witness_time")
    if isinstance(wt, str):
        return _parse_wall(wt)
    it = receipt.get("integrated_time")
    if isinstance(it, int) and it > 0:
        return datetime.fromtimestamp(it, tz=timezone.utc)
    return None


def anchor_summary(report, policy=None):
    """Render-ready summary of :func:`audit_anchors` for make_report."""
    epochs = []
    for ep in report.get("epochs", []):
        epochs.append({
            "epoch_id": ep.get("epoch_id"),
            "seq": ep.get("checkpoint_seq"),
            "grade": ep.get("grade"),
            "backend": ep.get("backend"),
            "witness_time": ep.get("witness_time"),
            "reasons": ep.get("reasons", []),
        })
    last = None
    for ep in reversed(epochs):
        if ep["grade"] == GRADE_ANCHORED:
            last = ep
            break
    return {
        "guarantee": GUARANTEE,
        "cadence": policy.describe() if policy is not None else None,
        "epochs": epochs,
        "last_anchor": last,
        "open_epoch": report.get("open_epoch"),
        "chain_ok": report.get("chain_ok"),
    }
