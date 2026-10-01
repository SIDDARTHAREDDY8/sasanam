"""Loss-accounted evidence fan-out queues (wave-273).

Evidence leaves the enforcement path asynchronously in exactly one
place today: :class:`gov.anchorer.Anchorer` hands anchor jobs to a daemon
worker. Before this module that handoff was an UNBOUNDED
``queue.Queue``: a producer flood (or a wedged backend with retries)
grew it without limit, and jobs that died -- non-retryable backend
failure, retry exhaustion, close-time abandonment -- left only a stderr
warning. There was no operator-visible loss accounting: dropped evidence
was silently lost as far as any monitor could tell.

This module provides the primitive: a BOUNDED queue with a
``queueLost``-style counter (Tetragon pattern, reimplemented
stdlib-only; no Tetragon code). Dropped items are COUNTED, never
silently lost.

Backpressure contract (per channel):

- ``policy="counted-drop"`` (default): a full queue refuses the item and
  counts it (``dropped`` + ``dropped_by_reason`` + ``last_drop_wall``).
  Use for evidence whose durable source already exists elsewhere: the
  anchor pipeline is the example -- the chained audit log and the
  checkpoint exist BEFORE the anchor job is enqueued, so a dropped job
  is recoverable (``Anchorer.recover()``) and the drop is honest, not a
  loss. Telemetry-style evidence (drift events, scan reports) is the
  other counted-drop channel.
- ``policy="fail-closed"``: a full queue RAISES
  :class:`FanoutFullError`. Use for critical evidence with no durable
  source -- but NEVER on a path that must not block: anchoring runs off
  the enforcement path precisely because ``maybe_anchor`` must never
  raise into a run close, so counted-drop is the anchor default and
  fail-closed is the operator's explicit opt-in for stricter pipelines.

Honest limits:

- The counter is in-memory. A process crash loses the counter -- the
  durable record is whatever the ``on_drop`` hook chained (the Anchorer
  chains an unanchored record per dropped job, which is what
  ``recover()`` reads). Counters are an operator metric, not evidence.
- Bounded means the OLDEST queued items are never evicted to make room:
  on full the NEW item is refused (drop-tail). Drop-tail keeps ordering
  and keeps the refusal decision local to the producer.
- The control channel (``submit_control``) bypasses the bound for the
  stop sentinel only: a single sentinel cannot cause unbounded growth,
  and a full queue must never deadlock ``close()``.
"""

import collections
import queue as _queue_mod
import threading
import time


class FanoutFullError(Exception):
    """Raised by a fail-closed :class:`FanoutQueue` when the queue is
    full. The item was NOT accepted."""


_DROP_EVENT_KEEP = 64


def _wall_now():
    return time.time()


class FanoutQueue(object):
    """A bounded, loss-accounted FIFO for evidence fan-out.

    ``maxsize``: maximum queued items (drop-tail on full). Must be >= 1.
    ``policy``: ``"counted-drop"`` (refuse + count) or ``"fail-closed"``
    (raise :class:`FanoutFullError`).
    ``on_drop``: optional callable ``(item, reason)`` invoked for every
    dropped item. Invoked OUTSIDE the queue lock; exceptions raised by
    the hook are swallowed (a hook must never break the producer).
    """

    COUNTED_DROP = "counted-drop"
    FAIL_CLOSED = "fail-closed"

    def __init__(self, maxsize=1024, policy=COUNTED_DROP, on_drop=None):
        if not isinstance(maxsize, int) or isinstance(maxsize, bool) \
                or maxsize < 1:
            raise ValueError("maxsize must be a positive int")
        if policy not in (self.COUNTED_DROP, self.FAIL_CLOSED):
            raise ValueError(
                "policy must be %r or %r" % (self.COUNTED_DROP,
                                             self.FAIL_CLOSED))
        if on_drop is not None and not callable(on_drop):
            raise ValueError("on_drop must be callable or None")
        self._maxsize = maxsize
        self._policy = policy
        self._on_drop = on_drop
        self._q = collections.deque()
        self._cond = threading.Condition()
        self._unfinished = 0
        self._accepted = 0
        self._dropped = 0
        self._dropped_by_reason = collections.Counter()
        self._high_water = 0
        self._last_drop_wall = None
        self._drop_events = collections.deque(maxlen=_DROP_EVENT_KEEP)
        self._drop_seq = 0

    # -- producer side -------------------------------------------------

    def _append_locked(self, item, count_accepted):
        """Append under the condition lock. Caller must hold ``_cond``."""
        self._q.append(item)
        if count_accepted:
            self._accepted += 1
        self._unfinished += 1
        if len(self._q) > self._high_water:
            self._high_water = len(self._q)
        self._cond.notify()

    def submit(self, item, reason="enqueue"):
        """Enqueue ``item``. Returns ``"accepted"`` or ``"dropped"``.

        Under ``fail-closed`` raises :class:`FanoutFullError` instead of
        returning ``"dropped"``.
        """
        hook = None
        with self._cond:
            if len(self._q) >= self._maxsize:
                if self._policy == self.FAIL_CLOSED:
                    raise FanoutFullError(
                        "fan-out queue full (maxsize=%d)" % self._maxsize)
                self._dropped += 1
                self._dropped_by_reason[str(reason)] += 1
                self._last_drop_wall = _wall_now()
                self._drop_seq += 1
                self._drop_events.append({
                    "seq": self._drop_seq,
                    "wall": self._last_drop_wall,
                    "reason": str(reason),
                })
                hook = self._on_drop
            else:
                self._append_locked(item, count_accepted=True)
                return "accepted"
        if hook is not None:
            try:
                hook(item, reason)
            except Exception:
                pass
        return "dropped"

    def submit_control(self, item):
        """Enqueue a control item, bypassing the bound.

        Reserved for the stop sentinel: ``close()`` must never deadlock
        on a full queue, and one control item cannot cause unbounded
        growth. Control items do not count toward ``accepted``.
        """
        with self._cond:
            self._append_locked(item, count_accepted=False)

    def submit_priority(self, item, reason="recover"):
        """Enqueue a job bypassing the bound. NEVER drops.

        Reserved for operator-initiated healing (``Anchorer.recover()``):
        requeueing an epoch that already has a chained unanchored record
        must be reliable -- routing it through the bounded ``submit``
        could drop it again, defeating the recovery. Counts toward
        ``accepted`` (it is a real job, unlike the sentinel). Never use
        on the hot producer path: that would defeat backpressure.
        """
        with self._cond:
            self._append_locked(item, count_accepted=True)
        return "accepted"

    # -- consumer side -------------------------------------------------

    def get(self, block=True, timeout=None):
        """Remove and return an item. Mirrors ``queue.Queue.get``."""
        with self._cond:
            if not block:
                if not self._q:
                    raise _queue_mod.Empty
            else:
                end = None if timeout is None else _wall_now() + timeout
                while not self._q:
                    remaining = None if end is None else end - _wall_now()
                    if remaining is not None and remaining <= 0:
                        raise _queue_mod.Empty
                    self._cond.wait(remaining)
            return self._q.popleft()

    def task_done(self):
        """Mirror ``queue.Queue.task_done``."""
        with self._cond:
            if self._unfinished <= 0:
                raise ValueError("task_done() called too many times")
            self._unfinished -= 1
            if self._unfinished == 0:
                self._cond.notify_all()

    def join(self):
        """Mirror ``queue.Queue.join``."""
        with self._cond:
            while self._unfinished > 0:
                self._cond.wait()

    def qsize(self):
        with self._cond:
            return len(self._q)

    @property
    def maxsize(self):
        return self._maxsize

    @property
    def policy(self):
        return self._policy

    # -- operator surface ----------------------------------------------

    def stats(self):
        """Operator-visible loss accounting. Counters are monotonic
        within the process lifetime."""
        with self._cond:
            return {
                "maxsize": self._maxsize,
                "policy": self._policy,
                "depth": len(self._q),
                "accepted": self._accepted,
                "dropped": self._dropped,
                "dropped_by_reason": dict(self._dropped_by_reason),
                "high_water": self._high_water,
                "last_drop_wall": self._last_drop_wall,
                "recent_drop_events": list(self._drop_events),
            }
