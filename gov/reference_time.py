"""Per-cycle atomic reference time (the TUF refresh pattern).

TUF's refresh cycle samples the clock ONCE and checks every
role-metadata ``expires`` against that single reference time. The
reason is consistency, not convenience: if each expiry check samples
the clock independently, a clock that advances (or is tampered with)
mid-cycle can produce contradictory verdicts inside ONE cycle -- role
A judged fresh at t1, role B judged expired at t2, and the refresh
acts on a mixture of two different "nows".

This module reimplements that pattern with stdlib only. A cycle
owner samples once, then hands the SAME atomic reference to every
expiry check in the cycle. The shared currency is INT EPOCH
SECONDS -- every consumer below accepts an int-epoch callable, so
one clock serves all of them with no adapter lambdas:

    source = lambda: int(time.time())           # int-epoch currency
    clock = AtomicClock(source)                 # the cycle's reference
    clock.sample()                              # one sample for the cycle
    rsl.open_log(path, wire, clock)             # callable `now` (F275)
    br = BundleRefresher(root, fetch, cache, clock=clock)
    manifest = ReplayManifestBuilder(actor, now=clock)

(RSL accepts float epochs too, truncated to int seconds; the
refresher converts int/float epochs to aware UTC datetimes at its
seam.) replay_manifest performs NO expiry checks -- its ``now``
feeds only ``int(self._now())`` timestamps -- so the "replay
manifest ... against it" leg of the pattern means its timestamps
share the cycle's reference, not an expiry verdict.

Every component treats the clock as a plain callable; only the
owner decides when a new sample is taken. The honest limit is
stated once, here: an atomic reference kills INTRA-CYCLE skew.
It does not authenticate the clock -- wall-clock tampering
(a skewed or attacker-controlled source) is a deployment trust
assumption, not something this module can fix.
"""

from datetime import datetime, timezone


class AtomicClock(object):
    """A clock that is sampled once per cycle.

    ``source`` is a zero-arg callable returning the current time
    (epoch seconds, a datetime, whatever the consumer expects -- the
    VALUE TYPE is the source's; this wrapper only freezes it).
    ``sample()`` takes one sample; calling the instance returns the
    most recent sample. Sampling never happens implicitly: the
    caller owns the cycle boundary.

    Raises ValueError if called before the first sample -- an
    un-sampled clock is a programming error, not a clock reading.
    """

    def __init__(self, source):
        if not callable(source):
            raise TypeError("source must be callable")
        self._source = source
        self._sampled = False
        self._value = None

    def sample(self):
        """Take one sample from the source. Returns the sample."""
        self._value = self._source()
        self._sampled = True
        return self._value

    def __call__(self):
        if not self._sampled:
            raise ValueError("AtomicClock used before sample()")
        return self._value

    @property
    def value(self):
        """The current sample (None before the first sample)."""
        return self._value if self._sampled else None


def epoch_clock():
    """Source adapter: the Unix-epoch source behind ``time.time``."""
    from time import time
    return time()


def utc_clock():
    """Source adapter: the UTC-datetime source behind
    ``datetime.now(timezone.utc)``."""
    return datetime.now(timezone.utc)


def frozen(value):
    """Build an already-sampled AtomicClock fixed at ``value``.

    Convenience for deterministic tests: the clock is sampled at
    construction, so it can be passed as a plain callable without
    a separate ``sample()`` call.
    """
    clock = AtomicClock(lambda: value)
    clock.sample()
    return clock
