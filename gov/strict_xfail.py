"""Strict expected-failure (strict-xfail) discipline for red-team batteries.

STEAL (idea only, Apache-2.0, no upstream source vendored) from
sigstore/attestation-verify (read 2026-09-29, wave-216 prospecting):
**strict-xfail expected-failure lists** -- an unexpected *pass* also
fails CI. Batteries keep a declared list of probes expected to fail
(known residuals, documented gaps); the manifest enforces three rules:

1. A declared-xfail probe that still BREAKS is recorded as EXPECTED
   (the battery stays green, the residual stays documented).
2. A declared-xfail probe that now PASSES is an UNEXPECTED PASS and
   FAILS THE RUN LOUDLY -- a residual that healed without anyone
   noticing is either a healed product (file the good news, drop the
   xfail) or a weakened probe (fix the probe). Either way it must not
   pass silently.
3. An UNDECLARED break (or error) still fails the run.

API::

    manifest = XFailManifest("battery-name", xfail=("probe_a", "probe_b"))
    report = manifest.run([("probe_a", fn_a), ("probe_b", fn_b), ...])
    # fn returns one of "held" / "break" / "error"
    report.raise_if_bad()   # loud on unexpected pass / undeclared break
    print(report.summary())

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env.
"""

from __future__ import annotations

__all__ = [
    "XFailManifest",
    "XFailReport",
    "UnexpectedPassError",
    "UnexpectedBreakError",
    "ProbeError",
]

_VERDICTS = ("held", "break", "error")


class UnexpectedPassError(ValueError):
    """A declared-xfail probe PASSED: the residual healed (or the probe
    weakened). Fails the run loudly -- do not let it pass silently."""


class UnexpectedBreakError(ValueError):
    """An UNDECLARED probe broke (or errored). Genuine finding, file
    it -- the run fails regardless."""


class ProbeError(ValueError):
    """The manifest itself was misused (duplicate probe name, unknown
    verdict, undeclared xfail name never exercised)."""


class XFailReport(object):
    """The outcome of one manifest run. ``ok`` is True only when every
    probe HELD and every declared xfail stayed broken."""

    def __init__(self, battery, records):
        # records: list of (name, verdict, expected) with expected in
        # {"held", "expected-break", "unexpected-pass",
        #  "unexpected-break", "error"}.
        self.battery = battery
        self.records = list(records)

    @property
    def held(self):
        return [n for n, v, e in self.records if e == "held"]

    @property
    def expected_breaks(self):
        return [n for n, v, e in self.records if e == "expected-break"]

    @property
    def unexpected_passes(self):
        return [n for n, v, e in self.records if e == "unexpected-pass"]

    @property
    def unexpected_breaks(self):
        return [n for n, v, e in self.records
                if e in ("unexpected-break", "error")]

    @property
    def ok(self):
        return not self.unexpected_passes and not self.unexpected_breaks

    def raise_if_bad(self):
        if self.unexpected_passes:
            raise UnexpectedPassError(
                "battery %r: declared-xfail probe(s) PASSED unexpectedly: "
                "%s -- drop the xfail or fix the probe, do not pass "
                "silently" % (self.battery,
                               ", ".join(self.unexpected_passes)))
        if self.unexpected_breaks:
            raise UnexpectedBreakError(
                "battery %r: undeclared probe failure(s): %s -- file "
                "the finding" % (self.battery,
                                  ", ".join(self.unexpected_breaks)))

    def summary(self):
        lines = ["battery=%s held=%d expected-break=%d "
                 "unexpected-pass=%d unexpected-break=%d ok=%s"
                 % (self.battery, len(self.held),
                    len(self.expected_breaks),
                    len(self.unexpected_passes),
                    len(self.unexpected_breaks), self.ok)]
        for name, verdict, expected in self.records:
            lines.append("  %-40s %-5s %s" % (name, verdict, expected))
        return "\n".join(lines)


class XFailManifest(object):
    """A declared expected-failure list for one battery.

    ``xfail`` names probes expected to break (known residuals). An
    xfail name that is never exercised by ``run`` is itself a loud
    error -- a stale xfail list is a lie about the battery's coverage.
    """

    def __init__(self, battery, xfail=()):
        if not isinstance(battery, str) or not battery:
            raise ProbeError("battery name must be a non-empty str")
        self.battery = battery
        self.xfail = frozenset(xfail)
        for name in self.xfail:
            if not isinstance(name, str) or not name:
                raise ProbeError("xfail names must be non-empty strs")

    def run(self, probes):
        """Run probes: ``[(name, fn), ...]`` with ``fn() -> "held" |
        "break" | "error"``. Returns an :class:`XFailReport`; raises
        :class:`ProbeError` on manifest misuse."""
        seen = set()
        records = []
        for name, fn in probes:
            if name in seen:
                raise ProbeError(
                    "duplicate probe name %r in battery %r"
                    % (name, self.battery))
            seen.add(name)
            try:
                verdict = fn()
            except Exception:  # noqa: BLE001 -- a dying probe is an error
                verdict = "error"
            if verdict not in _VERDICTS:
                raise ProbeError(
                    "probe %r returned unknown verdict %r"
                    % (name, verdict))
            declared = name in self.xfail
            # An "error" verdict is NEVER expected: a declared-xfail
            # probe that stops executing its attack shape (instead of
            # breaking cleanly) is probe rot, not a documented residual.
            if verdict == "error":
                expected = "error"
            elif verdict == "held":
                expected = "unexpected-pass" if declared else "held"
            elif declared:
                expected = "expected-break"
            else:
                expected = "unexpected-break"
            records.append((name, verdict, expected))
        stale = sorted(self.xfail - seen)
        if stale:
            raise ProbeError(
                "battery %r: xfail name(s) never exercised: %s -- "
                "stale xfail list" % (self.battery, ", ".join(stale)))
        return XFailReport(self.battery, records)
