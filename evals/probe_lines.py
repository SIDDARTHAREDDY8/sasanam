"""Canonical probe-line emission and coherence checking for eval batteries.

Canonical form (one probe, one line)::

    [VERDICT] pid: note

where VERDICT is one of BREAK / HELD / ERROR / SKIP, pid matches
``[A-Za-z0-9_.\\-]+``, and note is the first line of the probe note.
Every probe in a battery's results list is printed exactly once, in
recording order, before the ``----`` separator and the
``N BREAK / M HELD / K ERROR`` summary line.

Rationale: before the wave-308 migration, per-probe printing varied
across five shapes (bracketed, indented-bracketed, columnar, conditional
on non-HELD, summary-only), so a "probe lines cohere with the summary"
check was not tree-wide sound (wave-307 lane C). The canonical form is
the one shape the green-check contract already parses
(``green_check.BREAK_ID_RE``), so canonical batteries are checkable by
construction.

Stdlib only; no gov imports. Batteries import this as::

    sys.path.insert(0, os.path.join(REPO, "evals"))
    import probe_lines

See evals/SUMMARY_FORM_MIGRATION.md for the full spec and migration
rules.
"""

import re

VALID_VERDICTS = ("BREAK", "HELD", "ERROR", "SKIP")

# Probe ids must stay inside this class: the green-check contract's
# BREAK_ID_RE captures ``([A-Za-z0-9_.\\-]+)`` after "[BREAK] ", so a pid
# with any other character silently breaks expected-break matching.
PID_RE = re.compile(r"[A-Za-z0-9_.\-]+")

# Matches one canonical probe line. The note group is permissive on
# purpose: notes are human text, only the verdict/pid fields are load
# bearing.
LINE_RE = re.compile(r"\[(BREAK|HELD|ERROR|SKIP)\] ([A-Za-z0-9_.\-]+): ?(.*)")


def first_line(note):
    """First line of a probe note; never raises on empty/odd input."""
    return (str(note).splitlines() or [""])[0]


def format_line(pid, verdict, note):
    """Render one canonical probe line (no printing)."""
    return "[%s] %s: %s" % (verdict, pid, first_line(note))


def emit(results):
    """Print one canonical probe line per (pid, verdict, note) result.

    Prints EVERY probe, including HELD: a battery whose probes all hold
    must still emit one line per probe, otherwise a ">= 1 probe line"
    liveness rule cannot distinguish "all green" from "printed
    nothing". results is an iterable of (pid, verdict, note) triples.
    """
    for pid, verdict, note in results:
        print(format_line(pid, verdict, note))


def parse_line(line):
    """Parse a canonical probe line; returns (verdict, pid, note) or None.

    Strict: the line must start at column 0 (no indent) -- the
    canonical form is unindented, and an indented S2 line must not pass
    as canonical. A single trailing newline is tolerated.
    """
    m = LINE_RE.match(line)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


def check_coherence(results, n_break, n_held, n_err):
    """Non-enforcing coherence check between a results list and summary counts.

    Verifies: every result carries a known verdict; every pid is inside
    the load-bearing character class; and the per-verdict tallies over
    the results list equal the summary counts the battery is about to
    print. SKIP is informational and tallied separately -- it must not
    be silently folded into HELD.

    Returns ``(ok, diagnostics)`` and never raises: during the migration
    the check is ADVISORY, not a gate. A battery surfaces a mismatch by
    printing a ``coherence-WARNING:`` line (inert to the green-check
    contract's parsers) rather than by altering its verdicts -- a
    printing-hygiene problem must not move a battery's own result.
    """
    diags = []
    try:
        items = list(results)
    except Exception as e:  # noqa: BLE001
        return False, ["results not iterable: %r" % (e,)]
    counts = {v: 0 for v in VALID_VERDICTS}
    for item in items:
        try:
            pid, verdict, _note = item
        except (TypeError, ValueError):
            diags.append("malformed result entry %r (want (pid, verdict, note))"
                         % (item,))
            continue
        if verdict not in VALID_VERDICTS:
            diags.append("unknown verdict %r on pid %r" % (verdict, pid))
            continue
        counts[verdict] += 1
        if not PID_RE.fullmatch(pid or ""):
            diags.append("pid %r outside [A-Za-z0-9_.-]; green-check "
                         "BREAK matching would miss it" % (pid,))
    expected = {"BREAK": n_break, "HELD": n_held, "ERROR": n_err}
    for verdict, want in expected.items():
        if counts[verdict] != want:
            diags.append("count mismatch %s: results list has %d, summary "
                         "claims %d" % (verdict, counts[verdict], want))
    return (not diags), diags
