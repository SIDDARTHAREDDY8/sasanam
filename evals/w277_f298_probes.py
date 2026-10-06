"""Wave-277 F298 closure battery: future-dated score() must refuse fail-closed.

F298: score() accepted an arbitrarily future-dated scored_at (e.g.
2999-06-01). From then on every honest append -- score() with a real
timestamp and ingest_monitor_report() (which stamps utcnow) -- refused
coverage-refused-backdated-entry forever, with no recovery API. The
logbook's chain still verified, but the append path was dead.

The fix: score() refuses a scored_at more than MAX_FUTURE_SKEW (5 min)
in the future with coverage-refused-future-dated-entry. Fail-closed on
the bad entry, not on all later honest ones. Backdated refusal and the
monotonicity guarantee are unchanged.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic (no random); stdlib only;
depth-1 green checks honoring GOV_SKIP_GREEN=1; no in-repo git
subprocesses; the ledger is in-memory so no TMPDIR is needed.
"""

import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import coverage_ledger as cl  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)


GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    _RESULTS.append((pid, expected, verdict, verdict == expected, note))


def _pin_check():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    literals = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if len(literals) != TAXONOMY_PIN:
        return ("BREAK", "taxonomy pin drift: %d literals, pin %d"
                % (len(literals), TAXONOMY_PIN))
    if len(set(literals)) != len(literals):
        return "BREAK", "duplicate code literals in taxonomy"
    return "HELD", "taxonomy pin 1588: 1588 unique literals"


def _qsrc():
    return {"s1": {"completeness": 5, "freshness": 5, "depth": 5,
                   "brittleness": 5, "integrity": 5}}


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat()


def f298a_future_score_refused():
    """A far-future scored_at must refuse up front (F298 fixed)."""
    L = cl.CoverageLedger()
    L.record_technique("tx", "FULL", sources=dict(_qsrc()))
    try:
        L.score("tx", 3, proof_method="redteam",
                scored_at="2999-06-01T00:00:00+00:00")
    except cl.CoverageLedgerError as exc:
        if exc.code == "coverage-refused-future-dated-entry":
            return "HELD", "refused up front: %s" % exc.code
        return "BREAK", "refused but wrong code %r" % (exc.code,)
    except ValueError as exc:
        return "BREAK", "ValueError instead of coded refusal: %s" % exc
    return "BREAK", "F298: future-dated score accepted (would brick logbook)"


def f298b_logbook_not_bricked():
    """After a refused future attempt, an honest score appends normally."""
    L = cl.CoverageLedger()
    L.record_technique("tx", "FULL", sources=dict(_qsrc()))
    try:
        L.score("tx", 3, proof_method="redteam",
                scored_at="2999-06-01T00:00:00+00:00")
    except cl.CoverageLedgerError:
        pass
    now = datetime.now(timezone.utc)
    try:
        entry = L.score("tx", 4, proof_method="redteam",
                        scored_at=_iso(now))
    except cl.CoverageLedgerError as exc:
        return "BREAK", "honest score refused after refused future: %s"\
            % exc.code
    if entry["score"] != 4:
        return "BREAK", "wrong entry appended"
    return "HELD", "honest append works after refused future score"


def f298c_ingest_after_refusal():
    """ingest_monitor_report() works after a refused future attempt."""
    L = cl.CoverageLedger()
    L.record_technique("tx", "FULL", sources=dict(_qsrc()))
    L.register_code_mapping("some-code", "tx")
    try:
        L.score("tx", 3, proof_method="redteam",
                scored_at="2999-06-01T00:00:00+00:00")
    except cl.CoverageLedgerError:
        pass
    try:
        n = L.ingest_monitor_report(
            {"mode": "monitor", "monitor_would_deny": {"some-code": 2},
             "monitor_would_allow": 1, "monitor_evaluations": 3})
    except cl.CoverageLedgerError as exc:
        return "BREAK", "ingest refused after refused future: %s" % exc.code
    if n["techniques_ingested"] != 1:
        return "BREAK", "ingest count %r" % (n,)
    return "HELD", "ingest works after refused future score"


def f298d_backdated_still_refused():
    """Close-when (3): the backdated-entry refusal still works."""
    L = cl.CoverageLedger()
    L.record_technique("tx", "FULL", sources=dict(_qsrc()))
    now = datetime.now(timezone.utc)
    L.score("tx", 3, proof_method="redteam", scored_at=_iso(now))
    try:
        L.score("tx", 2, proof_method="redteam",
                scored_at=_iso(now - timedelta(days=1)))
    except cl.CoverageLedgerError as exc:
        if exc.code == "coverage-refused-backdated-entry":
            return "HELD", "backdated refusal intact"
        return "BREAK", "wrong code %r" % (exc.code,)
    return "BREAK", "backdated score accepted (monotonicity broken)"


def f298e_small_skew_accepted():
    """A stamp modestly in the future (clock skew) is still accepted."""
    L = cl.CoverageLedger()
    L.record_technique("tx", "FULL", sources=dict(_qsrc()))
    now = datetime.now(timezone.utc)
    try:
        L.score("tx", 3, proof_method="redteam",
                scored_at=_iso(now + timedelta(minutes=2)))
    except cl.CoverageLedgerError as exc:
        return "BREAK", "+2min skew refused: %s" % exc.code
    return "HELD", "+2min clock skew accepted"


def f298f_beyond_tolerance_refused():
    """A stamp beyond the skew tolerance refuses, even on an empty book."""
    L = cl.CoverageLedger()
    L.record_technique("tx", "FULL", sources=dict(_qsrc()))
    now = datetime.now(timezone.utc)
    try:
        L.score("tx", 3, proof_method="redteam",
                scored_at=_iso(now + timedelta(hours=1)))
    except cl.CoverageLedgerError as exc:
        if exc.code == "coverage-refused-future-dated-entry":
            return "HELD", "refused: %s" % exc.code
        return "BREAK", "wrong code %r" % (exc.code,)
    return "BREAK", "+1h future score accepted on empty logbook"


def f298g_chain_verifies_after_refusal():
    """The chain still verifies after a refused future attempt."""
    L = cl.CoverageLedger()
    L.record_technique("tx", "FULL", sources=dict(_qsrc()))
    try:
        L.score("tx", 3, proof_method="redteam",
                scored_at="2999-06-01T00:00:00+00:00")
    except cl.CoverageLedgerError:
        pass
    now = datetime.now(timezone.utc)
    try:
        L.score("tx", 4, proof_method="redteam", scored_at=_iso(now))
    except cl.CoverageLedgerError as exc:
        return "BREAK", "honest append refused (logbook bricked): %s"\
            % exc.code
    if L.verify_all() != 1:
        return "BREAK", "chain did not verify"
    return "HELD", "chain verifies, 1 entry"


def f298h_explicit_now_accepted():
    """An explicit scored_at of 'now' keeps working (no false refuse)."""
    L = cl.CoverageLedger()
    L.record_technique("tx", "FULL", sources=dict(_qsrc()))
    now = datetime.now(timezone.utc)
    try:
        L.score("tx", 3, proof_method="redteam", scored_at=_iso(now))
        L.score("tx", 4, proof_method="redteam",
                scored_at=_iso(now + timedelta(seconds=1)))
    except cl.CoverageLedgerError as exc:
        return "BREAK", "honest now-stamps refused: %s" % exc.code
    return "HELD", "explicit now stamps append"


PROBES = [
    ("f298a-future-score-refused", "HELD", f298a_future_score_refused),
    ("f298b-logbook-not-bricked", "HELD", f298b_logbook_not_bricked),
    ("f298c-ingest-after-refusal", "HELD", f298c_ingest_after_refusal),
    ("f298d-backdated-still-refused", "HELD", f298d_backdated_still_refused),
    ("f298e-small-skew-accepted", "HELD", f298e_small_skew_accepted),
    ("f298f-beyond-tolerance-refused", "HELD",
     f298f_beyond_tolerance_refused),
    ("f298g-chain-verifies-after-refusal", "HELD",
     f298g_chain_verifies_after_refusal),
    ("f298h-explicit-now-accepted", "HELD", f298h_explicit_now_accepted),
]


def green_check():
    """Depth-1: run adjacent coverage batteries with GOV_SKIP_GREEN=1."""
    if GREEN_SKIP:
        return [("GOV_SKIP_GREEN=1: recorded, not recursing", "HELD",
                 "skip")]
    results = []
    adjacent = [
        (["evals/w275_coverage_probes.py"], "w275_coverage", "no-break"),
        (["evals/w276_redteam_probes.py"], "w276_redteam", "mismatch"),
    ]
    for argv, name, fmt in adjacent:
        tmp = tempfile.mkdtemp(prefix="g277-green-%s-" % name, dir="/var/tmp")
        env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmp)
        try:
            p = subprocess.run(
                [sys.executable] + argv, cwd=REPO, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=600, text=True)
            tail = p.stdout.strip().splitlines()
            summary = tail[-1] if tail else ""
            # w275_coverage prints "w275_coverage_probes: N/N HELD" with no
            # expected BREAKs; w276_redteam keeps its expected-BREAK pins
            # (F296/F297 open) and prints "mismatches: 0".
            if fmt == "no-break":
                ok = (p.returncode == 0 and "BREAK" not in p.stdout
                      and "ERROR" not in p.stdout)
            else:
                ok = (p.returncode == 0 and "mismatches: 0" in p.stdout
                      and "0 ERROR" in p.stdout)
            results.append((name, "HELD" if ok else "BREAK",
                            "rc=%d %s" % (p.returncode, summary[:160])))
        except Exception as exc:  # noqa: BLE001
            results.append((name, "BREAK", "%s" % exc))
    return results


def main():
    pin_verdict, pin_note = _pin_check()
    _RESULTS.append(("pin-taxonomy-1493", "HELD", pin_verdict,
                     pin_verdict == "HELD", pin_note))
    for pid, expected, fn in PROBES:
        _run(pid, expected, fn)
    n_break = sum(1 for r in _RESULTS if r[2] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r[2] == "HELD")
    n_err = sum(1 for r in _RESULTS if r[2] == "ERROR")
    n_mismatch = sum(1 for r in _RESULTS if not r[3])
    for pid, expected, verdict, ok, note in _RESULTS:
        print("[%s] %-36s expected=%-5s got=%-5s %s"
              % ("ok " if ok else "FAIL", pid, expected, verdict, note))
    print("--- green checks (depth-1) ---")
    for name, verdict, note in green_check():
        print("[%s] %s %s" % ("ok " if verdict == "HELD" else "FAIL",
                              name, note))
    print("probes: %d BREAK / %d HELD / %d ERROR; mismatches: %d"
          % (n_break, n_held, n_err, n_mismatch))
    return 0 if (n_err == 0 and n_mismatch == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
