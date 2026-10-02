"""Wave-277 F297 closure battery: emit_coverage must deduplicate the
denominator so duplicate entries cannot inflate the coverage percentage.

F297 (LOW): `emit_coverage` validated the denominator's shape (non-empty
list/tuple, not a bare string) but never its uniqueness. Each occurrence
was counted independently, so `emit_coverage(["t1","t1","t2"], ...)` with
t1 covered and t2 visible-only reported 66.7% instead of the honest 50.0%.
Close-when: (1) emit_coverage deduplicates the denominator so the case
reports 50.0%; (2) cl01 flips to HELD; (3) honest denominators unaffected;
(4) evals/w275_coverage_probes.py stays green.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic; fresh /var/tmp/g277-f297
TMPDIR (`mkdir -p` first); depth-1 green checks honoring GOV_SKIP_GREEN=1;
no in-repo git subprocesses; stdlib only.
"""

import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TMP = tempfile.mkdtemp(prefix="g277-f297-%d-" % os.getpid(),
                        dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import gov.coverage_ledger as cl  # noqa: E402

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    _RESULTS.append((pid, expected, verdict, verdict == expected, note))


def _qsrc():
    return {"s1": {"completeness": 5, "freshness": 5, "depth": 5,
                   "brittleness": 5, "integrity": 5}}


def _ledger_t1_covered_t2_visible():
    L = cl.CoverageLedger()
    L.record_technique("t1", "FULL", sources=dict(_qsrc()))
    L.record_technique("t2", "FULL", sources=dict(_qsrc()))
    L.score("t1", 5, proof_method="red-probes",
            scored_at="2026-10-01T00:00:00+00:00")
    L.score("t2", 0, proof_method="red-probes",
            scored_at="2026-10-01T00:00:00+00:00")
    return L


def p01_duplicate_denominator():
    """Core F297 case: ["t1","t1","t2"] must report 50.0%, not 66.7%."""
    L = _ledger_t1_covered_t2_visible()
    r = L.emit_coverage(["t1", "t1", "t2"], proof_method="red-probes")
    if abs(r["percentage"] - 50.0) > 1e-9:
        return ("BREAK", "duplicate denominator inflated to %.1f%% "
                "(honest: 50.0%%)" % r["percentage"])
    if r["denominator"] != 2:
        return ("BREAK", "denominator count %r, honest is 2"
                % (r["denominator"],))
    return "HELD", "duplicate denominator deduplicated -> 50.0%"


def p02_triple_duplicate():
    """Three occurrences of the covered technique must still be 50.0%."""
    L = _ledger_t1_covered_t2_visible()
    r = L.emit_coverage(["t1", "t1", "t1", "t2"], proof_method="red-probes")
    if abs(r["percentage"] - 50.0) > 1e-9 or r["denominator"] != 2:
        return ("BREAK", "triple duplicate -> %.1f%% / denom %r"
                % (r["percentage"], r["denominator"]))
    return "HELD", "triple duplicate deduplicated -> 50.0%"


def p03_all_duplicates():
    """["t1","t1"] with t1 covered: honest denominator is 1, not 2."""
    L = _ledger_t1_covered_t2_visible()
    r = L.emit_coverage(["t1", "t1"], proof_method="red-probes")
    if r["denominator"] != 1 or abs(r["percentage"] - 100.0) > 1e-9:
        return ("BREAK", "all-duplicate denom %r pct %.1f%%"
                % (r["denominator"], r["percentage"]))
    return "HELD", "all-duplicate denominator collapses to 1"


def p04_honest_denominator_unaffected():
    """Control: an honest denominator is byte-for-byte the old behavior."""
    L = _ledger_t1_covered_t2_visible()
    r = L.emit_coverage(["t1", "t2"], proof_method="red-probes")
    if r["denominator"] != 2 or r["covered"] != 1 \
            or abs(r["percentage"] - 50.0) > 1e-9:
        return ("BREAK", "honest denominator changed: %r" % (r,))
    return "HELD", "honest denominator unaffected"


def p05_order_preserved():
    """Dedup keeps first-occurrence order: ["t2","t1","t2"] -> [t2,t1]."""
    L = _ledger_t1_covered_t2_visible()
    r = L.emit_coverage(["t2", "t1", "t2"], proof_method="red-probes")
    if abs(r["percentage"] - 50.0) > 1e-9 or r["denominator"] != 2:
        return ("BREAK", "order case -> %.1f%% / denom %r"
                % (r["percentage"], r["denominator"]))
    keys = list(r["techniques"].keys())
    if keys != ["t2", "t1"]:
        return ("BREAK", "detail order %r, want ['t2','t1']" % (keys,))
    return "HELD", "dedup preserves first-occurrence order"


def p06_malformed_still_refused():
    """Fail-closed shape validation is preserved: bare string, empty,
    None denominator and blank proof method still refuse loudly."""
    L = _ledger_t1_covered_t2_visible()
    bad = 0
    for denom in ("t1", [], None, ["t1"]):
        try:
            if denom == ["t1"]:
                L.emit_coverage(denom, proof_method="   ")
            else:
                L.emit_coverage(denom, proof_method="red-probes")
        except cl.CoverageLedgerError:
            bad += 1
        except Exception as exc:  # noqa: BLE001
            return ("BREAK", "wrong exception %r" % (exc,))
    if bad != 4:
        return ("BREAK", "only %d/4 malformed inputs refused" % bad)
    return "HELD", "malformed denominators still refused fail-closed"


def p07_tuple_denominator():
    """Tuples deduplicate the same as lists."""
    L = _ledger_t1_covered_t2_visible()
    r = L.emit_coverage(("t1", "t1", "t2"), proof_method="red-probes")
    if abs(r["percentage"] - 50.0) > 1e-9 or r["denominator"] != 2:
        return ("BREAK", "tuple dup -> %.1f%% / denom %r"
                % (r["percentage"], r["denominator"]))
    return "HELD", "tuple denominator deduplicated"


def p08_chain_intact_after_dedup():
    """Emitting with a duplicated denominator must not disturb the
    hash-chained logbooks."""
    L = _ledger_t1_covered_t2_visible()
    L.emit_coverage(["t1", "t1", "t2"], proof_method="red-probes")
    if not L.verify_all():
        return ("BREAK", "verify_all() failed after dedup emit")
    return "HELD", "hash-chain integrity intact"


_PROBES = [
    ("f297-01-duplicate-denominator", "HELD", p01_duplicate_denominator),
    ("f297-02-triple-duplicate", "HELD", p02_triple_duplicate),
    ("f297-03-all-duplicates", "HELD", p03_all_duplicates),
    ("f297-04-honest-unaffected", "HELD", p04_honest_denominator_unaffected),
    ("f297-05-order-preserved", "HELD", p05_order_preserved),
    ("f297-06-malformed-refused", "HELD", p06_malformed_still_refused),
    ("f297-07-tuple-denominator", "HELD", p07_tuple_denominator),
    ("f297-08-chain-intact", "HELD", p08_chain_intact_after_dedup),
]


def _green_checks():
    """Depth-1: run the adjacent coverage battery with GOV_SKIP_GREEN=1
    (it records the skip and does not recurse)."""
    if GREEN_SKIP:
        return [("green-checks", "SKIP",
                 "GOV_SKIP_GREEN=1: recorded, not recursing")]
    out = []
    name = "w275_coverage_probes"
    path = os.path.join(REPO, "evals", name + ".py")
    if not os.path.exists(path):
        return [(name, "SKIP", "battery absent")]
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    try:
        p = subprocess.run([sys.executable, path], env=env,
                           capture_output=True, text=True, timeout=600)
    except Exception as exc:  # noqa: BLE001
        return [(name, "BREAK", "green check failed: %s" % (exc,))]
    tail = (p.stdout or "").strip().split("\n")[-1] if p.stdout else ""
    out.append((name, "HELD" if p.returncode == 0 else "BREAK",
                "%s rc=%d" % (tail[:120], p.returncode)))
    return out


def main():
    print("w277 F297 battery: %d probes (TMPDIR=%s)" % (len(_PROBES), _TMP))
    failures = 0
    for pid, expected, fn in _PROBES:
        _run(pid, expected, fn)
    for pid, expected, verdict, ok, note in _RESULTS:
        flag = "ok " if ok else "FAIL"
        if not ok:
            failures += 1
        print("[%s] %-34s expected=%-5s got=%-5s %s"
              % (flag, pid, expected, verdict, note))
    print("--- green checks (depth-1) ---")
    for name, verdict, note in _green_checks():
        print("[%s] %s %s" % ("ok " if verdict in ("HELD", "SKIP") else "FAIL",
                              name, note))
        if verdict not in ("HELD", "SKIP"):
            failures += 1
    n_break = sum(1 for r in _RESULTS if r[2] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r[2] == "HELD")
    n_err = sum(1 for r in _RESULTS if r[2] == "ERROR")
    print("probes: %d BREAK / %d HELD / %d ERROR; mismatches: %d"
          % (n_break, n_held, n_err, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
