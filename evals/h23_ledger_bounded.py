"""H23: F170 exchange-ledger bounded-growth verification (measured-absent).

F170 was CLOSED in Wave-110 (append-time compaction + tail-budgeted
scans). H23's premise ("no rotation/compaction") is stale; this probe
re-verifies the closure's acceptance criterion on the current tree:
per-read cost stays flat as the ledger grows 10x.

GREEN = compaction holds, per-read cost flat. RED would mean the
Wave-110 closure regressed.

Run: python evals/h23_ledger_bounded.py
"""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock
from pathlib import Path
from gov import exchange_ledger as xl


def _old_record(ts, i):
    return {"ts": ts, "mono": 1.0, "boot_epoch": 1,
            "reader_run": "r%d" % i, "target_run": "v%d" % i,
            "decision": "allow"}


def measure(n_stale, workdir):
    d = Path(workdir) / ("L%d" % n_stale)
    d.mkdir(parents=True, exist_ok=True)
    p = d / "exchange_access.jsonl"
    if p.exists():
        p.unlink()
    now = 1_700_000_000.0
    with mock.patch("time.time", return_value=now):
        for i in range(n_stale):
            xl._append_record(p, _old_record(now - 100000, i))
        # One fresh record triggers append-time compaction.
        xl._append_record(p, _old_record(now, 9999))
        size = p.stat().st_size
        t0 = time.perf_counter()
        for _ in range(20):
            recs, truncated = xl._read_window_full(p, "unknown", 900)
        dt = (time.perf_counter() - t0) / 20
    return size, dt, truncated


def main():
    workdir = os.environ.get("TMPDIR", "/tmp") + "/h23probe"
    os.environ["GOV_EXCHANGE_LEDGER_COMPACT_BYTES"] = "20000"
    sizes, costs = [], []
    for n in (3000, 30000):
        size, dt, truncated = measure(n, workdir)
        sizes.append(size)
        costs.append(dt)
        print("stale=%5d file=%7dB per_read=%6.3fms truncated=%s"
              % (n, size, dt * 1000, truncated))
        if truncated:
            print("RED: window scan truncated (fail-closed deny, not flat cost)")
            return 1
    # File must stay bounded (compaction), and per-read cost must not
    # grow with total history: 10x records -> cost ratio < 3x.
    ratio = costs[1] / costs[0] if costs[0] > 0 else float("inf")
    bounded = sizes[1] < 4 * sizes[0]
    flat = ratio < 3.0
    print("10x growth: file ratio %.2f (bounded=%s), cost ratio %.2f (flat=%s)"
          % (sizes[1] / sizes[0], bounded, ratio, flat))
    if bounded and flat:
        print("GREEN: F170 closure holds -- ledger bounded, per-read cost "
              "flat across 10x growth (H23 measured-absent)")
        return 0
    print("RED: bounded-growth regression")
    return 1


if __name__ == "__main__":
    sys.exit(main())
