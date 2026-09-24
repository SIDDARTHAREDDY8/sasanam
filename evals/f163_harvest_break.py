"""F163 red battery: bulk trace/exchange harvest vs legitimate debugging.

Reproduces the Anthropic Sept-2026 "Illicit distillation" harvest
pattern (cross-session replay at harvest tempo: many distinct run
transcripts pulled in a tight loop) against the CURRENT tree, plus a
legitimate-debugging control group (own-run reads, one past-run
debug read).

Pre-fix (no guard): the harvest loop completes with NO extraction
record anywhere and trips NOTHING -> gap demonstrated, exit 1 (red).
Post-fix: the harvest trips fail-closed (ExchangeAccessDenied) with
an exchange_read_denied record, the controls stay green, exit 0.

Deterministic: no sleeps, no RNG; thresholds are driven by env vars
read at call time. Runs standalone in both deployment modes:
  python3 evals/f163_harvest_break.py
  env -u GOV_DEPLOYMENT_MODE python3 evals/f163_harvest_break.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import contextlib
import json
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from gov.log import read_entries  # noqa: E402

try:
    from gov import exchange_ledger as xl  # noqa: E402
    HAVE_GUARD = True
except ImportError:
    xl = None
    HAVE_GUARD = False

N_RUNS = 12
EXCHANGES_PER_RUN = 200


def make_fixture(root):
    """Synthetic runs/<run-id>/actions.jsonl exchange files."""
    runs = root / "runs"
    for i in range(N_RUNS):
        d = runs / ("run-%02d" % i)
        d.mkdir(parents=True)
        lines = []
        for j in range(EXCHANGES_PER_RUN):
            lines.append(json.dumps({
                "event": "tool_call",
                "run_id": "run-%02d" % i,
                "seq": j,
                "tool": "web_search",
                "reasoning": "synthetic chain-of-thought %d/%d" % (i, j),
            }))
        (d / "actions.jsonl").write_text("\n".join(lines) + "\n",
                                         encoding="utf-8")
    return runs


class StubLog:
    """Minimal chained-log stand-in: records mirrored events."""

    def __init__(self):
        self.events = []

    def append(self, event):
        self.events.append(dict(event))
        return event


@contextlib.contextmanager
def battery_env(tmp, **overrides):
    saved = {}
    battery_env.counter = getattr(battery_env, "counter", 0) + 1
    ledger = tmp / ("exchange_access_%d.jsonl" % battery_env.counter)
    base = {
        "GOV_EXCHANGE_LEDGER_PATH": str(ledger),
        "GOV_EXCHANGE_MAX_RUNS": "5",
        "GOV_EXCHANGE_WINDOW_SEC": "900",
        "GOV_EXCHANGE_MAX_SINGLE_READ": "100000",
        "GOV_EXCHANGE_STRICT_CROSS_PRINCIPAL": "0",
        "GOV_EXCHANGE_READ_ALLOW": "",
    }
    base.update(overrides)
    for k, v in base.items():
        saved[k] = os.environ.get(k)
        os.environ[k] = v
    try:
        yield ledger
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def ledger_records(ledger):
    if not ledger.exists():
        return []
    return [json.loads(l) for l in
            ledger.read_text(encoding="utf-8").splitlines() if l.strip()]


def scenario_harvest_tempo(runs, tmp):
    """Cross-session replay at harvest tempo: 12 distinct runs, fast."""
    with battery_env(tmp) as ledger:
        allowed, denied_at = 0, None
        for i in range(N_RUNS):
            try:
                entries = read_entries(runs / ("run-%02d" % i)
                                       / "actions.jsonl")
                assert len(entries) == EXCHANGES_PER_RUN
                allowed += 1
            except Exception as e:  # noqa: BLE001 - battery probes
                if HAVE_GUARD and isinstance(e, xl.ExchangeAccessDenied):
                    denied_at = i
                    break
                raise
        recs = ledger_records(ledger)
        return allowed, denied_at, recs


def scenario_full_trace_single_read(runs, tmp):
    """One giant full-trace pull (Moonshot/DeepSeek silent-relay shape)."""
    big = tmp / "runs" / "run-big"
    big.mkdir(parents=True)
    big.joinpath("actions.jsonl").write_text(
        "\n".join(json.dumps({"event": "tool_call", "seq": j})
                  for j in range(3000)) + "\n", encoding="utf-8")
    with battery_env(tmp, GOV_EXCHANGE_MAX_SINGLE_READ="1000") as ledger:
        try:
            read_entries(big / "actions.jsonl")
            return "allowed", ledger_records(ledger)
        except Exception as e:  # noqa: BLE001
            if HAVE_GUARD and isinstance(e, xl.ExchangeAccessDenied):
                return "denied", ledger_records(ledger)
            raise


def scenario_own_run_frictionless(runs, tmp):
    """Legit debugging: agent reads its OWN run's exchanges repeatedly."""
    with battery_env(tmp) as ledger:
        with xl.bind_reader("agent-7", "run-00"):
            for _ in range(10):
                entries = read_entries(runs / "run-00" / "actions.jsonl")
                assert len(entries) == EXCHANGES_PER_RUN
        recs = ledger_records(ledger)
    own = [r for r in recs if r.get("target_run_id") == "run-00"]
    return own


def scenario_past_run_debug(runs, tmp):
    """Legit debugging: same principal reads one past run's exchanges."""
    stub = StubLog()
    with battery_env(tmp) as ledger:
        with xl.bind_reader("agent-7", "run-00", action_log=stub):
            entries = read_entries(runs / "run-01" / "actions.jsonl")
            assert len(entries) == EXCHANGES_PER_RUN
        recs = ledger_records(ledger)
    return recs, stub.events


def scenario_strict_cross_principal(runs, tmp):
    """Strict posture: non-allowlisted cross-run read denied; allowlist
    restores access."""
    with battery_env(tmp,
                      GOV_EXCHANGE_STRICT_CROSS_PRINCIPAL="1") as ledger:
        denied_ok, allowed_ok = False, False
        with xl.bind_reader("agent-7", "run-00"):
            try:
                read_entries(runs / "run-02" / "actions.jsonl")
            except xl.ExchangeAccessDenied:
                denied_ok = True
        os.environ["GOV_EXCHANGE_READ_ALLOW"] = "agent-7:run-02"
        with xl.bind_reader("agent-7", "run-00"):
            entries = read_entries(runs / "run-02" / "actions.jsonl")
            assert len(entries) == EXCHANGES_PER_RUN
            allowed_ok = True
        recs = ledger_records(ledger)
    return denied_ok, allowed_ok, recs


def main():
    tmp = Path(tempfile.mkdtemp(prefix="f163-"))
    runs = make_fixture(tmp)
    failures = []

    if not HAVE_GUARD:
        # ---- PRE-FIX: demonstrate the gap -------------------------
        allowed, denied_at, recs = scenario_harvest_tempo(runs, tmp)
        stray = list(tmp.rglob("exchange_access.jsonl"))
        print("F163 PRE-FIX GAP CHECK")
        print("  harvest loop: %d/%d runs read, denied_at=%s"
              % (allowed, N_RUNS, denied_at))
        print("  extraction records written: %d" % len(recs))
        print("  ledger files created: %d" % len(stray))
        if allowed == N_RUNS and denied_at is None and not recs \
                and not stray:
            print("  => GAP DEMONSTRATED: bulk harvest of %d runs x %d "
                  "exchanges leaves NO extraction record and trips "
                  "NOTHING" % (N_RUNS, EXCHANGES_PER_RUN))
            return 1
        print("  => unexpected: harvest was impeded pre-fix?")
        return 2

    # ---- POST-FIX: harvest must trip, controls must pass ----------
    print("F163 POST-FIX VERIFICATION")
    allowed, denied_at, recs = scenario_harvest_tempo(runs, tmp)
    reads = [r for r in recs if r["event"] == "exchange_read"]
    denied = [r for r in recs if r["event"] == "exchange_read_denied"]
    print("  H1 harvest tempo: allowed=%d denied_at_run=%s "
          "exchange_read=%d exchange_read_denied=%d"
          % (allowed, denied_at, len(reads), len(denied)))
    if not (allowed == 5 and denied_at == 5 and len(reads) == 5
            and len(denied) == 1):
        failures.append("H1: harvest tempo did not trip fail-closed "
                        "at the 6th distinct run")

    verdict, recs2 = scenario_full_trace_single_read(runs, tmp)
    denied2 = [r for r in recs2 if r["event"] == "exchange_read_denied"]
    print("  H2 full-trace single read: %s denied_records=%d"
          % (verdict, len(denied2)))
    if verdict != "denied" or len(denied2) != 1:
        failures.append("H2: single 3000-exchange pull was not denied")

    own = scenario_own_run_frictionless(runs, tmp)
    print("  C1 own-run reads: 10/10 passed, ledger records for own "
          "run=%d" % len(own))
    if own:
        failures.append("C1: own-run reads were recorded (must stay "
                        "frictionless)")

    recs4, mirrored = scenario_past_run_debug(runs, tmp)
    print("  C2 past-run debug read: allowed, exchange_read=%d "
          "chained-log mirror=%d principal=%s"
          % (len(recs4),
             len([e for e in mirrored if e.get("event")
                  == "exchange_read"]),
             recs4[0].get("reader_principal") if recs4 else None))
    if len(recs4) != 1 or recs4[0]["event"] != "exchange_read" \
            or recs4[0]["reader_principal"] != "agent-7" \
            or not any(e.get("event") == "exchange_read"
                       for e in mirrored):
        failures.append("C2: past-run debug read not recorded/mirrored")

    denied_ok, allowed_ok, recs5 = scenario_strict_cross_principal(
        runs, tmp)
    print("  C3 strict posture: denied=%s allowlisted_allowed=%s"
          % (denied_ok, allowed_ok))
    if not (denied_ok and allowed_ok):
        failures.append("C3: strict default-deny / allowlist broken")

    if failures:
        print("FAILURES:")
        for f in failures:
            print("  - " + f)
        return 1
    print("ALL GREEN: harvest trips fail-closed, legit reads pass, "
          "extraction records exist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
