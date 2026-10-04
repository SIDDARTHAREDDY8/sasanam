"""Wave-275 coverage-ledger battery (clean-room DeTTECT patterns, GPL-3.0: no code reuse).

Break-first battery for gov/coverage_ledger.py -- the honest detection-coverage
ledger for the monitor-but-count seam (wave-273 lane A monitor verdict
accounting). Attacks:

  cov01  visible-but-not-detected reported as covered -- a technique the
         monitor saw (visibility FULL) but never detected (score 0) must
         never count toward the detection numerator.
  cov02  coverage percentage emitted without a denominator -- refused
         ``coverage-refused-no-denominator``.
  cov03  coverage emitted without a proof method -- refused
         ``coverage-refused-no-proof-method``.
  cov04  backdated logbook entry (scored_at earlier than the previous
         entry) -- refused ``coverage-refused-backdated-entry``.
  cov05  forged historical score (middle record rewritten, digests kept)
         -- ``verify_chain`` refuses ``coverage-logbook-chain-broken``.
  cov06  data-quality collapse silently dropped -- a source failing its
         quality contract after scoring excludes the technique from the
         numerator with an explicit qualified_exclusions entry, never a
         silent count and never a silent drop.
  cov07  monitor-mode wiring -- ingest_monitor_report() turns lane-A
         would-deny counters into visibility (score 0) entries that never
         count as detection; emit_coverage() never claims prevention
         (``coverage-refused-monitor-implies-prevention``).
  cov08  positive control -- a fully scored technique with good sources
         and a recorded proof method counts, with denominator + proof
         method on the emitted report.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic (explicit timestamps, fixed
keys); fresh unique /var/tmp/g275* TMPDIR (`mkdir -p` first); depth-1
green checks honoring GOV_SKIP_GREEN=1; no in-repo git subprocesses;
stdlib only.
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Deterministic chain key (fixed, not secrets.token_hex).
os.environ.setdefault(
    "GOV_LOG_KEY",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w275-coverage")

_TMP = tempfile.mkdtemp(prefix="g275-coverage-%d-" % os.getpid(),
                        dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import re  # noqa: E402

TAXONOMY_PIN = 2047 # Wave-275 lane D: pin 1485 -> 1485 (+5 coverage-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 lane 2: pin 2044 -> 2047 (+3: 1 supplychain-scan-already-registered + 1 advisory-version-tie + 1 advisory-input-unpinned)



RESULTS = []


def check(name, held, detail=""):
    RESULTS.append((name, "HELD" if held else "BREAK", detail))
    return held


def _expect_code(fn, code):
    """Run fn; return True iff it raises with .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None) == code
    return False


def _fresh_ledger(cl):
    return cl.CoverageLedger()


def run_all():
    try:
        import gov.coverage_ledger as cl  # noqa: E402
    except ImportError as exc:
        # RED baseline: the module does not exist on the base tree.
        for name in ("cov01", "cov02", "cov03", "cov04", "cov05",
                     "cov06", "cov07", "cov08"):
            check(name, False, "RED: gov.coverage_ledger absent: %s" % exc)
        return False

    # --- taxonomy self-pin (raw quoted literals, wave-270 method) ---
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    literals = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    check("pin", len(literals) == TAXONOMY_PIN and len(set(literals)) == len(literals),
          "literals=%d unique=%d pin=%d" % (len(literals), len(set(literals)), TAXONOMY_PIN))

    T0 = "2026-10-01T12:00:00+00:00"
    T1 = "2026-10-01T13:00:00+00:00"
    T2 = "2026-10-01T14:00:00+00:00"

    # cov01: visible-but-not-detected must never count as covered.
    led = _fresh_ledger(cl)
    led.record_technique("tech-vis", visibility="FULL",
                         sources={"gate": {"completeness": 5, "freshness": 5,
                                           "depth": 5, "brittleness": 5,
                                           "integrity": 5}})
    led.score("tech-vis", 0, proof_method="monitor-counts",
              scored_at=T1)  # score 0: visible/logged only
    rep = led.emit_coverage(denominator=["tech-vis"], proof_method="red-probes")
    check("cov01",
          rep["covered"] == 0 and rep["visible_not_detected"] == ["tech-vis"]
          and rep["prevents"] is False,
          "covered=%r vnd=%r" % (rep["covered"], rep["visible_not_detected"]))

    # cov02: no denominator -> refused.
    led = _fresh_ledger(cl)
    check("cov02",
          _expect_code(lambda: led.emit_coverage(denominator=None,
                                                 proof_method="red-probes"),
                       "coverage-refused-no-denominator"))

    # cov03: no proof method -> refused.
    led = _fresh_ledger(cl)
    led.record_technique("tech-a", visibility="FULL", sources={})
    led.score("tech-a", 3, proof_method="red-probes", scored_at=T1)
    check("cov03",
          _expect_code(lambda: led.emit_coverage(denominator=["tech-a"],
                                                 proof_method=None),
                       "coverage-refused-no-proof-method"))

    # cov04: backdated entry refused.
    led = _fresh_ledger(cl)
    led.record_technique("tech-b", visibility="FULL", sources={})
    led.score("tech-b", 2, proof_method="red-probes", scored_at=T2)
    check("cov04",
          _expect_code(
              lambda: led.score("tech-b", 3, proof_method="red-probes",
                                scored_at=T1),  # T1 < T2: backdated
              "coverage-refused-backdated-entry"))

    # cov05: forged historical score detected by chain verification.
    led = _fresh_ledger(cl)
    led.record_technique("tech-c", visibility="FULL", sources={})
    led.score("tech-c", 1, proof_method="red-probes", scored_at=T0)
    led.score("tech-c", 2, proof_method="red-probes", scored_at=T1)
    book = led.logbook("tech-c")
    forged = dict(book[0])
    forged["score"] = 5  # rewrite history, keep the digest
    book[0] = forged
    check("cov05",
          _expect_code(lambda: led.verify_chain(book),
                       "coverage-logbook-chain-broken"))

    # cov06: data-quality collapse -> qualified exclusion, never silent.
    led = _fresh_ledger(cl)
    led.record_technique("tech-d", visibility="FULL",
                         sources={"src1": {"completeness": 5, "freshness": 5,
                                           "depth": 5, "brittleness": 5,
                                           "integrity": 5}})
    led.score("tech-d", 4, proof_method="red-probes", scored_at=T1)
    led.set_source_quality("src1", {"completeness": 5, "freshness": 1,  # stale
                                    "depth": 5, "brittleness": 5,
                                    "integrity": 5})
    rep = led.emit_coverage(denominator=["tech-d"], proof_method="red-probes")
    check("cov06",
          rep["covered"] == 0
          and any(e["technique"] == "tech-d" and e["reason"] == "source-quality"
                  for e in rep["qualified_exclusions"]),
          "covered=%r excl=%r" % (rep["covered"], rep["qualified_exclusions"]))

    # cov07: monitor-mode wiring never implies prevention.
    led = _fresh_ledger(cl)
    led.register_code_mapping("gatehard-policy-denied", "tech-e")
    led.ingest_monitor_report(
        {"mode": "monitor",
         "monitor_would_deny": {"gatehard-policy-denied": 7},
         "monitor_would_allow": 3,
         "monitor_evaluations": 10})
    rep = led.emit_coverage(denominator=["tech-e"], proof_method="monitor-counts")
    held_monitor = (rep["covered"] == 0
                    and rep["mode"] == "monitor"
                    and rep["prevents"] is False
                    and rep["visible_not_detected"] == ["tech-e"])
    held_prevention = _expect_code(
        led.declare_prevention, "coverage-refused-monitor-implies-prevention")
    check("cov07", held_monitor and held_prevention,
          "monitor=%r prevention-refused=%r" % (held_monitor, held_prevention))

    # cov08: positive control.
    led = _fresh_ledger(cl)
    led.record_technique("tech-f", visibility="FULL",
                         sources={"src9": {"completeness": 5, "freshness": 5,
                                           "depth": 5, "brittleness": 5,
                                           "integrity": 5}})
    led.score("tech-f", 3, proof_method="simulated-events", scored_at=T1)
    rep = led.emit_coverage(denominator=["tech-f", "tech-g"],
                            proof_method="simulated-events")
    check("cov08",
          rep["covered"] == 1 and rep["denominator"] == 2
          and abs(rep["percentage"] - 50.0) < 1e-9
          and rep["proof_method"] == "simulated-events"
          and rep["prevents"] is False,
          "rep=%r" % (rep,))

    # cov09: scan_summary() shape is also wired (no mode key).
    led = _fresh_ledger(cl)
    led.register_code_mapping("gatehard-cap-deny", "tech-h")
    res = led.ingest_monitor_report(
        {"would_allow": 40, "would_deny": {"gatehard-cap-deny": 12}})
    entry = led.logbook("tech-h")[0]
    check("cov09",
          res["techniques_ingested"] == 1
          and entry["score"] == 0
          and entry["proof_method"] == "scan-summary"
          and entry["recorded_by"] == "scan-ingest:gatehard-cap-deny"
          and led._techniques["tech-h"]["visibility"] == "PARTIAL",
          "res=%r entry=%r" % (res, entry))

    # cov10: a bare-string denominator is malformed, not a denominator.
    led = _fresh_ledger(cl)
    check("cov10",
          _expect_code(lambda: led.emit_coverage(
              denominator="nolibs", proof_method="red-probes"),
              "coverage-refused-no-denominator"))

    # cov11: scored detection with no recorded sources is excluded with
    # reason "no-sources" -- never counted as contract-ok.
    led = _fresh_ledger(cl)
    led.record_technique("tech-i", visibility="FULL")
    led.score("tech-i", 3, proof_method="red-probes", scored_at=T1)
    rep = led.emit_coverage(denominator=["tech-i"], proof_method="red-probes")
    check("cov11",
          rep["covered"] == 0
          and rep["techniques"]["tech-i"]["sources_contract_ok"] is None
          and any(e["technique"] == "tech-i" and e["reason"] == "no-sources"
                  for e in rep["qualified_exclusions"]),
          "covered=%r excl=%r" % (rep["covered"],
                                  rep["qualified_exclusions"]))

    # cov12: re-ingesting an unchanged observation appends no duplicate;
    # a changed counter is new information and does append.
    led = _fresh_ledger(cl)
    led.register_code_mapping("gatehard-cap-deny", "tech-j")
    rep1 = {"mode": "monitor",
            "monitor_would_deny": {"gatehard-cap-deny": 7},
            "monitor_would_allow": 3, "monitor_evaluations": 10}
    led.ingest_monitor_report(rep1)
    led.ingest_monitor_report(rep1)
    n_same = len(led.logbook("tech-j"))
    led.ingest_monitor_report(
        {"mode": "monitor",
         "monitor_would_deny": {"gatehard-cap-deny": 9},
         "monitor_would_allow": 3, "monitor_evaluations": 12})
    n_changed = len(led.logbook("tech-j"))
    check("cov12", n_same == 1 and n_changed == 2,
          "n_same=%r n_changed=%r" % (n_same, n_changed))

    return all(status == "HELD" for _, status, _ in RESULTS)


def green_check():
    """Depth-1 green check: run the adjacent unit suite, no recursion."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green_check: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess  # noqa: E402
    import tempfile  # noqa: E402
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmp = tempfile.mkdtemp(prefix="g275-green-", dir="/var/tmp")
    env["TMPDIR"] = tmp
    env["GOV_RUN_ROOT"] = tmp
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_coverage_ledger"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
    print(proc.stdout[-2000:])
    print(proc.stderr[-2000:])
    return proc.returncode == 0


def main():
    ok = run_all()
    held = sum(1 for _, s, _ in RESULTS if s == "HELD")
    total = len(RESULTS)
    print("w275_coverage_probes: %d/%d HELD" % (held, total))
    for name, status, detail in RESULTS:
        print("  %-6s %-4s %s" % (name, status, detail))
    if not green_check():
        print("GREEN CHECK FAILED")
        return 2
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
