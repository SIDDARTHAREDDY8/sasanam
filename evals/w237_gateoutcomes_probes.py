#!/usr/bin/env python3
"""Wave-237 lane A: three-outcome gate rule (farley ACTA -04 section 5.3).

A verifier may return one of three outcomes: PASS, TAMPER, or UNDECIDABLE.
UNDECIDABLE is *failure to verify* -- missing trust material, unknown
algorithm, truncated or incomplete evidence -- and is neither "it looks
fine" nor "it was tampered". The gate rule:

* PASS        -> allow.
* TAMPER      -> refuse ``gate-tampered``.
* UNDECIDABLE -> refuse ``gate-undecidable``. The undecidable refusal code
  is DISTINCT from the tamper code, and the human message says "could not
  verify", never "was tampered".

A verifier that returns UNDECIDABLE without naming WHY (the reason is
mandatory and comes from a closed vocabulary) is refused by the gate
contract itself: ``gate-verdict-unreasoned``.

A gate that PASSES on undecidable (allow-when-unverified) fails a
compliance self-check: ``gate_selfcheck`` runs a probe UNDECIDABLE verdict
through the gate and refuses ``gate-undecidable-allowed`` when the gate
allows it, declaring the gate non-compliant.

Seams under test:
* gov/gate_outcomes.py -- Verdict, UNDECIDABLE_REASONS, gate_decide,
  gate_selfcheck, GateOutcomeError codes.

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-236 HEAD 9a725ce5fac37b95a2502eaebebfc33e7a8fb0d0.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g237a
  TMPDIR=/var/tmp/g237a ~/workspace/.gov-venv/bin/python evals/w237_gateoutcomes_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

HAVE_NEW_API = False
try:
    from gov import gate_outcomes as _go
    HAVE_NEW_API = all(hasattr(_go, n) for n in (
        "Verdict", "UNDECIDABLE_REASONS", "gate_decide", "gate_selfcheck",
        "GateOutcomeError"))
except ImportError:
    _go = None

PROBE_NAMES = [
    "gateoutcomes-undecidable-refused-named",
    "gateoutcomes-tamper-refused",
    "gateoutcomes-unreasoned-undecidable-refused",
    "gateoutcomes-unknown-reason-refused",
    "gateoutcomes-lenient-gate-noncompliant",
    "gateoutcomes-strict-gate-compliant",
    "gateoutcomes-legitimate-pass-allowed",
]


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return (name, "GAP", "module absent on base")
    t0 = time.time()
    try:
        verdict, note = fn()
    except Exception:  # noqa: BLE001
        return (name, "ERROR", traceback.format_exc(limit=3).strip())
    return (name, "HELD" if verdict else "BREAK",
            "%s (%.1fms)" % (note, 1000 * (time.time() - t0)))


def _undecidable(reason):
    return _go.Verdict(outcome="undecidable", reason=reason)


def probe_undecidable_named():
    # UNDECIDABLE is a failure to verify: the gate must refuse with the
    # DISTINCT gate-undecidable code, the human detail must say
    # "could not verify", and must never say "tampered".
    try:
        _go.gate_decide(_undecidable("trust-root-missing"))
    except _go.GateOutcomeError as exc:
        detail = exc.detail or ""
        ok = (exc.code == "gate-undecidable"
              and "could not verify" in detail.lower()
              and "tamper" not in detail.lower())
        return ok, "refused %s; detail names failure-to-verify" % exc.code
    return False, "UNDECIDABLE verdict was ALLOWED"


def probe_tamper():
    # TAMPER must refuse with the tamper code, distinct from undecidable.
    try:
        _go.gate_decide(_go.Verdict(outcome="tamper",
                                   reason="digest-mismatch-observed"))
    except _go.GateOutcomeError as exc:
        ok = (exc.code == "gate-tampered"
              and exc.code != "gate-undecidable")
        return ok, "refused %s (distinct from undecidable)" % exc.code
    return False, "TAMPER verdict was ALLOWED"


def probe_unreasoned():
    # An UNDECIDABLE verdict with NO reason is refused by the gate
    # contract itself: the reason vocabulary is mandatory, not advisory.
    try:
        _go.gate_decide(_undecidable(""))
    except _go.GateOutcomeError as exc:
        ok = exc.code == "gate-verdict-unreasoned"
        return ok, "unreasoned undecidable refused with %s" % exc.code
    return False, "unreasoned UNDECIDABLE was ACCEPTED"


def probe_unknown_reason():
    # A reason outside the mandatory closed vocabulary is the same
    # contract failure as no reason: refuse, never invent meaning.
    try:
        _go.gate_decide(_undecidable("the-moon-was-in-retrograde"))
    except _go.GateOutcomeError as exc:
        ok = exc.code == "gate-verdict-unreasoned"
        return ok, "off-vocabulary reason refused with %s" % exc.code
    return False, "off-vocabulary reason was ACCEPTED"


def _lenient_gate(verdict):
    # Allow-when-unverified: the exact failure mode the self-check
    # exists to catch.
    if verdict.outcome == "undecidable":
        return True  # bug: should refuse
    try:
        return _go.gate_decide(verdict)
    except _go.GateOutcomeError:
        return False


def _strict_gate(verdict):
    return _go.gate_decide(verdict)


def probe_lenient_gate():
    # A gate that passes on undecidable fails the compliance self-check:
    # gate-undecidable-allowed names the non-compliance.
    try:
        _go.gate_selfcheck(_lenient_gate)
    except _go.GateOutcomeError as exc:
        ok = exc.code == "gate-undecidable-allowed"
        return ok, "lenient gate declared non-compliant with %s" % exc.code
    return False, "lenient gate PASSED the self-check"


def probe_strict_gate():
    # A compliant gate (pass on pass, refuse on tamper/undecidable)
    # passes the self-check without refusing: the verdict mapping
    # carries ok=True (refusals are the return path, not bare strings).
    try:
        result = _go.gate_selfcheck(_strict_gate)
    except _go.GateOutcomeError as exc:
        return False, "strict gate wrongly refused: %s" % exc.code
    ok = (isinstance(result, dict) and result.get("ok") is True
          and result.get("compliance") == "compliant")
    return ok, "strict gate declared compliant via verdict mapping"


def probe_legitimate_pass():
    # The control: a PASS verdict still allows through the gate.
    try:
        allowed = _go.gate_decide(_go.Verdict(outcome="pass", reason=""))
    except _go.GateOutcomeError as exc:
        return False, "PASS wrongly refused with %s" % exc.code
    return allowed is True, "PASS allowed"


_PROBES = {
    "gateoutcomes-undecidable-refused-named": probe_undecidable_named,
    "gateoutcomes-tamper-refused": probe_tamper,
    "gateoutcomes-unreasoned-undecidable-refused": probe_unreasoned,
    "gateoutcomes-unknown-reason-refused": probe_unknown_reason,
    "gateoutcomes-lenient-gate-noncompliant": probe_lenient_gate,
    "gateoutcomes-strict-gate-compliant": probe_strict_gate,
    "gateoutcomes-legitimate-pass-allowed": probe_legitimate_pass,
}


def main():
    print("wave-237 three-outcome gate rule probes "
          "(new API: %s)" % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, note in results:
        print("%-48s %s  %s" % (name, verdict, note))
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR"
          % (held, gap, brk, err))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
