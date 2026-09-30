#!/usr/bin/env python3
"""Wave-242 exception-path TTL probes (W242-3, red-first).

ADAPT of draft-wei-capability-language-core -00, section 8.5: Wei's
Resolve forbids holding a cached allow past its discharge horizon.
Our gate-exception path had no TTL vocabulary: this battery probes
``gov/exception_ttl.py``.

Probes:
  exception-ttl-expired-refused -- exception with valid_until in the
      past is refused as ``gate-undecidable`` (the proposal's exact
      wording: the expired exception no longer shields anything, so
      the underlying undecidable verdict is refused fail-closed).
  exception-ttl-missing-valid-until -- a declaration without
      valid_until is malformed and refused as
      ``gate-exception-malformed``.
  exception-ttl-midflight-expiry -- an exception that is live at
      consume time but past its horizon on a second consume is
      refused as ``gate-undecidable`` (falsifies cache-past-horizon).
  exception-ttl-live-allows -- a live, scope-matching exception lets
      the gate allow an UNDECIDABLE verdict with a consumption
      receipt; a TAMPER verdict is still refused ``gate-tampered``
      (an exception never shields tamper).
  exception-ttl-scope-mismatch -- an exception for another scope is
      refused as ``gate-undecidable`` (no cross-scope shielding).

Stdlib only. Deterministic (clock arrives as an explicit ``now``).
No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import exception_ttl as _et
    HAVE_NEW_API = all(hasattr(_et, n) for n in (
        "declare_exception", "consume_exception",
        "gate_decide_with_exception", "ExceptionTTL"))
    from gov import gate_outcomes as _go
    HAVE_NEW_API = HAVE_NEW_API and hasattr(_go, "GateOutcomeError")
except ImportError:
    _et = None
    _go = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"


def _expect_refusal(fn, code):
    try:
        result = fn()
    except Exception as exc:
        got = getattr(exc, "code", None)
        assert got == code, \
            "expected refusal %r, got %r (%r)" % (code, got, exc)
        return "refused %s" % code
    raise AssertionError(
        "expected refusal %r, but allowed: %r" % (code, result))


def _probe_expired_refused():
    exc = _et.declare_exception(valid_until=1000,
                                reason="migration window",
                                scope="egress-gate")
    note = _expect_refusal(
        lambda: _et.gate_decide_with_exception(
            _go.Verdict(_go.UNDECIDABLE, "trust-root-missing"),
            exc, now=1001, scope="egress-gate"),
        "gate-undecidable")
    return "expired exception -> %s" % note


def _probe_missing_valid_until():
    return _expect_refusal(
        lambda: _et.declare_exception(valid_until=None,
                                      reason="no horizon",
                                      scope="egress-gate"),
        "gate-exception-malformed")


def _probe_midflight_expiry():
    exc = _et.declare_exception(valid_until=1000,
                                reason="migration window",
                                scope="egress-gate")
    receipt = _et.consume_exception(exc, now=999, scope="egress-gate")
    assert receipt.get("consumed") is True, \
        "live exception must consume, got %r" % (receipt,)
    note = _expect_refusal(
        lambda: _et.consume_exception(exc, now=1001, scope="egress-gate"),
        "gate-undecidable")
    return "live consume ok; later consume -> %s" % note


def _probe_live_allows():
    exc = _et.declare_exception(valid_until=1000,
                                reason="migration window",
                                scope="egress-gate")
    receipt = _et.gate_decide_with_exception(
        _go.Verdict(_go.UNDECIDABLE, "trust-root-missing"),
        exc, now=999, scope="egress-gate")
    assert isinstance(receipt, dict) and receipt.get("consumed") is True, \
        "exception path must return a consumption receipt, got %r" % (receipt,)
    # An exception never shields tamper: TAMPER with a live exception
    # still refuses gate-tampered.
    note = _expect_refusal(
        lambda: _et.gate_decide_with_exception(
            _go.Verdict(_go.TAMPER, ""),
            exc, now=999, scope="egress-gate"),
        "gate-tampered")
    return "undecidable allowed on receipt; %s" % note


def _probe_scope_mismatch():
    exc = _et.declare_exception(valid_until=1000,
                                reason="migration window",
                                scope="egress-gate")
    note = _expect_refusal(
        lambda: _et.consume_exception(exc, now=999, scope="other-gate"),
        "gate-undecidable")
    return "cross-scope exception -> %s" % note


_PROBES = {
    "exception-ttl-expired-refused": _probe_expired_refused,
    "exception-ttl-missing-valid-until": _probe_missing_valid_until,
    "exception-ttl-midflight-expiry": _probe_midflight_expiry,
    "exception-ttl-live-allows": _probe_live_allows,
    "exception-ttl-scope-mismatch": _probe_scope_mismatch,
}


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _run_green_checks():
    """Adjacent-seam sanity: no product-code regression. Depth-1 only;
    honors GOV_SKIP_GREEN=1 (never spawns another battery's main)."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import decision_codes as _dc
        _dc.code_for("gate-exception-malformed")
        # Existing gate vocabulary untouched.
        _dc.code_for("gate-undecidable")
        _dc.code_for("gate-tampered")
        notes.append("new refusal code mapped; gate vocabulary untouched")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-242 exception-path TTL probes (new API: %s)" % HAVE_NEW_API)
    results = []
    for name in _PROBES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, note in results:
        print("%-40s %s %s" % (name, verdict, note))
    print("HELD %d / GAP %d / BREAK %d / ERROR %d" % (held, gap, brk, err))
    for note in _run_green_checks():
        print("green-check: %s" % note)
    return 0 if (brk == 0 and err == 0) else 2


if __name__ == "__main__":
    sys.exit(main())
