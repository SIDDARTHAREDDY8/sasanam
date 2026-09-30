#!/usr/bin/env python3
"""Wave-242 three-outcome conformance probes (W242-6, red-first).

ADAPT of draft-farley-acta-signed-receipts -04, section 5.3
"Verification Outcomes" (staged-only draft, NOT on datatracker --
probe-oracle language only; this battery makes NO ACTA conformance
claim). The staged vocabulary says: valid / invalid / undecidable
must be distinguishable in every consumer-actionable output including
exit status; undecidable is never reported as invalid (nothing shown
false) nor valid (nothing shown true); causes are named.

This battery probes ``gov/three_outcome_conformance.py``:

  three-outcome-unsupported-alg-undecidable -- receipt naming an
      unsupported algorithm is undecidable with cause
      "algorithm-unknown", NOT invalid.
  three-outcome-embedded-key-undecidable -- receipt with an
      embedded-only key (ACTA section 9.5 forbids use) is
      undecidable with cause "trust-root-missing", NOT invalid
      even when the signature bytes fail: without a trust-anchored
      key we have not measured tamper.
  three-outcome-tampered-invalid -- supported algorithm,
      trust-anchored key, signature check fails: invalid
      (measured false), and refused by the gate.
  three-outcome-valid-pass -- supported algorithm, trust-anchored
      key, signature check passes: valid.
  three-outcome-unmeasured-undecidable -- signature_valid is None
      (not measured): undecidable with cause
      "evidence-incomplete", NOT valid.
  three-outcome-render-distinct -- every consumer-actionable
      output distinguishes the three outcomes: outcome strings
      are pairwise distinct and exit statuses are pairwise
      distinct (0 valid, 2 invalid, 4 undecidable).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import three_outcome_conformance as _oc
    HAVE_NEW_API = all(hasattr(_oc, n) for n in (
        "classify_receipt", "render_outcome",
        "EXIT_VALID", "EXIT_INVALID", "EXIT_UNDECIDABLE",
        "OUTCOME_VALID", "OUTCOME_INVALID", "OUTCOME_UNDECIDABLE",
        "ThreeOutcomeError"))
    from gov import gate_outcomes as _go
    HAVE_NEW_API = HAVE_NEW_API and hasattr(_go, "GateOutcomeError")
except ImportError:
    _oc = None
    _go = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"


def _classify(receipt):
    verdict = _oc.classify_receipt(receipt)
    assert isinstance(verdict, _go.Verdict), \
        "classify_receipt must return a gate_outcomes.Verdict, got %r" \
        % (verdict,)
    return verdict


def _probe_unsupported_alg():
    verdict = _classify({"algorithm": "dilithium-9000",
                         "key_source": "trust-anchor",
                         "signature_valid": True})
    assert verdict.outcome == _go.UNDECIDABLE, \
        "unsupported algorithm must be undecidable, got %r" \
        % (verdict.outcome,)
    assert verdict.reason == "algorithm-unknown", \
        "cause must be named 'algorithm-unknown', got %r" % (verdict.reason,)
    assert verdict.outcome != _go.TAMPER, \
        "undecidable must never be reported as invalid (tamper)"
    rendered = _oc.render_outcome(verdict)
    assert rendered["outcome"] == _oc.OUTCOME_UNDECIDABLE
    assert rendered["exit_status"] == _oc.EXIT_UNDECIDABLE == 4
    return "undecidable, cause algorithm-unknown, exit 4"


def _probe_embedded_key():
    verdict = _classify({"algorithm": "ed25519-rfc8032",
                         "key_source": "embedded",
                         "signature_valid": False})
    assert verdict.outcome == _go.UNDECIDABLE, \
        "embedded-only key must be undecidable, got %r" % (verdict.outcome,)
    assert verdict.reason == "trust-root-missing", \
        "cause must be named 'trust-root-missing', got %r" % (verdict.reason,)
    rendered = _oc.render_outcome(verdict)
    assert rendered["outcome"] == _oc.OUTCOME_UNDECIDABLE
    assert rendered["exit_status"] == _oc.EXIT_UNDECIDABLE
    return "undecidable, cause trust-root-missing, exit 4 (even on bad sig)"


def _probe_tampered_invalid():
    verdict = _classify({"algorithm": "ed25519-rfc8032",
                         "key_source": "trust-anchor",
                         "signature_valid": False})
    assert verdict.outcome == _go.TAMPER, (
        "tampered signature under a trust-anchored key must be "
        "invalid, got %r" % (verdict.outcome,))
    rendered = _oc.render_outcome(verdict)
    assert rendered["outcome"] == _oc.OUTCOME_INVALID
    assert rendered["exit_status"] == _oc.EXIT_INVALID == 2
    # The gate itself refuses the tampered verdict.
    try:
        _go.gate_decide(verdict)
    except _go.GateOutcomeError as exc:
        assert exc.code == "gate-tampered", \
            "gate must refuse with gate-tampered, got %r" % (exc.code,)
        return "invalid, exit 2, gate refuses gate-tampered"
    raise AssertionError("gate allowed a tampered verdict")


def _probe_valid_pass():
    verdict = _classify({"algorithm": "ed25519-rfc8032",
                         "key_source": "trust-anchor",
                         "signature_valid": True})
    assert verdict.outcome == _go.PASS, \
        "good signature under a trust-anchored key must be valid, got %r" \
        % (verdict.outcome,)
    rendered = _oc.render_outcome(verdict)
    assert rendered["outcome"] == _oc.OUTCOME_VALID
    assert rendered["exit_status"] == _oc.EXIT_VALID == 0
    return "valid, exit 0"


def _probe_unmeasured_undecidable():
    verdict = _classify({"algorithm": "ed25519-rfc8032",
                         "key_source": "trust-anchor",
                         "signature_valid": None})
    assert verdict.outcome == _go.UNDECIDABLE, \
        "unmeasured signature must be undecidable, got %r" % (verdict.outcome,)
    assert verdict.reason == "evidence-incomplete", \
        "cause must be named 'evidence-incomplete', got %r" % (verdict.reason,)
    rendered = _oc.render_outcome(verdict)
    assert rendered["outcome"] == _oc.OUTCOME_UNDECIDABLE
    assert rendered["exit_status"] == _oc.EXIT_UNDECIDABLE
    assert rendered["outcome"] != _oc.OUTCOME_VALID
    return "undecidable, cause evidence-incomplete, never reported valid"


def _probe_render_distinct():
    v_valid = _classify({"algorithm": "ed25519-rfc8032",
                         "key_source": "trust-anchor",
                         "signature_valid": True})
    v_invalid = _classify({"algorithm": "ed25519-rfc8032",
                           "key_source": "trust-anchor",
                           "signature_valid": False})
    v_undec = _classify({"algorithm": "dilithium-9000",
                         "key_source": "trust-anchor",
                         "signature_valid": True})
    r = [_oc.render_outcome(v) for v in (v_valid, v_invalid, v_undec)]
    outcomes = [x["outcome"] for x in r]
    exits = [x["exit_status"] for x in r]
    assert len(set(outcomes)) == 3, \
        "outcome strings must be pairwise distinct: %r" % (outcomes,)
    assert len(set(exits)) == 3, \
        "exit statuses must be pairwise distinct: %r" % (exits,)
    return "outcomes %r, exits %r" % (outcomes, exits)


_PROBES = {
    "three-outcome-unsupported-alg-undecidable": _probe_unsupported_alg,
    "three-outcome-embedded-key-undecidable": _probe_embedded_key,
    "three-outcome-tampered-invalid": _probe_tampered_invalid,
    "three-outcome-valid-pass": _probe_valid_pass,
    "three-outcome-unmeasured-undecidable": _probe_unmeasured_undecidable,
    "three-outcome-render-distinct": _probe_render_distinct,
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
        from gov import gate_outcomes as _g
        # The three-outcome gate contract is untouched by the oracle.
        assert _g.gate_decide(_g.Verdict(_g.PASS, "")) is True
        assert _g.OUTCOMES == (_g.PASS, _g.TAMPER, _g.UNDECIDABLE)
        assert "unsupported-profile" in _g.UNDECIDABLE_REASONS
        notes.append("gate_outcomes contract intact")
    except Exception as exc:  # noqa: BLE001
        notes.append("gate contract check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-242 three-outcome conformance probes (new API: %s)"
          % HAVE_NEW_API)
    results = []
    for name in _PROBES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, note in results:
        print("%-46s %s %s" % (name, verdict, note))
    print("HELD %d / GAP %d / BREAK %d / ERROR %d" % (held, gap, brk, err))
    for note in _run_green_checks():
        print("green-check: %s" % note)
    return 0 if (brk == 0 and err == 0) else 2


if __name__ == "__main__":
    sys.exit(main())
