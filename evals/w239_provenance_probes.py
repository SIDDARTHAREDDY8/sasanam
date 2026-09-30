"""Wave-239 AER-1 provenance non-upgrade probes (W239-7, red-first).

AER-1 -04 (deployed): "Verification MUST NOT upgrade a report into an
observation." This battery is the red-first harness for
gov/provenance_nonupgrade.py: provenance classes are named at emission,
surfaced with every field at the presentation seam, and chain/verify
operations preserve them exactly.

Provenance classes (closed vocabulary):
  LOGGED    -- a report that a log entry exists (claims "something was
               recorded"). Rank 0.
  EXECUTED  -- an observation that something actually happened. Rank 1.

The attack class: a verifier (or a sloppy presentation layer) that
promotes a LOGGED report to EXECUTED weight because "the chain
checked out". Chain validity proves the bytes were not altered; it
does NOT prove execution happened. The fix: every record names exactly
one class at emission, the presentation seam renders the class with
every field, and every verify operation returns the class it verified,
never a higher one.

Probes:
  provenance-logged-not-executed -- a LOGGED receipt pushed through the
      presentation seam with EXECUTED authority weight refuses
      provenance-upgraded; plain render labels every field with LOGGED.
  provenance-class-required -- emission without exactly one provenance
      class refuses provenance-class-missing.
  provenance-class-unknown-refused -- emission naming an unknown class
      refuses provenance-class-unknown.
  provenance-chain-preserves-class -- a chained LOGGED entry verifies as
      a chained report: chain validity never promotes the entry to
      EXECUTED (provenance-chain-class-mismatch on a class claim).
  provenance-step-delete-pinpoints -- workflow Merkle: deleting a step
      makes verification refuse provenance-step-break naming the
      index; surviving steps keep their class (no upgrade).
  provenance-step-reorder-pinpoints -- reordering steps refuses
      provenance-step-break naming the index, no class promotion.
  provenance-digest-tamper-refused -- editing a field of an emitted
      receipt refuses provenance-digest-mismatch on verify (no silent
      re-grade).
  provenance-executed-control -- an EXECUTED-class receipt with proper
      backing verifies and renders EXECUTED (positive control: the
      invariant is not a blanket demotion).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import hashlib
import json
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import provenance_nonupgrade as _pn
    HAVE_NEW_API = all(hasattr(_pn, n) for n in (
        "emit_receipt", "render", "present_with_authority",
        "verify_receipt", "chain_receipts", "verify_chain",
        "merkle_root", "commit_workflow", "verify_steps",
        "LOGGED", "EXECUTED", "ProvenanceError"))
except ImportError:
    _pn = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "provenance-logged-not-executed",
    "provenance-class-required",
    "provenance-class-unknown-refused",
    "provenance-chain-preserves-class",
    "provenance-step-delete-pinpoints",
    "provenance-step-reorder-pinpoints",
    "provenance-digest-tamper-refused",
    "provenance-executed-control",
]


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


def _expect_refusal(fn, code):
    """fn must raise ProvenanceError with .code == code; returns note."""
    try:
        fn()
    except _pn.ProvenanceError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_logged_not_executed():
    r = _pn.emit_receipt("LOGGED", {"action": "transfer", "amount": 10})
    rendered = _pn.render(r)
    # Every field carries the class.
    for field, value in r["fields"].items():
        assert rendered[field]["provenance"] == "LOGGED", field
        assert rendered[field]["value"] == value, field
    note = _expect_refusal(
        lambda: _pn.present_with_authority(r, "EXECUTED"),
        "provenance-upgraded")
    # Presenting at its own weight is conformant.
    _pn.present_with_authority(r, "LOGGED")
    return "LOGGED refused as EXECUTED (%s); own weight ok" % note


def _probe_class_required():
    note = _expect_refusal(
        lambda: _pn.emit_receipt(None, {"a": 1}), "provenance-class-missing")
    note2 = _expect_refusal(
        lambda: _pn.emit_receipt("", {"a": 1}), "provenance-class-missing")
    return "%s; %s" % (note, note2)


def _probe_class_unknown_refused():
    note = _expect_refusal(
        lambda: _pn.emit_receipt("OBSERVED", {"a": 1}),
        "provenance-class-unknown")
    note2 = _expect_refusal(
        lambda: _pn.emit_receipt("executed", {"a": 1}),
        "provenance-class-unknown")
    return "%s; %s (case-exact)" % (note, note2)


def _probe_chain_preserves_class():
    a = _pn.emit_receipt("LOGGED", {"step": "plan"})
    b = _pn.emit_receipt("LOGGED", {"step": "apply"})
    chain = _pn.chain_receipts([a, b])
    verdicts = _pn.verify_chain(chain)
    assert len(verdicts) == 2, verdicts
    for v in verdicts:
        assert v["verdict"] == "chained-report", v
        assert v["provenance"] == "LOGGED", v
    # Claiming the chain entry at a higher class refuses.
    def _claim():
        return _pn.present_with_authority(chain[1], "EXECUTED")
    note = _expect_refusal(_claim, "provenance-upgraded")
    return "chain verifies as chained-report x2 (%s)" % note


def _probe_step_delete_pinpoints():
    steps = [
        _pn.emit_receipt("EXECUTED", {"n": 0}),
        _pn.emit_receipt("EXECUTED", {"n": 1}),
        _pn.emit_receipt("EXECUTED", {"n": 2}),
    ]
    root = _pn.commit_workflow(steps)
    reduced = [steps[0], steps[2]]  # middle step deleted
    try:
        _pn.verify_steps(reduced, root)
    except _pn.ProvenanceError as exc:
        assert exc.code == "provenance-step-break", exc.code
        assert "index 1" in str(exc), "break must name the index: %s" % exc
    else:
        raise AssertionError("deletion not detected")
    # The survivors keep their own class: verify the two survivors alone
    # against their own commitment without class promotion.
    sub = _pn.commit_workflow(reduced)
    verdicts = _pn.verify_steps(reduced, sub)
    assert all(v["provenance"] == "EXECUTED" for v in verdicts), verdicts
    return "deletion pinned at index 1; survivors not promoted"


def _probe_step_reorder_pinpoints():
    steps = [
        _pn.emit_receipt("LOGGED", {"n": 0}),
        _pn.emit_receipt("LOGGED", {"n": 1}),
    ]
    root = _pn.commit_workflow(steps)
    try:
        _pn.verify_steps([steps[1], steps[0]], root)
    except _pn.ProvenanceError as exc:
        assert exc.code == "provenance-step-break", exc.code
        assert "index 0" in str(exc), "break must name the index: %s" % exc
    else:
        raise AssertionError("reorder not detected")
    return "reorder refused provenance-step-break at index 0"


def _probe_digest_tamper_refused():
    r = _pn.emit_receipt("EXECUTED", {"action": "deploy"})
    bad = dict(r)
    bad["fields"] = {"action": "destroy"}
    note = _expect_refusal(
        lambda: _pn.verify_receipt(bad), "provenance-digest-mismatch")
    # Untouched receipt verifies with its class unchanged.
    v = _pn.verify_receipt(r)
    assert v["provenance"] == "EXECUTED", v
    return "%s; clean verify keeps class" % note


def _probe_executed_control():
    r = _pn.emit_receipt("EXECUTED", {"action": "deploy"})
    v = _pn.verify_receipt(r)
    assert v["verdict"] == "verified-observation", v
    rendered = _pn.render(r)
    assert rendered["action"]["provenance"] == "EXECUTED", rendered
    _pn.present_with_authority(r, "EXECUTED")
    return "EXECUTED verifies and renders at its own weight"


_PROBES = {
    "provenance-logged-not-executed": _probe_logged_not_executed,
    "provenance-class-required": _probe_class_required,
    "provenance-class-unknown-refused": _probe_class_unknown_refused,
    "provenance-chain-preserves-class": _probe_chain_preserves_class,
    "provenance-step-delete-pinpoints": _probe_step_delete_pinpoints,
    "provenance-step-reorder-pinpoints": _probe_step_reorder_pinpoints,
    "provenance-digest-tamper-refused": _probe_digest_tamper_refused,
    "provenance-executed-control": _probe_executed_control,
}


def _run_green_checks():
    """Adjacent-seam sanity: no product-code regression. Depth-1 only;
    honors GOV_SKIP_GREEN=1 (never spawns another battery's main)."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import decision_codes as _dc
        for code in ("provenance-class-missing",
                     "provenance-class-unknown",
                     "provenance-upgraded",
                     "provenance-chain-class-mismatch",
                     "provenance-digest-mismatch",
                     "provenance-step-break"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-239 AER-1 provenance non-upgrade probes (new API: %s)"
          % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, note in results:
        print("%-42s %s  %s" % (name, verdict, note))
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR"
          % (held, gap, brk, err))
    for note in _run_green_checks():
        print("GREEN:", note)
    if not HAVE_NEW_API:
        return 2  # genuine red: the capability does not exist
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
