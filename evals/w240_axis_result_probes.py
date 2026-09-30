"""Wave-240 APS -04 axis/result model probes (W240-2, red-first).

Adapted from draft-pidlisnyi-aps -04 (read in full, prose re-derived;
IETF Trust -> no verbatim copying): the chain-verification axis carries
four terms -- valid / invalid / indeterminate / unsupported -- each with
a mandatory reason code. "Unsupported is carried as unsupported and is
neither erased nor folded into any other value on any axis."

The taxonomy decision (binding, from the wave-239 prospectus): the
per-axis verification result keeps all four terms; the top-level gate
keeps THREE outcomes (PASS/TAMPER/UNDECIDABLE, wave-237). ``unsupported``
folds into UNDECIDABLE with a dedicated reason code
("unsupported-profile") inside the UNDECIDABLE_REASONS vocabulary, and
the ceiling rule maps parser/implementation limits to indeterminate
naming the limit -- never invalid, never TAMPER.

Attack classes:
  axis-erasure -- a profile whose grammar the verifier does not
      implement gets silently dropped or folded into valid/tamper.
  ceiling-conflation -- a verifier depth/wire ceiling surfaces as
      tamper/invalid, turning a cautious limit into an accusation.
  unestablished-contribution -- a checker without the required state
      store (e.g. approval-state) still lets the aggregate read valid.
  revocation-upgrade -- unknown revocation state treated as active, or
      suspension presented as revocation.

Probes:
  axis-unsupported-fold -- an unregistered receipt profile yields a
      per-axis UNSUPPORTED verdict carried with its reason code; the
      gate verdict is UNDECIDABLE with reason "unsupported-profile" --
      never PASS, never TAMPER, and the axis result is not erased.
  axis-ceiling-indeterminate -- a chain past a configured depth ceiling
      aggregates to INDETERMINATE naming the ceiling; the gate verdict
      is UNDECIDABLE with reason "verifier-limit-reached" -- never
      TAMPER, never invalid.
  axis-syntax-violation-invalid -- a genuine syntax violation observed
      first still aggregates to INVALID (the ceiling rule does not
      soften real defects).
  axis-unestablished-not-valid -- a checker lacking the approval-state
      store marks the axis unestablished; the aggregate is not valid.
  axis-revocation-unknown-not-active -- unknown revocation state is
      classified not-active (refusal code revocation-state-unknown).
  axis-suspension-not-revocation -- presenting suspension as revocation
      refuses revocation-category-error.
  axis-valid-control -- a fully established, ceiling-clean chain of
      valid axes aggregates VALID and the gate verdict is PASS.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import axis_result_model as _ax
    from gov import gate_outcomes as _go
    HAVE_NEW_API = all(hasattr(_ax, n) for n in (
        "VALID", "INVALID", "INDETERMINATE", "UNSUPPORTED",
        "AxisVerdict", "ChainResult", "aggregate", "to_gate_verdict",
        "require_valid", "mark_unestablished", "ceiling",
        "check_revocation", "AxisModelError",
        "AXIS_UNESTABLISHED", "AXIS_CEILING_HIT", "AXIS_INDETERMINATE",
        "AXIS_INVALID",
        "REVOCATION_STATE_UNKNOWN", "REVOCATION_CATEGORY_ERROR"))
except ImportError:
    _ax = None

PROBE_NAMES = [
    "axis-unsupported-fold",
    "axis-ceiling-indeterminate",
    "axis-syntax-violation-invalid",
    "axis-unestablished-not-valid",
    "axis-revocation-unknown-not-active",
    "axis-suspension-not-revocation",
    "axis-valid-control",
]


def probe_axis_unsupported_fold():
    v = _ax.AxisVerdict("profile:passport-v9", _ax.UNSUPPORTED,
                        "unsupported-profile",
                        detail="verifier implements passport-v4 only")
    assert v.term == _ax.UNSUPPORTED
    assert v.reason == "unsupported-profile"
    chain = _ax.aggregate([v])
    assert chain.term == _ax.UNSUPPORTED, chain.term
    gate = _ax.to_gate_verdict(chain)
    assert gate.outcome == _go.UNDECIDABLE, gate.outcome
    assert gate.reason == "unsupported-profile", gate.reason
    # The dedicated reason is inside the gate vocabulary, so the gate
    # refuses gate-undecidable -- not gate-verdict-unreasoned and not
    # gate-tampered.
    try:
        _go.gate_decide(gate)
    except _go.GateOutcomeError as exc:
        assert exc.code == "gate-undecidable", exc.code
    else:
        raise AssertionError("gate allowed an unsupported chain")


def probe_axis_ceiling_indeterminate():
    v = _ax.ceiling("chain:delegation", "delegation-depth-64")
    assert v.term == _ax.INDETERMINATE
    assert "delegation-depth-64" in v.reason
    chain = _ax.aggregate([v])
    assert chain.term == _ax.INDETERMINATE, chain.term
    gate = _ax.to_gate_verdict(chain)
    assert gate.outcome == _go.UNDECIDABLE, gate.outcome
    assert gate.reason == "verifier-limit-reached", gate.reason
    # The gate must refuse it as undecidable ("could not verify"),
    # never as tampered.
    try:
        _go.gate_decide(gate)
    except _go.GateOutcomeError as exc:
        assert exc.code == "gate-undecidable", exc.code
        assert "could not verify" in (exc.detail or "").lower()
        assert "tamper" not in (exc.detail or "").lower()
    else:
        raise AssertionError("gate allowed a ceiling-hit chain")


def probe_axis_syntax_violation_invalid():
    v = _ax.AxisVerdict("record:syntax", _ax.INVALID,
                        "duplicate-member",
                        detail="duplicate member 'agent' in record")
    chain = _ax.aggregate([v,
                           _ax.ceiling("chain:delegation",
                                       "delegation-depth-64")])
    # A syntax violation observed first stays invalid: the ceiling rule
    # does not soften a real defect.
    assert chain.term == _ax.INVALID, chain.term
    gate = _ax.to_gate_verdict(chain)
    assert gate.outcome == _go.TAMPER, gate.outcome


def probe_axis_unestablished_not_valid():
    v = _ax.mark_unestablished("approval-state",
                               detail="checker has no approval-state store")
    chain = _ax.aggregate([v])
    assert chain.term != _ax.VALID, chain.term
    try:
        _ax.require_valid(chain)
    except _ax.AxisModelError as exc:
        assert exc.code == _ax.AXIS_UNESTABLISHED, exc.code
    else:
        raise AssertionError("require_valid passed an unestablished chain")


def probe_axis_revocation_unknown_not_active():
    outcome = _ax.check_revocation(claimed="revoked", observed="unknown")
    assert outcome.is_active is False, outcome.is_active
    assert outcome.code == _ax.REVOCATION_STATE_UNKNOWN, outcome.code


def probe_axis_suspension_not_revocation():
    try:
        _ax.check_revocation(claimed="revoked", observed="suspended")
    except _ax.AxisModelError as exc:
        assert exc.code == _ax.REVOCATION_CATEGORY_ERROR, exc.code
    else:
        raise AssertionError("suspension presented as revocation passed")


def probe_axis_valid_control():
    chain = _ax.aggregate([
        _ax.AxisVerdict("record:syntax", _ax.VALID, "syntax-ok"),
        _ax.AxisVerdict("chain:delegation", _ax.VALID, "chain-ok"),
        _ax.AxisVerdict("revocation:state", _ax.VALID, "not-revoked"),
    ])
    assert chain.term == _ax.VALID, chain.term
    _ax.require_valid(chain)
    gate = _ax.to_gate_verdict(chain)
    assert gate.outcome == _go.PASS, gate.outcome


PROBES = {
    "axis-unsupported-fold": probe_axis_unsupported_fold,
    "axis-ceiling-indeterminate": probe_axis_ceiling_indeterminate,
    "axis-syntax-violation-invalid": probe_axis_syntax_violation_invalid,
    "axis-unestablished-not-valid": probe_axis_unestablished_not_valid,
    "axis-revocation-unknown-not-active":
        probe_axis_revocation_unknown_not_active,
    "axis-suspension-not-revocation": probe_axis_suspension_not_revocation,
    "axis-valid-control": probe_axis_valid_control,
}


def main():
    held, gap, broke, errors = 0, 0, 0, 0
    for name in PROBE_NAMES:
        fn = PROBES[name]
        if not HAVE_NEW_API:
            gap += 1
            print("GAP   %s: module not implemented" % name)
            continue
        try:
            fn()
        except AssertionError as exc:
            broke += 1
            print("BREAK %s: %s" % (name, exc))
        except Exception:
            errors += 1
            print("ERROR %s:\n%s" % (name, traceback.format_exc()))
        else:
            held += 1
            print("HELD  %s" % name)
    print("%d HELD / %d GAP / %d BREAK / %d ERROR"
          % (held, gap, broke, errors))
    return 0 if (broke == 0 and errors == 0) else 2


if __name__ == "__main__":
    sys.exit(main())
