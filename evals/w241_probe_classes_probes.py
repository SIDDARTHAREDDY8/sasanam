"""Wave-241 probe-class lanes (red-first).

W241-6 — onedoor ND-038/ND-048 probe classes (ADAPT). Re-derived prose
only: the actual onedoor LICENSE file was not directly read, so no
code, fixtures, or test vectors are reused from that project.

  ND-038: obligations declared on a permit but silently ignored at
      execution. Our invariant: a permit's declared obligations must be
      evidenced as fulfilled before settlement; an unfulfilled
      obligation refuses settlement with obligation-unfulfilled.
  ND-048: obfuscated command construction (shell string-splicing,
      quote-juggling, sh -c wrapping) defeating parameter allowlists.
      Our invariant: parameters are canonicalized before the
      allowlist/denylist comparison; a command that passes the raw
      comparison but matches a denied pattern after canonicalization
      refuses with parameter-obfuscation.

W241-5 — Reddy expected-participants audit (WATCH, audit-first, NO
crypto construction). Per Reddy draft aggregate-signatures §11
verbatim: the aggregate mechanism proves which hops *signed*, not that
every *expected* hop was included — without a destination policy
naming the workload, omission is not detectable. Our invariant: a
declared expected-participants policy names the expected signers per
workload/scope; chain verification refuses expected-participant-missing
when a declared expected participant has no signed hop, and refuses
unexpected-participant-signed when a signed hop is not declared
expected. No BLS/aggregate crypto construction (deferred to WG
adoption); the aggregate repo still does not exist.

Probes:
  obligation-unfulfilled-refused -- permit declares obligation "notify",
      execution evidence lacks it -> refuse obligation-unfulfilled.
  obligation-fulfilled-ok -- same permit with the obligation evidenced
      -> settles (positive control).
  obfuscated-command-refused -- sh -c "\"ec\"ho /etc/passwd" passes the
      raw allowlist {"echo"} but canonicalizes to "echo /etc/passwd"
      which matches the denied parameter pattern -> refuse
      parameter-obfuscation.
  plain-command-allowed-ok -- plain "echo hello" allowed (positive
      control).
  expected-participant-missing-refused -- delegation chain declares
      {orchestrator, tool-runner, auditor} but the tool-runner hop is
      missing -> refuse expected-participant-missing.
  unexpected-participant-signed-refused -- chain carries a signed hop
      from "sidecar" not in the declared set -> refuse
      unexpected-participant-signed.
  expected-participants-full-chain-ok -- all declared expected hops
      signed, no extras -> verifies (positive control).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_OBLIG = False
try:
    from gov import obligation_binding as _ob
    HAVE_OBLIG = all(hasattr(_ob, n) for n in (
        "declare_obligations", "evidence_fulfilled", "verify_obligations",
        "settle_permit", "ObligationError"))
except ImportError:
    _ob = None

HAVE_PARAM = False
try:
    from gov import parameter_canonicalization as _pc
    HAVE_PARAM = all(hasattr(_pc, n) for n in (
        "canonicalize", "check_parameters", "ParameterError"))
except ImportError:
    _pc = None

HAVE_EXPECT = False
try:
    from gov import expected_participants as _ep
    HAVE_EXPECT = all(hasattr(_ep, n) for n in (
        "ExpectedParticipantsPolicy", "verify_delegation_chain",
        "ExpectedParticipantsError"))
except ImportError:
    _ep = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "obligation-unfulfilled-refused",
    "obligation-fulfilled-ok",
    "obfuscated-command-refused",
    "plain-command-allowed-ok",
    "expected-participant-missing-refused",
    "unexpected-participant-signed-refused",
    "expected-participants-full-chain-ok",
]


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


# ---------------------------------------------------------------------------
# ND-038 probes
# ---------------------------------------------------------------------------

def _probe_obligation_unfulfilled_refused():
    permit = _ob.declare_obligations("permit-1", ["notify-operator",
                                                  "write-receipt"])
    # Execution evidence only fulfills "write-receipt"; "notify-operator"
    # was silently ignored.
    evidence = _ob.evidence_fulfilled({"write-receipt"})
    try:
        _ob.verify_obligations(permit, evidence)
    except _ob.ObligationError as exc:
        assert exc.code == "obligation-unfulfilled", exc.code
        assert "notify-operator" in exc.detail, exc.detail
        return "refused obligation-unfulfilled naming notify-operator"
    raise AssertionError("unfulfilled obligation passed verification")


def _probe_obligation_fulfilled_ok():
    permit = _ob.declare_obligations("permit-1", ["notify-operator"])
    evidence = _ob.evidence_fulfilled({"notify-operator"})
    _ob.verify_obligations(permit, evidence)
    receipt = _ob.settle_permit(permit, evidence)
    assert receipt["permit_id"] == "permit-1", receipt
    assert receipt["obligations_fulfilled"] == ["notify-operator"], receipt
    return "obligations evidenced: settlement allowed"


# ---------------------------------------------------------------------------
# ND-048 probes
# ---------------------------------------------------------------------------

def _probe_obfuscated_command_refused():
    # Raw string "sh -c \"ec\"ho /etc/passwd" would survive a naive
    # startswith/contains allowlist for "echo"; after canonicalization it
    # is "echo /etc/passwd", which the denied parameter pattern bans.
    try:
        _pc.check_parameters(
            command='sh -c "ec"ho /etc/passwd',
            allowed_prefixes=("echo",),
            denied_substrings=("/etc/passwd",),
        )
    except _pc.ParameterError as exc:
        assert exc.code == "parameter-obfuscation", exc.code
        return "refused parameter-obfuscation on spliced sh -c payload"
    raise AssertionError("obfuscated command passed the allowlist")


def _probe_plain_command_allowed_ok():
    verdict = _pc.check_parameters(
        command="echo hello",
        allowed_prefixes=("echo",),
        denied_substrings=("/etc/passwd",),
    )
    assert verdict["allowed"] is True, verdict
    assert verdict["canonical"] == "echo hello", verdict
    return "plain command allowed after canonicalization"


# ---------------------------------------------------------------------------
# W241-5 probes
# ---------------------------------------------------------------------------

def _policy():
    return _ep.ExpectedParticipantsPolicy({
        "billing-run": ("orchestrator", "tool-runner", "auditor"),
    })


def _probe_expected_participant_missing_refused():
    chain = [
        {"participant_id": "orchestrator", "signature_present": True},
        {"participant_id": "auditor", "signature_present": True},
        # "tool-runner" signed nothing: omission.
    ]
    try:
        _ep.verify_delegation_chain(chain, _policy(), "billing-run")
    except _ep.ExpectedParticipantsError as exc:
        assert exc.code == "expected-participant-missing", exc.code
        assert "tool-runner" in exc.detail, exc.detail
        return "refused expected-participant-missing naming tool-runner"
    raise AssertionError("omitted expected participant went undetected")


def _probe_unexpected_participant_signed_refused():
    chain = [
        {"participant_id": "orchestrator", "signature_present": True},
        {"participant_id": "tool-runner", "signature_present": True},
        {"participant_id": "auditor", "signature_present": True},
        {"participant_id": "sidecar", "signature_present": True},
    ]
    try:
        _ep.verify_delegation_chain(chain, _policy(), "billing-run")
    except _ep.ExpectedParticipantsError as exc:
        assert exc.code == "unexpected-participant-signed", exc.code
        assert "sidecar" in exc.detail, exc.detail
        return "refused unexpected-participant-signed naming sidecar"
    raise AssertionError("undeclared signed hop went undetected")


def _probe_expected_participants_full_chain_ok():
    chain = [
        {"participant_id": "orchestrator", "signature_present": True},
        {"participant_id": "tool-runner", "signature_present": True},
        {"participant_id": "auditor", "signature_present": True},
    ]
    verdict = _ep.verify_delegation_chain(chain, _policy(), "billing-run")
    assert verdict["ok"] is True, verdict
    assert verdict["verified_participants"] == (
        "orchestrator", "tool-runner", "auditor"), verdict
    return "all declared expected hops signed; no extras"


_PROBES = {
    "obligation-unfulfilled-refused": (_probe_obligation_unfulfilled_refused,
                                       HAVE_OBLIG),
    "obligation-fulfilled-ok": (_probe_obligation_fulfilled_ok, HAVE_OBLIG),
    "obfuscated-command-refused": (_probe_obfuscated_command_refused,
                                   HAVE_PARAM),
    "plain-command-allowed-ok": (_probe_plain_command_allowed_ok, HAVE_PARAM),
    "expected-participant-missing-refused": (
        _probe_expected_participant_missing_refused, HAVE_EXPECT),
    "unexpected-participant-signed-refused": (
        _probe_unexpected_participant_signed_refused, HAVE_EXPECT),
    "expected-participants-full-chain-ok": (
        _probe_expected_participants_full_chain_ok, HAVE_EXPECT),
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
        for code in ("obligation-unfulfilled", "parameter-obfuscation",
                     "expected-participant-missing",
                     "unexpected-participant-signed"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-241 probe-class probes (obligations: %s, params: %s, "
          "expected-participants: %s)"
          % (HAVE_OBLIG, HAVE_PARAM, HAVE_EXPECT))
    held = gap = 0
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        if status == "HELD":
            held += 1
        elif status == "GAP":
            gap += 1
        print("%-42s %s %s" % (name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    print("summary: %d HELD / %d GAP / %d total"
          % (held, gap, len(PROBE_NAMES)))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
