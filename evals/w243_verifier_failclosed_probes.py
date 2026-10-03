"""Wave-243 verifier-side fail-closed probes (red-first).

W243-7 (jackson wimse-evaluation, ADAPT) + W243-8 (sankarshan ARPA,
ADAPT): the verifier's half of delegation-chain evaluation --
proof verification is not authority, and verdicts name the pinned
policy input that produced them.

  source-unavailable-refused -- chain_source unavailable -> refuse
      chain-source-unavailable (never allow).
  stale-source-verdict -- chain_source stale -> explicit verdict
      "stale" with code chain-source-stale (never a silent pass).
  verifier-input-blindness-falsified -- two verifiers with different
      pinned policy inputs both get valid verdicts, each naming its
      own input.
  proof-verifies-authority-revoked -- signature present, authority
      revoked -> refuse authority-stale (proof pass-through defect).
  proof-verifies-authority-expired -- signature present, authority
      expired -> refuse authority-stale.
  authority-source-unavailable -- authority_id not in the store ->
      refuse authority-unavailable (deterministic fail-safe, not a
      retry loop).
  lapsed-draft-citation -- minted after the emirdag lapse citing the
      draft -> refuse stale-authority (routed through
      gov.stale_authority, never passed on legacy text).
  prelapse-receipt-not-fresh -- minted before the lapse citing the
      draft -> refuse authority-stale (downgraded provenance is not
      fresh authority).
  malformed-input-fails-closed -- empty chain and policy without
      verifier_policy_input -> refuse verifier-input-malformed.
  expected-participant-audit -- declared expected participant with
      no signed hop -> expected-participant-missing via
      gov.expected_participants (reuse, not duplication).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback
from datetime import datetime, timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_VF = False
try:
    from gov import verifier_failclosed as _vf
    HAVE_VF = all(hasattr(_vf, n) for n in (
        "evaluate_delegation_chain", "VerifierFailclosedError"))
except ImportError:
    _vf = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "source-unavailable-refused",
    "stale-source-verdict",
    "verifier-input-blindness-falsified",
    "proof-verifies-authority-revoked",
    "proof-verifies-authority-expired",
    "authority-source-unavailable",
    "lapsed-draft-citation",
    "prelapse-receipt-not-fresh",
    "malformed-input-fails-closed",
    "expected-participant-audit",
]


def _run_probe(name, fn, have):
    if not have:
        # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
        # gap-demonstrated evidence in the note.
        return name, "BREAK", "GAP: capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _base_policy(**over):
    policy = {"verifier_policy_input": "pin:default-v1"}
    policy.update(over)
    return policy


def _hop(participant="agent-a", signed=True, authority_id=None,
         minted_at=None):
    hop = {"participant_id": participant, "signature_present": signed}
    if authority_id is not None:
        hop["authority_id"] = authority_id
    if minted_at is not None:
        hop["authority_minted_at"] = minted_at
    return hop


def _ts(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).replace(
        tzinfo=timezone.utc)


def _expect_refusal(fn, code):
    try:
        fn()
    except _vf.VerifierFailclosedError as exc:
        assert exc.code == code, "want %s, got %s" % (code, exc.code)
        return exc
    raise AssertionError("expected refusal %s, got allow" % (code,))


def _probe_source_unavailable_refused():
    policy = _base_policy(chain_source={"available": False})
    _expect_refusal(
        lambda: _vf.evaluate_delegation_chain([_hop()], policy),
        "chain-source-unavailable")
    return "unavailable chain source fails closed, never allows"


def _probe_stale_source_verdict():
    policy = _base_policy(chain_source={"stale": True})
    verdict = _vf.evaluate_delegation_chain([_hop()], policy)
    assert verdict["verdict"] == "stale", verdict
    assert verdict["code"] == "chain-source-stale", verdict
    assert verdict["verifier_policy_input"] == "pin:default-v1", verdict
    return "stale source input yields an explicit stale verdict"


def _probe_verifier_input_blindness_falsified():
    chain = [_hop("agent-a"), _hop("agent-b")]
    v1 = _vf.evaluate_delegation_chain(chain,
                                      _base_policy(
                                          verifier_policy_input="pin:a"))
    v2 = _vf.evaluate_delegation_chain(chain,
                                      _base_policy(
                                          verifier_policy_input="pin:b"))
    assert v1["verdict"] == "allow", v1
    assert v2["verdict"] == "allow", v2
    assert v1["verifier_policy_input"] == "pin:a", v1
    assert v2["verifier_policy_input"] == "pin:b", v2
    return "both verdicts valid, each names its own pinned policy input"


def _probe_proof_verifies_authority_revoked():
    policy = _base_policy(
        authority_store={"auth-x": {"status": "revoked"}})
    chain = [_hop("agent-a", signed=True, authority_id="auth-x")]
    _expect_refusal(
        lambda: _vf.evaluate_delegation_chain(chain, policy),
        "authority-stale")
    return "verified proof with revoked authority is refused"


def _probe_proof_verifies_authority_expired():
    policy = _base_policy(
        authority_store={"auth-x": {"status": "expired"}})
    chain = [_hop("agent-a", signed=True, authority_id="auth-x")]
    _expect_refusal(
        lambda: _vf.evaluate_delegation_chain(chain, policy),
        "authority-stale")
    return "verified proof with expired authority is refused"


def _probe_authority_source_unavailable():
    policy = _base_policy(authority_store={})
    chain = [_hop("agent-a", signed=True, authority_id="auth-missing")]
    _expect_refusal(
        lambda: _vf.evaluate_delegation_chain(chain, policy),
        "authority-unavailable")
    return "unknown authority id is unavailable, deterministic fail-safe"


def _probe_lapsed_draft_citation():
    chain = [_hop("agent-a", signed=True,
                  authority_id="draft-emirdag-scitt-ai-agent-execution-00",
                  minted_at=_ts("2026-10-14T00:00:00Z"))]
    exc = _expect_refusal(
        lambda: _vf.evaluate_delegation_chain(chain, _base_policy()),
        "stale-authority")
    assert "2026-10-13" in exc.detail, exc.detail
    return "post-lapse draft citation refuses stale-authority"


def _probe_prelapse_receipt_not_fresh():
    chain = [_hop("agent-a", signed=True,
                  authority_id="draft-emirdag-scitt-ai-agent-execution-00",
                  minted_at=_ts("2026-10-01T00:00:00Z"))]
    _expect_refusal(
        lambda: _vf.evaluate_delegation_chain(chain, _base_policy()),
        "authority-stale")
    return "pre-lapse receipt re-read as live authority is stale"


def _probe_malformed_input_fails_closed():
    _expect_refusal(
        lambda: _vf.evaluate_delegation_chain([], _base_policy()),
        "verifier-input-malformed")
    bad = {"not_policy_input": "x"}
    _expect_refusal(
        lambda: _vf.evaluate_delegation_chain([_hop()], bad),
        "verifier-input-malformed")
    return "empty chain and unpinned policy fail closed"


def _probe_expected_participant_audit():
    policy = _base_policy(
        expected_workload="wl-1",
        expected_declarations={"wl-1": ("agent-a", "agent-b")})
    chain = [_hop("agent-a")]
    try:
        _vf.evaluate_delegation_chain(chain, policy)
    except Exception as exc:  # noqa: BLE001
        assert getattr(exc, "code", None) == \
            "expected-participant-missing", repr(exc)
        return "declared missing participant refused via expected_participants"
    raise AssertionError("missing expected participant passed")


_PROBES = {
    "source-unavailable-refused": (_probe_source_unavailable_refused,
                                   HAVE_VF),
    "stale-source-verdict": (_probe_stale_source_verdict, HAVE_VF),
    "verifier-input-blindness-falsified":
        (_probe_verifier_input_blindness_falsified, HAVE_VF),
    "proof-verifies-authority-revoked":
        (_probe_proof_verifies_authority_revoked, HAVE_VF),
    "proof-verifies-authority-expired":
        (_probe_proof_verifies_authority_expired, HAVE_VF),
    "authority-source-unavailable":
        (_probe_authority_source_unavailable, HAVE_VF),
    "lapsed-draft-citation": (_probe_lapsed_draft_citation, HAVE_VF),
    "prelapse-receipt-not-fresh": (_probe_prelapse_receipt_not_fresh,
                                   HAVE_VF),
    "malformed-input-fails-closed": (_probe_malformed_input_fails_closed,
                                     HAVE_VF),
    "expected-participant-audit": (_probe_expected_participant_audit,
                                   HAVE_VF),
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
        for code in ("chain-source-unavailable", "chain-source-stale",
                     "authority-stale", "authority-unavailable",
                     "verifier-input-malformed"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-243 verifier fail-closed probes (module: %s)" % (HAVE_VF,))
    results = []
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        results.append((name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    held = sum(1 for _n, s, _d in results if s == "HELD")
    brk = sum(1 for _n, s, _d in results if s == "BREAK")
    err = sum(1 for _n, s, _d in results if s == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(results, brk, held, err)
    probe_lines.emit(results)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
