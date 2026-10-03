"""Wave-242 IR 8587 workload-credential conformance probes (W242-7, red-first).

NIST IR 8587, "Protecting Tokens and Assertions from Forgery, Theft,
and Misuse" -- Final, released 2026-09-15 (DOI 10.6028/NIST.IR.8587).
The five verbatim quotes backing this battery live in
~/workspace/teams/wave241-prospect/raw/ietf-drafts.md section 9; the
probes cite the final-text sections by number.

This battery is a CONFORMANCE PIN over existing seams
(gov.aauth_egress, gov.token_hygiene): it confirms and pins the
behaviors IR 8587 requires, and documents the honest boundary where
the report asks for a SHOULD rather than a MUST. It is red-first in
the falsifiable sense: any pass on a refusal probe, or any hit on the
log scan, is a control gap against final federal guidance.

Probes:
  ir8587-aud-missing-rejected -- tokens without an explicit audience
      are refused (8587 section 5.3.1.3: "all tokens and assertions
      MUST include explicit audience fields, and all access control
      mechanisms MUST reject tokens with incorrect or missing audience
      restrictions"). Probed at two seams: aauth_egress.check_audience
      and token_hygiene.validate_issuance.
  ir8587-aud-mismatch-rejected -- presentation to the wrong audience
      refuses token-audience-mismatch; the correct audience passes
      (positive control).
  ir8587-long-lived-refused-at-issuance -- a token issued with a TTL
      above the 1h cap refuses token-ttl-exceeded AT ISSUANCE (8587
      section 5.3.1.6: workload identities "MUST use tightly scoped,
      short-lived tokens").
  ir8587-ttl-cap-widening-refused -- the 1h cap is the invariant, not a
      default: constructing TokenHygiene with a wider cap refuses.
  ir8587-stale-key-refused -- a high-impact issuing key older than the
      rotation window refuses token-key-stale (key-hygiene half of
      the 5.3.1.6 sender-constraint posture).
  ir8587-scrub-removes-token-material -- a registered token value in
      an audit artifact is replaced by the redaction marker (8587
      section 5.3.1.7: "The tokens and assertions themselves MUST NOT
      be stored in logs").
  ir8587-redactor-flags-token-in-line -- a rendered log line still
      carrying a token value refuses token-in-log (scan-mode
      enforcement: a leak is an incident, never a quiet redact).
  ir8587-self-scrape-zero-hits -- the battery scrapes ITS OWN
      generated output (a scrubbed audit artifact plus this battery's
      own source, which is shipped output) for a registered probe
      token: zero hits (8587 section 5.3.1.7: "MUST NOT be stored in
      logs"). A hit is a control gap.
  ir8587-sender-constraint-honest-gap-pinned -- HONEST BOUNDARY: 8587
      section 5.3.1.6 says sender-constrained mechanisms (mTLS, DPoP)
      SHOULD be used "whenever feasible" -- a SHOULD, not a MUST.
      This probe pins the current behavior (issuance without a cnf
      confirmation field succeeds) so no future change can silently
      claim sender-constraint enforcement we do not have.

Stdlib only. Deterministic: every clock is injected. No in-repo git
subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_APIS = False
try:
    from gov import aauth_egress as _ae
    from gov import token_hygiene as _th
    HAVE_APIS = all(hasattr(_ae, n) for n in (
        "check_audience", "AauthEgressError")) and all(
        hasattr(_th, n) for n in (
            "TokenHygiene", "TokenHygieneError", "MAX_TTL_SECONDS",
            "register_known_token", "clear_known_tokens",
            "token_scrub", "TokenRedactor", "REDACTED_MARKER"))
except ImportError:
    _ae = _th = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

T0 = 1790817600  # 2026-09-30T12:00:00Z (fixed, deterministic)

PROBE_NAMES = [
    "ir8587-aud-missing-rejected",
    "ir8587-aud-mismatch-rejected",
    "ir8587-long-lived-refused-at-issuance",
    "ir8587-ttl-cap-widening-refused",
    "ir8587-stale-key-refused",
    "ir8587-scrub-removes-token-material",
    "ir8587-redactor-flags-token-in-line",
    "ir8587-self-scrape-zero-hits",
    "ir8587-sender-constraint-honest-gap-pinned",
]


def _run_probe(name, fn):
    if not HAVE_APIS:
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


def _claims(iat=T0, ttl=600, aud="svc:policy", iss="issuer:1",
            key_id="k1", key_issued_at=T0, impact="standard"):
    return {"type": "agent-credential", "iat": iat, "exp": iat + ttl,
            "aud": aud, "iss": iss, "scope": "policy:evaluate",
            "key_id": key_id, "key_issued_at": key_issued_at,
            "impact": impact}


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_aud_missing_rejected():
    # Seam 1: aauth_egress audience binding.
    try:
        _ae.check_audience(None, "svc:policy")
    except _ae.AauthEgressError as exc:
        assert exc.code == "aauth-aud-mismatch", exc.code
        note1 = "aauth-aud-mismatch"
    else:
        raise AssertionError("check_audience(None) passed")
    # Seam 2: token_hygiene issuance.
    hyg = _th.TokenHygiene()
    bad = _claims()
    del bad["aud"]
    try:
        hyg.validate_issuance(bad, now=T0)
    except _th.TokenHygieneError as exc:
        assert exc.code == "token-audience-missing", exc.code
        note2 = "token-audience-missing"
    else:
        raise AssertionError("validate_issuance without aud passed")
    return "%s; %s (8587 s5.3.1.3)" % (note1, note2)


def _probe_aud_mismatch_rejected():
    hyg = _th.TokenHygiene()
    try:
        hyg.present(_claims(), "svc:WRONG", now=T0)
    except _th.TokenHygieneError as exc:
        assert exc.code == "token-audience-mismatch", exc.code
        note = "token-audience-mismatch"
    else:
        raise AssertionError("present() to wrong audience passed")
    # Positive control: the declared audience passes.
    hyg.present(_claims(), "svc:policy", now=T0)
    return "%s; correct aud ok (8587 s5.3.1.3)" % note


def _probe_long_lived_refused_at_issuance():
    hyg = _th.TokenHygiene()
    try:
        hyg.validate_issuance(_claims(ttl=7200), now=T0)
    except _th.TokenHygieneError as exc:
        assert exc.code == "token-ttl-exceeded", exc.code
        return "refused token-ttl-exceeded at issuance (8587 s5.3.1.6)"
    raise AssertionError("2h TTL passed issuance")


def _probe_ttl_cap_widening_refused():
    try:
        _th.TokenHygiene(max_ttl_seconds=_th.MAX_TTL_SECONDS + 1)
    except _th.TokenHygieneError as exc:
        assert exc.code == "token-ttl-exceeded", exc.code
        return "cap widening refused; 1h is the invariant"
    raise AssertionError("wider cap constructed")


def _probe_stale_key_refused():
    hyg = _th.TokenHygiene()
    old_key = T0 - 100 * 86400  # 100 days old; window is 90 days
    try:
        hyg.validate_issuance(
            _claims(impact="high", key_issued_at=old_key), now=T0)
    except _th.TokenHygieneError as exc:
        assert exc.code == "token-key-stale", exc.code
        note = "token-key-stale"
    else:
        raise AssertionError("stale high-impact key passed")
    # Positive control: a fresh key passes.
    hyg.validate_issuance(_claims(impact="high"), now=T0)
    return "%s; fresh key ok (8587 s5.3.1.6 key hygiene)" % note


def _probe_scrub_removes_token_material():
    token = "ir8587-probe-token-" + "x" * 16
    try:
        _th.register_known_token(token)
        artifact = {"event": "lease-issued", "lease_id": "L1",
                    "note": "bearer %s delivered" % token,
                    "nested": {"raw": token}}
        scrubbed = _th.token_scrub(artifact)
        flat = repr(scrubbed)
        assert token not in flat, "token survived scrub"
        assert _th.REDACTED_MARKER in flat, "no redaction marker"
        return "token replaced by %r (8587 s5.3.1.7)" % (
            _th.REDACTED_MARKER,)
    finally:
        _th.clear_known_tokens()


def _probe_redactor_flags_token_in_line():
    token = "ir8587-probe-token-" + "y" * 16
    redactor = _th.TokenRedactor((token,))
    try:
        redactor.assert_clean("lease L1 issued for agent a1")
    except _th.TokenHygieneError as exc:
        raise AssertionError("clean line flagged: %r" % (exc,))
    try:
        redactor.assert_clean("delivered bearer %s to host" % token)
    except _th.TokenHygieneError as exc:
        assert exc.code == "token-in-log", exc.code
        return "leaking line refused token-in-log (8587 s5.3.1.7)"
    raise AssertionError("leaking line passed the redactor")


def _probe_self_scrape_zero_hits():
    # Spec W242-7(c): scrape OUR OWN output for bearer-token material
    # -> zero hits (8587 s5.3.1.7). Corpus = a lane-generated audit
    # artifact run through the scrub path, plus this battery's own
    # source (shipped output). The probe token is constructed, never
    # written raw, so any hit is a genuine leak.
    token = "ir8587-probe-token-" + "z" * 16
    try:
        _th.register_known_token(token)
        artifact = {"event": "ir8587-probe-run", "lease_id": "L9",
                    "note": "bearer %s issued" % token}
        scrubbed = _th.token_scrub(artifact)
        with open(__file__, encoding="utf-8") as handle:
            source = handle.read()
        redactor = _th.TokenRedactor((token,))
        corpus = [("scrubbed-audit-artifact", repr(scrubbed)),
                  ("battery-source", source)]
        hits = []
        for label, text in corpus:
            if token in text:
                hits.append(label)
            try:
                redactor.assert_clean(text)
            except _th.TokenHygieneError as exc:
                assert exc.code == "token-in-log", exc.code
                hits.append(label + "(redactor)")
        assert not hits, "SELF-SCRAPE HIT in %s" % hits
        return ("zero token-material hits in lane's own output "
                "(8587 s5.3.1.7)")
    finally:
        _th.clear_known_tokens()


def _probe_sender_constraint_honest_gap_pinned():
    # without a cnf confirmation field currently succeeds. Pin the
    # behavior so no future change silently claims enforcement.
    hyg = _th.TokenHygiene()
    out = hyg.validate_issuance(_claims(), now=T0)
    assert "cnf" not in out, "cnf unexpectedly required"
    return ("PINNED: no sender-constraint (cnf) requirement at issuance; "
            "8587 s5.3.1.6 SHOULD honored as honest gap, not a MUST claim")


_PROBES = {
    "ir8587-aud-missing-rejected": _probe_aud_missing_rejected,
    "ir8587-aud-mismatch-rejected": _probe_aud_mismatch_rejected,
    "ir8587-long-lived-refused-at-issuance":
        _probe_long_lived_refused_at_issuance,
    "ir8587-ttl-cap-widening-refused": _probe_ttl_cap_widening_refused,
    "ir8587-stale-key-refused": _probe_stale_key_refused,
    "ir8587-scrub-removes-token-material":
        _probe_scrub_removes_token_material,
    "ir8587-redactor-flags-token-in-line":
        _probe_redactor_flags_token_in_line,
    "ir8587-self-scrape-zero-hits": _probe_self_scrape_zero_hits,
    "ir8587-sender-constraint-honest-gap-pinned":
        _probe_sender_constraint_honest_gap_pinned,
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
        for code in ("aauth-aud-mismatch", "token-audience-missing",
                     "token-audience-mismatch", "token-ttl-exceeded",
                     "token-key-stale", "token-in-log"):
            _dc.code_for(code)
        notes.append("IR 8587 refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-242 IR 8587 conformance probes (APIs present: %s)"
          % HAVE_APIS)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for r in results if r[1] == "HELD")
    brk = sum(1 for r in results if r[1] == "BREAK")
    err = sum(1 for r in results if r[1] == "ERROR")
    bad = brk + err
    for note in _run_green_checks():
        print("  green: %s" % note)
    _coh_ok, _coh_diags = probe_lines.check_coherence(results, brk, held, err)
    probe_lines.emit(results)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
