"""Wave-241 Vaara recomputability probes (W241-2, red-first).

ADAPT (patterns only, prose re-derived from draft-sirkkavaara-vaara-receipt-12;
AGPL-3.0-or-later -- no upstream code, no imports, no vendoring): an
independent no-issuer-code acceptance checker for decision<->execution
receipt pairs. Conformance: signature verifies + digests recompute over
JCS-canonical bytes + backLink (digest+nonce of predecessor) matches.
Honest limits (draft section 10): an "allow" decision without a linked
execution receipt proves NOTHING about whether it ran; an absent refusal
is evidence only inside a declared coverage boundary.

Probes:
  recompute-valid-pair-ok -- a fully valid decision+execution pair
      verifies end to end (positive control).
  recompute-tampered-digest-refused -- a receipt whose body was edited
      after digesting refuses recompute-digest-mismatch.
  recompute-tampered-signature-refused -- a flipped signature byte
      refuses recompute-signature-invalid.
  recompute-backlink-mismatch-refused -- an execution receipt whose
      backLink names a different decision digest refuses
      recompute-backlink-mismatch.
  recompute-allow-without-execution-refused -- an allow decision with
      no linked execution receipt refuses recompute-no-execution-link
      (an allow proves nothing about execution).
  recompute-deny-without-execution-ok -- a deny decision with no
      execution receipt verifies as refusal evidence (positive
      control: refusals need no execution).
  recompute-absent-refusal-in-coverage-ok -- an absent refusal for an
      action inside the declared coverage boundary is accepted as
      evidence of absence (positive control).
  recompute-absent-refusal-no-coverage -- an absent refusal for an
      action outside the declared coverage boundary refuses
      recompute-absent-refusal-no-coverage (absence is not evidence
      where nothing promised to record).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_NEW_API = False
try:
    from gov import recompute_check as _rc
    HAVE_NEW_API = all(hasattr(_rc, n) for n in (
        "issue_decision_receipt", "issue_execution_receipt",
        "verify_receipt", "check_pair", "check_absence",
        "RecomputeRefusal", "canonical_json",
    ))
except ImportError:
    _rc = None

try:
    from gov import ed25519 as _ed
    HAVE_ED = all(hasattr(_ed, n)
                for n in ("generate_seed", "publickey", "sign"))
except ImportError:
    _ed = None
    HAVE_ED = False

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "recompute-valid-pair-ok",
    "recompute-tampered-digest-refused",
    "recompute-tampered-signature-refused",
    "recompute-backlink-mismatch-refused",
    "recompute-allow-without-execution-refused",
    "recompute-deny-without-execution-ok",
    "recompute-absent-refusal-in-coverage-ok",
    "recompute-absent-refusal-no-coverage",
]


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
        # gap-demonstrated evidence in the note.
        return name, "BREAK", "GAP: capability absent on pristine base"
    if not HAVE_ED:
        return name, "ERROR", "vendored ed25519 unavailable"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    """fn must raise RecomputeRefusal with .code == code; returns note."""
    try:
        fn()
    except _rc.RecomputeRefusal as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


def _keys():
    seed = _ed.generate_seed()
    return seed, _ed.publickey(seed)


def _decision(seed, decision="allow", nonce="cd" * 16):
    return _rc.issue_decision_receipt(
        decision=decision,
        action="tool.invoke",
        action_digest="ab" * 32,
        nonce=nonce,
        key_id="key-1",
        seed=seed,
    )


def _execution(seed, decision_receipt, outcome="ok"):
    return _rc.issue_execution_receipt(
        backlink_digest=decision_receipt["receipt_digest"],
        backlink_nonce=decision_receipt["nonce"],
        evidence_digest="ef" * 32,
        outcome=outcome,
        nonce="01" * 16,
        key_id="key-2",
        seed=seed,
    )


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_valid_pair_ok():
    d_seed, d_pub = _keys()
    e_seed, e_pub = _keys()
    decision = _decision(d_seed, "allow")
    execution = _execution(e_seed, decision)
    verdict = _rc.check_pair(decision, execution,
                             decision_pubkey=d_pub, execution_pubkey=e_pub)
    assert verdict["verdict"] == "accept", verdict
    assert verdict["decision_digest"] == decision["receipt_digest"], verdict
    return "valid decision+execution pair accepted"


def _probe_tampered_digest_refused():
    d_seed, d_pub = _keys()
    decision = _decision(d_seed, "allow")
    tampered = dict(decision)
    tampered["action"] = "tool.invoke.evil"  # body edited after digesting
    return _expect_refusal(
        lambda: _rc.verify_receipt(tampered, d_pub),
        "recompute-digest-mismatch")


def _probe_tampered_signature_refused():
    d_seed, d_pub = _keys()
    decision = _decision(d_seed, "allow")
    tampered = dict(decision)
    sig = dict(tampered["sig"])
    raw = bytearray(bytes.fromhex(sig["signature"]))
    raw[0] ^= 0x01
    sig["signature"] = bytes(raw).hex()
    tampered["sig"] = sig
    return _expect_refusal(
        lambda: _rc.verify_receipt(tampered, d_pub),
        "recompute-signature-invalid")


def _probe_backlink_mismatch_refused():
    d_seed, d_pub = _keys()
    e_seed, e_pub = _keys()
    decision = _decision(d_seed, "allow")
    other = _decision(d_seed, "allow", nonce="dc" * 16)  # different nonce
    assert other["receipt_digest"] != decision["receipt_digest"]
    # A fully valid execution receipt, but linked to the OTHER decision:
    # digest and signature verify, so the checker must reach the
    # backLink comparison and refuse there.
    execution = _execution(e_seed, other)
    return _expect_refusal(
        lambda: _rc.check_pair(decision, execution,
                               decision_pubkey=d_pub, execution_pubkey=e_pub),
        "recompute-backlink-mismatch")


def _probe_allow_without_execution_refused():
    d_seed, d_pub = _keys()
    decision = _decision(d_seed, "allow")
    return _expect_refusal(
        lambda: _rc.check_pair(
            decision, None, decision_pubkey=d_pub,
            execution_pubkey=b"\x00" * 32),
        "recompute-no-execution-link")


def _probe_deny_without_execution_ok():
    d_seed, d_pub = _keys()
    decision = _decision(d_seed, "deny")
    verdict = _rc.check_pair(
        decision, None, decision_pubkey=d_pub,
        execution_pubkey=b"\x00" * 32)
    assert verdict["verdict"] == "accept", verdict
    assert verdict["refusal_evidence"] is True, verdict
    return "deny without execution accepted as refusal evidence"


def _probe_absent_refusal_in_coverage_ok():
    verdict = _rc.check_absence("tool.invoke", coverage={"tool.invoke"})
    assert verdict["verdict"] == "accept", verdict
    assert verdict["absence_is_evidence"] is True, verdict
    return "absent refusal inside coverage accepted as evidence"


def _probe_absent_refusal_no_coverage():
    return _expect_refusal(
        lambda: _rc.check_absence("tool.uncovered", coverage={"tool.invoke"}),
        "recompute-absent-refusal-no-coverage")


_PROBES = {
    "recompute-valid-pair-ok": _probe_valid_pair_ok,
    "recompute-tampered-digest-refused": _probe_tampered_digest_refused,
    "recompute-tampered-signature-refused": _probe_tampered_signature_refused,
    "recompute-backlink-mismatch-refused": _probe_backlink_mismatch_refused,
    "recompute-allow-without-execution-refused":
        _probe_allow_without_execution_refused,
    "recompute-deny-without-execution-ok": _probe_deny_without_execution_ok,
    "recompute-absent-refusal-in-coverage-ok":
        _probe_absent_refusal_in_coverage_ok,
    "recompute-absent-refusal-no-coverage": _probe_absent_refusal_no_coverage,
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
        for code in ("recompute-digest-mismatch",
                     "recompute-signature-invalid",
                     "recompute-backlink-mismatch",
                     "recompute-malformed",
                     "recompute-no-execution-link",
                     "recompute-absent-refusal-no-coverage"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-241 Vaara recomputability probes (new API: %s)" % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, v, _ in results if v == "HELD")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for note in _run_green_checks():
        print("green-check: %s" % note)
    _coh_ok, _coh_diags = probe_lines.check_coherence(results, brk, held, err)
    probe_lines.emit(results)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    return 0 if (brk == 0 and err == 0) else 2


if __name__ == "__main__":
    sys.exit(main())
