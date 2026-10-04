#!/usr/bin/env python3
"""Wave-233 lane C: machine-enforced honest-claim discipline.

ADAPT of the NOA (nordensoft/noa) direction, re-derived: Sasanam
evidence must never EMIT reserved claim tokens (proves-execution,
tamper-proof, non-repudiation, ...). ``gov/honest_claims.py`` defines
the closed vocabulary and ``assert_no_reserved_claims``; the
evidence-bundle builder and the denial-receipt emitter call it
(additive, no silent bypass). ``evals/doc_truth.py`` is the
mechanical doc-truth gate: every NON-CLAIMS.md entry pins a module
and an exact docstring phrase; drift refuses ``doc-truth-missing``.

Seams under test:
* gov/honest_claims.py -- assert_no_reserved_claims: exact token
  named on refusal; variant normalization; does_not_prove exempt;
  dict keys never scanned; vocabulary closed (frozenset); no
  keyword bypass.
* gov/evidence_bundle.py -- EvidenceBundle.build() refuses when a
  rendered artifact carries a reserved token (scratch audit log).
* gov/deny_receipts.py -- emit() refuses when operator-supplied
  strings (rule_path) carry a reserved token.
* evals/doc_truth.py -- catches a module whose docstring lost its
  non-claim phrase (scratch copy; the real module is never touched).

Attack shapes: smuggle "tamper-proof" into a receipt rule_path;
smuggle "formally-verified" into a log reason that flows into a
bundle; strip the honesty phrase from a module docstring; pass
bypass=True (must not exist); claim via does_not_prove context
(honest, must pass).

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-232 HEAD
4ac83e2da908db2ec28b947bb8a2423f9dba20f6.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (helpers
absent) is expected GAP. Any BREAK is a real product defect.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g233c
  TMPDIR=/var/tmp/g233c ~/workspace/.gov-venv/bin/python evals/w233_nonclaims_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import inspect
import shutil
import sys
import tempfile
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_MODULE = False
_hc = None
_doc_truth = None
try:
    from gov import honest_claims as _hc
    from evals import doc_truth as _doc_truth
    HAVE_MODULE = all(hasattr(_hc, n) for n in (
        "assert_no_reserved_claims", "RESERVED_CLAIM_TOKENS"))
except ImportError:
    _hc = None
    _doc_truth = None

PROBE_NAMES = [
    "nonclaims-token-refused",
    "nonclaims-variant-normalized",
    "nonclaims-does-not-prove-exempt",
    "nonclaims-keys-not-scanned",
    "nonclaims-receipt-emitter-wired",
    "nonclaims-bundle-builder-wired",
    "nonclaims-doc-truth-catches-drift",
    "nonclaims-no-silent-bypass",
]


def _hold(cond, detail=""):
    return "HELD" if cond else "BREAK\n" + detail


def _probe_token_refused():
    try:
        _hc.assert_no_reserved_claims(
            {"claim": "this receipt is a tamper-proof guarantee"})
    except _hc.HonestClaimError as exc:
        return _hold(
            exc.token == "tamper-proof"
            and exc.code == "honest-claim-reserved-token",
            "token=%r code=%r" % (exc.token, exc.code))
    return "BREAK\nno refusal for reserved token"


def _probe_variant_normalized():
    try:
        _hc.assert_no_reserved_claims("Tamper_Proof by design")
    except _hc.HonestClaimError as exc:
        return _hold(exc.token == "tamper-proof",
                     "normalized token=%r" % (exc.token,))
    return "BREAK\nvariant not normalized"


def _probe_does_not_prove_exempt():
    # Honestly DECLARING non-proof is not a claim; must pass.
    try:
        _hc.assert_no_reserved_claims({
            "claim_bounds": {"proves": ["bundle-digest-integrity"],
                             "does_not_prove": ["non-repudiation",
                                                "key-custody"]}})
    except _hc.HonestClaimError as exc:
        return "BREAK\ndoes_not_prove refused: %r" % (exc.token,)
    return "HELD"


def _probe_keys_not_scanned():
    # The receipt's own "non_repudiation" KEY must not trip the scan.
    try:
        _hc.assert_no_reserved_claims(
            {"non_repudiation": False, "v": 1})
    except _hc.HonestClaimError as exc:
        return "BREAK\nkey scanned as value: %r" % (exc.token,)
    return "HELD"


def _probe_receipt_emitter_wired():
    from gov import deny_receipts as dr
    from gov import alg_registry as ar
    secret = hashlib.sha256(b"w233-nonclaims-probe").digest()
    signer = dr.Signer(alg=ar.ED25519_RFC8032, secret=secret,
                       key_id="probe-key")
    record = {
        "verdict": "DENY",
        "rule_path": "deny:tamper-proof-rule",
        "token_digest": "ab" * 32,
        "policy_bundle_digest": "cd" * 32,
        "intent_digest": "ef" * 32,
        "jurisdiction_profile": "probe",
    }
    try:
        dr.emit(record, signer=signer)
    except Exception as exc:  # noqa: BLE001 - any refusal shape counts
        code = getattr(exc, "code", "")
        return _hold(code == "honest-claim-reserved-token",
                     "refusal code=%r" % (code,))
    return "BREAK\nemit accepted a reserved token in rule_path"


def _probe_bundle_builder_wired():
    from gov.log import ActionLog
    from gov.evidence_bundle import EvidenceBundle
    from tests.keyfixture import provision_test_key, scrub_key_env
    provision_test_key()
    tmp = tempfile.mkdtemp(prefix="w233-nonclaims-")
    try:
        log_path = os.path.join(tmp, "audit.log")
        log = ActionLog(log_path)
        log.append({"event": "policy_loaded", "run_id": "r1",
                    "agent_id": "system", "decision": "policy_loaded"})
        log.append({"event": "tool_call", "tool": "write_file",
                    "agent_id": "a1", "run_id": "r1", "decision": "allow"})
        try:
            # operator_id is the operator-supplied prose surface of the
            # bundle payload: a claim smuggled here must be refused.
            EvidenceBundle(log_path,
                           operator_id="formally-verified by ACME").build()
        except Exception as exc:  # noqa: BLE001 - any refusal counts
            code = getattr(exc, "code", "")
            msg = str(exc)
            return _hold(code == "honest-claim-reserved-token"
                         or "honest-claim-reserved-token" in msg,
                         "refusal=%r" % (msg[:120],))
        return "BREAK\nbuild() accepted a reserved token in log prose"
    finally:
        scrub_key_env()
        shutil.rmtree(tmp, ignore_errors=True)


def _probe_doc_truth_catches_drift():
    # Scratch copy of a covered module with the honesty phrase
    # stripped; the real module is never modified.
    src = os.path.join(REPO, "gov", "deny_receipts.py")
    tmp = tempfile.mkdtemp(prefix="w233-nonclaims-drift-")
    try:
        dst = os.path.join(tmp, "deny_receipts_drift.py")
        with open(src, "r", encoding="utf-8") as fh:
            text = fh.read()
        entry = _doc_truth.entry_for("gov.deny_receipts")
        stripped = text.replace(entry["phrase"], "REMOVED-FOR-PROBE")
        if stripped == text:
            return "ERROR\nphrase not found in module source"
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(stripped)
        sys.path.insert(0, tmp)
        try:
            import deny_receipts_drift as drifted
        finally:
            sys.path.remove(tmp)
        verdict = _doc_truth.check_entry(entry, module=drifted)
        return _hold(verdict["ok"] is False
                     and verdict["reason"] == "doc-truth-missing",
                     "verdict=%r" % (verdict,))
    except Exception:  # noqa: BLE001
        return "ERROR\n" + traceback.format_exc(limit=3)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _probe_no_silent_bypass():
    sig = inspect.signature(_hc.assert_no_reserved_claims)
    params = list(sig.parameters)
    vocab = _hc.RESERVED_CLAIM_TOKENS
    return _hold(
        params == ["artifact"]
        and isinstance(vocab, frozenset)
        and "proves-execution" in vocab
        and "tamper-evident" not in vocab,  # integrity claim, legitimate
        "params=%r" % (params,))


_PROBES = {
    "nonclaims-token-refused": _probe_token_refused,
    "nonclaims-variant-normalized": _probe_variant_normalized,
    "nonclaims-does-not-prove-exempt": _probe_does_not_prove_exempt,
    "nonclaims-keys-not-scanned": _probe_keys_not_scanned,
    "nonclaims-receipt-emitter-wired": _probe_receipt_emitter_wired,
    "nonclaims-bundle-builder-wired": _probe_bundle_builder_wired,
    "nonclaims-doc-truth-catches-drift": _probe_doc_truth_catches_drift,
    "nonclaims-no-silent-bypass": _probe_no_silent_bypass,
}


def _green_check():
    """Depth-1: adjacent suites run once, never nested."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check: SKIP (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    ok = True
    targets = [
        ["tests/test_honest_claims.py"],
        ["evals/doc_truth.py"],
    ]
    for t in targets:
        cmd = [sys.executable, "-m", "unittest"] + t \
            if t[0].startswith("tests/") else [sys.executable] + t
        proc = subprocess.run(cmd, cwd=REPO, env=env,
                              capture_output=True, text=True, timeout=600)
        label = " ".join(t)
        if proc.returncode != 0:
            print("green check: FAIL %s\n%s" % (label, proc.stderr[-800:]))
            ok = False
        else:
            print("green check: PASS %s" % label)
    return ok


def _run_all():
    results = {}
    for name in PROBE_NAMES:
        try:
            results[name] = _PROBES[name]()
        except Exception:  # noqa: BLE001
            results[name] = "ERROR\n" + traceback.format_exc(limit=3)
    return results


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md), red-first: GAP -> BREAK.
# The verdict token is the first word of the recorded verdict string; the
# original first line is kept verbatim as the note (evidence preserved), with
# any multi-line detail collapsed to its first line (" // "-joined).
# Unknown tokens fail closed as ERROR (loud, never silent). Raw results keep
# the battery's own vocabulary (count code and exit contract untouched); the
# mapping happens at emission.
_VERDICT_TOKEN_MAP = {"HELD": "HELD", "GAP": "BREAK", "BREAK": "BREAK",
                      "ERROR": "ERROR"}


def _split_row(name, v):
    first = probe_lines.first_line(v)
    tok = (first.split(":")[0].split() or [""])[0]
    mapped = _VERDICT_TOKEN_MAP.get(tok)
    if mapped is None:
        return {"probe_id": name, "verdict": "ERROR",
                "note": "unparseable verdict string: %r" % (first,)}
    _, _, rest = v.partition("\n")
    rest_first = probe_lines.first_line(rest).strip()
    note = first if not rest_first else first + " // " + rest_first
    return {"probe_id": name, "verdict": mapped, "note": note}

def main():
    t0 = time.time()
    if not HAVE_MODULE:
        rows = [{"probe_id": name, "verdict": "BREAK",
                 "note": "GAP (honest_claims absent)"} for name in PROBE_NAMES]
        probe_lines.emit_dicts(rows)
        print("%d BREAK / %d HELD / %d ERROR" % (len(PROBE_NAMES), 0, 0))
        return 2
    results = _run_all()
    held = sum(1 for v in results.values() if v == "HELD")
    gap = sum(1 for v in results.values() if v.startswith("GAP"))
    brk = sum(1 for v in results.values() if v.startswith("BREAK"))
    err = sum(1 for v in results.values() if v.startswith("ERROR"))
    rows = [_split_row(name, results.get(name, "ERROR: missing"))
            for name in PROBE_NAMES]
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        [(r["probe_id"], r["verdict"], r["note"]) for r in rows],
        brk + gap, held, err)
    probe_lines.emit_dicts(rows)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR (%.1fs)"
          % (brk + gap, held, err, time.time() - t0))
    green_ok = _green_check()
    return 0 if (brk == 0 and err == 0 and green_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
