#!/usr/bin/env python3
"""Wave-238 lane C: attested-vs-asserted field column (aqta ACTION-v1 section 8).

Adapted (prose rewrite, attribution in gov/attestation_column.py) from the
aqta-ai ACTION-v1 section 8 attested-vs-asserted field table. The table
divides every audit-log field into one of four attestation classes:

* issuer-attested            -- outcome, policy_applied, timestamp
* issuer-assigned            -- org/session/action ids
* caller-declared-issuer-observed -- tool, args_hash
* caller-asserted-recorded-only   -- agent

The non-conformance rule this battery probes: a field labeled
caller-asserted (e.g. the agent identity) must NEVER be presented as
issuer-verified identity, and an issuer-attested outcome of ALLOWED
attests the DECISION, not the effect -- presenting ALLOWED as proof of
execution is a misread refusal.

Seams under test:
* gov/attestation_column.py -- ATTESTATION_CLASSES, FIELD_CLASS,
  label_record, emit, present_as_verified, present_as_proof_of_execution,
  AttestationColumnError codes.

Method (tdd / diagnosing-bugs): deterministic, minimal, against pushed
wave-237 HEAD dcfd52d2ecbacce8eff0cb5ee27f6332cb103dee.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g238c
  TMPDIR=/var/tmp/g238c ~/workspace/.gov-venv/bin/python evals/w238_attested_probes.py
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
    from gov import attestation_column as _ac
    HAVE_NEW_API = all(hasattr(_ac, n) for n in (
        "ATTESTATION_CLASSES", "FIELD_CLASS", "label_record", "emit",
        "present_as_verified", "present_as_proof_of_execution",
        "present_as_decision", "AttestationColumnError", "CLASS_INFLATION", "CLASS_UNLABELED",
        "OUTCOME_MISREAD", "RECORD_MALFORMED"))
except ImportError:
    _ac = None

PROBE_NAMES = [
    "attested-caller-asserted-not-verified",
    "attested-unlabeled-field-refused-at-emit",
    "attested-allowed-not-proof-of-execution",
    "attested-identity-inflation-named",
    "attested-fully-attested-record-passes",
    "attested-caller-declared-not-promoted",
    "attested-pass-verdict-is-control",
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


def _clean_record(**overrides):
    rec = {
        "outcome": "ALLOWED",
        "policy_applied": "policy/v1",
        "timestamp": "2026-09-30T14:00:00Z",
        "org_id": "org-1",
        "session_id": "sess-1",
        "action_id": "act-1",
        "tool": "read_file",
        "args_hash": "00" * 32,
        "agent": "assistant-42",
    }
    rec.update(overrides)
    return rec


def _expect_refusal(fn, code, label):
    try:
        fn()
    except _ac.AttestationColumnError as exc:
        ok = (exc.code == code)
        return ok, "%s: refused with %s (wanted %s)" % (label, exc.code, code)
    except Exception as exc:  # noqa: BLE001
        return False, "%s: wrong exception %r" % (label, exc)
    return False, "%s: allowed, nothing refused" % label


def probe_caller_asserted_not_verified():
    # Presenting the caller-asserted `agent` field as issuer-verified
    # identity is non-conformant: refuse, naming the class inflation.
    return _expect_refusal(
        lambda: _ac.present_as_verified(_clean_record(), "agent"),
        _ac.CLASS_INFLATION, "caller-asserted agent as verified")


def probe_unlabeled_field_refused_at_emit():
    # A field with no attestation class cannot be emitted unlabeled.
    return _expect_refusal(
        lambda: _ac.emit(_clean_record(mystery_field="??")),
        _ac.CLASS_UNLABELED, "unlabeled field at emit")


def probe_allowed_not_proof_of_execution():
    # ALLOWED attests the decision only. Presenting it as proof of
    # execution is a misread refusal.
    return _expect_refusal(
        lambda: _ac.present_as_proof_of_execution(_clean_record()),
        _ac.OUTCOME_MISREAD, "ALLOWED as proof-of-execution")


def probe_identity_inflation_named():
    # The refusal for inflating caller-asserted identity to verified
    # must name the field and the class, never say "tampered".
    try:
        _ac.present_as_verified(_clean_record(), "agent")
    except _ac.AttestationColumnError as exc:
        ok = (exc.code == _ac.CLASS_INFLATION
              and "agent" in exc.detail
              and "tampered" not in exc.detail.lower()
              and "caller-asserted" in exc.detail)
        return ok, "refusal names field/class without tamper language: %s" % exc.code
    except Exception as exc:  # noqa: BLE001
        return False, "wrong exception %r" % exc
    return False, "no refusal raised"


def probe_fully_attested_record_passes():
    # The control: a record where every field has a class emits cleanly
    # with per-field labels and no refusal.
    labeled = _ac.emit(_clean_record())
    if not isinstance(labeled, dict):
        return False, "emit did not return a record dict"
    fields = labeled.get("fields", {})
    missing = [f for f in _clean_record() if f not in fields]
    if missing:
        return False, "fields missing labels: %r" % missing
    bad = [f for f, c in fields.items()
           if c.get("class") not in _ac.ATTESTATION_CLASSES]
    if bad:
        return False, "fields with bad class: %r" % bad
    return True, "all %d fields labeled with closed-vocabulary classes" % len(fields)


def probe_caller_declared_not_promoted():
    # caller-declared-issuer-observed fields (tool, args_hash) also may
    # not be presented as issuer-verified -- they were declared by the
    # caller and only observed by the issuer.
    return _expect_refusal(
        lambda: _ac.present_as_verified(_clean_record(), "tool"),
        _ac.CLASS_INFLATION, "caller-declared tool as verified")


def probe_pass_verdict_is_control():
    # issuer-attested outcome may be presented as what it is -- the
    # decision -- without refusal. (ALLOWED read as "decision was
    # allow" is conformant; only the proof-of-execution leap refuses.)
    ok = _ac.present_as_decision(_clean_record())
    return ok.get("decision") == "ALLOWED", \
        "issuer-attested outcome read as decision: %r" % ok


_PROBES = {
    "attested-caller-asserted-not-verified": probe_caller_asserted_not_verified,
    "attested-unlabeled-field-refused-at-emit": probe_unlabeled_field_refused_at_emit,
    "attested-allowed-not-proof-of-execution": probe_allowed_not_proof_of_execution,
    "attested-identity-inflation-named": probe_identity_inflation_named,
    "attested-fully-attested-record-passes": probe_fully_attested_record_passes,
    "attested-caller-declared-not-promoted": probe_caller_declared_not_promoted,
    "attested-pass-verdict-is-control": probe_pass_verdict_is_control,
}


def main():
    print("wave-238 attested-vs-asserted probes (new API: %s)" % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, note in results:
        print("%-46s %s  %s" % (name, verdict, note))
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR"
          % (held, gap, brk, err))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
