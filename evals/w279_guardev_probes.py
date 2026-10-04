"""Wave-279 lane 5 red-first battery: uniform guardrail-run evidence records.

Gap (base 3e9767f): the audit log chains *decisions*, but guardrail *runs*
have no standard evidence record. A policy block and a guard technical
failure are indistinguishable in the audit trail -- neither produces a
guardrail-run record, and there is no intentional-block vs
technical-failure vocabulary at all (the LiteLLM
StandardLoggingGuardrailInformation / is_guardrail_intervention
distinction we steal).

Red-first: on base every probe BREAKs (module absent / no records).
After the fix: records exist with the distinct outcome vocabulary,
technical failures raise loudly, and the record chain verifies.

Pattern lineage: BerriAI/litellm StandardLoggingGuardrailInformation
(MIT -- mechanism only, no litellm code vendored) + the
_PRE_CALL_EXECUTED_TOKEN anti-forgery precedent: a record is evidence
only when bound inside the HMAC-chained audit log.
"""

import hashlib
import json
import os
import secrets
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w279-guardev")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe_lines  # noqa: E402  (canonical probe-line form)

TAXONOMY_PIN = 2021 # Wave-279 merge pin was 1495 (1493 + evbundle-contract-refused + tool-guardrail-tripwire); Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 1: pin 2020 -> 2021 (+1 witness-alert-state-lost)



_RESULTS = []


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})


def _needs_evidence(probe_id):
    try:
        from gov import guardrail_evidence as ge
        return ge
    except ImportError:
        _record(probe_id, "BREAK", "gov.guardrail_evidence absent on base")
        return None


def _fresh_log():
    d = tempfile.mkdtemp(prefix="g279_", dir=os.environ["TMPDIR"])
    from gov.log import ActionLog
    return ActionLog(os.path.join(d, "audit.jsonl"))


# -- probes ---------------------------------------------------------------

def p_module_present():
    ge = _needs_evidence("p_module_present")
    if ge is None:
        return
    _record("p_module_present", "HELD", "gov.guardrail_evidence present")


def p_intentional_block_recorded():
    ge = _needs_evidence("p_intentional_block_recorded")
    if ge is None:
        return
    log = _fresh_log()
    w = ge.GuardrailEvidenceWriter(log)

    class PolicyBlock(Exception):
        pass

    def deny():
        raise PolicyBlock("token would exfiltrate")

    try:
        ge.run_guardrail(w, guardrail_id="g-egress", guardrail_name="egress-screen",
                         mode="blocking", event_scope="pre_call", fn=deny,
                         input_bytes=b"req-bytes",
                         intentional_block_types=(PolicyBlock,))
    except PolicyBlock:
        pass
    recs = ge.guardrail_run_records(log)
    if len(recs) != 1 or recs[0]["outcome"] != "intentional_block":
        return _record("p_intentional_block_recorded", "BREAK",
                       "no intentional_block record, got %r" % (recs,))
    _record("p_intentional_block_recorded", "HELD",
            "deny -> outcome=intentional_block, original exception propagates")


def p_technical_failure_loud():
    ge = _needs_evidence("p_technical_failure_loud")
    if ge is None:
        return
    log = _fresh_log()
    w = ge.GuardrailEvidenceWriter(log)

    def boom():
        raise ValueError("scanner crashed")

    try:
        ge.run_guardrail(w, guardrail_id="g-scan", guardrail_name="scanner",
                         mode="blocking", event_scope="pre_call", fn=boom,
                         input_bytes=b"x")
    except ge.GuardrailFailureError:
        pass
    except Exception as e:  # noqa: BLE001 - probe asserts the loud type
        return _record("p_technical_failure_loud", "BREAK",
                       "wrong exception type: %r" % (type(e).__name__,))
    else:
        return _record("p_technical_failure_loud", "BREAK",
                       "technical failure was silent")
    recs = ge.guardrail_run_records(log)
    if len(recs) != 1 or recs[0]["outcome"] != "technical_failure":
        return _record("p_technical_failure_loud", "BREAK",
                       "no technical_failure record, got %r" % (recs,))
    _record("p_technical_failure_loud", "HELD",
            "undeclared exception -> GuardrailFailureError + outcome=technical_failure")


def p_block_vs_failure_distinct():
    ge = _needs_evidence("p_block_vs_failure_distinct")
    if ge is None:
        return
    log = _fresh_log()
    w = ge.GuardrailEvidenceWriter(log)

    class PolicyBlock(Exception):
        pass

    def deny():
        raise PolicyBlock("no")

    def boom():
        raise RuntimeError("crash")

    try:
        ge.run_guardrail(w, guardrail_id="g-a", guardrail_name="a",
                         mode="blocking", event_scope="pre_call", fn=deny,
                         input_bytes=b"a", intentional_block_types=(PolicyBlock,))
    except PolicyBlock:
        pass
    try:
        ge.run_guardrail(w, guardrail_id="g-b", guardrail_name="b",
                         mode="blocking", event_scope="pre_call", fn=boom,
                         input_bytes=b"b")
    except ge.GuardrailFailureError:
        pass
    recs = ge.guardrail_run_records(log)
    outcomes = [r["outcome"] for r in recs]
    if outcomes != ["intentional_block", "technical_failure"]:
        return _record("p_block_vs_failure_distinct", "BREAK",
                       "indistinguishable outcomes: %r" % (outcomes,))
    _record("p_block_vs_failure_distinct", "HELD",
            "intentional_block and technical_failure are distinct record shapes")


def p_advisory_flagged_not_blocked():
    ge = _needs_evidence("p_advisory_flagged_not_blocked")
    if ge is None:
        return
    log = _fresh_log()
    w = ge.GuardrailEvidenceWriter(log)

    class PolicyBlock(Exception):
        pass

    def deny():
        raise PolicyBlock("flag me")

    # advisory mode must not raise; execution continues
    allowed, rec = ge.run_guardrail(
        w, guardrail_id="g-adv", guardrail_name="advisory",
        mode="advisory", event_scope="during_call", fn=deny,
        input_bytes=b"a", intentional_block_types=(PolicyBlock,))
    recs = ge.guardrail_run_records(log)
    if allowed is not False or rec["outcome"] != "advisory_flagged"\
            or recs[0]["outcome"] != "advisory_flagged":
        return _record("p_advisory_flagged_not_blocked", "BREAK",
                       "advisory mishandled: allowed=%r outcome=%r"
                       % (allowed, rec.get("outcome") if rec else None))
    _record("p_advisory_flagged_not_blocked", "HELD",
            "advisory block -> outcome=advisory_flagged, no raise")


def p_chain_verifies():
    ge = _needs_evidence("p_chain_verifies")
    if ge is None:
        return
    log = _fresh_log()
    w = ge.GuardrailEvidenceWriter(log)
    w.record("g-1", "one", mode="blocking", event_scope="pre_call",
             outcome="allow", rationale="fine", input_bytes=b"1")
    w.record("g-2", "two", mode="blocking", event_scope="post_call",
             outcome="intentional_block", rationale="nope", input_bytes=b"2")
    recs = ge.guardrail_run_records(log)
    if not ge.verify_guardrail_records(recs):
        return _record("p_chain_verifies", "BREAK", "honest chain refused")
    tampered = json.loads(json.dumps(recs))
    tampered[1]["outcome"] = "allow"
    if ge.verify_guardrail_records(tampered):
        return _record("p_chain_verifies", "BREAK",
                       "tampered outcome verifies -- chain is fake")
    _record("p_chain_verifies", "HELD",
            "record chain verifies; tampered verdict refuses")


def p_input_rationale_binding():
    ge = _needs_evidence("p_input_rationale_binding")
    if ge is None:
        return
    log = _fresh_log()
    w = ge.GuardrailEvidenceWriter(log)
    rec = w.record("g-1", "one", mode="blocking", event_scope="pre_call",
                   outcome="allow", rationale="input clean",
                   input_bytes=b'{"tool":"read","args":{}}')
    want_input = hashlib.sha256(b'{"tool":"read","args":{}}').hexdigest()
    want_rat = hashlib.sha256(b"input clean").hexdigest()
    if rec["input_digest"] != want_input or rec["rationale_digest"] != want_rat:
        return _record("p_input_rationale_binding", "BREAK",
                       "digests do not bind actual input/rationale")
    _record("p_input_rationale_binding", "HELD",
            "input_digest and rationale_digest bind actual bytes")


def p_taxonomy_pin():
    import re
    src = open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "gov", "decision_codes.py")).read()
    codes = re.findall(r'"code":\s*\'([^\']+)\'', src)
    if len(codes) != TAXONOMY_PIN or len(set(codes)) != TAXONOMY_PIN:
        return _record("p_taxonomy_pin", "BREAK",
                       "pin drift: %d raw / %d unique, want %d"
                       % (len(codes), len(set(codes)), TAXONOMY_PIN))
    _record("p_taxonomy_pin", "HELD", "taxonomy pin %d holds, no new codes"
            % TAXONOMY_PIN)


def _green_checks():
    # Depth-1: adjacent suites only, never spawn another battery's main.
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "SKIP", "GOV_SKIP_GREEN=1")
        return
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    for mod in ("tests.test_decision_codes",):
        r = subprocess.run([sys.executable, "-m", "unittest", mod],
                           cwd=os.path.dirname(here), env=env,
                           capture_output=True, text=True, timeout=300)
        _record("green-check_" + mod,
                "HELD" if r.returncode == 0 else "ERROR",
                (r.stderr or r.stdout)[-200:])


def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    for probe in (p_module_present, p_intentional_block_recorded,
                  p_technical_failure_loud, p_block_vs_failure_distinct,
                  p_advisory_flagged_not_blocked, p_chain_verifies,
                  p_input_rationale_binding, p_taxonomy_pin):
        try:
            probe()
        except Exception as e:  # noqa: BLE001 - battery must never die
            _record(probe.__name__, "ERROR", "%r" % (e,))
    _green_checks()
    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    print("w279_guardev: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    probe_lines.emit_dicts(_RESULTS, verdict_key="verdict",
                           pid_key="probe_id", note_key="note")
    mism = [r for r in _RESULTS if r["verdict"] == "ERROR"]
    return 1 if (n_break or mism) else 0


if __name__ == "__main__":
    sys.exit(main())
