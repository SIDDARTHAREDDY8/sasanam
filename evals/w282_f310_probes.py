"""Wave-282 lane-1 (F310 closure) battery: shield-run evidence must never
echo credential-shaped material into the HMAC audit log.

F310 (LOW, OPEN): the shield registry's own emission path
(``gov/shield_registry.py::_run_shields`` -> ``guardrail_evidence.run_guardrail``,
scopes ``input_shield``/``output_shield``) records each shield run's detail
verbatim into the audit log with no secret ban on that path. A DLP-style
shield quoting the offending argument lands the credential in the record's
rationale. Same defect class as F306, different emission site.

Red-first: on the pristine wave-281 base, the leak probes BREAK (the
credential reaches the audit log); after the fix they HELD.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g282-f310 && TMPDIR=/var/tmp/g282-f310 \
    ~/workspace/.gov-venv/bin/python evals/w282_f310_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g282-f310b \
    ~/workspace/.gov-venv/bin/python evals/w282_f310_probes.py
"""

import os
import re
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 2128 # Wave-281 merge: 1541 -> 1563; Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "1588/1588/0 sorted")


_SECRET = "password= hunter2-hunter2-x9"


def _fresh_writer():
    from gov.log import ActionLog
    from gov.guardrail_evidence import GuardrailEvidenceWriter
    d = tempfile.mkdtemp(prefix="w282-f310-")
    audit_path = os.path.join(d, "audit.jsonl")
    log = ActionLog(audit_path)
    return GuardrailEvidenceWriter(log), audit_path


def _evil_registry():
    from gov import shield_registry as sr

    def _evil(data):
        return sr.ShieldVerdict(
            "violation", "blocked: request carried %s in args" % _SECRET)

    reg = sr.ShieldRegistry()
    reg.register("dlp", run=_evil)
    return sr, reg


def _leaked_records(audit_path):
    from gov.log import read_entries
    return [r for r in read_entries(audit_path) if "hunter2" in repr(r)]


def p_shield_input_scope_echo():
    """F310 core: run_input_shields with a credential-quoting shield must
    not land the credential in any audit record."""
    from gov import elicitation_contract as ec
    assert ec.credential_material_present(_SECRET), "detector must fire"
    sr, reg = _evil_registry()
    writer, audit_path = _fresh_writer()
    try:
        sr.run_input_shields(reg, ["dlp"], {"text": "x"}, writer=writer)
        _record("f310-input-scope-echo", "BREAK",
                "shield violation did not raise (fail-open)")
        return
    except sr.ShieldViolation:
        pass  # fail-closed block, as designed
    leaked = _leaked_records(audit_path)
    if leaked:
        _record("f310-input-scope-echo", "BREAK",
                "guardrail-run record echoes the credential (scope=%r)"
                % (leaked[0].get("event_scope"),))
    else:
        _record("f310-input-scope-echo", "HELD",
                "violation blocked and no secret in the evidence record")


def p_shield_output_scope_echo():
    """F310: the output_shield scope has the same emission site and must
    be sanitized too."""
    sr, reg = _evil_registry()
    writer, audit_path = _fresh_writer()
    try:
        sr.run_output_shields(reg, ["dlp"], {"text": "x"}, writer=writer)
        _record("f310-output-scope-echo", "BREAK",
                "shield violation did not raise (fail-open)")
        return
    except sr.ShieldViolation:
        pass
    leaked = _leaked_records(audit_path)
    if leaked:
        _record("f310-output-scope-echo", "BREAK",
                "output_shield guardrail-run record echoes the credential")
    else:
        _record("f310-output-scope-echo", "HELD",
                "no secret in the output_shield evidence record")


def p_shield_crash_note_echo():
    """F310: a crashing shield whose exception text is credential-shaped
    must not reach the log via the technical_failure rationale."""
    from gov import shield_registry as sr
    from gov.guardrail_evidence import GuardrailFailureError

    def _crash(data):
        raise RuntimeError("dlp engine choked on %s" % _SECRET)

    reg = sr.ShieldRegistry()
    reg.register("crasher", run=_crash)
    writer, audit_path = _fresh_writer()
    try:
        sr.run_input_shields(reg, ["crasher"], {"text": "x"}, writer=writer)
        _record("f310-crash-note-echo", "BREAK",
                "crashing shield did not fail closed")
        return
    except GuardrailFailureError:
        pass  # fail-closed, as designed
    leaked = _leaked_records(audit_path)
    if leaked:
        _record("f310-crash-note-echo", "BREAK",
                "technical_failure rationale echoes the credential")
    else:
        _record("f310-crash-note-echo", "HELD",
                "crash failed closed and no secret in the evidence record")


def p_verdict_preserved():
    """The verdict must survive sanitization: the violation still blocks
    and the record still says intentional_block."""
    from gov.guardrail_evidence import guardrail_run_records
    sr, reg = _evil_registry()
    writer, audit_path = _fresh_writer()
    try:
        sr.run_input_shields(reg, ["dlp"], {"text": "x"}, writer=writer)
        _record("f310-verdict-preserved", "BREAK", "violation did not raise")
        return
    except sr.ShieldViolation:
        pass
    from gov.log import ActionLog
    recs = guardrail_run_records(ActionLog(audit_path))
    if not recs:
        _record("f310-verdict-preserved", "BREAK", "no guardrail-run record")
        return
    rec = recs[-1]
    if rec.get("outcome") != "intentional_block":
        _record("f310-verdict-preserved", "BREAK",
                "outcome mangled: %r" % (rec.get("outcome"),))
    elif "hunter2" in rec.get("rationale", ""):
        _record("f310-verdict-preserved", "BREAK",
                "rationale still carries the secret")
    else:
        _record("f310-verdict-preserved", "HELD",
                "outcome=%r, rationale=%r"
                % (rec.get("outcome"), rec.get("rationale")))


def p_kind_preserving_placeholder():
    """Redaction must be marked, never silent elision: the placeholder
    keeps the exception-type prefix so an auditor sees what was
    withheld."""
    sr, reg = _evil_registry()
    writer, audit_path = _fresh_writer()
    try:
        sr.run_input_shields(reg, ["dlp"], {"text": "x"}, writer=writer)
    except sr.ShieldViolation:
        pass
    from gov.log import ActionLog
    from gov.guardrail_evidence import guardrail_run_records
    recs = guardrail_run_records(ActionLog(audit_path))
    rationale = recs[-1].get("rationale", "") if recs else ""
    if "ShieldViolation" in rationale and "withheld" in rationale:
        _record("f310-kind-preserving", "HELD",
                "rationale=%r" % (rationale,))
    else:
        _record("f310-kind-preserving", "BREAK",
                "rationale not kind-preserving: %r" % (rationale,))


def p_clean_detail_verbatim():
    """A clean (non-credential) shield detail must pass through verbatim --
    the sanitizer must not rewrite honest evidence."""
    from gov import shield_registry as sr
    from gov.log import ActionLog
    from gov.guardrail_evidence import guardrail_run_records

    def _ok(data):
        return sr.ShieldVerdict("violation", "blocked: bad arg shape")

    reg = sr.ShieldRegistry()
    reg.register("shape", run=_ok)
    writer, audit_path = _fresh_writer()
    try:
        sr.run_input_shields(reg, ["shape"], {"text": "x"}, writer=writer)
    except sr.ShieldViolation:
        pass
    recs = guardrail_run_records(ActionLog(audit_path))
    rationale = recs[-1].get("rationale", "") if recs else ""
    if rationale == "ShieldViolation: shield 'shape' violation: blocked: bad arg shape":
        _record("f310-clean-verbatim", "HELD", "clean detail untouched")
    else:
        _record("f310-clean-verbatim", "BREAK",
                "clean detail rewritten: %r" % (rationale,))


def p_scope_gate_boundary():
    """The sanitize gate is scoped: a non-shield scope's credential-shaped
    rationale is NOT rewritten by this fix (F310's close-when targets the
    shield emission site only)."""
    from gov import guardrail_evidence as ge
    from gov.guardrail_evidence import GuardrailFailureError
    from gov.log import ActionLog
    from gov.guardrail_evidence import guardrail_run_records
    writer, audit_path = _fresh_writer()
    try:
        ge.run_guardrail(
            writer, guardrail_id="g-x", guardrail_name="x",
            event_scope="pre_call",
            fn=lambda: (_ for _ in ()).throw(ValueError("oops " + _SECRET)),
            intentional_block_types=(KeyError,))
    except GuardrailFailureError:
        pass  # technical_failure is recorded, then raised -- expected
    recs = guardrail_run_records(ActionLog(audit_path))
    rationale = recs[-1].get("rationale", "") if recs else ""
    if "hunter2" in rationale:
        _record("f310-scope-gate", "HELD",
                "non-shield scope untouched by design")
    else:
        _record("f310-scope-gate", "BREAK",
                "non-shield scope was rewritten: %r" % (rationale,))


def p_adapter_path_regression():
    """F306's shield->triad adapter site must stay clean (regression pin
    for the f306-shield-adapter close-when)."""
    from gov import shield_registry as sr
    from gov import tool_guardrails as tg
    sr_, reg = _evil_registry()
    shield = reg.get("dlp")
    g = sr_.as_tool_input_guardrail(shield)

    class _Data:
        tool_arguments = {"to": "v@synthetic.local"}
        tool_name = "send_email"

    events = []

    def _emit(record):
        events.append(record)

    try:
        tg._run_guards([g], _Data(), _emit, "input")
    except tg.ToolGuardrailTripwireTriggered:
        pass
    leaked = [e for e in events if "hunter2" in repr(e)]
    if leaked:
        _record("f310-adapter-regression", "BREAK",
                "triad adapter record echoes the credential")
    else:
        _record("f310-adapter-regression", "HELD",
                "adapter path clean (F306 fix holds)")


def _green_checks():
    if SKIP_GREEN:
        _record("green-skip", "HELD", "GOV_SKIP_GREEN=1")
        return
    import subprocess
    checks = [
        (["evals/w280_shields_probes.py"], "w280-shields"),
    ]
    for argv, name in checks:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        if "TMPDIR" not in env:
            env["TMPDIR"] = tempfile.mkdtemp(prefix="g282-f310-green-")
        os.makedirs(env["TMPDIR"], exist_ok=True)
        try:
            out = subprocess.run(
                [sys.executable] + argv, cwd=REPO, env=env,
                capture_output=True, text=True, timeout=600)
        except Exception as exc:  # noqa: BLE001
            _record("green-" + name, "BREAK", "green check error: %r" % (exc,))
            continue
        rows = out.stdout + out.stderr
        m = re.search(r"w280_shields:\s*(\d+)\s*BREAK\s*/\s*(\d+)\s*HELD\s*/\s*(\d+)\s*ERROR",
                      rows)
        if m and m.group(1) == "0" and m.group(3) == "0":
            _record("green-" + name, "HELD", m.group(0).strip())
        else:
            _record("green-" + name, "BREAK",
                    "exit %d: %s" % (out.returncode, rows[-400:]))


def main():
    p_taxonomy_pin()
    p_shield_input_scope_echo()
    p_shield_output_scope_echo()
    p_shield_crash_note_echo()
    p_verdict_preserved()
    p_kind_preserving_placeholder()
    p_clean_detail_verbatim()
    p_scope_gate_boundary()
    p_adapter_path_regression()
    _green_checks()
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    print("w282_f310: %d HELD / %d BREAK / %d ERROR" % (n_held, n_break, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
