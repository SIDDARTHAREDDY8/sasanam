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

TAXONOMY_PIN = 1587  # Wave-281 merge: 1541 -> 1563; Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).

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
    _record("pin-taxonomy", "HELD", "1587/1587/0 sorted")


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
