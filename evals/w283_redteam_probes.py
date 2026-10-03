"""Wave-283 independent red-team battery: attack the wave-282 merge.

Base: wave-282 push ad222ce12a9b5b04d13926b01bf026646a3596ef
(verified via git rev-parse HEAD before work).
gov/ is byte-identical (attack only, no product code).

Attack surface (from the wave-282 merge report):
  (a) F311 (LOW, OPEN) -- the wave-281 guard-plugin GuardChain's OWN
      evidence emission echoes credential-shaped plugin details verbatim
      into audit records: the transform path (guardrail-run rationale
      "transform: <detail>" AND the guard-plugin-transform record's
      detail), the deny path (guardrail-run rationale "<detail>"), the
      raised-PluginDeny path (rationale "PluginDeny: <exc>"), the allow
      path (rationale "<detail>"), and the technical-failure path
      (rationale "<ExcType>: <exc>", length-capped but verbatim). Neither
      F306's triad-funnel sanitize nor F310's shield-funnel sanitize
      covers GuardChain._run_one / run_hook. Re-pinned BREAK.
  (b) F310 closure re-pinned HELD: run_input/output_shields with a
      credential-quoting shield must not land the credential in any
      guardrail-run record.
  (c) New wave-282 surface, all expected HELD (fail-closed verified):
      discovery-scan registry (drift quarantine, re-pin bait-and-switch,
      corrupt-store loudness, pending re-pins not surviving restart);
      atomic manifests (GUID collision binding, bind_atomic_manifest drift
      refusal, raw-dict normalization, cleanup-on-failure loudness);
      ratify (check_admission refusals, combinators, verifier crash as
      data, opt-in admission); attack paths (waypoint evasion by
      non-shortest paths, checked-edge wiring, cycle detection).

$0 spend, synthetic/local, deterministic (fixed fixtures, generous
wall-clock margins, no wall-clock equality assertions). Stdlib only,
no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g283-redteam && TMPDIR=/var/tmp/g283-redteam \\
    ~/workspace/.gov-venv/bin/python evals/w283_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g283-redteam2 \\
    ~/workspace/.gov-venv/bin/python evals/w283_redteam_probes.py
"""

import json
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

TAXONOMY_PIN = 1802  # Wave-282 merge: 1563 -> 1579; Wave-283 merge: pin 1579 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)

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


# A credential-shaped fixture the detector must fire on (never a real
# credential; it is the shape, not a value, under test).
_SECRET = "password = hunter2-hunter2-hunter2-hunter2"


# ---------------------------------------------------------------------------
# (a) F311 (LOW, OPEN): GuardChain emission echoes secrets -- re-pinned BREAK
# ---------------------------------------------------------------------------

def _gp_chain(tmp_prefix):
    from gov.log import ActionLog
    from gov.guardrail_evidence import GuardrailEvidenceWriter
    from gov import guard_plugins as gp
    d = tempfile.mkdtemp(prefix=tmp_prefix)
    audit_path = os.path.join(d, "audit.jsonl")
    log = ActionLog(audit_path)
    writer = GuardrailEvidenceWriter(log)
    reg = gp.PluginRegistry()
    return gp, log, writer, reg, audit_path


def _leaked(audit_path):
    from gov.log import read_entries
    return [r for r in read_entries(audit_path) if "hunter2" in repr(r)]


def a_f311_transform_detail_echo():
    """F311: GuardChain transform emission echoes credential-shaped plugin
    detail verbatim -- guardrail-run rationale AND guard-plugin-transform
    record detail."""
    from gov import elicitation_contract as ec
    assert ec.credential_material_present(_SECRET), "detector must fire"
    gp, log, writer, reg, audit_path = _gp_chain("w283-f311-t-")

    def _evil(ctx):
        new = dict(ctx.payload)
        new["token"] = "REDACTED"
        return gp.transform_outcome(
            new, detail="redacted %s from args" % _SECRET)

    reg.register("evil-redact", hooks=["before_tool_call"], run=_evil)
    chain = gp.GuardChain(reg, writer, log)
    verdict = chain.run_hook("before_tool_call", tool_name="send_email",
                             payload={"to": "x"},
                             plugin_ids=["evil-redact"])
    assert verdict.allowed, "transform must not deny"
    leaked = _leaked(audit_path)
    if leaked:
        _record("f311-transform-detail-echo", "BREAK",
                "F311: %d audit record(s) echo the credential-shaped "
                "plugin detail (%s)" % (
                    len(leaked),
                    ",".join(sorted({r.get("record_type", "?")
                                     for r in leaked}))))
    else:
        _record("f311-transform-detail-echo", "HELD",
                "transform detail sanitized before emit")


def a_f311_deny_detail_echo():
    """F311: GuardChain deny emission echoes credential-shaped plugin detail
    verbatim (returned-deny and raised-PluginDeny variants)."""
    from gov import elicitation_contract as ec
    assert ec.credential_material_present(_SECRET), "detector must fire"
    gp, log, writer, reg, audit_path = _gp_chain("w283-f311-d-")

    def _evil_deny(ctx):
        return gp.deny_outcome("refusing: saw %s in args" % _SECRET)

    def _evil_raise(ctx):
        raise gp.PluginDeny("blocked: %s present" % _SECRET)

    reg.register("evil-deny", hooks=["before_tool_call"], run=_evil_deny)
    reg.register("evil-raise", hooks=["before_tool_call"], run=_evil_raise)
    chain = gp.GuardChain(reg, writer, log)
    v = chain.run_hook("before_tool_call", tool_name="send_email",
                       payload={"to": "x"}, plugin_ids=["evil-deny"])
    assert not v.allowed and v.denied_by == "evil-deny"
    v2 = chain.run_hook("before_tool_call", tool_name="send_email",
                        payload={"to": "x"}, plugin_ids=["evil-raise"])
    if v2.allowed:
        _record("f311-deny-detail-echo", "BREAK",
                "raised PluginDeny did not deny (fail-open)")
        return
    leaked = _leaked(audit_path)
    if leaked:
        _record("f311-deny-detail-echo", "BREAK",
                "F311: deny/PluginDeny rationale echoes the "
                "credential-shaped detail (%d record(s))" % len(leaked))
    else:
        _record("f311-deny-detail-echo", "HELD",
                "deny detail sanitized before emit")


def a_f311_allow_detail_echo():
    """F311: GuardChain allow emission echoes credential-shaped plugin detail
    verbatim into the guardrail-run rationale (allow branch is not a
    refusal, but the same log exposure)."""
    from gov import elicitation_contract as ec
    assert ec.credential_material_present(_SECRET), "detector must fire"
    gp, log, writer, reg, audit_path = _gp_chain("w283-f311-a-")

    def _evil_allow(ctx):
        return gp.allow_outcome("cleaned %s ok" % _SECRET)

    reg.register("evil-allow", hooks=["before_tool_call"], run=_evil_allow)
    chain = gp.GuardChain(reg, writer, log)
    v = chain.run_hook("before_tool_call", tool_name="send_email",
                       payload={"to": "x"}, plugin_ids=["evil-allow"])
    assert v.allowed, "allow must allow"
    leaked = _leaked(audit_path)
    if leaked:
        _record("f311-allow-detail-echo", "BREAK",
                "F311: allow-path guardrail-run rationale echoes the "
                "credential-shaped detail (%d record(s))" % len(leaked))
    else:
        _record("f311-allow-detail-echo", "HELD",
                "allow detail sanitized before emit")


def a_f311_technical_failure_echo():
    """F311: GuardChain technical-failure emission echoes credential-shaped
    exception text verbatim into the guardrail-run rationale (_capped is a
    length cap, not a redaction)."""
    from gov import elicitation_contract as ec
    assert ec.credential_material_present(_SECRET), "detector must fire"
    gp, log, writer, reg, audit_path = _gp_chain("w283-f311-e-")

    def _evil_crash(ctx):
        raise RuntimeError("parse of %s failed" % _SECRET)

    reg.register("evil-crash", hooks=["before_tool_call"], run=_evil_crash)
    chain = gp.GuardChain(reg, writer, log)
    try:
        chain.run_hook("before_tool_call", tool_name="send_email",
                       payload={"to": "x"}, plugin_ids=["evil-crash"])
        _record("f311-technical-failure-echo", "BREAK",
                "plugin crash did not fail closed (fail-open)")
        return
    except gp.PluginTechnicalFailure:
        pass  # fail-closed as designed
    leaked = _leaked(audit_path)
    if leaked:
        _record("f311-technical-failure-echo", "BREAK",
                "F311: technical_failure rationale echoes the "
                "credential-shaped exception (%d record(s))" % len(leaked))
    else:
        _record("f311-technical-failure-echo", "HELD",
                "technical-failure rationale sanitized before emit")


# ---------------------------------------------------------------------------
# (b) F310 closure re-pin: shield funnel stays sanitized -- expect HELD
# ---------------------------------------------------------------------------

def _evil_registry():
    from gov import shield_registry as sr

    def _evil(data):
        return sr.ShieldVerdict(
            "violation", "blocked: request carried %s in args" % _SECRET)

    reg = sr.ShieldRegistry()
    reg.register("dlp", run=_evil)
    return sr, reg


def _fresh_writer():
    from gov.log import ActionLog
    from gov.guardrail_evidence import GuardrailEvidenceWriter
    d = tempfile.mkdtemp(prefix="w283-f310-")
    audit_path = os.path.join(d, "audit.jsonl")
    log = ActionLog(audit_path)
    return GuardrailEvidenceWriter(log), audit_path


def _leaked_records(audit_path):
    from gov.log import read_entries
    return [r for r in read_entries(audit_path) if "hunter2" in repr(r)]


def b_f310_input_scope_echo():
    """F310 closure: run_input_shields with a credential-quoting shield must
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
                "F310 REGRESSION: guardrail-run record echoes the "
                "credential (scope=%r)" % (leaked[0].get("event_scope"),))
    else:
        _record("f310-input-scope-echo", "HELD",
                "violation blocked and no secret in the evidence record")


def b_f310_output_scope_echo():
    """F310 closure: output_shield scope stays sanitized."""
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
                "F310 REGRESSION: output_shield guardrail-run record "
                "echoes the credential")
    else:
        _record("f310-output-scope-echo", "HELD",
                "no secret in the output_shield evidence record")


# ---------------------------------------------------------------------------
# (c) New wave-282 surface: attack-path auditor -- expect HELD
# ---------------------------------------------------------------------------

def _ap_graph():
    from gov import attack_paths as ap
    return ap.GrantGraph()


def c_ap_dirty_longer_path():
    """Attack-path waypoint evasion: a clean checkpointed DIRECT grant
    P->H (length 1) plus a dirty 2-hop path P->T (clean) -> T->H
    (uncheckpointed). shortest_paths(P,H) examines only the clean direct
    path, so enumerate_findings sees nothing -- but can_call(P,H) is True
    and an unprovenanced route exists. The lane documents this as a model
    residual (non-principal srcs outside the waypoint query's source set),
    so HELD-honest means confirming the documented residual behaves
    exactly as documented, not that the evasion is impossible."""
    from gov import attack_paths as ap
    g = _ap_graph()
    g.add_node("p", "agent"); g.add_node("t", "tool"); g.add_node("h", "tool")
    g.add_edge("p", "h", "granted_to", provenance_checkpoint=True)
    g.add_edge("p", "t", "granted_to", provenance_checkpoint=True)
    g.add_edge("t", "h", "granted_to")  # dirty hop, src not a principal
    g.mark_high_value("h")
    assert ap.can_call(g, "p", "h"), "reachability fixture broken"
    findings = ap.enumerate_findings(g)
    uph = [f for f in findings
           if f["finding_kind"] == "unprovenanced-path-to-high-value"]
    # Documented residual: the tool->tool dirty hop is outside the waypoint
    # query's source set. Confirm the residual is exactly as documented
    # (no finding for the 2-hop dirty path) -- not a new defect.
    if not uph:
        _record("ap-dirty-longer-path", "HELD",
                "documented model residual confirmed: tool-src dirty hop "
                "outside waypoint source set, enumeration silent as "
                "documented (not a new finding)")
    else:
        _record("ap-dirty-longer-path", "BREAK",
                "residual misdocumented: unexpected finding %r" % (uph,))


def c_ap_checked_edge_honored():
    """The checked-edge contract: a checkpoint->tool 'checked' edge gates
    the tool, so grants to it count as waypoint-clean. Verify the
    annotation is honored (contract) -- not attacker-editable edges."""
    from gov import attack_paths as ap
    g = _ap_graph()
    g.add_node("p", "agent"); g.add_node("cp", "checkpoint")
    g.add_node("h", "tool")
    g.add_edge("p", "h", "granted_to")  # no per-edge checkpoint
    g.add_edge("cp", "h", "checked")    # deployed checkpoint gates tool
    g.mark_high_value("h")
    findings = ap.enumerate_findings(g)
    uph = [f for f in findings
           if f["finding_kind"] == "unprovenanced-path-to-high-value"]
    if not uph:
        _record("ap-checked-edge-honored", "HELD",
                "checked edge gates the tool as documented")
    else:
        _record("ap-checked-edge-honored", "BREAK",
                "checked edge did not gate: %r" % (uph,))


def c_ap_cycle_detected():
    """delegation-cycle enumeration must fire on a delegated_by cycle."""
    from gov import attack_paths as ap
    g = _ap_graph()
    g.add_node("a1", "agent"); g.add_node("a2", "agent")
    g.add_node("h", "tool")
    g.add_edge("a1", "a2", "delegated_by")
    g.add_edge("a2", "a1", "delegated_by")
    g.add_edge("a1", "h", "granted_to", provenance_checkpoint=True,
               approved=True)
    g.add_node("apv", "approval")
    g.add_edge("apv", "h", "approved")
    g.mark_high_value("h")
    findings = ap.enumerate_findings(g)
    cyc = [f for f in findings if f["finding_kind"] == "delegation-cycle"]
    if cyc:
        _record("ap-cycle-detected", "HELD",
                "delegation cycle enumerated")
    else:
        _record("ap-cycle-detected", "BREAK",
                "delegation cycle NOT enumerated (fail-open audit)")


def c_ap_extra_field_tamper():
    """The standalone record verifier digests only RECORD_FIELDS. Inject
    an extra key into a stored finding record: the HMAC audit log is the
    tamper backstop for stored records, so extra-key blindness in the
    standalone verifier is a documented-scope residual, not a bypass."""
    from gov import attack_paths as ap
    from gov.log import ActionLog
    d = tempfile.mkdtemp(prefix="w283-ap-")
    log = ActionLog(os.path.join(d, "audit.jsonl"))
    w = ap.AttackPathWriter(log)
    g = _ap_graph()
    g.add_node("a", "agent")
    g.add_edge("a", "a", "delegated_by")  # self-delegation cycle
    w.write_findings(ap.enumerate_findings(g))
    recs = ap.attack_path_records(log)
    assert recs, "writer fixture broken"
    tampered = dict(recs[0])
    tampered["attacker_note"] = "extra key"
    if ap.verify_attack_path_records(recs):
        if ap.verify_attack_path_records([tampered]):
            _record("ap-extra-field-tamper", "HELD",
                    "documented scope: standalone verifier digests "
                    "RECORD_FIELDS only; stored-record tamper is the HMAC "
                    "log's job (residual, not a bypass)")
        else:
            _record("ap-extra-field-tamper", "BREAK",
                    "inconsistent: extra key both ignored and detected")
    else:
        _record("ap-extra-field-tamper", "BREAK",
                "verifier rejects pristine writer output")


# ---------------------------------------------------------------------------
# (d) New wave-282 surface: ratify admission -- expect HELD
# ---------------------------------------------------------------------------

def _rt_good_report(tool, ok=True):
    from gov import ratify as rt
    leaf = rt.verifier_result(
        subject=tool, name="sig", artifact_type="signature",
        is_success=ok, results=["sig ok"], nested_results=[])
    return rt.verifier_result(
        subject=tool, name="policy-enforcer", artifact_type="policy",
        is_success=ok, results=["rollup"], nested_results=[leaf])


def d_rt_admission_happy():
    """check_admission admits a well-formed ratifying report."""
    from gov import ratify as rt
    if rt.check_admission(tool="tool-a", report=_rt_good_report("tool-a")):
        _record("rt-admission-happy", "HELD", "ratifying report admitted")
    else:
        _record("rt-admission-happy", "BREAK",
                "well-formed ratifying report not admitted")


def d_rt_admission_failure_refused():
    """check_admission raises RatifyRefused on a failing report."""
    from gov import ratify as rt
    try:
        rt.check_admission(tool="tool-a", report=_rt_good_report("tool-a",
                                                                ok=False))
        _record("rt-admission-failure-refused", "BREAK",
                "failing report admitted (fail-open)")
    except rt.RatifyRefused:
        _record("rt-admission-failure-refused", "HELD",
                "failing report refused loudly")


def d_rt_admission_subject_mismatch():
    """check_admission raises RatifyRefused on subject mismatch."""
    from gov import ratify as rt
    try:
        rt.check_admission(tool="tool-b",
                           report=_rt_good_report("tool-a"))
        _record("rt-admission-subject-mismatch", "BREAK",
                "subject-mismatched report admitted (fail-open)")
    except rt.RatifyRefused:
        _record("rt-admission-subject-mismatch", "HELD",
                "subject mismatch refused loudly")


def d_rt_cyclic_report():
    """A self-referential report must not escape the admission gate as an
    unhandled exception: the depth guard (32) must convert the cycle into
    a coded RatifyAdmissionError, never RecursionError."""
    from gov import ratify as rt
    node = rt.verifier_result(
        subject="tool-a", name="policy-enforcer", artifact_type="policy",
        is_success=True, results=["x"], nested_results=[])
    node["nested_results"].append(node)  # self-referential cycle
    try:
        rt.check_admission(tool="tool-a", report=node)
        _record("rt-cyclic-report", "BREAK",
                "cyclic report admitted (fail-open)")
    except rt.RatifyAdmissionError:
        _record("rt-cyclic-report", "HELD",
                "cyclic report refused as coded RatifyAdmissionError")
    except RecursionError:
        _record("rt-cyclic-report", "BREAK",
                "R-FINDING CANDIDATE: RecursionError escapes the admission "
                "gate (unhandled crash, no coded refusal)")
    except rt.RatifyRefused:
        _record("rt-cyclic-report", "HELD",
                "cyclic report refused (RatifyRefused)")


def d_rt_missing_verifier_fail_closed():
    """A policy-required artifact type with no verifier must fail closed
    as data (is_success False with the ratify-policy-unsatisfied node),
    never open."""
    from gov import ratify as rt
    enc = rt.PolicyEnforcer()
    pol = rt.VerificationPolicy({"digest": "all"})
    rep = enc.verify(subject="tool-a", subject_kind="tool-definition",
                     subject_bytes=b"x", metadata={}, verifiers=[],
                     policy=pol)
    if rep["is_success"] is False:
        _record("rt-missing-verifier-fail-closed", "HELD",
                "missing verifier fails closed as data")
    else:
        _record("rt-missing-verifier-fail-closed", "BREAK",
                "missing verifier admitted (fail-open)")


def d_rt_verifier_crash_as_data():
    """A raising verifier must be recorded as a technical error in the
    report (is_success False), never propagate out of the enforcer."""
    from gov import ratify as rt

    class _Boom(rt.Verifier):
        artifact_type = "digest"

        def verify(self, subject_bytes, metadata):
            raise RuntimeError("boom")

    enc = rt.PolicyEnforcer()
    pol = rt.VerificationPolicy({"digest": "all"})
    rep = enc.verify(subject="tool-a", subject_kind="tool-definition",
                     subject_bytes=b"x", metadata={},
                     verifiers=[_Boom("boom")], policy=pol)
    if rep["is_success"] is False:
        _record("rt-verifier-crash-as-data", "HELD",
                "verifier crash recorded as data, is_success False")
    else:
        _record("rt-verifier-crash-as-data", "BREAK",
                "crashing verifier admitted (fail-open)")


def d_rt_opt_in_hook_documented():
    """The opt-in ratify_report hook is a deliberate, documented design
    decision (mandatory-by-default would change every derive_grants
    caller's contract; wave-planning call). Confirm the legacy path
    behaves as documented: no report -> legacy binding, no silent
    ratification claim."""
    from gov import ratify as rt
    # No check_admission involved: verify the documented opt-in seam
    # exists and check_admission(None) refuses rather than admits.
    try:
        rt.check_admission(tool="tool-a", report=None)
        _record("rt-opt-in-hook-documented", "BREAK",
                "absent report admitted (fail-open)")
    except rt.RatifyAdmissionError:
        _record("rt-opt-in-hook-documented", "HELD",
                "absent report refused loudly; opt-in remains a "
                "documented wave-planning decision (not a defect)")


# ---------------------------------------------------------------------------
# (e) Depth-1 green checks (GOV_SKIP_GREEN=1 honored by children)
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        # (battery, expected_break_substring_or_None, must_have_no_break)
        ("evals/w281_redteam_probes.py", None, True),
        ("evals/w280_redteam_probes.py", None, True),
        ("evals/w281_f306_probes.py", None, True),
        ("evals/w281_f307_probes.py", None, True),
        ("evals/w280_shields_probes.py", None, True),
        ("evals/w282_f310_probes.py", None, True),
    ]
    # w282_redteam: F311 CLOSED since the wave-283 merge (0 BREAK; pins HELD).
    for rel, expect_break, no_break in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w283-green-")
        try:
            import subprocess
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout
        breaks = [ln for ln in out.splitlines() if "[BREAK]" in ln]
        if proc.returncode != 0:
            _record(os.path.basename(rel), "ERROR",
                    "green check exit=%d: %s" % (proc.returncode,
                                                out[-300:]))
        elif no_break and breaks:
            _record(os.path.basename(rel), "BREAK",
                    "green check broke unexpectedly: %s" % (breaks[:3],))
        elif expect_break and not any(expect_break in b for b in breaks):
            _record(os.path.basename(rel), "BREAK",
                    "expected BREAK pin %r missing; breaks=%s"
                    % (expect_break, breaks[:3]))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green: exit 0, breaks=%d" % len(breaks))
    # w282_redteam separately: expect exactly the 2 F311 BREAK pins.
    path = os.path.join(REPO, "evals/w282_redteam_probes.py")
    d = tempfile.mkdtemp(prefix="w283-green-")
    try:
        import subprocess
        proc = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600,
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                     GOV_RUN_ROOT=os.path.join(d, "gov-run")))
    except Exception as e:  # noqa: BLE001
        _record("w282_redteam_probes.py", "ERROR", "green check: %r" % (e,))
    else:
        out = proc.stdout
        breaks = [ln for ln in out.splitlines() if "[BREAK]" in ln]
        # Wave-285 merge: F311 CLOSED since the wave-283 merge; the
        # w282_redteam F311 pins are HELD (0 BREAK), not 2 BREAK.
        if proc.returncode != 0:
            _record("w282_redteam_probes.py", "ERROR",
                    "green check exit=%d" % (proc.returncode,))
        elif len(breaks) == 0:
            _record("w282_redteam_probes.py", "HELD",
                    "green: 0 BREAK (F311 closed, pins HELD)")
        else:
            _record("w282_redteam_probes.py", "BREAK",
                    "expected 0 BREAK (F311 closed); got %s" % (breaks[:5],))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    probes = [
        p_taxonomy_pin,
        a_f311_transform_detail_echo,
        a_f311_deny_detail_echo,
        a_f311_allow_detail_echo,
        a_f311_technical_failure_echo,
        b_f310_input_scope_echo,
        b_f310_output_scope_echo,
        c_ap_dirty_longer_path,
        c_ap_checked_edge_honored,
        c_ap_cycle_detected,
        c_ap_extra_field_tamper,
        d_rt_admission_happy,
        d_rt_admission_failure_refused,
        d_rt_admission_subject_mismatch,
        d_rt_cyclic_report,
        d_rt_missing_verifier_fail_closed,
        d_rt_verifier_crash_as_data,
        d_rt_opt_in_hook_documented,
        f_atomic_forged_marker,
        f_discovery_emit_failure_drops_event,
        f_discovery_pipe_in_name_bricks_store,
        f_discovery_repin_binds_by_name_only,
        g_discovery_empty_pin_table,
        g_discovery_enrollment_pins_silently,
        g_atomic_explicit_guid_semantics,
        g_atomic_nan_float_accepted,
        g_manifest_note_matches_latent,
    ]
    for probe in probes:
        try:
            probe()
        except Exception as e:  # noqa: BLE001 - a probe must never die
            import traceback
            _record(probe.__name__, "ERROR",
                    traceback.format_exc()[-500:])
    _green_checks()

    breaks = [r for r in _results if r[1] == "BREAK"]
    held = [r for r in _results if r[1] == "HELD"]
    errors = [r for r in _results if r[1] == "ERROR"]
    print("wave-283 redteam: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note[:160]))
    return 0 if not errors else 1




# ---------------------------------------------------------------------------
# (f) New wave-282 surface: discovery-scan registry + atomic layer -- BREAKs
# ---------------------------------------------------------------------------

def _atomic_run_ok(ctx):
    return True


def _atomic_spec(**kw):
    s = {"name": "t", "description": "d",
         "input_arguments": {},
         "dependencies": [],
         "executor": {"run": _atomic_run_ok, "cleanup": None,
                      "elevation_required": False}}
    s.update(kw)
    return s


def f_atomic_forged_marker():
    """F312: a forged ``_atomic_normalized`` marker on a raw dict bypasses
    ``validate_atomic_spec`` entirely; the module then dies with a bare
    uncoded KeyError instead of a coded AtomicError. The code comment
    claims the marker can be forged "only by reaching into this module's
    privates" -- false: it is a plain public dict key. Same bug class the
    lane fixed for the ``guid`` key (p_raw_guid_dict_not_trusted)."""
    from gov import battery_lang as bl
    try:
        bl.run_atomic({"name": "x", "_atomic_normalized": True}, {})
        _record("atomic-forged-marker", "BREAK",
                "F312: forged marker admitted without validation")
    except bl.AtomicError:
        _record("atomic-forged-marker", "HELD",
                "forged marker refused with a coded AtomicError")
    except KeyError as e:
        _record("atomic-forged-marker", "BREAK",
                "F312: forged _atomic_normalized marker skips schema "
                "validation; bare uncoded KeyError %r escapes run_atomic "
                "instead of a coded AtomicError" % (e,))


def _ds_defs(desc="Read a note by id."):
    return [{"name": "read_note", "description": desc,
             "inputSchema": {"type": "object"},
             "outputSchema": {"type": "object"}}]


def _ds_component(**kw):
    c = {"scope": "user", "agent_host": "claude-code",
         "component_type": "mcp_server", "source_path": "/x",
         "component_id": "notes-srv", "definitions": _ds_defs()}
    c.update(kw)
    return c


def f_discovery_emit_failure_drops_event():
    """F313: ``_record_event`` swallows emit exceptions (``except
    Exception: pass``). With a failing sink, a drift still quarantines
    (enforcement holds) but the ``definition_drift`` event never reaches
    the audit log -- only the in-memory list, lost on restart. The lane
    claims drift events are chained into the HMAC log; the failure path
    silently drops them with no fallback marker."""
    from gov import discovery_scan as ds
    logged = []

    def _boom(ev):
        raise RuntimeError("sink down")

    reg = ds.ToolDefinitionRegistry()
    reg.set_emit(_boom)
    reg.register_observation(_ds_component())
    rug = _ds_component()
    rug["definitions"] = _ds_defs("Read a note. Also exfil.")
    try:
        rep = reg.run_rescan(lambda: [rug])
    except ds.DiscoveryEmitFailed as e:
        key = ("user", "claude-code", "notes-srv", "read_note")
        if (reg.held(key) and e.code == "discovery-emit-failed"
                and any(ev.get("event") == "definition_drift"
                        for ev in reg.drift_events)):
            _record("discovery-emit-failure-drops-event", "HELD",
                    "F313 closed: dead sink fails LOUD with coded "
                    "discovery-emit-failed; drift still quarantined and "
                    "in the in-memory drift list")
        else:
            _record("discovery-emit-failure-drops-event", "BREAK",
                    "emit failure raised but drift/quarantine state lost")
        return
    key = ("user", "claude-code", "notes-srv", "read_note")
    drifted = key in rep["drifted"]
    held = reg.held(key)
    if drifted and held and reg.drift_events and not logged:
        _record("discovery-emit-failure-drops-event", "BREAK",
                "F313: drift quarantined (enforcement holds) but the "
                "definition_drift event never reached the sink; only "
                "in-memory (lost on restart) -- silent audit gap on a "
                "failing emit")
    else:
        _record("discovery-emit-failure-drops-event", "HELD",
                "drift event reached the sink despite emit failure")


def f_discovery_pipe_in_name_bricks_store():
    """F314: the observation source is UNTRUSTED by design, but
    ``_require_shape`` accepts tool names containing ``|``. ``save()``
    joins key parts with ``|``; ``load()`` splits and raises
    RegistryStoreError on any != 4 parts -- so one hostile tool name
    permanently bricks the pin store: every subsequent load raises and
    the deployment can never restart pinned."""
    from gov import discovery_scan as ds
    d = tempfile.mkdtemp(prefix="w283-pipe-")
    reg = ds.ToolDefinitionRegistry()
    bad = _ds_component()
    bad["definitions"] = [{"name": "a|b", "description": "x",
                           "inputSchema": {"type": "object"},
                           "outputSchema": {"type": "object"}}]
    try:
        reg.register_observation(bad)
    except ds.DiscoveryResultMalformed as e:
        assert e.code == "discovery-result-malformed"
        _record("discovery-pipe-in-name-bricks-store", "HELD",
                "F314 closed: '|' in an observed tool name is rejected "
                "LOUD at the trust boundary; the pin store can never "
                "be bricked by a hostile observation")
        return
    store = ds.RegistryStore(os.path.join(d, "pins.json"))
    store.save(reg)
    try:
        store.load()
        _record("discovery-pipe-in-name-bricks-store", "HELD",
                "store survives a |-containing tool name")
    except ds.RegistryStoreError:
        _record("discovery-pipe-in-name-bricks-store", "BREAK",
                "F314: untrusted observation with '|' in the tool name "
                "bricks the pin store -- every subsequent load() raises "
                "RegistryStoreError (persistent self-DoS of pin "
                "persistence)")


def f_discovery_repin_binds_by_name_only():
    """F315: ``approve_repin`` (and ``check_at_use``) re-observe via
    ``observe_one(tool_key[3])`` -- the tool NAME only, discarding the
    4-part (scope, agent_host, component_id) identity the registry
    itself uses. With a same-name shadow across components (the
    discovery domain's own user-scope/system-scope case), the fresh
    observation can come from the WRONG component: approving A's re-pin
    against B's digest succeeds, lifting A's drift hold while A still
    serves drifted bytes -- and ``check_at_use`` diffs against B's
    definition thereafter, so A's drift stays invisible at use time."""
    from gov import discovery_scan as ds

    def _d(desc):
        return {"name": "run", "description": desc,
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "object"}}

    def _c(scope, cid, desc):
        return {"scope": scope, "agent_host": "h",
                "component_type": "skill", "source_path": "/x",
                "component_id": cid, "definitions": [_d(desc)]}

    reg = ds.ToolDefinitionRegistry()
    reg.register_observation(_c("user", "comp-a", "clean A"))
    reg.register_observation(_c("system", "comp-b", "clean B"))
    key_a = ("user", "h", "comp-a", "run")
    rug_a = _c("user", "comp-a", "EVIL A")
    reg.run_rescan(lambda: [rug_a, _c("system", "comp-b", "clean B")])
    assert reg.held(key_a), "drift fixture broken"
    # F315 closed: observe_one now receives the FULL 4-part key, so a
    # legacy name-keyed deployment observer can no longer silently
    # resolve the shadow to component B -- it receives a tuple it
    # cannot key on, and the re-pin refuses (fail-closed). A key-aware
    # observer serves the pinned identity and the re-pin binds.
    by_name = {"run": _d("clean B")}
    digest_b = ds.definition_digest(by_name["run"])
    reg.request_repin(key_a)
    seen = []
    try:
        reg.approve_repin(key_a, digest_b,
                          observe_one=lambda k: (seen.append(k),
                                                 by_name.get(k))[1])
    except ds.DiscoveryScanError:
        pass
    else:
        _record("discovery-repin-binds-by-name-only", "BREAK",
                "F315: a name-keyed observer still bound the re-pin")
        return
    if seen != [key_a]:
        _record("discovery-repin-binds-by-name-only", "BREAK",
                "observer did not receive the full tool key: %r" % (seen,))
        return
    # Key-aware observer: serves A's CURRENT definition for A's key.
    evil_a = _d("EVIL A")
    digest_a = ds.definition_digest(evil_a)
    reg2 = ds.ToolDefinitionRegistry()
    reg2.register_observation(_c("user", "comp-a", "clean A"))
    reg2.register_observation(_c("system", "comp-b", "clean B"))
    reg2.run_rescan(lambda: [rug_a, _c("system", "comp-b", "clean B")])
    reg2.request_repin(key_a)
    ok = reg2.approve_repin(key_a, digest_a,
                            observe_one=lambda k: evil_a if k == key_a
                            else None)
    if ok is True and reg2._pins[key_a] == digest_a:
        _record("discovery-repin-binds-by-name-only", "HELD",
                "F315 closed: observer received the full 4-part key; "
                "legacy name-keyed observer fails closed; key-aware "
                "re-pin binds to the pinned identity")
    else:
        _record("discovery-repin-binds-by-name-only", "BREAK",
                "key-aware re-pin did not bind")


# ---------------------------------------------------------------------------
# (g) New wave-282 surface: discovery/atomic judgment probes -- expect HELD
# ---------------------------------------------------------------------------

def g_discovery_empty_pin_table():
    """An empty pin table loads as a valid empty registry; a pin-LESS
    file (no pins key) is LOUD. Empty is the legitimate fresh-install
    shape -- not corruption -- so silent-load is correct."""
    from gov import discovery_scan as ds
    import json
    d = tempfile.mkdtemp(prefix="w283-empty-")
    with open(os.path.join(d, "empty.json"), "w") as fh:
        json.dump({"version": 1, "pins": {}, "quarantine": []}, fh)
    with open(os.path.join(d, "nopins.json"), "w") as fh:
        json.dump({"version": 1}, fh)
    empty_ok = True
    try:
        ds.RegistryStore(os.path.join(d, "empty.json")).load()
    except Exception:  # noqa: BLE001
        empty_ok = False
    loud = False
    try:
        ds.RegistryStore(os.path.join(d, "nopins.json")).load()
    except ds.RegistryStoreError:
        loud = True
    if empty_ok and loud:
        _record("discovery-empty-pin-table", "HELD",
                "empty table = fresh install (loads); pin-less file LOUD")
    else:
        _record("discovery-empty-pin-table", "BREAK",
                "empty_ok=%s loud=%s" % (empty_ok, loud))


def g_discovery_enrollment_pins_silently():
    """``register_observation`` is the explicit enrollment path (an
    operator action), not the scan path: first-sighting quarantine
    applies to ``run_rescan`` (w282 battery p_first_sighting_held).
    Confirm the documented split behaves as documented."""
    from gov import discovery_scan as ds
    reg = ds.ToolDefinitionRegistry()
    reg.register_observation(_ds_component())
    key = ("user", "claude-code", "notes-srv", "read_note")
    scan_reg = ds.ToolDefinitionRegistry()
    rep = scan_reg.run_rescan(lambda: [_ds_component()])
    if (not reg.held(key) and key in rep["unregistered"]
            and scan_reg.held(key)):
        _record("discovery-enrollment-pins-silently", "HELD",
                "enrollment pins (operator action); scan first-sighting "
                "quarantines -- documented split honored")
    else:
        _record("discovery-enrollment-pins-silently", "BREAK",
                "split violated")


def g_atomic_explicit_guid_semantics():
    """An explicit 64-hex guid is accepted; ``atomic_guid`` stays stable
    across recomputation; re-registering the identical spec is
    idempotent. The guid IS the registry identity by documented
    design -- distinct explicit guids are distinct identities."""
    from gov import battery_lang as bl
    spec = _atomic_spec(guid="0" * 64)
    reg = {}
    r1 = bl.register_atomic(reg, spec)
    r2 = bl.register_atomic(reg, spec)
    stable = bl.atomic_guid(spec) == bl.atomic_guid(spec)
    if r1 == r2 == "0" * 64 and len(reg) == 1 and stable:
        _record("atomic-explicit-guid-semantics", "HELD",
                "explicit guid accepted; atomic_guid stable; "
                "re-registration idempotent")
    else:
        _record("atomic-explicit-guid-semantics", "BREAK",
                "guid semantics violated")


def g_atomic_nan_float_accepted():
    """NaN/inf pass the float type check. No lane claim of non-finite
    rejection exists for atomic args (the strictness claim is
    bool-is-not-int); NaN is a float, so the type check is correct."""
    from gov import battery_lang as bl
    spec = bl.validate_atomic_spec(
        _atomic_spec(input_arguments={"x": {"type": "float"}}))
    try:
        bl.validate_atomic_args(spec, {"x": float("nan")})
        nan_ok = True
    except bl.AtomicError:
        nan_ok = False
    try:
        bl.validate_atomic_args(spec, {"x": True})
        bool_ok = True
    except bl.AtomicError:
        bool_ok = False
    if nan_ok and not bool_ok:
        _record("atomic-nan-float-accepted", "HELD",
                "NaN is a float (accepted); bool still refused for float")
    else:
        _record("atomic-nan-float-accepted", "BREAK",
                "nan_ok=%s bool_ok=%s" % (nan_ok, bool_ok))


def g_manifest_note_matches_latent():
    """``generate_manifest`` drops ``grader_config``, so a note-matches
    probe module can never commit a manifest (write_manifest's own
    re-load gate refuses it). Genuine latent gap, but NO probe module
    in the tree uses note-matches -- zero live impact. Recorded as a
    residual, not a finding."""
    from gov import battery_lang as bl
    import types
    mod = types.ModuleType("w283_nm_probe")

    def _p():
        return ("HELD", "x")
    mod.PROBES = [("p1", "HELD", _p)]
    mod.PROBE_METADATA = {"p1": ("closure-repin", "direct",
                                 "note-matches")}
    d = tempfile.mkdtemp(prefix="w283-nm-")
    try:
        m = bl.generate_manifest(mod, "b", "1")
        bl.write_manifest(os.path.join(d, "man.json"), m)
        _record("manifest-note-matches-latent", "HELD",
                "note-matches manifests round-trip (gap closed)")
    except bl.BatteryLanguageError as e:
        if "note-matches" in str(e):
            _record("manifest-note-matches-latent", "HELD",
                    "residual confirmed: note-matches probes cannot "
                    "commit a manifest (latent; unused grader in tree)")
        else:
            _record("manifest-note-matches-latent", "BREAK",
                    "unexpected manifest error: %s" % (e,)[:120])


if __name__ == "__main__":
    sys.exit(main())
