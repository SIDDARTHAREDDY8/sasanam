"""Wave-280 lane 6 red-first battery: shield registry + eval-tasks-as-evidence.

Gap (base 7849c86): there is no named-shield attach surface -- no
``input_shields``/``output_shields`` wrapping the inbound turn and the
outbound response/tool call, and no ``shield_call`` loop events with a
verdict field in the audit log. Guards attach only as per-tool input
guards through the wave-279 triad. Separately, eval batteries emit
ad-hoc scores; there is no registered EvalTask record (dataset x
scoring-functions) whose run is a pinned, reproducible evidence
artifact feeding the evidence-bundle machinery.

Red-first: on base every probe BREAKs (modules absent). After the fix:
named shields register/declare/run at both seams, shield verdicts are
chained audit-loop events, shield errors FAIL CLOSED (inverting the
fail-open default seen in the wild -- an erroring shield never
silently allows), and eval tasks run headless with digests an auditor
can recompute standalone.

Pattern lineage: ogx-ai/ogx (Llama Stack successor; repo moved
meta-llama/llama-stack -> llamastack/llama-stack -> ogx-ai/ogx), MIT --
``shields register --shield-id --params``, ``AgentConfig(input_shields=
..., output_shields=...)``, ``shield_call`` step events with a
``violation`` field, and ``benchmarks register --eval-task-id
--dataset-id --scoring-functions``. This is a clean-room stdlib
re-implementation of the *mechanisms* only; no ogx code is vendored.
The inline/remote provider trust split and the fail-closed-on-error
default are enforced, not optional.
"""

import hashlib
import json
import os
import secrets
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w280-shields")
os.environ.setdefault("TMPDIR", "/var/tmp/g280-shields")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe_lines  # noqa: E402  (canonical probe-line form)

TAXONOMY_PIN = 1946 # Wave-279 merge pin. This lane adds NO decision codes.; Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_RESULTS = []


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})


def _needs_modules(probe_id):
    try:
        from gov import shield_registry as sr
        from gov import eval_tasks as et
        return sr, et
    except ImportError:
        _record(probe_id, "BREAK", "shield_registry/eval_tasks absent on base")
        return None


def _fresh_log():
    d = tempfile.mkdtemp(prefix="g280_", dir=os.environ["TMPDIR"])
    from gov.log import ActionLog
    from gov.guardrail_evidence import GuardrailEvidenceWriter
    log = ActionLog(os.path.join(d, "audit.jsonl"))
    return log, GuardrailEvidenceWriter(log)


# -- shields ---------------------------------------------------------------

def p_shields_registry_declared():
    mods = _needs_modules("p_shields_registry_declared")
    if not mods:
        return
    sr, _ = mods
    reg = sr.ShieldRegistry()
    reg.register("no-pii", provider_kind="inline",
                 params={"max_len": 100},
                 run=lambda data: sr.ShieldVerdict("allow", "clean"))
    sh = reg.get("no-pii")
    if (sh.shield_id == "no-pii" and sh.provider_kind == "inline"
            and sh.params == {"max_len": 100}
            and reg.list_shields() == ["no-pii"]):
        _record("p_shields_registry_declared", "HELD",
                "named shield registered, retrievable, listed")
    else:
        _record("p_shields_registry_declared", "BREAK",
                "registry round-trip mismatch")


def p_shields_duplicate_rejected():
    mods = _needs_modules("p_shields_duplicate_rejected")
    if not mods:
        return
    sr, _ = mods
    reg = sr.ShieldRegistry()
    reg.register("dup", run=lambda data: sr.ShieldVerdict("allow", ""))
    try:
        reg.register("dup", run=lambda data: sr.ShieldVerdict("allow", ""))
    except ValueError:
        _record("p_shields_duplicate_rejected", "HELD",
                "duplicate shield_id refused at registration")
        return
    _record("p_shields_duplicate_rejected", "BREAK",
            "duplicate shield_id silently accepted (policy shadow)")


def p_shields_unknown_refused():
    mods = _needs_modules("p_shields_unknown_refused")
    if not mods:
        return
    sr, _ = mods
    log, writer = _fresh_log()
    reg = sr.ShieldRegistry()
    try:
        sr.run_input_shields(reg, ["ghost-shield"], {"text": "hi"},
                             writer=writer)
    except Exception as exc:  # fail-closed: refusal, never skip
        if "ghost-shield" in str(exc) or type(exc).__name__ in (
                "ShieldResolutionError", "ShieldError", "ValueError"):
            _record("p_shields_unknown_refused", "HELD",
                    "unregistered shield id refused: %s" % type(exc).__name__)
            return
        _record("p_shields_unknown_refused", "BREAK",
                "unexpected exception shape: %r" % (exc,))
        return
    _record("p_shields_unknown_refused", "BREAK",
            "unregistered shield id silently skipped")


def p_shields_input_order_violation():
    mods = _needs_modules("p_shields_input_order_violation")
    if not mods:
        return
    sr, _ = mods
    _, writer = _fresh_log()
    reg = sr.ShieldRegistry()
    ran = []
    reg.register("s1", run=lambda data: ran.append("s1") or
                 sr.ShieldVerdict("allow", "ok"))
    reg.register("s2", run=lambda data: ran.append("s2") or
                 sr.ShieldVerdict("violation", "pii detected"))
    reg.register("s3", run=lambda data: ran.append("s3") or
                 sr.ShieldVerdict("allow", "ok"))
    try:
        sr.run_input_shields(reg, ["s1", "s2", "s3"], {"text": "x"},
                             writer=writer)
    except sr.ShieldViolation as exc:
        if ran == ["s1", "s2"] and "pii detected" in str(exc):
            _record("p_shields_input_order_violation", "HELD",
                    "first violation decisive, later shields not run")
            return
        _record("p_shields_input_order_violation", "BREAK",
                "order/decisiveness wrong: ran=%r" % (ran,))
        return
    _record("p_shields_input_order_violation", "BREAK",
            "violation did not raise")


def p_shields_output_gate():
    mods = _needs_modules("p_shields_output_gate")
    if not mods:
        return
    sr, _ = mods
    _, writer = _fresh_log()
    reg = sr.ShieldRegistry()
    reg.register("out-scan",
                 run=lambda data: sr.ShieldVerdict(
                     "violation", "output contains forbidden content"))
    try:
        sr.run_output_shields(reg, ["out-scan"], {"result": "leak"},
                              writer=writer)
    except sr.ShieldViolation:
        _record("p_shields_output_gate", "HELD",
                "output shield violation blocks at the output gate")
        return
    _record("p_shields_output_gate", "BREAK", "output violation passed")


def p_shields_error_fails_closed():
    """The ogx cautionary data point inverted: a shield that raises
    must fail closed -- never silently allow, never record a block."""
    mods = _needs_modules("p_shields_error_fails_closed")
    if not mods:
        return
    sr, _ = mods
    from gov import guardrail_evidence as ge
    log, writer = _fresh_log()
    reg = sr.ShieldRegistry()

    def _boom(data):
        raise RuntimeError("scanner exploded")

    reg.register("crashy", run=_boom)
    raised = None
    try:
        sr.run_input_shields(reg, ["crashy"], {"text": "x"}, writer=writer)
    except Exception as exc:
        raised = exc
    records = ge.guardrail_run_records(log)
    rec = records[-1] if records else {}
    if (raised is not None
            and not isinstance(raised, sr.ShieldViolation)
            and rec.get("outcome") == "technical_failure"
            and rec.get("guardrail_id") == "shield:crashy"):
        _record("p_shields_error_fails_closed", "HELD",
                "crashing shield fails closed as technical_failure "
                "(%s), never allow" % type(raised).__name__)
    else:
        _record("p_shields_error_fails_closed", "BREAK",
                "crashing shield did not fail closed: raised=%r "
                "record=%r" % (raised, rec))


def p_shields_loop_events_chained():
    mods = _needs_modules("p_shields_loop_events_chained")
    if not mods:
        return
    sr, _ = mods
    from gov import guardrail_evidence as ge
    log, writer = _fresh_log()
    reg = sr.ShieldRegistry()
    reg.register("clean", run=lambda data: sr.ShieldVerdict("allow", "ok"))
    reg.register("dirty", run=lambda data: sr.ShieldVerdict(
        "violation", "blocked"))
    sr.run_input_shields(reg, ["clean"], {"text": "a"}, writer=writer)
    try:
        sr.run_output_shields(reg, ["dirty"], {"result": "b"},
                              writer=writer)
    except sr.ShieldViolation:
        pass
    records = ge.guardrail_run_records(log)
    by_id = {r["guardrail_id"]: r for r in records}
    if (ge.verify_guardrail_records(records)
            and by_id.get("shield:clean", {}).get("outcome") == "allow"
            and by_id.get("shield:dirty", {}).get("outcome")
            == "intentional_block"
            and by_id["shield:clean"]["event_scope"] == "input_shield"
            and by_id["shield:dirty"]["event_scope"] == "output_shield"):
        _record("p_shields_loop_events_chained", "HELD",
                "%d shield verdicts as chained loop events" % len(records))
    else:
        _record("p_shields_loop_events_chained", "BREAK",
                "shield verdict loop events missing/mis-shaped")


def p_shields_triad_composition():
    mods = _needs_modules("p_shields_triad_composition")
    if not mods:
        return
    sr, _ = mods
    from gov import tool_guardrails as tg
    ok_sh = sr.Shield("allow-sh", provider_kind="inline", params={}, run=lambda data:
                      sr.ShieldVerdict("allow", "fine"))
    bad_sh = sr.Shield("deny-sh", provider_kind="inline", params={}, run=lambda data:
                       sr.ShieldVerdict("violation", "policy says no"))
    boom_sh = sr.Shield("boom-sh", provider_kind="inline", params={}, run=lambda data:
                        (_ for _ in ()).throw(RuntimeError("x")))
    g_ok = sr.as_tool_input_guardrail(ok_sh)
    g_bad = sr.as_tool_input_guardrail(bad_sh)
    g_boom = sr.as_tool_input_guardrail(boom_sh)
    v_ok = tg.run_input_guardrails(
        [g_ok], tg.ToolInputGuardrailData("tool", {"a": 1}))
    v_bad = tg.run_input_guardrails(
        [g_bad], tg.ToolInputGuardrailData("tool", {"a": 1}))
    try:
        tg.run_input_guardrails(
            [g_boom], tg.ToolInputGuardrailData("tool", {"a": 1}))
        tripped = None
    except tg.ToolGuardrailTripwireTriggered as exc:
        tripped = exc
    if (v_ok.outcome == "allow" and not v_ok.tripwire_triggered
            and v_bad.outcome == "reject_content"
            and v_bad.message == "policy says no"
            and not v_bad.tripwire_triggered
            and tripped is not None):
        _record("p_shields_triad_composition", "HELD",
                "shield->triad: allow/reject_content(with detail)/tripwire")
    else:
        _record("p_shields_triad_composition", "BREAK",
                "triad composition wrong: %r %r %r"
                % (v_ok.outcome, v_bad.outcome, tripped))


def p_shields_remote_boundary():
    mods = _needs_modules("p_shields_remote_boundary")
    if not mods:
        return
    sr, _ = mods
    from gov import guardrail_evidence as ge
    log, writer = _fresh_log()
    reg = sr.ShieldRegistry()
    # remote without a declared endpoint: fail fast at registration
    try:
        reg.register("remote-x", provider_kind="remote",
                     run=lambda data: sr.ShieldVerdict("allow", ""))
    except ValueError:
        refused = True
    else:
        refused = False
    reg.register("remote-y", provider_kind="remote",
                 endpoint="https://shields.example/v1",
                 run=lambda data: sr.ShieldVerdict("allow", "remote-ok"))
    sr.run_input_shields(reg, ["remote-y"], {"text": "z"}, writer=writer)
    rec = ge.guardrail_run_records(log)[-1]
    if (refused and rec.get("outcome") == "allow"
            and reg.get("remote-y").provider_kind == "remote"):
        _record("p_shields_remote_boundary", "HELD",
                "remote shield needs a declared endpoint; verdicts "
                "carried across the boundary")
    else:
        _record("p_shields_remote_boundary", "BREAK",
                "remote boundary discipline broken: refused=%r rec=%r"
                % (refused, rec))


def p_shields_params_json():
    mods = _needs_modules("p_shields_params_json")
    if not mods:
        return
    sr, _ = mods
    reg = sr.ShieldRegistry()
    try:
        reg.register("weird", params={"fn": object()},
                     run=lambda data: sr.ShieldVerdict("allow", ""))
    except ValueError:
        _record("p_shields_params_json", "HELD",
                "non-JSON params refused at registration")
        return
    _record("p_shields_params_json", "BREAK",
            "non-JSON params accepted (audit record would not round-trip)")


# -- eval tasks ------------------------------------------------------------

def _sample_et():
    from gov import eval_tasks as et
    reg = et.EvalTaskRegistry()

    def _grader(sample, output):
        return 1.0 if output == sample["want"] else 0.0

    reg.register_dataset("ds1", [{"q": "a", "want": "A"},
                                 {"q": "b", "want": "B"}])
    reg.register_scoring_function("exact", _grader)
    reg.register_eval_task("t1", dataset_id="ds1", scoring_ids=["exact"],
                           run_config={"temperature": 0})
    return reg


def p_evaltask_pinned():
    mods = _needs_modules("p_evaltask_pinned")
    if not mods:
        return
    _, et = mods
    reg = _sample_et()
    task = reg.get_eval_task("t1")
    ds = reg.get_dataset("ds1")
    fn = reg.get_scoring_function("exact")
    if (task["dataset_digest"] == ds["dataset_digest"]
            and task["scoring_functions"]["exact"] == fn["digest"]):
        _record("p_evaltask_pinned", "HELD",
                "eval task pins dataset + scoring-function digests")
    else:
        _record("p_evaltask_pinned", "BREAK", "pin digests mismatch")


def p_evaltask_headless_run():
    mods = _needs_modules("p_evaltask_headless_run")
    if not mods:
        return
    _, et = mods
    reg = _sample_et()

    def _target(sample):
        return sample["want"]

    res = et.run_eval_task(reg, "t1", target=_target)
    mean = res["means"]["exact"]
    if (mean == 1.0 and res["sample_count"] == 2
            and et.verify_eval_result(res)):
        _record("p_evaltask_headless_run", "HELD",
                "headless run: mean=1.0, sample_count=2, digest verifies")
    else:
        _record("p_evaltask_headless_run", "BREAK",
                "run/record wrong: %r" % (res,))


def p_evaltask_tamper():
    mods = _needs_modules("p_evaltask_tamper")
    if not mods:
        return
    _, et = mods
    reg = _sample_et()

    def _target(sample):
        return sample["want"]

    res = et.run_eval_task(reg, "t1", target=_target)
    # attacker rewrites a per-sample score
    res["per_sample"][0]["scores"]["exact"] = 0.0
    if not et.verify_eval_result(res):
        _record("p_evaltask_tamper", "HELD",
                "rewritten score fails standalone verification")
    else:
        _record("p_evaltask_tamper", "BREAK", "tampered result verified")


def p_evaltask_grader_crash_loud():
    mods = _needs_modules("p_evaltask_grader_crash_loud")
    if not mods:
        return
    _, et = mods
    reg = et.EvalTaskRegistry()

    def _bad_grader(sample, output):
        raise RuntimeError("grader exploded")

    reg.register_dataset("ds2", [{"q": "a", "want": "A"}])
    reg.register_scoring_function("bad", _bad_grader)
    reg.register_eval_task("t2", dataset_id="ds2", scoring_ids=["bad"])
    try:
        et.run_eval_task(reg, "t2", target=lambda s: "A")
    except et.EvalTaskError:
        _record("p_evaltask_grader_crash_loud", "HELD",
                "crashing grader fails loud, no silent zeros")
        return
    _record("p_evaltask_grader_crash_loud", "BREAK",
            "crashing grader did not fail the run")


def p_evaltask_evidence_package():
    mods = _needs_modules("p_evaltask_evidence_package")
    if not mods:
        return
    _, et = mods
    reg = _sample_et()

    def _target(sample):
        return sample["want"]

    res = et.run_eval_task(reg, "t1", target=_target)
    pkg = et.eval_task_evidence_package(res)
    # standalone: recompute the package digest from the package body
    body = {k: pkg[k] for k in pkg if k != "package_digest"}
    expect = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, default=str).encode("utf-8")).hexdigest()
    if pkg.get("package_digest") == expect and pkg["eval_task_id"] == "t1":
        _record("p_evaltask_evidence_package", "HELD",
                "evidence package verifies standalone")
    else:
        _record("p_evaltask_evidence_package", "BREAK",
                "package digest mismatch")


# -- taxonomy ---------------------------------------------------------------

def p_shields_labels_boundary():
    mods = _needs_modules("p_shields_labels_boundary")
    if not mods:
        return
    sr, _ = mods
    from gov.guardrail_evidence import guardrail_run_records,\
        verify_guardrail_records
    log, w = _fresh_log()
    reg = sr.ShieldRegistry()
    reg.register("local-check", provider_kind="inline",
                 run=lambda data: sr.ShieldVerdict("allow", "ok"))
    reg.register("remote-check", provider_kind="remote",
                 endpoint="https://shields.example/v1",
                 run=lambda data: sr.ShieldVerdict("allow", "ok"))
    sr.run_input_shields(reg, ["local-check", "remote-check"],
                         {"text": "hello"}, writer=w)
    recs = guardrail_run_records(log)
    if not verify_guardrail_records(recs):
        _record("p_shields_labels_boundary", "BREAK",
                "records failed verification")
        return
    by_id = {r["guardrail_id"]: r for r in recs}
    if by_id["shield:local-check"]["labels"] == {"provider_kind": "inline"}\
            and by_id["shield:remote-check"]["labels"] ==\
            {"provider_kind": "remote"}:
        _record("p_shields_labels_boundary", "HELD",
                "provider_kind is a first-class record label, digested")
    else:
        _record("p_shields_labels_boundary", "BREAK",
                "labels missing or wrong: %r"
                % {k: v.get("labels") for k, v in by_id.items()})


def p_evaltask_bundle_feed():
    mods = _needs_modules("p_evaltask_bundle_feed")
    if not mods:
        return
    _, et = mods
    from tests.keyfixture import provision_test_key, scrub_key_env
    restore = scrub_key_env()  # hermetic: never depend on ambient keys
    provision_test_key()
    try:
        reg = _sample_et()
        res = et.run_eval_task(reg, "t1", target=lambda s: s["want"])
        log, _ = _fresh_log()
        log.append({"event": "policy_loaded", "run_id": "r1",
                    "agent_id": "system", "decision": "policy_loaded",
                    "policy_id": "policy-pin", "policy_path": "/x",
                    "policy_hash": "ab" * 32, "pinned": True,
                    "reason": "probe"})
        pkg = et.bind_eval_task_result(log, "t1", res, run_id="r1",
                                       agent_id="eval-harness")
        from gov.evidence_bundle import EvidenceBundle
        from gov.signing import Ed25519Signer
        signer = Ed25519Signer(secrets.token_bytes(32))
        eb = EvidenceBundle(log.path)
        manifest = eb.seal(eb.build(), signer=signer)
        from gov.log import read_entries
        found = [e for e in read_entries(log.path)
                 if e.get("event") == "eval-task-result"]
        if manifest.get("chain_verified") and len(found) == 1\
                and found[0]["package"] == pkg:
            _record("p_evaltask_bundle_feed", "HELD",
                    "eval result bound to the log and rode the sealed bundle")
        else:
            _record("p_evaltask_bundle_feed", "BREAK",
                    "bundle feed broken: chain_verified=%r entries=%d"
                    % (manifest.get("chain_verified"), len(found)))
    finally:
        restore()


def p_taxonomy_pin():
    import re
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    lits = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if len(lits) == TAXONOMY_PIN == len(set(lits)):
        _record("p_taxonomy_pin", "HELD",
                "taxonomy %d/%d/0 sorted" % (TAXONOMY_PIN, TAXONOMY_PIN))
    else:
        _record("p_taxonomy_pin", "BREAK",
                "taxonomy drift: %d raw / %d unique (pin %d)"
                % (len(lits), len(set(lits)), TAXONOMY_PIN))


# -- main -------------------------------------------------------------------

def _green_checks():
    # Depth-1: adjacent suites only, never spawn another battery's main.
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "SKIP", "GOV_SKIP_GREEN=1")
        return
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    checks = (["-m", "unittest", "tests.test_decision_codes"],
              [os.path.join(here, "w279_guardev_probes.py")])
    for argv in checks:
        r = subprocess.run([sys.executable] + argv,
                           cwd=os.path.dirname(here), env=env,
                           capture_output=True, text=True, timeout=300)
        tail = (r.stderr or r.stdout)[-200:].replace("\n", " | ")
        _record("green-check_" + os.path.basename(argv[-1]),
                "HELD" if r.returncode == 0 else "ERROR", tail)


def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    for probe in (p_shields_registry_declared, p_shields_duplicate_rejected,
                  p_shields_unknown_refused, p_shields_input_order_violation,
                  p_shields_output_gate, p_shields_error_fails_closed,
                  p_shields_loop_events_chained,
                  p_shields_triad_composition, p_shields_remote_boundary,
                  p_shields_params_json, p_evaltask_pinned,
                  p_evaltask_headless_run, p_evaltask_tamper,
                  p_evaltask_grader_crash_loud, p_evaltask_evidence_package,
                  p_shields_labels_boundary, p_evaltask_bundle_feed,
                  p_taxonomy_pin):
        try:
            probe()
        except Exception as e:  # noqa: BLE001 - battery must never die
            _record(probe.__name__, "ERROR", "%r" % (e,))
    _green_checks()
    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    print("w280_shields: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    probe_lines.emit_dicts(_RESULTS, verdict_key="verdict",
                           pid_key="probe_id", note_key="note")
    mism = [r for r in _RESULTS if r["verdict"] == "ERROR"]
    return 1 if (n_break or mism) else 0


if __name__ == "__main__":
    sys.exit(main())
