"""Wave-286 lane 8 red-first battery: KubeArmor+Istio-pattern tool-call policy.

Base: wave-285 push 76e0f24. The gap under test is the agent->tool runtime
seam: gov/sandbox_policy.py decides CONTAINMENT (namespaces/rlimits/syscalls)
but nothing decides AUTHORIZATION -- which agent identity may call which
tool with which arguments, under which rollout mode, with what evidence.
kubearmor/KubeArmor (Apache-2.0 root; GPL-2.0 BPF tree EXCLUDED -- pattern
only) supplies the mechanisms: fromSource caller binding, one-schema
compile, Audit-before-Block rollout, Alert evidence with hash-bound runtime
identity. istio/istio (Apache-2.0 on `master`) supplies the deterministic
CUSTOM->DENY->ALLOW rule-combining order and the AUDIT/dry-run
deployment-evidence pattern (Istio's dry-run telemetry is documented as
"not an API, may change anytime" -- Sasanam's audit-mode evidence is our
own stable schema, not a copy of Istio's metric names).

Red-first: on the pristine base (module absent) every capability probe
BREAKs. After the build, all HELD in staging and under
env -u GOV_DEPLOYMENT_MODE.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g286-toolpolicy && TMPDIR=/var/tmp/g286-toolpolicy \\
    ~/workspace/.gov-venv/bin/python evals/w286_toolpolicy_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g286-toolpolicy2 \\
    ~/workspace/.gov-venv/bin/python evals/w286_toolpolicy_probes.py
"""

import hashlib
import inspect
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w286-toolpolicy")
os.environ.setdefault("TMPDIR", "/var/tmp/g286-toolpolicy")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Wave-286 lane 8: pin 1652 -> 1652 (+11 toolcall-* codes).
TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)


_RESULTS = []

PLUGIN_META = ("toolcall-policy", "direct", "held-vs-expected")
PROBE_METADATA = {}

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict,
                     "note": note})
    PROBE_METADATA.setdefault(probe_id, PLUGIN_META)


def _needs_module(probe_id):
    try:
        from gov import tool_call_policy as tcp
        return tcp
    except ImportError:
        _record(probe_id, "BREAK", "gov.tool_call_policy absent on base")
        return None


def _literals():
    with open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "gov", "decision_codes.py"),
            encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def _policy(tcp, mode="enforce", rules=None):
    doc = {
        "format": "sasanam-tool-call-policy/v1",
        "name": "probe-policy",
        "selector": {"agents": ["agent-a", "agent-b"]},
        "mode": mode,
        "rules": rules if rules is not None else [],
    }
    return tcp.compile_policy(doc)


def _caller(ident="agent-a", authenticated=True, tags=None):
    return {"identity": ident, "authenticated": authenticated,
            "tags": tags or []}


# ---------------------------------------------------------------------------
# Capability probes (BREAK on base by missing module; HELD after the build)
# ---------------------------------------------------------------------------

def p_module_present():
    tcp = _needs_module("module-present")
    if tcp is None:
        return
    _record("module-present", "HELD", "gov.tool_call_policy importable")


def p_taxonomy_pin():
    lits = _literals()
    uniq = sorted(set(lits))
    if len(lits) != TAXONOMY_PIN or len(uniq) != TAXONOMY_PIN \
            or uniq != sorted(lits):
        _record("taxonomy-pin", "BREAK",
                "taxonomy %d raw / %d unique (pin %d)"
                % (len(lits), len(uniq), TAXONOMY_PIN))
        return
    for code in ("toolcall-unauthenticated-caller", "toolcall-policy-invalid",
                 "toolcall-policy-unpinned", "toolcall-policy-drift",
                 "toolcall-caller-out-of-scope", "toolcall-call-denied",
                 "toolcall-custom-denied",
                 "toolcall-no-allow", "toolcall-audit-would-deny",
                 "toolcall-exception-suppressed",
                 "toolcall-no-covering-exception"):
        if code not in uniq:
            _record("taxonomy-pin", "BREAK", "missing toolcall code %s"
                    % code)
            return
    _record("taxonomy-pin", "HELD",
            "%d/%d/0 sorted, toolcall-* codes present" % (len(lits),
                                                        len(uniq)))


def p_fromsource_binding():
    tcp = _needs_module("fromsource-binding")
    if tcp is None:
        return
    pol = _policy(tcp, rules=[
        {"from_source": "agent-a", "tool": "shell", "operation": "exec",
         "action": "ALLOW", "severity": 3, "message": "a may exec"},
    ])
    ok = pol.decide(_caller("agent-a"), "shell", "exec", {})
    if ok.verdict != "ALLOW":
        _record("fromsource-binding", "BREAK",
                "bound caller not allowed: %r" % (ok.verdict,))
        return
    denied = pol.decide(_caller("agent-b"), "shell", "exec", {})
    if denied.verdict != "DENY":
        _record("fromsource-binding", "BREAK",
                "unbound caller not denied: %r" % (denied.verdict,))
        return
    _record("fromsource-binding", "HELD",
            "from_source binds the caller; unbound callers fall through")


def p_unauthenticated_caller_refused():
    tcp = _needs_module("unauthenticated-caller-refused")
    if tcp is None:
        return
    pol = _policy(tcp, rules=[
        {"tool": "shell", "operation": "exec", "action": "ALLOW",
         "severity": 3, "message": "open"},
    ])
    try:
        pol.decide(_caller("agent-a", authenticated=False), "shell",
                   "exec", {})
    except tcp.ToolCallPolicyError as e:
        if e.code != "toolcall-unauthenticated-caller":
            _record("unauthenticated-caller-refused", "BREAK",
                    "wrong code: %r" % (e.code,))
            return
        layer = pol.alerts()[-1].get("rejection_layer")
        if layer != "authn":
            _record("unauthenticated-caller-refused", "BREAK",
                    "rejection_layer %r != authn" % (layer,))
            return
        _record("unauthenticated-caller-refused", "HELD",
                "identity-before-authorization: LOUD authn-layer refusal")
        return
    _record("unauthenticated-caller-refused", "BREAK",
            "unauthenticated caller was authorized")


def p_combining_deny_beats_allow():
    tcp = _needs_module("combining-deny-beats-allow")
    if tcp is None:
        return
    pol = _policy(tcp, rules=[
        {"tool": "shell", "operation": "exec", "action": "ALLOW",
         "severity": 3, "message": "allow"},
        {"tool": "shell", "operation": "exec", "action": "DENY",
         "severity": 8, "message": "deny"},
    ])
    d = pol.decide(_caller("agent-a"), "shell", "exec", {})
    if d.verdict != "DENY":
        _record("combining-deny-beats-allow", "BREAK",
                "DENY did not win over ALLOW: %r" % (d.verdict,))
        return
    if d.rule_index != 1:
        _record("combining-deny-beats-allow", "BREAK",
                "denial did not name the DENY rule index: %r"
                % (d.rule_index,))
        return
    _record("combining-deny-beats-allow", "HELD",
            "CUSTOM->DENY->ALLOW: DENY wins, rule index named in evidence")


def p_custom_before_deny():
    tcp = _needs_module("custom-before-deny")
    if tcp is None:
        return
    tcp.register_authorizer("strict", lambda ctx: "deny")
    pol = _policy(tcp, rules=[
        {"tool": "shell", "operation": "exec", "action": "CUSTOM",
         "custom_authorizer": "strict", "severity": 8,
         "message": "custom first"},
        {"tool": "shell", "operation": "exec", "action": "DENY",
         "severity": 8, "message": "native deny"},
    ])
    d = pol.decide(_caller("agent-a"), "shell", "exec", {})
    if d.verdict != "DENY":
        _record("custom-before-deny", "BREAK",
                "custom denial did not produce DENY: %r" % (d.verdict,))
        return
    if d.rejection_layer != "custom":
        _record("custom-before-deny", "BREAK",
                "rejection_layer %r != custom" % (d.rejection_layer,))
        return
    _record("custom-before-deny", "HELD",
            "CUSTOM evaluated before native DENY, layer recorded")


def p_custom_tighten_only():
    tcp = _needs_module("custom-tighten-only")
    if tcp is None:
        return
    tcp.register_authorizer("permissive", lambda ctx: "allow")
    # Case 1: native DENY + custom allow -> still DENY (cannot loosen).
    pol = _policy(tcp, rules=[
        {"tool": "shell", "operation": "exec", "action": "DENY",
         "severity": 8, "message": "native deny"},
        {"tool": "shell", "operation": "exec", "action": "CUSTOM",
         "custom_authorizer": "permissive", "severity": 8,
         "message": "custom allow"},
    ])
    d = pol.decide(_caller("agent-a"), "shell", "exec", {})
    if d.verdict != "DENY":
        _record("custom-tighten-only", "BREAK",
                "custom allow loosened a native DENY: %r" % (d.verdict,))
        return
    # Case 2: native ALLOW + custom deny -> DENY (can tighten).
    tcp.register_authorizer("strict2", lambda ctx: "deny")
    pol2 = _policy(tcp, rules=[
        {"tool": "shell", "operation": "exec", "action": "ALLOW",
         "severity": 3, "message": "native allow"},
        {"tool": "shell", "operation": "exec", "action": "CUSTOM",
         "custom_authorizer": "strict2", "severity": 8,
         "message": "custom deny"},
    ])
    d2 = pol2.decide(_caller("agent-a"), "shell", "exec", {})
    if d2.verdict != "DENY" or d2.rejection_layer != "custom":
        _record("custom-tighten-only", "BREAK",
                "custom deny did not tighten: %r/%r"
                % (d2.verdict, d2.rejection_layer))
        return
    _record("custom-tighten-only", "HELD",
            "CUSTOM can only tighten, never loosen")


def p_default_deny():
    tcp = _needs_module("default-deny")
    if tcp is None:
        return
    pol = _policy(tcp, rules=[
        {"tool": "other", "operation": "read", "action": "ALLOW",
         "severity": 3, "message": "unrelated"},
    ])
    d = pol.decide(_caller("agent-a"), "shell", "exec", {})
    if d.verdict != "DENY":
        _record("default-deny", "BREAK",
                "unmatched call not denied: %r" % (d.verdict,))
        return
    if pol.alerts()[-1].get("result") != "denied":
        _record("default-deny", "BREAK", "no denial alert emitted")
        return
    _record("default-deny", "HELD",
            "no rule match -> default DENY (documented Istio divergence)")


def p_deny_missing_attr_matches():
    tcp = _needs_module("deny-missing-attr-matches")
    if tcp is None:
        return
    pol = _policy(tcp, rules=[
        {"tool": "shell", "operation": "exec", "action": "DENY",
         "args": {"path": {"equals": "/etc/passwd"}}, "severity": 9,
         "message": "sensitive path"},
    ])
    # The call omits 'path' entirely: a DENY rule still matches
    # (fail-closed on under-specification, the Istio TCP lesson).
    d = pol.decide(_caller("agent-a"), "shell", "exec", {})
    if d.verdict != "DENY":
        _record("deny-missing-attr-matches", "BREAK",
                "DENY rule missed the under-specified call: %r"
                % (d.verdict,))
        return
    _record("deny-missing-attr-matches", "HELD",
            "DENY rules match under-specified calls (fail-closed)")


def p_allow_missing_attr_no_match():
    tcp = _needs_module("allow-missing-attr-no-match")
    if tcp is None:
        return
    pol = _policy(tcp, rules=[
        {"tool": "shell", "operation": "exec", "action": "ALLOW",
         "args": {"mode": {"equals": "read-only"}}, "severity": 3,
         "message": "read-only allow"},
    ])
    # The call omits 'mode': the ALLOW rule must NOT match; the call
    # falls through to default deny rather than the allow rule.
    d = pol.decide(_caller("agent-a"), "shell", "exec", {})
    if d.verdict != "DENY" or d.rule_index is not None:
        _record("allow-missing-attr-no-match", "BREAK",
                "ALLOW rule matched an under-specified call: %r/%r"
                % (d.verdict, d.rule_index))
        return
    _record("allow-missing-attr-no-match", "HELD",
            "ALLOW rules require the constrained args to be present")


def p_audit_mode_would_deny():
    tcp = _needs_module("audit-mode-would-deny")
    if tcp is None:
        return
    pol = _policy(tcp, mode="audit", rules=[
        {"tool": "shell", "operation": "exec", "action": "DENY",
         "severity": 8, "message": "would deny"},
    ])
    d = pol.decide(_caller("agent-a"), "shell", "exec", {})
    if d.verdict != "ALLOW":
        _record("audit-mode-would-deny", "BREAK",
                "audit mode enforced the denial: %r" % (d.verdict,))
        return
    alert = pol.alerts()[-1]
    if alert.get("action") != "AUDIT" or alert.get("result") != "would-deny":
        _record("audit-mode-would-deny", "BREAK",
                "prospective evidence missing: %r" % (alert,))
        return
    _record("audit-mode-would-deny", "HELD",
            "audit mode emits would-deny evidence without enforcing")


def p_alert_evidence_shape():
    tcp = _needs_module("alert-evidence-shape")
    if tcp is None:
        return
    pol = _policy(tcp, rules=[
        {"tool": "shell", "operation": "exec", "action": "ALLOW",
         "severity": 3, "tags": ["t"], "message": "ok"},
    ])
    args = {"path": "/tmp/x"}
    d1 = pol.decide(_caller("agent-a"), "shell", "exec", args)
    d2 = pol.decide(_caller("agent-a"), "shell", "exec", args)
    a1, a2 = d1.alert, d2.alert
    want = {"record_type", "timestamp", "policy_name", "policy_digest",
            "rule_index", "rule_action", "severity", "tags", "message",
            "source", "operation", "tool", "args_digest",
            "runtime_identity_hash", "action", "result", "code",
            "rejection_layer"}
    if set(a1) != want:
        _record("alert-evidence-shape", "BREAK",
                "alert keys %r != %r" % (sorted(a1), sorted(want)))
        return
    if a1["runtime_identity_hash"] != a2["runtime_identity_hash"]:
        _record("alert-evidence-shape", "BREAK",
                "identical calls produced different identity hashes")
        return
    d3 = pol.decide(_caller("agent-a"), "shell", "exec",
                    {"path": "/tmp/y"})
    if d3.alert["runtime_identity_hash"] == a1["runtime_identity_hash"]:
        _record("alert-evidence-shape", "BREAK",
                "identity hash did not bind the arguments")
        return
    if len(a1["runtime_identity_hash"]) != 64 or \
            not re.fullmatch(r"[0-9a-f]{64}",
                             a1["runtime_identity_hash"]):
        _record("alert-evidence-shape", "BREAK",
                "runtime_identity_hash not a 64-hex digest")
        return
    _record("alert-evidence-shape", "HELD",
            "Alert-shaped evidence, hash-bound runtime identity")


def p_unpinned_refused():
    tcp = _needs_module("unpinned-refused")
    if tcp is None:
        return
    pol = _policy(tcp, rules=[
        {"tool": "shell", "operation": "exec", "action": "ALLOW",
         "severity": 3, "message": "ok"},
    ])
    try:
        tcp.bind(pol, None)
    except tcp.ToolCallPolicyError as e:
        if e.code != "toolcall-policy-unpinned":
            _record("unpinned-refused", "BREAK", "wrong code: %r"
                    % (e.code,))
            return
        _record("unpinned-refused", "HELD",
                "unpinned policy binding refused fail-closed")
        return
    _record("unpinned-refused", "BREAK", "unpinned bind was allowed")


def p_drift_refused():
    tcp = _needs_module("drift-refused")
    if tcp is None:
        return
    doc = {"format": "sasanam-tool-call-policy/v1", "name": "p",
           "selector": {"agents": ["agent-a"]}, "mode": "enforce",
           "rules": [{"tool": "shell", "operation": "exec",
                      "action": "ALLOW", "severity": 3,
                      "message": "ok"}]}
    pol = tcp.compile_policy(dict(doc))
    pin = pol.digest
    # F340: the compiled document is deep-frozen -- tampering after
    # compile is blocked at the source (TypeError), so no drifted
    # document can reach bind(). A freeze-bypassing wholesale replacement
    # is still caught by bind()'s pin re-verification.
    try:
        pol._doc["rules"][0]["action"] = "DENY"
    except TypeError:
        _record("drift-refused", "HELD",
                "compiled policy frozen: post-compile mutation blocked "
                "at the source")
        return
    try:
        tcp.bind(pol, pin)
    except tcp.ToolCallPolicyError as e:
        if e.code != "toolcall-policy-drift":
            _record("drift-refused", "BREAK", "wrong code: %r"
                    % (e.code,))
            return
        _record("drift-refused", "HELD",
                "drifted policy refused at bind")
        return
    _record("drift-refused", "BREAK", "drifted policy bound cleanly")


def p_exception_suppress_skipped():
    tcp = _needs_module("exception-suppress-skipped")
    if tcp is None:
        return
    from gov import governed_exceptions as ge
    pol = _policy(tcp, rules=[
        {"tool": "shell", "operation": "exec", "action": "DENY",
         "severity": 8, "message": "denied"},
    ])
    d = pol.decide(_caller("agent-a"), "shell", "exec", {})
    if d.verdict != "DENY":
        _record("exception-suppress-skipped", "BREAK",
                "expected DENY, got %r" % (d.verdict,))
        return
    reg = ge.CheckRegistry()
    reg.register("TOOLCALL_DENY_1", "denied tool call", "policy", "high",
                 "test check", ["tool_call"])
    store = ge.ExceptionStore(reg)
    store.set_approvers(["op-1"])
    now = 1700000000.0
    exc = store.grant("TOOLCALL_DENY_1", ("tool", "shell"),
                      "risk accepted for the probe window by ops review",
                      "op-1", now + 30 * 24 * 3600, now, now=now)
    s = tcp.suppress_with_exception(pol, d.alert["runtime_identity_hash"],
                                    store, "TOOLCALL_DENY_1",
                                    ("tool", "shell"), now=now)
    if s["action"] != "SKIPPED" or not s.get("exception_digest"):
        _record("exception-suppress-skipped", "BREAK",
                "suppression not SKIPPED-with-digest: %r" % (s,))
        return
    if s.get("verdict") == "ALLOW" or s.get("result") == "passed":
        _record("exception-suppress-skipped", "BREAK",
                "exception converted the denial into a pass")
        return
    _record("exception-suppress-skipped", "HELD",
            "governed exception -> SKIPPED with digest; verdict stays DENY")


def p_malformed_inputs_refused():
    tcp = _needs_module("malformed-inputs-refused")
    if tcp is None:
        return
    pol = _policy(tcp, rules=[
        {"tool": "shell", "operation": "exec", "action": "ALLOW",
         "severity": 3, "message": "ok"},
    ])
    cases = [
        ("non-dict caller", (None, "shell", "exec", {})),
        ("non-dict args", (_caller("agent-a"), "shell", "exec",
                           [("p", "x")])),
    ]
    for name, (caller, tool, op, args) in cases:
        try:
            pol.decide(caller, tool, op, args)
        except tcp.ToolCallPolicyError:
            continue
        except Exception as e:  # noqa: BLE001
            _record("malformed-inputs-refused", "BREAK",
                    "%s: non-coded %r" % (name, e))
            return
        _record("malformed-inputs-refused", "BREAK",
                "%s: no refusal" % name)
        return
    _record("malformed-inputs-refused", "HELD",
            "malformed caller/args refused with coded errors")


def p_no_covering_exception_refused():
    tcp = _needs_module("no-covering-exception-refused")
    if tcp is None:
        return
    from gov import governed_exceptions as ge
    pol = _policy(tcp, rules=[
        {"tool": "shell", "operation": "exec", "action": "DENY",
         "severity": 8, "message": "denied"},
    ])
    d = pol.decide(_caller("agent-a"), "shell", "exec", {})
    reg = ge.CheckRegistry()
    reg.register("TOOLCALL_DENY_1", "denied tool call", "policy", "high",
                 "test check", ["tool_call"])
    store = ge.ExceptionStore(reg)  # no grant: nothing covers the scope
    try:
        tcp.suppress_with_exception(pol, d.alert["runtime_identity_hash"],
                                    store, "TOOLCALL_DENY_1",
                                    ("tool", "shell"))
    except tcp.ToolCallPolicyError as e:
        if e.code != "toolcall-no-covering-exception":
            _record("no-covering-exception-refused", "BREAK",
                    "wrong code: %r" % (e.code,))
            return
        _record("no-covering-exception-refused", "HELD",
                "suppression without a live exception refused LOUD")
        return
    _record("no-covering-exception-refused", "BREAK",
            "suppression succeeded with no covering exception")


def p_no_adhoc_skip():
    tcp = _needs_module("no-adhoc-skip")
    if tcp is None:
        return
    pol = _policy(tcp, rules=[
        {"tool": "shell", "operation": "exec", "action": "ALLOW",
         "severity": 3, "message": "ok"},
    ])
    bound = getattr(pol, "decide")
    params = set(inspect.signature(bound).parameters)
    if params & {"skip", "suppress", "exception", "bypass"}:
        _record("no-adhoc-skip", "BREAK",
                "decide() carries an ad-hoc skip parameter: %r"
                % (sorted(params),))
        return
    _record("no-adhoc-skip", "HELD",
            "no ad-hoc skip on decide(); suppression only via exceptions")


def p_invalid_policy_refused():
    tcp = _needs_module("invalid-policy-refused")
    if tcp is None:
        return
    bad_docs = [
        dict({"format": "nope", "name": "p",
              "selector": {"agents": ["a"]}, "mode": "enforce", "rules": []}),
        dict({"format": "sasanam-tool-call-policy/v1", "name": "p",
              "selector": {"agents": ["a"]}, "mode": "enforce",
              "rules": [{"tool": "t", "operation": "o", "action": "MAYBE",
                         "severity": 3, "message": "x"}]}),
        dict({"format": "sasanam-tool-call-policy/v1", "name": "p",
              "selector": {"agents": ["a"]}, "mode": "enforce",
              "rules": [{"tool": "t", "operation": "o", "action": "ALLOW",
                         "args": {"x": {"frobnicates": 1}}, "severity": 3,
                         "message": "x"}]}),
        dict({"format": "sasanam-tool-call-policy/v1", "name": "p",
              "selector": {"agents": ["a"]}, "mode": "enforce",
              "rules": [{"tool": "t", "operation": "o", "action": "ALLOW",
                         "args": {"x": {"regex": "(["}}, "severity": 3,
                         "message": "x"}]}),
        dict({"format": "sasanam-tool-call-policy/v1", "name": "p",
              "selector": {"agents": ["a"]}, "mode": "enforce",
              "rules": [{"tool": "t", "operation": "o", "action": "CUSTOM",
                         "severity": 3, "message": "x"}]}),
        dict({"format": "sasanam-tool-call-policy/v1", "name": "p",
              "selector": {"agents": None}, "mode": "enforce",
              "rules": [{"tool": "t", "operation": "o", "action": "ALLOW",
                         "severity": 3, "message": "x"}]}),
    ]
    for i, doc in enumerate(bad_docs):
        try:
            tcp.compile_policy(doc)
        except tcp.ToolCallPolicyError as e:
            if e.code != "toolcall-policy-invalid":
                _record("invalid-policy-refused", "BREAK",
                        "doc %d: wrong code %r" % (i, e.code))
                return
            continue
        _record("invalid-policy-refused", "BREAK",
                "doc %d compiled without refusal" % i)
        return
    _record("invalid-policy-refused", "HELD",
            "malformed policies refused LOUD at compile")


# ---------------------------------------------------------------------------
# Depth-1 green checks (adjacent batteries; GOV_SKIP_GREEN honored)
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        ("evals/w285_exceptions_probes.py", 0),
        ("evals/w284_nsjail_probes.py", 0),
    ]
    for rel, expected_breaks in checks:
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), rel)
        d = tempfile.mkdtemp(prefix="w286-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=900,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r"
                    % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != expected_breaks:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected %d)"
                    % (nbreak, expected_breaks))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: %d BREAK as expected" % nbreak)


_PROBES = [
    p_module_present,
    p_taxonomy_pin,
    p_fromsource_binding,
    p_unauthenticated_caller_refused,
    p_combining_deny_beats_allow,
    p_custom_before_deny,
    p_custom_tighten_only,
    p_default_deny,
    p_deny_missing_attr_matches,
    p_allow_missing_attr_no_match,
    p_audit_mode_would_deny,
    p_alert_evidence_shape,
    p_unpinned_refused,
    p_drift_refused,
    p_exception_suppress_skipped,
    p_no_covering_exception_refused,
    p_malformed_inputs_refused,
    p_no_adhoc_skip,
    p_invalid_policy_refused,
]


def main():
    for probe in _PROBES:
        try:
            probe()
        except Exception as e:  # noqa: BLE001
            _record(probe.__name__, "ERROR", "probe raised: %r" % (e,))
    _green_checks()
    nbreak = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    nheld = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    nerr = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    print("== w286_toolpolicy_probes: %d BREAK / %d HELD / %d ERROR =="
          % (nbreak, nheld, nerr))
    for r in _RESULTS:
        if r["verdict"] != "HELD":
            print("  %s %s: %s" % (r["verdict"], r["probe_id"],
                                   r["note"]))
    return 1 if (nbreak or nerr) else 0


if __name__ == "__main__":
    sys.exit(main())
