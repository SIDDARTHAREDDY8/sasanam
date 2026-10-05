"""Wave-288 lane 4 battery: close F340, F341, F342 (all LOW).

F340: CompiledToolPolicy._doc is mutable post-bind; the pin is checked
only at bind(). Post-bind mutation (mode flip enforce->audit, rule
neutering) silently changes decisions under a still-valid pin.
F341: suppress_with_exception hardcodes "verdict": "DENY" even when the
suppressed alert was an audit-mode would-deny whose decision was ALLOW.
F342: uncoded TypeError escapes tool_call_policy public seams
(decide(tool=None), mixed-type arg keys via json sort_keys).

Red-first: every defect probe BREAKs on the pristine base and HELDs
after the fix. F338 (MEDIUM, still OPEN) is deliberately NOT touched:
args={"cmd": None} must still reach a decision -- the battery asserts
no over-refusal there.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.
"""

import os
import re
import subprocess
import sys
import tempfile
import time

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-287 merge: pin 1660 -> 1684. Wave-288 lane 4: +1 toolcall-*.
TAXONOMY_PIN = 2130 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable).  Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*); Wave-339 merge: pin 2128 -> 2130 (+4 codes: oci-bundle-not-verifiable, witness-policy-dual-threshold-unmet, witness-daemon-state-failed, oci-registry-onboarding-refused)


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
    _record("pin-taxonomy", "HELD", "1700/1700/0 sorted")


def _deny_doc(name="w288f340", mode="enforce"):
    return {
        "format": "sasanam-tool-call-policy/v1",
        "name": name,
        "selector": {"agents": ["agent-1"]},
        "mode": mode,
        "rules": [
            {"action": "DENY", "tool": "shell", "operation": "run",
             "severity": 9, "tags": []},
        ],
    }


def _caller():
    return {"authenticated": True, "identity": "agent-1"}


# ---------------------------------------------------------------------------
# F340: post-bind _doc mutation must be impossible or detected.
# ---------------------------------------------------------------------------

def p_f340_mode_flip_blocked():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(_deny_doc())
    b = tp.bind(comp, comp.digest)
    try:
        b._compiled._doc["mode"] = "audit"
    except Exception as e:  # noqa: BLE001
        return _record("f340-mode-flip", "HELD",
                       "top-level mutation blocked at source: %s"
                       % type(e).__name__)
    # Mutation succeeded: the decision must still be DENY, or decide must
    # refuse LOUD with the drift code (per-decide pin re-verification).
    try:
        d = b.decide(_caller(), "shell", "run", args={})
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "toolcall-policy-drift":
            return _record("f340-mode-flip", "HELD",
                           "per-decide pin re-check refused the drift")
        return _record("f340-mode-flip", "ERROR",
                       "unexpected exception: %r" % (e,))
    if d.verdict == "DENY":
        return _record("f340-mode-flip", "HELD",
                       "mutation did not change enforcement")
    _record("f340-mode-flip", "BREAK",
            "post-bind mode flip changed enforcement to %s under a "
            "still-valid pin" % (d.verdict,))


def p_f340_nested_rule_mutation_blocked():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(_deny_doc())
    b = tp.bind(comp, comp.digest)
    try:
        b._compiled._doc["rules"][0]["action"] = "ALLOW"
    except Exception as e:  # noqa: BLE001
        return _record("f340-nested-mutation", "HELD",
                       "nested mutation blocked at source: %s"
                       % type(e).__name__)
    try:
        d = b.decide(_caller(), "shell", "run", args={})
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "toolcall-policy-drift":
            return _record("f340-nested-mutation", "HELD",
                           "per-decide pin re-check refused the drift")
        return _record("f340-nested-mutation", "ERROR",
                       "unexpected exception: %r" % (e,))
    if d.verdict == "DENY":
        return _record("f340-nested-mutation", "HELD",
                       "rule neutering did not change enforcement")
    _record("f340-nested-mutation", "BREAK",
            "post-bind rule neutering flipped the verdict to %s"
            % (d.verdict,))


def p_f340_wholesale_replace_detected():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(_deny_doc())
    b = tp.bind(comp, comp.digest)
    evil = dict(_deny_doc())
    evil["mode"] = "audit"
    object.__setattr__(b._compiled, "_doc", evil)
    try:
        d = b.decide(_caller(), "shell", "run", args={})
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "toolcall-policy-drift":
            return _record("f340-wholesale-replace", "HELD",
                           "wholesale _doc replacement detected at decide")
        return _record("f340-wholesale-replace", "ERROR",
                       "unexpected exception: %r" % (e,))
    _record("f340-wholesale-replace", "BREAK",
            "wholesale _doc replacement decided %s with no drift "
            "detection" % (d.verdict,))


def p_f340_digest_stable():
    # The freeze must not change the content digest: pins minted before
    # the fix keep working (no silent pin invalidation).
    from gov import tool_call_policy as tp
    doc = _deny_doc()
    comp = tp.compile_policy(doc)
    if comp.digest != tp.policy_digest(doc):
        return _record("f340-digest-stable", "BREAK",
                       "freeze changed the content digest; existing pins "
                       "would silently invalidate")
    _record("f340-digest-stable", "HELD",
            "compiled digest == policy_digest(doc)")


# ---------------------------------------------------------------------------
# F341: the suppression record must carry the actual decision's verdict.
# ---------------------------------------------------------------------------

def _f332_store():
    from gov import governed_exceptions as ge
    reg = ge.CheckRegistry()
    reg.register("W288CHECK", "denied tool call", "policy", "high",
                 "lane-4 check", ["tool_call"])
    store = ge.ExceptionStore(reg)
    store.set_approvers(["alice"])
    return store


def p_f341_auditmode_verdict():
    from gov import tool_call_policy as tp
    store = _f332_store()
    now = time.time()
    store.grant("W288CHECK", scope=("tool", "shell"),
                justification="business need for shell usage in this run",
                approver="alice", expiry_ts=now + 3600, created_at=now)
    comp = tp.compile_policy(_deny_doc(name="w288f341", mode="audit"))
    d = comp.decide(_caller(), "shell", "run", args={})
    if d.verdict != "ALLOW":
        return _record("f341-audit-verdict", "ERROR",
                       "expected audit-mode ALLOW, got %r" % (d.verdict,))
    rec = tp.suppress_with_exception(
        comp, d.alert["runtime_identity_hash"], store,
        "W288CHECK", ("tool", "shell"))
    if rec.get("verdict") == "DENY":
        return _record("f341-audit-verdict", "BREAK",
                       "suppression record hardcodes verdict=DENY for an "
                       "audit-mode would-deny whose decision was ALLOW")
    if rec.get("verdict") != "ALLOW":
        return _record("f341-audit-verdict", "BREAK",
                       "suppression record verdict is %r, want ALLOW"
                       % (rec.get("verdict"),))
    if "would-deny" not in str(rec.get("message", "")).lower() and \
            "audit" not in str(rec.get("message", "")).lower():
        return _record("f341-audit-verdict", "BREAK",
                       "suppression message does not describe the "
                       "audit-mode would-deny")
    _record("f341-audit-verdict", "HELD",
            "suppression record carries verdict=ALLOW for the would-deny")


def p_f341_enforce_verdict_still_deny():
    # No regression: a genuine enforced DENY still records verdict=DENY.
    from gov import tool_call_policy as tp
    store = _f332_store()
    now = time.time()
    store.grant("W288CHECK", scope=("tool", "shell"),
                justification="business need for shell usage in this run",
                approver="alice", expiry_ts=now + 3600, created_at=now)
    comp = tp.compile_policy(_deny_doc(name="w288f341b", mode="enforce"))
    d = comp.decide(_caller(), "shell", "run", args={})
    if d.verdict != "DENY":
        return _record("f341-enforce-verdict", "ERROR",
                       "expected enforce-mode DENY, got %r" % (d.verdict,))
    rec = tp.suppress_with_exception(
        comp, d.alert["runtime_identity_hash"], store,
        "W288CHECK", ("tool", "shell"))
    if rec.get("verdict") != "DENY":
        return _record("f341-enforce-verdict", "BREAK",
                       "enforced DENY suppression now records verdict=%r"
                       % (rec.get("verdict"),))
    _record("f341-enforce-verdict", "HELD",
            "enforced DENY suppression still records verdict=DENY")


# ---------------------------------------------------------------------------
# F342: ill-typed public inputs refuse with coded ToolCallPolicyError.
# The F338 residual (args={"cmd": None}) is deliberately NOT refused here:
# F338 is still OPEN and owns that seam.
# ---------------------------------------------------------------------------

def _expect_coded(pid, fn, label):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record(pid, "BREAK",
                           "%s: uncoded %s escapes -- expected coded "
                           "ToolCallPolicyError" % (label,
                                                    type(e).__name__))
        return _record(pid, "HELD",
                       "%s: coded refusal %s" % (label, code))
    _record(pid, "BREAK", "%s: no coded refusal (decided instead of "
                       "refusing LOUD)" % (label,))


def p_f342_tool_none():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(_deny_doc(name="w288f342"))
    _expect_coded("f342-tool-none",
                  lambda: comp.decide(_caller(), None, "run", args={}),
                  "decide(tool=None)")


def p_f342_operation_none():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(_deny_doc(name="w288f342b"))
    _expect_coded("f342-operation-none",
                  lambda: comp.decide(_caller(), "shell", None, args={}),
                  "decide(operation=None)")


def p_f342_tool_nonstring():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(_deny_doc(name="w288f342c"))
    _expect_coded("f342-tool-nonstring",
                  lambda: comp.decide(_caller(), 123, "run", args={}),
                  "decide(tool=123)")


def p_f342_mixed_arg_keys():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(_deny_doc(name="w288f342d"))
    _expect_coded("f342-mixed-arg-keys",
                  lambda: comp.decide(_caller(), "shell", "run",
                                      args={1: "x", "cmd": "y"}),
                  "decide(args with mixed-type keys)")


def p_f342_null_arg_value_not_overrefused():
    # F338's seam: a present null arg VALUE must still reach a decision
    # (F338 is OPEN and owns that behavior; this lane must not silently
    # close it by over-refusing).
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(_deny_doc(name="w288f342e"))
    try:
        d = comp.decide(_caller(), "shell", "run", args={"cmd": None})
    except Exception as e:  # noqa: BLE001
        return _record("f342-null-value", "BREAK",
                       "over-refusal: null arg value refused %s "
                       "(F338's seam)" % getattr(e, "code",
                                                 type(e).__name__))
    _record("f342-null-value", "HELD",
            "null arg value reaches a decision (%s); F338 untouched"
            % (d.verdict,))


# ---------------------------------------------------------------------------
# Depth-1 green checks.
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        # (battery, expected_breaks)
        ("evals/w286_toolpolicy_probes.py", 0),
        # Wave-288 merge: F334-F342 all closed -> 0 BREAK expected.
        ("evals/w287_redteam_probes.py", 0),
    ]
    for rel, expected in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w288-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak != expected:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected %d)"
                    % (nbreak, expected))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: %d BREAK as expected" % nbreak)


def main():
    p_taxonomy_pin()
    p_f340_mode_flip_blocked()
    p_f340_nested_rule_mutation_blocked()
    p_f340_wholesale_replace_detected()
    p_f340_digest_stable()
    p_f341_auditmode_verdict()
    p_f341_enforce_verdict_still_deny()
    p_f342_tool_none()
    p_f342_operation_none()
    p_f342_tool_nonstring()
    p_f342_mixed_arg_keys()
    p_f342_null_arg_value_not_overrefused()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w288_f340_f342: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
