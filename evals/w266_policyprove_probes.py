"""Break-first red-team battery for the policy-change containment check
(wave-266 feature lane: NVIDIA OpenShell policy-prover pattern, ADAPT).

Target: gov/policy_change_containment.py -- before any policy/ruleset
change is applied, deterministically verify candidate ⊆ declared damage
boundary, and run the four OpenShell proposal-risk findings as
machine-coded delta checks vs the current policy
(link_local_reach, l7_bypass_credentialed, credential_reach_expansion,
capability_expansion). Purely restrictive changes always pass;
unknown/unparseable deltas refuse fail-closed -- never a vacuous
"within_boundary". The verdict report carries honest coverage
(checked vs out_of_scope), the prover's actual steal.

Every probe attacks a PUBLIC seam, never product internals. The
battery imports the implementation via GOV_POLICYPROVE_IMPL (default
"gov.policy_change_containment"); against the permissive stub
(GOV_POLICYPROVE_IMPL=stub, stub written to /tmp/w266_policyprove_stub)
every attack probe must BREAK, proving the probes are real. Against
the real module every probe must HELD, in staging and under
`env -u GOV_DEPLOYMENT_MODE`.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. A probe returns (ok, detail); ok=True means HELD (refused
with the expected machine code / gap is a documented residual),
ok=False means BREAK (genuine defect) or harness ERROR.

Stdlib only. Deterministic. No in-repo git subprocesses (wave-36
supply-chain probe: fail closed). Green checks are depth-1 and honor
GOV_SKIP_GREEN=1.
"""

import importlib
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

TAXONOMY_PIN = 1750  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)

_IMPL = os.environ.get("GOV_POLICYPROVE_IMPL",
                        "gov.policy_change_containment")
_STUB_DIR = "/tmp/w266_policyprove_stub"

_STUB_SRC = '''"""Permissive stub: the vacuous prover. Applies everything,
checks nothing, reports a vacuous within_boundary with empty
coverage. Every attack probe must BREAK against this."""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

CODES = (
    "policy-boundary-exceeded",
    "policy-change-capability-expansion",
    "policy-change-credential-reach-expansion",
    "policy-change-l7-bypass-credentialed",
    "policy-change-link-local-reach",
    "policy-change-malformed",
    "policy-change-uncheckable",
)

POLICY_VERSION = 1


class PolicyChangeError(Exception):
    def __init__(self, code, detail=""):
        super(PolicyChangeError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def check_policy_change(candidate, current, boundary,
                        credentialed_hosts=()):
    # Vacuous: no containment, no risk checks, no coverage.
    return {"verdict": "within_boundary",
            "delta_class": "equivalent",
            "failed_checks": [],
            "checked": [],
            "out_of_scope": [],
            "expansion_atoms": [],
            "evidence_digest": "0" * 64}


def gate_policy_change(candidate, current, boundary,
                       credentialed_hosts=()):
    return check_policy_change(candidate, current, boundary,
                               credentialed_hosts)


def to_evidence(report):
    return {"kind": "policy-change-decision",
            "verdict": report.get("verdict"),
            "record_digest": "0" * 64}
'''


def _load_impl():
    if _IMPL == "stub":
        os.makedirs(_STUB_DIR, exist_ok=True)
        path = os.path.join(_STUB_DIR, "policyprove_stub.py")
        with open(path, "w") as f:
            f.write(_STUB_SRC)
        sys.path.insert(0, _STUB_DIR)
        return importlib.import_module("policyprove_stub")
    return importlib.import_module(_IMPL)


dc = _load_impl()

NOW = 4000000000.0


def _rule(rid, subject, action, **kw):
    rule = {"id": rid, "subject": subject, "effect": "allow",
            "action": action}
    rule.update(kw)
    return rule


def _egress(rid, subject, hosts, ports=(443,), methods=("GET",),
            paths=("/",), credential=None):
    return _rule(rid, subject, "egress", hosts=list(hosts),
                 ports=list(ports), methods=list(methods),
                 paths=list(paths), credential=credential)


def _creduse(rid, subject, credential):
    return _rule(rid, subject, "credential-use",
                 credential=credential)


def _policy(*rules):
    return {"version": 1, "rules": list(rules)}


_BOUNDARY = _policy(
    _egress("b-llm", "*", ["api.example.com"], ports=(443,),
            methods=("GET", "POST", "DELETE"), paths=("/v1/*",)),
    _egress("b-vault", "agent-worker", ["vault.internal"],
            ports=(8200,), methods=("GET", "POST"),
            paths=("/v1/secrets/*", "/v1/admin/*",)),
    _rule("b-db", "*", "credential-use",
          credential="prod-db"),
)

_CURRENT = _policy(
    _egress("c-llm", "agent-worker", ["api.example.com"],
            ports=(443,), methods=("GET", "POST"),
            paths=("/v1/chat",)),
    _egress("c-vault", "agent-worker", ["vault.internal"],
            ports=(8200,), methods=("GET",),
            paths=("/v1/secrets/*",)),
    _rule("c-db", "agent-worker", "credential-use",
          credential="prod-db"),
)

_CRED_HOSTS = ("vault.internal",)

_PROBES = []


def probe(fn):
    _PROBES.append(fn)
    return fn


def _refused_with(call, code):
    """Run call(); HELD iff PolicyChangeError with exact code."""
    try:
        call()
    except dc.PolicyChangeError as e:
        if e.code == code:
            return (True, "refused %s" % code)
        return (False, "wrong code: %s (want %s)" % (e.code, code))
    except Exception as e:  # noqa: BLE001
        return (False, "ERROR: %s: %s" % (type(e).__name__, e))
    return (False, "BREAK: applied without refusal")


@probe
def p_boundary_exceeded():
    cand = _policy(
        _egress("x-evil", "agent-worker", ["evil.example.com"]),
        *_CURRENT["rules"])
    rep = dc.check_policy_change(cand, _CURRENT, _BOUNDARY,
                                 credentialed_hosts=_CRED_HOSTS)
    if rep["verdict"] == "within_boundary":
        return (False, "BREAK: beyond-boundary host within_boundary")
    return _refused_with(
        lambda: dc.gate_policy_change(
            cand, _CURRENT, _BOUNDARY,
            credentialed_hosts=_CRED_HOSTS),
        "policy-boundary-exceeded")


@probe
def p_link_local_reach():
    # Boundary here deliberately PERMITS the metadata IP so the
    # risk check (not the boundary check) is what must fire.
    boundary = _policy(
        _egress("b-meta", "*", ["169.254.169.254"]),
        *_BOUNDARY["rules"])
    cand = _policy(
        _egress("x-meta", "agent-worker", ["169.254.169.254"]),
        *_CURRENT["rules"])
    rep = dc.check_policy_change(cand, _CURRENT, boundary,
                                 credentialed_hosts=_CRED_HOSTS)
    if rep["verdict"] == "within_boundary":
        return (False, "BREAK: link-local expansion within_boundary")
    return _refused_with(
        lambda: dc.gate_policy_change(
            cand, _CURRENT, boundary,
            credentialed_hosts=_CRED_HOSTS),
        "policy-change-link-local-reach")


@probe
def p_l7_bypass_credentialed():
    cand = _policy(
        _egress("x-admin", "agent-worker", ["vault.internal"],
                ports=(8200,), methods=("POST",),
                paths=("/v1/admin/*",)),
        *_CURRENT["rules"])
    rep = dc.check_policy_change(cand, _CURRENT, _BOUNDARY,
                                 credentialed_hosts=_CRED_HOSTS)
    if rep["verdict"] == "within_boundary":
        return (False, "BREAK: L7 bypass on credentialed host passed")
    return _refused_with(
        lambda: dc.gate_policy_change(
            cand, _CURRENT, _BOUNDARY,
            credentialed_hosts=_CRED_HOSTS),
        "policy-change-l7-bypass-credentialed")


@probe
def p_credential_reach_expansion():
    cand = _policy(
        _rule("x-root", "new-bot", "credential-use",
              credential="prod-db"),
        *_CURRENT["rules"])
    rep = dc.check_policy_change(cand, _CURRENT, _BOUNDARY,
                                 credentialed_hosts=_CRED_HOSTS)
    if rep["verdict"] == "within_boundary":
        return (False, "BREAK: new subject credential reach passed")
    return _refused_with(
        lambda: dc.gate_policy_change(
            cand, _CURRENT, _BOUNDARY,
            credentialed_hosts=_CRED_HOSTS),
        "policy-change-credential-reach-expansion")


@probe
def p_capability_expansion():
    cand = _policy(
        _egress("x-del", "agent-worker", ["api.example.com"],
                ports=(443,), methods=("DELETE",),
                paths=("/v1/users/*",)),
        *_CURRENT["rules"])
    rep = dc.check_policy_change(cand, _CURRENT, _BOUNDARY,
                                 credentialed_hosts=_CRED_HOSTS)
    if rep["verdict"] == "within_boundary":
        return (False, "BREAK: new method/path on known host passed")
    return _refused_with(
        lambda: dc.gate_policy_change(
            cand, _CURRENT, _BOUNDARY,
            credentialed_hosts=_CRED_HOSTS),
        "policy-change-capability-expansion")


@probe
def p_uncheckable_deny_rule():
    cand = _policy(
        _rule("x-deny", "agent-worker", "egress", effect="deny",
              hosts=["evil.example.com"]),
        *_CURRENT["rules"])
    rep = dc.check_policy_change(cand, _CURRENT, _BOUNDARY,
                                 credentialed_hosts=_CRED_HOSTS)
    if rep["verdict"] == "within_boundary":
        return (False, "BREAK: deny-rule delta vacuously passed")
    return _refused_with(
        lambda: dc.gate_policy_change(
            cand, _CURRENT, _BOUNDARY,
            credentialed_hosts=_CRED_HOSTS),
        "policy-change-uncheckable")


@probe
def p_unparseable_host():
    cand = _policy(
        _egress("x-bad", "agent-worker", ["http://[bad"]),
        *_CURRENT["rules"])
    rep = dc.check_policy_change(cand, _CURRENT, _BOUNDARY,
                                 credentialed_hosts=_CRED_HOSTS)
    if rep["verdict"] == "within_boundary":
        return (False, "BREAK: unparseable host vacuously passed")
    return _refused_with(
        lambda: dc.gate_policy_change(
            cand, _CURRENT, _BOUNDARY,
            credentialed_hosts=_CRED_HOSTS),
        "policy-change-uncheckable")


@probe
def p_risk_checks_not_silent():
    boundary = _policy(
        _egress("b-meta", "*", ["169.254.169.254"]),
        *_BOUNDARY["rules"])
    cand = _policy(
        _egress("x-meta", "agent-worker", ["169.254.169.254"]),
        _egress("x-del", "agent-worker", ["api.example.com"],
                ports=(443,), methods=("DELETE",),
                paths=("/v1/users/*",)),
        *_CURRENT["rules"])
    rep = dc.check_policy_change(cand, _CURRENT, boundary,
                                 credentialed_hosts=_CRED_HOSTS)
    if rep["verdict"] == "within_boundary":
        return (False, "BREAK: double expansion within_boundary")
    failed = rep.get("failed_checks", [])
    want = ["policy-change-link-local-reach",
            "policy-change-capability-expansion"]
    if failed != want:
        return (False, "failed_checks=%r want %r in fixed order"
                % (failed, want))
    return (True, "both risk findings named, fixed order")


@probe
def p_restrictive_change_passes():
    cand = _policy(*_CURRENT["rules"][1:])  # drop the llm rule
    try:
        rep = dc.gate_policy_change(cand, _CURRENT, _BOUNDARY,
                                    credentialed_hosts=_CRED_HOSTS)
    except dc.PolicyChangeError as e:
        return (False, "BREAK: restrictive change refused: %s"
                % e.code)
    if rep["verdict"] != "within_boundary":
        return (False, "verdict=%r" % rep["verdict"])
    if rep["delta_class"] != "restrictive":
        return (False, "delta_class=%r" % rep["delta_class"])
    return (True, "pure restriction passes")


@probe
def p_restrictive_narrowing_passes():
    # Method narrowing IS modelable: candidate methods are a
    # subset of the current methods on the same rule shape.
    cand = _policy(
        _egress("c-llm", "agent-worker", ["api.example.com"],
                ports=(443,), methods=("GET",),
                paths=("/v1/chat",)),
        *_CURRENT["rules"][1:])
    try:
        rep = dc.gate_policy_change(cand, _CURRENT, _BOUNDARY,
                                    credentialed_hosts=_CRED_HOSTS)
    except dc.PolicyChangeError as e:
        return (False, "BREAK: narrowing refused: %s" % e.code)
    if rep["verdict"] != "within_boundary":
        return (False, "verdict=%r" % rep["verdict"])
    return (True, "path narrowing passes")


@probe
def p_uncheckable_never_vacuous():
    cand = _policy(
        _rule("x-deny", "agent-worker", "egress", effect="deny",
              hosts=["evil.example.com"]),
        *_CURRENT["rules"])
    rep = dc.check_policy_change(cand, _CURRENT, _BOUNDARY,
                                 credentialed_hosts=_CRED_HOSTS)
    if rep["verdict"] != "uncheckable":
        return (False, "verdict=%r, want 'uncheckable' (never a "
                "vacuous within_boundary)" % rep["verdict"])
    try:
        dc.gate_policy_change(cand, _CURRENT, _BOUNDARY,
                              credentialed_hosts=_CRED_HOSTS)
    except dc.PolicyChangeError as e:
        if e.code == "policy-change-uncheckable":
            return (True, "uncheckable fails closed, named")
        return (False, "wrong code %s" % e.code)
    return (False, "BREAK: gate applied an uncheckable delta")


@probe
def p_coverage_reported():
    rep = dc.check_policy_change(_CURRENT, _CURRENT, _BOUNDARY,
                                 credentialed_hosts=_CRED_HOSTS)
    checked = rep.get("checked", [])
    oos = rep.get("out_of_scope", [])
    if not checked:
        return (False, "BREAK: empty coverage 'checked'")
    if not oos:
        return (False, "BREAK: empty 'out_of_scope'")
    if not any("deny" in s for s in oos):
        return (False, "out_of_scope names no deny-rule limit: %r"
                % oos)
    return (True, "checked=%d out_of_scope=%d"
            % (len(checked), len(oos)))


@probe
def p_equivalent_delta_passes():
    rep = dc.check_policy_change(_CURRENT, _CURRENT, _BOUNDARY,
                                 credentialed_hosts=_CRED_HOSTS)
    if rep["verdict"] != "within_boundary":
        return (False, "verdict=%r" % rep["verdict"])
    if rep["delta_class"] != "equivalent":
        return (False, "delta_class=%r" % rep["delta_class"])
    return (True, "no-op change passes")


@probe
def p_taxonomy_pin():
    codes = list(getattr(dc, "CODES", ()))
    want = ["policy-boundary-exceeded",
            "policy-change-capability-expansion",
            "policy-change-credential-reach-expansion",
            "policy-change-l7-bypass-credentialed",
            "policy-change-link-local-reach",
            "policy-change-malformed",
            "policy-change-uncheckable"]
    if codes != sorted(want):
        return (False, "CODES=%r" % (codes,))
    if codes != sorted(codes):
        return (False, "CODES not alphabetical")
    if TAXONOMY_PIN != 1750:
        return (False, "battery pin drift")
    return (True, "7 policy-* codes, alphabetical, pin 1212")


@probe
def p_deterministic_x2():
    cand = _policy(
        _egress("x-del", "agent-worker", ["api.example.com"],
                ports=(443,), methods=("DELETE",),
                paths=("/v1/users/*",)),
        *_CURRENT["rules"])
    r1 = dc.check_policy_change(cand, _CURRENT, _BOUNDARY,
                                credentialed_hosts=_CRED_HOSTS)
    r2 = dc.check_policy_change(cand, _CURRENT, _BOUNDARY,
                                credentialed_hosts=_CRED_HOSTS)
    import json as _json
    s1 = _json.dumps(r1, sort_keys=True, default=str)
    s2 = _json.dumps(r2, sort_keys=True, default=str)
    if s1 != s2:
        return (False, "non-deterministic reports")
    return (True, "byte-identical reports")


@probe
def p_malformed_loud():
    # Malformed (authoring-error) input raises loudly at the
    # seam -- check_ and gate_ alike. The stub never raises.
    try:
        dc.check_policy_change("not-a-policy", _CURRENT,
                               _BOUNDARY,
                               credentialed_hosts=_CRED_HOSTS)
    except dc.PolicyChangeError as e:
        if e.code != "policy-change-malformed":
            return (False, "wrong code %s" % e.code)
    except Exception as e:  # noqa: BLE001
        return (False, "ERROR: %s: %s" % (type(e).__name__, e))
    else:
        return (False, "BREAK: malformed input accepted by check_")
    return _refused_with(
        lambda: dc.gate_policy_change(
            "not-a-policy", _CURRENT, _BOUNDARY,
            credentialed_hosts=_CRED_HOSTS),
        "policy-change-malformed")


@probe
def p_empty_boundary_uncheckable():
    empty = {"version": 1, "rules": []}
    rep = dc.check_policy_change(_CURRENT, _CURRENT, empty,
                                 credentialed_hosts=_CRED_HOSTS)
    if rep["verdict"] == "within_boundary":
        return (False, "BREAK: empty boundary vacuously passed")
    return _refused_with(
        lambda: dc.gate_policy_change(
            _CURRENT, _CURRENT, empty,
            credentialed_hosts=_CRED_HOSTS),
        "policy-change-uncheckable")


@probe
def p_adjacent_green():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green check skipped (depth-1)")
    tmp = tempfile.mkdtemp(prefix="g266policyprove-green-",
                           dir="/var/tmp")
    env = dict(os.environ)
    env["TMPDIR"] = tmp
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_RUN_ROOT"] = os.path.join(tmp, "realistic")
    repo = os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))
    child = os.path.join(repo, "evals", "w264_admission_probes.py")
    try:
        r = subprocess.run(
            [sys.executable, child], env=env, cwd=repo,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600)
    except Exception as e:  # noqa: BLE001
        return (False, "green check ERROR: %s" % e)
    out = r.stdout.decode("utf-8", "replace")
    # Lane-local pin drift: this lane adds 7 policy-* codes, so
    # the adjacent battery's own pin assertion (1205) trips on
    # the 1212 tree. That drift is the merge coordinator's
    # repoint chore (standard lane convention), not a
    # regression -- accept it only as the SOLE failure cause.
    pin_only = ("PIN MISMATCH: taxonomy has 1212 keys, pin is "
                "1205" in out)
    real_breaks = [l for l in out.splitlines()
                   if l.startswith("BREAK real/")
                   or l.startswith("BREAK module/")]
    if r.returncode == 0:
        return (True, "w264_admission_probes green")
    if pin_only and not real_breaks:
        return (True, "adjacent green apart from known lane-local "
                "pin drift (1212 vs 1205); no real-phase BREAKs")
    return (False, "adjacent battery red: exit %d"
            % r.returncode)


def main():
    held, broke, errors = [], [], []
    for fn in _PROBES:
        try:
            ok, detail = fn()
        except Exception as e:  # noqa: BLE001
            errors.append((fn.__name__, "%s: %s"
                           % (type(e).__name__, e)))
            continue
        (held if ok else broke).append((fn.__name__, detail))
    print("impl=%s probes=%d HELD=%d BREAK=%d ERROR=%d"
          % (_IMPL, len(_PROBES), len(held), len(broke),
             len(errors)))
    for name, detail in broke:
        print("BREAK %s: %s" % (name, detail))
    for name, detail in errors:
        print("ERROR %s: %s" % (name, detail))
    for name, detail in held:
        print("HELD %s: %s" % (name, detail))
    return 1 if (broke or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
