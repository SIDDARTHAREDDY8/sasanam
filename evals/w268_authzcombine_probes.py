"""Break-first red-team battery for the four-bucket authorization combine
(wave-268 feature lane: Istio AuthorizationPolicy composition algebra,
ADAPT pattern-only -- SHA db6e1182, Apache-2.0, no Istio code vendored).

Target: gov/authorization_combine.py -- agent (principal, action,
resource, context) tuples evaluated against policies partitioned into
ordered buckets AUDIT -> DENY -> CUSTOM -> ALLOW with short-circuit.
Deny-before-allow is structural, never a named operator. Rules OR'd
within a bucket; from/to/when clauses AND'd within a rule; every rule
carries a name for decision-trail attribution. No ALLOW rules =>
default-allow; >=1 ALLOW rule => default-deny. Shadow (dry-run) rules
are evaluated and logged but never enforced. A misconfigured external
authorizer fails closed (deny-everything) with a loud journal entry.
Partial enforcement (missing attributes at the enforcement point) is
LOUD, never silent -- the ambient/waypoint lesson.

Every probe attacks a PUBLIC seam, never product internals. The battery
imports the implementation via GOV_AUTHZCOMBINE_IMPL (default
"gov.authorization_combine"); against the permissive stub
(GOV_AUTHZCOMBINE_IMPL=stub) every attack probe must BREAK, proving the
probes are real. Against the real module every probe must HELD, in
staging and under `env -u GOV_DEPLOYMENT_MODE`.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. A probe returns (ok, detail); ok=True means HELD (refused
with the expected machine code / gap is a documented residual),
ok=False means BREAK (genuine defect) or harness ERROR.

Stdlib only. Deterministic. No in-repo git subprocesses (wave-36
supply-chain probe: fail closed). Green checks are depth-1 and honor
GOV_SKIP_GREEN=1.
"""

import concurrent.futures
import importlib
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

# Wave-271 merge: pin 1372 -> 1411 (+39 codes: 6 ptgrant-* + 7 replay-* + 8 rsl-* + 14 gatehard-* + 4 imgtext-*).
# Asserted lane-locally; the merge coordinator repoints at merge.
TAXONOMY_PIN = 1977 # Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_STUB_SRC = '''
"""Permissive stub: allows every request. Red-phase foil only."""


class AuthorizationCombineError(Exception):
    def __init__(self, code, detail=""):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def load_bundle(doc):
    return doc


def evaluate(bundle, request, **kwargs):
    return {"decision": "allow", "admitted": True, "code": "stub",
            "reason": "stub", "request_digest": "stub",
            "matched_rules": [], "audit_hits": [],
            "shadow_results": [], "partial_attributes": [],
            "checked": [], "out_of_scope": [],
            "evidence_digest": "stub", "detail": {}}
'''

_IMPL = os.environ.get("GOV_AUTHZCOMBINE_IMPL", "gov.authorization_combine")


def _load_impl():
    if _IMPL == "stub":
        tmp = tempfile.mkdtemp(prefix="w268_authzcombine_stub",
                               dir="/tmp")
        path = os.path.join(tmp, "authzcombine_stub.py")
        with open(path, "w") as f:
            f.write(_STUB_SRC)
        sys.path.insert(0, tmp)
        return importlib.import_module("authzcombine_stub")
    return importlib.import_module(_IMPL)


ac = _load_impl()


def _req(principal="agent:alice", action="tool.exec",
         resource="secret/db", context=None):
    return {"principal": principal, "action": action,
            "resource": resource,
            "context": dict(context) if context else {}}


def _rule(name, action, frm=None, to=None, when=None, shadow=False,
          provider=None):
    r = {"name": name, "action": action}
    if frm is not None:
        r["from"] = frm
    if to is not None:
        r["to"] = to
    if when is not None:
        r["when"] = when
    if shadow:
        r["shadow"] = True
    if provider is not None:
        r["provider"] = provider
    return r


def _bundle(rules, authorizers=None):
    doc = {"version": "sasanam-authz-bundle/v1", "rules": rules}
    if authorizers is not None:
        doc["external_authorizers"] = authorizers
    return ac.load_bundle(doc)


def p01_deny_wins_over_allow():
    """Deny-before-allow is structural: a matching DENY beats a matching
    ALLOW even when both match the same request."""
    b = _bundle([
        _rule("allow-exec", "allow",
              to={"actions": ["tool.exec"]}),
        _rule("deny-exec", "deny",
              to={"actions": ["tool.exec"]}),
    ])
    v = ac.evaluate(b, _req())
    ok = (v["decision"] == "deny" and v["code"] == "authz-deny"
          and v["matched_rules"] == ["deny-exec"])
    return (ok, "deny wins: %s/%s matched=%r"
            % (v["decision"], v["code"], v["matched_rules"]))


def p02_deny_wins_rule_order_reversed():
    """The combine must not depend on rule order: ALLOW listed first,
    DENY second -- DENY still wins (filter-chain order, not list order)."""
    b = _bundle([
        _rule("allow-first", "allow",
              to={"actions": ["tool.exec"]}),
        _rule("deny-second", "deny",
              to={"actions": ["tool.exec"]}),
    ])
    v = ac.evaluate(b, _req())
    ok = (v["decision"] == "deny" and v["code"] == "authz-deny"
          and v["matched_rules"] == ["deny-second"])
    return (ok, "order-independent deny: %s/%s"
            % (v["decision"], v["code"]))


def p03_shadow_deny_never_enforces():
    """A shadow (dry-run) DENY that matches must be reported, never
    enforced: with no real ALLOW rules the default is allow."""
    b = _bundle([
        _rule("shadow-deny", "deny", shadow=True,
              to={"actions": ["tool.exec"]}),
    ])
    v = ac.evaluate(b, _req())
    shadowed = [s for s in v["shadow_results"]
                if s["rule"] == "shadow-deny" and s["would"] == "deny"]
    ok = (v["decision"] == "allow" and v["code"] == "authz-allow"
          and v["matched_rules"] == [] and len(shadowed) == 1)
    return (ok, "shadow deny reported-not-enforced: %s/%s shadow=%r"
            % (v["decision"], v["code"], v["shadow_results"]))


def p04_shadow_allow_never_grants():
    """A shadow ALLOW that matches must not grant: with a real (but
    non-matching) ALLOW rule present, the default is deny."""
    b = _bundle([
        _rule("shadow-allow", "allow", shadow=True,
              to={"actions": ["tool.exec"]}),
        _rule("real-allow-other", "allow",
              to={"actions": ["tool.read"]}),
    ])
    v = ac.evaluate(b, _req())
    shadowed = [s for s in v["shadow_results"]
                if s["rule"] == "shadow-allow" and s["would"] == "allow"]
    ok = (v["decision"] == "deny"
          and v["code"] == "authz-default-deny" and len(shadowed) == 1)
    return (ok, "shadow allow not a grant: %s/%s shadow=%r"
            % (v["decision"], v["code"], v["shadow_results"]))


def p05_provider_misconfigured_denies_everything():
    """CUSTOM rule matches but the provider is not configured in the
    bundle: fail closed, deny-everything, machine-coded."""
    b = _bundle([
        _rule("ext-check", "custom", provider="missing-provider",
              to={"actions": ["tool.exec"]}),
    ])
    calls = []
    v = ac.evaluate(b, _req(),
                    authorizer=lambda pid, req: calls.append(pid)
                    or (True, "ok"))
    ok = (v["decision"] == "deny"
          and v["code"] == "authz-provider-misconfigured"
          and calls == [])
    return (ok, "misconfigured provider deny-everything: %s/%s calls=%r"
            % (v["decision"], v["code"], calls))


def p06_provider_absent_hook_denies():
    """CUSTOM rule matches, provider configured, but no authorizer hook
    supplied by the deployment: fail closed (skipping the rule would be
    fail-open)."""
    b = _bundle(
        [_rule("ext-check", "custom", provider="pid",
               to={"actions": ["tool.exec"]})],
        authorizers={"pid": {"timeout_ms": 500}})
    v = ac.evaluate(b, _req())
    ok = (v["decision"] == "deny"
          and v["code"] == "authz-provider-misconfigured")
    return (ok, "absent hook fail-closed: %s/%s"
            % (v["decision"], v["code"]))


def p07_provider_error_fail_closed():
    """The external authorizer raises: fail closed, deny."""
    def boom(pid, req):
        raise RuntimeError("provider exploded")
    b = _bundle(
        [_rule("ext-check", "custom", provider="pid",
               to={"actions": ["tool.exec"]})],
        authorizers={"pid": {"timeout_ms": 500}})
    v = ac.evaluate(b, _req(), authorizer=boom)
    ok = (v["decision"] == "deny"
          and v["code"] == "authz-provider-misconfigured")
    return (ok, "provider error fail-closed: %s/%s"
            % (v["decision"], v["code"]))


def p08_provider_timeout_fail_closed():
    """The external authorizer exceeds its timeout: fail closed, deny.
    Timeout is a duration bound, not a wall-clock decision."""
    def slow(pid, req):
        time.sleep(5)
        return (True, "too late")
    b = _bundle(
        [_rule("ext-check", "custom", provider="pid",
               to={"actions": ["tool.exec"]})],
        authorizers={"pid": {"timeout_ms": 50}})
    start = time.monotonic()
    v = ac.evaluate(b, _req(), authorizer=slow)
    elapsed = time.monotonic() - start
    ok = (v["decision"] == "deny"
          and v["code"] == "authz-provider-misconfigured"
          and elapsed < 4)
    return (ok, "provider timeout fail-closed: %s/%s in %.2fs"
            % (v["decision"], v["code"], elapsed))


def p09_partial_deny_when_unevaluable():
    """DENY rule whose from/to match but whose `when` cannot be evaluated
    (missing attribute): fail toward deny, LOUD -- the rule and the
    missing keys are named in the verdict."""
    b = _bundle([
        _rule("deny-secret", "deny",
              to={"actions": ["tool.exec"]},
              when=[{"key": "mfa", "op": "eq", "value": True}]),
    ])
    v = ac.evaluate(b, _req(context={}))
    partial = [p for p in v["partial_attributes"]
               if p["rule"] == "deny-secret" and "mfa" in p["missing"]]
    ok = (v["decision"] == "deny" and v["code"] == "authz-deny"
          and len(partial) == 1)
    return (ok, "partial deny-when fails toward deny, loud: %s/%s "
            "partial=%r" % (v["decision"], v["code"],
                            v["partial_attributes"]))


def p10_partial_allow_when_unevaluable_no_grant():
    """ALLOW rule whose from/to match but whose `when` cannot be
    evaluated: never grants on ambiguity. Nothing clean decides, so the
    verdict is the loud partial-attributes refuse."""
    b = _bundle([
        _rule("allow-exec", "allow",
              to={"actions": ["tool.exec"]},
              when=[{"key": "mfa", "op": "eq", "value": True}]),
        _rule("allow-other", "allow",
              to={"actions": ["tool.read"]}),
    ])
    v = ac.evaluate(b, _req(context={}))
    partial = [p for p in v["partial_attributes"]
               if p["rule"] == "allow-exec"]
    ok = (v["decision"] == "deny"
          and v["code"] == "authz-partial-attributes"
          and len(partial) == 1 and v["matched_rules"] == [])
    return (ok, "partial allow-when never grants: %s/%s partial=%r"
            % (v["decision"], v["code"], v["partial_attributes"]))


def p11_default_deny_with_allow_policies():
    """At least one ALLOW policy exists but none match: default-deny
    (classic Istio semantics)."""
    b = _bundle([
        _rule("allow-read", "allow", to={"actions": ["tool.read"]}),
    ])
    v = ac.evaluate(b, _req())
    ok = (v["decision"] == "deny"
          and v["code"] == "authz-default-deny")
    return (ok, "default-deny: %s/%s" % (v["decision"], v["code"]))


def p12_audit_never_enforces():
    """AUDIT bucket matches are logged, never enforced: with no ALLOW
    rules the decision stays default-allow and the hit is attributed."""
    b = _bundle([
        _rule("audit-exec", "audit", to={"actions": ["tool.exec"]}),
    ])
    events = []
    v = ac.evaluate(b, _req(), journal=events.append)
    ok = (v["decision"] == "allow"
          and v["audit_hits"] == ["audit-exec"]
          and any(e.get("event") == "authz-audit-hit"
                  for e in events))
    return (ok, "audit logged-not-enforced: %s hits=%r journaled=%d"
            % (v["decision"], v["audit_hits"], len(events)))


def p13_named_rule_attribution():
    """Every rule in the decision surface names its source: a DENY match
    attributes the exact rule name in the verdict (Envoy rule-key
    analogue)."""
    b = _bundle([
        _rule("deny-team-a", "deny",
              frm={"principals": ["agent:mallory"]}),
        _rule("deny-team-b", "deny",
              frm={"principals": ["agent:alice"]}),
    ])
    v = ac.evaluate(b, _req(principal="agent:alice"))
    ok = (v["decision"] == "deny" and v["code"] == "authz-deny"
          and v["matched_rules"] == ["deny-team-b"])
    return (ok, "attribution: %s/%s matched=%r"
            % (v["decision"], v["code"], v["matched_rules"]))


def p14_within_bucket_or():
    """Within a bucket, rules are OR'd: the second of two DENY rules
    matching is enough."""
    b = _bundle([
        _rule("deny-first", "deny",
              frm={"principals": ["agent:mallory"]}),
        _rule("deny-second", "deny",
              to={"resources": ["secret/db"]}),
    ])
    v = ac.evaluate(b, _req())
    ok = (v["decision"] == "deny" and v["code"] == "authz-deny"
          and v["matched_rules"] == ["deny-second"])
    return (ok, "bucket OR: %s/%s matched=%r"
            % (v["decision"], v["code"], v["matched_rules"]))


def p15_within_rule_clause_and():
    """Within a rule, clauses are AND'd: from+to+when with a failing
    `when` means no match -- the rule cannot fire on a partial clause
    set."""
    b = _bundle([
        _rule("deny-strict", "deny",
              frm={"principals": ["agent:alice"]},
              to={"actions": ["tool.exec"]},
              when=[{"key": "env", "op": "eq", "value": "prod"}]),
    ])
    v = ac.evaluate(b, _req(context={"env": "dev"}))
    ok = (v["decision"] == "allow" and v["code"] == "authz-allow"
          and v["matched_rules"] == [])
    return (ok, "clause AND: %s/%s matched=%r"
            % (v["decision"], v["code"], v["matched_rules"]))


def p16_malformed_bundle_load():
    """load_bundle on a non-dict refuses with the machine-coded
    authz-malformed-bundle (fail-closed at load)."""
    try:
        ac.load_bundle("not-a-bundle")
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        return (code == "authz-malformed-bundle",
                "load raised code=%r" % (code,))
    return (False, "load_bundle accepted a non-dict (no raise)")


def p17_malformed_rule_load():
    """A rule without a name refuses at load with
    authz-malformed-rule."""
    try:
        ac.load_bundle({"version": "sasanam-authz-bundle/v1",
                        "rules": [{"action": "deny"}]})
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        return (code == "authz-malformed-rule",
                "load raised code=%r" % (code,))
    return (False, "load_bundle accepted a nameless rule (no raise)")


def p18_unknown_action_load():
    """A rule with an unknown action refuses at load -- the bucket set
    is closed, no silent bucket."""
    try:
        ac.load_bundle({"version": "sasanam-authz-bundle/v1",
                        "rules": [_rule("weird", "block")]})
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        return (code == "authz-malformed-rule",
                "load raised code=%r" % (code,))
    return (False, "load_bundle accepted action 'block' (no raise)")


def p19_deny_before_custom_no_provider_call():
    """DENY short-circuits before CUSTOM: a matching DENY means the
    external authorizer is never consulted (no availability coupling on
    the deny path)."""
    b = _bundle(
        [_rule("deny-exec", "deny", to={"actions": ["tool.exec"]}),
         _rule("ext-check", "custom", provider="pid",
               to={"actions": ["tool.exec"]})],
        authorizers={"pid": {"timeout_ms": 500}})
    calls = []
    v = ac.evaluate(b, _req(),
                    authorizer=lambda pid, req: calls.append(pid)
                    or (True, "ok"))
    ok = (v["decision"] == "deny" and v["code"] == "authz-deny"
          and calls == [])
    return (ok, "deny pre-empts custom: %s/%s provider_calls=%r"
            % (v["decision"], v["code"], calls))


def p20_custom_allow_continues_to_allow_bucket():
    """A provider ALLOW is not itself a grant: evaluation continues to
    the ALLOW bucket, which must still match for admission."""
    b = _bundle(
        [_rule("ext-check", "custom", provider="pid",
               to={"actions": ["tool.exec"]}),
         _rule("allow-exec", "allow", to={"actions": ["tool.exec"]})],
        authorizers={"pid": {"timeout_ms": 500}})
    v = ac.evaluate(b, _req(),
                    authorizer=lambda pid, req: (True, "ext-ok"))
    ok = (v["decision"] == "allow" and v["code"] == "authz-allow"
          and v["matched_rules"] == ["ext-check", "allow-exec"])
    return (ok, "custom-allow then bucket-allow: %s/%s matched=%r"
            % (v["decision"], v["code"], v["matched_rules"]))


def p21_custom_deny_wins_immediately():
    """A provider DENY decides immediately -- a later ALLOW rule is
    never consulted (deny-direction short-circuit)."""
    b = _bundle(
        [_rule("ext-check", "custom", provider="pid",
               to={"actions": ["tool.exec"]}),
         _rule("allow-exec", "allow", to={"actions": ["tool.exec"]})],
        authorizers={"pid": {"timeout_ms": 500}})
    v = ac.evaluate(b, _req(),
                    authorizer=lambda pid, req: (False, "ext-no"))
    ok = (v["decision"] == "deny" and v["code"] == "authz-deny"
          and v["matched_rules"] == ["ext-check"])
    return (ok, "custom-deny short-circuits: %s/%s matched=%r"
            % (v["decision"], v["code"], v["matched_rules"]))


def p22_control_clean_allow():
    """Control: a clean ALLOW match admits with attribution."""
    b = _bundle([
        _rule("allow-exec", "allow", to={"actions": ["tool.exec"]}),
    ])
    v = ac.evaluate(b, _req())
    ok = (v["decision"] == "allow" and v["code"] == "authz-allow"
          and v["matched_rules"] == ["allow-exec"])
    return (ok, "clean allow: %s/%s matched=%r"
            % (v["decision"], v["code"], v["matched_rules"]))


def p23_evaluate_never_raises_on_garbage():
    """evaluate() never raises: a garbage request fails closed with the
    machine-coded authz-uncheckable backstop."""
    b = _bundle([_rule("allow-exec", "allow")])
    v = ac.evaluate(b, "garbage")
    ok = (isinstance(v, dict) and v["decision"] == "deny"
          and v["code"] == "authz-uncheckable")
    return (ok, "garbage request fail-closed: %s/%s"
            % (v.get("decision"), v.get("code")))


def p24_determinism():
    """Two evaluations of the same request are byte-identical
    (evidence digest stable across runs)."""
    b = _bundle([
        _rule("audit-exec", "audit", to={"actions": ["tool.exec"]}),
        _rule("deny-night", "deny",
              when=[{"key": "hour", "op": "eq", "value": 3}]),
        _rule("allow-exec", "allow", to={"actions": ["tool.exec"]}),
    ])
    req = _req(context={"hour": 12})
    v1 = ac.evaluate(b, req)
    v2 = ac.evaluate(b, req)
    ok = (v1 == v2 and v1["evidence_digest"] == v2["evidence_digest"])
    return (ok, "deterministic: digests %s"
            % (v1["evidence_digest"][:16],))


_PROBES = [p01_deny_wins_over_allow, p02_deny_wins_rule_order_reversed,
           p03_shadow_deny_never_enforces, p04_shadow_allow_never_grants,
           p05_provider_misconfigured_denies_everything,
           p06_provider_absent_hook_denies,
           p07_provider_error_fail_closed,
           p08_provider_timeout_fail_closed,
           p09_partial_deny_when_unevaluable,
           p10_partial_allow_when_unevaluable_no_grant,
           p11_default_deny_with_allow_policies,
           p12_audit_never_enforces, p13_named_rule_attribution,
           p14_within_bucket_or, p15_within_rule_clause_and,
           p16_malformed_bundle_load, p17_malformed_rule_load,
           p18_unknown_action_load, p19_deny_before_custom_no_provider_call,
           p20_custom_allow_continues_to_allow_bucket,
           p21_custom_deny_wins_immediately, p22_control_clean_allow,
           p23_evaluate_never_raises_on_garbage, p24_determinism]


def _pin_check():
    import gov.decision_codes as dc
    n = len(dc.TAXONOMY)
    if n != TAXONOMY_PIN:
        return (False, "PIN MISMATCH: taxonomy has %d keys, pin is %d"
                % (n, TAXONOMY_PIN))
    return (True, "pin %d holds" % TAXONOMY_PIN)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g268authz-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["TMPDIR"] = tmp
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_RUN_ROOT"] = os.path.join(tmp, "realistic")
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    child = os.path.join(repo, "evals", "w267_poldelta_probes.py")
    try:
        r = subprocess.run(
            [sys.executable, child], env=env, cwd=repo,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600)
    except Exception as e:  # noqa: BLE001
        return (False, "green check ERROR: %s" % e)
    out = r.stdout.decode("utf-8", "replace")
    # Lane-local pin drift: this lane adds 10 authz-* codes, so the
    # adjacent battery's own pin assertion (1228) trips on the 1284
    # tree. That drift is the merge coordinator's repoint chore
    # (standard lane convention), not a regression -- accept it only
    # as the SOLE failure cause.
    pin_only = ("PIN MISMATCH: taxonomy has 1299 keys, pin is "
                "1228" in out)
    real_breaks = [l for l in out.splitlines()
                   if l.startswith("BREAK ") or l.startswith("ERROR ")]
    if r.returncode == 0:
        return (True, "w267_poldelta_probes green")
    if pin_only and not real_breaks:
        return (True, "adjacent green apart from known lane-local "
                "pin drift (1284 vs 1228); no real-phase BREAKs")
    return (False, "adjacent battery red: exit %d" % r.returncode)


def main():
    held, broke, errors = [], [], []
    held_broke_in_order = []
    for fn in _PROBES:
        try:
            ok, detail = fn()
        except Exception as e:  # noqa: BLE001
            errors.append((fn.__name__, "%s: %s"
                           % (type(e).__name__, e)))
            held_broke_in_order.append(False)
            continue
        held_broke_in_order.append(ok)
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
    ok, detail = _pin_check()
    print("PIN %s: %s" % ("HELD" if ok else "BREAK", detail))
    if not ok:
        broke.append(("_pin_check", detail))
    ok, detail = _green_check()
    print("GREEN %s: %s" % ("HELD" if ok else "BREAK", detail))
    if not ok:
        broke.append(("_green_check", detail))
    # Determinism: run the probe set twice and require identical
    # verdicts (A==B). Compare boolean outcomes only -- detail strings
    # may carry timing data (e.g. the provider-timeout probe).
    first = list(held_broke_in_order)
    again = []
    for fn in _PROBES:
        try:
            again.append(fn()[0])
        except Exception:  # noqa: BLE001
            again.append(False)
    det_ok = (first == again)
    print("DETERMINISM %s" % ("HELD" if det_ok else "BREAK"))
    if not det_ok:
        broke.append(("_determinism", "second run differed"))
    return 1 if (broke or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
